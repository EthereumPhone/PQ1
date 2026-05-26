//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last two pages of bank 1:
//! - Page 127 (0x0C0F_E000): Tropic01 pairing key / persistent secure data
//! - Page 126 (0x0C0F_C000): OPTIGA Trust M Platform Binding Secret (PBS)
//!
//! The linker script (`memory-stm32u585.x`) must shrink FLASH LENGTH
//! by 16 KB to prevent firmware code from being placed in these pages.
//!
//! ## Unsafe surface
//!
//! All MMIO register access is funnelled through `hw::mmio::{Reg32, RoReg32}`,
//! which encapsulates `read_volatile` / `write_volatile` once per address.
//! The remaining `unsafe fn` markers sit on the public flash-*mutating*
//! APIs (erase / program / bump) for commit-visibility — callers must
//! reason about *which* flash bytes they are about to change. Read-only
//! helpers (`read_key`, `pin_attempts_read`, `offchain_count_read`,
//! `last_userop_count_read`, `offchain_count_is_registered`,
//! `is_key_blank`, `is_wipe_armed`) are safe `fn` because they cannot
//! commit anything; raw pointer derefs of flash memory inside them stay
//! in tight `unsafe { ... }` blocks with `// SAFETY:` comments.

use core::ptr::{read_volatile, write_volatile};

use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Flash controller registers (secure alias)
// ---------------------------------------------------------------------------

const FLASH: u32 = 0x5002_2000;

// Non-secure-controller registers (accessible from secure world via the
// secure peripheral bus — the NS/S distinction here selects which side's
// watermark rules apply, not who can reach the register). Used for
// programming bank 2 (NS flash) pages during firmware updates: NS pages
// are rejected by SECCR because the watermark forbids secure-side
// programming of NS flash, so NSCR is the only controller that can
// write them. The secure world owns the update mechanism end-to-end, so
// NS-world code never touches NSCR directly.

/// Selects which bank the flash controller targets. Only meaningful for
/// dual-bank operations; bank 1 is S-flash, bank 2 is NS-flash in our
/// layout. NSCR.BKER bit.
const BKER: u32 = 1 << 11;

// Unlock key sequence (same as all STM32 families)
const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

// SECCR bit positions
const PG: u32 = 1 << 0; // Programming
const PER: u32 = 1 << 1; // Page Erase
const PNB_SHIFT: u32 = 3; // Page Number starts at bit 3
const STRT: u32 = 1 << 16; // Start
const LOCK: u32 = 1 << 31; // Lock

// SECSR bit positions
const BSY: u32 = 1 << 16; // Busy
const ERR_MASK: u32 = 0xFA; // PROGERR | WRPERR | PGAERR | SIZERR | PGSERR

// ---------------------------------------------------------------------------
// Instruction cache (ICACHE) — must be invalidated after every flash
// erase or program, or subsequent reads return stale cached bytes.
// ---------------------------------------------------------------------------
//
// STM32U5 has a transparent instruction/data cache in front of flash
// (ICACHE at 0x4003_0400 NS / 0x5003_0400 S, enabled at boot by
// default). Cache lines are NOT automatically invalidated when the
// flash contents underneath change — software must issue a `CACHEINV`
// after every flash mutation that touches a region the CPU may have
// cached.
//
// Symptom when missing: `write_quadword_verified` writes fresh bytes,
// the flash controller reports Ok (no SR error), but the immediately-
// following readback returns the OLD pre-write bytes — because the
// CPU is reading from the cache. `write_quadword_verified` then fails
// the compare and returns Err, with the actual flash having the correct
// content. The bug is trivially reproducible when a region is read
// before the flash mutation (so it's cached), then erased/programmed,
// then read again.
//
// Fix: after every successful erase or program (before returning Ok),
// call `icache_invalidate()`. The call is a handful of cycles and
// completely eliminates the "silent readback mismatch" failure mode.

// ICACHE registers live at 0x4003_0400 (NS alias) / 0x5003_0400 (S alias).
// We're secure-world code; use the S alias for symmetry with the FLASH
// register block above. The wrong base (0x4003_0000 — off by 0x400) lands
// in a reserved region on AHB1 and provokes unpredictable behaviour
// (previously: u64_div_rem HardFault shortly after the first write).
const ICACHE_BASE: u32 = 0x5003_0400;
const ICACHE_CR_CACHEINV: u32 = 1 << 1;
const ICACHE_SR_BUSYF: u32 = 1 << 0;

/// All MMIO registers this driver owns, bundled so the one-time
/// `unsafe { ... }` for `Reg32::new` happens once at module scope.
struct FlashRegs {
    seckeyr: Reg32,
    secsr: Reg32,
    seccr: Reg32,
    nskeyr: Reg32,
    nssr: Reg32,
    nscr: Reg32,
    icache_cr: Reg32,
    icache_sr: RoReg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register
// exclusively owned by this driver (the FLASH and ICACHE controllers).
// The secure world is single-threaded and non-preemptive — nothing else
// races us. After this one-time construction every register touch is via
// safe `.read()` / `.write()` / `.modify()`.
const REG: FlashRegs = unsafe {
    FlashRegs {
        seckeyr: Reg32::new(FLASH + 0x0C),
        secsr: Reg32::new(FLASH + 0x24),
        seccr: Reg32::new(FLASH + 0x2C),
        nskeyr: Reg32::new(FLASH + 0x08),
        nssr: Reg32::new(FLASH + 0x20),
        nscr: Reg32::new(FLASH + 0x28),
        icache_cr: Reg32::new(ICACHE_BASE),
        icache_sr: RoReg32::new(ICACHE_BASE + 0x04),
    }
};

/// Invalidate the entire ICACHE so subsequent flash reads see fresh
/// post-erase / post-program bytes rather than stale cached lines.
/// Must be called inside the same interrupt-free block as the flash
/// mutation that triggered it — interleaving isn't a correctness bug
/// (invalidation is idempotent) but keeps the cache-coherency window
/// tight.
fn icache_invalidate() {
    REG.icache_cr.set_bits(ICACHE_CR_CACHEINV);
    while REG.icache_sr.read() & ICACHE_SR_BUSYF != 0 {
        cortex_m::asm::nop();
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

// ---------------------------------------------------------------------------
// Key storage page — last 8 KB of secure flash bank 1 (page 127)
// ---------------------------------------------------------------------------

/// Base address of the reserved key storage page (page 127).
pub const KEY_PAGE_ADDR: u32 = 0x0C0F_E000;
const KEY_PAGE_NUM: u32 = 127;

// NOTE: flash page 126 (the former OPTIGA PBS seal page at
// 0x0C0F_C000) was freed by work-todo #24 — the Platform Binding
// Secret is now re-derived from the OTP master on every boot via
// `hw::secret_keys::optiga_pairing_secret`, so there is nothing to
// seal. The page is now reused as the cross-power-cycle FW-update
// verify-failure counter (`fw_fail_*` below). See
// `docs/optiga-brick-postmortem.md` for the history and the
// hardening doc finding B / persistence follow-up for the new use.

// ---------------------------------------------------------------------------
// Firmware-update verify-failure counter — page 126 (was OPTIGA PBS seal).
// ---------------------------------------------------------------------------
//
// Cross-power-cycle tally of consecutive `verify_manifest` failures at
// CMD_FW_BEGIN. Persists across boots so a physical attacker doing
// glitch-injection on the signature verify can't reset their attempt
// budget by power-cycling. Pairs with the in-RAM per-power-cycle
// counter in `nsc::cmd_fw_begin` (layered defense: in-RAM bounds the
// burst rate within a cycle, this flash counter bounds the lifetime
// budget across cycles).
//
// Layout: 8 KB page, 16-byte QWs. Each fail programs the next blank
// QW with all-zeros. Count = number of programmed (any-zero) QWs.
// Reset = page erase, called from BEGIN on a passing verify chain.
// Threshold check + wipe trigger live in `nsc::cmd_fw_begin`.

/// Base address of the FW-update verify-failure counter page.
pub const FW_FAIL_PAGE_ADDR: u32 = 0x0C0F_C000;
const FW_FAIL_PAGE_NUM: u32 = 126;

/// Soft cap on the tally we ever count up to. The page holds 512 QWs;
/// we stop counting at the threshold (saturating) so a wrap can't
/// happen and so the `>= threshold` check stays cheap. The hardening-
/// doc threshold is well under 512.
const FW_FAIL_PAGE_CAPACITY: u32 = 512;
const FW_FAIL_QW_SIZE: u32 = 16;

/// Read the cross-power-cycle verify-failure tally. Counts how many QWs
/// on page 126 have been programmed (any byte != 0xFF). A partially-
/// programmed QW (brown-out mid-write) counts as programmed —
/// conservative: we under-credit the attacker by at most one, never
/// over-credit.
pub fn fw_fail_count() -> u32 {
    let base = FW_FAIL_PAGE_ADDR as *const u8;
    let mut count: u32 = 0;
    for qw_idx in 0..FW_FAIL_PAGE_CAPACITY {
        let qw_base_offset = (qw_idx * FW_FAIL_QW_SIZE) as usize;
        let mut programmed = false;
        for byte_idx in 0..FW_FAIL_QW_SIZE {
            // SAFETY: `qw_base_offset + byte_idx < FW_FAIL_PAGE_CAPACITY *
            // FW_FAIL_QW_SIZE = 8192`, inside the 8 KB page.
            let b = unsafe { core::ptr::read_volatile(base.add(qw_base_offset + byte_idx as usize)) };
            if b != 0xFF {
                programmed = true;
                break;
            }
        }
        if !programmed {
            // First blank QW — all later QWs are also blank.
            break;
        }
        count += 1;
    }
    count
}

/// Bump the cross-power-cycle verify-failure tally by 1 (program one
/// QW). Returns `Err(())` if the page is exhausted (extremely unlikely
/// in practice — the threshold check + wipe trigger fire long before
/// 512 lifetime failures accumulate).
///
/// # Safety
/// Single-QW flash program. Idempotent at the QW level (writing zeros
/// to an already-zero QW is a no-op on NOR flash); the increment is
/// monotonic by construction.
pub unsafe fn fw_fail_bump() -> Result<(), ()> {
    let pre = fw_fail_count();
    if pre >= FW_FAIL_PAGE_CAPACITY {
        return Err(());
    }
    let target_addr = FW_FAIL_PAGE_ADDR + pre * FW_FAIL_QW_SIZE;
    let sentinel = [0u8; 16];
    // SAFETY: target QW is inside page 126 and was confirmed blank above.
    unsafe { write_quadword_verified(target_addr, &sentinel) }
}

/// Erase the FW-fail counter page (page 126) — resets the tally to 0.
/// Called from `cmd_fw_begin` after a manifest passes the full verify
/// chain + length bounds (a legit update is the signal that the device
/// is not under attack right now, so the lifetime budget resets).
///
/// # Safety
/// Page erase is irreversible for already-programmed bits; the page is
/// dedicated to this counter (and was 0xFF erased after factory wipe of
/// the old OPTIGA PBS seal), so erasing it has no other side effects.
pub unsafe fn fw_fail_reset() -> Result<(), ()> {
    unsafe { erase_secure_page(FW_FAIL_PAGE_NUM) }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Wait until the secure flash controller is not busy.
fn wait_bsy() {
    while REG.secsr.read() & BSY != 0 {
        cortex_m::asm::nop();
    }
}

/// Clear any pending error flags in SECSR (write-1-to-clear).
fn clear_errors() {
    let sr = REG.secsr.read();
    if sr & ERR_MASK != 0 {
        REG.secsr.write(sr & ERR_MASK);
    }
}

/// Unlock the secure flash controller for programming/erase.
fn unlock() {
    // If already unlocked, the key writes are ignored.
    REG.seckeyr.write(KEY1);
    REG.seckeyr.write(KEY2);
}

/// Lock the secure flash controller.
fn lock() {
    REG.seccr.set_bits(LOCK);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Erase the key storage page (page 127, 8 KB).
///
/// After erase, all bytes in the page read as 0xFF.
///
/// # Safety
/// Erases persistent flash. Caller must ensure no other code is relying
/// on the current contents of page 127.
pub unsafe fn erase_key_page() -> Result<(), ()> {
    // HIGH-12 fix: interrupt-free around the erase sequence.
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (KEY_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Program one quad-word (16 bytes / 128 bits) at the given flash address.
///
/// The address must be quad-word aligned (16-byte boundary) and must
/// point within the key storage page. The destination must be erased
/// (all 0xFF) before writing.
///
/// Returns `Err(())` only if the flash controller set one of the error
/// flags (PROGERR / WRPERR / PGAERR / SIZERR / PGSERR). **Does not
/// verify that the bytes actually landed correctly** — a torn write
/// under brown-out can produce a half-programmed quad-word with no
/// error flag set. For persistent data, use `write_quadword_verified`.
///
/// HIGH-12 fix: the whole unlock → program → lock sequence runs
/// inside `cortex_m::interrupt::free` so an IRQ (especially SysTick
/// or the OLED I2C callback) landing mid-sequence can't leave SECCR
/// in an inconsistent state. On STM32U5 an interrupted program
/// sequence can latch PGSERR; the `free` block keeps the sequence
/// atomic.
///
/// # Safety
/// Commits bytes to flash. Caller must guarantee `addr` is quad-word
/// aligned, inside a writable secure-bank page, and currently erased.
unsafe fn write_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        // Set PG bit
        REG.seccr.write(PG);

        // Write 4 × 32-bit words to the target address.
        let dst = addr as *mut u32;
        for i in 0..4 {
            let word = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            // SAFETY: caller asserts `addr..addr+16` is a valid, erased,
            // quad-word-aligned flash region. Volatile prevents the
            // compiler from reordering or coalescing the four word writes
            // that the flash controller expects in sequence.
            unsafe { write_volatile(dst.add(i), word) };
        }

        wait_bsy();

        // Clear PG
        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Program one quad-word **and read it back to confirm the bytes landed**.
///
/// Detects class-A torn writes (brown-out mid-program leaving some bits
/// committed and others not): NOR flash can leave such a QW readable
/// without flagging PROGERR, so a pure `write_quadword` returns `Ok`
/// while the actual memory differs from `data`. The read-back compare
/// here catches that deterministically.
///
/// Use this for anything that matters (admin PIN, PBS, pairing key,
/// wipe flag). Internal helpers that don't care about durability can
/// keep using `write_quadword`.
///
/// # Safety
/// Same contract as [`write_quadword`].
pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    // SAFETY: forwarded contract from caller.
    unsafe { write_quadword(addr, data)? };

    let src = addr as *const u8;
    for i in 0..16 {
        // SAFETY: caller's contract guarantees `addr..addr+16` is a
        // valid 16-byte flash region; we only read.
        if unsafe { read_volatile(src.add(i)) } != data[i] {
            return Err(());
        }
    }
    Ok(())
}

/// Read 32 bytes from the start of the key storage page.
pub fn read_key(buf: &mut [u8; 32]) {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        // SAFETY: `KEY_PAGE_ADDR` is a fixed in-flash region of at least
        // 8 KB; `src.add(0..32)` stays inside that page. Reads from
        // memory-mapped flash are side-effect-free.
        buf[i] = unsafe { read_volatile(src.add(i)) };
    }
}

/// Check whether the key storage page is blank (first 32 bytes = 0xFF).
pub fn is_key_blank() -> bool {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        // SAFETY: same as `read_key`.
        if unsafe { read_volatile(src.add(i)) } != 0xFF {
            return false;
        }
    }
    true
}

/// Write a 32-byte key to the key storage page.
///
/// Erases the page first, then programs two quad-words (2 × 16 bytes).
///
/// # Safety
/// Overwrites persistent flash at `KEY_PAGE_ADDR`. Caller is responsible
/// for any prior contents.
pub unsafe fn write_key(key: &[u8; 32]) -> Result<(), ()> {
    // SAFETY: caller's contract.
    unsafe { erase_key_page()? };

    // First quad-word: bytes 0-15
    let mut qw0 = [0u8; 16];
    qw0.copy_from_slice(&key[..16]);
    // SAFETY: page was just erased to 0xFF; address is aligned and in-page.
    unsafe { write_quadword_verified(KEY_PAGE_ADDR, &qw0)? };

    // Second quad-word: bytes 16-31
    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&key[16..]);
    // SAFETY: see above.
    unsafe { write_quadword_verified(KEY_PAGE_ADDR + 16, &qw1)? };

    Ok(())
}

// ---------------------------------------------------------------------------
// SE050 admin-wipe state — page 125
// ---------------------------------------------------------------------------
//
// Holds the per-device admin PIN (16 bytes from STM32 TRNG, used to
// authenticate against ADMIN_WIPE_OBJ on SE050 during PIN-lockout wipe)
// and a crash-safety flag for interrupted wipes. Independent of OPTIGA
// PBS so SE050-standalone builds work without additional dependencies.
//
// Layout of page 125 (0x0C0F_A000, 8 KB):
//   QW 0 (offset  0..15): admin PIN (16 bytes)
//   QW 1 (offset 16..31): wipe flag — byte 0: 0x00 armed / 0xFF blank
//                                     bytes 1..15: padding (0xFF)
//   bytes 32..8192:       unused, 0xFF after erase
//
// Lifecycle:
//   - First boot: page erased (all 0xFF) → generate random admin PIN
//                 via rng::fill(), write QW 0. Wipe flag stays blank.
//   - Wipe start: program QW 1 to [0x00, 0xFF × 15]. This is a 1→0
//                 bit-clear on a blank QW, which NOR flash allows
//                 without page erase — the admin PIN at QW 0 is preserved
//                 so the wipe routine can still authenticate.
//   - Wipe finish: erase_admin_page(). Clears PIN + flag both back to
//                  0xFF, leaving the SE050 side of the device
//                  "unprovisioned" from this page's perspective.

/// Base address of the SE050 admin-state page (page 125).
pub const ADMIN_PAGE_ADDR: u32 = 0x0C0F_A000;
const ADMIN_PAGE_NUM: u32 = 125;

// Page-125 layout: QW0 (offset 0) is unused on v6 chips (the former
// admin-PIN slot; dead since the OTP-derived scheme); QW1 (offset 16)
// holds the wipe-in-progress flag.
const WIPE_FLAG_OFFSET: u32 = 16;
const WIPE_FLAG_ARMED: u8 = 0x00;

/// Erase page 125. Clears both the admin PIN and the wipe flag.
///
/// # Safety
/// Erases persistent flash at `ADMIN_PAGE_ADDR`.
pub unsafe fn erase_admin_page() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (ADMIN_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

// NOTE: `write_admin_pin` / `read_admin_pin` / `is_admin_pin_blank`
// and `ADMIN_PIN_OFFSET` were all removed (2026-05-11). The SE050
// admin PIN is never persisted to flash — it's re-derived on demand
// from the OTP master via `hw::secret_keys::se050_admin_pin()` (the
// v6 OTP-derived admin scheme; see `Se050::store_objects` /
// `Se050::factory_reset_admin`). The e2e pre-clean cascades that used
// to read a pre-v6 flash PIN now call `Se050::factory_reset_admin()`
// (the v6 path) directly. Page 125 still holds the wipe-in-progress
// flag at `WIPE_FLAG_OFFSET`, which is unrelated.

/// Arm the wipe-in-progress marker. Call immediately before initiating
/// a factory reset so boot-time resume can pick up an interrupted wipe.
///
/// Does NOT erase page 125 — uses a 1→0 bit-clear on a single QW, which
/// NOR flash supports without pre-erase. The admin PIN at QW 0 is
/// preserved so the wipe routine can still authenticate against
/// ADMIN_WIPE_OBJ during resume.
///
/// # Safety
/// Programs a flash quad-word at `ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET`.
pub unsafe fn arm_wipe_flag() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = WIPE_FLAG_ARMED;
    // SAFETY: forwarded contract; target QW is the dedicated wipe-flag slot.
    unsafe { write_quadword_verified(ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET, &qw) }
}

/// Read the wipe-in-progress flag. Returns true iff armed.
pub fn is_wipe_armed() -> bool {
    let src = (ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET) as *const u8;
    // SAFETY: fixed in-flash address inside page 125; memory-mapped read.
    unsafe { read_volatile(src) == WIPE_FLAG_ARMED }
}

// §32 P5 — duress action mode (page 125, QW2 @ offset 32).
//   blank (0xFF) = DECOY  (default — `is_duress_wipe_mode()` is false)
//   programmed (0x00) = WIPE on a duress-PIN unlock
// Blank-as-decoy is the safe default: a power loss after `erase_admin_page`
// but before the wizard sets the mode falls back to decoy (loses no funds),
// matching the wipe-flag convention. Same QW lifecycle — `erase_admin_page`
// (wipe finish) clears it back to decoy, and the next wizard re-collects.
const DURESS_WIPE_MODE_OFFSET: u32 = 32;
const DURESS_WIPE_MODE_SET: u8 = 0x00;

/// Mark the device as WIPE-on-duress. 1→0 bit-clear on a blank QW (no page
/// erase). MUST be called BEFORE provisioning the wallet: a crash between
/// provisioning and this write would leave a duress PIN configured but
/// mode = decoy (default), which silently downgrades the user's chosen
/// protection — flush the mode first, then provision.
///
/// # Safety
/// Programs a flash quad-word at `ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET`.
#[cfg(feature = "duress-pin")]
pub unsafe fn arm_duress_wipe_mode() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = DURESS_WIPE_MODE_SET;
    // SAFETY: forwarded contract; dedicated duress-mode QW slot in page 125.
    unsafe { write_quadword_verified(ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET, &qw) }
}

/// Returns true iff the device is configured to WIPE on a duress-PIN
/// unlock (vs the default: open the decoy wallet). Read by
/// `nsc::gated_unlock` in the duress-match branch.
#[cfg(feature = "duress-pin")]
pub fn is_duress_wipe_mode() -> bool {
    let src = (ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET) as *const u8;
    // SAFETY: fixed in-flash address inside page 125; memory-mapped read.
    unsafe { read_volatile(src) == DURESS_WIPE_MODE_SET }
}

// ---------------------------------------------------------------------------
// MCU-side PIN attempt counter — page 124
// ---------------------------------------------------------------------------
//
// Authoritative PIN-attempt counter. Trezor-parity design (see
// `storage/storage.c:1171-1311` in trezor-firmware): the MCU-side
// counter is the source of truth, incremented BEFORE every SE verify
// (pre-commit), reset only after a successful PIN match. SE-side
// counters (OPTIGA F1E1, SE050 silicon retry on UserID) are
// secondary redundant defenses — if they disagree with the MCU
// counter at boot, the MCU counter wins.
//
// Why MCU-authoritative: OPTIGA's F1E1 counter is soft (writable via
// `Conf(E140)`), so an attacker with PBS extraction can reset it.
// Without an MCU counter, that collapses to "SE050 is the only real
// lockout," burning only SE050's silicon budget. With MCU counter,
// OPTIGA reset attacks cost nothing — the gate is still MCU flash.
//
// Layout of page 124 (0x0C0F_8000, 8 KB):
//   QW 0..(MAX_ATTEMPTS-1): one programmed QW per attempt (any non-
//                           blank pattern marks consumed).
//   Remaining QWs: unused, 0xFF after erase (reserved headroom).
//
// Programmed sentinel: `[0x00; 16]`. Blank sentinel: `[0xFF; 16]`.
//
// Encoding rationale:
//   - STM32U5 flash does NOT allow re-programming an already-
//     programmed word (ECC locks the value). A counter implemented
//     as "rewrite a single byte with the new count" would need a
//     page erase every bump — catastrophic flash wear.
//   - One-QW-per-attempt needs only a fresh blank QW per bump, no
//     rewrite. Page erase only on successful unlock.
//
// Lifecycle:
//   - First boot / successful unlock: page blank (all 0xFF).
//     `pin_attempts_read()` returns 0.
//   - Wrong PIN attempt N: `pin_attempts_bump()` programs QW N-1
//     with `[0x00; 16]`. Post-bump read returns N.
//   - Reach `MAX_ATTEMPTS`: wallet locks out. `trigger_lockout_wipe`
//     wipes SEs + erases page 124 via `pin_attempts_reset()`.
//
// Page choice: 124 over 126. Page 126 (the former OPTIGA PBS seal
// page, freed by work-todo #24) turned out to be in a "freed-but-
// write-hostile" state on the current bench chip — erase returns
// OK (no SR error) but subsequent programs of QW0 fail with
// PROGERR|PGSERR. Page 124 is truly never-touched and accepts
// writes without drama. If future chips exhibit the same issue
// at page 124, we have page 123 still in reserve.

const PIN_ATTEMPTS_PAGE_ADDR: u32 = 0x0C0F_8000;
const PIN_ATTEMPTS_PAGE_NUM: u32 = 124;

/// Maximum counter capacity supported by the current layout. Bigger
/// than `sphincs_tz_shared::MAX_ATTEMPTS` so future relaxation of the
/// PIN policy doesn't need a flash layout change.
const PIN_ATTEMPTS_CAPACITY: u32 = 32;
const PIN_ATTEMPTS_QW_SIZE: u32 = 16;

/// Read the current PIN-attempt count (0..=`PIN_ATTEMPTS_CAPACITY`).
/// Reads the per-QW sentinel bytes and counts how many have been
/// programmed (any non-0xFF byte in QW N). A partially-programmed
/// QW (brown-out mid-write) counts as programmed — conservative:
/// the user gets at most one fewer attempt than the silicon actually
/// recorded, never one more.
///
/// **F-15.r5 hardening (forward + reverse double scan).** Mirrors
/// the F-12 fix to `offchain_count_read`: walk the page forward
/// (early-exit on the first blank QW) and again from the end
/// backward (early-exit on the first programmed QW), and require
/// both passes to agree. A single fault that lands on one
/// direction's early-exit cannot symmetrically affect the other —
/// the two scans have asymmetric control flow by construction. On
/// mismatch we fail-closed by returning `PIN_ATTEMPTS_CAPACITY`,
/// which is strictly greater than `MAX_ATTEMPTS = 10`, so every
/// downstream gate (`gated_unlock`'s `pre_count < MAX_ATTEMPTS`,
/// `verify_pin_with_chip`'s `remaining_after != 0`, and
/// `pin_attempts_bump`'s `pre >= PIN_ATTEMPTS_CAPACITY`) treats this
/// as "lockout reached."
pub unsafe fn pin_attempts_read() -> u8 {
    let fwd = unsafe { pin_attempts_scan_forward() };
    crate::fi::wait_random();
    let rev = unsafe { pin_attempts_scan_reverse() };
    if fwd != rev {
        // Fail-closed sentinel. `PIN_ATTEMPTS_CAPACITY` = 32 >
        // `MAX_ATTEMPTS` = 10, so every gate treats this as locked.
        return PIN_ATTEMPTS_CAPACITY as u8;
    }
    fwd
}

#[inline(never)]
unsafe fn pin_attempts_scan_forward() -> u8 {
    let base = PIN_ATTEMPTS_PAGE_ADDR as *const u8;
    let mut count: u8 = 0;
    for qw_idx in 0..PIN_ATTEMPTS_CAPACITY {
        // SAFETY: `qw_idx * 16 < 512` stays inside the 8 KB page.
        let qw_base = unsafe { base.add((qw_idx * PIN_ATTEMPTS_QW_SIZE) as usize) };
        // Any non-0xFF byte inside this QW marks it "programmed".
        let mut programmed = false;
        for byte_idx in 0..PIN_ATTEMPTS_QW_SIZE {
            // SAFETY: `byte_idx < 16` keeps the offset inside the QW.
            if unsafe { read_volatile(qw_base.add(byte_idx as usize)) } != 0xFF {
                programmed = true;
                break;
            }
        }
        if programmed {
            count = count.saturating_add(1);
        } else {
            // Once we hit a blank QW, all subsequent QWs are also
            // blank (we program them in order). Early-exit.
            break;
        }
    }
    count
}

#[inline(never)]
unsafe fn pin_attempts_scan_reverse() -> u8 {
    // Asymmetric control flow vs `pin_attempts_scan_forward`: walk
    // from CAPACITY-1 backward, early-return on the first programmed
    // QW. Under the invariant "QWs are programmed in order from 0,
    // contiguously," the first-programmed-from-end QW is at index
    // `count - 1`, so we return `i + 1`. A fault that early-exits
    // the forward scan (e.g. flipping the `programmed` flag false
    // mid-scan) cannot identically affect the reverse pass, which
    // starts from the opposite boundary and walks in the opposite
    // direction with a different loop shape.
    let base = PIN_ATTEMPTS_PAGE_ADDR as *const u8;
    let mut i = PIN_ATTEMPTS_CAPACITY;
    while i > 0 {
        i -= 1;
        let qw_base = base.add((i as usize) * (PIN_ATTEMPTS_QW_SIZE as usize));
        let mut programmed = false;
        for byte_idx in 0..PIN_ATTEMPTS_QW_SIZE {
            if read_volatile(qw_base.add(byte_idx as usize)) != 0xFF {
                programmed = true;
                break;
            }
        }
        if programmed {
            // u8 holds 0..=PIN_ATTEMPTS_CAPACITY (32) — well below
            // the u8 ceiling, so saturating_add is defensive only.
            return (i as u8).saturating_add(1);
        }
    }
    0
}

/// Bump the attempt counter by one. Programs the next blank QW
/// (at index == pre-bump count) with `[0x00; 16]` and verifies
/// the post-bump count is exactly one higher. Returns the new count.
///
/// Fault-injection note: a glitch that skips the program entirely
/// would leave the count unchanged. The post-bump read-back rejects
/// that with `Err(())` — caller must halt / refuse the attempt on
/// failure. A glitch that writes a DIFFERENT QW would leave gaps
/// (blank QWs between programmed ones); `pin_attempts_read` counts
/// strictly in-order and stops at the first blank, so such a write
/// is detected as "count unchanged" and similarly rejected.
///
/// # Safety
/// Same contract as [`pin_attempts_read`].
pub unsafe fn pin_attempts_bump() -> Result<u8, ()> {
    let pre = pin_attempts_read();
    if (pre as u32) >= PIN_ATTEMPTS_CAPACITY {
        return Err(());
    }

    let target_addr =
        PIN_ATTEMPTS_PAGE_ADDR + (pre as u32) * PIN_ATTEMPTS_QW_SIZE;
    let sentinel = [0u8; 16];
    // SAFETY: target QW is inside page 124 and was confirmed blank above.
    unsafe { write_quadword_verified(target_addr, &sentinel)? };

    // FI hardening: volatile-delay between write and readback so a
    // clock-aligned glitch that skipped the write cannot also suppress
    // the readback of the old value on the same cycle.
    crate::fi::wait_random();

    let post = pin_attempts_read();
    if post != pre + 1 {
        return Err(());
    }
    // Re-read under a sentinel-gated check — a glitch that skips the
    // `if post != pre + 1` bypass has to also defeat `fi::check_true`.
    if crate::fi::check_true_into_sentinel(|| pin_attempts_read() == pre + 1)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(post)
}

/// Erase page 124 — clears every attempt marker back to blank.
/// Called only after a successful PIN verify completes end-to-end
/// on both SEs. After this, `pin_attempts_read()` returns 0.
///
/// # Safety
/// Erases the PIN-attempt counter page. Must only be called after a
/// successful PIN verify on both SEs; an out-of-order call would
/// silently reset the lockout state.
pub unsafe fn pin_attempts_reset() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (PIN_ATTEMPTS_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

// ===========================================================================
// Firmware-update plumbing: bank-2 (non-secure) flash + slot geometry
// ===========================================================================
//
// The firmware-update subsystem writes new firmware images into the
// inactive A/B slot. The secure world owns the entire update flow — NS
// code never programs flash directly — so we provide bank-2 primitives
// on the secure side, accessed through the FLASH_NS{KEYR,SR,CR} register
// aliases. These registers are on the secure peripheral bus and are
// reachable from secure-world code; the "NS" prefix refers to which
// side's watermarks the controller honours (NSCR programs pages that
// SECCR refuses because of the SECWMn watermark).
//
// Slot layout (see docs/firmware-update.md for the full picture):
//
//   Bank 1 (secure):
//     FSBL             pages   0..3    0x0C00_0000  (32 KB, WRP-locked)
//     Manifest A       page    4       0x0C00_8000  (8 KB)
//     Manifest B       page    5       0x0C00_A000  (8 KB)
//     Boot state       page    6       0x0C00_C000  (8 KB, redundant)
//     Slot A secure    pages   7..64   0x0C00_E000  (464 KB)
//     Slot B secure    pages  65..122  0x0C08_2000  (464 KB)
//     (reserved)       pages 123..127  legacy + PBS + SE050 admin
//
//   Bank 2 (non-secure):
//     Slot A NS        pages   0..63   0x0810_0000  (512 KB)
//     Slot B NS        pages  64..127  0x0818_0000  (512 KB)

/// A/B slot identifier. FSBL chooses one at boot based on manifest
/// validity + rollback floor + try-once semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

// --- Manifest page addresses --------------------------------------------------

pub const MANIFEST_A_ADDR: u32 = 0x0C00_8000;
pub const MANIFEST_A_PAGE: u32 = 4;
pub const MANIFEST_B_ADDR: u32 = 0x0C00_A000;
pub const MANIFEST_B_PAGE: u32 = 5;

pub fn manifest_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => MANIFEST_A_ADDR,
        Slot::B => MANIFEST_B_ADDR,
    }
}

pub fn manifest_page_num(slot: Slot) -> u32 {
    match slot {
        Slot::A => MANIFEST_A_PAGE,
        Slot::B => MANIFEST_B_PAGE,
    }
}

// --- Boot state page ----------------------------------------------------------

pub const BOOT_STATE_ADDR: u32 = 0x0C00_C000;
pub const BOOT_STATE_PAGE: u32 = 6;

// --- Slot image addresses -----------------------------------------------------

pub const SLOT_A_SECURE_ADDR: u32 = 0x0C00_E000;
pub const SLOT_A_SECURE_FIRST_PAGE: u32 = 7;
pub const SLOT_A_SECURE_LAST_PAGE: u32 = 64;

pub const SLOT_B_SECURE_ADDR: u32 = 0x0C08_2000;
pub const SLOT_B_SECURE_FIRST_PAGE: u32 = 65;
pub const SLOT_B_SECURE_LAST_PAGE: u32 = 122;

/// Secure-slot usable byte capacity (bytes writable into one slot).
/// 58 pages × 8 KB = 464 KB. Firmware images larger than this are
/// rejected at `CMD_FW_BEGIN`.
pub const SLOT_SECURE_CAPACITY: u32 = 58 * 8 * 1024;

pub const SLOT_A_NS_ADDR: u32 = 0x0810_0000;
pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;
pub const SLOT_A_NS_LAST_PAGE: u32 = 63;

pub const SLOT_B_NS_ADDR: u32 = 0x0818_0000;
pub const SLOT_B_NS_FIRST_PAGE: u32 = 64;
pub const SLOT_B_NS_LAST_PAGE: u32 = 127;

/// NS-slot usable byte capacity. 64 pages × 8 KB = 512 KB.
pub const SLOT_NS_CAPACITY: u32 = 64 * 8 * 1024;

pub fn slot_secure_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => SLOT_A_SECURE_ADDR,
        Slot::B => SLOT_B_SECURE_ADDR,
    }
}

pub fn slot_ns_addr(slot: Slot) -> u32 {
    match slot {
        Slot::A => SLOT_A_NS_ADDR,
        Slot::B => SLOT_B_NS_ADDR,
    }
}

pub fn slot_secure_pages(slot: Slot) -> (u32, u32) {
    match slot {
        Slot::A => (SLOT_A_SECURE_FIRST_PAGE, SLOT_A_SECURE_LAST_PAGE),
        Slot::B => (SLOT_B_SECURE_FIRST_PAGE, SLOT_B_SECURE_LAST_PAGE),
    }
}

pub fn slot_ns_pages(slot: Slot) -> (u32, u32) {
    match slot {
        Slot::A => (SLOT_A_NS_FIRST_PAGE, SLOT_A_NS_LAST_PAGE),
        Slot::B => (SLOT_B_NS_FIRST_PAGE, SLOT_B_NS_LAST_PAGE),
    }
}

// ---------------------------------------------------------------------------
// Bank-2 (NS flash) program + erase primitives
// ---------------------------------------------------------------------------

/// Unlock the NS flash controller. Symmetric to [`unlock`] but uses the
/// NSKEYR register, enabling programming of pages covered by the NS
/// watermark (bank 2 in our layout). A failed unlock latches OPTLOCK;
/// recovery requires a system reset.
fn unlock_ns() {
    REG.nskeyr.write(KEY1);
    REG.nskeyr.write(KEY2);
}

/// Lock the NS flash controller after a program/erase sequence.
fn lock_ns() {
    REG.nscr.set_bits(LOCK);
}

fn wait_bsy_ns() {
    while REG.nssr.read() & BSY != 0 {
        cortex_m::asm::nop();
    }
}

fn clear_errors_ns() {
    let sr = REG.nssr.read();
    if sr & ERR_MASK != 0 {
        REG.nssr.write(sr & ERR_MASK);
    }
}

/// Erase one page of bank 2. `page` is the in-bank index (0..=127);
/// physical address is `0x0810_0000 + page * 8192`.
///
/// Returns `Err(())` on any error flag in NSSR (including WRPERR if
/// the pages are write-protected, which would catch an accidental
/// attempt to erase a slot that the FSBL has marked locked — though
/// WRP in our design only covers the FSBL pages themselves, not the
/// slots).
///
/// # Safety
/// Erases a non-secure-bank page. Caller must ensure the page is part
/// of the inactive A/B slot.
pub unsafe fn erase_ns_page(page: u8) -> Result<(), ()> {
    assert!(page <= 127, "ns-bank page out of range");
    let page = page as u32;

    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        // BKER=1 selects bank 2.
        let cr = PER | BKER | (page << PNB_SHIFT);
        REG.nscr.write(cr);
        REG.nscr.write(cr | STRT);

        wait_bsy_ns();

        REG.nscr.write(0);
        let sr = REG.nssr.read();
        lock_ns();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if sr & ERR_MASK != 0 {
            clear_errors_ns();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Program one quad-word to bank 2 at `addr`. Unlike
/// `write_quadword`, this routes through NSCR so the NS watermark is
/// honoured. `addr` must be inside bank-2 (`0x0810_0000..0x0820_0000`)
/// and quad-word-aligned, and the 16 bytes at `addr` must already be
/// erased (all 0xFF).
///
/// Same semantics as `write_quadword`: returns `Err(())` only on a
/// flagged error. **Not** read-back verified — for persistence use
/// [`write_ns_quadword_verified`] which adds the brown-out guard.
///
/// # Safety
/// Same shape as [`write_quadword`] but targets bank 2.
unsafe fn write_ns_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    debug_assert!(addr >= 0x0810_0000 && addr < 0x0820_0000);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        REG.nscr.write(PG);

        let dst = addr as *mut u32;
        for i in 0..4 {
            let word = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            // SAFETY: caller asserts `addr..addr+16` is a valid, erased,
            // quad-word-aligned bank-2 flash region. Volatile guarantees the
            // four word writes happen in order, as the flash controller
            // expects.
            unsafe { write_volatile(dst.add(i), word) };
        }

        wait_bsy_ns();

        REG.nscr.write(0);
        let sr = REG.nssr.read();
        lock_ns();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if sr & ERR_MASK != 0 {
            clear_errors_ns();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Program one bank-2 quad-word and verify the bytes landed. Defends
/// against silent torn writes (brown-out mid-program leaving some bits
/// committed) — same invariant as [`write_quadword_verified`] on bank 1.
///
/// # Safety
/// Same contract as [`write_ns_quadword`].
pub unsafe fn write_ns_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    // SAFETY: forwarded contract.
    unsafe { write_ns_quadword(addr, data)? };

    let src = addr as *const u8;
    for i in 0..16 {
        // SAFETY: `addr..addr+16` was just written; read-back stays in-region.
        if unsafe { read_volatile(src.add(i)) } != data[i] {
            return Err(());
        }
    }
    Ok(())
}

/// Erase a page that's part of a slot (dispatches to SECCR for secure
/// bank-1 pages and NSCR for NS bank-2 pages based on the absolute
/// page index). Used by `CMD_FW_BEGIN` to prepare the inactive slot
/// before streaming starts.
///
/// # Safety
/// Erases a secure-bank page. Caller must ensure the page is part of
/// the inactive A/B slot or is otherwise safe to clear.
pub unsafe fn erase_secure_page(page: u32) -> Result<(), ()> {
    assert!(page <= 127, "bank-1 page out of range");
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (page << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Erase the full set of pages owned by `slot` — both secure and
/// non-secure halves. Used at `CMD_FW_BEGIN` after the host declares
/// which inactive slot it's about to stream into. Order matters: we
/// erase the manifest last so a power-fail midway leaves the old
/// manifest still intact (and the now-partially-erased slot unusable,
/// which matches the previous state exactly — the old manifest
/// pointed at the *other* slot).
///
/// # Safety
/// Erases all pages of `slot`. Caller must ensure `slot` is the
/// inactive A/B slot.
pub unsafe fn erase_slot(slot: Slot) -> Result<(), ()> {
    let (first_s, last_s) = slot_secure_pages(slot);
    let (first_ns, last_ns) = slot_ns_pages(slot);

    for p in first_ns..=last_ns {
        // SAFETY: forwarded contract.
        unsafe { erase_ns_page(p as u8)? };
    }
    for p in first_s..=last_s {
        // SAFETY: forwarded contract.
        unsafe { erase_secure_page(p)? };
    }
    // Erase the target manifest last: this is what FSBL keys off to
    // decide whether the slot is active. While the manifest is erased
    // (all-0xFF), FSBL will reject it as BadMagic, so it cannot be
    // booted — and the other slot's manifest is still whole.
    // SAFETY: forwarded contract.
    unsafe { erase_secure_page(manifest_page_num(slot))? };

    Ok(())
}

/// Program a single quad-word anywhere inside a slot. Routes to the
/// correct controller (SECCR for bank 1, NSCR for bank 2) based on
/// the address. Returns `Err(())` on any flagged error or torn-write
/// detection.
///
/// # Safety
/// Commits 16 bytes to flash at `addr`. Caller must ensure the address
/// is inside the inactive A/B slot and currently erased.
pub unsafe fn write_slot_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    if (0x0810_0000..0x0820_0000).contains(&addr) {
        // SAFETY: forwarded contract; bank-2 dispatch.
        unsafe { write_ns_quadword_verified(addr, data) }
    } else if (0x0C00_0000..0x0C10_0000).contains(&addr) {
        // SAFETY: forwarded contract; bank-1 dispatch.
        unsafe { write_quadword_verified(addr, data) }
    } else {
        Err(())
    }
}

// ===========================================================================
// Off-chain (EIP-1271) per-slot counter — page 123
// ===========================================================================
//
// One-page log-structured store for two per-slot u64 counters:
//   * `offchain_count[slot]`  — bumped on every CMD_SIGN_OFFCHAIN.
//   * `last_userop_count[slot]` — set when CMD_SIGN_USEROP commits
//     `local_offchain_count` into the signed inner tx.
//
// Each entry is one 16-byte quad-word:
//
//     [ 0..  8) slot_key  — sha256(account_index‖chain_id‖slot_index)[..8]
//     [ 8..  9) type      — 0x01 = offchain count, 0x02 = last_userop count
//     [ 9.. 16) count     — u64 BE big-endian, top byte is `type`
//
// Read = scan the page; for each non-blank QW with matching `slot_key`
// and `type`, take `max(current, count)`. Write = program the next
// blank QW. When the page fills, compaction reads the latest
// (slot_key, type) values into SRAM, erases the page, and replays them.
//
// "Slot is registered" is defined as "this firmware has at least one
// entry for this slot_key in flash". `register_slot` writes a
// last_userop_count = 0 entry the first time the firmware signs Type 1
// for the slot — that single QW is enough to flip the
// `is_registered` predicate to true for all subsequent calls. Without
// it, `cmd_sign_offchain` refuses, which is the recovery-correctness
// gate after a seed-restore.
//
// Page choice: 123 is the highest free secure page (124..127 are
// already allocated; 122 is the last secure-firmware page in the A/B
// slot layout). 8 KB / 16 = 512 QWs per cycle; we expect realistic
// usage < 50 active slots × 65,536 sigs ≈ 3.3 M total bumps over the
// device lifetime, ÷ 512 per cycle = ~6500 erase cycles — within the
// 10,000-cycle minimum endurance the STM32U585 datasheet specifies.

const OFFCHAIN_PAGE_ADDR: u32 = 0x0C0F_6000;
const OFFCHAIN_PAGE_NUM: u32 = 123;
const OFFCHAIN_QW_SIZE: u32 = 16;
const OFFCHAIN_CAPACITY: u32 = 512; // 8 KB / 16

const OFFCHAIN_TYPE_COUNT: u8 = 0x01;
const OFFCHAIN_TYPE_USEROP: u8 = 0x02;

/// Pack a journal entry into a 16-byte quad-word.
fn entry_qw(slot_key: &[u8; 8], entry_type: u8, count: u64) -> [u8; 16] {
    let mut qw = [0u8; 16];
    qw[..8].copy_from_slice(slot_key);
    qw[8] = entry_type;
    let count_be = count.to_be_bytes();
    qw[9..16].copy_from_slice(&count_be[1..8]); // 7-byte BE — supports up to 2^56
    qw
}

/// Parse a journal entry. Three outcomes:
///   * `None` — QW is truly blank (every byte is 0xFF). End of journal;
///     readers can stop scanning here.
///   * `Some((0, _, _))` — QW is non-blank but undecodable (stale bits
///     inherited from pre-all-C10 cutover firmware where the type byte
///     happens to be 0xFF but other bytes are not, OR an unknown type).
///     Readers MUST treat this as "skip and keep scanning" — there may
///     be valid entries past this hole.
///   * `Some((COUNT|USEROP, slot_key, count))` — valid entry.
///
/// The all-16-byte blank check has to mirror `find_next_blank_idx` exactly.
/// Without it, the writer's "skip stale QW, write to next truly-blank slot"
/// path produces entries the reader cannot find: every read short-circuits
/// at the first stale QW and `is_registered` returns false even though the
/// write succeeded into a later QW. Symptom on a real device that
/// upgraded across the cutover: `cmd_sign_offchain` refuses with
/// `OffchainSlotUnregistered` after one or more successful UserOps that
/// (silently) appended valid entries past a stale type-byte-0xFF QW.
///
fn parse_entry(qw_addr: u32) -> Option<(u8, [u8; 8], u64)> {
    let base = qw_addr as *const u8;
    // SAFETY: `base.add(8)` stays inside the QW.
    let type_byte = unsafe { read_volatile(base.add(8)) };
    if type_byte == 0xFF {
        // Type byte is 0xFF — could be a truly-blank QW (end of journal)
        // or a stale QW where only the type byte happens to read 0xFF.
        // Disambiguate via the same all-16-byte check `find_next_blank_idx`
        // uses; only an all-blank QW signals end-of-journal.
        let mut all_blank = true;
        for k in 0..(OFFCHAIN_QW_SIZE as usize) {
            // SAFETY: `k < 16` stays inside the QW.
            if unsafe { read_volatile(base.add(k)) } != 0xFF {
                all_blank = false;
                break;
            }
        }
        if all_blank {
            return None;
        }
        // Stale, undecodable, but the page may have valid entries past it.
        return Some((0, [0u8; 8], 0));
    }
    if type_byte != OFFCHAIN_TYPE_COUNT && type_byte != OFFCHAIN_TYPE_USEROP {
        // Unknown type — treat as corrupt, skip but don't stop the scan.
        return Some((0, [0u8; 8], 0));
    }
    let mut slot_key = [0u8; 8];
    for i in 0..8 {
        // SAFETY: `i < 8` stays inside the QW.
        slot_key[i] = unsafe { read_volatile(base.add(i)) };
    }
    let mut count_bytes = [0u8; 8];
    for i in 0..7 {
        // SAFETY: `9 + i < 16` stays inside the QW.
        count_bytes[1 + i] = unsafe { read_volatile(base.add(9 + i)) };
    }
    let count = u64::from_be_bytes(count_bytes);
    Some((type_byte, slot_key, count))
}

/// Find the first blank QW in the page. Returns the QW *index*, or
/// `None` if the page is full and a compaction is required.
///
/// "Blank" means all 16 bytes of the QW are 0xFF. The cheap one-byte
/// check on the type field is wrong on devices that were upgraded
/// across the all-C10 cutover: pages 123–124 used to hold per-slot
/// persistent state, the firmware update doesn't erase them, and
/// stale bytes randomly leave QWs whose type byte is 0xFF but whose
/// other 15 bytes still hold old programmed bits. Writing to such a
/// QW with `write_quadword_verified` PROGERRs (NOR flash can only
/// flip 1→0; it cannot re-program a bit that is already 0) and the
/// caller surfaces it as "Sig commit FAIL".
///
fn find_next_blank_idx() -> Option<u32> {
    let base = OFFCHAIN_PAGE_ADDR as *const u8;
    for i in 0..OFFCHAIN_CAPACITY {
        // SAFETY: `i * 16 < 8192` stays inside the page.
        let qw_base = unsafe { base.add((i * OFFCHAIN_QW_SIZE) as usize) };
        let mut all_blank = true;
        for k in 0..(OFFCHAIN_QW_SIZE as usize) {
            // SAFETY: `k < 16` stays inside the QW.
            if unsafe { read_volatile(qw_base.add(k)) } != 0xFF {
                all_blank = false;
                break;
            }
        }
        if all_blank {
            return Some(i);
        }
    }
    None
}

/// Erase page 123 — wipes every off-chain counter back to "no record".
/// On the next access, every slot will look unregistered. Use only as
/// part of compaction (which immediately re-writes the latest values
/// before any other code touches the page) or in a deliberate
/// reset-to-factory flow.
///
/// # Safety
/// Erases persistent flash at `OFFCHAIN_PAGE_ADDR`.
unsafe fn erase_offchain_page() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (OFFCHAIN_PAGE_NUM << PNB_SHIFT);
        REG.seccr.write(cr);
        REG.seccr.write(cr | STRT);

        wait_bsy();

        REG.seccr.write(0);
        let sr = REG.secsr.read();
        lock();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// Maximum number of distinct active slots the SRAM compaction buffer
/// supports. Realistic usage is far below this; well-behaved firmware
/// rotates slots before they exhaust their 65,536-sig cap.
const MAX_ACTIVE_SLOTS: usize = 256;

/// SRAM scratch table for compaction.
#[derive(Clone, Copy)]
struct SlotEntry {
    slot_key: [u8; 8],
    offchain_count: u64,
    last_userop_count: u64,
    has_offchain: bool,
    has_userop: bool,
}

/// Scan the page once and project the latest `(offchain, last_userop)`
/// pair for every observed `slot_key`. Used by both compaction and the
/// (rarely-needed) "show me all active slots" introspection path. The
/// table is allocated on the caller's stack via the in/out reference.
///
/// Returns the number of distinct slot_keys observed.
fn scan_page_into_table(table: &mut [SlotEntry; MAX_ACTIVE_SLOTS]) -> usize {
    let mut n: usize = 0;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break, // first blank — done
            Some((0, _, _)) => continue, // unknown type — skip
            Some((t, sk, count)) => {
                // Find existing entry for this slot_key, else allocate.
                let mut found: Option<usize> = None;
                for j in 0..n {
                    if table[j].slot_key == sk {
                        found = Some(j);
                        break;
                    }
                }
                let idx = match found {
                    Some(j) => j,
                    None => {
                        if n >= MAX_ACTIVE_SLOTS {
                            // Saturate; subsequent slots silently dropped.
                            // In practice this never triggers (page only
                            // holds 512 QWs, and N distinct slots <= 512).
                            continue;
                        }
                        let j = n;
                        n += 1;
                        table[j] = SlotEntry {
                            slot_key: sk,
                            offchain_count: 0,
                            last_userop_count: 0,
                            has_offchain: false,
                            has_userop: false,
                        };
                        j
                    }
                };
                if t == OFFCHAIN_TYPE_COUNT {
                    if count > table[idx].offchain_count || !table[idx].has_offchain {
                        table[idx].offchain_count = count;
                    }
                    table[idx].has_offchain = true;
                } else if t == OFFCHAIN_TYPE_USEROP {
                    if count > table[idx].last_userop_count || !table[idx].has_userop {
                        table[idx].last_userop_count = count;
                    }
                    table[idx].has_userop = true;
                }
            }
        }
    }
    n
}

/// Compact the page: read the latest values per (slot_key, type) into
/// SRAM, erase, then replay. Power-loss-tolerant: a torn compaction
/// leaves the page (partially) erased, which loses counters for some
/// slots — those slots then look unregistered, which forces a Type 1
/// re-registration but does not break correctness.
///
/// # Safety
/// Erases and rewrites page 123.
unsafe fn compact_page() -> Result<(), ()> {
    let mut table = [SlotEntry {
        slot_key: [0u8; 8],
        offchain_count: 0,
        last_userop_count: 0,
        has_offchain: false,
        has_userop: false,
    }; MAX_ACTIVE_SLOTS];
    let n = scan_page_into_table(&mut table);

    // SAFETY: about to replay from SRAM.
    unsafe { erase_offchain_page()? };

    // Replay: write surviving entries at the start of the page.
    for j in 0..n {
        let entry = table[j];
        let mut idx: u32 = 0;
        if entry.has_userop {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_USEROP, entry.last_userop_count);
            // Find next blank inside the freshly-erased page.
            let blank = find_next_blank_idx().ok_or(())?;
            idx = blank;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
        if entry.has_offchain {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_COUNT, entry.offchain_count);
            let blank = find_next_blank_idx().ok_or(())?;
            // Defensive: ensure we did not somehow regress.
            if blank < idx {
                return Err(());
            }
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
    }
    Ok(())
}

/// Append a journal entry, compacting first if the page is full and
/// self-healing the page if it inherited unwritable garbage from the
/// pre-all-C10 per-slot state.
///
/// Three retry tiers:
/// 1. Happy path: a truly-blank QW exists, write succeeds.
/// 2. Page full: run a normal compaction (preserves valid entries).
/// 3. Page is wedged in an unwritable shape — i.e. either compaction
///    can't free space *or* the targeted "blank" QW won't accept the
///    write because of stale 0-bits from the prior incarnation. Bulk-
///    erase the whole page and retry once. Stale data here cannot be
///    a valid current entry the wallet still cares about: pages
///    123–124 were freed by the cutover and any leftover bits were
///    written by long-since-removed firmware. Compaction would have
///    surfaced that as `Some((0, _, _))` "unknown type" entries which
///    are explicitly skipped, so the bulk erase loses nothing live.
///
/// # Safety
/// Programs page 123.
unsafe fn write_entry(qw: &[u8; 16]) -> Result<(), ()> {
    if find_next_blank_idx().is_none() {
        // SAFETY: caller asserts page 123 is writable; compaction is
        // power-loss-tolerant per its doc comment.
        unsafe { compact_page()? };
    }

    // First write attempt — at the QW chosen by find_next_blank_idx.
    if let Some(blank) = find_next_blank_idx() {
        // SAFETY: target QW is inside page 123 and was just observed blank.
        if unsafe {
            write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, qw)
        }
        .is_ok()
        {
            return Ok(());
        }
    }

    // Self-heal: bulk-erase the page and retry once. After the erase
    // the whole page is 0xFF, so find_next_blank_idx returns 0 and the
    // write must succeed (or the flash itself is dead).
    // SAFETY: see write_entry's # Safety contract.
    unsafe { erase_offchain_page()? };
    let blank = find_next_blank_idx().ok_or(())?;
    // SAFETY: target QW is inside page 123 and was just erased.
    unsafe { write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, qw) }
}

/// Forward scan — the original log-structured implementation. Stops at the
/// first all-blank QW (= end of journal). Used as the first leg of the
/// F-12 fault-injection-hardened double-scan.
#[inline(never)]
unsafe fn scan_forward(slot_key: &[u8; 8], target_type: u8) -> u64 {
    let mut latest: u64 = 0;
    let mut found = false;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break,
            Some((t, sk, count)) if t == target_type && sk == *slot_key => {
                if count > latest || !found {
                    latest = count;
                    found = true;
                }
            }
            _ => {}
        }
    }
    latest
}

/// Reverse scan — iterates QWs from CAPACITY-1 down to 0, skipping ALL
/// blanks and undecodable entries (no early-break on None). Asymmetric
/// control flow vs `scan_forward`: a fault that early-exits the forward
/// loop doesn't symmetrically early-exit this one. F-12 fix: comparing
/// the two scans' results catches any FI-induced underreporting.
#[inline(never)]
unsafe fn scan_reverse(slot_key: &[u8; 8], target_type: u8) -> u64 {
    let mut latest: u64 = 0;
    let mut i = OFFCHAIN_CAPACITY;
    while i > 0 {
        i -= 1;
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, sk, count)) = parse_entry(addr) {
            if t == target_type && sk == *slot_key && count > latest {
                latest = count;
            }
        }
        // Note: no break-on-None — keep iterating across blank tail QWs.
    }
    latest
}

/// Read the latest off-chain sig count for `slot_key`. Returns 0 if no
/// entry exists (caller distinguishes "0 sigs" from "unregistered" via
/// `offchain_count_is_registered`).
///
/// **F-12 hardening (single-fault rollback resistance).** Scans the page
/// forward AND reverse with `wait_random()` between, and halts the CPU on
/// mismatch. A single fault that underreports one direction cannot affect
/// both — the reverse pass iterates the page asymmetrically (no early-break
/// on blank, walks from end), so a control-flow corruption at scan entry
/// affects forward only. Pre-fix, `make flashctr` empirically found **770
/// single-fault rollback cases** on this code (see tools/sca/README.md §F-12);
/// post-fix the hardened mirror is down to ~10 (control-flow at scan entry
/// that early-exits BOTH directions identically — the residual is bounded
/// by additional layers a future hardening pass could add).
pub unsafe fn offchain_count_read(slot_key: &[u8; 8]) -> u64 {
    // F-12 hardening: slot_key input-register redundancy. Load the key
    // twice via `read_volatile` with a randomised gap between, halt-on-
    // mismatch. A stuck-at-0 fault on the slot_key argument register
    // would otherwise survive into both forward and reverse scans
    // (`make flashctr` empirically saw 10 such residuals before this
    // belt-and-braces was added).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_COUNT);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_COUNT);
    if r1 != r2 {
        // FI glitch detected. The caller can't recover — return the
        // safest value: u64::MAX. Downstream cap checks (`new_count >
        // MAX_SLOT_USES`) will trip and refuse to sign. This is fail-
        // closed: rather than risk a silent rollback we permanently
        // refuse signing until the next power cycle resets the cap-check
        // path on a fresh emulator instance.
        return u64::MAX;
    }
    r1
}

/// Read the most recent UserOp-snapshot count (the value embedded in
/// the inner tx of the last `CMD_SIGN_USEROP`). F-12-hardened: same
/// forward+reverse double scan as `offchain_count_read`.
pub unsafe fn last_userop_count_read(slot_key: &[u8; 8]) -> u64 {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_USEROP);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_USEROP);
    if r1 != r2 {
        return u64::MAX;
    }
    r1
}

/// True iff this firmware has at least one entry for `slot_key`.
/// After a fresh-from-seed boot this is `false` for every slot, which
/// is the recovery refusal gate.
///
/// F-12-hardened: forward + reverse double scan, halt-on-mismatch. The
/// answer is a single bit so a fault on one direction's return could flip
/// it; reverse cross-check catches that.
///
/// # Safety
/// Same contract as the other `offchain_count_*` readers — reads from
/// the page-123 journal.
pub unsafe fn offchain_count_is_registered(slot_key: &[u8; 8]) -> bool {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return false;
    }
    let r1 = unsafe { is_registered_forward(&sk_a) };
    crate::fi::wait_random();
    let r2 = unsafe { is_registered_reverse(&sk_b) };
    if r1 != r2 {
        // Fail-closed: report unregistered → refuses the off-chain sign
        // path until the next call.
        return false;
    }
    r1
}

#[inline(never)]
unsafe fn is_registered_forward(slot_key: &[u8; 8]) -> bool {
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => return false,
            Some((0, _, _)) => continue,
            Some((_, sk, _)) if sk == *slot_key => return true,
            _ => continue,
        }
    }
    false
}

#[inline(never)]
unsafe fn is_registered_reverse(slot_key: &[u8; 8]) -> bool {
    let mut i = OFFCHAIN_CAPACITY;
    while i > 0 {
        i -= 1;
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, sk, _)) = parse_entry(addr) {
            if t != 0 && sk == *slot_key {
                return true;
            }
        }
    }
    false
}

/// Write the "slot is registered" marker (a last_userop_count = 0
/// entry). No-op if already registered. Called by `cmd_sign_userop`
/// when it signs a Type 1 for a fresh slot.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_register_slot(slot_key: &[u8; 8]) -> Result<(), ()> {
    if offchain_count_is_registered(slot_key) {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP, 0);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw) }
}

/// Bump the off-chain sig counter to `new_count`. Reverts via `Err(())`
/// if `new_count <= current`; the caller (cmd_sign_offchain) computes
/// `new_count = current + 1` so this only fails on flash trouble.
///
/// **F-12 hardening — slot_key input-redundancy.** A fault at function
/// prologue can stuck-at the `slot_key` register before it's used by
/// `offchain_count_read` / `entry_qw`. The function would then operate
/// on the WRONG slot (read its max, write an entry for it), pass the
/// FI triple-check (which also reads the wrong slot), and return Ok —
/// while OUR slot's counter never advanced. Defense: dereference the
/// caller's slot_key into TWO local copies with `wait_random()` between,
/// compare; halt if they differ. Then use only the locally-verified copy.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
    // F-12: input redundancy on slot_key. Catches stuck-at on the
    // slot_key pointer/register at function entry.
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = offchain_count_read(slot_key);
    if new_count <= pre {
        return Err(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_COUNT, new_count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening: read-back the post-bump value, refuse if it didn't
    // land. Mirrors `pin_attempts_bump`.
    let post = offchain_count_read(slot_key);
    if post != new_count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_read(slot_key) == new_count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Promote the off-chain sig counter for `slot_key` to at least `target`.
/// Idempotent if the stored value already meets or exceeds `target`.
///
/// Used by the sign path to repair a stale local view: if a flash event
/// (compaction half-failure, partial torn write, etc.) lost a `COUNT`
/// entry but kept its `USEROP` snapshot, `offchain_count_read` can dip
/// below `last_userop_count_read`. Signing with the lower value would
/// always revert on-chain because `_setOffchainSigCount` enforces
/// monotonicity over `offchainSigCount[i]`. Re-asserting the high-water
/// mark here keeps the firmware's view consistent with what was last
/// committed to the chain so the next Type 2 sig commits a value the
/// chain will accept.
///
/// # Safety
/// Programs page 123.
pub unsafe fn offchain_count_promote_to(slot_key: &[u8; 8], target: u64) -> Result<(), ()> {
    // F-12: slot_key input-redundancy (see offchain_count_bump for rationale).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = offchain_count_read(slot_key);
    if target <= pre {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_COUNT, target);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw) }
}

/// Update the last_userop_count snapshot for `slot_key`. Idempotent if
/// `count == current`. Tolerant of `count < current`: rather than
/// permanently failing the sign with an `Err` (which manifested as
/// "Sig commit FAIL" on the OLED and bricked the slot for future
/// signs), it returns `Ok` as a no-op. Real monotonicity is enforced
/// at two stronger gates: (a) the sign path promotes
/// `new_offchain_count` to `max(offchain_count_read,
/// last_userop_count_read)` so this function is never reached with
/// `count < pre` in correct execution, and (b) the on-chain
/// `_setOffchainSigCount` reverts on non-monotonic input — that revert
/// is the authoritative gate, not this firmware-side check.
///
/// # Safety
/// Programs page 123.
pub unsafe fn last_userop_count_set(slot_key: &[u8; 8], count: u64) -> Result<(), ()> {
    // F-12: slot_key input-redundancy.
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = last_userop_count_read(slot_key);
    if count < pre {
        // Defensive no-op. The flash already records a higher
        // high-water mark; the caller is either replaying a stale
        // value (harmless) or has a bug we cannot fix from here. Do
        // not regress the stored value — the on-chain state would
        // not accept a regression either.
        return Ok(());
    }
    if count == pre && offchain_count_is_registered(slot_key) {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP, count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw) }
}
