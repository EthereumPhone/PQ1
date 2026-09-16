//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last two pages of bank 1:
//! - Page 127 (0x0C0F_E000): first-boot provisioning journal (KEY_PAGE)
//! - Page 126 (0x0C0F_C000): DHUK-wrapped SE050 BHK when `bhk` is enabled
//!
//! OPTIGA PBS bytes are derived rather than stored verbatim, but the
//! `rdp2-self-lock` final PBS depends on the persisted salt in page 127.
//! Firmware-update verification has no persistent failure counter.
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
//! helpers (`pin_attempts_read`, `offchain_count_read`,
//! `last_userop_count_read`, `offchain_count_is_registered`,
//! `is_wipe_armed`) are safe `fn` because they cannot
//! commit anything; raw pointer derefs of flash memory inside them stay
//! in tight `unsafe { ... }` blocks with `// SAFETY:` comments.

use core::ptr::{read_volatile, write_volatile};

use crate::flash_policy::{self, GenericSecurePage, GenericSecureQwAddr};
use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Flash controller registers (secure alias)
// ---------------------------------------------------------------------------

const FLASH: u32 = 0x5002_2000;

// Non-secure-controller registers MUST be reached via the NS alias of the
// FLASH peripheral block (0x4002_2000), even when called from the secure
// world. The secure alias of the SAME register set silently corrupts NSCR
// writes — every NSCR-initiated program/erase returns PGSERR on STM32U585.
// ST's HAL `FLASH_PageErase`/`FLASH_Program_QuadWord` confirm this: when
// `IS_FLASH_SECURE_OPERATION()` is false (i.e. the caller is operating on
// NS-classified pages) HAL uses `&(FLASH_NS->NSCR)` — the NS alias of the
// same register block. Driving NSCR via the secure alias was the cause of
// the bank-2 erase failure during the fwup-transport-e2e bring-up.
const FLASH_NS: u32 = 0x4002_2000;

/// `FLASH_OPTR` offset (RM0456 §7.11) — RDP[7:0] in the low byte. And
/// `FLASH_SECBOOTADD0R` offset (secure boot-address option register), confirmed
/// as `FLASH_S+0x4C` by the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`,
/// `FLASH_SECBOOTADD0R` addressOffset `0x4c`) and RM0456 §7.9.16.
#[allow(dead_code)]
const FLASH_OPTR_OFF: u32 = 0x40;
#[allow(dead_code)]
const FLASH_SECBOOTADD0R_OFF: u32 = 0x4C;

/// STM32U585 legacy bench FSBL base (secure bank-1 page 0).
///
/// The target shipping design keeps this entry, but production extent/WRP and
/// option-byte authority remain open until their reviewed ceremony and silicon
/// receipts close.
#[allow(dead_code)]
pub const FSBL_BASE_ADDR: u32 = pqsigner_geometry::BANK1_BASE;

// The pure RDP/SECBOOTADD0 decode + its host unit tests live in the
// host-compiled `sphincs_tz_shared::lockdown` (this whole `hw` module is
// `#[cfg(not(test))]`, so an in-module test never runs). Re-export the level
// enum so `hw::flash::RdpLevel` keeps working for callers.
pub use sphincs_tz_shared::lockdown::RdpLevel;

/// Read the live RDP level from `FLASH_OPTR` (secure alias, read-only).
///
/// NOTE (BOOT_LOCK/HDP1 follow-up): we check the RDP level and the boot
/// *address* (`secboot_selects_fsbl`) — the reliable, code-confirmed signals.
/// `BOOT_LOCK` is bit 0 (RM0456 §7.9.16, pinned as
/// `lockdown::SECBOOTADD0_BOOT_LOCK`); the apparent `0x0C00_007C` vs
/// `0x0018_0000` contradiction was register-word vs CubeProgrammer field-value,
/// not a disagreement about the bit (#214). `HDP1` polarity IS still
/// doc-ambiguous, so asserting that remains a bench-confirmation follow-up.
#[cfg(feature = "stm32u585")]
#[allow(dead_code)]
#[must_use]
pub fn rdp_level() -> RdpLevel {
    // SAFETY: `FLASH_OPTR` is a real, 4-byte-aligned MMIO register in the
    // secure FLASH-controller block (unlike NSCR, OPTR is readable via the
    // secure alias). The secure world is single-threaded; this is a pure read.
    let optr = unsafe { crate::hw::mmio::RoReg32::new(FLASH + FLASH_OPTR_OFF) }.read();
    sphincs_tz_shared::lockdown::rdp_level_from_byte((optr & 0xFF) as u8)
}

/// Read the live `SECBOOTADD0R` (secure alias, read-only).
#[cfg(feature = "stm32u585")]
#[allow(dead_code)]
#[must_use]
pub fn secboot_add0_reg() -> u32 {
    // SAFETY: a real, 4-byte-aligned secure option register (same class as
    // `FLASH_OPTR`); single-threaded secure world; pure read.
    unsafe { crate::hw::mmio::RoReg32::new(FLASH + FLASH_SECBOOTADD0R_OFF) }.read()
}

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
        // NS-controller registers via the NS alias — see the comment on
        // FLASH_NS above. The secure alias for NSCR fails with PGSERR.
        nskeyr: Reg32::new(FLASH_NS + 0x08),
        nssr: Reg32::new(FLASH_NS + 0x20),
        nscr: Reg32::new(FLASH_NS + 0x28),
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
// First-boot provisioning journal — last 8 KB of secure flash bank 1 (page 127)
// ---------------------------------------------------------------------------

/// Base address of the reserved first-boot journal page (page 127).
pub const KEY_PAGE_ADDR: u32 = flash_policy::FIRST_BOOT_JOURNAL_ADDR;

// NOTE: flash page 126 (the former OPTIGA PBS seal page at
// 0x0C0F_C000) was freed by work-todo #24 — the Platform Binding
// Secret is now resolved via `hw::secret_keys::current_pbs`; after first-boot
// completion that derivation also depends on the salt in page 127. Page 126
// is exclusively owned by the wrapped SE050 BHK store when `bhk` is enabled. Firmware
// update verification intentionally has no persistent failure counter:
// malformed companion input must never erase, reset, or write wallet state.

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

// The raw bank-1 program primitive is private to this child module.  Its only
// outward capabilities are (a) a generic writer that requires the pure
// policy's validated, journal-disjoint address type and (b) an index-bounded
// journal writer.  A same-file helper cannot alias the raw primitive because
// Rust privacy prevents the parent module from naming child-private items.
mod bank1_programming {
    use super::{
        clear_errors, icache_invalidate, lock, read_volatile, unlock, wait_bsy, write_volatile,
        GenericSecureQwAddr, ERR_MASK, PG, REG,
    };

    /// Program one raw bank-1 quad-word. The destination contract is supplied
    /// exclusively by one of the two capability-bearing wrappers below.
    unsafe fn write_raw(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
        cortex_m::interrupt::free(|_| {
            wait_bsy();
            clear_errors();
            unlock();

            REG.seccr.write(PG);
            let dst = addr as *mut u32;
            for i in 0..4 {
                let word = u32::from_le_bytes([
                    data[i * 4],
                    data[i * 4 + 1],
                    data[i * 4 + 2],
                    data[i * 4 + 3],
                ]);
                // SAFETY: the caller supplied either a validated generic
                // address or an index-bounded journal address. Volatile writes
                // preserve the controller's required four-word sequence.
                unsafe { write_volatile(dst.add(i), word) };
            }

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

    /// Program and read back a raw address already authorized by this module.
    unsafe fn write_verified_raw(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
        // SAFETY: forwarded contract from the capability-bearing caller.
        unsafe { write_raw(addr, data)? };

        let src = addr as *const u8;
        for (i, expected) in data.iter().enumerate() {
            // SAFETY: the capability proves `addr..addr+16` is a valid flash
            // quad-word. This is a read-only verification pass.
            if unsafe { read_volatile(src.add(i)) } != *expected {
                return Err(());
            }
        }
        Ok(())
    }

    pub(super) unsafe fn write_generic_verified(
        addr: GenericSecureQwAddr,
        data: &[u8; 16],
    ) -> Result<(), ()> {
        // SAFETY: `GenericSecureQwAddr` proves the full raw-writer contract
        // except erased state, which remains the caller's responsibility.
        unsafe { write_verified_raw(addr.get(), data) }
    }

    #[cfg(feature = "rdp2-self-lock")]
    pub(super) unsafe fn write_journal_verified(
        qw_index: usize,
        data: &[u8; 16],
    ) -> Result<(), ()> {
        if qw_index >= 512 {
            return Err(());
        }
        let addr = super::KEY_PAGE_ADDR + (qw_index as u32) * 16;
        // SAFETY: the checked index confines the address to page 127 and the
        // caller guarantees append-at-erased-frontier semantics.
        unsafe { write_verified_raw(addr, data) }
    }
}

/// Program one quad-word **and read it back to confirm the bytes landed**.
///
/// Detects class-A torn writes (brown-out mid-program leaving some bits
/// committed and others not). The first-boot journal page is deliberately
/// rejected: its only writer is [`write_journal_qw`], which holds the private
/// raw capability above. This makes a renamed or cross-module generic caller
/// unable to overwrite the persisted final-PBS salt.
///
/// # Safety
/// The destination must be erased. The address is validated here as an
/// aligned quad-word wholly inside bank-1 pages 0..=126; page 127 is never a
/// valid target.
pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    let addr = GenericSecureQwAddr::new(addr).ok_or(())?;
    // SAFETY: the validated capability excludes page 127, misalignment,
    // out-of-bank ranges, and checked-add overflow. The caller still owns the
    // erased-destination precondition.
    unsafe { bank1_programming::write_generic_verified(addr, data) }
}

// ===========================================================================
// work-todo #36 — first-boot RDP-2 self-lock + page-127 provisioning journal.
//
// Compiled ONLY for the shipping self-lock feature (`rdp2-self-lock`); every
// current dev / QEMU / bench build omits this block entirely, so their flash
// behaviour is byte-identical to before. The one genuinely new *mutating*
// routine is `program_rdp_level2_and_launch` — the irreversible RDP burn —
// which is why it lives behind the same feature the `nsc/mod.rs` ship fence
// forces on only for `mode-production`.
//
// Register offsets and the OPTSTRT/OBL_LAUNCH/OPTLOCK bit positions come from
// the vendor SVD (`STM32CubeProgrammer/SVD/STM32U585.svd`) and RM0456; they are
// mirrored as host-tested constants in `sphincs_tz_shared::lockdown`
// (`FLASH_NSCR_OFF`, `FLASH_OPTSTRT`, …). The former `tools/ob-configurator`
// is NOT the authority for them — it swapped the SECSR/SECCR offsets and has
// been deleted (#37). `secsr=0x24 / seccr=0x2C` as bound in `REG` above is
// SVD-correct. WRP1AR / SECWM offsets + the OEM-lock status register are
// BENCH-CONFIRM (RM0456) items — see the #36 deferred runbook.
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ KNOWN DEFECT #268 — the three option-byte accesses below use `seccr`.   │
// │ Per the SVD, `OPTSTRT` (17), `OBL_LAUNCH` (27) and `OPTLOCK` (30) exist │
// │ ONLY in `FLASH_NSCR` (0x28); `FLASH_SECCR` (0x2C) implements none of    │
// │ them. So the commit is inert, the OPTLOCK check can never fire, and     │
// │ `program_rdp_level2_and_launch` returns Ok(()) after failing to burn.   │
// │ NOT fixed here by deliberate decision: this is the irreversible RDP-2   │
// │ path and wants an owner decision plus a sacrificial-silicon plan, not a │
// │ drive-by edit. `REG.nscr` is already bound and correct for the fix.     │
// │ Never executed — `rdp2-self-lock` is production-quarantined.            │
// │ Guarded by `negative_optbyte_commit_defect_268_is_marked_or_fixed`.     │
// └─────────────────────────────────────────────────────────────────────────┘
// ===========================================================================

/// Option-byte key register offset (RM0456; `FLASH_S+0x10`).
#[cfg(feature = "rdp2-self-lock")]
const OPTKEYR_OFF: u32 = 0x10;
/// Option-byte unlock keys (RM0456 §7.9.2 `FLASH_OPTKEYR`).
#[cfg(feature = "rdp2-self-lock")]
const OPT_KEY1: u32 = 0x0819_2A3B;
#[cfg(feature = "rdp2-self-lock")]
const OPT_KEY2: u32 = 0x4C5D_6E7F;
/// `SECCR.OPTSTRT` (bit 17) — commit staged option bytes to flash.
#[cfg(feature = "rdp2-self-lock")]
const OPTSTRT: u32 = 1 << 17;
/// `SECCR.OBL_LAUNCH` (bit 27) — reload option bytes (triggers a reset).
#[cfg(feature = "rdp2-self-lock")]
const OBL_LAUNCH: u32 = 1 << 27;
/// `SECCR.OPTLOCK` (bit 30) — cleared by the `OPTKEYR` key sequence.
#[cfg(feature = "rdp2-self-lock")]
const OPTLOCK: u32 = 1 << 30;
/// `FLASH_OPTR.RDP` byte value for Level 2 (permanent debug lockdown).
#[cfg(feature = "rdp2-self-lock")]
const RDP_LEVEL2: u32 = 0xCC;
/// BENCH-CONFIRM (RM0456) register offsets for the ship-profile verifier.
#[cfg(feature = "rdp2-self-lock")]
const SECWM1R1_OFF: u32 = 0x50;
#[cfg(feature = "rdp2-self-lock")]
const WRP1AR_OFF: u32 = 0x58;
#[cfg(feature = "rdp2-self-lock")]
const SECWM2R1_OFF: u32 = 0x60;

/// Raw `FLASH_OPTR` (TZEN / BOR_LEV / RDP fields for the ship-profile check).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn optr_raw() -> u32 {
    // SAFETY: real, 4-byte-aligned secure option register; pure read.
    unsafe { RoReg32::new(FLASH + FLASH_OPTR_OFF) }.read()
}

/// Raw `SECWM1R1` (bank-1 secure watermark).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn secwm1r1_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + SECWM1R1_OFF) }.read()
}

/// Raw `SECWM2R1` (bank-2 secure watermark).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn secwm2r1_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + SECWM2R1_OFF) }.read()
}

/// Raw `WRP1AR` (FSBL write-protect span). BENCH-CONFIRM offset.
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn wrp1ar_raw() -> u32 {
    // SAFETY: as `optr_raw`.
    unsafe { RoReg32::new(FLASH + WRP1AR_OFF) }.read()
}

/// Raw OEM-lock status. BENCH-CONFIRM register (FLASH_NSSR vs FLASH_OPTSR) —
/// the bit *masks* live in `sphincs_tz_shared::lockdown` (`OEM1LOCK`/`OEM2LOCK`).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn oem_lock_status_raw() -> u32 {
    // SAFETY: real, 4-byte-aligned FLASH status register; pure read.
    unsafe { RoReg32::new(FLASH_NS + 0x20) }.read()
}

/// Is a bank-1 secure page fully erased (all `0xFF`)? Phase A blank-checks the
/// per-device pages 123..=127 before the RDP burn: a pre-planted page-127
/// journal salt would otherwise yield a predictable final PBS (#36 hardening).
#[cfg(feature = "rdp2-self-lock")]
#[must_use]
pub fn is_secure_page_blank(page: u32) -> bool {
    assert!(page <= 127, "bank-1 page out of range");
    let base = FSBL_BASE_ADDR + page * 0x2000; // 8 KB pages, secure alias
    let src = base as *const u32;
    for i in 0..(0x2000 / 4) {
        // SAFETY: `base..base+8KB` is a fixed in-flash page; read-only.
        if unsafe { read_volatile(src.add(i)) } != 0xFFFF_FFFF {
            return false;
        }
    }
    true
}

/// Append one 16-byte record to the page-127 provisioning journal at
/// `qw_index` (0..512). Read-back-verified; ICACHE is invalidated by
/// the same raw bank-1 writer used by `write_quadword_verified`.
///
/// # Safety
/// Programs persistent flash in page 127 (KEY_PAGE — owned outright by the
/// first-boot journal). Caller ensures the QW is
/// currently erased (the codec only ever appends at the scanned `next_free`).
#[cfg(feature = "rdp2-self-lock")]
pub unsafe fn write_journal_qw(qw_index: usize, rec: &[u8; 16]) -> Result<(), ()> {
    // SAFETY: the child-module capability checks the index and confines the
    // write to page 127; the caller guarantees append-at-erased-frontier.
    unsafe { bank1_programming::write_journal_verified(qw_index, rec) }
}

/// **Irreversible.** Stage `FLASH_OPTR.RDP = 0xCC` (Level 2), commit the
/// option bytes, and reload them (`OBL_LAUNCH` → system reset).
///
/// On success this **never returns** (the MCU resets). It only *returns* on a
/// pre-launch error — as `Err(())` — so Phase A can show a numbered fault and
/// halt UNLOCKED without having locked a bad unit. A power loss between the
/// `OPTSTRT` commit and `OBL_LAUNCH` is safe: the option bytes are already in
/// flash, so the next natural reset boots at RDP-2 (#36 (b) — the one
/// unavoidable residual window; keep it short, BOR on).
///
/// # Safety
/// Permanently sets RDP Level 2. Caller MUST have verified the ship option-
/// byte profile + blank per-device pages first (Phase A) — RDP-2 is
/// unrecoverable.
#[cfg(feature = "rdp2-self-lock")]
pub unsafe fn program_rdp_level2_and_launch() -> Result<(), ()> {
    let commit = cortex_m::interrupt::free(|_| -> Result<(), ()> {
        // SAFETY: option-byte registers in the secure FLASH block; single-
        // threaded secure world; each `unsafe` funnels through `Reg32` once.
        let optkeyr = unsafe { Reg32::new(FLASH + OPTKEYR_OFF) };
        let optr = unsafe { Reg32::new(FLASH + FLASH_OPTR_OFF) };

        wait_bsy();
        clear_errors();
        unlock();
        if REG.seccr.read() & LOCK != 0 {
            return Err(()); // flash controller still locked (not in secure mode?)
        }

        // Unlock the option-byte area.
        optkeyr.write(OPT_KEY1);
        optkeyr.write(OPT_KEY2);
        cortex_m::asm::dsb();
        if REG.seccr.read() & OPTLOCK != 0 {
            return Err(()); // option bytes still locked
        }

        // Stage RDP=0xCC, preserving TZEN / BOR / WRP / SECWM / … .
        let staged = (optr.read() & !0xFF) | RDP_LEVEL2;
        optr.write(staged);

        // Commit the staged option bytes to flash.
        REG.seccr.write(OPTSTRT);
        wait_bsy();
        let sr = REG.secsr.read();
        // NOTE (BENCH-CONFIRM): `ERR_MASK` catches the general program/erase
        // errors; option-write errors (`OPTWERR`) live in a separate bit that
        // is a runbook pin. A missed OPTWERR is non-fatal — the burn simply
        // didn't take, so the next boot re-attempts idempotently.
        if sr & ERR_MASK != 0 {
            clear_errors();
            return Err(());
        }
        Ok(())
    });

    commit?;

    // Success: reload option bytes → system reset. Diverges.
    // SAFETY: option bytes are staged + committed; OBL_LAUNCH resets the MCU.
    unsafe { obl_launch() }
}

/// Trigger `OBL_LAUNCH` (option-byte reload → system reset). Never returns.
#[cfg(feature = "rdp2-self-lock")]
unsafe fn obl_launch() -> ! {
    cortex_m::interrupt::free(|_| {
        REG.seccr.write(OBL_LAUNCH);
    });
    // OBL_LAUNCH triggers a system reset; if for any reason it doesn't, park
    // rather than continue into an inconsistent boot.
    loop {
        cortex_m::asm::wfe();
    }
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
pub const ADMIN_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, ADMIN_PAGE_NUM as u8);
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
// via `hw::secret_keys::se050_admin_pin()` (BHK in the production
// target, DHUK fallback, OTP only in explicit dev/legacy builds; see
// `Se050::store_objects` /
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
//
// F26/LIFE-1 (cut point B): the READ is fail-closed — anything OTHER than
// the pristine-blank byte (0xFF) means wipe. Only a deliberately-blank QW
// (never armed, or cleanly cleared by `erase_admin_page`) selects decoy;
// the armed 0x00 AND every unknown/torn/glitch pattern select the
// destruction path, so an ambiguous read can never silently downgrade the
// user's chosen protection to the decoy.
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
///
/// FAIL-CLOSED (F26/LIFE-1): true unless the byte reads the
/// pristine-blank `0xFF`. The armed value (`DURESS_WIPE_MODE_SET`)
/// and any unknown/torn pattern both read as wipe — only a
/// deliberately-blank QW opens the decoy.
#[cfg(feature = "duress-pin")]
pub fn is_duress_wipe_mode() -> bool {
    let src = (ADMIN_PAGE_ADDR + DURESS_WIPE_MODE_OFFSET) as *const u8;
    // SAFETY: fixed in-flash address inside page 125; memory-mapped read.
    unsafe { read_volatile(src) != 0xFF }
}

// ---------------------------------------------------------------------------
// MCU-side PIN attempt counter — page 124
// ---------------------------------------------------------------------------
//
// Persistent user-facing PIN-attempt counter. Trezor-parity design (see
// `storage/storage.c:1171-1311` in trezor-firmware): page 124 is precharged
// BEFORE every SE verify and reset only after a successful PIN match. It is
// therefore the firmware gate for the ten-attempt policy.
//
// Under `optiga-hw-counter`, OPTIGA E120 is a separate silicon-enforced LUC
// and the directional boot rollback witness. A benign cut can leave page 124
// one attempt ahead, so reconciliation accepts `mcu >= e120`; only
// `e120 > mcu` proves page-124 rollback. F1E1 is frozen as the
// provisioning/reset sentinel in this profile and is not an attempt counter.
// SE050 UserID independently enforces its max-ten retry policy, but its attempt
// attribute is not boot-readable under the production policy. Do not describe
// reconciliation as "the MCU counter always wins" or as a symmetric
// three-counter readback.
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
// page, now owned by the wrapped BHK store) turned out to be in a "freed-but-
// write-hostile" state on the current bench chip — erase returns
// OK (no SR error) but subsequent programs of QW0 fail with
// PROGERR|PGSERR. Page 124 is truly never-touched and accepts
// writes without drama. If future chips exhibit the same issue
// at page 124, we have page 123 still in reserve.

const PIN_ATTEMPTS_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, PIN_ATTEMPTS_PAGE_NUM as u8);
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
///
/// `#[inline(never)]` (MEDIUM-2, audit pin-unlock 20260625): the caller
/// (`nsc::gated_unlock`) FAIL-INs on a missing bump, which only works if the
/// bump is a real `bl` at the call site — an inlined body would let a glitch
/// skip the program without leaving a skippable branch for the sentinel to
/// catch.
#[inline(never)]
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
// Slot layout (see docs/firmware/firmware-update.md for the full picture):
//
//   Bank 1 (secure):
//     FSBL             pages   0..3    0x0C00_0000  (legacy 32 KB bench layout)
//     Manifest A       page    4       0x0C00_8000  (8 KB)
//     Manifest B       page    5       0x0C00_A000  (8 KB)
//     Boot state       page    6       0x0C00_C000  (8 KB, redundant)
//     Slot A secure    pages   7..64   0x0C00_E000  (464 KB)
//     Slot B secure    pages  65..122  0x0C08_2000  (464 KB)
//     (reserved)       pages 123..127  legacy state + admin/wipe + wrapped BHK
//
//   Bank 2 (non-secure):
//     Slot A NS        pages   0..63   0x0810_0000  (512 KB)
//     Slot B NS        pages  64..127  0x0818_0000  (512 KB)

/// A/B slot identifier. The current V1 selector is legacy bench code; the
/// Draft 1.1 proposes a replacement typed selector interface, but is not
/// implementation-approved.
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

/// Slot capacities are a shared host/device release-policy constant.
pub use fw_manifest::{SLOT_NS_CAPACITY, SLOT_SECURE_CAPACITY};

pub const SLOT_A_NS_ADDR: u32 = 0x0810_0000;
pub const SLOT_A_NS_FIRST_PAGE: u32 = 0;
pub const SLOT_A_NS_LAST_PAGE: u32 = 63;

pub const SLOT_B_NS_ADDR: u32 = 0x0818_0000;
pub const SLOT_B_NS_FIRST_PAGE: u32 = 64;
pub const SLOT_B_NS_LAST_PAGE: u32 = 127;

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

    // NSCR is reached via the NS alias of the FLASH register block
    // (see `FLASH_NS` at top of file). The single-shot CR write matches
    // ST HAL's `FLASH_PageErase` MODIFY_REG pattern.
    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        let cr = PER | BKER | (page << PNB_SHIFT) | STRT;
        REG.nscr.write(cr);

        wait_bsy_ns();

        REG.nscr.write(0);
        let sr = REG.nssr.read();
        lock_ns();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        // Invalidate ICACHE after the bank-2 erase/program, matching the
        // bank-1 helpers (see the file header comment: "after every
        // successful erase or program, call icache_invalidate()"). Without
        // this, a same-power-cycle re-flash whose target lines were cached
        // by a prior read (e.g. COMMIT's verify_images hashing the slot)
        // makes the verified read-back observe STALE bytes and fail the
        // compare — a spurious FlashError that dogs the FW-update retry
        // until a power cycle, even though the flash is correct.
        icache_invalidate();

        if sr & ERR_MASK != 0 {
            clear_errors_ns();
            Err(())
        } else {
            Ok(())
        }
    })
}

/// First byte after flash bank 2 (NS alias `0x0810_0000`, 128 × 8 KiB).
const BANK2_END: u32 = pqsigner_geometry::BANK2_BASE
    + pqsigner_geometry::PAGES_PER_BANK as u32 * pqsigner_geometry::PAGE_SIZE;
/// First byte after flash bank 1 (secure alias `0x0C00_0000`).
const BANK1_END: u32 = pqsigner_geometry::BANK1_BASE
    + pqsigner_geometry::PAGES_PER_BANK as u32 * pqsigner_geometry::PAGE_SIZE;

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
    debug_assert!(addr >= pqsigner_geometry::BANK2_BASE && addr < BANK2_END);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| {
        wait_bsy_ns();
        clear_errors_ns();
        unlock_ns();

        // Clear any latent op bits, then arm PG.
        REG.nscr.write(0);
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
        // Invalidate ICACHE after the bank-2 erase/program, matching the
        // bank-1 helpers (see the file header comment: "after every
        // successful erase or program, call icache_invalidate()"). Without
        // this, a same-power-cycle re-flash whose target lines were cached
        // by a prior read (e.g. COMMIT's verify_images hashing the slot)
        // makes the verified read-back observe STALE bytes and fail the
        // compare — a spurious FlashError that dogs the FW-update retry
        // until a power cycle, even though the flash is correct.
        icache_invalidate();

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
    // The proof constructor fails closed for page 127 and every out-of-range
    // value before the flash controller is unlocked or any MMIO write occurs.
    let page = GenericSecurePage::new(page).ok_or(())?.get();
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
        // Invalidate ICACHE after the bank-1 slot-page erase, matching the
        // other secure erase/program helpers (file header comment). A
        // stale cached line here would make a subsequent verified re-flash
        // read back the pre-erase bytes and spuriously fail (see the
        // erase_ns_page / write_ns_quadword twins).
        icache_invalidate();

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
    if (pqsigner_geometry::BANK2_BASE..BANK2_END).contains(&addr) {
        // SAFETY: forwarded contract; bank-2 dispatch.
        unsafe { write_ns_quadword_verified(addr, data) }
    } else if (pqsigner_geometry::BANK1_BASE..BANK1_END).contains(&addr) {
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

const OFFCHAIN_PAGE_ADDR: u32 =
    pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, OFFCHAIN_PAGE_NUM as u8);
const OFFCHAIN_PAGE_NUM: u32 = 123;
const OFFCHAIN_QW_SIZE: u32 = 16;
const OFFCHAIN_CAPACITY: u32 = 512; // 8 KB / 16

const OFFCHAIN_TYPE_COUNT: u8 = 0x01;
const OFFCHAIN_TYPE_USEROP: u8 = 0x02;
// MEDIUM-2 (audit counter-replay 20260611): durable per-slot count of
// Type-2 (slot-key) UserOp signatures this firmware has *produced* for
// the slot — including ones the companion never broadcast or that
// reverted on-chain. On-chain `slotUses[i]` only counts UserOps that
// *landed*, and EIP-1271 off-chain sigs are never counted on-chain at
// all, so the device cannot enforce the combined SPHINCS+ budget
// `slotUses + offchainSigCount <= MAX_SLOT_USES` from on-chain state
// alone. This local tally lets the firmware bound the *total* slot-key
// signatures it emits (off-chain + UserOp) to `MAX_SLOT_USES` per device
// incarnation, closing the ~2x combined-cap evasion a malicious companion
// could otherwise reach by withholding the publishing UserOps.
const OFFCHAIN_TYPE_USEROP_SIGS: u8 = 0x03;

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
    if type_byte != OFFCHAIN_TYPE_COUNT
        && type_byte != OFFCHAIN_TYPE_USEROP
        && type_byte != OFFCHAIN_TYPE_USEROP_SIGS
    {
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
    userop_sigs: u64,
    has_offchain: bool,
    has_userop: bool,
    has_userop_sigs: bool,
}

/// Scan the page once and project the latest `(offchain, last_userop,
/// userop_sigs)` triple for every observed `slot_key`. Used by both
/// compaction and the (rarely-needed) "show me all active slots"
/// introspection path. The table is allocated on the caller's stack via
/// the in/out reference.
///
/// Returns the number of distinct slot_keys observed. **HIGH-1 (audit
/// counter-replay 20260611):** if more than `MAX_ACTIVE_SLOTS` distinct
/// slot_keys are present, `*overflow` is set to `true` and the surplus
/// slots are NOT projected. The old code silently dropped them, which
/// erased those slots' counters on the next compaction — a counter
/// rollback. `compact_page` now refuses (fail-closed) when `overflow`
/// is set rather than committing a lossy compaction.
fn scan_page_into_table(
    table: &mut [SlotEntry; MAX_ACTIVE_SLOTS],
    overflow: &mut bool,
) -> usize {
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
                            // HIGH-1 fail-closed: do NOT silently drop. Flag
                            // the overflow so the caller refuses the
                            // (lossy) compaction instead of rolling back
                            // the surplus slots' counters to zero. The page
                            // only holds 512 QWs, so 256 distinct live slots
                            // is already pathological.
                            *overflow = true;
                            continue;
                        }
                        let j = n;
                        n += 1;
                        table[j] = SlotEntry {
                            slot_key: sk,
                            offchain_count: 0,
                            last_userop_count: 0,
                            userop_sigs: 0,
                            has_offchain: false,
                            has_userop: false,
                            has_userop_sigs: false,
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
                } else if t == OFFCHAIN_TYPE_USEROP_SIGS {
                    if count > table[idx].userop_sigs || !table[idx].has_userop_sigs {
                        table[idx].userop_sigs = count;
                    }
                    table[idx].has_userop_sigs = true;
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
        userop_sigs: 0,
        has_offchain: false,
        has_userop: false,
        has_userop_sigs: false,
    }; MAX_ACTIVE_SLOTS];
    let mut overflow = false;
    let n = scan_page_into_table(&mut table, &mut overflow);

    // HIGH-1 fail-closed: if the page holds more distinct slots than the
    // SRAM projection table can hold, a compaction would drop the surplus
    // and silently roll their counters back to zero. Refuse here —
    // BEFORE erasing — so the page (and every slot's budget) stays
    // intact. The caller surfaces this as a write failure and declines to
    // sign, which is strictly safer than a counter rollback.
    if overflow {
        return Err(());
    }

    // SAFETY: about to replay from SRAM.
    unsafe { erase_offchain_page()? };

    // Replay: write surviving entries at the start of the page. Each
    // present (slot, type) projection is written to the next blank QW;
    // blanks only advance as we write, so no regression is possible.
    //
    // F3 crash-atomicity: `compact_page` is erase-then-replay on a SINGLE
    // page with no two-phase staging, so a power-loss / reset BETWEEN the
    // erase and the end of replay can tear it. Because "registered" ==
    // "≥1 entry exists", the dangerous torn state is "slot registered but
    // its counter rolled back to 0" — the F-12 forward/reverse double-scan
    // cannot catch it (both scans agree on the durably-gone data). We make
    // the SECURITY-critical instance of that state UNREACHABLE by replaying
    // `USEROP_SIGS` FIRST for each slot:
    //
    //   * USEROP_SIGS is the unbounded, NO-on-chain-backstop few-time-key
    //     sig tally (off-chain / withheld slot-key sigs eroding the C10
    //     few-time margin). Writing it first means the instant a slot
    //     becomes registered after a torn compaction, its tally is already
    //     the true high-water mark. A tear BEFORE it leaves the slot
    //     unregistered → invariant #9 forces a Type-1 re-registration (safe).
    //   * COUNT (offchain) and USEROP (last on-chain userop count) are
    //     written after. A tear that rolls THESE back is bounded: COUNT is
    //     backstopped by the on-chain `_setOffchainSigCount` monotonicity +
    //     the firmware gap ≤ MAX_OFFCHAIN_GAP, and USEROP reflects landed
    //     userops the on-chain `slotUses` cap independently rejects.
    //
    // Residual (tracked): a torn COUNT/USEROP roll-back is still possible but
    // bounded as above. Full crash-atomicity (two-page ping-pong / commit
    // marker) is a larger flash-layout change; see docs/security/threat-model.md.
    for j in 0..n {
        let entry = table[j];
        if entry.has_userop_sigs {
            // F3 + MEDIUM-2: the durable few-time-sig tally is written FIRST so
            // a torn compaction can never leave a registered slot with this
            // (unbacked) counter rolled back to zero.
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_USEROP_SIGS, entry.userop_sigs);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
        if entry.has_userop {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_USEROP, entry.last_userop_count);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
        if entry.has_offchain {
            let qw = entry_qw(&entry.slot_key, OFFCHAIN_TYPE_COUNT, entry.offchain_count);
            let blank = find_next_blank_idx().ok_or(())?;
            // SAFETY: target QW is inside page 123 and was just erased.
            unsafe {
                write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, &qw)?
            };
        }
    }
    Ok(())
}

/// Count distinct live slot keys currently in the page, saturating at
/// `MAX_DISTINCT_SLOTS`. Lightweight companion to the `write_entry` Layer-2
/// cap (see [`crate::offchain_state::MAX_DISTINCT_SLOTS`]): it dedups seen keys
/// into a small fixed table (`MAX_DISTINCT_SLOTS` × 8 bytes ≈ 1 KB stack —
/// deliberately NOT the ~10 KB `[SlotEntry; MAX_ACTIVE_SLOTS]` compaction
/// table, given the documented secure-world stack pressure) and stops as soon
/// as it has seen `MAX_DISTINCT_SLOTS` distinct keys, since the only caller
/// compares `>= MAX_DISTINCT_SLOTS`. Stale / blank QWs are skipped exactly as
/// `scan_page_into_table` / `is_registered_forward` skip them.
fn distinct_slot_count_capped() -> usize {
    const CAP: usize = crate::offchain_state::MAX_DISTINCT_SLOTS;
    let mut seen = [[0u8; 8]; CAP];
    let mut n = 0usize;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        match parse_entry(addr) {
            None => break,               // first truly-blank QW — end of journal
            Some((0, _, _)) => continue, // stale / undecodable — skip, keep scanning
            Some((_, sk, _)) => {
                let mut found = false;
                for s in seen[..n].iter() {
                    if *s == sk {
                        found = true;
                        break;
                    }
                }
                if !found {
                    seen[n] = sk;
                    n += 1;
                    if n >= CAP {
                        // Already at the cap; the sole caller refuses a new
                        // slot at this point and more distinct keys can only
                        // keep n == CAP, so stop early (bounds-safe: the last
                        // write was seen[CAP-1]).
                        return n;
                    }
                }
            }
        }
    }
    n
}

/// Strict, read-only page-123 projection for the optional forced-blind
/// preflight. Unlike the legacy readers, this path accepts only one canonical
/// append prefix followed by erased QWs: an unknown record, a nonblank record
/// after the first blank, or more than the lifetime slot cap is fatal. It
/// computes the exact compacted live-QW count without erasing or repairing the
/// page and binds the receipt to every byte read.
///
/// # Safety
///
/// Reads the secure flash mapping at `OFFCHAIN_PAGE_ADDR`. The caller must
/// serialize the scan with page-123 mutators.
#[cfg(feature = "erc7730-forced-blind")]
#[inline(never)]
pub unsafe fn forced_capacity_snapshot(
    requested_slot: &[u8; 8],
) -> Result<crate::offchain_state::ForcedCapacitySnapshot, crate::offchain_state::ForcedCapacityError>
{
    use sha2::{Digest, Sha256};

    const CAP: usize = crate::offchain_state::MAX_DISTINCT_SLOTS;
    let mut keys = [[0u8; 8]; CAP];
    let mut type_masks = [0u8; CAP];
    let mut distinct_live = 0usize;
    let mut blank_qws = 0usize;
    let mut saw_blank = false;
    let mut slot_present = false;
    let mut state = Sha256::new();
    state.update(b"PQSigner/offchain-state/page123-capacity/v1");

    for index in 0..OFFCHAIN_CAPACITY {
        let base = (OFFCHAIN_PAGE_ADDR + index * OFFCHAIN_QW_SIZE) as *const u8;
        let mut raw = [0u8; OFFCHAIN_QW_SIZE as usize];
        for (offset, byte) in raw.iter_mut().enumerate() {
            // SAFETY: index < 512 and offset < 16 stay inside page 123.
            *byte = unsafe { read_volatile(base.add(offset)) };
        }
        state.update(raw);

        if raw.iter().all(|byte| *byte == 0xFF) {
            saw_blank = true;
            blank_qws += 1;
            continue;
        }
        if saw_blank {
            return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
        }

        let type_mask = match raw[8] {
            OFFCHAIN_TYPE_COUNT => 0b001,
            OFFCHAIN_TYPE_USEROP => 0b010,
            OFFCHAIN_TYPE_USEROP_SIGS => 0b100,
            _ => {
                return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
            }
        };
        let mut slot_key = [0u8; 8];
        slot_key.copy_from_slice(&raw[..8]);
        slot_present |= &slot_key == requested_slot;

        let mut existing = None;
        for (slot_index, key) in keys[..distinct_live].iter().enumerate() {
            if *key == slot_key {
                existing = Some(slot_index);
                break;
            }
        }
        let slot_index = match existing {
            Some(slot_index) => slot_index,
            None => {
                if distinct_live == CAP {
                    return Err(crate::offchain_state::ForcedCapacityError::InvalidProjection);
                }
                let slot_index = distinct_live;
                keys[slot_index] = slot_key;
                distinct_live += 1;
                slot_index
            }
        };
        type_masks[slot_index] |= type_mask;
    }

    let projected_live_qws = type_masks[..distinct_live]
        .iter()
        .map(|mask| mask.count_ones() as usize)
        .sum();
    let mut state_sha256 = [0u8; 32];
    state_sha256.copy_from_slice(&state.finalize());
    Ok(crate::offchain_state::ForcedCapacitySnapshot {
        state_sha256,
        distinct_live,
        projected_live_qws,
        blank_qws,
        slot_present,
    })
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
    // Layer-2 structural cap (page-123 exhaustion → permanent-brick fix; see
    // docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md and
    // crate::offchain_state::MAX_DISTINCT_SLOTS). Refuse to create a NEW
    // distinct slot once the page already holds MAX_DISTINCT_SLOTS of them, so
    // the page can never reach the un-compactable state that bricks every sign
    // path. Updates to an already-present slot are always allowed — they can't
    // grow the distinct-slot set. This sits ABOVE compact_page (which replays
    // via write_quadword_verified and bypasses write_entry), so existing slots
    // always re-compact; only brand-new slots beyond the cap are refused. The
    // distinct scan runs ONLY on the new-slot branch, so steady-state
    // existing-slot writes pay only the cheap presence check — negligible
    // against the ~1 s C10 sign. This does NOT weaken HIGH-1/F3: nothing is
    // evicted or erased, the few-time `userop_sigs` tally is untouched.
    let mut sk = [0u8; 8];
    sk.copy_from_slice(&qw[0..8]);
    // SAFETY: page-123 journal read only (same contract as the other readers).
    let already_present = unsafe { offchain_count_is_registered(&sk) };
    let distinct = if already_present {
        0 // ignored by may_create_distinct_slot when present; skips the scan
    } else {
        distinct_slot_count_capped()
    };
    if !crate::offchain_state::may_create_distinct_slot(distinct, already_present) {
        return Err(());
    }

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

    // HIGH-1 (audit counter-replay 20260611): the bulk-erase self-heal
    // must NEVER destroy live counters. A failed / fault-injected write on
    // a page full of live per-slot entries would otherwise erase every
    // slot's offchain / last_userop / userop_sigs counter to zero — a
    // single-fault rollback of the entire off-chain signing budget that
    // the F-12 read double-scan cannot detect (after the erase both the
    // forward and reverse scans agree on the empty page, so no mismatch
    // fires). Only bulk-erase when the page holds NO decodable COUNT /
    // USEROP / USEROP_SIGS entry — i.e. it is pure pre-all-C10 cutover
    // garbage, the only case this self-heal was ever designed for. If live
    // entries exist, fail closed: refuse the write (the caller surfaces
    // "Sig commit FAIL" and declines to sign), which is strictly safer
    // than rolling the budget back.
    if offchain_page_has_live_entries() {
        return Err(());
    }

    // Page is cutover-garbage only — safe to bulk-erase and retry once.
    // After the erase the whole page is 0xFF, so find_next_blank_idx
    // returns 0 and the write must succeed (or the flash itself is dead).
    // SAFETY: see write_entry's # Safety contract.
    unsafe { erase_offchain_page()? };
    let blank = find_next_blank_idx().ok_or(())?;
    // SAFETY: target QW is inside page 123 and was just erased.
    unsafe { write_quadword_verified(OFFCHAIN_PAGE_ADDR + blank * OFFCHAIN_QW_SIZE, qw) }
}

/// True iff page 123 holds at least one decodable COUNT / USEROP /
/// USEROP_SIGS entry — i.e. live per-slot counter state the wallet still
/// cares about. Gates the `write_entry` self-heal bulk erase (HIGH-1) so
/// a failed / glitched write can never roll back live counters. Pre-all-
/// C10 cutover garbage (non-decodable QWs) reads as "no live entries", so
/// the legitimate one-time self-heal of an inherited-garbage page is
/// preserved. Scans the whole page (no early-exit) so a live entry that
/// happens to sit past a blank QW is still detected — fail-closed.
fn offchain_page_has_live_entries() -> bool {
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = OFFCHAIN_PAGE_ADDR + i * OFFCHAIN_QW_SIZE;
        if let Some((t, _, _)) = parse_entry(addr) {
            if t == OFFCHAIN_TYPE_COUNT
                || t == OFFCHAIN_TYPE_USEROP
                || t == OFFCHAIN_TYPE_USEROP_SIGS
            {
                return true;
            }
        }
    }
    false
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
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring the `offchain_count_bump` / `userop_sigs_bump` twins —
    // a suppressed write or a value-faulted entry (wrong slot key) must
    // not report success. `write_quadword_verified` only proves the QW
    // landed AS GIVEN, not that `entry_qw` produced the intended value.
    if !offchain_count_is_registered(slot_key) {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_is_registered(slot_key))
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
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

    // Value-inflation brick defence (see
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md` and
    // `crate::offchain_state::OFFCHAIN_COUNT_CEILING`): never promote the
    // monotonic off-chain counter to a value at or above `MAX_SLOT_USES`. A
    // companion-inflated `last_userop` reaches this promote via the sign-path
    // repair branch; clamping here is the structural chokepoint that keeps every
    // caller (sync + both sign paths) from durably tripping the combined-cap gate
    // forever. The clamp never clips a legitimate value — a truthful on-chain
    // `offchainSigCount` is always `< MAX_SLOT_USES`.
    let target = crate::offchain_state::clamp_offchain_count(target);

    let pre = offchain_count_read(slot_key);
    if target <= pre {
        return Ok(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_COUNT, target);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring `offchain_count_bump` — a suppressed write or a
    // value-faulted entry (wrong slot key or count) must fail, not
    // silently leave the local view below the on-chain high-water mark.
    // `write_quadword_verified` only proves the QW landed AS GIVEN, not
    // that `entry_qw` produced the intended value.
    let post = offchain_count_read(slot_key);
    if post != target {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| offchain_count_read(slot_key) == target)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
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

    // Value-inflation brick defence (see
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md` and
    // `crate::offchain_state::OFFCHAIN_COUNT_CEILING`): the `count` here is the
    // untrusted companion's `CMD_OFFCHAIN_SYNC` target. Clamp it below
    // `MAX_SLOT_USES` so a hostile floor bump cannot be promoted into the
    // monotonic off-chain counter and permanently trip the combined-cap gate. A
    // legitimate on-chain `offchainSigCount` is always `< MAX_SLOT_USES`, so the
    // clamp is a no-op for every honest sync.
    let count = crate::offchain_state::clamp_offchain_count(count);

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
    unsafe { write_entry(&qw)? };
    // FI hardening (F16/SCAFI-4): read-back + sentinel-gated re-check,
    // mirroring the `offchain_count_bump` / `userop_sigs_bump` twins —
    // a suppressed write or a value-faulted entry (wrong slot key or
    // count) must not report success. `write_quadword_verified` only
    // proves the QW landed AS GIVEN, not that `entry_qw` produced the
    // intended value.
    let post = last_userop_count_read(slot_key);
    if post != count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| last_userop_count_read(slot_key) == count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}

/// Read the durable per-slot tally of Type-2 (slot-key) UserOp signatures
/// this firmware has produced for `slot_key` (MEDIUM-2). Returns 0 when
/// no entry exists. F-12-hardened: forward + reverse double scan with
/// `wait_random()` between, returning `u64::MAX` on disagreement so the
/// combined-cap check fails closed (refuses to sign).
///
/// # Safety
/// Reads from the page-123 journal.
pub unsafe fn userop_sigs_read(slot_key: &[u8; 8]) -> u64 {
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_forward(&sk_a, OFFCHAIN_TYPE_USEROP_SIGS);
    crate::fi::wait_random();
    let r2 = scan_reverse(&sk_b, OFFCHAIN_TYPE_USEROP_SIGS);
    if r1 != r2 {
        return u64::MAX;
    }
    r1
}

/// Bump the durable UserOp-signature tally for `slot_key` to `new_count`
/// (MEDIUM-2). Mirrors `offchain_count_bump`: monotonic (`Err(())` when
/// `new_count <= current`), F-12 slot_key input-redundancy, and a
/// read-back + sentinel-gated re-check so a glitched write that did not
/// land is rejected. The caller (cmd_sign_userop / batch) computes
/// `new_count = current + 1`, so a return of `Err` means flash trouble.
///
/// # Safety
/// Programs page 123.
pub unsafe fn userop_sigs_bump(slot_key: &[u8; 8], new_count: u64) -> Result<(), ()> {
    // F-12: input redundancy on slot_key (see offchain_count_bump).
    let sk_a: [u8; 8] = *slot_key;
    crate::fi::wait_random();
    let sk_b: [u8; 8] = *slot_key;
    if sk_a != sk_b {
        return Err(());
    }
    let slot_key = &sk_a;

    let pre = userop_sigs_read(slot_key);
    if new_count <= pre {
        return Err(());
    }
    let qw = entry_qw(slot_key, OFFCHAIN_TYPE_USEROP_SIGS, new_count);
    // SAFETY: forwarded contract.
    unsafe { write_entry(&qw)? };
    let post = userop_sigs_read(slot_key);
    if post != new_count {
        return Err(());
    }
    if crate::fi::check_true_into_sentinel(|| userop_sigs_read(slot_key) == new_count)
        != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    Ok(())
}
