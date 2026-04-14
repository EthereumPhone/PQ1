//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last two pages of bank 1:
//! - Page 127 (0x0C0F_E000): Tropic01 pairing key / persistent secure data
//! - Page 126 (0x0C0F_C000): OPTIGA Trust M Platform Binding Secret (PBS)
//!
//! The linker script (`memory-stm32u585.x`) must shrink FLASH LENGTH
//! by 16 KB to prevent firmware code from being placed in these pages.

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Flash controller registers (secure alias)
// ---------------------------------------------------------------------------

const FLASH: u32 = 0x5002_2000;

const FLASH_SECKEYR: *mut u32 = (FLASH + 0x0C) as *mut u32;
const FLASH_SECSR: *mut u32 = (FLASH + 0x24) as *mut u32;
const FLASH_SECCR: *mut u32 = (FLASH + 0x2C) as *mut u32;

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
// Key storage page — last 8 KB of secure flash bank 1 (page 127)
// ---------------------------------------------------------------------------

/// Base address of the reserved key storage page (page 127).
pub const KEY_PAGE_ADDR: u32 = 0x0C0F_E000;
const KEY_PAGE_NUM: u32 = 127;

// ---------------------------------------------------------------------------
// PBS storage page — second-to-last 8 KB (page 126)
// ---------------------------------------------------------------------------

/// Base address of the OPTIGA Trust M PBS page (page 126).
pub const PBS_PAGE_ADDR: u32 = 0x0C0F_C000;
const PBS_PAGE_NUM: u32 = 126;

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Wait until the flash controller is not busy.
unsafe fn wait_bsy() {
    while read_volatile(FLASH_SECSR) & BSY != 0 {
        cortex_m::asm::nop();
    }
}

/// Clear any pending error flags in SECSR (write-1-to-clear).
unsafe fn clear_errors() {
    let sr = read_volatile(FLASH_SECSR);
    if sr & ERR_MASK != 0 {
        write_volatile(FLASH_SECSR, sr & ERR_MASK);
    }
}

/// Unlock the secure flash controller for programming/erase.
unsafe fn unlock() {
    // If already unlocked, the key writes are ignored.
    write_volatile(FLASH_SECKEYR, KEY1);
    write_volatile(FLASH_SECKEYR, KEY2);
}

/// Lock the secure flash controller.
unsafe fn lock() {
    let cr = read_volatile(FLASH_SECCR);
    write_volatile(FLASH_SECCR, cr | LOCK);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Erase the key storage page (page 127, 8 KB).
///
/// After erase, all bytes in the page read as 0xFF.
pub unsafe fn erase_key_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    // Set PER + page number, then STRT
    let cr = PER | (KEY_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    // Clear PER
    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
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
unsafe fn write_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    // Set PG bit
    write_volatile(FLASH_SECCR, PG);

    // Write 4 × 32-bit words to the target address.
    // The flash controller latches all four and programs them atomically.
    let dst = addr as *mut u32;
    for i in 0..4 {
        let word = u32::from_le_bytes([
            data[i * 4],
            data[i * 4 + 1],
            data[i * 4 + 2],
            data[i * 4 + 3],
        ]);
        write_volatile(dst.add(i), word);
    }

    wait_bsy();

    // Clear PG
    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
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
pub unsafe fn write_quadword_verified(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    write_quadword(addr, data)?;

    let src = addr as *const u8;
    for i in 0..16 {
        if read_volatile(src.add(i)) != data[i] {
            return Err(());
        }
    }
    Ok(())
}

/// Read 32 bytes from the start of the key storage page.
pub unsafe fn read_key(buf: &mut [u8; 32]) {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the key storage page is blank (first 32 bytes = 0xFF).
pub unsafe fn is_key_blank() -> bool {
    let src = KEY_PAGE_ADDR as *const u8;
    for i in 0..32 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Write a 32-byte key to the key storage page.
///
/// Erases the page first, then programs two quad-words (2 × 16 bytes).
pub unsafe fn write_key(key: &[u8; 32]) -> Result<(), ()> {
    erase_key_page()?;

    // First quad-word: bytes 0-15
    let mut qw0 = [0u8; 16];
    qw0.copy_from_slice(&key[..16]);
    write_quadword_verified(KEY_PAGE_ADDR, &qw0)?;

    // Second quad-word: bytes 16-31
    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&key[16..]);
    write_quadword_verified(KEY_PAGE_ADDR + 16, &qw1)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// OPTIGA Trust M PBS storage (page 126)
// ---------------------------------------------------------------------------

/// Erase the PBS storage page (page 126, 8 KB).
pub unsafe fn erase_pbs_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    let cr = PER | (PBS_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Read 32 bytes from the start of the PBS storage page.
pub unsafe fn read_pbs(buf: &mut [u8; 32]) {
    let src = PBS_PAGE_ADDR as *const u8;
    for i in 0..32 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the PBS storage page is blank (first 32 bytes = 0xFF).
pub unsafe fn is_pbs_blank() -> bool {
    let src = PBS_PAGE_ADDR as *const u8;
    for i in 0..32 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Write a 32-byte PBS to the PBS storage page.
///
/// Erases the page first, then programs two quad-words (2 × 16 bytes).
pub unsafe fn write_pbs(pbs: &[u8; 32]) -> Result<(), ()> {
    erase_pbs_page()?;

    let mut qw0 = [0u8; 16];
    qw0.copy_from_slice(&pbs[..16]);
    write_quadword_verified(PBS_PAGE_ADDR, &qw0)?;

    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&pbs[16..]);
    write_quadword_verified(PBS_PAGE_ADDR + 16, &qw1)?;

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

const ADMIN_PIN_OFFSET: u32 = 0;
const WIPE_FLAG_OFFSET: u32 = 16;
const WIPE_FLAG_ARMED: u8 = 0x00;

/// Erase page 125. Clears both the admin PIN and the wipe flag.
pub unsafe fn erase_admin_page() -> Result<(), ()> {
    wait_bsy();
    clear_errors();
    unlock();

    let cr = PER | (ADMIN_PAGE_NUM << PNB_SHIFT);
    write_volatile(FLASH_SECCR, cr);
    write_volatile(FLASH_SECCR, cr | STRT);

    wait_bsy();

    write_volatile(FLASH_SECCR, 0);
    let sr = read_volatile(FLASH_SECSR);
    lock();

    if sr & ERR_MASK != 0 {
        clear_errors();
        Err(())
    } else {
        Ok(())
    }
}

/// Read the admin PIN from page 125 into `buf`. Caller checks
/// `is_admin_pin_blank()` first to determine if the PIN is populated.
pub unsafe fn read_admin_pin(buf: &mut [u8; 16]) {
    let src = (ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET) as *const u8;
    for i in 0..16 {
        buf[i] = read_volatile(src.add(i));
    }
}

/// Check whether the admin PIN slot is blank (first 16 bytes all 0xFF).
pub unsafe fn is_admin_pin_blank() -> bool {
    let src = (ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET) as *const u8;
    for i in 0..16 {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Persist a 16-byte admin PIN into page 125.
///
/// Erases the whole page first (so any stale wipe flag is cleared too),
/// then programs QW 0 with the PIN. After this call `is_admin_pin_blank()`
/// is false and `is_wipe_armed()` is false.
pub unsafe fn write_admin_pin(pin: &[u8; 16]) -> Result<(), ()> {
    erase_admin_page()?;

    let mut qw = [0u8; 16];
    qw.copy_from_slice(pin);
    write_quadword_verified(ADMIN_PAGE_ADDR + ADMIN_PIN_OFFSET, &qw)
}

/// Arm the wipe-in-progress marker. Call immediately before initiating
/// a factory reset so boot-time resume can pick up an interrupted wipe.
///
/// Does NOT erase page 125 — uses a 1→0 bit-clear on a single QW, which
/// NOR flash supports without pre-erase. The admin PIN at QW 0 is
/// preserved so the wipe routine can still authenticate against
/// ADMIN_WIPE_OBJ during resume.
pub unsafe fn arm_wipe_flag() -> Result<(), ()> {
    let mut qw = [0xFFu8; 16];
    qw[0] = WIPE_FLAG_ARMED;
    write_quadword_verified(ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET, &qw)
}

/// Read the wipe-in-progress flag. Returns true iff armed.
pub unsafe fn is_wipe_armed() -> bool {
    let src = (ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET) as *const u8;
    read_volatile(src) == WIPE_FLAG_ARMED
}
