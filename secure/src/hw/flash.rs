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
    // HIGH-12 fix: interrupt-free around the erase sequence.
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        let cr = PER | (KEY_PAGE_NUM << PNB_SHIFT);
        write_volatile(FLASH_SECCR, cr);
        write_volatile(FLASH_SECCR, cr | STRT);

        wait_bsy();

        write_volatile(FLASH_SECCR, 0);
        let sr = read_volatile(FLASH_SECSR);
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
unsafe fn write_quadword(addr: u32, data: &[u8; 16]) -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
        wait_bsy();
        clear_errors();
        unlock();

        // Set PG bit
        write_volatile(FLASH_SECCR, PG);

        // Write 4 × 32-bit words to the target address.
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
// OPTIGA Trust M PBS storage (page 126) — device-bound sealed
// ---------------------------------------------------------------------------
//
// CRIT-9 fix: the Platform Binding Secret is no longer stored in
// plaintext. On every write we AES-256-GCM-encrypt the 32-byte PBS
// under a wrap key derived from the STM32U585 chip UID and the
// measured-boot firmware hash (see `hw::huk`). A flash dump carried
// to a different chip — or read back under different firmware — no
// longer yields a usable PBS.
//
// On-disk layout (60 bytes at PBS_PAGE_ADDR):
//
//   offset  size  field
//     0     12    AES-GCM nonce (random, regenerated on every write)
//    12     32    AES-GCM ciphertext of the 32-byte PBS
//    44     16    AES-GCM authentication tag
//    60    ...    filler (0xFF) to the end of the page
//
// A legitimate `load_pbs` reads the 60-byte blob, re-derives the
// wrap key from UID + firmware hash, and runs AES-GCM decrypt. A
// tampered blob (wrong tag, wrong chip, wrong firmware) fails the
// GCM tag check and is rejected.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroize;

/// Domain tag for the PBS wrap key.
const PBS_WRAP_DOMAIN: &[u8] = b"pqsigner-pbs-wrap-v1";
/// Length of the sealed PBS blob: nonce(12) || ct(32) || tag(16).
const PBS_BLOB_LEN: usize = 12 + 32 + 16;

/// Result of an unseal attempt.
#[derive(Debug)]
pub enum PbsLoadError {
    /// Flash page is blank — no PBS has been sealed yet.
    Blank,
    /// Flash bytes didn't decrypt: either corrupted, from a different
    /// chip, or produced by a different firmware revision. Treat
    /// identically to "blank" from the caller's perspective (re-
    /// provision), but surface the distinction in logs.
    AuthFailed,
}

/// Erase the PBS storage page (page 126, 8 KB).
pub unsafe fn erase_pbs_page() -> Result<(), ()> {
    cortex_m::interrupt::free(|_| {
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

/// Read the sealed PBS blob from flash and unseal it, returning the
/// 32-byte Platform Binding Secret in `buf`.
pub unsafe fn read_pbs(buf: &mut [u8; 32]) -> Result<(), PbsLoadError> {
    // Slurp the blob.
    let src = PBS_PAGE_ADDR as *const u8;
    let mut blob = [0u8; PBS_BLOB_LEN];
    for i in 0..PBS_BLOB_LEN {
        blob[i] = read_volatile(src.add(i));
    }
    // Blank-page guard: an erased page reads as all-0xFF; nothing to
    // unseal.
    if blob.iter().all(|&b| b == 0xFF) {
        return Err(PbsLoadError::Blank);
    }

    // Derive the wrap key fresh. It stays in SRAM only for the
    // duration of the decrypt; no caching.
    let mut wrap_key = super::huk::derive_device_key(PBS_WRAP_DOMAIN);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();

    let nonce: [u8; 12] = blob[..12].try_into().unwrap();
    let mut pt = [0u8; 32];
    pt.copy_from_slice(&blob[12..44]);
    let tag = aes_gcm::Tag::from_slice(&blob[44..60]);

    let r = cipher.decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut pt, tag);
    wrap_key.zeroize();
    blob.zeroize();

    match r {
        Ok(()) => {
            buf.copy_from_slice(&pt);
            pt.zeroize();
            Ok(())
        }
        Err(_) => {
            pt.zeroize();
            Err(PbsLoadError::AuthFailed)
        }
    }
}

/// Check whether the PBS storage page has been sealed.
///
/// Returns true when the page reads as all-blank (0xFF). Does NOT try
/// to decrypt — a tampered-but-non-blank page reports `is_pbs_blank()
/// == false`; the caller gets an `AuthFailed` on `read_pbs` in that
/// case and can treat it as "re-provision required".
pub unsafe fn is_pbs_blank() -> bool {
    let src = PBS_PAGE_ADDR as *const u8;
    for i in 0..PBS_BLOB_LEN {
        if read_volatile(src.add(i)) != 0xFF {
            return false;
        }
    }
    true
}

/// Seal a 32-byte PBS to flash. Erases the page, derives the
/// device-bound wrap key, AES-GCM encrypts the PBS with a freshly
/// generated random nonce, and programs the resulting blob.
pub unsafe fn write_pbs(pbs: &[u8; 32]) -> Result<(), ()> {
    erase_pbs_page()?;

    // Fresh random nonce per write. Same PBS produced twice must not
    // yield the same ciphertext (defence against traffic-analysis
    // watermarking; also required by GCM unique-nonce invariant).
    let mut nonce = [0u8; 12];
    crate::rng::fill(&mut nonce).map_err(|_| ())?;

    let mut wrap_key = super::huk::derive_device_key(PBS_WRAP_DOMAIN);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();

    // Encrypt in-place into a working buffer so we can zeroize on
    // error without leaving the plaintext on the stack.
    let mut ct = [0u8; 32];
    ct.copy_from_slice(pbs);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut ct)
        .map_err(|_| ())?;
    wrap_key.zeroize();

    // Assemble the 60-byte blob: [nonce | ct | tag]. Program as 4 QWs.
    //   QW 0 = nonce(12) || ct[0..4]
    //   QW 1 = ct[4..20]
    //   QW 2 = ct[20..32] || tag[0..4]
    //   QW 3 = tag[4..16] || 0xFF × 4  (unused bits stay in erased state)
    let mut qw = [0xFFu8; 16];

    qw[..12].copy_from_slice(&nonce);
    qw[12..16].copy_from_slice(&ct[0..4]);
    let r0 = write_quadword_verified(PBS_PAGE_ADDR, &qw);
    qw.zeroize();
    if let Err(e) = r0 {
        ct.zeroize();
        return Err(e);
    }

    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&ct[4..20]);
    let r1 = write_quadword_verified(PBS_PAGE_ADDR + 16, &qw1);
    qw1.zeroize();
    if let Err(e) = r1 {
        ct.zeroize();
        return Err(e);
    }

    let mut qw2 = [0u8; 16];
    qw2[..12].copy_from_slice(&ct[20..32]);
    qw2[12..16].copy_from_slice(&tag[..4]);
    let r2 = write_quadword_verified(PBS_PAGE_ADDR + 32, &qw2);
    qw2.zeroize();
    if let Err(e) = r2 {
        ct.zeroize();
        return Err(e);
    }

    let mut qw3 = [0xFFu8; 16];
    qw3[..12].copy_from_slice(&tag[4..16]);
    let r3 = write_quadword_verified(PBS_PAGE_ADDR + 48, &qw3);
    qw3.zeroize();
    ct.zeroize();
    r3
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
    cortex_m::interrupt::free(|_| {
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
