//! Minimal secure flash driver for STM32U585.
//!
//! Provides read/write/erase for the last page of bank 1 (page 127,
//! address 0x0C0F_E000), which is reserved for persistent secure-world
//! data such as the Tropic01 pairing key and (future) intent log.
//!
//! The linker script (`memory-stm32u585.x`) must shrink FLASH LENGTH
//! by 8 KB to prevent firmware code from being placed in this page.

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
// Key storage page — last 8 KB of secure flash bank 1
// ---------------------------------------------------------------------------

/// Base address of the reserved key storage page (page 127).
pub const KEY_PAGE_ADDR: u32 = 0x0C0F_E000;
const KEY_PAGE_NUM: u32 = 127;

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
    write_quadword(KEY_PAGE_ADDR, &qw0)?;

    // Second quad-word: bytes 16-31
    let mut qw1 = [0u8; 16];
    qw1.copy_from_slice(&key[16..]);
    write_quadword(KEY_PAGE_ADDR + 16, &qw1)?;

    Ok(())
}
