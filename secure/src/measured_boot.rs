//! Firmware measurement display.
//!
//! Computes SHA-256 of the secure firmware flash region and displays
//! the first 88 bits as 8 BIP-39 words on the OLED / console. A companion
//! host tool (`fwmeasure`) can independently compute the same words from
//! the firmware ELF so the user can visually compare — no secrets, no
//! trust assumptions, just an open-source reproducible build.

use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};

use crate::timeout;
use crate::ui::{display, input, show_status, Button, Press, DISPLAY_COLS};

// ---------------------------------------------------------------------------
// Flash region boundaries
// ---------------------------------------------------------------------------

// Secure flash base address — same #[cfg] pattern as NS_FLASH_BASE in main.rs.
#[cfg(feature = "stm32u585")]
const FLASH_BASE: usize = 0x0C00_0000;
#[cfg(not(feature = "stm32u585"))]
const FLASH_BASE: usize = 0x1000_0000;

// Linker-defined symbols for determining the end of flash content.
//
// On STM32U585, CMSE veneers (.gnu.sgstubs) live in FLASH, so the last
// flash content is at __veneer_limit.
//
// On QEMU, build.rs redirects .gnu.sgstubs to the NSC memory region
// (0x103FF000), so __veneer_limit is NOT in flash. Instead we compute
// the end as __sidata + (__edata - __sdata) = end of .data init values.
extern "C" {
    #[cfg(feature = "stm32u585")]
    static __veneer_limit: u8;

    static __sidata: u8;
    static __sdata: u8;
    static __edata: u8;
}

/// End of firmware content in flash.
fn flash_end() -> usize {
    #[cfg(feature = "stm32u585")]
    {
        // Veneers are in FLASH on real hardware — include them.
        unsafe { core::ptr::addr_of!(__veneer_limit) as usize }
    }
    #[cfg(not(feature = "stm32u585"))]
    {
        // On QEMU, stop at the end of .data initial values in flash.
        let sidata = core::ptr::addr_of!(__sidata) as usize;
        let data_size =
            core::ptr::addr_of!(__edata) as usize - core::ptr::addr_of!(__sdata) as usize;
        sidata + data_size
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// SHA-256 hash of the firmware flash region.
fn firmware_hash() -> [u8; 32] {
    let end = flash_end();
    let size = end - FLASH_BASE;

    // SAFETY: flash is memory-mapped and readable from secure world.
    // The region [FLASH_BASE, end) covers the vector table, .text,
    // .rodata, .data init values, and (on STM32U585) CMSE veneers.
    let flash = unsafe { core::slice::from_raw_parts(FLASH_BASE as *const u8, size) };

    let hash: [u8; 32] = Sha256::digest(flash).into();
    hash
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

const WORDS_PER_PAGE: usize = 4;
const TOTAL_WORDS: usize = 8;
const TOTAL_PAGES: usize = TOTAL_WORDS / WORDS_PER_PAGE; // 2

/// Render one page of 4 measurement words.
fn render_page(indices: &[u16; TOTAL_WORDS], page: usize) {
    let d = display();
    d.clear();

    for slot in 0..WORDS_PER_PAGE {
        let word_idx = page * WORDS_PER_PAGE + slot;
        if word_idx >= TOTAL_WORDS {
            break;
        }
        let word = WORDLIST[indices[word_idx] as usize];
        let mut row = [b' '; DISPLAY_COLS];

        // Word number: "1 ocean"
        let n = (word_idx + 1) as u8;
        row[0] = b'0' + n;
        row[1] = b' ';
        let wb = word.as_bytes();
        let max = core::cmp::min(wb.len(), DISPLAY_COLS - 2);
        row[2..2 + max].copy_from_slice(&wb[..max]);

        // Page indicator on the last row, right-aligned: "1/2"
        if slot == WORDS_PER_PAGE - 1 {
            let col = DISPLAY_COLS - 3;
            row[col] = b'0' + (page + 1) as u8;
            row[col + 1] = b'/';
            row[col + 2] = b'0' + TOTAL_PAGES as u8;
        }

        // SAFETY: only ASCII written.
        let s = unsafe { core::str::from_utf8_unchecked(&row) };
        d.draw_line(slot, s);
    }

    d.flush();
}

// ---------------------------------------------------------------------------
// Boot-time entry point
// ---------------------------------------------------------------------------

/// Measure the firmware and display the resulting 8 BIP-39 words.
/// Called during boot, after UI init and before SE provisioning.
pub fn run() {
    let hash = firmware_hash();
    let indices = hash_to_word_indices(&hash);

    secure_log!("[S] FW measurement: {:02x}{:02x}{:02x}{:02x}...",
        hash[0], hash[1], hash[2], hash[3]);

    // Log words for semihosting comparison.
    for (i, &idx) in indices.iter().enumerate() {
        secure_log!("[S]   {} {}", i + 1, WORDLIST[idx as usize]);
    }

    // Intro screen — user can skip with Left or view with Right.
    show_status("FW Measurement", "R=view L=skip");
    let mut idle = || timeout::is_idle();
    match input().wait_button(&mut idle) {
        Some((Button::Right, _)) => {}
        _ => return, // Skip or idle timeout
    }

    // Paginate: 2 pages of 4 words.
    let mut page: usize = 0;
    timeout::reset_activity();

    loop {
        render_page(&indices, page);

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return, // Idle timeout
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                if page + 1 < TOTAL_PAGES {
                    page += 1;
                }
            }
            (Button::Left, Press::Short) => {
                if page > 0 {
                    page -= 1;
                }
            }
            // Long press either button dismisses.
            (_, Press::Long) => return,
        }
    }
}
