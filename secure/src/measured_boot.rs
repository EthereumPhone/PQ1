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
use crate::ui::{display, input, DISPLAY_COLS};

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

/// Auto-boot delay in SysTick ticks (~1 ms each).
const AUTO_BOOT_MS: u32 = 4_000;

/// Render all 8 measurement words on a single screen.
/// Layout: 2 words per row, 4 rows.
///
/// ```text
/// 1 close  5 grape
/// 2 agent  6 though
/// 3 own    7 sail
/// 4 deputy 8 simple
/// ```
fn render_all_words(indices: &[u16; 8]) {
    let d = display();
    d.clear();

    for row in 0..4 {
        let mut buf = [b' '; DISPLAY_COLS];

        // Left column: words 1-4 (cols 0-7)
        let li = row;
        buf[0] = b'1' + row as u8;
        buf[1] = b' ';
        let lw = WORDLIST[indices[li] as usize].as_bytes();
        let lmax = core::cmp::min(lw.len(), 6);
        buf[2..2 + lmax].copy_from_slice(&lw[..lmax]);

        // Right column: words 5-8 (cols 8-15)
        let ri = row + 4;
        buf[8] = b'5' + row as u8;
        buf[9] = b' ';
        let rw = WORDLIST[indices[ri] as usize].as_bytes();
        let rmax = core::cmp::min(rw.len(), 6);
        buf[10..10 + rmax].copy_from_slice(&rw[..rmax]);

        // SAFETY: only ASCII written.
        let s = unsafe { core::str::from_utf8_unchecked(&buf) };
        d.draw_line(row, s);
    }

    d.flush();
}

// ---------------------------------------------------------------------------
// Boot-time entry point
// ---------------------------------------------------------------------------

/// Measure the firmware and display the resulting 8 BIP-39 words.
/// Called during boot, after UI init and before SE provisioning.
///
/// Shows all 8 words on a single screen and auto-boots after 4 seconds.
/// Any button press dismisses immediately.
pub fn run() {
    let hash = firmware_hash();
    let indices = hash_to_word_indices(&hash);

    secure_log!("[S] FW measurement: {:02x}{:02x}{:02x}{:02x}...",
        hash[0], hash[1], hash[2], hash[3]);

    // Log words for semihosting comparison.
    for (i, &idx) in indices.iter().enumerate() {
        secure_log!("[S]   {} {}", i + 1, WORDLIST[idx as usize]);
    }

    // Show all 8 words, then wait up to 4 seconds or until any button press.
    render_all_words(&indices);

    let start = timeout::now();
    let mut auto_boot = || timeout::now().wrapping_sub(start) >= AUTO_BOOT_MS;
    let _ = input().wait_button(&mut auto_boot);
}
