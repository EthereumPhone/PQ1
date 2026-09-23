//! Firmware measurement display.
//!
//! Computes SHA-256 of the secure firmware flash region and displays
//! the first 88 bits as 8 BIP-39 words on the LCD / console. A companion
//! host tool (`fwmeasure`) can independently compute the same words from
//! the firmware ELF so the user can visually compare — no secrets, no
//! trust assumptions, just an open-source reproducible build.

use sha2::{Digest, Sha256};
use sphincs_tz_bip39::firmware_fingerprint_lines;
#[cfg(feature = "debug-log")]
use sphincs_tz_bip39::{hash_to_word_indices, word_bytes_at};

use crate::timeout;
use crate::ui::{ascii_str, display, input, show_status};

// ---------------------------------------------------------------------------
// Flash region boundaries
// ---------------------------------------------------------------------------

// Linker-defined symbols delimiting the firmware image in flash.
//
// `__vector_table` is emitted by cortex-m-rt's `link.x` exactly at
// `ORIGIN(FLASH)` (`__vector_table = .;` is the first symbol inside
// `.vector_table ORIGIN(FLASH) : { ... }`), so its address is the base the
// image is BOTH linked and loaded at: `0x0C00_0000` for the monolithic
// secure build, `0x1000_0000` on QEMU mps2-an505, and the slot base (e.g.
// `0x0C00_E000`) once the A/B slot-relocated build ships.
//
// We derive the measurement base from this symbol rather than a hardcoded
// constant so `firmware_hash()` always measures the bytes the image
// ACTUALLY runs from — which is precisely the range the legacy bench FSBL
// hashes for its trusted-display fingerprint (`fsbl/src/verify.rs` hashes
// `[slot_secure_addr, slot_secure_addr + secure_len)` = `[ORIGIN(FLASH),
// __veneer_limit)`). A hardcoded `0x0C00_0000` would silently measure the
// FSBL + manifest region instead of the running slot the moment the A/B
// layout relocates the image, making the FSBL-vs-secure-world fingerprint
// cross-check (CLAUDE.md "divergence ⇒ tamper") mis-fire on honest
// firmware. See docs/security/measured-boot.md and
// docs/security/audits/boot-fsbl-20260611-141459.md (MEDIUM-1).
//
// On STM32U585, CMSE veneers (.gnu.sgstubs) live in FLASH, so the last
// flash content is at __veneer_limit.
//
// On QEMU, build.rs redirects .gnu.sgstubs to the NSC memory region
// (0x103FF000), so __veneer_limit is NOT in flash. Instead we compute
// the end as __sidata + (__edata - __sdata) = end of .data init values.
extern "C" {
    static __vector_table: u8;

    #[cfg(feature = "stm32u585")]
    static __veneer_limit: u8;

    static __sidata: u8;
    static __sdata: u8;
    static __edata: u8;
}

/// Base address of the firmware image in flash — `ORIGIN(FLASH)`, i.e. the
/// address the running image is both linked and loaded at. Tracks the
/// active layout (monolithic vs A/B slot) automatically; see the `extern`
/// block above for why this must NOT be a hardcoded constant.
fn image_base() -> usize {
    // SAFETY: `addr_of!` on an `extern "C"` static yields the linker-defined
    // address without dereferencing; converting to `usize` does not read
    // memory.
    unsafe { core::ptr::addr_of!(__vector_table) as usize }
}

/// End of firmware content in flash.
fn flash_end() -> usize {
    #[cfg(feature = "stm32u585")]
    {
        // SAFETY: `addr_of!` on an `extern "C"` static yields the linker-defined
        // address without dereferencing; converting to `usize` does not read
        // memory.
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
///
/// Covers `[image_base(), flash_end())` — the vector table, .text,
/// .rodata, .data init values, and (on STM32U585) the CMSE veneers — i.e.
/// the exact bytes the running image occupies in flash. This is the same
/// range the legacy bench FSBL hashes for its measured-display fingerprint,
/// so an honest slot yields identical words on both rows regardless of
/// which slot the firmware runs from (see docs/security/measured-boot.md).
pub fn firmware_hash() -> [u8; 32] {
    let base = image_base();
    let end = flash_end();
    // `end >= base` always holds for an honestly-linked image (both are
    // linker-emitted, `__veneer_limit` after `__vector_table`).
    // `saturating_sub` is belt-and-braces against a future linker-script
    // edit that reorders them: a zero-length measurement is a visible, safe
    // failure (all words render "abandon") rather than an arithmetic
    // overflow panic (release builds set `overflow-checks = true`) or an
    // out-of-bounds slice.
    let size = end.saturating_sub(base);

    // SAFETY: flash is memory-mapped and readable from secure world.
    // The region [base, end) covers the vector table, .text, .rodata,
    // .data init values, and (on STM32U585) CMSE veneers — all inside the
    // image's own flash bank.
    let flash = unsafe { core::slice::from_raw_parts(base as *const u8, size) };

    let hash: [u8; 32] = Sha256::digest(flash).into();
    hash
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Title screen duration in SysTick ticks (~1 ms each).
const TITLE_MS: u32 = 1_500;

/// Fallback bound for the phase-1 title spin: if `timeout::now()` has not
/// advanced by a single tick after this many spins, the SysTick tick source
/// isn't running yet (QEMU starts it after `measured_boot`), and the
/// `< TITLE_MS` deadline would otherwise never be reached — spinning
/// forever. This is far more iterations than one ~1 ms SysTick period takes
/// on any supported clock, so on real hardware (where SysTick runs before
/// `measured_boot`) `now()` always advances long before this and the bound
/// never truncates the real title delay.
const TITLE_STALLED_TICK_SPINS: u32 = 2_000_000;

/// Word screen auto-dismiss delay in SysTick ticks (~1 ms each).
const WORDS_MS: u32 = 4_000;

/// Render all 8 measurement words on a single screen.
/// Layout: 2 words per row, 4 rows.
///
/// ```text
/// 1 close  5 grape
/// 2 agent  6 though
/// 3 own    7 sail
/// 4 deputy 8 simple
/// ```
fn render_all_words(hash: &[u8; 32]) {
    // Consume the exact same pure 4x16 byte grid as the legacy bench FSBL.
    // Keeping layout and prefix truncation in one shared helper makes an
    // honest FSBL/secure-world mismatch a meaningful tamper signal instead
    // of a renderer-width artifact.
    let rows = firmware_fingerprint_lines(hash);

    // Port step 4: the same eight prefixes on the design's words grid. The
    // FSBL's own window is NOT ported — it stays text (plan § 4).
    #[cfg(feature = "ui-px")]
    if crate::ui::px::screens::show(&crate::ui::px::status_map::fingerprint_grid(&rows)) {
        return;
    }

    let d = display();
    d.clear();
    for (row_idx, row) in rows.iter().enumerate() {
        d.draw_line(row_idx, ascii_str(row));
    }

    d.flush();
}

// ---------------------------------------------------------------------------
// Boot-time entry point
// ---------------------------------------------------------------------------

/// Measure the firmware and display the resulting 8 BIP-39 words.
/// Called during boot, after UI init and before SE provisioning.
///
/// 1. Shows "OS Fingerprint" title for 1.5 s so the user knows these
///    are firmware identification words, not their seed phrase.
/// 2. Shows all 8 words on a single screen for 4 s (any button skips).
pub fn run() {
    let hash = firmware_hash();
    #[cfg(feature = "debug-log")]
    let indices = hash_to_word_indices(&hash);

    secure_log!(
        "[S] FW measurement: {:02x}{:02x}{:02x}{:02x}...",
        hash[0],
        hash[1],
        hash[2],
        hash[3]
    );

    // Log words for semihosting comparison. Public data — words derive
    // from firmware_hash — but route through the CT lookup so the leaky
    // `WORDLIST[idx]` pattern doesn't survive in the codebase.
    #[cfg(feature = "debug-log")]
    for (i, &idx) in indices.iter().enumerate() {
        let (wb, wlen) = word_bytes_at(idx);
        let s = crate::ui::ascii_str(&wb[..wlen as usize]);
        secure_log!("[S]   {} {}", i + 1, s);
    }

    // Phase 1: title screen — tells the user what's coming.
    //
    // Driven by SysTick via timeout::now(). On real STM32U585 hardware
    // SysTick is already running (main::setup_systick runs before
    // measured_boot), so now() advances and this exits after TITLE_MS. On
    // QEMU SysTick is started *after* measured_boot (see main.rs — the
    // #[cfg(stm32u585)] setup_systick is skipped, and the QEMU one runs
    // later), so now() is frozen at 0 here: t0 == 0 and
    // `0.wrapping_sub(0) < TITLE_MS` is permanently true. A bare deadline
    // loop therefore spins FOREVER, wedging boot at the title screen (the
    // words + gateway never appear). The TITLE_STALLED_TICK_SPINS fallback
    // detects the stopped tick source (counter never advances) and skips
    // the cosmetic delay instead of hanging.
    show_status("OS Fingerprint", "");
    let t0 = timeout::now();
    let mut spins: u32 = 0;
    while timeout::now().wrapping_sub(t0) < TITLE_MS {
        cortex_m::asm::nop();
        spins = spins.saturating_add(1);
        if spins >= TITLE_STALLED_TICK_SPINS && timeout::now() == t0 {
            // Tick source hasn't moved — not running yet. Don't hang.
            break;
        }
    }

    // Phase 2: show all 8 words, auto-dismiss after 4 s or any button.
    render_all_words(&hash);

    let start = timeout::now();
    let mut auto_boot = || timeout::now().wrapping_sub(start) >= WORDS_MS;
    let _ = input().wait_button(&mut auto_boot);
}
