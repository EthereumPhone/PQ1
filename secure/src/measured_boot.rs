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
    let d = display();
    d.clear();

    // Consume the exact same pure 4x16 byte grid as the legacy bench FSBL.
    // Keeping layout and prefix truncation in one shared helper makes an
    // honest FSBL/secure-world mismatch a meaningful tamper signal instead
    // of a renderer-width artifact.
    let rows = firmware_fingerprint_lines(hash);
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
/// Hold the current screen for `ms`, tolerating a tick source that has not
/// started yet.
///
/// Driven by SysTick via `timeout::now()`. On real STM32U585 hardware SysTick
/// is already running (`main::setup_systick` runs before `measured_boot`), so
/// `now()` advances and this returns after `ms`. On QEMU SysTick starts
/// *after* `measured_boot`, so `now()` is frozen at 0: `t0 == 0` and
/// `0.wrapping_sub(0) < ms` is permanently true, and a bare deadline loop
/// would spin FOREVER, wedging boot at this screen. The spin-count fallback
/// detects the stopped tick source and skips the cosmetic delay instead of
/// hanging.
fn hold_ms(ms: u32) {
    let t0 = timeout::now();
    let mut spins: u32 = 0;
    while timeout::now().wrapping_sub(t0) < ms {
        cortex_m::asm::nop();
        spins = spins.saturating_add(1);
        if spins >= TITLE_STALLED_TICK_SPINS && timeout::now() == t0 {
            // Tick source hasn't moved — not running yet. Don't hang.
            break;
        }
    }
}

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
    // #705 diagnostic (dev images only): the AW99703 backlight chip's state
    // BEFORE this boot reprogrammed it, shown in the otherwise-empty subtitle
    // of a screen that already holds for TITLE_MS. Put here because the
    // earlier BOOT-step screens are overwritten faster than a human can read.
    //
    // Legend CORRECTED 2026-09-23 (the previous one misread AW=0, and MSB is
    // degenerate in one build):
    //
    //   AW=1 M=BF MD=15 -> config survived this reset: the FSBL's fingerprint
    //                      window would be VISIBLE
    //   AW=1 M=FF MD=00 -> the part was reset (HWEN low / POR / soft reset):
    //                      these are the documented defaults, so the window is
    //                      DARK and the FSBL must program the part
    //   AW=0            -> the chip is not answering NOW: bus fault, chip
    //                      absent, or still in power-on reset. It does NOT
    //                      mean "HWEN went low" — `init_dc_res_gpios` drives
    //                      HWEN high before `configure()`, which then waits
    //                      ~5 ms, far beyond the 250 us t_reset.
    //
    // MODE is the discriminator and MSB alone is not. That mattered acutely
    // while the retired `aw99703-full-brightness` experiment wrote MSB=FF,
    // which IS the reset default, leaving that build unable to tell "survived"
    // from "reset" on MSB at all. MODE's default is 0x00 (Standby) against the
    // 0x15 we write, in every build, so prefer it regardless.
    //
    // `HW=` was dropped from this row: `hwen_float_level` is documented
    // INVALID AS MEASURED (PB15 resets to analog mode, so IDR reads 0 whatever
    // the pin voltage), and printing an invalid number next to valid ones is
    // how it got believed the first time.
    #[cfg(all(feature = "board-pq1", feature = "dev-testkey", feature = "ui-lcd"))]
    {
        let (acked, msb, mode) = crate::hw::aw99703::pre_init_snapshot();
        let hex = |n: u8| -> [u8; 2] {
            let d = |x: u8| if x < 10 { b'0' + x } else { b'A' + (x - 10) };
            [d(n >> 4), d(n & 0xF)]
        };
        let m = hex(msb);
        let md = hex(mode);
        let row = [
            b'A', b'W', b'=', if acked { b'1' } else { b'0' },
            b' ', b'M', b'=', m[0], m[1],
            b' ', b'M', b'D', b'=', md[0], md[1],
        ];
        show_status("OS Fingerprint", crate::ui::ascii_str(&row));
        // Dev images hold 8 s because one 16-column subtitle is unreadable in
        // the production 1.5 s. Two diagnostics now SPLIT that budget rather
        // than extending it, so boot time is unchanged.
        hold_ms(4_000);

        // #733: the fault registers, read ONCE, seconds after `enable()` — late
        // enough for a protection to have tripped, and never on a timer (the
        // read is itself a documented restart path once a flag is set).
        //
        //   ID03 B1=26 MO=15 -> bus verified; BSTCTR1 and MODE read back as
        //                       written.
        //   ID=xx BUS FAULT  -> CHIP_ID is not 0x03, so nothing else could be
        //                       believed and no register was read. A stuck-low
        //                       bus reads 0x00 everywhere, which is
        //                       byte-identical to a good value of 0x00.
        //
        // WHY THESE TWO, and not the fault flags they replaced (2026-09-23):
        // the OVP question the flags answered is CLOSED — OVPSEL stays 001. The
        // open question is now the FSBL's, and it is sharper. A fail-closed
        // FSBL that refuses handoff when a read-back mismatches is unpatchable
        // after the RDP-2 self-lock, so a constant that does not match on
        // HEALTHY silicon does not mean a false alarm: it means every unit
        // refuses forever. `CHIP_ID == 0x03` has a receipt (#733). These two
        // have none — nothing has ever read them back on hardware. This is that
        // receipt. Expected: B1=26 (reset is 0x2E, so 26/2E/00/-- are four
        // distinguishable states) and MO=15 (reset is 0x00, Standby).
        //
        // FLAGS1/FLAGS2 are still read and still logged; only the LCD row
        // changed, because the panel has 16 columns and this is what is open.
        // Full detail goes to `secure_log!`, since the bench board has no panel.
        let f = crate::hw::aw99703::read_fault_snapshot();
        let frow: [u8; 16] = if f.bus_trustworthy() {
            // `--` distinguishes "did not ACK" from any real byte value.
            let dash = [b'-', b'-'];
            let b1 = f.bstctr1.map_or(dash, hex);
            let mo = f.mode.map_or(dash, hex);
            [
                b'I', b'D', b'0', b'3',
                b' ', b'B', b'1', b'=', b1[0], b1[1],
                b' ', b'M', b'O', b'=', mo[0], mo[1],
            ]
        } else {
            let id = f.chip_id.map_or([b'-', b'-'], hex);
            [
                b'I', b'D', b'=', id[0], id[1],
                b' ', b'B', b'U', b'S', b' ', b'F', b'A', b'U', b'L', b'T', b' ',
            ]
        };
        show_status("OS Fingerprint", crate::ui::ascii_str(&frow));
        hold_ms(4_000);
    }
    #[cfg(not(all(feature = "board-pq1", feature = "dev-testkey", feature = "ui-lcd")))]
    {
        show_status("OS Fingerprint", "");
        hold_ms(TITLE_MS);
    }

    // Phase 2: show all 8 words, auto-dismiss after 4 s or any button.
    render_all_words(&hash);

    let start = timeout::now();
    let mut auto_boot = || timeout::now().wrapping_sub(start) >= WORDS_MS;
    let _ = input().wait_button(&mut auto_boot);
}
