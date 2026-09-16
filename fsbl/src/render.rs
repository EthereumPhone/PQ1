//! FSBL firmware-fingerprint NV3007 LCD render.
//!
//! Composes:
//!   * The pure layout function [`sphincs_tz_bip39::firmware_fingerprint_lines`]
//!     (digest → 4 × 16 ASCII grid; host-testable in `bip39/tests/`).
//!   * The minimal NV3007 142×428 SPI LCD driver in [`crate::nv3007`].
//!
//! The hold delay lives here. The pure render-glue lives in `bip39` so the
//! secure-world `measured_boot::run` can re-use the exact same byte grid
//! (visual parity is part of the trust story: FSBL's screen and the slot's
//! advisory screen must show the same words for the same digest; any
//! divergence is a strong tamper signal).

use sphincs_tz_bip39::firmware_fingerprint_lines;

use crate::nv3007::{delay_ms, Lcd};

/// How long the FSBL fingerprint stays on the LCD before branching into the
/// slot — long enough for a human to glance at and recognise the words.
///
/// **Set to 10 s by owner decision (2026-09-16), MEASURED at 10.002 s** — a
/// +0.02% error, since `nv3007::delay_ms` derives its calibration from
/// `clock::achieved_hz()` and the FSBL runs at HSI16.
///
/// It is deliberately the dominant term: 10.002 s of a **12.932 s** boot
/// (77%), against 2.930 s of actual work. This is the user-visible boot-time
/// trust window described in `docs/security/measured-boot.md` — the seconds in
/// which the user reads the 8 fingerprint words before the slot can display
/// anything — so a longer hold buys reading time at the cost of boot latency.
/// That trade is an owner call, not a performance bug; do not "optimise" it.
///
/// History: 3,000 nominal delivered 24.0 s when the delay loop ran 8× long,
/// then 3.001 s once the clock switch and calibration were fixed. Changing
/// this constant is the only lever on boot time that costs no code.
///
/// Deliberately NOT retuned: this is the user-visible boot-time trust window
/// that `docs/security/measured-boot.md` and invariant #10 describe, so
/// shortening it is an owner decision rather than a comment fix. A longer
/// window is at least the safe direction — more time to read the words.
pub const FINGERPRINT_HOLD_MS: u32 = 10_000;

/// Drive the LCD end-to-end: init, render, flush, delay, return.
///
/// Safe to call exactly once during FSBL boot, immediately before
/// `branch::into_slot`. The NV3007 is a write-only SPI panel, so there is no
/// presence probe — the FSBL only ever builds for real `thumbv8m` silicon
/// (no QEMU FSBL path), where the panel is always wired.
pub fn render_fingerprint(digest: &[u8; 32]) {
    let mut lcd = Lcd::new();
    lcd.init();

    // `LcdInited` / `RenderFlushed` were DEFINED in `marker.rs` but never
    // recorded anywhere, which made their absence from the marker page
    // vacuous — every build ever flashed "failed to reach" them. Wiring them
    // here is what makes the render observable at all: with only
    // `RenderEntered` (main.rs) and `Branching` (after this returns), a stall
    // anywhere inside this function is indistinguishable from any other.
    // Splitting it separates panel bring-up from the glyph blit, which is the
    // distinction the pq1 pin port needs to confirm.
    #[cfg(feature = "stage-marker")]
    crate::marker::record(crate::marker::Stage::LcdInited, 0);

    lcd.clear();

    let rows = firmware_fingerprint_lines(digest);
    for (i, row) in rows.iter().enumerate() {
        lcd.draw_text(i, row);
    }
    lcd.flush();

    // Payload = how many `spi_wait` polls timed out. On a correctly-mapped
    // panel this is 0; a wrong pin map leaves SPI1 without its pins, so TXP
    // never asserts once the FIFO fills and essentially every byte burns the
    // full bound. Recording the count turns that from an invisible hang into
    // a number. See `nv3007::spi_wait_timeouts`.
    #[cfg(feature = "stage-marker")]
    crate::marker::record(
        crate::marker::Stage::RenderFlushed,
        crate::nv3007::spi_wait_timeouts(),
    );

    // Hold so the user can read the words — MEASURED 3.001 s against the
    // 3,000 ms nominal now that the clock switch and the delay calibration
    // agree (it was 24.0 s when the loop ran 8x long). No button-wait — FSBL
    // doesn't init GPIO buttons; a power-cycle is the abort path.
    delay_ms(FINGERPRINT_HOLD_MS);
}
