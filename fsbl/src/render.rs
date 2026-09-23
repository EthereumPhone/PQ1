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

use crate::fi;
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

/// Drive the LCD end-to-end: init, render, flush, hold, return a VERDICT.
///
/// Returns [`fi::OK_SENTINEL`] iff every SPI transfer completed **and** the
/// backlight came on. Any other value means a transfer timed out or the
/// AW99703 did not reach Backlight mode, and under the #705 recoverable
/// fail-closed policy the caller must refuse to hand off to the slot.
///
/// Safe to call exactly once during FSBL boot, immediately before
/// `branch::into_slot`.
///
/// # What the verdict does NOT mean — accepted residuals, invariant #10
///
/// The NV3007 is write-only and pq1 has **no LCD MISO** (PA6 is `NC`), so
/// nothing here can prove the panel received a byte or that the pixels are
/// right. `TXP`/`EOT` are internal to the SPI peripheral. The backlight leg is
/// the one part that IS read back — `BSTCTR1` and `MODE` over I2C — but that
/// proves the driver IC entered Backlight mode, not that light reached the
/// user's eye: the LED string, its connector and the panel are all downstream
/// of the last thing we can observe. `OK_SENTINEL` therefore still means only
/// *"no step we can observe failed"* — never *"the user saw the fingerprint"*.
///
/// It also does not detect a wrong pin map:
/// `docs/hardware/evt-silicon-validation.md` settles that against us, noting
/// the timeout count *"is NOT the receipt"* and that the real blocking
/// mechanism in that incident is *"not yet identified"*.
///
/// On failure this returns BEFORE the hold, so a refusal is not preceded by
/// ten seconds of blank screen.
#[must_use]
pub fn render_fingerprint(digest: &[u8; 32]) -> u32 {
    let mut lcd = Lcd::new();
    let mut ok = lcd.init();

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
    ok &= lcd.flush();

    // Payload = how many `spi_wait` polls timed out. On a correctly-mapped
    // panel this is 0. It stays a marker payload rather than the control
    // input — the control input is `ok` — because a count distinguishes "one
    // timeout, aborted early" from "the bus is dead", which a bool cannot.
    #[cfg(feature = "stage-marker")]
    crate::marker::record(
        crate::marker::Stage::RenderFlushed,
        crate::nv3007::spi_wait_timeouts(),
    );

    if !ok {
        // Fail closed, and do it WITHOUT the hold: ten seconds of blank screen
        // before a refusal teaches the operator nothing and delays the only
        // recovery action there is (power-cycle).
        //
        // Drop HWEN on the way out so a refusal is never accompanied by a lit
        // panel showing a half-painted screen. Belt-and-braces: the enable
        // below has not run yet on this path.
        #[cfg(feature = "board-pq1")]
        crate::aw99703::off();
        return 0;
    }

    // #730 stage 2: illuminate LAST, now that the words are on the panel.
    // Everything before this point ran with the AW99703 in Standby, so the
    // panel was dark — `DISPON` is the final command of the init sequence, and
    // enabling earlier would have lit undefined GRAM.
    let backlight_on = lcd.backlight_on();

    // The receipt: CHIP_ID, BSTCTR1 and MODE as read back by THIS transport,
    // packed `0x00_CC_BB_MM` with the top byte set if any NACKed.
    //
    // RECORDED BEFORE THE FOLD BELOW, deliberately. A unit that refuses handoff
    // has one observable left — this page — and the refusal is worth far less
    // without the reason. Moving this after the fold would erase the
    // diagnostic in exactly the case it is needed.
    #[cfg(all(feature = "stage-marker", feature = "board-pq1"))]
    crate::marker::record(
        crate::marker::Stage::BacklightProbe,
        crate::aw99703::read_receipt(),
    );

    // ARMED 2026-09-23 on the receipt this marker recorded: bench board
    // `002F0023 30465002 2033314C`, stage 18 payload `0x00032615` — CHIP_ID
    // 0x03, BSTCTR1 0x26, MODE 0x15, nack 0, read back by THIS bit-banged
    // transport at HSI16 rather than by the secure world's.
    //
    // Two properties make that payload a receipt for `backlight_on` itself and
    // not merely for "some chip answered":
    //
    //   * `configure` opens with a HWEN low pulse, which resets every register
    //     to its default. `BSTCTR1`'s default is 0x2E; reading 0x26 therefore
    //     cannot be state left by a previous secure-world boot, and `MODE`
    //     0x15 is the value `enable` writes.
    //   * A failed `configure` leaves HWEN LOW, which disables the I2C
    //     interface outright, so a refusal reads `0x01FFFFFF`, not 0x00032615.
    //
    // A dark panel is precisely the failure invariant #10's boot-time window
    // cannot absorb: the GRAM can be perfect and the user still sees nothing,
    // which is indistinguishable from a panel that was never written. So it
    // refuses handoff, on the same footing as a failed SPI transfer.
    ok &= backlight_on;

    if !ok {
        // Same policy as the flush failure above: refuse WITHOUT the hold, and
        // drop HWEN so a refusal is never accompanied by a lit panel.
        #[cfg(feature = "board-pq1")]
        crate::aw99703::off();
        return 0;
    }

    // Hold so the user can read the words — MEASURED 10.002 s against the
    // 10,000 ms nominal now that the clock switch and the delay calibration
    // agree (it was 24.0 s when the loop ran 8x long). No button-wait — FSBL
    // doesn't init GPIO buttons; a power-cycle is the abort path.
    delay_ms(FINGERPRINT_HOLD_MS);

    // Recomputed through the FI gate rather than returning a plain bool: this
    // verdict is the last thing standing between a failed display and a branch
    // into the slot, so it gets the same single-glitch treatment as the
    // signature check in `main`.
    fi::scrub_sentinel_register();
    fi::check_true_into_sentinel(|| ok)
}
