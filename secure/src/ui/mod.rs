//! Trusted UI in the secure world.
//!
//! Two backends are provided behind mutually exclusive Cargo features:
//!
//! * `ui-semihosting` — mock backend that prints a 4x16 framebox to the QEMU
//!   console and reads "buttons" from semihosting `READC`. Used for QEMU
//!   development today.
//! * `ui-oled` — real backend that drives an SSD1306 128x32 I2C OLED via the
//!   `ssd1306` crate and reads two GPIO buttons via `embedded-hal`. Used on
//!   the STM32U585 + SSD1306 0.91"/0.96" OLED hardware.
//!
//! Both backends export the same `Display` and `Input` types so the rest of
//! the secure world is backend-agnostic.

#[cfg(feature = "ui-semihosting")]
mod semihosting;
#[cfg(feature = "ui-semihosting")]
pub use semihosting::{Display, Input};

#[cfg(feature = "ui-oled")]
mod oled;
#[cfg(feature = "ui-oled")]
pub use oled::{Display, Input};

#[cfg(feature = "ui-noop")]
mod noop;
#[cfg(feature = "ui-noop")]
pub use noop::{Display, Input};

#[cfg(feature = "ui-mirror")]
pub mod mirror;

/// Screenshot-hash capture — emits a SHA-256 fingerprint per displayed
/// frame over the secure log, parsed by `tools/ui_fixture.py` for UI
/// regression testing. See `docs/trezor-comparison.md §2.3`.
#[cfg(feature = "ui-capture")]
pub mod capture;

pub mod confirm;
pub mod pin_entry;
pub mod seed_wizard;

/// Logical display dimensions (cells, not pixels).
/// 16 columns × 4 rows: fits 5×8 font on 128×32 OLED, 8×13 on 128×64.
pub const DISPLAY_COLS: usize = 16;
pub const DISPLAY_ROWS: usize = 4;

/// Convert an ASCII-by-construction byte buffer into a `&str` without `unsafe`.
///
/// All call sites build their buffers from printable ASCII (digits, hex,
/// BIP-39 words, fixed labels). The `from_utf8` validator is O(n) over a
/// ≤64-byte buffer — negligible vs. the OLED I2C flush that follows. The
/// `"?"` fallback is structurally unreachable; it exists only so this
/// helper is safe (no `unsafe { from_utf8_unchecked }`).
#[inline]
pub(crate) fn ascii_str(buf: &[u8]) -> &str {
    core::str::from_utf8(buf).unwrap_or("?")
}

/// Two-button input event.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Button {
    Left,
    Right,
}

/// Press duration. Long press is detected when the button is held for at
/// least ~500 ms; the exact threshold is backend-defined.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Press {
    Short,
    Long,
}

/// Trusted-display capability. Phase 10 PR A of the modularity refactor
/// codifies the surface every UI backend (`semihosting`, `oled`,
/// `noop`, `mirror`, `capture`) exposes, so future code can take
/// `&mut impl Ui` instead of being implicitly tied to whichever backend
/// the active feature gate selects.
///
/// Each backend's `Display` already provides matching inherent methods;
/// the per-backend `impl Ui for Display` blocks below delegate into
/// those bodies. This keeps existing call sites
/// (`display().clear()`, `display().draw_line(0, "…")`, etc.)
/// working unchanged while letting future code (Phase 7 / Phase 9 PR
/// 4) thread `&mut dyn Ui` through the display layer instead of
/// reaching for the global singleton.
///
/// `secure/build.rs` and the `nsc/mod.rs` `compile_error!` fence
/// already enforce *exactly one* backend at compile time, so this
/// trait does not need its own per-axis enforcement.
pub trait Ui {
    /// Wipe every cell in the framebuffer to the empty state.
    fn clear(&mut self);
    /// Draw a 16-column ASCII-only line at `row` (0..=DISPLAY_ROWS-1).
    /// Out-of-range rows are silently dropped; non-ASCII bytes are
    /// replaced with `'?'` so a hostile DB row cannot smuggle Unicode
    /// homoglyphs onto the trusted display.
    fn draw_line(&mut self, row: usize, text: &str);
    /// Render the framebuffer to the underlying transport (OLED I2C,
    /// QEMU semihosting, or no-op).
    fn flush(&mut self);
    /// Show the boot animation. Default no-op so backends that don't
    /// render one (`ui-noop`, `ui-mirror`) don't have to override it.
    fn splash(&mut self) {}
}

#[cfg(feature = "ui-semihosting")]
impl Ui for semihosting::Display {
    #[inline] fn clear(&mut self) { self.clear() }
    #[inline] fn draw_line(&mut self, row: usize, text: &str) { self.draw_line(row, text) }
    #[inline] fn flush(&mut self) { self.flush() }
    #[inline] fn splash(&mut self) { self.splash() }
}

#[cfg(feature = "ui-oled")]
impl Ui for oled::Display {
    #[inline] fn clear(&mut self) { self.clear() }
    #[inline] fn draw_line(&mut self, row: usize, text: &str) { self.draw_line(row, text) }
    #[inline] fn flush(&mut self) { self.flush() }
    #[inline] fn splash(&mut self) { self.splash() }
}

#[cfg(feature = "ui-noop")]
impl Ui for noop::Display {
    #[inline] fn clear(&mut self) { self.clear() }
    #[inline] fn draw_line(&mut self, row: usize, text: &str) { self.draw_line(row, text) }
    #[inline] fn flush(&mut self) { self.flush() }
    #[inline] fn splash(&mut self) { self.splash() }
}

// ---------------------------------------------------------------------------
// Global UI singletons
//
// Two `Option`s let us defer construction to `init()` so that backends with
// runtime-only resources (e.g. I2C peripheral handles for the OLED) work the
// same way as the const-constructible mock backend.
// ---------------------------------------------------------------------------

static mut DISPLAY: Option<Display> = None;
static mut INPUT: Option<Input> = None;

/// Initialize the global Display and Input. Must be called once at boot.
pub fn init() {
    #[cfg(feature = "ui-mirror")]
    mirror::init();

    unsafe {
        let d = &raw mut DISPLAY;
        let i = &raw mut INPUT;
        (*d) = Some(Display::new());
        (*i) = Some(Input::new());
        if let Some(disp) = (*d).as_mut() {
            disp.init();
        }
        if let Some(inp) = (*i).as_mut() {
            inp.init();
        }
    }
}

#[allow(static_mut_refs)]
pub fn display() -> &'static mut Display {
    unsafe { DISPLAY.as_mut().expect("ui::init() not called") }
}

#[allow(static_mut_refs)]
pub fn input() -> &'static mut Input {
    unsafe { INPUT.as_mut().expect("ui::init() not called") }
}

// ---------------------------------------------------------------------------
// High-level helpers used by both backends
// ---------------------------------------------------------------------------

/// Play the boot/plug-in animation. Backend-specific; a no-op on backends
/// without a pixel display. Safe to call once, after `init()`.
pub fn splash() {
    display().splash();
}

/// Show a single-line status message ("Locked", "Signing...", etc.).
pub fn show_status(title: &str, sub: &str) {
    let d = display();
    d.clear();
    d.draw_line(1, title);
    d.draw_line(2, sub);
    d.flush();
}

/// Show a status title with a text progress bar (0-100%).
///
/// Display layout (4 rows × 16 cols):
///   row 0: (empty)
///   row 1: title
///   row 2: (empty)
///   row 3: [######          ]   <- 14 usable cells
pub fn show_progress(title: &str, percent: u8) {
    let pct = if percent > 100 { 100 } else { percent };
    let filled = (pct as usize * 14 + 50) / 100; // 0..14, rounded

    let mut bar = [b' '; DISPLAY_COLS]; // 16 chars
    bar[0] = b'[';
    bar[15] = b']';
    for i in 0..14 {
        bar[i + 1] = if i < filled { b'#' } else { b'-' };
    }

    let d = display();
    d.clear();
    d.draw_line(1, title);
    d.draw_line(3, ascii_str(&bar));
    d.flush();
}
