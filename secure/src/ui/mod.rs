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

pub mod confirm;
pub mod pin_entry;
pub mod seed_wizard;

/// Logical display dimensions (cells, not pixels).
/// 16 columns × 4 rows: fits 5×8 font on 128×32 OLED, 8×13 on 128×64.
pub const DISPLAY_COLS: usize = 16;
pub const DISPLAY_ROWS: usize = 4;

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

/// Show a single-line status message ("Locked", "Signing...", etc.).
pub fn show_status(title: &str, sub: &str) {
    let d = display();
    d.clear();
    d.draw_line(1, title);
    d.draw_line(2, sub);
    d.flush();
}
