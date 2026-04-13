//! No-op UI backend for standalone USB operation.
//!
//! All display and input calls are silent no-ops. Used when the device
//! runs headless (USB HID mode without a debugger or OLED attached).

use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};

pub struct Display {
    _rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
}

impl Display {
    pub const fn new() -> Self {
        Self {
            _rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
        }
    }

    pub fn init(&mut self) {}
    pub fn splash(&mut self) {}
    pub fn clear(&mut self) {}

    pub fn draw_line(&mut self, _row: usize, _text: &str) {}

    pub fn flush(&mut self) {}
}

pub struct Input;

impl Input {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {}

    /// Always returns Right+Short immediately (auto-confirm).
    pub fn wait_button(&mut self, _idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        Some((Button::Right, Press::Short))
    }
}
