//! No-op UI backend for standalone USB operation.
//!
//! All display and input calls are silent no-ops. Used when the device
//! runs headless (USB HID mode without a debugger or OLED attached).

use super::{Button, Press};

pub struct Display;

impl Display {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {}
    pub fn splash(&mut self) {}
    pub fn clear(&mut self) {}

    pub fn draw_line(&mut self, _row: usize, _text: &str) {}

    pub fn flush(&mut self) {}

    /// No-op equivalent of `oled::Display::flush_with_secret_rows`. The
    /// secret-text constant-time blit is OLED-only (it writes to a
    /// pixel framebuffer); the noop backend has no display surface so
    /// the secret rows are silently dropped.
    pub fn flush_with_secret_rows(&mut self, _secret_rows: &[(usize, &[u8])]) {}
}

pub struct Input;

impl Input {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {}

    /// Returns `None` when the caller's abort predicate fires; otherwise
    /// returns Right+Short immediately (auto-confirm).
    /// [`Self::wait_button`] with a `tick` hook (#783). This backend drives
    /// no panel, so there is nothing to animate: tick once for symmetry with
    /// the LCD backend and then wait normally.
    pub fn wait_button_ticking(
        &mut self,
        idle_check: &mut dyn FnMut() -> bool,
        tick: &mut dyn FnMut() -> bool,
    ) -> Option<(Button, Press)> {
        let _ = tick();
        self.wait_button(idle_check)
    }

    pub fn wait_button(&mut self, idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        if idle_check() {
            None
        } else {
            Some((Button::Right, Press::Short))
        }
    }
}
