//! Semihosting mock backend for QEMU. Prints a 4x16 framebox to the host
//! console and reads "buttons" from a single character on the host stdin.
//!
//! Key bindings:
//!
//! | Char       | Event              |
//! |------------|--------------------|
//! | `h` / `a`  | Left, Short        |
//! | `l` / `d`  | Right, Short       |
//! | `H` / `A`  | Left, Long         |
//! | `L` / `D`  | Right, Long        |
//!
//! Limitation: `READC` is a blocking semihosting call, so the mock cannot
//! interrupt a waiting dialog when the inactivity timer expires. The
//! background SysTick path still wipes after 2 minutes of no command. On real
//! hardware (`ui-oled`), the GPIO poll loop checks `idle_check` every
//! iteration and CAN interrupt blocking dialogs.

use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use cortex_m_semihosting::{hprintln, syscall};

pub struct Display {
    rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
}

impl Display {
    pub const fn new() -> Self {
        Self {
            rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
        }
    }

    pub fn init(&mut self) {
        // nothing to do for the mock
    }

    pub fn clear(&mut self) {
        for row in &mut self.rows {
            *row = [b' '; DISPLAY_COLS];
        }
    }

    pub fn draw_line(&mut self, row: usize, text: &str) {
        if row >= DISPLAY_ROWS {
            return;
        }
        let bytes = text.as_bytes();
        let mut col = 0;
        for &b in bytes {
            if col >= DISPLAY_COLS {
                break;
            }
            // Print only ASCII; replace anything else with '?'.
            self.rows[row][col] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
            col += 1;
        }
        // Pad the rest with spaces.
        for c in col..DISPLAY_COLS {
            self.rows[row][c] = b' ';
        }
    }

    /// Mock splash: print a single banner line so QEMU logs mirror the
    /// real-hardware boot animation. No timing, no frames.
    pub fn splash(&mut self) {
        hprintln!("    +----------------+");
        hprintln!("    |   PQ SIGNER    |");
        hprintln!("    +----------------+");
    }

    pub fn flush(&mut self) {
        // Render a framebox so the user sees a "screen" in the QEMU console.
        hprintln!("    +----------------+");
        for row in &self.rows {
            // SAFETY: draw_line restricts to printable ASCII so this is valid UTF-8.
            let s = unsafe { core::str::from_utf8_unchecked(row) };
            hprintln!("    |{}|", s);
        }
        hprintln!("    +----------------+");
    }
}

pub struct Input;

impl Input {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {}

    /// Block on a single character from the host. The `_idle_check` argument
    /// is ignored on the semihosting mock; see module-level note.
    pub fn wait_button(&mut self, _idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        loop {
            let c = unsafe { syscall!(READC) } as u8;
            match c {
                b'h' | b'a' => return Some((Button::Left, Press::Short)),
                b'l' | b'd' => return Some((Button::Right, Press::Short)),
                b'H' | b'A' => return Some((Button::Left, Press::Long)),
                b'L' | b'D' => return Some((Button::Right, Press::Long)),
                b'q' | b'Q' => {
                    // Treat as long-cancel for ergonomics
                    return Some((Button::Left, Press::Long));
                }
                _ => continue, // ignore whitespace, newlines, etc.
            }
        }
    }
}
