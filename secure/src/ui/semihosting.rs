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
            hprintln!("    |{}|", super::ascii_str(row));
        }
        hprintln!("    +----------------+");

        // Screenshot-hash capture (feature-gated). Flatten the 4×16
        // grid into 64 contiguous bytes and emit a SHA-256 fingerprint.
        // Parsed by `tools/ui_fixture.py` for UI regression testing.
        #[cfg(feature = "ui-capture")]
        {
            let mut flat = [0u8; super::DISPLAY_COLS * super::DISPLAY_ROWS];
            for (ri, row) in self.rows.iter().enumerate() {
                let off = ri * super::DISPLAY_COLS;
                flat[off..off + super::DISPLAY_COLS].copy_from_slice(row);
            }
            super::capture::emit(&flat);
        }
    }

    /// `oled::Display::flush_with_secret_rows` parity. The semihosting
    /// backend has no pixel framebuffer, so F-24 stage D's constant-
    /// time blit is moot — we just stamp the rows and delegate to
    /// `flush`. QEMU builds are public-only anyway.
    pub fn flush_with_secret_rows(&mut self, secret_rows: &[(usize, &[u8])]) {
        for &(row, text) in secret_rows {
            if row < DISPLAY_ROWS {
                let mut padded = [b' '; DISPLAY_COLS];
                let n = text.len().min(DISPLAY_COLS);
                padded[..n].copy_from_slice(&text[..n]);
                self.rows[row] = padded;
            }
        }
        self.flush();
    }
}

pub struct Input;

impl Input {
    pub const fn new() -> Self {
        Self
    }

    pub fn init(&mut self) {
        #[cfg(feature = "gpio-buttons")]
        unsafe {
            crate::hw::buttons::init();
            hprintln!("[S][SEMI] GPIO buttons ready (LEFT=PC1/D8, RIGHT=PA8/D9)");
        }
    }

    /// Read a button press.
    ///
    /// With `gpio-buttons`: polls PC1 (LEFT) and PA8 (RIGHT) hardware pins.
    /// Without: blocks on semihosting READC for keyboard input from host.
    pub fn wait_button(&mut self, idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        #[cfg(feature = "gpio-buttons")]
        {
            return crate::hw::buttons::wait_event(idle_check);
        }

        #[cfg(not(feature = "gpio-buttons"))]
        {
            let _ = idle_check;
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
                    _ => continue,
                }
            }
        }
    }
}
