//! Real OLED backend for STM32U585 + SSD1306 128×64 I2C display.
//!
//! Renders the same 4×16 character grid as the semihosting mock, but on a
//! physical SSD1306 OLED driven over I2C1 (PB8=SCL, PB9=SDA).
//!
//! Text is drawn with `embedded-graphics` FONT_8X13 (8 px wide → 16 cols,
//! 13 px tall at 16 px row pitch → 4 rows in 64 px).
//!
//! The `Input` struct is a stub: without physical GPIO buttons, only the
//! `e2e-test` feature (which auto-confirms every dialog) is usable.

#![cfg(feature = "ui-oled")]

use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::hw;
use embedded_graphics::{
    mono_font::{ascii::FONT_8X13, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};

/// SSD1306 7-bit I2C address. Most modules use 0x3C; some use 0x3D.
/// `init()` probes both and latches the one that ACKs.
const SSD1306_ADDR_PRIMARY: u8 = 0x3C;
const SSD1306_ADDR_ALT: u8 = 0x3D;

/// Resolved address (set during init).
static mut SSD1306_ADDR: u8 = SSD1306_ADDR_PRIMARY;

// ---------------------------------------------------------------------------
// Minimal 128×64 framebuffer in SSD1306 page format (8 pages × 128 bytes).
// Implements `DrawTarget` so embedded-graphics can render text directly.
// ---------------------------------------------------------------------------

struct Framebuf {
    buf: [u8; 1024],
}

impl Framebuf {
    const fn new() -> Self {
        Self { buf: [0; 1024] }
    }

    fn clear(&mut self) {
        self.buf = [0; 1024];
    }
}

impl DrawTarget for Framebuf {
    type Color = BinaryColor;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(coord, color) in pixels {
            if coord.x >= 0 && coord.x < 128 && coord.y >= 0 && coord.y < 64 {
                let x = coord.x as usize;
                let y = coord.y as usize;
                let page = y / 8;
                let bit = y % 8;
                let idx = page * 128 + x;
                if color == BinaryColor::On {
                    self.buf[idx] |= 1 << bit;
                } else {
                    self.buf[idx] &= !(1 << bit);
                }
            }
        }
        Ok(())
    }
}

impl OriginDimensions for Framebuf {
    fn size(&self) -> Size {
        Size::new(128, 64)
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

pub struct Display {
    rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
    fb: Framebuf,
}

impl Display {
    pub const fn new() -> Self {
        Self {
            rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
            fb: Framebuf::new(),
        }
    }

    pub fn init(&mut self) {
        // Probe for the display on both possible I2C addresses.
        let addr = unsafe {
            // Try primary address first (0x3C), then alternate (0x3D).
            if hw::i2c::write(SSD1306_ADDR_PRIMARY, &[0x00, 0xAE]) {
                secure_log!("[S][OLED] found display at 0x{:02x}", SSD1306_ADDR_PRIMARY);
                SSD1306_ADDR_PRIMARY
            } else if hw::i2c::write(SSD1306_ADDR_ALT, &[0x00, 0xAE]) {
                secure_log!("[S][OLED] found display at 0x{:02x}", SSD1306_ADDR_ALT);
                SSD1306_ADDR_ALT
            } else {
                secure_log!("[S][OLED] no display found on I2C1 — skipping");
                return;
            }
        };
        unsafe { SSD1306_ADDR = addr };

        // SSD1306 initialization sequence (128×64, charge-pump enabled).
        // 0xAE (display OFF) was already sent during the address probe.
        let init_cmds: &[u8] = &[
            0xD5, 0x80, // Clock divide / oscillator frequency
            0xA8, 0x3F, // Multiplex ratio = 63 (64 lines)
            0xD3, 0x00, // Display offset = 0
            0x40,       // Start line = 0
            0x8D, 0x14, // Charge pump ON
            0x20, 0x00, // Horizontal addressing mode
            0xA1,       // Segment remap (col 127 → SEG0)
            0xC8,       // COM scan direction remapped
            0xDA, 0x12, // COM pins: alternative, no L/R remap
            0x81, 0xCF, // Contrast
            0xD9, 0xF1, // Pre-charge period
            0xDB, 0x40, // VCOMH deselect level
            0xA4,       // Output follows RAM
            0xA6,       // Normal (not inverted)
            0xAF,       // Display ON
        ];
        for &cmd in init_cmds {
            unsafe { hw::i2c::write(addr, &[0x00, cmd]) };
        }

        // Set full-screen column/page window for bulk writes.
        unsafe {
            hw::i2c::write(addr, &[0x00, 0x21, 0x00, 0x7F]); // col 0–127
            hw::i2c::write(addr, &[0x00, 0x22, 0x00, 0x07]); // page 0–7
        }

        // Clear display.
        self.fb.clear();
        self.flush_fb();

        secure_log!("[S][OLED] display initialized (128x64)");
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
            self.rows[row][col] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
            col += 1;
        }
        for c in col..DISPLAY_COLS {
            self.rows[row][c] = b' ';
        }
    }

    pub fn flush(&mut self) {
        // Render the 4×16 character grid onto the pixel framebuffer.
        self.fb.clear();
        let style = MonoTextStyle::new(&FONT_8X13, BinaryColor::On);
        for (i, row) in self.rows.iter().enumerate() {
            // SAFETY: draw_line restricts to printable ASCII → valid UTF-8.
            let s = unsafe { core::str::from_utf8_unchecked(row) };
            let _ = Text::with_baseline(s, Point::new(0, i as i32 * 16), style, Baseline::Top)
                .draw(&mut self.fb);
        }
        self.flush_fb();
    }

    /// Send the pixel framebuffer to the SSD1306 over I2C.
    /// Sends 8 pages of 128 bytes each (129 bytes per I2C transaction
    /// including the 0x40 data control byte).
    fn flush_fb(&self) {
        let addr = unsafe { SSD1306_ADDR };

        // Reset address window to full screen.
        unsafe {
            hw::i2c::write(addr, &[0x00, 0x21, 0x00, 0x7F]);
            hw::i2c::write(addr, &[0x00, 0x22, 0x00, 0x07]);
        }

        for page in 0..8 {
            let start = page * 128;
            let mut chunk = [0u8; 129];
            chunk[0] = 0x40; // Co=0, D/C#=1 → data stream
            chunk[1..].copy_from_slice(&self.fb.buf[start..start + 128]);
            unsafe { hw::i2c::write(addr, &chunk) };
        }
    }
}

// ---------------------------------------------------------------------------
// Input — semihosting file I/O for button input via probe-rs
// ---------------------------------------------------------------------------
//
// probe-rs does not support SYS_READC (0x07), but it does support file-based
// semihosting (SYS_OPEN / SYS_READ) via `--semihosting-file`.
//
// When `debug-log` is active, init() opens "/input" through semihosting.
// The host side (wallet_run_hw.py) maps this to a TCP socket:
//   probe-rs run --semihosting-file /input=tcp:127.0.0.1:PORT ...
//
// SYS_READ blocks until the host sends a button character, so the target
// halts cleanly between presses (no busy-loop, no READC spam).

pub struct Input {
    /// Semihosting file descriptor for button input (-1 = not opened).
    #[cfg(feature = "debug-log")]
    fd: usize,
}

impl Input {
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "debug-log")]
            fd: usize::MAX,
        }
    }

    pub fn init(&mut self) {
        #[cfg(feature = "debug-log")]
        {
            use cortex_m_semihosting::syscall;
            let path = b"/input\0";
            let fd = unsafe {
                syscall!(OPEN, path.as_ptr(), 0usize, path.len() - 1)
            };
            if fd != usize::MAX {
                self.fd = fd;
                secure_log!("[S][OLED] button input ready (fd={})", fd);
            } else {
                secure_log!("[S][OLED] no button input (semihosting OPEN failed)");
                secure_log!("[S][OLED]   use `make play-hw-display` for interactive mode");
            }
        }
    }

    /// Read a button press.
    ///
    /// When `debug-log` is enabled and the semihosting input file was
    /// opened successfully, blocks on SYS_READ until the host sends a
    /// button character (`h`/`l` = short, `H`/`L` = long — same protocol
    /// as the semihosting UI backend).
    ///
    /// Without semihosting input, loops on WFE until the idle timer fires
    /// (stub for future GPIO buttons).
    pub fn wait_button(&mut self, _idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        #[cfg(feature = "debug-log")]
        if self.fd != usize::MAX {
            use cortex_m_semihosting::syscall;
            loop {
                let mut buf = [0u8; 1];
                let not_read = unsafe {
                    syscall!(READ, self.fd, buf.as_mut_ptr(), 1usize)
                };
                if not_read == 0 {
                    // 1 byte read successfully.
                    match buf[0] {
                        b'h' | b'a' => return Some((Button::Left, Press::Short)),
                        b'l' | b'd' => return Some((Button::Right, Press::Short)),
                        b'H' | b'A' => return Some((Button::Left, Press::Long)),
                        b'L' | b'D' => return Some((Button::Right, Press::Long)),
                        _ => continue,
                    }
                }
                // SYS_READ returned non-zero — EOF or error. Should not
                // happen on a live TCP socket; retry.
            }
        }
        // Fallback: no semihosting input — WFE until idle timer fires.
        loop {
            if _idle_check() {
                return None;
            }
            cortex_m::asm::wfe();
        }
    }
}
