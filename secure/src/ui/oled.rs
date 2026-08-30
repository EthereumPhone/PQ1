//! Bench-only SSD1306 OLED backend, over **bit-banged** I2C.
//!
//! Renders the same 16x4 character grid every other backend renders — the
//! NV3007's 142x428 pixels are just a bigger canvas for the same
//! `DISPLAY_COLS` x `DISPLAY_ROWS` of text — so a 128x32 SSD1306 fits it
//! exactly: 16 columns of `FONT_5X8`, 4 rows at 8 px pitch.
//!
//! ## Why this exists again
//!
//! This backend was deleted on 2026-06-30 (commit `c42f248e`) when the NV3007
//! became the only shipping display, and it is **not** a step back toward
//! shipping an OLED. It came back for one narrow job: the pq1 production board
//! exposes almost nothing — a 2x5 debug header and four pads — and until the
//! NV3007 panel is physically present there is no way to see the trusted UI on
//! the device itself.
//!
//! It validates **nothing** about the shipping display path: different bus
//! (I2C vs SPI), different driver, different geometry. While a debugger is
//! attached, `ui-semihosting` shows the identical 16x4 text for free and is
//! the better tool. This wins only when untethered, or at `RDP >= 1` where SWD
//! and semihosting are both gone.
//!
//! ## Wiring (pq1)
//!
//! Four connections, three of them on the debug header:
//!
//! | OLED | Board |
//! |---|---|
//! | VCC | header `VDD` |
//! | GND | header `GND` |
//! | SCL | header `SWO` — **PB3** |
//! | SDA | `RX` pad — **PA3** |
//!
//! Those are the only two free GPIOs the board brings out, and no I2C
//! peripheral can reach them (see `hw::soft_i2c`), hence software I2C. `PB3`
//! is also the side-channel scope trigger, so `ui-oled-bench` and
//! `sca-trigger` are mutually exclusive — enforced in `hw::soft_i2c`.
//!
//! On iota2 the pins are the historical PB8/PB9, which are that board's
//! secure-element bus; build with `mock-se` there.
//!
//! ## Not for shipping
//!
//! `ui-oled-bench` is in the Makefile's `PROD_FORBIDDEN` list.

#![cfg(all(feature = "ui-oled-bench", feature = "stm32u585"))]


use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::hw;
use embedded_graphics::{
    mono_font::{ascii::{FONT_5X8, FONT_6X10}, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Line, PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};

/// SSD1306 7-bit I2C address. Most modules use 0x3C; some use 0x3D.
/// `init()` probes both and latches the one that ACKs.
const SSD1306_ADDR_PRIMARY: u8 = 0x3C;
const SSD1306_ADDR_ALT: u8 = 0x3D;

/// Resolved address (set during init).
static mut SSD1306_ADDR: u8 = SSD1306_ADDR_PRIMARY;

// ---------------------------------------------------------------------------
// Minimal 128×32 framebuffer in SSD1306 page format (4 pages × 128 bytes).
// Implements `DrawTarget` so embedded-graphics can render text directly.
// ---------------------------------------------------------------------------

struct Framebuf {
    buf: [u8; 512],
}

impl Framebuf {
    const fn new() -> Self {
        Self { buf: [0; 512] }
    }

    fn clear(&mut self) {
        self.buf = [0; 512];
    }

    /// Read-only access to the raw 512-byte SSD1306 page buffer.
    /// Used by `ui::capture` (feature-gated) to hash the exact pixels
    /// that will be pushed to the OLED.
    #[cfg(feature = "ui-capture")]
    fn pages(&self) -> &[u8; 512] {
        &self.buf
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
            if coord.x >= 0 && coord.x < 128 && coord.y >= 0 && coord.y < 32 {
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
        Size::new(128, 32)
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
            if hw::soft_i2c::write(SSD1306_ADDR_PRIMARY, &[0x00, 0xAE]) {
                secure_log!("[S][OLED] found display at 0x{:02x}", SSD1306_ADDR_PRIMARY);
                SSD1306_ADDR_PRIMARY
            } else if hw::soft_i2c::write(SSD1306_ADDR_ALT, &[0x00, 0xAE]) {
                secure_log!("[S][OLED] found display at 0x{:02x}", SSD1306_ADDR_ALT);
                SSD1306_ADDR_ALT
            } else {
                secure_log!("[S][OLED] no display at 0x3C/0x3D on the bit-banged bus — skipping");
                return;
            }
        };
        unsafe { SSD1306_ADDR = addr };

        // SSD1306 initialization sequence (128×32, charge-pump enabled).
        // 0xAE (display OFF) was already sent during the address probe.
        let init_cmds: &[u8] = &[
            0xD5, 0x80, // Clock divide / oscillator frequency
            0xA8, 0x1F, // Multiplex ratio = 31 (32 lines)
            0xD3, 0x00, // Display offset = 0
            0x40,       // Start line = 0
            0x8D, 0x14, // Charge pump ON
            0x20, 0x00, // Horizontal addressing mode
            0xA1,       // Segment remap (col 127 → SEG0)
            0xC8,       // COM scan direction remapped
            0xDA, 0x02, // COM pins: sequential, no L/R remap (128x32)
            0x81, 0x8F, // Contrast (128x32 modules run cooler)
            0xD9, 0xF1, // Pre-charge period
            0xDB, 0x40, // VCOMH deselect level
            0xA4,       // Output follows RAM
            0xA6,       // Normal (not inverted)
            0xAF,       // Display ON
        ];
        for &cmd in init_cmds {
            unsafe { hw::soft_i2c::write(addr, &[0x00, cmd]) };
        }

        // Set full-screen column/page window for bulk writes.
        unsafe {
            hw::soft_i2c::write(addr, &[0x00, 0x21, 0x00, 0x7F]); // col 0–127
            hw::soft_i2c::write(addr, &[0x00, 0x22, 0x00, 0x03]); // page 0–3
        }

        // Clear display.
        self.fb.clear();
        self.flush_fb();

        secure_log!("[S][OLED] display initialized (128x32)");
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
        let style = MonoTextStyle::new(&FONT_5X8, BinaryColor::On);
        for (i, row) in self.rows.iter().enumerate() {
            let s = super::ascii_str(row);
            let _ = Text::with_baseline(s, Point::new(0, i as i32 * 8), style, Baseline::Top)
                .draw(&mut self.fb);
        }
        self.flush_fb();

        // Screenshot-hash capture (feature-gated). Emit a SHA-256
        // fingerprint of the raw SSD1306 page bytes. Captures actual
        // pixels, not the char grid — catches font / position drift.
        #[cfg(feature = "ui-capture")]
        {
            super::capture::emit(self.fb.pages());
        }
    }

    /// F-24 stage D: flush with constant-time rendering for selected
    /// rows. The rows listed in `secret_rows` are rendered via
    /// `secret_text::render_secret_row` — every glyph load is a 96-entry
    /// scan with no address dependence on the secret character. The rest
    /// of `self.rows` go through embedded-graphics as usual.
    ///
    /// Used by `seed_wizard::render_mnemonic_page` for the word-display
    /// rows. Caller MUST ensure the secret-row indices match what
    /// they've stored in `self.rows` (e.g., still call `draw_line` for
    /// the secret rows to keep the `rows` buffer consistent — the
    /// `flush_with_secret_rows` path SKIPS those rows in the
    /// embedded-graphics pass and instead uses CT rendering, so the
    /// public render path doesn't expose the secret addressing).
    ///
    /// `secret_rows`: slice of `(page, text)` pairs. `page` is the OLED
    /// row index 0..4. `text` is ASCII bytes (max DISPLAY_COLS = 16
    /// chars + leading whitespace).
    pub fn flush_with_secret_rows(&mut self, secret_rows: &[(usize, &[u8])]) {
        self.fb.clear();
        let style = MonoTextStyle::new(&FONT_5X8, BinaryColor::On);
        // Render non-secret rows via embedded-graphics.
        for (i, row) in self.rows.iter().enumerate() {
            let is_secret = secret_rows.iter().any(|(p, _)| *p == i);
            if is_secret {
                // Skip — the CT render below handles this page.
                continue;
            }
            let s = super::ascii_str(row);
            let _ = Text::with_baseline(s, Point::new(0, i as i32 * 8), style, Baseline::Top)
                .draw(&mut self.fb);
        }
        // Render secret rows via the constant-time blit. We use the
        // raw fb buffer via a small accessor; `Framebuf::buf_mut`
        // returns `&mut [u8; 512]` keyed to the SSD1306 page layout.
        for &(page, text) in secret_rows {
            super::secret_text::render_secret_row(&mut self.fb.buf, page, text);
        }
        self.flush_fb();

        #[cfg(feature = "ui-capture")]
        {
            super::capture::emit(self.fb.pages());
        }
    }

    /// Play the plug-in boot animation.
    ///
    /// Two stages over ~1 s total:
    ///   1. Vertical scan line sweeps left→right, progressively uncovering
    ///      the "PQ SIGNER" title rendered in FONT_6X10.
    ///   2. A hollow progress bar under the title fills from left to right.
    /// Ends with a cleared framebuffer so the next UI draw starts from blank.
    pub fn splash(&mut self) {
        const TITLE: &str = "PQ SIGNER";
        // FONT_6X10 is 6 px wide; 9 chars = 54 px; centered x = (128-54)/2 = 37.
        const TITLE_X: i32 = 37;
        const TITLE_Y: i32 = 4;
        let title_style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);

        // Stage 1: scan-line reveal. Step of 4 gives 33 frames × ~12 ms ≈ 400 ms.
        let mut sweep: usize = 0;
        while sweep <= 128 {
            self.fb.clear();
            // Draw the full title, then black out everything at/past the sweep
            // column so the title appears to be uncovered as the line moves.
            let _ = Text::with_baseline(
                TITLE,
                Point::new(TITLE_X, TITLE_Y),
                title_style,
                Baseline::Top,
            )
            .draw(&mut self.fb);
            for x in sweep..128 {
                for page in 0..4 {
                    self.fb.buf[page * 128 + x] = 0;
                }
            }
            if sweep < 128 {
                let _ = Line::new(
                    Point::new(sweep as i32, 0),
                    Point::new(sweep as i32, 31),
                )
                .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
                .draw(&mut self.fb);
            }
            self.flush_fb();
            delay_ms(12);
            sweep += 4;
        }

        // Stage 2: progress bar. 20×22 origin, 88 wide, 6 tall, 2 px border.
        const BAR_X: i32 = 20;
        const BAR_Y: i32 = 22;
        const BAR_W: u32 = 88;
        const BAR_H: u32 = 6;
        let outline = PrimitiveStyle::with_stroke(BinaryColor::On, 1);
        let fill = PrimitiveStyle::with_fill(BinaryColor::On);
        let fill_max: u32 = BAR_W - 4;

        let mut f: u32 = 0;
        while f <= fill_max {
            self.fb.clear();
            let _ = Text::with_baseline(
                TITLE,
                Point::new(TITLE_X, TITLE_Y),
                title_style,
                Baseline::Top,
            )
            .draw(&mut self.fb);
            let _ = Rectangle::new(Point::new(BAR_X, BAR_Y), Size::new(BAR_W, BAR_H))
                .into_styled(outline)
                .draw(&mut self.fb);
            if f > 0 {
                let _ = Rectangle::new(
                    Point::new(BAR_X + 2, BAR_Y + 2),
                    Size::new(f, BAR_H - 4),
                )
                .into_styled(fill)
                .draw(&mut self.fb);
            }
            self.flush_fb();
            delay_ms(6);
            f += 1;
        }

        // Hold the completed frame briefly, then blank the screen.
        delay_ms(250);
        self.fb.clear();
        self.flush_fb();
    }


    /// Send the pixel framebuffer to the SSD1306.
    ///
    /// Four pages of 128 bytes, 129 bytes per transaction including the 0x40
    /// data control byte. (The original also mirrored the same buffer to a
    /// host RTT viewer under `ui-mirror`; that backend was removed with this
    /// file and its feature no longer exists.)
    fn flush_fb(&self) {
        let addr = unsafe { SSD1306_ADDR };

        // Reset the address window to the full screen.
        hw::soft_i2c::write(addr, &[0x00, 0x21, 0x00, 0x7F]);
        hw::soft_i2c::write(addr, &[0x00, 0x22, 0x00, 0x03]);

        for page in 0..4 {
            let start = page * 128;
            let mut chunk = [0u8; 129];
            chunk[0] = 0x40; // Co=0, D/C#=1 -> data stream
            chunk[1..].copy_from_slice(&self.fb.buf[start..start + 128]);
            hw::soft_i2c::write(addr, &chunk);
        }
    }
}

/// Crude millisecond spin for splash-animation pacing.
///
/// (The original carried a copy-pasted "OPTIGA IFX I2C driver" doc comment
/// here, which described nothing in this file.) Precision does not matter —
/// the splash runs once at boot — so this is an uncalibrated nop loop rather
/// than anything clock-derived.
fn delay_ms(ms: u32) {
    for _ in 0..ms {
        for _ in 0..40_000 {
            cortex_m::asm::nop();
        }
    }
}

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
        // Initialize GPIO buttons when available.
        #[cfg(feature = "gpio-buttons")]
        unsafe {
            crate::hw::buttons::init();
            secure_log!(
                "[S][OLED] GPIO buttons ready on {} (LEFT=pin {}, RIGHT=pin {})",
                crate::board::BOARD_NAME,
                crate::board::BTN_LEFT_PIN,
                crate::board::BTN_RIGHT_PIN
            );
        }

        #[cfg(feature = "debug-log")]
        {
            // DHCSR.C_DEBUGEN gate: the semihosting OPEN below is a
            // `BKPT 0xAB` instruction. With a debugger attached the
            // probe intercepts it and returns a file descriptor (or
            // an error under probe-rs, which lacks `--semihosting-file`
            // support). **Without a debugger**, the BKPT escalates to
            // a DebugMonitor fault and then HardFault — the device
            // hangs before finishing UI init, which is what broke the
            // standalone-testkey build. Skipping the OPEN when
            // `C_DEBUGEN == 0` keeps the GPIO-button path working on
            // USB-C-only power.
            let c_debugen = unsafe {
                core::ptr::read_volatile(0xE000_EDF0 as *const u32) & 1
            };
            if c_debugen != 0 {
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
                    #[cfg(not(feature = "gpio-buttons"))]
                    secure_log!("[S][OLED]   use `make play-hw-display` for interactive mode");
                }
            }
        }
    }

    /// Read a button press.
    ///
    /// Priority:
    /// 1. GPIO buttons (`gpio-buttons` feature) — the real path on hardware
    /// 2. Semihosting file I/O (`debug-log`) — keyboard via a debugger
    /// 3. WFE idle loop (stub fallback)
    ///
    /// The old RTT `oled-mirror` branch is gone: that backend was removed
    /// alongside this file in `c42f248e` and its feature no longer exists.
    pub fn wait_button(&mut self, idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        // GPIO hardware buttons — preferred when physically present.
        #[cfg(feature = "gpio-buttons")]
        {
            return crate::hw::buttons::wait_event(idle_check);
        }

        // Semihosting file I/O — keyboard via probe-rs TCP socket bridge.
        #[cfg(all(not(feature = "gpio-buttons"), feature = "debug-log"))]
        if self.fd != usize::MAX {
            use cortex_m_semihosting::syscall;
            loop {
                let mut buf = [0u8; 1];
                let not_read = unsafe {
                    syscall!(READ, self.fd, buf.as_mut_ptr(), 1usize)
                };
                if not_read == 0 {
                    match buf[0] {
                        b'h' | b'a' => return Some((Button::Left, Press::Short)),
                        b'l' | b'd' => return Some((Button::Right, Press::Short)),
                        b'H' | b'A' => return Some((Button::Left, Press::Long)),
                        b'L' | b'D' => return Some((Button::Right, Press::Long)),
                        _ => continue,
                    }
                }
            }
        }

        // Fallback: no input source — WFE until idle timer fires.
        #[cfg(not(feature = "gpio-buttons"))]
        loop {
            if idle_check() {
                return None;
            }
            cortex_m::asm::wfe();
        }
    }
}
