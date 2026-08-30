//! NV3007 SPI LCD backend for the trusted UI (Phase C).
//!
//! Renders the SAME 16×4 character grid as the OLED/semihosting backends
//! (`DISPLAY_COLS`×`DISPLAY_ROWS`), so the trusted-path dialogs (`confirm`,
//! `pin_entry`, `seed_wizard`, `measured_boot`) port with ZERO changes — they
//! keep calling `draw_line(row, text)` and `flush()`.
//!
//! ## Orientation — software rotation (no MADCTL)
//!
//! The panel is physically 142(X)×428(Y) portrait, but the UI is landscape
//! (the OLED layout: wide, few rows). Rather than rotate in the controller via
//! MADCTL (which would remap the proven `X_OFFSET`=12 gutter onto a different
//! axis — an unvalidated coordinate system), we keep the panel in its native,
//! bring-up-validated portrait coordinates and rotate in the blitter: a logical
//! landscape point `(lx, ly)` maps to native `(nx, ny) = (ly, lx)` (a transpose).
//! The user sees 428-wide × 142-tall. If text comes out mirrored/flipped on a
//! given mount, adjust `FLIP_*` below — they're the only orientation knobs.
//!
//! ## Font — FONT_5X8 upscaled 3× → 15×24 glyph cells
//!
//! Integer 3× of the same `FONT_5X8` the OLED uses (via the build-generated
//! `FONT_FLAT_5X8`). 16 cols × 26 px pitch = 416 ≤ 428; 4 rows × 35 px pitch =
//! 140 ≤ 142. White-on-black (constant backlight current — helps F-24 §E).
//!
//! ## Constant-time seed rendering
//!
//! `flush_with_secret_rows` MUST NOT route secret characters through an
//! address-keyed font lookup. It fetches glyph columns via
//! `secret_text::secret_glyph_cols` (the 96-entry constant-time scan with its
//! `black_box` barriers) and expands them through the SAME branchless
//! `blit_glyph` the public path uses — every pixel is written unconditionally
//! (FG or BG via a mask), so the memory-access + SPI-traffic pattern is
//! independent of the secret. Only the pixel VALUE depends on the secret, which
//! is the accepted F-24 stage-E display-broadcast residual. The `tools/sca`
//! F-24 harness — not a bench photo — is the gate before the seed screen is
//! trusted.

#![cfg(feature = "ui-lcd")]

use super::secret_text::{public_glyph_cols, secret_glyph_cols};
use super::{Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::hw::lcd_nv3007 as lcd;

// ---------------------------------------------------------------------------
// Colors (RGB565)
// ---------------------------------------------------------------------------
const FG: u16 = 0xFFFF; // white text
const BG: u16 = 0x0000; // black background

// ---------------------------------------------------------------------------
// Font geometry
// ---------------------------------------------------------------------------
const FONT_W: usize = 5; // source glyph width  (FONT_5X8)
const FONT_H: usize = 8; // source glyph height
const SCALE: usize = 3; // integer upscale

/// Glyph extent in LANDSCAPE coords: 15 wide (X) × 24 tall (Y).
const GLYPH_LW: usize = FONT_W * SCALE; // 15 — landscape X
const GLYPH_LH: usize = FONT_H * SCALE; // 24 — landscape Y

/// Per-cell spacing in LANDSCAPE coords (glyph + inter-cell gap).
const COL_PITCH: usize = 26; // landscape X between columns (15 glyph + 11 gap)
const ROW_PITCH: usize = 35; // landscape Y between rows    (24 glyph + 11 gap)

/// Top-left of the centered 16×4 block, in LANDSCAPE coords.
/// `(428 - 16*26)/2 = 6`, `(142 - 4*35)/2 = 1`.
const ORIGIN_X: usize = 6; // landscape X
const ORIGIN_Y: usize = 1; // landscape Y

/// A glyph's NATIVE-pixel footprint after the landscape→native transpose:
/// native-X extent = the glyph's landscape-Y height (24); native-Y extent =
/// the glyph's landscape-X width (15).
const CELL_NX: usize = GLYPH_LH; // 24 — native X extent of a glyph
const CELL_NY: usize = GLYPH_LW; // 15 — native Y extent of a glyph
const CELL_N: usize = CELL_NX * CELL_NY; // 360 RGB565 pixels = 720 B

/// Native panel dimensions (portrait), for the landscape→native flips.
const PANEL_W: usize = 142; // native X (FRAME_WIDTH)
const PANEL_H: usize = 428; // native Y (FRAME_HEIGHT)

/// Orientation = `(flip_native_x, flip_native_y)`. The NV3007's default scan
/// direction + how the panel is physically mounted decide which axes must be
/// reversed so text reads upright and un-mirrored. **Resolved on real hardware
/// 2026-06-09 via the `lcd-test` orientation sweep: `(true, false)` (flip
/// native-X only) renders upright + un-mirrored.**
/// SAFETY: single-threaded secure world (same pattern as `oled::SSD1306_ADDR`).
static mut FLIP: (bool, bool) = (true, false);

/// Set the active orientation (bench sweep only).
#[cfg(feature = "lcd-test")]
pub fn set_flip(fx: bool, fy: bool) {
    unsafe { FLIP = (fx, fy) };
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

pub struct Display {
    /// The logical char grid — identical shape to oled.rs. Public render path
    /// reads from here; the CT path takes secret bytes directly from the caller.
    rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
    /// Per-glyph RGB565 scratch (lives in the static singleton, not the stack).
    cell: [u16; CELL_N],
}

impl Display {
    pub const fn new() -> Self {
        Self {
            rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
            cell: [BG; CELL_N],
        }
    }

    pub fn init(&mut self) {
        // SPI1 init + SWRESET + full dgen1 init + clear (RES tied to 3V3).
        lcd::init();
        secure_log!("[S][LCD] NV3007 initialized (16x4 grid, 3x font, landscape)");
    }

    /// Reset the char grid to spaces. Panel-agnostic — identical to oled.rs.
    pub fn clear(&mut self) {
        for row in &mut self.rows {
            *row = [b' '; DISPLAY_COLS];
        }
    }

    /// Stamp one ASCII line into the char grid. Panel-agnostic — identical to
    /// oled.rs (bounds-check, 0x20..=0x7e anti-homoglyph clip, space-pad).
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

    /// Render the whole 16×4 grid (non-secret). No full-screen clear: every
    /// glyph cell is fully repainted (FG and BG) and the inter-cell gaps stay
    /// black from `init()`'s clear, so a full wipe would only add flicker
    /// (it races the panel scan) and ~24 ms with no benefit. `draw_line`
    /// space-pads every row to 16 cols, so all 64 cells are overwritten.
    pub fn flush(&mut self) {
        for r in 0..DISPLAY_ROWS {
            for c in 0..DISPLAY_COLS {
                let ch = self.rows[r][c];
                let cols = public_glyph_cols(ch);
                self.blit_glyph(c, r, &cols);
            }
        }
    }

    /// Flush with constant-time rendering for `secret_rows` (mnemonic words).
    /// The listed rows are rendered via the CT glyph scan + the branchless
    /// `blit_glyph`; all other rows go through the public path. Mirrors the
    /// `oled.rs::flush_with_secret_rows` security contract: secret rows never
    /// touch the address-keyed public lookup.
    ///
    /// `secret_rows`: `(row, text)` pairs; `row` in 0..DISPLAY_ROWS, `text` is
    /// the ASCII bytes for that row (already space-padded by the caller).
    pub fn flush_with_secret_rows(&mut self, secret_rows: &[(usize, &[u8])]) {
        // No full-screen clear (see `flush`): every cell — including the secret
        // rows' — is fully overwritten, so there's no stale-content leak and the
        // constant-time write pattern is preserved (overwrite, not OR-accumulate).
        // Public pass — skip secret rows.
        for r in 0..DISPLAY_ROWS {
            let is_secret = secret_rows.iter().any(|(p, _)| *p == r);
            if is_secret {
                continue;
            }
            for c in 0..DISPLAY_COLS {
                let ch = self.rows[r][c];
                let cols = public_glyph_cols(ch);
                self.blit_glyph(c, r, &cols);
            }
        }
        // Secret pass — constant-time glyph fetch, same branchless blit. Iterate
        // ALL DISPLAY_COLS columns regardless of text length; out-of-range
        // positions feed ch=0 and STILL run the full 96-entry scan, keeping the
        // access pattern uniform across word length and content.
        for &(row, text) in secret_rows {
            if row >= DISPLAY_ROWS {
                continue;
            }
            for c in 0..DISPLAY_COLS {
                let ch = if c < text.len() { text[c] } else { 0u8 };
                let cols = secret_glyph_cols(ch);
                self.blit_glyph(c, row, &cols);
            }
        }
    }

    /// Minimal boot splash: centered title, hold, blank. (The OLED's animated
    /// reveal is cosmetic; a static title is fine for Phase C.)
    pub fn splash(&mut self) {
        self.clear();
        self.draw_line(1, "   PQ SIGNER");
        self.flush();
        delay_ms(700);
        self.clear();
        self.flush();
    }

    /// Render one glyph cell `(col, row)` from its 5 column-bytes. SHARED by
    /// the public and secret paths — its write pattern depends only on the
    /// column bytes (the glyph SHAPE), never on the character's address, and it
    /// writes EVERY pixel (FG or BG via a branchless mask). This is what keeps
    /// the secret path constant-time once `cols` came from the CT scan.
    ///
    /// Coordinate model: a logical LANDSCAPE pixel `(lx, ly)` (lx 0..428 = the
    /// wide axis, ly 0..142 = the short axis) maps to a NATIVE pixel via a 90°
    /// transpose (native-X ← landscape-Y, native-Y ← landscape-X) plus optional
    /// per-axis flips `FLIP = (fx, fy)`:
    ///   nx = fx ? (PANEL_W-1 - ly) : ly      ny = fy ? (PANEL_H-1 - lx) : lx
    /// We fill the cell in native scan order (RASET row outer = ny, CASET col
    /// inner = nx) and inverse-map each native pixel back to the glyph source,
    /// so any of the 4 flip combos renders correctly with the same code.
    fn blit_glyph(&mut self, col: usize, row: usize, cols: &[u8; FONT_W]) {
        let (fx, fy) = unsafe { FLIP };
        let lx0 = ORIGIN_X + col * COL_PITCH; // landscape X of glyph left
        let ly0 = ORIGIN_Y + row * ROW_PITCH; // landscape Y of glyph top

        // Native window min-corner = forward transform of the glyph's
        // landscape extent (flips reverse the axis, so the min flips to the far
        // edge). Native-X extent = landscape-Y height (CELL_NX=24); native-Y
        // extent = landscape-X width (CELL_NY=15).
        let nx0 = if fx { (PANEL_W - 1) - (ly0 + GLYPH_LH - 1) } else { ly0 };
        let ny0 = if fy { (PANEL_H - 1) - (lx0 + GLYPH_LW - 1) } else { lx0 };

        let mut cy = 0usize; // native-Y offset within the cell 0..CELL_NY
        while cy < CELL_NY {
            let mut cx = 0usize; // native-X offset within the cell 0..CELL_NX
            while cx < CELL_NX {
                let nx = nx0 + cx;
                let ny = ny0 + cy;
                // Inverse-map native → landscape.
                let ly = if fx { (PANEL_W - 1) - nx } else { nx };
                let lx = if fy { (PANEL_H - 1) - ny } else { ny };
                let gx = lx - lx0; // landscape-X within glyph 0..GLYPH_LW
                let gy = ly - ly0; // landscape-Y within glyph 0..GLYPH_LH
                let sx = gx / SCALE; // glyph column 0..FONT_W
                let sy = gy / SCALE; // glyph row    0..FONT_H
                let bit = (cols[sx] >> sy) & 1; // 0 or 1
                let mask = (bit as u16).wrapping_neg(); // 0xFFFF if set, else 0x0000
                self.cell[cy * CELL_NX + cx] = (mask & FG) | (!mask & BG);
                cx += 1;
            }
            cy += 1;
        }

        // set_window applies the proven native X_OFFSET=12.
        lcd::set_window(
            nx0 as u16,
            ny0 as u16,
            (nx0 + CELL_NX - 1) as u16,
            (ny0 + CELL_NY - 1) as u16,
        );
        lcd::write_pixels(&self.cell[..CELL_N]);
    }

    /// Bench orientation sweep (`lcd-test`): cycles the 4 flip combos, clearing
    /// between each, so a bench observer can identify which renders upright +
    /// un-mirrored. The active combo is logged per window. Never returns.
    #[cfg(feature = "lcd-test")]
    pub fn orientation_test_loop(&mut self) -> ! {
        const COMBOS: [(bool, bool); 4] =
            [(false, false), (true, false), (false, true), (true, true)];
        let mut k = 0usize;
        loop {
            let (fx, fy) = COMBOS[k % 4];
            set_flip(fx, fy);
            lcd::fill_screen(BG); // clear between orientations (text positions move)
            self.clear();
            self.draw_line(0, "PQ SIGNER");
            self.draw_line(1, "the quick brown");
            self.draw_line(
                2,
                match k % 4 {
                    0 => "0: flip none",
                    1 => "1: flip X",
                    2 => "2: flip Y",
                    _ => "3: flip XY",
                },
            );
            self.draw_line(3, "L=back   R=next");
            self.flush();
            secure_log!("[LCD-UI] orient {} flip=({},{})", k % 4, fx, fy);
            delay_ms(3000);
            k += 1;
        }
    }
}

/// Blocking ~ms delay at 160 MHz (splash pacing only; precision unimportant).
fn delay_ms(ms: u32) {
    for _ in 0..ms {
        for _ in 0..40_000 {
            cortex_m::asm::nop();
        }
    }
}

// ---------------------------------------------------------------------------
// Input — GPIO buttons (panel-independent; same as the OLED backend).
// ---------------------------------------------------------------------------

pub struct Input {
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
        #[cfg(feature = "gpio-buttons")]
        unsafe {
            crate::hw::buttons::init();
            secure_log!(
                "[S][LCD] GPIO buttons ready on {} (LEFT=pin {}, RIGHT=pin {})",
                crate::board::BOARD_NAME,
                crate::board::BTN_LEFT_PIN,
                crate::board::BTN_RIGHT_PIN
            );
        }

        #[cfg(feature = "debug-log")]
        {
            // DHCSR.C_DEBUGEN gate: the semihosting OPEN is a BKPT; without a
            // debugger it HardFaults, so only open when a debugger is attached
            // (see oled.rs for the full rationale).
            let c_debugen = unsafe { core::ptr::read_volatile(0xE000_EDF0 as *const u32) & 1 };
            if c_debugen != 0 {
                use cortex_m_semihosting::syscall;
                let path = b"/input\0";
                let fd = unsafe { syscall!(OPEN, path.as_ptr(), 0usize, path.len() - 1) };
                if fd != usize::MAX {
                    self.fd = fd;
                    secure_log!("[S][LCD] button input ready (fd={})", fd);
                }
            }
        }
    }

    pub fn wait_button(&mut self, idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
        #[cfg(feature = "gpio-buttons")]
        {
            return crate::hw::buttons::wait_event(idle_check);
        }

        #[cfg(all(not(feature = "gpio-buttons"), feature = "debug-log"))]
        if self.fd != usize::MAX {
            use cortex_m_semihosting::syscall;
            loop {
                let mut buf = [0u8; 1];
                let not_read = unsafe { syscall!(READ, self.fd, buf.as_mut_ptr(), 1usize) };
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

        #[cfg(not(feature = "gpio-buttons"))]
        loop {
            if idle_check() {
                return None;
            }
            cortex_m::asm::wfe();
        }
    }
}
