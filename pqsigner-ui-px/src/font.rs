//! Baked Aileron glyph atlases (`secure/assets/ui-px/fonts.bin`, produced by
//! `tools/ui_px_assets.py`) and text runs.
//!
//! Atlas format (little-endian):
//!
//! ```text
//! FileHeader  magic "PQ1F" | version u16 | n_tiers u16 | total_len u32          (12 B)
//! Tier[n]     size_px u8 | weight u8 | first_code u8 | n_glyphs u8 |
//!             ascent_q6 i16 | descent_q6 i16 | glyph_tab_off u32 | bitmap_off u32 (16 B)
//! Glyph[n]    w u8 | h u8 | bearing_x i8 | bearing_top i8 | advance_q6 u16 |
//!             bmp_off u16                                                       (8 B)
//! Bitmap      rows of (w+1)/2 bytes, 4-bit alpha, high nibble first
//! ```
//!
//! The reader validates every offset before use and treats a malformed
//! atlas as "no glyphs" (a rendering defect the golden tests catch, never a
//! panic on the device).

use crate::fixed::Q8;
use crate::raster::{Rgb, Strip};

const FILE_HDR: usize = 12;
const TIER_HDR: usize = 16;
const GLYPH_REC: usize = 8;

/// A tier identity: pixel size and weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierId {
    pub px: u8,
    pub semibold: bool,
}

impl TierId {
    #[must_use]
    pub const fn regular(px: u8) -> Self {
        Self { px, semibold: false }
    }

    #[must_use]
    pub const fn semibold(px: u8) -> Self {
        Self { px, semibold: true }
    }
}

/// A parsed glyph.
#[derive(Clone, Copy, Debug)]
pub struct Glyph<'a> {
    pub w: u8,
    pub h: u8,
    pub bearing_x: i8,
    /// Rows above the baseline at which the bitmap's top row sits.
    pub bearing_top: i8,
    pub advance_q6: u16,
    pub rows: &'a [u8],
}

/// One tier's view into the atlas.
#[derive(Clone, Copy, Debug)]
pub struct Tier<'a> {
    pub id: TierId,
    first_code: u8,
    n_glyphs: u8,
    pub ascent_q6: i16,
    pub descent_q6: i16,
    table: &'a [u8],
    bitmap: &'a [u8],
}

impl<'a> Tier<'a> {
    /// Glyph for an ASCII code (0x7F = ellipsis in caption tiers).
    #[must_use]
    pub fn glyph(&self, code: u8) -> Option<Glyph<'a>> {
        let i = usize::from(code.checked_sub(self.first_code)?);
        if i >= usize::from(self.n_glyphs) {
            return None;
        }
        let rec = self.table.get(i * GLYPH_REC..(i + 1) * GLYPH_REC)?;
        let w = rec[0];
        let h = rec[1];
        let bearing_x = rec[2] as i8;
        let bearing_top = rec[3] as i8;
        let advance_q6 = u16::from_le_bytes([rec[4], rec[5]]);
        let off = usize::from(u16::from_le_bytes([rec[6], rec[7]]));
        if advance_q6 == 0 && w == 0 {
            return None; // not baked
        }
        let stride = (usize::from(w) + 1) / 2;
        let rows = if w == 0 || h == 0 {
            &self.bitmap[..0]
        } else {
            self.bitmap.get(off..off + stride * usize::from(h))?
        };
        Some(Glyph {
            w,
            h,
            bearing_x,
            bearing_top,
            advance_q6,
            rows,
        })
    }
}

/// The atlas.
#[derive(Clone, Copy, Debug)]
pub struct Font<'a> {
    data: &'a [u8],
    n_tiers: usize,
}

impl<'a> Font<'a> {
    /// Parse and validate the file header; `None` if malformed.
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < FILE_HDR || &data[..4] != b"PQ1F" {
            return None;
        }
        let version = u16::from_le_bytes([data[4], data[5]]);
        let n_tiers = usize::from(u16::from_le_bytes([data[6], data[7]]));
        let total = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if version != 1 || total != data.len() || data.len() < FILE_HDR + n_tiers * TIER_HDR {
            return None;
        }
        let f = Self { data, n_tiers };
        // Every tier's table and bitmap must lie inside the file.
        for i in 0..n_tiers {
            f.tier_at(i)?;
        }
        Some(f)
    }

    /// An atlas with no glyphs (tests / bring-up without assets).
    #[must_use]
    pub const fn empty() -> Self {
        Self { data: &[], n_tiers: 0 }
    }

    fn tier_at(&self, i: usize) -> Option<Tier<'a>> {
        let h = self.data.get(FILE_HDR + i * TIER_HDR..FILE_HDR + (i + 1) * TIER_HDR)?;
        let n_glyphs = h[3];
        let tab = u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as usize;
        let bmp = u32::from_le_bytes([h[12], h[13], h[14], h[15]]) as usize;
        let table = self.data.get(tab..tab + usize::from(n_glyphs) * GLYPH_REC)?;
        let bitmap = self.data.get(bmp..)?;
        Some(Tier {
            id: TierId {
                px: h[0],
                semibold: h[1] == 1,
            },
            first_code: h[2],
            n_glyphs,
            ascent_q6: i16::from_le_bytes([h[4], h[5]]),
            descent_q6: i16::from_le_bytes([h[6], h[7]]),
            table,
            bitmap,
        })
    }

    #[must_use]
    pub fn tier(&self, id: TierId) -> Option<Tier<'a>> {
        (0..self.n_tiers).filter_map(|i| self.tier_at(i)).find(|t| t.id == id)
    }

    /// Width of a run in Q6 (advances + letter-spacing between glyphs);
    /// `None` when a glyph is missing at this tier.
    #[must_use]
    pub fn measure_q6(&self, id: TierId, text: &[u8], ls_q6: i32) -> Option<i32> {
        let t = self.tier(id)?;
        let mut w = 0i32;
        for (i, &c) in text.iter().enumerate() {
            w += i32::from(t.glyph(c)?.advance_q6);
            if i + 1 < text.len() {
                w += ls_q6;
            }
        }
        Some(w)
    }

    /// Composite a run into the strip.
    pub fn blit_run(&self, run: &TextRun<'_>, color: Rgb, s: &mut Strip<'_>) {
        let Some(t) = self.tier(run.tier) else { return };
        let width = self.measure_q6(run.tier, run.text, run.ls_q6).unwrap_or(0);
        // Origin: x in Q6 (left edge), y = baseline in px.
        let mut x_q6 = match run.align {
            Align::Left => run.x << 6,
            Align::Center => (run.x << 6) - width / 2,
            Align::Right => (run.x << 6) - width,
        };
        let baseline = if run.baseline {
            run.y
        } else {
            // Vertical centre: Pillow's "mm" anchor centres the ascender box.
            run.y + ((i32::from(t.ascent_q6) - i32::from(t.descent_q6)) / 2 + 32) / 64
        };
        // Cheap reject: the tier's vertical extent misses the strip.
        let top = baseline - (i32::from(t.ascent_q6) + 63) / 64 - 1;
        let bottom = baseline + (i32::from(t.descent_q6) + 63) / 64 + 1;
        if bottom < s.y0 || top >= s.y0 + s.h {
            return;
        }
        for (i, &c) in run.text.iter().enumerate() {
            let Some(g) = t.glyph(c) else { continue };
            let gx = ((x_q6 + 32) >> 6) + i32::from(g.bearing_x);
            let gy = baseline - i32::from(g.bearing_top);
            blit_glyph(s, &g, gx, gy, color, run.alpha);
            x_q6 += i32::from(g.advance_q6);
            if i + 1 < run.text.len() {
                x_q6 += run.ls_q6;
            }
        }
    }
}

fn blit_glyph(s: &mut Strip<'_>, g: &Glyph<'_>, x0: i32, y0: i32, color: Rgb, alpha: u8) {
    if g.w == 0 || g.h == 0 {
        return;
    }
    let stride = (usize::from(g.w) + 1) / 2;
    let y_lo = y0.max(s.y0);
    let y_hi = (y0 + i32::from(g.h)).min(s.y0 + s.h);
    // Per-run colour LUT over the 16 alpha levels × the run alpha.
    let mut lut = [0u8; 16];
    for (n, v) in lut.iter_mut().enumerate() {
        *v = ((n as u16 * 17 * u16::from(alpha) + 127) / 255) as u8;
    }
    for y in y_lo..y_hi {
        let row = &g.rows[(y - y0) as usize * stride..];
        for x in 0..i32::from(g.w) {
            let b = row[(x / 2) as usize];
            let n = if x % 2 == 0 { b >> 4 } else { b & 0x0F };
            if n != 0 {
                s.blend(x0 + x, y, color, lut[usize::from(n)]);
            }
        }
    }
}

/// Horizontal alignment of a run about its `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

/// A text run to draw.
#[derive(Clone, Copy, Debug)]
pub struct TextRun<'a> {
    pub text: &'a [u8],
    pub tier: TierId,
    /// Anchor x in px.
    pub x: i32,
    /// Baseline y (when `baseline`) or vertical centre y, px.
    pub y: i32,
    pub align: Align,
    pub baseline: bool,
    /// Letter-spacing between glyphs, Q6.
    pub ls_q6: i32,
    /// Run alpha (the design's text crossfade), 0..=255.
    pub alpha: u8,
}

/// Q8 helper for layout code that mixes px and Q8.
#[must_use]
pub const fn px_q8(px: i32) -> Q8 {
    px << 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raster::{Frame, Item, W};
    use std::vec::Vec;

    const FONTS: &[u8] = include_bytes!("../../secure/assets/ui-px/fonts.bin");

    #[test]
    fn atlas_parses_and_has_every_tier() {
        let f = Font::parse(FONTS).expect("valid atlas");
        for (px, sb) in [(36, false), (32, false), (28, false), (22, false), (22, true), (18, false), (16, true), (16, false)] {
            assert!(f.tier(TierId { px, semibold: sb }).is_some(), "tier {px}/{sb}");
        }
        assert!(f.tier(TierId::semibold(36)).is_none());
        let t = f.tier(TierId::regular(36)).unwrap();
        let a = t.glyph(b'A').unwrap();
        assert!(a.w > 15 && a.h > 20, "{a:?}");
        assert!(t.glyph(b'{').is_none(), "trimmed charset");
        assert!(f.tier(TierId::regular(18)).unwrap().glyph(0x7F).is_some(), "ellipsis");
    }

    #[test]
    fn metrics_match_the_generated_table() {
        let f = Font::parse(FONTS).unwrap();
        for m in &crate::metrics_gen::TIERS {
            let t = f.tier(TierId { px: m.px, semibold: m.semibold }).unwrap();
            for code in 0x20u8..0x7F {
                let adv = t.glyph(code).map_or(0, |g| g.advance_q6);
                assert_eq!(adv, m.advance_q6[usize::from(code - 0x20)], "tier {} code {code}", m.px);
            }
        }
    }

    #[test]
    fn malformed_atlas_is_rejected() {
        assert!(Font::parse(&[]).is_none());
        let mut bad = FONTS.to_vec();
        bad[0] = b'X';
        assert!(Font::parse(&bad).is_none());
        let mut short = FONTS.to_vec();
        short.truncate(FONTS.len() - 1);
        assert!(Font::parse(&short).is_none(), "total_len mismatch");
    }

    #[test]
    fn text_run_draws_within_its_measured_box() {
        let f = Font::parse(FONTS).unwrap();
        let mut buf = vec![0u16; (W * 142) as usize];
        let mut s = Strip::new(0, 142, &mut buf).unwrap();
        let run = TextRun {
            text: b"SEND 250 USDC?",
            tier: TierId::regular(18),
            x: 214,
            y: 128,
            align: Align::Center,
            baseline: true,
            ls_q6: 32,
            alpha: 255,
        };
        let mut fr = Frame::new();
        fr.push(Item::Text { run, color: Rgb::WHITE });
        crate::raster::render_strip(&fr, &f, &mut s);
        let w = f.measure_q6(TierId::regular(18), run.text, 32).unwrap() / 64;
        let lit: Vec<(i32, i32)> = (0..142).flat_map(|y| (0..W).map(move |x| (x, y))).filter(|&(x, y)| s.get(x, y) != 0).collect();
        assert!(!lit.is_empty());
        let (min_x, max_x) = (lit.iter().map(|p| p.0).min().unwrap(), lit.iter().map(|p| p.0).max().unwrap());
        let (min_y, max_y) = (lit.iter().map(|p| p.1).min().unwrap(), lit.iter().map(|p| p.1).max().unwrap());
        assert!(min_x >= 214 - w / 2 - 2 && max_x <= 214 + w / 2 + 2, "x {min_x}..{max_x} vs w {w}");
        assert!(max_y <= 129 && min_y >= 128 - 18, "y {min_y}..{max_y}");
    }
}
