//! Strip rasteriser: a display list of anti-aliased primitives rendered
//! into a caller-provided 428 × N RGB565 strip.
//!
//! The panel is 428 × 142 landscape; a full RGB565 frame (121 KB) does not
//! fit secure SRAM, so a frame is rendered as horizontal strips (the firmware
//! uses 16 rows = 13.7 KB) and each strip streamed to the panel. Every
//! primitive is clipped to the strip's rows, so rendering the same [`Frame`]
//! into successive strips yields the full picture.
//!
//! The background is pure black, so the design's "alpha = scale toward
//! black" idiom is exact: an item's colour is pre-scaled by its alpha and
//! composited **over** whatever is already in the strip (text under a
//! passing disc, the hold film over the disc art, a ring over the film).
//!
//! Coordinates are Q8 (1/256 px), coverage is 0..=255. Everything is
//! integer; host and device renders are bit-identical.

use crate::fixed::{dist_q8, isqrt_u64, Q16, Q8, ONE_Q8};
use crate::font::{Font, TextRun};

pub const W: i32 = 428;
pub const H: i32 = 142;

/// An 8-bit-per-channel colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub const BLACK: Self = Self::new(0, 0, 0);
    pub const WHITE: Self = Self::new(255, 255, 255);
    /// DESIGN.md palette.
    pub const YELLOW: Self = Self::new(0xDC, 0xC4, 0x19);
    pub const GREEN: Self = Self::new(0x2E, 0xE5, 0x6A);
    pub const RED: Self = Self::new(0xFF, 0x42, 0x3D);
    pub const ORANGE: Self = Self::new(0xF5, 0xA0, 0x33);
    /// Safe brand fill (`#13FF7F`) and its trail ramp, far → near.
    pub const SAFE_FILL: Self = Self::new(0x13, 0xFF, 0x7F);
    pub const SAFE_TRAIL: [Self; 5] = [
        Self::new(0x35, 0x4E, 0x40),
        Self::new(0x2A, 0x6E, 0x4C),
        Self::new(0x22, 0x92, 0x5A),
        Self::new(0x1C, 0xB8, 0x69),
        Self::new(0x18, 0xDD, 0x75),
    ];
    /// Black-body mono token: white ring, grey trail.
    pub const MONO_TRAIL: [Self; 5] = [
        Self::new(0x28, 0x28, 0x28),
        Self::new(0x3A, 0x3A, 0x3A),
        Self::new(0x50, 0x50, 0x50),
        Self::new(0x6A, 0x6A, 0x6A),
        Self::new(0x88, 0x88, 0x88),
    ];

    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Scale toward black by `a` (0..=255) — the design's alpha idiom.
    #[must_use]
    pub const fn scale(self, a: u8) -> Self {
        let a = a as u16;
        Self {
            r: ((self.r as u16 * a + 127) / 255) as u8,
            g: ((self.g as u16 * a + 127) / 255) as u8,
            b: ((self.b as u16 * a + 127) / 255) as u8,
        }
    }

    /// Scale toward black by a Q16 factor in `[0, 1]`.
    #[must_use]
    pub fn scale_q16(self, k: Q16) -> Self {
        let a = ((i64::from(k.clamp(0, 1 << 16)) * 255) >> 16) as u8;
        self.scale(a)
    }

    #[must_use]
    pub const fn to565(self) -> u16 {
        ((self.r as u16 & 0xF8) << 8) | ((self.g as u16 & 0xFC) << 3) | (self.b as u16 >> 3)
    }

    #[must_use]
    pub const fn from565(p: u16) -> Self {
        let r5 = (p >> 11) & 0x1F;
        let g6 = (p >> 5) & 0x3F;
        let b5 = p & 0x1F;
        Self {
            r: ((r5 << 3) | (r5 >> 2)) as u8,
            g: ((g6 << 2) | (g6 >> 4)) as u8,
            b: ((b5 << 3) | (b5 >> 2)) as u8,
        }
    }
}

/// `dst + (src − dst)·a`, in RGB565.
#[must_use]
pub fn blend_over(dst: u16, src: Rgb, a: u8) -> u16 {
    if a == 0 {
        return dst;
    }
    if a == 255 {
        return src.to565();
    }
    let d = Rgb::from565(dst);
    let a = i32::from(a);
    let ch = |d: u8, s: u8| -> u8 { (i32::from(d) + ((i32::from(s) - i32::from(d)) * a + 127) / 255) as u8 };
    Rgb::new(ch(d.r, src.r), ch(d.g, src.g), ch(d.b, src.b)).to565()
}

/// A horizontal band of the frame: rows `y0 .. y0 + h`, row-major landscape.
pub struct Strip<'a> {
    pub y0: i32,
    pub h: i32,
    pub buf: &'a mut [u16],
}

impl<'a> Strip<'a> {
    /// `buf` must hold `W * h` pixels.
    #[must_use]
    pub fn new(y0: i32, h: i32, buf: &'a mut [u16]) -> Option<Self> {
        if h <= 0 || y0 < 0 || y0 + h > H || buf.len() < (W * h) as usize {
            return None;
        }
        Some(Self { y0, h, buf })
    }

    pub fn clear(&mut self) {
        for p in self.buf[..(W * self.h) as usize].iter_mut() {
            *p = 0;
        }
    }

    #[inline]
    fn idx(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || x >= W || y < self.y0 || y >= self.y0 + self.h {
            return None;
        }
        Some(((y - self.y0) * W + x) as usize)
    }

    /// Composite `color` at coverage `a` over pixel `(x, y)` (clipped).
    #[inline]
    pub fn blend(&mut self, x: i32, y: i32, color: Rgb, a: u8) {
        if let Some(i) = self.idx(x, y) {
            self.buf[i] = blend_over(self.buf[i], color, a);
        }
    }

    /// Landscape pixel readback (clipped: black outside the strip).
    #[must_use]
    pub fn get(&self, x: i32, y: i32) -> u16 {
        self.idx(x, y).map_or(0, |i| self.buf[i])
    }
}

/// A 4-bit alpha mask asset (disc marks), centred art.
#[derive(Clone, Copy, Debug)]
pub struct Mask<'a> {
    pub w: u16,
    pub h: u16,
    /// Rows of `(w + 1) / 2` bytes, high nibble first.
    pub rows: &'a [u8],
}

impl Mask<'_> {
    #[must_use]
    pub fn alpha4(&self, x: u16, y: u16) -> u8 {
        if x >= self.w || y >= self.h {
            return 0;
        }
        let stride = (usize::from(self.w) + 1) / 2;
        let b = self.rows.get(usize::from(y) * stride + usize::from(x) / 2).copied().unwrap_or(0);
        if x % 2 == 0 {
            b >> 4
        } else {
            b & 0x0F
        }
    }
}

/// One display-list entry. Colours are pre-scaled by the item's alpha.
#[derive(Clone, Copy, Debug)]
pub enum Item<'a> {
    None,
    /// Filled anti-aliased disc.
    Disc { cx: Q8, cy: Q8, r: Q8, color: Rgb },
    /// Anti-aliased annulus `[r − w, r]` (strokes inward).
    Ring { cx: Q8, cy: Q8, r: Q8, w: Q8, color: Rgb },
    /// The hold flood: the part of the disc below `level_y`, composited at `a`.
    Chord { cx: Q8, cy: Q8, r: Q8, level_y: Q8, color: Rgb, a: u8 },
    /// A text run (glyphs composited over).
    Text { run: TextRun<'a>, color: Rgb },
    /// Rounded chevron (the design's corner marker), `angle` in Q16 turns:
    /// 0 = pointing right, 0.25 = up, 0.5 = left.
    Chevron { cx: Q8, cy: Q8, angle: Q16, color: Rgb },
    /// Check mark inside a disc of radius `r` (marks.py geometry), `k` in Q16 = draw progress.
    Check { cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16 },
    /// Cross mark inside a disc of radius `r`.
    Cross { cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16 },
    /// A 4-bit mask centred at `(cx, cy)`, scaled by `scale` (Q8, 1.0 = 256).
    Mask { cx: Q8, cy: Q8, mask: Mask<'a>, scale: Q8, color: Rgb, a: u8 },
    /// Axis-aligned filled rectangle (integer px).
    Rect { x: i32, y: i32, w: i32, h: i32, color: Rgb, a: u8 },
}

/// Display list capacity: chevrons (2) + texts (≤ 12 across two screens) +
/// trail (5) + disc + mark + chord + ring + pager + band + spares.
pub const MAX_ITEMS: usize = 40;

/// A frame's display list, drawn in order.
pub struct Frame<'a> {
    pub items: [Item<'a>; MAX_ITEMS],
    pub n: usize,
}

impl<'a> Frame<'a> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [Item::None; MAX_ITEMS],
            n: 0,
        }
    }

    /// Append; silently drops past capacity (a rendering, not a security,
    /// failure — the transcript is what is proven, and the golden tests
    /// pin that every scene fits).
    pub fn push(&mut self, item: Item<'a>) -> bool {
        if self.n >= MAX_ITEMS {
            return false;
        }
        self.items[self.n] = item;
        self.n += 1;
        true
    }

    #[must_use]
    pub fn items(&self) -> &[Item<'a>] {
        &self.items[..self.n]
    }
}

impl Default for Frame<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Render every item of `frame` that intersects `strip` (cleared first).
pub fn render_strip(frame: &Frame<'_>, font: &Font<'_>, strip: &mut Strip<'_>) {
    strip.clear();
    for item in frame.items() {
        draw_item(item, font, strip);
    }
}

fn draw_item(item: &Item<'_>, font: &Font<'_>, s: &mut Strip<'_>) {
    match *item {
        Item::None => {}
        Item::Disc { cx, cy, r, color } => disc(s, cx, cy, r, color, None),
        Item::Ring { cx, cy, r, w, color } => ring(s, cx, cy, r, w, color),
        Item::Chord { cx, cy, r, level_y, color, a } => chord(s, cx, cy, r, level_y, color, a),
        Item::Text { ref run, color } => font.blit_run(run, color, s),
        Item::Chevron { cx, cy, angle, color } => chevron(s, cx, cy, angle, color),
        Item::Check { cx, cy, r, color, k } => check(s, cx, cy, r, color, k),
        Item::Cross { cx, cy, r, color, k } => cross(s, cx, cy, r, color, k),
        Item::Mask { cx, cy, mask, scale, color, a } => mask_blit(s, cx, cy, &mask, scale, color, a),
        Item::Rect { x, y, w, h, color, a } => {
            for yy in y.max(s.y0)..(y + h).min(s.y0 + s.h) {
                for xx in x.max(0)..(x + w).min(W) {
                    s.blend(xx, yy, color, a);
                }
            }
        }
    }
}

/// Coverage of a pixel at signed distance `d` (Q8) from an edge, where the
/// inside is `d ≤ 0`: 1 − clamp(d + ½).
#[inline]
fn edge_cov(d: Q8) -> u8 {
    let v = ONE_Q8 / 2 - d; // (0.5 − d) in Q8
    (v.clamp(0, ONE_Q8) * 255 / ONE_Q8) as u8
}

/// Filled disc; `max_y` limits the fill to rows `≥ max_y` when given (chord).
fn disc(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, color: Rgb, min_y: Option<(Q8, u8)>) {
    let (level, a) = min_y.unwrap_or((i32::MIN / 2, 255));
    let y_lo = ((cy - r) >> 8) - 1;
    let y_hi = ((cy + r) >> 8) + 1;
    let x_lo = ((cx - r) >> 8) - 1;
    let x_hi = ((cx + r) >> 8) + 1;
    for y in y_lo.max(s.y0)..=y_hi.min(s.y0 + s.h - 1) {
        let py = (y << 8) + ONE_Q8 / 2; // pixel centre
        if py < level {
            continue;
        }
        let dy = py - cy;
        for x in x_lo.max(0)..=x_hi.min(W - 1) {
            let px = (x << 8) + ONE_Q8 / 2;
            let d = dist_q8(px - cx, dy) - r;
            let cov = edge_cov(d);
            if cov != 0 {
                let aa = ((u16::from(cov) * u16::from(a) + 127) / 255) as u8;
                s.blend(x, y, color, aa);
            }
        }
    }
}

fn chord(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, level_y: Q8, color: Rgb, a: u8) {
    disc(s, cx, cy, r, color, Some((level_y, a)));
}

fn ring(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, w: Q8, color: Rgb) {
    let r_in = r - w;
    let y_lo = ((cy - r) >> 8) - 1;
    let y_hi = ((cy + r) >> 8) + 1;
    let x_lo = ((cx - r) >> 8) - 1;
    let x_hi = ((cx + r) >> 8) + 1;
    for y in y_lo.max(s.y0)..=y_hi.min(s.y0 + s.h - 1) {
        let dy = (y << 8) + ONE_Q8 / 2 - cy;
        if dy.abs() > r + ONE_Q8 {
            continue;
        }
        for x in x_lo.max(0)..=x_hi.min(W - 1) {
            let px = (x << 8) + ONE_Q8 / 2;
            let d = dist_q8(px - cx, dy);
            // Inside the annulus when r_in ≤ d ≤ r: signed distance to the
            // nearest edge, negative inside.
            let sd = (d - r).max(r_in - d);
            let cov = edge_cov(sd);
            if cov != 0 {
                s.blend(x, y, color, cov);
            }
        }
    }
}

/// Distance (Q8) from `p` to the segment `a → b`.
fn seg_dist(px: Q8, py: Q8, ax: Q8, ay: Q8, bx: Q8, by: Q8) -> Q8 {
    let abx = i64::from(bx - ax);
    let aby = i64::from(by - ay);
    let apx = i64::from(px - ax);
    let apy = i64::from(py - ay);
    let ab2 = abx * abx + aby * aby;
    let t = if ab2 == 0 { 0 } else { ((apx * abx + apy * aby) << 8) / ab2 }; // Q8 in [0,1]
    let t = t.clamp(0, i64::from(ONE_Q8));
    let qx = ax + ((abx * t) >> 8) as Q8;
    let qy = ay + ((aby * t) >> 8) as Q8;
    dist_q8(px - qx, py - qy)
}

/// Stroke a polyline with round caps/joins (capsule union), `hw` half-width.
fn capsules(s: &mut Strip<'_>, pts: &[(Q8, Q8)], hw: Q8, color: Rgb) {
    if pts.len() < 2 {
        return;
    }
    let (mut x_lo, mut x_hi, mut y_lo, mut y_hi) = (i32::MAX, i32::MIN, i32::MAX, i32::MIN);
    for &(x, y) in pts {
        x_lo = x_lo.min(x);
        x_hi = x_hi.max(x);
        y_lo = y_lo.min(y);
        y_hi = y_hi.max(y);
    }
    let pad = hw + ONE_Q8;
    for y in ((y_lo - pad) >> 8).max(s.y0)..=((y_hi + pad) >> 8).min(s.y0 + s.h - 1) {
        let py = (y << 8) + ONE_Q8 / 2;
        for x in ((x_lo - pad) >> 8).max(0)..=((x_hi + pad) >> 8).min(W - 1) {
            let px = (x << 8) + ONE_Q8 / 2;
            let mut d = i32::MAX;
            for w in pts.windows(2) {
                d = d.min(seg_dist(px, py, w[0].0, w[0].1, w[1].0, w[1].1));
            }
            let cov = edge_cov(d - hw);
            if cov != 0 {
                s.blend(x, y, color, cov);
            }
        }
    }
}

/// Rotate a point around the origin by `angle` (Q16 turns).
fn rot(x: Q8, y: Q8, angle: Q16) -> (Q8, Q8) {
    use crate::fixed::{cos_turns_q16, sin_turns_q16};
    let c = i64::from(cos_turns_q16(angle));
    let sn = i64::from(sin_turns_q16(angle));
    let rx = ((i64::from(x) * c - i64::from(y) * sn) >> 16) as Q8;
    let ry = ((i64::from(x) * sn + i64::from(y) * c) >> 16) as Q8;
    (rx, ry)
}

/// The design's chevron (`components.chevron`): a triangle with apex at
/// (0, −4) and base at y 3.2, stroked 4.5 with round joints — here the
/// filled rounded triangle: polygon inset by the stroke half-width, then
/// re-expanded with round corners. `angle` 0 = pointing right.
fn chevron(s: &mut Strip<'_>, cx: Q8, cy: Q8, angle: Q16, color: Rgb) {
    // Base geometry points up (apex at −y). Angles are mathematical turns
    // (0 = right, 0.25 = up, 0.5 = left) but the screen's y axis points
    // down, so the rotation that carries the apex from "up" to `angle` is
    // (0.25 − angle) in the y-down matrix.
    let apex = (0, -4 * ONE_Q8);
    let bl = (-4 * ONE_Q8 - ONE_Q8 / 5, 3 * ONE_Q8 + ONE_Q8 / 5);
    let br = (4 * ONE_Q8 + ONE_Q8 / 5, 3 * ONE_Q8 + ONE_Q8 / 5);
    let a = (1i32 << 14).wrapping_sub(angle); // 0.25 − angle
    let p = |(x, y): (Q8, Q8)| {
        let (rx, ry) = rot(x, y, a);
        (cx + rx, cy + ry)
    };
    let pts = [p(bl), p(apex), p(br)];
    // A stroke of half-width 2.25 px around the two arms reads as the
    // design's rounded chevron.
    capsules(s, &pts, (9 * ONE_Q8) / 4, color);
}

/// Check mark: polyline (−.40r, .02r) → (−.10r, .30r) → (.44r, −.28r),
/// stroke 0.16 r, drawn progressively by `k`.
fn check(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16) {
    let f = |num: i32, den: i32| ((i64::from(r) * i64::from(num)) / i64::from(den)) as Q8;
    let a = (cx + f(-40, 100), cy + f(2, 100));
    let b = (cx + f(-10, 100), cy + f(30, 100));
    let c = (cx + f(44, 100), cy + f(-28, 100));
    let hw = f(8, 100);
    if k >= (1 << 16) {
        capsules(s, &[a, b, c], hw, color);
        return;
    }
    // Progressive: first arm over k ∈ [0, .4], second over [.4, 1].
    let split = (2 << 16) / 5;
    if k <= split {
        let t = (i64::from(k) << 16) / i64::from(split);
        let m = (crate::fixed::lerp(a.0, b.0, t as i32), crate::fixed::lerp(a.1, b.1, t as i32));
        capsules(s, &[a, m], hw, color);
    } else {
        let t = ((i64::from(k - split)) << 16) / i64::from((1 << 16) - split);
        let m = (crate::fixed::lerp(b.0, c.0, t as i32), crate::fixed::lerp(b.1, c.1, t as i32));
        capsules(s, &[a, b, m], hw, color);
    }
}

/// Cross mark: two segments at ±0.30 r, stroke 0.16 r.
fn cross(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16) {
    let f = |num: i32, den: i32| ((i64::from(r) * i64::from(num)) / i64::from(den)) as Q8;
    let hw = f(8, 100);
    let e = f(30, 100);
    let kk = k.clamp(0, 1 << 16);
    let ex = ((i64::from(e) * i64::from(kk)) >> 16) as Q8;
    capsules(s, &[(cx - e, cy - e), (cx - e + 2 * ex, cy - e + 2 * ex)], hw, color);
    if kk > (1 << 15) {
        let e2 = ((i64::from(e) * i64::from(kk - (1 << 15))) >> 15) as Q8;
        capsules(s, &[(cx + e, cy - e), (cx + e - 2 * e2, cy - e + 2 * e2)], hw, color);
    }
}

fn mask_blit(s: &mut Strip<'_>, cx: Q8, cy: Q8, m: &Mask<'_>, scale: Q8, color: Rgb, a: u8) {
    if scale <= 0 {
        return;
    }
    let dw = (i64::from(m.w) * i64::from(scale) >> 8) as i32; // drawn size, px
    let dh = (i64::from(m.h) * i64::from(scale) >> 8) as i32;
    let x0 = (cx >> 8) - dw / 2;
    let y0 = (cy >> 8) - dh / 2;
    for y in y0.max(s.y0)..(y0 + dh).min(s.y0 + s.h) {
        let sy = (((y - y0) << 8) / scale.max(1)) as u16;
        for x in x0.max(0)..(x0 + dw).min(W) {
            let sx = (((x - x0) << 8) / scale.max(1)) as u16;
            let a4 = m.alpha4(sx, sy);
            if a4 != 0 {
                let cov = u16::from(a4) * 17;
                let aa = ((cov * u16::from(a) + 127) / 255) as u8;
                s.blend(x, y, color, aa);
            }
        }
    }
}

/// Convenience: isqrt of a Q8·Q8 product.
#[must_use]
pub fn sqrt_q16_to_q8(v: i64) -> Q8 {
    isqrt_u64(v.max(0) as u64) as Q8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_round_trips_and_scales() {
        assert_eq!(Rgb::WHITE.to565(), 0xFFFF);
        assert_eq!(Rgb::BLACK.to565(), 0);
        let g = Rgb::SAFE_FILL;
        let back = Rgb::from565(g.to565());
        assert!((i32::from(back.r) - i32::from(g.r)).abs() < 8);
        assert_eq!(Rgb::WHITE.scale(0), Rgb::BLACK);
        assert_eq!(Rgb::WHITE.scale(255), Rgb::WHITE);
        assert_eq!(blend_over(0, Rgb::WHITE, 255), 0xFFFF);
        assert_eq!(blend_over(0xFFFF, Rgb::WHITE, 0), 0xFFFF);
        let half = Rgb::from565(blend_over(0, Rgb::WHITE, 128));
        assert!((120..=136).contains(&half.r));
    }

    #[test]
    fn disc_covers_interior_and_edge_is_soft() {
        let mut buf = [0u16; (W * 16) as usize];
        let mut s = Strip::new(64, 16, &mut buf).unwrap();
        let mut f = Frame::new();
        // r = 30.5 px puts the edge through the centre of column 244.
        f.push(Item::Disc { cx: 214 << 8, cy: 72 << 8, r: (30 << 8) + 128, color: Rgb::WHITE });
        let font = Font::empty();
        render_strip(&f, &font, &mut s);
        assert_eq!(s.get(214, 72), 0xFFFF, "centre is solid");
        assert_eq!(s.get(214, 65), 0xFFFF);
        assert_eq!(s.get(100, 72), 0, "far outside is black");
        assert_eq!(s.get(243, 72), 0xFFFF, "inside the edge");
        let e = Rgb::from565(s.get(244, 72));
        assert!(e.r > 0 && e.r < 255, "edge {e:?}");
        assert_eq!(s.get(246, 72), 0);
    }

    #[test]
    fn ring_leaves_the_centre_black() {
        let mut buf = [0u16; (W * 16) as usize];
        let mut s = Strip::new(64, 16, &mut buf).unwrap();
        let mut f = Frame::new();
        f.push(Item::Ring { cx: 214 << 8, cy: 72 << 8, r: 30 << 8, w: (24 * 256) / 10, color: Rgb::WHITE });
        render_strip(&f, &Font::empty(), &mut s);
        assert_eq!(s.get(214, 72), 0);
        assert_eq!(s.get(214 + 29, 72), 0xFFFF);
    }

    #[test]
    fn chord_fills_only_below_the_level() {
        let mut buf = [0u16; (W * 16) as usize];
        let mut s = Strip::new(64, 16, &mut buf).unwrap();
        let mut f = Frame::new();
        f.push(Item::Chord { cx: 214 << 8, cy: 72 << 8, r: 30 << 8, level_y: 72 << 8, color: Rgb::WHITE, a: 255 });
        render_strip(&f, &Font::empty(), &mut s);
        assert_eq!(s.get(214, 66), 0);
        assert_eq!(s.get(214, 78), 0xFFFF);
    }

    #[test]
    fn marks_and_chevron_draw_something_inside_their_bounds() {
        let mut buf = [0u16; (W * 142) as usize];
        let mut s = Strip::new(0, 142, &mut buf).unwrap();
        let mut f = Frame::new();
        f.push(Item::Check { cx: 214 << 8, cy: 72 << 8, r: 29 << 8, color: Rgb::WHITE, k: 1 << 16 });
        f.push(Item::Cross { cx: 100 << 8, cy: 72 << 8, r: 29 << 8, color: Rgb::WHITE, k: 1 << 16 });
        f.push(Item::Chevron { cx: (235 << 8) / 10, cy: 19 << 8, angle: 1 << 14, color: Rgb::WHITE });
        render_strip(&f, &Font::empty(), &mut s);
        let lit = |x0: i32, y0: i32, x1: i32, y1: i32| (y0..y1).flat_map(|y| (x0..x1).map(move |x| (x, y))).filter(|&(x, y)| s.get(x, y) != 0).count();
        assert!(lit(184, 42, 244, 102) > 50, "check");
        assert!(lit(70, 42, 130, 102) > 50, "cross");
        assert!(lit(14, 10, 34, 30) > 10, "chevron");
        assert_eq!(lit(300, 0, 428, 142), 0, "nothing elsewhere");
    }

    #[test]
    fn frame_capacity_drops_gracefully() {
        let mut f = Frame::new();
        for _ in 0..MAX_ITEMS {
            assert!(f.push(Item::None));
        }
        assert!(!f.push(Item::None));
    }
}
