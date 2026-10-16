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
    /// CoW Swap brand disc (`#65D9FF`), the navy cow head (`#012F7A`,
    /// `colors.COWSWAP_DARK`) and the brand trail (`COWSWAP_GRADIENT`
    /// stops 1–5), far → near.
    pub const COWSWAP_FILL: Self = Self::new(0x65, 0xD9, 0xFF);
    pub const COWSWAP_NAVY: Self = Self::new(0x01, 0x2F, 0x7A);
    pub const COWSWAP_TRAIL: [Self; 5] = [
        Self::new(0x02, 0x1E, 0x34),
        Self::new(0x01, 0x2F, 0x7A),
        Self::new(0x00, 0x5E, 0xB7),
        Self::new(0x00, 0xA1, 0xFF),
        Self::new(0x3F, 0xC4, 0xFF),
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

/// A VERTICAL band of the frame: landscape columns `x0 .. x0 + w`, every row.
///
/// **The band axis is x, and the storage is the panel's wire order.** Both
/// follow from the 90-degree rotation (`nx = 141 - y`, `ny = x`): the panel
/// scans native rows `ny`, i.e. landscape *columns*, so a band of landscape x
/// is a contiguous run of scan rows, and laying it out as
/// `(x - x0) * H + (H - 1 - y)` is exactly the byte order a
/// `set_window(0, x0, H-1, x0+w-1)` stream wants. No transpose.
///
/// It was a horizontal `y0 .. y0 + h` band until #780. That made every band a
/// native COLUMN band spanning all 428 scan rows, so each one re-crossed the
/// beam independently and the blit could never be synchronised to the panel —
/// a TE wait bolted onto it cleans up at most the first band.
pub struct Strip<'a> {
    pub x0: i32,
    pub w: i32,
    pub buf: &'a mut [u16],
}

impl<'a> Strip<'a> {
    /// `buf` must hold `w * H` pixels.
    #[must_use]
    pub fn new(x0: i32, w: i32, buf: &'a mut [u16]) -> Option<Self> {
        if w <= 0 || x0 < 0 || x0 + w > W || buf.len() < (w * H) as usize {
            return None;
        }
        Some(Self { x0, w, buf })
    }

    pub fn clear(&mut self) {
        for p in self.buf[..(self.w * H) as usize].iter_mut() {
            *p = 0;
        }
    }

    /// Does the inclusive landscape-x range `xa ..= xb` touch this band?
    ///
    /// Every rasteriser calls this first. Without it an item outside the band
    /// still walks its whole bounding box computing coverage that `idx` then
    /// discards — nine times per frame, once per band.
    #[inline]
    #[must_use]
    pub fn x_hits(&self, xa: i32, xb: i32) -> bool {
        xb >= self.x0 && xa < self.x0 + self.w
    }

    #[inline]
    fn idx(&self, x: i32, y: i32) -> Option<usize> {
        if x < self.x0 || x >= self.x0 + self.w || y < 0 || y >= H {
            return None;
        }
        Some(((x - self.x0) * H + (H - 1 - y)) as usize)
    }

    /// Composite `color` at coverage `a` over pixel `(x, y)` (clipped).
    #[inline]
    pub fn blend(&mut self, x: i32, y: i32, color: Rgb, a: u8) {
        if let Some(i) = self.idx(x, y) {
            self.buf[i] = blend_over(self.buf[i], color, a);
        }
    }

    /// [`Strip::blend`] without the zero / full-coverage shortcuts: the
    /// same arithmetic and the same store for every `a`, so the time and
    /// the write pattern do not depend on a secret coverage (the seed-word
    /// run). Clipping is on the public coordinates only.
    #[inline(never)]
    pub fn blend_ct(&mut self, x: i32, y: i32, color: Rgb, a: u8) {
        if let Some(i) = self.idx(x, y) {
            let d = Rgb::from565(self.buf[i]);
            let a = i32::from(core::hint::black_box(a));
            let ch = |d: u8, s: u8| -> u8 { (i32::from(d) + ((i32::from(s) - i32::from(d)) * a + 127) / 255) as u8 };
            self.buf[i] = Rgb::new(ch(d.r, color.r), ch(d.g, color.g), ch(d.b, color.b)).to565();
        }
    }

    /// Composite `color` at coverage `a` over the run `x0 ..= x1` of row `y`
    /// (clipped). Same per-pixel result as [`Strip::blend`]; the bounds are
    /// checked once.
    ///
    /// Under the x-band layout a horizontal run STRIDES by `H`, so this is a
    /// per-pixel store rather than the contiguous run it was before #780.
    /// On this part that costs little — the Cortex-M33 has no data cache and
    /// SRAM1 is zero-wait — the only loss is 32-bit store merging. Render
    /// hides under the 24.31 ms wire either way.
    pub fn fill_span(&mut self, x0: i32, x1: i32, y: i32, color: Rgb, a: u8) {
        if y < 0 || y >= H || a == 0 {
            return;
        }
        let xa = x0.max(self.x0);
        let xb = x1.min(self.x0 + self.w - 1);
        if xb < xa {
            return;
        }
        let row = (H - 1 - y) as usize;
        let stride = H as usize;
        let mut i = (xa - self.x0) as usize * stride + row;
        if a == 255 {
            let p = color.to565();
            for _ in xa..=xb {
                self.buf[i] = p;
                i += stride;
            }
        } else {
            for _ in xa..=xb {
                self.buf[i] = blend_over(self.buf[i], color, a);
                i += stride;
            }
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
    /// A SECRET run (a seed word, zero-padded to `font::SECRET_CELLS`)
    /// drawn by the constant-time cell path ([`Font::blit_secret_run`]),
    /// left edge `x`, vertical centre `y`.
    Secret { text: &'a [u8], tier: crate::font::TierId, x: i32, y: i32, color: Rgb },
    /// A procedural shape (the verdict signs, the PIN row marks): a static
    /// outline in Q4 design units placed by `xf`, filled / stroked / ringed
    /// per `mode`, composited at `a`.
    Shape { pts: &'static [(i16, i16)], xf: Xform, mode: ShapeMode, color: Rgb, a: u8 },
    /// An elliptical ring (the explosion's blast, `burst.py`): the band of
    /// width `w` just inside the ellipse with semi-axes `rx`, `ry`, stroked
    /// inward like [`Item::Ring`]. Q8 throughout.
    EllipseRing { cx: Q8, cy: Q8, rx: Q8, ry: Q8, w: Q8, color: Rgb },
    /// The explosion's clump (`burst.py` `clump_poly`): a filled disc of
    /// radius `r` whose edge trembles by three harmonics,
    /// `r · (1 + i · (0.012 sin(3a + p3) + 0.008 sin(5a − p5) + 0.005 sin(7a + p7)))`,
    /// `i` = `intensity` (Q16), the phases in Q16 turns.
    Clump { cx: Q8, cy: Q8, r: Q8, intensity: Q16, phases: [Q16; 3], color: Rgb },
}

/// Where a [`Item::Shape`]'s Q4 outline lands: uniform scale `k` (Q8,
/// 256 = design size), an extra horizontal factor `kx` (Q12, 4096 = 1 —
/// the padlock shackle's foreshortening), a rotation `rot` (Q16 turns,
/// wrapping; y points down, so a positive angle turns clockwise), then the
/// translation `(ox, oy)` (Q8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Xform {
    pub ox: Q8,
    pub oy: Q8,
    pub k: i16,
    pub kx: i16,
    pub rot: u16,
}

impl Xform {
    /// Design size at `(ox, oy)`.
    #[must_use]
    pub const fn at(ox: Q8, oy: Q8) -> Self {
        Self { ox, oy, k: 256, kx: 4096, rot: 0 }
    }

    /// Uniform scale `k` (Q8).
    #[must_use]
    pub const fn scaled(self, k: i16) -> Self {
        Self { k, ..self }
    }

    /// Rotation (Q16 turns).
    #[must_use]
    pub const fn turned(self, rot: u16) -> Self {
        Self { rot, ..self }
    }

    /// Horizontal factor (Q12).
    #[must_use]
    pub const fn squeezed(self, kx: i16) -> Self {
        Self { kx, ..self }
    }

    fn apply(&self, (x, y): (i16, i16)) -> (Q8, Q8) {
        // Q4 · Q8 · Q12 → Q8 is a shift of 4 + 8 + 12 − 8 = 16; Q4 · Q8 → Q8 is 4.
        let px = ((i64::from(x) * i64::from(self.k) * i64::from(self.kx)) >> 16) as Q8;
        let py = ((i64::from(y) * i64::from(self.k)) >> 4) as Q8;
        let (px, py) = if self.rot == 0 { (px, py) } else { rot(px, py, Q16::from(self.rot)) };
        (self.ox + px, self.oy + py)
    }
}

/// How a shape's outline becomes coverage. All widths are Q8 px and never
/// scale with the transform (a stroke keeps its weight as the sign grows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeMode {
    /// The closed polygon (non-zero winding), grown outward by `grow` —
    /// a polygon inset by `grow` then grown back is the rounded-corner
    /// polygon (the Minkowski sum with a disc).
    Fill { grow: i16 },
    /// The open polyline stroked with round caps and joins, half-width `hw`.
    Stroke { hw: i16 },
    /// The closed outline stroked (round joins), half-width `hw`.
    Loop { hw: i16 },
    /// The rim of the outline grown by `r`, stroked at half-width `hw`: for
    /// a single segment the capsule's rim (the PIN pill); for a closed
    /// polygon (≥ 3 points) the edge of the rounded polygon `Fill { grow: r }`
    /// fills (the die faces' black edges).
    Rim { r: i16, hw: i16 },
}

/// Points a shape may have (a larger outline is a build-time error the
/// geometry tests catch; the rasteriser draws nothing rather than clip).
pub const SHAPE_MAX_PTS: usize = 48;

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
    /// Out of line on purpose: inlined, every `push` site in the per-frame
    /// scene builder carried its own capacity check and 36-byte store, ~1 KB
    /// of flash in all (measured 2026-10-14). ~40 calls a frame cost
    /// microseconds against a millisecond render.
    #[inline(never)]
    pub fn push(&mut self, item: Item<'a>) -> bool {
        if self.n >= MAX_ITEMS {
            return false;
        }
        self.items[self.n] = item;
        self.n += 1;
        true
    }

    /// [`Item::Disc`] by its fields: the variant is built here once instead
    /// of at each of the scene's call sites (flash, not speed).
    #[inline(never)]
    pub fn disc(&mut self, cx: Q8, cy: Q8, r: Q8, color: Rgb) -> bool {
        self.push(Item::Disc { cx, cy, r, color })
    }

    /// [`Item::Ring`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn ring(&mut self, cx: Q8, cy: Q8, r: Q8, w: Q8, color: Rgb) -> bool {
        self.push(Item::Ring { cx, cy, r, w, color })
    }

    /// [`Item::Mask`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn mask(&mut self, cx: Q8, cy: Q8, mask: Mask<'a>, scale: Q8, color: Rgb, a: u8) -> bool {
        self.push(Item::Mask { cx, cy, mask, scale, color, a })
    }

    /// [`Item::Text`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn text(&mut self, run: TextRun<'a>, color: Rgb) -> bool {
        self.push(Item::Text { run, color })
    }

    /// [`Item::Chevron`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn chevron(&mut self, cx: Q8, cy: Q8, angle: Q16, color: Rgb) -> bool {
        self.push(Item::Chevron { cx, cy, angle, color })
    }

    /// [`Item::Check`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn check(&mut self, cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16) -> bool {
        self.push(Item::Check { cx, cy, r, color, k })
    }

    /// [`Item::Cross`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn cross(&mut self, cx: Q8, cy: Q8, r: Q8, color: Rgb, k: Q16) -> bool {
        self.push(Item::Cross { cx, cy, r, color, k })
    }

    /// [`Item::Shape`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn shape(&mut self, pts: &'static [(i16, i16)], xf: Xform, mode: ShapeMode, color: Rgb, a: u8) -> bool {
        self.push(Item::Shape { pts, xf, mode, color, a })
    }

    /// [`Item::EllipseRing`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn ellipse_ring(&mut self, cx: Q8, cy: Q8, rx: Q8, ry: Q8, w: Q8, color: Rgb) -> bool {
        self.push(Item::EllipseRing { cx, cy, rx, ry, w, color })
    }

    /// [`Item::Clump`] by its fields (see [`Self::disc`]).
    #[inline(never)]
    pub fn clump(&mut self, cx: Q8, cy: Q8, r: Q8, intensity: Q16, phases: [Q16; 3], color: Rgb) -> bool {
        self.push(Item::Clump { cx, cy, r, intensity, phases, color })
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

/// Where a display-list item's rasterisation time goes, in raw cycles.
///
/// The classes are chosen to answer ONE question: how much of the render could
/// Chrom-ART (DMA2D) actually take? It can fill rectangles and blend 4-bit
/// alpha sources (our glyph atlas is 4-bit), and it has NO geometry engine.
///
/// * `shapes` — discs, rings, chords, chevrons, checks, crosses, procedural
///   outlines. CPU forever; DMA2D cannot draw these.
/// * `glyphs` — text runs and mask blits. The offloadable part.
/// * `secret` — [`Item::Secret`], the constant-time seed-word path. Counted
///   APART from `glyphs` because it must never be offloaded whatever its size:
///   a DMA2D source address would be the glyph of a secret letter, i.e. a
///   secret-dependent access by a bus master, which is exactly what the
///   constant-time cell path exists to prevent.
/// * `fills` — axis-aligned rectangles. Trivially offloadable.
#[cfg(feature = "render-split")]
#[derive(Default, Clone, Copy)]
pub struct RenderSplit {
    pub shapes: u32,
    pub glyphs: u32,
    pub secret: u32,
    pub fills: u32,
    /// Items DISPATCHED to the rasteriser this frame.
    pub items: u32,
    /// Of those, how many survived their band cull and actually drew (#794).
    ///
    /// This is the discriminator the cycle counts cannot provide: if `items`
    /// and `drawn` are FLAT while `shapes`/`glyphs` grow, the same work is
    /// taking longer — bus contention or fetch cost — and the animation is
    /// out of scope. If they grow, there is work being submitted that
    /// inspection of the motion code did not find.
    pub drawn: u32,
}

/// [`render_strip`], accumulating per-class cycle counts into `acc`.
///
/// `now` is the caller's cycle source (the secure world passes its DWT reader);
/// this crate stays free of any debug-block knowledge. Bench only.
#[cfg(feature = "render-split")]
pub fn render_strip_split(
    frame: &Frame<'_>,
    font: &Font<'_>,
    strip: &mut Strip<'_>,
    now: fn() -> u32,
    acc: &mut RenderSplit,
) {
    strip.clear();
    let drawn_before = work_count();
    for item in frame.items() {
        if !matches!(*item, Item::None) {
            acc.items = acc.items.wrapping_add(1);
        }
        let t0 = now();
        draw_item(item, font, strip);
        let dt = now().wrapping_sub(t0);
        let slot = match *item {
            Item::Text { .. } | Item::Mask { .. } => &mut acc.glyphs,
            Item::Secret { .. } => &mut acc.secret,
            Item::Rect { .. } => &mut acc.fills,
            Item::None => continue,
            _ => &mut acc.shapes,
        };
        *slot = slot.wrapping_add(dt);
    }
    acc.drawn = acc.drawn.wrapping_add(work_count().wrapping_sub(drawn_before));
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
        Item::Shape { pts, xf, mode, color, a } => shape(s, pts, xf, mode, color, a),
        Item::EllipseRing { cx, cy, rx, ry, w, color } => ellipse_ring(s, cx, cy, rx, ry, w, color),
        Item::Clump { cx, cy, r, intensity, phases, color } => clump(s, cx, cy, r, intensity, phases, color),
        Item::Secret { text, tier, x, y, color } => font.blit_secret_run(tier, text, x, y, color, s),
        Item::Rect { x, y, w, h, color, a } => {
            if !s.x_hits(x, x + w - 1) {
                return;
            }
            note_work();
            for yy in y.max(0)..(y + h).min(H) {
                for xx in x.max(s.x0)..(x + w).min(s.x0 + s.w) {
                    s.blend(xx, yy, color, a);
                }
            }
        }
    }
}

/// Counts rasteriser invocations that got PAST their band cull.
///
/// A missing x cull is invisible to the goldens — output is identical either
/// way, it is only 9x slower — and that is exactly how `x_hits` came to be
/// defined, documented as "every rasteriser calls this first", and called by
/// nothing. `cull_rejects_items_outside_the_band` reads this.
/// Also compiled under `render-split` (#794), where the question is whether a
/// render that got 50% slower over two minutes is doing MORE work or the SAME
/// work more slowly. Cycle counts alone cannot tell those apart; a count of
/// the items that survived the band cull can.
#[cfg(any(test, feature = "render-split"))]
pub(crate) static WORK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// Rust runs rendering tests concurrently. A cull test must measure only its
// own render calls, while the production profiler retains the global count.
#[cfg(test)]
std::thread_local! {
    static TEST_WORK: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "render-split"))]
#[inline]
fn note_work() {
    WORK.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    TEST_WORK.with(|count| count.set(count.get().wrapping_add(1)));
}

#[cfg(not(any(test, feature = "render-split")))]
#[inline(always)]
fn note_work() {}

/// Items that have survived a band cull since boot (saturating view).
#[cfg(feature = "render-split")]
#[must_use]
pub fn work_count() -> u32 {
    WORK.load(core::sync::atomic::Ordering::Relaxed) as u32
}

/// Coverage of a pixel at signed distance `d` (Q8) from an edge, where the
/// inside is `d ≤ 0`: 1 − clamp(d + ½).
#[inline]
fn edge_cov(d: Q8) -> u8 {
    let v = ONE_Q8 / 2 - d; // (0.5 − d) in Q8
    (v.clamp(0, ONE_Q8) * 255 / ONE_Q8) as u8
}

/// Coverage thresholds of [`edge_cov`], in Q8 signed distance: a pixel is
/// fully covered at `d ≤ −FULL_D` and untouched at `d ≥ ZERO_D`.
const FULL_D: Q8 = ONE_Q8 / 2;
const ZERO_D: Q8 = ONE_Q8 / 2 - 1;

/// Pixel centres `x` (inclusive range) whose Q8 offset `256·x + c` satisfies
/// `|offset| ≤ bound`; empty when `bound < 0`.
#[inline]
fn centres_within(c: Q8, bound: Q8) -> (i32, i32) {
    if bound < 0 {
        return (1, 0);
    }
    // ceil((−bound − c) / 256) ..= floor((bound − c) / 256); `>> 8` floors.
    (-((bound + c) >> 8), (bound - c) >> 8)
}

/// Largest `|offset|` with `offset² < limit`, or `None` when `limit ≤ 0`.
#[inline]
fn half_width(limit: i64) -> Option<Q8> {
    if limit <= 0 {
        return None;
    }
    Some(isqrt_u64((limit - 1) as u64) as Q8)
}

/// Filled disc; `min_y` limits the fill to rows `≥ min_y` when given (chord).
///
/// Per row the interior (`dist ≤ r − ½ px`, always coverage 255) is one span
/// fill and the outside (`dist ≥ r + ½ px`, always 0) is skipped; only the
/// ≈ 1 px anti-aliased rim evaluates the exact distance. Pixel-for-pixel the
/// same output as evaluating [`edge_cov`] everywhere, ~15× fewer square roots.
fn disc(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, color: Rgb, min_y: Option<(Q8, u8)>) {
    // Band cull FIRST: the row loop below runs an isqrt (`half_width`) per
    // row, and a band spans every row, so a disc outside this band would cost
    // 142 isqrts for nothing -- nine times per frame.
    if !s.x_hits(((cx - r) >> 8) - 1, ((cx + r) >> 8) + 1) {
        return;
    }
    note_work();
    let (level, a) = min_y.unwrap_or((i32::MIN / 2, 255));
    let y_lo = ((cy - r) >> 8) - 1;
    let y_hi = ((cy + r) >> 8) + 1;
    let c = ONE_Q8 / 2 - cx; // offset of pixel centre x = 0
    let r_zero = i64::from(r + ZERO_D); // dist ≥ r + ZERO_D ⇒ cov 0
    let r_full = i64::from(r - FULL_D + 1); // dist ≤ r − FULL_D ⇔ dist² < r_full²
    for y in y_lo.max(0)..=y_hi.min(H - 1) {
        let py = (y << 8) + ONE_Q8 / 2; // pixel centre
        if py < level {
            continue;
        }
        let dy = py - cy;
        let dy2 = i64::from(dy) * i64::from(dy);
        // Non-zero coverage ⇔ dist < r + ZERO_D ⇔ dx² < r_zero² − dy².
        let Some(hz) = half_width(r_zero * r_zero - dy2) else { continue };
        let (xa, xb) = centres_within(c, hz);
        let (xa, xb) = (xa.max(0), xb.min(W - 1));
        if xb < xa {
            continue;
        }
        // Full coverage ⇔ dist ≤ r − FULL_D ⇔ dx² < r_full² − dy² (r_full > 0).
        let (fa, fb) = if r_full > 0 {
            match half_width(r_full * r_full - dy2) {
                Some(hf) => centres_within(c, hf),
                None => (1, 0),
            }
        } else {
            (1, 0)
        };
        let (fa, fb) = (fa.max(xa), fb.min(xb));
        let rim = |s: &mut Strip<'_>, x0: i32, x1: i32| {
            for x in x0..=x1 {
                let px = (x << 8) + ONE_Q8 / 2;
                let d = dist_q8(px - cx, dy) - r;
                let cov = edge_cov(d);
                if cov != 0 {
                    let aa = ((u16::from(cov) * u16::from(a) + 127) / 255) as u8;
                    s.blend(x, y, color, aa);
                }
            }
        };
        if fb < fa {
            rim(s, xa, xb);
        } else {
            rim(s, xa, fa - 1);
            s.fill_span(fa, fb, y, color, a);
            rim(s, fb + 1, xb);
        }
    }
}

fn chord(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, level_y: Q8, color: Rgb, a: u8) {
    disc(s, cx, cy, r, color, Some((level_y, a)));
}

/// Ring (annulus `r − w ..= r`). Only the band that can carry coverage —
/// `r_in − ½ px < dist < r + ½ px` — evaluates the exact distance; the hole
/// and the outside are skipped by row span. Output identical to evaluating
/// every pixel of the bounding box.
fn ring(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, w: Q8, color: Rgb) {
    if !s.x_hits(((cx - r) >> 8) - 1, ((cx + r) >> 8) + 1) {
        return;
    }
    note_work();
    let r_in = r - w;
    let y_lo = ((cy - r) >> 8) - 1;
    let y_hi = ((cy + r) >> 8) + 1;
    let c = ONE_Q8 / 2 - cx;
    let r_zero = i64::from(r + ZERO_D); // dist ≥ r + ZERO_D ⇒ 0 (outside)
    let r_hole = i64::from(r_in - ZERO_D + 1); // dist ≤ r_in − ZERO_D ⇔ dist² < r_hole² ⇒ 0 (hole)
    for y in y_lo.max(0)..=y_hi.min(H - 1) {
        let dy = (y << 8) + ONE_Q8 / 2 - cy;
        if dy.abs() > r + ONE_Q8 {
            continue;
        }
        let dy2 = i64::from(dy) * i64::from(dy);
        let Some(hz) = half_width(r_zero * r_zero - dy2) else { continue };
        let (xa, xb) = centres_within(c, hz);
        let (xa, xb) = (xa.max(0), xb.min(W - 1));
        if xb < xa {
            continue;
        }
        let (ha, hb) = if r_hole > 0 {
            match half_width(r_hole * r_hole - dy2) {
                Some(hh) => centres_within(c, hh),
                None => (1, 0),
            }
        } else {
            (1, 0)
        };
        let (ha, hb) = (ha.max(xa), hb.min(xb));
        let band = |s: &mut Strip<'_>, x0: i32, x1: i32| {
            for x in x0..=x1 {
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
        };
        if hb < ha {
            band(s, xa, xb);
        } else {
            band(s, xa, ha - 1);
            band(s, hb + 1, xb);
        }
    }
}

/// Elliptical ring: the band of width `w` inside the ellipse `rx` × `ry`.
///
/// Per row only the stroke band is evaluated: columns between the outer
/// ellipse grown by a pixel and the hole (the ellipse shrunk by `w` + 2 px,
/// which the stroke's inner edge never reaches) — the rest of a blast ring's
/// huge bounding box is skipped. Signed distance to the ellipse is the
/// first-order estimate `F / |∇F|` taken in the space where the ellipse is a
/// circle of radius `rx`: `S = |(x, y·rx/ry)|`, `T = |(x, y·(rx/ry)²)|`,
/// `d ≈ (S − rx) · S / T` (exact on both axes). The stroke's inner edge is
/// the curve `w` inside, so a stroke keeps its width all round.
fn ellipse_ring(s: &mut Strip<'_>, cx: Q8, cy: Q8, rx: Q8, ry: Q8, w: Q8, color: Rgb) {
    if rx <= 0 || ry <= 0 || !s.x_hits(((cx - rx) >> 8) - 2, ((cx + rx) >> 8) + 2) {
        return;
    }
    note_work();
    let (ox, oy) = (rx + ONE_Q8, ry + ONE_Q8);
    let (hx, hy) = (rx - w - 2 * ONE_Q8, ry - w - 2 * ONE_Q8);
    let c = ONE_Q8 / 2 - cx;
    let (rx64, ry64) = (i64::from(rx), i64::from(ry));
    let y_lo = ((cy - oy) >> 8) - 1;
    let y_hi = ((cy + oy) >> 8) + 1;
    for y in y_lo.max(0)..=y_hi.min(H - 1) {
        let dy = (y << 8) + ONE_Q8 / 2 - cy;
        if dy.abs() >= oy {
            continue;
        }
        let dy64 = i64::from(dy);
        // Half-width of an ellipse a × b at this row: a·√(b² − dy²) / b.
        let half = |a: Q8, b: Q8| -> Q8 {
            let b64 = i64::from(b);
            ((i64::from(a) * i64::from(isqrt_u64((b64 * b64 - dy64 * dy64) as u64))) / b64) as Q8
        };
        let (xa, xb) = centres_within(c, half(ox, oy));
        let (xa, xb) = (xa.max(s.x0), xb.min(s.x0 + s.w - 1));
        if xb < xa {
            continue;
        }
        let (ha, hb) = if hx > 0 && hy > 0 && dy.abs() < hy { centres_within(c, half(hx, hy)) } else { (1, 0) };
        let (ha, hb) = (ha.max(xa), hb.min(xb));
        let (ky, k2y) = ellipse_row(dy64, rx64, ry64);
        let band = |s: &mut Strip<'_>, x0: i32, x1: i32| {
            for x in x0..=x1 {
                let cov = ellipse_ring_cov(i64::from((x << 8) + ONE_Q8 / 2 - cx), ky, k2y, rx64, w);
                if cov != 0 {
                    s.blend(x, y, color, cov);
                }
            }
        };
        if hb < ha {
            band(s, xa, xb);
        } else {
            band(s, xa, ha - 1);
            band(s, hb + 1, xb);
        }
    }
}

/// A row's scaled offsets for [`ellipse_ring_cov`]: `dy·rx/ry`, `dy·(rx/ry)²`.
#[inline]
fn ellipse_row(dy: i64, rx: i64, ry: i64) -> (i64, i64) {
    (dy * rx / ry, dy * rx * rx / (ry * ry))
}

/// Coverage of the ring band at column offset `dx` on a row whose
/// [`ellipse_row`] offsets are `ky`, `k2y` (see [`ellipse_ring`]).
#[inline]
fn ellipse_ring_cov(dx: i64, ky: i64, k2y: i64, rx: i64, w: Q8) -> u8 {
    let sq = isqrt_u64((dx * dx + ky * ky) as u64) as i64;
    let t = isqrt_u64((dx * dx + k2y * k2y) as u64) as i64;
    if t == 0 {
        return 0;
    }
    let d = ((sq - rx) * sq / t) as Q8;
    edge_cov(d.max(-d - w))
}

/// The clump's three harmonics for [`clump_cov`]: (weight·intensity, cos φ,
/// ±sin φ) for n = 3, 5, 7 (the 5th turns the other way, `sin(5a − φ5)`).
fn clump_harmonics(intensity: Q16, phases: [Q16; 3]) -> [(Q16, Q16, Q16); 3] {
    use crate::fixed::{cos_turns_q16, mul_q16, sin_turns_q16};
    let k = |w: Q16| mul_q16(intensity, w);
    [
        (k(786), cos_turns_q16(phases[0]), sin_turns_q16(phases[0])),
        (k(524), cos_turns_q16(phases[1]), -sin_turns_q16(phases[1])),
        (k(328), cos_turns_q16(phases[2]), sin_turns_q16(phases[2])),
    ]
}

/// Coverage of the clump at offset `(dx, dy)` from its centre.
#[inline]
fn clump_cov(dx: Q8, dy: Q8, r: Q8, h: &[(Q16, Q16, Q16); 3]) -> u8 {
    use crate::fixed::mul_q16;
    let d = dist_q8(dx, dy);
    if d == 0 {
        return 255;
    }
    // z = (cos a, sin a) in Q16; z³, z⁵, z⁷ by complex products.
    let z = (((i64::from(dx) << 16) / i64::from(d)) as Q16, ((i64::from(dy) << 16) / i64::from(d)) as Q16);
    let mul = |a: (Q16, Q16), b: (Q16, Q16)| -> (Q16, Q16) {
        (mul_q16(a.0, b.0) - mul_q16(a.1, b.1), mul_q16(a.0, b.1) + mul_q16(a.1, b.0))
    };
    let z2 = mul(z, z);
    let z3 = mul(z2, z);
    let z5 = mul(z3, z2);
    let z7 = mul(z5, z2);
    let mut wv: Q16 = 0;
    for (zn, &(wt, cp, sp)) in [z3, z5, z7].into_iter().zip(h) {
        // sin(n a ± φ) = Im(zⁿ)·cos φ ± Re(zⁿ)·sin φ (the sign folded into sp).
        wv += mul_q16(wt, mul_q16(zn.1, cp) + mul_q16(zn.0, sp));
    }
    let edge = r + ((i64::from(r) * i64::from(wv)) >> 16) as Q8;
    edge_cov(d - edge)
}

/// The explosion's clump: a disc whose edge trembles by three harmonics.
///
/// The edge stays within `r · (1 ± 0.025 · intensity)`, so the interior below
/// that is one span fill and the outside above it is skipped; only the rim
/// evaluates the angle. `cos a`, `sin a` come from the pixel's offset over its
/// distance, and `sin(n·a + φ)` from the complex power `(cos a + i sin a)^n`,
/// so no inverse trigonometry runs per pixel.
fn clump(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, intensity: Q16, phases: [Q16; 3], color: Rgb) {
    use crate::fixed::mul_q16;
    // 0.012 + 0.008 + 0.005 = 0.025 (Q16 1638.4, rounded up).
    let amp = ((i64::from(r) * i64::from(mul_q16(intensity, 1_639))) >> 16) as Q8 + 1;
    let (r_max, r_min) = (r + amp, r - amp);
    if !s.x_hits(((cx - r_max) >> 8) - 1, ((cx + r_max) >> 8) + 1) {
        return;
    }
    note_work();
    let h = clump_harmonics(intensity, phases);
    let c = ONE_Q8 / 2 - cx;
    let r_zero = i64::from(r_max + ZERO_D);
    let r_full = i64::from(r_min - FULL_D + 1);
    let y_lo = ((cy - r_max) >> 8) - 1;
    let y_hi = ((cy + r_max) >> 8) + 1;
    for y in y_lo.max(0)..=y_hi.min(H - 1) {
        let dy = (y << 8) + ONE_Q8 / 2 - cy;
        let dy2 = i64::from(dy) * i64::from(dy);
        let Some(hz) = half_width(r_zero * r_zero - dy2) else { continue };
        let (xa, xb) = centres_within(c, hz);
        let (xa, xb) = (xa.max(s.x0), xb.min(s.x0 + s.w - 1));
        if xb < xa {
            continue;
        }
        let (fa, fb) = if r_full > 0 {
            match half_width(r_full * r_full - dy2) {
                Some(hf) => centres_within(c, hf),
                None => (1, 0),
            }
        } else {
            (1, 0)
        };
        let (fa, fb) = (fa.max(xa), fb.min(xb));
        let rim = |s: &mut Strip<'_>, x0: i32, x1: i32| {
            for x in x0..=x1 {
                let cov = clump_cov((x << 8) + ONE_Q8 / 2 - cx, dy, r, &h);
                if cov != 0 {
                    s.blend(x, y, color, cov);
                }
            }
        };
        if fb < fa {
            rim(s, xa, xb);
        } else {
            rim(s, xa, fa - 1);
            s.fill_span(fa, fb, y, color, 255);
            rim(s, fb + 1, xb);
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
    if !s.x_hits((x_lo - pad) >> 8, ((x_hi + pad) >> 8) + 1) {
        return;
    }
    note_work();
    // Clip x to the BAND, not the frame: this inner loop pays a 64-bit
    // division per pixel per segment in `seg_dist`, so iterating columns the
    // band cannot hold is the most expensive possible way to do nothing.
    let xa = ((x_lo - pad) >> 8).max(s.x0);
    let xb = ((x_hi + pad) >> 8).min(s.x0 + s.w - 1);
    for y in ((y_lo - pad) >> 8).max(0)..=((y_hi + pad) >> 8).min(H - 1) {
        let py = (y << 8) + ONE_Q8 / 2;
        for x in xa..=xb {
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
    // CLOSED loop: bl -> apex -> br -> bl. `components.chevron` is a FILLED
    // triangle outlined with a 4.5 px round-joint stroke, so all three
    // corners are round — not two arms. Stroking the open polyline left the
    // base edge missing and the interior hollow, which is why every screen
    // drew `<` where the reference draws a solid rounded triangle. The
    // triangle is 8.4 x 7.2 px against a 2.25 px stroke half-width, so the
    // closed loop covers the interior; `chevron_is_solid` pins that.
    let pts = [p(bl), p(apex), p(br), p(bl)];
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

/// One edge of a transformed outline, with the reciprocal of its squared
/// length precomputed so the per-pixel projection needs no division.
#[derive(Clone, Copy, Default)]
struct Edge {
    ax: i32,
    ay: i32,
    bx: i32,
    by: i32,
    /// `2⁴⁰ / |ab|²` (0 for a degenerate edge).
    inv: i64,
}

impl Edge {
    fn new((ax, ay): (Q8, Q8), (bx, by): (Q8, Q8)) -> Self {
        let dx = i64::from(bx - ax);
        let dy = i64::from(by - ay);
        let ab2 = dx * dx + dy * dy;
        Self { ax, ay, bx, by, inv: if ab2 == 0 { 0 } else { (1i64 << 40) / ab2 } }
    }

    /// Squared distance (Q16) from `(px, py)` to the segment.
    #[inline]
    fn dist2(&self, px: Q8, py: Q8) -> i64 {
        let abx = i64::from(self.bx - self.ax);
        let aby = i64::from(self.by - self.ay);
        let apx = i64::from(px - self.ax);
        let apy = i64::from(py - self.ay);
        let dot = apx * abx + apy * aby;
        let t = ((dot * self.inv) >> 24).clamp(0, 1 << 16); // Q16 in [0, 1]
        let qx = apx - ((abx * t) >> 16);
        let qy = apy - ((aby * t) >> 16);
        qx * qx + qy * qy
    }

    /// True when `(px, py)` lies outside the edge's bounding box grown by
    /// `far` on every side, i.e. the segment is farther than `far` away.
    #[inline]
    fn misses(&self, px: Q8, py: Q8, far: Q8) -> bool {
        px < self.ax.min(self.bx) - far
            || px > self.ax.max(self.bx) + far
            || py < self.ay.min(self.by) - far
            || py > self.ay.max(self.by) + far
    }

    /// Winding contribution of the edge for a rightward ray from `(px, py)`.
    #[inline]
    fn winding(&self, px: Q8, py: Q8) -> i32 {
        let cross = i64::from(self.bx - self.ax) * i64::from(py - self.ay) - i64::from(px - self.ax) * i64::from(self.by - self.ay);
        if self.ay <= py {
            i32::from(self.by > py && cross > 0)
        } else {
            -i32::from(self.by <= py && cross < 0)
        }
    }
}

/// Rasterise an [`Item::Shape`] into the strip. Kept out of line so the
/// edge table only occupies stack while a shape is actually drawn (the
/// signing film never draws one).
#[inline(never)]
fn shape(s: &mut Strip<'_>, pts: &[(i16, i16)], xf: Xform, mode: ShapeMode, color: Rgb, a: u8) {
    let n = pts.len();
    if !(2..=SHAPE_MAX_PTS).contains(&n) || a == 0 {
        return;
    }
    let closed = matches!(mode, ShapeMode::Fill { .. } | ShapeMode::Loop { .. }) || (matches!(mode, ShapeMode::Rim { .. }) && n >= 3);
    let signed = closed && !matches!(mode, ShapeMode::Loop { .. });
    let mut edges = [Edge::default(); SHAPE_MAX_PTS];
    let (mut x_lo, mut x_hi, mut y_lo, mut y_hi) = (i32::MAX, i32::MIN, i32::MAX, i32::MIN);
    let mut prev = xf.apply(pts[0]);
    let first = prev;
    let mut ne = 0usize;
    for (i, &p) in pts.iter().enumerate() {
        let q = if i == 0 { first } else { xf.apply(p) };
        x_lo = x_lo.min(q.0);
        x_hi = x_hi.max(q.0);
        y_lo = y_lo.min(q.1);
        y_hi = y_hi.max(q.1);
        if i > 0 {
            edges[ne] = Edge::new(prev, q);
            ne += 1;
        }
        prev = q;
    }
    if closed && prev != first {
        edges[ne] = Edge::new(prev, first);
        ne += 1;
    }
    let edges = &edges[..ne];
    let reach = Q8::from(match mode {
        ShapeMode::Fill { grow } => grow,
        ShapeMode::Stroke { hw } | ShapeMode::Loop { hw } => hw,
        ShapeMode::Rim { r, hw } => r.saturating_add(hw),
    }) + ONE_Q8;
    let ya = ((y_lo - reach) >> 8).max(0);
    let yb = ((y_hi + reach) >> 8).min(H - 1);
    let xa = ((x_lo - reach) >> 8).max(s.x0);
    let xb = ((x_hi + reach) >> 8).min(s.x0 + s.w - 1);
    if xb < xa {
        return;
    }
    // NEAR-EDGE CULL (2026-10-15, owner: verdict shields "super laggy").
    // The exact distance to the outline is only needed where it decides the
    // coverage. Past `far` (Q8) from every edge the signed distance below is
    // saturated whatever its exact value: `edge_cov` is 0 for sd >= 127 and
    // full for sd <= -128, and `far` is mode's offset + 256 so both hold. So:
    //   * an edge whose bounding box, grown by `far`, misses the pixel is
    //     farther than `far` and cannot be the nearest edge of a pixel whose
    //     coverage depends on the distance — its `dist2` is skipped;
    //   * when every edge is skipped the pixel is far from the outline, and
    //     its coverage is the saturated value: full inside a filled shape,
    //     nothing otherwise — no `isqrt`.
    // The winding still runs over EVERY edge, so inside/outside is exact.
    // Pixel-identical to the plain loop (`shape_reference` in the tests runs
    // it against this one); the shield used to take every-edge `dist2` +
    // `isqrt` for every pixel of its box.
    let far: Q8 = 256
        + match mode {
            ShapeMode::Fill { grow } => Q8::from(grow).abs(),
            ShapeMode::Stroke { hw } | ShapeMode::Loop { hw } => Q8::from(hw).abs(),
            ShapeMode::Rim { r, hw } => Q8::from(r).abs() + Q8::from(hw).abs(),
        };
    note_work();
    for y in ya..=yb {
        let py = (y << 8) + ONE_Q8 / 2;
        for x in xa..=xb {
            let px = (x << 8) + ONE_Q8 / 2;
            let mut d2 = i64::MAX;
            let mut near = false;
            let mut wind = 0i32;
            for e in edges {
                if signed {
                    wind += e.winding(px, py);
                }
                if e.misses(px, py, far) {
                    continue;
                }
                near = true;
                d2 = d2.min(e.dist2(px, py));
            }
            let cov = if near {
                let d = isqrt_u64(d2 as u64) as Q8;
                let d_signed = if wind != 0 { -d } else { d };
                let sd = match mode {
                    ShapeMode::Fill { grow } => d_signed - Q8::from(grow),
                    ShapeMode::Stroke { hw } | ShapeMode::Loop { hw } => d - Q8::from(hw),
                    ShapeMode::Rim { r, hw } => (d_signed - Q8::from(r)).abs() - Q8::from(hw),
                };
                edge_cov(sd)
            } else if matches!(mode, ShapeMode::Fill { .. }) && wind != 0 {
                255
            } else {
                0
            };
            if cov != 0 {
                let aa = ((u16::from(cov) * u16::from(a) + 127) / 255) as u8;
                s.blend(x, y, color, aa);
            }
        }
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
    if !s.x_hits(x0, x0 + dw - 1) {
        return;
    }
    note_work();
    let xa = x0.max(s.x0);
    let xb = (x0 + dw).min(s.x0 + s.w);
    for y in y0.max(0)..(y0 + dh).min(H) {
        let sy = (((y - y0) << 8) / scale.max(1)) as u16;
        for x in xa..xb {
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

    /// The shape loop as it was before the near-edge cull (2026-10-15):
    /// every edge's distance and an `isqrt` for every pixel of the box. The
    /// reference the cull must match pixel for pixel.
    fn shape_reference(s: &mut Strip<'_>, pts: &[(i16, i16)], xf: Xform, mode: ShapeMode, color: Rgb, a: u8) {
        let n = pts.len();
        if !(2..=SHAPE_MAX_PTS).contains(&n) || a == 0 {
            return;
        }
        let closed =
            matches!(mode, ShapeMode::Fill { .. } | ShapeMode::Loop { .. }) || (matches!(mode, ShapeMode::Rim { .. }) && n >= 3);
        let signed = closed && !matches!(mode, ShapeMode::Loop { .. });
        let mut edges = [Edge::default(); SHAPE_MAX_PTS];
        let (mut x_lo, mut x_hi, mut y_lo, mut y_hi) = (i32::MAX, i32::MIN, i32::MAX, i32::MIN);
        let mut prev = xf.apply(pts[0]);
        let first = prev;
        let mut ne = 0usize;
        for (i, &p) in pts.iter().enumerate() {
            let q = if i == 0 { first } else { xf.apply(p) };
            x_lo = x_lo.min(q.0);
            x_hi = x_hi.max(q.0);
            y_lo = y_lo.min(q.1);
            y_hi = y_hi.max(q.1);
            if i > 0 {
                edges[ne] = Edge::new(prev, q);
                ne += 1;
            }
            prev = q;
        }
        if closed && prev != first {
            edges[ne] = Edge::new(prev, first);
            ne += 1;
        }
        let edges = &edges[..ne];
        let reach = Q8::from(match mode {
            ShapeMode::Fill { grow } => grow,
            ShapeMode::Stroke { hw } | ShapeMode::Loop { hw } => hw,
            ShapeMode::Rim { r, hw } => r.saturating_add(hw),
        }) + ONE_Q8;
        let ya = ((y_lo - reach) >> 8).max(0);
        let yb = ((y_hi + reach) >> 8).min(H - 1);
        let xa = ((x_lo - reach) >> 8).max(s.x0);
        let xb = ((x_hi + reach) >> 8).min(s.x0 + s.w - 1);
        if xb < xa {
            return;
        }
        for y in ya..=yb {
            let py = (y << 8) + ONE_Q8 / 2;
            for x in xa..=xb {
                let px = (x << 8) + ONE_Q8 / 2;
                let mut d2 = i64::MAX;
                let mut wind = 0i32;
                for e in edges {
                    d2 = d2.min(e.dist2(px, py));
                    if signed {
                        wind += e.winding(px, py);
                    }
                }
                let d = isqrt_u64(d2 as u64) as Q8;
                let d_signed = if wind != 0 { -d } else { d };
                let sd = match mode {
                    ShapeMode::Fill { grow } => d_signed - Q8::from(grow),
                    ShapeMode::Stroke { hw } | ShapeMode::Loop { hw } => d - Q8::from(hw),
                    ShapeMode::Rim { r, hw } => (d_signed - Q8::from(r)).abs() - Q8::from(hw),
                };
                let cov = edge_cov(sd);
                if cov != 0 {
                    let aa = ((u16::from(cov) * u16::from(a) + 127) / 255) as u8;
                    s.blend(x, y, color, aa);
                }
            }
        }
    }

    /// The near-edge cull is pixel-identical to the plain loop: every baked
    /// verdict outline, in every mode, at several sizes, turns and offsets,
    /// rendered into a full-width strip and into 48-px bands.
    /// The two burst primitives' row culls (band, hole, interior span) are
    /// exact: the same pixels as evaluating their coverage everywhere.
    #[test]
    fn burst_primitive_culls_match_the_reference_pixel_for_pixel() {
        let mut cases = 0;
        for band in [W, 48] {
            let mut x0 = 0;
            while x0 < W {
                let w = band.min(W - x0);
                let cx = 214 << 8;
                let cy = 72 << 8;
                for (rx, sw) in [(10 << 8, 666), (40 << 8, 576), (150 << 8, 486), (230 << 8, 397), (310 << 8, 307)] {
                    let ry = (i64::from(rx) * 47_186 >> 16) as Q8;
                    let mut got = std::vec![0u16; (w * H) as usize];
                    let mut want = got.clone();
                    ellipse_ring(&mut Strip::new(x0, w, &mut got).unwrap(), cx, cy, rx, ry, sw, Rgb::WHITE);
                    let mut st = Strip::new(x0, w, &mut want).unwrap();
                    for y in 0..H {
                        let (ky, k2y) = ellipse_row(i64::from((y << 8) + 128 - cy), i64::from(rx), i64::from(ry));
                        for x in x0..x0 + w {
                            let cov = ellipse_ring_cov(i64::from((x << 8) + 128 - cx), ky, k2y, i64::from(rx), sw);
                            if cov != 0 {
                                st.blend(x, y, Rgb::WHITE, cov);
                            }
                        }
                    }
                    assert!(got == want, "ellipse ring cull differs: rx {} band {x0}+{w}", rx >> 8);
                    cases += 1;
                }
                for (r, i, ph) in [(22 << 8, 39_322, [0, 0, 0]), (18 << 8, 120_000, [9_000, 40_000, 63_000]), ((143 << 8) / 10, 196_608, [30_000, 1_000, 50_000])] {
                    let (ccx, ccy) = (cx + 700, cy - 900);
                    let mut got = std::vec![0u16; (w * H) as usize];
                    let mut want = got.clone();
                    clump(&mut Strip::new(x0, w, &mut got).unwrap(), ccx, ccy, r, i, ph, Rgb::WHITE);
                    let h = clump_harmonics(i, ph);
                    let mut st = Strip::new(x0, w, &mut want).unwrap();
                    for y in 0..H {
                        for x in x0..x0 + w {
                            let cov = clump_cov((x << 8) + 128 - ccx, (y << 8) + 128 - ccy, r, &h);
                            if cov != 0 {
                                st.blend(x, y, Rgb::WHITE, cov);
                            }
                        }
                    }
                    assert!(got == want, "clump cull differs: r {} band {x0}+{w}", r >> 8);
                    cases += 1;
                }
                x0 += w;
            }
        }
        assert!(cases > 60);
    }

    /// The ring lands where the ellipse is: lit on its rim at both axes, dark
    /// in the hole and outside; the clump is solid inside and trembles only
    /// within its 2.5 %·intensity bound.
    #[test]
    fn burst_primitives_land_on_their_geometry() {
        let mut buf = std::vec![0u16; (W * H) as usize];
        let mut st = Strip::new(0, W, &mut buf).unwrap();
        let (cx, cy, rx, ry, sw) = (214 << 8, 72 << 8, 100 << 8, 72 << 8, 666);
        ellipse_ring(&mut st, cx, cy, rx, ry, sw, Rgb::WHITE);
        let px = |st: &Strip<'_>, x: i32, y: i32| st.buf[((x - st.x0) * H + (H - 1 - y)) as usize];
        assert_ne!(px(&st, 214 + 99, 72), 0, "rim on the x axis");
        assert_ne!(px(&st, 214 - 99, 72), 0);
        assert_ne!(px(&st, 214, 72 - 71), 0, "rim on the y axis");
        assert_eq!(px(&st, 214, 72), 0, "the hole");
        assert_eq!(px(&st, 214 + 95, 72), 0, "inside the stroke's inner edge");
        assert_eq!(px(&st, 214 + 102, 72), 0, "outside");
        let mut buf = std::vec![0u16; (W * H) as usize];
        let mut st = Strip::new(0, W, &mut buf).unwrap();
        clump(&mut st, cx, cy, 20 << 8, 196_608, [1_000, 2_000, 3_000], Rgb::WHITE);
        assert_eq!(px(&st, 214, 72), Rgb::WHITE.to565(), "solid inside");
        assert_eq!(px(&st, 214 + 18, 72), Rgb::WHITE.to565());
        assert_eq!(px(&st, 214 + 23, 72), 0, "never past r·(1 + 0.025·3) + ½");
    }

    #[test]
    fn shape_cull_matches_the_reference_pixel_for_pixel() {
        use crate::verdict_geom as g;
        let outlines: [&[(i16, i16)]; 9] = [
            &g::SHIELD, &g::HEART, &g::BRUSH_BODY, &g::BRUSH_BRISTLES, &g::SHACKLE_ARCH, &g::TRIANGLE, &g::PILL,
            &g::GEAR_TOOTH, &g::DIE_PIP_4,
        ];
        let modes = [
            ShapeMode::Fill { grow: 0 },
            ShapeMode::Fill { grow: 300 },
            ShapeMode::Stroke { hw: 200 },
            ShapeMode::Loop { hw: 384 },
            ShapeMode::Loop { hw: 0 },
            ShapeMode::Rim { r: 900, hw: 330 },
            ShapeMode::Rim { r: 0, hw: 150 },
        ];
        let mut cases = 0;
        for pts in outlines {
            for mode in modes {
                for (k, rot, ox, oy) in [(256i16, 0u16, 214, 70), (180, 4000, 120, 60), (330, 30000, 300, 80), (90, 60000, 10, 140)] {
                    let xf = Xform::at(ox << 8, oy << 8).scaled(k).turned(rot);
                    for band in [W, 48] {
                        let mut x0 = 0;
                        while x0 < W {
                            let w = band.min(W - x0);
                            let mut got = std::vec![0u16; (w * H) as usize];
                            let mut want = got.clone();
                            shape(&mut Strip::new(x0, w, &mut got).unwrap(), pts, xf, mode, Rgb::WHITE, 255);
                            shape_reference(&mut Strip::new(x0, w, &mut want).unwrap(), pts, xf, mode, Rgb::WHITE, 255);
                            assert!(got == want, "cull differs: {} pts, mode {:?}, k {k}, rot {rot}, band {x0}+{w}", pts.len(), mode);
                            x0 += w;
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert!(cases > 2000);
    }

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
        let mut buf = [0u16; (W * H) as usize];
        let mut s = Strip::new(0, W, &mut buf).unwrap();
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
        let mut buf = [0u16; (W * H) as usize];
        let mut s = Strip::new(0, W, &mut buf).unwrap();
        let mut f = Frame::new();
        f.push(Item::Ring { cx: 214 << 8, cy: 72 << 8, r: 30 << 8, w: (24 * 256) / 10, color: Rgb::WHITE });
        render_strip(&f, &Font::empty(), &mut s);
        assert_eq!(s.get(214, 72), 0);
        assert_eq!(s.get(214 + 29, 72), 0xFFFF);
    }

    #[test]
    fn chord_fills_only_below_the_level() {
        let mut buf = [0u16; (W * H) as usize];
        let mut s = Strip::new(0, W, &mut buf).unwrap();
        let mut f = Frame::new();
        f.push(Item::Chord { cx: 214 << 8, cy: 72 << 8, r: 30 << 8, level_y: 72 << 8, color: Rgb::WHITE, a: 255 });
        render_strip(&f, &Font::empty(), &mut s);
        assert_eq!(s.get(214, 66), 0);
        assert_eq!(s.get(214, 78), 0xFFFF);
    }

    #[test]
    fn marks_and_chevron_draw_something_inside_their_bounds() {
        let mut buf = [0u16; (W * H) as usize];
        let mut s = Strip::new(0, W, &mut buf).unwrap();
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

#[cfg(test)]
mod span_equivalence {
    //! The span-based disc / ring must be pixel-identical to the brute-force
    //! per-pixel evaluation they replaced (the goldens depend on it).
    use super::*;

    fn brute_disc(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, color: Rgb, min_y: Option<(Q8, u8)>) {
        let (level, a) = min_y.unwrap_or((i32::MIN / 2, 255));
        let y_lo = ((cy - r) >> 8) - 1;
        let y_hi = ((cy + r) >> 8) + 1;
        let x_lo = ((cx - r) >> 8) - 1;
        let x_hi = ((cx + r) >> 8) + 1;
        for y in y_lo.max(0)..=y_hi.min(H - 1) {
            let py = (y << 8) + ONE_Q8 / 2;
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

    fn brute_ring(s: &mut Strip<'_>, cx: Q8, cy: Q8, r: Q8, w: Q8, color: Rgb) {
        let r_in = r - w;
        let y_lo = ((cy - r) >> 8) - 1;
        let y_hi = ((cy + r) >> 8) + 1;
        let x_lo = ((cx - r) >> 8) - 1;
        let x_hi = ((cx + r) >> 8) + 1;
        for y in y_lo.max(0)..=y_hi.min(H - 1) {
            let dy = (y << 8) + ONE_Q8 / 2 - cy;
            if dy.abs() > r + ONE_Q8 {
                continue;
            }
            for x in x_lo.max(0)..=x_hi.min(W - 1) {
                let px = (x << 8) + ONE_Q8 / 2;
                let d = dist_q8(px - cx, dy);
                let sd = (d - r).max(r_in - d);
                let cov = edge_cov(sd);
                if cov != 0 {
                    s.blend(x, y, color, cov);
                }
            }
        }
    }

    /// Deterministic LCG so the sweep covers many sub-pixel phases.
    fn lcg(seed: &mut u32) -> u32 {
        *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *seed >> 8
    }

    #[test]
    fn disc_ring_and_chord_match_brute_force() {
        let mut seed = 7u32;
        let color = Rgb::new(0x13, 0xFF, 0x7F);
        let under = Rgb::new(0x40, 0x20, 0x90);
        for case in 0..400 {
            let cx = (lcg(&mut seed) % ((W as u32 + 80) << 8)) as i32 - (40 << 8);
            let cy = (lcg(&mut seed) % ((H as u32 + 80) << 8)) as i32 - (40 << 8);
            let r = (lcg(&mut seed) % (40 << 8)) as i32;
            let w = (lcg(&mut seed) % (6 << 8)) as i32 + 1;
            let a = (lcg(&mut seed) % 256) as u8;
            let level = cy + (lcg(&mut seed) % (80 << 8)) as i32 - (40 << 8);
            // Band ORIGIN in landscape x since #780, not a row.
            let x0 = (lcg(&mut seed) % (W as u32 - 16)) as i32;
            let mut b1 = [0u16; (W * 16) as usize];
            let mut b2 = [0u16; (W * 16) as usize];
            // A non-black background so partial coverage is exercised.
            for (i, p) in b1.iter_mut().enumerate() {
                *p = if i % 3 == 0 { under.to565() } else { 0 };
            }
            b2.copy_from_slice(&b1);
            let mut s1 = Strip::new(x0, 16, &mut b1).unwrap();
            let mut s2 = Strip::new(x0, 16, &mut b2).unwrap();
            match case % 3 {
                0 => {
                    disc(&mut s1, cx, cy, r, color, None);
                    brute_disc(&mut s2, cx, cy, r, color, None);
                }
                1 => {
                    ring(&mut s1, cx, cy, r, w, color);
                    brute_ring(&mut s2, cx, cy, r, w, color);
                }
                _ => {
                    disc(&mut s1, cx, cy, r, color, Some((level, a)));
                    brute_disc(&mut s2, cx, cy, r, color, Some((level, a)));
                }
            }
            assert!(b1 == b2, "case {case}: cx={cx} cy={cy} r={r} w={w} a={a} level={level} x0={x0}");
        }
    }

    /// Every rasteriser must reject an item its band cannot hold, BEFORE doing
    /// per-row work.
    ///
    /// This is the test that was missing. `x_hits` was defined, documented as
    /// "every rasteriser calls this first", asserted in a commit message to be
    /// wired in -- and called by nothing. The goldens could not catch it
    /// because the OUTPUT is identical either way: a band spans every row, so
    /// an unculled disc still clips correctly in `idx`, it just walks 142 rows
    /// running an isqrt each, nine times per frame instead of once. On glass
    /// that was render 7.8 ms -> 51.6 ms of shapes, which overran the frame and
    /// brought the tearing back as stationary seams.
    ///
    /// Both directions are asserted: an out-of-band frame must do NO work, and
    /// the same frame must do work when the band contains it. Without the
    /// positive leg a cull that rejects everything would pass.
    #[test]
    fn cull_rejects_items_outside_the_band() {
        // Every item kind that has a cull, all parked in x = [0, 60).
        let mut f = Frame::new();
        f.push(Item::Disc { cx: 30 << 8, cy: 72 << 8, r: 20 << 8, color: Rgb::WHITE });
        f.push(Item::Ring { cx: 30 << 8, cy: 72 << 8, r: 18 << 8, w: 2 << 8, color: Rgb::WHITE });
        f.push(Item::Chord { cx: 30 << 8, cy: 72 << 8, r: 16 << 8, level_y: 72 << 8, color: Rgb::WHITE, a: 200 });
        f.push(Item::Chevron { cx: 20 << 8, cy: 19 << 8, angle: 1 << 14, color: Rgb::WHITE });
        f.push(Item::Check { cx: 30 << 8, cy: 100 << 8, r: 15 << 8, color: Rgb::WHITE, k: 1 << 16 });
        f.push(Item::Cross { cx: 45 << 8, cy: 40 << 8, r: 12 << 8, color: Rgb::WHITE, k: 1 << 16 });
        f.push(Item::Rect { x: 10, y: 4, w: 40, h: 9, color: Rgb::WHITE, a: 180 });
        let font = Font::empty();

        // NEGATIVE: a band far to the right holds none of them.
        let mut buf = [0u16; (48 * H) as usize];
        TEST_WORK.with(|count| count.set(0));
        // A parallel test may render after this test resets its measurement.
        // Joining makes that interference deterministic for this regression.
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let mut other_buf = [0u16; (48 * H) as usize];
                let mut other = Strip::new(0, 48, &mut other_buf).unwrap();
                render_strip(&f, &font, &mut other);
            }).join().unwrap();
        });
        {
            let mut st = Strip::new(336, 48, &mut buf).unwrap();
            render_strip(&f, &font, &mut st);
        }
        let rejected = TEST_WORK.with(core::cell::Cell::get);
        assert_eq!(rejected, 0, "every item should have been culled by the x = [336, 384) band");
        assert!(buf.iter().all(|&p| p == 0), "a culled band must also be blank");

        // POSITIVE control: the band that DOES hold them must do work, or the
        // assertion above would pass for a cull that rejects everything.
        TEST_WORK.with(|count| count.set(0));
        {
            let mut st = Strip::new(0, 48, &mut buf).unwrap();
            render_strip(&f, &font, &mut st);
        }
        let accepted = TEST_WORK.with(core::cell::Cell::get);
        assert!(accepted >= 7, "the x = [0, 48) band holds all 7 items, got {accepted}");
        assert!(buf.iter().any(|&p| p != 0), "the holding band must have drawn something");
    }

    /// Nine vertical bands must compose to exactly the same frame as one
    /// full-width render.
    ///
    /// This is the property the device depends on and that nothing asserted
    /// before #780: `present_frame_ex` renders the frame in bands, so a
    /// rasteriser whose x-cull is off by a pixel, or that reads state it
    /// should not across a band edge, would paint a seam that only appears on
    /// glass. The goldens cannot catch it -- `png::render_full` composes bands
    /// too, so a cull bug would corrupt the golden and the comparison equally.
    #[test]
    fn bands_compose_to_the_same_frame_as_one_full_render() {
        let mut f = Frame::new();
        // Items chosen to STRADDLE band edges at x = 48, 96, 144, ... : a disc
        // and ring on a boundary, a chord, a chevron near x = 0, and marks far
        // right, so every rasteriser is exercised across a cut.
        f.push(Item::Disc { cx: 96 << 8, cy: 72 << 8, r: (30 << 8) + 128, color: Rgb::WHITE });
        f.push(Item::Ring { cx: 144 << 8, cy: 60 << 8, r: 28 << 8, w: (24 * 256) / 10, color: Rgb::new(0x20, 0xFF, 0x7F) });
        f.push(Item::Chord { cx: 192 << 8, cy: 80 << 8, r: 26 << 8, level_y: 80 << 8, color: Rgb::new(0x40, 0x80, 0xC0), a: 200 });
        f.push(Item::Chevron { cx: (235 << 8) / 10, cy: 19 << 8, angle: 1 << 14, color: Rgb::WHITE });
        f.push(Item::Check { cx: 384 << 8, cy: 72 << 8, r: 29 << 8, color: Rgb::WHITE, k: 1 << 16 });
        f.push(Item::Cross { cx: 336 << 8, cy: 100 << 8, r: 20 << 8, color: Rgb::new(0xFF, 0x40, 0x40), k: 1 << 16 });
        f.push(Item::Rect { x: 40, y: 4, w: 120, h: 9, color: Rgb::new(0x10, 0x30, 0x50), a: 180 });
        let font = Font::empty();

        let mut full = [0u16; (W * H) as usize];
        {
            let mut s = Strip::new(0, W, &mut full).unwrap();
            render_strip(&f, &font, &mut s);
        }

        const BW: i32 = 48;
        let mut band = [0u16; (BW * H) as usize];
        let mut x0 = 0;
        let mut bands = 0;
        while x0 < W {
            let w = BW.min(W - x0);
            {
                let mut s = Strip::new(x0, w, &mut band).unwrap();
                render_strip(&f, &font, &mut s);
            }
            for x in 0..w {
                for y in 0..H {
                    let got = band[(x * H + (H - 1 - y)) as usize];
                    let want = full[((x0 + x) * H + (H - 1 - y)) as usize];
                    assert_eq!(got, want, "band at x0={x0} differs at ({}, {y})", x0 + x);
                }
            }
            x0 += w;
            bands += 1;
        }
        assert_eq!(bands, 9, "428 landscape columns in 48-wide bands");
    }

    #[test]
    fn fill_span_matches_blend() {
        let color = Rgb::new(200, 100, 50);
        for a in [0u8, 1, 77, 128, 254, 255] {
            let mut b1 = [0x1234u16; (W * 16) as usize];
            let mut b2 = [0x1234u16; (W * 16) as usize];
            let mut s1 = Strip::new(32, 16, &mut b1).unwrap();
            let mut s2 = Strip::new(32, 16, &mut b2).unwrap();
            // Spans that straddle the band's left edge, its right edge, and
            // one that misses it entirely in x -- the clip that replaced the
            // old off-row case when bands became vertical (#780).
            s1.fill_span(-5, 100, 40, color, a);
            s1.fill_span(30, W + 10, 47, color, a);
            s1.fill_span(10, 5, 41, color, a); // empty
            s1.fill_span(200, 300, 10, color, a); // wholly outside the band
            for x in -5..=100 {
                s2.blend(x, 40, color, a);
            }
            for x in 30..=W + 10 {
                s2.blend(x, 47, color, a);
            }
            for x in 200..=300 {
                s2.blend(x, 10, color, a);
            }
            assert!(b1 == b2, "a={a}");
        }
    }
}
