//! Which columns of the panel a new frame changes, for the busy film's
//! partial redraw (#934, scoped to the loading film, owner 2026-10-16).
//!
//! The frame is a pure function of its ordered item list, so a column no
//! changed item touches composes to the same pixels. [`FrameSigs`] keeps, per
//! item, a 64-bit fingerprint of every field that reaches the rasteriser and
//! the columns the item can touch; [`FrameSigs::damage`] compares two such
//! lists index by index and unions the columns of every item that differs,
//! old and new position both. Anything it cannot bound is a full repaint:
//! a different item count, or a changed item of a kind whose columns are not
//! computed here (`Item::cols` returns `None`).
//!
//! Display only. Nothing here decides what is signed; the film carries no
//! consent. Callers restrict it to the busy film, start every film with a
//! full frame, and repaint everything when anything else drew in between.

use crate::font::{Align, Font};
use crate::raster::{Frame, Item, MAX_ITEMS, W};

/// Columns added on each side of a text run's measured advance: glyph
/// bearings and overhangs reach past the advance box (the host test checks
/// this margin against the real atlas).
const TEXT_SLACK: i32 = 12;

/// One item's fingerprint and the landscape columns it can touch
/// (inclusive), `None` when they are not computed for its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sig {
    pub h: u64,
    pub cols: Option<(i32, i32)>,
}

impl Sig {
    const NONE: Self = Self { h: 0, cols: None };
}

/// The fingerprints of one frame, in item order.
#[derive(Clone, Copy, Debug)]
pub struct FrameSigs {
    sigs: [Sig; MAX_ITEMS],
    n: usize,
}

/// What a new frame needs on the glass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    /// Nothing changed.
    Nothing,
    /// Only these columns (inclusive) changed.
    Cols(i32, i32),
    /// Repaint everything.
    All,
}

struct Fnv(u64);

impl Fnv {
    fn new(tag: u8) -> Self {
        let mut h = Self(0xcbf2_9ce4_8422_2325);
        h.u(u64::from(tag));
        h
    }
    fn u(&mut self, v: u64) {
        for b in v.to_le_bytes() {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
    fn i(&mut self, v: i32) {
        self.u(u64::from(v as u32));
    }
    fn rgb(&mut self, c: crate::raster::Rgb) {
        self.u(u64::from(c.r) | u64::from(c.g) << 8 | u64::from(c.b) << 16);
    }
    /// A slice by identity (address and length): every slice an item carries
    /// is atlas or static data that does not change under the same address.
    fn slice<T>(&mut self, s: &[T]) {
        self.u(s.as_ptr() as usize as u64);
        self.u(s.len() as u64);
    }
}

/// The fingerprint and columns of one item. Kinds the busy film never draws
/// get a fingerprint of everything but no columns, so a change in one forces
/// a full repaint.
#[must_use]
pub fn sig(item: &Item<'_>, font: &Font<'_>) -> Sig {
    let disc_cols = |cx: i32, r: i32| Some((((cx - r) >> 8) - 2, ((cx + r) >> 8) + 2));
    match *item {
        Item::None => Sig { h: Fnv::new(0).0, cols: Some((i32::MAX, i32::MIN)) },
        Item::Disc { cx, cy, r, color } => {
            let mut h = Fnv::new(1);
            h.i(cx);
            h.i(cy);
            h.i(r);
            h.rgb(color);
            Sig { h: h.0, cols: disc_cols(cx, r) }
        }
        Item::Ring { cx, cy, r, w, color } => {
            let mut h = Fnv::new(2);
            h.i(cx);
            h.i(cy);
            h.i(r);
            h.i(w);
            h.rgb(color);
            Sig { h: h.0, cols: disc_cols(cx, r) }
        }
        Item::Mask { cx, cy, mask, scale, color, a } => {
            let mut h = Fnv::new(3);
            h.i(cx);
            h.i(cy);
            h.u(u64::from(mask.w) | u64::from(mask.h) << 16);
            h.slice(mask.rows);
            h.i(scale);
            h.rgb(color);
            h.u(u64::from(a));
            let dw = (i64::from(mask.w) * i64::from(scale) >> 8) as i32;
            let x0 = (cx >> 8) - dw / 2;
            Sig { h: h.0, cols: Some((x0 - 1, x0 + dw + 1)) }
        }
        Item::Text { ref run, color } => {
            let mut h = Fnv::new(4);
            h.slice(run.text);
            h.u(u64::from(run.tier.px) | u64::from(run.tier.semibold) << 8);
            h.i(run.x);
            h.i(run.y);
            h.u(run.align as u64);
            h.u(u64::from(run.baseline));
            h.i(run.ls_q6);
            h.u(u64::from(run.alpha));
            h.rgb(color);
            let cols = font.measure_q6(run.tier, run.text, run.ls_q6).map(|width| {
                let left_q6 = match run.align {
                    Align::Left => run.x << 6,
                    Align::Center => (run.x << 6) - width / 2,
                    Align::Right => (run.x << 6) - width,
                };
                ((left_q6 >> 6) - TEXT_SLACK, ((left_q6 + width) >> 6) + TEXT_SLACK)
            });
            Sig { h: h.0, cols }
        }
        Item::Rect { x, y, w, h: hh, color, a } => {
            let mut h = Fnv::new(5);
            h.i(x);
            h.i(y);
            h.i(w);
            h.i(hh);
            h.rgb(color);
            h.u(u64::from(a));
            Sig { h: h.0, cols: Some((x, x + w - 1)) }
        }
        // Not drawn by the busy film: never bounded here, so any change in
        // one of these repaints everything. The tag alone distinguishes the
        // kind; the fields are deliberately not trusted to be complete.
        Item::Chord { .. } => Sig { h: Fnv::new(6).0, cols: None },
        Item::Chevron { .. } => Sig { h: Fnv::new(7).0, cols: None },
        Item::Check { .. } => Sig { h: Fnv::new(8).0, cols: None },
        Item::Cross { .. } => Sig { h: Fnv::new(9).0, cols: None },
        Item::Shape { .. } => Sig { h: Fnv::new(10).0, cols: None },
        Item::Secret { .. } => Sig { h: Fnv::new(11).0, cols: None },
        Item::EllipseRing { .. } => Sig { h: Fnv::new(12).0, cols: None },
        Item::Clump { .. } => Sig { h: Fnv::new(13).0, cols: None },
    }
}

impl FrameSigs {
    /// A list that matches no frame: the first comparison is a full repaint.
    pub const UNKNOWN: Self = Self { sigs: [Sig::NONE; MAX_ITEMS], n: usize::MAX };

    #[must_use]
    pub fn of(frame: &Frame<'_>, font: &Font<'_>) -> Self {
        let mut out = Self { sigs: [Sig::NONE; MAX_ITEMS], n: 0 };
        for (slot, item) in out.sigs.iter_mut().zip(frame.items()) {
            *slot = sig(item, font);
            out.n += 1;
        }
        out
    }

    /// What changes from `prev` (on the glass) to `self`.
    #[must_use]
    pub fn damage(&self, prev: &Self) -> Damage {
        if self.n != prev.n || self.n > MAX_ITEMS {
            return Damage::All;
        }
        let mut lo = i32::MAX;
        let mut hi = i32::MIN;
        for (a, b) in self.sigs[..self.n].iter().zip(&prev.sigs[..self.n]) {
            // An unbounded kind anywhere, changed or not, repaints everything:
            // its fields are not fingerprinted, so "equal" would only mean
            // "same kind".
            let (Some(ca), Some(cb)) = (a.cols, b.cols) else { return Damage::All };
            if a == b {
                continue;
            }
            for (x0, x1) in [ca, cb] {
                lo = lo.min(x0);
                hi = hi.max(x1);
            }
        }
        if lo > hi {
            return Damage::Nothing;
        }
        Damage::Cols(lo.max(0), hi.min(W - 1))
    }
}
