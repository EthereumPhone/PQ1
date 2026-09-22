//! The scene: DESIGN.md's layout grid + the animation runtime that turns a
//! screen transcript position into a display list, frame after frame.
//!
//! Static geometry (`layout_of`) is the design's `layout.layout_of`; the
//! runtime (`Anim`) is the device half of `pq1/flow.py`'s `Sim` — springs
//! drive the disc between screens with the text crossfading underneath,
//! the follower chain trails the head, the idle hero sweeps, the chevrons
//! hint, the confirm band alternates, the hold fills the disc like liquid,
//! and the endings resolve the disc into the branded result look.
//!
//! Everything here is pure: the presenter owns the clock and the strip
//! buffer, calls [`Anim::step`] with `now`, then [`Anim::build`] into a
//! [`Frame`] and rasterises it strip by strip. Nothing draws without a
//! press except the ambient cycles (`next_wake` says when they need a frame).

use crate::driver::Btn;
use crate::fixed::{lerp, q16, Q16, Q8, ONE_Q16, ONE_Q8};
use crate::font::{Align, Font, TextRun, TierId};
use crate::motion::{
    self, Profile, Spring, CHAIN_GAP_CAP_PX, CHAIN_TAU_IDLE_MS, CHAIN_TAU_MS, HOLD_OVERLAY_A8, OSC_TAU_MS,
    PRESS_FEEDBACK_MS, TEXT_IN_DELAY_MS,
};
use crate::raster::{Frame, Item, Mask, Rgb};
use crate::screen::{Icon, Kind, ResultMark, Screen, State, Tier, Weight};

// ---- grid (DESIGN.md § Layout grid & anchors) -----------------------------
pub const CIRCLE_R: i32 = 30;
pub const CIRCLE_CY: i32 = 72;
pub const CENTER_X: i32 = 214;
pub const COL_LEFT_CX: i32 = 74;
pub const COL_RIGHT_CX: i32 = 352;
pub const TEXT_CX_CIRCLE_LEFT: i32 = 263;
pub const TEXT_CX_CIRCLE_RIGHT: i32 = 163;
/// Detail text vertical centre (72.5 px) in Q8.
pub const TEXT_CY_Q8: Q8 = (72 << 8) + 128;
pub const BASELINE_Y: i32 = 128;
pub const CHEV_Y: i32 = 19;
/// Chevron x anchors (23.5 / 403.5) in Q8.
pub const CHEV_LEFT_X_Q8: Q8 = (23 << 8) + 128;
pub const CHEV_RIGHT_X_Q8: Q8 = (403 << 8) + 128;
pub const CONFIRM_CIRCLE_X: i32 = 291;
pub const CONFIRM_TEXT_X: i32 = 175;
pub const VALUE_PARK_X: i32 = -60;
pub const PAGER_BASELINE_Y: i32 = 24;
/// Token ring: stroke 2.4 px inward, art inset 1.2 px (Q8).
pub const TOKEN_RING_W_Q8: Q8 = (2 << 8) + 102; // 2.4
pub const TOKEN_INSET_Q8: Q8 = (1 << 8) + 51; // 1.2
/// Letter-spacing: question 0.5 px, label 1 px (Q6).
pub const LS_QUESTION_Q6: i32 = 32;
pub const LS_LABEL_Q6: i32 = 64;

const MAX_TEXTS: usize = 6;

/// One laid-out text.
#[derive(Clone, Copy, Debug)]
pub struct TextSpec {
    pub start: usize,
    pub len: usize,
    pub tier: TierId,
    pub x: i32,
    pub y: i32,
    pub align: Align,
    pub baseline: bool,
    pub ls_q6: i32,
}

/// How the corner chevrons rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chev {
    /// Tap navigation available: point outward.
    Lr,
    /// A hold is armed: point up.
    Up,
    /// No input (status screens).
    None,
}

/// A screen's static geometry.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Disc centre (px); `None` = parked off-panel / no disc.
    pub circle: Option<(i32, i32)>,
    pub texts: [Option<TextSpec>; MAX_TEXTS],
    pub chev: Chev,
    pub sweep: bool,
    pub hint: bool,
    pub band: bool,
}

/// Which record bytes a text spec refers to — the layout only carries
/// offsets so `Layout` is `Copy` and lifetime-free.
#[derive(Clone, Copy, Debug)]
enum Src {
    Caption,
    Label,
    Line(u8, u8),
}

fn spec(s: &Screen, src: Src, tier: TierId, x: i32, y: i32, align: Align, baseline: bool, ls_q6: i32) -> Option<TextSpec> {
    let (start, len) = match src {
        Src::Caption => (32usize, s.caption().len()),
        Src::Label => (20usize, s.label().len()),
        Src::Line(p, i) => {
            let rec = line_rec(s, p, i)?;
            (64 + rec * 32 + 1, s.line(p, i)?.1.len())
        }
    };
    if len == 0 {
        return None;
    }
    Some(TextSpec {
        start,
        len,
        tier,
        x,
        y,
        align,
        baseline,
        ls_q6,
    })
}

fn line_rec(s: &Screen, p: u8, i: u8) -> Option<usize> {
    if s.kind() == Some(Kind::Legacy) {
        if p != 0 || i >= 4 {
            return None;
        }
        Some(usize::from(i))
    } else {
        if p >= 2 || i >= 3 {
            return None;
        }
        Some(usize::from(p) * 3 + usize::from(i))
    }
}

fn tier_id(s: &Screen, w: Weight) -> TierId {
    let px = s.tier().map_or(22, Tier::px);
    match w {
        Weight::SemiBold if px == 22 => TierId::semibold(22),
        _ => TierId::regular(px),
    }
}

/// Stack `n` value lines about the detail centre with the tier's leading.
fn stacked_y_q8(tier: Tier, n: u8, i: u8) -> Q8 {
    let lh = i32::from(tier.line_height()) << 8;
    TEXT_CY_Q8 + (i32::from(i) * 2 - (i32::from(n) - 1)) * lh / 2
}

/// The design's layout of a screen at `page`.
#[must_use]
pub fn layout_of(s: &Screen, page: u8) -> Layout {
    let mut l = Layout {
        circle: None,
        texts: [None; MAX_TEXTS],
        chev: Chev::Lr,
        sweep: false,
        hint: false,
        band: false,
    };
    let mut nt = 0usize;
    let mut push = |t: Option<TextSpec>| {
        if let Some(t) = t {
            if nt < MAX_TEXTS {
                l.texts[nt] = Some(t);
                nt += 1;
            }
        }
    };
    match s.kind() {
        Some(Kind::Hero) => {
            l.circle = Some((CENTER_X, CIRCLE_CY));
            l.sweep = true;
            l.hint = true;
            push(spec(s, Src::Caption, TierId::regular(18), CENTER_X, BASELINE_Y, Align::Center, true, LS_QUESTION_Q6));
        }
        Some(Kind::Status) => {
            l.circle = Some((CENTER_X, CIRCLE_CY));
            l.chev = Chev::None;
            push(spec(s, Src::Caption, TierId::regular(18), CENTER_X, BASELINE_Y, Align::Center, true, LS_QUESTION_Q6));
        }
        Some(Kind::Confirm) => {
            l.circle = Some((CONFIRM_CIRCLE_X, CIRCLE_CY));
            l.chev = Chev::Up;
            l.band = true;
            push(spec(s, Src::Caption, TierId::regular(36), CONFIRM_TEXT_X, 72, Align::Center, false, 0));
        }
        Some(Kind::Detail) => {
            let (cx, tx) = match s.side() {
                Some(crate::screen::Side::Right) => (COL_RIGHT_CX, TEXT_CX_CIRCLE_RIGHT),
                _ => (COL_LEFT_CX, TEXT_CX_CIRCLE_LEFT),
            };
            // The chain screen nudges (DESIGN.md: circle x 291 / text x 175).
            let (cx, tx) = if s.icon() == Some(Icon::Chain) { (CONFIRM_CIRCLE_X, CONFIRM_TEXT_X) } else { (cx, tx) };
            l.circle = Some((cx, CIRCLE_CY));
            push(spec(s, Src::Label, TierId::semibold(16), cx, BASELINE_Y, Align::Center, true, LS_LABEL_Q6));
            let tier = s.tier().unwrap_or(Tier::T22);
            let n = s.nlines(page);
            for i in 0..n {
                let w = s.line(page, i).map_or(Weight::Regular, |(w, _)| w);
                let y = stacked_y_q8(tier, n, i) >> 8;
                push(spec(s, Src::Line(page, i), tier_id(s, w), tx, y, Align::Center, false, 0));
            }
        }
        Some(Kind::Value) => {
            l.circle = None;
            push(spec(s, Src::Label, TierId::semibold(16), CENTER_X, BASELINE_Y, Align::Center, true, LS_LABEL_Q6));
            let tier = s.tier().unwrap_or(Tier::T22);
            let n = s.nlines(page);
            for i in 0..n {
                let w = s.line(page, i).map_or(Weight::Regular, |(w, _)| w);
                let y = stacked_y_q8(tier, n, i) >> 8;
                push(spec(s, Src::Line(page, i), tier_id(s, w), CENTER_X, y, Align::Center, false, 0));
            }
        }
        Some(Kind::Legacy) | None => {
            // Four 16-column rows as full-width 22 px text stacked about y 66.
            l.circle = None;
            let n = s.nlines(0).min(4);
            for i in 0..n {
                let y = 66 + (i32::from(i) * 2 - (i32::from(n) - 1)) * 15;
                push(spec(s, Src::Line(0, i), TierId::regular(22), CENTER_X, y, Align::Center, false, 0));
            }
        }
    }
    l
}

// ---- disc styling ---------------------------------------------------------

/// The disc's look for an icon.
#[derive(Clone, Copy, Debug)]
pub struct DiscStyle {
    pub fill: Rgb,
    pub ring: Rgb,
    pub mark: Rgb,
    pub trail: [Rgb; 5],
    /// Black film over a coloured body; white film inside a black body.
    pub film_white: bool,
}

#[must_use]
pub fn disc_style(icon: Option<Icon>) -> DiscStyle {
    match icon {
        Some(Icon::Safe) => DiscStyle {
            fill: Rgb::SAFE_FILL,
            ring: Rgb::BLACK,
            mark: Rgb::new(0x12, 0x12, 0x12),
            trail: Rgb::SAFE_TRAIL,
            film_white: false,
        },
        Some(Icon::Fingerprint) => DiscStyle {
            fill: Rgb::WHITE,
            ring: Rgb::BLACK,
            mark: Rgb::BLACK,
            trail: Rgb::MONO_TRAIL,
            film_white: false,
        },
        _ => DiscStyle {
            fill: Rgb::BLACK,
            ring: Rgb::WHITE,
            mark: Rgb::WHITE,
            trail: Rgb::MONO_TRAIL,
            film_white: true,
        },
    }
}

/// Baked marks the scene may draw.
#[derive(Clone, Copy, Debug, Default)]
pub struct Marks<'a> {
    pub safe: Option<Mask<'a>>,
    pub mainnet: Option<Mask<'a>>,
    pub base: Option<Mask<'a>>,
    pub fingerprint: Option<Mask<'a>>,
}

/// Parse a `*.a4` mark asset (`"PQ1M" | w u8 | h u8 | reserved u16 | rows`).
#[must_use]
pub fn parse_mark(data: &[u8]) -> Option<Mask<'_>> {
    if data.len() < 8 || &data[..4] != b"PQ1M" {
        return None;
    }
    let w = u16::from(data[4]);
    let h = u16::from(data[5]);
    let stride = (usize::from(w) + 1) / 2;
    let rows = data.get(8..8 + stride * usize::from(h))?;
    Some(Mask { w, h, rows })
}

// ---- the runtime ------------------------------------------------------------

/// An ending the disc resolves into after the transcript is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Branded fill + black check (Safe: `#13FF7F`), caption `SIGNED SAFE TX`.
    Signed,
    /// Red disc, black ring, black X, caption `SAFE TX DECLINED`.
    Declined,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct Hold {
    side: Btn,
    /// Fill level (Q16) — driven while held, drained after release.
    level: Q16,
    /// Level at the moment of release (the drain starts from here).
    release_level: Q16,
    released_at: Option<u32>,
    committed: bool,
}

/// The animation runtime for one transcript walk.
pub struct Anim {
    prev: Screen,
    prev_page: u8,
    cur: Screen,
    cur_page: u8,
    /// Disc position springs (px in Q16).
    sx: Spring,
    sy: Spring,
    /// Text alphas (Q16): outgoing (prev) and incoming (cur).
    alpha_out: Spring,
    alpha_in: Spring,
    text_in_at: Option<u32>,
    /// Page flip (sequential fade) start time.
    flip_at: Option<u32>,
    flip_from: u8,
    /// Follower chain positions (Q16 px).
    chain: [(Q16, Q16); 5],
    /// Sweep chase (Q16 px offset from the circle target).
    sweep: Q16,
    settled_at: Option<u32>,
    last_step: u32,
    hold: Option<Hold>,
    press: Option<(Btn, u32)>,
    ending: Option<(Ending, u32)>,
    /// Idle-since (last settle or last input), for the ambient cycles.
    idle_since: u32,
}

impl Anim {
    /// Start at `screen` / `page` with the disc resting at its layout position.
    #[must_use]
    pub fn new(screen: &Screen, page: u8, now: u32) -> Self {
        let l = layout_of(screen, page);
        let (cx, cy) = l.circle.unwrap_or((VALUE_PARK_X, CIRCLE_CY));
        let mut a = Self {
            prev: *screen,
            prev_page: page,
            cur: *screen,
            cur_page: page,
            sx: Spring::at(q16(cx), Profile::NAV),
            sy: Spring::at(q16(cy), Profile::NAV),
            alpha_out: Spring::at(0, Profile::NAV),
            alpha_in: Spring::at(ONE_Q16, Profile::NAV),
            text_in_at: None,
            flip_at: None,
            flip_from: page,
            chain: [(q16(cx), q16(cy)); 5],
            sweep: 0,
            settled_at: Some(now),
            last_step: now,
            hold: None,
            press: None,
            ending: None,
            idle_since: now,
        };
        a.alpha_out.snap(0);
        a
    }

    #[must_use]
    pub fn current(&self) -> (&Screen, u8) {
        (&self.cur, self.cur_page)
    }

    /// Move to another screen: the disc springs to its new place, outgoing
    /// text fades now, incoming text is released 150 ms later so the circle
    /// leads (DESIGN.md § Motion, Transition anatomy). Retargets mid-flight.
    pub fn go_to(&mut self, screen: &Screen, page: u8, now: u32) {
        // Drop whichever endpoint is dimmer if a third screen arrives
        // mid-flight: the current `cur` becomes `prev` at its live alpha.
        self.prev = self.cur;
        self.prev_page = self.cur_page;
        self.alpha_out.snap(self.alpha_in.value);
        self.alpha_out.retarget(0);
        self.cur = *screen;
        self.cur_page = page;
        self.alpha_in.snap(0);
        self.text_in_at = Some(now.wrapping_add(TEXT_IN_DELAY_MS));
        let l = layout_of(screen, page);
        let (cx, cy) = l.circle.unwrap_or((VALUE_PARK_X, CIRCLE_CY));
        self.sx.retarget(q16(cx));
        self.sy.retarget(q16(cy));
        self.settled_at = None;
        self.flip_at = None;
        self.idle_since = now;
        self.sweep = 0;
    }

    /// Turn a page within the current screen: sequential fade (out, then in).
    pub fn flip_page(&mut self, page: u8, now: u32) {
        if page == self.cur_page {
            return;
        }
        self.flip_from = self.cur_page;
        self.cur_page = page;
        self.flip_at = Some(now);
        self.idle_since = now;
    }

    /// A physical press: nudge the pressed side's chevron.
    pub fn press(&mut self, side: Btn, now: u32) {
        self.press = Some((side, now));
        self.idle_since = now;
    }

    /// The hold on `side` has been held `held_ms` (≥ TAP_MAX_MS).
    pub fn hold(&mut self, side: Btn, held_ms: u32, now: u32) {
        let level = motion::hold_fill(held_ms);
        self.hold = Some(Hold {
            side,
            level,
            release_level: level,
            released_at: None,
            committed: false,
        });
        self.idle_since = now;
    }

    /// Early release: the fill drains over 200 ms.
    pub fn hold_release(&mut self, now: u32) {
        if let Some(h) = &mut self.hold {
            if h.released_at.is_none() {
                h.released_at = Some(now);
                h.release_level = h.level;
            }
        }
    }

    /// The hold fired: the full fill fades over the transition.
    pub fn hold_commit(&mut self, now: u32) {
        if let Some(h) = &mut self.hold {
            h.level = ONE_Q16;
            h.committed = true;
            h.released_at = Some(now);
        }
    }

    /// Resolve the disc into an ending look (after the sign / decline).
    pub fn ending(&mut self, e: Ending, now: u32) {
        self.ending = Some((e, now));
        self.hold = None;
        self.sx.retarget(q16(CENTER_X));
        self.sy.retarget(q16(CIRCLE_CY));
        self.alpha_out.retarget(0);
        self.alpha_in.retarget(0);
        self.settled_at = None;
        self.idle_since = now;
    }

    /// Advance to `now`. Returns `true` when something is still moving (or
    /// an ambient cycle wants frames).
    pub fn step(&mut self, now: u32) -> bool {
        let dt = now.wrapping_sub(self.last_step).min(100);
        self.last_step = now;
        // Release the incoming text after the delay.
        if let Some(t) = self.text_in_at {
            if now.wrapping_sub(t) < (1 << 31) {
                self.alpha_in.retarget(ONE_Q16);
                self.text_in_at = None;
            }
        }
        self.sx.step(dt);
        self.sy.step(dt);
        self.alpha_out.step(dt);
        self.alpha_in.step(dt);
        // Hold drain.
        if let Some(h) = &mut self.hold {
            if let Some(r) = h.released_at {
                let since = now.wrapping_sub(r);
                if h.committed {
                    // Fade the full fill over ~one transition leg.
                    let u = motion::phase(since, 0, 500);
                    h.level = ONE_Q16 - motion::ease_out(u);
                } else {
                    h.level = motion::hold_snapback(h.release_level, since);
                }
                if since >= 600 {
                    self.hold = None;
                }
            }
        }
        // Press nudge expiry.
        if let Some((_, t)) = self.press {
            if now.wrapping_sub(t) > PRESS_FEEDBACK_MS {
                self.press = None;
            }
        }
        let moving = !(self.sx.settled() && self.sy.settled() && self.alpha_out.settled() && self.alpha_in.settled())
            || self.text_in_at.is_some();
        if !moving && self.settled_at.is_none() {
            self.settled_at = Some(now);
            self.idle_since = now;
        }
        // Idle sweep (hero only): chase the sine target with τ 180.
        let l = layout_of(&self.cur, self.cur_page);
        let idle = now.wrapping_sub(self.idle_since);
        let target = if l.sweep && !moving && self.hold.is_none() && self.ending.is_none() {
            q16(motion::sweep_offset(idle))
        } else {
            0
        };
        let k = motion::tau_k(dt, OSC_TAU_MS);
        self.sweep = lerp(self.sweep, target, k);
        // Follower chain: each link chases the one ahead, gap capped.
        let head = (self.sx.value + self.sweep, self.sy.value);
        let tau = if l.sweep && !moving { CHAIN_TAU_IDLE_MS } else { CHAIN_TAU_MS };
        let kc = motion::tau_k(dt, tau);
        let mut ahead = head;
        for link in &mut self.chain {
            let mut nx = lerp(link.0, ahead.0, kc);
            let mut ny = lerp(link.1, ahead.1, kc);
            let dx = nx - ahead.0;
            let dy = ny - ahead.1;
            let cap = q16(CHAIN_GAP_CAP_PX);
            let d = crate::fixed::dist_q8(dx >> 8, dy >> 8) << 8;
            if d > cap && d > 0 {
                nx = ahead.0 + ((i64::from(dx) * i64::from(cap) / i64::from(d)) as Q16);
                ny = ahead.1 + ((i64::from(dy) * i64::from(cap) / i64::from(d)) as Q16);
            }
            *link = (nx, ny);
            ahead = *link;
        }
        let flip_live = self.flip_at.is_some_and(|t| now.wrapping_sub(t) < 2 * motion::PAGE_FADE_MS);
        if !flip_live {
            self.flip_at = None;
        }
        let ambient = (l.sweep || l.hint || l.band) && self.ending.is_none();
        let ending_live = self.ending.is_some_and(|(_, t)| now.wrapping_sub(t) < 1500);
        // The trail is still catching up with the head.
        let chain_live = self
            .chain
            .iter()
            .any(|(x, y)| (x - head.0).abs() + (y - head.1).abs() >= ONE_Q16 / 2);
        moving || chain_live || self.hold.is_some() || self.press.is_some() || flip_live || ambient || ending_live
    }

    /// When the next frame is due, if nothing is moving: `None` = sleep until
    /// input; `Some(ms)` = wake for an ambient cycle.
    #[must_use]
    pub fn next_wake(&self, now: u32) -> Option<u32> {
        let l = layout_of(&self.cur, self.cur_page);
        if self.ending.is_some() || self.hold.is_some() || self.settled_at.is_none() || self.flip_at.is_some() {
            return Some(now.wrapping_add(16));
        }
        if l.sweep || l.hint {
            return Some(now.wrapping_add(33));
        }
        if l.band {
            return Some(now.wrapping_add(33));
        }
        None
    }

    /// Build the display list for the current pose.
    pub fn build<'a>(&'a self, marks: &Marks<'a>, font: &Font<'a>, frame: &mut Frame<'a>) {
        let now = self.last_step;
        let l = layout_of(&self.cur, self.cur_page);
        let idle = now.wrapping_sub(self.idle_since);

        // ---- corner chevrons ----------------------------------------------
        if l.chev != Chev::None && self.ending.is_none() {
            let (hint_up, bob) = if l.hint || l.band {
                motion::chevron_hint(idle)
            } else {
                (0, 0)
            };
            let up_amount = if l.chev == Chev::Up { ONE_Q16 } else { hint_up };
            for (side, x, out_turns) in [(Btn::Left, CHEV_LEFT_X_Q8, ONE_Q16 / 2), (Btn::Right, CHEV_RIGHT_X_Q8, 0)] {
                // Rest: outward; hint / armed: up (0.25 turns).
                let angle = lerp(out_turns, ONE_Q16 / 4, up_amount);
                let nudge = match self.press {
                    Some((s, t)) if s == side => {
                        let u = motion::phase(now.wrapping_sub(t), 0, PRESS_FEEDBACK_MS);
                        let k = ONE_Q16 - motion::ease_out(u);
                        let px = (3 * i64::from(k) >> 16) as i32;
                        if side == Btn::Left { -px } else { px }
                    }
                    _ => 0,
                };
                frame.push(Item::Chevron {
                    cx: x + (nudge << 8),
                    cy: ((CHEV_Y + bob) << 8),
                    angle,
                    color: Rgb::WHITE,
                });
            }
        }

        // ---- texts: outgoing screen at alpha_out, current at alpha_in -----
        let a_out = (i64::from(self.alpha_out.value.clamp(0, ONE_Q16)) * 255 >> 16) as u8;
        let a_in = (i64::from(self.alpha_in.value.clamp(0, ONE_Q16)) * 255 >> 16) as u8;
        if a_out > 0 && !(self.prev.0 == self.cur.0 && self.prev_page == self.cur_page) {
            push_texts(frame, &self.prev, self.prev_page, a_out);
        }
        if self.ending.is_none() {
            if let Some(t) = self.flip_at {
                let (out_a, in_a) = motion::page_flip(now.wrapping_sub(t));
                let ao = (i64::from(out_a) * i64::from(a_in) >> 16) as u8;
                let ai = (i64::from(in_a) * i64::from(a_in) >> 16) as u8;
                push_texts(frame, &self.cur, self.flip_from, ao);
                push_texts(frame, &self.cur, self.cur_page, ai);
            } else {
                push_texts(frame, &self.cur, self.cur_page, a_in);
            }
            // Pager `n/m` when the screen turns pages.
            if self.cur.npages() > 1 {
                let np = self.cur.npages();
                let pager: &'static [u8] = match (self.cur_page, np) {
                    (0, 2) => b"1/2",
                    (1, 2) => b"2/2",
                    _ => b"1/1",
                };
                frame.push(Item::Text {
                    run: TextRun {
                        text: pager,
                        tier: TierId::regular(16),
                        x: CENTER_X,
                        y: PAGER_BASELINE_Y,
                        align: Align::Center,
                        baseline: true,
                        ls_q6: 0,
                        alpha: a_in,
                    },
                    color: Rgb::WHITE,
                });
            }
            // Confirm band: OR VIEW MORE ▸ / ◂ TO GO BACK.
            if l.band {
                let settled = self.settled_at.map_or(0, |t| now.wrapping_sub(t));
                let (which, alpha) = motion::confirm_band(settled);
                let a = (i64::from(alpha) * i64::from(a_in) >> 16) as u8;
                let (text, x, chev_x, turns): (&'static [u8], i32, Q8, Q16) = if which == 0 {
                    (b"OR VIEW MORE", 204, (287 << 8), 0)
                } else {
                    (b"TO GO BACK", 224, (140 << 8), ONE_Q16 / 2)
                };
                frame.push(Item::Text {
                    run: TextRun {
                        text,
                        tier: TierId::regular(18),
                        x,
                        y: BASELINE_Y,
                        align: Align::Center,
                        baseline: true,
                        ls_q6: LS_QUESTION_Q6,
                        alpha: a,
                    },
                    color: Rgb::WHITE,
                });
                frame.push(Item::Chevron {
                    cx: chev_x,
                    cy: (BASELINE_Y - 6) << 8,
                    angle: turns,
                    color: Rgb::WHITE.scale(a),
                });
            }
        } else if let Some((e, t)) = self.ending {
            let caption: &'static [u8] = match e {
                Ending::Signed => b"SIGNED SAFE TX",
                Ending::Declined => b"SAFE TX DECLINED",
            };
            let a = (i64::from(motion::ease_out(motion::phase(now.wrapping_sub(t), 400, 300))) * 255 >> 16) as u8;
            frame.push(Item::Text {
                run: TextRun {
                    text: caption,
                    tier: TierId::regular(18),
                    x: CENTER_X,
                    y: BASELINE_Y,
                    align: Align::Center,
                    baseline: true,
                    ls_q6: LS_QUESTION_Q6,
                    alpha: a,
                },
                color: Rgb::WHITE,
            });
        }

        // ---- the disc, its trail, film and ring ---------------------------
        let icon = self.cur.icon();
        let style = disc_style(icon);
        let head_x = self.sx.value + self.sweep;
        let cx_q8 = head_x >> 8;
        let cy_q8 = self.sy.value >> 8;
        let visible_r = (CIRCLE_R << 8) - TOKEN_INSET_Q8;
        let has_disc = l.circle.is_some() || !self.sx.settled() || self.ending.is_some();
        if has_disc && cx_q8 > -(CIRCLE_R << 8) {
            // Trail: farthest link first, only while the chain is spread out.
            for (i, (lx, ly)) in self.chain.iter().enumerate().rev() {
                let dx = (lx - head_x) >> 8;
                let dy = (ly - self.sy.value) >> 8;
                if dx.abs() + dy.abs() < ONE_Q8 {
                    continue;
                }
                frame.push(Item::Disc {
                    cx: lx >> 8,
                    cy: ly >> 8,
                    r: visible_r,
                    color: style.trail[i.min(4)],
                });
            }
            match self.ending {
                None => {
                    frame.push(Item::Disc { cx: cx_q8, cy: cy_q8, r: visible_r, color: style.fill });
                    let mark = match icon {
                        Some(Icon::Safe) => marks.safe,
                        // The chain mark follows the proven NETWORK text: Base
                        // gets its own mark, everything else the Ethereum one.
                        Some(Icon::Chain) => {
                            if self.cur.line(self.cur_page, 0).is_some_and(|(_, t)| t == b"Base" || t.ends_with(b" Base")) {
                                marks.base.or(marks.mainnet)
                            } else {
                                marks.mainnet
                            }
                        }
                        Some(Icon::Fingerprint) => marks.fingerprint,
                        _ => None,
                    };
                    if let Some(m) = mark {
                        frame.push(Item::Mask { cx: cx_q8, cy: cy_q8, mask: m, scale: ONE_Q8, color: style.mark, a: 255 });
                    }
                    // Hold flood: liquid rising from the bottom, 30 % film.
                    if let Some(h) = self.hold {
                        if h.level > 0 {
                            let level_y = cy_q8 + ((i64::from(visible_r) * (ONE_Q16 as i64 - 2 * i64::from(h.level))) >> 16) as Q8;
                            frame.push(Item::Chord {
                                cx: cx_q8,
                                cy: cy_q8,
                                r: visible_r - TOKEN_RING_W_Q8,
                                level_y,
                                color: if style.film_white { Rgb::WHITE } else { Rgb::BLACK },
                                a: HOLD_OVERLAY_A8,
                            });
                        }
                    }
                    frame.push(Item::Ring { cx: cx_q8, cy: cy_q8, r: visible_r, w: TOKEN_RING_W_Q8, color: style.ring });
                }
                Some((e, t)) => {
                    // Resolve: the arrived disc crossfades to the result look
                    // over a 400 ms flash beat, the mark draws in after.
                    let since = now.wrapping_sub(t);
                    let u = motion::ease_out(motion::phase(since, 0, 400));
                    let (fill, ring, mark_c) = match e {
                        Ending::Signed => (Rgb::SAFE_FILL, Rgb::BLACK, Rgb::BLACK),
                        Ending::Declined => (Rgb::RED, Rgb::BLACK, Rgb::BLACK),
                    };
                    let f = blend_rgb(style.fill, fill, u);
                    let rg = blend_rgb(style.ring, ring, u);
                    frame.push(Item::Disc { cx: cx_q8, cy: cy_q8, r: visible_r, color: f });
                    let k = motion::ease_out(motion::phase(since, 400, 350));
                    if k > 0 {
                        match e {
                            Ending::Signed => frame.push(Item::Check { cx: cx_q8, cy: cy_q8, r: visible_r, color: mark_c, k }),
                            Ending::Declined => frame.push(Item::Cross { cx: cx_q8, cy: cy_q8, r: visible_r, color: mark_c, k }),
                        };
                    }
                    frame.push(Item::Ring { cx: cx_q8, cy: cy_q8, r: visible_r, w: TOKEN_RING_W_Q8, color: rg });
                }
            }
        }
        let _ = font;
    }
}

fn blend_rgb(a: Rgb, b: Rgb, t: Q16) -> Rgb {
    Rgb::new(
        lerp(i32::from(a.r), i32::from(b.r), t) as u8,
        lerp(i32::from(a.g), i32::from(b.g), t) as u8,
        lerp(i32::from(a.b), i32::from(b.b), t) as u8,
    )
}

fn push_texts<'a>(frame: &mut Frame<'a>, s: &'a Screen, page: u8, alpha: u8) {
    if alpha == 0 {
        return;
    }
    let l = layout_of(s, page);
    for t in l.texts.iter().flatten() {
        let text = &s.0[t.start..t.start + t.len];
        frame.push(Item::Text {
            run: TextRun {
                text,
                tier: t.tier,
                x: t.x,
                y: t.y,
                align: t.align,
                baseline: t.baseline,
                ls_q6: t.ls_q6,
                alpha,
            },
            color: Rgb::WHITE,
        });
    }
}

// The state colours are available for status screens (`State`), kept here
// so the palette lives next to the styling table.
#[must_use]
pub fn state_color(state: Option<State>) -> Rgb {
    match state {
        Some(State::Done) => Rgb::GREEN,
        Some(State::Failed) => Rgb::RED,
        Some(State::Warning) => Rgb::ORANGE,
        Some(State::Awaiting) => Rgb::YELLOW,
        _ => Rgb::WHITE,
    }
}

#[must_use]
pub fn result_mark(r: Option<ResultMark>) -> Option<Ending> {
    match r {
        Some(ResultMark::Check) => Some(Ending::Signed),
        Some(ResultMark::Cross) => Some(Ending::Declined),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::{ScreenBuilder, Side};

    fn hero() -> Screen {
        ScreenBuilder::hero(b"APPROVE", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap()
    }
    fn detail() -> Screen {
        ScreenBuilder::detail(b"SAFEACCT", Icon::Safe, Side::Left, b"SAFE ACCT")
            .tier(Tier::T22)
            .line(b"0x5afe000000000000000", Weight::Regular)
            .line(b"000000000000000000001", Weight::Regular)
            .finish()
            .unwrap()
    }

    #[test]
    fn layouts_follow_the_grid() {
        let h = layout_of(&hero(), 0);
        assert_eq!(h.circle, Some((CENTER_X, CIRCLE_CY)));
        assert!(h.sweep && h.hint);
        let cap = h.texts[0].unwrap();
        assert_eq!((cap.x, cap.y, cap.tier.px), (CENTER_X, BASELINE_Y, 18));
        let d = layout_of(&detail(), 0);
        assert_eq!(d.circle, Some((COL_LEFT_CX, CIRCLE_CY)));
        let label = d.texts[0].unwrap();
        assert_eq!((label.x, label.y, label.tier), (COL_LEFT_CX, BASELINE_Y, TierId::semibold(16)));
        let l1 = d.texts[1].unwrap();
        let l2 = d.texts[2].unwrap();
        assert_eq!(l1.x, TEXT_CX_CIRCLE_LEFT);
        assert_eq!(l2.y - l1.y, 30, "22-tier leading");
        assert!(d.texts[3].is_none());
        let c = layout_of(&ScreenBuilder::confirm(Icon::Safe).finish().unwrap(), 0);
        assert_eq!(c.circle, Some((CONFIRM_CIRCLE_X, CIRCLE_CY)));
        assert_eq!(c.chev, Chev::Up);
        assert!(c.band);
        let page: pqsigner_erc7730::display::Page = [[b'a'; 16]; 4];
        let lg = layout_of(&Screen::legacy(&page), 0);
        assert!(lg.circle.is_none());
        assert_eq!(lg.texts.iter().flatten().count(), 4);
    }

    #[test]
    fn transition_moves_the_disc_and_crossfades_text() {
        let h = hero();
        let d = detail();
        let mut a = Anim::new(&h, 0, 0);
        a.go_to(&d, 0, 0);
        let marks = Marks::default();
        let font = Font::empty();
        // Just after the retarget: the disc has not arrived, both texts are present.
        a.step(16);
        let mut f = Frame::new();
        a.build(&marks, &font, &mut f);
        let discs = f.items().iter().filter(|i| matches!(i, Item::Disc { .. })).count();
        assert!(discs >= 1);
        let texts = f.items().iter().filter(|i| matches!(i, Item::Text { .. })).count();
        assert!(texts >= 1, "{texts}");
        // Settle.
        let mut t = 16;
        while a.step(t) && t < 3000 {
            t += 16;
        }
        let mut f = Frame::new();
        a.build(&marks, &font, &mut f);
        // The head disc is drawn last (after the trail).
        let disc_x = f.items().iter().rev().find_map(|i| if let Item::Disc { cx, .. } = i { Some(*cx >> 8) } else { None }).unwrap();
        assert_eq!(disc_x, COL_LEFT_CX);
        let discs = f.items().iter().filter(|i| matches!(i, Item::Disc { .. })).count();
        assert_eq!(discs, 1, "the trail has caught up");
        assert!(a.next_wake(t).is_none(), "a settled detail sleeps until input");
    }

    #[test]
    fn hero_sweeps_and_hold_floods() {
        let h = hero();
        let mut a = Anim::new(&h, 0, 0);
        assert!(a.next_wake(0).is_some(), "hero keeps animating");
        for t in (16..4000).step_by(16) {
            a.step(t);
        }
        let mut f = Frame::new();
        a.build(&Marks::default(), &Font::empty(), &mut f);
        let disc_x = f.items().iter().rev().find_map(|i| if let Item::Disc { cx, .. } = i { Some(*cx >> 8) } else { None }).unwrap();
        assert!(disc_x != CENTER_X, "the idle sweep moved the disc");
        a.hold(Btn::Right, 1200, 4000);
        a.step(4016);
        let mut f = Frame::new();
        a.build(&Marks::default(), &Font::empty(), &mut f);
        assert!(f.items().iter().any(|i| matches!(i, Item::Chord { .. })), "hold film present");
        a.hold_release(4100);
        for t in (4116..5000).step_by(16) {
            a.step(t);
        }
        let mut f = Frame::new();
        a.build(&Marks::default(), &Font::empty(), &mut f);
        assert!(!f.items().iter().any(|i| matches!(i, Item::Chord { .. })), "drained");
    }

    #[test]
    fn ending_resolves_into_the_result_look() {
        let h = hero();
        let mut a = Anim::new(&h, 0, 0);
        a.ending(Ending::Signed, 0);
        for t in (16..1200).step_by(16) {
            a.step(t);
        }
        let mut f = Frame::new();
        a.build(&Marks::default(), &Font::empty(), &mut f);
        assert!(f.items().iter().any(|i| matches!(i, Item::Check { .. })));
        assert!(f.items().iter().any(|i| matches!(i, Item::Disc { color, .. } if *color == Rgb::SAFE_FILL)));
        assert!(!f.items().iter().any(|i| matches!(i, Item::Chevron { .. })), "no input on an ending");
    }
}
