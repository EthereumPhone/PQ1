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
use crate::loading::{self, Body, Phase, QubitFilm, ResolveFilm, TRAIL_COUNT};
use crate::motion::{
    self, Profile, Spring, CHAIN_GAP_CAP_PX, CHAIN_TAU_IDLE_MS, CHAIN_TAU_MS, HOLD_OVERLAY_A8, OSC_TAU_MS,
    PRESS_FEEDBACK_MS, TEXT_IN_DELAY_MS,
};
use crate::raster::{Frame, Item, Mask, Rgb};
use crate::screen::{Icon, Kind, ResultMark, Screen, State, Tier, Weight, N_RAMPS};

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
    /// Follower colours in the engine's existing order (`Rgb::SAFE_TRAIL`'s
    /// convention: ramp stop 1 at index 0 … stop 5 at index 4); the chain
    /// and the film index it the same way for every family.
    pub trail: [Rgb; 5],
    /// Black film over a coloured body; white film inside a black body.
    pub film_white: bool,
    /// The qubit film's body colour: the ramp's brightest stop, so a
    /// black-bodied token never plays black-on-black qubits
    /// (`components.token_style_from_spec` "film").
    pub film: Rgb,
    /// A brand family (Safe): its endings FILL the disc (DESIGN.md "The
    /// ending disc splits on branding"); every other family strokes it.
    pub branded: bool,
}

/// `colors.PLACEHOLDER_GRADIENTS`: fourteen six-stop ramps, far follower →
/// the token (stop 6 = the disc; ramp 13 is the mono entry, whose disc the
/// design overrides to black).
pub const PLACEHOLDER_RAMPS: [[Rgb; 6]; N_RAMPS as usize] = [
    [Rgb::new(0x41, 0x3D, 0x2E), Rgb::new(0x48, 0x42, 0x2C), Rgb::new(0x5C, 0x52, 0x23), Rgb::new(0x75, 0x64, 0x00), Rgb::new(0x7D, 0x65, 0x00), Rgb::new(0x8A, 0x75, 0x00)],
    [Rgb::new(0x64, 0x12, 0x20), Rgb::new(0x85, 0x18, 0x2A), Rgb::new(0xA7, 0x1E, 0x34), Rgb::new(0xB2, 0x1E, 0x35), Rgb::new(0xC7, 0x1F, 0x37), Rgb::new(0xE0, 0x1E, 0x37)],
    [Rgb::new(0x05, 0x19, 0x23), Rgb::new(0x00, 0x2E, 0x4A), Rgb::new(0x00, 0x4F, 0x75), Rgb::new(0x00, 0x60, 0x97), Rgb::new(0x00, 0x74, 0xB1), Rgb::new(0x00, 0x7E, 0xB2)],
    [Rgb::new(0x38, 0x16, 0x0D), Rgb::new(0x4C, 0x26, 0x1B), Rgb::new(0x56, 0x2F, 0x21), Rgb::new(0x60, 0x37, 0x28), Rgb::new(0x6A, 0x3F, 0x2F), Rgb::new(0x7E, 0x50, 0x3C)],
    [Rgb::new(0x31, 0x00, 0x55), Rgb::new(0x3C, 0x06, 0x63), Rgb::new(0x4A, 0x0A, 0x77), Rgb::new(0x5A, 0x10, 0x8F), Rgb::new(0x68, 0x18, 0xA5), Rgb::new(0x8B, 0x2F, 0xC9)],
    [Rgb::new(0x5C, 0x2E, 0x0C), Rgb::new(0x70, 0x38, 0x10), Rgb::new(0x83, 0x43, 0x14), Rgb::new(0x95, 0x4D, 0x18), Rgb::new(0xA6, 0x57, 0x1B), Rgb::new(0xB6, 0x5F, 0x1F)],
    [Rgb::new(0x03, 0x19, 0x11), Rgb::new(0x06, 0x2A, 0x1D), Rgb::new(0x08, 0x33, 0x24), Rgb::new(0x0E, 0x45, 0x30), Rgb::new(0x12, 0x56, 0x3D), Rgb::new(0x17, 0x68, 0x49)],
    [Rgb::new(0x03, 0x31, 0x2E), Rgb::new(0x00, 0x52, 0x52), Rgb::new(0x00, 0x67, 0x5E), Rgb::new(0x00, 0x6E, 0x67), Rgb::new(0x00, 0x7A, 0x76), Rgb::new(0x00, 0x84, 0x82)],
    [Rgb::new(0x64, 0x0E, 0x30), Rgb::new(0x75, 0x17, 0x3A), Rgb::new(0x86, 0x20, 0x45), Rgb::new(0x96, 0x2A, 0x50), Rgb::new(0xA7, 0x32, 0x55), Rgb::new(0xC5, 0x4C, 0x71)],
    [Rgb::new(0x7C, 0x05, 0x0A), Rgb::new(0x8C, 0x19, 0x17), Rgb::new(0x9B, 0x27, 0x23), Rgb::new(0xAA, 0x35, 0x2F), Rgb::new(0xBA, 0x42, 0x39), Rgb::new(0xCA, 0x4D, 0x45)],
    [Rgb::new(0x26, 0x26, 0x2C), Rgb::new(0x2F, 0x30, 0x37), Rgb::new(0x39, 0x3A, 0x41), Rgb::new(0x4B, 0x4C, 0x52), Rgb::new(0x5B, 0x5C, 0x62), Rgb::new(0x6A, 0x6B, 0x70)],
    [Rgb::new(0x11, 0x00, 0x1C), Rgb::new(0x22, 0x07, 0x32), Rgb::new(0x37, 0x17, 0x4C), Rgb::new(0x5C, 0x31, 0x7E), Rgb::new(0x6F, 0x40, 0x97), Rgb::new(0x8C, 0x57, 0xBC)],
    [Rgb::new(0x07, 0x23, 0x8B), Rgb::new(0x15, 0x37, 0x9A), Rgb::new(0x24, 0x48, 0xA9), Rgb::new(0x32, 0x58, 0xB8), Rgb::new(0x40, 0x67, 0xC4), Rgb::new(0x4C, 0x73, 0xCF)],
    [Rgb::new(0x05, 0x05, 0x05), Rgb::new(0x2E, 0x2E, 0x2E), Rgb::new(0x5C, 0x5C, 0x5C), Rgb::new(0x8F, 0x8F, 0x8F), Rgb::new(0xC4, 0xC4, 0xC4), Rgb::new(0xF4, 0xF4, 0xF4)],
];
/// `TOKEN_GRADIENTS["USDC"]` (`ramp_from(#2775CA)`).
pub const RAMP_USDC: [Rgb; 6] = [Rgb::new(0x06, 0x12, 0x1E), Rgb::new(0x0C, 0x23, 0x3D), Rgb::new(0x14, 0x3A, 0x65), Rgb::new(0x1B, 0x52, 0x8D), Rgb::new(0x22, 0x65, 0xAE), Rgb::new(0x27, 0x75, 0xCA)];
/// `TOKEN_GRADIENTS["USDT"]` (`ramp_from(#50AF95)`).
pub const RAMP_USDT: [Rgb; 6] = [Rgb::new(0x0C, 0x1A, 0x16), Rgb::new(0x18, 0x34, 0x2D), Rgb::new(0x28, 0x58, 0x4A), Rgb::new(0x38, 0x7A, 0x68), Rgb::new(0x45, 0x96, 0x80), Rgb::new(0x50, 0xAF, 0x95)];
/// `TOKEN_GRADIENTS["DAI"]` (`ramp_from(#F5AC37)`).
pub const RAMP_DAI: [Rgb; 6] = [Rgb::new(0x25, 0x1A, 0x08), Rgb::new(0x4A, 0x34, 0x10), Rgb::new(0x7A, 0x56, 0x1C), Rgb::new(0xAC, 0x78, 0x26), Rgb::new(0xD3, 0x94, 0x2F), Rgb::new(0xF5, 0xAC, 0x37)];
/// `ROTATE_GRADIENT`: the gold trail under the black rotation disc (stop 6 = the film colour, never the disc).
pub const RAMP_ROTATE: [Rgb; 6] = [Rgb::new(0x41, 0x3D, 0x2E), Rgb::new(0x51, 0x4B, 0x33), Rgb::new(0x7A, 0x6E, 0x3B), Rgb::new(0xAF, 0x99, 0x2E), Rgb::new(0xDD, 0xC0, 0x19), Rgb::new(0xDD, 0xC0, 0x19)];

/// A six-stop ramp's five followers in the `DiscStyle::trail` order (stop 1
/// … stop 5, like `Rgb::SAFE_TRAIL`).
#[must_use]
pub const fn ramp_trail(r: &[Rgb; 6]) -> [Rgb; 5] {
    [r[0], r[1], r[2], r[3], r[4]]
}

/// `colors.luma` × 1000 (Rec. 709 weights).
#[must_use]
pub const fn luma_milli(c: Rgb) -> u32 {
    (2126 * c.r as u32 + 7152 * c.g as u32 + 722 * c.b as u32) / 2550
}

/// `components.HOLD_DARK_BODY`: a body below this luma is black — the hold
/// film rises white inside it instead of black over it.
const HOLD_DARK_BODY_MILLI: u32 = 150;
/// `colors.CHAIN_DARK_MARK_LUMA`: above this a disc takes a black mark.
const DARK_MARK_LUMA_MILLI: u32 = 620;

/// The mono body (ETH, the blind mark): black disc, white ring and mark,
/// the MONO ramp's grey trail, the film on its brightest stop.
const fn mono_style() -> DiscStyle {
    let r = &PLACEHOLDER_RAMPS[13];
    DiscStyle {
        fill: Rgb::BLACK,
        ring: Rgb::WHITE,
        mark: Rgb::WHITE,
        trail: ramp_trail(r),
        film_white: true,
        film: r[5],
        branded: false,
    }
}

/// A popular token's own colour under its (white) logo mark, on its ramp.
const fn token_style(r: &[Rgb; 6]) -> DiscStyle {
    DiscStyle {
        fill: r[5],
        ring: Rgb::WHITE,
        mark: Rgb::WHITE,
        trail: ramp_trail(r),
        // Logo art darkens (components.hold_style: art never hides a film).
        film_white: false,
        film: r[5],
        branded: false,
    }
}

/// A solid placeholder disc on ramp `i` (`colors.PLACEHOLDER_PALETTES`).
fn tinted_style(i: u8) -> DiscStyle {
    let r = &PLACEHOLDER_RAMPS[usize::from(i.min(N_RAMPS - 1))];
    // The mono entry's disc is black (colors.PLACEHOLDER_PALETTES[MONO_RAMP]).
    let fill = if i == N_RAMPS - 1 { Rgb::BLACK } else { r[5] };
    DiscStyle {
        fill,
        ring: Rgb::WHITE,
        mark: if luma_milli(fill) > DARK_MARK_LUMA_MILLI { Rgb::BLACK } else { Rgb::WHITE },
        trail: ramp_trail(r),
        film_white: luma_milli(fill) < HOLD_DARK_BODY_MILLI,
        film: r[5],
        branded: false,
    }
}

/// The disc look for an icon and its optional placeholder tint.
#[must_use]
pub fn disc_style(icon: Option<Icon>, tint: Option<u8>) -> DiscStyle {
    if let (Some(t), Some(i)) = (tint, icon) {
        if t < N_RAMPS && !matches!(i, Icon::Safe | Icon::Fingerprint | Icon::Chain) {
            return tinted_style(t);
        }
    }
    match icon {
        Some(Icon::Safe) => DiscStyle {
            fill: Rgb::SAFE_FILL,
            ring: Rgb::BLACK,
            mark: Rgb::new(0x12, 0x12, 0x12),
            trail: Rgb::SAFE_TRAIL,
            film_white: false,
            film: Rgb::SAFE_FILL,
            branded: true,
        },
        Some(Icon::Fingerprint) => DiscStyle {
            fill: Rgb::WHITE,
            ring: Rgb::BLACK,
            mark: Rgb::BLACK,
            trail: Rgb::MONO_TRAIL,
            film_white: false,
            film: Rgb::WHITE,
            branded: false,
        },
        Some(Icon::Eth | Icon::Blind) => mono_style(),
        Some(Icon::Usdc) => token_style(&RAMP_USDC),
        Some(Icon::Usdt) => token_style(&RAMP_USDT),
        Some(Icon::Dai) => token_style(&RAMP_DAI),
        // Slot rotation: the rotate mark white on a BLACK body over the gold
        // trail; the film takes stop 6 (colors.ROTATE_GRADIENT).
        Some(Icon::Rotate) => DiscStyle {
            fill: Rgb::BLACK,
            ring: Rgb::WHITE,
            mark: Rgb::WHITE,
            trail: ramp_trail(&RAMP_ROTATE),
            film_white: true,
            film: RAMP_ROTATE[5],
            branded: false,
        },
        _ => DiscStyle {
            fill: Rgb::BLACK,
            ring: Rgb::WHITE,
            mark: Rgb::WHITE,
            trail: Rgb::MONO_TRAIL,
            film_white: true,
            film: Rgb::BLACK,
            branded: false,
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
    pub eth: Option<Mask<'a>>,
    pub usdc: Option<Mask<'a>>,
    pub usdt: Option<Mask<'a>>,
    pub dai: Option<Mask<'a>>,
    pub blind: Option<Mask<'a>>,
    pub rotate: Option<Mask<'a>>,
}

impl<'a> Marks<'a> {
    /// The mark an icon wears (the chain disc picks Base vs the Ethereum
    /// mark from its NETWORK text at the call site).
    #[must_use]
    pub fn for_icon(&self, icon: Option<Icon>) -> Option<Mask<'a>> {
        match icon {
            Some(Icon::Safe) => self.safe,
            Some(Icon::Chain) => self.mainnet,
            Some(Icon::Fingerprint) => self.fingerprint,
            Some(Icon::Eth) => self.eth,
            Some(Icon::Usdc) => self.usdc,
            Some(Icon::Usdt) => self.usdt,
            Some(Icon::Dai) => self.dai,
            Some(Icon::Blind) => self.blind,
            Some(Icon::Rotate) => self.rotate,
            Some(Icon::Wallet | Icon::None) | None => None,
        }
    }
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

/// The status film playing over the disc, if any (DESIGN.md § Status
/// animations): the qubit loading loop that resolves into the result, or
/// the film-less cancel resolve.
#[derive(Clone, Copy, Debug)]
enum Film {
    Qubit {
        film: QubitFilm,
        /// The circle the film was handed (position + visible radius).
        seed: Body,
        /// Known once the work answered.
        outcome: Option<Ending>,
    },
    Resolve {
        film: ResolveFilm,
        outcome: Ending,
    },
}

/// One trail copy every `TRAIL_STEP_TURNS` of orbit: 0.035 turns × 850 ms.
const TRAIL_DT_MS: u32 = 30;

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
    film: Option<Film>,
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
            film: None,
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

    /// Resolve the disc into an ending look with the film-less cancel
    /// resolve (no work was done: the arrived token resolves in place over
    /// one flash beat, then the result holds `RESULT_HOLD_MS`).
    pub fn ending(&mut self, e: Ending, now: u32) {
        self.film = Some(Film::Resolve { film: ResolveFilm::start(now), outcome: e });
        self.leave_flow(now);
    }

    /// Start the qubit loading film (the work is under way): the disc where
    /// it stands becomes the seed, the texts fade, the orbit loops until
    /// [`Self::film_resolve`].
    pub fn film_start(&mut self, now: u32) {
        let seed = Body {
            x: (self.sx.value + self.sweep) >> 8,
            y: self.sy.value >> 8,
            r: (CIRCLE_R << 8) - TOKEN_INSET_Q8,
        };
        self.film = Some(Film::Qubit { film: QubitFilm::start(now), seed, outcome: None });
        self.leave_flow(now);
    }

    /// The work answered: a running qubit film finishes its turn and lands
    /// on `e`; with no film running this is the cancel resolve.
    pub fn film_resolve(&mut self, e: Ending, now: u32) {
        match &mut self.film {
            Some(Film::Qubit { film, outcome, .. }) => {
                film.resolve(now);
                *outcome = Some(e);
            }
            _ => self.ending(e, now),
        }
    }

    /// A film is playing (loading, resolving, or holding its result).
    #[must_use]
    pub fn film_live(&self) -> bool {
        self.film.is_some()
    }

    /// The film has landed its result and held it for `RESULT_HOLD_MS`.
    #[must_use]
    pub fn film_done(&self, now: u32) -> bool {
        match self.film {
            Some(Film::Qubit { film, outcome: Some(_), .. }) => film.done(now),
            Some(Film::Resolve { film, .. }) => film.done(now),
            _ => false,
        }
    }

    fn leave_flow(&mut self, now: u32) {
        self.hold = None;
        self.press = None;
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
        let target = if l.sweep && !moving && self.hold.is_none() && self.film.is_none() {
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
        let ambient = (l.sweep || l.hint || l.band) && self.film.is_none();
        let ending_live = self.film.is_some() && !self.film_done(now);
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
        if self.film.is_some() || self.hold.is_some() || self.settled_at.is_none() || self.flip_at.is_some() {
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
        if l.chev != Chev::None && self.film.is_none() {
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
        if self.film.is_none() {
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
        } else if let Some(film) = self.film {
            // The film's captions: the breathing busy line over the orbit,
            // the resolved caption after the flash.
            let (busy_a, text_a, outcome) = match film {
                Film::Qubit { film, outcome, .. } => {
                    let p = film.pose(now, Body { x: 0, y: 0, r: 0 });
                    (film.busy_alpha(now), p.text_a, outcome)
                }
                Film::Resolve { film, outcome } => (0, film.pose(now).text_a, Some(outcome)),
            };
            let (signed, declined) = ending_captions(&self.cur);
            let caption_of = |e: Ending| -> &[u8] {
                match e {
                    Ending::Signed => signed,
                    Ending::Declined => declined,
                }
            };
            for (text, a_q16) in [(&b"SIGNING"[..], busy_a), (outcome.map_or(&b""[..], caption_of), text_a)] {
                let a = (i64::from(a_q16.clamp(0, ONE_Q16)) * 255 >> 16) as u8;
                if a > 0 && !text.is_empty() {
                    frame.push(Item::Text {
                        run: TextRun {
                            text,
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
            }
        }

        // ---- the disc, its trail, film and ring ---------------------------
        let icon = self.cur.icon();
        let style = disc_style(icon, self.cur.tint());
        let head_x = self.sx.value + self.sweep;
        let cx_q8 = head_x >> 8;
        let cy_q8 = self.sy.value >> 8;
        let visible_r = (CIRCLE_R << 8) - TOKEN_INSET_Q8;
        if let Some(film) = self.film {
            self.build_film(frame, marks, &style, icon, film, now);
            let _ = font;
            return;
        }
        let has_disc = l.circle.is_some() || !self.sx.settled();
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
            {
                {
                    frame.push(Item::Disc { cx: cx_q8, cy: cy_q8, r: visible_r, color: style.fill });
                    let mark = match icon {
                        // The chain mark follows the proven NETWORK text: Base
                        // gets its own mark, everything else the Ethereum one.
                        Some(Icon::Chain) => {
                            if self.cur.line(self.cur_page, 0).is_some_and(|(_, t)| t == b"Base" || t.ends_with(b" Base")) {
                                marks.base.or(marks.mainnet)
                            } else {
                                marks.mainnet
                            }
                        }
                        other => marks.for_icon(other),
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
            }
        }
        let _ = font;
    }

    /// The resting look an ending lands on: (fill, ring, mark colour).
    /// A branded family fills the disc (Safe: `#13FF7F` / the shared red
    /// cancel disc, black stroke, black mark); an unbranded one keeps the
    /// black disc and strokes ring + result mark in the state colour.
    fn resting(e: Ending, branded: bool) -> (Rgb, Rgb, Rgb) {
        match (e, branded) {
            (Ending::Signed, true) => (Rgb::SAFE_FILL, Rgb::BLACK, Rgb::BLACK),
            (Ending::Declined, true) => (Rgb::RED, Rgb::BLACK, Rgb::BLACK),
            (Ending::Signed, false) => (Rgb::BLACK, Rgb::GREEN, Rgb::GREEN),
            (Ending::Declined, false) => (Rgb::BLACK, Rgb::RED, Rgb::RED),
        }
    }

    fn push_result(frame: &mut Frame<'_>, e: Ending, cx: Q8, cy: Q8, r: Q8, mark_c: Rgb, k: Q16) {
        if k > 0 {
            match e {
                Ending::Signed => frame.push(Item::Check { cx, cy, r, color: mark_c, k }),
                Ending::Declined => frame.push(Item::Cross { cx, cy, r, color: mark_c, k }),
            };
        }
    }

    /// The status film over the disc (DESIGN.md § Status animations).
    fn build_film<'a>(&self, frame: &mut Frame<'a>, marks: &Marks<'a>, style: &DiscStyle, icon: Option<Icon>, film: Film, now: u32) {
        let visible_r = (CIRCLE_R << 8) - TOKEN_INSET_Q8;
        let mark = marks.for_icon(icon);
        match film {
            Film::Resolve { film, outcome } => {
                // The arrived disc crossfades to the result look over the
                // flash beat; the flash ring fires in the state colour; the
                // mark draws in after.
                let p = film.pose(now);
                let cx = self.sx.value >> 8;
                let cy = self.sy.value >> 8;
                let (fill, ring, mark_c) = Self::resting(outcome, style.branded);
                let state = match outcome {
                    Ending::Signed => Rgb::GREEN,
                    Ending::Declined => Rgb::RED,
                };
                let r = lerp(visible_r, CIRCLE_R << 8, p.u);
                frame.push(Item::Disc { cx, cy, r, color: blend_rgb(style.fill, fill, p.u) });
                if let (Some(m), true) = (mark, p.glyph_a > 0) {
                    frame.push(Item::Mask { cx, cy, mask: m, scale: ONE_Q8, color: style.mark, a: p.glyph_a });
                }
                frame.push(Item::Ring { cx, cy, r, w: TOKEN_RING_W_Q8, color: blend_rgb(style.ring, ring, p.u) });
                if p.flash_a > 0 {
                    frame.push(Item::Ring { cx, cy, r: p.flash_r, w: (2 << 8) + 128, color: state.scale(p.flash_a) });
                }
                Self::push_result(frame, outcome, cx, cy, r, mark_c, p.check_k);
            }
            Film::Qubit { film, seed, outcome } => {
                let p = film.pose(now, seed);
                let cx = loading::GC_X_Q8;
                let cy = loading::GC_Y_Q8;
                match p.phase {
                    Phase::Seed => {
                        let b = p.bodies[0];
                        frame.push(Item::Disc { cx: b.x, cy: b.y, r: b.r, color: style.fill });
                        if let (Some(m), true) = (mark, p.glyph_a > 0) {
                            let scale = ((i64::from(b.r) << 8) / i64::from(visible_r.max(1))) as Q8;
                            frame.push(Item::Mask { cx: b.x, cy: b.y, mask: m, scale, color: style.mark, a: p.glyph_a });
                        }
                        if p.glyph_a > 0 {
                            frame.push(Item::Ring { cx: b.x, cy: b.y, r: b.r, w: TOKEN_RING_W_Q8, color: style.ring.scale(p.glyph_a) });
                        }
                    }
                    Phase::Split | Phase::Join | Phase::Orbit | Phase::Spiral => {
                        // Trail: past poses behind each qubit, farthest first.
                        let ft = film.film_t(now);
                        for k in (1..=TRAIL_COUNT).rev() {
                            let back = k * TRAIL_DT_MS;
                            if ft < loading::T2 + back {
                                continue;
                            }
                            let q = loading::qubit_pose(ft - back, seed);
                            if !matches!(q.phase, Phase::Split | Phase::Join | Phase::Orbit | Phase::Spiral) {
                                continue;
                            }
                            let c = style.trail[(k as usize - 1).min(4)];
                            for b in &q.bodies[..usize::from(q.n)] {
                                frame.push(Item::Disc { cx: b.x, cy: b.y, r: b.r, color: c });
                            }
                        }
                        for b in &p.bodies[..usize::from(p.n)] {
                            frame.push(Item::Disc { cx: b.x, cy: b.y, r: b.r, color: style.film });
                        }
                    }
                    Phase::Flash | Phase::Result => {
                        let e = outcome.unwrap_or(Ending::Declined);
                        let (fill, ring, mark_c) = Self::resting(e, style.branded);
                        let state = match e {
                            Ending::Signed => Rgb::GREEN,
                            Ending::Declined => Rgb::RED,
                        };
                        let b = p.bodies[0];
                        let u = if p.phase == Phase::Flash { motion::ease_out(motion::phase(ft_of(&film, now), loading::T6, loading::QUBIT_T_FLASH)) } else { ONE_Q16 };
                        frame.push(Item::Disc { cx, cy, r: b.r, color: blend_rgb(style.film, fill, u) });
                        frame.push(Item::Ring { cx, cy, r: b.r, w: TOKEN_RING_W_Q8, color: blend_rgb(style.ring, ring, u) });
                        if p.flash_a > 0 {
                            frame.push(Item::Ring { cx, cy, r: p.flash_r, w: (2 << 8) + 128, color: state.scale(p.flash_a) });
                        }
                        Self::push_result(frame, e, cx, cy, b.r, mark_c, p.check_k);
                    }
                }
            }
        }
    }
}

/// The endings' captions a film status screen carries: line 0 = the signed
/// caption, line 1 = the declined caption. A screen without them (the Safe
/// flow, a hero the cancel resolves on) gets the Safe family's captions.
#[must_use]
pub fn ending_captions(s: &Screen) -> (&[u8], &[u8]) {
    const SIGNED: &[u8] = b"SIGNED SAFE TX";
    const DECLINED: &[u8] = b"SAFE TX DECLINED";
    if s.kind() != Some(Kind::Status) {
        return (SIGNED, DECLINED);
    }
    match (s.line(0, 0), s.line(0, 1)) {
        (Some((_, a)), Some((_, b))) if !a.is_empty() && !b.is_empty() => (a, b),
        _ => (SIGNED, DECLINED),
    }
}

fn ft_of(film: &QubitFilm, now: u32) -> u32 {
    film.film_t(now)
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

    #[test]
    fn ramp_table_matches_the_reference_palette() {
        // Spot values from tools/pq-ui/pq1/colors.py (PLACEHOLDER_GRADIENTS,
        // TOKEN_GRADIENTS via ramp_from, ROTATE_GRADIENT).
        assert_eq!(PLACEHOLDER_RAMPS[0][5], Rgb::new(0x8A, 0x75, 0x00));
        assert_eq!(PLACEHOLDER_RAMPS[1][0], Rgb::new(0x64, 0x12, 0x20));
        assert_eq!(PLACEHOLDER_RAMPS[10][5], Rgb::new(0x6A, 0x6B, 0x70));
        assert_eq!(PLACEHOLDER_RAMPS[13][5], Rgb::new(0xF4, 0xF4, 0xF4));
        assert_eq!(RAMP_USDC[5], Rgb::new(0x27, 0x75, 0xCA));
        assert_eq!(RAMP_USDT[5], Rgb::new(0x50, 0xAF, 0x95));
        assert_eq!(RAMP_DAI[5], Rgb::new(0xF5, 0xAC, 0x37));
        assert_eq!(RAMP_DAI[0], Rgb::new(0x25, 0x1A, 0x08));
        assert_eq!(RAMP_ROTATE[4], Rgb::new(0xDD, 0xC0, 0x19));
        // luma: Rec. 709 on 0..255.
        assert_eq!(luma_milli(Rgb::WHITE), 1000);
        assert_eq!(luma_milli(Rgb::BLACK), 0);
    }

    #[test]
    fn disc_styles_per_family() {
        let safe = disc_style(Some(Icon::Safe), None);
        assert!(safe.branded && safe.fill == Rgb::SAFE_FILL && safe.trail == Rgb::SAFE_TRAIL);
        // A tint never re-dresses the Safe disc.
        assert_eq!(disc_style(Some(Icon::Safe), Some(3)).fill, Rgb::SAFE_FILL);
        for icon in [Icon::Eth, Icon::Blind] {
            let m = disc_style(Some(icon), None);
            assert!(!m.branded && m.fill == Rgb::BLACK && m.ring == Rgb::WHITE && m.mark == Rgb::WHITE);
            assert!(m.film_white);
            assert_eq!(m.film, PLACEHOLDER_RAMPS[13][5], "no black-on-black qubits");
            assert_eq!(m.trail, ramp_trail(&PLACEHOLDER_RAMPS[13]));
        }
        for (icon, ramp) in [(Icon::Usdc, RAMP_USDC), (Icon::Usdt, RAMP_USDT), (Icon::Dai, RAMP_DAI)] {
            let t = disc_style(Some(icon), None);
            assert_eq!((t.fill, t.ring, t.mark), (ramp[5], Rgb::WHITE, Rgb::WHITE));
            assert_eq!(t.trail, ramp_trail(&ramp));
            assert!(!t.film_white && !t.branded);
        }
        let r = disc_style(Some(Icon::Rotate), None);
        assert_eq!((r.fill, r.mark, r.film), (Rgb::BLACK, Rgb::WHITE, RAMP_ROTATE[5]));
        assert_eq!(r.trail, ramp_trail(&RAMP_ROTATE));
        for i in 0..N_RAMPS {
            let t = disc_style(Some(Icon::Eth), Some(i));
            let ramp = &PLACEHOLDER_RAMPS[usize::from(i)];
            assert_eq!(t.trail, ramp_trail(ramp));
            assert_eq!(t.film, ramp[5]);
            if i == N_RAMPS - 1 {
                assert_eq!(t.fill, Rgb::BLACK, "the mono entry fills black");
                assert!(t.film_white);
            } else {
                assert_eq!(t.fill, ramp[5]);
                assert!(!t.film_white, "ramp {i}: a coloured body darkens");
                assert_eq!(t.mark, Rgb::WHITE);
            }
        }
    }

    #[test]
    fn every_icon_maps_to_its_mark() {
        let m = |b: u8| Some(Mask { w: 2, h: 2, rows: if b == 0 { &[0x10, 0] } else { &[0x20, 0] } });
        let marks = Marks {
            safe: m(1),
            mainnet: m(1),
            base: None,
            fingerprint: None,
            eth: m(1),
            usdc: m(1),
            usdt: m(1),
            dai: m(1),
            blind: m(1),
            rotate: m(1),
        };
        for icon in [Icon::Safe, Icon::Chain, Icon::Eth, Icon::Usdc, Icon::Usdt, Icon::Dai, Icon::Blind, Icon::Rotate] {
            assert!(marks.for_icon(Some(icon)).is_some(), "{icon:?}");
        }
        assert!(marks.for_icon(Some(Icon::None)).is_none());
        assert!(marks.for_icon(Some(Icon::Wallet)).is_none());
        assert!(marks.for_icon(Some(Icon::Fingerprint)).is_none());
    }

    #[test]
    fn ending_captions_come_from_the_film_screen() {
        assert_eq!(ending_captions(&hero()), (&b"SIGNED SAFE TX"[..], &b"SAFE TX DECLINED"[..]));
        let film = ScreenBuilder::status(b"SIGN", Icon::Eth, b"", State::Awaiting, ResultMark::None)
            .line(b"TRANSFER SUCCESSFUL", Weight::Regular)
            .line(b"TRANSFER DECLINED", Weight::Regular)
            .finish()
            .unwrap();
        assert_eq!(ending_captions(&film), (&b"TRANSFER SUCCESSFUL"[..], &b"TRANSFER DECLINED"[..]));
        let bare = ScreenBuilder::status(b"SIGN", Icon::Safe, b"", State::Awaiting, ResultMark::None).finish().unwrap();
        assert_eq!(ending_captions(&bare).0, b"SIGNED SAFE TX");
        // Resting looks: brand fills, the rest strokes in the state colour.
        assert_eq!(Anim::resting(Ending::Signed, true).0, Rgb::SAFE_FILL);
        assert_eq!(Anim::resting(Ending::Declined, true).0, Rgb::RED);
        assert_eq!(Anim::resting(Ending::Signed, false), (Rgb::BLACK, Rgb::GREEN, Rgb::GREEN));
        assert_eq!(Anim::resting(Ending::Declined, false), (Rgb::BLACK, Rgb::RED, Rgb::RED));
    }
}
