//! Verdict screens (DESIGN.md § Verdict screens): a procedural sign states a
//! fact — LOCKED, WRONG PIN, WALLET WIPED — then the caption names it.
//!
//! The registry is the sign byte of a `Kind::Verdict` record
//! ([`Icon::Lock`] … [`Icon::Verified`]); this module owns each sign's art
//! (outlines baked from the vendored `pq1/procedural/` modules into
//! [`crate::verdict_geom`]), its timeline (`pq1/verdict.py` + the screen's
//! own mechanism) and its pose at `t` ms after the screen arrived. Pure
//! function of `t`, like every other screen here.
//!
//! The common law: black hold → the sign fades in and rises 0.97 → 1 over
//! `ARRIVE_MS` (ease-out, never an overshoot) → the mechanism on the arrived
//! sign → the caption fades in over 300 ms. Mechanisms ported: the padlock
//! turning in and clicking shut / snapping open, the attention pulses (alert,
//! wipe), the shield's nod and wiggle, the PIN pill filling, turning and
//! shaking, the result ring's head shake, the gear's coast. Deviations
//! (`tools/pq-ui/PORT_DEVIATIONS.toml`): the die rests (no tumble), the wipe
//! brush does not swiffle (the pulse treatment), no lead films.

use crate::fixed::{clamp01, cos_turns_q16, exp_neg_q16, lerp, mul_q16, sin_turns_q16, Q16, Q8, ONE_Q16, ONE_Q8};
use crate::motion::{self, ease, ease_out, phase, ARRIVE_MS};
use crate::raster::{Frame, Item, Rgb, ShapeMode, Xform};
use crate::scene::{state_color, CENTER_X, CIRCLE_CY, CIRCLE_R, COL_LEFT_CX, COL_RIGHT_CX, TOKEN_RING_W_Q8};
use crate::screen::{Icon, Kind, ResultMark, Screen, Side, State};
use crate::verdict_geom as g;

/// `colors.FACTORY_BLUE` — the factory gear's own colour.
pub const FACTORY_BLUE: Rgb = Rgb::new(74, 159, 240);

/// A verdict's phases (ms): black hold, the sign's window (entrance, and
/// for the padlock the whole mechanism), the wait (mechanism + beat), the
/// caption fade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeline {
    pub hold: u32,
    pub sign: u32,
    pub wait: u32,
    pub text: u32,
}

impl Timeline {
    const fn new(hold: u32, sign: u32, wait: u32) -> Self {
        Self { hold, sign, wait, text: 300 }
    }

    /// When the caption has landed and the screen rests.
    #[must_use]
    pub const fn resolve(&self) -> u32 {
        self.hold + self.sign + self.wait + self.text
    }

    /// When the caption starts fading in.
    #[must_use]
    pub const fn caption_at(&self) -> u32 {
        self.hold + self.sign + self.wait
    }
}

// Mechanism windows (the screens' own constants).
const LOCK_TURN: u32 = 520;
const LOCK_DROP: u32 = 260;
const LOCK_CLICK: u32 = 290;
const UNLOCK_SNAP: u32 = 145;
const UNLOCK_KICK: u32 = 250;
const UNLOCK_PAUSE: u32 = 250;
const UNLOCK_TURN_OUT: u32 = 800;
const OPEN_LIFT_Q8: Q8 = 9 << 8;
const KICK_Q8: Q8 = 10 << 8;
const BEAT: u32 = 450;
const PULSES: u32 = 900;
const WIPE_MARK: u32 = 300;
const NOD: u32 = 700;
const WIGGLE: u32 = 420;
const PILL_FILL: u32 = 200;
const PILL_FILLED: u32 = 200;
const PILL_TURN: u32 = 200;
const PILL_SHAKE: u32 = 420;
const PILL_BEAT: u32 = 200;
const GEAR_SPIN: u32 = 1800;
const HEART_REST: u32 = 400;
const HEARTBEAT: u32 = 700;

/// The timeline of a verdict record (a non-verdict gets the default law).
#[must_use]
pub fn timeline(s: &Screen) -> Timeline {
    let docked = matches!(s.side(), Some(Side::Left | Side::Right));
    match s.icon() {
        Some(Icon::Lock) => Timeline::new(500, LOCK_TURN + LOCK_DROP + LOCK_CLICK, 0),
        Some(Icon::Unlock) => Timeline::new(500, ARRIVE_MS + UNLOCK_KICK + UNLOCK_PAUSE + UNLOCK_TURN_OUT, 0),
        Some(Icon::Alert) => Timeline::new(350, ARRIVE_MS, PULSES),
        Some(Icon::Wipe) => Timeline::new(400, ARRIVE_MS, WIPE_MARK + PULSES),
        Some(Icon::Shield) if s.result() == Some(ResultMark::Check) => Timeline::new(400, ARRIVE_MS, NOD + BEAT),
        Some(Icon::Shield) => Timeline::new(400, ARRIVE_MS, WIGGLE + BEAT),
        Some(Icon::Pill) if s.state() == Some(State::Awaiting) => Timeline::new(250, ARRIVE_MS, PILL_FILL),
        Some(Icon::Pill) => Timeline::new(250, ARRIVE_MS, PILL_FILL + PILL_FILLED + PILL_TURN + PILL_SHAKE + PILL_BEAT),
        Some(Icon::ResultRing) if s.result() == Some(ResultMark::Cross) => Timeline::new(400, ARRIVE_MS, WIGGLE + BEAT),
        Some(Icon::Gear) => Timeline::new(400, ARRIVE_MS, GEAR_SPIN),
        Some(Icon::Heart) => Timeline::new(400, ARRIVE_MS, HEART_REST + HEARTBEAT),
        _ if docked => Timeline::new(350, ARRIVE_MS, PULSES),
        _ => Timeline::new(400, ARRIVE_MS, BEAT),
    }
}

/// Caption alpha (Q16) at `t`.
#[must_use]
pub fn caption_alpha(s: &Screen, t: u32) -> Q16 {
    let tl = timeline(s);
    ease_out(phase(t, tl.caption_at(), tl.text))
}

/// Whether the verdict is still moving at `t`.
#[must_use]
pub fn live(s: &Screen, t: u32) -> bool {
    s.kind() == Some(Kind::Verdict) && t < timeline(s).resolve()
}

// ---- small curves -----------------------------------------------------------

/// `sin(2π·cycles·u)·(1 − u)` — the decaying error shake, unit amplitude.
fn shake(u: Q16, cycles: i32) -> Q16 {
    let u = clamp01(u);
    mul_q16(sin_turns_q16(u.wrapping_mul(cycles)), ONE_Q16 - u)
}

/// `sin(π·u)·(1 − u)` — the click recoil.
fn recoil(u: Q16) -> Q16 {
    let u = clamp01(u);
    mul_q16(sin_turns_q16(u / 2), ONE_Q16 - u)
}

/// `1 + 0.09·e^(−3v)·|sin(2.5π·v)|` — the attention pulse.
fn attention_pulse(v: Q16) -> Q16 {
    let v = clamp01(v);
    let e = exp_neg_q16(3 * v);
    let s = sin_turns_q16(v + v / 4).abs(); // 1.25 turns · v
    ONE_Q16 + mul_q16(mul_q16(5898, e), s) // 0.09
}

/// `1 + 0.22·e^(−4u)·|sin(3π·u)|` — the heart's decaying pump train.
fn heartbeat(u: Q16) -> Q16 {
    let u = clamp01(u);
    let e = exp_neg_q16(4 * u);
    let s = sin_turns_q16(u + u / 2).abs(); // 1.5 turns · u
    ONE_Q16 + mul_q16(mul_q16(14_418, e), s) // 0.22
}

/// `(1 − e^(−4.2u)) / (1 − e^(−4.2))` — the coasting spin-down.
fn freewheel(u: Q16) -> Q16 {
    let u = clamp01(u);
    let k: Q16 = 275_251; // 4.2
    let num = ONE_Q16 - exp_neg_q16(mul_q16(k, u));
    let den = ONE_Q16 - exp_neg_q16(k);
    ((i64::from(num) << 16) / i64::from(den.max(1))) as Q16
}

/// `v · k` for a Q8 length and a Q16 factor.
fn sc(v: Q8, k: Q16) -> Q8 {
    ((i64::from(v) * i64::from(k)) >> 16) as Q8
}

/// A Q16 scale as the transform's Q8 factor.
fn k8(k: Q16) -> i16 {
    (k >> 8).clamp(0, i32::from(i16::MAX)) as i16
}

fn px(v: i32) -> Q8 {
    v << 8
}

/// `v` tenths of a pixel in Q8.
const fn tenths(v: i32) -> Q8 {
    v * 256 / 10
}

// ---- the sign ---------------------------------------------------------------

/// Draw the verdict's sign at `t` ms after arrival.
pub fn build_sign(s: &Screen, t: u32, frame: &mut Frame<'_>) {
    let Some(icon) = s.icon() else { return };
    let tl = timeline(s);
    if t < tl.hold {
        return;
    }
    let tm = t - tl.hold; // the sign's clock
    let (a_q16, mut k) = motion::arrive(phase(tm, 0, ARRIVE_MS));
    let a = ((i64::from(a_q16) * 255) >> 16) as u8;
    if a == 0 {
        return;
    }
    let state = s.state();
    let color = match icon {
        Icon::Gear => FACTORY_BLUE,
        _ => state_color(state),
    };
    let col = color.scale(a);
    let black = Rgb::BLACK;
    let (cx, cy) = match s.side() {
        Some(Side::Left) => (px(COL_LEFT_CX), px(CIRCLE_CY)),
        Some(Side::Right) => (px(COL_RIGHT_CX), px(CIRCLE_CY)),
        _ => (px(CENTER_X), px(CIRCLE_CY)),
    };
    // The mechanism clock starts on the arrived sign.
    let m = tm.saturating_sub(ARRIVE_MS);
    let wait_u = phase(m, 0, tl.wait);
    match icon {
        Icon::Alert => {
            if tm >= ARRIVE_MS && m < tl.wait {
                k = attention_pulse(wait_u);
            }
            // 64 px on the circle grid, 60 in a detail column (sig_error).
            let h: Q16 = if matches!(s.side(), Some(Side::Left | Side::Right)) { 61_440 } else { ONE_Q16 };
            alert(frame, cx, cy, mul_q16(k, h), col, black);
        }
        Icon::Wipe => {
            if m >= WIPE_MARK && m < WIPE_MARK + PULSES {
                k = attention_pulse(phase(m, WIPE_MARK, PULSES));
            }
            triangle(frame, cx, cy, k, col);
            let bx = Xform::at(cx, cy + sc(px(9), k)).scaled(k8(k));
            frame.push(Item::Shape { pts: &g::BRUSH_BODY, xf: bx, mode: ShapeMode::Fill { grow: 0 }, color: black, a: 255 });
            frame.push(Item::Shape { pts: &g::BRUSH_BRISTLES, xf: bx, mode: ShapeMode::Fill { grow: 0 }, color: black, a: 255 });
        }
        Icon::Lock | Icon::Unlock => {
            let pose = if icon == Icon::Lock { lock_pose(tm) } else { unlock_pose(tm) };
            padlock(frame, cx, cy, k, col, pose);
        }
        Icon::Shield => {
            let check = s.result() == Some(ResultMark::Check);
            let (mut x, mut y) = (cx, cy);
            if check && m < NOD {
                y += sc(px(5), shake(phase(m, 0, NOD), 1));
            } else if !check && m < WIGGLE {
                x += sc(px(6), shake(phase(m, 0, WIGGLE), 1));
            }
            // 62 px tall (the design box is 63): stroke 3 px at 63.
            let kh = mul_q16(k, 64_496);
            frame.push(Item::Shape {
                pts: &g::SHIELD,
                xf: Xform::at(x, y).scaled(k8(kh)),
                mode: ShapeMode::Loop { hw: sc(tenths(15), kh) as i16 },
                color: col,
                a: 255,
            });
            let my = y - sc(px(2), k);
            match s.result() {
                Some(ResultMark::Check) => frame.push(Item::Check { cx: x, cy: my, r: sc(px(25), k), color: col, k: ONE_Q16 }),
                Some(ResultMark::Cross) => frame.push(Item::Cross { cx: x, cy: my, r: sc(7_253, k), color: col, k: ONE_Q16 }),
                // The bare shield (WRITE DOWN 24 WORDS): the backup, no verdict yet.
                _ => true,
            };
        }
        Icon::Pill => {
            let checking = state == Some(State::Awaiting);
            let fill = ease(phase(m, 0, PILL_FILL));
            let turn = if checking { 0 } else { ease(phase(m, PILL_FILL + PILL_FILLED, PILL_TURN)) };
            let pc = blend(Rgb::WHITE, color, turn).scale(a);
            let mut x = cx;
            let shake_at = PILL_FILL + PILL_FILLED + PILL_TURN;
            if !checking && m >= shake_at && m < shake_at + PILL_SHAKE {
                x += sc(px(7), shake(phase(m, shake_at, PILL_SHAKE), 2));
            }
            frame.push(Item::Shape {
                pts: &g::PILL,
                xf: Xform::at(x, cy).scaled(k8(k)),
                mode: ShapeMode::Rim { r: sc(tenths(167), k) as i16, hw: sc(tenths(13), k) as i16 },
                color: pc,
                a: 255,
            });
            let da = ((i64::from(fill) * 255) >> 16) as u8;
            if da > 0 {
                for i in 0..4 {
                    let dx = sc(px(24), k) * (2 * i - 3) / 2;
                    frame.push(Item::Disc { cx: x + dx, cy, r: sc(px(8), k), color: pc.scale(da) });
                }
            }
        }
        Icon::ResultRing => {
            let cross = s.result() == Some(ResultMark::Cross);
            let mut x = cx;
            if cross && m < WIGGLE {
                x += sc(px(6), shake(phase(m, 0, WIGGLE), 1));
            }
            let r = sc(px(CIRCLE_R), k);
            frame.push(Item::Disc { cx: x, cy, r, color: black });
            frame.push(Item::Ring { cx: x, cy, r: r - sc(tenths(12), k), w: TOKEN_RING_W_Q8, color: col });
            if cross {
                frame.push(Item::Cross { cx: x, cy, r, color: col, k: ONE_Q16 });
            } else {
                frame.push(Item::Check { cx: x, cy, r, color: col, k: ONE_Q16 });
            }
        }
        Icon::Verified => {
            // The FIRMWARE VERIFIED look: the white disc, black flush ring,
            // black check (status.branded_resting(WHITE)).
            let r = sc(px(CIRCLE_R), k);
            frame.push(Item::Disc { cx, cy, r, color: Rgb::WHITE.scale(a) });
            frame.push(Item::Ring { cx, cy, r, w: TOKEN_RING_W_Q8, color: black });
            frame.push(Item::Check { cx, cy, r, color: black, k: ONE_Q16 });
        }
        Icon::Die => {
            let xf = Xform::at(cx, cy).scaled(k8(k));
            let grow = sc(tenths(35), k) as i16;
            let hw = sc(px(1), k) as i16;
            for face in [&g::DIE_FACE_1[..], &g::DIE_FACE_2[..], &g::DIE_FACE_3[..]] {
                frame.push(Item::Shape { pts: face, xf, mode: ShapeMode::Fill { grow }, color: col, a: 255 });
                frame.push(Item::Shape { pts: face, xf, mode: ShapeMode::Rim { r: grow, hw }, color: black, a: 255 });
            }
            for pip in g::DIE_PIPS {
                frame.push(Item::Shape { pts: pip, xf, mode: ShapeMode::Fill { grow: 0 }, color: black, a: 255 });
            }
        }
        Icon::Gear => {
            // Arrives spinning, coasts one turn to a tooth-aligned stop.
            let spin = freewheel(phase(tm, 0, ARRIVE_MS + GEAR_SPIN));
            let rot = spin as u32; // one full turn = 65536 wraps to 0
            let body = sc(tenths(256), k);
            frame.push(Item::Disc { cx, cy, r: body, color: col });
            for i in 0..8u32 {
                let r16 = (rot.wrapping_add(i * 8192) & 0xFFFF) as u16;
                frame.push(Item::Shape {
                    pts: &g::GEAR_TOOTH,
                    xf: Xform::at(cx, cy).scaled(k8(k)).turned(r16),
                    mode: ShapeMode::Fill { grow: sc(tenths(26), k) as i16 },
                    color: col,
                    a: 255,
                });
            }
            frame.push(Item::Disc { cx, cy, r: sc(tenths(141), k), color: black });
        }
        Icon::Heart => {
            // The counter's 1 (sign art: the 36 px face, the largest baked)
            // and the heart beside it, the pair centred on the grid; the
            // heart pumps once the count has been read.
            let beat = if m >= HEART_REST { heartbeat(phase(m, HEART_REST, HEARTBEAT)) } else { ONE_Q16 };
            frame.push(Item::Text {
                run: crate::font::TextRun {
                    text: b"1",
                    tier: crate::font::TierId::regular(36),
                    x: (cx + sc(tenths(-225), k)) >> 8,
                    y: (cy >> 8) - 1,
                    align: crate::font::Align::Center,
                    baseline: false,
                    ls_q6: 0,
                    alpha: 255,
                },
                color: col,
            });
            frame.push(Item::Shape {
                pts: &g::HEART,
                xf: Xform::at(cx + sc(tenths(115), k), cy).scaled(k8(mul_q16(k, beat))),
                mode: ShapeMode::Fill { grow: 0 },
                color: col,
                a: 255,
            });
        }
        _ => {}
    }
}

fn blend(a: Rgb, b: Rgb, t: Q16) -> Rgb {
    let ch = |x: u8, y: u8| lerp(i32::from(x), i32::from(y), t).clamp(0, 255) as u8;
    Rgb::new(ch(a.r, b.r), ch(a.g, b.g), ch(a.b, b.b))
}

/// The rounded warning triangle, `k` = height / 64 px.
fn triangle(frame: &mut Frame<'_>, cx: Q8, cy: Q8, k: Q16, col: Rgb) {
    frame.push(Item::Shape {
        pts: &g::TRIANGLE,
        xf: Xform::at(cx, cy).scaled(k8(k)),
        mode: ShapeMode::Fill { grow: sc(px(6), k) as i16 },
        color: col,
        a: 255,
    });
}

/// The triangle carrying its black exclamation (tamper, sig_error).
fn alert(frame: &mut Frame<'_>, cx: Q8, cy: Q8, k: Q16, col: Rgb, mark: Rgb) {
    triangle(frame, cx, cy, k, col);
    frame.push(Item::Shape {
        pts: &g::EXCLAMATION_BAR,
        xf: Xform::at(cx, cy).scaled(k8(k)),
        mode: ShapeMode::Stroke { hw: sc(px(2), k) as i16 },
        color: mark,
        a: 255,
    });
    frame.push(Item::Disc { cx, cy: cy + sc(tenths(195), k), r: sc(tenths(28), k), color: mark });
}

/// The padlock rig's pose: shackle spin (Q16 turns, 0 = seated, ½ = open
/// mirrored), lift and body drop (Q8 px), click recoil (Q16).
#[derive(Clone, Copy, Debug)]
struct LockPose {
    spin: Q16,
    lift: Q8,
    drop: Q8,
    recoil: Q16,
}

fn lock_pose(tm: u32) -> LockPose {
    LockPose {
        spin: (ONE_Q16 - ease(phase(tm, 0, LOCK_TURN))) / 2,
        lift: sc(OPEN_LIFT_Q8, ONE_Q16 - ease_out(phase(tm, LOCK_TURN, LOCK_DROP))),
        drop: 0,
        recoil: recoil(phase(tm, LOCK_TURN + LOCK_DROP, LOCK_CLICK)),
    }
}

fn unlock_pose(tm: u32) -> LockPose {
    let ts = tm.saturating_sub(ARRIVE_MS);
    let started = tm >= ARRIVE_MS;
    LockPose {
        spin: ease(phase(ts, UNLOCK_KICK + UNLOCK_PAUSE, UNLOCK_TURN_OUT)) / 2,
        lift: if started { sc(OPEN_LIFT_Q8, ease_out(phase(ts, 0, UNLOCK_SNAP))) } else { 0 },
        drop: if started { sc(KICK_Q8, recoil(phase(ts, 0, UNLOCK_KICK))) } else { 0 },
        recoil: 0,
    }
}

/// `padlock.draw` with (cx, cy) at the closed composite's optical centre.
fn padlock(frame: &mut Frame<'_>, cx: Q8, cy: Q8, f: Q16, col: Rgb, p: LockPose) {
    let body_r = sc(px(21), f);
    let rest_y = cy + sc(tenths(65) + sc(tenths(7), p.recoil), f);
    let body_y = rest_y + p.drop;
    let eff = p.lift - sc(sc(tenths(9), p.recoil), f);
    let seat_y = rest_y - body_r + sc(px(3), f) - eff;
    let tail = sc(px(8), f).max(body_y - body_r + sc(px(2), f) - seat_y);
    let arm = sc(tenths(115), f);
    let leg_y = sc(tenths(135), f);
    let hw = sc(tenths(27), f) as i16;
    // z-spin about the right (seated) leg: x' = pivot + (x − pivot)·cos.
    let mut c = cos_turns_q16(p.spin);
    if c.abs() < 3_932 {
        c = if c < 0 { -3_932 } else { 3_932 }; // never fully edge-on (0.06)
    }
    let kx = (c >> 4) as i16; // Q16 → Q12
    let pivot_x = cx + arm;
    let top = seat_y - leg_y;
    frame.push(Item::Shape {
        pts: &g::SHACKLE_ARCH,
        xf: Xform::at(pivot_x, top).scaled(k8(f)).squeezed(kx),
        mode: ShapeMode::Stroke { hw },
        color: col,
        a: 255,
    });
    // The free leg: from the arch's left end down to the raised tip.
    let free_x = pivot_x + sc(-2 * arm, c);
    let free_len = leg_y - sc(eff.max(0), 26_214); // 0.4 · lift
    leg(frame, free_x, top, free_len, hw, col);
    // The pivot leg runs behind the body into the disc.
    leg(frame, pivot_x, top, leg_y + tail, hw, col);
    // Body: the black halo (the legs pass behind), the disc, the keyhole.
    frame.push(Item::Disc { cx, cy: body_y, r: body_r + sc(tenths(26), f), color: Rgb::BLACK });
    frame.push(Item::Disc { cx, cy: body_y, r: body_r, color: col });
    frame.push(Item::Disc { cx, cy: body_y - sc(tenths(35), f), r: sc(tenths(46), f), color: Rgb::BLACK });
    frame.push(Item::Shape {
        pts: &g::KEYHOLE_SLOT,
        xf: Xform::at(cx, body_y).scaled(k8(f)),
        mode: ShapeMode::Fill { grow: 0 },
        color: Rgb::BLACK,
        a: 255,
    });
}

/// A vertical shackle leg of `len` (Q8) hanging from `(x, y)`.
fn leg(frame: &mut Frame<'_>, x: Q8, y: Q8, len: Q8, hw: i16, col: Rgb) {
    if len <= 0 {
        return;
    }
    frame.push(Item::Shape {
        pts: &g::UNIT_LEG,
        xf: Xform::at(x, y).scaled(len.min(i32::from(i16::MAX)) as i16),
        mode: ShapeMode::Stroke { hw },
        color: col,
        a: 255,
    });
}

/// `ONE_Q8` is used by the tests below; keep the import honest.
const _: Q8 = ONE_Q8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::ScreenBuilder;

    fn verdict(icon: Icon, state: State, result: ResultMark) -> Screen {
        ScreenBuilder::verdict(b"V", icon, b"CAPTION", state, result).finish().unwrap()
    }

    #[test]
    fn timelines_follow_the_design() {
        assert_eq!(timeline(&verdict(Icon::Lock, State::Failed, ResultMark::None)).resolve(), 500 + 1070 + 300);
        assert_eq!(timeline(&verdict(Icon::Unlock, State::Done, ResultMark::None)).resolve(), 500 + 1600 + 300);
        assert_eq!(timeline(&verdict(Icon::Alert, State::Failed, ResultMark::None)).resolve(), 1850);
        assert_eq!(timeline(&verdict(Icon::Wipe, State::Failed, ResultMark::None)).resolve(), 2200);
        assert_eq!(timeline(&verdict(Icon::Shield, State::Done, ResultMark::Check)).resolve(), 2150);
        assert_eq!(timeline(&verdict(Icon::Shield, State::Failed, ResultMark::Cross)).resolve(), 1870);
        assert_eq!(timeline(&verdict(Icon::Pill, State::Failed, ResultMark::None)).resolve(), 2070);
        assert_eq!(timeline(&verdict(Icon::ResultRing, State::Failed, ResultMark::Cross)).resolve(), 1870);
        for s in [verdict(Icon::Die, State::Failed, ResultMark::None), verdict(Icon::Verified, State::Done, ResultMark::Check)] {
            assert_eq!(timeline(&s).resolve(), 1450);
        }
    }

    #[test]
    fn curves_match_their_python_twins() {
        // shake(0.25, 1) = sin(π/2)·0.75
        assert!((shake(ONE_Q16 / 4, 1) - 49_152).abs() < 200);
        // recoil(0.5) = sin(π/2)·0.5
        assert!((recoil(ONE_Q16 / 2) - 32_768).abs() < 200);
        // attention_pulse(0.2) = 1 + 0.09·e^-0.6·|sin(0.5π)| = 1.0494
        assert!((attention_pulse(13_107) - 68_775).abs() < 200);
        assert_eq!(freewheel(0), 0);
        assert!((freewheel(ONE_Q16) - ONE_Q16).abs() < 100);
    }

    #[test]
    fn every_sign_draws_inside_the_frame_budget() {
        for icon in [Icon::Lock, Icon::Unlock, Icon::Alert, Icon::Wipe, Icon::Shield, Icon::Pill, Icon::Die, Icon::Gear, Icon::ResultRing, Icon::Verified, Icon::Heart] {
            let s = verdict(icon, State::Failed, ResultMark::Cross);
            for t in (0..3000).step_by(50) {
                let mut f = Frame::new();
                build_sign(&s, t, &mut f);
                assert!(f.n < crate::raster::MAX_ITEMS - 4, "{icon:?} at {t}: {} items", f.n);
            }
        }
    }
}
