//! The qubit status film — a fixed-point port of `tools/pq-ui/pq1/loading.py`
//! and the status timing of `pq1/status.py` (`RESULT_HOLD_MS`, the busy
//! caption, the film-less cancel resolve).
//!
//! The film is a pure function of film time: the token seeds into one qubit
//! (`T_SEED`), splits into its twin (`T_SPLIT`), the pair swings onto the
//! orbit while spinning up (`T_JOIN` / `T_RAMP`), spins whole turns
//! (`T_SPIN` = `REVS` × `TURN_MS`; the LOOP region — the only part that may
//! repeat), spirals in (`T_SPIRAL`), flashes (`T_FLASH`) and lands the
//! result; the result then holds `RESULT_HOLD_MS`. On the device the work
//! (the double sign + verify) answers at an unknown time, so [`QubitFilm`]
//! loops the orbit's last turn until [`QubitFilm::resolve`] and lengthens
//! the film only in whole turns — the reference's `wraps_for` /
//! `film_time`, kept pixel-exact so any frame stays seekable.
//!
//! Constants carry the reference's names so upstream's `port_diff` pairs
//! them (`make pq-ui-port-diff`). Geometry is Q8 px, curves Q16.

use crate::fixed::{clamp01, cos_turns_q16, lerp, mul_q16, sin_turns_q16, Q16, Q8, ONE_Q16};
use crate::motion::{back_out, ease, ease_out};

// ---- timing (pq1/motion.py, pq1/loading.py, pq1/status.py) ---------------
/// The seed beat: the handed circle travels to the film centre.
pub const SEED_MS: u32 = 300;
/// The seed's dress (ring + art) fades over this fraction of the seed window.
pub const SEED_ART_Q16: Q16 = ONE_Q16 / 2;
/// One orbit turn.
pub const TURN_MS: u32 = 850;
/// Whole turns before the spiral — the film's MINIMUM length.
pub const REVS: u32 = 3;
/// The result holds this long before the flow moves on.
pub const RESULT_HOLD_MS: u32 = 2450;
/// Busy caption fade in / out.
pub const BUSY_FADE_MS: u32 = 300;
/// The busy caption's breath.
pub const BUSY_PULSE_MS: u32 = 2000;
/// The film-less resolve's glyph leaves over this fraction of the flash beat.
pub const RESOLVE_ART_Q16: Q16 = 29_491; // 0.45
/// Follower copies drawn behind each qubit.
pub const TRAIL_COUNT: u32 = 5;
/// Angular spacing of the trail copies (0.22 rad = 0.035 turns).
pub const TRAIL_STEP_TURNS_Q16: Q16 = 2_295;

pub const QUBIT_T_SEED: u32 = SEED_MS;
pub const QUBIT_T_SPLIT: u32 = 650;
pub const QUBIT_T_JOIN: u32 = 1300;
pub const QUBIT_T_RAMP: u32 = 1300;
pub const QUBIT_T_SPIN: u32 = REVS * TURN_MS;
pub const QUBIT_T_SPIRAL: u32 = 1000;
pub const QUBIT_T_FLASH: u32 = 400;
/// Timeline seams (pq1/loading.py `QubitCfg`).
pub const T2: u32 = QUBIT_T_SEED;
pub const T_ORBIT: u32 = T2 + QUBIT_T_SPLIT + QUBIT_T_JOIN;
pub const T5: u32 = T_ORBIT + QUBIT_T_SPIN;
pub const T6: u32 = T5 + QUBIT_T_SPIRAL;
pub const T7: u32 = T6 + QUBIT_T_FLASH;
/// The loop unit: one whole turn.
pub const LOOP_MS: u32 = TURN_MS;
const _: () = assert!(T_ORBIT == 2250 && T5 == 4800 && T6 == 5800 && T7 == 6200);

// ---- geometry (Q8 px) -----------------------------------------------------
pub const GC_X_Q8: Q8 = 214 << 8;
pub const GC_Y_Q8: Q8 = 72 << 8;
pub const ORBIT_R_Q8: Q8 = 23 << 8;
pub const R_BIG_Q8: Q8 = 30 << 8;
pub const R_Q_Q8: Q8 = 13 << 8;
pub const SPLIT_X_Q8: Q8 = 120 << 8;
const Y_MAX_Q8: Q8 = 44 << 8;
const FLASH_R0_Q8: Q8 = 17 << 8;
const FLASH_GROW_Q8: Q8 = 55 << 8;
const SPIRAL_R_GROW_Q8: Q8 = 4 << 8;
/// The spiral's extra 2.2 turns.
const SPIRAL_EXTRA_TURNS_Q16: Q16 = 144_179;

/// One body: centre and radius in Q8 px.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Body {
    pub x: Q8,
    pub y: Q8,
    pub r: Q8,
}

/// Which beat of the film a pose belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Seed,
    Split,
    Join,
    Orbit,
    Spiral,
    Flash,
    Result,
}

/// One frame of the film.
#[derive(Clone, Copy, Debug)]
pub struct Pose {
    pub phase: Phase,
    pub bodies: [Body; 2],
    /// 1 or 2 live bodies.
    pub n: u8,
    /// The pair is close enough for the fluid bridge (not drawn on device).
    pub bind: bool,
    /// The seed's dress alpha (ring + mark) during the seed beat.
    pub glyph_a: u8,
    /// The flash ring, alpha and radius.
    pub flash_a: u8,
    pub flash_r: Q8,
    /// Result glyph draw progress and caption alpha (Q16).
    pub check_k: Q16,
    pub text_a: Q16,
}

fn frac(num: u32, den: u32) -> Q16 {
    clamp01(((u64::from(num) << 16) / u64::from(den.max(1))) as Q16)
}

fn a8(q: Q16) -> u8 {
    ((i64::from(clamp01(q)) * 255) >> 16) as u8
}

/// Scale a Q8 length by a Q16 factor.
fn scale_q8(len: Q8, k: Q16) -> Q8 {
    ((i64::from(len) * i64::from(k)) >> 16) as Q8
}

/// The spin angle (turns, Q16, unbounded) `e` ms into the join: constant
/// angular acceleration over `T_RAMP`, then `1 / TURN_MS` turns per ms.
pub fn spin_turns_q16(e: u32) -> Q16 {
    let e = u64::from(e);
    if e < u64::from(QUBIT_T_RAMP) {
        ((e * e) << 16) / (2 * u64::from(TURN_MS) * u64::from(QUBIT_T_RAMP))
    } else {
        ((e - u64::from(QUBIT_T_RAMP) / 2) << 16) / u64::from(TURN_MS)
    }
    .min(i64::from(i32::MAX) as u64) as Q16
}

fn polar(turns: Q16, rx: Q8, ry: Q8) -> (Q8, Q8) {
    let t = turns.rem_euclid(ONE_Q16);
    (
        GC_X_Q8 + scale_q8(rx, cos_turns_q16(t)),
        GC_Y_Q8 + scale_q8(ry, sin_turns_q16(t)),
    )
}

/// The pair at angle `turns` (one body half a turn behind), radii `rx`/`ry`.
fn pair(turns: Q16, rx: Q8, ry: Q8, r: Q8) -> [Body; 2] {
    let (x0, y0) = polar(turns + ONE_Q16 / 2, rx, ry);
    let (x1, y1) = polar(turns, rx, ry);
    [Body { x: x0, y: y0, r }, Body { x: x1, y: y1, r }]
}

/// The pose at film time `t` (ms). `seed` is the circle the film was handed
/// (position + VISIBLE radius): it becomes the first qubit.
#[must_use]
pub fn qubit_pose(t: u32, seed: Body) -> Pose {
    let rest = Body { x: GC_X_Q8, y: GC_Y_Q8, r: R_BIG_Q8 };
    let mut p = Pose {
        phase: Phase::Result,
        bodies: [rest, rest],
        n: 1,
        bind: false,
        glyph_a: 0,
        flash_a: 0,
        flash_r: 0,
        check_k: 0,
        text_a: 0,
    };
    if t < T2 {
        let u = ease_out(frac(t, QUBIT_T_SEED));
        p.phase = Phase::Seed;
        p.bodies[0] = Body {
            x: lerp(seed.x, GC_X_Q8, u),
            y: lerp(seed.y, GC_Y_Q8, u),
            r: lerp(seed.r, R_Q_Q8, u),
        };
        // The dress leaves on LINEAR time (ease_out would empty it in one frame).
        let lin = frac(t, QUBIT_T_SEED);
        let art = ONE_Q16 - ((i64::from(lin) << 16) / i64::from(SEED_ART_Q16)).min(i64::from(ONE_Q16)) as Q16;
        p.glyph_a = a8(art);
        return p;
    }
    if t < T5 {
        let e = t - T2;
        p.n = 2;
        if e < QUBIT_T_SPLIT {
            let u = ease(frac(e, QUBIT_T_SPLIT));
            let dx = scale_q8(SPLIT_X_Q8, u);
            p.phase = Phase::Split;
            p.bind = true;
            p.bodies = [
                Body { x: GC_X_Q8 - dx, y: GC_Y_Q8, r: R_Q_Q8 },
                Body { x: GC_X_Q8 + dx, y: GC_Y_Q8, r: R_Q_Q8 },
            ];
        } else {
            let je = e - QUBIT_T_SPLIT;
            let th = spin_turns_q16(je);
            let uj = frac(je, QUBIT_T_JOIN);
            // (1 - uj)^2 (1 + 2 uj): the smoothstep complement.
            let one_m = ONE_Q16 - uj;
            let k = mul_q16(mul_q16(one_m, one_m), ONE_Q16 + 2 * uj);
            let rx = ORBIT_R_Q8 + scale_q8(SPLIT_X_Q8 - ORBIT_R_Q8, k);
            let ry = if rx <= ORBIT_R_Q8 {
                rx
            } else {
                ORBIT_R_Q8
                    + ((i64::from(Y_MAX_Q8 - ORBIT_R_Q8) * i64::from(rx - ORBIT_R_Q8))
                        / i64::from(SPLIT_X_Q8 - ORBIT_R_Q8)) as Q8
            };
            p.phase = if je < QUBIT_T_JOIN { Phase::Join } else { Phase::Orbit };
            p.bodies = pair(th, rx, ry, R_Q_Q8);
        }
        return p;
    }
    if t < T6 {
        let e = t - T5;
        let u = frac(e, QUBIT_T_SPIRAL);
        let th0 = spin_turns_q16(QUBIT_T_JOIN + QUBIT_T_SPIN);
        let lin = ((u64::from(e) << 16) / u64::from(TURN_MS)) as Q16;
        let u3 = mul_q16(mul_q16(u, u), u);
        let th = th0.wrapping_add(lin).wrapping_add(mul_q16(SPIRAL_EXTRA_TURNS_Q16, u3));
        let rr = ORBIT_R_Q8 - scale_q8(ORBIT_R_Q8, mul_q16(u, u));
        let r = R_Q_Q8 + scale_q8(SPIRAL_R_GROW_Q8, u);
        p.phase = Phase::Spiral;
        p.n = 2;
        p.bind = true;
        p.bodies = pair(th, rr, rr, r);
        return p;
    }
    if t < T7 {
        let u = frac(t - T6, QUBIT_T_FLASH);
        p.phase = Phase::Flash;
        p.bodies[0] = Body { x: GC_X_Q8, y: GC_Y_Q8, r: lerp(FLASH_R0_Q8, R_BIG_Q8, back_out(u)) };
        // (1 - u) · 0.85
        p.flash_a = a8(mul_q16(ONE_Q16 - u, 55_706));
        p.flash_r = R_BIG_Q8 + scale_q8(FLASH_GROW_Q8, u);
        return p;
    }
    let e = t - T7;
    p.check_k = frac(e, 350);
    p.text_a = if e > 120 { frac(e - 120, 350) } else { 0 };
    p
}

/// Whole turns the film adds before its spiral when the work answers at
/// film time `t_ready`: none before the loop seam, else enough that the
/// spiral starts at the first whole-turn boundary at or after the answer.
#[must_use]
pub fn wraps_for(t_ready: u32) -> u32 {
    if t_ready <= T5 {
        0
    } else {
        (t_ready - T5).div_ceil(LOOP_MS)
    }
}

/// Pose time for film time `t` on a film lengthened by `wraps` whole turns
/// (`None` while the answer is pending): the identity up to the loop seam,
/// then the orbit's last turn repeats until the wraps are spent.
#[must_use]
pub fn film_time(t: u32, wraps: Option<u32>) -> u32 {
    if t <= T5 {
        return t;
    }
    let k = (t - T5).div_ceil(LOOP_MS);
    let k = match wraps {
        Some(w) => k.min(w),
        None => k,
    };
    t - LOOP_MS * k
}

/// The busy caption's breath: a raised cosine over one `BUSY_PULSE_MS`.
#[must_use]
pub fn busy_pulse(u: Q16) -> Q16 {
    (ONE_Q16 - cos_turns_q16(u.rem_euclid(ONE_Q16))) / 2
}

/// A live qubit film: started at a wall-clock ms, answered (or not) later.
#[derive(Clone, Copy, Debug)]
pub struct QubitFilm {
    t0: u32,
    /// Film time at which the work answered; `None` = pending (looping).
    ready: Option<u32>,
}

impl QubitFilm {
    #[must_use]
    pub const fn start(now: u32) -> Self {
        Self { t0: now, ready: None }
    }

    fn elapsed(&self, now: u32) -> u32 {
        now.wrapping_sub(self.t0)
    }

    /// The pose clock: film time with the loop's wraps taken out.
    #[must_use]
    pub fn film_t(&self, now: u32) -> u32 {
        film_time(self.elapsed(now), self.ready.map(wraps_for))
    }

    /// The host's answer at wall-clock `now`: the film finishes its current
    /// turn and spirals in. `false` if answered already. A pending film is
    /// always inside the loop region, so it can never be "too late".
    pub fn resolve(&mut self, now: u32) -> bool {
        if self.ready.is_some() {
            return false;
        }
        self.ready = Some(self.elapsed(now));
        true
    }

    #[must_use]
    pub fn pending(&self) -> bool {
        self.ready.is_none()
    }

    #[must_use]
    pub fn pose(&self, now: u32, seed: Body) -> Pose {
        qubit_pose(self.film_t(now), seed)
    }

    /// Alpha (Q16) of the busy caption: breathing over the orbit, fading
    /// over `BUSY_FADE_MS` once the spiral starts.
    #[must_use]
    pub fn busy_alpha(&self, now: u32) -> Q16 {
        let e = self.elapsed(now);
        if e < T_ORBIT {
            return 0;
        }
        let a = busy_pulse(frac((e - T_ORBIT) % BUSY_PULSE_MS, BUSY_PULSE_MS));
        let ft = self.film_t(now);
        if ft <= T5 {
            return a;
        }
        let fade = ease_out(frac(ft - T5, BUSY_FADE_MS));
        mul_q16(a, ONE_Q16 - fade)
    }

    /// The film has landed its result and held it.
    #[must_use]
    pub fn done(&self, now: u32) -> bool {
        self.ready.is_some() && self.film_t(now) >= T7 + RESULT_HOLD_MS
    }
}

/// The film-less cancel resolve (`pq1/status.py` `ResolveStatus`): the
/// arrived token resolves in place over one flash beat, then the result
/// glyph and caption land on the film's own timing, then the hold.
#[derive(Clone, Copy, Debug)]
pub struct ResolveFilm {
    t0: u32,
}

/// One frame of the resolve.
#[derive(Clone, Copy, Debug)]
pub struct ResolvePose {
    /// Linear beat progress and its ease-out (colour / geometry crossfade).
    pub lu: Q16,
    pub u: Q16,
    /// The token glyph's alpha as it leaves.
    pub glyph_a: u8,
    pub flash_a: u8,
    pub flash_r: Q8,
    pub check_k: Q16,
    pub text_a: Q16,
}

impl ResolveFilm {
    #[must_use]
    pub const fn start(now: u32) -> Self {
        Self { t0: now }
    }

    #[must_use]
    pub fn pose(&self, now: u32) -> ResolvePose {
        let t = now.wrapping_sub(self.t0);
        let lu = frac(t, QUBIT_T_FLASH);
        let u = ease_out(lu);
        let glyph = ONE_Q16 - ((i64::from(lu) << 16) / i64::from(RESOLVE_ART_Q16)).min(i64::from(ONE_Q16)) as Q16;
        // (1 - lu) · 0.85 · clamp01(lu / 0.12): the flash fades in over the
        // first 12 % so t 0 equals the arrived token exactly.
        let fade_in = clamp01(((i64::from(lu) << 16) / 7_864) as Q16);
        let flash = mul_q16(mul_q16(ONE_Q16 - lu, 55_706), fade_in);
        let e = t.saturating_sub(QUBIT_T_FLASH);
        ResolvePose {
            lu,
            u,
            glyph_a: a8(glyph),
            flash_a: a8(flash),
            flash_r: R_BIG_Q8 + scale_q8(FLASH_GROW_Q8, lu),
            check_k: if t > QUBIT_T_FLASH { frac(e, 350) } else { 0 },
            text_a: if e > 120 { frac(e - 120, 350) } else { 0 },
        }
    }

    #[must_use]
    pub fn done(&self, now: u32) -> bool {
        now.wrapping_sub(self.t0) >= QUBIT_T_FLASH + RESULT_HOLD_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Body = Body { x: 100 << 8, y: 60 << 8, r: 28 << 8 };

    fn dist_px(a: Body, b: Body) -> i32 {
        (((a.x - b.x) >> 8).abs()).max(((a.y - b.y) >> 8).abs())
    }

    #[test]
    fn seed_travels_to_the_centre_and_shrinks() {
        let p0 = qubit_pose(0, SEED);
        assert_eq!(p0.phase, Phase::Seed);
        assert_eq!(p0.bodies[0], SEED);
        assert_eq!(p0.glyph_a, 255);
        let p = qubit_pose(T2, SEED);
        assert_eq!(p.phase, Phase::Split);
        assert!(dist_px(p.bodies[0], Body { x: GC_X_Q8, y: GC_Y_Q8, r: R_Q_Q8 }) <= 1);
        assert_eq!(p.bodies[0].r, R_Q_Q8);
        assert_eq!(qubit_pose(T2 - 1, SEED).glyph_a, 0, "the dress is gone by half the seed window");
    }

    #[test]
    fn split_reaches_split_x_and_the_pair_lands_on_the_orbit() {
        let p = qubit_pose(T2 + QUBIT_T_SPLIT - 1, SEED);
        assert_eq!(p.n, 2);
        assert!((p.bodies[1].x - p.bodies[0].x) >> 8 >= 2 * 120 - 2);
        let p = qubit_pose(T_ORBIT, SEED);
        assert_eq!(p.phase, Phase::Orbit);
        for b in &p.bodies {
            let dx = (b.x - GC_X_Q8) >> 8;
            let dy = (b.y - GC_Y_Q8) >> 8;
            let d2 = dx * dx + dy * dy;
            assert!((22 * 22..=24 * 24).contains(&d2), "body off the orbit: {b:?}");
        }
    }

    #[test]
    fn the_orbit_is_periodic_in_one_turn() {
        for t in [T_ORBIT + 100, T_ORBIT + 400, T5 - 300] {
            let a = qubit_pose(t, SEED);
            let b = qubit_pose(t + LOOP_MS, SEED);
            if b.phase == Phase::Orbit {
                assert!(dist_px(a.bodies[0], b.bodies[0]) <= 1, "{t}: {:?} vs {:?}", a.bodies, b.bodies);
            }
        }
    }

    #[test]
    fn spiral_flash_and_result_timings() {
        let p = qubit_pose(T5 + 500, SEED);
        assert_eq!(p.phase, Phase::Spiral);
        let p = qubit_pose(T6 + 1, SEED);
        assert_eq!(p.phase, Phase::Flash);
        assert!(p.flash_a > 200 && p.flash_r >= R_BIG_Q8);
        let p = qubit_pose(T7 - 1, SEED);
        assert!(p.flash_a <= 2);
        assert!(((p.bodies[0].r - R_BIG_Q8) >> 8).abs() <= 1);
        let p = qubit_pose(T7 + 350, SEED);
        assert_eq!(p.phase, Phase::Result);
        assert_eq!(p.check_k, ONE_Q16);
        assert_eq!(qubit_pose(T7 + 470, SEED).text_a, ONE_Q16);
        assert_eq!(qubit_pose(T7 + 100, SEED).text_a, 0);
    }

    #[test]
    fn wraps_and_film_time_match_the_reference() {
        assert_eq!(wraps_for(0), 0);
        assert_eq!(wraps_for(T5), 0);
        assert_eq!(wraps_for(T5 + 1), 1);
        assert_eq!(wraps_for(T5 + LOOP_MS), 1);
        assert_eq!(wraps_for(T5 + LOOP_MS + 1), 2);
        // Identity up to the seam, then the last turn repeats while pending.
        assert_eq!(film_time(1234, None), 1234);
        assert_eq!(film_time(T5, None), T5);
        assert_eq!(film_time(T5 + 1, None), T5 + 1 - LOOP_MS);
        assert_eq!(film_time(T5 + LOOP_MS, None), T5);
        assert_eq!(film_time(T5 + 3 * LOOP_MS + 7, None), T5 - LOOP_MS + 7);
        // With the wraps spent the spiral runs.
        assert_eq!(film_time(T5 + 2 * LOOP_MS + 100, Some(2)), T5 + 100);
        assert_eq!(film_time(T5 + 100, Some(0)), T5 + 100);
    }

    #[test]
    fn a_live_film_loops_until_answered_then_lands_and_holds() {
        let mut f = QubitFilm::start(1000);
        assert!(f.pending());
        // Long past the stock length, still on the orbit.
        let far = 1000 + T5 + 10 * LOOP_MS + 200;
        assert_eq!(f.pose(far, SEED).phase, Phase::Orbit);
        assert!(!f.done(far));
        assert!(f.resolve(far));
        assert!(!f.resolve(far + 1));
        // The current turn completes (11 wraps), then the spiral.
        let spiral_at = 1000 + T5 + 11 * LOOP_MS + 10;
        assert_eq!(f.pose(spiral_at, SEED).phase, Phase::Spiral);
        let landed = 1000 + T7 + 11 * LOOP_MS + 500;
        assert_eq!(f.pose(landed, SEED).phase, Phase::Result);
        assert!(!f.done(landed));
        assert!(f.done(landed + RESULT_HOLD_MS));
    }

    #[test]
    fn busy_caption_breathes_on_the_orbit_only() {
        let f = QubitFilm::start(0);
        assert_eq!(f.busy_alpha(T_ORBIT - 1), 0);
        assert!(f.busy_alpha(T_ORBIT + BUSY_PULSE_MS / 2) > ONE_Q16 * 9 / 10);
        assert!(f.busy_alpha(T_ORBIT + BUSY_PULSE_MS) < ONE_Q16 / 20);
    }

    #[test]
    fn resolve_film_beat_and_hold() {
        let f = ResolveFilm::start(0);
        let p = f.pose(0);
        assert_eq!(p.flash_a, 0, "t 0 equals the arrived token");
        assert_eq!(p.glyph_a, 255);
        let p = f.pose(QUBIT_T_FLASH / 2);
        assert!(p.glyph_a == 0 && p.flash_a > 0 && p.u > ONE_Q16 / 2);
        let p = f.pose(QUBIT_T_FLASH + 350);
        assert_eq!(p.check_k, ONE_Q16);
        assert!(!f.done(QUBIT_T_FLASH + RESULT_HOLD_MS - 1));
        assert!(f.done(QUBIT_T_FLASH + RESULT_HOLD_MS));
    }
}
