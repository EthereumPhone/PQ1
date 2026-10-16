//! The explosion finale — a fixed-point port of the MAJOR burst of
//! `tools/pq-ui/pq1/procedural/burst.py` (played by `screens/fx/explosion.py`).
//!
//! The explosion is the qubit loading film ([`crate::loading`]) with a
//! different landing: where the film's spiral ([`loading::T6`]) would flash
//! into a result, the merged pair becomes a trembling CLUMP that shakes
//! harder, compresses and (optionally) shifts colour for [`T_CLUMP`], then
//! BOOMS: a core flash blooms and fades while [`RINGS`] near-circular
//! ellipses launch [`STAGGER_MS`] apart and fly out past the frame. The film
//! ends on an EMPTY canvas ([`T_EMPTY`]), so it can lead the next screen.
//!
//! Everything here is a pure function of the film's pose time `t` (ms, the
//! loop's wraps taken out, exactly the time `burst.draw` is given), in Q8 px
//! and Q16 curves. Constants keep the reference's names (`BurstCfg` fields
//! upper-cased) so upstream's `port_diff` can pair them.
//!
//! Device notes: the loading leg up to `T6` is the film the device already
//! draws (its seed, split, orbit, trail and spiral), unchanged; the reference
//! entrances (`enter`: left / right / sides) are not ported — the device's
//! explosion always starts from the busy film's own disc.

use crate::fixed::{clamp01, lerp, mul_q16, sin_turns_q16, Q16, Q8, ONE_Q16};
use crate::loading;
use crate::motion::ease;

// ---- MAJOR (`burst.MAJOR`) ------------------------------------------------
/// Blast ring count.
pub const RINGS: u32 = 5;
/// Launch offset between rings (ms).
pub const STAGGER_MS: u32 = 145;
/// Clump phase length (ms).
pub const T_CLUMP: u32 = 1100;
/// Each ring's flight time (ms).
pub const T_BOOM: u32 = 900;
/// Clump squash: 22 → 22·(1 − 0.35).
pub const SQUEEZE_Q16: Q16 = 22_938;
/// Clump shake (px, Q8): base + ramp·u.
pub const JITTER_Q8: (Q8, Q8) = (358, 1_075);
/// Edge-tremble strength (Q16): base + ramp·u.
pub const INTENSITY_Q16: (Q16, Q16) = (39_322, 157_286);
/// Core flash: fade (ms), growth (px, Q8).
pub const BLOOM: (u32, Q8) = (300, 44 << 8);
/// Ring `i` reach: base + step·i (px, Q8).
pub const RING_SPAN_Q8: (Q8, Q8) = (300 << 8, -(42 << 8));
/// Ring ry / rx.
pub const ASPECT_Q16: Q16 = 47_186;
/// Ring `i` stroke: base + step·i (px, Q8) — 2.6 and −0.35.
pub const RING_W_Q8: (Q8, Q8) = (666, -90);
/// Ring peak brightness (0.9).
pub const RING_A_Q16: Q16 = 58_982;
/// The clump's radius before it squashes (px, Q8): the reference's literal 22.
pub const CLUMP_R_Q8: Q8 = 22 << 8;
/// The sources' post-boom dwell past [`T_RESOLVE`] (ms).
pub const HOLD_END: u32 = 1400;

// ---- timeline (film pose time, ms) ---------------------------------------
/// The clump forms where the spiral ends.
pub const T_CLUMP_AT: u32 = loading::T6;
/// The boom: core flash + first ring.
pub const T_BOOM_AT: u32 = T_CLUMP_AT + T_CLUMP;
/// The boom lands (the first ring is done): `burst.t_resolve`.
pub const T_RESOLVE: u32 = T_BOOM_AT + T_BOOM;
/// The late rings are still fading this long past [`T_RESOLVE`]: `burst.t_tail`.
pub const T_TAIL: u32 = STAGGER_MS * (RINGS - 1);
/// The canvas is empty from here: the last ring has flown.
pub const T_EMPTY: u32 = T_RESOLVE + T_TAIL;
const _: () = assert!(T_CLUMP_AT == 5_800 && T_BOOM_AT == 6_900 && T_RESOLVE == 7_800 && T_EMPTY == 8_380);

/// `(1 − u)^GROW_P` (GROW_P = 2.6) for u = i/32, Q16 (a fractional power has
/// no closed fixed-point form; linear between samples is within 0.4 % of it).
const ONE_MINUS_POW_2_6: [u16; 33] = [
    65535, 60343, 55412, 50737, 46313, 42134, 38196, 34493, 31020, 27770, 24739, 21921, 19309, 16899, 14682,
    12655, 10809, 9140, 7639, 6300, 5116, 4080, 3185, 2422, 1783, 1260, 844, 525, 294, 139, 49, 8, 0,
];

fn one_minus_pow(u: Q16) -> Q16 {
    let u = clamp01(u);
    let pos = i64::from(u) * 32;
    let i = ((pos >> 16) as usize).min(31);
    let f = (pos - ((i as i64) << 16)) as Q16;
    lerp(i32::from(ONE_MINUS_POW_2_6[i]), i32::from(ONE_MINUS_POW_2_6[i + 1]), f)
}

fn frac(num: u32, den: u32) -> Q16 {
    clamp01(((u64::from(num) << 16) / u64::from(den.max(1))) as Q16)
}

/// Q16 turns of `t · rad_per_ms`, the per-ms rate given as `turns_q16` Q16
/// turns per 100 ms (the reference's `t * 0.093` radians etc.).
fn phase(t: u32, turns_q16_per_100ms: u64) -> Q16 {
    ((u64::from(t) * turns_q16_per_100ms / 100) & 0xFFFF) as Q16
}

/// The clump at pose time `t` (`T_CLUMP_AT ≤ t < T_BOOM_AT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clump {
    /// Centre (Q8 px), shaken by the jitter.
    pub cx: Q8,
    pub cy: Q8,
    /// Radius (Q8 px), squashing.
    pub r: Q8,
    /// Edge tremble strength (Q16) and its three phases (Q16 turns).
    pub intensity: Q16,
    pub phases: [Q16; 3],
    /// The colour shift `clump_from → clump_to` (Q16).
    pub tint: Q16,
}

/// One blast ring (Q8 px semi-axes and stroke, brightness Q16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    pub rx: Q8,
    pub ry: Q8,
    pub w: Q8,
    pub a: Q16,
}

/// The boom at pose time `t` (`t ≥ T_BOOM_AT`): the core flash (radius,
/// brightness — `None` once it has faded) and the rings in flight.
#[derive(Clone, Copy, Debug)]
pub struct Boom {
    pub flash: Option<(Q8, Q16)>,
    pub rings: [Option<Ring>; RINGS as usize],
}

/// What the burst draws at pose time `t`.
#[derive(Clone, Copy, Debug)]
pub enum Pose {
    /// Before the spiral ends: the loading film's own pose.
    Loading,
    Clump(Clump),
    Boom(Boom),
    /// The canvas is empty.
    Empty,
}

/// The burst at pose time `t` (`burst.draw`, MAJOR, no entrance).
#[must_use]
pub fn pose(t: u32) -> Pose {
    if t < T_CLUMP_AT {
        return Pose::Loading;
    }
    if t < T_BOOM_AT {
        let u = frac(t - T_CLUMP_AT, T_CLUMP);
        let intensity = INTENSITY_Q16.0 + mul_q16(INTENSITY_Q16.1, u);
        let jitter = JITTER_Q8.0 + mul_q16(JITTER_Q8.1, u);
        // jx = jitter · sin(0.093 t) · sin(0.041 t); jy = jitter · sin(0.081 t + 1.7) · sin(0.037 t)
        let jx = mul_q16(jitter, mul_q16(sin_turns_q16(phase(t, 97_003)), sin_turns_q16(phase(t, 42_765))));
        let jy = mul_q16(
            jitter,
            mul_q16(sin_turns_q16(phase(t, 84_486).wrapping_add(17_732)), sin_turns_q16(phase(t, 38_592))),
        );
        let e = ease(u);
        return Pose::Clump(Clump {
            cx: loading::GC_X_Q8 + jx,
            cy: loading::GC_Y_Q8 + jy,
            r: CLUMP_R_Q8 - ((i64::from(CLUMP_R_Q8) * i64::from(mul_q16(SQUEEZE_Q16, e))) >> 16) as Q8,
            intensity,
            // sin(3a + 0.035 t), sin(5a − 0.052 t), sin(7a + 0.070 t)
            phases: [phase(t, 36_506), phase(t, 54_238), phase(t, 73_013)],
            tint: e,
        });
    }
    let e = t - T_BOOM_AT;
    let mut boom = Boom { flash: None, rings: [None; RINGS as usize] };
    let cu = frac(e, BLOOM.0);
    if cu < ONE_Q16 {
        boom.flash = Some(((6 << 8) + ((i64::from(BLOOM.1) * i64::from(cu)) >> 16) as Q8, ONE_Q16 - cu));
    }
    let mut any = boom.flash.is_some();
    for (i, slot) in boom.rings.iter_mut().enumerate() {
        let launch = i as u32 * STAGGER_MS;
        if e < launch {
            continue;
        }
        let ru = frac(e - launch, T_BOOM);
        if ru >= ONE_Q16 {
            continue;
        }
        let grow = ONE_Q16 - one_minus_pow(ru);
        let span = RING_SPAN_Q8.0 + RING_SPAN_Q8.1 * i as Q8;
        let rx = (10 << 8) + ((i64::from(span) * i64::from(grow)) >> 16) as Q8;
        *slot = Some(Ring {
            rx,
            ry: ((i64::from(rx) * i64::from(ASPECT_Q16)) >> 16) as Q8,
            w: RING_W_Q8.0 + RING_W_Q8.1 * i as Q8,
            a: mul_q16(ONE_Q16 - ru, RING_A_Q16),
        });
        any = true;
    }
    if any {
        Pose::Boom(boom)
    } else {
        Pose::Empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_timeline_matches_the_reference() {
        // burst.t_resolve = t6 + t_clump + t_boom; t_tail = stagger · (rings − 1).
        assert_eq!(T_RESOLVE, loading::T6 + 1100 + 900);
        assert_eq!(T_TAIL, 580);
        assert!(matches!(pose(T_CLUMP_AT - 1), Pose::Loading));
        assert!(matches!(pose(T_CLUMP_AT), Pose::Clump(_)));
        assert!(matches!(pose(T_BOOM_AT - 1), Pose::Clump(_)));
        assert!(matches!(pose(T_BOOM_AT), Pose::Boom(_)));
        assert!(matches!(pose(T_EMPTY - 1), Pose::Boom(_)));
        assert!(matches!(pose(T_EMPTY), Pose::Empty), "the last ring has flown: an empty canvas");
        assert!(matches!(pose(T_EMPTY + 10_000), Pose::Empty));
    }

    #[test]
    fn the_clump_squashes_and_shakes_harder() {
        let Pose::Clump(a) = pose(T_CLUMP_AT) else { panic!() };
        let Pose::Clump(b) = pose(T_BOOM_AT - 1) else { panic!() };
        assert_eq!(a.r, CLUMP_R_Q8, "22 px at the start");
        // 22 · (1 − 0.35) = 14.3 px at the end.
        assert!((b.r - (143 * 256 / 10)).abs() <= 64, "{}", b.r);
        assert!(b.intensity > a.intensity);
        // The shake never exceeds its ramped amplitude (1.4 + 4.2 px).
        for t in (T_CLUMP_AT..T_BOOM_AT).step_by(7) {
            let Pose::Clump(c) = pose(t) else { panic!() };
            assert!((c.cx - loading::GC_X_Q8).abs() <= 5 * 256 + 154 + 2);
            assert!((c.cy - loading::GC_Y_Q8).abs() <= 5 * 256 + 154 + 2);
        }
    }

    #[test]
    fn the_rings_launch_staggered_grow_and_fade() {
        let Pose::Boom(b) = pose(T_BOOM_AT) else { panic!() };
        assert_eq!(b.flash.map(|f| f.0), Some(6 << 8), "the core flash starts at 6 px");
        assert!(b.rings[0].is_some() && b.rings[1].is_none());
        let Pose::Boom(b) = pose(T_BOOM_AT + STAGGER_MS) else { panic!() };
        assert!(b.rings[1].is_some() && b.rings[2].is_none());
        let Pose::Boom(b) = pose(T_BOOM_AT + BLOOM.0) else { panic!() };
        assert!(b.flash.is_none(), "the flash has faded at 300 ms");
        // Ring 0 near its end: reach 10 + 300·grow, ry = 0.72 rx, almost dark.
        let Pose::Boom(b) = pose(T_BOOM_AT + T_BOOM - 1) else { panic!() };
        let r0 = b.rings[0].unwrap();
        assert!(r0.rx > (300 << 8) && r0.rx <= (310 << 8), "{}", r0.rx >> 8);
        assert!((r0.ry - (r0.rx * 72 / 100)).abs() <= 256);
        assert!(r0.a < ONE_Q16 / 100);
        assert_eq!(b.rings[4].unwrap().w, 666 - 4 * 90, "the last ring is the thinnest");
    }

    #[test]
    fn the_growth_table_is_the_fractional_power() {
        assert_eq!(one_minus_pow(0), 65535);
        assert_eq!(one_minus_pow(ONE_Q16), 0);
        // (1 - 0.5)^2.6 = 0.1649
        assert!((one_minus_pow(ONE_Q16 / 2) - 10_809).abs() <= 1);
        let mut last = i32::MAX;
        for u in (0..=ONE_Q16).step_by(97) {
            let v = one_minus_pow(u);
            assert!(v <= last, "monotone");
            last = v;
        }
    }
}
