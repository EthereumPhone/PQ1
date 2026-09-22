//! Motion vocabulary — a fixed-point port of `tools/pq-ui/pq1/motion.py`.
//!
//! Springs drive every transition (Apple's `response` / `damping`
//! parameterisation, damping 1.0 everywhere: two buttons carry no momentum,
//! so navigation never overshoots). A landed spring snaps onto its target
//! and sleeps — zero cost per frame until the next retarget.
//!
//! Timing constants are the design's (§ Input, § Motion); the accent curves
//! are the named one-shots verdict screens use.

use crate::fixed::{clamp01, exp_neg_q16, lerp, mul_q16, Q16, ONE_Q16};

// ---- gesture timing (DESIGN.md § Input) ----------------------------------
/// Press-down acknowledgment: the pressed-side chevron nudges.
pub const PRESS_FEEDBACK_MS: u32 = 120;
/// Released under this = a tap; held past it = a hold begins.
/// A release up to this long after the press is a tap; longer is an aborted
/// hold. The PQ-UI reference says 250 ms; on the pq1's physical switches a
/// deliberate press runs 250–400 ms (EVT #1, 2026-09-22: single "clicks"
/// nudged the hero and did nothing, only a fast double-click advanced), so
/// the device uses the 500 ms the legacy button driver already validated.
pub const TAP_MAX_MS: u32 = 500;
/// A second press within this of a tap converts it (entry contexts only).
pub const DOUBLE_TAP_MS: u32 = 250;
/// A press on the other side within this is the chord.
pub const CHORD_MS: u32 = 150;
/// The hold fires exactly here; earlier release does nothing.
pub const HOLD_COMMIT_MS: u32 = 2000;
/// Early-release snap-back of the fill.
pub const HOLD_SNAPBACK_MS: u32 = 200;

// ---- choreography ---------------------------------------------------------
/// Incoming text is released this long after the circle starts moving.
pub const TEXT_IN_DELAY_MS: u32 = 150;
/// Idle sweep: centred hold, then a 5 s left-right cycle of ±95 px.
pub const SWEEP_HOLD_MS: u32 = 1000;
pub const SWEEP_PERIOD_MS: u32 = 5000;
pub const SWEEP_AMPLITUDE_PX: i32 = 95;
/// τ-chase time constants.
pub const OSC_TAU_MS: u32 = 180;
pub const CHAIN_TAU_MS: u32 = 60;
pub const CHAIN_TAU_IDLE_MS: u32 = 150;
pub const CHAIN_GAP_CAP_PX: i32 = 30;
/// Chevron hint: starts 1.4 s into the idle, repeats every 3.6 s.
pub const HINT_START_MS: u32 = 1400;
pub const HINT_PERIOD_MS: u32 = 3600;
pub const HINT_ROTATE_MS: u32 = 350;
pub const HINT_BOB_MS: u32 = 1200;
pub const HINT_BOB_PX: i32 = 4;
/// Confirm band: OR VIEW MORE ▸ / ◂ TO GO BACK swap every 5 s over 300 ms.
pub const BAND_SWAP_MS: u32 = 5000;
pub const BAND_FADE_MS: u32 = 300;
/// Page flip: sequential fade out then in, 300 ms each.
pub const PAGE_FADE_MS: u32 = 300;
/// Verdict entrance.
pub const ARRIVE_MS: u32 = 300;
/// Every one-shot accent phase spans at least two panel frames at 14 fps.
pub const VERDICT_ACCENT_MIN_MS: u32 = 145;
/// Hold overlay film alpha (30 %).
pub const HOLD_OVERLAY_A8: u8 = 77;

/// Spring profile: `w = 2π / response` in Q16 per millisecond.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    pub w_q16_per_ms: Q16,
}

impl Profile {
    /// Hardware button pace (`response` 0.40 s).
    pub const NAV: Self = Self {
        // 2π / 400 ms = 0.015708 → Q16 = 1029.4
        w_q16_per_ms: 1029,
    };
    /// Demo loops (`response` 0.55 s); not used on the device.
    pub const KIOSK: Self = Self {
        // 2π / 550 ms = 0.011424 → Q16 = 748.7
        w_q16_per_ms: 749,
    };
}

/// A critically damped spring on a Q16 value.
#[derive(Clone, Copy, Debug)]
pub struct Spring {
    pub value: Q16,
    /// Q16 per millisecond.
    pub velocity: Q16,
    pub target: Q16,
    pub profile: Profile,
    asleep: bool,
}

/// Snap tolerance: 1/64 of a unit (a sixty-fourth of a pixel, 4/255 of an
/// alpha) — integer truncation stalls the closed form a few Q16 units short
/// of the target, well inside this.
const SNAP_EPS: Q16 = 1 << 10;
/// Velocity sleep tolerance: ~1e-4 per ms (8 Q16/ms) — well under a pixel per second.
const SNAP_VEL: Q16 = 64;

impl Spring {
    #[must_use]
    pub const fn at(value: Q16, profile: Profile) -> Self {
        Self {
            value,
            velocity: 0,
            target: value,
            profile,
            asleep: true,
        }
    }

    /// Retarget from the live pose (velocity carries over).
    pub fn retarget(&mut self, target: Q16) {
        self.target = target;
        self.asleep = false;
    }

    /// Snap onto a value and sleep.
    pub fn snap(&mut self, value: Q16) {
        self.value = value;
        self.target = value;
        self.velocity = 0;
        self.asleep = true;
    }

    #[must_use]
    pub fn settled(&self) -> bool {
        self.asleep
    }

    /// Advance by `dt` ms (capped at 100 by the caller).
    pub fn step(&mut self, dt_ms: u32) {
        if self.asleep || dt_ms == 0 {
            return;
        }
        let w = i64::from(self.profile.w_q16_per_ms);
        let dt = i64::from(dt_ms.min(100));
        let x = i64::from(self.value) - i64::from(self.target);
        let v = i64::from(self.velocity);
        // Critically damped: d(t) = (A + B t) e^{-w t}, A = x, B = v + w x.
        let b = v + ((w * x) >> 16);
        let e = i64::from(exp_neg_q16(((w * dt) as i32).min(8 << 16)));
        let disp = x + b * dt;
        let nx = (disp * e) >> 16;
        let nv = ((b - ((w * disp) >> 16)) * e) >> 16;
        self.value = (i64::from(self.target) + nx) as Q16;
        self.velocity = nv as Q16;
        if (self.value - self.target).abs() <= SNAP_EPS && self.velocity.abs() <= SNAP_VEL {
            self.snap(self.target);
        }
    }
}

// ---- named curves ---------------------------------------------------------

/// Cubic ease in-out, `u` in Q16.
#[must_use]
pub fn ease(u: Q16) -> Q16 {
    let u = clamp01(u);
    if u < ONE_Q16 / 2 {
        4 * mul_q16(mul_q16(u, u), u)
    } else {
        let f = 2 * u - 2 * ONE_Q16;
        ONE_Q16 + mul_q16(mul_q16(f, f), f) / 2
    }
}

/// Cubic ease out.
#[must_use]
pub fn ease_out(u: Q16) -> Q16 {
    let f = clamp01(u) - ONE_Q16;
    ONE_Q16 + mul_q16(mul_q16(f, f), f)
}

/// The one sanctioned overshoot (status flash pop): back-out with s = 1.70158.
#[must_use]
pub fn back_out(u: Q16) -> Q16 {
    let f = clamp01(u) - ONE_Q16;
    let s: Q16 = 111_529; // 1.70158
    // 1 + f² ((s+1) f + s)
    ONE_Q16 + mul_q16(mul_q16(f, f), mul_q16(s + ONE_Q16, f) + s)
}

/// Verdict entrance: (alpha, scale) both ease-out, scale 0.97 → 1.
#[must_use]
pub fn arrive(u: Q16) -> (Q16, Q16) {
    let e = ease_out(u);
    (e, lerp(63_570, ONE_Q16, e))
}

/// Progress `[0, 1]` of `t` within `[start, start + dur]`.
#[must_use]
pub fn phase(t_ms: u32, start_ms: u32, dur_ms: u32) -> Q16 {
    if dur_ms == 0 || t_ms <= start_ms {
        return 0;
    }
    let el = t_ms - start_ms;
    if el >= dur_ms {
        return ONE_Q16;
    }
    ((u64::from(el) << 16) / u64::from(dur_ms)) as Q16
}

/// Hold fill level for a press that started at t 0: flat until
/// `TAP_MAX_MS`, then linear to 1 at `HOLD_COMMIT_MS`.
#[must_use]
pub fn hold_fill(held_ms: u32) -> Q16 {
    if held_ms <= TAP_MAX_MS {
        return 0;
    }
    phase(held_ms, TAP_MAX_MS, HOLD_COMMIT_MS - TAP_MAX_MS)
}

/// Snap-back from `level` starting at release: ease-out drain over 200 ms.
#[must_use]
pub fn hold_snapback(level: Q16, since_release_ms: u32) -> Q16 {
    let u = phase(since_release_ms, 0, HOLD_SNAPBACK_MS);
    mul_q16(level, ONE_Q16 - ease_out(u))
}

/// Frame-rate-independent τ-chase factor `1 − e^{−dt/τ}` in Q16.
#[must_use]
pub fn tau_k(dt_ms: u32, tau_ms: u32) -> Q16 {
    if tau_ms == 0 {
        return ONE_Q16;
    }
    let t = ((u64::from(dt_ms.min(1000)) << 16) / u64::from(tau_ms)) as Q16;
    ONE_Q16 - exp_neg_q16(t.min(8 << 16))
}

/// Chevron hint pose at idle time `t`: (rotate-up amount Q16, bob px).
/// Starts at 1.4 s, repeats every 3.6 s: 350 ms rotate up, 1200 ms bob
/// (−4 px sine), 350 ms return.
#[must_use]
pub fn chevron_hint(idle_ms: u32) -> (Q16, i32) {
    if idle_ms < HINT_START_MS {
        return (0, 0);
    }
    let t = (idle_ms - HINT_START_MS) % HINT_PERIOD_MS;
    if t < HINT_ROTATE_MS {
        (ease(phase(t, 0, HINT_ROTATE_MS)), 0)
    } else if t < HINT_ROTATE_MS + HINT_BOB_MS {
        let u = phase(t, HINT_ROTATE_MS, HINT_BOB_MS);
        // −4 px · sin(π u): half a turn.
        let s = crate::fixed::sin_turns_q16(u / 2);
        (ONE_Q16, -(((i64::from(s) * i64::from(HINT_BOB_PX)) + (1 << 15)) >> 16) as i32)
    } else if t < 2 * HINT_ROTATE_MS + HINT_BOB_MS {
        (ONE_Q16 - ease(phase(t, HINT_ROTATE_MS + HINT_BOB_MS, HINT_ROTATE_MS)), 0)
    } else {
        (0, 0)
    }
}

/// Confirm band state at settled time `t`: (which message: 0 = OR VIEW MORE,
/// 1 = TO GO BACK; its alpha Q16). Sequential 300 ms swap every 5 s.
#[must_use]
pub fn confirm_band(settled_ms: u32) -> (u8, Q16) {
    let cycle = 2 * BAND_SWAP_MS;
    let t = settled_ms % cycle;
    let (which, local) = if t < BAND_SWAP_MS { (0u8, t) } else { (1u8, t - BAND_SWAP_MS) };
    // Fade out over the last 300 ms of the slot, fade in over the first 300.
    let alpha = if local < BAND_FADE_MS {
        ease(phase(local, 0, BAND_FADE_MS))
    } else if local > BAND_SWAP_MS - BAND_FADE_MS {
        ONE_Q16 - ease_out(phase(local, BAND_SWAP_MS - BAND_FADE_MS, BAND_FADE_MS))
    } else {
        ONE_Q16
    };
    (which, alpha)
}

/// Page flip alphas at `t` since the flip started: (outgoing, incoming) —
/// out fades over 300 ms (ease-out), THEN in over 300 ms (ease).
#[must_use]
pub fn page_flip(t_ms: u32) -> (Q16, Q16) {
    if t_ms < PAGE_FADE_MS {
        (ONE_Q16 - ease_out(phase(t_ms, 0, PAGE_FADE_MS)), 0)
    } else {
        (0, ease(phase(t_ms, PAGE_FADE_MS, PAGE_FADE_MS)))
    }
}

/// Idle sweep target x-offset (px) at idle time `t`: 0 for the first second,
/// then a ±95 px sine with a 5 s period.
#[must_use]
pub fn sweep_offset(idle_ms: u32) -> i32 {
    if idle_ms < SWEEP_HOLD_MS {
        return 0;
    }
    let t = (idle_ms - SWEEP_HOLD_MS) % SWEEP_PERIOD_MS;
    let turns = ((u64::from(t) << 16) / u64::from(SWEEP_PERIOD_MS)) as Q16;
    let s = crate::fixed::sin_turns_q16(turns);
    (((i64::from(s) * i64::from(SWEEP_AMPLITUDE_PX)) + (1 << 15)) >> 16) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(q: Q16) -> f64 {
        f64::from(q) / 65536.0
    }

    #[test]
    fn spring_converges_without_overshoot_and_sleeps() {
        let mut s = Spring::at(0, Profile::NAV);
        s.retarget(100 << 16);
        let mut last = 0;
        let mut t = 0;
        while !s.settled() && t < 5000 {
            s.step(16);
            t += 16;
            assert!(s.value >= last - 64, "monotonic (±1e-3): {} then {}", last, s.value);
            assert!(s.value <= (100 << 16), "no overshoot");
            last = s.value;
        }
        assert!(s.settled(), "settles");
        assert_eq!(s.value, 100 << 16);
        // NAV settles in roughly half a second (design: ~500 ms per leg).
        assert!((400..=1100).contains(&t), "settled at {t} ms");
    }

    #[test]
    fn spring_closed_form_matches_python_reference() {
        // motion.py: response 0.40 → after 100 ms from x=1, v=0:
        // d = (1 + w·0.1) e^{-w·0.1}, w = 2π/0.4 = 15.708 → (2.5708)(0.2079) = 0.5345
        let mut s = Spring::at(ONE_Q16, Profile::NAV);
        s.retarget(0);
        s.step(100);
        assert!((f(s.value) - 0.5345).abs() < 0.01, "{}", f(s.value));
    }

    #[test]
    fn curves_have_the_right_endpoints() {
        assert_eq!(ease(0), 0);
        assert!((f(ease(ONE_Q16)) - 1.0).abs() < 1e-3);
        assert!((f(ease(ONE_Q16 / 2)) - 0.5).abs() < 1e-3);
        assert_eq!(ease_out(0), 0);
        assert!((f(ease_out(ONE_Q16)) - 1.0).abs() < 1e-3);
        assert!(f(back_out(ONE_Q16 * 7 / 10)) > 1.0, "back-out overshoots");
        assert!((f(back_out(ONE_Q16)) - 1.0).abs() < 1e-3);
        let (a, sc) = arrive(ONE_Q16);
        assert!((f(a) - 1.0).abs() < 1e-3 && (f(sc) - 1.0).abs() < 1e-3);
        assert!((f(arrive(0).1) - 0.97).abs() < 1e-3);
    }

    #[test]
    fn hold_fill_timing() {
        assert_eq!(hold_fill(0), 0);
        assert_eq!(hold_fill(TAP_MAX_MS), 0);
        assert!((f(hold_fill((TAP_MAX_MS + HOLD_COMMIT_MS) / 2)) - 0.5).abs() < 0.01);
        assert_eq!(hold_fill(HOLD_COMMIT_MS), ONE_Q16);
        assert_eq!(hold_snapback(ONE_Q16, 0), ONE_Q16);
        assert_eq!(hold_snapback(ONE_Q16, HOLD_SNAPBACK_MS), 0);
    }

    #[test]
    fn hint_band_flip_and_sweep_cycles() {
        assert_eq!(chevron_hint(0), (0, 0));
        let (r, _) = chevron_hint(HINT_START_MS + HINT_ROTATE_MS + 10);
        assert_eq!(r, ONE_Q16);
        let (_, bob) = chevron_hint(HINT_START_MS + HINT_ROTATE_MS + HINT_BOB_MS / 2);
        assert_eq!(bob, -HINT_BOB_PX);
        assert_eq!(chevron_hint(HINT_START_MS + HINT_PERIOD_MS - 10), (0, 0));

        assert_eq!(confirm_band(2500), (0, ONE_Q16));
        assert_eq!(confirm_band(7500), (1, ONE_Q16));
        assert!(confirm_band(BAND_SWAP_MS - 1).1 < ONE_Q16 / 10);

        assert_eq!(page_flip(0).0, ONE_Q16);
        assert_eq!(page_flip(PAGE_FADE_MS), (0, 0));
        assert_eq!(page_flip(2 * PAGE_FADE_MS).1, ONE_Q16);

        assert_eq!(sweep_offset(500), 0);
        assert_eq!(sweep_offset(SWEEP_HOLD_MS + SWEEP_PERIOD_MS / 4), SWEEP_AMPLITUDE_PX);
        assert_eq!(sweep_offset(SWEEP_HOLD_MS + 3 * SWEEP_PERIOD_MS / 4), -SWEEP_AMPLITUDE_PX);
        assert!((f(tau_k(180, 180)) - 0.632).abs() < 0.01);
    }
}
