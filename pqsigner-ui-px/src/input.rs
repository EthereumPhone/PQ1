//! The two-button input grammar (DESIGN.md § Input) as a non-blocking,
//! edge-driven state machine.
//!
//! The presenter feeds it debounced-or-raw button levels with a timestamp
//! (`poll`); it emits gestures:
//!
//! * `Press` on the first down edge (the chevron nudge acknowledges it);
//! * `Tap` on a release within `TAP_MAX_MS`;
//! * `HoldStart` when a press outlives `TAP_MAX_MS` (the fill starts),
//!   `HoldCommit` when it reaches `HOLD_COMMIT_MS`, `HoldCancel` on an
//!   earlier release (the fill snaps back);
//! * `Chord` when the other side goes down while one is down, or within
//!   `CHORD_MS` of its tap — both sides are consumed and **both hold clocks
//!   stop**, so a two-thumb press can never complete a sign. Navigation
//!   screens leave the chord unbound (`InputCtx::chord_bound = false`), in
//!   which case it is reported and ignored by the driver;
//! * `DoubleTap` only in entry contexts (`double_tap_bound`), so navigation
//!   taps never wait (DESIGN.md: "double-tap never delays a tap").
//!
//! Debounce: the first raw edge is accepted immediately (exact timing,
//! instant feedback); further changes on that side are ignored for
//! `DEBOUNCE_MS`.

use crate::driver::Btn;
use crate::motion::{CHORD_MS, DOUBLE_TAP_MS, HOLD_COMMIT_MS, TAP_MAX_MS};

/// Debounce lockout after an accepted edge.
pub const DEBOUNCE_MS: u32 = 25;

/// A gesture the FSM emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gesture {
    Press(Btn),
    Release(Btn),
    Tap(Btn),
    DoubleTap(Btn),
    HoldStart(Btn),
    HoldCommit(Btn),
    HoldCancel(Btn),
    Chord,
}

/// Up to four gestures per poll.
#[derive(Clone, Copy, Debug, Default)]
pub struct Events {
    buf: [Option<Gesture>; 4],
    n: u8,
}

impl Events {
    fn push(&mut self, g: Gesture) {
        if usize::from(self.n) < self.buf.len() {
            self.buf[usize::from(self.n)] = Some(g);
            self.n += 1;
        }
    }

    #[must_use]
    pub fn iter(&self) -> impl Iterator<Item = Gesture> + '_ {
        self.buf[..usize::from(self.n)].iter().filter_map(|g| *g)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

/// Which optional bindings the current screen has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputCtx {
    pub chord_bound: bool,
    pub double_tap_bound: bool,
}

impl InputCtx {
    /// Navigation screens: taps and holds only.
    pub const NAV: Self = Self {
        chord_bound: false,
        double_tap_bound: false,
    };
    /// Entry screens (PIN): chord = ENTER, double-tap = move the cursor.
    pub const ENTRY: Self = Self {
        chord_bound: true,
        double_tap_bound: true,
    };
}

#[derive(Clone, Copy, Debug, Default)]
struct SideState {
    down: bool,
    /// Time of the current press (hold clock origin).
    t_edge: u32,
    /// Time of the last ACCEPTED edge on this side, press or release: the
    /// debounce lockout is measured from here. (Measuring it from `t_edge`
    /// — the press — left a release bounce free to re-press the side, after
    /// which the FSM believed the button was down and swallowed the next
    /// real press: the "tap twice" symptom on the EVT, 2026-09-22.)
    t_last_edge: u32,
    /// `t_last_edge` is meaningful.
    edged: bool,
    hold_started: bool,
    hold_fired: bool,
    /// Consumed by a chord: no tap / hold from this press.
    consumed: bool,
    last_tap_at: Option<u32>,
}

/// The state machine.
#[derive(Clone, Copy, Debug)]
pub struct InputFsm {
    left: SideState,
    right: SideState,
    ctx: InputCtx,
    /// Latest `now` seen; `poll` never lets time run backwards (a presenter
    /// that replays timestamped edges and then polls with a stale clock
    /// would otherwise measure a wrapped, multi-hour hold and fire a commit).
    last_now: u32,
    started: bool,
}

fn after(now: u32, t: u32) -> u32 {
    now.wrapping_sub(t)
}

impl InputFsm {
    #[must_use]
    pub const fn new(ctx: InputCtx) -> Self {
        Self {
            left: SideState {
                down: false,
                t_edge: 0,
                t_last_edge: 0,
                edged: false,
                hold_started: false,
                hold_fired: false,
                consumed: false,
                last_tap_at: None,
            },
            right: SideState {
                down: false,
                t_edge: 0,
                t_last_edge: 0,
                edged: false,
                hold_started: false,
                hold_fired: false,
                consumed: false,
                last_tap_at: None,
            },
            ctx,
            last_now: 0,
            started: false,
        }
    }

    pub fn set_ctx(&mut self, ctx: InputCtx) {
        self.ctx = ctx;
    }

    /// Hold progress on the side currently held past `TAP_MAX_MS`, as
    /// `(side, held_ms)` — the presenter draws the fill from it.
    #[must_use]
    pub fn hold_progress(&self, now: u32) -> Option<(Btn, u32)> {
        let now = self.clamp_now(now);
        for (btn, s) in [(Btn::Left, &self.left), (Btn::Right, &self.right)] {
            if s.down && s.hold_started && !s.consumed && !s.hold_fired {
                return Some((btn, after(now, s.t_edge)));
            }
        }
        None
    }

    /// Feed the current levels at `now` (ms). Call at least every few ms
    /// while a button is down (the SysTick edge ring provides exact edge
    /// times; the frame loop provides the time-driven events).
    pub fn poll(&mut self, now: u32, left_down: bool, right_down: bool) -> Events {
        let now = self.clamp_now(now);
        self.last_now = now;
        self.started = true;
        let mut ev = Events::default();
        // Edges first, left then right.
        self.edge(now, Btn::Left, left_down, &mut ev);
        self.edge(now, Btn::Right, right_down, &mut ev);
        // Time-driven: hold start / commit.
        for btn in [Btn::Left, Btn::Right] {
            let held = {
                let s = self.side(btn);
                if s.down && !s.consumed {
                    Some(after(now, s.t_edge))
                } else {
                    None
                }
            };
            if let Some(held) = held {
                let s = self.side_mut(btn);
                if !s.hold_started && held > TAP_MAX_MS {
                    s.hold_started = true;
                    ev.push(Gesture::HoldStart(btn));
                }
                if s.hold_started && !s.hold_fired && held >= HOLD_COMMIT_MS {
                    s.hold_fired = true;
                    ev.push(Gesture::HoldCommit(btn));
                }
            }
        }
        ev
    }

    /// `now`, or the last `now` when the clock appears to have stepped back
    /// (wrapping-aware: a backward step is a difference in the top half).
    fn clamp_now(&self, now: u32) -> u32 {
        if self.started && now.wrapping_sub(self.last_now) >= (1 << 31) {
            self.last_now
        } else {
            now
        }
    }

    fn side(&self, b: Btn) -> &SideState {
        match b {
            Btn::Left => &self.left,
            Btn::Right => &self.right,
        }
    }

    fn side_mut(&mut self, b: Btn) -> &mut SideState {
        match b {
            Btn::Left => &mut self.left,
            Btn::Right => &mut self.right,
        }
    }

    fn other(b: Btn) -> Btn {
        match b {
            Btn::Left => Btn::Right,
            Btn::Right => Btn::Left,
        }
    }

    fn edge(&mut self, now: u32, btn: Btn, level: bool, ev: &mut Events) {
        let s = *self.side(btn);
        if level == s.down {
            return;
        }
        // Debounce lockout: ignore a change within `DEBOUNCE_MS` of the last
        // accepted edge on this side (press OR release).
        if s.edged && after(now, s.t_last_edge) < DEBOUNCE_MS {
            return;
        }
        if level {
            // ---- press ----
            let other = *self.side(Self::other(btn));
            let chord = other.down
                || other.last_tap_at.is_some_and(|t| after(now, t) <= CHORD_MS);
            let s = self.side_mut(btn);
            s.down = true;
            s.t_edge = now;
            s.t_last_edge = now;
            s.edged = true;
            s.hold_started = false;
            s.hold_fired = false;
            s.consumed = false;
            if chord {
                // Both sides consumed; a running hold on the other side is cancelled.
                let o = self.side_mut(Self::other(btn));
                let was_holding = o.hold_started && !o.hold_fired;
                o.consumed = true;
                o.last_tap_at = None;
                self.side_mut(btn).consumed = true;
                if was_holding {
                    ev.push(Gesture::HoldCancel(Self::other(btn)));
                }
                ev.push(Gesture::Chord);
                return;
            }
            ev.push(Gesture::Press(btn));
            // Double-tap: a second press within the window converts the
            // previous tap (entry contexts only).
            if self.ctx.double_tap_bound {
                let s = self.side_mut(btn);
                if let Some(t) = s.last_tap_at {
                    if after(now, t) <= DOUBLE_TAP_MS {
                        s.last_tap_at = None;
                        s.consumed = true;
                        ev.push(Gesture::DoubleTap(btn));
                    }
                }
            }
        } else {
            // ---- release ----
            let s = self.side_mut(btn);
            s.down = false;
            let held = after(now, s.t_edge);
            s.t_last_edge = now;
            s.edged = true;
            if s.consumed {
                s.consumed = false;
                ev.push(Gesture::Release(btn));
                return;
            }
            ev.push(Gesture::Release(btn));
            if s.hold_fired {
                // The commit already fired; nothing more.
            } else if s.hold_started || held > TAP_MAX_MS {
                ev.push(Gesture::HoldCancel(btn));
            } else {
                s.last_tap_at = Some(now);
                ev.push(Gesture::Tap(btn));
            }
            s.hold_started = false;
            s.hold_fired = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(ev: Events) -> alloc::vec::Vec<Gesture> {
        ev.iter().collect()
    }
    extern crate alloc;

    #[test]
    fn tap_fires_on_release_under_250ms() {
        let mut f = InputFsm::new(InputCtx::NAV);
        assert_eq!(collect(f.poll(1000, true, false)), [Gesture::Press(Btn::Left)]);
        assert!(f.poll(1100, true, false).is_empty());
        assert_eq!(collect(f.poll(1200, false, false)), [Gesture::Release(Btn::Left), Gesture::Tap(Btn::Left)]);
    }

    #[test]
    fn hold_starts_commits_and_cancels() {
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, false, true);
        assert!(f.hold_progress(100).is_none());
        assert_eq!(collect(f.poll(260, false, true)), [Gesture::HoldStart(Btn::Right)]);
        assert_eq!(f.hold_progress(600), Some((Btn::Right, 600)));
        assert!(f.poll(1999, false, true).is_empty());
        assert_eq!(collect(f.poll(2000, false, true)), [Gesture::HoldCommit(Btn::Right)]);
        assert!(f.hold_progress(2100).is_none(), "fired holds stop reporting progress");
        assert_eq!(collect(f.poll(2500, false, false)), [Gesture::Release(Btn::Right)]);

        // Early release → cancel, no tap, no commit.
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, false, true);
        f.poll(300, false, true);
        assert_eq!(collect(f.poll(1200, false, false)), [Gesture::Release(Btn::Right), Gesture::HoldCancel(Btn::Right)]);
        // A release just past TAP_MAX without a HoldStart poll is still a cancel, never a tap.
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, false, true);
        assert_eq!(collect(f.poll(400, false, false)), [Gesture::Release(Btn::Right), Gesture::HoldCancel(Btn::Right)]);
    }

    #[test]
    fn chord_consumes_both_and_stops_hold_clocks() {
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, false, true);
        f.poll(300, false, true); // right hold started
        let ev = collect(f.poll(400, true, true));
        assert_eq!(ev, [Gesture::HoldCancel(Btn::Right), Gesture::Chord]);
        // Holding both for 3 s never commits.
        assert!(f.poll(3500, true, true).is_empty());
        assert!(f.hold_progress(3500).is_none());
        let ev = collect(f.poll(3600, false, false));
        assert_eq!(ev, [Gesture::Release(Btn::Left), Gesture::Release(Btn::Right)]);
        // Chord within CHORD_MS of the other side's tap.
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, true, false);
        f.poll(100, false, false); // tap left at 100
        assert_eq!(collect(f.poll(200, false, true)), [Gesture::Chord]);
    }

    #[test]
    fn double_tap_only_in_entry_contexts() {
        let mut nav = InputFsm::new(InputCtx::NAV);
        nav.poll(0, true, false);
        nav.poll(100, false, false);
        assert_eq!(collect(nav.poll(200, true, false)), [Gesture::Press(Btn::Left)]);
        let mut entry = InputFsm::new(InputCtx::ENTRY);
        entry.poll(0, true, false);
        assert_eq!(collect(entry.poll(100, false, false)), [Gesture::Release(Btn::Left), Gesture::Tap(Btn::Left)]);
        assert_eq!(collect(entry.poll(200, true, false)), [Gesture::Press(Btn::Left), Gesture::DoubleTap(Btn::Left)]);
        assert_eq!(collect(entry.poll(300, false, false)), [Gesture::Release(Btn::Left)]);
    }

    #[test]
    fn debounce_ignores_bounces_but_keeps_first_edge() {
        let mut f = InputFsm::new(InputCtx::NAV);
        assert_eq!(collect(f.poll(0, true, false)), [Gesture::Press(Btn::Left)]);
        assert!(f.poll(5, false, false).is_empty(), "bounce ignored");
        assert!(f.poll(10, true, false).is_empty());
        assert_eq!(collect(f.poll(120, false, false)), [Gesture::Release(Btn::Left), Gesture::Tap(Btn::Left)]);
    }

    #[test]
    fn release_bounce_cannot_re_press_the_side() {
        // Press 0, release 100 (tap); the switch bounces at 102/104 on the
        // way up. Before the fix the 102 re-press was accepted (the lockout
        // was measured from the PRESS), the FSM stayed "down", and the real
        // press at 500 was swallowed.
        let mut f = InputFsm::new(InputCtx::NAV);
        assert_eq!(collect(f.poll(0, true, false)), [Gesture::Press(Btn::Left)]);
        assert_eq!(collect(f.poll(100, false, false)), [Gesture::Release(Btn::Left), Gesture::Tap(Btn::Left)]);
        assert!(f.poll(102, true, false).is_empty(), "release bounce (down) ignored");
        assert!(f.poll(104, false, false).is_empty(), "release bounce (up) ignored");
        assert!(f.poll(200, false, false).is_empty());
        assert_eq!(collect(f.poll(500, true, false)), [Gesture::Press(Btn::Left)], "next real press is seen");
        assert_eq!(collect(f.poll(600, false, false)), [Gesture::Release(Btn::Left), Gesture::Tap(Btn::Left)]);
    }

    #[test]
    fn a_change_that_outlives_the_lockout_is_accepted_late() {
        // A 10 ms tap: the release lands inside the press lockout and is
        // ignored; the level is still up at 30 ms, so the release is accepted
        // then (held 30 ≤ TAP_MAX → still a tap).
        let mut f = InputFsm::new(InputCtx::NAV);
        f.poll(0, false, true);
        assert!(f.poll(10, false, false).is_empty());
        assert_eq!(collect(f.poll(30, false, false)), [Gesture::Release(Btn::Right), Gesture::Tap(Btn::Right)]);
    }

    #[test]
    fn clock_stepping_backwards_cannot_fire_a_commit() {
        // A press stamped 1000 by the edge ring, then a level poll with a
        // clock read before the drain (990): the hold must read 0, not 2^32.
        let mut f = InputFsm::new(InputCtx::NAV);
        assert_eq!(collect(f.poll(1000, false, true)), [Gesture::Press(Btn::Right)]);
        assert!(f.poll(990, false, true).is_empty(), "no HoldStart/HoldCommit from a backwards clock");
        assert!(f.hold_progress(990).is_none());
        assert_eq!(collect(f.poll(1100, false, false)), [Gesture::Release(Btn::Right), Gesture::Tap(Btn::Right)]);
    }

    #[test]
    fn wrapping_clock_is_fine() {
        let mut f = InputFsm::new(InputCtx::NAV);
        let t0 = u32::MAX - 100;
        f.poll(t0, false, true);
        assert_eq!(collect(f.poll(t0.wrapping_add(150), false, false)), [Gesture::Release(Btn::Right), Gesture::Tap(Btn::Right)]);
    }
}
