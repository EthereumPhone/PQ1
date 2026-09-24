"""Padlock — the shackle turns in and clicks shut, or springs open.

Merged port of lock.py + unlock.py on the procedural padlock rig. Each
direction fills its own mechanism window after the hold, then the
caption:

    lock    arrive 300 under the turn-in 520 -> drop 260 -> click 290      1070
    unlock  arrive 300 (closed) -> snap 145 under the kick 250 -> pause 250
            -> turn-out 800                                               1600

The click is widened 260 -> 290 ms (2x motion.VERDICT_ACCENT_MIN_MS) so
the snap survives the panel's 14 fps. The unlock snap is the way a real
padlock lets go: the shackle springs up in two panel frames (ease_out over
T_SNAP) while the body takes the reaction — knocked down on the recoil
curve and back at rest before the shackle swings out. The swing itself is
unhurried: a beat after the kick, then 800 ms out (the user asked for a
slower UNLOCKED, the padlock part above all, Sep 2026 — the snap stays
fast; it is what reads as a real lock).
"""
import math

from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import ARRIVE_MS, arrive, clamp01, ease, ease_out, recoil
from pq1.procedural import padlock
from pq1.verdict import VerdictAnim

ANIM = "padlock"
SPEC = dict(direction="lock", state="failed", bottom="LOCKED")
PRESETS = dict(
    lock=dict(direction="lock", state="failed", bottom="LOCKED"),
    unlock=dict(direction="unlock", state="done", bottom="UNLOCKED"),
)

T_TURN, T_DROP, T_CLICK = 520, 260, 290   # lock: turn-in, drop, click
T_SNAP, T_KICK = 145, 250                 # unlock: the shackle's spring-up
                                          # (two panel frames); the body's kick
T_PAUSE, T_TURN_OUT = 250, 800            # unlock: the beat after the kick,
                                          # then the unhurried swing out
T_MECH = T_TURN + T_DROP + T_CLICK        # the lock's window
T_MECH_UNLOCK = ARRIVE_MS + T_KICK + T_PAUSE + T_TURN_OUT   # the unlock's
OPEN_LIFT = 9.0     # the open shackle's rest raise (px)
KICK = 10.0         # the body's kick amplitude on recoil's unit curve
                    # (peaks ~5.7 px down a third of the way into T_KICK)
DIRECTIONS = ("lock", "unlock")


class Padlock(VerdictAnim):
    T_HOLD = 500
    T_IN = T_MECH                         # the whole mechanism window
    T_WAIT = 0

    def __init__(self, spec):
        super().__init__(spec)
        self.direction = spec.get("direction", "lock")
        if self.direction not in DIRECTIONS:
            raise ValueError(f"unknown padlock direction "
                             f"{self.direction!r}; expected one of "
                             f"{', '.join(DIRECTIONS)}")
        if self.direction == "unlock":
            self.T_IN = T_MECH_UNLOCK     # its own, longer window

    def _pose_lock(self, tm):
        """arrive under the turn-in, drop, click -> seated rest"""
        a = ease_out(clamp01(tm / ARRIVE_MS))
        spin = math.pi * (1 - ease(clamp01(tm / T_TURN)))
        lift = OPEN_LIFT * (1 - ease_out(clamp01((tm - T_TURN) / T_DROP)))
        k = recoil(clamp01((tm - T_TURN - T_DROP) / T_CLICK))
        return a, spin, lift, 0.0, k

    def _pose_unlock(self, tm):
        """the closed lock arrives; the shackle springs up while the body
        is kicked down and recovers; then the turn-out -> open-mirrored
        rest"""
        a = ease_out(clamp01(tm / ARRIVE_MS))
        ts = tm - ARRIVE_MS                   # the snap starts on the arrived lock
        lift = OPEN_LIFT * ease_out(clamp01(ts / T_SNAP))
        drop = KICK * recoil(clamp01(ts / T_KICK))
        spin = math.pi * ease(clamp01((ts - T_KICK - T_PAUSE) / T_TURN_OUT))
        return a, spin, lift, drop, 0.0

    def draw_icon(self, cv, t, u):
        pose = (self._pose_lock if self.direction == "lock"
                else self._pose_unlock)
        a, spin, lift, drop, k = pose(t - self.T_HOLD)
        s = arrive(clamp01((t - self.T_HOLD) / ARRIVE_MS))   # the entrance law
        padlock.draw(cv, CENTER_X, CIRCLE_CY, body_r=padlock.BODY_R * s,
                     color=self.style["color"], alpha=a, spin=spin, lift=lift,
                     drop=drop, recoil_k=k)


def add_args(ap):
    ap.add_argument("--dir", choices=DIRECTIONS, default=None,
                    help="mechanism direction (default lock)")


def spec_from_args(args):
    return {} if args.dir is None else dict(direction=args.dir)


status.register(ANIM, Padlock)
