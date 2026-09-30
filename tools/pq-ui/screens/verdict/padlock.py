"""Padlock — the shackle turns in and clicks shut, or springs open.

Merged port of lock.py + unlock.py on the procedural padlock rig. Each
direction fills its own mechanism window after the hold, then the
caption. The sign arrives on the verdict law (T_IN = ARRIVE_MS); the rest
of the mechanism runs on in T_WAIT:

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
fast; it is what reads as a real lock). The lock's click answers it: the
seated shackle drives the whole lock down on the same recoil kick and it
bobs back to rest inside the click window (user, Sep 2026).
"""
import math

from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY, VERDICT_BOX
from pq1.motion import ARRIVE_MS, VERDICT_HOLD_MS, clamp01, ease, ease_out, recoil
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
KICK = 6.0          # the body's kick amplitude on recoil's unit curve
                    # (peaks ~3.4 px down a third of the way into T_KICK;
                    # 10 -> 6, the user asked for a smaller bob, Sep 2026);
                    # the lock's click bobs the whole lock by the same
DIRECTIONS = ("lock", "unlock")
# the closed lock fits the sign box (audit ICO-03): the rig at BODY_R inks
# INK_H tall, so the body is drawn at BODY_R * BOX_FIT and the whole
# composite scales with it (the open rest, lifted OPEN_LIFT, stands taller)
BOX_FIT = VERDICT_BOX / padlock.INK_H


class Padlock(VerdictAnim):
    T_HOLD = VERDICT_HOLD_MS              # the verdict law's hold
    T_IN = ARRIVE_MS                      # the entrance law: fade + rise
    T_WAIT = T_MECH - ARRIVE_MS           # ... the mechanism runs on past it

    def __init__(self, spec):
        super().__init__(spec)
        self.direction = spec.get("direction", "lock")
        if self.direction not in DIRECTIONS:
            raise ValueError(f"unknown padlock direction "
                             f"{self.direction!r}; expected one of "
                             f"{', '.join(DIRECTIONS)}")
        if self.direction == "unlock":
            self.T_WAIT = T_MECH_UNLOCK - ARRIVE_MS   # its own, longer window

    def _pose_lock(self, tm):
        """arrive under the turn-in, drop, click -> seated rest"""
        a = ease_out(clamp01(tm / ARRIVE_MS))
        spin = math.pi * (1 - ease(clamp01(tm / T_TURN)))
        lift = OPEN_LIFT * (1 - ease_out(clamp01((tm - T_TURN) / T_DROP)))
        tc = tm - T_TURN - T_DROP             # the click starts on the seat
        k = recoil(clamp01(tc / T_CLICK))
        bob = KICK * recoil(clamp01(tc / T_KICK))   # the whole lock, pushed in
        return a, spin, lift, 0.0, k, bob

    def _pose_unlock(self, tm):
        """the closed lock arrives; the shackle springs up while the body
        is kicked down and recovers; then the turn-out -> open-mirrored
        rest"""
        a = ease_out(clamp01(tm / ARRIVE_MS))
        ts = tm - ARRIVE_MS                   # the snap starts on the arrived lock
        lift = OPEN_LIFT * ease_out(clamp01(ts / T_SNAP))
        drop = KICK * recoil(clamp01(ts / T_KICK))
        spin = math.pi * ease(clamp01((ts - T_KICK - T_PAUSE) / T_TURN_OUT))
        return a, spin, lift, drop, 0.0, 0.0

    def draw_icon(self, cv, t, u):
        pose = (self._pose_lock if self.direction == "lock"
                else self._pose_unlock)
        a, spin, lift, drop, k, bob = pose(t - self.T_HOLD)
        _, s = self.entrance(u)                    # the entrance law
        padlock.draw(cv, CENTER_X, CIRCLE_CY + bob,
                     body_r=padlock.BODY_R * BOX_FIT * s,
                     color=self.style["color"], alpha=a, spin=spin, lift=lift,
                     drop=drop, recoil_k=k)


def add_args(ap):
    ap.add_argument("--dir", choices=DIRECTIONS, default=None,
                    help="mechanism direction (default lock)")


def spec_from_args(args):
    return {} if args.dir is None else dict(direction=args.dir)


status.register(ANIM, Padlock)
