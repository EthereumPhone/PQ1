"""Last attempt — the attempt counter reels down to 1 beside a red heart.

Port of reference/design_canvas/last_attempt-2.py onto the verdict law.
The sign is a slot-reel digit (pq1.procedural.digit_reel) and the bezier
heart (pq1.procedural.heart) on one line: the digit's foot stands on the
heart's tip and its cap height matches the heart, so the pair reads as
one mark. The source shows the start digit at rest, then the mechanism:
the reel rolls down to 1 in one decelerating sweep, the 1 overshoots and
wobbles into place, the heart answers with a decaying double pump, and
the caption names it. The law adds the entrance in front (fade + rise
within ARRIVE_MS, no overshoot); the source's visible hold survives as
the rest on the arrived sign, so the count is read before it falls:

    hold 400 -> arrive 300 -> rest 400 -> roll 2000 -> settle 700
             -> heartbeat 700 -> caption 300        t_resolve 4800

Geometry from the source (digit x 199 / heart x 233, 34 px apart, one
line y 67; 40 px digit, 30 px heart) re-centred so the RESTING sign —
the 1 and the heart — sits on the circle grid (214, 72). The digit is
sign art, not type: it keeps the source's 40 px, whose cap height is the
heart's height, rather than the type scale's 36, and it is SemiBold (the
600 weight, the label caps' face — user request, Sep 2026; the source's
own medium weight is not a PQ1 face).

    screens.spec("last_attempt")                # 8 -> 1
    screens.spec("last_attempt", attempts=3)    # 3 -> 1
    python3 -m screens last_attempt --attempts 5
"""
from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import decel, heartbeat, wobble
from pq1.procedural import digit_reel, heart
from pq1.verdict import VerdictAnim

ANIM = "last_attempt"
SPEC = dict(state="failed", attempts=8, bottom="LAST ATTEMPT")

# the mechanism, on the arrived sign (source windows)
T_REST = 400      # the start digit at rest — the source's visible hold
T_ROLL = 2000     # the reel rolls attempts -> 1, decelerating (decel 2.6)
T_SETTLE = 700    # the 1 overshoots and wobbles into place (wobble, decay 3)
T_BEAT = 700      # the heart's decaying pump train (heartbeat defaults:
                  # 3 pumps, amp 0.22, decay 4 — the source's double beat)
BOUNCE = 0.18     # settle overshoot in reel steps (source amplitude)

# composition: the source's 34 px digit-to-heart spacing on one line; the
# resting 1 + heart ink box centred on (CENTER_X, CIRCLE_CY)
DIGIT_PX = 40.0   # the digit's size — cap height 28.5, the heart's height
DIGIT_WEIGHT = "semibold"   # the 600 weight (user request); the ink metrics
                            # below hold for both PQ1 faces
HEART_H = 30.0    # the heart's height (design box 40 x 34.6)
HEART_DX = 34.0   # heart centre right of the digit anchor
NUM_X = 191.5     # digit anchor: Aileron's 1 inks 1 px left of its anchor
DIGIT_DY = -0.8   # Aileron's digit ink hangs 0.8 px under its em middle
                  # where the source's Helvetica did not — lifted so the
                  # digit's foot stays on the heart's tip
WIN_DN = 0.40     # the reel window's opaque reach below the digit line, x
                  # size: 16 px, 4 px lower than the source's 12 — the
                  # bottom fade starts past the digit's foot (15.3 px), so
                  # the resting digit is never dimmed (user request)
ATTEMPTS = range(1, 10)   # a one-digit reel


class LastAttempt(VerdictAnim):
    T_WAIT = T_REST + T_ROLL + T_SETTLE + T_BEAT   # the mechanism window

    def __init__(self, spec):
        super().__init__(spec)
        self.start = int(spec.get("attempts", SPEC["attempts"]))
        if self.start not in ATTEMPTS:
            raise ValueError(f"last_attempt counts down from a single "
                             f"digit, 1-9; got {self.start}")

    @property
    def previews(self):
        return (self.T_HOLD + self.T_IN + T_REST + T_ROLL // 2,
                self.duration - 600)

    def _p(self, tm):
        """reel progress 0 -> 1 at tm ms after the arrival: the rest, the
        decelerating sweep, then the settle spring past 1 and back"""
        n = self.start - 1
        t_roll = T_REST + T_ROLL
        if n <= 0 or tm < T_REST:
            return 0.0
        if tm < t_roll:
            return decel((tm - T_REST) / T_ROLL)
        if tm < t_roll + T_SETTLE:
            return 1 + BOUNCE * wobble((tm - t_roll) / T_SETTLE) / n
        return 1.0

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        tm = t - (self.T_HOLD + self.T_IN)
        t_beat = T_REST + T_ROLL + T_SETTLE
        beat = 1.0
        if t_beat < tm < t_beat + T_BEAT:
            beat = heartbeat((tm - t_beat) / T_BEAT)
        col = self.style["color"]
        # the sign rises about the grid centre it rests on
        gx = CENTER_X + (NUM_X - CENTER_X) * s
        gy = CIRCLE_CY + DIGIT_DY * s
        hx = CENTER_X + (NUM_X + HEART_DX - CENTER_X) * s
        digit_reel.draw(cv, gx, gy, p=self._p(tm), size=DIGIT_PX * s,
                        color=col, alpha=a, start=self.start,
                        weight=DIGIT_WEIGHT, win_dn=WIN_DN)
        heart.draw(cv, hx, CIRCLE_CY, h=HEART_H * s * beat, color=col,
                   alpha=a)


def add_args(ap):
    ap.add_argument("--attempts", type=int, default=None, metavar="N",
                    help="the reel's start digit, 1-9 (default 8)")


def spec_from_args(a):
    return {} if a.attempts is None else dict(attempts=a.attempts)


status.register(ANIM, LastAttempt)
