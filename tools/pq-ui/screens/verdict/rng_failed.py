"""RNG failed — the red die rests, tumbles on three axes and lands on 1-2-3.

Port of reference/design_canvas/rng_failed.py onto the verdict law. The
sign is the procedural 3D die (pq1.procedural.die3d) in the failed red.
The source shows the die still in its wound-up pose, then the mechanism:
one multi-axis tumble decelerating (motion.decel, p 2.8) into
die3d.REST, the corner view of the 1-2-3 faces — pinned to the centre,
its decelerating settle the beat before the caption. The law adds the
entrance in front (fade + rise within ARRIVE_MS, no overshoot); the
source's visible hold survives as the rest on the arrived die, so it is
seen still before it is thrown.

The tumble is tamer than the source's (3pi / 4pi / 1.5pi over 2600 ms
read as too much spinning, too much blur, too long — user, Sep 2026):
half a turn about X, three quarters about Y, a quarter about Z, over
1500 ms — one throw that lands, not a spin:

    hold 400 -> arrive 300 -> rest 350 -> tumble 1500 -> beat 150
             -> caption 300                              t_resolve 3000

The panel runs at 14 fps, and the launch turns the die ~36 degrees a
frame about Y (24 about X) — under half the cube's 90-degree symmetry,
so the sharp frames already read as one die turning. A light motion
blur over the angles it swept in a third of a panel frame (SHUTTER_MS)
takes the edge off the first frames the way a camera sees a thrown die,
without smearing the faces away: the die is sharp again well before
it settles.

The die keeps the source's half-edge 21; its resting ink box (64 x 55)
centres on the circle grid (214, 72) with a half-pixel nudge right
(DIE_DX — the corner view inks 0.5 px left of the cube's centre). The
caption is the source's 18 px caps with 0.5 px tracking on the y 128
baseline — components.caption.

    screens.spec("rng_failed")
    python3 -m screens rng_failed
"""
import math

from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import VERDICT_ACCENT_MIN_MS, clamp01, decel
from pq1.procedural import die3d
from pq1.verdict import VerdictAnim

ANIM = "rng_failed"
SPEC = dict(state="failed", bottom="RNG FAILED")

SIZE = 21.0                                        # half-edge (source)
SPIN = (math.pi, 1.5 * math.pi, 0.5 * math.pi)     # per-axis tumble (the
                                                   # source's 3pi/4pi/1.5pi tamed)
DECEL_P = 2.8      # the tumble's deceleration (source)
DIE_DX = 0.5       # the resting corner view inks 0.5 px left of the cube centre

# the mechanism, on the arrived sign (source windows)
T_REST = 350       # the wound-up die at rest — the source's visible hold
T_TUMBLE = 1500    # the 3-axis tumble, decelerating into the corner rest
T_BEAT = 150       # the settled die before the caption
SHUTTER_MS = VERDICT_ACCENT_MIN_MS / 6   # the blur's exposure: a third of a panel frame


def _rot(tm):
    """the die's pose tm ms into the tumble: wound back SPIN from REST and
    unwinding on the decel curve — still before 0 and past T_TUMBLE"""
    e = decel(clamp01(tm / T_TUMBLE), DECEL_P)
    return tuple(r - sp * (1 - e) for r, sp in zip(die3d.REST, SPIN))


class RngFailed(VerdictAnim):
    T_WAIT = T_REST + T_TUMBLE + T_BEAT   # the mechanism window, then the beat

    @property
    def previews(self):
        return (self.T_HOLD + self.T_IN + T_REST + T_TUMBLE // 2,
                self.duration - 600)

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        tm = t - (self.T_HOLD + self.T_IN + T_REST)    # the tumble clock
        rot = _rot(tm)
        die3d.draw(cv, CENTER_X + DIE_DX, CIRCLE_CY, size=SIZE * s,
                   color=self.style["color"], alpha=a, rot=rot,
                   sweep=tuple(r - p for r, p
                               in zip(rot, _rot(tm - SHUTTER_MS))))


status.register(ANIM, RngFailed)
