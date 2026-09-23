"""Factory signing — the blue signing-machine gear coasts to a stop.

Port of reference/design_canvas/factory_signing-2.py onto the verdict law.
The sign is the 8-tooth factory gear (pq1.procedural.gear) in factory
blue. The mechanism is the source's freewheel: the gear spins fast and
coasts down like a bicycle wheel left to coast (motion.freewheel, k 4.2),
1 turn over 1800 ms, landing tooth-aligned. The source launches the
spin as its hold ends — the gear appears already turning — so the spin
starts with the arrival, the entrance law's fade + rise running over its
first 300 ms (a gear at rest that jumped to full speed would read as
fake). Then the source's 150 ms beat on the stopped gear, and the caption:

    hold 350 -> spin 1800 (arrive 300 under its start) -> beat 150
             -> caption 300                                t_resolve 2600

The panel runs at 14 fps, and the launch turns the gear ~61 degrees a
frame — more than a tooth's 45 — which would alias into a gear crawling
backwards. The teeth are motion-blurred over the angle swept in one panel
frame (SHUTTER_MS), the way a camera sees a spinning wheel: a smear at
launch that resolves into teeth as it slows, and sharp at rest.

The gear keeps the source's r 32 (a shade over the 30 px circle); its ink
box is symmetric about its centre at rest, which sits on the circle grid
(214, 72). The caption is the source's 18 px caps with 0.5 px tracking on
the y 128 baseline — components.caption.
"""
import math

from pq1 import colors, status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import ARRIVE_MS, VERDICT_ACCENT_MIN_MS, clamp01, freewheel
from pq1.procedural import gear
from pq1.verdict import VerdictAnim

ANIM = "factory_signing"
SPEC = dict(color=list(colors.FACTORY_BLUE),
            bottom="FACTORY SIGNING SLOT - 0")

GEAR_R = 32          # source proportion — a shade over the 30 px circle
TOTAL_TURNS = 1.0    # whole eighths land tooth-aligned (8 teeth); the
                     # source's 2.25 cut to one turn — user request
DECAY_K = 4.2        # the freewheel's decay (source)

# the mechanism (source windows)
T_SPIN = 1800        # the coast, launched with the arrival (source 2800)
T_BEAT = 150         # the stopped gear before the caption
SHUTTER_MS = VERDICT_ACCENT_MIN_MS / 2   # the blur's exposure: one panel frame


def _angle(tm):
    """gear angle (radians) tm ms into the spin; before the launch the gear
    is already turning at the launch speed (freewheel's slope at 0), so the
    arrival's first exposures smear like the rest instead of flashing a
    sharp gear"""
    if tm < 0:
        launch = DECAY_K / (1 - math.exp(-DECAY_K))
        return 2 * math.pi * TOTAL_TURNS * launch * tm / T_SPIN
    return 2 * math.pi * TOTAL_TURNS * freewheel(clamp01(tm / T_SPIN), DECAY_K)


class FactorySigning(VerdictAnim):
    T_HOLD = 350                          # source hold
    T_WAIT = T_SPIN - ARRIVE_MS + T_BEAT  # the rest of the spin, then the beat

    @property
    def previews(self):
        return (self.T_HOLD + 600, self.duration - 600)

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        tm = t - self.T_HOLD
        ang = _angle(tm)
        gear.draw(cv, CENTER_X, CIRCLE_CY, r=GEAR_R * s,
                  color=self.style["color"], alpha=a, rot=ang,
                  sweep=ang - _angle(tm - SHUTTER_MS))


status.register(ANIM, FactorySigning)
