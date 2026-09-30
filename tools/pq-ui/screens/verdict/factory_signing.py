"""Factory signing — the white signing-machine gear coasts to a stop.

Port of reference/design_canvas/factory_signing-2.py onto the verdict law.
The sign is the 8-tooth factory gear (pq1.procedural.gear) in WHITE — the
firmware / neutral role the FIRMWARE VERIFIED sign already wears. The
source's factory blue was retired with the role it was the only user of
(audit COL-05, user decision Sep 2026): a sign takes a state colour or it
takes white, never a per-context accent. The mechanism is the source's
freewheel: the gear spins fast and
coasts down like a bicycle wheel left to coast (motion.freewheel, k 4.2),
1 turn over 1800 ms, landing tooth-aligned. The source launches the
spin as its hold ends — the gear appears already turning — so the spin
starts with the arrival, the entrance law's fade + rise running over its
first 300 ms (a gear at rest that jumped to full speed would read as
fake). Then the source's 150 ms beat on the stopped gear, and the caption:

    hold 429 -> spin 1800 (arrive 300 under its start) -> beat 150
             -> caption 300                                t_resolve 2679

The panel runs at 14 fps, and the launch turns the gear ~61 degrees a
frame — more than a tooth's 45 — which would alias into a gear crawling
backwards. The teeth are motion-blurred over the angle swept in one panel
frame (SHUTTER_MS), the way a camera sees a spinning wheel: a smear at
launch that resolves into teeth as it slows, and sharp at rest.

The gear's radius is half the sign box (layout.VERDICT_BOX — the source's
r 32, a shade over the 30 px circle); its ink box is symmetric about its
centre at rest, which sits on the circle grid (214, 72). The caption is the Question caps (typography.SIZE_QUESTION /
LS_QUESTION) on the y 128 baseline — components.caption. The slot number
is VARIABLE — the slot being signed, never a digit fixed into the string
(audit HS-10; the old "SLOT - 0" read as a range):

    screens.spec("factory_signing", bottom=factory_signing.caption(3))
"""
import math

from pq1 import colors, status
from pq1.layout import CENTER_X, CIRCLE_CY, VERDICT_BOX
from pq1.motion import ARRIVE_MS, VERDICT_ACCENT_MIN_MS, VERDICT_HOLD_MS, clamp01, freewheel
from pq1.procedural import gear
from pq1.verdict import VerdictAnim

ANIM = "factory_signing"


def caption(slot=0):
    """the caption for the slot being signed"""
    return f"FACTORY SIGNING SLOT {slot}"


SPEC = dict(color=list(colors.WHITE), bottom=caption(0))

# the gear's radius is half the sign box (audit ICO-03): its rounded teeth
# ink the box (64.3 at r 32), a shade over the 30 px circle as the source drew it
GEAR_R = VERDICT_BOX / 2
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
    T_HOLD = VERDICT_HOLD_MS              # the verdict law's hold
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
