"""Wallet wiped — the warning triangle carries the brush, two treatments.

treatment="pulse" (preset wallet_wiped): the icon arrives, rests a beat,
then draws the eye with two decaying attention pulses. treatment="sweep"
(preset wallet_wiped_anim): the icon arrives, then the brush swiffles —
swinging around the top of its handle while the bristle strip drags
against the ground, curving opposite the motion.

Preset wallet_wiped_explosion leads the sweep with the major explosion
(status "lead"): two red qubits fly in from both edges and spiral
straight onto the orbit (enter="sides" — never stopping and restarting),
spin, clump and tremble, then blow apart in red, the caption alternating
"WIPING…" / "DO NOT POWER OFF" from the orbit until the blast;
the sign arrives LEAD_GAP after the boom, once the blast has cleared,
the brush swiffles, WALLET WIPED lands. One screen, one dwell (user
request, Sep 2026).
"""
import math

from pq1 import colors, loading, status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import attention_pulse
from pq1.procedural import brush, warning_triangle
from pq1.verdict import VerdictAnim

ANIM = "wipe"
SPEC = dict(treatment="pulse", state="failed", bottom="WALLET WIPED")
PRESETS = dict(wallet_wiped=dict(treatment="pulse"),
               wallet_wiped_anim=dict(treatment="sweep"),
               wallet_wiped_explosion=dict(
                   treatment="sweep", lead_gap=700,
                   lead=dict(anim="explosion", severity="major",
                             enter="sides", busy_until="boom",
                             revs=loading.REVS_LONG,   # two turns past the stock 3: it endures
                             busy=["WIPING…", "DO NOT POWER OFF"],
                             body=list(colors.RED), trail=list(colors.RED),
                             clump_from=list(colors.RED),
                             clump_to=list(colors.RED),   # unset = white
                             ring=list(colors.RED))))

TREATMENTS = ("pulse", "sweep")

TRI_H = 64      # triangle height (bounding box 72 x 64), from the sources
BRUSH_W = 30    # brush width; its centre sits BRUSH_DY below the triangle's
BRUSH_DY = 9

T_MARK = 300                          # beat between entrance and accent
ACCENT = dict(pulse=900, sweep=1400)  # attention pulses / brush swiffle


class Wipe(VerdictAnim):
    def __init__(self, spec):
        super().__init__(spec)
        self.treatment = spec.get("treatment", "pulse")
        if self.treatment not in TREATMENTS:
            raise ValueError(f"unknown wipe treatment {self.treatment!r}; "
                             f"expected one of {', '.join(TREATMENTS)}")
        self.T_WAIT = T_MARK + ACCENT[self.treatment]

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive, both treatments
        swivel = bend = 0.0
        v = (t - (self.T_HOLD + self.T_IN + T_MARK)) / ACCENT[self.treatment]
        if 0.0 < v < 1.0:
            if self.treatment == "pulse":
                s = attention_pulse(v)
            else:
                decay = 1 - v ** 3
                swivel = 0.30 * math.sin(4 * math.pi * v) * decay
                # positive swivel moves the brush bottom left, so the
                # drag lag points the opposite way of that motion (+cos)
                bend = 0.28 * math.cos(4 * math.pi * v) * decay
        warning_triangle.draw(cv, CENTER_X, CIRCLE_CY, h=TRI_H * s,
                              color=self.style["color"], alpha=a)
        # black inside the state-red fill stays black at any alpha
        brush.draw(cv, CENTER_X, CIRCLE_CY + BRUSH_DY * s, w=BRUSH_W * s,
                   color=colors.BLACK, alpha=a, swivel=swivel, bend=bend)


def add_args(ap):
    ap.add_argument("--treatment", choices=TREATMENTS, default=None,
                    help="pulse (wallet_wiped) or sweep (wallet_wiped_anim)")


def spec_from_args(args):
    return {} if args.treatment is None else dict(treatment=args.treatment)


status.register(ANIM, Wipe)
