"""Wallet wiped — the warning triangle carries the brush.

Preset wallet_wiped_anim (the one WALLET WIPED sign — the pulse
treatment was retired, user request Sep 2026): the icon arrives, rests a
beat, then the brush swiffles — swinging around the top of its handle
while the bristle strip drags against the ground, curving opposite the
motion.

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
from pq1.procedural import brush, warning_triangle
from pq1.verdict import VerdictAnim

ANIM = "wipe"
SPEC = dict(state="failed", bottom="WALLET WIPED")
PRESETS = dict(wallet_wiped_anim=dict(),
               wallet_wiped_explosion=dict(
                   lead_clear=700,
                   lead=dict(anim="explosion", severity="major",
                             enter="sides", busy_until="boom",
                             revs=loading.REVS_LONG,   # two turns past the stock 3: it endures
                             busy=["WIPING…", "DO NOT POWER OFF"],
                             body=list(colors.RED), trail=list(colors.RED),
                             clump_from=list(colors.RED),
                             clump_to=list(colors.RED),   # unset = white
                             ring=list(colors.RED))))

# the triangle's height is the notice token — the sign box sizes its width
# (warning_triangle.NOTICE_H, audit ICO-03); TRI_H is the name the handoff
# pages cite, never a second number
TRI_H = warning_triangle.NOTICE_H
# the brush was drawn against the sources' h-64 triangle (bounding box
# 72 x 64 units): 30 wide, its centre 9 below the triangle's. Both ride
# UNIT — one source unit in UI px; the 64.0 is the SOURCE box's height,
# not the icon box — so the brush keeps its proportion inside the sign
UNIT = TRI_H / 64.0
BRUSH_W = 30 * UNIT     # brush width; its centre sits BRUSH_DY below the triangle's
BRUSH_DY = 9 * UNIT

T_MARK = 300    # beat between entrance and accent
ACCENT = 1400   # the brush swiffle


class Wipe(VerdictAnim):
    T_WAIT = T_MARK + ACCENT

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive
        swivel = bend = 0.0
        v = (t - (self.T_HOLD + self.T_IN + T_MARK)) / ACCENT
        if 0.0 < v < 1.0:
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


status.register(ANIM, Wipe)
