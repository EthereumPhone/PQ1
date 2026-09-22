"""PIN pill — the four-dot PIN chip the pin-error screens rest on.

Geometry from the design-canvas pin error mockups (pin_missmatch.py,
pin_differ-2.py): a 108 x 36 rounded outline centred on the circle grid,
stroke 2.6, holding up to four r-8 dots on a 24 px pitch. The screens own
the entry state — they pass one alpha per dot — and the rig also carries
the scanline that sweeps the pill while a PIN is checked: a short thick
bar overhanging the pill 7 px top and bottom, black-stroked so it stays
legible crossing the outline, fading away as the sweep ends.

API convention: draw(cv, cx, cy, *, color, alpha=1.0, scale, dots).
"""
import math

from .. import colors
from ..layout import CENTER_X, CIRCLE_CY
from ..motion import clamp01, ease_out

# source geometry (both mockups agree), in UI px
PW, PH = 108.0, 36.0     # pill box
STROKE = 2.6
DOT_R, SPAN = 8.0, 24.0  # dot radius, centre-to-centre pitch
SLOTS = 4

# the check sweep
SCAN_HW = 4.0        # bar half-width
SCAN_OVER = 7.0      # overhang past the pill, top and bottom
SCAN_INSET = 8.0     # travel inset from each pill end
SCAN_STROKE = 1.6
SCAN_FADE = 0.1      # the bar fades out over the sweep's last tenth


def draw(cv, cx=CENTER_X, cy=CIRCLE_CY, *, color, alpha=1.0, scale=1.0,
         dots=()):
    """the pill centred on (cx, cy), one filled dot per entry in dots (its
    own 0..1 alpha, left to right); scale is the entrance rise"""
    if alpha <= 0.01:
        return
    s = scale
    cv.rounded_rect((cx - PW / 2 * s, cy - PH / 2 * s,
                     cx + PW / 2 * s, cy + PH / 2 * s), PH / 2 * s,
                    outline=colors.scale(color, alpha), width=STROKE * s)
    for i, da in enumerate(dots):
        a = alpha * clamp01(da)
        if a <= 0.01:
            continue
        cv.circle(cx + (i - (SLOTS - 1) / 2.0) * SPAN * s, cy, DOT_R * s,
                  colors.scale(color, a))


def scanline(cv, cx, cy, u, *, color, alpha=1.0, scale=1.0, cycles=1.0):
    """the check sweep at unit progress u: the bar ping-pongs across the
    pill `cycles` times (1 comes back where it started, 1.5 ends at the far
    end) and fades out over SCAN_FADE, the sweep's tail"""
    a = alpha * ease_out(clamp01((1 - u) / SCAN_FADE))
    if a <= 0.01:
        return
    s = scale
    pos = 0.5 - 0.5 * math.cos(clamp01(u) * math.pi * 2 * cycles)
    x = cx + (-PW / 2 + SCAN_INSET + (PW - 2 * SCAN_INSET) * pos) * s
    k = int(round(255 * a))
    cv.rounded_rect((x - SCAN_HW * s, cy - (PH / 2 + SCAN_OVER) * s,
                     x + SCAN_HW * s, cy + (PH / 2 + SCAN_OVER) * s),
                    SCAN_HW * s, fill=(*color, k),
                    outline=(*colors.BLACK, k), width=SCAN_STROKE * s)
