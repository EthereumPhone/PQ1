"""Warning triangle — the rounded alert triangle behind the notice marks.

Apex-up filled triangle, corners trimmed by rr along both edges and bridged
with flattened quadratics whose control point is the original vertex —
geometry.rounded_polygon, verified bit-identical to the wallet_wiped /
sig_error construction. Proportions from those sources: bounding box
72 x 64 units (half-width 36, half-height 32), corner radius 6, all
normalized to h. The exclamation mark is NOT drawn here — it lives in
marks.exclamation; screens compose the two."""
from .. import colors
from ..layout import VERDICT_BOX
from . import geometry

# The notice sign's height — the one number TAMPER, WALLET WIPED and SIG
# ERROR draw their triangle at (audit ICO-03 / ICO-06: one box for every
# sign, the centred slot and the column slot alike). The rounded 72 x 64
# source triangle inks 16/15 of its height WIDE (measured 64.0 wide at
# h 60 on the 3x grid — the rounded corners trim the 9/8 bounding box),
# so the box sizes its WIDTH and the height follows.
NOTICE_H = VERDICT_BOX * 15 / 16


def draw(cv, cx, cy, *, h, color, alpha=1.0, rr=None):
    """filled rounded triangle, h tall and 1.125 * h wide, its (un-rounded)
    bounding box centred on (cx, cy); rr defaults to the source's 6/64 of
    the height"""
    if alpha <= colors.ALPHA_FLOOR:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    s = h / 64.0
    if rr is None:
        rr = 6 * s
    pts3 = [(cx, cy - 32 * s), (cx + 36 * s, cy + 32 * s),
            (cx - 36 * s, cy + 32 * s)]
    cv.polygon(geometry.rounded_polygon(pts3, rr, n=8), fill=col)


def glyph(rr=None):
    """freeze a pose into the components glyph signature; the triangle
    spans the r circle top to bottom (h = 2 * r, the source's slot fit)"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, h=2 * r, color=color or colors.WHITE,
             alpha=alpha, rr=rr)
    return fn
