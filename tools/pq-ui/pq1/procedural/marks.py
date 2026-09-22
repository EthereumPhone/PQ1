"""Result / notice marks — check, x (cancel), exclamation — and the
entry signs, plus / minus.

The home of PQ1's outcome iconography. check and x are the status system's
result glyphs (moved verbatim from pq1.components, which re-exports them and
keeps them registered in GLYPHS); exclamation is the notice mark used inside
the warning triangle; plus and minus are the increment / decrement signs an
entry screen shows beside its corner chevrons (the PIN row — typed signs
were too thin to read on glass, user request Sep 2026): the x mark's arm
span (0.6 r) and stroke (0.16 r), round-capped. All follow the components
glyph signature."""
import math

from .. import colors
from ..layout import SUP


def check(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in (color or colors.WHITE))
    pts = [((cx - 0.40 * r) * SUP, (cy + 0.02 * r) * SUP),
           ((cx - 0.10 * r) * SUP, (cy + 0.30 * r) * SUP),
           ((cx + 0.44 * r) * SUP, (cy - 0.28 * r) * SUP)]
    cv.d.line(pts, fill=col, width=int(round(0.16 * r * SUP)), joint="curve")
    rr = 0.08 * r * SUP
    for p in (pts[0], pts[2]):
        cv.d.ellipse([p[0] - rr, p[1] - rr, p[0] + rr, p[1] + rr], fill=col)


def x_mark(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in (color or colors.WHITE))
    X, Y, R = cx * SUP, cy * SUP, r * SUP
    ca, sa = math.cos(rot), math.sin(rot)

    def pt(px, py):
        return (X + (px * ca - py * sa) * R, Y + (px * sa + py * ca) * R)

    wd = int(0.16 * R)
    for pts in ([pt(-.30, -.30), pt(.30, .30)], [pt(.30, -.30), pt(-.30, .30)]):
        cv.d.line(pts, fill=col, width=wd, joint="curve")
        for px, py in pts:
            cv.d.ellipse([px - wd / 2, py - wd / 2, px + wd / 2, py + wd / 2], fill=col)


SIGN_STROKE = 0.16      # the signs' stroke as a fraction of r (the x mark's)


def _bars(cv, cx, cy, r, alpha, color, rot, vertical, stroke=SIGN_STROKE):
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in (color or colors.WHITE))
    X, Y, R = cx * SUP, cy * SUP, r * SUP
    ca, sa = math.cos(rot), math.sin(rot)

    def pt(px, py):
        return (X + (px * ca - py * sa) * R, Y + (px * sa + py * ca) * R)

    wd = max(1, int(round(stroke * R)))
    bars = [[pt(-.30, 0), pt(.30, 0)]]
    if vertical:
        bars.append([pt(0, -.30), pt(0, .30)])
    for pts in bars:
        cv.d.line(pts, fill=col, width=wd, joint="curve")
        for px, py in pts:
            cv.d.ellipse([px - wd / 2, py - wd / 2, px + wd / 2, py + wd / 2], fill=col)


def minus(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0, stroke=SIGN_STROKE):
    """the decrement sign: one bar on the x mark's span; stroke as a
    fraction of r (the x mark's 0.16 by default — an entry's hint row
    asks for a lighter one)"""
    _bars(cv, cx, cy, r, alpha, color, rot, vertical=False, stroke=stroke)


def plus(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0, stroke=SIGN_STROKE):
    """the increment sign: the bar and its upright"""
    _bars(cv, cx, cy, r, alpha, color, rot, vertical=True, stroke=stroke)


def exclamation(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """exclamation mark, optically centred on (cx, cy), half-height ~= r.
    Proportions from the sig_error notice art (bar w 4s, len 22s, dot r 2.8s,
    7s gap, s = r / 16); draw black on a warning triangle."""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in (color or colors.WHITE))
    s = r / 16.0
    mw = 4 * s
    x0, y0 = (cx - mw / 2) * SUP, (cy - 15.9 * s) * SUP
    x1, y1 = (cx + mw / 2) * SUP, (cy + 6.1 * s) * SUP
    cv.d.rounded_rectangle((x0, y0, x1, y1), radius=mw / 2 * SUP, fill=col)
    rr = 2.8 * s * SUP
    dx, dy = cx * SUP, (cy + 13.1 * s) * SUP
    cv.d.ellipse((dx - rr, dy - rr, dx + rr, dy + rr), fill=col)
