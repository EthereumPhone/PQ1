"""Result / notice marks — check, x (cancel), exclamation — the entry
signs, plus / minus — and dots, the setup family's 3 x 3 dot grid.

The home of PQ1's outcome iconography. check and x are the status system's
result glyphs (moved verbatim from pq1.components, which re-exports them and
keeps them registered in GLYPHS); exclamation is the notice mark used inside
the warning triangle; plus and minus are the increment / decrement signs an
entry screen shows beside its corner chevrons (the PIN row — typed signs
were too thin to read on glass, user request Sep 2026): the x mark's arm
span (0.6 r) and stroke (SIGN_STROKE, 0.16 r), round-capped. All follow the
components glyph signature.

Two compositing models live here, on purpose. check, x_mark and dots REST
ON A DISC — the SAFE green, the cancel red, the setup white — so they go through base_mark and
fade by true alpha; the exclamation fades inside its own triangle and the
signs sit on the black panel, so they scale their colour toward black, which
is exact there (pq1.canvas's idiom)."""
import math

from PIL import Image, ImageDraw

from .. import colors
from ..layout import SUP

SIGN_STROKE = 0.16      # the result marks' and the signs' stroke, a fraction of r
DOTS_R = 0.10           # the dot grid's dot radius, a fraction of r
DOTS_PITCH = 0.32       # the dot grid's centre-to-centre pitch, a fraction of r


def base_mark(cv, paint, cx, cy, r, color=None, alpha=1.0, rot=0.0, pad=4):
    """draw a mark by TRUE alpha: `paint(d, ox, oy, R, a)` inks the shape
    into an L mask — an ImageDraw whose centre is (ox, oy), R = r * SUP the
    supersampled radius, a = int(255 * alpha) the ink value — and the tile
    is pasted in `color` through that mask. The one compositing model for a
    mark that sits on a disc (audit ICO-01; re-exported as
    components.base_mark): scaling the colour toward black instead is exact
    only on the black panel — on a lit disc a black check scaled by alpha is
    still black, so SAFE SIGNED's mark cut in at full strength on frame one
    while the caption faded. The traced marks (eth, the chains, blind, dev,
    rotate, fingerprint, download) build the same tile themselves. rot turns
    the mask; the tile side covers the diagonal so a turn never clips, and it
    is EVEN, so the tile's centre is a whole pixel and the rounded paste
    lands it on (cx, cy) exactly — an odd side or a truncated paste sat
    every mark half a supersampled pixel up and left (audit ICO-09)."""
    if alpha <= colors.ALPHA_FLOOR:
        return
    R = r * SUP
    side = int(math.ceil(2 * R * math.sqrt(2))) + 2 * pad
    side += side % 2
    mask = Image.new("L", (side, side), 0)
    paint(ImageDraw.Draw(mask), side / 2, side / 2, R, int(round(255 * alpha)))
    if rot:
        mask = mask.rotate(-math.degrees(rot), resample=Image.BICUBIC)
    tile = Image.new("RGBA", (side, side), (*tuple(color or colors.WHITE), 255))
    tile.putalpha(mask)
    cv.paste(tile, int(round(cx * SUP - side / 2)),
             int(round(cy * SUP - side / 2)), tile)


def check(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """the result check: a round-capped SIGN_STROKE polyline, arms
    -0.40 .. +0.44 r; true alpha (base_mark) — it rests on lit discs"""
    def paint(d, ox, oy, R, a):
        pts = [(ox - 0.40 * R, oy + 0.02 * R), (ox - 0.10 * R, oy + 0.30 * R),
               (ox + 0.44 * R, oy - 0.28 * R)]
        d.line(pts, fill=a, width=int(round(SIGN_STROKE * R)), joint="curve")
        rr = 0.08 * R
        for p in (pts[0], pts[2]):
            d.ellipse([p[0] - rr, p[1] - rr, p[0] + rr, p[1] + rr], fill=a)
    base_mark(cv, paint, cx, cy, r, color, alpha, rot)


def x_mark(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """the cancel X: two round-capped SIGN_STROKE bars over ±0.30 r; true
    alpha (base_mark) — it rests on the cancel red"""
    def paint(d, ox, oy, R, a):
        wd = int(SIGN_STROKE * R)
        for pts in ([(ox - .30 * R, oy - .30 * R), (ox + .30 * R, oy + .30 * R)],
                    [(ox + .30 * R, oy - .30 * R), (ox - .30 * R, oy + .30 * R)]):
            d.line(pts, fill=a, width=wd, joint="curve")
            for px, py in pts:
                d.ellipse([px - wd / 2, py - wd / 2, px + wd / 2, py + wd / 2], fill=a)
    base_mark(cv, paint, cx, cy, r, color, alpha, rot)


def _bars(cv, cx, cy, r, alpha, color, rot, vertical, stroke=SIGN_STROKE):
    if alpha <= colors.ALPHA_FLOOR:
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


def dots(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """the 3 x 3 dot grid — the setup family's mark (a new device, a keypad
    of choices to come): nine round dots DOTS_PITCH apart, each
    DOTS_R across its radius; true alpha (base_mark) — it rests on the
    white disc"""
    def paint(d, ox, oy, R, a):
        rr = DOTS_R * R
        for i in (-1, 0, 1):
            for j in (-1, 0, 1):
                px, py = ox + DOTS_PITCH * R * i, oy + DOTS_PITCH * R * j
                d.ellipse([px - rr, py - rr, px + rr, py + rr], fill=a)
    base_mark(cv, paint, cx, cy, r, color, alpha, rot)


def exclamation(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
    """exclamation mark, optically centred on (cx, cy), half-height ~= r.
    Proportions from the sig_error notice art (bar w 4s, len 22s, dot r 2.8s,
    7s gap, s = r / 16); draw black on a warning triangle."""
    if alpha <= colors.ALPHA_FLOOR:
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
