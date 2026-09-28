"""Bezier heart — the last-attempt verdict's companion mark.

Nine cubic segments (rounded lobes, soft notch, rounded bottom tip) on a
40 x 34.6 design box, ported verbatim from the last_attempt mockup. The
module is static: the heartbeat pulse is the caller's job (they scale h
frame by frame)."""

from .. import colors
from . import geometry

# design-box outline (40 wide, ~34.6 tall), flattened once at import
_SEGS = [
    ((21.6, 33.4), (20.7, 34.2), (19.3, 34.2), (18.4, 33.4)),  # bottom cap
    ((18.4, 33.4), (10.2, 26.6), (4.5, 21.2), (1.9, 15.9)),    # left flank
    ((1.9, 15.9), (0.6, 13.2), (0.0, 11.4), (0.0, 9.4)),
    ((0.0, 9.4), (0.0, 4.1), (4.2, 0.0), (9.6, 0.0)),          # left lobe
    ((9.6, 0.0), (13.6, 0.0), (17.4, 2.6), (20.0, 6.3)),       # notch
    ((20.0, 6.3), (22.6, 2.6), (26.4, 0.0), (30.4, 0.0)),      # right lobe
    ((30.4, 0.0), (35.8, 0.0), (40.0, 4.1), (40.0, 9.4)),
    ((40.0, 9.4), (40.0, 11.4), (39.4, 13.2), (38.1, 15.9)),
    ((38.1, 15.9), (35.5, 21.2), (29.8, 26.6), (21.6, 33.4)),  # right flank
]
_BOX_W, _BOX_H = 40.0, 34.6
_OUTLINE = [p for seg in _SEGS for p in geometry.bezier(*seg, n=22)]


def draw(cv, cx, cy, *, h, color, alpha=1.0):
    """filled heart, h UI px tall, design box centred on (cx, cy)"""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    k = h / _BOX_H
    ox, oy = cx - _BOX_W / 2 * k, cy - _BOX_H / 2 * k
    cv.polygon([(ox + x * k, oy + y * k) for x, y in _OUTLINE], fill=col)


def glyph(k=2.0):
    """components-style glyph: heart height frozen at k * r (default 2.0,
    the heart spans the token's full height)"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, h=k * r, color=color or colors.WHITE, alpha=alpha)
    return fn
