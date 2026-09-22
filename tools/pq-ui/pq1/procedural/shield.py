"""Encrypted-backup shield outline.

Centerline traced from encrypted.svg (51 x 63 design box), drawn as a
closed stroked loop with round joints. The module draws the outline only —
screens compose marks.check / marks.x_mark on top for the backup_ok /
no_match verdicts."""
from .. import colors
from ..layout import SUP
from .geometry import bezier


def _outline():
    """centerline of the encrypted.svg shield (51 x 63 design box)"""
    pts = []
    pts += bezier((24.0615, 1.73633), (24.9944, 1.4217), (26.0056, 1.4217),
                  (26.9385, 1.73633), n=18)
    pts.append((46.4385, 8.3125))
    pts += bezier((46.4385, 8.3125), (48.268, 8.9297), (49.4999, 10.6453),
                  (49.5, 12.5762), n=18)
    pts.append((49.5, 27.3076))
    pts += bezier((49.5, 27.3076), (49.5, 35.0972), (47.21, 42.2514),
                  (42.6016, 48.8057), n=18)
    pts += bezier((42.6016, 48.8057), (38.4092, 54.768), (33.2021, 58.7008),
                  (26.9746, 60.6895), n=18)
    pts += bezier((26.9746, 60.6895), (26.0159, 60.9956), (24.9841, 60.9956),
                  (24.0254, 60.6895), n=18)
    pts += bezier((24.0254, 60.6895), (17.7979, 58.7008), (12.5908, 54.768),
                  (8.39844, 48.8057), n=18)
    pts += bezier((8.39844, 48.8057), (3.79, 42.2514), (1.5, 35.0972),
                  (1.5, 27.3076), n=18)
    pts.append((1.5, 12.5762))
    pts += bezier((1.5, 12.5762), (1.50013, 10.6453), (2.732, 8.9297),
                  (4.56152, 8.3125), n=18)
    pts.append((24.0615, 1.73633))
    return pts


_SHIELD = _outline()


def draw(cv, cx, cy, *, h, color, alpha=1.0, lw=None):
    """shield outline, h UI px tall, design-box centre on (cx, cy).
    lw defaults to the source stroke, 3 px at the design height of 63."""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    k = (h / 63.0) * SUP
    ox, oy = cx * SUP - 25.5 * k, cy * SUP - 31.5 * k
    pts = [(ox + x * k, oy + y * k) for x, y in _SHIELD]
    w = (lw if lw is not None else 3.0 * h / 63.0) * SUP
    cv.d.line(pts, fill=col, width=int(round(w)), joint="curve")


def glyph(lw=None):
    """freeze into the components glyph signature. r maps to h / 2: the
    design box is taller than wide, so r is the half-height and the shield
    spans 2r vertically (width follows at 51/63). rot is ignored."""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, h=2.0 * r, color=color or colors.WHITE,
             alpha=alpha, lw=lw)
    return fn
