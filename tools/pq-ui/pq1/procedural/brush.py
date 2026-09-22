"""Wipe brush — the wallet-wiped icon, rigged for the swiffle sweep.

Procedural brush in a 32 x 26 local box (mirrors brush.svg): a rounded
handle flaring into a wide head bar, plus a flared bristle strip with six
rounded notches cut into its top edge. The rig swivels the whole brush
around the top of its handle (local pivot 16, 0) while the bristle strip
warps quadratically against the ground, dragging opposite the motion.
swivel=0, bend=0 is the static wallet-wiped pose. Ported verbatim from
wallet_wiped_anim.py draw_brush (which subsumes wallet_wiped.py's)."""
import math

from .. import colors
from ..layout import SUP
from .geometry import bezier, quad_bezier


def draw(cv, cx, cy, *, w=30, color, alpha=1.0, swivel=0.0, bend=0.0):
    """brush centred on (cx, cy), w px wide; swivel in radians (source
    sweep range ~±0.30), bend is the bristle drag (~±0.28)"""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    k = w / 32.0
    ox, oy = cx - 16 * k, cy - 13 * k
    ca, sa = math.cos(swivel), math.sin(swivel)

    def T(pts):
        out = []
        for x, y in pts:
            # rotate around the local handle-top pivot (16, 0)
            rx, ry = x - 16, y
            x2 = 16 + rx * ca - ry * sa
            y2 = rx * sa + ry * ca
            out.append(((ox + x2 * k) * SUP, (oy + y2 * k) * SUP))
        return out

    # handle + flared head
    body = [(12.9, 10.6), (12.9, 3.1)]
    body += quad_bezier((12.9, 3.1), (12.9, 0), (16, 0), 8)
    body += quad_bezier((16, 0), (19.1, 0), (19.1, 3.1), 8)
    body.append((19.1, 10.6))
    body += bezier((19.1, 10.6), (19.1, 13), (21, 14.2), (22.6, 14.2), 10)
    body.append((25.8, 14.2))
    body += bezier((25.8, 14.2), (28.3, 14.3), (29.6, 15.5), (30.1, 17), 10)
    body += quad_bezier((30.1, 17), (30.5, 18.2), (30.6, 20), 8)
    body.append((1.4, 20))
    body += quad_bezier((1.4, 20), (1.5, 18.2), (1.9, 17), 8)
    body += bezier((1.9, 17), (2.4, 15.5), (3.7, 14.3), (6.2, 14.2), 10)
    body.append((9.4, 14.2))
    body += bezier((9.4, 14.2), (11, 14.2), (12.9, 13), (12.9, 10.6), 10)
    cv.d.polygon(T(body), fill=col)

    # bristle strip: flared bar, six rounded notches in the top edge,
    # quadratic ground-drag warp (top edge stays glued to the head)
    sy = 21.8
    notch_w, notch_d, nr = 1.29, 2.29, 0.645
    strip = [(0.9, sy)]
    for i in range(6):
        n0 = 3.13 + i * 5.06
        n1 = n0 + notch_w
        strip.append((n0, sy))
        strip.append((n0, sy + notch_d - nr))
        strip += quad_bezier((n0, sy + notch_d - nr), (n0, sy + notch_d),
                             (n0 + notch_w / 2, sy + notch_d), 5)
        strip += quad_bezier((n0 + notch_w / 2, sy + notch_d),
                             (n1, sy + notch_d), (n1, sy + notch_d - nr), 5)
        strip.append((n1, sy))
    strip += [(31.1, sy), (32, sy + 4.2), (0, sy + 4.2)]
    warped = []
    for x, y in strip:
        dy = max(0.0, y - sy)
        warped.append((x + bend * dy * dy / 3.2, y))
    cv.d.polygon(T(warped), fill=col)


def glyph(swivel=0.0, bend=0.0):
    """freeze a pose into the components glyph signature; the default is
    the static wallet-wiped rest pose. w tracks r, so r=30 (the main
    circle radius) reproduces the source's 30 px brush."""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, w=r, color=color or colors.WHITE, alpha=alpha,
             swivel=swivel, bend=bend)
    return fn
