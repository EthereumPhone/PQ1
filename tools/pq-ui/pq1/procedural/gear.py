"""8-tooth factory gear — the signing-machine cog.

Ported from the factory-signing mockup (source drew at R = 32, factory
blue). Proportions, normalized to r = outer radius including teeth:
body disc 0.80 r, hole 0.44 r, tooth width = ring thickness (0.36 r),
tooth height 0.20 r, tooth corner radius 0.08 r, teeth seated 0.125 r
into the body so the join never shows a seam. The hole is punched with
a black ellipse, as in the source. rot spins the gear (radians); the
freewheel timing is the screen's job — this module just draws at an
angle.

sweep is the motion blur: the angle the gear turned during the exposure,
trailing behind rot. The teeth are averaged over that arc the way a
camera's open shutter smears a spinning wheel, so a fast spin reads as a
blur that resolves into teeth as it slows — without it the 14 fps panel
samples the 45-degree tooth pattern too coarsely and a fast gear appears
to crawl backwards (the wagon-wheel effect). The body and hole are round,
so only the teeth blur; sweep 0 draws the sharp gear."""
import math

from PIL import Image, ImageChops, ImageDraw

from .. import colors
from ..layout import SUP

TEETH = 8
BLUR_STEP = math.radians(2.0)   # one exposure sample per 2 degrees swept
BLUR_SAMPLES_MAX = 48


def _rounded_rect_poly(x0, y0, x1, y1, rad, steps=6):
    """rounded rectangle as a polygon (for rotation) — circular-arc
    corners, ported verbatim from the source (geometry.rounded_polygon
    bridges corners with quadratic beziers, which sag slightly)"""
    pts = []
    corners = [(x1 - rad, y0 + rad, -90, 0), (x1 - rad, y1 - rad, 0, 90),
               (x0 + rad, y1 - rad, 90, 180), (x0 + rad, y0 + rad, 180, 270)]
    for cx, cy, a0, a1 in corners:
        for i in range(steps + 1):
            a = math.radians(a0 + (a1 - a0) * i / steps)
            pts.append((cx + rad * math.cos(a), cy + rad * math.sin(a)))
    return pts


def _teeth(local, cx, cy, rot):
    """the tooth polygons at rot, in UI pixels"""
    for i in range(TEETH):
        a = rot + i / TEETH * 2 * math.pi
        ca, sa = math.cos(a), math.sin(a)
        yield [(cx + lx * ca - ly * sa, cy + lx * sa + ly * ca)
               for lx, ly in local]


def _blurred_teeth(cv, local, cx, cy, r, rot, sweep, col, n):
    """the teeth averaged over n poses spread across (rot - sweep, rot]:
    every pose adds an equal share to a coverage mask, and the colour is
    pasted through it"""
    ox = int(math.floor((cx - r) * SUP)) - 2
    oy = int(math.floor((cy - r) * SUP)) - 2
    size = int(math.ceil(2 * r * SUP)) + 4
    share = 255 // n
    acc = Image.new("L", (size, size), 0)
    for k in range(n):
        pose = Image.new("L", (size, size), 0)
        d = ImageDraw.Draw(pose)
        for poly in _teeth(local, cx, cy, rot - sweep * (k + 0.5) / n):
            d.polygon([(x * SUP - ox, y * SUP - oy) for x, y in poly],
                      fill=share)
        acc = ImageChops.add(acc, pose)      # n * share <= 255: never clips
    full = share * n
    mask = acc.point(lambda p: min(255, round(p * 255 / full)))
    cv.paste(Image.new("RGB", (size, size), col), ox, oy, mask)


def draw(cv, cx, cy, *, r, color, alpha=1.0, rot=0.0, sweep=0.0):
    """8-tooth gear at (cx, cy): body circle + rotated rounded teeth
    (motion-blurred over sweep radians behind rot), hole punched black"""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    body_r = r * 0.80
    hole_r = r * 0.44
    tw = body_r - hole_r          # tooth width = ring thickness
    th = r * 0.20
    tr = r * 0.08

    cv.circle(cx, cy, body_r, col)
    local = _rounded_rect_poly(-tw / 2, -body_r - th, tw / 2,
                               -body_r + 0.125 * r, tr)
    n = min(BLUR_SAMPLES_MAX, math.ceil(abs(sweep) / BLUR_STEP))
    if n >= 2:
        _blurred_teeth(cv, local, cx, cy, r, rot, sweep, col, n)
    else:
        for poly in _teeth(local, cx, cy, rot):
            cv.polygon(poly, fill=col)
    # punch the hole
    cv.circle(cx, cy, hole_r, colors.BLACK)


def glyph(rot=0.0):
    """gear frozen at rot, with the components glyph signature (the
    runtime rot spins on top of the frozen pose)"""
    base = rot

    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, r=r, color=color or colors.FACTORY_BLUE,
             alpha=alpha, rot=base + rot)
    return fn
