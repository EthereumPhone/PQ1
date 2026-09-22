"""3-axis rotating die — the RNG die, rigged for the tumble.

Fully procedural 3D die ported verbatim from the rng_failed mockup: a
unit cube rotated with X/Y/Z matrices, orthographically projected and
back-face culled; pips are circles sampled on each face plane and
projected, so they foreshorten correctly. Standard western layout
(1-2-3 counterclockwise around a corner, opposite faces sum 7). Faces
are rounded silhouettes with black edge strokes and black pips; the
source's 3.5 px corner radius and 2 px stroke (at half-edge 21) scale
with size; the silhouettes use geometry.rounded_polygon (n=6), which
matches the source's rounded_poly exactly except that its corner-trim
clamp only engages on faces foreshortened below ~7 px, where the
source's trim would self-cross. rot = (ax, ay, az) radians is the full pose; REST is the
source's settled corner view showing the 1-2-3 corner. The tumble
timing is the screen's job — this module just draws at an
orientation.

sweep is the motion blur: the per-axis angles the die turned during the
exposure, trailing behind rot. The die is averaged over that arc of
poses the way a camera's open shutter smears a thrown die, so a fast
tumble reads as a blur that resolves into faces as it slows — without
it the 14 fps panel samples the launch (~55 degrees a frame about one
axis, over the cube's 90-degree symmetry) as a strobe of unrelated
poses. sweep (0, 0, 0) draws the sharp die."""
import math

from PIL import Image, ImageDraw

from .. import colors
from ..layout import SUP
from .geometry import rounded_polygon

# the source's settled corner view (rotX -0.62, rotY 0.66): three faces
REST = (-0.62, 0.66, 0.0)
BLUR_STEP = math.radians(2.0)   # one exposure sample per 2 degrees swept
BLUR_SAMPLES_MAX = 48


def _rot_xyz(p, ax, ay, az):
    x, y, z = p
    c, s = math.cos(ax), math.sin(ax)
    y, z = y * c - z * s, y * s + z * c
    c, s = math.cos(ay), math.sin(ay)
    x, z = x * c + z * s, -x * s + z * c
    c, s = math.cos(az), math.sin(az)
    x, y = x * c - y * s, x * s + y * c
    return (x, y, z)


def _pips(n):
    o = 0.62
    return {
        1: [(0, 0)],
        2: [(-o, -o), (o, o)],
        3: [(-o, -o), (0, 0), (o, o)],
        4: [(-o, -o), (o, -o), (-o, o), (o, o)],
        5: [(-o, -o), (o, -o), (0, 0), (-o, o), (o, o)],
        6: [(-o, -o), (o, -o), (-o, 0), (o, 0), (-o, o), (o, o)],
    }[n]


# standard western die: 1-2-3 counterclockwise around a corner, opposites sum 7
_FACES = [
    dict(n=(0, 0, 1), u=(1, 0, 0), v=(0, 1, 0), pips=1),
    dict(n=(0, 0, -1), u=(-1, 0, 0), v=(0, 1, 0), pips=6),
    dict(n=(1, 0, 0), u=(0, 0, -1), v=(0, 1, 0), pips=2),
    dict(n=(-1, 0, 0), u=(0, 0, 1), v=(0, 1, 0), pips=5),
    dict(n=(0, 1, 0), u=(1, 0, 0), v=(0, 0, -1), pips=3),
    dict(n=(0, -1, 0), u=(1, 0, 0), v=(0, 0, 1), pips=4),
]


def _add(a, b, k):
    return (a[0] + b[0] * k, a[1] + b[1] * k, a[2] + b[2] * k)


def _draw_pose(d, cx, cy, size, col, rot, ox=0, oy=0):
    """the die's visible faces at rot onto the ImageDraw d, in
    supersampled pixels offset by (ox, oy)"""
    ax, ay, az = rot
    k = size / 21.0

    def R(p):
        return _rot_xyz(p, ax, ay, az)

    def P(p):
        return (cx * SUP + p[0] * size * SUP - ox,
                cy * SUP - p[1] * size * SUP - oy)

    for f in _FACES:
        n3 = R(f["n"])
        if n3[2] <= 0.02:
            continue
        u3, v3, c3 = R(f["u"]), R(f["v"]), n3
        corners = [P(_add(_add(c3, u3, a), v3, b))
                   for a, b in ((-1, -1), (1, -1), (1, 1), (-1, 1))]
        d.polygon(rounded_polygon(corners, 3.5 * k * SUP, n=6),
                  fill=col, outline=colors.BLACK,
                  width=int(round(2 * k * SUP)))
        pip_r = 0.185
        spread = 0.78 if f["pips"] == 6 else 0.72
        for pu, pv in _pips(f["pips"]):
            center = _add(_add(c3, u3, pu * spread), v3, pv * spread)
            ring = []
            for i in range(13):
                a = i / 12 * 2 * math.pi
                q = _add(_add(center, u3, math.cos(a) * pip_r),
                         v3, math.sin(a) * pip_r)
                ring.append(P(q))
            d.polygon(ring, fill=colors.BLACK)


def draw(cv, cx, cy, *, size, color, alpha=1.0, rot=(0.0, 0.0, 0.0),
         sweep=(0.0, 0.0, 0.0)):
    """die at (cx, cy): size = half-edge in UI px (source SIZE 21),
    rot = (ax, ay, az) radians applied X then Y then Z, motion-blurred
    over the sweep (per-axis radians) it turned through behind rot"""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    n = min(BLUR_SAMPLES_MAX,
            int(math.ceil(max(abs(a) for a in sweep) / BLUR_STEP)))
    if n < 2:
        _draw_pose(cv.d, cx, cy, size, col, rot)
        return
    # the exposure: n poses spread across (rot - sweep, rot], each drawn
    # over a copy of what lies under the die and averaged in — a running
    # mean, the i-th pose blended in at 1 / i — inside the box any pose
    # can reach (the cube's space diagonal plus the stroke)
    reach = size * math.sqrt(3) + 2.0 * size / 21.0 + 1.0
    ox = int(math.floor((cx - reach) * SUP))
    oy = int(math.floor((cy - reach) * SUP))
    w = int(math.ceil(2 * reach * SUP)) + 2
    base = cv.img.crop((ox, oy, ox + w, oy + w))
    acc = None
    for i in range(n):
        pose = base.copy()
        _draw_pose(ImageDraw.Draw(pose, "RGBA"), cx, cy, size, col,
                   tuple(r - s * (i + 0.5) / n for r, s in zip(rot, sweep)),
                   ox, oy)
        acc = pose if acc is None else Image.blend(acc, pose, 1.0 / (i + 1))
    cv.paste(acc, ox, oy)


def glyph(rot=REST):
    """freeze a pose into the components glyph signature; the default is
    the settled corner view. r is the half-edge, so r=21 reproduces the
    source die. The runtime rot spins the projected die in the screen
    plane (it stacks onto az, the last matrix)."""
    ax0, ay0, az0 = rot

    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, size=r, color=color or colors.RED, alpha=alpha,
             rot=(ax0, ay0, az0 + rot))
    return fn
