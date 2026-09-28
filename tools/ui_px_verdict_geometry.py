#!/usr/bin/env python3
"""Bake the verdict signs' outlines into `pqsigner-ui-px/src/verdict_geom.rs`.

The PQ-UI signs are procedural Python (`tools/pq-ui/pq1/procedural/`): beziers
and rounded polygons drawn with Pillow. The firmware rasteriser draws static
outlines (`raster::Item::Shape`, Q4 = 1/16 px, at the design size) placed by
a transform, so this script flattens each outline once, from the vendored
sources' own constants, and writes them as Rust `const` arrays.

    python3 tools/ui_px_verdict_geometry.py            # rewrite the file
    python3 tools/ui_px_verdict_geometry.py --check    # fail if stale

Rounded convex outlines (the triangle, the die faces, the gear tooth, the
keyhole) are baked as the polygon INSET by the corner radius; the rasteriser
grows them back (`ShapeMode::Fill { grow }`), which is the exact circular-arc
rounding (the sources' quadratic corners sag a hair less). Every outline is
at most `raster::SHAPE_MAX_PTS` (48) points.
"""
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "pqsigner-ui-px/src/verdict_geom.rs"
MAX_PTS = 48


def bezier(p0, p1, p2, p3, n):
    out = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        out.append((mt ** 3 * p0[0] + 3 * mt * mt * t * p1[0] + 3 * mt * t * t * p2[0] + t ** 3 * p3[0],
                    mt ** 3 * p0[1] + 3 * mt * mt * t * p1[1] + 3 * mt * t * t * p2[1] + t ** 3 * p3[1]))
    return out


def quad(p0, p1, p2, n):
    out = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        out.append((mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0],
                    mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]))
    return out


def dedup(pts):
    out = []
    for p in pts:
        if not out or abs(out[-1][0] - p[0]) > 1e-6 or abs(out[-1][1] - p[1]) > 1e-6:
            out.append(p)
    if len(out) > 1 and abs(out[0][0] - out[-1][0]) < 1e-6 and abs(out[0][1] - out[-1][1]) < 1e-6:
        out.pop()
    return out


def inset_convex(pts, d):
    """offset every edge of a convex polygon inward by d and re-intersect"""
    n = len(pts)
    # orientation: positive area = clockwise on a y-down screen
    area = sum(pts[i][0] * pts[(i + 1) % n][1] - pts[(i + 1) % n][0] * pts[i][1] for i in range(n))
    sgn = 1 if area > 0 else -1
    lines = []
    for i in range(n):
        (x0, y0), (x1, y1) = pts[i], pts[(i + 1) % n]
        dx, dy = x1 - x0, y1 - y0
        ln = math.hypot(dx, dy)
        # inward normal
        nx, ny = -dy / ln * sgn, dx / ln * sgn
        lines.append(((x0 + nx * d, y0 + ny * d), (dx, dy)))
    out = []
    for i in range(n):
        (p, r), (q, s) = lines[i - 1], lines[i]
        den = r[0] * s[1] - r[1] * s[0]
        t = ((q[0] - p[0]) * s[1] - (q[1] - p[1]) * s[0]) / den
        out.append((p[0] + r[0] * t, p[1] + r[1] * t))
    return out


def q4(pts):
    return [(int(round(x * 16)), int(round(y * 16))) for x, y in pts]


# ---- the warning triangle (warning_triangle.py: 72 x 64 box, rr 6) ---------
TRI = inset_convex([(0, -32), (36, 32), (-36, 32)], 6.0)

# ---- the exclamation (marks.exclamation at r 16, +6.4 px in the triangle) ---
EXCL_BAR = [(0, -15.9 + 2 + 6.4), (0, 6.1 - 2 + 6.4)]   # capsule hw 2
# the dot: r 2.8 at y 13.1 + 6.4 (drawn as a disc)

# ---- the padlock (padlock.py) -----------------------------------------------
ARM = 11.5
# the arch, relative to the pivot leg's top (the right leg), centre (-ARM, 0)
SHACKLE_ARCH = [(-ARM + ARM * math.cos(math.pi - math.pi * i / 12), -ARM * math.sin(math.pi - math.pi * i / 12))
                for i in range(13)]
UNIT_LEG = [(0.0, 0.0), (0.0, 1.0)]          # scaled to a leg's length
KEYHOLE = [(-2.1, -1.0), (2.1, -1.0), (3.4, 8.4), (-3.4, 8.4)]  # below the bore

# ---- the backup shield (shield.py, 51 x 63 box centred) --------------------
def shield():
    n = 5
    pts = []
    pts += bezier((24.0615, 1.73633), (24.9944, 1.4217), (26.0056, 1.4217), (26.9385, 1.73633), 2)
    pts.append((46.4385, 8.3125))
    pts += bezier((46.4385, 8.3125), (48.268, 8.9297), (49.4999, 10.6453), (49.5, 12.5762), 3)
    pts.append((49.5, 27.3076))
    pts += bezier((49.5, 27.3076), (49.5, 35.0972), (47.21, 42.2514), (42.6016, 48.8057), n)
    pts += bezier((42.6016, 48.8057), (38.4092, 54.768), (33.2021, 58.7008), (26.9746, 60.6895), n)
    pts += bezier((26.9746, 60.6895), (26.0159, 60.9956), (24.9841, 60.9956), (24.0254, 60.6895), 2)
    pts += bezier((24.0254, 60.6895), (17.7979, 58.7008), (12.5908, 54.768), (8.39844, 48.8057), n)
    pts += bezier((8.39844, 48.8057), (3.79, 42.2514), (1.5, 35.0972), (1.5, 27.3076), n)
    pts.append((1.5, 12.5762))
    pts += bezier((1.5, 12.5762), (1.50013, 10.6453), (2.732, 8.9297), (4.56152, 8.3125), 3)
    pts = dedup(pts)
    return [(x - 25.5, y - 31.5) for x, y in pts]


SHIELD = shield()

# ---- the PIN pill (pin_pill.py: 108 x 36, stroke 2.6) ----------------------
PILL = [(-36.0, 0.0), (36.0, 0.0)]           # rim r 16.7, hw 1.3

# ---- the wipe brush (brush.py, 32 x 26 box, drawn at w 30) -----------------
def brush():
    body = [(12.9, 10.6), (12.9, 3.1)]
    body += quad((12.9, 3.1), (12.9, 0), (16, 0), 3)
    body += quad((16, 0), (19.1, 0), (19.1, 3.1), 3)
    body.append((19.1, 10.6))
    body += bezier((19.1, 10.6), (19.1, 13), (21, 14.2), (22.6, 14.2), 3)
    body.append((25.8, 14.2))
    body += bezier((25.8, 14.2), (28.3, 14.3), (29.6, 15.5), (30.1, 17), 3)
    body += quad((30.1, 17), (30.5, 18.2), (30.6, 20), 2)
    body.append((1.4, 20))
    body += quad((1.4, 20), (1.5, 18.2), (1.9, 17), 2)
    body += bezier((1.9, 17), (2.4, 15.5), (3.7, 14.3), (6.2, 14.2), 3)
    body.append((9.4, 14.2))
    body += bezier((9.4, 14.2), (11, 14.2), (12.9, 13), (12.9, 10.6), 3)
    sy = 21.8
    notch_w, notch_d, nr = 1.29, 2.29, 0.645
    strip = [(0.9, sy)]
    for i in range(6):
        n0 = 3.13 + i * 5.06
        n1 = n0 + notch_w
        strip.append((n0, sy))
        strip.append((n0, sy + notch_d - nr))
        strip.append((n0 + notch_w / 2, sy + notch_d))
        strip.append((n1, sy + notch_d - nr))
        strip.append((n1, sy))
    strip += [(31.1, sy), (32, sy + 4.2), (0, sy + 4.2)]
    k = 30 / 32.0
    place = lambda pts: [((x - 16) * k, (y - 13) * k) for x, y in dedup(pts)]
    return place(body), place(strip)


BRUSH_BODY, BRUSH_BRISTLES = brush()

# ---- the factory gear (gear.py at r 32) ------------------------------------
GEAR_R = 32.0
BODY_R, HOLE_R = GEAR_R * 0.80, GEAR_R * 0.44
TW, TH, TR = BODY_R - HOLE_R, GEAR_R * 0.20, GEAR_R * 0.08
TOOTH = inset_convex([(-TW / 2, -BODY_R - TH), (TW / 2, -BODY_R - TH),
                      (TW / 2, -BODY_R + 0.125 * GEAR_R), (-TW / 2, -BODY_R + 0.125 * GEAR_R)], TR)

# ---- the last-attempt heart (heart.py, 40 x 34.6 box, drawn 30 tall) -------
def heart():
    segs = [
        ((21.6, 33.4), (20.7, 34.2), (19.3, 34.2), (18.4, 33.4)),
        ((18.4, 33.4), (10.2, 26.6), (4.5, 21.2), (1.9, 15.9)),
        ((1.9, 15.9), (0.6, 13.2), (0.0, 11.4), (0.0, 9.4)),
        ((0.0, 9.4), (0.0, 4.1), (4.2, 0.0), (9.6, 0.0)),
        ((9.6, 0.0), (13.6, 0.0), (17.4, 2.6), (20.0, 6.3)),
        ((20.0, 6.3), (22.6, 2.6), (26.4, 0.0), (30.4, 0.0)),
        ((30.4, 0.0), (35.8, 0.0), (40.0, 4.1), (40.0, 9.4)),
        ((40.0, 9.4), (40.0, 11.4), (39.4, 13.2), (38.1, 15.9)),
        ((38.1, 15.9), (35.5, 21.2), (29.8, 26.6), (21.6, 33.4)),
    ]
    n = [2, 5, 2, 4, 4, 4, 4, 2, 5]
    pts = []
    for seg, k in zip(segs, n):
        pts += bezier(*seg, k)
    pts = dedup(pts)
    k = 30.0 / 34.6
    return [((x - 20) * k, (y - 17.3) * k) for x, y in pts]


HEART = heart()

# ---- the die at rest (die3d.py REST, half-edge 21) -------------------------
def die():
    ax, ay, az = -0.62, 0.66, 0.0

    def rot(p):
        x, y, z = p
        c, s = math.cos(ax), math.sin(ax)
        y, z = y * c - z * s, y * s + z * c
        c, s = math.cos(ay), math.sin(ay)
        x, z = x * c + z * s, -x * s + z * c
        c, s = math.cos(az), math.sin(az)
        x, y = x * c - y * s, x * s + y * c
        return (x, y, z)

    def add(a, b, k):
        return (a[0] + b[0] * k, a[1] + b[1] * k, a[2] + b[2] * k)

    size = 21.0
    P = lambda p: (0.5 + p[0] * size, -p[1] * size)   # DIE_DX nudge
    o = 0.62
    pips = {1: [(0, 0)], 2: [(-o, -o), (o, o)], 3: [(-o, -o), (0, 0), (o, o)],
            4: [(-o, -o), (o, -o), (-o, o), (o, o)], 5: [(-o, -o), (o, -o), (0, 0), (-o, o), (o, o)],
            6: [(-o, -o), (o, -o), (-o, 0), (o, 0), (-o, o), (o, o)]}
    # die3d._FACES: standard western die, opposite faces sum to 7
    faces = [((0, 0, 1), (1, 0, 0), (0, 1, 0), 1), ((0, 0, -1), (-1, 0, 0), (0, 1, 0), 6),
             ((1, 0, 0), (0, 0, -1), (0, 1, 0), 2), ((-1, 0, 0), (0, 0, 1), (0, 1, 0), 5),
             ((0, 1, 0), (1, 0, 0), (0, 0, -1), 3), ((0, -1, 0), (1, 0, 0), (0, 0, 1), 4)]
    out_faces, out_pips = [], []
    for n, u, v, npips in faces:
        n3 = rot(n)
        if n3[2] <= 0.02:
            continue
        u3, v3 = rot(u), rot(v)
        corners = [P(add(add(n3, u3, a), v3, b)) for a, b in ((-1, -1), (1, -1), (1, 1), (-1, 1))]
        out_faces.append(inset_convex(corners, 3.5))
        for pu, pv in pips[npips]:
            spread = 0.78 if npips == 6 else 0.72
            c = add(add(n3, u3, pu * spread), v3, pv * spread)
            ring = [P(add(add(c, u3, math.cos(a) * 0.185), v3, math.sin(a) * 0.185))
                    for a in (i / 10 * 2 * math.pi for i in range(10))]
            out_pips.append(ring)
    return out_faces, out_pips


DIE_FACES, DIE_PIPS = die()


def rs_array(name, pts, doc):
    pts = q4(pts)
    assert 2 <= len(pts) <= MAX_PTS, f"{name}: {len(pts)} points"
    for x, y in pts:
        assert -32768 <= x < 32768 and -32768 <= y < 32768
    body = ", ".join(f"({x}, {y})" for x, y in pts)
    return f"/// {doc}\npub const {name}: [(i16, i16); {len(pts)}] = [{body}];\n"


def render():
    out = ["// @generated by tools/ui_px_verdict_geometry.py — do not edit.\n",
           "//! Verdict sign outlines in Q4 (1/16 px) at the design size, flattened\n",
           "//! from the vendored PQ-UI procedural art (`tools/pq-ui/pq1/procedural/`).\n\n"]
    out.append(rs_array("TRIANGLE", TRI, "Warning triangle inset by its 6 px corner radius (grow it back), centred on its box."))
    out.append(rs_array("EXCLAMATION_BAR", EXCL_BAR, "The exclamation's bar (capsule, half-width 2 px), in triangle coordinates."))
    out.append(rs_array("SHACKLE_ARCH", SHACKLE_ARCH, "Padlock shackle arch, relative to the pivot (right) leg's top."))
    out.append(rs_array("UNIT_LEG", UNIT_LEG, "A 1 px vertical segment, scaled to a shackle leg."))
    out.append(rs_array("KEYHOLE_SLOT", KEYHOLE, "Keyhole slot, relative to the body centre."))
    out.append(rs_array("SHIELD", SHIELD, "Backup shield outline (closed loop), centred on its 51 x 63 box."))
    out.append(rs_array("PILL", PILL, "PIN pill centre segment (rim radius 16.7 px)."))
    out.append(rs_array("BRUSH_BODY", BRUSH_BODY, "Wipe brush handle + head at width 30, centred on its box."))
    out.append(rs_array("BRUSH_BRISTLES", BRUSH_BRISTLES, "Wipe brush bristle strip with its six notches."))
    out.append(rs_array("HEART", HEART, "Last-attempt heart, 30 px tall, centred on its box."))
    out.append(rs_array("GEAR_TOOTH", TOOTH, "One gear tooth (pointing up) inset by its corner radius, about the gear centre."))
    for i, f in enumerate(DIE_FACES):
        out.append(rs_array(f"DIE_FACE_{i + 1}", f, f"Die face {i + 1} at rest, inset by its 3.5 px corner radius."))
    assert len(DIE_FACES) == 3
    out.append("/// Die pips at rest (the three visible faces' pips).\n")
    out.append(f"pub const DIE_PIPS: [&[(i16, i16)]; {len(DIE_PIPS)}] = [" + ", ".join(f"&DIE_PIP_{i}" for i in range(len(DIE_PIPS))) + "];\n")
    for i, p in enumerate(DIE_PIPS):
        out.append(rs_array(f"DIE_PIP_{i}", p, f"Die pip {i}."))
    return "".join(out)


def main():
    text = render()
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} is stale — run tools/ui_px_verdict_geometry.py")
            return 1
        print("verdict geometry up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
