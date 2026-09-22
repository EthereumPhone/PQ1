"""Shared path math for procedural imagery — no pq1 imports beyond layout.

Self-contained on purpose (no pq1.loading import): procedural modules must
stay importable from pq1.components without cycles.
"""
import math
import re


def bezier(p0, p1, p2, p3, n=24):
    """flatten a cubic bezier into n+1 points"""
    pts = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def quad_bezier(p0, p1, p2, n=12):
    """flatten a quadratic bezier into n+1 points"""
    pts = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0]
        y = mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def rounded_polygon(pts, rr, n=10):
    """round every corner of a closed polygon: trim each vertex by rr along
    both edges and bridge with a flattened quadratic whose control point is
    the original vertex. rr is one trim for every corner, or a per-vertex
    sequence of len(pts). Returns the flattened outline points."""
    out = []
    m = len(pts)
    for i in range(m):
        ri = rr[i] if isinstance(rr, (list, tuple)) else rr
        p_prev, p, p_next = pts[(i - 1) % m], pts[i], pts[(i + 1) % m]
        v1 = (p_prev[0] - p[0], p_prev[1] - p[1])
        v2 = (p_next[0] - p[0], p_next[1] - p[1])
        l1 = math.hypot(*v1) or 1.0
        l2 = math.hypot(*v2) or 1.0
        t1 = min(ri / l1, 0.5)
        t2 = min(ri / l2, 0.5)
        a1 = (p[0] + v1[0] * t1, p[1] + v1[1] * t1)
        a2 = (p[0] + v2[0] * t2, p[1] + v2[1] * t2)
        out.extend(quad_bezier(a1, p, a2, n))
    return out


def svg_subpaths(d):
    """flatten absolute SVG path data (M/L/H/V/C/Z) into closed point
    lists — a traced mark carries its SVG's path data verbatim (rotate, dev)"""
    toks = re.findall(r"[MLHVCZ]|-?(?:\d+\.?\d*|\.\d+)(?:e-?\d+)?", d)
    out, cur, pos, i, cmd = [], [], (0.0, 0.0), 0, None
    while i < len(toks):
        if toks[i] in "MLHVCZ":
            cmd, i = toks[i], i + 1
            if cmd == "Z":
                out.append(cur)
                cur = []
            continue
        n = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6}[cmd]
        v = [float(t) for t in toks[i:i + n]]
        i += n
        if cmd in "ML":
            pos = (v[0], v[1])
            cur.append(pos)
        elif cmd == "H":
            pos = (v[0], pos[1])
            cur.append(pos)
        elif cmd == "V":
            pos = (pos[0], v[0])
            cur.append(pos)
        else:
            end = (v[4], v[5])
            n_seg = 16 if math.dist(pos, end) > 1.0 else 3   # the tiny corner arcs
            cur.extend(bezier(pos, (v[0], v[1]), (v[2], v[3]), end, n_seg)[1:])
            pos = end
    if cur:
        out.append(cur)
    return out
