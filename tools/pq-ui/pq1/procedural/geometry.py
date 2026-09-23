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


_TOKENS = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]"
                     r"|[-+]?(?:\d*\.\d+|\d+\.?)(?:[eE][-+]?\d+)?")
_ARGC = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}


def _seg(a, b, k=3.0, lo=3, hi=24):
    """segments for a curve spanning a to b in SVG units — a long sweep gets
    the detail, a corner fillet does not pay for it"""
    return max(lo, min(hi, int(math.ceil(math.dist(a, b) * k))))


def _arc(p0, rx, ry, phi_deg, large, sweep, p1):
    """flatten an SVG elliptical arc: endpoint -> centre parameterization
    (SVG 1.1 implementation notes F.6.5 / F.6.6), then sampled every ~11.25
    degrees. Returns the points AFTER p0."""
    x0, y0 = p0
    x1, y1 = p1
    if (x0, y0) == (x1, y1):
        return []
    rx, ry = abs(rx), abs(ry)
    if rx == 0 or ry == 0:                       # degenerate radii: a straight line
        return [p1]
    phi = math.radians(phi_deg)
    cp, sp = math.cos(phi), math.sin(phi)
    dx2, dy2 = (x0 - x1) / 2.0, (y0 - y1) / 2.0
    x1p, y1p = cp * dx2 + sp * dy2, -sp * dx2 + cp * dy2
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:                                  # F.6.6: scale the radii up to fit
        s = math.sqrt(lam)
        rx, ry = rx * s, ry * s
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    num = rx * rx * ry * ry - den
    co = math.sqrt(max(0.0, num / den)) if den else 0.0
    if large == sweep:
        co = -co
    cxp, cyp = co * rx * y1p / ry, -co * ry * x1p / rx
    cx = cp * cxp - sp * cyp + (x0 + x1) / 2.0
    cy = sp * cxp + cp * cyp + (y0 + y1) / 2.0

    def ang(ux, uy, vx, vy):
        n = math.hypot(ux, uy) * math.hypot(vx, vy)
        if not n:
            return 0.0
        a = math.acos(max(-1.0, min(1.0, (ux * vx + uy * vy) / n)))
        return -a if ux * vy - uy * vx < 0 else a

    ux, uy = (x1p - cxp) / rx, (y1p - cyp) / ry
    vx, vy = (-x1p - cxp) / rx, (-y1p - cyp) / ry
    th0, dth = ang(1, 0, ux, uy), ang(ux, uy, vx, vy)
    if not sweep and dth > 0:
        dth -= 2 * math.pi
    elif sweep and dth < 0:
        dth += 2 * math.pi
    n = max(2, int(math.ceil(abs(dth) / (math.pi / 16))))
    pts = []
    for i in range(1, n + 1):
        th = th0 + dth * i / n
        xp, yp = rx * math.cos(th), ry * math.sin(th)
        pts.append((cp * xp - sp * yp + cx, sp * xp + cp * yp + cy))
    return pts


def svg_outline(d):
    """flatten ANY SVG path data into closed point lists.

    The whole command set — M L H V C S Q T A Z, absolute and relative —
    plus implicit command repetition (the pairs trailing an `m` are linetos)
    and elliptical arcs. `svg_subpaths` below reads only the absolute
    M/L/H/V/C/Z subset the older marks happen to carry and drops anything
    else *silently*, so new traced art uses this one; the old parser stays
    exactly as it was, and with it the marks that already ship.
    """
    toks = _TOKENS.findall(d)
    out, cur = [], []
    pos = start = (0.0, 0.0)
    prev_c = prev_q = None       # last cubic / quadratic control, for S and T
    cmd, i = None, 0
    while i < len(toks):
        if toks[i][-1].isalpha():
            cmd, i = toks[i], i + 1
            if cmd in "Zz":
                if len(cur) >= 3:
                    out.append(cur)
                cur, pos = [], start
                prev_c = prev_q = None
            continue
        if cmd is None:
            break
        up, rel = cmd.upper(), cmd.islower()
        n = _ARGC[up]
        if len(toks) - i < n:
            break
        v = [float(t) for t in toks[i:i + n]]
        i += n
        ox, oy = pos if rel else (0.0, 0.0)
        if up == "M":
            if len(cur) >= 3:
                out.append(cur)
            pos = start = (ox + v[0], oy + v[1])
            cur = [pos]
            cmd = "l" if rel else "L"        # the pairs after an M are linetos
            prev_c = prev_q = None
        elif up == "L":
            pos = (ox + v[0], oy + v[1])
            cur.append(pos)
            prev_c = prev_q = None
        elif up == "H":
            pos = (ox + v[0], pos[1])
            cur.append(pos)
            prev_c = prev_q = None
        elif up == "V":
            pos = (pos[0], oy + v[0])
            cur.append(pos)
            prev_c = prev_q = None
        elif up in ("C", "S"):
            if up == "C":
                c1, c2 = (ox + v[0], oy + v[1]), (ox + v[2], oy + v[3])
                end = (ox + v[4], oy + v[5])
            else:                            # S: reflect the previous cubic control
                c1 = ((2 * pos[0] - prev_c[0], 2 * pos[1] - prev_c[1])
                      if prev_c else pos)
                c2, end = (ox + v[0], oy + v[1]), (ox + v[2], oy + v[3])
            cur.extend(bezier(pos, c1, c2, end, _seg(pos, end))[1:])
            pos, prev_c, prev_q = end, c2, None
        elif up in ("Q", "T"):
            if up == "Q":
                c1, end = (ox + v[0], oy + v[1]), (ox + v[2], oy + v[3])
            else:                            # T: reflect the previous quad control
                c1 = ((2 * pos[0] - prev_q[0], 2 * pos[1] - prev_q[1])
                      if prev_q else pos)
                end = (ox + v[0], oy + v[1])
            cur.extend(quad_bezier(pos, c1, end, max(3, _seg(pos, end) // 2))[1:])
            pos, prev_q, prev_c = end, c1, None
        elif up == "A":
            end = (ox + v[5], oy + v[6])
            cur.extend(_arc(pos, v[0], v[1], v[2], int(v[3]), int(v[4]), end))
            pos = end
            prev_c = prev_q = None
    if len(cur) >= 3:
        out.append(cur)
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
