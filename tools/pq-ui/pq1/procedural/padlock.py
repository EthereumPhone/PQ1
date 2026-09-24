"""Padlock — rigged lock composite: body disc, keyhole, swinging shackle.

Ported verbatim from the lock.py / unlock.py mockups (identical rigs; only
the fill colour differed). The shackle is a polyline arch that z-spins
about the vertical axis through its seated right leg with horizontal
foreshortening (x' = px + (x - px) * cos(spin)); the body keeps the black
halo ellipse so the legs read as passing behind the disc, and the round
bore + tapered slot keyhole. The pose covers the whole lock choreography:
spin (0 = seated, pi = fully open-mirrored), lift (the drop / pop raise)
recoil_k (the click snap) and drop (the unlock kick: the body is knocked
down while the shackle flies up, the long leg stretching to stay captive).
"""
import math

from .. import colors

# source rig constants (lock.py), scaled by f = body_r / BODY_R
BODY_R = 21.0
ARM_R, LEG_Y, LW, TAIL = 11.5, 13.5, 5.4, 8.0
HALO = 2.6

# closed-rest centring: with the body at body_y the composite's ink spans
# body_y - 45.3 .. body_y + 21 (arch top incl. stroke .. disc bottom), so
# the bbox mid (body_y - 12.2) over-weights the thin arch; the measured
# ink centroid — the optical centre — sits at body_y - 6.5. The body
# therefore drops BODY_DY below cy (the plan estimated ~5.5; on the y-72
# grid the source's body_y 82 becomes 78.5).
BODY_DY = 6.5


def draw(cv, cx, cy, *, body_r=BODY_R, color, alpha=1.0, spin=0.0,
         lift=0.0, drop=0.0, recoil_k=0.0):
    """padlock with (cx, cy) at the CLOSED composite's optical centre.

    spin: shackle z-rotation about its seated right leg, 0 = seated,
    pi = fully open-mirrored; lift: vertical shackle raise in UI px (the
    drop / snap phases); drop: the body's own downward kick in UI px — the
    shackle keeps its place, so lift + drop is how far the two have parted
    (the unlock snap's reaction); recoil_k: click recoil 0..1 — the
    shackle bites down 0.9 k while the body nudges 0.7 k (lock.py:136-140)."""
    if alpha <= 0.01:
        return
    col = tuple(int(round(c * alpha)) for c in color)
    f = body_r / BODY_R
    rest_y = cy + (BODY_DY + 0.7 * recoil_k) * f
    body_y = rest_y + drop
    eff = lift - 0.9 * recoil_k * f
    seat_y = rest_y - body_r + 3.0 * f - eff      # the shackle's arch line
    # the long leg always reaches 2 px into the disc, however far the
    # shackle and the kicked body have parted — a real shackle's long leg
    # never leaves the body
    tail = max(TAIL * f, body_y - body_r + 2.0 * f - seat_y)
    _shackle(cv, cx, seat_y, f, col, spin, max(0.0, eff), tail)
    _body(cv, cx, body_y, body_r, f, col)


def glyph(**pose):
    """freeze a pose (default: the closed rest) into the components glyph
    signature; r maps to body_r"""
    def fn(cv, cx, cy, r, alpha=1.0, color=None, rot=0.0):
        draw(cv, cx, cy, body_r=r, color=color or colors.WHITE,
             alpha=alpha, **pose)
    return fn


def _shackle(cv, cx, cy, f, col, spin, lift, tail):
    """z-spin about the vertical axis through the right (seated) leg:
    horizontal foreshortening x' = px + (x - px) * cos(spin); tail is the
    long leg's reach below the arch line (>= TAIL * f)"""
    arm = ARM_R * f
    pts = [(cx - arm, cy - lift * 0.4)]       # free leg tip (raised open)
    pts.append((cx - arm, cy - LEG_Y * f))
    for i in range(25):                       # top arch
        a = math.pi - math.pi * i / 24
        pts.append((cx + arm * math.cos(a),
                    cy - LEG_Y * f - arm * math.sin(a)))
    pts.append((cx + arm, cy + tail))         # pivot leg, behind the disc
    sc = math.cos(spin)
    if abs(sc) < 0.06:                        # never fully edge-on
        sc = -0.06 if sc < 0 else 0.06
    px = cx + arm
    pts = [(px + (x - px) * sc, y) for x, y in pts]
    cv.line(pts, col, LW * f)
    r = LW * f / 2
    for p in (pts[0], pts[-1]):               # round end caps
        cv.circle(p[0], p[1], r, col)


def _body(cv, cx, cy, body_r, f, col):
    # black halo — the shackle legs read as passing behind the disc
    cv.circle(cx, cy, body_r + HALO * f, colors.BLACK)
    cv.circle(cx, cy, body_r, col)
    # keyhole: round bore + tapered slot
    cv.circle(cx, cy - 3.5 * f, 4.6 * f, colors.BLACK)
    cv.polygon([(cx - 2.1 * f, cy - 1.0 * f), (cx + 2.1 * f, cy - 1.0 * f),
                (cx + 3.4 * f, cy + 8.4 * f), (cx - 3.4 * f, cy + 8.4 * f)],
               fill=colors.BLACK)
