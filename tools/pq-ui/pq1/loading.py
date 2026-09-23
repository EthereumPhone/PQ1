"""PQ1 loading — the qubit status sequence.

The token splits into two qubits, they sweep onto a circular path and spin
(metaball merge as they pass), spiral in, flash, and resolve to a black
token with a result-coloured ring and glyph — the one loading film behind
every status screen (the "qubit" animation; see pq1.status for the
registry). The old orbit loader (the lighter cancel spinner) is gone:
success and cancellation share this film and differ only in the resolve.

The film is OPEN-ENDED on the device (DESIGN.md § Status animations, the
film's length): its steady orbit — the loop region (t_orbit, t5) — is
pixel-periodic in one turn, so while the real work is outstanding the pose
clock wraps that region in whole turns (film_time / wraps_for) and the
outcome is latched at the spiral, never later than t6; the split, the
spiral, the flash and the rest never stretch. With no answer pending the
helpers are the identity: every render is the stock film.
"""
import math

from . import colors, components
from .layout import BASELINE_Y, CENTER_X
from .motion import SEED_ART, SEED_MS, back_out, clamp01, ease, ease_out, lerp


# ------------------------------------------------------------ qubit status --
REVS = 3          # the stock orbit: whole turns before the spiral (a signature)
REVS_LONG = 5     # a loading that must endure (the firmware reboot, the wipe):
                  # two turns more, at the same spin
TURN_MS = 850     # one orbit turn — the unit of loading length: a film is made
                  # longer only in whole turns (revs at build time, the wrap at
                  # run time), never with a slower spin or a longer spiral


class QubitCfg:
    """geometry / timing of the qubit status sequence"""

    def __init__(self, gc=(214.0, 72.0), orbit_r=23.0, r_big=30.0, r_q=13.0,
                 split_x=120.0, t_seed=SEED_MS, t_split=650, t_join=1300, t_ramp=1300,
                 rev_ms=TURN_MS, revs=REVS, t_spiral=1000, t_flash=400):
        if not isinstance(revs, int) or isinstance(revs, bool) or revs < 1:
            raise ValueError(f"revs must be a whole number of orbit turns "
                             f">= 1, got {revs!r}")
        self.gc = gc
        self.orbit_r = orbit_r
        self.r_big = r_big
        self.r_q = r_q
        self.split_x = split_x
        self.T_SEED = t_seed
        self.T_SPLIT = t_split
        self.T_JOIN = t_join
        self.T_RAMP = t_ramp
        self.rev_ms = rev_ms
        self.T_SPIN = revs * rev_ms
        self.T_SPIRAL = t_spiral
        self.T_FLASH = t_flash
        self.t2 = self.T_SEED
        self.t_orbit = self.t2 + self.T_SPLIT + self.T_JOIN   # the pair is ON the orbit
        self.t5 = self.t_orbit + self.T_SPIN                   # the spiral starts: the loop seam
        self.t6 = self.t5 + self.T_SPIRAL                      # the flash: the OUTCOME seam —
        self.t7 = self.t6 + self.T_FLASH                       # the first frame that differs
        # the loop region — the only part of the film that may repeat (and
        # the only part over which a busy caption may show): from the join
        # done to the spiral, whole turns of loop_ms
        self.loop = (self.t_orbit, self.t5)
        self.loop_ms = rev_ms


def spin_th(e, c):
    w = 2 * math.pi / c.rev_ms
    if e < c.T_RAMP:
        return 0.5 * w * e * e / c.T_RAMP
    return w * (e - c.T_RAMP / 2)


def wraps_for(c, t_ready):
    """whole turns the film adds before its spiral when the work answers at
    film time t_ready: none if the answer is in before the loop seam t5 (a
    film is a MINIMUM-length depiction), else enough that the spiral starts
    at the first whole-turn boundary at or after the answer — a loading
    lengthens only in whole turns"""
    if t_ready is None or t_ready <= c.t5:
        return 0
    return math.ceil((t_ready - c.t5) / c.loop_ms)


def film_time(t, c, wraps=0):
    """pose time for film time t on a film lengthened by `wraps` whole turns
    (math.inf while the answer is pending): the identity up to the loop
    seam t5, then the orbit's last turn (t5 - loop_ms, t5] repeats until
    the wraps are spent and the spiral runs — pixel-exact, the orbit being
    periodic in one turn. The identity when wraps is 0: every stock render
    is untouched. Pure in (t, wraps), so any frame stays seekable"""
    if not wraps or t <= c.t5 or not math.isfinite(t):
        return t
    return t - c.loop_ms * min(wraps, math.ceil((t - c.t5) / c.loop_ms))


def qubit_pose(t, c, seed=None):
    """bodies + overlay alphas of the status sequence at time t ms.

    seed — (x, y, r): the circle the film was HANDED, at the token's VISIBLE
    radius (flow.Sim.draw). The film opens on the SEED (c.T_SEED): that one
    body travels to gc, shrinks to r_q and — in draw_status — tints into the
    film's colour on one ease_out, its ring and its art fading over the first
    SEED_ART of the WINDOW (linear time: the eased travel front-loads and
    would empty the dress inside one panel frame at 14 fps).
    A bare qubit lands on the frame the split begins,
    and divides into its identical twin: the seed IS a qubit, so the two
    halves part at r_q. None — a standalone render, or a film nobody handed a
    circle to: the same morph in place at gc, from the token's visible radius.
    """
    gx, gy = c.gc
    # the defaults are the RESTING pose: the landed disc at full size, no
    # dress (the tail branch past t7 returns P unchanged)
    P = dict(bodies=[dict(x=gx, y=gy, r=c.r_big)], glyph_a=0.0, glyph_r=c.r_q,
             seed_u=1.0, check_a=0.0, text_a=0.0, flash_a=0.0, flash_r=0.0,
             bind=0)
    t = max(0.0, t)
    if t < c.t2:
        sx, sy, sr = seed or (gx, gy, c.r_big - components.TOKEN_INSET)
        u = ease_out(clamp01(t / c.T_SEED))
        r = lerp(sr, c.r_q, u)
        P["bodies"] = [dict(x=lerp(sx, gx, u), y=lerp(sy, gy, u), r=r)]
        # the dress leaves on LINEAR time, not the eased travel: ease_out
        # front-loads u, which would empty it in under one panel frame
        P["glyph_a"] = clamp01(1 - (t / c.T_SEED) / SEED_ART)
        P["glyph_r"] = r
        P["seed_u"] = u
        return P
    if t < c.t5:
        e = t - c.t2
        if e < c.T_SPLIT:
            u = ease(e / c.T_SPLIT)
            R = c.split_x * u
            P["bind"] = 1
            P["bodies"] = [dict(x=gx - R, y=gy, r=c.r_q),
                           dict(x=gx + R, y=gy, r=c.r_q)]
        else:
            je = e - c.T_SPLIT
            th = spin_th(je, c)
            uj = clamp01(je / c.T_JOIN)
            R = c.orbit_r + (c.split_x - c.orbit_r) * (1 - uj) ** 2 * (1 + 2 * uj)
            y_max = 44.0
            ry = R if R <= c.orbit_r else c.orbit_r + (y_max - c.orbit_r) * \
                (R - c.orbit_r) / (c.split_x - c.orbit_r)
            P["bind"] = 0
            P["bodies"] = [dict(x=gx + math.cos(a) * R, y=gy + math.sin(a) * ry, r=c.r_q)
                           for a in (math.pi + th, th)]
        return P
    if t < c.t6:
        e = t - c.t5
        u = e / c.T_SPIRAL
        th0 = spin_th(c.T_JOIN + c.T_SPIN, c)
        th = th0 + (2 * math.pi / c.rev_ms) * e + 2 * math.pi * 2.2 * u ** 3
        R = c.orbit_r * (1 - u * u)
        r = c.r_q + 4 * u
        P["bodies"] = [dict(x=gx + math.cos(a) * R, y=gy + math.sin(a) * R, r=r)
                       for a in (math.pi + th, th)]
        P["bind"] = 1
        return P
    if t < c.t7:
        u = clamp01((t - c.t6) / c.T_FLASH)
        P["bodies"] = [dict(x=gx, y=gy, r=lerp(17, c.r_big, back_out(u)))]
        P["flash_a"] = (1 - u) * 0.85
        P["flash_r"] = c.r_big + 55 * u
        return P
    e = t - c.t7
    P["check_a"] = clamp01(e / 350)
    P["text_a"] = clamp01((e - 120) / 350)
    return P


def bezier(p0, p1, p2, p3, n=16):
    out = []
    for i in range(n + 1):
        t = i / n
        m = 1 - t
        out.append((m ** 3 * p0[0] + 3 * m * m * t * p1[0] + 3 * m * t * t * p2[0] + t ** 3 * p3[0],
                    m ** 3 * p0[1] + 3 * m * m * t * p1[1] + 3 * m * t * t * p2[1] + t ** 3 * p3[1]))
    return out


def metaball(cv, b1, b2, max_dist, color):
    """fluid bridge between two circles (same construction as the HTML)"""
    x1, y1, r1 = b1["x"], b1["y"], b1["r"]
    x2, y2, r2 = b2["x"], b2["y"], b2["r"]
    d = math.hypot(x2 - x1, y2 - y1)
    if d < 0.01 or d > max_dist or d <= abs(r1 - r2):
        return
    v, handle_rate = 0.5, 2.4
    u1 = u2 = 0.0
    if d < r1 + r2:
        u1 = math.acos(max(-1, min(1, (r1 * r1 + d * d - r2 * r2) / (2 * r1 * d))))
        u2 = math.acos(max(-1, min(1, (r2 * r2 + d * d - r1 * r1) / (2 * r2 * d))))
    ab = math.atan2(y2 - y1, x2 - x1)
    spread = math.acos(max(-1, min(1, (r1 - r2) / d)))
    a1 = ab + u1 + (spread - u1) * v
    a2 = ab - u1 - (spread - u1) * v
    a3 = ab + math.pi - u2 - (math.pi - u2 - spread) * v
    a4 = ab - math.pi + u2 + (math.pi - u2 - spread) * v

    def pt(cx, cy, a, r):
        return (cx + r * math.cos(a), cy + r * math.sin(a))

    p1, p2 = pt(x1, y1, a1, r1), pt(x1, y1, a2, r1)
    p3, p4 = pt(x2, y2, a3, r2), pt(x2, y2, a4, r2)
    total = r1 + r2
    d2 = min(v * handle_rate, math.hypot(p1[0] - p3[0], p1[1] - p3[1]) / total)
    d2 *= min(1.0, d * 2 / total)
    R1, R2 = r1 * d2, r2 * d2
    h1 = pt(p1[0], p1[1], a1 - math.pi / 2, R1)
    h2 = pt(p2[0], p2[1], a2 + math.pi / 2, R1)
    h3 = pt(p3[0], p3[1], a3 + math.pi / 2, R2)
    h4 = pt(p4[0], p4[1], a4 - math.pi / 2, R2)
    poly = bezier(p1, h1, h3, p3) + [p4] + bezier(p4, h4, h2, p2)
    cv.polygon(poly, fill=color)


def draw_status(cv, t, caption_text, cfg=None, result_color=None,
                glyph_name="eth", body_fill=None, trail=None,
                result_glyph="check", unknown_ramp=None, ring_color=None,
                resting=None, glyph_color=None, seed=None):
    """Draw one frame of the qubit status sequence at time t ms.

    body_fill=None renders unknown-token gradient bodies on the placeholder
    ramp `unknown_ramp` (neutral grey if None); pass a solid colour for a
    known token's loading treatment. trail is the follower palette (default:
    the resolved ramp's trail; pass a placeholder ramp's trail for a known
    token without an image). result_glyph is the glyph name shown on resolve
    ("check" | "x" | None). ring_color is an explicit token-spec ring
    (components.token draws it OVER the glyph): it strokes the glyph art
    here too, riding the glyph's alpha, so the flow -> status handoff keeps
    the stroke with no pop. resting is status.style_of's resting dict — a
    branded ending overrides the resting disc fill / ring / result-glyph
    colours and strokes the ring flush at the disc edge (flush=True);
    default: black disc, result_color ring + glyph.

    seed is the circle the flow HANDED the film (flow.Sim.draw) —
    dict(x, y, r, fill, ring, icon, icon_color) at the token's VISIBLE
    radius; the dress that leaves is the icon it was wearing, glyph_name /
    glyph_color dressing only a seed nobody handed over. Over the
    seed window (QubitCfg.T_SEED) that one body travels to gc, shrinks to
    r_q and tints from its own fill into body_fill, its stroke and its art
    fading over the first motion.SEED_ART of that WINDOW, on linear time (two
    panel frames at 14 fps): a BARE qubit lands on the frame the split begins. None — the same morph in place at gc. The
    follower stream is dark over the seed.
    """
    c = cfg or QubitCfg()
    result_color = result_color or colors.GREEN
    rest = resting or dict(fill=colors.BLACK, ring=result_color,
                           glyph=result_color, flush=False)
    ramp = colors.NEUTRAL_RAMP if unknown_ramp is None else unknown_ramp
    trail = trail or colors.ramp_palette(ramp)[1]
    src = None if seed is None else (seed["x"], seed["y"], seed["r"])
    P = qubit_pose(min(t, c.t7 + 800), c, src)
    done = t > c.t5
    u = P["seed_u"]          # 0 -> the circle the flow handed over, 1 -> a qubit
    seed_fill = (seed or {}).get("fill") or body_fill
    seed_ring = (seed or {}).get("ring") or ring_color
    if seed is not None:
        # the dress that leaves is the one the flow was drawing; the film's
        # own icon dresses only a seed nobody handed over (a standalone render)
        glyph_name = seed.get("icon") or glyph_name
        if "icon_color" in seed:
            glyph_color = seed["icon_color"]

    # follower stream: one solid gradient colour per circle. DARK over the
    # seed — one body arriving has nothing to trail, and every sample behind
    # it would smear back to where the flow handed it over
    if u >= 1.0:
        gap = (0.22 / (2 * math.pi)) * c.rev_ms
        for bi, b in enumerate(P["bodies"]):
            prev = b
            pts = []
            for j in range(1, 6):
                Q = qubit_pose(min(t, c.t7 + 800) - j * gap, c, src)
                q = Q["bodies"][min(bi, len(Q["bodies"]) - 1)]
                if abs(q["x"] - prev["x"]) < 0.8 and abs(q["y"] - prev["y"]) < 0.8:
                    break
                pts.append(q)
                prev = q
            for j in range(len(pts) - 1, -1, -1):
                cv.circle(pts[j]["x"], pts[j]["y"], b["r"], trail[min(j, len(trail) - 1)])

    single = len(P["bodies"]) == 1

    if P["bind"] and len(P["bodies"]) == 2:
        b1, b2 = P["bodies"]
        max_dist = b1["r"] + b2["r"] + 2
        d = math.hypot(b2["x"] - b1["x"], b2["y"] - b1["y"])
        if clamp01((max_dist - d) / 8) > 0.5:
            metaball(cv, b1, b2, max_dist,
                     body_fill if body_fill
                     else colors.grad_color(0.5, colors.ramp_stops(ramp)))

    for b in P["bodies"]:
        if single and done:
            cv.circle(b["x"], b["y"], b["r"], rest["fill"])
        elif body_fill:
            # over the seed the body tints from the token's own fill into
            # the film's; past it the film colour, as before
            cv.circle(b["x"], b["y"], b["r"],
                      body_fill if u >= 1.0 else
                      colors.grad_color(u, [(0.0, tuple(seed_fill)),
                                            (1.0, tuple(body_fill))]))
        else:
            components.unknown_disc(cv, b["x"], b["y"], b["r"], ramp)
        if single and done:
            cv.ring(b["x"], b["y"], b["r"] if rest["flush"] else b["r"] - 1.2,
                    rest["ring"], components.TOKEN_RING_W)

    if u < 1.0 and P["glyph_a"] > 0.01:
        # the token's own dress leaving over the first SEED_ART of the morph:
        # the art, then its stroke OVER it (components.token's layer order),
        # both on the arriving body — a BARE qubit is what divides
        b, a = P["bodies"][0], P["glyph_a"]
        components.glyph(cv, glyph_name, b["x"], b["y"], P["glyph_r"], a,
                         color=glyph_color)
        cv.ring(b["x"], b["y"], b["r"],
                (*(seed_ring or colors.WHITE), int(round(255 * a))),
                components.TOKEN_RING_W)
    if result_glyph is not None and P["check_a"] > 0.01:
        components.GLYPHS[result_glyph](cv, c.gc[0], c.gc[1], c.r_big,
                                        P["check_a"], rest["glyph"])
    components.flash_ring(cv, c.gc[0], c.gc[1], P["flash_r"], result_color,
                          P["flash_a"], width=2.5)

    cv.text(caption_text, CENTER_X, BASELINE_Y, 18, P["text_a"], ls=0.5, baseline=True)
