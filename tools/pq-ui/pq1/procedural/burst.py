"""Explosion choreography — the major blast and the minor pop.

The finale of major_explosion / minor_explosion rebuilt on pq1.loading:
the split / orbit / spiral leg is loading.qubit_pose on a stock QubitCfg
(whose defaults match the forks' timeline — split 650, join 1300, ramp
1300, 3 x 850 ms revs, spiral 1000, with the seed (motion.SEED_MS) where
the forks held 250 — and whose gc (214, 72)
fixes their 1 px GY drift), with loading.metaball for the goo bridge.
Module-local are the pieces the loader does not have: the brightness-
faded follower stream, the trembling clump polygon that compresses and
colour-shifts, and the core-flash bloom + staggered elliptical ring
blast. Severity lives in BurstCfg (MAJOR blast / MINOR pop); the ring
stagger is unified at 145 ms (the forks' 110 / 130 are sub-2-frame at
the 14 fps panel). draw is pure in t; centre and geometry come from
cfg.qubit. Imported from screens/ only — this is the one procedural
module allowed to depend on pq1.loading.
"""
import bisect
import functools
import math

from .. import colors, components, gradients, loading
from ..layout import SUP, VALUE_PARK_X, W
from ..motion import ENTER_MS, clamp01, ease, spring_travel


class BurstCfg:
    """severity table for one burst; every other numeric is shared"""

    def __init__(self, *, rings, stagger_ms, t_clump, t_boom, squeeze,
                 jitter, intensity, bloom, ring_span, aspect, grow_p,
                 ring_w, ring_a, qubit=None):
        self.qubit = qubit or loading.QubitCfg()
        self.rings = rings            # blast ring count
        self.stagger_ms = stagger_ms  # launch offset between rings
        self.t_clump = t_clump        # clump phase length (ms)
        self.t_boom = t_boom          # each ring's flight time (ms)
        self.squeeze = squeeze        # clump squash: 22 -> 22*(1-squeeze)
        self.jitter = jitter          # (base, ramp) clump shake px
        self.intensity = intensity    # (base, ramp) edge-tremble strength
        self.bloom = bloom            # core flash (fade ms, growth px)
        self.ring_span = ring_span    # ring i reach: base + step * i px
        self.aspect = aspect          # ring ry / rx
        self.grow_p = grow_p          # ring ease-out exponent
        self.ring_w = ring_w          # ring i stroke: base + step * i px
        self.ring_a = ring_a          # ring peak brightness


MAJOR = BurstCfg(rings=5, stagger_ms=145, t_clump=1100, t_boom=900,
                 squeeze=0.35, jitter=(1.4, 4.2), intensity=(0.6, 2.4),
                 bloom=(300, 44), ring_span=(300, -42), aspect=0.72,
                 grow_p=2.6, ring_w=(2.6, -0.35), ring_a=0.9)

MINOR = BurstCfg(rings=2, stagger_ms=145, t_clump=800, t_boom=750,
                 squeeze=0.22, jitter=(0.8, 1.6), intensity=(0.5, 1.0),
                 bloom=(240, 22), ring_span=(62, -16), aspect=0.9,
                 grow_p=2.4, ring_w=(2.4, -0.5), ring_a=0.85)

# the sources' post-boom rest (ms): the staggered late rings finish within
# 600 ms of t_resolve, so a dwell of HOLD_END after t_resolve matches the
# forks' tail exactly
HOLD_END = 1400


ENTERS = (None, "left", "right", "sides")

# enter="sides": the two qubits fly in from both edges and spiral straight
# onto the orbit — no rest, no split. The path is laid out first (a polar
# spiral from SIDES_R0 down to the orbit radius over SIDES_TURN, its
# vertical reach squashed toward SIDES_Y_MAX like the qubit join's
# ellipse) and each qubit travels it by ARC LENGTH at a speed that only
# falls: SIDES_V0 x the orbit speed at the edge, easing (1 - u)^2 onto
# exactly the orbit speed at the join — so the motion never stops and
# restarts, and the orbit picks it up at the same speed and heading.
SIDES_R0 = 240.0            # start radius: both qubits fully off the panel
SIDES_TURN = 2 * math.pi    # angle swept while spiralling in
SIDES_K = 3                 # radius easing exponent (flat onto the orbit)
SIDES_Y_MAX = 44.0          # vertical reach cap (loading's join ellipse)
SIDES_V0 = 2.5              # entry speed, in orbit speeds


def t_enter(enter):
    """validate an entrance; the single-circle slide's length (ENTER_MS)
    for "left" / "right", 0 otherwise (the sides approach's length is
    geometry — _sides(cfg.qubit)["t_in"])"""
    if enter not in ENTERS:
        raise ValueError(f"unknown burst entrance {enter!r}; "
                         f"expected one of left, right, sides (or None)")
    return ENTER_MS if enter in ("left", "right") else 0


@functools.lru_cache(maxsize=None)
def _sides(q):
    """the sides approach for one QubitCfg: the arc-length table of the
    spiral (for the qubit starting on the right; its twin is the same
    path turned by pi), the approach length t_in, and the shift from film
    time to qubit_pose time at which the orbit takes over"""
    gx, gy = q.gc
    w = 2 * math.pi / q.rev_ms          # orbit angular speed, rad / ms
    v = w * q.orbit_r                   # orbit speed, px / ms
    d = SIDES_R0 - q.orbit_r
    ym = SIDES_Y_MAX - q.orbit_r
    n = 4000
    ths, xs, ys, ss = [], [], [], []
    s = 0.0
    for i in range(n + 1):
        th = SIDES_TURN * i / n
        R = q.orbit_r + d * (1 - i / n) ** SIDES_K
        ry = q.orbit_r + ym * math.tanh((R - q.orbit_r) / ym)
        x, y = gx + math.cos(th) * R, gy + math.sin(th) * ry
        if xs:
            s += math.hypot(x - xs[-1], y - ys[-1])
        ths.append(th)
        xs.append(x)
        ys.append(y)
        ss.append(s)
    # s(t) = v t + (v0 - v) t_in / 3 (1 - (1 - u)^3) must cover the path
    t_in = s / (v * (1 + (SIDES_V0 - 1) / 3))
    # the orbit must pick the pair up at the arrival angle: qubit_pose's
    # post-join spin is th = w (tau - base); first such tau after the join
    base = q.t2 + q.T_SPLIT + q.T_RAMP / 2
    joined = q.t2 + q.T_SPLIT + q.T_JOIN
    tau = base + SIDES_TURN / w
    while tau < joined:
        tau += 2 * math.pi / w
    return dict(ths=ths, xs=xs, ys=ys, ss=ss, length=s, v=v, t_in=t_in,
                shift=round(t_in - tau))


def t_shift(cfg, enter=None):
    """film time minus stock qubit time once the loading leg is under way
    — everything after the entrance (orbit, spiral, clump, boom) plays
    this much later (or earlier: the sides approach replaces the hold,
    split and join)"""
    if enter == "sides":
        return _sides(cfg.qubit)["shift"]
    return t_enter(enter)


def t_arrive(cfg, enter=None):
    """when the loading pair is ON the orbit — the sides pair joining it,
    else the split and the sweep onto the circle done (the busy caption's
    start, as the qubit film's: the text breathes only once the circles
    are already going round — user rule, Sep 2026)"""
    if enter == "sides":
        return _sides(cfg.qubit)["t_in"]
    q = cfg.qubit
    return t_enter(enter) + q.t2 + q.T_SPLIT + q.T_JOIN


def t_resolve(cfg, enter=None):
    """time at which the boom lands (first ring done; late rings keep
    fading into the HOLD_END dwell, as in the sources)"""
    return t_shift(cfg, enter) + cfg.qubit.t6 + cfg.t_clump + cfg.t_boom


def t_tail(cfg):
    """how long the late rings keep fading past t_resolve — the staggered
    launches, each flying t_boom (the last lands (rings - 1) * stagger
    after the first); after this the canvas is empty"""
    return cfg.stagger_ms * (cfg.rings - 1)


def pose(t, cfg, enter=None, seed=None):
    """loading-leg bodies at t: the side entrance (enter="left"/"right":
    one full-size body travelling in from off the panel — the value
    screen's park spot, layout.VALUE_PARK_X, mirrored for "right" — on
    the flows' KIOSK spring, motion.spring_travel; enter="sides": the two
    qubits spiralling in from both edges onto the orbit) then the qubit
    pose"""
    q = cfg.qubit
    if enter == "sides":
        S = _sides(q)
        if t >= S["t_in"]:
            return loading.qubit_pose(t - S["shift"], q)
        u = clamp01(t / S["t_in"])
        s = S["v"] * t + (SIDES_V0 - 1) * S["v"] * S["t_in"] / 3 * (1 - (1 - u) ** 3)
        i = min(max(bisect.bisect_left(S["ss"], s), 1), len(S["ss"]) - 1)
        s0, s1 = S["ss"][i - 1], S["ss"][i]
        f = clamp01((s - s0) / (s1 - s0)) if s1 > s0 else 0.0
        x = S["xs"][i - 1] + (S["xs"][i] - S["xs"][i - 1]) * f
        y = S["ys"][i - 1] + (S["ys"][i] - S["ys"][i - 1]) * f
        gx, gy = q.gc
        # body order matches qubit_pose's (pi + th, th): the twin first
        return dict(bodies=[dict(x=2 * gx - x, y=2 * gy - y, r=q.r_q),
                            dict(x=x, y=y, r=q.r_q)], bind=0)
    t0 = t_enter(enter)
    if t0 and t < t0:
        gx, gy = q.gc
        x0 = VALUE_PARK_X if enter == "left" else W - VALUE_PARK_X
        k = spring_travel(t)
        # the body slides in at the token's VISIBLE radius: the seed it lands
        # on opens there (loading.qubit_pose), so the edge never steps out
        return dict(bodies=[dict(x=x0 + (gx - x0) * k, y=gy,
                                 r=q.r_big - components.TOKEN_INSET)],
                    bind=0)
    # a side entrance IS the travel: the seed then runs in place, so the
    # flow's circle is handed on only to the plain film
    return loading.qubit_pose(t - t0, q, seed if enter is None else None)


def clump_poly(cx, cy, r, t, intensity):
    """near-circle with a faint fast edge tremble"""
    pts = []
    for i in range(48):
        a = i / 48 * 2 * math.pi
        w = (1
             + intensity * 0.012 * math.sin(3 * a + t * 0.035)
             + intensity * 0.008 * math.sin(5 * a - t * 0.052)
             + intensity * 0.005 * math.sin(7 * a + t * 0.070))
        rr = r * w
        pts.append((cx + math.cos(a) * rr, cy + math.sin(a) * rr))
    return pts


def draw(cv, t, cfg=MAJOR, *, trail=None, body=colors.WHITE,
         clump_from=colors.WHITE, clump_to=None, ring=colors.WHITE,
         enter=None, seed=None):
    """Draw one frame of the burst at time t ms (pure in t).

    trail is one colour (default white, like the sources) faded per
    follower link; clump_to=None keeps the clump on clump_from. enter
    ("left" / "right") opens on the circle sliding in from that side;
    "sides" on the two qubits flying in from both edges onto the orbit —
    the follower stream samples the same pose, so the trail rides in
    with them.
    """
    trail = trail or colors.WHITE
    clump_to = clump_to or clump_from
    q = cfg.qubit
    gx, gy = q.gc
    t0 = t_shift(cfg, enter)

    src = None if seed is None else (seed["x"], seed["y"], seed["r"])
    if t < t0 + q.t6:
        # loading leg: entrance, split, orbit, spiral, with the follower stream
        P = pose(t, cfg, enter, src)
        u = P.get("seed_u", 1.0)
        seed_fill = (seed or {}).get("fill") or body
        gap = (0.22 / (2 * math.pi)) * q.rev_ms
        # the stream is DARK over the seed: one arriving body has nothing to
        # trail, and every sample behind it smears back to the handover
        for bi, b in enumerate(P["bodies"] if u >= 1.0 else []):
            prev = b
            pts = []
            for j in range(1, 6):
                Q = pose(t - j * gap, cfg, enter, src)
                p = Q["bodies"][min(bi, len(Q["bodies"]) - 1)]
                if (abs(p["x"] - prev["x"]) < 0.8
                        and abs(p["y"] - prev["y"]) < 0.8):
                    break
                pts.append(p)
                prev = p
            for j in range(len(pts) - 1, -1, -1):
                f = 1 - (j + 1) / 6.5
                cv.circle(pts[j]["x"], pts[j]["y"], b["r"],
                          gradients.scale(trail, f))
        if P["bind"] and len(P["bodies"]) == 2:
            b1, b2 = P["bodies"]
            max_dist = b1["r"] + b2["r"] + 2
            d = math.hypot(b2["x"] - b1["x"], b2["y"] - b1["y"])
            if clamp01((max_dist - d) / 8) > 0.5:
                loading.metaball(cv, b1, b2, max_dist, body)
        for b in P["bodies"]:
            cv.circle(b["x"], b["y"], b["r"],
                      body if u >= 1.0 else gradients.mix(seed_fill, body, u))
        return
    t -= t0
    t7 = q.t6 + cfg.t_clump
    if t < t7:
        # clump: trembles, shakes harder, compresses, colour shifts
        u = clamp01((t - q.t6) / cfg.t_clump)
        intensity = cfg.intensity[0] + cfg.intensity[1] * u
        jitter = cfg.jitter[0] + cfg.jitter[1] * u
        jx = jitter * math.sin(t * 0.093) * math.sin(t * 0.041)
        jy = jitter * math.sin(t * 0.081 + 1.7) * math.sin(t * 0.037)
        r = 22 * (1 - cfg.squeeze * ease(u))
        col = gradients.mix(clump_from, clump_to, ease(u))
        cv.polygon(clump_poly(gx + jx, gy + jy, r, t, intensity), fill=col)
    else:
        # boom: core flash bloom + staggered near-circular ring blast
        e = t - t7
        cu = clamp01(e / cfg.bloom[0])
        if cu < 1:
            cv.circle(gx, gy, 6 + cfg.bloom[1] * cu,
                      gradients.scale(ring, 1 - cu))
        for i in range(cfg.rings):
            re = e - i * cfg.stagger_ms
            if re < 0:
                continue
            ru = clamp01(re / cfg.t_boom)
            if ru >= 1:
                continue
            grow = 1 - (1 - ru) ** cfg.grow_p
            rx = 10 + (cfg.ring_span[0] + cfg.ring_span[1] * i) * grow
            ry = rx * cfg.aspect
            w = cfg.ring_w[0] + cfg.ring_w[1] * i
            col = gradients.scale(ring, (1 - ru) * cfg.ring_a)
            cv.d.ellipse([(gx - rx) * SUP, (gy - ry) * SUP,
                          (gx + rx) * SUP, (gy + ry) * SUP],
                         outline=col, width=max(1, int(round(w * SUP))))
