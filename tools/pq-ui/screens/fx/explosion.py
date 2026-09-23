"""Explosion — the token loads, clumps, and blows apart; major or minor.

Merged port of major_explosion.py + minor_explosion.py. A full-canvas
film, not a verdict: every frame is pq1.procedural.burst — the split /
orbit / spiral loading leg, the trembling clump, then the core flash
and the staggered ring blast. severity picks the burst table: "major"
is the five-ring blast past the frame, "minor" the contained two-ring
pop. Each element keeps its own spec colour (trail, body, clump_from,
clump_to, ring — "#RRGGBB" or [r, g, b]), all white by default like
the sources. bottom is empty by default; a flow can set one and it
fades onto the baseline once the boom lands; busy ("RECONNECTING…") is
the loading caption, riding the orbit like the qubit film's (split done
-> spiral; busy_until below holds it longer). enter ("left" / "right") opens on the circle sliding in from
that side of the panel at the flows' KIOSK spring pace, its follower
trail riding in with it; enter="sides" opens on the two qubits flying in
from both edges and spiralling straight onto the orbit — no rest, no
split, a speed that only falls onto the orbit's (burst.SIDES_*).
busy_until="boom" keeps the busy caption up past the orbit — through the
spiral and the trembling clump, faded out as the blast launches — for a
caption that must hold the whole loading (a list alternating
"WIPING…" / "DO NOT POWER OFF", status.BUSY_SWAP_MS). A spec that names an icon (a flow's ending,
dressed by its DEFAULTS) hands the token's glyph and explicit edge
stroke off over the seed exactly as the qubit film does, so the flow's
disc never pops to a plain body; the standalone film names none and
keeps the sources' plain white token.

The film ends on an empty canvas, so it can LEAD another status screen:
a spec's lead=dict(anim="explosion", ...) plays it first, the led
screen starting when the boom lands (status.LedAnim; the wipe verdict's
wallet_wiped_explosion preset).

revs sets how many turns the pair spins on the orbit before the spiral
(default the qubit film's loading.REVS, at its one turn a time) — a longer
loading without a slower one: the spin speed, the entrance and the spiral
are untouched, only the steady orbit lasts longer. That is the film's
MINIMUM: like the qubit film it LOOPS (status.StatusAnim.loops) — built
live by the bench driver its orbit repeats in whole turns until the host
answers (resolve), and everything after (clump, boom, the led screen)
moves with it; "ready" renders a film answered at that ms.
"""
import copy
import functools

from pq1 import colors, components, gradients, loading, status
from pq1.motion import clamp01, ease_out
from pq1.procedural import burst

ANIM = "explosion"
SPEC = dict(severity="major", bottom="", enter=None, busy_until="spiral", revs=None)
PRESETS = dict(major_explosion=dict(severity="major"),
               minor_explosion=dict(severity="minor"))

SEVERITIES = ("major", "minor")
BUSY_UNTIL = ("spiral", "boom")   # busy window end: the orbit's, or the boom
CFGS = dict(major=burst.MAJOR, minor=burst.MINOR)
COLOR_FIELDS = ("trail", "body", "clump_from", "clump_to", "ring")


@functools.lru_cache(maxsize=None)
def _cfg(sev, revs):
    """the severity's burst table, its orbit spinning `revs` turns (None:
    the stock table itself; loading.QubitCfg validates the count); cached
    so each geometry is built once — never loop state on it"""
    if revs is None:
        return CFGS[sev]
    cfg = copy.copy(CFGS[sev])
    cfg.qubit = loading.QubitCfg(revs=revs)
    return cfg


def _col(v):
    """spec colour: "#RRGGBB" or [r, g, b]; None -> white"""
    if v is None:
        return colors.WHITE
    if isinstance(v, str):
        return gradients.hex_to_rgb(v)
    return tuple(v)


class Explosion(status.StatusAnim):
    busy_pulse = True   # a loading film: the busy caption breathes over the orbit
    rests_on_token = False   # ends on an empty canvas (it leads; t_tail below)
    loops = True        # the orbit repeats until the host answers
    seeded = True       # the flow's circle becomes the first qubit

    @classmethod
    def seeds(cls, spec):
        """a side entrance is the film's OWN prologue — the body arrives from
        off the panel, not from the flow's circle — so only the plain film
        takes a seed from the transit; "sides" never reaches the window"""
        return spec.get("enter") is None

    def __init__(self, spec):
        super().__init__(spec)
        sev = spec.get("severity", "major")
        if sev not in SEVERITIES:
            raise ValueError(f"unknown explosion severity {sev!r}; "
                             f"expected one of {', '.join(SEVERITIES)}")
        self.cfg = _cfg(sev, spec.get("revs"))
        self.enter = spec.get("enter")
        self.t_tail = burst.t_tail(self.cfg)   # empty canvas after: can lead
        self.cols = {k: _col(spec.get(k)) for k in COLOR_FIELDS}
        q, t0 = self.cfg.qubit, burst.t_shift(self.cfg, self.enter)
        until = spec.get("busy_until") or "spiral"
        if until not in BUSY_UNTIL:
            raise ValueError(f"unknown explosion busy_until {until!r}; "
                             f"expected one of {', '.join(BUSY_UNTIL)}")
        t_out = (t0 + q.loop[1] if until == "spiral"   # the orbit, as the qubit film
                 else t0 + q.t6 + self.cfg.t_clump - status.BUSY_FADE_MS)  # gone as it blasts
        self.t_busy = (burst.t_arrive(self.cfg, self.enter), t_out)
        self.handoff_glyph = "icon" in spec   # a flow's token rides into the split

    def _loop(self):
        return self.cfg.qubit, burst.t_shift(self.cfg, self.enter)

    @property
    def loop(self):
        """the loop region: from the pair being ON the orbit (a sides
        entrance lands later than the stock join) to the spiral"""
        q, t0 = self._loop()
        return (burst.t_arrive(self.cfg, self.enter), t0 + q.t5)

    @property
    def t_resolve(self):
        """the boom lands — later by the loop's whole turns"""
        return burst.t_resolve(self.cfg, self.enter) + self.loop_shift

    @property
    def previews(self):
        return (burst.t_shift(self.cfg, self.enter) + 3000, self.t_resolve + 600)

    def draw(self, cv, t):
        c = self.cols
        tf = self.film_t(t)                  # the pose clock: the loop's wraps taken out
        burst.draw(cv, tf, self.cfg, trail=c["trail"], body=c["body"],
                   clump_from=c["clump_from"], clump_to=c["clump_to"],
                   ring=c["ring"], enter=self.enter, seed=self.seed)
        if self.handoff_glyph:
            self._draw_token_handoff(cv, tf)
        ta = ease_out(clamp01((t - self.t_resolve) / status.BUSY_FADE_MS))
        self.draw_caption(cv, ta)
        self.draw_busy(cv, t)                # the caption on the real clock

    def _draw_token_handoff(self, cv, t):
        """the flow token's glyph (and its explicit edge stroke) on the body
        over the SEED, shrinking and fading with the body that carries it
        (loading.qubit_pose glyph_r / glyph_a) — the same handoff every
        status film performs; on a side entrance the glyph rides the
        sliding body in, then seeds in place with it"""
        st, q = self.style, self.cfg.qubit
        if self.enter == "sides":
            return    # no token body: the pair flies in already split
        src = (None if self.seed is None
               else (self.seed["x"], self.seed["y"], self.seed["r"]))
        t0 = burst.t_enter(self.enter)
        if t < t0:
            b = burst.pose(t, self.cfg, self.enter, src)["bodies"][0]
            gr, ga = q.r_big, 1.0
        else:
            P = loading.qubit_pose(t - t0, q, src)
            b, gr, ga = P["bodies"][0], P["glyph_r"], P["glyph_a"]
        if ga <= 0.01:
            return
        gx, gy = b["x"], b["y"]
        components.glyph(cv, st["icon"], gx, gy, gr, ga, color=st["icon_color"])
        if st["ring"] is not None:
            cv.ring(gx, gy, b["r"], (*st["ring"], int(round(255 * ga))),
                    components.TOKEN_RING_W)


def add_args(ap):
    ap.add_argument("--severity", choices=SEVERITIES, default=None,
                    help="major (five-ring blast) or minor (two-ring pop)")
    ap.add_argument("--trail", default=None, metavar="HEX",
                    help="follower-stream colour, e.g. '#65D9FF'")
    ap.add_argument("--body", default=None, metavar="HEX",
                    help="token / qubit colour")
    ap.add_argument("--clump-from", default=None, metavar="HEX",
                    help="clump colour the moment it forms")
    ap.add_argument("--clump-to", default=None, metavar="HEX",
                    help="colour it vibrates toward")
    ap.add_argument("--ring", default=None, metavar="HEX",
                    help="explosion ring + core-flash colour")
    ap.add_argument("--revs", type=int, default=None, metavar="N",
                    help="orbit turns before the spiral (default 3) — a "
                         "longer loading at the same spin speed")
    ap.add_argument("--enter", choices=("left", "right", "sides"), default=None,
                    help="left / right: the circle slides in from that side "
                         "first; sides: two qubits fly in from both edges "
                         "onto the orbit")


def spec_from_args(args):
    d = {}
    if args.severity is not None:
        d["severity"] = args.severity
    for k in COLOR_FIELDS + ("enter", "revs"):
        v = getattr(args, k)
        if v is not None:
            d[k] = v
    return d


status.register(ANIM, Explosion)
