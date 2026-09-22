"""PQ1 status screens — one resting look, pluggable loading animations.

A status screen ("kind": "status") is a flow's terminal screen: the token
loads (animated), then resolves to the shared resting look — a black disc,
a state-coloured ring, the result glyph, and the caption on the y 128
baseline; chevrons are hidden (no input). The resting look is fixed here so
every flow ends the same way; the loading choreography is a StatusAnim
chosen per screen with "anim" (a registry, like components.GLYPHS):

    dict(kind="status", bottom="TRANSACTION CONFIRMED")   # qubit film, check
    dict(kind="status", result="x", state="failed",
         bottom="DECLINED")                    # no film: resolves in place

The film is for work. An ending that resolves done plays the qubit film
(the loading choreography) and lands the check; a cancel ending — any
non-done state — plays NO film: the arrived token resolves in place
(ResolveStatus — one flash beat, then the X and caption land on the
film's own resolve timing). default_anim picks by state; an explicit
"anim" always wins. There is no other cancel or failure choreography
(the old orbit spinner is gone from the project). A brand flow family
(SAFE, COWSWAP) rests its endings on branded_resting — the disc FILLED:
SIGNED on the brand fill with a black ring and the result glyph in the
family's mark colour (SAFE black, CoW Swap navy), DECLINED on the
failed-red disc with a black ring + X — the one cancel circle every
family shares. The stroke is black on every branded ending. An
unbranded flow's endings keep the default resting look:
no fill (black disc), the red/green state colour as the ring STROKE,
check / X in that same colour (DESIGN.md § Color).

Fields (all optional):
    "anim"   : loading choreography; default_anim when unset — "qubit"
                                                for done endings, "resolve"
                                                for cancels; "arrive" — the
                                                resting look ARRIVING on the
                                                verdict entrance law after
                                                a lead film emptied the
                                                canvas (the firmware
                                                endings: the explosion,
                                                then the filled disc)
                                                (the screens package
                                                registers more: verdicts,
                                                explosion)
    "result" : "check" (default) | "x" | None   glyph shown on resolve
    "state"  : "done" (default) | "failed" | "warning" | "awaiting"
                                                -> colors.STATE ring/glyph colour
    "color"  : [r, g, b]                        explicit flash / ring / glyph
                                                colour, wins over state
                                                (default: a branded ending's
                                                resting fill, else the state
                                                colour)
    "busy"   : "SIGNING…"                       caption shown while loading;
                                                a list alternates its lines
                                                (["WIPING…", "DO NOT POWER
                                                OFF"], BUSY_SWAP_MS slots)
    "icon"   : "eth"                            glyph in the token while loading
    "bottom" : "TRANSACTION CONFIRMED"          the resolved caption
    "lead"   : dict(anim="explosion",           a film played FIRST; the screen
                    severity="major",           starts when the lead resolves
                    enter="left")               (LedAnim). Only a film that
                                                ends on an empty canvas can
                                                lead (StatusAnim.t_tail set —
                                                the explosion); anything else
                                                raises. "handoff" crossfades
                                                the flow token out under the
                                                lead, never after it
    "lead_gap" : 700                            ms of black between the lead
                                                resolving and the screen
                                                starting (default 0)

Unknown anim / result / state names raise with the valid names — no silent
fallback on a device whose whole job is showing the right state.
"""
from . import colors, components, layout, loading, motion
from .motion import clamp01, ease_out

RESULT_HOLD_MS = 2450   # result shown before the flow moves on; with the qubit
                        # resolve at t7 6150 ms this reproduces motion.STATUS_DWELL
BUSY_FADE_MS = 300      # busy-caption fade in / out (ease-out both ways)
BUSY_SWAP_MS = 2000     # an alternating busy caption: each line holds at least
                        # this long (a warning must be readable), fading out
                        # then in between lines like the confirm band

RESULTS = ("check", "x")     # valid "result" glyphs (None = no glyph)


def branded_resting(fill, mark=colors.BLACK):
    """A brand flow family's resting override (DESIGN.md § Color): the disc
    filled with a brand colour, a BLACK ring stroked flush at the disc
    edge — the stroke is black on every branded ending — and the result
    glyph in the family's mark colour (black by default — SAFE; CoW Swap
    passes its #012F7A cow-head navy, colors.COWSWAP_DARK, for the
    check). SIGNED rests on the brand fill; DECLINED rests on the
    failed red with the default black mark — colors.RED disc, black ring
    + X — the one cancel circle every family shares (a family's own mark
    colours SIGNED only). An
    unbranded flow's endings keep the default resting look instead —
    black disc, state-coloured ring and glyph, no fill."""
    return dict(fill=list(fill), ring=list(colors.BLACK), glyph=list(mark))


def style_of(spec):
    """Resolve + validate a status screen's optional fields -> style dict."""
    result = spec.get("result", "check")
    if result is not None and result not in RESULTS:
        raise ValueError(f"unknown status result {result!r}; "
                         f"expected one of {', '.join(RESULTS)} or None")
    state = spec.get("state", "done")
    if state not in colors.STATE:
        raise ValueError(f"unknown status state {state!r}; "
                         f"expected one of {', '.join(sorted(colors.STATE))}")
    rest = spec.get("resting") or {}
    # the resolve flash ring's colour (and, unbranded, the resting ring +
    # glyph): an explicit "color" wins; a branded ending pulses in its own
    # resting disc fill (SAFE green, CoW Swap blue, the cancel red) — never
    # the state green over a brand disc; an unbranded ending flashes its
    # state colour
    if "color" in spec:
        color = tuple(spec["color"])
    elif "fill" in rest:
        color = tuple(rest["fill"])
    else:
        color = colors.STATE[state]
    resting = dict(
        fill=tuple(rest["fill"]) if "fill" in rest else colors.BLACK,
        ring=tuple(rest["ring"]) if "ring" in rest else color,
        glyph=tuple(rest["glyph"]) if "glyph" in rest else color,
        flush="resting" in spec)   # a branded look strokes the disc edge
    st = components.token_style_from_spec(spec)
    return dict(icon=spec.get("icon", "eth"), result=result, color=color,
                resting=resting, icon_color=st["icon_color"],
                variant=st["variant"], ramp=st["ramp"], ring=st["ring"],
                fill=st["fill"] if st["variant"] != "unknown" else None,
                film=st["film"] if st["variant"] != "unknown" else None,
                trail=components.trail_palette_from_spec(spec),
                bottom=spec.get("bottom", ""), busy=spec.get("busy"))


def draw_handoff(cv, spec, style, t, span):
    """flow splicing: with spec handoff=True the resting token Sim was
    drawing crossfades out over span ms instead of popping to black"""
    if not spec.get("handoff"):
        return
    k = ease_out(clamp01(t / span))
    if k >= 1.0:
        return
    components.token_from_spec(cv, layout.CENTER_X, layout.CIRCLE_CY,
                               layout.CIRCLE_R, spec, glyph_a=style["icon"])
    if k > 0.003:
        cv.circle(layout.CENTER_X, layout.CIRCLE_CY, layout.CIRCLE_R + 2.5,
                  (*colors.BLACK, int(round(255 * k))))


class StatusAnim:
    """One loading choreography ending in the shared resting look.

    Subclasses set t_resolve (ms when the result begins), t_busy (the busy
    caption's (in, out) window, or None) and previews ((mid-animation,
    resolved) frame times for stills sheets), and implement draw(cv, t) as a
    pure function of t so any frame is seekable (--at renders, resumable
    panel playback). A film that ends on an empty canvas sets t_tail (ms it
    keeps drawing past t_resolve — the explosion's late rings) and may then
    lead another screen (the "lead" field, LedAnim)."""

    name = None
    t_resolve = 0
    t_busy = None
    busy_pulse = False  # True on a loading film: the busy caption breathes
    t_tail = None       # None: the film rests on a look — it cannot lead
    previews = (0, 0)
    # what the screen leaves on the canvas, for the flow Sim's transit
    # (flow.Sim.draw): True = the resting token disc (the qubit film, a
    # resolve, an idle screen) — Sim morphs it into the next screen;
    # False = the screen owns its canvas (a verdict sign, a PIN row) — Sim
    # fades the screen out on the outgoing alpha spring and draws no
    # token over the transit, and the next screen's handoff is dropped
    rests_on_token = True
    # True on an ENTRY (the PIN row): input-driven — the driver routes
    # taps, double-taps and holds to the animation (input / outcome /
    # finished, screens/pin/pin_entering.py) instead of navigating
    interactive = False

    def __init__(self, spec):
        self.spec = spec
        self.style = style_of(spec)

    @property
    def duration(self):
        """total ms — the screen's default dwell"""
        return self.t_resolve + RESULT_HOLD_MS

    def draw(self, cv, t):
        raise NotImplementedError

    def draw_busy(self, cv, t):
        """the optional "busy" caption inside the t_busy window.

        On a loading film (busy_pulse True — the qubit film, the explosion)
        the caption BREATHES: it fades in and out on a slow pulse
        (motion.busy_pulse, BUSY_PULSE_MS a cycle — whole cycles fitted to
        the window, so it starts and ends dark) for as long as the loading
        runs; the films open the window only once the qubits are ON the
        orbit, never over the split (user rule, Sep 2026). A steady caption
        (busy_pulse False) is for a gesture, not a loading — "HOLD TO
        CONFIRM" — and fades once at each end. A list of lines ("WIPING…",
        "DO NOT POWER OFF") alternates through the window in equal slots of
        at least BUSY_SWAP_MS: one breath per line on a film, else each line
        fading out before the next fades in (the confirm band's sequential
        swap)."""
        s = self.style["busy"]
        if not s or self.t_busy is None:
            return
        t_in, t_out = self.t_busy
        if isinstance(s, (list, tuple)):
            span = t_out + BUSY_FADE_MS - t_in
            n = max(len(s), int(span // BUSY_SWAP_MS))
            slot = span / n
            k = min(n - 1, max(0, int((t - t_in) // slot)))
            t0 = t_in + k * slot
            if self.busy_pulse:
                a = motion.busy_pulse((t - t0) / slot)
            else:
                a = (ease_out(clamp01((t - t0) / BUSY_FADE_MS))
                     * (1 - ease_out(clamp01((t - (t0 + slot - BUSY_FADE_MS))
                                             / BUSY_FADE_MS))))
            components.caption(cv, s[k % len(s)], a)
            return
        if self.busy_pulse:
            if not t_in <= t < t_out:
                return
            span = t_out - t_in
            period = span / max(1, int(round(span / motion.BUSY_PULSE_MS)))
            a = motion.busy_pulse(((t - t_in) % period) / period)
        else:
            a = (ease_out(clamp01((t - t_in) / BUSY_FADE_MS))
                 * (1 - ease_out(clamp01((t - t_out) / BUSY_FADE_MS))))
        components.caption(cv, s, a)

    def draw_caption(self, cv, alpha):
        """the resolved caption ("bottom") on the y 128 baseline"""
        if alpha > 0.01:
            components.caption(cv, self.style["bottom"], alpha)


class QubitStatus(StatusAnim):
    """The qubit sequence (loading.draw_status): the token splits into two
    qubits, they sweep onto a circular path and spin (metaball merge as they
    pass), spiral in, flash, and resolve. The PQ1 status film."""

    busy_pulse = True   # the busy caption breathes over the orbit

    def __init__(self, spec):
        super().__init__(spec)
        self.cfg = loading.QubitCfg()
        self.t_resolve = self.cfg.t7                    # flash done, result in
        c = self.cfg
        self.t_busy = (c.t2 + c.T_SPLIT + c.T_JOIN,     # on the orbit -> spiral
                       c.t5)
        self.previews = (3500, 6800)                    # mid-spin, resolved

    def draw(self, cv, t):
        st = self.style
        loading.draw_status(cv, t, st["bottom"], self.cfg,
                            result_color=st["color"], glyph_name=st["icon"],
                            body_fill=st["film"], trail=st["trail"],
                            result_glyph=st["result"], unknown_ramp=st["ramp"],
                            ring_color=st["ring"], resting=st["resting"],
                            glyph_color=st["icon_color"])
        self.draw_busy(cv, t)


class ResolveStatus(StatusAnim):
    """No film — the cancel resolve (DESIGN.md § Status animations).

    A cancellation did no work, so it shows no loading: the arrived token
    resolves in place over one flash beat (the film's T_FLASH). The token
    glyph hands off at the film's split rate, disc and ring crossfade into
    the resting look (branded: the filled disc; unbranded: black disc,
    state-colour stroke), the flash ring fires in the state colour, then
    the result glyph and caption land on the film's own resolve timing.
    default_anim picks this for every non-done ending."""

    def __init__(self, spec):
        super().__init__(spec)
        self.cfg = loading.QubitCfg()      # geometry + the resolve beat
        self.t_resolve = self.cfg.T_FLASH
        self.previews = (200, 1600)        # mid-flash, resolved

    def draw(self, cv, t):
        st, c = self.style, self.cfg
        rest = st["resting"]
        gx, gy = c.gc
        lu = clamp01(t / self.t_resolve)   # the flash beat, linear
        u = ease_out(lu)                   # colour / geometry crossfade

        def mix(a, b):
            return colors.grad_color(u, [(0.0, tuple(a)), (1.0, tuple(b))])

        # disc: token body -> resting fill, edge easing out to the film's
        # full resting radius
        disc_r = motion.lerp(c.r_big - components.TOKEN_INSET, c.r_big, u)
        if st["variant"] == "unknown":     # gradient base, resting fades over
            components.unknown_disc(cv, gx, gy, disc_r, st["ramp"])
            if u > 0.004:
                cv.circle(gx, gy, disc_r, (*rest["fill"], int(round(255 * u))))
        else:
            tok_fill = st["fill"] if st["fill"] is not None else colors.BLACK
            cv.circle(gx, gy, disc_r, mix(tok_fill, rest["fill"]))
        # token glyph hands off at the film's split rate
        ga = clamp01(1 - lu / 0.45)
        if ga > 0.01:
            components.glyph(cv, st["icon"], gx, gy, c.r_big, ga,
                             color=st["icon_color"])
        # ring: the token stroke -> the resting ring. Every token stroke —
        # default white or explicit — sits at the token's visible edge
        # (r_big - TOKEN_INSET, components.token); a branded resting ring
        # rides flush at the film's full resting radius
        ring_from = st["ring"] if st["ring"] is not None else colors.WHITE
        r0 = c.r_big - components.TOKEN_INSET
        r1 = c.r_big if rest["flush"] else c.r_big - 1.2
        cv.ring(gx, gy, motion.lerp(r0, r1, u), mix(ring_from, rest["ring"]),
                components.TOKEN_RING_W)
        # flash fades IN over the first 12% of the beat: at t 0 the frame
        # equals the arrived token exactly (no red pop on the disc edge),
        # then the ring detaches and fades like the film's
        components.flash_ring(cv, gx, gy, c.r_big + 55 * lu, st["color"],
                              (1 - lu) * 0.85 * clamp01(lu / 0.12))
        e = t - self.t_resolve
        if st["result"] is not None and e > 0:
            components.GLYPHS[st["result"]](cv, gx, gy, c.r_big,
                                            clamp01(e / 350), rest["glyph"])
        self.draw_caption(cv, clamp01((e - 120) / 350))


class ArriveStatus(StatusAnim):
    """The resting look arrives — no film of its own (DESIGN.md § Status
    animations).

    The ending for a screen whose work was shown by a LEAD film that ends
    on an empty canvas (the explosion): after a black hold the resolved
    token — the resting disc, its ring and the result glyph together —
    fades in and rises 0.97 -> 1 on the verdict entrance law (motion.arrive
    within ARRIVE_MS, never an overshoot), a beat, then the caption. The
    verdict phases (T_HOLD 400 / T_IN 300 / T_WAIT 450 / T_TEXT 300 —
    pq1.verdict.VerdictAnim), so t_resolve is 1450 and the screen dwells
    3900. Branded: the filled disc under the flush ring (the firmware
    endings — green disc + black check, red disc + black X); unbranded:
    the black disc under the state-colour stroke."""

    T_HOLD = 400
    T_IN = motion.ARRIVE_MS
    T_WAIT = 450
    T_TEXT = 300

    def __init__(self, spec):
        super().__init__(spec)
        self.cfg = loading.QubitCfg()      # the resting geometry
        self.t_resolve = self.T_HOLD + self.T_IN + self.T_WAIT + self.T_TEXT
        self.previews = (self.T_HOLD + self.T_IN // 2, self.duration - 600)

    def draw(self, cv, t):
        draw_handoff(cv, self.spec, self.style, t, self.T_HOLD)
        st, c = self.style, self.cfg
        rest = st["resting"]
        gx, gy = c.gc
        u = clamp01((t - self.T_HOLD) / self.T_IN)
        if u > 0.001:
            a, s = ease_out(u), motion.arrive(u)     # the entrance law
            r = c.r_big * s
            cv.circle(gx, gy, r, colors.scale(rest["fill"], a))
            cv.ring(gx, gy, r if rest["flush"] else r - 1.2,
                    colors.scale(rest["ring"], a), components.TOKEN_RING_W)
            if st["result"] is not None:
                components.GLYPHS[st["result"]](cv, gx, gy, r, a, rest["glyph"])
        ta = ease_out(clamp01((t - (self.T_HOLD + self.T_IN + self.T_WAIT))
                              / self.T_TEXT))
        self.draw_caption(cv, ta)


class LedAnim(StatusAnim):
    """A status screen led by a film: the lead plays from t 0, the screen's
    own animation starts when the lead resolves (its t 0 = lead.t_resolve)
    while the lead's tail finishes underneath — the explosion's late rings
    fade through a verdict's black hold as the icon pops in. Built by
    anim_for when a spec carries "lead"; durations add, so a flow dwells
    for the whole sequence. "lead_gap" (ms, default 0) holds the screen
    back that much longer after the lead resolves — WALLET WIPED waits
    for the blast to clear."""

    HANDOFF_MS = 400    # the verdict handoff span (verdict.VerdictAnim.T_HOLD)

    def __init__(self, spec, lead, main):
        super().__init__(spec)
        self.lead = lead
        self.main = main
        self.name = main.name
        self.gap = spec.get("lead_gap") or 0

    @property
    def t_start(self):
        """when the led screen's own animation begins"""
        return self.lead.t_resolve + self.gap

    @property
    def t_resolve(self):
        return self.t_start + self.main.t_resolve

    @property
    def duration(self):
        return self.t_start + self.main.duration

    @property
    def previews(self):
        return (self.lead.previews[0], self.t_start + self.main.previews[1])

    @property
    def rests_on_token(self):
        return self.main.rests_on_token

    @property
    def interactive(self):
        return self.main.interactive

    def draw(self, cv, t):
        draw_handoff(cv, self.spec, self.style, t, self.HANDOFF_MS)
        if t < self.lead.t_resolve + self.lead.t_tail:
            self.lead.draw(cv, t)
        if t >= self.t_start:
            self.main.draw(cv, t - self.t_start)


# --------------------------------------------------------------- registry --
ANIMS = {}


def register(name, cls):
    """add a status animation (like components.register_glyph)"""
    cls.name = name
    ANIMS[name] = cls


def default_anim(spec):
    """The animation when "anim" is unset — the cancel rule (DESIGN.md
    § Status animations): an ending that resolves done plays the qubit
    film; a cancel ending (any non-done state) skips the film and
    resolves in place."""
    return "qubit" if spec.get("state", "done") == "done" else "resolve"


def anim_class(spec):
    """the registered class one status screen description resolves to —
    a lookup, never an instance (a "lead" spec resolves to the LED
    screen's own class: what rests on the canvas is the main's)"""
    name = spec["anim"] if "anim" in spec else default_anim(spec)
    if name not in ANIMS:
        raise ValueError(f"unknown status anim {name!r}; "
                         f"expected one of {', '.join(sorted(ANIMS))}")
    return ANIMS[name]


def rests_on_token(spec):
    """does the screen's animation leave the resting token disc on the
    canvas (StatusAnim.rests_on_token)? A verdict or an entry does not:
    the flow Sim then fades the screen out and draws no token over the
    transit (flow.Sim.draw)"""
    return bool(anim_class(spec).rests_on_token)


def is_interactive(spec):
    """is the screen an ENTRY — an input-driven animation the driver
    types into (StatusAnim.interactive)?"""
    return bool(anim_class(spec).interactive)


def anim_for(spec):
    """the StatusAnim instance for one status screen description (a
    LedAnim when the spec carries a "lead" film)"""
    cls = anim_class(spec)
    if spec.get("lead") is None:
        return cls(spec)
    lead = anim_for(dict(spec["lead"], handoff=False))
    if lead.t_tail is None:
        raise ValueError(f"status anim {lead.name!r} cannot lead a screen: "
                         f"its film rests on a look instead of ending on an "
                         f"empty canvas (a lead sets t_tail — e.g. "
                         f"\"explosion\")")
    main = cls(dict(spec, lead=None, handoff=False))
    return LedAnim(spec, lead, main)


register("qubit", QubitStatus)
register("resolve", ResolveStatus)
register("arrive", ArriveStatus)

# the default animation's duration IS the documented status dwell
assert loading.QubitCfg().t7 + RESULT_HOLD_MS == motion.STATUS_DWELL
