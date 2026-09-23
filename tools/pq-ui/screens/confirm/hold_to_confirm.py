"""Hold to confirm — a hold fills the token's ring; confirm or cancel.

The standalone demo of the design system's hold gesture (DESIGN.md § Input).
A teal placeholder token drifts on a scaled-down idle sweep under "HOLD TO
CONFIRM" with the chevrons in the up (hold-armed) pose; the press lands at
T_IDLE and the system hold fill rises from TAP_MAX_MS after it to a full
disc at HOLD_COMMIT_MS — the same components.hold_flood on the same
motion.hold_fill curve that pq1.flow.Sim draws on a flow's commit screens:
a 30 % see-through liquid rising from the bottom of the disc — black over
the teal art and glyph, under the white ring (a black body such as the ETH
mono token gets the white film inside instead). The spec's token / icon /
resting fields are honoured, so a SAFE-pinned spec renders the Safe disc,
black flush ring and the same dark film rising over the logo (`--family safe`).
ending="confirm": the token fades and the inner qubit status film plays on
the token's palette to "TRANSACTION CONFIRMED" — a branded spec lands on its
filled resting disc. ending="cancel": the hold releases at 60 %, snaps back,
the token fades, and the failed resting look pops in over procedural.burst's
MINOR boom — burst.draw is called at an offset entering its boom phase, so
the bloom + ring constants are reused, never copied — "TRANSACTION
CANCELLED": unbranded = black disc, red stroke, red X; branded = red disc,
black flush ring, black X (the endings rule, DESIGN.md § Color).
"""
import copy
import importlib
import math

from pq1 import colors, components, gradients, motion, status
from pq1.layout import CENTER_X, CIRCLE_CY, CIRCLE_R
from pq1.motion import clamp01, ease_out
from pq1.procedural import burst

ANIM = "hold_to_confirm"
SPEC = dict(ending="confirm", result=None, busy="HOLD TO CONFIRM",
            icon="eth", token={"palette": gradients.TEAL_RAMP})
PRESETS = dict(hold_confirm_success=dict(ending="confirm"),
               hold_confirm_cancel=dict(ending="cancel"))

ENDINGS = ("confirm", "cancel")

# timeline (ms): idle drift, the system hold fill, then the ending's tail
T_IDLE = 1800                                   # phase a: gentle drift, then the press
T_COMMIT = T_IDLE + motion.HOLD_COMMIT_MS       # 3800: the disc is full, commit fires
T_FADE = 260                                    # confirm: token fade-out
RELEASE_K = 0.6                                 # cancel: released at 60 % fill
T_REL = T_IDLE + int(motion.hold_fill_ms(RELEASE_K))        # 3100
T_POP = T_REL + motion.HOLD_SNAPBACK_MS + motion.FADE_MS   # 3480
T_IN, T_WAIT, T_TEXT = motion.ARRIVE_MS, 450, 300   # cancel tail (verdict pacing: fade + arrive)

# geometry (UI px)
DRIFT_AMP = motion.SWEEP_AMP / 8                # idle sweep, scaled way down
T_RECENTER = 300                                # the press pulls the drift home


class HoldToConfirm(status.StatusAnim):
    """drift -> hold fill -> qubit film (confirm) or the failed disc arriving (cancel)"""

    def __init__(self, spec):
        self.ending = spec.get("ending", "confirm")
        if self.ending not in ENDINGS:
            raise ValueError(f"unknown hold ending {self.ending!r}; "
                             f"expected one of {', '.join(ENDINGS)}")
        if self.ending == "confirm":
            super().__init__(spec)
            self.t_c = T_COMMIT + T_FADE
            # the whole spec rides into the film — resting / icon / icon_color
            # / token survive, so a branded ending lands on its filled disc;
            # busy stays out: "HOLD TO CONFIRM" must not caption the spin
            inner = {k: v for k, v in spec.items()
                     if k not in ("anim", "ending", "busy")}
            inner.update(state="done", result="check",
                         bottom=spec.get("bottom") or "TRANSACTION CONFIRMED")
            self.inner = status.QubitStatus(inner)
            self.t_resolve = self.t_c + self.inner.t_resolve
            self.t_busy = (0, T_COMMIT)
        else:
            cancel = dict(spec, state="failed", result="x")
            if "resting" in spec:   # branded: the SIGNED construction, red swapped in
                cancel["resting"] = dict(spec["resting"],
                                         fill=list(colors.STATE["failed"]))
            super().__init__(cancel)
            if not self.style["bottom"]:
                self.style["bottom"] = "TRANSACTION CANCELLED"
            self.boom0 = burst.MINOR.qubit.t6 + burst.MINOR.t_clump
            self.t_resolve = T_POP + T_IN + T_WAIT + T_TEXT    # 4530
            self.t_busy = (0, T_REL)
        self.tok = components.token_style_from_spec(spec)
        self.hold = components.hold_style(self.tok)

    @property
    def previews(self):
        return (T_IDLE + int(motion.hold_fill_ms(0.5)), self.duration - 600)

    def _fill(self, t):
        """hold progress 0..1 on the system curve; the cancel ending
        releases at RELEASE_K and snaps back"""
        return motion.hold_fill(t - T_IDLE,
                                T_REL - T_IDLE if self.ending == "cancel" else None)

    def _hold_alpha(self, t):
        """the hold composition's fade-out per ending"""
        if self.ending == "confirm":
            return 1 - ease_out(clamp01((t - T_COMMIT) / T_FADE))
        t0 = T_REL + motion.HOLD_SNAPBACK_MS
        return 1 - ease_out(clamp01((t - t0) / motion.FADE_MS))

    def _draw_hold(self, cv, t):
        self.draw_busy(cv, t)
        a = self._hold_alpha(t)
        if a <= 0.01:
            return
        drift = 1 - ease_out(clamp01((t - T_IDLE) / T_RECENTER))
        cx = CENTER_X + DRIFT_AMP * drift * math.sin(
            2 * math.pi * t / motion.SWEEP_PERIOD_MS)
        icon = self.style["icon"]
        placement, col = self.hold
        components.token_styled(cv, cx, CIRCLE_CY, CIRCLE_R, self.tok,
                                glyph_a=icon, glyph_b=icon, alpha=a,
                                hold=dict(k=self._fill(t), placement=placement,
                                          color=col, alpha=a))
        ca = a * ease_out(clamp01(t / status.BUSY_FADE_MS))
        if self.ending == "cancel":
            ca *= 1 - ease_out(clamp01((t - T_REL) / motion.FADE_MS))
        components.chevron_pair(cv, 0, 0, alpha=ca)

    def _draw_cancel(self, cv, t):
        e = t - T_POP
        st = self.style
        rest = st["resting"]
        burst.draw(cv, self.boom0 + e, burst.MINOR, ring=st["color"])
        u = clamp01(e / T_IN)
        a, s = ease_out(u), motion.arrive(u)   # the verdict entrance law
        r = CIRCLE_R * s
        # the failed resting look (status.style_of): branded = filled disc,
        # flush black ring, black X; unbranded = black disc, red stroke, red X
        cv.circle(CENTER_X, CIRCLE_CY, r, colors.scale(rest["fill"], a))
        rr = r if rest["flush"] else r - components.TOKEN_INSET
        if rr > 0:   # arrive starts at 0.97 r, so the ring always draws — a safety net
            cv.ring(CENTER_X, CIRCLE_CY, rr, colors.scale(rest["ring"], a),
                    components.TOKEN_RING_W)
        components.GLYPHS["x"](cv, CENTER_X, CIRCLE_CY, r, a, rest["glyph"])
        self.draw_caption(cv, ease_out(
            clamp01((t - (T_POP + T_IN + T_WAIT)) / T_TEXT)))

    def draw(self, cv, t):
        if self.ending == "confirm":
            if t < self.t_c:
                self._draw_hold(cv, t)
            else:
                self.inner.draw(cv, t - self.t_c)
        elif t < T_POP:
            self._draw_hold(cv, t)
        else:
            self._draw_cancel(cv, t)


def add_args(ap):
    ap.add_argument("--ending", choices=ENDINGS, default=None,
                    help="confirm (qubit film) or cancel (failed pop + x)")
    ap.add_argument("--family", default=None, metavar="NAME",
                    help="dress the demo in a flow family's brand (flows/NAME: "
                         "its DEFAULTS + branded resting), e.g. safe; pair with "
                         "-o so the teal demo's render isn't overwritten")


def spec_from_args(args):
    over = {} if args.ending is None else dict(ending=args.ending)
    if args.family:
        # lazy: the flows package is imported only on demand, so the screens
        # library never depends on flows (flows/unlock_batch imports screens)
        fam = importlib.import_module(f"flows.{args.family}")
        over.update(copy.deepcopy(fam.DEFAULTS))
        done = next(e for e in fam.ends().values()
                    if e.get("state", "done") == "done")
        over["resting"] = done["resting"]
    return over


status.register(ANIM, HoldToConfirm)
