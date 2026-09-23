"""PIN entering — the eight-ring input, typed with the two buttons.

The 8 idle rings (procedural.pin_slots) fade in on the cy 72 row. The
active slot eases idle -> YELLOW and lifts 3 px; a tap dials its digit
(right +1, left -1, 0..9 wrapping) with a 220 ms micro-bounce; BOTH
buttons together ENTER the digit (the ring turns white, the cursor
advances); a double press only moves the cursor over entered digits —
left BACK to fix one (its slot is active again, its dial live), right
NEXT forward again — moving never takes a dial away: a changed digit
stays changed, a digit dialed on a fresh slot stays in its grey ring
until it is entered (user correction, Sep 2026). ENTERING THE 8TH DIGIT
SUBMITS: the PIN is checked at once, no hold (user decision, Sep 2026 —
the right hold is unbound on an entry). A left hold cancels the entry
while it is open (DESIGN.md § Input — the entry grammar; user
decision, Sep 2026: enter on both buttons, the double press for
navigation, so a fast run of taps always dials); its progress is the
rings filling bottom-up with the entry's liquid — opaque white, rising
over the stroke too, the part of each digit under its surface turning
black (the token has no disc here — the row is what fills), full at
HOLD_COMMIT_MS, draining on an early release. Instruction labels beside
the corner chevrons PULSE — each hint 3 s on (fading in and out), 3 s
off, then the next (user request, Sep 2026): − / +, ENTER (BOTH),
BACK (2X) / NEXT (2X). The 8th entry is checked DIRECTLY: its ring
turns white, the hints fade out (SWAP_MS) and the row — rings, ENTER
PIN — holds T_CHECK (200 ms) and fades (user request, Sep 2026: no
BACK, no CONFIRM, then "it should directly check … 200ms"). Only the
exit="rest" preview, which never submits, swaps its caption to "PIN
ENTERED".

The row is an EVENT log — [(t, kind, arg)]: tick / tap / enter / next /
back / hold / release / submit / cancel / restart — replayed by
entry_state(t, events), so every frame is a pure function of time. A
"tick" (the demo's) changes the digit at once; a "tap" (a live button)
bounces the ring at once but its digit LANDS a beat later — the chord
window (motion.CHORD_MS) on a fresh slot, the double-tap window
(DOUBLE_TAP_MS) where a double press could move the cursor — so a tap
the other button turns into ENTER, or a second press into NEXT / BACK, is
undone before the ring ever shows a number it then takes back (user
correction, Sep 2026). The scripted demo writes the log
from `typed` (the dial pace of the design canvas: STEP_TICK per +1,
STEP_SETTLE, STEP_ADV) and, with exit="submit", submits on its 8th
enter (exit="rest" stops short of the check: the row rests on PIN
ENTERED, a preview); the bench driver (pq1.driver) appends the same
events from key edges — input(), undo_last_tick(), outcome, finished().
A cancel fades the row out; a restart event (the driver's, once the row
is gone) starts a fresh round in place.

After the submit the entered row — eight white rings — holds T_CHECK
(200 ms: the device checks),
then the whole picture fades to black over T_OUT as one piece (no fill —
there is no hold to show): the entry ENDS EMPTY, and the verdict its digits
earned — the spec's `miss` or `match` screen dict (screens.spec(...)) —
plays in the SAME screen from t_exit, its own T_HOLD the black beat before
its sign. duration and t_resolve follow the tail (a tail-less submit
rests T_BLACK on black).

    screens.spec("pin_entering", pin="24031958")            # the demo dials it and rests (exit="rest")
    screens.spec("pin_entering", pin="00000000", typed="00000001", exit="submit",
                 miss=screens.spec("pin_mismatch", preset="wrong_pin"),
                 match=screens.spec("padlock", preset="unlock"))   # one try = one screen
    python3 -m screens pin_entering --pin 19580324
    python3 -m screens pin_entering --exit submit --at 9800
"""
import math

from pq1 import colors, components, motion, status, typography
from pq1.layout import CENTER_X, CHEV_LEFT, CHEV_RIGHT, CIRCLE_CY, CIRCLE_R
from pq1.motion import CHORD_MS, DOUBLE_TAP_MS, LEFT, RIGHT, clamp01, ease, ease_out
from pq1.procedural import marks, pin_slots

ANIM = "pin_entering"
SPEC = dict(pin="24031958", typed=None, exit="rest", busy="ENTER PIN",
            bottom="PIN ENTERED", miss=None, match=None, labels=None,
            done_labels=None)
DIGITS = 8
EXITS = ("rest", "submit")

# timeline (ms)
T_FADE, T_TEXT = 500, 300
T_UI = T_FADE                 # captions start with the rings settled
T_SETTLE = 600                # beat after the ui lands, before typing
STEP_TICK = 260               # per +1 tick while dialing a digit
STEP_SETTLE = 420             # pause on the digit, before the commit
STEP_ADV = 240                # commit + cursor advance
REST_MS = 2600                # exit="rest": rest on "PIN ENTERED" (the source loop tail)
ACT_MS = 400                  # idle -> active ring ease + 3 px lift
BOUNCE_MS = 220               # per-tick micro-bounce
CHEV_STAGGER = 250            # chevrons trail the instruction labels
SWAP_MS = status.BUSY_FADE_MS  # a caption / label swap: out, then in
T_CHECK = 200                 # the 8th ENTER: the PIN is checked directly — the row
                              # holds this beat, then leaves (user request, Sep 2026)
T_OUT = T_FADE                # the row leaves: rings, labels, chevrons fade to black
T_BLACK = 400                 # a tail-less submit rests on black this long

# instruction labels pulse: each hint 3 s on (fading in and out), 3 s off,
# then the next (user request, Sep 2026)
L_SHOW, L_FADE, L_GAP = 2000, 500, 3000
L_SLOT = L_SHOW + L_FADE * 2 + L_GAP
PAIRS = (("−", "+"), ("ENTER (BOTH)",),      # a 1-tuple is centred between the chevrons
         ("BACK (2X)", "NEXT (2X)"))
DONE_PAIR = ()                # the 8th digit entered: no hint — the PIN is being checked
                              # (user request, Sep 2026: no BACK, then no CONFIRM)

# labels keep the source's 8.8 px chevron-to-label gap, measured off the
# pq1 corner slots (chevron half-width 4.2). The caps labels wear the
# LABEL size (16 — the band-edge annotation size the pager wears too),
# centred on the chevron line by their measured ink box; the − / + signs
# are MARKS (procedural.marks.minus / plus — typed signs were too thin to
# read on glass; user request, Sep 2026) on the chevron line, their arm
# span SIGN_R * 0.6, a lighter stroke than the x mark's and a wider gap
# to the chevron (user request, Sep 2026)
LBL_GAP = 8.8
LBL_L = CHEV_LEFT[0] + 4.2 + LBL_GAP
LBL_R = CHEV_RIGHT[0] - 4.2 - LBL_GAP
LBL_LS = 0.5
LBL_SIZE = typography.SIZE_LABEL     # ENTER (BOTH), BACK (2X), NEXT (2X), …
SIGN_R = 19.0                        # − / + : arm span 11.4 (the caps' height)
SIGN_STROKE = 0.11                   # ... on a 2.1 px stroke (the x mark's is 3)
SIGN_GAP = 22.0                      # ... this far from the chevron's edge
SIGNS = {"−": marks.minus, "-": marks.minus, "+": marks.plus}


def script(typed, submit):
    """the demo's event log for `typed`: per digit, the ticks at the dial
    pace, the commit, the advance; with submit, the 8th enter submits"""
    ev, t = [], T_UI + T_TEXT + T_SETTLE
    for ch in typed:
        d = int(ch)
        for k in range(1, d + 1):
            ev.append((t + k * STEP_TICK, "tick", 1))
        t_adv = t + STEP_TICK * d + STEP_SETTLE
        ev.append((t_adv, "enter", None))
        t = t_adv + STEP_ADV
    if submit:
        ev.append((t - STEP_ADV, "submit", None))
    return ev


def entry_state(t, events, digits=DIGITS):
    """the row at time t, replayed from the events up to t -> dict:
    t0 (the round's start), values (every slot's digit — the dial is
    LIVE in its slot: moving the cursor never takes one away), touched
    (slots dialed at least once — a fresh slot's dial shows in its grey
    ring), n (the entered slots — always a prefix), cursor (the active
    slot; == digits once the row is done), draft (the active slot's dial
    — values[cursor]), shown (the digit the active ring displays — a live
    tap's value lands a beat after the tap, so a converted tap never
    shows), bump (the last dial / enter / move — the bounce), done (all
    entered and the cursor past the row — PIN ENTERED; a live row is
    submitted on that 8th enter),
    t_swap (when done last changed — the caption / label swap), hold
    ((side, t_press, t_release | None) or None), submit, t_exit, cancel.
    A restart event opens a fresh round at its time; after a cancel only
    a restart lands (the row is leaving)"""
    st = _round(0.0)
    pending = []            # live taps whose digit has not landed: (t_land, arg)
    for te, kind, arg in events:
        if te > t or st["submit"] is not None:
            break
        if kind == "restart":
            st, pending = _round(te), []
            continue
        if st["cancel"] is not None:
            continue
        was, c = st["done"], st["cursor"]
        if kind in ("tick", "tap"):
            if c < digits:
                st["values"][c] = st["draft"] = (st["draft"] + arg) % 10
                st["touched"][c] = True
                st["bump"] = te
                if kind == "tap":       # lands once no double press can take it back
                    can_move = c < st["n"] if arg > 0 else c > 0
                    pending.append((te + (DOUBLE_TAP_MS if can_move else CHORD_MS), arg))
        elif kind == "enter":
            if c < digits:
                st["touched"][c] = True
                st["n"] = max(st["n"], c + 1)
                _move(st, c + 1, te, digits)
        elif kind == "next":
            if c < st["n"]:             # forward only over entered digits
                _move(st, c + 1, te, digits)
        elif kind == "back":
            if c > 0:
                _move(st, c - 1, te, digits)
        elif kind == "hold":
            st["hold"] = (arg, te, None)
        elif kind == "release":
            h = st["hold"]
            if h is not None and h[2] is None:
                st["hold"] = (h[0], h[1], te)
        elif kind == "submit":
            if st["done"]:
                st["submit"], st["t_exit"] = te, te + T_CHECK + T_OUT
        elif kind == "cancel":
            if not st["done"]:          # a done row only confirms
                st["cancel"] = te
        if kind not in ("tick", "tap", "hold", "release"):
            pending = []        # an enter / move lands whatever was pending
        st["done"] = st["n"] == digits and st["cursor"] == digits
        if st["done"] != was:
            st["t_swap"] = te
    late = sum(arg for t_land, arg in pending if t_land > t)
    st["shown"] = (st["draft"] - late) % 10
    return st


def _move(st, to, te, digits):
    """the cursor lands on slot `to`, its dial the slot's digit — nothing
    is taken away from the slot it leaves"""
    st["cursor"] = to
    st["draft"] = st["values"][to] if to < digits else 0
    st["bump"] = te


def _round(t0, digits=DIGITS):
    """an empty row opening at t0"""
    return dict(t0=t0, values=[0] * digits, touched=[False] * digits, n=0,
                cursor=0, draft=0, shown=0, bump=-1e9, done=False, t_swap=None,
                hold=None, submit=None, t_exit=None, cancel=None)


def seg_alpha(p):
    """label alpha in one rotation slot: fade in, hold, fade out, gap"""
    if p < 0:
        return 0.0
    if p < L_FADE:
        return ease_out(p / L_FADE)
    if p < L_FADE + L_SHOW:
        return 1.0
    if p < L_FADE + L_SHOW + L_FADE:
        return 1 - ease_out((p - L_FADE - L_SHOW) / L_FADE)
    return 0.0


_LIFT = {}


def _ink_lift(s, size):
    """baseline offset (px) that centres the string's ink box on a line —
    caps and the − / + symbols alike, measured once per (string, size)"""
    key = (s, size)
    if key not in _LIFT:
        from pq1.layout import SUP
        x0, y0, x1, y1 = typography.font(size).getbbox(s, anchor="ls")
        _LIFT[key] = -(y0 + y1) / 2 / SUP
    return _LIFT[key]


def swap(t, t_swap):
    """(old, new) alphas of a sequential swap at t_swap: the old fades out
    over SWAP_MS, then the new fades in"""
    if t_swap is None:
        return 1.0, 0.0
    return (1 - ease_out(clamp01((t - t_swap) / SWAP_MS)),
            ease_out(clamp01((t - t_swap - SWAP_MS) / SWAP_MS)))


class PinEntering(status.StatusAnim):
    interactive = True          # the driver types into it (DESIGN.md § Input)
    rests_on_token = False      # the row owns the canvas: Sim fades it out

    def __init__(self, spec):
        super().__init__(spec)
        self.pin = self._digits(spec.get("pin", SPEC["pin"]), "pin")
        typed = spec.get("typed")
        self.typed = self.pin if typed is None else self._digits(typed, "typed")
        self.exit = spec.get("exit", "rest")
        if self.exit not in EXITS:
            raise ValueError(f"pin_entering exit is one of {', '.join(EXITS)}; "
                             f"got {self.exit!r}")
        self.labels = tuple(tuple(p) for p in (spec.get("labels") or PAIRS))
        self.done_labels = tuple(spec.get("done_labels") or DONE_PAIR)
        self.live = bool(spec.get("live"))
        self.events = [] if self.live else script(self.typed, self.exit == "submit")
        self.tail = None
        self.t_busy = None          # the captions are drawn per round below
        if not self.live:
            self._settle_tail()

    @staticmethod
    def _digits(v, field):
        s = "".join(c for c in str(v) if c.isdigit())
        if len(s) != DIGITS:
            raise ValueError(f"pin_entering {field} needs exactly {DIGITS} "
                             f"digits, got {v!r}")
        return s

    # ------------------------------------------------------- the outcome --
    @property
    def final(self):
        """the row after every event"""
        return entry_state(float("inf"), self.events)

    @property
    def outcome(self):
        """None while the entry is open; "match" / "miss" once submitted,
        "cancel" once cancelled (until a restart opens a fresh round)"""
        st = self.final
        if st["submit"] is not None:
            return "match" if "".join(map(str, st["values"])) == self.pin else "miss"
        if st["cancel"] is not None:
            return "cancel"
        return None

    def _settle_tail(self):
        """build the verdict the outcome earned (spec miss / match)"""
        oc = self.outcome
        tail = self.spec.get(oc) if oc in ("match", "miss") else None
        self.tail = (status.anim_for(dict(tail, handoff=False))
                     if tail else None)

    @property
    def t_done(self):
        """when the row was last done — the 8th digit entered (None until then)"""
        st = self.final
        return st["t_swap"] if st["done"] else None

    @property
    def t_exit(self):
        return self.final["t_exit"]

    @property
    def t_resolve(self):
        st = self.final
        if st["submit"] is not None:
            return st["t_exit"] + (self.tail.t_resolve if self.tail else 0)
        return self.t_done if self.t_done is not None else float("inf")

    @property
    def duration(self):
        st = self.final
        if st["submit"] is not None:
            return st["t_exit"] + (self.tail.duration if self.tail else T_BLACK)
        if st["cancel"] is not None:
            return st["cancel"] + T_OUT
        if not self.live and self.t_done is not None:
            return self.t_done + STEP_ADV + REST_MS   # the source's loop tail
        return float("inf")

    @property
    def previews(self):
        td = self.t_done
        if td is None:
            return (T_UI + T_TEXT + T_SETTLE, T_UI + T_TEXT + T_SETTLE)
        st = self.final
        if st["submit"] is not None and self.tail:
            return (td // 2, st["t_exit"] + self.tail.previews[1])
        return (td // 2, min(self.duration - 600, td + 800))

    def finished(self, t):
        return t >= self.duration

    # ---------------------------------------------------- the live input --
    def input(self, kind, t, arg=None):
        """append one gesture (anim time — the driver's now - idle_since):
        tap ±1 (a live button: the digit lands a beat later) / tick ±1 (at
        once — the demo) / enter (both buttons) / next / back (the double
        press) / hold side / release / submit / cancel / restart (a fresh
        round after a cancel)"""
        self.events.append((t, kind, arg))
        if kind in ("submit", "cancel", "restart"):
            self._settle_tail()

    def undo_last_tick(self):
        """a conversion (a chord, a double press): the last tap — its
        digit not yet landed — is undone"""
        for i in range(len(self.events) - 1, -1, -1):
            if self.events[i][1] in ("tap", "tick"):
                del self.events[i]
                return True
            if self.events[i][1] not in ("hold", "release"):
                return False
        return False

    def state(self, t):
        return entry_state(t, self.events)

    def complete(self, t):
        """all eight entered and the cursor past the row: the PIN is checked"""
        return self.state(t)["done"]

    def can_move(self, side, t):
        """would a double press on `side` move the cursor now? right: only
        forward over entered digits; left: back off the first slot"""
        st = self.state(t)
        return st["cursor"] < st["n"] if side == RIGHT else st["cursor"] > 0

    def digits(self, t):
        st = self.state(t)
        return "".join(map(str, st["values"][:st["n"]]))

    # ------------------------------------------------------------ drawing --
    def draw_handoff(self, cv, t):
        """flow splicing: the incoming resting token crossfades out under
        the ring fade (spec handoff=True — the verdict idiom)"""
        if not self.spec.get("handoff"):
            return
        k = ease_out(clamp01(t / T_FADE))
        if k >= 1.0:
            return
        components.token_from_spec(cv, CENTER_X, CIRCLE_CY, CIRCLE_R,
                                   self.spec, glyph_a=self.style["icon"])
        if k > 0.003:
            cv.circle(CENTER_X, CIRCLE_CY, CIRCLE_R + 2.5,
                      (*colors.BLACK, int(round(255 * k))))

    def _pair(self, cv, pair, a):
        """a hint: a 1-tuple centred between the chevrons, a pair beside
        them (an empty side draws nothing)"""
        if len(pair) == 1:
            self._label(cv, pair[0], a, "center")
        else:
            self._label(cv, pair[0], a, "left")
            self._label(cv, pair[1], a, "right")

    def _label(self, cv, s, a, side):
        if a <= 0.01 or not s:
            return
        col = colors.scale(colors.WHITE, 0.8)
        if s in SIGNS:                       # the − / + marks
            w = 0.6 * SIGN_R
            x = (CHEV_LEFT[0] + 4.2 + SIGN_GAP + w / 2 if side == "left"
                 else CHEV_RIGHT[0] - 4.2 - SIGN_GAP - w / 2)
            SIGNS[s](cv, x, CHEV_LEFT[1], SIGN_R, a, color=col,
                     stroke=SIGN_STROKE)
            return
        w = typography.text_width(s, LBL_SIZE) + LBL_LS * (len(s) - 1)
        x = (LBL_L + w / 2 if side == "left" else LBL_R - w / 2
             if side == "right" else CENTER_X)
        cv.text(s, x, CHEV_LEFT[1] + _ink_lift(s, LBL_SIZE), LBL_SIZE, a,
                ls=LBL_LS, color=col, baseline=True)

    def _fill(self, st, t):
        """(level, presence) of the hold liquid in the rings — the left
        hold's (cancel) progress while the row is open; the right hold is
        unbound on an entry (the 8th ENTER submits), so a done row never
        fills"""
        h = st["hold"]
        if h is None or st["done"] or st["submit"] is not None:
            return 0.0, 1.0
        side, t0, t_rel = h
        if side == RIGHT:
            return 0.0, 1.0
        return motion.hold_fill(t - t0, None if t_rel is None else t_rel - t0), 1.0

    def draw(self, cv, t):
        self.draw_handoff(cv, t)
        st = entry_state(t, self.events)
        if st["submit"] is not None and t >= st["t_exit"]:
            if self.tail is not None:
                self.tail.draw(cv, t - st["t_exit"])
            return
        tr = t - st["t0"]
        # the row's own alpha: in on the round's fade, out after a submit's
        # check beat or at once on a cancel — the whole picture, captions
        # and liquid included, leaves as one
        exit_a = 1.0
        if st["submit"] is not None:
            exit_a = 1 - ease_out(clamp01((t - st["submit"] - T_CHECK) / T_OUT))
        elif st["cancel"] is not None:
            exit_a = 1 - ease_out(clamp01((t - st["cancel"]) / T_OUT))
        row_a = ease(clamp01(tr / T_FADE)) * exit_a
        act_a = ease(clamp01((tr - T_UI) / ACT_MS))
        cursor, n = st["cursor"], st["n"]
        fill, fill_a = self._fill(st, t)
        row = []
        for i in range(DIGITS):
            active = (i == cursor and cursor < DIGITS and tr > T_FADE
                      and st["submit"] is None)
            slot = dict(a=row_a, fill=fill, fill_a=fill_a)
            if active:
                slot["digit"] = st["shown"]
                slot["active"] = act_a
                slot["lift"] = 3.0 * act_a
                b = t - st["bump"]
                if 0 <= b < BOUNCE_MS:
                    slot["bounce"] = 2.5 * math.sin(math.pi * b / BOUNCE_MS)
            elif i < n:
                slot["digit"] = st["values"][i]
                slot["committed"] = True
            elif st["touched"][i]:       # dialed, not entered: pending in its grey ring
                slot["digit"] = st["values"][i]
            row.append(slot)
        pin_slots.draw(cv, slots=row)
        self.draw_row(cv, t, st, tr, row_a)
        self.draw_captions(cv, t, st, tr, exit_a)

    def draw_row(self, cv, t, st, tr, row_a):
        """the corner chevrons and the instruction labels, every hint on the
        same pulse (3 s on, 3 s off): the rotating hints while a slot is
        active; once the row is done the rotation fades out and no hint
        follows (spec `done_labels` can name one — it pulses in after the
        sequential swap)"""
        ui_a = ease_out(clamp01((tr - T_UI) / T_TEXT)) * row_a
        if ui_a <= 0.01:
            return
        chev_a = ease_out(clamp01((tr - T_UI - CHEV_STAGGER) / T_TEXT)) * row_a
        components.chevron_pair(cv, *components.chevron_angles("lr"),
                                alpha=chev_a)
        a_old, a_new = swap(t, st["t_swap"])
        a_rot = 1.0 if st["t_swap"] is None else a_old if st["done"] else a_new
        if a_rot > 0.01:                # the 8th entry: the hints leave at once
            ph = (tr - T_UI) % (L_SLOT * len(self.labels))
            slot = int(ph // L_SLOT)
            self._pair(cv, self.labels[slot],
                       seg_alpha(ph - slot * L_SLOT) * ui_a * a_rot)
        if st["done"] and self.done_labels and st["submit"] is None:
            p = t - st["t_swap"] - SWAP_MS      # its fade-in is the swap's "in"
            if p > 0:
                self._pair(cv, self.done_labels, seg_alpha(p % L_SLOT) * ui_a)

    def draw_captions(self, cv, t, st, tr, exit_a):
        """ENTER PIN while a slot is active, PIN ENTERED once the row is
        done (the sequential swap either way) — except on a submit: the PIN
        is checked at once, so ENTER PIN stays and leaves with the row (a
        PIN ENTERED could not land inside T_CHECK); both leave with the row"""
        ui_a = ease_out(clamp01((tr - T_UI) / T_TEXT)) * exit_a
        a_old, a_new = swap(t, st["t_swap"])
        if st["t_swap"] is None or st["submit"] is not None:
            a_busy, a_done = 1.0, 0.0
        elif st["done"]:
            a_busy, a_done = a_old, a_new
        else:
            a_busy, a_done = a_new, a_old
        busy = self.style["busy"]
        if busy and a_busy * ui_a > 0.01:
            components.caption(cv, busy, a_busy * ui_a)
        self.draw_caption(cv, a_done * ui_a)


def add_args(ap):
    ap.add_argument("--pin", default=None, help="the PIN the device accepts (8 digits)")
    ap.add_argument("--typed", default=None,
                    help="the 8 digits the demo dials (default: the PIN)")
    ap.add_argument("--exit", default=None, choices=EXITS,
                    help='"rest" (dial, then PIN ENTERED) or "submit" '
                         "(dial; the 8th digit submits, the row fades out)")


def spec_from_args(args):
    d = {}
    if args.pin is not None:
        d["pin"] = args.pin
    if args.typed is not None:
        d["typed"] = args.typed
    if args.exit is not None:
        d["exit"] = args.exit
    return d


status.register(ANIM, PinEntering)
