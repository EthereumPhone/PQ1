"""Check word — pick the backup word asked for, out of nine.

Port of reference/device/pq1_check_word.py onto the design system (audit
HS-09): the seed's word n is shown among eight decoys, a 3 x 3 grid of
candidates — three columns measured from their widest word and spaced
evenly across the width (outer margins = the gaps, so the block centres on
the caption's axis), row centre lines ROW_Y, stepping down column 1, then
2, then 3 — the words at the words grid's one size
(layout.WORDS_SIZE, 22 Regular, white), CHECK WORD n the caption on the
y 128 baseline. The selection is the system chevron (components.chevron,
pointing right, CHEVRON_DX left of the selected word's edge); it GLIDES to
the next word on a tap (GLIDE_MS, ease_out). No corner chevrons: the
selector stands where the left one would.

The entry grammar (DESIGN.md § Input): a right tap selects the next word,
a left tap the previous one — clamped at the ends, like the reference —
BOTH buttons choose the selected word, and the choice is checked at once
(the PIN's 8th ENTER). A left hold cancels while the grid is open. There
is no double press: a fast run of taps always steps. A live tap moves the
chevron a chord window later (motion.CHORD_MS), so the first half of a
chord never flashes a step it takes back.

After the choice the grid holds T_CHECK (the device checks), fades out
over T_OUT, and the verdict the choice earned — the spec's `match` or
`miss` screen dict — plays in the SAME screen (the PIN attempt's idiom,
screens/pin/pin_entering.py). The demo (not live) steps to `typed` — an
index into the candidates, default the right word — and chooses it.

    screens.spec("check_word", n=5, words=SEED, match=None,
                 miss=screens.spec("headshake", preset="wrong_seed_phrase"))
    python3 -m screens check_word --n 5 --typed 0
"""
from pq1 import colors, components, status
from pq1.layout import W, WORDS_SIZE
from pq1.motion import CHORD_MS, clamp01, ease_out
from pq1.typography import text_width

from .pin_entering import BOUNCE_MS, T_BLACK, T_CHECK, T_FADE, T_OUT   # one entry clock

ANIM = "check_word"

# the reference's sample list — placeholders; the device's seed is the user's
DEFAULT_WORDS = (
    "close", "agent", "own", "deputy", "grape", "though", "sail", "simple",
    "ribbon", "cactus", "noble", "violet", "ember", "lucky", "orbit", "pencil",
    "tundra", "mimic", "gravel", "spice", "fetch", "cabin", "motor", "dawn",
)
SPEC = dict(n=5, words=None, candidates=None, typed=None, exit="submit",
            busy=None, miss=None, match=None)

COLS = 3               # word columns, laid out by columns()
ROW_Y = (27, 55, 83)    # row centre lines (reference)
CHOICES = COLS * len(ROW_Y)
CHEVRON_DX = 15         # the selector's centre, left of the word's edge (reference)
SELECT_ANG = components.chevron_angles("lr")[1]   # pointing right, at the word

# timeline (ms) — the PIN entry's pace
T_TEXT = 300            # the caption after the grid
T_SETTLE = 600          # a beat before the demo steps
STEP_MS = 420           # the demo's step, one word per
STEP_SETTLE = 600       # the demo rests on its choice, then chooses
GLIDE_MS = BOUNCE_MS    # the selector's glide: the PIN ring's per-tick bounce


def candidates(words, n):
    """the right word + 8 decoys, deterministically shuffled — the
    reference's own algorithm, so a port lands the same order"""
    w = list(words)
    out = [w[(n - 1) % len(w)]]
    i = 0
    while len(out) < CHOICES and i < len(w):
        c = w[(n + 2 + i * 3) % len(w)]
        if c not in out:
            out.append(c)
        i += 1
    # the reference's stride of 3 never closes on a list whose length 3
    # divides (a 24-word seed: 8 decoys at most) — fill from the list in
    # order; the reference's own 32-word sample never reaches this
    for c in w:
        if len(out) >= CHOICES:
            break
        if c not in out:
            out.append(c)
    seed = (n * 2654435761) & 0xFFFFFFFF
    for i in range(len(out) - 1, 0, -1):
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        j = seed % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def columns(cands):
    """the column left edges: each column as wide as its widest word, the
    four spaces (two margins, two gaps) equal — the block centred on W/2"""
    rows = len(ROW_Y)
    widths = [max(text_width(w, WORDS_SIZE) for w in cands[c * rows:(c + 1) * rows])
              for c in range(COLS)]
    gap = (W - sum(widths)) / (COLS + 1)
    if gap < CHEVRON_DX + 8:    # the selector stands in the gap
        raise ValueError(f"check_word candidates too wide for the grid ({widths})")
    xs, x = [], gap
    for w in widths:
        xs.append(round(x))
        x += w + gap
    return tuple(xs)


def slot_xy(k, col_x):
    """the left edge and centre line of candidate k (down column 1 first)"""
    return col_x[k // len(ROW_Y)], ROW_Y[k % len(ROW_Y)]


def script(typed, submit=True):
    """the demo's event log: step to candidate `typed`, rest, choose"""
    t = T_FADE + T_TEXT + T_SETTLE
    ev = [(t + STEP_MS * (k + 1), "tick", 1) for k in range(typed)]
    t_enter = t + STEP_MS * typed + STEP_SETTLE
    ev.append((t_enter, "enter", None))
    if submit:
        ev.append((t_enter, "submit", None))
    return ev


def entry_state(t, events):
    """the grid at time t, replayed from the events up to t -> dict: t0
    (the round's start), sel (the selection), shown (where the chevron
    stands — a live tap lands CHORD_MS later), moved ((t, from) of the
    last landed move — the glide), entered, submit, t_exit, cancel, hold"""
    st = _round(0.0)
    pending = []
    for te, kind, arg in events:
        if te > t or st["submit"] is not None:
            break
        if kind == "restart":
            st, pending = _round(te), []
            continue
        if st["cancel"] is not None:
            continue
        if kind in ("tick", "tap"):
            if not st["entered"]:
                new = max(0, min(CHOICES - 1, st["sel"] + arg))
                if new != st["sel"]:
                    t_land = te + (CHORD_MS if kind == "tap" else 0)
                    pending.append((t_land, st["sel"], new))
                    st["sel"] = new
        elif kind == "enter":
            st["entered"] = True
            pending = [(te, a, b) for _, a, b in pending]   # lands at once
        elif kind == "submit":
            if st["entered"]:
                st["submit"], st["t_exit"] = te, te + T_CHECK + T_OUT
        elif kind == "hold":
            st["hold"] = (arg, te, None)
        elif kind == "release":
            h = st["hold"]
            if h is not None and h[2] is None:
                st["hold"] = (h[0], h[1], te)
        elif kind == "cancel":
            if not st["entered"]:
                st["cancel"] = te
    # the chevron stands on the last LANDED move; a live tap still inside
    # its chord window keeps it where it stood
    landed = [p for p in pending if p[0] <= t]
    if landed:
        t_land, frm, to = landed[-1]
        st["shown"], st["moved"] = to, (t_land, frm)
    elif pending:
        st["shown"] = pending[0][1]
    else:
        st["shown"] = st["sel"]
    return st


def _round(t0):
    return dict(t0=t0, sel=0, shown=0, moved=None, entered=False,
                submit=None, t_exit=None, cancel=None, hold=None)


class CheckWord(status.StatusAnim):
    interactive = True          # the driver types into it (DESIGN.md § Input)
    rests_on_token = False      # the grid owns the canvas: Sim fades it out

    def __init__(self, spec):
        super().__init__(spec)
        self.n = int(spec.get("n", SPEC["n"]))
        words = spec.get("words") or DEFAULT_WORDS
        self.answer = str(words[(self.n - 1) % len(words)])
        self.cands = [str(w) for w in (spec.get("candidates")
                                       or candidates(words, self.n))]
        if len(self.cands) != CHOICES or self.answer not in self.cands:
            raise ValueError(f"check_word needs {CHOICES} candidates holding "
                             f"word {self.n} ({self.answer!r})")
        self.col_x = columns(self.cands)
        typed = spec.get("typed")
        self.typed = self.cands.index(self.answer) if typed is None else int(typed)
        if not 0 <= self.typed < CHOICES:
            raise ValueError(f"check_word typed is a candidate index 0-{CHOICES - 1}")
        self.caption_text = spec.get("busy") or f"CHECK WORD {self.n}"
        self.live = bool(spec.get("live"))
        self.events = [] if self.live else script(self.typed)
        self.tail = None
        if not self.live:
            self._settle_tail()

    # ------------------------------------------------------- the outcome --
    @property
    def final(self):
        return entry_state(float("inf"), self.events)

    @property
    def outcome(self):
        st = self.final
        if st["submit"] is not None:
            return "match" if self.cands[st["sel"]] == self.answer else "miss"
        if st["cancel"] is not None:
            return "cancel"
        return None

    def _settle_tail(self):
        oc = self.outcome
        tail = self.spec.get(oc) if oc in ("match", "miss") else None
        self.tail = status.anim_for(dict(tail, handoff=False)) if tail else None

    @property
    def t_resolve(self):
        st = self.final
        if st["submit"] is not None:
            return st["t_exit"] + (self.tail.t_resolve if self.tail else 0)
        return float("inf")

    @property
    def duration(self):
        st = self.final
        if st["submit"] is not None:
            return st["t_exit"] + (self.tail.duration if self.tail else T_BLACK)
        if st["cancel"] is not None:
            return st["cancel"] + T_OUT
        return float("inf")

    @property
    def previews(self):
        st = self.final
        if st["submit"] is not None:
            t_sub = st["submit"]
            return (t_sub - STEP_SETTLE // 2,
                    st["t_exit"] + self.tail.previews[1] if self.tail else t_sub)
        return (T_FADE + T_TEXT + T_SETTLE,) * 2

    def finished(self, t):
        return t >= self.duration

    # ---------------------------------------------------- the live input --
    def input(self, kind, t, arg=None):
        self.events.append((t, kind, arg))
        if kind in ("submit", "cancel", "restart"):
            self._settle_tail()

    def undo_last_tick(self):
        """a chord's first half: its tap is taken back before it lands"""
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
        """a word was chosen: it is checked at once"""
        return self.state(t)["entered"]

    def can_move(self, side, t):
        return False            # no double press: every tap steps

    def digits(self, t):
        """the bench status line's reading: the selected word"""
        return self.cands[self.state(t)["sel"]]

    # ------------------------------------------------------------ drawing --
    def draw(self, cv, t):
        status.draw_handoff(cv, self.spec, self.style, t, T_FADE)
        st = entry_state(t, self.events)
        if st["submit"] is not None and t >= st["t_exit"]:
            if self.tail is not None:
                self.tail.draw(cv, t - st["t_exit"])
            return
        tr = t - st["t0"]
        exit_a = 1.0
        if st["submit"] is not None:
            exit_a = 1 - ease_out(clamp01((t - st["submit"] - T_CHECK) / T_OUT))
        elif st["cancel"] is not None:
            exit_a = 1 - ease_out(clamp01((t - st["cancel"]) / T_OUT))
        grid_a = ease_out(clamp01(tr / T_FADE)) * exit_a
        if grid_a > colors.ALPHA_FLOOR:
            for k, w in enumerate(self.cands):
                x, y = slot_xy(k, self.col_x)
                components.draw_text(cv, dict(str=w, y=y, size=WORDS_SIZE,
                                              x=x + text_width(w, WORDS_SIZE) / 2),
                                     grid_a)
            # the selector glides from the word it left (GLIDE_MS, ease_out)
            x, y = slot_xy(st["shown"], self.col_x)
            if st["moved"] is not None:
                t_m, frm = st["moved"]
                k = ease_out(clamp01((t - t_m) / GLIDE_MS))
                x0, y0 = slot_xy(frm, self.col_x)
                x, y = x0 + (x - x0) * k, y0 + (y - y0) * k
            # the selector stays through the cancel hold (§ Input: a hold
            # never fades a chevron)
            components.chevron(cv, x - CHEVRON_DX, y, SELECT_ANG, grid_a)
        cap_a = ease_out(clamp01((tr - T_FADE) / T_TEXT)) * exit_a
        if cap_a > colors.ALPHA_FLOOR:
            components.caption(cv, self.caption_text, cap_a)


def add_args(ap):
    ap.add_argument("--n", type=int, default=None, help="the word number asked for")
    ap.add_argument("--typed", type=int, default=None,
                    help="the candidate index the demo chooses (default: the right word)")


def spec_from_args(args):
    d = {}
    if args.n is not None:
        d["n"] = args.n
    if args.typed is not None:
        d["typed"] = args.typed
    return d


status.register(ANIM, CheckWord)
