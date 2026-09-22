"""PQ1 layout grid — the canonical geometry every screen respects.

Canvas
  428 x 142 landscape, 12 px margins, pure black, drawn at 3x supersample
  and LANCZOS-downscaled (the NV3007 driver handles rotation to the panel).

Grid
  main circle: diameter 60, vertical centre y 72, never resizes
  idle screens: circle centred x 214, sweep stays inside x 89-339
  info screens: circle column x 24-123 (left) or x 303-402 (right),
                circle centre x 74 / x 352, label baseline y 128
  detail text centred in the opposite region, vertical centre y 72.5
  value screens: no circle on the panel (parked off-canvas, x -60), the
                text centred x 214 across the full 404 px region
  chevrons: corner slots (x 23.5 / x 403.5, y 19), hidden on status screens
  bottom band y 105-129, all band text baseline-aligned to y 128

Screen description (dict / JSON object per screen)
--------------------------------------------------
Common
    "id"     : name used on the command line
    "kind"   : "hero" | "detail" | "value" | "confirm" | "status"
    "icon"   : "eth" | "base" | "blind" | "rotate"
               | "dev" | "fingerprint" | "download"  glyph inside the circle
                                                 (components.GLYPHS; a popular
                                                 token's logo art comes via
                                                 components.token_defaults)
    "icon_color": [r, g, b]                      vector-mark colour override
                                                 (image logos keep their art;
                                                 SAFE flows pin it black)
    "chev"   : "lr" | "up" | None                "lr" tap-nav available, "up"
                                                 hold armed, None = no input
    "dwell"  : ms held before auto-advancing     (optional; demo loops only —
                                                 the last HOLD_COMMIT_MS of a
                                                 commit screen's dwell is the
                                                 demo's own hold gesture)
    "next"   : 7 | "SIGNED"                      where the demo loop advances
                                                 after dwell (optional; default
                                                 the following screen). Index,
                                                 or a screen id resolved as the
                                                 first match scanning forward.
                                                 THE branch primitive: the
                                                 confirm screen's early exit
                                                 pins next to the ending
                                                 (flows --early)
    "sweep"  : True | False                      idle side-to-side sweep
                                                 (default: hero screens only)
    "commit" : True | False                      hold-right sign/submit armed
                                                 (optional; DESIGN.md § Input
                                                 — reference driver:
                                                 pq1/driver.py; device
                                                 firmware implements the
                                                 grammar natively; the demo
                                                 loop performs the hold —
                                                 the disc filling up — here
                                                 before a done ending)
    "token"  : {"variant": "solid" | "unknown",  (optional; default "solid")
                "fill": [r, g, b],               solid fill colour
                "ring": [r, g, b],               ring colour; an explicit
                                                 ring strokes INSIDE the disc
                                                 edge and draws over logo art
                "palette": 0-13 | "SYMBOL"       placeholder ramp pin: fill +
                           | "SAFE" | "COWSWAP", the five trail colours come
                                                 from colors.PLACEHOLDER_
                                                 GRADIENTS (13 = MONO_RAMP,
                                                 the recognized-logo look:
                                                 black body + white ring); a
                                                 brand name (colors.BRAND_
                                                 GRADIENTS, e.g. "SAFE") pins
                                                 that brand ramp instead
                "address": "0x…",                unknown-token identity: the
                "symbol": "XYZ"}                 gradient disc + trail take
                                                 the ramp hashed from address
                                                 (preferred) or symbol, so
                                                 the same token always wears
                                                 the same gradient
               "solid" is the normal treatment for a KNOWN token (and the
               default); "unknown" draws the gradient disc reserved for
               unrecognized tokens, coloured by components.token_ramp
               ("palette" -> "address" -> "symbol" -> "icon" -> neutral).

hero — circle centred x 214, question text on the y 128 baseline
    "bottom" : "SEND 5.25 ETH?"
    "hint"   : True                              chevrons bob up and back
    "pager"  : [2, 3]                            this hero's position in a
                                                 sequence of asks — the pager
                                                 "n/m" in the same top-centre
                                                 spot a paged detail uses
                                                 (12 px, 80 % white). A
                                                 batch's transactions
                                                 (flows/batch). NOT text
                                                 pages: nothing flips and the
                                                 dwell is untouched
    "band_chev": True                            the caption carries the
                                                 confirm band's right-
                                                 pointing chevron and the
                                                 corner chevrons hide (chev
                                                 defaults None) — the intro
                                                 ahead of an ask
                                                 (flows/erc7730); not an ask
                                                 itself, so "commit": False
    "commit" : True                              (default) hold-right signs on
                                                 every ask — opening or returning

confirm — the long-flow early exit (DESIGN.md § Flow shape: inserted as the
          6th screen when a flow has 7+ detail screens): the big prompt in
          the detail region, circle docked right of centre, and the band
          alternates "OR VIEW MORE" ▸ / ◂ "TO GO BACK" with a fade every
          5 s (components.confirm_band driven by motion.confirm_band);
          corner chevrons rest in the "up" (hold-armed) pose and point —
          the hero bob — on the same 5 s beat
    "bottom" : "Confirm?"                        (default) 36 px prompt
    "commit" : True                              (default) hold-right sign armed

detail — circle docked in a 100 px column, text centred in the other region
    "side"     : "left" | "right"
    "label"    : "MAX FEE"                       16 px SEMIBOLD caps, baseline y 128
    "lines"    : ["45.5 gwei", "Tip: 2 gwei"]    detail value, 1-3 lines; a
                                                 line is a str, or {"str": …,
                                                 "weight": "semibold"} — a
                                                 NAME inside the value (the
                                                 resolved contract / recipient
                                                 / spender identity) rides
                                                 SemiBold over its Regular
                                                 address lines (DESIGN.md
                                                 § Text rules, Names); or
                                                 {"transition": [old, new]}
                                                 — one value becoming
                                                 another on ONE row, a
                                                 right chevron between
                                                 them ("Slot 3 ▸ Slot 4",
                                                 § Text rules, Transitions)
    "size"     : 36 | 32 | 28 | 22               largest tier that fits
    "circle_x" : 291                             optional nudge off the column
    "text_x"   : 175                             optional nudge
    "pulse"    : True | [r, g, b]                pulsating rings around the
                                                 token (components.pulse;
                                                 True = token fill colour)
    "pages"    : [[line, line], [line, line]]    ONE value too long for its
                                                 tier's three lines — a full
                                                 32-byte hash — shown in
                                                 2+ pages of 1-3 lines at
                                                 the screen's one "size";
                                                 the pager "n/m" (12 px,
                                                 80 % white, top centre)
                                                 shows only then. The demo
                                                 turns a page per detail
                                                 dwell (motion.page_flip:
                                                 the page fades away
                                                 ease-out, the next fades
                                                 in ease); a right tap
                                                 turns the page before it
                                                 advances (DESIGN.md
                                                 § Input). "lines" is
                                                 filled with the first
                                                 page for single-page
                                                 readers

value — the value alone, full width: NO token on the panel — the circle
        LEAVES (parked off-canvas at VALUE_PARK_X: the position spring
        carries it off the left edge, the followers after it, and it
        comes back the same way for the next screen) and the text takes
        the whole 404 px region, centred on x 214 (DESIGN.md
        § Typography: the per-line budgets x 1.45); the corner chevrons
        stay for tap-nav, the pager as on a detail. A detail without the
        docked token — it counts as one for the Confirm? rule. The hash
        the user matches (flows/fingerprint)
    "lines"    : ["0x…", "…", "…"]               1-3 lines, as a detail's
    "pages"    : [[…], […]]                      as a detail's — the pager with them
    "size"     : 36 | 32 | 28 | 22               largest tier that fits the
                                                 full-width budgets
    "words"    : ["close", "agent", …]           a NUMBERED WORD GRID in
                                                 place of lines: up to 8
                                                 short words on the seed-
                                                 words grid — two columns
                                                 of four (WORDS_COLS: the
                                                 number right-aligned, the
                                                 word left-aligned beside
                                                 it), numbered 1-4 down the
                                                 left, 5-8 down the right,
                                                 rows on WORDS_ROWS, the
                                                 words white and the
                                                 numbers WORDS_NUM_ALPHA
                                                 grey, all at WORDS_SIZE
                                                 (22, Regular) — a
                                                 fingerprint read as words
                                                 (flows/firmware; the
                                                 design's pq1_seed_words)
    "label"    : "KEY FINGERPRINT"               with words only (optional):
                                                 a caps label centred on
                                                 the bottom baseline

status — animated loading, then the shared resting look: black token,
         state-coloured ring + result glyph, caption (see pq1/status.py);
         a "resting" override brands the ending (fill / ring / glyph)
    "bottom" : "TRANSACTION CONFIRMED"           the resolved caption
    "anim"   : "qubit"                           status animation (default by
                                                 outcome — "qubit" for done
                                                 endings, the film-less
                                                 "resolve" for cancels;
                                                 registry in status.py, the
                                                 screens package registers
                                                 more)
    "result" : "check" | "x" | None              resolve glyph (default "check")
    "state"  : "done" | "failed" | "warning" | "awaiting"
                                                 -> colors.STATE ring/glyph
                                                 colour (default "done")
    "color"  : [r, g, b]                         explicit colour, wins over state
                                                 (default: the resolve flash
                                                 pulses in a branded ending's
                                                 resting fill, else the state
                                                 colour)
    "resting": {"fill": [r,g,b],                 branded resting-look override:
                "ring": [r,g,b],                 disc fill, ring and result-
                "glyph": [r,g,b]}                glyph colours (defaults: black
                                                 disc, state ring/glyph); the
                                                 override strokes its ring
                                                 flush at the disc edge —
                                                 status.branded_resting(fill,
                                                 mark): SAFE SIGNED #13FF7F
                                                 disc, black ring + check;
                                                 COWSWAP SIGNED #65D9FF disc,
                                                 black ring + navy check; every
                                                 brand DECLINED the same
                                                 failed-red #FF423D disc,
                                                 black ring + X
    "busy"   : "SIGNING…"                        caption while loading (optional;
                                                 film only — the cancel resolve
                                                 has no loading window)
    dwell defaults to the animation's duration (qubit 8600 ms, the cancel
    resolve 2850 ms). Any extra
    fields ride along to the registered animation via its spec (the screens/
    library uses this for per-screen params like pin= or direction=).
"""
import copy

# ------------------------------------------------------------------ canvas --
W, H = 428, 142
SUP = 3                     # supersample factor; all APIs take UI pixels
MARGIN = 12

# -------------------------------------------------------------------- grid --
CENTER_X = 214
CIRCLE_CY = 72              # main circle vertical centre
CIRCLE_R = 30               # diameter 60, never resizes
TEXT_CY = 72.5              # vertical centre of detail text blocks

SWEEP_X_MIN, SWEEP_X_MAX = 89, 339

COL_LEFT = (24, 123)        # detail circle column, left
COL_RIGHT = (303, 402)      # detail circle column, right
COL_LEFT_CX = 74
COL_RIGHT_CX = 352
DETAIL_TEXT_CX = {"left": 263, "right": 163}   # text centre opposite the circle

BAND_TOP, BAND_BOTTOM = 105, 129
BASELINE_Y = 128            # all bottom-band text baselines

CHEV_LEFT = (23.5, 19.0)    # corner chevron slots
CHEV_RIGHT = (403.5, 19.0)

# ------------------------------------------------------------- flow shape --
# DESIGN.md § Flow shape: a flow with CONFIRM_MIN_DETAILS or more detail
# screens takes a confirm-kind screen at CONFIRM_INDEX — the 6th screen,
# an early exit ahead of the remaining details (insert_confirm).
CONFIRM_MIN_DETAILS = 7
CONFIRM_INDEX = 5

CONFIRM_CIRCLE_X = 291      # confirm circle right of centre ...
CONFIRM_TEXT_X = 175        # ... prompt centred to its left (the CHAIN nudges)

VALUE_TEXT_CX = CENTER_X    # a value screen's text: the full region, centred ...
VALUE_PARK_X = -2 * CIRCLE_R   # ... its token parked off the panel to the left

# a words value (the seed-words grid of the design canvas,
# reference/device/pq1_seed_words.py): two columns of four numbered words — the
# number right-aligned so digits line up, the word left-aligned beside it
# — numbered down the left column, then the right (user request, Sep 2026:
# the words and numbers a tier up from the design's 16 px)
WORDS_ROWS = (32, 58, 84, 110)         # row centre lines
WORDS_COLS = ((88, 98), (272, 282))    # (number right edge, word left edge) per column
WORDS_SIZE = 22                        # the words' and numbers' one size: the Default tier
WORDS_NUM_ALPHA = 0.5                  # the numbers' grey (the design's ~50 % GRAY)
WORDS_MAX = len(WORDS_COLS) * len(WORDS_ROWS)
                               # (disc and trail clear the edge at rest)


def line_height(size):
    """PQ1 stacking rule for multi-line detail text"""
    return size if size >= 32 else size + 8


def line_str(ln):
    """the text of one detail line — a str, a {"str", "weight"} dict, or a
    {"transition": [old, new]} row (read as "old ▸ new")"""
    if isinstance(ln, dict):
        return " ▸ ".join(ln["transition"]) if "transition" in ln else ln["str"]
    return ln


def line_weight(ln):
    """a detail line's face: "regular", or "semibold" for a NAME inside the
    value (DESIGN.md § Text rules, Names — the identity rides SemiBold over
    its Regular address lines; layout_of hands it to typography.font)"""
    return ln.get("weight", "regular") if isinstance(ln, dict) else "regular"


def _value_texts(lines, tx, size):
    """the text specs of one detail value: 1-3 lines stacked on
    line_height about TEXT_CY, centred on tx"""
    lh = line_height(size)
    n = len(lines)
    out = []
    for i, ln in enumerate(lines):
        y = TEXT_CY - (n - 1) * lh / 2 + i * lh
        t = dict(str=line_str(ln), x=tx, y=y, size=size, weight=line_weight(ln))
        if isinstance(ln, dict) and "transition" in ln:
            t["transition"] = list(ln["transition"])   # components.draw_text lays out the row
        out.append(t)
    return out


def _words_texts(words):
    """the text specs of a numbered word grid: word k in column k // 4,
    row k % 4 — its number (k + 1, grey) right-aligned at the column's
    number edge, the word (white) left-aligned at its word edge (cv.text
    centres on x, so each anchor is the edge plus or minus half the width)"""
    from . import colors, typography   # lazy: typography imports SUP from here
    rows, out = len(WORDS_ROWS), []
    grey = colors.scale(colors.WHITE, WORDS_NUM_ALPHA)
    for k, w in enumerate(words):
        num_x, word_x = WORDS_COLS[k // rows]
        y, n = WORDS_ROWS[k % rows], str(k + 1)
        out.append(dict(str=n, x=num_x - typography.text_width(n, WORDS_SIZE) / 2,
                        y=y, size=WORDS_SIZE, color=grey))
        out.append(dict(str=w, x=word_x + typography.text_width(w, WORDS_SIZE) / 2,
                        y=y, size=WORDS_SIZE))
    return out


def layout_of(s):
    """PQ1 grid positions for one screen description; a paged detail
    (DESIGN.md § Text rules, Pages) carries "pages" — one text list per
    page — and "fixed" (the label) beside "texts" (label + first page)"""
    if s["kind"] == "status":
        return dict(circle=dict(cx=CENTER_X, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                    texts=[], chev=s["chev"])
    if s["kind"] == "hero":
        out = dict(circle=dict(cx=CENTER_X, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                   texts=[dict(str=s["bottom"], x=CENTER_X, y=BASELINE_Y,
                               size=18, ls=0.5, base=True,
                               band_chev=bool(s.get("band_chev")))],
                   chev=s["chev"])
        if s.get("pager"):
            # position in a sequence, not text pages — Sim draws it under the
            # screen's own alpha and never turns it (flow.Sim.draw)
            out["pager"] = tuple(s["pager"])
        return out
    if s["kind"] == "confirm":
        return dict(circle=dict(cx=CONFIRM_CIRCLE_X, cy=CIRCLE_CY, r=CIRCLE_R,
                                icon=s["icon"]),
                    texts=[dict(str=s["bottom"], x=CONFIRM_TEXT_X, y=TEXT_CY,
                                size=36)],
                    chev=s["chev"])
    if s["kind"] == "value":
        # full width: the token leaves the panel, the value takes the region
        cx, tx, texts = VALUE_PARK_X, VALUE_TEXT_CX, []
        if s.get("words"):
            # the numbered word grid; an optional label sits centred on the
            # bottom baseline
            if s.get("label"):
                texts.append(dict(str=s["label"], x=CENTER_X, y=BASELINE_Y, size=16,
                                  ls=1, base=True, weight="semibold"))
            return dict(circle=dict(cx=cx, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                        chev=s["chev"], texts=texts + _words_texts(s["words"]))
    else:
        left = s["side"] == "left"
        cx = s.get("circle_x", COL_LEFT_CX if left else COL_RIGHT_CX)
        texts = []
        if s.get("label"):
            texts.append(dict(str=s["label"], x=cx, y=BASELINE_Y, size=16, ls=1,
                              base=True, weight="semibold"))
        tx = s.get("text_x", DETAIL_TEXT_CX["left"] if left else DETAIL_TEXT_CX["right"])
    out = dict(circle=dict(cx=cx, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
               chev=s["chev"])
    if s.get("pages"):
        # a paged value: every page laid out at the screen's one size; the
        # Sim shows one page at a time (flow.Sim._draw_pages, motion.page_flip)
        # under the pager n/m — "texts" carries the first page for readers
        # that know one page
        out["fixed"] = list(texts)
        out["pages"] = [_value_texts(p, tx, s["size"]) for p in s["pages"]]
        out["texts"] = texts + out["pages"][0]
    else:
        out["texts"] = texts + _value_texts(s["lines"], tx, s["size"])
    return out


def normalize_screens(data, defaults=None):
    """Fill schema defaults in place (the JSON contract of transitions.py).

    defaults: optional dict of per-flow shared fields (e.g. icon, token)
    applied to every screen before the kind defaults — so a flow can set its
    glyph or palette once instead of on each screen."""
    for i, s in enumerate(data):
        for k, v in (defaults or {}).items():
            s.setdefault(k, copy.deepcopy(v))
        s.setdefault("id", f"screen{i}")
        s.setdefault("kind", "detail")
        s.setdefault("icon", "eth")
        # chevrons: hidden on status screens (no input — DESIGN.md
        # § Input); confirm screens rest them in the "up" (hold-armed)
        # pose — they bob on the band's 5 s beat; a band_chev hero hides
        # them — its caption carries the one chevron
        s.setdefault("chev",
                     None if s["kind"] == "status" or s.get("band_chev")
                     else "up" if s["kind"] == "confirm" else "lr")
        if s["kind"] in ("detail", "value"):   # value: a detail without the docked token
            if s["kind"] == "detail":
                s.setdefault("side", "left" if i % 2 == 0 else "right")
                s.setdefault("label", None)
            pages = s.get("pages")
            if pages is not None:   # a paged value (DESIGN.md § Text rules, Pages)
                if len(pages) < 2 or not all(1 <= len(p) <= 3 for p in pages):
                    raise ValueError(
                        f"screen {s['id']!r}: \"pages\" is two or more pages of "
                        f"1-3 lines at one size (DESIGN.md § Text rules, Pages)")
                s["lines"] = list(pages[0])   # the first page, for single-page readers
            words = s.get("words")
            if words is not None:   # a numbered word grid (the seed-words layout)
                if s["kind"] != "value" or pages is not None or s.get("lines"):
                    raise ValueError(
                        f"screen {s['id']!r}: \"words\" is a VALUE screen's whole "
                        f"value — no lines, no pages beside it (pq1/layout.py, value)")
                if not 1 <= len(words) <= WORDS_MAX:
                    raise ValueError(
                        f"screen {s['id']!r}: \"words\" holds 1-{WORDS_MAX} words "
                        f"(two columns of four); got {len(words)}")
                s["words"] = [str(w) for w in words]
                s["size"] = WORDS_SIZE
            s.setdefault("lines", [])
            s.setdefault("size", 28)
        elif s["kind"] == "hero":
            s.setdefault("bottom", "")
            pg = s.get("pager")
            if pg is not None:
                pg = list(pg)
                if (len(pg) != 2 or not all(isinstance(v, int) for v in pg)
                        or not 1 <= pg[0] <= pg[1]):
                    raise ValueError(
                        f"screen {s['id']!r}: \"pager\" is [n, m] — the "
                        f"hero's position in a sequence of asks, 1 <= n <= m "
                        f"(DESIGN.md § Typography, Paging); got {s['pager']!r}")
                s["pager"] = pg
            # every ask signs: hold-right is armed on the opening hero as
            # much as on the returning one ("back on the idle ask, then
            # resolves", DESIGN.md § Flow shape) — the transaction can be
            # confirmed at the beginning, after every detail, or at the
            # mid-flow Confirm?; never on a detail. Semantics for drivers;
            # the demo loop performs the hold only where an ending follows.
            s.setdefault("commit", True)
        elif s["kind"] == "confirm":
            s.setdefault("bottom", "Confirm?")
            s.setdefault("commit", True)
        elif s["kind"] == "status":
            s.setdefault("bottom", "")
            # "anim" stays unset here: the default splits on outcome and
            # lives in ONE place — status.default_anim ("qubit" for done
            # endings, the film-less "resolve" for cancels), applied by
            # status.anim_for
            s.setdefault("result", "check")
            s.setdefault("state", "done")
            s.setdefault("busy", None)
            # no dwell default: Sim dwells for the animation's duration
    return data


def _segments(data):
    """(start, stop) index pairs — a status screen closes a segment, so a
    batch's transactions are counted apart (DESIGN.md § Flow shape). A flow
    with one ending is one segment starting at 0."""
    out, start = [], 0
    for i, s in enumerate(data):
        if s.get("kind") == "status":
            out.append((start, i))
            start = i + 1
    out.append((start, len(data)))
    return [(a, b) for a, b in out if b > a]


def insert_confirm(data):
    """DESIGN.md § Flow shape — insert AND enforce the flow-shape rules.

    1. Confirm is ALWAYS the 6th screen of a SEGMENT: a segment with
       CONFIRM_MIN_DETAILS or more detail screens takes a confirm-kind
       screen at CONFIRM_INDEX — the early exit: hold-right sign is armed
       there, VIEW MORE points at the remaining details. It is inserted
       there when absent; a segment that places a confirm-kind screen
       anywhere else (or doubles it) is rejected. A segment is one run of
       screens up to a status screen: an ordinary flow is a single segment
       starting at 0, so this is the plain "6th screen of the flow"; a
       batch signs one transaction per segment (flows/batch) and each
       earns its Confirm? on its OWN detail count, never the batch total.
    2. The CHAIN screen directly follows TO or AMOUNT: a chain context
       screen (canonical id "CHAIN") sits immediately after the detail it
       contextualizes — the address (TO) or value (AMOUNT) just shown.

    Call BEFORE normalize_screens, so the flow's DEFAULTS (icon, token)
    dress the inserted screen — the circle wears the flow's logo."""
    plan = []
    for a, b in _segments(data):
        seg = data[a:b]
        # a value screen is a detail without the docked token — it counts
        details = sum(1 for s in seg
                      if s.get("kind", "detail") in ("detail", "value"))
        if details < CONFIRM_MIN_DETAILS:
            continue
        ci = [a + k for k, s in enumerate(seg) if s.get("kind") == "confirm"]
        want = a + CONFIRM_INDEX
        if not ci:
            plan.append(want)
        elif ci != [want]:
            raise ValueError(
                f"the confirm screen is always screen {CONFIRM_INDEX + 1} of "
                f"a {CONFIRM_MIN_DETAILS}+-detail flow (DESIGN.md § Flow "
                f"shape); expected screen {want + 1}, found kind 'confirm' "
                f"at screen {[i + 1 for i in ci]}")
    for at in reversed(plan):   # last segment first, so earlier indices hold
        data.insert(at, dict(id="CONFIRM?", kind="confirm"))
    for i, s in enumerate(data):
        if s.get("kind", "detail") == "detail" and s.get("id") == "CHAIN":
            prev = data[i - 1] if i else {}
            if prev.get("id") not in ("TO", "AMOUNT"):
                raise ValueError(
                    "the CHAIN screen directly follows the TO or AMOUNT "
                    "detail (DESIGN.md § Flow shape); found CHAIN after "
                    f"{prev.get('id')!r}")
    return data
