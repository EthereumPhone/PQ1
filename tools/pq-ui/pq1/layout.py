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
    "icon"   : "eth" | "blind" | "rotate" | "dev"
               | "fingerprint" | "download"
               | a chain mark ("base", "op", ...)
               | "letter:X"                      glyph inside the circle
                                                 (components.GLYPHS; a popular
                                                 token's logo art comes via
                                                 components.token_defaults;
                                                 "letter:X" draws that initial
                                                 — an unknown chain, pq1.chains)
    "icon_color": [r, g, b]                      vector-mark colour override
                                                 (image logos keep their art;
                                                 SAFE flows pin it black)
    "chain"  : 1 | 8453 | 42161 | ...            numeric EIP-155 chain id on a
                                                 chain screen; the mark, the
                                                 disc colour, the trail ramp
                                                 and the caption are DERIVED
                                                 from it (pq1.chains), so the
                                                 network can never disagree
                                                 with the art naming it. Detail
                                                 screens only — never a flow's
                                                 DEFAULTS
    "chain_name": "Celo"                         the chain's name when the id
                                                 is not in pq1.chains.CHAINS:
                                                 the disc shows its first
                                                 letter instead of borrowing
                                                 another network's mark
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
                "symbol": "XYZ"}                 solid disc + trail take the
                                                 ramp hashed from address
                                                 (preferred) or symbol, so
                                                 the same token always wears
                                                 the same colour
               "solid" is the treatment for EVERY live token, known or not
               (and the default); "unknown" draws the gradient disc, which
               is RESERVED and asked for by no screen (audit A11-12) — a
               port must not implement it. Either way the ramp comes from
               components.token_ramp ("palette" -> "address" -> "symbol"
               -> "icon" -> neutral).

hero — circle centred x 214, question text on the y 128 baseline
    "bottom" : "SEND 5.25 ETH?"
    "hint"   : True                              chevrons bob up and back
    "pager"  : [2, 3]                            this hero's position in a
                                                 sequence of asks — the pager
                                                 "n/m" in the same top-centre
                                                 spot a paged detail uses
                                                 (the Label face, INK_PAGING).
                                                 A
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
    "bottom" : "Confirm?"                        (default) the prompt at SIZE_XL
    "commit" : True                              (default) hold-right sign armed

detail — circle docked in a 100 px column, text centred in the other region
    "side"     : "left" | "right"                (default: the opposite of the
                                                 previous detail in the segment,
                                                 the first on the left — details
                                                 alternate columns)
    "label"    : "MAX FEE"                       the Label face (SIZE_LABEL SEMIBOLD caps), baseline y 128
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
                                                 (no per-screen x nudges: a
                                                 detail sits on the column
                                                 grid; a chain screen composes
                                                 itself — chain_compose)
    "pulse"    : True | <STATE key>              pulsating rings around the
                                                 token (components.pulse;
                                                 True = STATE["warning"])
    "pages"    : [[line, line], [line, line]]    ONE value too long for its
                                                 tier's three lines — a full
                                                 32-byte hash — shown in
                                                 2+ pages of 1-3 lines at
                                                 the screen's one "size";
                                                 the pager "n/m" (the Label
                                                 face, INK_PAGING, top centre)
                                                 shows only then. The demo
                                                 turns a page per detail
                                                 dwell (motion.page_flip:
                                                 the page fades away
                                                 ease-out, the next fades
                                                 in ease-out); a right tap
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
                                                 a page (up to 24, paged
                                                 in 8s under the n/m
                                                 pager, the numbers
                                                 counting on — the setup
                                                 seed), short words on the seed-
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
                                                 design's pq1_seed_words).
                                                 A value screen carries NO
                                                 label — the value stands
                                                 alone, and a words grid
                                                 has no caption

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
    "accept" : "any"                             a PIN entry CHOOSING a PIN:
                                                 any entry matches (SET PIN,
                                                 flows/setup)
    "forbid" : "00000000"                        ... any entry BUT this one
                                                 matches (the duress PIN
                                                 must differ)
    "on_match": "next"                           an entry's bench route on a
                                                 match: the very next screen,
                                                 even another entry (default:
                                                 past the entries)
    "on_miss": "SET PIN"                         ... on a miss: the screen with
                                                 this id, its own retrying in
                                                 place (pq1.driver
                                                 _after_entry; default: the
                                                 next attempt)
    dwell defaults to the animation's duration (qubit 8650 ms, the cancel
    resolve 2850 ms). Any extra
    fields ride along to the registered animation via its spec (the screens/
    library uses this for per-screen params like pin= or direction=).
"""
import copy

from . import colors, typography   # both safe at module level: colors imports
                                   # only motion; typography reads SUP back from
                                   # here lazily, inside font() / text_width()

# ------------------------------------------------------------------ canvas --
W, H = 428, 142
SUP = 3                     # supersample factor; all APIs take UI pixels
MARGIN = 12

# -------------------------------------------------------------------- grid --
CENTER_X = 214
CIRCLE_CY = 72              # main circle vertical centre
CIRCLE_R = 30               # diameter 60, never resizes
TEXT_CY = 72.5              # vertical centre of detail text blocks

# The sign box: a verdict's icon — a triangle, a padlock, a shield, a gear,
# a die — inks its LARGEST dimension to VERDICT_BOX, centred on the circle
# grid: one size for every sign that stands where the token would (audit
# ICO-03; the value is the owner's, Sep 2026). A disc ending (FIRMWARE
# VERIFIED's white disc, the X ring) is the token itself, 2 * CIRCLE_R, and
# is not a sign. Screens derive their art constants from it; tools/check
# rule V-BOX measures the resting frame.
VERDICT_BOX = 64
# The stroke vocabulary — every line weight the port draws, by name (audit
# ICO-05): hair = the PIN rings at rest and the die's edges, ring = the token
# ring (components.TOKEN_RING_W), sign = the corner chevrons, heavy = the
# padlock's shackle. A width that is a recorded decision off this scale is
# named where it is drawn (the ± hint stroke, the pin pill, the shield
# outline, the exclamation bar, the result marks' SIGN_STROKE — a fraction
# of r) — DESIGN.md § Iconography.
STROKE = dict(hair=2.0, ring=2.4, sign=4.5, heavy=5.4)

SWEEP_X_MIN, SWEEP_X_MAX = 89, 339

# The detail grid is ONE layout and its mirror image about CENTER_X: every
# right-hand anchor is derived from the left one (pixel-edge coordinates,
# so a point mirrors as W - x and a pixel column as W - 1 - x — DESIGN.md
# § Canvas). The left values are the designer's (reference/design_canvas).
COL_LEFT = (24, 123)        # detail circle column, left (pixel columns)
COL_RIGHT = (W - 1 - COL_LEFT[1], W - 1 - COL_LEFT[0])   # (304, 403)
COL_LEFT_CX = 74
COL_RIGHT_CX = W - COL_LEFT_CX                            # 354
DETAIL_TEXT_CX = {"left": 263, "right": W - 263}   # text centre opposite the
                            # circle: the designer's 263, and its mirror 165

# The detail text's own width — the budget the fit rule measures against.
# Derived from the two constraints the detail grid already obeys, rather
# than typed: OUTSIDE, the panel margin; INSIDE, one MARGIN of air past the
# circle's ink (COL_LEFT_CX +/- CIRCLE_R, not the wider reserved column).
# The inner bound binds (147 < 153) and mirrors exactly on the other side:
# a right-docked circle leaves 165 - 147 = 18, still clear of MARGIN.
TEXT_REGION_W = 2 * min(W - MARGIN - DETAIL_TEXT_CX["left"],
                        DETAIL_TEXT_CX["left"] - (COL_LEFT_CX + CIRCLE_R + MARGIN))
TEXT_REGION_FULL_W = W - 2 * MARGIN   # a value screen: no circle to clear

BAND_TOP, BAND_BOTTOM = 105, 129
BASELINE_Y = 128            # all bottom-band text baselines

# the confirm band's two units — "OR VIEW MORE ▸" and "◂ TO GO BACK" — each
# centre their TEXT off the panel centre so that text + chevron read centred
# as one unit; the two alternate every 5 s, so they share one visual centre.
# A band_chev hero's caption sits on VIEW_MORE_CX too (it points right).
VIEW_MORE_CX = 206          # text centre, chevron after it: nudged left
GO_BACK_CX = 2 * CENTER_X - VIEW_MORE_CX   # 222: the mirror, chevron before it

CHEV_LEFT = (23.5, 19.0)    # corner chevron slots ...
CHEV_RIGHT = (W - CHEV_LEFT[0], CHEV_LEFT[1])   # ... (404.5, 19): the mirror

# ------------------------------------------------------------- flow shape --
# DESIGN.md § Flow shape: a flow with CONFIRM_MIN_DETAILS or more detail
# screens takes a confirm-kind screen at CONFIRM_INDEX — the 6th screen,
# an early exit ahead of the remaining details (insert_confirm).
CONFIRM_MIN_DETAILS = 7
CONFIRM_INDEX = 5

# The Confirm? screen is composed like the chain screen: the prompt +
# CHAIN_GAP + the disc as ONE group centred on the panel (layout_of calls
# chain_compose on the prompt). These two are that composition's result for
# the default prompt "Confirm?" — pinned here for the pages and the port, and
# held equal to chain_compose by tools/check rule G-CONFIRM (a module-level
# chain_compose call is impossible: typography reads SUP back from here).
CONFIRM_TEXT_X = 175        # prompt centre ...
CONFIRM_CIRCLE_X = 297      # ... and the disc, CHAIN_GAP past the prompt's edge
CHAIN_GAP = 18              # chain screen: the FIXED air between the caption's
                            # right edge and the disc's left edge. A chain screen
                            # composes itself — caption + gap + disc as one group,
                            # centred — instead of pinning the disc to a column, so
                            # the spacing reads identical whatever the network is
                            # called (user rule, Sep 2026)

VALUE_TEXT_CX = CENTER_X    # a value screen's text: the full region, centred ...
VALUE_PARK_X = -2 * CIRCLE_R   # ... its token parked off the panel to the left

# a words value (the seed-words grid of the design canvas,
# reference/device/pq1_seed_words.py): two columns of four numbered words — the
# number right-aligned so digits line up, the word left-aligned beside it
# — numbered down the left column, then the right (user request, Sep 2026:
# the words and numbers a tier up from the design's 16 px)
WORDS_ROWS = (32, 58, 84, 110)         # row centre lines
WORDS_COLS = ((88, 98), (272, 282))    # (number right edge, word left edge) per column
WORDS_SIZE = typography.SIZE_BODY      # the words' and numbers' one size: the Default tier
WORDS_NUM_ALPHA = colors.INK_MUTED     # the numbers' grey (the design's ~50 % GRAY)
WORDS_MAX = len(WORDS_COLS) * len(WORDS_ROWS)   # words on ONE page of the grid
WORDS_TOTAL_MAX = 24                   # a longer list pages in WORDS_MAX (a 24-word
                                       # seed: 3 pages under the n/m pager — audit HS-09)
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


def fit_tiers():
    """the detail ladder, largest first: (size, max lines per screen).

    The tiers are the typography tokens, never re-typed (DESIGN.md
    § Typography)."""
    return ((typography.SIZE_XL, 1), (typography.SIZE_L, 1),
            (typography.SIZE_M, 2), (typography.SIZE_BODY, 3))


def line_width(ln, size):
    """the width one detail line occupies at `size`, measured in its own face.

    A transition row measures as the WHOLE run — both values plus one size of
    chevron space (components.TRANSITION_GAP past each value's edge), because
    the pair is fitted as one row (DESIGN.md § Text rules, Transitions)."""
    w = line_weight(ln)
    if isinstance(ln, dict) and "transition" in ln:
        old, new = ln["transition"]
        return (typography.text_width(old, size, w)
                + typography.text_width(new, size, w) + size)
    return typography.text_width(line_str(ln), size, w)


def fit_size(lines, full=False):
    """the largest tier whose every line MEASURES inside the text region.

    The one fit rule (DESIGN.md § Typography, Choosing the size), in pixels.
    A character count is not a width: "D" x 21 measures 327.6 px at 22 — well
    past the region — while "l" x 21 measures 132.2. Each line is measured in
    the face it will be drawn in, so a SemiBold name is never counted as
    Regular. `full` is a value screen's full-width region.

    Raises when nothing fits: the answer is to split the value across screens,
    or to page it (§ Text rules, Pages) — never to shrink below the floor."""
    budget = TEXT_REGION_FULL_W if full else TEXT_REGION_W
    for size, rows in fit_tiers():
        if len(lines) <= rows and all(line_width(ln, size) <= budget
                                      for ln in lines):
            return size
    floor, rows = fit_tiers()[-1]
    widest = max(line_width(ln, floor) for ln in lines)
    raise ValueError(
        f"{len(lines)} lines, widest {widest:.1f} px at {floor}, fits no tier "
        f"({floor} holds {rows} lines inside {budget:.0f} px) — split the "
        f"value or page it, never shrink or ellipsize "
        f"(DESIGN.md § Typography, Choosing the size)")


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


def _words_texts(words, first=1):
    """the text specs of a numbered word grid: word k in column k // 4,
    row k % 4 — its number (k + first, grey; a later page of a paged list
    counts on) right-aligned at the column's
    number edge, the word (white) left-aligned at its word edge (cv.text
    centres on x, so each anchor is the edge plus or minus half the width)"""
    rows, out = len(WORDS_ROWS), []
    grey = colors.scale(colors.WHITE, WORDS_NUM_ALPHA)
    for k, w in enumerate(words):
        num_x, word_x = WORDS_COLS[k // rows]
        y, n = WORDS_ROWS[k % rows], str(k + first)
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
        # a band_chev caption is the confirm band's unit: its text centres on
        # VIEW_MORE_CX so text + chevron read centred together — the layout
        # reports the x the renderer draws at (components.draw_text)
        band = bool(s.get("band_chev"))
        out = dict(circle=dict(cx=CENTER_X, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                   texts=[dict(str=s["bottom"], x=VIEW_MORE_CX if band else CENTER_X,
                               y=BASELINE_Y, size=typography.SIZE_QUESTION,
                               ls=typography.LS_QUESTION, base=True,
                               band_chev=band)],
                   chev=s["chev"])
        if s.get("pager"):
            # position in a sequence, not text pages — Sim draws it under the
            # screen's own alpha and never turns it (flow.Sim.draw)
            out["pager"] = tuple(s["pager"])
        return out
    if s["kind"] == "confirm":
        # composed like the chain screen: prompt + CHAIN_GAP + disc as one
        # centred group (CONFIRM_TEXT_X / CONFIRM_CIRCLE_X for "Confirm?")
        tx, cx = chain_compose(s["bottom"], typography.SIZE_XL)
        return dict(circle=dict(cx=cx, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                    texts=[dict(str=s["bottom"], x=tx, y=TEXT_CY,
                                size=typography.SIZE_XL)],
                    chev=s["chev"])
    if s["kind"] == "value":
        # full width: the token leaves the panel, the value takes the region
        cx, tx, texts = VALUE_PARK_X, VALUE_TEXT_CX, []
        if s.get("words"):
            # the numbered word grid alone — a value screen carries no label
            # (normalize_screens rejects one; DESIGN.md § Text rules, Words)
            w = s["words"]
            if len(w) <= WORDS_MAX:
                return dict(circle=dict(cx=cx, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                            chev=s["chev"], texts=_words_texts(w))
            # a longer list PAGES the grid, WORDS_MAX words a page, the
            # numbers counting on — the paged value's machinery (the Sim's
            # page flip, the n/m pager, the driver's page taps)
            pages = [_words_texts(w[i:i + WORDS_MAX], i + 1)
                     for i in range(0, len(w), WORDS_MAX)]
            return dict(circle=dict(cx=cx, cy=CIRCLE_CY, r=CIRCLE_R, icon=s["icon"]),
                        chev=s["chev"], fixed=[], pages=pages, texts=pages[0])
    else:
        left = s["side"] == "left"
        if "chain" in s:
            # a chain screen composes itself: caption + CHAIN_GAP + disc as
            # one group centred on the panel (_expand_chain wrote the caption)
            tx, cx = chain_compose(line_str(s["lines"][0]), s["size"])
        else:
            cx = COL_LEFT_CX if left else COL_RIGHT_CX
            tx = DETAIL_TEXT_CX["left" if left else "right"]
        texts = []
        if s.get("label"):
            texts.append(dict(str=s["label"], x=cx, y=BASELINE_Y,
                              size=typography.SIZE_LABEL, ls=typography.LS_LABEL,
                              base=True, weight=typography.WEIGHT_LABEL))
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


def _expand_chain(s):
    """`chain=<id>` -> the mark, the disc colour and the caption it implies.

    Runs AFTER the per-flow DEFAULTS have landed and ASSIGNS rather than
    defaults: a branded family has already written its own `icon`, `token`
    and `icon_color` onto every screen by this point, so setdefault would be
    a no-op and the chain would never reach the disc. On a chain screen the
    chain owns the disc — it says which network is being signed for, and the
    flow's palette resumes on the next screen.

    The family's `ring` / `fill` are dropped for the same reason: they dress
    the flow's token, and a Safe-black ring around a Base-blue disc belongs
    to neither identity.

    `lines` and `size` are only filled when the screen states neither, so a
    flow can still write its own caption.
    """
    if "chain" not in s:
        return
    from . import chains        # local: the registry is a leaf of the flows'
    #                             world — the schema module stays importable
    #                             without it (no cycle: typography reads SUP lazily)
    cid = s["chain"]
    if not isinstance(cid, int) or isinstance(cid, bool):
        raise ValueError(
            f"screen {s.get('id')!r}: \"chain\" is a numeric EIP-155 chain id "
            f"(1, 8453, 42161 ...), not {cid!r}")
    kind = s.get("kind", "detail")
    if kind not in ("detail", "value"):
        raise ValueError(
            f"screen {s.get('id')!r}: \"chain\" belongs on the chain screen (a "
            f"detail), not on a {kind} — a flow's DEFAULTS must never carry it, "
            f"or every screen would wear the network's colours")
    st = chains.style(cid, s.get("chain_name"))
    s["icon"] = st["icon"]
    s["icon_color"] = st["icon_color"]
    tok = dict(s.get("token") or {})
    for k in ("fill", "ring", "address", "symbol", "variant"):
        tok.pop(k, None)                  # the family's dress, not the chain's
    tok.update(st["token"])
    s["token"] = tok
    if "lines" not in s and "pages" not in s and "words" not in s:
        s["lines"] = [chains.caption(cid, s.get("chain_name"))]
    line = s["lines"][0] if s.get("lines") else ""
    s.setdefault("size", chain_caption_size(line))
    # the caption and the disc are ONE centred group with a fixed gap, so the
    # air between them never changes with the length of the network's name —
    # composed at layout time (layout_of -> chain_compose); nothing about the
    # composition is written onto the screen dict


def chain_group_w(line, size):
    """width of a chain screen's caption + CHAIN_GAP + disc, as one group"""
    return typography.text_width(line, size) + CHAIN_GAP + 2 * CIRCLE_R


def chain_caption_size(line):
    """the largest Big tier at which the whole chain group fits the panel.

    Because the caption and the disc compose as a group rather than sitting on
    fixed anchors, the constraint is the MARGINs, not the disc: nothing can run
    under the token any more. Every network in the registry clears this at the
    top tier; the ladder is the safety net for a longer name later.
    """
    from . import chains
    for size in chains.CAPTION_TIERS:
        if chain_group_w(line, size) <= W - 2 * MARGIN:
            return size
    return chains.CAPTION_TIERS[-1]


def chain_compose(line, size):
    """(text centre, disc centre) for a chain screen — and the Confirm?
    screen: the caption and the disc as one group centred on the panel,
    CHAIN_GAP of air between them.

    Rounded to whole pixels — every other anchor in this module is an integer,
    and a port should not have to carry a repeating fraction to place a disc.
    The gap it costs is under half a pixel."""
    tw = typography.text_width(line, size)
    left = CENTER_X - chain_group_w(line, size) / 2.0
    return round(left + tw / 2.0), round(left + tw + CHAIN_GAP + CIRCLE_R)


def normalize_screens(data, defaults=None):
    """Fill schema defaults in place (the JSON contract of transitions.py).

    defaults: optional dict of per-flow shared fields (e.g. icon, token)
    applied to every screen before the kind defaults — so a flow can set its
    glyph or palette once instead of on each screen."""
    prev_side = None   # the last detail's column in this segment
    for i, s in enumerate(data):
        for k, v in (defaults or {}).items():
            s.setdefault(k, copy.deepcopy(v))
        for k in ("circle_x", "text_x"):
            if k in s:
                raise ValueError(
                    f"screen {s.get('id')!r}: {k!r} is not a field — there are no "
                    f"per-screen nudges: a detail sits on the column grid and a "
                    f"chain screen composes itself (chain=<id>; DESIGN.md "
                    f"§ Layout grid)")
        _expand_chain(s)
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
        if s["chev"] not in CHEV_STATES:
            raise ValueError(
                f"screen {s['id']!r}: unknown chev {s['chev']!r} — "
                f"one of {CHEV_STATES} (pq1/layout.py, chev)")
        if s["kind"] in ("detail", "value"):   # value: a detail without the docked token
            if s["kind"] == "detail":
                # a flow that does not say: details alternate columns within
                # a segment, the first on the left (the rule every live flow
                # writes out; a bench tour may pin one column)
                s.setdefault("side", "right" if prev_side == "left" else "left")
                prev_side = s["side"]
                s.setdefault("label", None)
            elif s.get("label") is not None:
                raise ValueError(
                    f"screen {s['id']!r}: a value screen has no label — the value "
                    f"stands alone, full width, and a words grid has no caption "
                    f"(DESIGN.md § Text rules, Words)")
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
                if not 1 <= len(words) <= WORDS_TOTAL_MAX:
                    raise ValueError(
                        f"screen {s['id']!r}: \"words\" holds 1-{WORDS_TOTAL_MAX} "
                        f"words (two columns of four a page, paged past "
                        f"{WORDS_MAX}); got {len(words)}")
                s["words"] = [str(w) for w in words]
                s["size"] = WORDS_SIZE
            s.setdefault("lines", [])
            if len(s["lines"]) > 3:
                # A detail value is 1-3 lines (DESIGN.md § Typography). The
                # fourth stacks at y 117.5 — inside the bottom band — and
                # fit_size only guards a screen that does NOT pin a size, so
                # a typed `size` would otherwise draw it there silently.
                # "pages" is already validated 1-3 above; bare lines was not.
                raise ValueError(
                    f"screen {s['id']!r}: a detail value is 1-3 lines at one "
                    f"size (DESIGN.md § Typography, Choosing the size); got "
                    f"{len(s['lines'])} — a fourth line lands in the bottom "
                    f"band. Split the value across screens, or page it "
                    f"(§ Text rules, Pages)")
            if "size" in s:
                # a typed size is the author's PIN — honoured, never re-fitted
                # (T-FIT only reports one below the measured tier). It must
                # still be ON the ladder: an off-scale size is a typo, not a
                # decision (DESIGN.md § Typography, Choosing the size).
                tiers = [t[0] for t in fit_tiers()]
                if s["size"] not in tiers and s.get("words") is None:
                    raise ValueError(
                        f"screen {s['id']!r}: unknown size {s['size']!r} — the "
                        f"detail tiers are {' / '.join(map(str, tiers))} "
                        f"(DESIGN.md § Typography, Choosing the size)")
            else:
                # fitted, never a flat default a long value could overflow
                # (DESIGN.md § Typography, Choosing the size). A paged value
                # takes the size its WIDEST page can carry — one size for the
                # whole screen (§ Text rules, Pages).
                if s["lines"]:
                    full = s["kind"] == "value"
                    s["size"] = min(fit_size(p, full=full)
                                    for p in (pages if pages is not None
                                              else [s["lines"]]))
                else:
                    s["size"] = typography.SIZE_M
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
                        f"(DESIGN.md § Layout grid, Pager); got {s['pager']!r}")
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
            prev_side = None   # a status screen closes the segment
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


CHEV_STATES = ("lr", "up", None)   # the corner-chevron states (normalize_screens)


def back_target(data, i):
    """where a LEFT tap lands from navigable screen i: the screen before
    it, or None when nothing navigable is behind it — the flow's first
    screen, or the first screen after a status (a mid-batch ending closes
    its segment and is never walked back into). The rule the driver's left
    tap reads (DESIGN.md § Input, "Left never leads on"): on an idle screen
    left goes back or does nothing, never forward — only right enters the
    details. The chevrons do not follow it: a hero keeps both (user
    decision, Sep 2026)."""
    if i <= 0 or data[i - 1].get("kind") == "status":
        return None
    return i - 1


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
