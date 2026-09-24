"""ROTATE SLOT flow — screen content only (grid/type/motion come from pq1).

  ROTATE SLOT? (idle sweep) -> ROTATE -> DETAIL -> back on the idle hero
  (every detail seen, the ask again) -> status (ROTATED by default)
  — the full walkthrough.

Two detail screens: below the 7-detail threshold there is no mid-flow
Confirm? and no `--early` variant (DESIGN.md § Flow shape). The rotation
is committed on an ask only — the opening hero or the returning one —
never on a detail.

Endings (--end on the CLI): ROTATED is the qubit film resolving to a
green check; DECLINED plays no film (the cancel resolve) — the token
resolves in place, red ring stroke and red X on the unfilled black disc.
Captions "SLOT ROTATED" / "SLOT ROTATION DECLINED".

The rotation is the device's own operation, not a token: every screen
wears the rotate mark (pq1/assets/rotate_icon.svg as procedural art,
pq1/procedural/rotate.py) white on a black disc with the white ring, over
the gold rotation trail (colors.ROTATE_GRADIENT, pinned by name as
palette "ROTATE" — never hashed).

EVERY value line is VARIABLE content — the flow fixes the screens, their
order, labels and sides, never a value. ROTATE shows the slot being
retired and the slot taking over on ONE row, a right chevron between them
(§ Text rules, Transitions): "Slot 3 ▸ Slot 4" at 36, the tier the whole
row fits (a two-digit pair drops to 32); DETAIL what the rotation spends ("One Bootstrap
used" — 18 characters, broken once between words at 28).
Render with `python -m flows rotate_slot --end all`.
"""
DEFAULTS = dict(icon="rotate", token=dict(palette="ROTATE"))   # black disc, gold trail

BODY = [
    dict(id="ROTATE SLOT", kind="hero", bottom="ROTATE SLOT?", chev="lr", hint=True),
    dict(id="ROTATE", kind="detail", side="left", label="ROTATE",
         lines=[dict(transition=["Slot 3", "Slot 4"])], size=36, chev="lr"),
    dict(id="DETAIL", kind="detail", side="right", label="DETAIL",
         lines=["One Bootstrap", "used"], size=28, chev="lr"),
]

ENDS = {
    "rotated": dict(id="ROTATED", kind="status", bottom="SLOT ROTATED", chev=None),
    "declined": dict(id="DECLINED", kind="status", result="x", state="failed",
                     bottom="SLOT ROTATION DECLINED", chev=None),
}
DEFAULT_END = "rotated"
# the full walkthrough: every detail, back on the idle ask, then the ending
SCREENS = BODY + [dict(BODY[0]), ENDS[DEFAULT_END]]
