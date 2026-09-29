"""Shield — the backup shield arrives with its mark and nods yes, or shakes no.

Port of reference/design_canvas/backup_ok_nod.py and no_match-2.py onto
the verdict law. One screen, two gestures on the one shield outline
(pq1.procedural.shield): the check shield NODS — one decaying up-down dip,
+-5 px over 700 ms — for BACKUP OK; the x shield WIGGLES — one decaying
left-right shake, +-6 px over 420 ms — for NO MATCH. Both are motion.shake
at one cycle, played on the arrived sign as the mechanism, the mark riding
with the shield; the state colours both (done green / failed red). The
sources' spring pop becomes the entrance law (fade + rise within
ARRIVE_MS, no overshoot); then the beat and the caption:

    backup_ok  hold 400 -> arrive 300 -> nod 700    -> beat 450 -> caption 300
               t_resolve 2150
    no_match   hold 400 -> arrive 300 -> wiggle 420 -> beat 450 -> caption 300
               t_resolve 1870

    screens.spec("shield", preset="backup_ok")
    screens.spec("shield", preset="no_match")
    python3 -m screens no_match --text "NO BACKUP"
"""
from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import shake
from pq1.procedural import marks, shield
from pq1.verdict import VerdictAnim

ANIM = "shield"
SPEC = dict(result="check", state="done", bottom="BACKUP OK", gesture="nod")
PRESETS = dict(
    backup_ok=dict(result="check", state="done", bottom="BACKUP OK",
                   gesture="nod"),
    no_match=dict(result="x", state="failed", bottom="NO MATCH",
                  gesture="wiggle"),
)

SHIELD_H = 62.0    # source height, design box centred on the circle
MARK_DY = 2.0      # both sources sit the mark 2 px above the shield centre
# check r from the source; the x source drew diagonals to +/-8.5 px and
# x_mark's corners sit at 0.30 r
MARK_R = {"check": 25.0, "x": 8.5 / 0.30}
T_BEAT = 450       # the verdict beat before the caption
# the gestures, on the arrived sign: (axis, excursion px, window ms) — one
# decaying cycle each (sources: 5 sin(2 pi w)(1 - w) on y; 6 sin(2 pi w)(1 - w)
# on x); gesture=None in a spec is the plain arrival
GESTURES = dict(
    nod=("y", 5.0, 700),      # yes: the shield dips and comes back up
    wiggle=("x", 6.0, 420),   # no: the shield shakes its head
)


class Shield(VerdictAnim):
    def __init__(self, spec):
        super().__init__(spec)
        name = spec.get("gesture")
        if name is not None and name not in GESTURES:
            raise ValueError(f"unknown shield gesture {name!r}; expected "
                             f"one of {', '.join(GESTURES)} or None")
        self.gesture = GESTURES.get(name)
        self.T_WAIT = (self.gesture[2] if self.gesture else 0) + T_BEAT

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        cx, cy = CENTER_X, CIRCLE_CY
        if self.gesture:
            axis, px, ms = self.gesture
            w = (t - (self.T_HOLD + self.T_IN)) / ms
            if 0.0 < w < 1.0:
                d = px * shake(w, cycles=1.0)
                if axis == "y":
                    cy += d
                else:
                    cx += d
        col = self.style["color"]
        shield.draw(cv, cx, cy, h=SHIELD_H * s, color=col, alpha=a)
        result = self.style["result"]
        if result:
            mark = marks.check if result == "check" else marks.x_mark
            mark(cv, cx, cy - MARK_DY, MARK_R[result] * s, alpha=a, color=col)


def add_args(ap):
    ap.add_argument("--text", default=None, metavar="CAPTION",
                    help="the caption (default the preset's)")


def spec_from_args(a):
    return {} if a.text is None else dict(bottom=a.text)


status.register(ANIM, Shield)
