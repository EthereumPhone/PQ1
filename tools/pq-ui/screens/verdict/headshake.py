"""Headshake — the X ring arrives and shakes its head once: no.

Port of reference/design_canvas/wrong_seed_phrase.py onto the verdict
law. The sign is the one every unbranded DECLINED ending rests on
(status.ArriveStatus): the black disc under the state-colour stroke, the
x mark in the same colour — so CANCELED and WRONG SEED PHRASE read as the
same refusal the flows' cancel endings land on. The source's spring pop
becomes the entrance law (fade + rise within ARRIVE_MS, no overshoot);
its one decaying left-right wiggle (+-6 px, one cycle over 420 ms —
motion.shake at one cycle) plays on the arrived sign as the mechanism;
then the beat and the caption:

    hold 400 -> arrive 300 -> shake 420 -> beat 450 -> caption 300
    t_resolve 1870

Presets name the two captions; --text renders any other one:

    screens.spec("headshake", preset="canceled")
    screens.spec("headshake", preset="wrong_seed_phrase")
    python3 -m screens headshake --text "WRONG PIN"
"""
from pq1 import colors, components, status
from pq1.layout import CENTER_X, CIRCLE_CY, CIRCLE_R
from pq1.motion import clamp01, shake
from pq1.verdict import VerdictAnim

ANIM = "headshake"
SPEC = dict(result="x", state="failed", bottom="CANCELED")
PRESETS = dict(
    canceled=dict(result="x", state="failed", bottom="CANCELED"),
    wrong_seed_phrase=dict(result="x", state="failed",
                           bottom="WRONG SEED PHRASE"),
)

T_SHAKE = 420     # the wiggle window (source), on the arrived sign
T_BEAT = 450      # the verdict beat before the caption
SHAKE_PX = 6.0    # the wiggle's excursion (source: cx += 6 sin(2 pi w)(1 - w))
RING_INSET = 1.2  # an unbranded resting ring sits just inside the disc edge
                  # (status.ArriveStatus / ResolveStatus)


class Headshake(VerdictAnim):
    T_WAIT = T_SHAKE + T_BEAT

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        w = (t - (self.T_HOLD + self.T_IN)) / T_SHAKE
        cx = CENTER_X
        if 0.0 < w < 1.0:
            cx += SHAKE_PX * shake(w, cycles=1.0)
        rest = self.style["resting"]
        r = CIRCLE_R * s
        cv.circle(cx, CIRCLE_CY, r, colors.scale(rest["fill"], a))
        cv.ring(cx, CIRCLE_CY, r if rest["flush"] else r - RING_INSET,
                colors.scale(rest["ring"], a), components.TOKEN_RING_W)
        result = self.style["result"]
        if result is not None:
            components.GLYPHS[result](cv, cx, CIRCLE_CY, r, a, rest["glyph"])


def add_args(ap):
    ap.add_argument("--text", default=None, metavar="CAPTION",
                    help="the caption (default the preset's)")


def spec_from_args(a):
    return {} if a.text is None else dict(bottom=a.text)


status.register(ANIM, Headshake)
