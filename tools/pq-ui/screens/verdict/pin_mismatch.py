"""PIN mismatch — the entered PIN fills the pill, turns red, is shaken off.

Port of reference/design_canvas/pin_missmatch.py onto the verdict law. The
source's 400 ms pill fade becomes the entrance (fade + rise within
ARRIVE_MS) and the pill arrives EMPTY and WHITE — the entry reads normal
until the device answers. The four dots land together, the filled row
holds one beat while the device checks, and the refusal is the mechanism:
pill and dots turn white -> the state red, and the row shakes the PIN off
(motion.shake, at the source's 210 ms per cycle). Then the beat and the
caption:

    hold 250 -> arrive 300 -> fill 200 -> hold 200 -> turn 200
             -> shake 420 -> beat 200 -> caption 300      t_resolve 2070

Pace (user, Sep 2026, settled over three passes — twice "too slow", then
"a bit slower"): roughly half the source's timings. The beats sit at
200 ms, just under three frames at the NV3007's 14 fps, rather than on
VERDICT_ACCENT_MIN_MS (145 — two frames, the floor a beat can hold and
still be seen), which read as rushed. The dots land together rather than
one by one; restoring the one-by-one count costs ~400 ms.

The art is pq1.procedural.pin_pill, shared with duress_differ (the same
pill refused for the other reason).

    python3 -m screens pin_mismatch
    python3 -m screens pin_mismatch --text "WRONG PIN"
    python3 -m screens wrong_pin                 # the preset: WRONG PIN (flows/pin)
"""
from pq1 import colors, gradients, status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import ARRIVE_MS, clamp01, ease, shake
from pq1.procedural import pin_pill
from pq1.verdict import VerdictAnim

ANIM = "pin_mismatch"
SPEC = dict(state="failed", bottom="PIN MISMATCH")
PRESETS = dict(
    wrong_pin=dict(bottom="WRONG PIN"),      # the entry's first miss (flows/pin)
)

T_FILL = 200      # the four dots come in together
T_FILLED = 200    # the filled row holds: the device is checking
T_TURN = 200      # white -> the state colour: the refusal
T_SHAKE = 420     # the row shakes the PIN off — 2 source-rate cycles
T_BEAT = 200      # the verdict beat before the caption
SHAKE_CYCLES = 2.0
SHAKE_PX = 7.0    # the source's excursion


class PinMismatch(VerdictAnim):
    T_HOLD = 250
    T_IN = ARRIVE_MS            # the empty pill arrives — the entrance law
    T_WAIT = T_FILL + T_FILLED + T_TURN + T_SHAKE + T_BEAT

    T0_TURN = T_FILL + T_FILLED     # both on the mechanism clock, which
    T0_SHAKE = T0_TURN + T_TURN     # starts on the arrived pill

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        tm = t - (self.T_HOLD + self.T_IN)
        col = gradients.mix(colors.WHITE, self.style["color"],
                            ease(clamp01((tm - self.T0_TURN) / T_TURN)))
        cx = CENTER_X
        w = (tm - self.T0_SHAKE) / T_SHAKE
        if 0.0 < w < 1.0:
            cx += SHAKE_PX * shake(w, cycles=SHAKE_CYCLES)
        dots = [ease(clamp01(tm / T_FILL))] * pin_pill.SLOTS
        pin_pill.draw(cv, cx, CIRCLE_CY, color=col, alpha=a, scale=s,
                      dots=dots)


def add_args(ap):
    ap.add_argument("--text", default=None, metavar="CAPTION",
                    help="the caption (default PIN MISMATCH)")


def spec_from_args(a):
    return {} if a.text is None else dict(bottom=a.text)


status.register(ANIM, PinMismatch)
