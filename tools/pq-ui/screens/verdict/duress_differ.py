"""Duress PIN must differ — the pill is scanned, the rule refuses it.

Port of reference/design_canvas/pin_differ-2.py onto the verdict law, all
in the warning orange (state="warning"; the source's #FF9B3D is the
palette's ORANGE). The pill arrives ALREADY FILLED and already in the
state colour — one sign, pill and four dots entering together on the
entrance law (user, Sep 2026), the way every other verdict sign arrives
whole; a duress PIN that repeats the real one never read normal, so
there is no entry to recap. The row holds a beat, and the mechanism is
the device checking it: the scanline crosses the pill and comes back
(one ping-pong cycle over T_SCAN, ending where it started), finds the
same PIN, and the row shakes it off. Then the beat and the rule:

    hold 250 -> arrive 300 (pill + dots) -> hold 200 -> scan 650
             -> shake 420 -> beat 200 -> caption 300      t_resolve 2320

Pace (user, Sep 2026, settled over three passes — twice "too slow", then
"a bit slower"): the source's 1500 ms sweep is 650, the bar crossing in
325 ms each way (four and a half frames at the NV3007's 14 fps), and the
beats sit at 200 ms rather than on VERDICT_ACCENT_MIN_MS (145 — two
frames, the floor a beat can hold and still be seen), which read as
rushed.

The art is pq1.procedural.pin_pill, shared with pin_mismatch (the same
pill refused for the other reason — that one still fills after the pill
arrives, since its dots go in white and only then turn red).
screens/pin/pin_differ.py states this rule as a plain pin-category
screen — its own longer 1.5-cycle sweep, no verdict entrance.

    python3 -m screens duress_differ
"""
from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import ARRIVE_MS, clamp01, shake
from pq1.procedural import pin_pill
from pq1.verdict import VerdictAnim

ANIM = "duress_differ"
SPEC = dict(state="warning", bottom="DURESS PIN MUST DIFFER")

T_FILLED = 200    # the arrived row holds, before the check
T_SCAN = 650      # the scanline crosses and comes back: one cycle
T_SHAKE = 420     # the row shakes the duress PIN off — 2 source cycles
T_BEAT = 200      # the verdict beat before the caption
SHAKE_CYCLES = 2.0
SHAKE_PX = 7.0    # the source's excursion
SCAN_CYCLES = 1.0  # right once, left once — the sweep ends where it began


class DuressDiffer(VerdictAnim):
    T_HOLD = 250
    T_IN = ARRIVE_MS        # pill AND dots arrive — the entrance law
    T_WAIT = T_FILLED + T_SCAN + T_SHAKE + T_BEAT

    T0_SCAN = T_FILLED      # both on the mechanism clock, which starts
    T0_SHAKE = T0_SCAN + T_SCAN     # on the arrived, filled pill

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        tm = t - (self.T_HOLD + self.T_IN)
        col = self.style["color"]
        cx = CENTER_X
        w = (tm - self.T0_SHAKE) / T_SHAKE
        if 0.0 < w < 1.0:
            cx += SHAKE_PX * shake(w, cycles=SHAKE_CYCLES)
        # the dots ride the entrance alpha with the outline: one sign
        pin_pill.draw(cv, cx, CIRCLE_CY, color=col, alpha=a, scale=s,
                      dots=(1.0,) * pin_pill.SLOTS)
        v = (tm - self.T0_SCAN) / T_SCAN
        if 0.0 < v < 1.0:
            pin_pill.scanline(cv, cx, CIRCLE_CY, v, color=col, alpha=a,
                              scale=s, cycles=SCAN_CYCLES)


status.register(ANIM, DuressDiffer)
