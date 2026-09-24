"""Duress PIN differ — the PIN pill is scanned, rejected by a shake.

Port of pin_differ.py, all in colors.ORANGE (state="warning"; the
source's #FF9B3D corrected to the palette). The pill outline fades in,
the four dots land, a beat, then a black-stroked scanline sweeps
forward-back-forward across the pill and fades; the row shakes off the
duress PIN and the caption names the rule. Not a verdict — the pill row
is the whole picture, so it runs its own timeline on StatusAnim; the
verdict twin (screens/verdict/duress_differ.py) states the same rule on
the verdict law, and both draw the same art, pq1.procedural.pin_pill.

    hold 250 -> fill 200 -> hold 200 -> scan 975 -> shake 420
             -> caption 300                               t_resolve 2345

Paced with that twin (user, Sep 2026): the same 200 ms fill and beats,
the same 325 ms per scanline traverse — three of them here, for this
screen's 1.5-cycle sweep — and the same 210 ms shake cycle. Every phase
clears VERDICT_ACCENT_MIN_MS (145 ms, two frames at the panel's 14 fps)
with room to spare, so no beat reads as rushed on the device.
"""
from pq1 import status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import clamp01, ease, ease_out, shake
from pq1.procedural import pin_pill

ANIM = "pin_differ"
SPEC = dict(state="warning", result=None, bottom="DURESS PIN MUST DIFFER")

# timeline (ms): pill fade, dot fill, full-row pause, scanline sweep,
# error shake, caption fade
T_HOLD = 250
T_FILL = 200
T_FILLED, T_SCAN, T_SHAKE, T_TEXT = 200, 975, 420, 300

SCAN_CYCLES = 1.5   # right, left, right — the sweep ends at the far end
SHAKE_CYCLES = 2.0
SHAKE_PX = 7.0


class PinDiffer(status.StatusAnim):
    rests_on_token = False      # the pill owns the canvas (no token disc)
    T0_FILL = T_HOLD
    T0_FILLED = T0_FILL + T_FILL
    T0_SCAN = T0_FILLED + T_FILLED
    T0_SHAKE = T0_SCAN + T_SCAN
    T0_TEXT = T0_SHAKE + T_SHAKE
    t_resolve = T0_TEXT + T_TEXT                       # 2345
    previews = (T0_SCAN + T_SCAN // 2,                 # mid-sweep
                t_resolve + status.RESULT_HOLD_MS - 600)

    def draw(self, cv, t):
        col = self.style["color"]
        cx = CENTER_X
        if t > self.T0_SHAKE:
            cx += SHAKE_PX * shake(clamp01((t - self.T0_SHAKE) / T_SHAKE),
                                   cycles=SHAKE_CYCLES)
        a = ease(clamp01(t / T_HOLD))
        dots = [ease(clamp01((t - self.T0_FILL) / T_FILL))] * pin_pill.SLOTS
        pin_pill.draw(cv, cx, CIRCLE_CY, color=col, alpha=a, dots=dots)
        if self.T0_SCAN < t < self.T0_SHAKE:
            pin_pill.scanline(cv, cx, CIRCLE_CY,
                              clamp01((t - self.T0_SCAN) / T_SCAN),
                              color=col, alpha=a, cycles=SCAN_CYCLES)
        self.draw_caption(cv, ease_out(clamp01((t - self.T0_TEXT) / T_TEXT)))


status.register(ANIM, PinDiffer)
