"""Tamper detected — the warning triangle's exclamation, centred, sounds the alarm.

The sig_error notice icon on the circle grid: the red triangle arrives on
(214, 72) carrying a black exclamation, throws two decaying attention
pulses, then TAMPER DETECTED fades onto the baseline. Default VerdictAnim
draw — one icon, one caption; sig_error is its detail-grid twin.
"""
from pq1 import colors, status
from pq1.layout import CENTER_X, CIRCLE_CY
from pq1.motion import attention_pulse
from pq1.procedural import marks, warning_triangle
from pq1.verdict import VerdictAnim

ANIM = "tamper"
SPEC = dict(state="failed", bottom="TAMPER DETECTED")

TRI_H = 64      # triangle height in the centred slot (bounding box 72 x 64)


class Tamper(VerdictAnim):
    T_HOLD = 350    # sig_error's timeline: 350 + 300 + 900 + 300 -> t_resolve 1850
    T_WAIT = 900    # two decaying attention pulses

    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)     # fade + arrive (the entrance law)
        v = (t - (self.T_HOLD + self.T_IN)) / self.T_WAIT
        if 0.0 < v < 1.0:
            s = attention_pulse(v)
        warning_triangle.draw(cv, CENTER_X, CIRCLE_CY, h=TRI_H * s,
                              color=self.style["color"], alpha=a)
        # the mark sits 6.4 triangle units below the bbox centre (source);
        # black inside the state-red fill stays black at any alpha
        k = TRI_H * s / 64.0
        marks.exclamation(cv, CENTER_X, CIRCLE_CY + 6.4 * k, 16 * k,
                          alpha=a, color=colors.BLACK)


status.register(ANIM, Tamper)
