"""Firmware verified — a white disc arrives carrying a black check.

The reference verdict: default VerdictAnim phases, one icon, one caption.
"""
from pq1 import colors, status
from pq1.layout import CENTER_X, CIRCLE_CY, CIRCLE_R
from pq1.procedural import marks
from pq1.verdict import VerdictAnim

ANIM = "firmware_verified"
SPEC = dict(color=list(colors.WHITE), bottom="FIRMWARE VERIFIED")


class FirmwareVerified(VerdictAnim):
    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)
        r = CIRCLE_R * s
        col = tuple(int(round(c * a)) for c in self.style["color"])
        cv.circle(CENTER_X, CIRCLE_CY, r, col)
        marks.check(cv, CENTER_X, CIRCLE_CY, r, color=colors.BLACK)


status.register(ANIM, FirmwareVerified)
