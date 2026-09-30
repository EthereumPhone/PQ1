"""Slot registered — a white disc arrives carrying the black rotate mark.

The secure-boot verdict for a key slot the device has just registered
(audit HS-10): firmware_verified's construction — the white disc, the
firmware / neutral role (a sign takes a state colour or white, never a
per-context accent — audit COL-05) — carrying the slot-rotation flow's
mark (pq1.procedural.rotate, the two arrows chasing each other) in black
instead of the check. Default VerdictAnim phases, one icon, one caption;
no mechanism — the mark states a fact, it does not act one out.

The slot number is VARIABLE — the slot registered, never a digit fixed
into the string:

    screens.spec("slot_registered", bottom=slot_registered.caption(4))
"""
from pq1 import colors, status
from pq1.layout import CENTER_X, CIRCLE_CY, CIRCLE_R
from pq1.procedural import rotate
from pq1.verdict import VerdictAnim

ANIM = "slot_registered"


def caption(slot=0):
    """the caption for the slot registered"""
    return f"SLOT {slot} REGISTERED"


SPEC = dict(color=list(colors.WHITE), bottom=caption(0))


class SlotRegistered(VerdictAnim):
    def draw_icon(self, cv, t, u):
        a, s = self.entrance(u)
        r = CIRCLE_R * s
        col = tuple(int(round(c * a)) for c in self.style["color"])
        cv.circle(CENTER_X, CIRCLE_CY, r, col)
        # the flow token's own mark scale (rotate.MARK_SCALE), black on the
        # white fill stays black at any alpha — firmware_verified's check
        rotate.draw(cv, CENTER_X, CIRCLE_CY, r=rotate.MARK_SCALE * r,
                    color=colors.BLACK, alpha=a)


status.register(ANIM, SlotRegistered)
