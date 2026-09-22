"""PQ1 verdict screens — an icon delivers the outcome, the caption names it.

A verdict is a status-kind screen whose animation draws a procedural icon
(pq1.procedural) instead of the resting token: the icon arrives on the
circle grid (cx 214, cy 72), the caption fades onto the y 128 baseline,
then the screen rests. Use a *status* screen when the device did work and
shows that work resolving (token loads -> result); use a *verdict* when the
device is stating a fact — LOCKED, BACKUP OK, WALLET WIPED, LAST ATTEMPT.

Timing contract (same law as every status anim):

    t_resolve = T_HOLD + T_IN + T_WAIT + T_TEXT     (1450 by default)
    duration  = t_resolve + status.RESULT_HOLD_MS

Entrance law (user rule, Sep 2026): the icon fades in and rises 0.97 -> 1,
both ease_out, within motion.ARRIVE_MS (300) — entrance() below, never an
overshoot. A mechanism (a turn, a tumble, a coast) plays on the arrived icon.

Concrete verdicts live in screens/verdict/ and self-register via
status.register, so flows splice them as dict(kind="status", anim=...).
A verdict may be LED by a film that ends on an empty canvas — the spec's
"lead" (status.LedAnim): WALLET WIPED after the major explosion, the
verdict's T_HOLD running under the blast's fading rings.
"""
from . import status
from .motion import ARRIVE_MS, arrive, clamp01, ease_out


class VerdictAnim(status.StatusAnim):
    """Base choreography: hold -> icon arrives -> beat -> caption -> rest.

    Subclasses implement draw_icon(cv, t, u); u is the raw entrance
    progress in [0, 1] — apply entrance() (or your own accent curves) to
    it per channel. Override the T_* phase lengths for longer mechanisms
    (a gear spin-down, a die tumble); t_resolve and duration follow. The
    sign's own fade + rise stays within ARRIVE_MS whatever the window.
    """

    rests_on_token = False   # the sign owns the canvas: Sim fades it out,
                             # no token disc rides the transit (status.py)
    T_HOLD = 400    # black hold / handoff crossfade
    T_IN = ARRIVE_MS   # icon entrance: fade + arrive — 300, the law's maximum
    T_WAIT = 450    # beat before the caption
    T_TEXT = 300    # caption fade (status.BUSY_FADE_MS pace, ease-out)

    @property
    def t_resolve(self):
        return self.T_HOLD + self.T_IN + self.T_WAIT + self.T_TEXT

    @property
    def previews(self):
        return (self.T_HOLD + self.T_IN // 2, self.duration - 600)

    def entrance(self, u):
        """(alpha, scale) for the icon entrance: ease_out fade, ease_out rise
        0.97 -> 1 (motion.arrive) — the entrance law, never an overshoot"""
        return ease_out(u), arrive(u)

    def draw_icon(self, cv, t, u):
        raise NotImplementedError

    def draw_handoff(self, cv, t):
        """flow splicing: with spec handoff=True the resting token Sim was
        drawing crossfades out over T_HOLD instead of popping to black"""
        status.draw_handoff(cv, self.spec, self.style, t, self.T_HOLD)

    def draw(self, cv, t):
        self.draw_handoff(cv, t)
        u = clamp01((t - self.T_HOLD) / self.T_IN)
        if u > 0.001:
            self.draw_icon(cv, t, u)
        ta = ease_out(clamp01((t - (self.T_HOLD + self.T_IN + self.T_WAIT))
                              / self.T_TEXT))
        self.draw_caption(cv, ta)
        self.draw_busy(cv, t)
