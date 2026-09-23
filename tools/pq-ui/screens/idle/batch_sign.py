"""Batch sign — the teal token drifts on the idle sweep, trail following.

Ambient idle screen (port of batch_sign.py): a known teal token
(placeholder ramp 7, eth glyph) rides the idle sweep chased with the
shared tau easing, five followers trail it, the pager "n/total" sits top
centre, the caption names the batch and the right corner chevron nudges
outward on the hint envelope.

Stateful: the sweep chase and follower chain are physics, so draw(cv, t)
advances internal state from the last drawn t — call it with monotonic t
(the flow Sim does); a backwards seek resets and replays from 0. The CLI
renders through build()'s step_fn instead.
"""
import copy
import math

from pq1 import (canvas, colors, components, gradients, motion, status,
                 typography)
from pq1.layout import CENTER_X, CHEV_RIGHT, CIRCLE_CY, CIRCLE_R

ANIM = "batch_sign"
SPEC = dict(tx=1, total=5, token={"palette": gradients.TEAL_RAMP})

LOOP_MS = 5000          # one sweep cycle; --loops repeats it in the harness
STEP_MS = 1000.0 / 30   # physics chunk when draw() advances / replays


class BatchSign(status.StatusAnim):
    previews = (2250, 3750)   # leftmost / rightmost sweep poses

    def __init__(self, spec):
        super().__init__(spec)
        self.tx = int(spec.get("tx", 1))
        self.total = int(spec.get("total", 5))
        if not self.style["bottom"]:
            self.style["bottom"] = f"BATCH SIGN TX {self.tx} OF {self.total}"
        self.reset()

    @property
    def duration(self):
        return LOOP_MS

    def reset(self):
        self.t = 0.0
        self.osc = 0.0
        self.chain = motion.FollowerChain(CENTER_X, CIRCLE_CY)

    def step(self, dt):
        """advance the sweep chase and follower chain by dt ms"""
        while dt > 1e-6:
            d = min(dt, STEP_MS)
            dt -= d
            self.t += d
            idle_t = max(0.0, self.t - motion.SWEEP_DELAY_MS)
            target = -math.sin(idle_t / motion.SWEEP_PERIOD_MS
                               * 2 * math.pi) * motion.SWEEP_AMP
            self.osc = motion.tau_chase(self.osc, target, d,
                                        motion.OSC_TAU)
            self.chain.step(CENTER_X + self.osc, CIRCLE_CY, d,
                            motion.CHAIN_TAU_IDLE)

    def render(self, cv):
        """draw the current state (pure; step()/draw() advance it)"""
        st = self.style
        hx = CENTER_X + self.osc
        components.trail_chain(cv, self.chain, hx, CIRCLE_CY, CIRCLE_R,
                               st["trail"])
        components.token_from_spec(cv, hx, CIRCLE_CY, CIRCLE_R, self.spec,
                                   glyph_a=st["icon"])
        components.pager(cv, self.tx, self.total)   # the system's n/m spot
        components.caption(cv, st["bottom"])
        # hint bob pushed along the chevron's pointing direction (right)
        _, y_off = motion.chevron_hint(self.t)
        components.chevron(cv, CHEV_RIGHT[0] - y_off, CHEV_RIGHT[1],
                           math.pi / 2)

    def draw(self, cv, t):
        """monotonic t only — advances from the last drawn t; a backwards
        seek resets and replays from 0"""
        if t < self.t - 1e-6:
            self.reset()
        self.step(t - self.t)
        self.render(cv)


def add_args(ap):
    ap.add_argument("--tx", type=int, default=None, help="current tx in batch")
    ap.add_argument("--total", type=int, default=None,
                    help="tx count in batch")


def spec_from_args(args):
    d = {}
    if args.tx is not None:
        d["tx"] = args.tx
    if args.total is not None:
        d["total"] = args.total
    return d


def build(args, preset_overrides):
    """CLI path: one LOOP_MS sweep; step_fn owns the physics"""
    spec = copy.deepcopy(SPEC)
    spec.update(preset_overrides)
    spec.update(spec_from_args(args))
    spec.setdefault("result", None)
    anim = BatchSign(spec)

    def frame(t):
        cv = canvas.Canvas()
        anim.render(cv)
        return cv.out()

    return frame, LOOP_MS, anim.step


status.register(ANIM, BatchSign)
