"""Token idle — a solid token drifts on the idle sweep, its ramp trailing.

Ambient idle screen and the library's default demo: the token is a SOLID
disc wearing the first colour of one of the design-system gradients (the
ramp's fill stop — head + five followers spell the whole six-stop ramp,
brightest at the head, darkening away), with the send flow's white ETH
logo inside and the caption below; the right corner chevron nudges outward
on the hint envelope. No gradient disc here — that treatment stays
reserved for variant="unknown" tokens in real flows.

The ramp is deterministic per token — --ramp pins an index, --address /
--symbol hash to a stable ramp (address outranks symbol). Rendered bare,
build() picks a RANDOM ramp and prints it.

Stateful like batch_sign: the sweep chase and follower chain are physics,
so draw(cv, t) advances internal state from the last drawn t — call it
with monotonic t (the flow Sim does); a backwards seek resets and replays
from 0. The CLI renders through build()'s step_fn instead.
"""
import copy
import math
import random

from pq1 import canvas, components, gradients, motion, status
from pq1.layout import CENTER_X, CHEV_RIGHT, CIRCLE_CY, CIRCLE_R

ANIM = "unknown_token"
SPEC = dict(token={}, icon="eth", bottom="UNKNOWN TOKEN")

LOOP_MS = 5000          # one sweep cycle; --loops repeats it in the harness
STEP_MS = 1000.0 / 30   # physics chunk when draw() advances / replays


class UnknownToken(status.StatusAnim):
    previews = (2250, 3750)   # leftmost / rightmost sweep poses

    def __init__(self, spec):
        super().__init__(spec)
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
    ap.add_argument("--ramp", type=int, default=None, metavar="0-13",
                    help="pin a placeholder ramp index")
    ap.add_argument("--symbol", default=None,
                    help="token symbol — hashes to a stable ramp")
    ap.add_argument("--address", default=None,
                    help="contract address — hashes to a stable ramp "
                         "(outranks --symbol)")


def spec_from_args(args):
    """identity -> the matching token-spec key: --ramp pins a palette index;
    --symbol/--address ride the spec's hash keys (crc32 via token_ramp,
    address outranks symbol) — so a brand name typed here still hashes like
    any other ticker and can never pin a brand ramp"""
    tok = {}
    if getattr(args, "symbol", None):
        tok["symbol"] = args.symbol
    if getattr(args, "address", None):
        tok["address"] = args.address
    if getattr(args, "ramp", None) is not None:
        tok = {"palette": args.ramp}
    return {"token": tok} if tok else {}


def build(args, preset_overrides):
    """CLI path: one LOOP_MS sweep; step_fn owns the physics.

    Without an identity (--ramp/--symbol/--address or a preset palette) the
    ramp is picked at random — resolved HERE, before the anim exists, so
    every frame and --at seek of one render agrees."""
    spec = copy.deepcopy(SPEC)
    spec.update(preset_overrides)
    over = spec_from_args(args)
    spec["token"].update(over.get("token", {}))
    spec.setdefault("result", None)
    tok = spec["token"]
    if "palette" not in tok:
        tok["palette"] = random.randrange(len(gradients.PLACEHOLDER_GRADIENTS))
        print(f"ramp {tok['palette']} (random — pin with --ramp/"
              f"--symbol/--address)")
    anim = UnknownToken(spec)

    def frame(t):
        cv = canvas.Canvas()
        anim.render(cv)
        return cv.out()

    return frame, LOOP_MS, anim.step


status.register(ANIM, UnknownToken)
