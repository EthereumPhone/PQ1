"""PQ1 motion vocabulary — easing, timing and input-gesture constants, follower chain, chevron hint.

Screen-to-screen choreography lives in pq1.flow.Sim (and pq1.driver for
interactive playback); this module holds the shared
building blocks so every screen moves the same way.
"""
import math


# ---------------------------------------------------------------- easing ----
def clamp01(t):
    return max(0.0, min(1.0, t))


def ease(t):
    """cubic in-out"""
    return 4 * t * t * t if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


def ease_out(t):
    """cubic ease-out — press feedback, hold snap-back, scripted fades"""
    return 1 - (1 - t) ** 3


def back_out(t):
    c1 = 1.70158
    c3 = c1 + 1
    return 1 + c3 * (t - 1) ** 3 + c1 * (t - 1) ** 2


def lerp(a, b, t):
    return a + (b - a) * t


# ----------------------------------------------------------------- spring ---
class Spring:
    """Damped spring in Apple's designer parameterization.

    response — seconds; how quickly the value approaches the target (not a
    duration: the settle time emerges from the physics). damping — damping
    ratio; 1.0 = critically damped, no overshoot, the default for every UI
    value here (two buttons carry no momentum, so nothing should bounce).

    step() advances with the closed-form solution of the damped linear ODE
    over the frame's dt, so it is exact at any frame rate — the same
    dt-stepping idiom as FollowerChain.step. retarget() only moves the
    goalpost: position and velocity always carry over, which is what makes
    spring motion interruptible mid-flight.

    A landed spring (within SNAP_EPS of its target, velocity under SNAP_VEL)
    snaps exactly onto the target and sleeps: step() early-returns until
    retarget() moves the goal. Code that pokes .value/.target directly must
    leave them consistent (at target, zero velocity) or clear .asleep --
    retarget() handles this for you.
    """

    SNAP_EPS = 1e-3   # position snap tolerance (px or alpha units)
    SNAP_VEL = 1e-2   # velocity snap tolerance (units per second)

    def __init__(self, value=0.0, response=0.4, damping=1.0):
        self.value = float(value)
        self.velocity = 0.0  # units per second
        self.target = float(value)
        self.response = response
        self.damping = min(1.0, max(0.05, damping))  # overdamped never wanted in UI
        self.asleep = False

    def retarget(self, target):
        """move the goalpost; the live pose and velocity are kept"""
        t = float(target)
        if t != self.target:
            self.asleep = False  # a real goal change always wakes the spring
        self.target = t

    def settled(self, tol=0.5):
        return abs(self.value - self.target) < tol and abs(self.velocity) < tol * 10

    def step(self, dt_ms):
        if self.asleep:
            return self.value
        dt = dt_ms / 1000.0
        if dt <= 0:
            return self.value
        w = 2 * math.pi / self.response
        z = self.damping
        x = self.value - self.target
        v = self.velocity
        if z >= 1.0:  # critically damped: x(t) = (x0 + B t) e^{-wt}
            B = v + w * x
            e = math.exp(-w * dt)
            self.value = self.target + (x + B * dt) * e
            self.velocity = (B - w * (x + B * dt)) * e
        else:  # underdamped: decaying oscillation at wd
            wd = w * math.sqrt(1 - z * z)
            B = (v + z * w * x) / wd
            e = math.exp(-z * w * dt)
            c, s = math.cos(wd * dt), math.sin(wd * dt)
            self.value = self.target + e * (x * c + B * s)
            self.velocity = e * ((B * wd - z * w * x) * c - (x * wd + z * w * B) * s)
        if (abs(self.value - self.target) < self.SNAP_EPS
                and abs(self.velocity) < self.SNAP_VEL):
            self.value = self.target  # settle-snap: land exactly, then sleep
            self.velocity = 0.0
            self.asleep = True
        return self.value


# spring profiles — one pace per context for every transition value: circle
# travel/radius, glyph+chevron morph AND the per-screen text alpha crossfade
# (text arrives with the circle rather than popping in ahead of it)
NAV = dict(response=0.40, damping=1.0)    # hardware button pace (Apple "move")
KIOSK = dict(response=0.55, damping=1.0)  # demo-loop pace; the Sim default


def spring_travel(t_ms, profile=KIOSK):
    """progress 0 -> 1 of a critically damped spring released from rest at
    t = 0 — Spring.step's closed form, 1 - (1 + wt) e^-wt, as a pure function
    of t: a film's circle travels exactly like a flow transition's"""
    if t_ms <= 0:
        return 0.0
    wt = 2 * math.pi / profile["response"] * t_ms / 1000.0
    return 1.0 - (1.0 + wt) * math.exp(-wt)


ENTER_MS = 800  # a film's side entrance (off-panel -> centre) at KIOSK pace:
                # the ~274 px trip has settled to 0.3 px by here, then snaps


# ------------------------------------------------------------ timing (ms) ---
TEXT_IN_DELAY_MS = 150  # incoming text starts its alpha spring this long after
                        # the leg begins: the circle leads, the text lands just
                        # after it (outgoing text starts fading immediately)
FADE_MS = 180           # pre-spring serial fade; survives as a span estimate
MOVE_MS = 900           # pre-spring travel time; MOVE_MS + 2*FADE_MS still
                        # bounds a transition (springs settle well inside it)
HERO_DWELL = 5000       # hero screens idle time (one full sweep)
DETAIL_DWELL = 4100     # detail screens idle time
STATUS_DWELL = 8600     # the qubit status animation's duration (loading +
                        # resolve + hold); status screens now dwell for their
                        # own animation's duration — status.py asserts the
                        # film ("qubit", the done-ending default) still equals
                        # this documented value (the film-less cancel
                        # "resolve" dwells 2850 ms)

# -------------------------------------------------------------- input (ms) --
# Two-button gesture timing — spec'd in DESIGN.md § Input; consumed by the
# reference driver (pq1/driver.py, the bench player's grammar). Device
# firmware re-implements the grammar natively on-device from the same spec.
PRESS_FEEDBACK_MS = 120  # press-down acknowledgment nudge on the pressed-side chevron
TAP_MAX_MS = 250         # released under this = tap; held past it = hold begins
DOUBLE_TAP_MS = 250      # second press within this converts a tap (entry contexts only)
CHORD_MS = 150           # both buttons: a press on one side within this of the other
                         # side's press is the chord (ENTER on an entry)
HOLD_COMMIT_MS = 2000    # linear progress fill; the hold action fires ONLY at
                         # completion — releasing a moment earlier does nothing
HOLD_SNAPBACK_MS = 200   # ease-out snap-back when a hold is released early

LEFT, RIGHT = "left", "right"   # the two buttons (pq1.driver re-exports them)


def hold_fill(t_since_press, t_release=None):
    """Hold progress 0..1 — DESIGN.md § Input made code.

    Flat 0 until TAP_MAX_MS (a tap never flashes a partial arc — the fill's
    appearance IS the "this became a hold" signal), then linear to 1 at
    HOLD_COMMIT_MS from press-down, exactly when the hold action fires.
    t_release (ms since press at which the button came up, before commit)
    freezes the fill at its release value and snaps it back with ease_out
    over HOLD_SNAPBACK_MS. A pure function of time, so any frame is seekable.
    The visual is components.hold_flood; pq1.flow.Sim and the library's
    hold_to_confirm screen both draw through it."""
    def k_at(t):
        return clamp01((t - TAP_MAX_MS) / (HOLD_COMMIT_MS - TAP_MAX_MS))
    if t_release is None:
        return k_at(t_since_press)
    k = k_at(min(t_since_press, t_release))
    return k * (1 - ease_out(clamp01((t_since_press - t_release)
                                     / HOLD_SNAPBACK_MS)))


def hold_fill_ms(k):
    """inverse of hold_fill's rising edge: ms since press at which the fill
    reaches k (hold_fill_ms(1.0) == HOLD_COMMIT_MS)"""
    return TAP_MAX_MS + k * (HOLD_COMMIT_MS - TAP_MAX_MS)

# -------------------------------------------------------------- idle sweep --
SWEEP_DELAY_MS = 1000   # centred hold before the sweep starts
SWEEP_PERIOD_MS = 5000  # one full left-right cycle
SWEEP_AMP = 95          # sweep amplitude (px)
OSC_TAU = 180.0         # easing constant chasing the sweep target

# --------------------------------------------------------- follower chain ---
TRAIL_COUNT = 5         # follower circles in the streak chain
MAX_GAP = 30.0          # px cap between consecutive links
CHAIN_TAU = 60.0        # ms easing constant per link
CHAIN_TAU_IDLE = 150.0  # slower chase during the idle sweep -> more separation


def tau_k(dt_ms, tau_ms):
    """per-frame coefficient of the frame-rate-independent tau-chase"""
    return 1.0 - math.exp(-dt_ms / tau_ms)


def tau_chase(current, target, dt_ms, tau_ms):
    """one tau-chase step: move current toward target by 1 - exp(-dt/tau) --
    THE ambient-motion idiom (idle sweep, follower chain); DESIGN.md S Motion"""
    return current + (target - current) * tau_k(dt_ms, tau_ms)


class FollowerChain:
    """Eased chain of follower points trailing a moving head.

    Call step() once per frame with the head position; read .points
    (nearest-first) to draw the streak.
    """

    def __init__(self, x, y, count=TRAIL_COUNT, max_gap=MAX_GAP):
        self.points = [dict(x=x, y=y) for _ in range(count)]
        self.max_gap = max_gap

    def step(self, hx, hy, dt, tau=CHAIN_TAU):
        for p in self.points:  # at rest (head + links coincident)? skip it all
            if abs(p["x"] - hx) > 1e-3 or abs(p["y"] - hy) > 1e-3:
                break
        else:
            return
        k = tau_k(dt, tau)  # hoisted: one exp per call, not one per link
        gap = self.max_gap
        px, py = hx, hy
        for p in self.points:
            x = p["x"] + (px - p["x"]) * k
            y = p["y"] + (py - p["y"]) * k
            dx, dy = x - px, y - py
            if dx * dx + dy * dy > gap * gap:  # sqrt only when clamping
                d = math.hypot(dx, dy)
                x = px + dx / d * gap
                y = py + dy / d * gap
            p["x"], p["y"] = x, y
            px, py = x, y


# ---------------------------------------------------------- view-more hint --
BAND_SWAP_MS = 5000   # confirm band: each message holds this long
BAND_FADE_MS = 300    # ... and fades away / back in over this
CONFIRM_DWELL = 2 * BAND_SWAP_MS   # demo dwell: both band messages play


def confirm_band(idle_ms):
    """Confirm-screen band alternation -> (a_more, a_back): the "OR VIEW
    MORE" unit holds for BAND_SWAP_MS, fades away over BAND_FADE_MS, and
    "TO GO BACK" fades in for the next slot — a sequential swap every 5 s
    while the screen idles. Alphas multiply the screen's own alpha."""
    p = idle_ms % (2 * BAND_SWAP_MS)
    t = p % BAND_SWAP_MS
    a = (ease_out(clamp01(t / BAND_FADE_MS))
         * (1 - ease_out(clamp01((t - (BAND_SWAP_MS - BAND_FADE_MS))
                                 / BAND_FADE_MS))))
    return (a, 0.0) if p < BAND_SWAP_MS else (0.0, a)


# ------------------------------------------------------------- page flip --
PAGE_SWAP_MS = DETAIL_DWELL   # a paged detail: each page holds one detail dwell
PAGE_FADE_MS = BAND_FADE_MS   # ... the showing page fades away / the next in over this


def page_flip(t_ms):
    """Paged-detail swap envelope -> (a_out, a_in) for a flip that began
    t_ms ago (DESIGN.md § Motion, Page flip): the outgoing page fades away
    over PAGE_FADE_MS on the ease-out curve, THEN the incoming page fades
    in over the next PAGE_FADE_MS on the ease curve — a sequential swap on
    the confirm band's timing; the pager number switches between the two
    phases. Alphas multiply the screen's own alpha."""
    if t_ms < PAGE_FADE_MS:
        return 1.0 - ease_out(clamp01(t_ms / PAGE_FADE_MS)), 0.0
    return 0.0, ease(clamp01((t_ms - PAGE_FADE_MS) / PAGE_FADE_MS))


BUSY_PULSE_MS = 2000   # a loading caption breathes: one fade-in + fade-out a cycle


def busy_pulse(u):
    """the loading caption's breathing alpha over one cycle's unit progress
    u in [0, 1]: a raised cosine — dark at 0, full at 1/2, dark again at 1 —
    so the text fades in and out, slowly, for as long as the loading runs
    (status.StatusAnim.draw_busy fits whole cycles into the busy window;
    user rule, Sep 2026: text during a loading animation pulsates, and only
    once the circles are already going round)"""
    return 0.5 - 0.5 * math.cos(2 * math.pi * clamp01(u))


CHEV_HINT_PERIOD_MS = 3600   # hero hint cycle; confirm screens run the
                             # same envelope on the band beat (BAND_SWAP_MS)


def chevron_hint(idle_ms, period_ms=CHEV_HINT_PERIOD_MS):
    """Chevron hint envelope: (hint_up, y_offset).

    hint_up 0..1 rotates the corner chevrons toward "up"; y_offset bobs them
    while fully up. Starts 1.4 s into the idle and repeats every period_ms —
    3.6 s on hero screens; confirm screens pass BAND_SWAP_MS so the pointing
    gesture lands on the band's 5 s beat (their chevrons already rest up,
    so only the bob shows).
    """
    hint_up = 0.0
    y_off = 0.0
    if idle_ms > 1400:
        p = (idle_ms - 1400) % period_ms
        if p < 350:
            hint_up = ease(p / 350)
        elif p < 1550:
            hint_up = 1.0
            y_off = -4 * math.sin(math.pi * (p - 350) / 1200)
        elif p < 1900:
            hint_up = 1 - ease((p - 1550) / 350)
    return hint_up, y_off


# ------------------------------------------------------------ accent curves --
# One-shot expressive curves for verdict/notice screens (screens/ library).
# All are pure functions of normalized progress t in [0, 1] (clamp before
# calling). One overshoot is sanctioned in PQ1 — back_out (the status
# flash pop), a celebration, never navigation. The verdict icon ENTRANCE
# never overshoots: it fades in and rises 0.97 -> 1 (arrive), both
# ease_out, within ARRIVE_MS (user rule, Sep 2026).

ARRIVE_MS = 300      # the verdict sign's entrance (fade + arrive) — never longer
ARRIVE_FROM = 0.97   # the entrance scale starts here and settles on 1.0


def arrive(t):
    """verdict icon entrance scale — a near-rest rise ARRIVE_FROM -> 1 on
    ease_out; pair it with an ease_out fade (VerdictAnim.entrance)"""
    return lerp(ARRIVE_FROM, 1.0, ease_out(t))


def pop(t):
    """springy overshoot with one designed wobble — an opt-in celebration
    accent, no longer any entrance (the verdict sign arrives, above)"""
    return 1 - math.exp(-5 * t) * math.cos(2.2 * math.pi * t)


def attention_pulse(t):
    """decaying scale pulse (1.0-centred) — draws the eye to a settled icon"""
    return 1 + 0.09 * math.exp(-3 * t) * abs(math.sin(2.5 * math.pi * t))


def heartbeat(t, pumps=3.0, amp=0.22, decay=4.0):
    """decaying pump train (1.0-centred) — last-attempt heart"""
    return 1 + amp * math.exp(-decay * t) * abs(math.sin(pumps * math.pi * t))


def shake(t, cycles=2.5):
    """decaying error shake, unit amplitude — multiply by the px excursion"""
    return math.sin(2 * math.pi * cycles * t) * (1 - t)


def wobble(t, decay=3.0):
    """decaying settle oscillation, unit amplitude"""
    return math.exp(-decay * t) * math.sin(2 * math.pi * t)


def recoil(t):
    """mechanical click recoil, unit amplitude — rises and dies within t"""
    return math.sin(math.pi * t) * (1 - t)


def freewheel(t, k=4.2):
    """coasting spin-down: fast start, exponential decay to a stop at t=1"""
    return (1 - math.exp(-k * t)) / (1 - math.exp(-k))


def decel(t, p=2.6):
    """simple power deceleration 1-(1-t)^p — tumbles, reels, ring growth"""
    return 1 - (1 - t) ** p


# every one-shot accent phase (ring stagger, click, bounce) must span at
# least this long — two panel frames at the NV3007's 14 fps
VERDICT_ACCENT_MIN_MS = 145
