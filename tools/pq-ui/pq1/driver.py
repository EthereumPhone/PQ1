"""PQ1 flow driver — the reference implementation of DESIGN.md § Input.

FlowDriver walks a flow's normalized screens under the two-button grammar.
The ask is the hub: on a hero either tap enters the details at their
first screen, first page (an intro leads on to the ask, and the ask never
regresses to it); inside the details left regresses, right progresses —
taps navigate, holds commit. A batch (flows/batch) is a run of SEGMENTS,
each closed by its own ending (layout._segments): every segment's BATCH
screen is that segment's hub, hold-right signs the segment's own ending,
and a mid-batch ending plays through and moves on to the next segment —
the decline ending is reachable from every segment. On a paged
detail (DESIGN.md § Text rules, Pages) a tap turns the page first: right
tap the next page until the last, then the next screen; left tap the
previous page until the first, then the previous screen (which is
entered on its last page — left undoes right). It consumes
the gesture constants in motion.py (TAP_MAX_MS, HOLD_COMMIT_MS, ...) and
drives Sim.go_to from press/release edges, so input during a transition
retargets from the live pose — presses are never dropped. Auto-advance is
neutralized (every screen's dwell pinned to inf on copies before the Sim is
built): nothing moves without a press, exactly as on hardware.

This is a bench / design-review tool — the NV3007 harness
(tools/panel/play_flow.py) feeds it keyboard edges so the grammar can be felt on real
glass before firmware exists. Production firmware implements the same
grammar natively on-device and will probably NOT run this code; when the
two disagree, DESIGN.md § Input is the contract.

The hold's progress fill is drawn by the Sim (components.hold_flood — the
token filling from the bottom up): press() starts it where the gesture is
armed, an early release() snaps it back, and the commit fades it out over
the transition. Not simulated yet (spec-only in
the renderer): the 120 ms pressed-side chevron nudge (PRESS_FEEDBACK_MS).
"""
import copy

from . import layout, motion, status
from .flow import Sim
from .motion import LEFT, RIGHT  # noqa: F401  (the button names live with the gestures)


class FlowDriver:
    """Input-driven walk of one flow: taps navigate the pass (either tap on
    an ask enters the details — _hub_target), hold-left
    declines from any navigable screen, hold-right signs where "commit" is
    armed. sign/decline are indices of the two terminal status screens
    (flows.playable builds a list carrying both); decline may be None for
    a flow that declares no failing ending."""

    def __init__(self, screens, sign=None, decline=None, profile=motion.NAV):
        scr = copy.deepcopy(list(screens))
        # an ENTRY (a PIN row — status.is_interactive) is navigable: it is
        # typed into, live, under the § Input entry grammar; "live" tells
        # the animation to start empty instead of dialing its demo digits
        self._entry = [s.get("kind") == "status" and status.is_interactive(s)
                       for s in scr]
        for i, s in enumerate(scr):     # the driver advances, never the dwell
            s["dwell"] = float("inf")
            if self._entry[i]:
                s["live"] = True
        statuses = [i for i, s in enumerate(scr)
                    if s.get("kind") == "status" and not self._entry[i]]
        nav = [i for i, s in enumerate(scr)
               if s.get("kind") != "status" or self._entry[i]]
        if not nav or (statuses and statuses[0] < nav[0]):
            raise ValueError("the driver needs at least one navigable screen "
                             "(a hero, a detail, an entry) ahead of a status "
                             "ending")
        self.screens = scr
        self.sign = (statuses[0] if statuses else None) if sign is None else sign
        if decline is None:
            fails = [i for i in statuses
                     if scr[i].get("state", "done") != "done"]
            decline = fails[0] if fails else None
        self.decline = decline
        # the segments: (start, closing status) per transaction — one for
        # an ordinary flow, one per transaction of a batch (layout._segments);
        # last_nav / section_start / the sign target read the CURRENT one
        self._segments = layout._segments(scr)
        self.sim = Sim(scr, profile)
        self._press = {LEFT: None, RIGHT: None}    # side -> press-down ms
        self._hold_fired = {LEFT: False, RIGHT: False}
        self._last_tap = {LEFT: None, RIGHT: None}  # entry: when a tap last fired
        self._consumed = {LEFT: False, RIGHT: False}  # entry: a press already spent
        self._final = None                  # frozen frame once an ending rests

    # ------------------------------------------------------------- state --
    @property
    def state(self):
        """"navigating" on the pass, "resolving" while an ending plays,
        "finished" once it rests"""
        i = self.sim.cur
        if self.screens[i].get("kind") != "status":
            return "navigating"
        if not self.sim.settled:
            return "resolving"
        t = self.sim.last_now - self.sim.idle_since
        if self._entry[i]:
            # an entry: open (typing) until it has an outcome, then its
            # verdict tail plays, then the driver routes (frame)
            an = self.sim._anim(i)
            if an.outcome is None:
                return "navigating"
            return "finished" if an.finished(t) else "resolving"
        return "finished" if t > self.sim._anim(i).duration else "resolving"

    def _t(self, now=None):
        """anim time on the current screen (the entry's event clock)"""
        now = self.sim.last_now if now is None else now
        return now - self.sim.idle_since

    def _anim(self):
        return self.sim._anim(self.sim.cur)

    def armed(self):
        """gestures live on the current screen (§ Input: declining is always
        cheap; signing only where "commit" is flagged; status screens are
        input-dead)"""
        i = self.sim.cur
        if self._entry[i]:
            if self.state != "navigating":
                return set()
            an, t = self._anim(), self._t()
            out = {"inc", "dec", "enter", "cancel"}     # the 8th enter submits
            if an.can_move(RIGHT, t):
                out.add("next")
            if an.can_move(LEFT, t):
                out.add("back")
            return out
        if self.screens[i].get("kind") == "status":
            return set()
        out = {"decline"} if self.decline is not None else set()
        if self.screens[i].get("kind") == "hero":
            if self._hub_target(i) is not None:
                out |= {"back", "forward"}      # either tap enters the details
        else:
            page, last = self._paged()
            if i > 0 or page > 0:
                out.add("back")
            if i < self.last_nav or page < last:
                out.add("forward")
        if self.screens[i].get("commit"):
            out.add("sign")
        return out

    def _segment(self, i):
        """the (start, stop) segment holding screen i — stop is the status
        that closes it (a closing status belongs to its own segment); None
        for a screen in no segment (the appended decline ending)"""
        for a, b in self._segments:
            if a <= i <= b:
                return a, b
        return None

    @property
    def last_nav(self):
        """the current segment's last navigable screen — the one before
        its closing status: the pass ends where the ending begins"""
        seg = self._segment(self.sim.cur)
        return seg[1] - 1 if seg else self.sim.cur

    @property
    def section_start(self):
        """the current segment's detail section: its first screen that is
        not an ask (DESIGN.md § Input, "The ask is the hub"); None when the
        segment is a hero + its ending only"""
        seg = self._segment(self.sim.cur)
        if seg is None:
            return None
        return next((k for k in range(seg[0], seg[1])
                     if self.screens[k].get("kind") in ("detail", "value", "confirm")),
                    None)

    def _paged(self):
        """(page, last page) of the current screen — (0, 0) unpaged"""
        i = self.sim.cur
        return self.sim.page[i], self.sim.page_count[i] - 1

    def status_line(self):
        i, s = self.sim.cur, self.screens[self.sim.cur]
        page, last = self._paged()
        paged = f" p{page + 1}/{last + 1}" if last else ""
        marks = {"back": "<-tap", "forward": "tap->",
                 "sign": "hold-R sign", "decline": "hold-L decline",
                 "dec": "tap-L −", "inc": "tap-R +", "enter": "both enter",
                 "next": "2x-R next", "cancel": "hold-L cancel"}
        if self._entry[i]:
            marks["back"] = "2x-L back"
        armed = "  ".join(marks[a] for a in
                          ("back", "forward", "sign", "decline", "dec", "inc",
                           "enter", "next", "cancel")
                          if a in self.armed()) or "none"
        kind = s.get("kind")
        if self._entry[i]:
            an = self._anim()
            typed = an.digits(self._t()).ljust(8, "_")
            kind = f"entry {typed}" + (f" · {an.outcome}" if an.outcome else "")
        line = (f"[{i + 1}/{len(self.screens)}] {s.get('id')}{paged} "
                f"({kind}) · {self.state} · input: {armed}")
        h = self.sim.hold
        if h is not None and not h["done"] and h["t_rel"] is None:
            k = motion.hold_fill(self.sim.last_now - h["t0"])
            line += f" · holding {'R' if h['side'] == RIGHT else 'L'} {k:.0%}"
        return line

    # ------------------------------------------------------------- input --
    def press(self, side, now):
        """a button went down (ms clock shared with frame())"""
        if self.state != "navigating":      # endings accept no input
            return None
        if self._entry[self.sim.cur]:
            return self._entry_press(side, now)
        if self._press[side] is None:
            self._press[side] = now
            self._hold_fired[side] = False
            # the fill draws only where the hold is ARMED (§ Input: decline
            # everywhere, sign where "commit"); an unarmed side stays dark
            if {LEFT: "decline", RIGHT: "sign"}[side] in self.armed():
                self.sim.hold_begin(side, now)
        return None

    def release(self, side, now):
        """the button came up: under TAP_MAX_MS it was a tap; past it and
        before the hold committed, the hold snaps back and does nothing"""
        if self._entry[self.sim.cur]:
            return self._entry_release(side, now)
        self.sim.hold_release(side, now)
        t0, fired = self._press[side], self._hold_fired[side]
        self._press[side] = None
        self._hold_fired[side] = False
        if t0 is None or fired or self.state != "navigating":
            return None
        if now - t0 <= motion.TAP_MAX_MS:
            return self._tap(side, now)
        return "snapback"

    def hold(self, side, now):
        """fire the full hold gesture at once (harnesses without key
        release edges — play_flow --instant-holds)"""
        return self._hold(side, now)

    def double_tap(self, side, now):
        """the double press alone (the bench's explicit D / A keys): on an
        entry the cursor moves — right NEXT forward over entered digits,
        left BACK to the previous one; a dial is never taken away"""
        if self.state != "navigating" or not self._entry[self.sim.cur]:
            return None
        act = "next" if side == RIGHT else "back"
        self._anim().input(act, self._t(now))
        self._last_tap[side] = None
        return act

    def enter(self, now):
        """both buttons at once (the bench's space / e key): on an entry,
        ENTER the digit"""
        if self.state != "navigating" or not self._entry[self.sim.cur]:
            return None
        self._last_tap = {LEFT: None, RIGHT: None}
        return self._enter(self._anim(), self._t(now))

    def _enter(self, an, t):
        """ENTER the active digit; the one that completes the row SUBMITS
        it — the PIN is checked at once, no hold (user decision, Sep 2026).
        Every ENTER goes through here: the chord and the bench key alike"""
        an.input("enter", t)
        if an.complete(t):
            an.input("submit", t)
            return "submit"
        return "enter"

    def restart(self, now):
        """back to the opening screen, springs snapped (post-ending); the
        built animations are dropped so an entry starts empty again"""
        self._press = {LEFT: None, RIGHT: None}
        self._hold_fired = {LEFT: False, RIGHT: False}
        self._last_tap = {LEFT: None, RIGHT: None}
        self._consumed = {LEFT: False, RIGHT: False}
        self._final = None
        self.sim.reset_anims()
        self.sim.cur = 0
        self.sim.chain = None
        self.sim.osc = 0.0
        self.sim.idle_since = now
        self.sim.last_now = now
        return "restart"

    def _hub_target(self, i):
        """where a tap on EITHER side lands from hero i (DESIGN.md § Input,
        "The ask is the hub"): the ask when the next screen is one (the
        ERC-7730 intro), else the section's first screen; None when i is
        not a hero or the flow has no section (hero + endings only)"""
        if self.screens[i].get("kind") != "hero":
            return None
        if i < self.last_nav and self.screens[i + 1].get("kind") == "hero":
            return i + 1                    # an intro leads on to the ask
        return self.section_start

    def _tap(self, side, now):
        i = self.sim.cur
        if self.screens[i].get("kind") == "hero":
            hub = self._hub_target(i)       # the ask is the hub: either tap enters
            if hub is None:
                return None                 # no section (hero + endings only)
            self.sim.go_to(hub, now)        # ... always on its first page
            return "enter"
        page, last = self._paged()
        if side == RIGHT:
            if page < last:                 # a paged detail: the next page first
                self.sim.flip_page(page + 1, now)
                return "page"
            if i < self.last_nav:
                self.sim.go_to(i + 1, now)
                return "forward"
        elif page > 0:                      # ... and the previous page back
            self.sim.flip_page(page - 1, now)
            return "page"
        elif i > 0:
            self.sim.go_to(i - 1, now, back=True)   # left undoes right: last page
            return "back"
        return None

    # ------------------------------------------------------- the entry --
    def _entry_press(self, side, now):
        """a press on an entry (DESIGN.md § Input). BOTH buttons — the other
        side still down, or tapped within CHORD_MS — is the chord: ENTER the
        digit (a tap the other button already fired is undone, its hold
        clock stopped). A second press on one side within DOUBLE_TAP_MS of
        its last tap is the double press: the cursor moves (right NEXT over
        entered digits, left BACK) and that tap is undone — only where the
        cursor CAN move, so a fast run of taps on a fresh slot always
        dials. The chord that enters the 8th digit SUBMITS the row: the
        PIN is checked at once, no hold (user decision, Sep 2026).
        Otherwise the hold clock starts; only the left hold fills the row
        (cancel) — the right hold is unbound on an entry."""
        an, t = self._anim(), self._t(now)
        other = LEFT if side == RIGHT else RIGHT
        last_other = self._last_tap[other]
        if self._press[other] is not None:      # the other button is down
            an.input("release", t)              # its hold clock stops here
            self._press[other] = None
            self._hold_fired[other] = False
            self._consumed[other] = True        # its release is spent
            chord = True
        elif last_other is not None and now - last_other <= motion.CHORD_MS:
            an.undo_last_tick()                 # its tap was the chord's first half
            chord = True
        else:
            chord = False
        if chord:
            self._last_tap = {LEFT: None, RIGHT: None}
            self._consumed[side] = True
            return self._enter(an, t)       # the 8th digit: checked at once
        last = self._last_tap[side]
        if (last is not None and now - last <= motion.DOUBLE_TAP_MS
                and an.can_move(side, t)):
            an.undo_last_tick()
            act = "next" if side == RIGHT else "back"
            an.input(act, t)
            self._last_tap[side] = None
            self._consumed[side] = True     # its release is not another tap
            return act
        if self._press[side] is None:
            self._press[side] = now
            self._hold_fired[side] = False
            an.input("hold", t, side)       # flat until TAP_MAX_MS (hold_fill)
        return None

    def _entry_release(self, side, now):
        """the release on an entry: a tap ticks the digit (+1 right, −1
        left) and is remembered for the double-tap conversion; an early
        release drains the fill"""
        t0, fired = self._press[side], self._hold_fired[side]
        self._press[side] = None
        self._hold_fired[side] = False
        if self._consumed[side]:
            self._consumed[side] = False
            if t0 is not None:              # a press that became a double press
                self._anim().input("release", self._t(now))
            return None
        if t0 is None or fired or self.state != "navigating":
            return None
        an, t = self._anim(), self._t(now)
        an.input("release", t)
        if now - t0 <= motion.TAP_MAX_MS:
            # the digit lands when the double-tap window closes (the ring
            # bounces now): a converting second press takes the tap back
            # before it ever shows
            an.input("tap", t, 1 if side == RIGHT else -1)
            self._last_tap[side] = now
            return "tick"
        return "snapback"

    def _entry_hold(self, side, now):
        """the hold fired on an entry: left cancels the open row (the row
        fades; frame() routes the outcome); the right hold is unbound — the
        8th enter submits (user decision, Sep 2026)"""
        an, t = self._anim(), self._t(now)
        if side == RIGHT or an.complete(t):
            return None
        an.input("cancel", t)
        return "cancel"

    def _after_entry(self, i, now):
        """where the driver goes once an entry's outcome has played: a
        miss retries on the next attempt (the following entry) or, with
        none left, rests on the verdict (None); a match continues to the
        first screen after the attempts, else rests; a cancel returns to
        the ask before the entry, else opens a fresh round here (i)"""
        oc, n = self.sim._anim(i).outcome, len(self.screens)
        if oc == "miss":
            return i + 1 if i + 1 < n and self._entry[i + 1] else None
        if oc == "match":
            return next((j for j in range(i + 1, n) if not self._entry[j]), None)
        prev = next((j for j in range(i - 1, -1, -1)
                     if self.screens[j].get("kind") != "status"), None)
        if prev is None:
            self.sim._anim(i).input("restart", self._t(now))
            return i
        return prev

    def _hold(self, side, now):
        if self.state != "navigating":
            return None
        if self._entry[self.sim.cur]:
            return self._entry_hold(side, now)
        if side == LEFT:                    # decline: armed everywhere
            if self.decline is not None:
                self._go_end(side, self.decline, now)
                return "decline"
        elif self.screens[self.sim.cur].get("commit"):
            seg = self._segment(self.sim.cur)     # sign: only where armed —
            self._go_end(side, seg[1] if seg else self.sign, now)   # the segment's ending
            return "sign"
        return None

    def _go_end(self, side, idx, now):
        self._press = {LEFT: None, RIGHT: None}
        self._fresh(idx)
        self.sim.hold_commit(side, idx, now)   # the full fill fades over the leg

    def _fresh(self, idx):
        """an entry is empty on every visit: its built animation (the
        events typed last time) is dropped on ARRIVAL — never on leaving,
        so the transit still fades the frame it rests on"""
        if self._entry[idx]:
            self.sim._anims.pop(idx, None)

    def _go(self, nxt, now):
        self._fresh(nxt)
        self.sim.go_to(nxt, now)

    # ------------------------------------------------------------- frame --
    def frame(self, now):
        """time-step the grammar (pending holds commit at HOLD_COMMIT_MS)
        and render; a finished ending freezes on its resting frame — unless
        a segment follows it (a mid-batch ending): then the player moves
        on to that segment's first screen, the demo's own advance"""
        for side, t0 in self._press.items():
            if (t0 is not None and not self._hold_fired[side]
                    and now - t0 >= motion.HOLD_COMMIT_MS):
                self._hold_fired[side] = True
                self._hold(side, now)
        if self._final is not None:
            self.sim.last_now = now         # keep the clock honest
            return self._final
        im = self.sim.draw(now)
        if self.state == "finished":
            i = self.sim.cur
            if self._entry[i]:
                nxt = self._after_entry(i, now)
                if nxt is None:
                    self._final = im
                elif nxt != i:
                    self._go(nxt, now)
                return im
            nxt = i + 1
            if any(a == nxt for a, _ in self._segments):   # a mid-batch ending
                self.sim.go_to(nxt, now)                    # on to the next segment
            else:
                self._final = im
        return im
