"""PQ1 flow driver — walks a list of screen descriptions with the PQ1 motion.

Sim takes the screens as instance state (no module-level registry): build one
with any list of normalized screen dicts and call draw(now_ms) per frame.

Transitions are spring-driven (motion.Spring): every animated value — circle
position and radius, glyph/chevron morph, per-screen text alpha — moves from
its live pose toward the target and carries velocity. go_to() during a
transition therefore retargets instead of being dropped (DESIGN.md § Input:
presses are never dropped). go_to(back=True) enters a paged screen on its
last page — the driver's left tap, left undoes right (§ Input). Assigning `sim.cur = i` snaps to screen i with
no animation, for harnesses that start a render mid-flow.

Screen dicts are treated as frozen once handed to Sim: layouts, trail
palettes and token styles are resolved once at construction and shared
across frames. Mutate copies before constructing a Sim, never after.

The hold gesture (DESIGN.md § Input) is drawn here too: hold_begin /
hold_release / hold_commit take press edges from a driver (pq1.driver), and
the demo loop performs the hold itself through the last HOLD_COMMIT_MS of a
commit screen's dwell before an ending — the token disc fills from the
bottom up (components.hold_flood, inside the token drawing), the press
pulls a sweeping circle home, and the fill fades out over the transition.
Dwell lengths are untouched by it.
"""
import math
import os

from . import canvas, colors, components, motion, status
from .layout import layout_of
from .motion import (CHAIN_TAU, CHAIN_TAU_IDLE, DETAIL_DWELL, HERO_DWELL,
                     HOLD_COMMIT_MS, HOLD_SNAPBACK_MS, KIOSK, LEFT, OSC_TAU,
                     RIGHT, SWEEP_AMP, SWEEP_DELAY_MS, SWEEP_PERIOD_MS,
                     TEXT_IN_DELAY_MS, Spring, clamp01, lerp)


def _pulse_color(s, st):
    """ring colour for a screen's optional "pulse" field: an explicit
    [r, g, b] wins, True takes the token fill; None = no rings"""
    p = s.get("pulse")
    if not p:
        return None
    return tuple(p) if isinstance(p, (list, tuple)) else (st["fill"] or colors.WHITE)


class Sim:
    def __init__(self, screens, profile=KIOSK):
        self.screens = screens
        self.sx = Spring(0.0, **profile)
        self.sy = Spring(0.0, **profile)
        self.sr = Spring(0.0, **profile)
        self.mix = Spring(0.0, **profile)  # glyph/chevron morph: 0 -> a, 1 -> b
        self.alpha = [Spring(0.0, **profile) for _ in screens]  # text trails the circle
        self.text_in_at = None  # when the incoming screen's alpha is released (ms)
        self.idle_since = 0.0
        self.chain = None
        self.osc = 0.0
        self.osc_dir = -1
        self.last_now = 0.0
        self.loops = 0
        self._anims = {}  # idx -> StatusAnim, built lazily per status screen
        # status screens that own their canvas (a verdict sign, a PIN row —
        # status.rests_on_token False): leaving one, draw() fades the
        # screen out instead of morphing a token that was never there
        self._tokenless = [s["kind"] == "status" and not status.rests_on_token(s)
                           for s in screens]
        # per-screen pure-function results, resolved once (screens are frozen)
        self._layouts = [layout_of(s) for s in screens]
        self._nexts = [self._resolve_next(i) for i in range(len(screens))]
        self._trail_pals = [components.trail_palette_from_spec(s) for s in screens]
        self._tok_styles = [components.token_style_from_spec(s) for s in screens]
        self._pulse_cols = [_pulse_color(s, st)
                            for s, st in zip(screens, self._tok_styles)]
        # the hold gesture: each screen's fill dress (placement + colour) and
        # the hold the demo loop performs before leaving it; the live hold
        self._hold_styles = [components.hold_style(st) for st in self._tok_styles]
        self._hold_sides = [self._demo_hold_side(i) for i in range(len(screens))]
        self.hold = None  # dict(side, t0, t_rel, done, idx, mix_dir) while one lives
        # paged details (DESIGN.md § Text rules, Pages): pages per screen,
        # the page each one shows, and the flip in flight (frm, to, t0)
        self.page_count = [len(L["pages"]) if L.get("pages") else 1
                           for L in self._layouts]
        self.page = [0] * len(screens)
        self._flip = [None] * len(screens)
        self.cur = 0  # snaps springs onto screen 0

    def _resolve_next(self, i):
        """where the demo loop advances after screen i's dwell: the screen's
        "next" field (index, or id — first match scanning forward, so a
        repeated id resolves to the upcoming one), default the following
        screen. Unknown ids raise — no silent fallback."""
        nxt = self.screens[i].get("next")
        n = len(self.screens)
        if nxt is None:
            return (i + 1) % n
        if isinstance(nxt, int):
            return nxt % n
        for k in range(1, n + 1):
            j = (i + k) % n
            if self.screens[j]["id"] == nxt:
                return j
        raise ValueError(f"screen {self.screens[i]['id']!r}: "
                         f"next {nxt!r} matches no screen id")

    def _demo_hold_side(self, i):
        """the hold the demo loop performs before leaving screen i (DESIGN.md
        § Input): None unless the dwell leads into a status screen — an
        ending. LEFT (decline — armed on every navigable screen) when that
        ending is a cancel; RIGHT (sign) when it resolves done and hold-right
        is armed here ("commit" — normalize_screens arms the returning ask
        and the Confirm? screen). A done ending behind an unarmed screen
        keeps today's plain cut: the hold is never faked where it isn't armed."""
        s, nxt = self.screens[i], self.screens[self._nexts[i]]
        if s["kind"] == "status" or nxt.get("kind") != "status":
            return None
        if nxt.get("state", "done") != "done":
            return LEFT
        return RIGHT if s.get("commit") else None

    def _springs(self):
        return (self.sx, self.sy, self.sr, self.mix, *self.alpha)

    def _anim(self, idx):
        """the status animation bound to screen idx (cached)"""
        a = self._anims.get(idx)
        if a is None:
            spec = self.screens[idx]
            # after a token-less screen there is no token to hand off: a
            # spliced screen's handoff crossfade (screens.spec) is dropped
            # so nothing pops in at its t 0 — the wrap covers screen 0 of
            # a flow that opens on a PIN entry
            if (spec.get("handoff")
                    and self._tokenless[(idx - 1) % len(self.screens)]):
                spec = dict(spec, handoff=False)
            a = self._anims[idx] = status.anim_for(spec)
        return a

    def reset_anims(self):
        """forget the built animations (the driver's restart: an entry
        keeps the events typed into it, a fresh one starts empty)"""
        self._anims = {}

    @property
    def cur(self):
        return self._cur

    @cur.setter
    def cur(self, idx):
        """jump to a screen with no animation (harness entry points)"""
        idx %= len(self.screens)
        self._cur = idx
        self.a = self.b = idx
        c = self._layouts[idx]["circle"]
        for s, v in ((self.sx, c["cx"]), (self.sy, c["cy"]), (self.sr, c["r"])):
            s.value, s.target, s.velocity = v, v, 0.0
        self.mix.value = self.mix.target = self.mix.velocity = 0.0
        for i, sp in enumerate(self.alpha):
            sp.value = sp.target = 1.0 if i == idx else 0.0
            sp.velocity = 0.0
        self.text_in_at = None
        self.hold = None
        self.page = [0] * len(self.screens)
        self._flip = [None] * len(self.screens)
        self.settled = True

    def go_to(self, nxt, now, back=False):
        n = len(self.screens)
        nxt %= n
        if nxt == self._cur:
            return
        # retarget every spring from its live pose — presses are never dropped
        if nxt == self.a:            # reversing mid-flight: same endpoints, new goal
            self.mix.retarget(0.0)
        elif nxt == self.b:
            self.mix.retarget(1.0)
        else:                        # a fresh leg: rebase on the dominant endpoint
            self.a = self.b if self.mix.value >= 0.5 else self.a
            self.b = nxt
            self.mix.value = self.mix.velocity = 0.0
            self.mix.asleep = False  # poked off its target -> wake by hand
            self.mix.retarget(1.0)
        # a paged screen is entered on its first page unless the caller is
        # coming BACK into it (the driver's left tap, back=True): then on
        # its last page, so left undoes right (DESIGN.md § Input). Never
        # inferred from adjacency — a hub tap onto a one-screen section is
        # forward even when nxt == cur - 1
        self.page[nxt] = self.page_count[nxt] - 1 if back else 0
        self._flip[nxt] = None
        la = self._layouts[self._cur]["circle"]["cx"]
        c = self._layouts[nxt]["circle"]
        self.osc_dir = 1 if c["cx"] >= la else -1
        self._cur = nxt
        self.sx.retarget(c["cx"])
        self.sy.retarget(c["cy"])
        self.sr.retarget(c["r"])
        # outgoing text starts fading now; the incoming text is released
        # TEXT_IN_DELAY_MS later (draw() fires it) so the circle leads. A
        # retarget before then simply moves the pending release to the new goal.
        for i, sp in enumerate(self.alpha):
            if i != nxt:
                sp.retarget(0.0)
        self.text_in_at = now + TEXT_IN_DELAY_MS
        self.settled = False

    def flip_page(self, page, now):
        """turn the current screen — a paged detail — to `page`: the showing
        page fades away, then the new one fades in (motion.page_flip); the
        demo loop turns pages on the detail dwell, the driver on a tap"""
        i = self._cur
        page = max(0, min(self.page_count[i] - 1, page))
        if page == self.page[i]:
            return
        self._flip[i] = dict(frm=self.page[i], to=page, t0=now)
        self.page[i] = page

    # ------------------------------------------------------- the hold ----
    def hold_begin(self, side, now):
        """a hold press begins at `now` (press-down time); the first live
        hold wins — a second button pressed during it draws nothing"""
        if self.hold is None:
            self.hold = dict(side=side, t0=now, t_rel=None, done=False,
                             idx=self._cur, mix_dir=1.0)

    def hold_release(self, side, now):
        """the button came up before the hold committed: the fill snaps back
        over HOLD_SNAPBACK_MS (draw() drops it after); a release inside
        TAP_MAX_MS was a tap — nothing was drawn, so it clears at once"""
        h = self.hold
        if h is None or h["side"] != side or h["done"] or h["t_rel"] is not None:
            return
        if motion.hold_fill(now - h["t0"]) <= 0.0:
            self.hold = None
        else:
            h["t_rel"] = now

    def hold_commit(self, side, nxt, now):
        """the hold completed (HOLD_COMMIT_MS from press-down): go_to(nxt)
        with the full fill fading out over the leg. An instant hold — no prior
        hold_begin (play_flow --instant-holds) — shows the full fill too. A
        hold committing onto the screen it is on simply clears."""
        h = self.hold
        if h is None or h["side"] != side or h["done"] or h["t_rel"] is not None:
            self.hold = h = dict(side=side, t0=now - HOLD_COMMIT_MS, t_rel=None,
                                 done=False, idx=self._cur, mix_dir=1.0)
        if nxt % len(self.screens) == self._cur:
            self.hold = None
            return
        self.go_to(nxt, now)
        h["done"] = True
        h["mix_dir"] = self.mix.target   # which way the morph spring reads progress

    def _draw_pages(self, cv, i, al, now):
        """a paged detail's text: the label, the showing page — or, while a
        flip is in flight, the outgoing page fading away then the incoming
        one fading in (motion.page_flip) — and the pager n/m reading the
        page on screen, all under the screen's own alpha"""
        L = self._layouts[i]
        for t in L["fixed"]:
            components.draw_text(cv, t, al)
        page, f = self.page[i], self._flip[i]
        if f is not None:
            a_out, a_in = motion.page_flip(now - f["t0"])
            if a_out > 0.0:
                page = f["frm"]             # the pager reads the page still showing
                for t in L["pages"][page]:
                    components.draw_text(cv, t, al * a_out)
            else:
                for t in L["pages"][f["to"]]:
                    components.draw_text(cv, t, al * a_in)
                if a_in >= 1.0:
                    self._flip[i] = None    # landed: nothing left to blend
        else:
            for t in L["pages"][page]:
                components.draw_text(cv, t, al)
        components.pager(cv, page + 1, self.page_count[i], al)

    def _all_settled(self):
        return (self.text_in_at is None
                and self.sx.settled(0.5) and self.sy.settled(0.5)
                and self.sr.settled(0.5) and self.mix.settled(0.005)
                and all(a.settled(0.005) for a in self.alpha))

    def draw(self, now):
        # frame step; capped so a real-time hitch never teleports the springs
        # (100 ms still covers offline renders down to 10 fps at true speed)
        dt = min(100.0, now - self.last_now if self.last_now else 16.0)
        self.last_now = now

        h = self.hold
        if (h is not None and h["t_rel"] is not None
                and now - h["t_rel"] >= HOLD_SNAPBACK_MS):
            self.hold = None            # the snap-back has run: nothing left to draw

        if self.text_in_at is not None and now >= self.text_in_at:
            self.alpha[self._cur].retarget(1.0)   # release the incoming text
            self.text_in_at = None
        if not self.settled:  # settled => every spring at target, asleep
            for s in self._springs():
                s.step(dt)
            if self._all_settled():
                for s in self._springs():   # land exactly on the layout values
                    s.value, s.velocity = s.target, 0.0
                self.settled = True
                self.idle_since = now
                if self.hold is not None and self.hold["done"]:
                    self.hold = None    # the committed fill has faded with the leg
                if self._cur == 0:
                    self.loops += 1

        if self.settled:
            s = self.screens[self._cur]
            dwell = s.get("dwell")
            if dwell is None:  # status screens dwell for their animation
                dwell = (self._anim(self._cur).duration if s["kind"] == "status"
                         else motion.CONFIRM_DWELL if s["kind"] == "confirm"
                         else HERO_DWELL if s["kind"] == "hero"
                         else DETAIL_DWELL * self.page_count[self._cur])
            # a paged detail turns its pages on the demo clock: each page
            # holds one PAGE_SWAP_MS, the flip starting PAGE_FADE_MS before
            # the slot ends so the outgoing fade lands on the boundary (the
            # driver pins dwell to inf — there only a tap turns a page)
            if self.page_count[self._cur] > 1 and math.isfinite(dwell):
                k = min(self.page_count[self._cur] - 1,
                        int((now - self.idle_since + motion.PAGE_FADE_MS)
                            // motion.PAGE_SWAP_MS))
                if k > self.page[self._cur]:
                    self.flip_page(k, now)
            # the demo performs the hold through the dwell's last
            # HOLD_COMMIT_MS — the press backdated so the fill lands exactly
            # at dwell — then commits; dwell lengths (GIF durations) unchanged
            side = self._hold_sides[self._cur]
            if (side is not None and self.hold is None
                    and now - self.idle_since >= dwell - HOLD_COMMIT_MS):
                self.hold_begin(side, self.idle_since + dwell - HOLD_COMMIT_MS)
            if now - self.idle_since > dwell:
                if side is not None:
                    self.hold_commit(side, self._nexts[self._cur], now)
                else:
                    self.go_to(self._nexts[self._cur], now)

        cv = canvas.Canvas()
        cur_s = self.screens[self._cur]
        La, Lb = self._layouts[self.a], self._layouts[self.b]
        m = clamp01(self.mix.value)

        # leaving a token-less screen (a verdict, an entry — the endpoint
        # the morph moves away from): its resting frame fades to black on
        # the outgoing alpha spring — a fade, never a cut — under whatever
        # the next screen brings in; no token disc rides this transit
        # (status.rests_on_token; the token was never on that screen)
        out_idx = self.a if self.mix.target >= 0.5 else self.b
        leaving = not self.settled and self._tokenless[out_idx]
        if leaving:
            an = self._anim(out_idx)
            an.draw(cv, an.duration)
            cv.dim(1 - clamp01(self.alpha[out_idx].value))

        # chevrons -----------------------------------------------------------
        ca = components.chevron_angles(La["chev"])
        cb = components.chevron_angles(Lb["chev"])
        a_chev = lerp(1.0 if La["chev"] else 0.0, 1.0 if Lb["chev"] else 0.0, m)
        chev_y = 0.0
        hint_up = 0.0
        if self.settled and cur_s.get("hint"):
            hint_up, chev_y = motion.chevron_hint(now - self.idle_since)
        elif self.settled and cur_s["kind"] == "confirm":
            # up-pose chevrons point (bob) on the band's 5 s beat
            hint_up, chev_y = motion.chevron_hint(now - self.idle_since,
                                                  motion.BAND_SWAP_MS)
        ang_l = lerp(ca[0], cb[0], m)
        ang_r = lerp(ca[1], cb[1], m)
        ang_l += (0 - ang_l) * hint_up
        ang_r += (0 - ang_r) * hint_up
        components.chevron_pair(cv, ang_l, ang_r, chev_y, a_chev)

        # text ---------------------------------------------------------------
        for i, s in enumerate(self.screens):
            al = clamp01(self.alpha[i].value)
            if al > 0.01:
                if self._layouts[i].get("pages"):
                    self._draw_pages(cv, i, al, now)
                else:
                    for t in self._layouts[i]["texts"]:
                        components.draw_text(cv, t, al)
                    # a hero's position in a sequence of asks (a batch's
                    # transactions): the same n/m spot a paged detail uses,
                    # under the screen's own alpha so it crossfades with it —
                    # but static, never turned (layout "pager", flows/batch)
                    pg = self._layouts[i].get("pager")
                    if pg:
                        components.pager(cv, pg[0], pg[1], al)
                if s["kind"] == "confirm":
                    # band: OR VIEW MORE ▸ / ◂ TO GO BACK, swapping every 5 s
                    if self.settled and i == self._cur:
                        a_more, a_back = motion.confirm_band(now - self.idle_since)
                        components.confirm_band(cv, a_more, a_back, al)

        # circle position ----------------------------------------------------
        c = dict(cx=self.sx.value, cy=self.sy.value, r=self.sr.value)

        idle_t = max(0.0, now - self.idle_since - SWEEP_DELAY_MS)
        # a live hold pulls a sweeping circle home (the press recentres it)
        target = (self.osc_dir * math.sin(idle_t / SWEEP_PERIOD_MS * 2 * math.pi) * SWEEP_AMP
                  if (self.settled and self.hold is None
                      and cur_s.get("sweep", cur_s["kind"] == "hero")) else 0.0)
        self.osc = motion.tau_chase(self.osc, target, dt, OSC_TAU)
        c["cx"] += self.osc

        if self.settled and cur_s["kind"] == "status":
            self._anim(self._cur).draw(cv, now - self.idle_since)
            self.chain = None
            return cv.out()

        if leaving:
            # into another token-less screen: black until it starts; into
            # a screen that rests on the token (a hero, a detail, a film):
            # the token fades in with the incoming text, so the screen
            # opens on the disc it starts from
            self.chain = None
            if not self._tokenless[self._cur]:
                Lc = self._layouts[self._cur]["circle"]
                components.token_styled(cv, c["cx"], c["cy"], c["r"],
                                        self._tok_styles[self._cur],
                                        glyph_a=Lc["icon"], glyph_b=Lc["icon"],
                                        alpha=clamp01(self.alpha[self._cur].value))
            return cv.out()

        # follower chain -----------------------------------------------------
        if self.chain is None:
            self.chain = motion.FollowerChain(c["cx"], c["cy"])
        tau = CHAIN_TAU_IDLE if (self.settled and cur_s["kind"] == "hero") else CHAIN_TAU
        self.chain.step(c["cx"], c["cy"], dt, tau)
        bi = self.b if m >= 0.5 else self.a
        components.trail_chain(cv, self.chain, c["cx"], c["cy"], c["r"],
                               palette=self._trail_pals[bi])

        # pulse rings (screens flagged "pulse" — e.g. SAFE BLIND SIGN) --------
        for i, col in enumerate(self._pulse_cols):
            if col is not None:
                al = clamp01(self.alpha[i].value)
                if al > 0.01:
                    components.pulse(cv, c["cx"], c["cy"], c["r"], now, col, al)

        # the hold fill (DESIGN.md § Input): the disc filling from the bottom up
        hold = None
        h = self.hold
        if h is not None:
            k = motion.hold_fill(now - h["t0"],
                                 None if h["t_rel"] is None else h["t_rel"] - h["t0"])
            ha = 1.0
            if h["done"]:   # committed: the full fill fades out riding the morph spring
                ha = 1 - (m if h["mix_dir"] >= 0.5 else 1 - m)
            placement, col = self._hold_styles[h["idx"]]
            hold = dict(k=k, placement=placement, color=col, alpha=ha)
        components.token_styled(cv, c["cx"], c["cy"], c["r"], self._tok_styles[bi],
                                glyph_a=La["circle"]["icon"],
                                glyph_b=Lb["circle"]["icon"], mix=m, hold=hold)
        return cv.out()


def render_flow(screens, fps=30, loops=1, guard_s=180, profile=KIOSK):
    """render full passes of the flow; returns the frame list"""
    sim = Sim(screens, profile)
    step = 1000.0 / fps
    frames = []
    now = 0.0
    guard = int(fps * guard_s)
    while sim.loops < loops and len(frames) < guard:
        frames.append(sim.draw(now))
        now += step
    return frames


def save_gif(frames, out, fps, frames_dir=None):
    """save an animated GIF (and optionally per-frame PNGs for the panel)"""
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    step = 1000.0 / fps
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=int(step), loop=0, optimize=False)
    print(len(frames), "frames ->", out)
    if frames_dir:
        os.makedirs(frames_dir, exist_ok=True)
        # a shorter re-render must not leave the old tail behind: the panel
        # player plays every NNNN.png in the folder
        for name in os.listdir(frames_dir):
            stem, ext = os.path.splitext(name)
            if ext == ".png" and len(stem) == 4 and stem.isdigit():
                os.remove(os.path.join(frames_dir, name))
        for i, f in enumerate(frames):
            f.save(os.path.join(frames_dir, f"{i:04d}.png"))
        print("frames ->", frames_dir + "/")
