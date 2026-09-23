{{doc-self}}

## Timeline

Three acts: the **loading leg** (the qubit film's, borrowed whole), the **clump**, the **blast**. `t` is milliseconds since the screen's own t 0; `burst.draw` ({{loc:pq1.procedural.burst.draw}}) is pure in `t`, so any frame is seekable.

The loading leg is not a copy — it *is* `loading.qubit_pose` on a stock `QubitCfg`, so every phase of it is the one documented on [status — the qubit film](../screen-types/status-qubit.md). One difference matters: the explosion **cuts away at the end of the spiral**. The qubit film's flash ({{tok:qubit:T_FLASH}}) never plays here; the clump takes its place.

**`major` — the default, and the `major_explosion` preset.**

{{motion-head}}
{{row:seed: the flow's circle becomes one qubit | qubit:T_SEED | ease_out | shrinks to {{val:qubit:r_q}} at x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}} — the centre comes from `cfg.qubit.gc`, not from the layout. A side entrance slides a full-size body in first and the seed then runs in place; `enter="sides"` never reaches it}}
{{row:split: two qubits part | qubit:T_SPLIT | ease | reach 0 to {{val:qubit:split_x}} px, both halves already at {{val:qubit:r_q}}, goo bridge while they overlap. A flow's glyph hands off over the SEED, before this}}
{{row:join: the pair swings onto the orbit | qubit:T_JOIN | linear | hand-rolled: the reach falls to the orbit radius {{val:qubit:orbit_r}} on a smoothstep of linear progress}}
{{row:spin-up ramp — runs INSIDE the join | qubit:T_RAMP | linear | angular speed rises from rest to orbit speed. Not a phase of its own: do not add it to the timeline}}
{{row:steady orbit — THE LOOP REGION | qubit:T_SPIN | linear | whole turns of {{tok:qubit:rev_ms}}. `revs` lengthens ONLY this row — the entrance, the spin speed and the spiral are untouched. On the device it repeats, whole turns at a time, until the host answers — the region starts where the pair is on the orbit (a sides entrance lands later than the stock join) — [loading loop](../transitions/loading-loop.md)}}
{{row:spiral: the pair falls to the centre | qubit:T_SPIRAL | linear | hand-rolled: radius shrinks with the square of progress, plus 2.2 extra turns on its cube}}
{{row:the cut: the loading leg ends | qubit:t6 | cut | measured from the leg's own t 0. The spiral leaves two bodies of r 17 on the centre and the clump opens at r 22 — one frame of growth, by design}}
{{row:clump: trembles, shakes harder, squashes, shifts colour | burst:MAJOR.t_clump | ease | a 48-point near-circle. Radius 22 px falls by the `squeeze` fraction on `ease`; the shake amplitude and the edge tremble both rise LINEARLY in progress, `clump_from` to `clump_to` on `ease`}}
{{row:core flash bloom — fades over `MAJOR.bloom` first element | - | linear | a filled disc from r 6, growing by the pair's second element in px, its colour scaled 1 to 0. Both numbers are in the Constants table; they are never re-typed here}}
{{row:ring i launches, i after i | burst:MAJOR.stagger_ms | cut | ring `i` starts this much times `i` after the boom. The stagger is one number for both severities — the two sources' own staggers were each shorter than two panel frames, so the panel could not have told them apart}}
{{row:one ring's flight | burst:MAJOR.t_boom | linear | hand-rolled ease-out: reach = 1 minus (1 minus u) to the power `grow_p`. An ellipse of `aspect` ry to rx, stroke and reach both shrinking per ring index, alpha (1 minus u) times `ring_a`}}
{{row:resolve — the boom lands (first ring done) | anim:fx/explosion:t_resolve | — | the cut plus the clump plus one flight}}
{{row:tail — the late rings keep fading | anim:fx/explosion:t_tail | linear | rings minus one, times the stagger. After it the canvas is EMPTY: that is what lets this film lead another screen}}
{{row:caption fades in, if `bottom` is set | pq1.status.BUSY_FADE_MS | ease_out | from resolve. The standalone film sets no caption}}
{{row:standalone only: the result hold | pq1.status.RESULT_HOLD_MS | hold | never runs when the film leads — see [lead film](../transitions/lead-film.md)}}
{{row:whole screen, standalone | anim:fx/explosion:duration | — | resolve plus the result hold}}

**`minor` — the `minor_explosion` preset.** The loading leg is identical, row for row. Only the finale changes: a contained two-ring pop.

{{motion-head}}
{{row:clump | burst:MINOR.t_clump | ease | a gentler squeeze and a much smaller shake than `major`}}
{{row:core flash bloom | - | linear | `MINOR.bloom` — a shorter fade, half the growth}}
{{row:ring i launches | burst:MINOR.stagger_ms | cut | the same stagger, over 2 rings instead of 5}}
{{row:one ring's flight | burst:MINOR.t_boom | linear | reach about a fifth of `major`'s, and nearly round (`aspect` close to 1) rather than wide}}
{{row:resolve | anim:fx/explosion@minor_explosion:t_resolve | — | }}
{{row:tail | anim:fx/explosion@minor_explosion:t_tail | linear | one stagger: the pop clears almost at once}}
{{row:whole screen, standalone | anim:fx/explosion@minor_explosion:duration | — | }}

### The follower stream

Through the whole loading leg each body drags a stream of five circles: `burst.draw` re-samples its own `pose` at fixed steps back in time — a fixed fraction of one orbit turn per step — and draws the samples farthest-first at the head's radius, in the spec's `trail` colour scaled down link by link. The walk stops early once two consecutive samples all but coincide, so a body that is not moving grows no tail. This is not the flow's [trail](../components/trail.md): no chain physics, no ramp palette, one colour.

### The busy caption

The film breathes its `busy` caption (`busy_pulse` is true): whole raised-cosine cycles of about {{tok:pq1.motion.BUSY_PULSE_MS}} fitted to the window, so it starts and ends dark. The window **opens only once the pair is on the orbit** — never over the split. See [busy caption](../components/busy-caption.md).

{{motion-head}}
{{row:window opens: the pair is ON the orbit | qubit:T_SEED + qubit:T_SPLIT + qubit:T_JOIN | — | plus the entrance, when there is one}}
{{row:window closes, `busy_until="spiral"` (default) | qubit:t5 | — | the orbit's end, exactly as the qubit film}}
{{row:window closes, `busy_until="boom"` | qubit:t6 + burst:MAJOR.t_clump - pq1.status.BUSY_FADE_MS | — | held through the spiral and the clump, gone as the blast launches. Shown for the stock orbit; `revs` moves it}}

A list of lines (`["WIPING…", "DO NOT POWER OFF"]`) splits the window into equal slots of at least {{tok:pq1.status.BUSY_SWAP_MS}}, one breath per slot.

### Entrances

{{motion-head}}
{{row:`enter="left"` / `"right"`: one body slides in | pq1.motion.ENTER_MS | spring KIOSK | from x {{val:pq1.layout.VALUE_PARK_X}} (mirrored for `"right"`) to the centre on `motion.spring_travel`, the follower stream riding in with it. Everything after it is delayed by exactly this}}
{{row:`enter="sides"`: two qubits fly in and join the orbit | - | linear | length is geometry, not a constant — `burst._sides` measures the path and divides it by the speed. Hand-rolled, and NOT constant speed: the profile below eases it down onto the orbit's. It REPLACES the seed, the split and the join, so the film resolves EARLIER than the table above}}

The slide-in is the one place a film uses a spring. It is `motion.spring_travel` on its **KIOSK** profile — the demo pace — released from rest, as a pure function of `t`, not a live spring retargeted by input. Port it as that curve: the device's NAV pace belongs to transits between screens, not inside this film.

The `sides` approach is a polar spiral from r {{val:pq1.procedural.burst.SIDES_R0}} px (both qubits fully off the panel) down to the orbit radius over one full turn, the radius easing in on the power {{val:pq1.procedural.burst.SIDES_K}} and the vertical reach squashed toward {{val:pq1.procedural.burst.SIDES_Y_MAX}} px by a `tanh`. Each qubit travels it **by arc length** at a speed that only ever falls: {{val:pq1.procedural.burst.SIDES_V0}} times the orbit speed at the edge, easing on (1 − u)² onto exactly the orbit speed at the join. The join angle is solved so the orbit picks the pair up at the same speed *and* heading — nothing stops and restarts. See [side entrance](../transitions/side-entrance.md).

### The glyph handoff

When the spec names an `icon` (a flow's ending, dressed by its family defaults) the flow's glyph and explicit edge stroke ride the body into the split and fade at the qubit film's own rate, so the disc never pops to a plain body ({{loc:screens.fx.explosion.Explosion._draw_token_handoff}}). `enter="sides"` has no body to hand off from and draws no glyph at all.

## Variants

{{variants}}

`(default)` is the `major_explosion` preset — identical specs, so the build renders it once. Neither variant rests on a token: both end on an empty canvas.

## Phases

{{phases}}

The timings live in the two severity tables (`BurstCfg`), not in `T_*` attributes — read them from Constants below.

## Constants

{{constants}}

`CFGS` is the live `BurstCfg` pair; `qubit` inside it is the stock `QubitCfg` whose fields the timeline above names. `burst.HOLD_END` is **not** in this table and is not used by any code — the post-boom rest is {{tok:pq1.status.RESULT_HOLD_MS}}, like every other ending.

## Spec a flow splices in

{{spec}}

{{used-in}}

That line is literally true and misleading: no flow sets `anim="explosion"` on a screen. The film is always spliced as a **`lead`** — `flows/firmware/__init__.py` leads both firmware endings with it (major for UPDATED on a five-turn orbit, minor for DECLINED), and the `wallet_wiped_explosion` preset of [verdict / wipe](verdict-wipe.md) leads the wipe verdict with a red `sides` blast. See [status — led by a film](../screen-types/status-led.md).

## Preview

{{preview}}

## Do / Don't

- **Do** end on a truly empty canvas. The tail row is not decoration: a screen may only lead another if it stops drawing, and the led screen's hold starts while those last rings are still fading underneath.
- **Do** lengthen a loading with `revs` — whole extra turns of the steady orbit. Never by slowing the spin, the spiral or the blast.
- **Don't** give the two severities different staggers. They were unified on purpose: each source's own stagger was shorter than two panel frames, which the panel cannot show.
- **Don't** port the demo's colours as constants. `trail`, `body`, `clump_from`, `clump_to` and `ring` are per-spec; the standalone film is white because no flow dressed it.

{{partial:port-notes}}
