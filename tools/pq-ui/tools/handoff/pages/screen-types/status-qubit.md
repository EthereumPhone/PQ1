## What it is

The ending of a flow whose work was done: signed, sent, confirmed. The film **is** the depiction of work. The token splits into two qubits, they swing onto a circular orbit and spin, spiral back into one body, flash, and the resting look lands: the disc, a ring in the result colour, the check, then the caption. It is the core system's one loading film; the `screens` library adds a second, the explosion, which ends on an empty canvas and so can [lead](status-led.md) another screen instead of resolving on one. The old orbit spinner is gone and must not come back.

It is a `status` screen whose animation is `"qubit"` — the default for every ending whose `state` is `"done"` (`status.default_anim`, {{loc:pq1.status.default_anim}}) and, named explicitly (`anim="qubit"`), the ending of a flow whose work FAILED after dispatch (`send`'s TRANSACTION FAILED): the same film colliding into the red X. A user decline never plays it ([the resolve](status-resolve.md)). On the device the film is open-ended: it starts when the work is dispatched and the orbit repeats until the host answers — see [the loading loop](../transitions/loading-loop.md). The class is `QubitStatus` ({{loc:pq1.status.QubitStatus}}). Every frame is `loading.draw_status` ({{loc:pq1.loading.draw_status}}) drawing the pose `loading.qubit_pose(t)` ({{loc:pq1.loading.qubit_pose}}).

## When it appears

After a completed [hold right](../actions/hold-right-sign.md) on a screen that commits. A cancel never plays it — see [the resolve](status-resolve.md); a failure the host reports after the hold does. An ending whose work is shown by another film is [led](status-led.md) and lands with [arrive](status-arrive.md) instead. {{used-in}}

## Spec

{{fields:kind,status.bottom,anim,result,state,color,resting}}

{{example}}

`anim` is left unset on a success: the state picks it. A post-dispatch failure names `anim="qubit"` with `result="x"`, `state="failed"` (the checker's `F-ENDPAIR` accepts exactly that pair). `revs` — whole turns of the steady orbit, {{tok:pq1.loading.REVS}} by default, {{tok:pq1.loading.REVS_LONG}} where a loading must endure — sets the film's MINIMUM length. `ready` (demo only: the ms at which the work answers) renders the loop; `live` is set by the bench driver, never by a flow. `busy` is optional: the caption shown while loading — a string, or a list of lines (below). `icon` and `token` come from the flow's defaults, so the film wears the flow's colours. An unknown `anim`, `result` or `state` raises — there is no silent fallback.

## Geometry

All of it is centred on x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}. The numbers are the fields of `QubitCfg` ({{loc:pq1.loading.QubitCfg}}); the px values with no field are literals in `qubit_pose` / `draw_status`.

| part | value |
|---|---|
| token body, and the resting disc | r {{val:qubit:r_big}} |
| one qubit | r {{val:qubit:r_q}}; it grows by 4 px over the spiral, so the flash starts from r 17 |
| split reach | each qubit travels {{val:qubit:split_x}} px out from the centre, along the centre line |
| orbit | radius {{val:qubit:orbit_r}}, one turn per {{tok:qubit:rev_ms}} |
| join ellipse | while the pair is wider than the orbit, its vertical reach is squashed to at most 44 px |
| flash ring | starts at r {{val:qubit:r_big}}, grows 55 px, 2.5 px stroke, result colour |
| rings on the single body | 2.4 px stroke; unbranded: 1.2 px inside the body edge; branded (`resting`): flush |
| caption | 18 px caps, centred, baseline y {{val:pq1.layout.BASELINE_Y}} |

**Colour.** The bodies take the token's *film* colour (`components.token_style_from_spec`, {{loc:pq1.components.token_style_from_spec}}): the fill, or the brightest stop of the ramp when a `palette` is named — so a black-bodied token (the ETH mono look) spins light qubits, never black on black. An unknown token spins gradient discs. Qubits carry no ring.

**Trail.** Not the flow's follower chain. Each body draws up to five copies of its own pose at earlier times — one step back, two steps back … (one step is 0.22 rad of orbit travel) — all at the body's *current* radius. The trail palette is read nearest-first (copy 1 takes the first trail colour), but the copies are drawn farthest first, so the nearest one sits on top. The chain stops at the first copy that is within 0.8 px of the one before it in **both** x and y, so a body at rest has no trail. The trail is a pure function of time, like the pose.

## Motion

Time 0 is the frame the flow hands its circle over — the end of the entrance beat ([entering a film](../transitions/film-entrance.md)) — not the moment the hold fires. There is no spring leg into a film. The phases run back to back:

{{motion-head}}
{{row:seed: the flow's circle becomes one qubit | qubit:T_SEED | ease_out | the circle the flow was drawing travels to the centre, shrinks from the token's VISIBLE radius to {{val:qubit:r_q}} and tints into the film's colour; its ring and its art fade out over the first half of that WINDOW ({{tok:pq1.motion.SEED_ART}} of it, on LINEAR time — the eased travel front-loads and would empty the dress inside one panel frame), so a BARE qubit lands on the frame the split begins. With no flow to hand one over (a standalone render) the same morph runs in place at `gc`}}
{{row:split: two qubits part along the centre line | qubit:T_SPLIT | ease | one eased progress drives the reach; both halves are already {{val:qubit:r_q}} — the seed IS a qubit, so it divides into its identical twin rather than shrinking as it parts. A goo bridge (`loading.metaball`) joins the two while they overlap}}
{{row:join: the pair swings onto the orbit | qubit:T_JOIN | linear | hand-rolled: the radius falls from the split reach to the orbit on a smoothstep of linear progress; the angle starts from rest with constant angular acceleration (`spin_th`)}}
{{row:spin-up ramp — runs INSIDE the join | qubit:T_RAMP | linear | angular speed rises linearly from zero to orbit speed. It is as long as the join, so the pair lands on the orbit at full speed. It is NOT a phase of its own: do not add it to the timeline}}
{{row:spin: steady orbit — THE LOOP REGION | qubit:T_SPIN | linear | constant speed, the qubits opposite each other; `revs` whole turns of {{tok:qubit:loop_ms}} ({{val:pq1.loading.REVS}} stock). From {{val:qubit:t_orbit}} to {{val:qubit:t5}} the pose is pixel-periodic in one turn: on the device this row repeats, whole turns at a time, until the work answers — [loading loop](../transitions/loading-loop.md)}}
{{row:spiral: the pair falls into the centre | qubit:T_SPIRAL | linear | hand-rolled: orbit speed plus 2.2 extra turns on the cube of progress; the radius shrinks with the square of progress; the bridge returns as they merge. The spiral is the LATCH: it starts at the first turn boundary after the answer, and its end ({{val:qubit:t6}} on the stock film) is the first frame that differs between check and X}}
{{row:flash: one body pops, the ring fires | qubit:T_FLASH | back_out + linear | disc radius on `back_out` — the ONE sanctioned overshoot of the system; the flash ring grows and fades linearly from 85 %}}
{{row:result glyph fades in | 350 | linear | starts when the flash ends. A bare literal in `qubit_pose` — there is no token for it}}
{{row:caption waits | 120 | hold | counted from the end of the flash; bare literal}}
{{row:caption fades in | 350 | linear | bare literal}}
{{row:resolved, from time 0 | anim:core/qubit:t_resolve | — | hold + split + join + spin + spiral + flash, at the stock turns; on the device add wraps × {{val:qubit:loop_ms}} — `t_resolve` is a property ({{loc:pq1.status.QubitStatus.t_resolve}})}}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | the resting look stays — see [result hold](../transitions/result-hold.md)}}
{{row:whole screen | anim:core/qubit:duration | — | resolved + result hold}}

From the first frame of the flash the single body **is** the resting look: the disc in the resting fill (black, or a brand fill) under the ring in the result colour. Check and caption land on it. See [flash ring + result glyphs](../components/flash-ring.md) and [the resting look](resting-look.md). The film rests on that disc (`rests_on_token` stays true), so leaving the ending is an ordinary token transit — the disc morphs into the next screen, it does not fade to black.

On the film's first frame the body **is** the circle the flow handed over — same centre, same visible radius ({{val:pq1.components.TOKEN_INSET}} px inside the layout radius), same colour — because that is where the seed starts. The reference this was ported from did neither: it drew the body at the full radius, stepping the edge out by that inset, and wore the film colour from frame 0, so a black-bodied token turned light at once. The seed removes both pops. [The resolve](status-resolve.md) eases out of the token's own look the same way.

### The busy caption

Optional (`busy`, e.g. `SIGNING…`). It breathes on a raised cosine (`motion.busy_pulse`): whole cycles of about {{tok:pq1.motion.BUSY_PULSE_MS}}, stretched to fit the window, so it starts and ends dark. A list of lines alternates: the window is cut into equal slots of about {{tok:pq1.status.BUSY_SWAP_MS}} (never fewer slots than lines), one line and one breath per slot. The caption never shows over the split or the join. On the device it runs on the UNWRAPPED clock while the film loops: the same period carries on, and it fades out over {{tok:pq1.status.BUSY_FADE_MS}} when the spiral starts — the pose wraps, the breath does not. See [busy caption](../components/busy-caption.md).

{{motion-head}}
{{row:window opens: the pair is ON the orbit | qubit:T_SEED + qubit:T_SPLIT + qubit:T_JOIN | — | measured from time 0}}
{{row:window closes: the spiral starts | qubit:t5 | — | measured from time 0}}

## Input

None. A status screen hides the chevrons, and the driver ignores every press while an ending plays and after it rests ([unbound gestures](../actions/unbound-gestures.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** compute every frame from elapsed ms: `qubit_pose(t)` is pure, so the film can be seeked or resumed.
- **Do** lengthen a loading with more whole turns on the steady orbit — never with a slower spin, a longer split or a longer spiral. `revs` is a spec key on this film and on the explosion alike, and sets the minimum; the loop adds turns at run time on the same rule.
- **Do** start the film at dispatch and answer it later ({{loc:pq1.status.StatusAnim.resolve}}); never build it with the outcome — the drawing is outcome-blind until {{val:qubit:t6}} ([loading loop](../transitions/loading-loop.md)).
- **Don't** port {{tok:pq1.motion.STATUS_DWELL}} or the loop back to the first screen: that is the demo's auto-advance. The driver freezes a finished ending on its resting frame.
- **Don't** ease the orbit, and don't swap `back_out` on the flash for a spring.
- **Don't** play this film for a user cancel (hold left): that is [the resolve](status-resolve.md). A failure the host reports after the hold DOES play it — into the X.

{{partial:port-notes}}
