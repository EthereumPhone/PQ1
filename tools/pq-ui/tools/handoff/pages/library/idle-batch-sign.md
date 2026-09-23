{{doc-self}}

## Timeline

There are no phases here. This screen is **ambient**: a loop of physics with no beginning, no resolve and no result. `t_resolve` stays zero, and the class overrides `duration` with its own `LOOP_MS` — one sweep period — instead of the usual resolve-plus-result-hold. The flow Sim dwells exactly that long.

It is also one of only two screens in the library that are **not pure in `t`** ([idle / unknown_token](idle-unknown-token.md) is the other). `draw(cv, t)` advances internal state from the last drawn `t` ({{loc:screens.idle.batch_sign.BatchSign.draw}}); a backwards seek resets and replays the whole loop from zero. Everything else in the catalog can be seeked to a single frame — this cannot.

{{motion-head}}
{{row:the physics slice | screens.idle.batch_sign.STEP_MS | — | `step()` advances in chunks of at most this, however long the frame was. The chase is frame-rate independent, so the slice only bounds the error}}
{{row:the disc holds centred before the sweep starts | pq1.motion.SWEEP_DELAY_MS | hold | the sweep clock is `t` minus this, floored at zero}}
{{row:the sweep target, one full left-right cycle | pq1.motion.SWEEP_PERIOD_MS | sine | target x offset = minus the sine of the cycle, times {{val:pq1.motion.SWEEP_AMP}} px. It is a TARGET, not the disc's position}}
{{row:the disc chases the target | pq1.motion.OSC_TAU | tau_chase | one exponential step per slice. The lag is why the disc never quite reaches the amplitude and why it eases at the turns without an easing curve}}
{{row:each follower chases the link ahead of it | pq1.motion.CHAIN_TAU_IDLE | tau_chase | deliberately slower than a transit's {{tok:pq1.motion.CHAIN_TAU}}, so the streak spreads out. See [trail](../components/trail.md)}}
{{row:the first chevron bob starts | 1400 | — | a bare literal inside `motion.chevron_hint` ({{loc:pq1.motion.chevron_hint}})}}
{{row:the chevron hint cycle | pq1.motion.CHEV_HINT_PERIOD_MS | ease | rise, bob, fall, then rest for the remainder. The bob is a half sine of amplitude 4 px}}
{{row:the loop | screens.idle.batch_sign.LOOP_MS | — | equals the sweep period, and equals the screen's `duration`}}

Two things about that loop, both verified against the running code. The chevron bob closes exactly — its start plus the hint period is the loop length, so the corner is at rest at both ends. The **sweep does not**: because the sweep clock starts {{tok:pq1.motion.SWEEP_DELAY_MS}} late, the disc is still near its right extreme (about 92 px out) when the loop ends, where at t 0 it was centred. The loop is a window onto continuous physics, not a closed cycle; the CLI's `--loops` keeps stepping the same state rather than restarting it.

### The composition

| part | value |
|---|---|
| token | solid disc, the placeholder ramp's fill stop — ramp {{val:pq1.gradients.TEAL_RAMP}}, the demo teal — at y {{val:pq1.layout.CIRCLE_CY}}, white ring, white ETH glyph. The layout radius is {{val:pq1.layout.CIRCLE_R}} but disc and ring are drawn {{val:pq1.components.TOKEN_INSET}} px inside it, so the head is exactly a trail link's size and never bigger |
| travel | x {{val:pq1.layout.CENTER_X}} plus the chase, so the disc edges stay inside x {{val:pq1.layout.SWEEP_X_MIN}} to {{val:pq1.layout.SWEEP_X_MAX}} |
| trail | {{val:pq1.motion.TRAIL_COUNT}} links at that same visible radius, in the ramp's five trail stops, brightest nearest the head; each link is clamped to at most {{val:pq1.motion.MAX_GAP}} px behind the one ahead, and a link within 0.8 px of the one ahead is not drawn at all |
| pager | `tx` / `total` at the top-centre spot, the label size, {{val:pq1.components.PAGER_ALPHA}} white — drawn only when there is more than one transaction; see [pager](../components/pager.md) |
| caption | `BATCH SIGN TX n OF m` unless the spec sets `bottom` |
| chevrons | the RIGHT one only, pointing right, bobbing outward. The left corner is empty |

The chevron never rotates: the module takes only the bob out of `motion.chevron_hint` and throws the up-rotation away, so the mark keeps pointing along the direction it bobs in. See [chevrons](../components/chevrons.md).

### In a flow

This is a `status` screen, so the reference driver binds no button on it and the Sim simply dwells for its `duration`. The right chevron is a picture of progress, not an affordance — and in `flows/unlock_batch` the driver picks this screen as the flow's `sign` ending, because it is the first non-entry status in the list. A port that gives the idle screen real buttons is inventing behaviour the reference does not have.

## Variants

{{variants}}

No presets: one variant, `tx` and `total` are the spec's. The "result hold" column is the whole loop only because the table subtracts a zero `t_resolve` from the overridden duration — nothing is ever held here, and `RESULT_HOLD_MS` plays no part.

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** keep the two tau constants apart. The head chases its target on one, the trail chases the head on the slower one; collapse them and the streak sticks to the disc.
- **Do** advance the chase with elapsed ms, not per frame: `1 − exp(−dt/tau)` is frame-rate independent, and the fixed slice only caps the integration error.
- **Don't** assume this screen is seekable. It is the exception; resuming it means replaying from zero.
- **Don't** read the corner chevron as a button hint here. Nothing is armed on an ambient screen.

{{partial:port-notes}}
