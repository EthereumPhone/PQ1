{{doc-self}}

## Timeline

Ambient, like its twin [idle / batch_sign](idle-batch-sign.md): no phases, no resolve, no result. `t_resolve` stays zero and the class overrides `duration` with its own `LOOP_MS` — one sweep period, not the usual resolve-plus-result-hold — so a flow dwells exactly that long. The physics are the same code, constant for constant; only the composition differs (no pager, its own caption).

It is **not pure in `t`**. `draw(cv, t)` advances internal state from the last drawn `t` ({{loc:screens.idle.unknown_token.UnknownToken.draw}}); a backwards seek resets and replays from zero. These two idle screens are the only ones in the catalog that cannot be seeked to a single frame.

{{motion-head}}
{{row:the physics slice | screens.idle.unknown_token.STEP_MS | — | `step()` advances in chunks of at most this, whatever the real frame took. The chase itself is frame-rate independent}}
{{row:the disc holds centred before the sweep starts | pq1.motion.SWEEP_DELAY_MS | hold | the sweep clock is `t` minus this, floored at zero}}
{{row:the sweep target, one full left-right cycle | pq1.motion.SWEEP_PERIOD_MS | sine | target x offset = minus the sine of the cycle, times {{val:pq1.motion.SWEEP_AMP}} px — a target, not the disc's position}}
{{row:the disc chases the target | pq1.motion.OSC_TAU | tau_chase | the lag is what rounds the turns; there is no easing curve anywhere in this screen's travel}}
{{row:each follower chases the link ahead of it | pq1.motion.CHAIN_TAU_IDLE | tau_chase | the idle chase, slower than a transit's {{tok:pq1.motion.CHAIN_TAU}}, so the ramp spreads out and stays readable. See [trail](../components/trail.md)}}
{{row:the first chevron bob starts | 1400 | — | a bare literal inside `motion.chevron_hint` ({{loc:pq1.motion.chevron_hint}})}}
{{row:the chevron hint cycle | pq1.motion.CHEV_HINT_PERIOD_MS | ease | rise, bob, fall, rest. Only the bob shows: the module discards the up-rotation and keeps the mark pointing right}}
{{row:the loop | screens.idle.unknown_token.LOOP_MS | — | equals the sweep period, and equals the screen's `duration`}}

The bob closes on the loop exactly (its start plus the hint period is the loop length). The sweep does not: the sweep clock starts {{tok:pq1.motion.SWEEP_DELAY_MS}} late, so at the end of the loop the disc is still out near its right extreme, about 92 px from centre, where at t 0 it was on the centre line. Treat the loop as a window on continuous physics, not a cycle that closes.

### The composition

| part | value |
|---|---|
| token | a **solid** disc — the ramp's fill stop — at y {{val:pq1.layout.CIRCLE_CY}}, white ring, white ETH glyph. The layout radius is {{val:pq1.layout.CIRCLE_R}}; disc and ring are drawn {{val:pq1.components.TOKEN_INSET}} px inside it, exactly a trail link's size |
| travel | x {{val:pq1.layout.CENTER_X}} plus the chase; the disc edges stay inside x {{val:pq1.layout.SWEEP_X_MIN}} to {{val:pq1.layout.SWEEP_X_MAX}} |
| trail | {{val:pq1.motion.TRAIL_COUNT}} links at that same visible radius, in the ramp's five trail stops, brightest nearest the head, each clamped to at most {{val:pq1.motion.MAX_GAP}} px behind the one ahead |
| caption | `UNKNOWN TOKEN` unless the spec sets `bottom` |
| chevrons | the RIGHT one only, pointing right, bobbing outward. No left corner, no pager |

Head plus trail spell the whole ramp: the fill stop on the disc, the five darker stops behind it. That is the point of the screen.

### Identity is the colour

The ramp is deterministic, resolved in one place, `components.token_ramp` ({{loc:pq1.components.token_ramp}}): `palette`, then `address`, then `symbol`, then the screen's `icon`, then the neutral ramp. Address outranks symbol because two tokens can share a ticker but never a contract. A `palette` that names a brand pins that brand by name, outside the hash space — a brand ramp can never be reached by hashing a typed-in ticker.

Three traps a porter should know:

- **The stock spec carries no identity.** `SPEC` sets `token={}`, so a flow splicing this screen unchanged gets no ramp fill at all: the default token look, a black body under the white ring, with the neutral grey trail.
- **Only `palette` paints it.** The disc's fill and the coloured trail are both taken from a `palette` key (`components.token_style_from_spec`, `components.trail_palette_from_spec`). `address` or `symbol` alone resolve a ramp index that nothing on this screen reads — black disc, grey trail. Put the identity under `palette` (an index, a ticker, a contract address or a brand name) and the whole composition follows it.
- **The random ramp is CLI-only.** With no `palette` pinned, `build()` picks a random ramp before the animation exists — resolved once so every frame and every seek of that render agree — and prints which one it chose ({{loc:screens.idle.unknown_token.build}}). It does this even when `--symbol` / `--address` named something, so a bare render is not the place to check a hash. Nothing on the device ever picks a colour at random.

The disc here is always solid. `variant="unknown"` — the gradient disc DESIGN.md § Color reserves for an unrecognized token — is still in `components.token`, but no live flow asks for it: even the unknown-token transfer flow dresses its token as a solid disc on the address's ramp. See [token disc](../components/token-disc.md).

### In a flow

A `status` screen: the reference driver binds no button on it and the Sim dwells for its `duration`. The bobbing corner chevron is ambience, not an affordance.

## Variants

{{variants}}

No presets: one variant. The "result hold" column is the whole loop only because the table subtracts a zero `t_resolve` from the overridden duration — nothing is held here, and `RESULT_HOLD_MS` plays no part.

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

`flows/transfer_unknown_token` is a different thing despite the name: a real transfer flow for a token the device cannot resolve. Its navigable screens carry the ordinary token disc, solid, on the ramp hashed from the contract address (`token={"palette": CONTRACT}`) — not this idle screen.

## Preview

{{preview}}

## Do / Don't

- **Do** derive the ramp from the token's identity every time, with the same hash, so the disc and the trail can never disagree.
- **Do** keep the disc solid. A gradient on a flow's token circle is wrong; the ramp lives in the trail.
- **Don't** ship the random-ramp path. It exists so a bare render is not always the same colour.
- **Don't** assume this screen is seekable, and don't give it buttons.

{{partial:port-notes}}
