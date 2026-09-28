## What it is

{{val:pq1.motion.TRAIL_COUNT}} flat discs that follow the token wherever it goes. Each one chases the disc ahead of it, so the chain stretches when the token moves fast and folds back under the token when it rests. It is ambient motion: it has no start, no end and no duration, only a time constant.

The physics is `motion.FollowerChain` ({{loc:pq1.motion.FollowerChain}}); the drawing is `components.trail_chain` ({{loc:pq1.components.trail_chain}}); the colours come from `components.trail_palette_from_spec` ({{loc:pq1.components.trail_palette_from_spec}}).

## When it appears

On every screen that rests on the token — hero, detail, value, Confirm? — and through every transit between them ({{loc:pq1.flow.Sim.draw}}). You see it in two situations:

- **in a transit**: the token springs to its new place and the links string out behind it;
- **on a hero at rest**: the links fan out behind the token as it drifts on the [idle sweep](idle-sweep.md).

On a detail at rest the links sit exactly under the token and are not drawn. The chain is dropped when a status ending takes the canvas and on a [token-less transit](../transitions/tokenless-fade.md); the next token screen builds a new chain with every link on the token's centre, so nothing streaks in from an old position. On a [value](../screen-types/value.md) screen the token parks off-panel and the links follow it off the edge.

## Geometry

| part | value |
|---|---|
| links | {{tok:pq1.motion.TRAIL_COUNT}}, nearest first |
| link radius | the token's **visible** radius: layout r − {{tok:pq1.components.TOKEN_INSET}} px. A link is exactly the size of the disc, never bigger |
| gap cap | {{tok:pq1.motion.MAX_GAP}} between a link and the point ahead of it, so the whole trail is never longer than {{val:pq1.motion.TRAIL_COUNT}} × {{val:pq1.motion.MAX_GAP}} px |
| fill | flat and opaque, one colour per link. No alpha, no blur, no gradient |
| order | farthest link first, nearest last, then the [pulse rings](pulse-rings.md), then the [token](token-disc.md) on top |
| skip | a link within 0.8 px (x and y) of the point ahead is not drawn — it is hidden anyway |

## Colours

The trail takes the **same ramp as the disc** (`components.token_ramp`), so identity can never split between the two. A six-stop ramp reads: stop 6 = the token's fill, stop 5 = the nearest link, … stop 1 = the farthest link. The trail darkens away from the token.

- the token names a `palette`, or is `variant: "unknown"` → that ramp's five trail stops (`colors.ramp_palette`, {{loc:pq1.colors.ramp_palette}});
- the mono look (ETH) → the mono ramp's greys; a brand or popular token → its named ramp (SAFE greens, USDC blues);
- no `token` field at all → the neutral grey ramp ({{val:pq1.colors.NEUTRAL_RAMP}});
- a token keyed by `address` or `symbol` **without** a `palette` → also the neutral grey ramp. `trail_palette_from_spec` reads the resolved ramp only when a `palette` is named or the token is `unknown`, and the solid body is black for the same reason. Every live flow pins `palette` (an address string is a legal `palette` value); only the library's idle screen takes the other keys.

Mid-transit the palette **cuts** from the old screen's to the new one's when the mix passes one half — the same frame the disc's body switches. See [glyph morph](glyph-morph.md).

## The step (once per drawn frame)

`chain.step(head_x, head_y, dt, tau)` with `dt` in ms ({{loc:pq1.motion.FollowerChain.step}}):

1. If every link is within 0.001 px of the head, return. A resting chain costs nothing.
2. `k = 1 − e^(−dt / tau)` — one exponential per frame, shared by all links.
3. Walk the links nearest first. The point ahead is the head for link 0, otherwise the link ahead **as already moved this frame**. Move the link toward that point by `k` of the distance, on x and y.
4. If the link is now farther than the gap cap from the point ahead, pull it straight back onto the cap distance.

The head is the token's live centre: the position springs **plus** the sweep offset.

## Motion

{{motion-head}}
{{row:a link chases the point ahead — in a transit, and at rest on any screen but a hero | pq1.motion.CHAIN_TAU | tau_chase | a time constant, not a duration: after one tau a link has closed 63 % of its gap}}
{{row:the same chase while settled on a hero | pq1.motion.CHAIN_TAU_IDLE | tau_chase | slower on purpose: more separation behind the sweeping token}}
{{row:the head itself, in a transit | - | spring NAV | see [spring morph](../transitions/spring-morph.md)}}
{{row:the head itself, on the idle sweep | pq1.motion.SWEEP_PERIOD_MS | sine + tau_chase | see [idle sweep](idle-sweep.md)}}

The tau is chosen per frame ({{loc:pq1.flow.Sim.draw}}): the idle value only when the flow is **settled** and the current screen is a hero; the instant a press starts a transit it is the fast value again.

**The look depends on the frame step.** `k` is frame-rate independent for a fixed target, but each link chases a target that itself moves once per frame, so a longer `dt` gives a tighter chain. Measured on the reference with the device profile `NAV`, stepped at the panel's {{val:tools.handoff.introspect.PANEL_FPS}} fps: on a sweeping hero the links separate by up to about 13 px and the chain reaches some 63 px behind the token; the longest transit (detail left ↔ detail right, 278 px apart) briefly rides the {{val:pq1.motion.MAX_GAP}} px cap and strings out to about 129 px. Stepped four times as often the same transit sits on the cap much longer and the chain opens to its full length ({{val:pq1.motion.TRAIL_COUNT}} × {{val:pq1.motion.MAX_GAP}} px). Every preview is rendered at the panel rate, but the flow-window clips walk the demo Sim on the slower `KIOSK` pace, where that transit peaks just under the cap; the scripted two-button clips run at `NAV`, the device pace. Step the chain once per displayed frame with the real elapsed `dt`; do not sub-step it.

`flow.Sim` caps `dt` at {{lit:100 ms}} — a literal in `draw`, no token — so a hitch never teleports the chain or the springs.

## Preview

No clip of its own — the trail shows in every flow GIF: see [Hero — the ask](../screen-types/hero-ask.md) (idle fan-out) and [spring morph](../transitions/spring-morph.md) (transit).

## Do / Don't

- **Do** keep the chain alive across screens of one flow. It is one object that follows one token; it is not rebuilt per screen.
- **Do** reset it (all links on the token) whenever the token was not on the previous frame.
- **Do** take the colours from the ramp tables by index. The placeholder and brand ramps are hand-picked stops; only the popular-token ramps are derived, once, by `colors.ramp_from`. Never darken the fill at run time to fake a trail.
- **Don't** fade, blur or shrink the links. Flat discs of the token's own size.
- **Don't** port `components.trail_static`: no live screen calls it.
- **Don't** give the trail a spring. It is a first-order chase; it cannot overshoot and it must not.

{{partial:port-notes}}
