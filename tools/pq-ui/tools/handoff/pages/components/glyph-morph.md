## What it is

What happens **inside** the disc and in the two corners while the disc travels from one screen to the next. One spring, `Sim.mix` ({{loc:pq1.flow.Sim}}), runs from 0 (the screen being left, `a`) to 1 (the screen being entered, `b`). Everything on this page is a plain function of that one number:

- the glyph of `a` fades out, then the glyph of `b` fades in (`components.token`, {{loc:pq1.components.token}});
- the corner chevrons turn and fade between the two screens' resting poses ({{loc:pq1.flow.Sim.draw}});
- the disc's body, ring, glyph colour and the trail palette switch from `a` to `b`.

It is part of the [spring morph](../transitions/spring-morph.md): the mix spring is created with the same profile as the position springs and is stepped with them.

## When it appears

On every transit between two screens that rest on the token — hero, detail, value, Confirm?. Most legs of a flow keep the same `icon`, so the glyph does not change and only the chevrons may move. The morph shows where the icon changes: into and out of a chain screen (`base`, `mainnet`), from an intro mark (`dev`) to the ask.

Inside the disc it does **not** run on a [token-less transit](../transitions/tokenless-fade.md) (leaving a verdict or a PIN row): there the old frame fades to black and the next disc fades in carrying one glyph, drawn at the incoming screen's own alpha. The chevrons still blend on the mix — a verdict and a PIN row have none (alpha 0), so the pair simply fades in with the screen that is arriving.

## The glyph: sequential, not a crossfade

With `m` the mix clamped to 0–1:

| glyph | alpha |
|---|---|
| outgoing (`glyph_a`) | `max(0, 1 − 2m)` — gone when `m` reaches one half |
| incoming (`glyph_b`) | `max(0, 2m − 1)` — starts at one half, full at 1 |

The two never overlap. At `m` = one half the disc carries **no glyph** for an instant. When both screens name the same glyph it is drawn once at full alpha — no dip.

A token glyph fades by **true alpha** over the body: image glyphs and the traced marks (`mainnet`, the chain marks, `blind`, `dev`, `rotate`, `fingerprint`, `download`) composite an alpha mask, because the body may be coloured and a mark merely darkened toward black would show as a dark shape on it ({{loc:pq1.procedural.chains.draw}}). The fallback `eth_mark` diamond, the monogram (an unknown chain's `letter:X`) and the check / X marks scale their colour toward black instead — exact only on a black body. A glyph under alpha 0.01 is not drawn.

## The body: a cut at one half

The style of the disc is not blended. `Sim.draw` picks **one** screen's resolved style per frame — `b` once `m` ≥ 0.5, else `a` — and the same index picks the [trail](trail.md) palette. So fill, ring, `icon_color`, the `unknown` ramp and the five trail colours all switch in a single frame, exactly when no glyph is showing. Inside one flow the style is usually shared by every screen (a flow's `DEFAULTS`), so the cut is invisible; it shows on a leg such as the ERC-7730 intro (black body, gold trail) to its ask (the token's own ramp).

## The chevrons

Each screen has a resting pose (`components.chevron_angles`, {{loc:pq1.components.chevron_angles}}): `"lr"` points the left chevron left and the right one right (−π/2, +π/2); `"up"` points both up (0, 0); `None` is the `"lr"` pose at alpha 0.

- angle = `lerp(angle_a, angle_b, m)` per chevron — `"lr"` → `"up"` is a quarter turn;
- alpha = `lerp(shown_a, shown_b, m)` with shown = 1 or 0 — so the chevrons fade out on the way into a status ending or a band-chevron intro, and fade in on the way out.

The hint rotation and bob are added on top, only at rest — see [chevrons](chevrons.md).

## Motion

{{motion-head}}
{{row:outgoing glyph fades out | - | spring NAV | alpha follows 1 − 2·mix; done at mix one half}}
{{row:incoming glyph fades in | - | spring NAV | alpha follows 2·mix − 1; from mix one half to 1}}
{{row:body, ring, glyph colour and trail palette switch | - | cut | the frame the mix reaches one half}}
{{row:chevron angle and alpha | - | spring NAV | linear in the mix}}
{{row:incoming text is released | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | not part of the mix — each screen's text has its own alpha spring, see [text-in delay](../transitions/text-in-delay.md)}}

There is no duration to port. The mix is a critically damped spring released from rest: progress = `1 − (1 + ωt)·e^(−ωt)`, ω = 2π / response (`motion.spring_travel`, {{loc:pq1.motion.spring_travel}}). It reaches one half when ωt ≈ 1.678, that is 0.267 × the response time after the leg starts. The device profile is `NAV` ({{loc:pq1.motion.NAV}}) — the pair {{val:pq1.motion.NAV}}, `response` in seconds and `damping` the ratio. Damping is 1: the mix never overshoots, and it is clamped to 0–1 before use.

## A press during the morph

Presses are never dropped ({{loc:pq1.flow.Sim.go_to}}); see [reversal](../transitions/reversal.md).

- **Back to where it came from** (the new target is `a` or `b`): the mix is retargeted to 0 or 1. Its value and velocity are kept, so the glyphs and chevrons run back through the same states.
- **On to a third screen**: the pair is rebased. `a` becomes the dominant endpoint (`b` if the mix is past one half, else `a`), `b` becomes the new target, and the mix is reset to 0 with zero velocity. The disc keeps its position and speed, but the glyph **jumps** to the dominant screen's glyph at full alpha, and the chevrons jump to that screen's pose. This is the reference behaviour; keep it.

When a hold fires, the full [hold flood](hold-flood.md) fades out on this same mix — see [hold commit fade](../transitions/hold-commit-fade.md).

## Preview

No clip of its own. Watch a leg where the icon changes (the ask → the chain screen) in [spring morph](../transitions/spring-morph.md).

## Do / Don't

- **Do** drive glyph, chevrons and the style switch from the **one** mix value. Do not give them timers of their own.
- **Do** keep the glyph fade sequential. Two marks drawn over each other at half alpha read as noise at this size.
- **Do** switch the body and the trail palette in the same frame.
- **Don't** port the `KIOSK` profile — the pair {{val:pq1.motion.KIOSK}}, a longer response. It is the demo-loop pace; the device uses `NAV`.
- **Don't** blend fills between screens. The reference cuts; a blend would show colours that belong to no token.

{{partial:port-notes}}
