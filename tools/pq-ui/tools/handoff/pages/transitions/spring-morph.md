## What it is

The one transition the flow owns. Going from one screen to the next does not cut and does not tween: a set of critically damped springs is given new targets, and every animated value walks to them from wherever it currently is. No moving value has a duration — the settle emerges from the physics, which is exactly what makes a press mid-flight cheap ([reversal](reversal.md)). The leg holds one timer only, the [text-in delay](text-in-delay.md).

One transit is not a spring: **entering a loading film**. The springs are never retargeted — the screen fades out over a fixed beat with its circle parked, and the film then morphs that circle into its first qubit ([entering a film](film-entrance.md)). Everything below is about every other leg.

Three kinds of value ride the set, all on one profile:

| spring | drives | settled within |
|---|---|---|
| `sx`, `sy`, `sr` | the token disc's centre x, centre y and radius, from this screen's layout to the next one's | 0.5 px |
| `mix` | `0` = endpoint `a`, `1` = endpoint `b`: the glyph crossfade inside the disc, the corner chevrons' angle lerp and their alpha when one of the two screens hides them, the token's own style and trail palette (both swap at 0.5) and a committed hold fill's alpha | 0.005 |
| `alpha[i]`, one per screen | that whole screen's text block — caption, label, value lines, pager, confirm band | 0.005 |

`settled(tol)` is `|value − target| < tol` **and** `|velocity| < tol × 10` ({{loc:pq1.flow.Sim._all_settled}}). The leg is over only when all of them pass **and** no text release is still pending ([text-in delay](text-in-delay.md)); then every spring is written exactly onto its target, the idle clock starts and a committed hold fill is dropped.

## The maths a port needs

`motion.Spring` ({{loc:pq1.motion.Spring}}) is a damped harmonic oscillator in Apple's designer parameterization — `response` in seconds, `damping` as the ratio ζ — with ω = 2π / response. ζ is **1.0 everywhere in navigation**: two buttons carry no momentum, so nothing overshoots.

One step over the frame's `dt` (seconds), with `x = value − target` and `v` the carried velocity:

```
B = v + w*x
e = exp(-w*dt)
value    = target + (x + B*dt) * e
velocity = (B - w*(x + B*dt)) * e
```

That is the closed-form solution of the ODE, so it is **exact at any dt**: the panel and a faster offline preview trace the same curve. Do not integrate it per fixed tick.

Released from rest the same thing has a pure form, `1 − (1 + ωt)·e^(−ωt)` — `motion.spring_travel` ({{loc:pq1.motion.spring_travel}}), which a film uses so its circle travels like a flow leg. Checked frame by frame against the stepped spring: the same curve. Note its default profile is `KIOSK`, and the film's [side entrance](side-entrance.md) calls it that way — that one is deliberate, not the demo pace leaking in.

Profiles: response 0.40 (`NAV`, {{loc:pq1.motion.NAV}}) and 0.55 (`KIOSK`, {{loc:pq1.motion.KIOSK}}), both at damping 1.0. **Navigation on the device is NAV**; `KIOSK` is the `Sim`'s own default, which the reference driver overrides ({{loc:pq1.driver.FlowDriver}}), so a port reads NAV for every leg. The per-panel-frame progress ladder for both, and the time to come within 1 px on a short and a full-width trip, are in `spec/motion.json` → `springs` — port from there rather than from a stopwatch.

A spring that lands (inside {{tok:pq1.motion.Spring.SNAP_EPS}} of its target with velocity under {{tok:pq1.motion.Spring.SNAP_VEL}}) snaps exactly onto the target and sleeps: it costs nothing per frame until the next retarget.

## Motion

{{motion-head}}
{{row:circle travel — cx, cy, r | - | spring NAV | retargeted from the live pose, velocity carried; no duration}}
{{row:glyph + chevron morph, mix 0 → 1 | - | spring NAV | see [glyph morph](../components/glyph-morph.md), [chevrons](../components/chevrons.md)}}
{{row:outgoing text fades | - | spring NAV | every screen but the destination is retargeted to alpha 0 the instant the leg starts}}
{{row:incoming text released after the leg begins | pq1.motion.TEXT_IN_DELAY_MS | — | then its own alpha spring runs — see [text-in delay](text-in-delay.md)}}
{{row:incoming text fades in | - | spring NAV | lands with the disc rather than ahead of it}}
{{row:legacy span bound (pre-spring, do not port) | pq1.motion.MOVE_MS + 2 * pq1.motion.FADE_MS | — | not a timing and nothing waits for it: the window offline renders allot to a leg. A NAV leg settles well inside it}}

The frame step is clamped ({{loc:pq1.flow.Sim.draw}}): `dt` is the real gap between draws, capped at {{lit:100 ms}} so a scheduling hitch cannot teleport a spring, and the very first draw assumes {{lit:16 ms}}.

## Snapping without animation

Assigning `sim.cur = i` ({{loc:pq1.flow.Sim.cur}}) teleports: springs are written onto screen `i`'s layout with zero velocity, the pending text release is dropped, pages reset to the first and any live hold is discarded. That is a harness entry point — a port needs the equivalent only for "boot straight into screen N".

## Preview

{{preview}}

## Do / Don't

- **Do** keep one spring object per animated value and step them all once per frame with the measured `dt`.
- **Do** carry position **and** velocity through a retarget. That is the whole contract.
- **Don't** replace the spring with duration + easing. A tween cannot be redirected mid-flight without a jump, and § Input promises presses are never dropped.
- **Don't** navigate at the `KIOSK` pace: it is the demo loop's, and the `Sim` default the driver replaces. Legs are `NAV`. The one KIOSK curve that does reach the device is inside a film's side entrance, through `spring_travel`'s default.
- **Don't** spring into a film. That entrance is sequential and the film owns the travel ([entering a film](film-entrance.md)).
- **Don't** drive the springs from a frame counter. They are dt-exact; a fixed-step port drifts as soon as a frame is late.

{{partial:port-notes}}
