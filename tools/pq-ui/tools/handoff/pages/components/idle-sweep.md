## What it is

A hero that is left alone does not sit still. After a short rest the token drifts slowly to one side, back through the centre, to the other side, and again — with its [trail](trail.md) fanning out behind it. It says "the device is waiting for you" without a word. The sweep moves the disc, its trail and its [pulse rings](pulse-rings.md) and nothing else: the caption does not move with it, and the corner chevrons run their own hint cycle on their own clock (see [chevrons](chevrons.md)) — the two are independent.

It is a few lines in `Sim.draw` ({{loc:pq1.flow.Sim.draw}}): a sine target, and a first-order chase of that target. The offset is **added to** the x of the position spring, so the sweep and the [spring morph](../transitions/spring-morph.md) never fight.

## When it appears

On every hero — the [ask](../screen-types/hero-ask.md), an [intro](../screen-types/hero-intro.md), a [batch hero](../screen-types/hero-pager.md) — once the screen has settled. No other kind sweeps.

{{fields:sweep}}

No live flow sets `sweep`; every hero takes the default. The library's idle screens (`screens/idle/`) run the same formula by hand.

## The formula

Per frame, with `dt` the elapsed ms since the last frame:

```
idle_t = max(0, now − idle_since − SWEEP_DELAY_MS)
target = dir · sin(2π · idle_t / SWEEP_PERIOD_MS) · SWEEP_AMP     when sweeping
target = 0                                                         otherwise
osc    = osc + (target − osc) · (1 − e^(−dt / OSC_TAU))            motion.tau_chase
disc x = spring x + osc
```

"Sweeping" means all three: the flow is **settled** (every transit spring has landed), **no hold is live**, and the screen's `sweep` is true.

- `idle_since` is the moment the arrival springs settled — not the moment of the press. The rest is counted from there.
- `dir` is the direction of the **last transit**: +1 (first drift to the right) if the token travelled right or did not move in x, −1 if it travelled left. It is set on every leg by `Sim.go_to` ({{loc:pq1.flow.Sim.go_to}}), comparing the two screens' layout x. Before any transit — the opening hero of a flow — it is the constructor's −1, so the first drift is to the left ({{loc:pq1.flow.Sim}}). The token keeps going the way it arrived.
- The sine starts at zero, at the centre, at full speed. The chase is what makes the start soft.

## Geometry

| part | value |
|---|---|
| centre | x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}} |
| target amplitude | {{tok:pq1.motion.SWEEP_AMP}} each side of the centre |
| amplitude the disc really reaches | about 92.6 px: the chase is a low-pass filter and trims the peak by 2–3 % |
| bounds | the disc's **outer edge** stays inside x {{val:pq1.layout.SWEEP_X_MIN}}–{{val:pq1.layout.SWEEP_X_MAX}} = centre ∓ (amplitude + {{tok:pq1.layout.CIRCLE_R}}) |

`SWEEP_X_MIN` / `SWEEP_X_MAX` ({{loc:pq1.layout.SWEEP_X_MIN}}) are a stated contract, not a clamp: nothing in the code reads them. The amplitude is what keeps the disc inside. If you change one, change the other.

## Motion

{{motion-head}}
{{row:rest at the centre after the screen settles | pq1.motion.SWEEP_DELAY_MS | hold | counted from the settle of the arrival, see above}}
{{row:one full cycle: centre, one side, centre, other side, centre | pq1.motion.SWEEP_PERIOD_MS | sine | hand-rolled in `Sim.draw`: dir · sin(2π·t / period) · amplitude. It loops for as long as the screen rests}}
{{row:the disc chases the sine target | pq1.motion.OSC_TAU | tau_chase | a time constant, not a duration. It softens the start and makes the disc lag the sine by about one tau}}
{{row:a press or a transit: the offset glides home | pq1.motion.OSC_TAU | tau_chase | the target drops to 0 and the same chase brings the offset back; nothing snaps}}
{{row:the trail behind the sweeping disc | pq1.motion.CHAIN_TAU_IDLE | tau_chase | slower than in a transit ({{val:pq1.motion.CHAIN_TAU}}) so the links separate — see [trail](trail.md)}}

## Input

The sweep never blocks input and never delays it.

- **Press-down on an armed side** (hold-right where the screen commits, hold-left where the flow can decline): the hold goes live at press-down, so the disc starts gliding to the centre at once — before any fill shows, even if the press turns out to be a tap. The [hold flood](hold-flood.md) then rises in a disc that stands still.
- **A tap**: the transit starts, the flow is no longer settled, the target is 0. The leftover offset decays on the same chase **while** the position spring carries the token away. The two are simply summed.
- **An early release**: the target stays 0 until the snap-back ({{tok:pq1.motion.HOLD_SNAPBACK_MS}}) has run. Then the sweep resumes **where the sine is now** — the idle clock never stopped — and the disc chases out to it. There is no second rest.
- **Press-down on an unarmed side** (right on an intro): nothing changes until the release makes it a tap.

The full truth table of the hero is on [Hero — the ask](../screen-types/hero-ask.md).

## Preview

No clip of its own. See the sweep, the recentring press and the trail in [Hero — the ask](../screen-types/hero-ask.md) and [hold right — sign](../actions/hold-right-sign.md).

## Do / Don't

- **Do** keep the sweep as an offset on top of the spring position. Do not retarget the position spring to make it sweep.
- **Do** compute the target from the ms clock and chase it with the real `dt`. The result is the same at any frame rate.
- **Do** let it loop. On the device the hero rests until a press; there is no timeout in this design.
- **Don't** port {{tok:pq1.motion.HERO_DWELL}}: it is the demo loop's auto-advance. In the demo a hero by default never completes a cycle — the rest plus one period is longer than the dwell — and on the one hero whose dwell leads into an ending the demo performs the hold itself over the dwell's last {{tok:pq1.motion.HOLD_COMMIT_MS}}, which pulls the disc home and ends the sweep earlier still. None of that exists on the device: on hardware the hero sweeps until a real press.
- **Don't** ease the sine with a curve of your own, and don't clamp x. Sine plus chase is the whole look.
- **Don't** sweep a detail, a value or Confirm?. Their token is docked beside text.

{{partial:port-notes}}
