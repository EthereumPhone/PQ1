## What it is

A press that arrives while a [spring morph](spring-morph.md) is still running. It is never queued and never dropped: `go_to` moves the goalposts and every spring keeps its live position **and** its live velocity, so the disc decelerates, turns and comes back instead of restarting. This is the reason transitions are springs at all.

## What the press does to the springs

`go_to` ({{loc:pq1.flow.Sim.go_to}}) first drops a press that targets the screen already current — that one is a genuine no-op. Otherwise it takes one of three branches, named by the morph's two endpoints `a` and `b` (`mix` runs `0` → `a`, `1` → `b`):

| the press targets | branch | what happens to `mix` |
|---|---|---|
| `a` — straight back where you came from | reverse | `retarget(0.0)`. Value and velocity are kept: the glyph crossfade runs backwards from exactly where it is |
| `b` — you already reversed, now you change your mind again | reverse | `retarget(1.0)`, same way |
| anything else — a third screen | **rebase** | `a` becomes whichever endpoint is dominant (`b` if `mix ≥ 0.5`, else `a` stays), `b` becomes the new target, and `mix` is **reset to 0 with zero velocity** |

`sx`, `sy`, `sr` retarget in every branch and always carry velocity. Only `mix` is rebased — see the Don't below.

The text springs are handled the same way in all three: every screen but the destination is retargeted to alpha 0 at once, and the incoming release is re-armed to {{tok:pq1.motion.TEXT_IN_DELAY_MS}} from the **new** leg's start ([text-in delay](text-in-delay.md)).

Also reset on the press, for the destination screen only: its page goes back to the first — or to the **last** when the caller passes `back` (the left tap, so left undoes right) — and any page flip in flight on it is discarded. A flip on the screen being *left* keeps running under its fading text.

## What the grammar reads mid-flight

The current screen index changes at the press, not at the settle. So while you can still mostly see the old screen, the driver is already answering for the new one:

- a tap resolves against the **destination** — tap right during hero → detail lands on the *second* detail, not the first;
- `armed()` reads the destination, so a hold started mid-flight is armed (or not) by the screen you are heading to, and its fill dress is that screen's;
- the fill draws on the travelling disc, not on a parked one.

Once a hold commits, the destination is a status screen and the driver's state turns `resolving`: an ending's transit cannot be reversed ({{loc:pq1.driver.FlowDriver.press}}).

## Motion

{{motion-head}}
{{row:circle keeps travelling toward the new target | - | spring NAV | velocity carried through the retarget; measured mid-leg at a few hundred px/s}}
{{row:mix reverses (branch 1 and 2) | - | spring NAV | live value and velocity kept}}
{{row:mix rebases (branch 3) | - | cut | value and velocity forced to 0 in one frame}}
{{row:incoming text release, re-armed by the new leg | pq1.motion.TEXT_IN_DELAY_MS | hold | a run of presses faster than this keeps postponing it}}
{{row:whole set declared settled | - | — | tolerances in [spring morph](spring-morph.md); the idle clock starts here}}

## Input

The truth table is executed from a settled screen. Mid-flight the same presses give the same results — read against the destination row, not the one on the glass.

{{gestures:detail — middle}}

## Preview

{{preview}}

## Do / Don't

- **Do** retarget. Never restart a transition, never queue the press until the current one finishes.
- **Do** let the index change at the press. The button grammar, the armed set and the hold dress all follow the destination immediately.
- **Don't** assume the caption is up when the screen is: a fast run of taps can leave the panel with the disc travelling and **no text at all** until the taps stop.
- **Don't** treat a rebase as free — see the note below; if your port can carry `mix` through a rebase without a pop, that is an improvement, but match this behaviour first and change it deliberately.

> **Known rough edge.** In the rebase branch the glyph morph hard-cuts: `mix` is zeroed while the position springs flow on. Because `a` rebases at the 0.5 crossover, the glyph jumps by up to half the crossfade in a single frame. Measured on `send_token`, a second forward tap landing one panel frame into the leg rebases from `mix` 0.309 and snaps the glyph back 0.31 toward the screen you came from; two frames in it rebases from 0.656 and snaps 0.34 the other way. Any tap naming a third screen reaches it — the second tap of a forward run already does — and the disc itself never jumps.

{{partial:port-notes}}
