## What it is

What the completed [hold flood](../components/hold-flood.md) does at the moment the gesture fires. The disc is full; the flow leaves for its ending. The fill does not cut and does not drain — it stays full and **fades out riding the transition's own morph spring**, on the disc as it travels. By the time the leg lands the fill is gone, and the ending draws on a clean disc.

When the ending is a loading film there is no leg to ride: the fill fades over the entrance **beat** instead, with the disc parked, and the film seeds a clean disc ([entering a film](film-entrance.md)). That is every sign; a decline into the film-less resolve rides the spring as described here.

## When it appears

Every time a hold completes on a screen that arms one: [hold right — sign](../actions/hold-right-sign.md) from the [ask](../screen-types/hero-ask.md) or [Confirm?](../screen-types/confirm.md), and [hold left — decline](../actions/hold-left-decline.md) from any navigable screen of a flow that has a failing ending. An early release is a different thing entirely — it drains ([release early](../actions/hold-release-early.md)).

An entry (the PIN row) is the exception: its hold-left cancel fills the rings, not a token disc, and it never goes through this fade — the row plays its own outcome in place ([hold left cancels the row](../actions/entry-cancel.md)).

## How the alpha is driven

`hold_commit` ({{loc:pq1.flow.Sim.hold_commit}}) calls `go_to` first, then marks the hold `done` and records `mix_dir` — the morph spring's **new** target, i.e. the direction the leg it just started points in. Read it before the `go_to` and you get the previous leg's direction, which makes the fade run backwards whenever the two differ. The draw then reads the fill's alpha straight off that spring ({{loc:pq1.flow.Sim.draw}}):

```
ha = 1 - (m if mix_dir >= 0.5 else 1 - m)      # m = the morph spring, clamped 0..1
```

Into a seeded film the same alpha is the beat's fade instead — `1 − ease_out(k)` over {{tok:pq1.motion.FADE_MS}}, the factor the text and chevrons take ([entering a film](film-entrance.md)). On every other leg the fade has **no duration of its own**. It is the leg's progress, inverted, and it works in either direction. Measured on `send_token` at the `NAV` pace, the fill's alpha over the first panel frames of the leg: 0.69, 0.34, 0.15, 0.06, 0.02 — essentially gone in under half a leg, while the disc is still moving.

The fill *level* does not move: `motion.hold_fill` clamps at 1 past the commit ({{loc:pq1.motion.hold_fill}}), so the liquid never appears to fall back. Only opacity changes. When the leg settles, the hold record is discarded.

Two details worth copying exactly:

- the fill's **dress** (black film over a coloured disc, white inside a dark one) is the one resolved for the screen the hold *started* on, not for the disc now being drawn — the disc's own style swaps to the destination's at the morph's halfway point. The two agree on every live commit path but one: on `erc7730/swap` a hold-left from the intro (a black disc, so a **white** film) declines into DECLINED, whose disc is a coloured solid, and the white film rides on over it for the frame or two before it fades. Resolve the dress once, at the hold's start, and keep it;
- a commit whose target is the screen already current simply clears the hold: no leg, no fade.

## Motion

{{motion-head}}
{{row:the hold fires, measured from press-down | pq1.motion.HOLD_COMMIT_MS | — | only at completion; a release a moment earlier does nothing}}
{{row:the leg to the ending starts, same frame | - | spring NAV | an ordinary [spring morph](spring-morph.md)}}
{{row:the full fill fades out | - | spring NAV | alpha = the morph spring, inverted — no timer of its own}}
{{row:into a film: the fill fades over the entrance beat instead | pq1.motion.FADE_MS | ease_out | the disc is parked, the fill goes with the text — [entering a film](film-entrance.md)}}
{{row:the fill level holds at full | - | hold | clamped; the liquid never drains after a commit}}
{{row:the hold record is dropped | - | — | when every spring in the set has settled}}

From the commit on, the screen is input-dead: the current index is already the status screen, so the driver reports `resolving` and refuses presses ({{loc:pq1.driver.FlowDriver.press}}).

## Input

{{gestures:hero — the ask}}

## Do / Don't

- **Do** tie the fade to the transition's progress, not to a duration. If the leg is retargeted or slow, the fill still lands with it.
- **Do** keep the level clamped at full while it fades.
- **Don't** clear the fill at the commit frame. The pop is exactly what this transition exists to avoid.
- **Don't** port the fabricated instant hold: a `hold_commit` with no live hold on that side — none started, the other button's, or one already released — invents one back-dated by {{tok:pq1.motion.HOLD_COMMIT_MS}} so the fill shows full. That is for the bench player's key-down-only harness ([bench keys](../actions/bench-keys.md)).
- **Don't** port the demo's self-performed hold either — it runs through the last {{tok:pq1.motion.HOLD_COMMIT_MS}} of a commit screen's dwell so the GIF shows the gesture ([demo auto-advance](../actions/demo-auto-advance.md)). On hardware a finger starts it.

{{partial:port-notes}}
