## What it is

The refusal gesture. Holding the **left** button fills the token disc; when the fill completes the flow leaves for its failing ending — DECLINED. It is the mirror of [hold right — sign](hold-right-sign.md) in shape and timing, and its opposite in reach: **declining is always cheap, signing is not.**

## Where it is armed

On **every navigable screen** of a flow that has a failing ending: the [intro](../screen-types/hero-intro.md), the [ask](../screen-types/hero-ask.md), every [detail](../screen-types/detail.md), every [value](../screen-types/value.md), the [Confirm?](../screen-types/confirm.md), the returning ask. The signer never has to walk back to say no.

Two places it is not the decline:

- **Status screens take no input at all** ({{loc:pq1.driver.FlowDriver.armed}}) — once an ending is playing, the transaction is already dispatched. Decline has to happen before that.
- **On a PIN row the left hold is the cancel**, not a decline: it fills the eight rings instead of a disc and discards the row. See [entry — hold left cancels the row](entry-cancel.md).

`armed()` adds `decline` only when the flow declares a failing ending. `flows.playable` picks it — the `ENDS` entry named `declined` if there is one, else the first by name among the entries whose `state` is not `done` (an entry's own verdicts never count) — and appends it as the last screen so the driver can branch to it from anywhere ({{loc:flows.playable}}). Of the live flows exactly one has none: `pin/unlock`, whose verdicts live inside its entries. Because the decline ending is appended after the last segment it belongs to no segment at all ({{loc:pq1.layout._segments}}), so in a [batch](../screen-types/batch-segment.md) it is reachable from transaction 1 and transaction 3 alike.

## Timeline (ms since press-down)

{{motion-head}}
{{row:nothing visible: the press may still be a tap | pq1.motion.TAP_MAX_MS | hold | a tap never flashes a partial fill}}
{{row:the fill rises | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | the same constant-speed gauge the sign hold uses — [hold flood](../components/hold-flood.md)}}
{{row:the decline fires, measured from press-down | pq1.motion.HOLD_COMMIT_MS | — | only at completion; a moment earlier does nothing}}
{{row:the full fill fades out over the leg to the ending | - | spring NAV | [hold commit fade](../transitions/hold-commit-fade.md)}}
{{row:released early: the fill drains | pq1.motion.HOLD_SNAPBACK_MS | ease_out | [release early](hold-release-early.md)}}

The fill is drawn in whatever token the screen is resting on, in the dress that body asks for ({{loc:pq1.components.hold_style}}) — never a special decline graphic. On a detail it is the same disc as on the ask — radius {{tok:pq1.layout.CIRCLE_R}}, only docked to the detail's side; the circle never resizes. Both holds fill the same way; the pressed side is what the chevrons say. A sweeping disc glides home while the hold is live.

## The race between the two holds

Only one fill exists at a time: `Sim.hold_begin` keeps the **first** live hold and ignores a second button pressed during it ({{loc:pq1.flow.Sim.hold_begin}}). But both press clocks keep running, and `FlowDriver.frame` commits whichever reaches {{tok:pq1.motion.HOLD_COMMIT_MS}} first ({{loc:pq1.driver.FlowDriver.frame}}).

Executed: press both buttons in the same instant on the ask and hold them, and the flow **declines** — `frame()` walks the sides in the order left, right, so an exact tie goes to the left. Press right first and left a moment later, and it signs. Whichever fires first ends the screen's input: the other side's pending hold is dropped.

## Input

{{gestures:detail — first}}

{{gestures:hero — an intro}}

The `hold left` row fires from a plain detail and from an intro that arms nothing else.

## Preview

{{preview}}

## Do / Don't

- **Do** arm it on every navigable screen, including the ones where nothing else is armed.
- **Do** fire it only at completion, and drain it on an early release.
- **Do** send it to the flow's own failing ending. A family's decline screen is part of the flow, not a generic error.
- **Don't** arm it on a status screen, or let it interrupt an ending that is already playing.
- **Don't** draw a fill when the flow declares no failing ending — there is nothing to commit to.
- **Don't** invent a second, shorter decline (a tap, a double press). The weight of the gesture is the point.

{{partial:port-notes}}
