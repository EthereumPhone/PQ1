## What it is

The signature gesture. Holding the **right** button on a screen that commits fills the token disc from the bottom up; when the fill is complete the flow leaves for its success ending. Letting go a moment earlier does nothing.

## Where it is armed

Only where the screen's `commit` is true — the [ask](../screen-types/hero-ask.md) and the mid-flow [Confirm?](../screen-types/confirm.md). On every other screen the right hold is unbound: no fill is drawn and nothing fires. In a batch the hold signs the **current segment's** ending.

## Timeline (ms since press-down)

{{motion-head}}
{{row:nothing visible: the press may still be a tap | pq1.motion.TAP_MAX_MS | hold | a tap never flashes a partial fill}}
{{row:the fill rises | pq1.motion.HOLD_COMMIT_MS - pq1.motion.TAP_MAX_MS | linear | constant speed: progress you can trust}}
{{row:the action fires, measured from press-down | pq1.motion.HOLD_COMMIT_MS | — | only at completion}}
{{row:the full fill fades out | - | spring NAV | it rides the transit's own spring — see [hold commit fade](../transitions/hold-commit-fade.md)}}
{{row:released early: the fill drains | pq1.motion.HOLD_SNAPBACK_MS | ease_out | see [release early](hold-release-early.md)}}

The fill's value is `motion.hold_fill(ms since press)` ({{loc:pq1.motion.hold_fill}}) — a pure function, so any frame can be recomputed.

## Rules

- The **first** live hold wins: a second button pressed during a hold draws nothing.
- A sweeping disc glides to the centre while the hold is live.
- Once the ending starts playing, the screen accepts no input. The ending is the film: on the device it loops until the signing core answers ([loading loop](../transitions/loading-loop.md)).

## Truth table (executed against the reference driver)

{{gestures:hero — the ask}}

## Preview

The strip under the panel is a reading aid (which button is down) — it is not part of the display.

{{preview}}

{{partial:port-notes}}
