## What it is

Inside the details the two buttons split: **left regresses, right progresses**. The mapping never flips while the signer reads — not on a [detail](../screen-types/detail.md), not on a full-width [value](../screen-types/value.md), not on the mid-flow [Confirm?](../screen-types/confirm.md). A tap fires on release, inside {{tok:pq1.motion.TAP_MAX_MS}}, and moves exactly one step.

On a hero both taps do the same thing instead — see [tap on the ask](tap-hub.md). On a PIN row a tap dials a digit — see [entry — tap to dial](entry-dial.md).

## When it appears

On every navigable screen that is not a hero and not an entry. `FlowDriver._tap` ({{loc:pq1.driver.FlowDriver._tap}}) is the whole rule; `FlowDriver.armed` ({{loc:pq1.driver.FlowDriver.armed}}) decides which of the two sides is live.

## Where the tap lands

| tap | first | then | at the edge |
|---|---|---|---|
| right | a page ahead on this screen → turn it | the next screen | on the segment's last navigable screen: unbound, nothing fires |
| left | a page behind on this screen → turn it back | the previous screen, **entered on its last page** | on the flow's first screen: unbound |

The page cases are [tap on a paged screen](tap-page.md). The screen cases use two different bounds, and only the forward one is segment-aware:

- **Forward** stops at `last_nav` ({{loc:pq1.driver.FlowDriver.last_nav}}) — the last navigable screen of the **current segment**, the one before the status that closes it. Forward is armed while the current index is below it. In a [batch](../screen-types/batch-segment.md) that is this transaction's returning ask, not the end of the whole screen list.
- **Back** is armed on plain index: any screen but the first one of the whole list ({{loc:pq1.driver.FlowDriver.armed}}). So the first detail's left tap lands on the ask. It is not segment-aware, and does not need to be: every segment after the first opens on a hero, and a hero's taps are [hub taps](tap-hub.md), so a left tap can never step backwards out of a segment.

The walk is a straight line: right from the last detail arrives on the returning ask, and from there either tap starts the details again from the top.

## Motion

Every step is one leg of the [spring morph](../transitions/spring-morph.md), at the NAV profile ({{val:pq1.motion.NAV}}) on the device.

{{motion-head}}
{{row:press-down: the pressed side's chevron nudges | pq1.motion.PRESS_FEEDBACK_MS | ease_out | specified, not rendered — [press feedback](../components/press-feedback.md)}}
{{row:the tap window: nothing is drawn yet | pq1.motion.TAP_MAX_MS | hold | past it the press is a hold, not a tap}}
{{row:the leg — circle x / y / r, glyph mix, both text alphas | - | spring NAV | the outgoing text starts fading at once}}
{{row:the incoming text is released after the circle | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | see [text-in delay](../transitions/text-in-delay.md)}}
{{row:a page turn instead of a leg: out, then in | 2 * pq1.motion.PAGE_FADE_MS | ease_out + ease | the disc does not move — [tap on a paged screen](tap-page.md)}}

A tap during a transit is never dropped: `Sim.go_to` retargets every spring from its live pose and carries the velocity ({{loc:pq1.flow.Sim.go_to}}). Tapping forward twice quickly walks two screens; tapping back mid-flight turns around where it stands — see [reversal](../transitions/reversal.md).

## Input

{{gestures:detail — first}}

{{gestures:detail — middle}}

{{gestures:value — full-width}}

{{gestures:confirm —}}

Read the `hold right` rows: on a detail and on a value it is unbound; on the Confirm? it signs. Only `commit` screens take the signature — see [hold right — sign](hold-right-sign.md).

One row reads like a contradiction and is not. In the value table both taps land on `SAFE TX HASH FINGERPRINT`: that flow's opening ask and returning ask carry the same caption, and the value sits between them. Left goes to the screen before, right to the screen after — two different screens with one name.

## Preview

{{preview}}

## Do / Don't

- **Do** keep left = back and right = forward for the whole detail section, in every flow and every family.
- **Do** arm the two sides from the current segment's bounds, so a batch's transaction 2 cannot walk into transaction 1.
- **Do** let a tap land during a transit and retarget from the pose on screen.
- **Don't** wait to see whether a second tap is coming. Double-tap is unbound outside an entry precisely so a navigation tap can fire the instant the button comes up — see [unbound gestures](unbound-gestures.md).
- **Don't** read the corner chevrons as the tap cue everywhere: a Confirm? wears the "up" pose (a hold is armed here) and still takes both taps; its [band](../components/confirm-band.md) is what says so.
- **Don't** port the detail dwell ({{tok:pq1.motion.DETAIL_DWELL}}) or the confirm dwell ({{tok:pq1.motion.CONFIRM_DWELL}}): on the device a detail waits for a press — see [demo auto-advance](demo-auto-advance.md).

{{partial:port-notes}}
