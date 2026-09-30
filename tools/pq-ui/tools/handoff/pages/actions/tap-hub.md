## What it is

On a hero — an idle screen — **right leads on and left never does**. A right tap goes into the details; that is what "the ask is the hub" means. A left tap goes back one screen where there is one and does **nothing** where there is not (user rule, Sep 2026): pressing left must never move the signer forward.

Two functions hold the rule. `FlowDriver._hub_target` ({{loc:pq1.driver.FlowDriver._hub_target}}) says where a right tap lands, and `layout.back_target` ({{loc:pq1.layout.back_target}}) says where a left tap lands, or that it lands nowhere. `_tap` reads the side first ({{loc:pq1.driver.FlowDriver._tap}}). The chevrons do not follow it: a hero keeps **both** corner chevrons even where the left tap does nothing (user decision, Sep 2026).

## When it appears

On every `hero` screen: the opening [ask](../screen-types/hero-ask.md), the [intro](../screen-types/hero-intro.md) that some families put in front of it, the returning ask after the last detail, and every [batch segment's](../screen-types/batch-segment.md) own hero.

## Where the tap lands

| the hero | right tap goes to | left tap goes to |
|---|---|---|
| an intro, with a hero right after it | that next hero — the ask | the screen before it, or nothing on the flow's first screen |
| any other hero | the **current segment's** first `detail` / `value` / `confirm` screen (`section_start`, {{loc:pq1.driver.FlowDriver.section_start}}) | the screen before it — the last detail from the returning ask, the intro or BATCH screen from an opening ask — or nothing |
| a hero whose segment has no such screen | nowhere — the tap returns nothing | as above |

"Nothing" means the flow's first screen, or the first screen after a status: a mid-batch ending is never walked back into.

Two things follow from reading `section_start` rather than the neighbour:

- **The returning ask restarts the walkthrough on the right.** Standing on the ask at the end of the details, a right tap goes back to the *first* detail; a left tap steps back to the *last* one, on its last page.
- **The section is always entered at its first screen and its first page.** Even when the hub target sits *behind* the current screen, `go_to` is called forward (`back=False`), so a [paged](../screen-types/detail-paged.md) first screen opens on page 1. Only a left tap inside the details enters a screen on its last page — see [tap on a paged screen](tap-page.md).

In a [batch](../screen-types/batch-segment.md) every segment has its own hub: `section_start` and `last_nav` are read from the segment holding the current screen ({{loc:pq1.driver.FlowDriver._segment}}), so the ask inside transaction 2 enters transaction 2's details and can never reach transaction 1's. In the shipped batch a segment opens on a BATCH n screen with the ask right behind it, so the first rule applies there: a tap on BATCH 2 lands on its ask, and the next tap enters the details.

On a hero `armed()` ({{loc:pq1.driver.FlowDriver.armed}}) lists `forward` when a hub target exists and `back` only when `back_target` finds a screen behind — so the opening ask never lists `back`.

## Motion

A hub tap is an ordinary forward leg — one [spring morph](../transitions/spring-morph.md) at the NAV profile ({{val:pq1.motion.NAV}}; the demo loop's KIOSK pace is not the device's).

{{motion-head}}
{{row:press-down: the pressed side's chevron nudges | pq1.motion.PRESS_FEEDBACK_MS | ease_out | specified, not rendered here — see [press feedback](../components/press-feedback.md)}}
{{row:nothing else moves: the press may still become a hold | pq1.motion.TAP_MAX_MS | hold | the tap fires on RELEASE, only if the press stayed inside this window}}
{{row:the leg — circle x / y / r, glyph mix, text alphas | - | spring NAV | retargeted from the live pose, so a second tap mid-flight is not dropped}}
{{row:the incoming caption is released after the circle | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the disc leads, the words follow}}
{{row:once every spring sleeps, the idle clock restarts | pq1.motion.SWEEP_DELAY_MS | — | then the [idle sweep](../components/idle-sweep.md) and the chevron hint begin again on the new screen}}

## Input

{{gestures:hero — the ask}}

{{gestures:hero — an intro}}

Both tables are executed against the reference driver. Read the intro's `hold right` row: `commit` is false there, so the right hold is unbound — see [unbound gestures](unbound-gestures.md).

## Preview

{{preview}}

## Do / Don't

- **Do** resolve the hub target at the moment of the tap, from the segment the flow is standing in.
- **Do** fire on release, inside {{tok:pq1.motion.TAP_MAX_MS}}.
- **Don't** let a left tap on a hero move forward — ever. It goes back one screen or does nothing.
- **Don't** read the corner chevrons as the only source of truth for what is bound. An intro draws no corner pair — its caption carries the [band chevron](../components/band-chevron.md) instead — and still takes the right tap and the left hold.
- **Don't** port the hero dwell ({{tok:pq1.motion.HERO_DWELL}}): on the device a hero waits forever — see [demo auto-advance](demo-auto-advance.md).

{{partial:port-notes}}
