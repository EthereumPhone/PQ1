## What it is

A screen whose value needs more room than three lines holds **pages** ([detail — paged](../screen-types/detail-paged.md), [value — paged](../screen-types/value-paged.md)). On such a screen a tap turns the page **before** it moves the flow: the pages are walked first, and only at the end of them does the same button leave for the next screen.

The rule is the first branch of `FlowDriver._tap` ({{loc:pq1.driver.FlowDriver._tap}}); the flip itself is `Sim.flip_page` ({{loc:pq1.flow.Sim.flip_page}}).

## When it appears

Wherever a screen's layout resolves to more than one page. Today one live flow has one: the two-page `HASH` of `eip1271/personal_counterfactual_hash`. The paged [value](../screen-types/value-paged.md) is specified and rendered by the layout, but no shipped flow uses it yet — treat both the same.

## The rule

| tap | while pages are left on that side | at the end of them | result |
|---|---|---|---|
| right | not on the last page → next page | on the last page → next screen | `page`, then `forward` |
| left | not on the first page → previous page | on the first page → previous screen, **entered on its LAST page** | `page`, then `back` |

The back edge is the point of it: **left undoes right.** `Sim.go_to(..., back=True)` sets the arriving screen to its last page, so walking backwards through a two-page hash shows page 2, then page 1, then the screen before it. Every other arrival — a forward tap, a [hub tap](tap-hub.md) from an ask, a restart — opens the screen on page 1. The page is never remembered between visits; it is set on arrival ({{loc:pq1.flow.Sim.go_to}}).

Forward and back stay armed for the pages as well as the screens: `armed()` adds `back` when there is a page behind *or* a screen behind, and `forward` when there is a page ahead *or* a screen ahead ({{loc:pq1.driver.FlowDriver.armed}}).

## Motion

A page turn is the only navigation that moves no disc. The token stays exactly where it is, the [pager](../components/pager.md) stays in its corner, and only the text swaps — sequentially, never crossfading.

{{motion-head}}
{{row:the showing page fades away | pq1.motion.PAGE_FADE_MS | ease_out | `motion.page_flip` first half — {{loc:pq1.motion.page_flip}}}}
{{row:the new page fades in | pq1.motion.PAGE_FADE_MS | ease | the pager number switches between the two halves, at the moment the panel is blank}}
{{row:a screen change instead, at the end of the pages | - | spring NAV | the ordinary leg — [spring morph](../transitions/spring-morph.md)}}
{{row:demo only: each page holds by itself | pq1.motion.PAGE_SWAP_MS | — | DO NOT PORT — the flip starts one fade early so it lands on the slot boundary; the driver pins the dwell to infinity}}

Two consequences worth knowing:

- The screen never leaves its settled state to turn a page, so the [idle sweep](../components/idle-sweep.md) and the chevron hint keep running through the flip.
- A second tap while a flip is in flight starts a new flip whose outgoing page is the page the interrupted flip was turning **to** — `flip_page` reads `sim.page`, which was already set to that destination. Its outgoing alpha starts at 1, so that page appears at full strength and then fades out, even if it never showed. Fast paging is legible but not smooth; do not copy that as a feature.

## Input

{{gestures:detail — paged}}

The `tap right` row turns to page 2; `tap left` from page 1 leaves for the screen before it. The `double press right` row is the rule composing with itself: outside an entry a double press is simply two taps ([unbound gestures](unbound-gestures.md)), so the first turns the page and the second, now on the last page, leaves for the next screen.

## Preview

{{preview}}

## Do / Don't

- **Do** turn the page before moving the flow, on both sides.
- **Do** enter a paged screen on its last page when arriving backwards, and on its first page every other time.
- **Do** keep the pager reading the page that is actually on the panel — it switches with the text, not with the tap.
- **Don't** move the token disc for a page turn.
- **Don't** crossfade the two pages. The swap is sequential: out, then in.
- **Don't** port the page dwell ({{tok:pq1.motion.PAGE_SWAP_MS}}). On the device only a tap turns a page.

{{partial:port-notes}}
