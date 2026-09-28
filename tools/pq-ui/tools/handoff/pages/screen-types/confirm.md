## What it is

The early exit of a long flow. A big `Confirm?` sits in the detail region, the token disc docks right of centre, and the bottom band alternates two instructions: `OR VIEW MORE ▸` and `◂ TO GO BACK`. The corner chevrons rest pointing **up**: a hold is armed here. It is the second of the only two places a signature can be given — the other is [the ask](hero-ask.md).

The remaining details exist for verification, not as a toll on signing. Holding right here signs at once and skips them.

## When it appears

No flow needs to author this screen. `layout.insert_confirm` ({{loc:pq1.layout.insert_confirm}}) adds it when the flow is built:

- A **segment** is one run of screens up to a status screen ({{loc:pq1.layout._segments}}). An ordinary flow is one segment; a [batch](batch-segment.md) has one per transaction.
- A segment with {{val:pq1.layout.CONFIRM_MIN_DETAILS}} or more `detail` / `value` screens takes a `confirm` screen at index {{val:pq1.layout.CONFIRM_INDEX}} of the segment — its 6th screen. In today's flows that is the ask plus four details, then Confirm?.
- The index counts **every** screen of the segment, heroes included. A segment that opens with an [intro](hero-intro.md) ahead of its ask gets Confirm? after three details, not four. No live flow does this today; keep the rule as the code has it.
- Each segment counts its own details, never the batch total.
- A flow may spell the screen out itself, but only at that same index: a `confirm` screen anywhere else in such a segment, or a second one, is rejected when the flow is built. A segment under the threshold is not checked at all: never author one by hand there.
- The screen is inserted **before** the flow's defaults are applied, so it wears the flow's own icon and token.

{{used-in}}

## Spec

{{fields:kind,confirm.bottom,confirm.commit,chev,icon,token,next,dwell}}

{{example}}

`chev` defaults to `"up"` on this kind ({{loc:pq1.layout.normalize_screens}}). `next` and `dwell` drive the demo loop only — see Do / Don't.

## Geometry

{{geometry}}

- Disc centre x {{val:pq1.layout.CONFIRM_CIRCLE_X}}, y {{val:pq1.layout.CIRCLE_CY}}, radius {{val:pq1.layout.CIRCLE_R}}. The disc does not sweep here.
- Prompt: {{val:pq1.typography.SIZE_XL}} px Regular, mixed case, centred on x {{val:pq1.layout.CONFIRM_TEXT_X}}, vertical centre y {{val:pq1.layout.TEXT_CY}}.
- Band: {{val:pq1.typography.SIZE_QUESTION}} px caps, letter spacing {{val:pq1.typography.LS_QUESTION}}, baseline y {{val:pq1.layout.BASELINE_Y}}, text centred on x {{val:pq1.components.VIEW_MORE_CX}} (nudged left of the panel centre so text plus chevron read centred). The band chevron's centre sits {{val:pq1.components.VIEW_MORE_CHEV_GAP}} px past the text edge at y {{val:pq1.components.VIEW_MORE_CHEV_CY}}: after the text pointing right for VIEW MORE, before the text pointing left for GO BACK. Details: [confirm band](../components/confirm-band.md).
- Corner chevrons: the usual slots ({{loc:pq1.layout.CHEV_LEFT}}), both pointing up.

## Motion

All band and chevron clocks count from the moment the arriving transit **settles** (`idle_since`), not from the tap. Each arrival restarts them, so the band always opens on `OR VIEW MORE ▸`.

{{motion-head}}
{{row:arrive from a neighbour screen | - | spring NAV | the disc travels to its dock; the corner chevrons turn from sideways to up on the mix spring — see [spring morph](../transitions/spring-morph.md)}}
{{row:the prompt fades in after the disc starts | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | see [text-in delay](../transitions/text-in-delay.md)}}
{{row:band message fades in, once settled | pq1.motion.BAND_FADE_MS | ease_out | the band is not drawn during the transit at all}}
{{row:band message holds at full | pq1.motion.BAND_SWAP_MS - 2 * pq1.motion.BAND_FADE_MS | hold | }}
{{row:band message fades out | pq1.motion.BAND_FADE_MS | ease_out | alpha reaches zero exactly on the slot boundary; then the other message fades in — out, then in, never a crossfade}}
{{row:one message slot | pq1.motion.BAND_SWAP_MS | — | VIEW MORE takes the even slots, GO BACK the odd ones}}
{{row:full band cycle | 2 * pq1.motion.BAND_SWAP_MS | — | `motion.confirm_band(ms at rest)` is a pure function: {{loc:pq1.motion.confirm_band}}}}
{{row:corner chevrons bob, once per slot | pq1.motion.BAND_SWAP_MS | sine | `motion.chevron_hint` with the band slot as its period; half a sine up and back, peak 4 px. The envelope's own literals: first bob {{lit:1750 ms}} after settling, {{lit:1200 ms}} long — see [chevrons](../components/chevrons.md)}}
{{row:leaving: the prompt fades, the disc travels | - | spring NAV | }}
{{row:leaving: the band | - | cut | it is drawn only while the screen is settled and current, so it disappears on the first frame of the transit}}

The hint envelope also turns chevrons "up" before it bobs them. Here they already rest up, so only the bob shows.

A hold does not pause the band or the bob. The fill rises in the docked disc; there is no sweep to recentre.

## Input

{{gestures:confirm —}}

The standard mapping, never flipped: right tap continues into the remaining details (what `OR VIEW MORE ▸` promises), left tap goes back one detail (what `◂ TO GO BACK` says). [Hold right](../actions/hold-right-sign.md) signs and jumps straight to the segment's success ending; the remaining details are skipped. [Hold left](../actions/hold-left-decline.md) declines, as on every navigable screen. Neither the double press nor the both-button chord is a gesture here — both belong to [PIN entry](../actions/entry-enter.md); a double press lands as two plain taps, which is why the table's rows move two screens.

## Preview

{{preview}}

## Do / Don't

- **Do** insert the screen from the detail count at build time. It is a rule of the flow's shape, not a screen an author chooses.
- **Do** dress it from the flow's defaults: the disc wears the flow's own logo, ring and trail.
- **Do** restart the band on every arrival, and keep the swap sequential (out, then in).
- **Don't** port the dwell ({{tok:pq1.motion.CONFIRM_DWELL}}): it lets both messages play in the demo loop, then auto-advances. On the device the screen waits for a press, the band cycling for as long as it takes.
- **Don't** port `next`. `flows.screens(early=True)` pins the confirm screen's `next` to the ending so the demo can render the early-exit path ({{loc:flows.screens}}). On the device the hold picks the ending, not a field.
- **Don't** port the demo-performed hold: in an early-exit render the last {{val:pq1.motion.HOLD_COMMIT_MS}} ms of the dwell is the demo filling the disc by itself — see [demo auto-advance](../actions/demo-auto-advance.md).
- **Don't** flip the taps to match the alternating band. The band only names what each tap already does.

{{partial:port-notes}}
