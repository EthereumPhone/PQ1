## What it is

The BATCH screen: a hero that carries the pager `n/m` at the top centre. It tells the signer which transaction of the batch is on the panel — `1/3`, `2/3`, `3/3`. The pager is a **position**, not text pages: nothing flips and no tap turns it. Only the two BATCH screens of a transaction carry it — the transaction's own ask and its details draw no pager at all — and the number changes only when the next [segment](batch-segment.md) opens.

It wears two forms, both built by `flows.batch.batch_hero()` ({{loc:flows.batch.batch_hero}}):

| form | caption | chevrons | `commit` |
|---|---|---|---|
| **announce** | `BATCH SIGN TX 1 OF 3` + the [band chevron](../components/band-chevron.md) | corners hidden | false — not an ask (the [intro](hero-intro.md) idiom) |
| **ask** | `BATCH SIGN TX 1 OF 3 TX?` | corners back (`"lr"`), `hint` on | true — the right hold signs this transaction |

## When it appears

{{used-in}}

Twice per transaction: the announce form opens the segment, the ask form closes it after the details. The **last** transaction has nothing to point on to, so it opens on the ask form too and never wears the band chevron.

## Spec

{{fields:pager,bottom,band_chev,commit,chev,hint}}

{{example}}

- `pager` is `[n, m]`, two integers with 1 ≤ n ≤ m. Anything else raises in `normalize_screens` ({{loc:pq1.layout.normalize_screens}}).
- A pager with m under 2 draws nothing (`components.pager`, {{loc:pq1.components.pager}}): a batch of one shows no pager.
- The schema note above still says the pager is 12 px. The code draws it at the label size, {{tok:pq1.typography.SIZE_LABEL}}, and `DESIGN.md` § Typography agrees with the code.
- The `chev` note above ("None = no input") describes the drawing, not the arming: the announce form takes both taps and the left hold although its corner chevrons are hidden — see [hero — an intro](hero-intro.md) § Spec.
- n and m are per-batch data. So is the caption: it is built from them.

## Geometry

{{geometry}}

The table above does not list the pager. It is drawn at x {{val:pq1.layout.CENTER_X}}, baseline y {{val:pq1.components.PAGER_BASELINE}}, size {{val:pq1.typography.SIZE_LABEL}}, letter spacing 1, white scaled to {{val:pq1.components.PAGER_ALPHA}} — the same spot and style a [paged detail](detail-paged.md) uses, between the two corner chevrons. See [pager](../components/pager.md).

In the announce form the caption is drawn centred on x {{val:pq1.components.VIEW_MORE_CX}}, not on the x the layout reports, to make room for the band chevron — see [hero — an intro](hero-intro.md) § Geometry.

## Motion

{{motion-head}}
{{row:arrive from the previous screen | - | spring NAV | disc, glyph mix and text alpha on one spring set — see [spring morph](../transitions/spring-morph.md)}}
{{row:caption and pager fade in, after the disc starts | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the pager is drawn under the hero's own text alpha, so it fades with the caption}}
{{row:caption and pager fade out when the screen is left | - | spring NAV | at once, no delay}}
{{row:the pager while the screen rests | - | hold | static; `motion.page_flip` never runs for a hero}}
{{row:rest before the idle sweep starts | pq1.motion.SWEEP_DELAY_MS | — | both forms sweep like any hero}}
{{row:idle sweep, one full side-to-side cycle | pq1.motion.SWEEP_PERIOD_MS | sine + tau_chase | only the disc and its trail move; the pager and the caption stay still}}
{{row:chevron hint cycle (ask form only) | pq1.motion.CHEV_HINT_PERIOD_MS | ease + sine | the corner chevrons turn up on `ease`, bob on a half sine, turn back — see [chevrons](../components/chevrons.md)}}

Between the announce hero and the transaction's own ask the pager fades out, because the inner ask has no pager. Two numbers never crossfade directly: a pager hero is always left for the inner ask, the details or an ending. The old number fades out with its screen, the ending plays, and the new number fades in with the next BATCH screen. The number never rolls or slides.

## Input

Verified on the reference driver with flow `batch/transfers`:

| form | either tap | hold right | hold left |
|---|---|---|---|
| announce | to the next hero: the transaction's own ask (`SEND 1,250 TOSHI?`) | unbound, no fill | declines the whole batch |
| ask, opening the last transaction | to the transaction's own ask | signs the last transaction: the batch ending plays | declines the whole batch |
| ask, returning after the details | back into the details, at their first screen | signs this transaction: its own ending plays | declines the whole batch |

The executed truth tables for the two forms are on [hero — an intro](hero-intro.md) (announce) and [hero — the ask](hero-ask.md) (ask). The rule for the taps is `_hub_target` ({{loc:pq1.driver.FlowDriver._hub_target}}). What a hold reaches is on [batch — a run of segments](batch-segment.md).

The announce form is never returned to: a left tap on the first detail goes to the transaction's own ask, and that ask's taps go back into the details.

## Preview

The clip is the demo walk: dwell timers advance it, at the KIOSK pace. On the device each step waits for a tap and moves on the NAV spring.

{{preview}}

## Do / Don't

- **Do** keep the pager fixed for the whole segment. It changes only when the next transaction's BATCH screen arrives.
- **Do** open the last transaction on the ask form, with no band chevron.
- **Don't** bind a tap to the pager. Taps on a pager hero follow the hub rule, never a page turn.
- **Don't** lengthen the demo dwell for it: the hero dwell is untouched ({{tok:pq1.motion.HERO_DWELL}}), and the dwell is not ported anyway.

{{partial:port-notes}}
