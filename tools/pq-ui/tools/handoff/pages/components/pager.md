## What it is

The small `n/m` mark at the top centre of the panel, between the two [corner chevrons](chevrons.md). One drawing, `components.pager` ({{loc:pq1.components.pager}}), with two jobs:

| where | `n/m` means | does it change on the screen? |
|---|---|---|
| a paged [detail](../screen-types/detail-paged.md) or [value](../screen-types/value-paged.md) | page `n` of `m` of ONE long value (a full hash) | yes — it follows the [page flip](../transitions/page-flip.md) |
| a batch [hero](../screen-types/hero-pager.md) | transaction `n` of `m` in the batch | never — it is a position, not a page |

It is drawn only when `m` is 2 or more. A single-page screen has no pager.

## When it appears

On a screen whose spec has `pages` (two or more pages), and on a hero whose spec has `pager`. In the live flows: the two-page hash detail of `eip1271/personal_counterfactual_hash` (the only paged screen today — no live value screen overflows into pages), and every BATCH hero, in both its announce form (with the [band chevron](band-chevron.md)) and its ask form.

## Spec

{{fields:pager,pages}}

A hero's `pager` is validated in `normalize_screens` ({{loc:pq1.layout.normalize_screens}}): two whole numbers, 1 ≤ n ≤ m. On a paged screen there is no field for the pager: `m` is the number of pages and `n` is the page showing.

Size: the code draws the pager at the **label** size ({{val:pq1.typography.SIZE_LABEL}}), so it reads like the detail label at the other edge of the panel — and `pq1/DESIGN.md` § Typography says the same. The two schema rows above still say the smaller paging size ({{val:pq1.typography.SIZE_PAGING}}): that half-sentence in the `pq1/layout.py` docstring is stale. Port the label size.

## Geometry

| part | value |
|---|---|
| text | `n/m`, Regular weight, letter spacing 1 px |
| centre x | {{val:pq1.layout.CENTER_X}} |
| baseline y | {{tok:pq1.components.PAGER_BASELINE}} |
| size | {{val:pq1.typography.SIZE_LABEL}} |
| colour | white × {{val:pq1.components.PAGER_ALPHA}} (`PAGER_ALPHA`) — white scaled toward black, then scaled again by the screen's alpha |

The corner chevrons share the top strip (slots {{val:pq1.layout.CHEV_LEFT}} and {{val:pq1.layout.CHEV_RIGHT}}); the pager sits centred between them, far from both.

## Motion

{{motion-head}}
{{row:arrives and leaves with its screen | - | spring NAV | drawn under the screen's own text-alpha spring, like every text of that screen — see [spring morph](../transitions/spring-morph.md)}}
{{row:page flip, first half: the old page fades out | pq1.motion.PAGE_FADE_MS | ease_out | the code runs it inverted (1 − ease_out); the pager still reads the OLD page, at full strength}}
{{row:the number switches | - | cut | on the first frame the old page has reached zero; the pager itself never fades during a flip}}
{{row:page flip, second half: the new page fades in | pq1.motion.PAGE_FADE_MS | ease | the pager already reads the NEW page}}
{{row:demo only: each page holds this long, then turns by itself | pq1.motion.PAGE_SWAP_MS | — | the demo starts the flip one `PAGE_FADE_MS` BEFORE the slot ends, so the fade-out lands on the boundary; **do not port** — on the device only a tap turns a page}}

The rule in one line: the pager reads the page that is visible. The code is `Sim._draw_pages` ({{loc:pq1.flow.Sim._draw_pages}}); the envelope is `motion.page_flip` ({{loc:pq1.motion.page_flip}}).

On a hero the pager is static. It is drawn by `Sim.draw` under the hero's alpha, so between two screens it simply crossfades with the rest of the text. Nothing turns.

A tap that lands **during** a flip starts a new flip from the page the first one was heading to. In the reference that page pops to full strength on the frame the tap lands and then fades over the new flip's first half, and the pager jumps to its number at once. This is an artefact of the reference, not a rule — a flip is the one motion here that is not retargeted from its live pose. Decide it with the designer rather than copying it blind.

A screen is entered on page 1 — or on its **last** page when the user comes back into it with a left tap, so left undoes right. The pager shows that page from the first frame of the arrival.

## Input

{{gestures:detail — paged}}

The pager takes no input; it reports. On a paged screen a right tap turns to the next page until the last, then leaves; a left tap turns back until the first, then leaves — see [tap on a paged screen](../actions/tap-page.md). On a batch hero the pager changes nothing: the hero behaves as any [ask](../screen-types/hero-ask.md) or [intro](../screen-types/hero-intro.md).

## Preview

No clip of its own. The flipping pager plays in [Detail — paged](../screen-types/detail-paged.md) (there the demo clock turns the page); the static one in [Hero — batch position](../screen-types/hero-pager.md).

## Do / Don't

- **Do** switch the number at the midpoint of the flip, in one frame.
- **Do** keep `n/m` as data: the batch size and the page count are per-transaction values.
- **Don't** fade or slide the pager during a flip.
- **Don't** draw `1/1`.
- **Don't** turn a batch hero's pager with taps — it is not a page count.
- **Don't** port the demo's page-turn clock ({{tok:pq1.motion.PAGE_SWAP_MS}}).

{{partial:port-notes}}
