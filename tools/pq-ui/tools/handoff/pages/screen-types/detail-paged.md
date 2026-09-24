## What it is

A [detail](detail.md) whose value is too long for its tier's three lines but must be read **in full** — a 32-byte hash. It stays ONE value on ONE screen and turns pages: two or more pages of 1–3 lines, all at the screen's one `size`, with the [pager](../components/pager.md) `n/m` top centre. The disc, the label and the chevrons do not move when the page turns; only the value lines and the pager number change.

## When it appears

Only when a value overflows and cannot be shortened. Never two screens for one value, never an ellipsis where the value must be verified. {{used-in}}

The same paging works on a full-width value — see [value — paged](value-paged.md).

## Spec

{{fields:kind,side,label,pages,size}}

{{example}}

- `pages` replaces `lines`. `normalize_screens` copies the first page into `lines` for readers that know one page ({{loc:pq1.layout.normalize_screens}}).
- Fewer than two pages, an empty page or a page over three lines raises `ValueError` — the flow does not load.
- How to split is the flow's choice. The live hash pages on byte lines: `0x` + 8 bytes / 8 bytes, then 8 / 8, at 22.
- The schema note above still says the pager is 12 px. The code draws it at the label size ({{val:pq1.typography.SIZE_LABEL}}) — the code wins.

## Geometry

{{geometry}}

- The table lists the label and the **first** page. `layout_of` also returns `fixed` (the label) and `pages` (one text list per page) — {{loc:pq1.layout.layout_of}}.
- Every page is centred on {{tok:pq1.layout.TEXT_CY}} **by its own line count**. A two-line page and a three-line page of one screen do not share line positions.
- Pager: text `n/m`, centre x {{val:pq1.layout.CENTER_X}}, baseline y {{val:pq1.components.PAGER_BASELINE}}, size {{val:pq1.typography.SIZE_LABEL}} Regular, tracking +1 px, white at {{tok:pq1.components.PAGER_ALPHA}} ({{loc:pq1.components.pager}}). It sits between the corner chevrons and is drawn only when there is more than one page.

## Motion

The screen arrives and leaves like any detail. The page turn is its own scripted envelope, `motion.page_flip(ms since the turn)` → `(a_out, a_in)` ({{loc:pq1.motion.page_flip}}) — a pure function of time. It is **sequential**, never a crossfade.

{{motion-head}}
{{row:first page arrives with the screen | - | spring NAV | the screen's own text alpha; every page alpha below multiplies it}}
{{row:turn, phase 1: the showing page fades away | pq1.motion.PAGE_FADE_MS | ease_out | alpha = 1 − ease_out(t); the incoming page is not drawn yet}}
{{row:the pager number switches | - | cut | the instant phase 1 ends; the pager itself never fades during a turn}}
{{row:turn, phase 2: the new page fades in | pq1.motion.PAGE_FADE_MS | ease | alpha = ease(t)}}
{{row:whole turn | pq1.motion.PAGE_FADE_MS * 2 | ease_out + ease | for one instant between the phases no value text is drawn}}
{{row:DEMO ONLY: each page rests | pq1.motion.PAGE_SWAP_MS | hold | the demo's page clock, equal to the detail dwell; do not port}}
{{row:DEMO ONLY: the turn starts this long into a page's slot | pq1.motion.PAGE_SWAP_MS - pq1.motion.PAGE_FADE_MS | hold | so the fade-out lands on the slot boundary; do not port}}

The demo dwell of a paged screen is the detail dwell times the page count ({{loc:pq1.flow.Sim.draw}}). The driver pins every dwell to infinity, so under input only a tap turns a page.

`flip_page` sets the page counter **at once** and then plays the envelope ({{loc:pq1.flow.Sim.flip_page}}). A second turn during a flip restarts the envelope from the page the counter already points at: the interrupted turn's incoming page — which the reader never saw — appears at **full** alpha and fades out. The live alpha is not carried over, so the text jumps in brightness. That is how the reference behaves, not a design rule: keep "the press is never dropped", and ask the designer before copying the jump.

## Input

{{gestures:detail — paged}}

- **Right tap:** the next page until the last, then the next screen.
- **Left tap:** the previous page until the first, then the previous screen.
- Stepping **back** onto a paged screen enters it on its **last** page, so left undoes right (`go_to(..., back=True)`, {{loc:pq1.flow.Sim.go_to}}). Every other arrival — forward, or from the ask — enters on page 1.
- A tap during a flip is not dropped: on the last page a right tap leaves for the next screen while the flip is still fading.
- Holds are the same as on a detail: `hold left` declines, `hold right` is unbound.

See [tap on a paged screen](../actions/tap-page.md) and [page flip](../transitions/page-flip.md).

## Preview

Walked by the demo loop (KIOSK pace, dwell timers). On the device a page turns only on a tap.

{{preview}}

## Do / Don't

- **Do** keep the label, the disc and the chevrons still during a turn.
- **Do** compute the two alphas from the ms since the turn began — never step them per frame.
- **Don't** crossfade the pages, slide them, or fade the pager.
- **Don't** port {{tok:pq1.motion.PAGE_SWAP_MS}} or the dwell: they are the demo's clock.
- **Don't** let the page state survive a forward re-entry: forward always opens page 1.

{{partial:port-notes}}
