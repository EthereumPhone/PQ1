## What it is

A [value screen](value.md) whose value does not fit three full-width lines: the same centred text with no disc on the panel, shown over two or more pages with the [pager](../components/pager.md) `n/m` top centre. It is the full-width twin of the [paged detail](detail-paged.md) — one value, one screen, read in full.

## When it appears

{{used-in}}

No shipped flow needs it today: both live digests are 32 bytes and fit three lines. The path is real and was exercised in memory for this page — `flows/fingerprint` `digest(value)` returns `pages` as soon as the hex needs more than {{val:flows.fingerprint.LINES_PER_PAGE}} lines of {{val:flows.fingerprint.BYTES_PER_LINE}} bytes, that is from 40 bytes up ({{loc:flows.fingerprint.digest}}). Port it together with the value screen; it costs nothing extra once the paged detail exists.

## Spec

{{fields:kind,value.pages,value.size,chev}}

`pages` obeys the paged detail's contract: two or more pages, each 1–3 lines, one `size` for the screen; anything else raises `ValueError` when the flow loads. `words` and `pages` cannot be combined. A sketch (the hex is per-request data):

```python
dict(id="DIGEST", kind="value", chev="lr", **digest(value))   # value: a 64-byte hex string
# digest() -> {"pages": [[line1, line2, line3], [line4, line5]], "size": 22}
```

How `digest` splits: the bytes are balanced over the fewest lines of at most {{val:flows.fingerprint.BYTES_PER_LINE}} bytes **across the whole value**, then cut into pages of {{val:flows.fingerprint.LINES_PER_PAGE}} lines. So 64 bytes give five lines of 13 / 13 / 13 / 13 / 12 bytes — pages of three and two lines; 40 bytes give four lines of 10 bytes — pages of three lines and one. The `0x` rides on the first line only.

## Geometry

- Disc parked at {{tok:pq1.layout.VALUE_PARK_X}}, as on every value screen. No label.
- Text centre x {{val:pq1.layout.VALUE_TEXT_CX}}. Each page is centred on {{tok:pq1.layout.TEXT_CY}} by its **own** line count: at 22 a three-line page sits at y 42.5 / 72.5 / 102.5 and a two-line page at y 57.5 / 87.5. Lines do not keep their position from page to page.
- Pager: centre x {{val:pq1.layout.CENTER_X}}, baseline y {{val:pq1.components.PAGER_BASELINE}}, size {{val:pq1.typography.SIZE_LABEL}}, white at {{tok:pq1.components.PAGER_ALPHA}} ({{loc:pq1.components.pager}}). Its ink ends above the first line of a three-line page.
- Corner chevrons stay in their slots.

## Motion

Two motions, both defined elsewhere and unchanged here: the disc leaves and returns as on a [value screen](value.md), and the page turns as on a [paged detail](detail-paged.md) — `Sim._draw_pages` draws both kinds ({{loc:pq1.flow.Sim._draw_pages}}).

{{motion-head}}
{{row:the disc travels off the left edge | - | spring NAV | see [value](value.md)}}
{{row:the first page is released | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the screen's own text alpha; the pager rides it too}}
{{row:turn, phase 1: the showing page fades away | pq1.motion.PAGE_FADE_MS | ease_out | }}
{{row:the pager number switches | - | cut | between the two phases}}
{{row:turn, phase 2: the new page fades in | pq1.motion.PAGE_FADE_MS | ease | sequential, never a crossfade — see [page flip](../transitions/page-flip.md)}}
{{row:DEMO ONLY: each page rests | pq1.motion.PAGE_SWAP_MS | hold | the demo dwell is this times the page count; do not port}}

## Input

The executed truth table has no paged value, because no live flow has one. The rows below are the paged **detail's**; the driver runs the same code for both — `_tap` reads the page state of every non-hero screen ({{loc:pq1.driver.FlowDriver._tap}}). A probe on a synthetic 64-byte digest gave the same results.

{{gestures:detail — paged}}

- Right tap: next page, then the next screen. Left tap: previous page, then the previous screen.
- Stepping back onto it from a later screen enters on the **last** page. Entering from an ask — either tap, the opening or the returning one — always opens page 1. When the value is the only screen of its section, its right neighbour is the returning ask, so the last-page entry never happens there.
- `hold left` declines but shows no fill: the disc is off the panel. See the gap noted on [value](value.md).

See [tap on a paged screen](../actions/tap-page.md).

## Preview

The clip is **synthetic**: no live flow pages a full-width value, so the generator builds one — an ask, then `digest()` of a 64-byte value — and lets the demo loop walk it (KIOSK pace). The page turns on the demo's page clock; on the device only a tap turns it.

{{preview}}

## Do / Don't

- **Do** reuse the paged detail's page state and envelope — one implementation, two layouts.
- **Do** keep every page at the one size; never shrink the last page to avoid a turn.
- **Don't** shorten, ellipsize or split the value over two screens to avoid a page turn: the user must be able to verify all of it.
- **Don't** port {{tok:pq1.motion.PAGE_SWAP_MS}}: on the device only a tap turns a page.

{{partial:port-notes}}
