## What it is

The reading half of a [detail](../screen-types/detail.md) or [value](../screen-types/value.md) screen: one value, one to three lines, centred in the region the token does not occupy. On a detail a caps **label** names the field in the band; a value screen carries the lines alone — `layout_of` draws a label there only on a [words grid](words-grid.md) ({{loc:pq1.layout.layout_of}}).

The label says what it is; the lines say what it is worth. Nothing else sits in the block — one value at the largest tier, one label, and if a screen needs two values of equal weight it is two screens.

Everything here is laid out by `layout_of` ({{loc:pq1.layout.layout_of}}) into flat text specs and drawn by `components.draw_text` ({{loc:pq1.components.draw_text}}).

## When it appears

On every `detail` screen, and on a `value` screen (the same block, full width, with the token parked off the panel). Never on a hero or a status screen. A [Confirm?](../screen-types/confirm.md) screen puts its one prompt in the same region, but it is a fixed word at the top tier, not a value block: no label, no line stacking, no tier fitting.

## Spec

{{fields:detail.label,detail.lines,detail.size,detail.text_x,detail.circle_x}}

A line takes one of three forms:

| form | what it is | drawn by |
|---|---|---|
| `"45.5 gwei"` | a plain value line, Regular | `cv.text` |
| `{"str": "USD Coin", "weight": "semibold"}` | a **name**: the identity the device resolved, SemiBold over its Regular address lines | `cv.text`, semibold face |
| `{"transition": ["Slot 3", "Slot 4"]}` | one value **becoming** another, on one row, a chevron between them | `components.transition_row` ({{loc:pq1.components.transition_row}}) |

`layout.line_str` ({{loc:pq1.layout.line_str}}) flattens any of them to text (a transition reads `Slot 3 ▸ Slot 4`) and `layout.line_weight` ({{loc:pq1.layout.line_weight}}) gives the face. Both are what you measure with.

Live example — `approve_token` / CONTRACT, a name over its address halves at the Default tier:

```python
lines = [{"str": "USD Coin", "weight": "semibold"},
         "0x833589fCD6eDb6E08f4",
         "c7C32D4f71b54bdA02913"]
```

## Geometry

| part | value |
|---|---|
| lines centred on x | `DETAIL_TEXT_CX` {{val:pq1.layout.DETAIL_TEXT_CX}} — keyed by the side the **circle** is docked on, so the text sits in the other region; a value screen uses `VALUE_TEXT_CX` {{val:pq1.layout.VALUE_TEXT_CX}} |
| block centred on y | {{val:pq1.layout.TEXT_CY}} (`TEXT_CY`) |
| line `i` of `n` | `TEXT_CY − (n−1)·lh/2 + i·lh`, vertically centred on that y ({{loc:pq1.layout._value_texts}}) |
| leading `lh` | `line_height(size)` ({{loc:pq1.layout.line_height}}): the size itself at 36 and 32, size + 8 at 28 and 22 |
| label | size {{val:pq1.typography.SIZE_LABEL}}, SemiBold, caps, tracking {{val:pq1.typography.LS_LABEL}} px, centred on the **circle's** x, baseline y {{val:pq1.layout.BASELINE_Y}} |
| circle column | left `COL_LEFT` spans {{val:pq1.layout.COL_LEFT}}, centre x {{val:pq1.layout.COL_LEFT_CX}}; right `COL_RIGHT` spans {{val:pq1.layout.COL_RIGHT}}, centre x {{val:pq1.layout.COL_RIGHT_CX}} |
| nudges | `circle_x` / `text_x` move the pair off the column; the CHAIN / NETWORK detail carries both, at the Confirm? screen's coordinates {{val:pq1.layout.CONFIRM_CIRCLE_X}} / {{val:pq1.layout.CONFIRM_TEXT_X}} (a confirm screen does not read the fields — `layout_of` pins it there) |
| transition row | old value, chevron, new value, the whole run centred on the text x; the chevron centre sits `{{val:pq1.components.TRANSITION_GAP}} × size` past each value's edge |

Three lines at the Default tier land on y 42.5 / 72.5 / 102.5, so the third dips into the band's y range. That is intended and safe: the label is over in the circle's column, far to the side.

### The tiers

Always the largest tier whose content fits. Measure the longest unbreakable run with `typography.text_width` ({{loc:pq1.typography.text_width}}), in the face that line will use.

| tier | max characters per line | max lines | full-width (value screens) |
|---|---|---|---|
| {{val:pq1.typography.SIZE_XL}} | 12 | 1 | 17 |
| {{val:pq1.typography.SIZE_L}} | 14 | 1 | 20 |
| {{val:pq1.typography.SIZE_M}} | 16 | 2 | 23 |
| {{val:pq1.typography.SIZE_BODY}} | 21 | 3 | 30 |

Does not fit at the Default tier? Split it across two screens — or, when it is ONE value that must stay whole (a 32-byte hash), page it inside its screen ([detail — paged](../screen-types/detail-paged.md)). Never below the Default tier, never truncated, never an ellipsis.

The reference **does not fit at runtime**: `size` is written in the flow and `normalize_screens` accepts it as given — even an off-scale one ({{loc:pq1.layout.normalize_screens}}; a known gap in the checker's baseline). On the device the value is real data, so the firmware has to run the rule itself and pick the tier per transaction.

SemiBold runs wider than Regular — about 3 % on the live name lines, more on some strings — so measure a name in its own face (`typography.text_width(name, size, "semibold")`), not in Regular.

## Motion

The block does not animate. It arrives and leaves with its screen.

{{motion-head}}
{{row:outgoing block starts fading as the leg begins | - | spring NAV | the screen's own alpha spring, label and lines together}}
{{row:incoming block is released after | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the token leads, the text lands just after — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:no stagger inside the block | - | cut | all lines share one alpha; they never come in one by one}}
{{row:a paged value: the showing page fades out | pq1.motion.PAGE_FADE_MS | ease_out | sequential, never a crossfade — see [page flip](../transitions/page-flip.md)}}
{{row:… then the next page fades in | pq1.motion.PAGE_FADE_MS | ease | the incoming half of the same swap ({{loc:pq1.motion.page_flip}}); the pager's number switches between the two}}
{{row:demo only: a detail advances itself after | pq1.motion.DETAIL_DWELL | — | **do not port** — on the device a detail waits for a press}}

Nothing reflows, ever. A value is laid out once, from the screen's own `size`, and then only its alpha changes.

## Input

{{gestures:detail — middle}}

Reading a detail is navigation: either tap moves, hold left declines, hold right is unbound here — a signature is given on the [ask](../screen-types/hero-ask.md) or at [Confirm?](../screen-types/confirm.md), never on a detail.

## Preview

No clip of its own. The block plays in [Detail](../screen-types/detail.md) and [Value — full-width text](../screen-types/value.md).

## Do / Don't

- **Do** fit the tier on the device, from the real value, with the rule above.
- **Do** put the resolved name on SemiBold and leave the address lines Regular — the face is the hierarchy.
- **Do** break an amount **after** the number when the pair is too long ("min. 1,842.31" / "USDC"). A number never breaks.
- **Do** keep a token the device cannot resolve in address mode: the address alone, two lines at the Default tier.
- **Don't** re-case, re-punctuate or reformat a value that came from the transaction.
- **Don't** ellipsize or truncate to make something fit.
- **Don't** hard-code a sample value from a flow module. Every line on a detail is per-transaction data.
- **Don't** centre the label over the text; it belongs to the circle's column.

{{partial:port-notes}}
