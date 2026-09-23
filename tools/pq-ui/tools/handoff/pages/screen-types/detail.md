## What it is

One fact of the transaction per screen — the network, the recipient, the amount, the fee. The token disc docks in a 100 px column on one side with a caps label under it; the value takes the region on the other side, centred, 1–3 lines at **one** size tier. A detail is read-only: nothing is signed here, the right hold is unbound.

## When it appears

Every screen between the [ask](hero-ask.md) and its return. {{used-in}}

- Sides alternate, so the disc crosses the panel on every step. Flows set `side` explicitly; when absent it falls out of the screen's index (even = left, odd = right — `normalize_screens`, {{loc:pq1.layout.normalize_screens}}).
- A segment with {{val:pq1.layout.CONFIRM_MIN_DETAILS}} or more details (value screens count) gets a [Confirm?](confirm.md) inserted at the segment's index {{val:pq1.layout.CONFIRM_INDEX}} — its 6th screen.
- A value too long for three lines becomes a [paged detail](detail-paged.md); a value that needs the whole width becomes a [value screen](value.md).

## Spec

{{fields:kind,side,label,lines,size,circle_x,text_x,pulse,icon,chev}}

{{example}}

- `kind` defaults to `"detail"`, `label` to none, `size` to 28, `chev` to `"lr"`.
- A line is a plain string, a **name** line `{"str": NAME, "weight": "semibold"}`, or a **transition** row `{"transition": [old, new]}` drawn as `old ▸ new` on one row. See [detail text](../components/detail-text.md).
- `circle_x` / `text_x` nudge the disc and the text off the column grid. A **chain badge** sets neither: it says `chain=<id>` and composes itself — see [chain badge](chain.md).
- `pulse` adds the attention rings around the docked disc — see [pulse rings](../components/pulse-rings.md).

### Choosing the tier (the design rule — the Python does not enforce it)

| size | max characters per line | max lines |
|---|---|---|
| 36 | 12 | 1 |
| 32 | 14 | 1 |
| 28 | 16 | 2 |
| 22 | 21 | 3 |

Use the largest tier that fits. Never below 22, never truncate, never ellipsize. `layout_of` does not measure, clip or shrink the value: `size` is whatever the flow wrote. On the device every value line is per-transaction data, so **the firmware must run this rule itself**.

## Geometry

{{geometry}}

A [chain badge](chain.md) composes its own anchors; an ordinary detail sits on the column grid:

- Disc column centre: x {{val:pq1.layout.COL_LEFT_CX}} (side left) or x {{val:pq1.layout.COL_RIGHT_CX}} (side right); centre y {{val:pq1.layout.CIRCLE_CY}}, {{tok:pq1.layout.CIRCLE_R}}. It never resizes.
- Text centre: x 263 when the disc is left, x 163 when it is right (`DETAIL_TEXT_CX`, {{loc:pq1.layout.DETAIL_TEXT_CX}}) — always the region opposite the disc.
- The block is centred on {{tok:pq1.layout.TEXT_CY}}. Line pitch is `line_height(size)` ({{loc:pq1.layout.line_height}}): the size itself at 32 and 36, size + 8 below (28 → 36, 22 → 30). Line `i` of `n` sits at `TEXT_CY − (n − 1) · pitch / 2 + i · pitch`; each line is centred on its own x and y (`_value_texts`, {{loc:pq1.layout._value_texts}}).
- The label is {{val:pq1.typography.SIZE_LABEL}} px SemiBold caps, tracking +{{val:pq1.typography.LS_LABEL}} px, centred on the **disc's** x, baseline y {{val:pq1.layout.BASELINE_Y}}. Value lines carry no tracking.
- Three lines at 22 put the third line's centre at y 102.5: it reaches into the bottom band on the text side. That is allowed — the label sits on the other side.

## Motion

{{motion-head}}
{{row:arrive: the disc travels to its column | - | spring NAV | circle x / y / r, glyph mix and every screen's text alpha are one spring set — see [spring morph](../transitions/spring-morph.md)}}
{{row:the previous screen's text fades out | - | spring NAV | starts on the press, not after the disc lands}}
{{row:label + value are released | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the wait before the text's alpha spring gets its target, so the disc leads — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:the trail chases the travelling disc | pq1.motion.CHAIN_TAU | tau_chase | per link, links at most {{val:pq1.motion.MAX_GAP}} px apart — see [trail](../components/trail.md)}}
{{row:DEMO ONLY: rest, then auto-advance | pq1.motion.DETAIL_DWELL | hold | counted from spring settle; do not port}}

At rest a detail stands still: no sweep (heroes only), no chevron hint. Only `pulse` rings move. A text fade is the text colour multiplied by the alpha — the ground is black, so no blending is needed; text under alpha 0.01 is not drawn ({{loc:pq1.canvas.Canvas.text}}).

## Input

{{gestures:detail — middle}}

- Taps fire on **release**. Left goes back one screen, right goes forward. From the first detail, left returns to the ask; from the last, right lands on the returning ask.
- `hold left` declines from every detail (when the flow has a failing ending); the fill rises in the docked disc. `hold right` is unbound: no fill, nothing fires.
- A press during the travel is never dropped — the springs retarget from the live pose ([reversal](../transitions/reversal.md)).

See [tap left / right](../actions/tap-navigate.md), [hold left — decline](../actions/hold-left-decline.md).

## Preview

Walked by the demo loop (KIOSK pace, dwell timers) — the device moves only on a press, at the NAV pace.

{{preview}}

## Do / Don't

- **Do** render a value exactly as supplied: never re-case, re-punctuate or reformat it.
- **Do** keep one tier for the whole screen — a SemiBold name line and its Regular address lines share the size.
- **Do** break an address mid-string into centred lines of 21 characters or fewer; the full value must be verifiable.
- **Don't** fix a sample value into firmware: `lines` in a flow module are placeholders that exercise the tier rule.
- **Don't** port {{tok:pq1.motion.DETAIL_DWELL}} or the KIOSK spring pace.

{{partial:port-notes}}
