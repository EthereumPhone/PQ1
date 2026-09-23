## What it is

A [value screen](value.md) whose value is a list of up to {{val:pq1.layout.WORDS_MAX}} short words, laid on a fixed numbered grid instead of centred lines: two columns of four, numbered 1–4 down the left and 5–8 down the right. It is a fingerprint read as words — the firmware signing key's. No disc on the panel, no tier fitting. The grid itself is described in [words grid](../components/words-grid.md).

## When it appears

{{used-in}}

In `firmware/update` it follows the [intro](hero-intro.md) captioned FIRMWARE KEY FINGERPRINT and comes before the CONFIRM UPDATE [ask](hero-ask.md). The helper is `flows/firmware` `words(values, label=None)` ({{loc:flows.firmware.words}}).

## Spec

{{fields:kind,words,value.label,chev}}

{{example}}

- `words` is the screen's **whole** value: `normalize_screens` raises `ValueError` if it sits on a `"detail"`, if `lines` or `pages` sit beside it, or if the count is outside 1–{{val:pq1.layout.WORDS_MAX}} ({{loc:pq1.layout.normalize_screens}}). On any other kind — a hero, a status — `words` is **silently ignored**, never drawn: only a value screen has the grid.
- `size` is forced to {{tok:pq1.layout.WORDS_SIZE}}; every entry is turned into a string. `lines` stays empty.
- The words are data. The flow carries a sample; the Python defines no wordlist and no key-to-words mapping — that is the firmware's.
- `label` is optional and the live flow passes none. Leave it out — see Geometry.

## Geometry

{{geometry}}

The table shows **centre** x values because the Python canvas only draws centred text: `_words_texts` turns each edge into a centre with the measured half width ({{loc:pq1.layout._words_texts}}). On the device draw from the edges directly:

| part | rule |
|---|---|
| word `k` (0-based) | column `k // 4`, row `k % 4` |
| row centre lines, y | {{val:pq1.layout.WORDS_ROWS}} ({{loc:pq1.layout.WORDS_ROWS}}) |
| (number **right** edge x, word **left** edge x) per column | {{val:pq1.layout.WORDS_COLS}} |
| number | `k + 1`, right-aligned so digits line up, white at {{tok:pq1.layout.WORDS_NUM_ALPHA}} — grey (128, 128, 128) |
| word | left-aligned, white, as supplied |
| face | both {{val:pq1.layout.WORDS_SIZE}} px Regular, vertically centred on the row line |

- The row pitch is the grid's own (26 px). It is **not** `line_height(22)`.
- A short list is not re-centred: five words fill the left column and the first row of the right.
- Nothing measures the words. A left-column word has the space up to the right column's numbers; a right-column word has the space up to the margin. Keep them short.
- The disc is parked at {{tok:pq1.layout.VALUE_PARK_X}}; the corner chevrons stay ({{loc:pq1.layout.CHEV_LEFT}}).
- **`label` collides.** When set it is drawn as a detail label — {{val:pq1.typography.SIZE_LABEL}} px SemiBold caps, centred x {{val:pq1.layout.CENTER_X}}, baseline y {{val:pq1.layout.BASELINE_Y}}. Row 4 (centre y 110) carries ink down to y 126 on a descender, and a label such as KEY FINGERPRINT spans x 138–292 from y 114: it overlaps the fourth left word and the `8`. DESIGN.md says the grid has no caption. Do not use `label` with a full grid.

## Motion

Exactly a [value screen](value.md): the disc leaves by the left edge on the position spring and returns the same way. All numbers and words are one text block under the screen's single alpha — they arrive together and leave together. No stagger, no per-word reveal.

{{motion-head}}
{{row:the disc travels off the left edge | - | spring NAV | see [spring morph](../transitions/spring-morph.md)}}
{{row:the previous screen's text fades out | - | spring NAV | starts on the press}}
{{row:numbers + words are released together | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | one alpha for the whole grid — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:the trail follows the disc out | pq1.motion.CHAIN_TAU | tau_chase | visible only while the disc travels}}
{{row:DEMO ONLY: rest, then auto-advance | pq1.motion.DETAIL_DWELL | hold | do not port}}

At rest nothing moves.

## Input

The grammar is the value screen's; the executed rows for that context:

{{gestures:value — full-width}}

Probed on `firmware/update`: on WORDS a left tap goes back to the KEY FINGERPRINT intro, a right tap goes forward to the CONFIRM UPDATE ask. Either tap on that ask, or on the intro, enters WORDS again. `hold right` is unbound here — the words are read, not signed. `hold left` declines, with **no visible fill** because the disc is off the panel: see the gap noted on [value](value.md).

## Preview

Walked by the demo loop (KIOSK pace, dwell timers) — the device moves only on a press, at the NAV pace.

{{preview}}

## Do / Don't

- **Do** right-align the numbers and left-align the words on the fixed edges; the columns never move with the content.
- **Do** keep numbers grey and words white at one size.
- **Don't** fit a tier, wrap a word, or shrink the type for a long word.
- **Don't** animate words one by one.
- **Don't** port {{tok:pq1.motion.DETAIL_DWELL}}.

{{partial:port-notes}}
