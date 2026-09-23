## What it is

A fingerprint read as words: up to eight short words on a fixed grid of two columns of four, each word numbered. It replaces the value lines of a [value](../screen-types/value.md) screen — `words` instead of `lines` — so the panel shows the whole fingerprint at once and the user can compare it with the one published for the release.

It is a fixed grid, not a text layout: no tier fitting, no wrapping, no stacking rule. The words are white, the numbers grey, both at one size. The band stays empty — the schema allows an optional caps label there, and the live screen does not use it.

## When it appears

On a `value` screen whose spec carries `words`. Live: the WORDS screen of the firmware update flow (`flows/firmware/update`), between the KEY FINGERPRINT [intro](../screen-types/hero-intro.md) and the CONFIRM UPDATE ask that signs. It counts as a detail for the Confirm? rule, like any value screen.

## Spec

{{fields:value.words,value.label}}

`normalize_screens` ({{loc:pq1.layout.normalize_screens}}) enforces the shape and raises otherwise:

- `words` belongs to a **value** screen only, and nothing else may share it — no `lines`, no `pages`
- between one and {{val:pq1.layout.WORDS_MAX}} words (`WORDS_MAX` = the two columns of four)
- every entry is coerced to a string
- `size` is overwritten with {{val:pq1.layout.WORDS_SIZE}}: a words screen has no tier to choose

```python
dict(id="WORDS", kind="value", chev="lr",
     words=["close", "agent", "own", "deputy", "grape", "though", "sail", "simple"])
```

## Geometry

Built by `_words_texts` ({{loc:pq1.layout._words_texts}}).

| part | value |
|---|---|
| row centre lines | `WORDS_ROWS` {{val:pq1.layout.WORDS_ROWS}} |
| columns | `WORDS_COLS` {{val:pq1.layout.WORDS_COLS}} — per column: the number's **right** edge, then the word's **left** edge |
| size | {{val:pq1.layout.WORDS_SIZE}}, Regular, words and numbers alike |
| word colour | white |
| number colour | white × {{val:pq1.layout.WORDS_NUM_ALPHA}} (`WORDS_NUM_ALPHA`) |
| fill order | word `k` goes to column `k // 4`, row `k % 4` — 1–4 down the left, 5–8 down the right |
| the token | parked off the panel at {{tok:pq1.layout.VALUE_PARK_X}}, as on any value screen |
| corner chevrons | stay: taps still navigate |

Alignment is what makes the grid read: the **number is right-aligned** on its column's number edge so the digits line up, and the **word is left-aligned** on its word edge so the words start on one line. The drawing primitive centres text on an x, so the code offsets each anchor by half the measured width — port the alignment, not the centre points.

Vertically each piece is centred on its row line (the band's baseline rule does not apply here).

The code measures each word, but only to place it: nothing checks that it fits, and nothing shrinks it. The budget is therefore fixed — from the right column's word edge to the right margin (the panel is {{val:pq1.layout.W}} px wide with {{val:pq1.layout.MARGIN}} px margins) there are 134 px. An eight-letter word (`mountain`, `withdraw`) measures about 95 px at this size and the longest word on the live screen under 75 px, so a standard wordlist fits with room to spare — and a word that does not fit runs off the panel unnoticed. The left column is wider: its word edge to the right column's number edge is 174 px.

## Motion

The grid does not animate. It arrives and leaves with its screen.

{{motion-head}}
{{row:outgoing screen starts fading as the leg begins | - | spring NAV | a full grid is sixteen pieces — eight numbers, eight words — on the screen's one alpha}}
{{row:the grid is released after | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the token leads — here it leads by leaving the panel — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:no stagger | - | cut | the words never count themselves in one by one}}
{{row:the token travels off the left edge and back | - | spring NAV | the position spring, the trail following — see [spring morph](../transitions/spring-morph.md)}}
{{row:demo only: the screen advances itself after | pq1.motion.DETAIL_DWELL | — | **do not port** — the reader decides when to move on}}

## Input

{{gestures:value — full-width}}

Nothing here is interactive: taps navigate, hold left declines, hold right is unbound (the update is committed on the ask that follows, never on the words).

## Preview

No clip of its own. It plays in [Value — numbered words grid](../screen-types/value-words.md) and in the firmware flow's walkthrough.

## Do / Don't

- **Do** keep the words as data: they are the fingerprint of the firmware being installed, filled per update.
- **Do** number in reading order — down the left column, then down the right.
- **Don't** wrap, hyphenate, shrink or truncate a word. Nothing fits it at runtime; a word that does not fit is a wordlist bug.
- **Don't** put a caption under a grid of four or more words: the fourth row's ink and the band's text overlap.
- **Don't** use the grid for an arbitrary list. It is the fingerprint's layout.
- **Don't** change the row lines or column edges to centre a shorter list. Four words fill the left column and leave the right empty — that is the layout.

{{partial:port-notes}}
