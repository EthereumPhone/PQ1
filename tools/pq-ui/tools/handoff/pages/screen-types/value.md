## What it is

A value shown alone: 1–3 centred lines across the whole panel, **no token disc on the screen**. It is a [detail](detail.md) without the docked disc — same line forms, same tiers, same stacking — used when the value needs the full width, such as a digest the user matches character by character against another source. There is no label and no `side`.

## When it appears

Inside the detail section, wherever a detail could be. {{used-in}}

- It counts as a detail for the [Confirm?](confirm.md) rule ({{loc:pq1.layout.insert_confirm}}), and the driver treats it as one: it can be the section's first screen.
- The live use is the fingerprint family: `flows/fingerprint` `digest(value)` splits a hex string into balanced lines of at most {{val:flows.fingerprint.BYTES_PER_LINE}} bytes, the `0x` riding on the first ({{loc:flows.fingerprint.digest}}). A 32-byte digest is three lines of 11 / 11 / 10 bytes at {{val:flows.fingerprint.SIZE}}. Over {{val:flows.fingerprint.LINES_PER_PAGE}} lines it returns `pages` instead — see [value — paged](value-paged.md).
- A value made of numbered words is its own page: [value — words grid](value-words.md).

## Spec

{{fields:kind,value.lines,value.size,icon,token,chev}}

{{example}}

- `size` defaults to 28; `chev` defaults to `"lr"` — the corner chevrons stay, taps navigate.
- `icon` and `token` still matter: the disc is off the panel at rest, but it is the same disc that travels in and out, with the flow's trail colours.
- A `label` on a value screen without `words` is ignored: `layout_of` never reads it.

### Full-width budgets (the design rule — the Python does not enforce it)

The [detail](detail.md) budgets times 1.45:

| size | max characters per line | max lines |
|---|---|---|
| 36 | 17 | 1 |
| 32 | 20 | 1 |
| 28 | 23 | 2 |
| 22 | 30 | 3 |

## Geometry

{{geometry}}

- Text centre x {{val:pq1.layout.VALUE_TEXT_CX}} — the panel's centre — across the full region between the margins ({{val:pq1.layout.W}} − 2 × {{val:pq1.layout.MARGIN}} px wide). Block centred on {{tok:pq1.layout.TEXT_CY}}, stacked with `line_height(size)` exactly as a detail ({{loc:pq1.layout._value_texts}}).
- The disc is **parked** at {{tok:pq1.layout.VALUE_PARK_X}} (minus one diameter), centre y {{val:pq1.layout.CIRCLE_CY}}, radius unchanged. Its right edge rests one radius outside the panel; the trail links rest under it, so nothing of the token shows.
- Corner chevrons in their usual slots ({{loc:pq1.layout.CHEV_LEFT}}).

## Motion

The disc does not fade or shrink. It **leaves**: the same position spring that moves it between columns carries it off the left edge, the trail after it, and brings it back for the next screen. It always exits left, whatever side it came from.

{{motion-head}}
{{row:the disc travels off the left edge | - | spring NAV | x to the park position; y and r keep their values — see [spring morph](../transitions/spring-morph.md)}}
{{row:the previous screen's text fades out | - | spring NAV | starts on the press}}
{{row:the value lines are released | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | the disc leads, the text follows — see [text-in delay](../transitions/text-in-delay.md)}}
{{row:the trail follows the disc out | pq1.motion.CHAIN_TAU | tau_chase | per link; it is visible only while the disc travels}}
{{row:leaving: the disc comes back in from the left | - | spring NAV | towards the next screen's circle x; the value text fades at once}}
{{row:DEMO ONLY: rest, then auto-advance | pq1.motion.DETAIL_DWELL | hold | do not port}}

At rest nothing moves.

## Input

{{gestures:value — full-width}}

- Taps are a detail's: left back, right forward. In the live flows the value is the only screen of its section, so both neighbours are the ask — and either tap on the ask comes back here.
- `hold right` is unbound. `hold left` declines.
- **Gap to know:** the hold fill is drawn inside the token disc ([hold flood](../components/hold-flood.md)), and here the disc is parked off the panel. In the reference a `hold left` on a value screen therefore shows **no progress at all** until it fires — the frames are pixel-identical to the resting screen. This is not a stated design decision. Raise it with the designer before porting; do not invent a fill.

## Preview

Walked by the demo loop (KIOSK pace, dwell timers) — the device moves only on a press, at the NAV pace.

{{preview}}

## Do / Don't

- **Do** show the value in full, split mid-string into centred lines. No ellipsis, no truncation, no re-casing.
- **Do** keep the disc alive off-screen: the next transit starts from the park position, not from a fade-in.
- **Don't** draw a label, a disc or a placeholder where the token was.
- **Don't** hard-code the digest: the lines are per-request data; only the splitting rule is fixed.
- **Don't** port {{tok:pq1.motion.DETAIL_DWELL}}.

{{partial:port-notes}}
