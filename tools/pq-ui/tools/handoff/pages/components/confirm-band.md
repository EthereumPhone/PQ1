## What it is

The bottom band of the [Confirm?](../screen-types/confirm.md) screen. The big prompt asks for the hold; the band says what the taps do instead. Two messages share the one slot and take turns:

| message | chevron | the tap it names |
|---|---|---|
| `OR VIEW MORE ▸` | after the text, pointing right | right tap — on to the remaining details |
| `◂ TO GO BACK` | before the text, pointing left | left tap — back to the previous detail |

Only one is visible at a time. The swap is sequential: one fades out completely, then the other fades in. They never crossfade.

The texts are fixed strings of the design system ({{loc:pq1.components.VIEW_MORE_TEXT}}), not flow data. The drawing is `components.confirm_band` ({{loc:pq1.components.confirm_band}}), two calls of the band unit ({{loc:pq1.components._band_unit}}) that an intro's [band chevron](band-chevron.md) also uses. The timing is `motion.confirm_band` ({{loc:pq1.motion.confirm_band}}).

## When it appears

Only on a `confirm` screen, and only while that screen is **settled**. The Sim draws it outside the screen's text list ({{loc:pq1.flow.Sim.draw}}), so it is not part of the transit.

## Geometry

| part | value |
|---|---|
| text centre x, both messages | {{val:pq1.components.VIEW_MORE_CX}} |
| baseline y | {{val:pq1.layout.BASELINE_Y}} |
| type | the question caps: size {{val:pq1.typography.SIZE_QUESTION}}, letter spacing {{val:pq1.typography.LS_QUESTION}}, white |
| chevron centre x | {{val:pq1.components.VIEW_MORE_CHEV_GAP}} px past the text's right edge (VIEW MORE), or the same distance before its left edge (GO BACK) |
| chevron centre y | {{val:pq1.components.VIEW_MORE_CHEV_CY}} |
| chevron shape | the [corner chevron](chevrons.md)'s, turned a quarter right or left |

Both texts are centred on the same x. That x is the panel centre ({{val:pq1.layout.CENTER_X}}) nudged left so that `OR VIEW MORE ▸` reads centred as a unit; `◂ TO GO BACK` keeps the same text centre, so as a unit it reads further left. Port it as the code has it.

## Motion

The clock is the ms since the Confirm? screen settled. Each alpha below multiplies the screen's own alpha.

{{motion-head}}
{{row:arrival: the band stays empty until the screen settles | - | — | the band is not drawn at all during the transit; its clock starts at settle, where the envelope is zero, so it fades up from nothing}}
{{row:a message fades in | pq1.motion.BAND_FADE_MS | ease_out | first part of its slot}}
{{row:it holds at full | pq1.motion.BAND_SWAP_MS - 2 * pq1.motion.BAND_FADE_MS | hold | }}
{{row:it fades out | pq1.motion.BAND_FADE_MS | ease_out | last part of its slot; the same curve run as 1 − ease_out}}
{{row:one slot = one message | pq1.motion.BAND_SWAP_MS | — | VIEW MORE takes the first slot, GO BACK the second}}
{{row:full cycle, then it repeats | 2 * pq1.motion.BAND_SWAP_MS | — | for as long as the screen rests}}
{{row:the corner chevrons bob once per slot | pq1.motion.BAND_SWAP_MS | sine | the hero hint's envelope run with the band's period; the chevrons already rest up, so its turn does nothing and only the bob shows — see [chevrons](chevrons.md)}}
{{row:leaving: the band disappears | - | cut | it is not drawn during a transit, so it is gone on the frame a tap lands, while the prompt fades on its spring}}
{{row:demo only: the screen's dwell | pq1.motion.CONFIRM_DWELL | — | **do not port** — two slots, so a GIF shows both messages}}

The cut on leaving never shows in a GIF: the demo leaves at the end of the second slot (its default dwell), where the band has already faded to zero. On the device a tap can land at any time, so the reference cuts a fully lit message. Keep it a deliberate choice in the port (cut as the reference does, or fade it with the prompt) and check it with the designer.

A live hold does not stop the band. While the disc fills, the messages keep taking turns and the chevrons keep bobbing.

## Input

{{gestures:confirm —}}

The band names the taps; the prompt and the up-pointing corner chevrons name the holds. Hold right signs from here ([hold right — sign](../actions/hold-right-sign.md)); hold left declines. A right tap walks on through the remaining details, which end on the returning ask.

## Preview

No clip of its own. Both messages play in the preview of [Confirm?](../screen-types/confirm.md).

## Do / Don't

- **Do** drive both alphas from one function of the ms since settle; restart the clock at every settle.
- **Do** show `OR VIEW MORE ▸` first.
- **Don't** crossfade the two messages, and don't show both chevrons at once.
- **Don't** port the dwell. On the device the band alternates until a press.
- **Don't** make the strings flow data.

{{partial:port-notes}}
