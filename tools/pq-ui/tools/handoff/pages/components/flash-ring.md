## What it is

How a result lands. On the last beat of an ending the disc snaps back to full size, a bright ring detaches from its edge and expands away into the black, and then the result glyph — a check or an X — fades in on the disc, with the [caption](caption.md) a beat behind it.

Three parts, one moment:

| part | what it is | drawn by |
|---|---|---|
| the flash ring | a one-shot stroked circle, growing and fading | `components.flash_ring` ({{loc:pq1.components.flash_ring}}) |
| the result glyph | `check` or `x`, on the resting disc | `pq1.procedural.marks` ({{loc:pq1.procedural.marks.check}}), registered in `components.GLYPHS` |
| the resting look under it | black disc + state-coloured ring, or a branded filled disc | {{loc:pq1.status.style_of}} |

## When it appears

Exactly twice in the system, and nowhere else:

- the **qubit film**'s last beat ({{loc:pq1.loading.qubit_pose}}) — the two qubits have spiralled together and the merged body flashes
- the **cancel resolve** ({{loc:pq1.status.ResolveStatus}}) — no film, so the arrived token resolves in place over one flash beat

An ending that arrives after a lead film ([status — arrive](../screen-types/status-arrive.md)) and every [verdict](../transitions/verdict-law.md) have **no flash**: disc, ring and glyph fade in together on the entrance law. Do not add one there.

A screen with `"result": None` shows no glyph at all — the glyph is guarded on it in both places, the flash ring is not, so the beat plays and the disc simply rests empty. No live ending does this today: the two specs that carry `result: None` either override it before the resolve (`hold_to_confirm`) or draw no disc at all (`pin_differ`).

## Spec

{{fields:status.result,status.state,status.color,status.resting}}

The colour is resolved once, in `style_of` ({{loc:pq1.status.style_of}}):

| the flash's colour | when |
|---|---|
| the screen's explicit `color` | it always wins |
| the branded ending's `resting.fill` | a brand family flashes in its own disc colour, never the state green over a brand disc |
| `colors.STATE[state]` | otherwise — done green, failed red |

The glyph takes `resting.glyph`, which is **not** the same value on a branded ending: the disc flashes in the brand fill while the check is drawn in the family's mark colour.

## Geometry

| part | value |
|---|---|
| centre | the disc's — x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}} |
| ring start radius | the full disc radius {{val:pq1.layout.CIRCLE_R}} — it leaves the disc edge, it does not appear around it |
| ring end radius | + 55 px, so it runs past the top and bottom edges of the panel and is clipped |
| ring stroke | 2.5 px (the function's default), a touch heavier than the system ring {{val:pq1.components.TOKEN_RING_W}} |
| ring colour | the flash colour, scaled toward black as it fades |
| check | a three-point polyline at (−0.40, +0.02) → (−0.10, +0.30) → (+0.44, −0.28) × r, stroked 0.16 r |
| the caps | the drawing primitive has no round cap: the code fills a circle of half the stroke width at each open end (the check's two ends, the x's four). Port the caps, or the marks read cut off |
| x | two diagonals at ±0.30 r, same stroke and ends ({{loc:pq1.procedural.marks.x_mark}}) |
| glyph radius | the disc's, so the mark fills the face |

## Motion

The clock is ms since the screen started; the flash begins when the bodies have merged.

{{motion-head}}
{{row:the merged body pops back to the full disc | qubit:T_FLASH | back_out | from r 17 to the disc radius, peaking about 4 % over it (back_out itself overshoots 10 % of the travel) — the ONE sanctioned overshoot in PQ1, a celebration, never navigation}}
{{row:the ring expands off the disc edge and fades out | qubit:T_FLASH | linear | radius + 55 px, alpha 0.85 → 0; it is at full strength on its first frame}}
{{row:a cancel resolve instead fades the ring IN first | qubit:T_FLASH * 0.12 | linear | so frame 0 of the beat equals the arrived token exactly — no coloured pop on the disc edge; it is shorter than one panel frame, so what it buys is that clean first frame, not a visible fade}}
{{row:a cancel resolve: under it, the token becomes the resting look | qubit:T_FLASH | ease_out | disc fill, stroke colour and stroke radius cross over together; the token's own glyph hands off at the film's split rate ({{loc:pq1.status.ResolveStatus.draw}})}}
{{row:the result glyph fades in, from the moment the screen resolves | 350 | linear | an unnamed literal, written out in {{loc:pq1.loading.qubit_pose}} and again in {{loc:pq1.status.ResolveStatus.draw}}}}
{{row:the caption starts behind the glyph | 120 | linear | same two places; the caption then uses the same ramp}}
{{row:the ending rests before the flow moves on | pq1.status.RESULT_HOLD_MS | hold | every ending, the same — see [result hold](../transitions/result-hold.md)}}

Those two literals are the only durations in the resolve that have no name; the conformance checker carries all four copies as known exceptions (rule `M-DIVLIT`). **Give them names in the port** and use the same pair in both places.

Both ramps are linear, and both are pure functions of the elapsed ms: any frame of the resolve can be recomputed from the clock alone, which is what makes the film seekable and resumable on the panel.

The flash never repeats. One expansion, one fade, then the disc is simply the resting look.

## Input

None. An ending accepts no input at all: presses during a resolve do nothing, and the flow leaves on its own ([result hold](../transitions/result-hold.md)).

## Preview

No clip of its own. It plays at the end of [status — the qubit film](../screen-types/status-qubit.md) and, in its fade-in dress, in [status — the resolve](../screen-types/status-resolve.md).

## Do / Don't

- **Do** drive the ring from one clock: radius and alpha are both functions of the same progress.
- **Do** start the ring exactly at the disc's radius, so it reads as the disc releasing it.
- **Do** keep the overshoot to this one pop. Everything else in PQ1 settles without bouncing.
- **Don't** ease the expansion or the glyph ramp — they are linear on purpose.
- **Don't** flash a verdict or an arriving ending.
- **Don't** colour the glyph from the flash colour on a branded ending; they differ.
- **Don't** draw the glyph before the flash finishes, or the caption before the glyph.

{{partial:port-notes}}
