{{doc-self}}

## Timeline

One variant, no presets. `t` is milliseconds since the screen's own t 0. The whole screen is the default `VerdictAnim.draw` — this module only supplies `draw_icon` and two shorter phase lengths.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.tamper.Tamper.T_HOLD | ease_out | shorter than the base verdict hold ({{tok:pq1.verdict.VerdictAnim.T_HOLD}}): this screen keeps the timeline of its detail-grid twin, [sig error](verdict-sig-error.md). The token crossfade runs only where the spec's `handoff` survives; otherwise the hold is plain black — see [handoff](../transitions/handoff.md)}}
{{row:the triangle arrives — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | alpha 0 to 1, height scales {{val:pq1.motion.ARRIVE_FROM}} to 1. The exclamation scales with it and is drawn opaque black from the first frame}}
{{row:two decaying attention pulses | screens.verdict.tamper.Tamper.T_WAIT | attention_pulse | the height is REPLACED by the pulse: 1 plus 0.09 times a decaying rectified sine at 2.5 half-cycles. It peaks 1.053 about a sixth of the way in and 1.016 past the middle — a 3.4 px swell on a {{val:screens.verdict.tamper.TRI_H}} px triangle, and the mark swells with it}}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | TAMPER DETECTED on the y {{val:pq1.layout.BASELINE_Y}} baseline}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}

There is no separate beat on this screen: `T_WAIT` is the pulse window AND the verdict's beat, so the caption starts the instant the window closes. The pulse is gated `0 < v < 1`, and it *replaces* the entrance scale rather than multiplying it. The two never overlap — the entrance is finished before `v` goes positive — so the icon is never scaled twice, and after the window the height is exactly `TRI_H`. Note that 2.5 half-cycles put a third, nearly dead crest (scale 1.005) right at the end of the window, so the sign snaps back about a third of a pixel when it closes; close the window on a zero if you ever scale this sign up.

**The rig** ({{loc:pq1.procedural.warning_triangle.draw}}). An apex-up filled triangle on a 72 x 64 unit bounding box (half-width 36, half-height 32), corners trimmed by 6/64 of the height and bridged with flattened quadratics whose control point is the original vertex. The un-rounded bounding box is centred on the circle grid (cx {{val:pq1.layout.CENTER_X}}, cy {{val:pq1.layout.CIRCLE_CY}}); at `TRI_H` the triangle is {{val:screens.verdict.tamper.TRI_H}} px tall and 1.125 times that wide. The exclamation is not part of the triangle — it is `marks.exclamation` composed on top ({{loc:pq1.procedural.marks.exclamation}}), at radius 16 units and 6.4 units below the bbox centre, both scaled by the same factor as the triangle. The triangle takes the screen's `state` colour (failed red); the mark is **always black**.

That black is a real detail: the mark is drawn with the icon's alpha but the colour black, so scaling it by alpha leaves it black. During the fade-in the triangle rises out of the background while the exclamation is already a solid hole punched through it. Composite the icon as one layer with a layer alpha and you will get a different — wrong — result.

[Sig error](verdict-sig-error.md) is the same icon and the same timing on the detail grid. Use this one when the fact needs no body text.

## Variants

{{variants}}

## Phases

{{phases}}

## Constants

{{constants}}

`TRI_H` is the triangle's height in UI pixels, chosen so the icon fills the centred circle slot.

## Input

None. It is a verdict: an ending accepts no press from its first frame to its last ({{loc:pq1.driver.FlowDriver.press}}), and the corner chevrons are hidden.

## Spec a flow splices in

{{spec}}

{{used-in}}

Splice it as `screens.spec("tamper")`, or with your own `bottom` for another alarm on the same icon. It is a verdict, so it owns its canvas — the flow leaves it by fading to black ([token-less transit](../transitions/tokenless-fade.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** draw the mark as opaque black over an alpha-faded triangle, in that order. It is two draws, not one composited icon.
- **Do** scale the mark by the same factor as the triangle so the two stay locked; `k` is derived from the drawn height, never fixed.
- **Don't** add a beat after the pulses: `T_WAIT` already is both.
- **Don't** repeat or loop the pulses. Two decaying swells draw the eye once; a loop turns an alarm into wallpaper.

{{partial:port-notes}}
