{{doc-self}}

## Timeline

One variant, no presets — the content varies, the timing does not. `t` is milliseconds since the screen's own t 0. This is the only verdict that owns `draw()` outright: it lays out on the detail grid instead of the centred circle, so it draws its own text block as well as the icon.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.sig_error.SigError.T_HOLD | ease_out | shorter than the base verdict hold ({{tok:pq1.verdict.VerdictAnim.T_HOLD}}); this is the source timeline that its centred twin [tamper](verdict-tamper.md) also keeps. The token crossfade runs only where the spec's `handoff` survives; otherwise the hold is plain black — see [handoff](../transitions/handoff.md)}}
{{row:the triangle arrives — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | alpha 0 to 1, height scales {{val:pq1.motion.ARRIVE_FROM}} to 1 in its column. The exclamation scales with it and is drawn opaque black from the first frame}}
{{row:two decaying attention pulses | screens.verdict.sig_error.SigError.T_WAIT | attention_pulse | the height is REPLACED by the pulse: 1 plus 0.09 times a decaying rectified sine at 2.5 half-cycles. It peaks 1.053 about a sixth of the way in and 1.016 past the middle — a 3.2 px swell on a {{val:screens.verdict.sig_error.TRI_H}} px triangle, mark included}}
{{row:the value lines and the label fade in together | pq1.verdict.VerdictAnim.T_TEXT | ease_out | one alpha drives both, plus the caption if the spec sets one; nothing staggers}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}

There is no separate beat: `T_WAIT` is the pulse window and the verdict's beat at once. The pulse is gated `0 < v < 1` and *replaces* the entrance scale rather than multiplying it, so the icon is never scaled twice. Its 2.5 half-cycles leave a third, nearly dead crest (scale 1.005) on the window's last frames, so the triangle snaps back about a third of a pixel when it closes.

**Geometry.** The detail grid, not the circle grid ([detail](../screen-types/detail.md)). `side` docks the triangle in one column — centre x {{val:pq1.layout.COL_LEFT_CX}} for `"left"`, {{val:pq1.layout.COL_RIGHT_CX}} for `"right"` — and the value goes in the other, centred on x 263 when the triangle is left and x 163 when it is right (`layout.DETAIL_TEXT_CX`, {{loc:pq1.layout.DETAIL_TEXT_CX}}). The triangle sits on the circle row (cy {{val:pq1.layout.CIRCLE_CY}}) at {{val:screens.verdict.sig_error.TRI_H}} px tall — shorter than [tamper](verdict-tamper.md)'s centred slot. The 1 to 3 value lines stack on `layout.line_height(size)` about y {{val:pq1.layout.TEXT_CY}}. The label sits under the triangle on the shared band baseline, y {{val:pq1.layout.BASELINE_Y}}, at the label size with label tracking, centred on the triangle's column — so it reads as a detail label, not as a caption.

**The text is data, not decoration.** `lines` and `label` are the screen's content; `size` is FITTED by `fit_size` to the largest tier whose budget the longest line and the line count both fit, unless the spec pins it. The tiers are (size, max characters per line, max lines): see `TIERS` below. A value that fits no tier RAISES — the design system will not shrink or ellipsize a security-relevant string; split it into more lines, or page it. A line may be a plain string or `{"str": NAME, "weight": "semibold"}` for a name inside the value ([detail text](../components/detail-text.md)).

`bottom` defaults to empty on this screen: the bottom band carries the label under the triangle instead of a centred caption. Set both only if you have checked they do not collide — the label is centred in its column, the caption across the whole panel.

## Variants

{{variants}}

## Phases

{{phases}}

## Constants

{{constants}}

`TRI_H` is the triangle's height in UI pixels. `SIDES` maps `side` to the triangle's column centre x. `TIERS` is the fitting table, largest first.

## Input

None. It is a verdict: an ending accepts no press from its first frame to its last ({{loc:pq1.driver.FlowDriver.press}}), and the corner chevrons are hidden. The lines are not paged and not scrollable — whatever the fitted tier shows is the whole value.

## Spec a flow splices in

{{spec}}

{{used-in}}

The sample line is a placeholder, never content: `screens.spec("sig_error", lines=["Sig verify FAIL"], label="ERROR", side="right")`. It is a verdict, so it owns its canvas — the flow leaves it by fading to black ([token-less transit](../transitions/tokenless-fade.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** fit the size to the text at build time and keep the tier table. The device must pick the same tier the catalog would, or two builds will disagree about the same string.
- **Do** fade the lines and the label on one alpha, at the same instant. A staggered label reads as a second event.
- **Don't** ellipsize, shrink past the last tier or letter-space a value to make it fit — split it. The Python raises here on purpose.
- **Don't** treat the sample as the message: `lines` and `label` are per-transaction data, the same rule as every detail value.

{{partial:port-notes}}
