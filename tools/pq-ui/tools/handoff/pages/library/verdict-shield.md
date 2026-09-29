{{doc-self}}

## Timeline

One class, one shield outline, two gestures. `t` is milliseconds since the screen's own t 0. The gesture is a pure translation of the whole sign — outline and mark move together, nothing scales once the entrance is over.

**`backup_ok` (the default) — the check shield nods yes.**

{{motion-head}}
{{row:black hold — the flow's token hands over | pq1.verdict.VerdictAnim.T_HOLD | ease_out | the base verdict hold; nothing of the shield is drawn yet. The token crossfade runs only where the spec's `handoff` survives; otherwise the hold is plain black — see [handoff](../transitions/handoff.md)}}
{{row:icon entrance — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | alpha 0 to 1; the outline height and the mark radius both scale {{val:pq1.motion.ARRIVE_FROM}} to 1. The entrance law, no overshoot — see [the verdict law](../transitions/verdict-law.md)}}
{{row:the nod — one decaying dip | anim:verdict/shield:T_WAIT - screens.verdict.shield.T_BEAT | shake | `cy` plus 5 px times shake at one cycle. Down first, then up: the realized peaks are 3.8 px down about a fifth of the way in and 1.4 px back up past the middle — the unit curve tops out at 0.77, not 1}}
{{row:beat before the caption | screens.verdict.shield.T_BEAT | — | the sign rests, dead still}}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | BACKUP OK on the y {{val:pq1.layout.BASELINE_Y}} baseline}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}

**`no_match` — the x shield shakes its head.** Same phases; only the gesture axis, its excursion and its window change.

{{motion-head}}
{{row:black hold | pq1.verdict.VerdictAnim.T_HOLD | ease_out | }}
{{row:icon entrance — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | identical to the nod's}}
{{row:the wiggle — one decaying shake | anim:verdict/shield@no_match:T_WAIT - screens.verdict.shield.T_BEAT | shake | `cx` plus 6 px times shake at one cycle. Right first, then left: 4.6 px and 1.7 px realized. Shorter and wider than the nod — a refusal is quicker than an agreement}}
{{row:beat before the caption | screens.verdict.shield.T_BEAT | — | }}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | NO MATCH}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | }}

The gesture is gated `0 < w < 1`, so the sign sits exactly on its centre before and after it — no clamping, no residual. `T_WAIT` is not a constant here: the class computes it in `__init__` as the gesture's own window plus `T_BEAT`, so a spec with `gesture: None` is a plain arrival and the screen falls back to the base law's beat ({{tok:pq1.verdict.VerdictAnim.T_WAIT}}) and its default resolve — see [the verdict law](../transitions/verdict-law.md). The `defined at` cell of the gesture rows points at that base declaration; the ms come from the live instance.

**The rig** ({{loc:pq1.procedural.shield.draw}}). The outline is the `encrypted.svg` centreline on a 51 x 63 design box, flattened to a point list once at import and drawn as one closed stroked loop with curve joints — never a filled shape. It is {{val:screens.verdict.shield.SHIELD_H}} px tall, design-box centre on (cx {{val:pq1.layout.CENTER_X}}, cy {{val:pq1.layout.CIRCLE_CY}}), stroked 3/63 of its height. The mark is composed on top from `pq1.procedural.marks` — never redrawn locally — sitting {{val:screens.verdict.shield.MARK_DY}} px above the shield centre at its own radius, `MARK_R` (check 25 px, x 28.3 px — the second derived so the x's corners land where the source drew its diagonals). Outline and mark share one colour: the screen's `state` through `colors.STATE` — green for done, red for failed — unless the spec pins an explicit `color`, which wins.

## Variants

{{variants}}

`(default)` is the `backup_ok` preset — the same spec, so the build renders it once.

## Phases

{{phases}}

## Constants

{{constants}}

`GESTURES` maps a gesture name to (axis, excursion in px, window in ms). `SHIELD_H` and `MARK_DY` are UI pixels; `MARK_R` is the mark radius per result.

## Input

None. It is a verdict: an ending accepts no press from its first frame to its last ({{loc:pq1.driver.FlowDriver.press}}), and the corner chevrons are hidden. It owns its canvas, so the flow leaves it by fading to black — see [token-less transit](../transitions/tokenless-fade.md).

## Spec a flow splices in

{{spec}}

{{used-in}}

Splice it as `screens.spec("shield", preset="backup_ok")` or `preset="no_match"`; `--text` (or a `bottom` in the spec) renders any other caption on the same gesture — NO BACKUP on the wiggle, for instance.

## Preview

{{preview}}

## Do / Don't

- **Do** keep one cycle and let it decay. Two shakes read as an error animation from a phone; one dip that dies is a head nodding.
- **Do** move the mark with the shield. They are one object; a mark that stays put while the outline swings breaks the illusion instantly.
- **Don't** scale on the gesture. The only scale on this screen is the entrance rise; the nod and the wiggle are translation only.
- **Don't** hard-code the caption or the colour: the state picks green or red, and the caption is the flow's content.

{{partial:port-notes}}
