{{doc-self}}

## Timeline

Nothing is added to the law here: the default `VerdictAnim` phases, one icon, one caption.
Read this page first — every other verdict is this skeleton with a mechanism dropped into the
beat. The whole screen is a pure function of `t`, so any frame can be recomputed from scratch.

{{motion-head}}
{{row:black hold — the flow's token hands over | pq1.verdict.VerdictAnim.T_HOLD | ease_out | a black disc of radius {{val:pq1.layout.CIRCLE_R}} + 2.5 px is laid over the resting token at rising alpha (`status.draw_handoff`); with `handoff` unset the canvas is simply black}}
{{row:the disc arrives — fade | pq1.verdict.VerdictAnim.T_IN | ease_out | white, alpha 0 to 1. The colour is multiplied by alpha before drawing, not composited}}
{{row:the disc arrives — rise | pq1.verdict.VerdictAnim.T_IN | arrive | radius {{tok:pq1.layout.CIRCLE_R}} scaled from {{tok:pq1.motion.ARRIVE_FROM}} to 1 — under a pixel of growth, and never an overshoot}}
{{row:beat on the arrived sign | pq1.verdict.VerdictAnim.T_WAIT | — | nothing moves. The disc is simply seen before it is named}}
{{row:the caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | FIRMWARE VERIFIED onto the shared baseline y {{val:pq1.layout.BASELINE_Y}} — see [caption](../components/caption.md)}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | the screen rests, then the flow moves on — see [result hold](../transitions/result-hold.md)}}

The check is **not** animated and **not** faded: `marks.check` draws it in flat black at full
alpha over the disc, so it is a hole punched in the white, legible at every stage of the fade.
Its three points sit at −0.40 r / +0.02 r, −0.10 r / +0.30 r and +0.44 r / −0.28 r — x right, y
DOWN the panel — with a stroke 0.16 r wide and round caps of 0.08 r on the two ends, so the mark
scales with the disc.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}} — the module itself calls none; the fade and the rise come
from `VerdictAnim.entrance` (`motion.ease_out` and `motion.arrive`), which every verdict shares.
See [the verdict law](../transitions/verdict-law.md).

## Constants

{{constants}}

The module declares no constants of its own: the geometry is `layout.CENTER_X`, `layout.CIRCLE_CY`
and `layout.CIRCLE_R`, the colour is `colors.WHITE` in the spec.

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** punch the check out in black instead of fading it in beside the disc. The disc is the
  only thing that arrives; the mark is part of its shape.
- **Do** keep the fade and the rise on the same clock: they start and end together, inside
  {{tok:pq1.motion.ARRIVE_MS}}, whatever the mechanism that follows.
- **Don't** stroke a ring around it. This is a verdict sign, not the resting look of a status
  ending — that one is `arrive`, see [status — arrive](../screen-types/status-arrive.md).
- **Don't** bind a button. A verdict accepts no input; the flow leaves on its own clock.

{{partial:port-notes}}
