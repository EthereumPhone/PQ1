{{doc-self}}

## Timeline

Two parts move, one after the other, never together: the reel falls to 1, and only once it has
settled does the heart answer. The count is shown at rest first, so the reader sees what it was
before they see what it became.

{{motion-head}}
{{row:black hold — the flow's token hands over | pq1.verdict.VerdictAnim.T_HOLD | ease_out | `status.draw_handoff` veils the resting token. Inside a PIN attempt the entry builds this verdict with `handoff` off, so the hold is plain black — see [token-less transit](../transitions/tokenless-fade.md)}}
{{row:the sign arrives — fade | pq1.verdict.VerdictAnim.T_IN | ease_out | digit and heart on one alpha}}
{{row:the sign arrives — rise | pq1.verdict.VerdictAnim.T_IN | arrive | scale {{tok:pq1.motion.ARRIVE_FROM}} to 1. The rise is about the grid centre, so both anchors converge on it as they grow — x = CENTER_X + (x_rest - CENTER_X) x s — and the pair is never seen drifting apart}}
{{row:rest on the start digit | screens.verdict.last_attempt.T_REST | — | the source's visible hold. The count is read before it falls}}
{{row:the reel rolls start to 1 | screens.verdict.last_attempt.T_ROLL | decel | progress 0 to 1 across start - 1 steps, decel at its default p 2.6. One step is 1.16 x the digit size, about 46.4 px of strip through the window}}
{{row:the settle | screens.verdict.last_attempt.T_SETTLE | wobble | the 1 overshoots and comes back: progress goes past 1 by {{tok:screens.verdict.last_attempt.BOUNCE}} x wobble, divided by start - 1, so the strip travels the same distance whatever the start digit. wobble's first crest is about 0.53 of its amplitude, so the overshoot peaks near a tenth of a reel step — about 4.4 px — and dies on decay 3}}
{{row:the heart's pump train | screens.verdict.last_attempt.T_BEAT | heartbeat | height = {{tok:screens.verdict.last_attempt.HEART_H}} px x heartbeat: 3 pumps, amplitude 0.22, decay 4 — a peak height near 33.7 px on the first pump, smaller on each one after. The digit does not move}}
{{row:the caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | LAST ATTEMPT on the baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | see [result hold](../transitions/result-hold.md)}}

`T_WAIT` is the whole mechanism — `T_REST + T_ROLL + T_SETTLE + T_BEAT` — and its clock starts
at `T_HOLD + T_IN`, after the entrance. The heart's window opens exactly where the settle's
closes; the two accents never overlap.

The reel is pose-parametric: `digit_reel.draw` is handed a raw progress and draws whichever two
digits straddle it, so the overshoot is the caller's arithmetic, not the rig's. With
`attempts` set to 1 there is nothing to roll — progress stays at 0 — but every phase keeps its
length, so the screen is the same length whatever the count.

## Geometry

The digit is sign art, not type: {{tok:screens.verdict.last_attempt.DIGIT_PX}} px in
{{tok:screens.verdict.last_attempt.DIGIT_WEIGHT}} (the label caps' 600 weight), sized so its cap
height — about 28.5 px in that face — reads level with the heart's
{{tok:screens.verdict.last_attempt.HEART_H}} px and the two read as one mark. The digit anchor sits at
{{tok:screens.verdict.last_attempt.NUM_X}} with the heart centre
{{tok:screens.verdict.last_attempt.HEART_DX}} px to its right, and the resting pair — the 1 and
the heart, not the start digit — is what is centred on the circle grid.
{{tok:screens.verdict.last_attempt.DIGIT_DY}} px lifts the digit so its foot stands on the
heart's tip. The reel window's opaque band reaches
{{tok:screens.verdict.last_attempt.WIN_DN}} x the digit size below the line — wider than the
rig's default — so the bottom fade begins past the digit's foot and the resting digit is never
dimmed.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}}. The fade and the rise are `VerdictAnim.entrance`
(`motion.ease_out`, `motion.arrive`) — see [the verdict law](../transitions/verdict-law.md).

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

`attempts` is the reel's start digit, 1 to 9; anything else raises. `state` is failed, so the
digit and the heart both take the failed red from `colors.STATE`, and `result` is None — no glyph
lands on the sign.

The PIN family splices it as `last_attempt(left)` into an attempt's `miss`: it then plays INSIDE
the entry screen, after the row has faded out, never as a screen of its own — see
[PIN entry — after the row](../actions/entry-outcome.md).

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** divide the overshoot by the number of steps. It is specified in reel steps, so a count
  from 8 and a count from 3 bounce by the same distance on screen.
- **Do** keep the heart still while the reel rolls, and the reel still while the heart pumps.
  Two mechanisms moving at once reads as noise, not as a consequence.
- **Don't** treat the digit as a text label on the type scale. It is 40 px art whose cap height
  is tuned to the heart; re-sizing it breaks the pair.
- **Don't** let the window's bottom fade reach the digit's foot — the resting 1 must be solid.

{{partial:port-notes}}
