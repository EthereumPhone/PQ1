{{doc-self}}

## Timeline

Both presets have exactly the same timing — only the caption differs. `t` is milliseconds since the screen's own t 0.

{{motion-head}}
{{row:black hold — the flow's token hands over | pq1.verdict.VerdictAnim.T_HOLD | ease_out | the base verdict hold; nothing is drawn yet. The token crossfade runs only where the spec's `handoff` survives; otherwise the hold is plain black — see [handoff](../transitions/handoff.md)}}
{{row:the sign arrives — fade + rise | pq1.motion.ARRIVE_MS | ease_out + arrive | disc, ring and x fade in together and scale {{val:pq1.motion.ARRIVE_FROM}} to 1 about the circle centre. The entrance law, no overshoot — see [the verdict law](../transitions/verdict-law.md)}}
{{row:the headshake — one decaying wiggle | screens.verdict.headshake.T_SHAKE | shake | `cx` plus {{val:screens.verdict.headshake.SHAKE_PX}} px times shake at one cycle. Right first, then left: the realized peaks are 4.6 px right about a fifth of the way in and 1.7 px left past the middle — the unit curve tops out at 0.77, not 1. The whole sign translates; nothing scales}}
{{row:beat before the caption | screens.verdict.headshake.T_BEAT | — | the sign rests, dead still, on the circle centre}}
{{row:caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | CANCELED or WRONG SEED PHRASE on the y {{val:pq1.layout.BASELINE_Y}} baseline}}
{{row:rest, then the flow moves on | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}

`T_WAIT` is the shake window plus the beat — a class attribute here, not computed per spec. The shake window is gated `0 < w < 1`, so the offset is exactly zero before and after it: no clamping, no residual.

**The rig.** There is no procedural art on this screen. It draws the *resting look* itself — the same three layers every unbranded ending lands on ([the resting look](../screen-types/resting-look.md), `status.ArriveStatus`), on the same geometry: a disc of radius {{tok:pq1.layout.CIRCLE_R}} at (cx {{val:pq1.layout.CENTER_X}}, cy {{val:pq1.layout.CIRCLE_CY}}), a ring of width {{val:pq1.components.TOKEN_RING_W}} px whose radius sits {{val:screens.verdict.headshake.RING_INSET}} px inside the disc edge, and the result glyph from `components.GLYPHS`. Unbranded that is a black disc with the state colour as stroke and x; a spec that carries `resting` (a brand family) fills the disc instead and rides the ring flush at the edge. That is the whole point of the screen: WRONG SEED PHRASE must read as the same refusal as a flow's own CANCELED, because it is the same sign — only shaken.

## Variants

{{variants}}

`(default)` is `canceled`; `wrong_seed_phrase` differs only in `bottom`, so both rows carry identical timings. `--text` renders any other refusal caption — WRONG PIN, for instance — on the same sign.

## Phases

{{phases}}

## Constants

{{constants}}

`SHAKE_PX` and `RING_INSET` are UI pixels; `T_SHAKE` and `T_BEAT` sum to `T_WAIT`.

## Input

None. It is a verdict: an ending accepts no press from its first frame to its last ({{loc:pq1.driver.FlowDriver.press}}), and the corner chevrons are hidden.

## Spec a flow splices in

{{spec}}

{{used-in}}

A flow splices it as `screens.spec("headshake", preset="canceled")`. It is a verdict, so it owns its canvas: `rests_on_token` is false and the flow leaves it by fading to black — see [token-less transit](../transitions/tokenless-fade.md).

## Preview

{{preview}}

## Do / Don't

- **Do** draw the resting look, not a lookalike. If the device's ending screen and this verdict draw different discs, the user sees two different refusals.
- **Do** translate all three layers together. Disc, ring and glyph share one `cx`; shaking only the glyph inside a still ring reads as a bug.
- **Don't** add cycles. One decaying wiggle is a head shaking "no"; two is an error toast.
- **Don't** use it for a `done` state. This sign is the refusal; a success ending arrives instead ([status — arrive](../screen-types/status-arrive.md)).

{{partial:port-notes}}
