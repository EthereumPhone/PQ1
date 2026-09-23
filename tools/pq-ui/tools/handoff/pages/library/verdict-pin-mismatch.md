{{doc-self}}

The answer a wrong PIN earns. It is spliced as the `miss` of one try of the
[PIN entry](pin-pin-entering.md) — the entry fades the ring row out, then this plays in the same
screen — so a port must build it as part of the try, not as a screen the flow advances to.

The art is `pq1.procedural.pin_pill` ({{loc:pq1.procedural.pin_pill.draw}}): a rounded outline
{{val:pq1.procedural.pin_pill.PW}} × {{val:pq1.procedural.pin_pill.PH}} px, stroke
{{val:pq1.procedural.pin_pill.STROKE}}, holding {{val:pq1.procedural.pin_pill.SLOTS}} dots of radius
{{val:pq1.procedural.pin_pill.DOT_R}} on a {{val:pq1.procedural.pin_pill.SPAN}} px pitch, centred on
the circle grid (x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}). The same pill, refused
for the other reason, is [verdict / duress_differ](verdict-duress-differ.md).

## Timeline

Play order, one table: the `wrong_pin` preset changes the caption only, never a duration. The
mechanism clock `tm` starts when the entrance ends — at `T_HOLD` + `T_IN` on the screen's clock — so
the fill, the turn and the shake all play on an already-arrived pill.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.pin_mismatch.PinMismatch.T_HOLD | ease_out | the resting token is drawn, and a black disc of FIXED radius — the token's ({{val:pq1.layout.CIRCLE_R}} px) plus a hair — fades in over it; the disc never grows ({{loc:pq1.status.draw_handoff}}). Spliced after the PIN row there is no token, so this window is plain black}}
{{row:the pill arrives — fade and rise | screens.verdict.pin_mismatch.PinMismatch.T_IN | ease_out + arrive | the entrance law: alpha 0 to 1 and scale {{val:pq1.motion.ARRIVE_FROM}} to 1, never an overshoot. The pill arrives EMPTY and WHITE — the entry still reads normal}}
{{row:the four dots fade in together | screens.verdict.pin_mismatch.T_FILL | ease | one alpha for all {{val:pq1.procedural.pin_pill.SLOTS}} dots, still white. Landing them one by one costs about this phase over again and was cut}}
{{row:the filled row holds | screens.verdict.pin_mismatch.T_FILLED | hold | the device is checking. Nothing moves}}
{{row:pill and dots turn to the state colour | screens.verdict.pin_mismatch.T_TURN | ease | one mix from white to the failed red 255 66 61; outline and dots share the value, so the refusal is one sign}}
{{row:the row shakes the PIN off | screens.verdict.pin_mismatch.T_SHAKE | shake | horizontal only. The centre x moves by {{val:screens.verdict.pin_mismatch.SHAKE_PX}} px times a decaying sine of {{val:screens.verdict.pin_mismatch.SHAKE_CYCLES}} cycles, so the first swing is about 6.1 px and the last is nearly nothing}}
{{row:the verdict beat | screens.verdict.pin_mismatch.T_BEAT | hold | the red pill sits still before the words}}
{{row:the caption fades in | screens.verdict.pin_mismatch.PinMismatch.T_TEXT | ease_out | PIN MISMATCH, or WRONG PIN on the preset, on the shared baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:the verdict rests | pq1.status.RESULT_HOLD_MS | hold | from `t_resolve` {{val:anim:verdict/pin_mismatch:t_resolve}} to the end. In a flow the driver leaves when this is over}}

There is no result glyph and no ring flash: the pill is the whole picture, and `rests_on_token` is
false, so the flow draws no token disc over the transit out — see
[token-less transit](../transitions/tokenless-fade.md).

## Variants

{{variants}}

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

That line counts top-level flow screens only. This verdict is reached through `flows/pin`
`attempt(wrong_pin())`, nested in the entry's `miss` field — which is exactly the point: it is part
of a try, not a screen of the flow.

## Preview

{{preview}}

## Do / Don't

- **Do** arrive empty and white. The pill filling, then turning, is the whole story — a pill that
  arrives red has already given the answer away.
- **Do** keep the shake horizontal and decaying. A constant-amplitude wobble, or one that also moves
  the pill vertically, reads as a glitch rather than a refusal.
- **Don't** shorten the beats. Each one is under three panel frames already; the pace was settled
  with the user at roughly half the design canvas's timings.
- **Don't** treat this as a screen of its own in the flow. It plays inside the try that earned it —
  see [after the row](../actions/entry-outcome.md).

{{partial:port-notes}}
