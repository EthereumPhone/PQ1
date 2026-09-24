{{doc-self}}

The same rule as [verdict / duress_differ](verdict-duress-differ.md), stated as a plain `pin`-category
screen instead of a verdict. The difference is the opening and the sweep, not the message: here the
pill fades in flat — **no black hold, no rise, no entrance law** — and the scanline crosses the pill
three times instead of two, so it ends at the far side rather than back where it began.

Both draw the same art, `pq1.procedural.pin_pill` ({{loc:pq1.procedural.pin_pill.draw}}), in the
warning orange 245 160 51, and their resting frames are pixel-identical. Write the pill, the sweep and
the shake ONCE and give them the two openings as parameters: the verdict twin when a token hands over
to it, this one when the pill is already the whole picture.

## Timeline

Play order; no presets, so one table. Every offset is absolute — this module lays its phases out as
`T0_*` start times from t 0 ({{loc:screens.pin.pin_differ.PinDiffer}}), not on a mechanism clock.

{{motion-head}}
{{row:the pill outline fades in | screens.pin.pin_differ.T_HOLD | ease | alpha 0 to 1 on the outline alone, from t 0. Despite the name this is NOT a black hold: the pill is drawn from the first frame, and there is no scale rise}}
{{row:the four dots fade in together | screens.pin.pin_differ.T_FILL | ease | starts at {{tok:screens.pin.pin_differ.PinDiffer.T0_FILL}}. One alpha for all {{val:pq1.procedural.pin_pill.SLOTS}} dots, already in the state colour — nothing turns later}}
{{row:the full row pauses | screens.pin.pin_differ.T_FILLED | hold | starts at {{tok:screens.pin.pin_differ.PinDiffer.T0_FILLED}}. The beat before the check}}
{{row:the scanline sweeps forward, back, forward | screens.pin.pin_differ.T_SCAN | raised cosine | starts at {{tok:screens.pin.pin_differ.PinDiffer.T0_SCAN}}. Position is 0.5 − 0.5·cos(2π·u·cycles) with {{val:screens.pin.pin_differ.SCAN_CYCLES}} cycles: three traverses of 92 px, each a third of this, ending at the far end}}
{{row:… and the bar fades out over the sweep's tail | screens.pin.pin_differ.T_SCAN * pq1.procedural.pin_pill.SCAN_FADE | ease_out | the last tenth of the sweep — the fraction is {{tok:pq1.procedural.pin_pill.SCAN_FADE}}. Still under two panel frames, so the bar effectively cuts out}}
{{row:the row shakes the duress PIN off | screens.pin.pin_differ.T_SHAKE | shake | starts at {{tok:screens.pin.pin_differ.PinDiffer.T0_SHAKE}}, exactly where the scanline stops being drawn. Centre x moves by {{val:screens.pin.pin_differ.SHAKE_PX}} px times a decaying sine of {{val:screens.pin.pin_differ.SHAKE_CYCLES}} cycles — about 6.1 px on the first swing, nothing by the end}}
{{row:the caption fades in | screens.pin.pin_differ.T_TEXT | ease_out | starts at {{tok:screens.pin.pin_differ.PinDiffer.T0_TEXT}}, the instant the shake ends. There is NO verdict beat here — the twin inserts one}}
{{row:the screen rests | pq1.status.RESULT_HOLD_MS | hold | from `t_resolve` {{val:anim:pin/pin_differ:t_resolve}} to the end}}

The shake's progress is clamped, so the pill sits exactly on centre once the shake is spent — the
offset never leaves a residue. `rests_on_token` is false: the pill owns the canvas, no token disc is
drawn, and the flow fades this frame out when it leaves.

## Variants

{{variants}}

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

Note the `handoff` key in that spec: `screens.spec()` sets it on every library screen, but this
screen's `draw` never calls the handoff helper, so an incoming token is **not** crossfaded out — it
is simply gone from the first frame. The verdict twin does draw it. If a port wants a hand-over into
this screen, it has to add one.

## Preview

{{preview}}

## Do / Don't

- **Do** start the pill visible. There is no black beat to hide behind: the outline is on screen at
  t 0 and fades up in place.
- **Do** end the sweep at the far side. Three traverses say *scanned end to end*; coming home is the
  verdict twin's reading.
- **Don't** write the pill twice. Only the opening (a black hold and the entrance law, or a flat
  fade) and the sweep's cycle count differ; everything else is shared.
- **Don't** insert a beat before the caption to match the twin. The words land on the pill as the
  shake dies out, and the shake's decay was paced for exactly that overlap.

{{partial:port-notes}}
