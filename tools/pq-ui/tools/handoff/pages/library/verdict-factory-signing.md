{{doc-self}}

## Timeline

The mechanism is a coast, not a spin-up: the gear is **already turning at full speed** the
instant it appears, and slows to a stop like a bicycle wheel left to itself. The launch is
deliberately put under the entrance — the first part of the coast and the fade-in share a
clock — because a gear that sat still and then jumped to speed reads as fake.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.factory_signing.FactorySigning.T_HOLD | ease_out | shorter than the law's default ({{tok:pq1.verdict.VerdictAnim.T_HOLD}}): the source's own hold, kept}}
{{row:the gear arrives — fade | pq1.verdict.VerdictAnim.T_IN | ease_out | alpha 0 to 1 on the body and the teeth. The hole does NOT fade: it is punched flat black at every alpha, so the gear reads as a ring from the first frame}}
{{row:the gear arrives — rise | pq1.verdict.VerdictAnim.T_IN | arrive | radius {{tok:screens.verdict.factory_signing.GEAR_R}} scaled from {{tok:pq1.motion.ARRIVE_FROM}} to 1 — about a pixel. The gear is a shade wider than the token circle ({{tok:pq1.layout.CIRCLE_R}}), by design}}
{{row:the coast — one whole turn, launched WITH the arrival | screens.verdict.factory_signing.T_SPIN | freewheel | angle = 2 pi x {{tok:screens.verdict.factory_signing.TOTAL_TURNS}} x freewheel(t, k = {{tok:screens.verdict.factory_signing.DECAY_K}}). About 61 degrees a panel frame at launch, nothing at the end. Whole turns land tooth-aligned on the 8 teeth}}
{{row:motion-blur exposure, re-taken every frame of the coast | screens.verdict.factory_signing.SHUTTER_MS | linear | the teeth are averaged over the angle swept in the exposure, one pose per 2 degrees up to {{tok:pq1.procedural.gear.BLUR_SAMPLES_MAX}} of them. Body and hole are round, so only the teeth smear}}
{{row:beat on the stopped gear | screens.verdict.factory_signing.T_BEAT | — | the gear is still, and seen still, before the words}}
{{row:the caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | FACTORY SIGNING SLOT - 0 on the baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | see [result hold](../transitions/result-hold.md)}}

`T_WAIT` is not a free number: it is what is left of the coast once the entrance has run, plus
the beat — `T_SPIN - ARRIVE_MS + T_BEAT`. Move the spin and the phase follows.

**Why the blur is not decoration.** The panel samples the coast slowly, and a tooth repeats
every 45 degrees; at launch the gear turns further than that between two samples, so a sharp
render aliases into a gear crawling backwards (the wagon-wheel effect). The exposure is
{{tok:screens.verdict.factory_signing.SHUTTER_MS}} — half the accent floor, near enough one
panel frame — so the smear is widest at launch and gone by the time the gear stops.
The screen's own `_angle` (not the rig's — `procedural.gear` only draws at an angle) extrapolates
**backwards past the launch** at the freewheel's slope at zero, so the very first exposures smear
like all the others instead of flashing one sharp gear.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}}. The entrance fade and rise come from
`VerdictAnim.entrance` (`motion.ease_out`, `motion.arrive`) — see
[the verdict law](../transitions/verdict-law.md).

## Constants

{{constants}}

Proportions inside `procedural.gear`, all normalized to r: body disc 0.80, hole 0.44, tooth
width 0.36, tooth height 0.20, tooth corner radius 0.08, teeth seated 0.125 into the body so the
join never shows a seam. The hole is punched with a black ellipse, not left transparent.

## Spec a flow splices in

{{spec}}

The colour is explicit (`colors.FACTORY_BLUE`), not a `state`, and `result` is None — no
check or cross lands on this sign.

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** launch the spin at the hold's end, not at the entrance's end. The overlap is the whole
  trick: the gear is seen already turning.
- **Do** blur the teeth over the exposure. Without it the panel samples the tooth pattern too
  coarsely and a sharp gear reads as turning the wrong way.
- **Do** end on a whole number of turns so the gear stops tooth-aligned with where it started.
- **Don't** fade the hole with the body. It is flat black at every alpha — a hole, not a
  dark disc, exactly like the check in [firmware verified](verdict-firmware-verified.md).
- **Don't** ease the coast with a generic ease-out. `motion.freewheel` is an exponential decay
  with a hard launch; an ease-out starts soft and the mechanism dies.

{{partial:port-notes}}
