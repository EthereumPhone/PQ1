{{doc-self}}

The rule a duress PIN breaks: it may not be the real one. Unlike
[verdict / pin_mismatch](verdict-pin-mismatch.md), nothing is being revealed here, so the pill
arrives whole — outline and all {{val:pq1.procedural.pin_pill.SLOTS}} dots already in the warning
orange — and the mechanism is the device *checking* it: a scanline crosses the pill and comes back,
finds the same PIN, and the row shakes it off.

Everything is in `state="warning"` (orange 245 160 51). The art is the shared
`pq1.procedural.pin_pill` ({{loc:pq1.procedural.pin_pill.draw}}), plus its scanline
({{loc:pq1.procedural.pin_pill.scanline}}): a bar {{val:pq1.procedural.pin_pill.SCAN_HW}} px to each
side of its centre, overhanging the pill {{val:pq1.procedural.pin_pill.SCAN_OVER}} px top and bottom,
filled in the state colour and stroked BLACK so it stays legible where it crosses the outline.

## Timeline

Play order; this module has no presets, so one table. The mechanism clock `tm` starts when the
entrance ends — at `T_HOLD` + `T_IN` on the screen's clock.

{{motion-head}}
{{row:black hold — the flow's token hands over | screens.verdict.duress_differ.DuressDiffer.T_HOLD | ease_out | the resting token is drawn, and a black disc of FIXED radius — the token's ({{val:pq1.layout.CIRCLE_R}} px) plus a hair — fades in over it; the disc never grows ({{loc:pq1.status.draw_handoff}}); with no token before it, plain black}}
{{row:pill AND dots arrive together | screens.verdict.duress_differ.DuressDiffer.T_IN | ease_out + arrive | the entrance law: one alpha over outline and dots, scale {{val:pq1.motion.ARRIVE_FROM}} to 1, no overshoot. Already orange — there is no normal state to recap}}
{{row:the filled row holds | screens.verdict.duress_differ.T_FILLED | hold | the beat before the check}}
{{row:the scanline crosses and comes back | screens.verdict.duress_differ.T_SCAN | raised cosine | position is 0.5 − 0.5·cos(2π·u) for {{val:screens.verdict.duress_differ.SCAN_CYCLES}} cycle, so the bar eases at each end, travels 92 px each way and ENDS WHERE IT STARTED. Each traverse is half this}}
{{row:… and the bar fades out over the sweep's tail | screens.verdict.duress_differ.T_SCAN * pq1.procedural.pin_pill.SCAN_FADE | ease_out | the last tenth of the sweep — the fraction is {{tok:pq1.procedural.pin_pill.SCAN_FADE}}. Shorter than ONE panel frame: on glass the bar all but cuts out}}
{{row:the row shakes the duress PIN off | screens.verdict.duress_differ.T_SHAKE | shake | horizontal only. Centre x moves by {{val:screens.verdict.duress_differ.SHAKE_PX}} px times a decaying sine of {{val:screens.verdict.duress_differ.SHAKE_CYCLES}} cycles — first swing about 6.1 px, then nothing. The scanline is already gone}}
{{row:the verdict beat | screens.verdict.duress_differ.T_BEAT | hold | the pill sits still before the rule is named}}
{{row:the caption fades in | screens.verdict.duress_differ.DuressDiffer.T_TEXT | ease_out | DURESS PIN MUST DIFFER on the shared baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:the verdict rests | pq1.status.RESULT_HOLD_MS | hold | from `t_resolve` {{val:anim:verdict/duress_differ:t_resolve}} to the end}}

The sweep and the shake never overlap: the scanline is drawn only while its progress is strictly
inside 0 to 1, which ends exactly when the shake begins. No result glyph, no flash ring —
`rests_on_token` is false, so the flow fades this frame out and carries no token over the transit.

## Variants

{{variants}}

## Phases

{{phases}}

## Constants

{{constants}}

## Spec a flow splices in

{{spec}}

{{used-in}}

No flow splices it yet — it is the library answer for a duress-PIN rule, ready for the flow that
sets one. Its plain (non-verdict) twin, [pin / pin_differ](pin-pin-differ.md), states the same rule
with a longer sweep and no entrance.

## Preview

{{preview}}

## Do / Don't

- **Do** arrive filled. A duress PIN that repeats the real one was never a normal entry, so there is
  nothing to replay — the sign lands whole, like every other verdict sign.
- **Do** keep the bar's black stroke. Orange on orange vanishes where the bar crosses the outline.
- **Don't** let the sweep end at the far side. One whole cycle returning home says *checked, and
  nothing changed*; the one-and-a-half-cycle version belongs to the twin.
- **Don't** give the pill a result glyph or a ring flash. The colour and the shake are the answer.

{{partial:port-notes}}
