{{doc-self}}

## Timeline

One throw that lands, not a spin. The die arrives in the pose it will unwind **from** — wound
back from the resting corner by the full tumble — rests there long enough to be read as a still
object, then turns once on three axes and decelerates into `die3d.REST`, the corner view of the
1-2-3 faces. The settle is the beat: nothing else happens before the caption.

{{motion-head}}
{{row:black hold — the flow's token hands over | pq1.verdict.VerdictAnim.T_HOLD | ease_out | `status.draw_handoff` veils the resting token; with `handoff` unset the canvas is black}}
{{row:the die arrives — fade | pq1.verdict.VerdictAnim.T_IN | ease_out | alpha 0 to 1 on the face FILLS only; the edge strokes and the pips are drawn flat black at every alpha, so the die reads as a die before it is fully in}}
{{row:the die arrives — rise | pq1.verdict.VerdictAnim.T_IN | arrive | half-edge {{tok:screens.verdict.rng_failed.SIZE}} px scaled from {{tok:pq1.motion.ARRIVE_FROM}} to 1 — well under a pixel}}
{{row:rest on the wound-up die | screens.verdict.rng_failed.T_REST | — | the source's visible hold. The die is still, and still in the wrong pose: it is seen before it is thrown}}
{{row:the tumble | screens.verdict.rng_failed.T_TUMBLE | decel | three axes unwind at once into `die3d.REST` — pi about X, 1.5 pi about Y, 0.5 pi about Z (`SPIN`) — on decel with p = {{tok:screens.verdict.rng_failed.DECEL_P}}. At launch that is about 36 degrees a panel frame about Y and 24 about X}}
{{row:motion-blur exposure, re-taken every frame of the tumble | screens.verdict.rng_failed.SHUTTER_MS | linear | the die is averaged over the per-axis angles swept in the exposure, one pose per 2 degrees up to {{tok:pq1.procedural.die3d.BLUR_SAMPLES_MAX}} of them}}
{{row:beat on the settled die | screens.verdict.rng_failed.T_BEAT | — | the corner view is held still before the words}}
{{row:the caption fades in | pq1.verdict.VerdictAnim.T_TEXT | ease_out | RNG FAILED on the baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | see [result hold](../transitions/result-hold.md)}}

`T_WAIT` is built from the mechanism — `T_REST + T_TUMBLE + T_BEAT` — so the law's beat and the
throw are the same window. The mechanism's clock starts at `T_HOLD + T_IN`, after the entrance:
first the rest, then the tumble's own clock at `T_HOLD + T_IN + T_REST`. Nothing runs under the
entrance — unlike [factory signing](verdict-factory-signing.md), this sign arrives at rest.

**The blur is lighter here than on the gear.** The cube repeats every 90 degrees and the launch
stays under half of that, so the sharp frames already read as one die turning; the exposure is
only {{tok:screens.verdict.rng_failed.SHUTTER_MS}} — a third of a panel frame — enough to take
the edge off the first frames without smearing the faces away. Before the tumble starts,
`_rot` clamps to the wound-up pose, so the sweep is zero and the resting die is sharp.

## Geometry

The resting ink box is 64 x 55 px, centred on the circle grid — `layout.CENTER_X`,
`layout.CIRCLE_CY` — with a half-pixel nudge right ({{tok:screens.verdict.rng_failed.DIE_DX}}
px), because the corner view inks slightly left of the cube's true centre. That nudge is a
constant: it does not scale with the entrance. Faces are back-face culled, rounded, stroked
black, and the pips are sampled on each face plane and projected, so they foreshorten.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}}. The fade and the rise are `VerdictAnim.entrance`
(`motion.ease_out`, `motion.arrive`) — see [the verdict law](../transitions/verdict-law.md).

## Constants

{{constants}}

`SPIN` is stored in radians, per axis, in the order X, Y, Z.

## Spec a flow splices in

{{spec}}

`state` is failed, so the die takes the failed red from `colors.STATE`; `result` is None, so no
glyph lands on top of it.

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** wind the die back from its rest pose and unwind it. Do not tumble it forward and hope
  it lands on the 1-2-3 corner: the landing is the point, and this way it cannot miss.
- **Do** keep the rest before the throw. Without it the die is never seen as an object, only as
  a blur that stops.
- **Don't** spin it further or longer. The bigger tumble of the original design read as too much
  spinning, too much blur, too long.
- **Don't** blur it as hard as the gear. Over-blurring loses the pips, and the pips are what say
  the die landed.

{{partial:port-notes}}
