{{doc-self}}

## Timeline

One sign — the warning triangle with the brush cut out of it — and two presets: the sign alone,
and the same sign with a film in front of it. The pulse treatment is retired (user request, Sep
2026): the swiffle is the one WALLET WIPED accent. The accent window is `ACCENT` and the law's
beat `T_WAIT` is built from it (`T_MARK + ACCENT`).

### `wallet_wiped_anim` — the swiffle (the default)

{{motion-head}}
{{row:black hold — the flow's token hands over | anim:verdict/wipe@wallet_wiped_anim:T_HOLD | ease_out | `status.draw_handoff` veils the resting token; with `handoff` unset the canvas is black}}
{{row:the sign arrives — fade | anim:verdict/wipe@wallet_wiped_anim:T_IN | ease_out | the triangle fades in the failed red. The brush does not: it is drawn in flat black, so it is a hole in the triangle at every alpha}}
{{row:the sign arrives — rise | anim:verdict/wipe@wallet_wiped_anim:T_IN | arrive | triangle height {{tok:screens.verdict.wipe.TRI_H}} px scaled from {{tok:pq1.motion.ARRIVE_FROM}} to 1, about 2 px of growth. The brush's width and its offset below the centre ride the same scale}}
{{row:beat between the entrance and the accent | screens.verdict.wipe.T_MARK | — | the sign is still, and seen still}}
{{row:the brush swings | screens.verdict.wipe.ACCENT | sine | swivel = 0.30 x sin(4 pi v) x (1 - v cubed): two full swings about the TOP of the handle, peaking near 0.30 rad (about 17 degrees), which throws the bristle tip about 7.2 px sideways. The decay is cubic, so the last swing is nearly still}}
{{row:the bristles drag, in the same window | screens.verdict.wipe.ACCENT | sine | bend = 0.28 x cos(4 pi v) x (1 - v cubed). The strip warps quadratically away from its top edge, which stays glued to the head — about 1.4 px of lag at the bottom edge. It is a cosine against the swing's sine on purpose: the drag points opposite the motion}}
{{row:the caption fades in | anim:verdict/wipe@wallet_wiped_anim:T_TEXT | ease_out | WALLET WIPED on the baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | see [result hold](../transitions/result-hold.md)}}

The triangle does not move. Only the brush inside it does, and the scale stays at 1 once the
entrance has settled.

### `wallet_wiped_explosion` — led by the blast

One screen, one dwell: the film and the verdict are not two flow steps. See
[status — led by a film](../screen-types/status-led.md) and [lead film](../transitions/lead-film.md).

{{motion-head}}
{{row:the lead film, its tail, then black until the sign's hold | anim:verdict/wipe@wallet_wiped_explosion:t_resolve - anim:verdict/wipe@wallet_wiped_anim:t_resolve | — | the major [explosion](fx-explosion.md) in red, entering from BOTH edges and spiralling straight onto the orbit, five turns instead of the stock three, WIPING… and DO NOT POWER OFF alternating from the orbit to the boom. The sign's black hold ends `lead_clear=700` ms after the last ring clears}}
{{row:the sign's own timeline — the swiffle table above, unchanged | anim:verdict/wipe@wallet_wiped_anim:t_resolve | ease_out + arrive + sine | hold, entrance, mark, swiffle, caption, on its own clock starting at the row above}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | }}

The first row's token cell names the subtraction it is read from — the led screen's resolve less
the sign's own — because the clearance is written inline in `PRESETS` (`lead_clear=700`), not as
a named constant. Every other led screen takes the default clearance,
{{tok:pq1.status.LEAD_CLEAR_MS}}: its sign rises as the blast clears.

Two things a porter gets wrong here. First, the flow's token crossfades out under the **lead's**
first {{tok:pq1.status.LedAnim.HANDOFF_MS}}, never after the film. Second, the sign is placed from
the tail's clearance, not from the boom: with this positive `lead_clear` the canvas is black for
a beat before the sign arrives — the general case (the default, negative clearance) runs the
sign's hold under the blast's fading rings.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}} — plus the entrance's `motion.ease_out` and `motion.arrive`
from `VerdictAnim.entrance`. The swiffle is hand-rolled sine and cosine in `draw_icon`, not a
named curve: port the formulas, not an easing name.

## Constants

{{constants}}

`ACCENT` is the swiffle window; `T_MARK` is the beat in front of it. `TRI_H` is the
ONE notice height, `warning_triangle.NOTICE_H` ({{loc:pq1.procedural.warning_triangle.NOTICE_H}}),
derived from the sign box ({{tok:pq1.layout.VERDICT_BOX}}) and shared with [tamper](verdict-tamper.md)
and [sig error](verdict-sig-error.md). The triangle's bounding box is 72 x 64 units with a corner
radius of 6 at that height; the brush lives in a 32 x 26 local box with its pivot at the top of
the handle.

## Spec a flow splices in

{{spec}}

{{used-in}}

## Preview

{{preview}}

## Do / Don't

- **Do** draw the brush as flat black, never as a faded colour. It is a cut-out in the triangle
  and must read at every alpha, exactly like the check in
  [firmware verified](verdict-firmware-verified.md).
- **Do** swing the brush about the top of its handle. Rotating it about its centre turns a
  sweeping motion into a spinning object.
- **Do** lag the bristles against the swing. That single cosine is what makes the strip feel
  like it is dragging on a surface rather than being painted on the handle.
- **Don't** hand the explosion preset to the flow as two screens with a transit between them.
  One screen, one dwell, one ending.

{{partial:port-notes}}
