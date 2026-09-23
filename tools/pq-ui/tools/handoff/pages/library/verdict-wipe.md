{{doc-self}}

## Timeline

One sign — the warning triangle with the brush cut out of it — and three presets: two differ
only in the accent that plays once the sign has arrived, the third puts a film in front of the
whole thing. The entrance is the same in all three; the accent
window is `ACCENT[treatment]` and the law's beat `T_WAIT` is built from it in `Wipe.__init__`,
so `T_WAIT` is an instance value, not a class constant — the tables' `defined at` cell points at
the law's declaration, while the ms are read from the live instance.

### `wallet_wiped` — the pulse (the default)

{{motion-head}}
{{row:black hold — the flow's token hands over | anim:verdict/wipe:T_HOLD | ease_out | `status.draw_handoff` veils the resting token; with `handoff` unset the canvas is black}}
{{row:the sign arrives — fade | anim:verdict/wipe:T_IN | ease_out | the triangle fades in the failed red. The brush does not: it is drawn in flat black, so it is a hole in the triangle at every alpha}}
{{row:the sign arrives — rise | anim:verdict/wipe:T_IN | arrive | triangle height {{tok:screens.verdict.wipe.TRI_H}} px scaled from {{tok:pq1.motion.ARRIVE_FROM}} to 1, about 2 px of growth. The brush's width and its offset below the centre ride the same scale}}
{{row:beat between the entrance and the accent | screens.verdict.wipe.T_MARK | — | the sign is still, and seen still}}
{{row:the attention pulse | anim:verdict/wipe:T_WAIT - screens.verdict.wipe.T_MARK | attention_pulse | the whole sign breathes about its centre: 2.5 half-cycles under an exponential decay, peaking near scale 1.05 on the first — about 3.4 px of extra triangle height — and fading to nothing}}
{{row:the caption fades in | anim:verdict/wipe:T_TEXT | ease_out | WALLET WIPED on the baseline y {{val:pq1.layout.BASELINE_Y}}}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | see [result hold](../transitions/result-hold.md)}}

During the pulse the scale **replaces** the entrance scale; it is not multiplied onto it. That is
safe because the window opens well after the entrance has settled on 1. The window also closes on
a lobe's crest rather than at zero, so the sign snaps back a hair when the accent ends — a
fraction of a pixel at this size, but close the window on a zero if you ever scale the sign up.

### `wallet_wiped_anim` — the swiffle

The first four rows are identical. Then, instead of the pulse:

{{motion-head}}
{{row:the brush swings | anim:verdict/wipe@wallet_wiped_anim:T_WAIT - screens.verdict.wipe.T_MARK | sine | swivel = 0.30 x sin(4 pi v) x (1 - v cubed): two full swings about the TOP of the handle, peaking near 0.30 rad (about 17 degrees), which throws the bristle tip about 7.2 px sideways. The decay is cubic, so the last swing is nearly still}}
{{row:the bristles drag, in the same window | anim:verdict/wipe@wallet_wiped_anim:T_WAIT - screens.verdict.wipe.T_MARK | sine | bend = 0.28 x cos(4 pi v) x (1 - v cubed). The strip warps quadratically away from its top edge, which stays glued to the head — about 1.4 px of lag at the bottom edge. It is a cosine against the swing's sine on purpose: the drag points opposite the motion}}
{{row:the caption fades in | anim:verdict/wipe@wallet_wiped_anim:T_TEXT | ease_out | }}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | }}

The triangle does not move in this treatment. Only the brush inside it does, and the scale stays
at 1 throughout.

### `wallet_wiped_explosion` — led by the blast

One screen, one dwell: the film and the verdict are not two flow steps. See
[status — led by a film](../screen-types/status-led.md) and [lead film](../transitions/lead-film.md).

{{motion-head}}
{{row:the lead film, then the gap of black | anim:verdict/wipe@wallet_wiped_explosion:t_resolve - anim:verdict/wipe@wallet_wiped_anim:t_resolve | — | the major [explosion](fx-explosion.md) in red, entering from BOTH edges and spiralling straight onto the orbit, five turns instead of the stock three, WIPING… and DO NOT POWER OFF alternating from the orbit to the boom. Then `lead_gap` of black}}
{{row:the sign's own timeline — the swiffle table above, unchanged | anim:verdict/wipe@wallet_wiped_anim:t_resolve | ease_out + arrive + sine | hold, entrance, mark, swiffle, caption, on its own clock starting at the row above}}
{{row:resolved — the result hold | pq1.status.RESULT_HOLD_MS | — | }}

The first row's token cell names the subtraction it is read from — the led screen's resolve less
the sign's own — because the gap is written inline in `PRESETS`, not as a named constant.

Two things a porter gets wrong here. First, the flow's token crossfades out under the **lead's**
first {{tok:pq1.status.LedAnim.HANDOFF_MS}}, never after the film. Second, with this gap the
film's tail is already finished when the sign's clock starts, so the canvas really is empty
across the gap and the sign's hold — the general case, where the hold runs under the blast's
fading rings, needs a gap shorter than the tail.

## Variants

{{variants}}

## Phases

{{phases}}

Curves this module calls: {{curves}} — plus the entrance's `motion.ease_out` and `motion.arrive`
from `VerdictAnim.entrance`. The swiffle is hand-rolled sine and cosine in `draw_icon`, not a
named curve: port the formulas, not an easing name.

## Constants

{{constants}}

`ACCENT` is the accent window per treatment; `T_MARK` is the beat in front of it. The triangle's
bounding box is 72 x 64 units with a corner radius of 6 at that height; the brush lives in a
32 x 26 local box with its pivot at the top of the handle.

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
