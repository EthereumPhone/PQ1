## What it is

The ending of a flow that was cancelled. A cancel does no work, so it shows no loading: there is **no film**. The token that arrived at the centre resolves in place over one flash beat — its glyph fades, the disc and ring crossfade into the resting look, the flash ring fires in the result colour — then the X and the caption land. It is the **default** cancel choreography and the only film-less one: there is no other spinner. A failure the device learns of AFTER the hold — the host rejects what was signed — is not a cancel: that ending names the [qubit film](status-qubit.md) and collides into the X (`send`'s TRANSACTION FAILED). A flow may still name something else for its failing ending — a verdict (`unlock_batch` ends on the padlock LOCKED) or an ending led by a film (the firmware `DECLINED`) — but it must say so.

It is a `status` screen whose animation is `"resolve"` — the default for every ending whose `state` is **not** `"done"` (`status.default_anim`, {{loc:pq1.status.default_anim}}). The class is `ResolveStatus` ({{loc:pq1.status.ResolveStatus}}).

## When it appears

After a completed [hold left](../actions/hold-left-decline.md) — armed on every navigable screen of a flow that has a failing ending — and on any other ending the device reaches whose `state` is not `"done"` and that names no film — a decline, a rejection before dispatch. The token first travels to the centre on the normal [spring morph](../transitions/spring-morph.md); the resolve starts when that transit has settled. {{used-in}}

## Spec

{{fields:kind,status.bottom,anim,result,state,color,resting}}

{{example}}

The **state** picks the animation, not the glyph: any state other than `"done"` resolves in place unless the ending names `anim="qubit"` (the post-dispatch failure). `result` still defaults to `"check"`, so a cancel names `result="x"` itself. There is no loading window, so `busy` is ignored here.

## Geometry

Centred on x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}. It borrows the film's geometry (`QubitCfg`, {{loc:pq1.loading.QubitCfg}}) so both endings rest on the same disc.

| part | from (the arrived token) | to (the resting look) |
|---|---|---|
| disc radius | {{val:qubit:r_big}} − {{val:pq1.components.TOKEN_INSET}} (the token's visible edge) | {{val:qubit:r_big}} |
| disc colour | the token's fill (an unknown token: its gradient) | the resting fill — black, or the brand's cancel red |
| ring colour | the token's ring (white, or its explicit stroke) | the resting ring — the state colour, or black when branded |
| ring radius | {{val:qubit:r_big}} − {{val:pq1.components.TOKEN_INSET}} | unbranded: the same; branded: flush at {{val:qubit:r_big}} |
| ring stroke | {{val:pq1.components.TOKEN_RING_W}} px | the same |
| flash ring | r {{val:qubit:r_big}}, in the flash colour: `color` if set, else a branded ending's resting fill, else the state colour | grown by 55 px, 2.5 px stroke |

For an unknown token the gradient stays underneath and the resting fill fades in over it. See [the resting look](resting-look.md).

## Motion

Time 0 is the frame on which the transit into the screen has settled. At time 0 the frame is pixel-identical to the arrived token — nothing pops.

{{motion-head}}
{{row:the beat: disc, ring colour and ring radius crossfade | qubit:T_FLASH | ease_out | one linear progress over the film's flash length, passed through `ease_out` for every colour and radius}}
{{row:the token glyph fades out | qubit:T_FLASH * 0.45 | linear | gone at 45 % of the beat; it does not shrink (in the film it does)}}
{{row:the flash ring fades in | qubit:T_FLASH * 0.12 | linear | a gate over the first 12 % of the beat: at t 0 there is no ring sitting on the disc edge, and by the next panel frame the gate is already fully open. It is a gate, not an accent — the two-frame minimum does not apply}}
{{row:the flash ring grows and fades | qubit:T_FLASH | linear | radius and alpha both linear, alpha from 85 % to nothing — the same ring as the film's}}
{{row:result glyph fades in | 350 | linear | starts at the end of the beat; the film's own resolve timing — a bare literal, no token}}
{{row:caption waits | 120 | hold | counted from the end of the beat; bare literal}}
{{row:caption fades in | 350 | linear | bare literal}}
{{row:resolved, from time 0 | anim:core/resolve:t_resolve | — | the beat}}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | the same hold as every ending — see [result hold](../transitions/result-hold.md)}}
{{row:whole screen | anim:core/resolve:duration | — | resolved + result hold}}

The disc does not overshoot here: the `back_out` pop belongs to the [film](status-qubit.md) only. See [flash ring + result glyphs](../components/flash-ring.md). Like the film, the resolve rests on the token disc (`rests_on_token` stays true), so leaving it is an ordinary token transit, not a fade to black.

## Input

None. The chevrons are hidden and the driver ignores every press while the ending plays and after it rests ([unbound gestures](../actions/unbound-gestures.md)).

## Preview

{{preview}}

## Do / Don't

- **Do** start from the exact token the flow was showing — fill, ring, glyph — so the first frame cannot pop.
- **Do** keep it short. A cancel must feel instant next to a signature.
- **Don't** add a spinner, a film or a busy caption to a cancel. The film is for work.
- **Don't** port the demo's auto-advance after the ending; the driver freezes a finished ending on its resting frame.
- **Don't** shake, bounce or pulse the X. The flash ring is the whole accent.

{{partial:port-notes}}
