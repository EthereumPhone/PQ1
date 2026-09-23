## What it is

An ending with no film of its own. The canvas is already empty — a [lead film](status-led.md) has just shown the work and blown the token apart — so the resting look simply **arrives**: after a black hold the resolved disc, its ring and the result glyph fade in together and rise from {{val:pq1.motion.ARRIVE_FROM}} to full size, a beat passes, the caption fades in, the screen rests.

It is a `status` screen with `anim="arrive"`; the class is `ArriveStatus` ({{loc:pq1.status.ArriveStatus}}). It obeys [the verdict law](../transitions/verdict-law.md) — the same four phases and the same entrance as every verdict icon — but what arrives is the token-shaped [resting look](resting-look.md), not an icon.

## When it appears

Never by default: `status.default_anim` only picks the [qubit film](status-qubit.md) or [the resolve](status-resolve.md). A flow names `anim="arrive"` itself, on an ending that carries a `lead`. Today that is the firmware family: the explosion, then the white disc with the black check (`UPDATED`), or the red disc with the black X (`DECLINED`). {{used-in}}

## Spec

{{fields:kind,anim,status.bottom,result,state,color,resting}}

{{example}}

`lead` (and `lead_gap`, `handoff`) are documented in the `pq1/status.py` docstring and on [status — led by a film](status-led.md). `result` and `state` work as on every status screen; `resting` brands the look (a filled disc under a flush black ring). Without `resting` the look is the default one: black disc, ring and glyph in the state colour.

## Geometry

Centred on x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}.

| part | value |
|---|---|
| disc | r {{val:qubit:r_big}} × the entrance scale |
| ring | {{val:pq1.components.TOKEN_RING_W}} px stroke; branded: flush at the disc edge; unbranded: 1.2 px inside it |
| result glyph | drawn at the disc's live radius, so it scales with the disc |
| caption | 18 px caps, centred, baseline y {{val:pq1.layout.BASELINE_Y}} |

Disc, ring and glyph share **one** alpha and **one** scale. Nothing inside the look moves on its own: no flash ring, no separate glyph fade.

## Motion

Time 0 is the start of the screen's own animation. Under a lead that is the moment the lead resolves (plus any gap) — see [led](status-led.md).

{{motion-head}}
{{row:black hold | pq1.status.ArriveStatus.T_HOLD | hold | the screen draws nothing; under a lead the film's last rings keep fading here (a major blast's tail outlasts this hold — see [led](status-led.md)). With `handoff` and no lead, the flow's token crossfades out over this span on `ease_out`}}
{{row:entrance: the look fades in and rises | pq1.status.ArriveStatus.T_IN | ease_out + arrive | alpha on `ease_out`, scale on `motion.arrive` — both from the same linear progress. `T_IN` is {{tok:pq1.motion.ARRIVE_MS}}: the law's maximum, never longer, never an overshoot}}
{{row:beat | pq1.status.ArriveStatus.T_WAIT | hold | the look stands alone}}
{{row:caption fades in | pq1.status.ArriveStatus.T_TEXT | ease_out | }}
{{row:resolved, from time 0 | anim:core/arrive:t_resolve | — | hold + entrance + beat + caption}}
{{row:result hold | pq1.status.RESULT_HOLD_MS | hold | see [result hold](../transitions/result-hold.md)}}
{{row:whole screen | anim:core/arrive:duration | — | resolved + result hold; under a lead the lead's length is added}}

The fade is a colour fade toward black (`colors.scale`), which on this panel's black ground equals alpha.

`ArriveStatus` types the phase lengths itself; they are copies of `VerdictAnim`'s ({{loc:pq1.verdict.VerdictAnim.T_HOLD}}). If you port one table, port them as one.

## Input

None. The chevrons are hidden and every press is ignored for the whole ending, the lead included ([unbound gestures](../actions/unbound-gestures.md)).

## What it leaves behind

`arrive` rests on the token disc (`rests_on_token` stays true), unlike a verdict icon. Leaving it is an ordinary token transit ([spring morph](../transitions/spring-morph.md)), not the [fade to black](../transitions/tokenless-fade.md) of a screen that owns its canvas.

## Preview

The preview plays `arrive` alone, from an empty canvas. In a real flow a lead film comes first.

{{preview}}

## Do / Don't

- **Do** bring disc, ring and glyph in as one object.
- **Do** keep the entrance inside {{tok:pq1.motion.ARRIVE_MS}}.
- **Don't** add the flash ring or the `back_out` pop: those belong to the qubit film. The lead was the spectacle; the arrival is calm.
- **Don't** use `arrive` after a screen that still shows the token, unless `handoff` fades that token out first — otherwise the token cuts to black.
- **Don't** split the lead and the arrival into two status screens: two dwells and a black transit between them.

{{partial:port-notes}}
