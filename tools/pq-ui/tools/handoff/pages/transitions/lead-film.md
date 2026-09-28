## What it is

The joint between a film and the screen it introduces. A film that ends on an **empty canvas** can be glued to the front of any status screen: the film plays, and the moment it resolves the screen's own animation starts drawing — over the film's still-fading **tail**. One screen, one clock, one dwell. The screen-level view is [status — led by a film](../screen-types/status-led.md); this page is the joint itself.

## What a film must be to lead

Two properties, both on `StatusAnim`:

| property | meaning | why it matters |
|---|---|---|
| `t_tail` set | ms the film keeps drawing past its `t_resolve` | it is the proof that the film **empties** the canvas instead of resting on a look |
| `rests_on_token` False | the film owns the canvas | nothing of it is left for the flow to morph |

Only the [explosion](../library/fx-explosion.md) qualifies today. `status.anim_for` ({{loc:pq1.status.anim_for}}) tests `t_tail` alone and raises a `ValueError` naming the reason when a spec asks anything else to lead — a build-time refusal, not a runtime fallback. Keep that refusal in a port: a film that rests on a look would leave its token sitting under the sign. (`rests_on_token` is not tested there, because the led screen reports the **main's** flag either way; it is simply true of every film that empties the canvas.)

## The joint

`LedAnim` ({{loc:pq1.status.LedAnim}}) holds one clock `t` from the screen's time 0.

| moment | expression |
|---|---|
| the lead resolves — the boom lands, the first ring is done | `lead.t_resolve` — a property: a looping lead moves it by its wraps, and `t_start` ({{loc:pq1.status.LedAnim.t_start}}) follows ([loading loop](loading-loop.md)) |
| the main starts, on its own clock `t − t_start` | `t_start` = `lead.t_resolve` + `lead_gap` |
| the lead stops drawing | `lead.t_resolve` + `lead.t_tail` |
| the screen resolves | `t_start` + `main.t_resolve` |
| the screen ends | `t_start` + `main.duration` |

Both draw in the overlap, the main second — so the main is always on top. Everything else the screen reports is the **main's**: what rests on the canvas, whether it is interactive, its name — except `loops`, which is the lead's: a led screen loops while its lead does. The previews it offers are one from each (the lead's mid-film still, the main's resolved one).

## The tail, and why the overlap is deliberate

The explosion's rings are launched one stagger apart and each flies for the same time, so the last ring lands `(rings − 1) × stagger` after the first — that is `t_tail`. A **major** tail outlasts the black hold that opens a verdict or an [arriving ending](../screen-types/status-arrive.md): with no gap the entrance begins while the last faint ring is still expanding, which is exactly the intended read — the sign appears *as* the blast clears, not after it. That is what the firmware endings show (the major film, then `arrive`).

`lead_gap` (ms, default 0) pushes the main later and opts out of that overlap. WALLET WIPED sets one longer than the tail, so the blast is completely gone and the panel is black before the verdict's own hold even starts.

## Motion

{{motion-head}}
{{row:the lead plays, to the boom | anim:fx/explosion:t_resolve | — | the stock major film; `revs` and `enter` move this — see [side entrance](side-entrance.md)}}
{{row:the major tail, drawing past the resolve | anim:fx/explosion:t_tail | linear + decel | {{val:burst:MAJOR.rings}} rings, one launched every {{val:burst:MAJOR.stagger_ms}} ms; each ring's brightness falls linearly over its flight while its radius grows on the inlined power curve `1 − (1 − u)^p`, p {{val:burst:MAJOR.grow_p}}}}
{{row:the minor tail | anim:fx/explosion@minor_explosion:t_tail | linear + decel | {{val:burst:MINOR.rings}} rings: one stagger}}
{{row:the main's black hold, under the tail | pq1.verdict.VerdictAnim.T_HOLD | hold | shorter than a major tail — the overlap is by design; an `arrive` ending declares the same span itself ({{loc:pq1.status.ArriveStatus}})}}
{{row:the flow-token handoff, when `handoff` is set | pq1.status.LedAnim.HANDOFF_MS | ease_out | from the screen's time 0, under the lead — see [handoff crossfade](handoff.md)}}
{{row:WALLET WIPED — where its main starts | anim:verdict/wipe@wallet_wiped_explosion:t_resolve - anim:verdict/wipe@wallet_wiped_explosion:T_HOLD - anim:verdict/wipe@wallet_wiped_explosion:T_IN - anim:verdict/wipe@wallet_wiped_explosion:T_WAIT - anim:verdict/wipe@wallet_wiped_explosion:T_TEXT | — | its `lead_gap` outlasts the tail, so black separates the two}}
{{row:WALLET WIPED — the whole screen | anim:verdict/wipe@wallet_wiped_explosion:duration | — | lead + gap + verdict + one result hold}}

Durations add, once. The [result hold](result-hold.md) is the main's and is counted once, at the end — never after the lead.

## Input

None, from the lead's first frame to the end of the result hold ([unbound gestures](../actions/unbound-gestures.md)).

## Do / Don't

- **Do** keep it **one** screen. Two status screens would mean two dwells, two result holds and a black transit in the middle.
- **Do** draw the main over the tail, and only delay it when `lead_gap` says so.
- **Do** force `handoff=False` on the lead itself: only the outer screen crossfades the flow's token, and it does so under the lead.
- **Don't** port `burst.HOLD_END` ({{loc:pq1.procedural.burst.HOLD_END}}). It records the original films' post-boom rest and nothing reads it; the rest that actually plays is {{tok:pq1.status.RESULT_HOLD_MS}}.
- **Don't** let a film that rests on a look lead. Refuse it where the screen is built, as the reference does.

{{partial:port-notes}}
