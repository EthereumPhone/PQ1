## What it is

A screen that owns its canvas opens on black — a [verdict](verdict-law.md), an [arriving ending](../screen-types/status-arrive.md), a [led film](lead-film.md), a [PIN row](../components/pin-row.md). One frame earlier the flow was resting its token disc in the middle of the panel. `handoff` stops that disc from vanishing: the incoming screen **redraws the token itself** and washes it out to black under its own opening phase.

It is a field on the screen dict, not a property of the transition. The receiving screen does the work, on its own clock, inside its first phase — so a port needs no state carried between screens, only the token description the screen already holds.

## When it appears

Every screen spliced from the library carries the flag: `screens.spec()` sets `handoff=True` (and pins the token solid) so a library screen never pops into a flow. Only four animations act on it — a verdict, an [arriving ending](../screen-types/status-arrive.md), a [led screen](lead-film.md) and the PIN row. The films and the idle screens ignore the flag: they open on the token themselves, so there is nothing to hide. A flow writing its own status dict asks for it or not; the firmware endings do not, because their lead film opens on a disc of the same size in the same place.

In the live flows it is mostly **dropped**: of the six screens carrying the flag, exactly one runs it — `unlock_batch`'s padlock, the only one whose previous screen rests on a token. It is dropped in three places:

- after a token-less screen — `flow.Sim._anim` ({{loc:pq1.flow.Sim._anim}}) rebuilds the spec with `handoff=False` when the previous screen left no token. The lookup wraps, so it also covers screen 0 of a flow that opens on a PIN entry.
- on a `lead` film — `status.anim_for` ({{loc:pq1.status.anim_for}}) builds the lead with `handoff=False`. The outer screen crossfades **under** the lead instead.
- on a verdict played inside an entry — the PIN row builds its miss / match tail the same way: the row is already on the canvas.

## Spec

Not a `pq1/layout.py` schema key; it is documented in the `pq1/status.py` docstring beside `lead` and `lead_gap`.

| key | form | meaning |
|---|---|---|
| `handoff` | `True` | this screen redraws the flow's resting token and fades it out over its opening phase |

## How it draws

`status.draw_handoff` ({{loc:pq1.status.draw_handoff}}), called as the screen's **first** drawing step:

1. nothing at all when the spec has no `handoff`, and nothing once the wash is complete — so it costs nothing after its span;
2. the token, from **this screen's own spec** (`components.token_from_spec`), at x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}, r {{val:pq1.layout.CIRCLE_R}}, carrying the screen's glyph;
3. a black disc over it at r {{val:pq1.layout.CIRCLE_R}} + 2.5 px — just past the token's ring — at alpha `ease_out(t / span)`.

It is a **local** wash, not a frame dim: whatever the screen draws afterwards (the lead film, the verdict icon, the caption) is untouched. Contrast the [token-less transit](tokenless-fade.md), which dims the whole frame with `canvas.dim`.

The position is not a coincidence: a status screen's layout parks the circle at exactly that centre and radius, so the redrawn disc lands where the [spring morph](spring-morph.md) left the real one. The *look* matches for the same reason — past the halfway mark the morph already dresses the disc in **this** screen's token style, so the redraw at t 0 repeats the frame the transit ended on. `screens.spec()` pins `token={"variant": "solid"}` so a spliced screen never inherits the unknown gradient, and the flow's `DEFAULTS` supply the icon.

The clock starts at the *end* of the transit, not at the press: a status screen's animation is drawn only once every spring has settled, from its own t 0 ({{loc:pq1.flow.Sim.draw}}). Nothing of the screen is on the panel before then.

## Motion

{{motion-head}}
{{row:the wash rises over the token — a verdict | pq1.verdict.VerdictAnim.T_HOLD | ease_out | the span IS the verdict's black hold, so the token is gone exactly as the icon starts}}
{{row:… a verdict with its own hold (the padlock) | anim:verdict/padlock@unlock:T_HOLD | ease_out | the span follows the instance's `T_HOLD`, not a shared constant}}
{{row:… an arriving ending | pq1.status.ArriveStatus.T_HOLD | ease_out | same span, declared again}}
{{row:… a led screen | pq1.status.LedAnim.HANDOFF_MS | ease_out | measured from the screen's time 0, under the lead — never after it}}
{{row:… the PIN row | screens.pin.pin_entering.T_FADE | ease_out | the row's own ring fade, deliberately longer than the verdict hold}}

One span, three declarations. `VerdictAnim.T_HOLD`, `ArriveStatus.T_HOLD` and `LedAnim.HANDOFF_MS` are the same number meaning the same thing; the PIN row's is different on purpose. Port them as one constant plus the entry's own.

## Input

Nothing is bound *by* the handoff, and nothing about it changes with input. On a verdict or an arriving ending the question does not arise: an ending refuses every press for its whole life ([unbound gestures](../actions/unbound-gestures.md)). The PIN row is the exception — it is an entry, live from its first settled frame, so the first digit can already be dialled while the wash is still running under the rings. Do not gate an entry's input on its own fade.

## Do / Don't

- **Do** drive the wash from the screen's own clock, as a pure function of `t`.
- **Do** drop it when the previous screen left no token — otherwise a disc appears out of black at time 0, which is worse than the pop it was meant to fix.
- **Do** run it under a lead film, from time 0, not between the lead and the main.
- **Don't** dim the frame. Only the disc's own area darkens; the ring is covered because the wash is 2.5 px wider than the token.
- **Don't** let the redrawn token differ from the one the flow was showing. The screen's `icon` / `token` are what get drawn, not the previous screen's.

{{partial:port-notes}}
