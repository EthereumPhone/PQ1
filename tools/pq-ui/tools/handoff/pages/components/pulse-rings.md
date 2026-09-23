## What it is

Two thin rings that are born at the edge of the token, grow a few pixels and fade out, one after the other, for as long as the screen is up. They mark a screen that needs **extra attention** — the user is about to approve something the device cannot fully show. They are an accent on the token, not a state: the screen keeps its normal layout, caption and input.

The drawing is `components.pulse` ({{loc:pq1.components.pulse}}); `flow.Sim` calls it for every screen whose spec carries `pulse` ({{loc:pq1.flow.Sim.draw}}). Do not confuse it with `motion.attention_pulse` (a verdict icon's scale pulse) or `motion.busy_pulse` (the [busy caption](busy-caption.md)).

## When it appears

Exactly one live screen uses it today: **BLIND SIGN** in `safe/can_not_decode` ("Can not decode data / Confirm on dapp"), with `pulse: True`, so the rings take the Safe green of the token's fill. The `flows/blind/` family does **not** pulse; it carries the `blind` mark instead. Treat the rings as a rare emphasis a flow author opts into per screen, never as a default.

## Spec

{{fields:pulse}}

- `True` → the rings take the token's resolved **fill** (`token_style_from_spec`), or white when the style has no fill (`_pulse_color`, {{loc:pq1.flow._pulse_color}}).
- `[r, g, b]` → that colour.
- The schema lists `pulse` under detail, but the code reads it on any screen that rests on the token.

## Geometry

Both rings share the token's live centre — they travel with it in a transit and on the [idle sweep](idle-sweep.md). `r` below is the token's **layout** radius (the radius spring's live value, {{tok:pq1.layout.CIRCLE_R}} on every navigable screen), **not** its visible edge — the rings are measured from the layout circle. With `phase` running 0 → 1 over one period:

| part | value |
|---|---|
| ring count | 2, the second half a period behind the first |
| outer radius | `r + 1.5 + 7 · phase` — from r + 1.5 to r + 8.5 px, linear |
| stroke | {{tok:pq1.components.TOKEN_RING_W}} px — the system ring weight — stroked inward from that radius |
| alpha | `(1 − phase) · 0.4 · screen alpha`, linear; composited with **true alpha**, not scaled toward black |
| cut-off | a ring under alpha 0.02 is not drawn (the last 5 % of its life) |
| layer | over the [trail](trail.md) links, under the [token](token-disc.md) |

A newborn ring hugs the token: its stroke spans r − 0.9 to r + 1.5 px, a hair outside the token's visible edge (r − {{val:pq1.components.TOKEN_INSET}}). It appears at its full 0.4 alpha — there is no fade-in.

## Motion

{{motion-head}}
{{row:one ring: born at the token's edge, grows 7 px and fades to nothing | 2000 | linear | one whole `period`; radius and alpha are both straight lines of the phase. The token column shows the literal because the value is the `period` default argument of `components.pulse` ({{loc:pq1.components.pulse}}), not a named constant — give it one in the port}}
{{row:the second ring is half a period behind | 2000 * 0.5 | — | its life is the same; so a ring is born every half period and two are always alive}}
{{row:the rings appear when the screen arrives | pq1.motion.TEXT_IN_DELAY_MS | spring NAV | they ride the screen's **text alpha** spring: released after this delay, then fading in with the words}}
{{row:the rings leave when the screen leaves | - | spring NAV | the same alpha spring, retargeted to 0 the moment the transit starts}}

The phase is `(now / period + k · 0.5) mod 1` for ring `k` = 0, 1, where `now` is the flow's **running clock**, not the time on this screen. The rings are free-running: they do not restart when the screen arrives, and the first ring you see may be born mid-life as the alpha comes up. That is the reference behaviour; nothing needs to be synchronised.

During a transit the rings are drawn around the **moving** token at the alpha of the pulsing screen's text, so they visibly travel out with the token while they fade. They are not drawn during a status ending or a [token-less transit](../transitions/tokenless-fade.md).

## Input

None. The rings change nothing about what the buttons do, and a press does not pause them. They keep running under a live hold: the [hold flood](hold-flood.md) rises inside the token while the rings pulse outside it.

## Preview

No clip of its own. Render the one live use with `python3 -m flows safe/can_not_decode`.

## Do / Don't

- **Do** compute the phase from the ms clock with a modulo. Never count frames or accumulate a radius.
- **Do** composite the rings with real alpha: they cross the trail links, which are coloured.
- **Do** multiply by the screen's text alpha, so the rings arrive and leave with the words.
- **Don't** ease the growth or the fade. Both are linear; the softness comes from the alpha ending at zero.
- **Don't** add rings to a screen on your own. The flow's spec decides; blind-signing flows outside the Safe family do not use them.
- **Don't** reuse the rings as a loading or a success effect. The result flash is a different part — see [flash ring](flash-ring.md).

{{partial:port-notes}}
