## What it is

The frame a flow's endings rest on: one disc at the panel centre with a ring and a result glyph (check or X), the caption on the bottom baseline, no chevrons, no trail. It is not a screen kind of its own — it is the last state of the three core status animations, whichever way the screen got there ([qubit film](status-qubit.md), [cancel resolve](status-resolve.md), [arrive](status-arrive.md)).

Not every `status` screen ends here. A **verdict** screen — the `screens/verdict/` library: LOCKED, WALLET WIPED, LAST ATTEMPT — is a status screen whose animation draws its own procedural sign instead of the token disc, and a PIN entry is a status screen that is typed into. Those rest on their own frame; only the three animations above resolve to this look.

One law, two dresses. **Branding fills the disc; no branding strokes it.**

| | unbranded (the default) | branded (`resting` set) |
|---|---|---|
| disc fill | black — nothing shows | the brand fill on SIGNED; failed red on every DECLINED |
| ring | the state colour, inset like a token's ring | black, flush at the disc edge |
| result glyph | the state colour | the family's mark colour (black by default) |
| flash ring as the result lands | the state colour | the resting fill — never state green over a brand disc |
| caption | white | white |

State colours come from `colors.STATE` ({{loc:pq1.colors.STATE}}): done {{val:pq1.colors.GREEN}}, failed {{val:pq1.colors.RED}}, warning {{val:pq1.colors.ORANGE}}, awaiting {{val:pq1.colors.YELLOW}}. Live flows use only done and failed today; warning appears on library screens.

## When it appears

Unbranded is the default: every ending whose screen sets no `resting` key (send, approve, blind, EIP-1271, batch …). A family can brand its token and still rest unbranded — ERC-7730 and fingerprint flows carry their own named ramp on the disc, and their endings are the plain black disc with the state-colour stroke.

Branded: three families today — the three that pass a `resting` override.

| family | SIGNED / done | DECLINED |
|---|---|---|
| SAFE ({{loc:flows.safe.ends}}) | `#13FF7F` disc, black check | red disc, black X |
| CoW Swap ({{loc:flows.cowswap.ends}}) | `#65D9FF` disc, navy check {{val:pq1.colors.COWSWAP_DARK}} | red disc, **black** X |
| firmware ({{loc:flows.firmware.ends}}) | white disc, black check | red disc, black X |

Red is {{val:pq1.colors.RED}}. It is the **one cancel circle every family shares**: a family's own mark colour dresses SIGNED only.

{{used-in}}

## Spec

{{fields:status.resting,status.state,status.result,status.color,status.bottom}}

{{example}}

Build the override with `status.branded_resting(fill, mark=BLACK)` ({{loc:pq1.status.branded_resting}}); it always returns a black ring. `status.style_of` ({{loc:pq1.status.style_of}}) resolves the look:

- The accent colour (flash ring; unbranded ring and glyph) is `color` if given, else the `resting` fill, else the state colour.
- The ring is flush as soon as the screen carries a `resting` key at all, even a partial one. Missing keys fall back to black fill and accent-coloured ring and glyph. Always pass all three.
- An unknown `state` or `result` raises. There is no silent fallback.

## Geometry

- Disc: centre x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}, the full layout radius {{val:pq1.layout.CIRCLE_R}}.
- Ring: {{tok:pq1.components.TOKEN_RING_W}} px wide, stroked **inward** from its radius. Unbranded: outer edge {{val:pq1.components.TOKEN_INSET}} px inside the layout radius — exactly where a flow token's ring sits, so the ring does not jump when the token resolves. Branded: outer edge on the layout radius.
- What shows on the black panel: a black ring over a black ground is invisible. A branded disc therefore reads as a filled disc whose radius is the layout radius minus the ring width. Draw it as the code does — the full disc, then the black ring over its rim — and the size comes out right.
- Glyph: `check` or `x`, drawn at the disc centre for the full radius ({{loc:pq1.status.RESULTS}}). `result: None` draws no glyph.
- Caption: see [caption](../components/caption.md). Chevrons are hidden on every status screen ({{loc:pq1.layout.normalize_screens}}); here they are hidden because an ending takes no input.

## Motion

The look itself does not move. How it lands depends on the screen's animation; the glyph-then-caption order is the same everywhere.

{{motion-head}}
{{row:qubit film: the flash beat — the single body returns already wearing the resting fill and ring | qubit:T_FLASH | back_out | radius 17 px to full; the one sanctioned overshoot. Flash ring: radius +55 px, alpha 0.85 to 0, both linear — see [flash ring](../components/flash-ring.md)}}
{{row:cancel resolve: token disc, ring and radius crossfade into the look | qubit:T_FLASH | ease_out | the resolve runs one flash beat — `ResolveStatus` takes the film's `T_FLASH` as its whole resolve. Fill and ring colours mix; the disc edge eases out to the full radius; a branded (flush) ring travels the inset outward, an unbranded one is already at the token edge and does not move. The token glyph is gone by 45 % of the beat (linear)}}
{{row:film and resolve: the result glyph fades in | - | linear | starts when the beat ends; length is a literal in the code: {{lit:350 ms}}}}
{{row:film and resolve: the caption fades in | - | linear | same length, starts {{lit:120 ms}} after the glyph}}
{{row:arrive: black hold | pq1.status.ArriveStatus.T_HOLD | hold | after a [lead film](../transitions/lead-film.md) emptied the canvas}}
{{row:arrive: disc, ring and glyph together | pq1.status.ArriveStatus.T_IN | ease_out + arrive | alpha on ease_out, scale {{val:pq1.motion.ARRIVE_FROM}} to 1 on arrive — the [verdict entrance law](../transitions/verdict-law.md); no flash ring}}
{{row:arrive: beat | pq1.status.ArriveStatus.T_WAIT | hold | }}
{{row:arrive: the caption fades in | pq1.status.ArriveStatus.T_TEXT | ease_out | }}
{{row:the rest | pq1.status.RESULT_HOLD_MS | hold | every ending rests this long once resolved — see [result hold](../transitions/result-hold.md)}}

## Input

None. An ending is input-dead from its first frame to its last — every gesture, tap or hold, is ignored; see [unbound gestures](../actions/unbound-gestures.md). (The one status screen that does take input is the PIN entry, and it never wears this look.) Once the rest is over the reference driver freezes on the resting frame; the exception is a mid-batch ending, which moves on to the next segment's hero — see [batch](batch-segment.md).

## Preview

{{preview}}

## Do / Don't

- **Do** pick the dress from the flow family, not per screen: a branded family brands **both** its endings.
- **Do** give a new family its ramp's token-disc colour as the fill and its logo's dark colour as the mark — `branded_resting(fill, mark)`.
- **Do** let the flash follow the disc: brand fill on a branded ending, state colour on an unbranded one.
- **Don't** fill an unbranded ending, and don't stroke a branded one in the state colour.
- **Don't** give a family its own cancel colour or a coloured X. DECLINED is red disc, black ring, black X everywhere.
- **Don't** carry the state colour into the caption. Captions stay white.
- **Don't** port the demo loop's wrap back to the first screen after the rest. On the device the ending stays until the firmware moves on.

{{partial:port-notes}}
