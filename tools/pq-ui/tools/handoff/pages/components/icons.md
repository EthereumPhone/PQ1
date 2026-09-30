## What it is

Every mark the device can draw inside a circle or in place of one, and the four laws that keep them one family: **one compositing model**, **one sign box**, **one optical centre**, **one stroke vocabulary**. The set itself is a registry, `components.GLYPHS` ({{loc:pq1.components.GLYPHS}}); `spec/icons.json` publishes it entry by entry with the art, the scale and what each one measures at rest.

A screen names an icon with the `icon` key; the [token disc](token-disc.md) draws it, and the [glyph morph](glyph-morph.md) fades between two of them. This page is about the art itself.

## The legal set

{{icon-table}}

Read the table as: **scale** is what multiplies the glyph radius the disc hands the mark; **ink box** is the mark's own ink at the disc's radius ({{tok:pq1.layout.CIRCLE_R}}), measured white on black; **ink %** and **extent %** are that ink as a fraction of the token's **visible** disc — the disc's layout radius less {{tok:pq1.components.TOKEN_INSET}}, the radius the body, the ring and every trail link share.

`eth` and `mainnet` are the same function under two names, so a morph between them draws the mark once at full alpha instead of dipping through nothing at the midpoint (`components.same_art`, {{loc:pq1.components.same_art}}).

Beside the registry there is one **namespace**, `letter:<CHAR>`: an unknown chain wears its own initial rather than borrowing another network's mark. It is matched by shape at draw time and is deliberately **not** a registry entry — registering letters lazily would make the published icon set depend on what had been rendered first ({{loc:pq1.components.letter_glyph}}). `spec/screens.schema.json` publishes it as `enums.icon_namespaces`.

A name in neither the registry nor the namespace draws the ether mark ({{loc:pq1.components.glyph}}). That fallback is for art the device genuinely lacks — see `CLAUDE.md` rule 20.

## The kinds

| kind | what the port re-creates | who |
|---|---|---|
| traced | the SVG path data, verbatim in `spec/icons.json`, flattened and filled by the entry's stated rule | the chain marks, `blind`, `dev`, `rotate`, `fingerprint`, `download` |
| geometry | points and fractions of r — no path to parse | `eth` / `mainnet`, `check`, `x`, `exclamation`, `plus`, `minus` |
| logo | full-bleed raster art, circle-masked to the visible disc | the token and family logos (`usdc`, `safe`, …) |
| text | a letter set in Bold, sized off r | `letter:<CHAR>` |

Traced art is the rule: icon art is procedural, never a recoloured bitmap. The one raster mark the system used to carry — the ether logo as a PNG — is gone; `eth` is the traced, rounded-edge mark in `pq1/procedural/eth.py` and it is what `mainnet` draws too. Full-bleed logos are the exception the rule allows: a brand's own artwork, worn by the disc rather than drawn as a mark.

## One compositing model

A mark that rests on a disc is composited by **true alpha**: its shape is inked into an L mask at the mark's alpha and the mask is pasted in the mark's colour ({{loc:pq1.procedural.marks.base_mark}}). `check`, `x` and the monogram go through that function; the traced modules build the same tile themselves, with an **even** tile side and a **rounded** paste so the mark lands on its centre exactly.

The alternative — scaling the colour toward black — is exact only against the black panel, so it survives in exactly two places that never meet a lit body: the `exclamation` inside its own warning triangle, and the `plus` / `minus` entry signs beside the corner chevrons. Everything else composites the mask.

This is not a detail. A colour-scaled check on the SAFE green is still green-black at alpha 0, so it cut in at full strength on its first frame while the caption faded in behind it.

## The sign box

A **sign** — the warning triangle, the padlock, the shield, the gear, the die — stands where the token would on a verdict, and inks its **largest** dimension to {{tok:pq1.layout.VERDICT_BOX}} px, centred on the circle grid (x {{val:pq1.layout.CENTER_X}}, y {{val:pq1.layout.CIRCLE_CY}}). One size for every sign, so a walk through the endings does not breathe. Screens derive their art constants from that one token; the checker's `V-BOX` rule measures the resting frame.

A sign is a filled silhouette in the state colour with its detail knocked out in **black**. The shield is the one written exception and keeps its outline: the shield is the container, and the mark inside it is the verdict.

These endings are not signs at all, and do not take the box:

{{sign-box}}

## The optical centre

A mark's ink sits on the circle grid in its **resting** frame. The bounding box is centred by construction; where the ink is lopsided the art is nudged until the centre of **mass** lands there instead — Avalanche's A is a wide base under a point, so its box is deliberately high (`chains.NUDGE`, {{loc:pq1.procedural.chains.NUDGE}}).

Measure the box with **exclusive** edges — the minimum and the maximum plus one. Inclusive indices read a phantom half-pixel offset whenever the ink spans an even number of supersampled pixels, which is a measurement artefact, not a mark that needs moving.

Two written exceptions: a `letter:<CHAR>` is text and is centred by the font's metrics, not by its ink; and LAST ATTEMPT's digit-and-heart pair is composed by the type tier rather than drawn as a mark.

## The stroke vocabulary

Every line weight the port draws has a name ({{loc:pq1.layout.STROKE}}):

{{stroke-table}}

The token ring reads the `ring` weight ({{tok:pq1.components.TOKEN_RING_W}}), and so does the resolve [flash ring](flash-ring.md) — it is the system ring leaving the disc, not a weight of its own. Widths off the scale are recorded decisions, each named where it is drawn:

{{stroke-exceptions}}

## The mark band

Weight, not size: within the sign box and the disc, the non-brand marks were tuned to read as one family. Extent is a mark's largest ink dimension over the visible disc's diameter; ink is the area it covers over that disc's area.

{{icon-band}}

Chain brand logos and full-bleed token art are exempt — their proportions belong to the brand, not to us — and so are the marks that never rest on a disc. A new mark outside the band is not a bug; it is a decision to take with the designer rather than by eye.

## Preview

No clip of its own. See the marks on the disc in [token disc](token-disc.md) and in the ending pages under [library](../INDEX.md).

## Do / Don't

- **Do** port the traced path data from `spec/icons.json` verbatim, with the entry's own fill rule. Re-drawing a logo by eye is how a brand mark stops being the brand's.
- **Do** composite a mark on a disc through an alpha mask. Only the exclamation and the entry signs may scale their colour.
- **Do** ink a verdict sign's largest dimension to the sign box and centre it on the circle grid.
- **Don't** raster a mark the system draws procedurally, and don't recolour a bitmap to get a second tint of one.
- **Don't** add a weight beside the four named ones without recording where it is drawn and why.
- **Know** that a mark's measured centre is its **ink**, not its box: a mark whose mass is lopsided is nudged, and its box is then off centre on purpose.

{{partial:port-notes}}
