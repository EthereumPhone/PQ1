## What it is

The circle every navigable screen carries. It says **which asset or actor** the screen is about. One function draws it, `components.token` ({{loc:pq1.components.token}}); the flow calls it through `token_styled` with a style resolved once per screen by `token_style_from_spec` ({{loc:pq1.components.token_style_from_spec}}).

A disc is three independent choices: a **body**, a **ring** and a **glyph**.

| body | when | what is drawn |
|---|---|---|
| solid, mono | a recognized token that shows its own mark (ETH, WETH) — `palette` = `MONO_RAMP` ({{val:pq1.colors.MONO_RAMP}}) | black fill, white ring, white glyph, grey trail |
| solid, placeholder ramp | a token with no logo asset — `palette` = a symbol, an address or a ramp index | the ramp's last stop as a flat fill, white ring; the [trail](trail.md) takes the other five stops |
| solid, named ramp | a brand family, a popular token or a device action pins a ramp by name (`"SAFE"`, `"USDC"`, `"FIRMWARE"` …) | that ramp's palette fill — its last stop, or the black (`ROTATE`, `ERC7730`) / white (`FINGERPRINT`, `FIRMWARE`) override of a device action; often full-bleed logo art over it and an explicit ring |
| solid, chain brand | a chain screen — `chain=<id>` pins `CHAIN:<NAME>` (`colors.CHAIN_COLORS`) | the network's own colour as the fill, its ramp as the trail, the mark knocked out white — or black once the fill is light (`colors.luma`). A chain whose body is not the ramp's last stop pins it in `CHAIN_DISC_FILL` and keeps the ramp for its trail, Mantle and Linea BLACK, Base and zkSync WHITE. Only a disc the ramp cannot produce is pinned: a merely dark brand darkens its ramp, or its nearest follower outshines the token and the trail law inverts |
| unknown | `variant: "unknown"` — a token the device does **not** recognize | a gradient disc on the ramp hashed from the token's identity, white ring |

## When it appears

On every hero, detail and Confirm? screen. A [value](../screen-types/value.md) screen parks it off-panel at x {{val:pq1.layout.VALUE_PARK_X}}. A status ending starts from it (see [handoff](../transitions/handoff.md)). A verdict or a PIN row owns its canvas and has no disc.

No live flow sets `variant: "unknown"` today. Even TRANSFER UNKNOWN TOKEN draws a **solid** disc whose ramp is hashed from the contract address (`token = {"palette": <address>}`). The gradient body is implemented and reserved; spliced library screens pin `variant: "solid"` so it cannot leak in.

## Spec

{{fields:icon,icon_color,token}}

`token_style_from_spec` returns `variant`, `fill`, `ring`, `ramp`, `film` (the colour status-film bodies take), `icon_color` and `art` (the glyph is full-bleed logo art). Screens are frozen: resolve the style once, not per frame.

`components.token_defaults(symbol)` ({{loc:pq1.components.token_defaults}}) is the one switch between the looks for a token a flow signs for: a symbol in `TOKEN_LOGOS` wears its logo art under a white explicit ring, on the ramp registered for that symbol in `colors.TOKEN_GRADIENTS` — the mono ramp when it has none; ETH / WETH wear the white ether mark on the mono body; any other symbol gets the solid placeholder hashed from the symbol.

## Identity becomes colour in one place

`components.token_ramp` ({{loc:pq1.components.token_ramp}}) resolves the ramp for the disc **and** the trail, so they cannot diverge. Order: `token.palette` → `token.address` → `token.symbol` → the screen's `icon` → the neutral grey ramp ({{val:pq1.colors.NEUTRAL_RAMP}}).

- A string key is hashed by `colors.placeholder_index` ({{loc:pq1.colors.placeholder_index}}): upper-case the string, CRC-32 (the zlib / IEEE polynomial) over its bytes, modulo the number of placeholder ramps ({{val:pq1.colors.MONO_RAMP}} + 1). An integer key wraps with the same modulo.
- Test vector: `0x3cA9e5F1b72D04E8a6c1D9B3f57E28a0C4d6B1e9` → hashed as `0X3CA9…B1E9` → CRC-32 760397135 → ramp 1. Letter case does not matter; the `0x` prefix is part of the hashed string.
- `address` outranks `symbol`: two tokens can share a ticker, never a contract.
- A `palette` that names a ramp in `colors.BRAND_GRADIENTS` is **pinned by name** and never hashed. The hash can only land on a placeholder ramp, so no unknown token can wear a brand, a popular token's colour or a device-action look.

**Security rule.** The gradient disc is reserved for unrecognized tokens and its ramp is hashed deterministically from the token's address — the same contract always wears the same gradient, on every device, on every run. It is not decoration, it is not a blind-signing mark, and a known token never uses it. There is no fixed "unknown" gradient.

## Geometry

| part | value |
|---|---|
| layout radius | {{tok:pq1.layout.CIRCLE_R}}, centre y {{val:pq1.layout.CIRCLE_CY}}; it never resizes between screens |
| visible edge | layout radius − {{tok:pq1.components.TOKEN_INSET}} px — body, ring, full-bleed art and every trail link share this radius |
| ring | {{tok:pq1.components.TOKEN_RING_W}} px, stroked **inward** from the visible edge |
| image glyph | a square of half-side 0.78 × r, centred |
| chain marks | each network's logo traced from its SVG, flattened once at import (`pq1/procedural/chains.py`); the half-extent is `MARK_SCALE × r` on the mark's dominant axis — wide marks (`op`, `zksync`) scale off width |
| monogram | the symbol's first letter, upper-case, font size 1.05 × r |
| gradient | linear, six evenly spaced stops, along the axis from (−0.8 r, −r) to (+0.8 r, +r) about the centre: dark top-left, bright bottom-right |

The gradient is rendered once per ramp as a master tile at radius {{val:pq1.components.R_MASTER}} and resized; radii are kept exact (no quantizing — the disc edge shows it).

## Layer order (bottom to top)

1. body disc at the visible edge — black first when `unknown`, then the gradient tile over it
2. the [hold flood](hold-flood.md) when its placement is `under` (white film in a black body)
3. the **default** white ring — **only** when `token.ring` is unset
4. the glyph, or two glyphs mid-morph — see [glyph morph](glyph-morph.md)
5. the hold flood when its placement is `over` (black film over colour or art) — up to the ring's inner edge, or out to the visible edge when full-bleed art carries no explicit ring
6. an **explicit** ring (`token.ring`), flush at the visible edge, over the art

Steps 3 and 6 are exclusive: a disc gets one ring, either the default white one under the glyph or the explicit one over it — never both. So full-bleed art covers the default ring, and an explicit ring is a deliberate stroke that survives on top of the art (the white stroke on USDC, the black stroke on SAFE).

Glyph lookup (`resolve_glyph`, {{loc:pq1.components.resolve_glyph}}): a named icon in `GLYPHS` → image logo, circle-masked → a vector mark for the symbol → the monogram. `components.glyph` falls back to the `eth` mark for an unregistered name — except a `letter:X` name, which draws that initial through the same monogram: an unknown CHAIN names its own network rather than borrowing the ether mark, which would name a different one (`letter:` is a namespace resolved at draw time, never a `GLYPHS` entry, so the published icon set cannot depend on render order). The disc is never empty. Marks are traced vector art (`pq1/procedural/`); logos are full-bleed PNGs in `pq1/assets/`. The one exception is `eth`: `eth-logo.png` recoloured to white when it is loaded (`image_glyph(..., recolor_white=True)`).

## Motion

The disc has no motion of its own. Position and radius ride the transit springs ([spring morph](../transitions/spring-morph.md)); on a hero it drifts on the [idle sweep](idle-sweep.md). Between two screens the glyph crossfades, but the **body, ring and trail colours cut** from the old screen's style to the new one when the mix passes one half — see [glyph morph](glyph-morph.md). The `alpha` argument fades the whole token toward black; `flow.Sim` uses it only to bring the disc in after a [token-less transit](../transitions/tokenless-fade.md).

## Preview

No clip of its own. See the disc at rest and in transit in [Hero — the ask](../screen-types/hero-ask.md) and [Detail](../screen-types/detail.md).

## Do / Don't

- **Do** port `token_ramp` and `placeholder_index` bit-exact, and the ramp tables in `pq1/colors.py` value for value. The colour is an identity check the user learns.
- **Do** hash the address when you have one. Hash the symbol only when there is no address.
- **Don't** use the gradient body for a known token, for a brand, or as a warning.
- **Don't** let a hashed key reach a named ramp. Only a flow's own `palette` string may pin one.
- **Know** that the hash space includes the mono ramp ({{val:pq1.colors.MONO_RAMP}}) and the neutral ramp ({{val:pq1.colors.NEUTRAL_RAMP}}). An address that lands on the mono ramp through `palette` gets the black body, white ring and grey trail — the same style dict as ETH. The reference does not exclude it. Settle this with the designer before shipping.

{{partial:port-notes}}
