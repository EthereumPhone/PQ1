# PQ1 — design definition

The canonical spec for the NV3007 wallet UI (428 × 142 landscape, pure black).
Every number here is mirrored by a constant in this package — `layout.py`,
`typography.py`, `colors.py`, `motion.py` — and the code is the source of
truth: if this file and a module ever disagree, fix this file. The
[README](README.md) maps the modules; this file defines the system.

## Canvas & rendering

- 428 × 142 UI pixels, pure black background, 12 px margins for resting
  elements. The corner chevrons' hint bob may cross the top margin by
  `CHEV_BOB_PX` (4); films (burst, flash, explosion) bleed to the panel edge.
- Coordinates are continuous and pixel-EDGE based: x 0 is the panel's left
  edge, a UI point maps to `x × SUP` with no half-pixel offset. So the mirror
  of a point about the centre line is 428 − x (the chevron slots 23.5 and
  404.5, the detail text centres 263 and 165), and the mirror of a pixel
  COLUMN is 427 − x (the columns 24 – 123 and 304 – 403). The right-hand
  anchors are derived from the left ones in `layout.py`, never typed. A 1×
  port that must round a .5 rounds both chevron slots toward the centre.
- Everything draws at 3× supersample and is LANCZOS-downscaled in
  `Canvas.out()`; all APIs take UI pixels.
- Alpha idiom: colours are scaled toward black, which is exact on the pure
  black background. The draw context is RGBA so components that need true
  compositing (pulse rings, the hold fill) get it.
- **The raster contract** (audit RAD-14): every stroke is a fractional UI
  width drawn at 3× as `round(w × 3)` supersampled pixels, stroked INWARD
  from its radius, then LANCZOS-downscaled to 428 × 142, then quantised to
  RGB565 by truncation (R and B `>> 3`, G `>> 2`), no dither — the pipeline
  the owner signs off on glass (`tools/panel/image_convert.py`). So
  `TOKEN_RING_W` (2.4) is 7 supersampled pixels, the PIN pill's 2.6 and the
  active PIN ring's 2.5 are 8, the hair stroke 2.0 is 6, and
  `TOKEN_INSET` (1.2) is 4. A port that renders at 1× must state its equivalent per
  stroke token and have it approved on the panel; it may not pick one
  silently.
- **Visibility floors**: nothing is drawn at or under
  `ALPHA_FLOOR` (0.0137), the panel's first visible alpha under
  truncation — every fade in the system vanishes on the same frame. A
  black film over ink already drawn (the transit dim, the handoff wash)
  starts at `FILM_FLOOR` (0.003); a hold fill's LEVEL uses
  `LEVEL_EPS` (0.003). Checker rule
  `A-FLOOR` forbids a bare floor.
- **Viewing distance: 30 cm.** The panel is read at 30 cm — a device held
  in the hand or sitting in front of a keyboard, not at arm's length. Every
  size judgement in this file assumes it. Measured on this glass (Aileron,
  cap height 0.69 em, 273 ppi) the scale stands: Label 16 px = 1.09 mm
  (12.4′), Question 18 px = 1.21 mm (13.9′), Default 22 px = 1.49 mm
  (17.1′), Mid 28 px = 1.86 mm (21.3′), Big 36 px = 2.39 mm (27.4′),
  Display 40 px = 2.64 mm (30.2′). The value tiers clear the ≈16′ usually
  quoted for comfortable sustained reading; the Label tier does not, and
  that is an accepted trade — it carries field names, the pager and the PIN
  hints, never a value the signer must verify. A port that targets another
  distance must restate these numbers, not assume them.
- The NV3007 driver handles rotation to the physical panel.

## Layout grid & anchors

| Anchor | Value |
|---|---|
| Main circle | diameter 60 (r 30), centre y 72 — never resizes |
| Idle / hero circle | centred x 214 |
| Idle sweep range | x 89 – 339 |
| Detail circle columns | x 24 – 123 (centre `COL_LEFT_CX` (74)) or x 304 – 403 (centre `COL_RIGHT_CX` (354)) — mirror images about x 214 |
| Detail text centre | x 263 (circle left) / x 165 (circle right), vertical centre y 72.5 |
| Detail text region | `TEXT_REGION_W` (294) × 77 px (x 116 – 410 or x 18 – 312, y 28 – 104); `TEXT_REGION_FULL_W` (404) on full-width screens. Derived, not chosen: the panel margin outside, one margin of air past the circle's ink inside |
| Bottom band | y 105 – 129, all band text baseline-aligned to y 128 |
| Chevron slots | (23.5, 19) and (404.5, 19), hidden on status screens |
| Confirm screen | composed like the chain screen: prompt + `CHAIN_GAP` (18) + disc as one group centred on x 214 (`layout.chain_compose`) — prompt centre `CONFIRM_TEXT_X` (175), disc `CONFIRM_CIRCLE_X` (297) |
| Confirm band | OR VIEW MORE ▸ text centred on `VIEW_MORE_CX` (206), ◂ TO GO BACK on its mirror `GO_BACK_CX` (222): each unit, text plus chevron, reads centred on x 214 |
| Value screen | text centred x 214 across the full 404 px region; no circle on the panel — the token parks off-canvas at x −60 (`layout.VALUE_PARK_X`) |
| Pager | `n/m` top centre — x 214, baseline y 24, in the **Label face** (`SIZE_LABEL` (16), SemiBold, +1 px) — a screen with pages, or a hero's position in a sequence of asks (`pager`) |
| Sign box | `VERDICT_BOX` (64) — a verdict sign inks its LARGEST dimension to it, centred on the circle grid, so every sign standing where the token would stands the same size. A disc ending (FIRMWARE VERIFIED's white disc, the headshake ring) is the token itself, not a sign — § Iconography |
| Strokes | `STROKE` — hair 2.0, ring 2.4, sign 4.5, heavy 5.4: the whole line-weight vocabulary, one name per weight. A width off this scale is a recorded decision named where it is drawn — § Iconography lists all seven |

## Typography

One family, six sizes on the scale (36 / 32 / 28 / 22 / 18 / 16) plus the 40
display digit, fixed roles, three faces. Aileron Regular for every value;
Aileron SemiBold for the label caps and every band-edge annotation (the pager
`n/m`, the PIN hints, a verdict's label), for a **name** line inside a value
(see Text rules, Names) and for the entry / display digits; Aileron Bold for
one glyph only — the monogram, a lone letter standing as a disc's whole
content. No italic, no other family, nothing below `SIZE_LABEL` (16) — a
1.0 mm cap height at the panel's 273 ppi. The scale is `typography.ROLES`,
which the handoff publishes as it stands (`screens.schema.json`, typography).

| Role | Size | Spec | Use |
|---|---|---|---|
| Big | 32–36 | Regular, leading = size | Short one-liners: "Unlimited", "on Mainnet" |
| Mid | 28 | Regular, leading 36 | One- or two-liners: "50 gwei / Tip: 1 gwei" |
| Default | 22 | Regular, leading 30 | Multi-line content: addresses, call data, hashes |
| Question | 18 | Caps, +0.5 px tracking | Idle / confirm prompt in the bottom band |
| Label | 16 | SemiBold caps, +1 px tracking (`WEIGHT_LABEL`, `LS_LABEL`) | Every band-edge annotation: the field name under the circle (SPENDER, MAX FEE), the pager `n/m`, the PIN hints, a verdict's label — one face, so they read alike (user decision, Sep 2026) |

The scale is a fitted set of tiers, not a modular ratio: each size is the
largest that holds its content class (§ Choosing the size), and 32 stays for
the one-liner 36 cannot hold. Beside the scale, three things are type in
another face or size, and one grid sets its own pitch:

| | Size | Spec | Where |
|---|---|---|---|
| Display digit | `SIZE_DISPLAY` (40) | SemiBold, one digit alone | the LAST ATTEMPT reel (`screens/verdict/last_attempt.py`) |
| Entry digit | 22 | SemiBold (`pin_slots.DIGIT_WEIGHT`) | the digit inside a PIN ring |
| Monogram | `MONOGRAM_SCALE` (1.34) × r — 40.2 at rest | Bold, upper-case | an unknown chain's or a long-tail token's initial on its disc; it shrinks with the disc in the seed film |
| Words grid | 22 | Regular on the grid's 26 px row pitch (`WORDS_ROWS`), not `line_height` | the seed-words grid (Text rules, Words) |

Leading is the stacking rule `line_height(size)` — size for 32/36, size + 8
below (28 → 36, 22 → 30).

**Font resolution** (`typography.font`): `$PQ1_FONT` override → the bundled
copy in `pq1/assets/` (Aileron-Regular/SemiBold/Bold.otf, so pq1 is self-contained)
→ system font directories → PIL's built-in default as a last resort. A warning is printed
once if the face that loads is not Aileron, so a missing font can never
silently restyle the UI.

### Choosing the size

Always use the largest tier whose content fits the detail region — and "fits"
is **measured, not counted**. `layout.fit_size` is the one rule: the largest
tier whose every line measures inside the region **in the face it will be
drawn in**. `normalize_screens` calls it for any screen that does not pin a
`size`, `sig_error` fits its variable text with it, and the checker's
`T-WIDTH` fails a line that would clip.

A character count is not a width: 21 "D"s measure 327.6 px at 22 — well past
the region — while 21 "l"s measure 132.2.

| Tier | Typical characters per line | Max lines | Typical, full-width |
|---|---|---|---|
| 36 | 14 | 1 | 19 |
| 32 | 15 | 1 | 21 |
| 28 | 18 | 2 | 24 |
| 22 | 23 | 3 (the third line overflows into the text band — info screens only) | 31 |

**The character columns are authoring guidance, not the rule** — they are
`region / digit advance`, and a digit is narrower than a capital. Nothing
checks against them; `T-WIDTH` checks the measure.

Fits at 36? Use 36. Otherwise try 32, then 28 (up to 2 lines), then 22 (up to
3 lines). If it still does not fit, split the content across two screens — or,
when it is ONE value that must stay whole (a 32-byte hash), page it within its
screen (Text rules, Pages) — never shrink below 22, never truncate, never
ellipsize. A transition row is fitted on the whole row (Text rules,
Transitions); a paged value on its widest page, at one size for the screen.

A typed `size` is a **pin**: the author's judgement, and the fit rule does not
override it. The checker reports a pin below the measured tier as `T-FIT`
(info — a note, never a failure).

### Text rules

- **Baseline, not centering.** Any text in the bottom band is
  baseline-aligned to y 128 — never vertically centered in the band.
- **Addresses and hashes.** Default tier, broken into centred lines of
  typically 21 characters — the measure decides, not the count: a
  capital-heavy half can exceed the region where a digit-heavy one of the
  same length sits well inside it. Split mid-string, no ellipsis — the full
  value must be verifiable on screen. The companion app shows the same
  address broken at the same positions and in the same checksum case, so the
  two match glyph for glyph; the panel is read at 30 cm (§ Canvas),
  where the Default tier's caps stand ≈1.49 mm (Aileron cap height 0.69 em
  at 273 ppi).
- **Pages.** A value that overflows its tier's three lines yet must be read
  in full — a 32-byte hash, 66 characters — stays ONE value on ONE screen
  and turns pages: `pages` in the screen dict, two or more pages of 1–3
  lines at the screen's one `size`, the pager `n/m` (Layout grid, Pager)
  top centre only then. A hash pages on byte lines: page 1 `0x` + 8 bytes /
  8 bytes, page 2 8 / 8 bytes, at 22
  (`flows/eip1271/personal_counterfactual_hash.py`, and the two-page
  safeTxHash of `flows/safe/clear_sign.py`). Never two screens for one
  value, never an ellipsis where the value must be verified. The page turn
  is the swap of § Motion, Page flip; a tap turns the page before it moves
  the screen (§ Input).
- **The two sanctioned shortenings.** Exactly two values shorten, both
  around a single `…` — a real Aileron glyph, never three ASCII periods:
  the **DATA HASH** of a blind call, first 12 and last 12 characters at 28
  (`flows/blind/unknown_call.py`), because that hash is a fingerprint to
  match against the dapp, not a value to read; and a **resolved
  recipient**, the address's first 8 and last 8 under its SemiBold name at
  22 (`flows/send_token_named.py`), where the name is the identity and the
  short address its fingerprint — keep the full-address twin
  (`flows/send_token.py`) for when the address must be read in full. Every
  other value is shown whole: split it mid-string, page it, or move it to
  its own screen. A hash a signer is asked to verify — a safeTxHash, a
  message digest, a calldata hash under its own label — is never one of
  these two (`F-ELLIPSIS`).
- **Names.** A resolved identity inside a value — the contract's, the
  recipient's, the spender's name the device knows — rides **SemiBold** on
  its line; the address (or fingerprint) lines under it stay Regular. One
  tier for the whole screen ("USD Coin" SemiBold over the two 22 px
  address halves). The heavier face is the hierarchy: the name identifies,
  the address confirms. In a screen dict a line is a str, or
  `{"str": …, "weight": "semibold"}` (`layout.line_str` / `line_weight`).
  SemiBold runs ~3 % wider than Regular — measure a name near the tier
  budget with `typography.text_width(name, size, "semibold")`.
- **Transitions.** A value that becomes another — the slot a rotation
  retires and the slot taking over — sits on **one row**, the old value, a
  right-pointing system chevron, the new value: "Slot 3 ▸ Slot 4"
  (`components.transition_row`, the chevron centred `TRANSITION_GAP` × size
  past each value's edge). In a screen dict the line is
  `{"transition": [old, new]}`. The tier is fit on the whole row — the two
  values plus one size of chevron space — and the pair counts as ONE
  primary value (`flows/rotate_slot.py`).
- **Numbers keep their unit** on the same line while the pair fits a
  one-line tier: "0.05 ETH", "50 gwei" (36 / 32). An amount + symbol pair
  too long for 32 breaks **once, after the number** — the amount on line 1,
  the symbol on line 2 ("min. 1,842.31" / "USDC" at 28; 22 when the amount
  alone passes 16 characters) — never inside the number, never symbol
  first. A number never breaks. A token the device cannot resolve shows
  its contract address instead (address mode): the address alone, the
  address treatment above — two measured lines at 22.
- **Case.** Labels and questions are caps. Detail values are rendered
  exactly as supplied — never re-case, re-punctuate, or reformat a value
  coming from the transaction. A message the DEVICE writes — a verdict's
  or a warning detail's value lines — is sentence case: no shouting, no
  abbreviation ("Signature" / "verify failed", "Can not decode data");
  its label names the check in caps (SIG CHECK).
- **The big detail text is variable — on every screen.** A value line is
  transaction data filled on the device: the ask's symbol, a spender, an
  allowance ("Unlimited" or a capped amount), a contract's name and
  address, the fee figures — every one. A flow fixes the screen's
  structure — order, id, label, side — and the tier rule, never a value.
  Samples in a flow module are placeholders that exercise the tier rule,
  not content.
- **Alignment.** Detail text is centred in its region. Labels are centred on
  their column. Notice text in the top band aligns away from its chevron
  (left slot → left-aligned, right slot → right-aligned).
- **Words.** A fingerprint read as words — the firmware signing key's —
  sits on the seed-words grid of the design canvas
  (`reference/device/pq1_seed_words.py`): two columns of four, numbered 1–4 down the
  left and 5–8 down the right, rows on centre lines y 32 / 58 / 84 / 110;
  each number 50 % grey and right-aligned (x 88 / 272) so digits line up,
  its word white and left-aligned beside it (x 98 / 282); words and
  numbers at one size, the Default tier (22 px, Regular — a step up from
  the design's 16, user request Sep 2026); up to eight words on one
  screen, no tier fitting, no caption. In a screen dict it is a value
  screen's `words` (`layout.WORDS_*`) (`flows/firmware`).
- **Hierarchy.** One value at the largest tier, one label, nothing else. If
  a screen needs two values at equal weight, it is two screens.

## Color

Solid colors are the primary language. Color = state, never decoration:

| Color | RGB | State |
|---|---|---|
| Yellow `#DCC419` | 220, 196, 25 | awaiting input |
| Green `#2EE56A` | 46, 229, 106 | done / success |
| Red `#FF423D` | 255, 66, 61 | failed / canceled |
| Orange `#F5A033` | 245, 160, 51 | warning |
| White | 255, 255, 255 | firmware / neutral |
| 70 % white | `INK_SECONDARY` (0.7) | secondary ink — the PIN idle ring, not text |
| 80 % white | `INK_PAGING` (0.8) | paging: the `n/m` pager, the PIN hint labels |
| 50 % white | `INK_MUTED` (0.5) | the seed-word numbers |
| pulse peak | `PULSE_PEAK_ALPHA` (0.4) | the pulse ring's peak, true alpha, decaying to 0 |
| flash peak | `FLASH_ALPHA` (0.85) | the resolve flash ring's first frame, the minor burst's rings; fades toward black |
| hold film | `HOLD_OVERLAY_ALPHA` (0.3) | the hold fill's see-through liquid (Input) |

Prefer the semantic aliases in `colors.STATE` (`awaiting` / `done` /
`failed` / `warning`) so intent stays readable in screen code. Status
screens take their ring / result-glyph colour from their `state` field
(default `done`), so GREEN and RED are wired to real outcomes. A status
screen may brand its ending with a `resting` override (fill / ring / glyph
colours, ring stroked flush at the disc edge; `status.branded_resting`
builds it: `branded_resting(fill, mark)`, the mark defaulting to black) — the
SAFE SIGNED ending resolves into the brand look: `#13FF7F` disc, black
stroke, black check; COWSWAP SIGNED into `#65D9FF` disc, black stroke, navy
check (`colors.COWSWAP_DARK`, the cow head's own colour). The stroke is
black on every branded ending; the mark colours the glyph only.

**Pulse rings are a state, not a dress.** The rings a screen's `pulse`
field throws around the token (`components.pulse`) report what the device
**knows** about the transaction, not which asset it is — so they take a
`colors.STATE` colour and never the token's own fill. `pulse: True` is the
warning tier; a STATE key names another, and nothing else is accepted. The
one live use is the screen that admits the device cannot read the call data
(`flows/safe/can_not_decode` BLIND SIGN): ORANGE rings around the Safe disc,
so the caution is never mistaken for the brand's SIGNED green.

**The ending disc splits on branding.** A brand flow family (SAFE and
CowSwap; any future family) **fills the circle**: its endings rest on
`status.branded_resting` — SIGNED on the brand fill, DECLINED on the
failed-red version of the same look — the disc **filled `#FF423D`**,
black stroke flush at the disc edge, **black X**
(`status.branded_resting(colors.RED)`) — the **one cancel circle every
family shares**; a family's own mark colour (CoW Swap navy) dresses
SIGNED only. **The resolve flash follows the disc**: the ring that pulses
out as the result lands takes a branded ending's own fill (Safe green,
CoW blue, the cancel red — `status.style_of`) and the state colour on an
unbranded ending — never the state green over a brand disc. An unbranded flow never fills:
**no fill / black disc**, red or green as the ring **stroke**, and the
check / X in that same stroke colour (the default resting look). Same
law, two dresses: branding fills the disc, absence of branding strokes
it. The film splits on outcome instead: a done ending plays the qubit
film; a cancel ending plays **no film** — it resolves in place (see
Components § Status animations). The hold fill (§ Input) is one see-through
liquid whose shade follows the body it rises in: black over a coloured disc
(brand art, placeholder ramps), white inside a black
body (the ETH mono token) — never a paint that hides the glyph.

**An unknown token is solid, and says so in words.** A token the device
does **not** recognize wears a **solid** disc — the same treatment every
other art-less token gets. Its hue is one of the placeholder ramps below,
resolved deterministically from the token's identity by
`components.token_ramp` (`palette` → `address` → `symbol` → the screen's
`icon` → the neutral grey ramp; crc32-hashed and case-folded — except a
`palette` naming a brand ramp, which is pinned by name, never hashed; see
Brand ramps), so the same unknown token always wears the same colour, and
the same ramp supplies its five follower colours. `address` outranks
`symbol` because two tokens can share a ticker but never a contract. A
token with a symbol wears its **initial** on the disc (the Bold monogram,
`letter:<X>` — `components.token_defaults`; user rule, Sep 2026); one known
only by its address carries the ether mark, the honest answer for art the
device cannot resolve (see § Screen schema, Glyph resolution). The colour is an identity
check, never the warning: what the device does not know is stated in text —
`TRANSFER UNKNOWN TOKEN?`, `(RAW)`, the bare contract address.

**The gradient disc is reserved, not live.** `components.unknown_disc` and
`variant: "unknown"` still exist in the renderer, but no flow and no
library screen asks for them: across every normalised flow screen and every
`screens/` SPEC, nothing resolves to anything but `"solid"`. A firmware port
must **not** implement a gradient disc (audit A11-12, Sep 2026).

**Placeholder palettes (known token, no image).** A recognized token that
has no logo asset stays solid and takes one of the six-stop ramps in
`colors.PLACEHOLDER_GRADIENTS`. Reading a ramp top → bottom, the **last**
stop is the token circle, the 5th stop is the first follower (nearest the
token), the 4th the second … the 1st stop is the farthest follower — so the
trail darkens away from the token. `colors.placeholder_palette(key)` returns
`(fill, trail)`; `key` is a ramp index or the token symbol (hashed stably, so
a symbol always lands on the same ramp) — but to reproduce a SCREEN's
resolved colours use `colors.ramp_palette(components.token_ramp(spec))`,
which also reads brand names. Screens opt in with
`token={"palette": …}` (implies `variant="solid"`); an explicit `fill` still
wins.

**The fill stop has a floor.** Every placeholder disc carries the system's
white ring and a white mark, so its fill stop is chosen against them, not
freely: `PLACEHOLDER_MIN_CONTRAST` (4.5) against WHITE, the AA bar, because
the mark on that disc is read as a glyph. Ramps 0, 2, 5, 7, 8, 9 and 12 were
darkened to exactly this floor and the tightest sits 0.006 above it, so the
rule `C-CONTRAST` measures every ramp on every build — the floor was prose
until Sep 2026 and one "darken it a touch" edit could have crossed it
silently (audit A11-05). The same rule guards the ink tiers against the
black panel and every mark against its disc once the hold film has risen
over it. A chain's brand colour is NOT held to this: a chain mark is a logo,
and `F-MARKCONTRAST` holds it to the 3:1 a meaningful graphic needs — mainnet
(3.69), OP (3.97) and Avalanche (3.99) sit between the two floors by design,
and must not be "corrected" toward AA.

**Brand ramps (context-pinned identity).** `colors.BRAND_GRADIENTS` holds
six-stop ramps keyed by NAME (`"SAFE"`: trail `#354E40 → #20DD77` far → near,
fill `#13FF7F`; `"COWSWAP"`: trail `#021E34 → #3FC4FF`, fill `#65D9FF` — the
official blue primary palette, its mark `COWSWAP_DARK` `#012F7A`). A brand's
ramp and logo are the brand's own assets — the user's files or the official
public ones — never guessed. They live outside the hash space — `placeholder_index` can
never land on one — and render only when a flow pins one explicitly with
`token={"palette": "SAFE"}` (case-folded), so the SAFE gradient appears
exactly when a SAFE transaction is on screen. A resolved ramp key
(`components.token_ramp`) is therefore a placeholder index **or** a brand
name; read it with `colors.ramp_gradient` / `ramp_palette` / `ramp_stops`.
The SAFE token pairs its ramp with full-bleed logo art and an explicit black
`ring` — an explicit ring is a deliberate stroke, drawn OVER logo art and
flush at the disc edge, stroking inward (`components.token`), and it rides
the glyph through the status handoff so it never pops.

**Chain ramps (the network's own identity).** `colors.CHAIN_COLORS` pins one
ramp per supported network, keyed `CHAIN:<NAME>`, and a chain screen's disc
fills with it while the trail takes the ramp — derived from `chain=<id>`, never
written by a flow. The `CHAIN:` prefix is a safety property, not a style: `OP`,
`BNB`, `BASE` and `SCROLL` are also real token tickers, and `token_ramp`
resolves ANY palette string that matches a brand key, so a bare `"OP"` would
make the OP *token's* disc wear the Optimism *chain's* colours with no change
at that call site. The mark colour is not a per-chain taste decision either: it
is WHITE, or BLACK once `colors.luma` says the fill is light enough to swallow
it — and that is not a chain speciality but the disc-wide rule every disc
obeys, `colors.mark_color` (§ Iconography), of which
`CHAIN_DARK_MARK_LUMA` is only this section's alias. Not every brand is a
filled disc, though, and the registry names the exceptions
rather than pretending otherwise: `colors.CHAIN_DISC_FILL` pins the disc for a
chain whose body is not simply the last stop of its ramp, and the ramp stays the
network's bright accent for the trail. **Splitting the disc from the ramp is
what keeps a dark brand legible in motion** — ramping from the dark colour
instead fades the far followers into the black panel, and it darkens stop 6,
which does not paint the disc at all but is the status film's body colour, the
black-on-black qubit trap `ROTATE_GRADIENT` documents. Two shapes use it:
black-brand networks (Mantle, Linea) take the `ROTATE` treatment, and a network
that reads as a mark ON WHITE (Base) fills WHITE — the `FINGERPRINT` /
`FIRMWARE` shape per chain — under the ordinary white ring, which on a white body
reads as no stroke at all, because the mark is the brand and the disc is the
paper behind it. **Only pin a disc that cannot come from the ramp**: a merely
dark brand darkens its ramp instead, because pinning a dark disc over a bright
ramp puts the nearest follower ABOVE the token in luminance and inverts the
trail law, which darkens away from the disc everywhere else. A pale brand body
needs no pin at all — zkSync simply ramps FROM its body (`#D7E2F5`), so the disc
is stop 6 and the trail darkens circle by circle away from it. The mark then
follows the same luma rule as everywhere else,
read off the disc's ACTUAL fill; the pinned exceptions are in
`CHAIN_MARK_COLORS`, where luma is too coarse — Base's identity is specifically
the BLUE square, zkSync's the deep navy `#051A6A` on its own pale blue, and
luma would knock both out flat black (user rule, Sep 2026).

**The mono entry (recognized token with a logo).** The last ramp,
`colors.MONO_RAMP`, is the treatment for a recognized token that shows its
own logo: black body, white ring, white glyph, grey trail (its palette fill
is overridden to black; status-film bodies take the ramp's brightest stop
so they never render black-on-black). **It is outside the hash space**:
`placeholder_index` hashes a symbol, a name or an address over the 13 ramps
BELOW it, so no unrecognized token can land on the recognized-token look —
a hashed hit there would draw a stranger exactly as the device draws ether,
on the screen where the disc is part of what the user checks. An int still
wraps over every ramp, so `token={"palette": colors.MONO_RAMP}` remains the
one way in, and it is the only way the checker (`C-RAMP`) allows. The SEND flow pins ETH to it; WETH, ether's ERC-20 wrapper, wears the same
mark (`components.ETHER_SYMBOLS`). Popular tokens with a logo asset
(`components.TOKEN_LOGOS`: USDC, USDT, DAI → `pq1/assets/<stem>.png`,
registered by `components.register_logo`) wear the art full-bleed under a
**white edge stroke** — the explicit `ring`, flush at the disc edge and
drawn over the art, so every token circle keeps the system's white ring
(the mono body's default ring made explicit; user rule, Sep 2026) — the
hold film rises over the art as black, up to the ring, on a trail in the
**token's own colour** (see Token ramps). **The art fills the token's
visible disc**, `r − TOKEN_INSET` — the solid disc's and the trail circles'
exact radius — never the layout radius: the top circle is the same size as
the circles in its trail (user rule, Sep 2026; `components.resolve_glyph`). `components.token_defaults(symbol)`
is the one switch point: logo art on its own ramp for a listed symbol, the
ether mark on the mono body for ETH / WETH, otherwise the symbol's
**initial** (the Bold monogram, `letter:<X>`) on the placeholder ramp hashed
from the symbol — a long-tail token names itself, never borrowing the ether
mark (user rule, Sep 2026). One flow serves every token on device. A screen
that stands for the session rather than the token keeps the ether mark by
naming it: the BATCH screen (`flows/batch.batch_hero`, `icon="eth"`). A flow with
one fixed sample uses a long-tail symbol so the module shows the placeholder
look; a flow that declares `SAMPLES` cycles the popular tokens through its
example renders (`flows/__init__.py`: one sample per variant slot), so the
example set shows every logo on its coloured trail — production is untouched.

**Token ramps (a logo's own colour).** `colors.TOKEN_GRADIENTS` holds a
six-stop ramp per popular token, keyed by SYMBOL and derived by
`colors.ramp_from` from the dominant colour of the token's own logo asset
(`colors.TOKEN_COLORS`: USDC `#2775CA`, USDT `#50AF95`, DAI `#F5AC37` —
sampled from `pq1/assets/<stem>.png`, never guessed): the token colour is
the fill under the art, the five followers scale it toward black
(`RAMP_STEPS` 0.86 → 0.15) so the trail darkens away like every ramp. They
share the named-ramp registry with the brands (`BRAND_GRADIENTS` includes
them), so `token_ramp` pins them by name, outside the hash space;
`token_defaults` sets `palette=SYMBOL` for a listed logo that has a ramp
and falls back to the mono trail for one that has none.

## Motion

Shared vocabulary in `motion.py`; screen-to-screen choreography lives in
each flow's driver (`pq1.flow.Sim` or a flow's transitions module).

- **Springs drive transitions.** Circle travel, the glyph/chevron morph
  and per-screen text alphas are `motion.Spring` values — Apple's
  parameterization (`response` seconds, `damping` ratio). Springs animate
  from the live pose and carry velocity, so a press during a transition
  retargets it mid-flight (§ Input: presses are never dropped). Profiles:
  `NAV` (response 0.40 — hardware button pace; the bench player's
  `pq1/driver.py` profile) and `KIOSK` (response 0.55 — demo loops; the
  `Sim` default). The per-screen text alpha
  crossfade runs on the same profile as the circle, so incoming text
  fades in over the travel and lands with the circle rather than
  popping in ahead of it. A landed spring (within 1e-3 of its target, at
  rest) snaps exactly onto it and sleeps — zero cost per frame until the
  next retarget.
- **Damping is 1.0 everywhere.** Two buttons carry no momentum, so
  navigation never overshoots. One overshoot is sanctioned — the status
  flash pop (`back_out`), a celebration, never navigation. The verdict
  icon entrance never overshoots: it fades in and rises 0.97 → 1
  (`motion.arrive`), both ease-out, within `ARRIVE_MS` (300 ms) — `pop`
  stays an opt-in accent, never an entrance (user rule, Sep 2026).
- **Accent curves** (`motion.py` § accent curves) are the named one-shot
  vocabulary for verdict/notice screens: `arrive`, `pop`, `attention_pulse`,
  `heartbeat`, `shake`, `wobble`, `recoil`, `freewheel`, `decel`. Screens
  use these names — never a hand-rolled formula. Every one-shot accent
  phase (ring stagger, click, bounce) spans at least
  `VERDICT_ACCENT_MIN_MS` (145 ms) — two panel frames at 14 fps, so the
  beat survives on the device. The floor holds for every timing token, not
  only accents: checker rule `M-ACCENT` scans the screens' `T_*` phases and
  every `*_MS` in `motion.py` / `status.py` (the press nudge, the result
  caption's lag, the resolve flash's fade-in are all 145), exempting only
  the gesture windows.
- **The panel grid.** The NV3007 draws `PANEL_FPS` (14) frames a second,
  one frame every ≈ 71.4 ms — `FRAME_MS`. A repeating period that plays on the
  device is a whole number of panel frames, so a loop never drifts through
  its phases (the chevron hint's 3571 ms = 50 frames; the sweep and the
  band's 5000 = 70). Known exceptions, left on purpose: the orbit turn
  `TURN_MS` 850 (periodic in pose time — the frame grid only samples it),
  the demo's page-turn clock, and the busy caption's fitted breath.
- **Duration never scales with distance or size.** Every travel on the
  device, whatever its length, is the `NAV` spring; its length is derived
  from the spring (`motion.settle_ms`), never typed — the explosion's side
  entrance included (`burst.ENTER_MS`, ~582 ms over its 274 px trip).
- **Every curve has ONE purpose** — the role picks the curve, not taste.
  Nothing on this panel ever eases in from black: an in-out curve is for
  motion BETWEEN two rests, never for an appearance.

  | the motion | the curve |
  | --- | --- |
  | **appear** — any alpha rising from 0: a mark, a caption, a page, the band, a hint, the PIN row, the film seed, the film's RESULT | `ease_out` |
  | **leave** — any scripted alpha falling to 0 | `1 - ease_out` |
  | **change in place** — position, angle, radius, colour or fill on something already on screen | `ease` |
  | **navigate** — screen to screen | the `Spring`, damping 1.0 (never a curve) |
  | **progress / physics** — the hold fill, ring alpha, the dress fade | `linear`, by law |
  | **ambient** — the idle sweep, the follower chain | `motion.tau_chase` |
  | **accent on an arrived sign** | the accent curves (`shake`, `recoil`, `decel`, …) |
  | **the one overshoot** | `back_out`, the status flash pop |

  At 14 fps the difference is the whole point: over 300 ms an appearance on
  `ease_out` carries 56 % of its ink on the first panel frame, the same fade
  on `ease` carries 5 %. Checker rule `M-ROLE` holds the first and third
  rows — a bare `ease()` result never becomes an alpha (user rule, Sep 2026:
  the PIN rows, the page flip and the film's result landing had each drifted
  before the rule was written down).
- **Transition anatomy**: everything moves at once — outgoing text fades
  while the circle travels and the incoming text arrives. A KIOSK leg
  settles in ~700 ms, NAV in ~500 ms; `MOVE_MS + 2*FADE_MS` (1260 ms)
  survives only as the span bound harnesses render into. A film entrance
  is sequential (fade, hold, seed — below); every other leg overlaps and
  settles when its VISIBLE springs do: into a token-less screen (a
  verdict, a PIN row) nothing rides the incoming alpha, so it is released
  at once instead of `TEXT_IN_DELAY_MS` late, and the verdict's clock is
  never held back behind an invisible spring.
- **Entering a loading film is the exception — it is SEQUENTIAL** (user
  rule, Sep 2026). There is no spring leg into a film. The screen goes
  out first: text, chevrons and follower trail fade over `FADE_MS`
  (180 ms) with the circle PARKED where it stands and a committed hold
  fill draining with them. The bare circle then HOLDS alone on black for
  `SEED_HOLD_MS` (180 ms; user rule, Sep 2026 — fade, hold, morph). Then
  the film takes the canvas and does the travelling itself — the circle it was handed travels to the film's
  centre, shrinks from the token's VISIBLE radius to `r_q` and tints
  into the film's colour over `SEED_MS` (300 ms), all on `ease_out`,
  its ring and its art fading out over the first half of that window
  (`motion.SEED_ART`, linear time so the fade survives two panel
  frames). A BARE qubit lands on the frame the split begins: the seed
  IS a qubit, and it divides into its identical twin. The seed replaces
  the film's old 250 ms hold — a film is never handed a cold canvas; the
  hold before it is the flow's, so the film's own timing is unchanged.
  `flow.Sim` marks the beat and calls `StatusAnim.enter_from`; the film
  owns the morph (`loading.qubit_pose`), so a standalone render seeds
  in place at `gc` and the page flip's sequential law now has company.
- **Dwell**: hero 5000 ms (one full sweep), detail 4100 ms — per page on a
  paged detail; a status screen
  dwells for its animation's duration — loading + resolve + the result's
  landing + a 2450 ms result hold (qubit 9095 ms; the film-less cancel
  resolve 3295 ms). Dwell counts from spring settle.
- **The result lands like every caption.** On the two core endings the
  check / X fades in over `RESULT_FADE_MS` (300) on `ease_out` from
  `t_resolve`, the caption `RESULT_LAG_MS` (145) behind it on the same
  curve; the result hold then counts from `t_landed` — the result fully
  visible — so every ending rests on its whole result for the same 2450 ms.
- **Hold fill (demo loops)**: the demo performs the hold gesture through
  the last 2000 ms (`HOLD_COMMIT_MS`) of a commit screen's dwell before an
  ending — hold-right into a done ending, hold-left into a cancel — the
  disc full on the frame the screen advances (`motion.hold_full`). It lives inside the dwell, so
  durations are unchanged (§ Input: the hold fill).
- **Idle sweep** (hero screens by default): centred hold 1000 ms, then a
  5000 ms left-right cycle, amplitude 95 px, the circle chasing the target
  with τ 180 ms. The sweep stays inside x 89 – 339.
- **Follower chain**: 5 links trailing the head, per-link easing τ 60 ms
  (150 ms during the idle sweep, for more separation), consecutive links
  capped at 30 px apart.
- **Chevron hint** (hero screens): starts `CHEV_HINT_START_MS` (1429) into
  the idle and repeats every `CHEV_HINT_PERIOD_MS` (3571) —
  `CHEV_HINT_TURN_MS` (357) rotate up on `ease_out`, `CHEV_HINT_BOB_MS`
  (1214) bob (−4 px sine), the same span back; all on whole panel frames
  (20 / 50 / 5 / 17). The envelope is `motion.hint_env`, the one every
  in-place hint uses (the band's slot, the busy caption, the PIN hints);
  a sequential swap is `motion.seq_swap` (the page flip, the PIN row's
  caption swap).
- **Confirm band alternation** (confirm screens): once settled, the
  band shows **OR VIEW MORE** with a right-pointing chevron, and **every
  5 s** it fades away and **◂ TO GO BACK** fades in (then back — a
  sequential 300 ms swap, `motion.confirm_band`). The corner chevrons
  rest in the **up** (hold-armed) pose there and point — the hero bob —
  on the same 5 s beat (`motion.chevron_hint` at `BAND_SWAP_MS`).
- **Page flip** (paged details — Text rules, Pages): each page holds one
  detail dwell (`PAGE_SWAP_MS`, 4100 ms). 300 ms before its slot ends the
  showing page fades away on `ease_out`, THEN the next page fades in over
  300 ms on `ease_out` (`PAGE_FADE_MS`; `motion.page_flip`) — a sequential swap
  on the confirm band's rhythm, never a crossfade; the pager's number
  switches between the two phases. The first page arrives with the screen
  (the transition's own text alpha) and the last leaves with it. On the
  bench a tap starts the same swap.
- **There is no reduced-motion mode, by design** (audit A11-04, Sep 2026).
  PQ1 has no settings surface — no settings flow, no settings screen, no
  companion switch — so there is nowhere for a calm profile to live, and a
  port must not invent one. The decision is defensible on this glass and is
  recorded with its measurement: the panel is 40 × 13 mm, the largest
  repeating excursion is the idle sweep at ±95 px (±8.8 mm) over 5000 ms,
  and the shakes are ±7 px (0.65 mm). Rendering every library screen at
  `PANEL_FPS` and measuring mean frame luminance, **no film exceeds 0.07 of
  full white at its peak, and no frame-to-frame step exceeds 0.025** — the
  brightest moment in the system is `verdict/firmware_verified` (peak 0.061,
  step 0.024) and the explosion is thin rings on black (peak 0.045). That is
  far under any photosensitivity threshold, and no excursion is large enough
  on a 13 mm-tall panel to carry a vestibular one. If a settings surface is
  ever added, this bullet is the thing to revisit — not the films.

## Flow shape

- **The mid-flow Confirm? screen.** A flow with **7 or more detail
  screens** takes a `confirm`-kind screen as its **6th screen** — an
  early exit ahead of the remaining details. "Confirm?" sits big in the
  detail region (Big tier, mixed case), the token circle docks right of
  centre (composed like the chain screen: prompt centre x 175, disc x
  297, the chain screen's 18 px of air between them), and the
  bottom band alternates **OR VIEW MORE ▸** (right-tap: the remaining
  details) with **◂ TO GO BACK** (left-tap), fading between them every
  5 s. The corner chevrons rest in the up (hold-armed) pose and bob on
  the same beat — the standing reminder that hold-right signs here.
- **Grammar on this screen**: hold-right sign is armed (`commit`
  defaults True); right-tap continues into the remaining details — that
  is what OR VIEW MORE ▸ promises — and left-tap regresses, as ◂ TO GO
  BACK says. The standard mapping, never flipped.
- **Confirming here dispatches.** The early exit is a real commit point:
  hold-right jumps the flow straight to its **status sequence** — the
  loading film resolving to the flow's success ending (or the declined /
  failed ending) — and the remaining details are skipped. Hold-left
  declines → DECLINED, as on every navigable screen. The remaining
  details exist for verification, not as a toll on signing. Demo loops
  keep the linear pass (the VIEW MORE path);
  `python -m flows <name> --early [--end …]` renders the early-exit
  pass — the confirm screen's `next` pinned to the ending, the hold fill
  rising on Confirm? before it.
- **The full walkthrough returns to idle, then resolves.** After the
  last detail the flow comes back to the idle hero — every detail seen,
  the ask again — the returning ask performs the hold (right for the
  success ending, left for a cancel `--end`), and then the ending plays:
  the loading film resolving to success, or the cancellation ending via
  `--end`. `--early` renders
  the commit path instead (Confirm? jumps straight to the ending; the
  flow's `DEFAULT_END` when no `--end` is given). Every flow's ending
  renders land in a folder per flow, split `success/` vs `cancel/`
  (ending state `done` vs `failed`), named `<flow>_<full|early>_<end>`.
- **Automatic, and the placement is canonical**: `flows.screens()`
  enforces the shape via `layout.insert_confirm` (`CONFIRM_MIN_DETAILS`
  7, `CONFIRM_INDEX` 5). The confirm screen is **always the 6th screen**
  of a 7+-detail flow — inserted there when absent; a flow that places a
  confirm-kind screen anywhere else (or doubles it) is rejected at build
  time. The inserted screen inherits the flow's `DEFAULTS` (icon, token),
  so the circle wears the flow's own logo — SAFE flows get the Safe disc,
  the SEND flow would get ETH.
- **Confirm? is counted per segment.** A segment is one run of screens up
  to a status screen. An ordinary flow is a single segment starting at
  screen 0, so the rule above reads unchanged. A flow that resolves more
  than once — a batch signing a transaction per segment (`flows/batch`) —
  takes the threshold against each segment's OWN detail count, never the
  total, so a 6-detail transaction gets no Confirm? however many
  transactions follow it (`layout._segments`).
- **The chain screen follows TO / AMOUNT.** A chain context screen
  (canonical id `CHAIN` — `on Base`, Big tier, self-composing)
  sits **directly after** the `TO` or `AMOUNT` detail it contextualizes —
  the chain qualifies the address or value just shown, never floats
  elsewhere. Enforced with the flow-shape checks.
- **One id, one identity.** A chain screen states its network as a numeric
  EIP-155 chain id and nothing else — `chain=8453`. The mark, the disc
  fill, the trail ramp and the caption are all derived from that one number
  (`pq1/chains.py`, expanded in `layout.normalize_screens`), and the
  caption and the disc compose as ONE centred group with `CHAIN_GAP` of air
  between them, so the spacing never changes with the length of the network's
  name and the disc is not pinned to a column. Writing the
  icon or the caption by hand is a rule violation (`tools/check` rule
  `F-CHAIN`), because two hand-typed fields can name two different
  networks, and on a signer the disc is part of what the user is checking
  (user rule, Sep 2026).
- **A chain screen wears the chain, not the flow.** The disc takes the
  network's own brand colour with the mark knocked out of it, over that
  chain's trail — pinned by name in `colors.CHAIN_COLORS` under a
  `CHAIN:` prefix, outside the hash space. The prefix is load-bearing:
  `OP`, `BNB`, `BASE` and `SCROLL` are also token tickers, and an
  un-namespaced ramp would silently repaint those *tokens*. A branded
  family's palette yields for that one screen and resumes on the next.
- **An unknown chain says which one it is.** A chain id the registry does
  not hold draws the **first letter of the chain's name** on its disc
  (`letter:<X>`, a glyph namespace, not a registry entry) on a solid ramp
  hashed from the chain id — deterministic, so the same network looks the
  same on every device. The circle does **not** leave the screen. This
  narrows the ether fallback rather than replacing it: the ether mark
  stays the honest answer for a mark the device cannot resolve, but naming Celo with Ethereum's mark would be a different network's
  identity, so a chain answers with a letter (user rule, Sep 2026).
- **Dwell**: 10 s in demo loops (`motion.CONFIRM_DWELL` — one full band
  cycle, so both messages play); on hardware it idles until input.

## Verdict screens

A **verdict** is a status-kind screen whose animation draws a procedural
icon instead of the resting token: the icon arrives on the circle grid
(cx 214, cy 72 — or the detail grid for detail verdicts like SIG ERROR),
the caption fades onto the y 128 baseline, then the screen rests.
Chevrons are hidden (no input), like every status screen.

When to use which: a **status** screen shows work the device is doing
resolving (the token loads — on the device for as long as the work
takes — then lands on the result) — signing, broadcasting. A **verdict** states a fact — LOCKED, BACKUP OK, WALLET
WIPED, RNG FAILED, LAST ATTEMPT. No loading: the icon *is* the message.

Anatomy and timing (`pq1/verdict.py`):

    T_HOLD 429 → T_IN 300 (icon: fade + motion.arrive) → T_WAIT 450 → T_TEXT 300
    t_resolve = the phase sum (1479 by default; mechanisms override T_WAIT)
    duration  = t_landed + RESULT_HOLD_MS — the same law as every
                status animation, so flows dwell correctly for free

`T_HOLD` is one of two values, both on whole panel frames so every
entrance starts on a frame and shows the same poses: `VERDICT_HOLD_MS`
(429, 6 frames) for every verdict, the lead handoff and the `arrive`
ending; `PIN_HOLD_MS` (286, 4 frames) for the PIN outcomes (a PIN
answers a keypress). A mechanism (the padlock's turn and click) runs in
`T_WAIT`, never in `T_IN`.

Rules:

- The icon colour comes from the screen's `state` (`colors.STATE`) or an
  explicit `color` naming a system constant — today only `colors.WHITE`, the
  firmware / neutral role worn by FIRMWARE VERIFIED and the factory signing
  gear. Never a local hex, and never a new per-context accent: the retired
  factory blue is why that rule is written down (audit COL-05).
- Icon art comes from `pq1/procedural/` — one module per image; the
  result/notice marks (check, x, exclamation) live in
  `pq1/procedural/marks.py`. Screens compose marks onto art; they never
  redraw them. A sign's SIZE is not the module's taste: every one derives
  it from `VERDICT_BOX` (see § Iconography), so a screen that wants a
  bigger icon is asking for a different box, not a local multiplier.
- **The sign box.** A verdict sign inks its largest resting dimension to
  `VERDICT_BOX` (64), centred on the circle grid — the notice triangle,
  the padlock, the gear, the die and the shield all measure the same
  across their widest reach, so the panel never reads one verdict as
  louder than another. Exempt: a verdict whose art IS the token disc
  (FIRMWARE VERIFIED, the headshake ring), the PIN pill, and LAST
  ATTEMPT, which the type tier composes. `tools/check` rule `V-BOX`
  measures every resting frame.
- **The optical centre**, defined: the resting frame's luminance-weighted
  ink centroid sits within 1.5 px of (`CENTER_X` (214), `CIRCLE_CY` (72))
  — the sign's own column on a detail verdict. Centre of MASS, not of
  bounding box: a shape that hangs its weight low reads low even when its
  box is centred. Rule `V-CENTRE` holds every sign and every registered
  mark to it; the written exceptions — the notice triangle family, the
  shield, LAST ATTEMPT, a letter, the sprung padlock — are in
  § Iconography with their reasons.
- **The entrance law** (user rule, Sep 2026): the icon fades in and rises
  from 0.97 to 1.0, both `ease_out`, within `motion.ARRIVE_MS` (300 ms) —
  `VerdictAnim.entrance` is the one source; never an overshoot, never
  longer. A mechanism (a shackle turning, a die tumbling, a gear
  coasting) plays on the arrived icon: its own window may run longer, the
  fade + rise inside it may not.
- The caption is `components.caption` — 18 px caps, baseline 128, fading
  in over 300 ms ease-out. One caption; a verdict that needs body text is
  a detail verdict on the detail grid.
- Concrete verdicts live in `screens/verdict/` and register their
  animation via `status.register`, so any flow can splice them as
  `dict(kind="status", anim=...)` (see the `screens` package docstring).
- **Leaving a token-less screen.** A verdict (and a PIN entry) owns its
  canvas — `StatusAnim.rests_on_token` is False — so there is no token
  for the flow to morph when it moves on. `Sim` then fades the screen's
  resting frame to black on the outgoing alpha spring (a fade, never a
  cut) and draws no token disc over the transit: into another token-less
  screen the transit is black until it starts, and that screen's
  `handoff` is dropped (nothing pops in at its t 0); into a screen that
  rests on the token (a hero, a detail, a film) the token fades in with
  the incoming text, so a film after a PIN opens on the disc it splits.
  **A result ending leaves the same way** (audit DUR-03): a signing's
  result (SIGNED 1 OF 3 before the next transaction) fades out on the
  outgoing spring while the next token fades in on the incoming one —
  the trust moment never leaves on a one-frame cut. Only the screens
  that rest on the token WITHOUT a result (the idle screens) keep the
  morph.
- **Lead films.** A verdict that follows destructive work may open on a
  film that ends on an empty canvas — the screen's `lead`
  (`status.LedAnim`): the lead plays first, the verdict starts when it
  resolves and its black `T_HOLD` runs under the lead's fading tail. ONE
  clearance places every led screen: its sign starts to fade in
  `lead_clear` ms after the lead's tail has cleared — by default
  `LEAD_CLEAR_MS` (−180: the sign rises as the blast clears; FIRMWARE
  UPDATED and UPDATE DECLINED alike), WALLET WIPED passing 700 so the
  blast is gone first. Durations add (one screen, one
  dwell). Only a film with `t_tail` set may lead (the explosion); one
  that rests on a look raises. The explosion's `enter` ("left" /
  "right") slides its circle in from off the panel (`VALUE_PARK_X`) on
  the device's NAV spring (`motion.spring_travel`; its length
  `burst.ENTER_MS` derived from the spring, ~582 ms), the
  follower trail riding in with it; `enter="sides"` flies the two qubits
  in from both edges straight onto the orbit — laid out as a spiral and
  travelled by arc length at a speed that only falls onto the orbit's,
  so they never stop and restart (`burst.SIDES_*`). The reference is
  WALLET WIPED, `wipe` preset `wallet_wiped_explosion`: red qubits from
  both sides (red from the first frame — body, trail, clump and rings),
  the busy caption alternating `WIPING…` / `DO NOT POWER OFF` from the
  orbit until the blast (a `busy` LIST alternates its lines in slots of
  at least `status.BUSY_SWAP_MS` 2000, fading out then in like the confirm
  band; the explosion's `busy_until="boom"` holds it through the spiral
  and clump), the orbit held two extra turns (`revs=5` — a longer loading
  at the same spin speed), a red blast, the sign 700 ms after the boom (user request,
  Sep 2026). The caption waits for the orbit: on the way in a qubit
  crosses the caption band. A status ENDING is led the same
  way: `anim="arrive"` brings the resting look in on the entrance law once
  the explosion has cleared (`flows/firmware`). Never split a film and its
  verdict into two status screens: two dwells, a black transit between
  them, and the verdict's own hold twice — the lead is one screen.

---

## Input

Two physical buttons, one grammar: **left regresses, right progresses** —
the mapping never flips while reading the details, and **left never leads
on** — on an idle screen (a hero: the ask, an intro, a batch screen) left
goes back one screen or does nothing; only right enters the details
(below). Gesture weight scales with consequence: a tap
moves, a double-tap commits a step, a hold commits (or cancels) the whole
thing. The first entry screen is the PIN row
(`screens/pin/pin_entering.py`, Sep 2026): a status-kind screen whose
animation is **interactive** (`StatusAnim.interactive`) — it draws its own
chevrons and instruction labels, keeps the gestures as an event log
(tick / commit / delete / hold / release / submit / cancel), and plays the
verdict its digits earn in the same screen (its `miss` / `match` tails).
The driver types into it; the demo dials it. Amount editing is not built
yet; the grammar below is fixed ahead of it.

| Gesture | Navigate (hero / detail) | Entry (character / value) |
|---|---|---|
| Left tap | back one screen (the previous page first on a paged detail); on an idle screen too — never forward, and nothing where nothing is behind it (the opening ask) | previous character / decrement |
| Left double-tap | — (unbound) | BACK: the cursor to the previous entered character (to fix it) |
| Left hold | decline / cancel the flow → DECLINED | cancel the entry, discard (while it is open) |
| Right tap | forward one screen (the next page first on a paged detail); on an ask: into the details, at their first screen | next character / increment |
| Right double-tap | — (unbound) | NEXT: the cursor forward again over entered characters (moving never takes a dial away) |
| Right hold | sign / complete → CONFIRMED | — (unbound: the PIN submits on its 8th ENTER) |
| Both buttons together | — (unbound) | ENTER the character / accept the step (user decision, Sep 2026: enter on the chord, the double press for navigation, so a fast run of taps always dials); the ENTER of the PIN's 8th digit submits it — checked at once, no hold (user decision, Sep 2026) |

- **Taps are instant.** Acknowledgment on press-down: the pressed-side
  chevron nudges, 145 ms ease-out (`PRESS_FEEDBACK_MS` — two panel
  frames, so the panel always shows it). The action fires
  on release when the press stayed inside `TAP_MAX_MS` (500) ms — seven
  panel frames. It was 250 (3.5 frames) until Sep 2026: a 300–500 ms press,
  which is what a slow, gloved, arthritic or tremoring hand routinely makes,
  fired nothing at all and the screen simply did not move (audit A11-02).
  Widening it is safe because taps only ever move — signing and declining
  are holds — so the worst a late tap can do is step a screen.
- **The grammar receives clean edges.** Everything above is written in
  press and release EDGES, and something must remove the contact bounce a
  mechanical switch makes before they reach the grammar: an edge within
  `DEBOUNCE_MS` (30) of the previous edge on the same button is bounce and
  is ignored. Undebounced, one press on a PIN row reads as a double press —
  a cursor jump, not a digit. The reference driver assumes the job is
  already done; on hardware it belongs to the button or the HAL, and the
  port owns saying which (audit A11-09). The three entry windows
  (`TAP_MAX_MS`, `DOUBLE_TAP_MS`, `CHORD_MS`) are FIXED — there is no pace
  multiplier, because the device has no settings surface to adjust one
  from, and widening the chord would slow every PIN dial by the same
  amount (it is the digit-landing delay on a fresh slot).
- **A tap turns the page first.** On a paged detail (Text rules, Pages)
  right tap shows the next page until the last, then the next screen; left
  tap the previous page until the first, then the previous screen — which
  is entered on its LAST page, so left undoes right. The flip is § Motion's
  page swap; the pager tracks the page (`pq1/driver.py`).
- **The ask is the hub; left never leads on.** On an idle screen (a
  hero) a RIGHT tap enters the details at their first screen (first
  page); an intro ahead of the ask (`band_chev`) leads on to the ask. A
  LEFT tap there is never forward (user rule, Sep 2026): it goes back one
  screen where there is one — the returning ask to the last detail (on its
  last page), an ask to the intro or BATCH screen before it — and does
  **nothing** where there is not: the flow's first screen, or the first
  screen after a status (a mid-batch ending is never walked back into).
  The chevrons do not change: a hero keeps **both** corner chevrons even
  where left does nothing (user decision, Sep 2026). The rule lives in
  `layout.back_target`. Inside the
  details the mapping holds — left regresses, right progresses: left from
  the first detail returns to the ask, right from the last detail arrives
  on the returning ask, and a right tap there starts the details from the
  beginning again. A flow with no details (an ask straight to its endings)
  leaves the right tap unbound on it. In a batch every segment's BATCH
  screen is that segment's hub — a right tap enters ITS details,
  hold-right signs ITS ending, and the mid-batch ending plays through into
  the next segment (`layout._segments`). Reference: `pq1/driver.py`
  `_hub_target` + `_tap`, `pq1/layout.py` `back_target`.
- **Double-tap never delays a tap.** Double-tap is bound only in entry
  contexts, where a tap is a reversible selection change. The first tap
  fires immediately; a second press within 250 ms (`DOUBLE_TAP_MS`)
  converts it — the first tap is undone and the double press applied —
  but only where the cursor CAN move (right: entered characters ahead;
  left: not on the first slot): dialing a fresh slot, a fast run of taps
  is a run of taps. What the entry SHOWS follows the windows: the ring
  bounces at the tap, its digit lands a beat later — the chord window
  (`CHORD_MS` 150) on a fresh slot, the double-tap window where a double
  press could move — so a tap the chord or the double press takes is
  never flashed and then taken back (user correction, Sep 2026 — the PIN
  row read as glitching between digits). An enter or a move lands a
  pending tap at once. Navigation screens leave double-tap unbound, so
  nav taps never wait.
- **Both buttons are the chord.** A press on one side while the other is
  down, or within `CHORD_MS` (150) of the other side's tap, is the chord
  — bound only in entry contexts, where it ENTERS the character (a tap
  the first button fired is undone, its hold clock stopped). Navigation
  screens leave it unbound.
- **Hold is deliberate, release is snappy.** A press held past `TAP_MAX_MS`
  starts a linear progress fill that completes at 2000 ms
  (`HOLD_COMMIT_MS`), when the hold action fires. Releasing earlier snaps
  the fill back in 200 ms ease-out (`HOLD_SNAPBACK_MS`) and does nothing —
  slow where the user decides, fast where the system responds.
- **The fill is the token filling up.** The disc fills from the bottom to
  the top like liquid (`components.hold_flood`, drawn inside the token;
  curve `motion.hold_fill`), full exactly when the hold fires: the draw
  and the fire share ONE test (`motion.hold_full`), so no frame shows a
  full disc a release could still cancel. Gesture windows (`TAP_MAX_MS`,
  `DOUBLE_TAP_MS`, `CHORD_MS`, `HOLD_COMMIT_MS`) are timed from button
  edges, never frame ticks — the only durations exempt from the frame
  grid. The liquid
  is a **see-through film** (`HOLD_OVERLAY_ALPHA` 0.3), never a paint:
  over a coloured body — brand logo art, a placeholder-ramp solid, an
  unknown token's gradient — it is **black**, rising over the art and the
  glyph, under the ring, so the disc darkens below the surface; inside a
  **black body** (the ETH mono token, any near-black fill) black would be
  invisible, so it is **white**, rising under the ring and the glyph as a
  dark grey that leaves the logo crisp (`components.hold_style` is the one
  resolver, so a new brand family gets it for free). Both holds fill the
  same way, and **a hold never fades a chevron**: while either button is
  held — sign, decline, the PIN row's cancel, the check-word selector — both
  corner chevrons stay exactly as they rest (user decision, Sep 2026: "it
  should keep on showing both chevrons"). Audit A11-01 / COMP-01 had the
  corner on the un-held side fade so a sign and a decline would differ; the
  user retired that cue, and `tools/check` rule I-ARMED keeps it retired. The press pulls a sweeping circle home; on commit the full
  fill fades out over the transition; an early release drains it back.
  Nothing draws on an unarmed side. Demo loops perform the hold themselves
  through the last 2000 ms of a commit screen's dwell before an ending
  (`pq1.flow.Sim`).
- **Declining is always cheap; signing is not.** Hold-left (decline) is
  armed on every navigable screen. Hold-right (sign / submit) is armed only
  on screens flagged `commit`. Status screens accept no input (chevrons
  hidden) — declining must happen before dispatch. The one exception is
  an **entry**, which is navigable: it takes the entry column of the
  table above.
- **The PIN submits on its 8th digit; the entry's fill is the cancel.**
  ENTERING THE 8TH DIGIT CHECKS THE PIN at once — no hold, no confirm
  gesture (user decision, Sep 2026; it replaces the hold-right submit):
  the PIN is checked DIRECTLY — the 8th ring turns white and the whole
  row (rings, ENTER PIN — the hints fade out, no caption swap: user request,
  Sep 2026: no BACK, no CONFIRM, "it should directly check … 200ms")
  holds `T_CHECK` 200 ms and fades to black as one picture over
  `T_OUT` 500 ms, no fill; the verdict —
  WRONG PIN, LAST ATTEMPT, LOCKED / UNLOCKED — plays in the same screen,
  then the driver moves on: a miss to the next attempt (the next entry
  screen), a match to the first screen after the attempts, no screen
  left → rest. The right hold is unbound on an entry. A PIN row has no
  token disc, so the LEFT hold's liquid (the cancel, armed while the row
  is open) rises in every ring at once (`pin_slots` `fill`) — the
  entry's own liquid: OPAQUE white (not the token's 30 % film) rising
  over the stroke too, the part of each digit under its surface turning
  BLACK (user request, Sep 2026 — gold first, then white) — full at
  `HOLD_COMMIT_MS`, draining on an early release. Cancel discards the
  entry: back to the ask before the PIN when the flow has one, else a
  fresh row in place (`flows/pin`, user decisions Sep 2026). The
  instruction labels beside the chevrons PULSE — each hint 3 s on
  (fading in and out), 3 s off, then the next (user request, Sep 2026):
  − / +, ENTER (BOTH), BACK (2X) / NEXT (2X). A right tap dials
  the active digit +1, a left tap −1 (0..9 wrapping); both buttons ENTER
  it (the ring turns white, the cursor advances); a left double press
  goes BACK to an entered digit (its slot is active again, its dial
  live), a right double press NEXT forward again. Moving the cursor
  never takes a dial away (user correction, Sep 2026): a changed digit
  stays changed, and a digit dialed on a fresh slot stays visible in its
  grey ring until it is entered.
- **The cursor carries three cues, and a port keeps all three.** Which ring
  is live is said by (1) hue — the idle grey easing to `YELLOW`; (2) weight
  and height — the ring's stroke goes to `ACTIVE_LW` (3), a full panel pixel
  over the hair weight its neighbours take, and it rides `ACTIVE_LIFT` (4)
  px above the row; (3) the digit's ink — the cursor's digit and every
  entered digit are full white, while a digit dialed on a fresh slot and
  left behind wears `INK_SECONDARY`, the grey of the ring it sits in. The
  hue step alone measures 1.21:1 against the idle grey — near-isoluminant on
  this glass — so a port that ships the colour and drops the weight, the
  lift or the ink leaves the cursor findable only by someone who can see
  that hue (audit A11-10, Sep 2026).
- **Presses are never dropped.** Input during any transition retargets from
  the current interpolated pose — never queued, never eaten.
- **Chevron meaning.** `"lr"` = tap navigation available; `"up"` = a hold is
  armed and there is no tap navigation to announce; `None` = no input. The
  hero hint cycle (rotate up → bob) is the periodic reminder that holds are
  armed on that screen. `"lr"` does NOT mean holds are off: hold-left declines
  from every navigable screen, and an ask rests in `"lr"` while hold-right
  signs there. One pose cannot say both, and on a detail the left button does
  both jobs — tap goes back, hold declines — so the resting pose keeps the
  navigation legend, and it keeps it through a hold (both chevrons stay,
  above).
- **Dwell auto-advance is demo-loop behavior only** — on hardware nothing
  moves without a press, with the two exceptions named below. The film's
  clock is the other demo-only time: on hardware a loading film starts at
  dispatch and loops until the work answers (Components, Status animations —
  the film's length).
- **The two endings that leave on their own.** An ending rests until a press
  — except (1) a mid-batch ending, which plays through into the next segment,
  and (2) an entry verdict with another entry behind it, which rests
  `RESULT_HOLD_MS` and then opens the next row (a PIN miss with attempts
  left). Both are device behaviour and both are exhaustive: the last miss,
  a match and a cancel all route elsewhere or rest. A port implements these
  two and generalises neither. A verdict that leaves on a clock may not be
  the only place its warning appears — which is why TRY 3 of `flows/pin`
  is captioned LAST ATTEMPT rather than ENTER PIN: the warning belongs on
  the row being typed, where it cannot time out (audit A11-03).
- **Commit arming.** Every hero — the opening ask as much as the
  returning "back on the idle ask" of § Flow shape — and the
  auto-inserted mid-flow `Confirm?` carry `commit=True`
  (`layout.normalize_screens`): a transaction can be confirmed at the
  beginning, at Confirm?, or after every detail. Detail screens never arm
  accept — signing happens on an ask, never while reading. Demo loops
  perform the hold only where an ending follows the screen (the returning
  ask, Confirm? under `--early`); on the opening ask the sign is a
  player / firmware path.

### The bench player

The grammar can be felt on the physical NV3007 before firmware exists:
`pq1/driver.py` (`FlowDriver`) is the reference implementation of this
section — press/release edges in, `motion.py`'s gesture constants, `NAV`
springs, `Sim.go_to` retargeting — and `tools/panel/play_flow.py` feeds it
keyboard input while streaming live-rendered frames to the panel
(`.venv/bin/python tools/panel/play_flow.py safe/add_owner`; flow lists come from
`python3 -m flows`).

| key | gesture | effect |
|---|---|---|
| `→` / `d` | right tap | forward one screen (into the details from an ask); on a PIN entry: digit +1 |
| `←` / `a` | left tap | back one screen (into the details from an ask); on a PIN entry: digit −1 |
| `space` / `e`, or `a` + `d` together | both buttons | PIN entry: ENTER the digit — the 8th checks the PIN |
| `D`, or `d` `d` within 250 ms | right double-tap | PIN entry: NEXT — the cursor forward over entered digits (the fast pair converts the first tap; the shifted key fires the double press alone) |
| `A`, or `a` `a` within 250 ms | left double-tap | PIN entry: BACK — the cursor to the previous digit |
| hold `s` / `enter` ~2 s | right hold | sign / commit (armed screens only); unbound on a PIN entry |
| hold `x` / `backspace` ~2 s | left hold | decline from anywhere → DECLINED; PIN entry: cancel |
| `y` / `n` | — (the host, not a button) | answer a loading film: the work succeeded / failed — the film finishes its turn and spirals into the check / the X (`FlowDriver.answer`; `n` needs a flow with a failure film — `send`'s TRANSACTION FAILED, the Safe / CoW families' FAILED, firmware's UPDATE FAILED: a led ending opting in with `film_fail`). `--ready MS` answers "succeeded" by itself |
| `r` | — | restart after an ending (an entry starts empty again) |
| `q` / Ctrl-C | — | quit |

A mid-batch ending (SIGNED n OF m) plays through, then the player moves on
to the next transaction's BATCH screen; the batch's decline ending is
reachable from every segment. Holds ride the terminal's key-repeat stream; `--instant-holds` fires a
full hold on one press where key-repeat is off. The hold fill rises live
from the real press and drains back on an early release — the player
reads a release from a gap in the key-repeat stream (`--initial-gap`
until the first repeat, then the short `--repeat-gap`), so on the bench a
release is seen up to that gap late; real buttons have exact edges. Not yet
simulated: the press-feedback chevron nudge.

**The player is a bench / design-review tool.** Production firmware
implements this grammar natively on-device (reading real buttons) and
will probably never run the player or `FlowDriver` — this section stays
the contract; the driver exists so flows can be driven by hand on real
glass before that firmware lands.

## Components

- **Token circle** — the centrepiece. `variant="solid"`: solid fill +
  white ring, the normal treatment for a known token. `variant="unknown"`:
  the gradient disc. Ring width is the system ring weight
  (`TOKEN_RING_W` (2.4), `STROKE` ring — § Iconography), inset 1.2; inner
  glyphs crossfade during transitions.
- **Glyph resolution**: a screen's `icon` is looked up in the registry
  (`components.GLYPHS`); a registered logo draws its circle-masked image.
  An icon the registry does not hold — and a screen that names none —
  draws the **ether mark**, and that is a design decision, not a gap
  (user rule, Sep 2026): this is an Ethereum wallet, so the ether mark is
  the honest answer for art the device cannot resolve, and `"eth"` is the
  schema default (`layout.normalize_screens`). `screens/idle/batch_sign`
  is the worked example. The ether mark is procedural art
  (`pq1/procedural/eth.py`) like every other mark — there is no raster
  logo left in the system, so it takes the screen's `icon_color`, and
  when a screen names none it takes `colors.mark_color` of the disc it
  rests on (§ Iconography). Never an empty circle, and never a `?` in
  place of an icon — the monogram answers only a name: an unknown chain's
  or a long-tail token's initial (below), never a missing logo file, which
  is a build error, not a screen.
  What the fallback does **not** license: a name the registry DOES hold
  must never degrade to a different mark. Family marks (`safe`,
  `cowswap`) register when their flow package is imported, so resolve
  them eagerly — a brand mark silently becoming another brand's is a bug
  (it also drops the screen's `icon_color`). `tools/check` rule `F-ICON`
  fails the build on any icon name the registry cannot resolve, so the
  fallback only ever answers art that is genuinely absent.
  The one narrowing: a **chain** does not take the ether mark. An
  unrecognised chain id resolves to `letter:<X>` and the disc shows the
  network's initial (`components.letter_glyph`, the Bold `monogram`) — the
  ether mark would name Ethereum, which is a different network, and that
  is the one case where the fallback would state something false rather
  than merely generic. A **long-tail token** narrows it the same way: a
  symbol outside `TOKEN_LOGOS` and ETH / WETH draws its initial
  (`components.token_defaults` → `letter:<X>`), because the ether mark on
  TOSHI's disc would read as ether; a symbol with no letter or digit to
  show keeps the ether mark. The disc is still never empty, and `letter:` is a
  namespace resolved at draw time, never a `GLYPHS` entry: the registry is
  dumped as the legal icon set the handoff spec publishes, so writing to
  it lazily would make that set depend on render order (audit G17-07).
- **Chevrons**: corner slots only; `"lr"` points out (tap navigation
  available), `"up"` points up (a hold action is armed), `None` hidden (no
  input — status screens). The one exception: a `band_chev` hero — the
  intro screen (`flows/firmware/`, `flows/setup/`) — moves its chevron into the
  band, the confirm band's right-pointing unit after the caption
  (`components._band_unit`), the corner pair hidden; taps still navigate.
- **Caption**: bottom-band text, 18 px caps, centred, baseline y 128.
- **Trails**: `trail_static` (resting stream, 22 px gaps) and `trail_chain`
  (a `FollowerChain` behind a moving head), both stepped along a palette —
  the TRAIL ramp for unknown tokens, or the screen's placeholder ramp
  (`trail_palette_from_spec(screen)`) for a known token without an image.
  Links are drawn at the token's visible radius (r − inset), so every link
  is exactly the size of the circle.
- **Pulse**: two staggered rings expanding r + 1.5 → r + 8.5 px and fading,
  2000 ms period, stroked at the system ring weight (`TOKEN_RING_W` 2.4).
- **Hold fill** (`hold_flood` / `hold_style`, drawn by `token()`): the
  hold gesture's progress — the disc filling from the bottom up on
  `motion.hold_fill` with a 30 % see-through film: black over a coloured
  body (art and glyph, under the ring); white inside a black body (under
  ring and glyph). The glyph is never hidden. See Input.
- **Flash ring** (`components.flash_ring`): the one-shot ring a resolve
  fires in the result colour — off the disc edge, + 55 px, from
  `FLASH_ALPHA` to nothing, at the system ring weight `TOKEN_RING_W`
  like every ring the token casts (owner decision, Sep 2026). There is
  one ring weight for the token family; the PIN pill (2.6) and the
  active PIN ring (2.5) are the recorded exceptions.
- **Two radii, one rule** (`components.visible_r`): the token's layout
  radius is `r`, its visible edge `r − TOKEN_INSET`. Anything that IS the
  token — disc, ring, full-bleed art, trail links, an unbranded resting
  ring — sits at `visible_r(r)`; anything that LEAVES it — the pulse
  rings, the flash ring, the handoff wash (`status.HANDOFF_WASH_R`), a
  branded flush resting ring — measures from `r`. A new component picks
  its radius by that sentence, never by eye.
- **Rounded rectangles are capsules**: corner radius = half the short
  side, never a fixed px (the PIN pill, its scanline, the exclamation
  bar). Vector signs keep their traced source rounding; do not
  normalise it.
- **Status animations** (`status.py` registry): every status screen loads
  with a named choreography and resolves to the shared resting look — black
  disc, state-coloured ring, result glyph, caption on the y 128 baseline —
  unless the screen brands it with a `resting` override (see Color).
  The default splits on outcome (`status.default_anim`): a done ending
  plays `"qubit"` — **the film, the depiction of work**: the flow's
  circle is handed over and SEEDS — it travels in, shrinks and tints
  into one qubit (see Motion, entering a loading film) — then splits
  into two qubits that orbit (metaball merge), spiral in, flash
  and resolve green under the check. A cancel ending (any non-done
  state) plays `"resolve"` — **no film**: the arrived token resolves in
  place over one flash beat — the token glyph hands off, disc and ring
  crossfade into the resting look, the flash ring fires in the state
  colour, and the X and caption land on the film's own resolve timing
  (400 ms + the shared result hold). A FAILURE the host reports after
  dispatch is not a cancel: the ending names the film (`anim="qubit"`,
  `result="x"`, `state="failed"` — `flows/send.py` FAILED) and the same
  loading collides into the red X. There is no other cancel choreography
  — the old orbit spinner is gone from the project and must not come
  back. The film follows the screen's token palette; an
  optional `busy` caption ("SIGNING…") shows during the film's loading
  and BREATHES: it fades in and out on a slow pulse (`motion.busy_pulse`,
  `BUSY_PULSE_MS` 2 s a cycle, whole cycles fitted to the window so it
  starts and ends dark) for as long as the loading runs, and its window
  opens only once the qubits are ON the orbit — the join done, never over
  the split or the sweep (user rule, Sep 2026; `StatusAnim.busy_pulse`,
  `burst.t_arrive`). A steady busy caption is for a gesture, not a
  loading — `HOLD TO CONFIRM`. The film-less cancel has no busy
  window. An ending may be LED by a film instead (`lead`,
  `status.LedAnim` — Verdict screens, Lead films): the explosion plays
  first — the flow's token hands its mark and edge stroke off into the
  split exactly as the qubit film does, the `busy` caption rides the
  orbit — and when the canvas is empty the ending's own animation
  starts: `"arrive"` (`status.ArriveStatus`) brings the resting look in —
  disc, ring and result glyph together — on the verdict entrance law
  (`motion.arrive`, 300 ms), a beat, then the caption; 1479 ms to
  resolve. The firmware endings (`flows/firmware`): the major explosion
  under "UPDATING…", then the WHITE disc + black check (the family's
  own disc resolved, the FIRMWARE VERIFIED look); the minor
  explosion, then the red disc + black X. The `screens` package registers
  further animations (verdicts, explosion).
- **The film's length is the demo's.** A film is a scripted depiction of
  work whose real length the device does not know. On hardware it starts
  when the work is dispatched (the hold fires); the steady orbit —
  `QubitCfg.loop` = (`t_orbit` 2250, `t5` 4800), the loop region, the only
  part of the film that is pixel-periodic — repeats in whole turns of
  `QubitCfg.loop_ms` (the orbit's `rev_ms`: `TURN_MS` (850), the unit of
  loading length) until the work answers; the film then finishes the
  current turn and spirals in, and the outcome is LATCHED there — at the
  spiral, no later than `t6` of the last turn, the first frame that
  differs between check and X — instead of at construction
  (`StatusAnim.resolve(t)`; `t_resolve` is a property, `t7` + wraps ×
  `loop_ms`, infinite while a live film is unanswered; `loading.film_time`
  maps the real clock to the pose clock and is the identity with no
  wraps, so every stock render is untouched). The spiral + flash tail
  (`T_SPIRAL` 1000 + `T_FLASH` 400) and the result hold
  (`RESULT_HOLD_MS` 2450) are fixed; a finished ending freezes forever.
  The pose wraps, the busy caption does not: it breathes on the unwrapped
  clock — whole cycles fitted to the film's stock window, continuing at
  that period while the loop runs — and fades out over `BUSY_FADE_MS`
  (300) as the spiral starts, so a wrap never jumps the caption. A film is
  made longer only in whole turns — at build time with `revs` (`REVS` (3)
  stock, `REVS_LONG` (5) where a loading must endure: the firmware reboot,
  the wipe — the film's MINIMUM), at run time with a wrap — never with a
  slower spin, a longer split or a longer spiral. A port that cannot loop
  holds the last orbit frame; it never starts the film after the work is
  done. The waiting state is not a `state` value (`awaiting` stays the
  input colour). On the bench every qubit / explosion ending is live
  (`FlowDriver` sets `live`; `y` / `n` answer it — Input, The bench
  player); `ready` in a spec (`--ready MS` on both CLIs) renders a film
  answered at that ms. The checker's `L-LOOP` proves the wrap pixel-exact.

## Depth

The panel is pure black and emissive: there is **no shadow, no glow, no
blur** anywhere in PQ1, and none may be added. The gear / die shutter is
exposure, not a style. Depth is exactly two things:

- **Draw order**, bottom to top: canvas · corner chevrons · text · follower
  trail · pulse rings · token disc + hold fill. The disc draws last because
  the alpha idiom fades toward black: a faded element is always the lower
  layer, so any other order would let a fading ring or trail darken a disc
  it passes under.
- **A pure-black knockout** wherever one shape passes behind another: the
  padlock's halo around the body, the black outline on the PIN scanline
  crossing the pill, the die's edge between its faces. A knockout is
  black, never a darker tint of the shape behind it.

## Screen schema

A screen is a plain dict (see `layout.py` for the full contract):

- Common: `id`, `kind` (`"hero"` | `"detail"` | `"value"` | `"confirm"` | `"status"`), `icon`
  (+ optional `icon_color` — vector-mark colour override; image logos keep
  their own art — the SAFE family pins it black),
  `chain` (a numeric EIP-155 chain id on a chain screen — the mark, the
  disc colour, the trail ramp and the caption are derived from it, so a
  chain screen sets no `icon`, `lines` or `size`; detail screens only,
  never a flow's DEFAULTS) with `chain_name` beside it when the id is one
  the registry does not hold (the disc then shows the name's initial),
  `chev` (`"lr"` | `"up"` | `None`), optional `dwell`, `next` (where the
  demo loop advances after dwell — an index or a screen id, first match
  scanning forward; the branch primitive behind the confirm screen's
  early exit), `sweep`, `commit`
  (hold-right sign/submit armed on this screen, and where the demo loop
  performs the hold before a done ending — see Input), `token`
  (`{"variant": "solid"|"unknown", "fill": …, "ring": …, "palette": …,
  "address": …, "symbol": …}` — defaults to `"solid"`; the gradient disc
  must be asked for with `variant="unknown"` and takes the ramp hashed from
  the token's identity (`palette` → `address` → `symbol` → `icon`);
  `palette` picks a placeholder ramp for a known token without an image,
  or pins a brand ramp by name (`"SAFE"` — see Brand ramps); an explicit
  `ring` draws over logo art, stroked flush at the disc edge).
- **hero**: `bottom` (question text on the y 128 baseline), `hint`;
  `commit` defaults True — every ask signs. `pager` (`[n, m]`) marks the
  hero's place in a sequence of asks — a batch's transactions
  (`flows/batch`) — drawing the pager `n/m` in its top-centre spot; it is a
  position, not text pages, so nothing turns and the dwell is unchanged.
  `band_chev` makes the hero an
  intro ahead of the ask: the caption carries the band chevron ▸, `chev`
  defaults `None`, and the flow sets `commit` False — it is not an ask
  (`flows/firmware/`, `flows/setup/`).
- **confirm**: `bottom` (default `"Confirm?"` — the 36 px prompt),
  `commit` defaults True, corner chevrons up (hold-armed) with a 5 s
  pointing bob. The alternating band
  (`components.confirm_band`: OR VIEW MORE ▸ / ◂ TO GO BACK, 5 s swap)
  comes with the kind; inserted automatically as the 6th screen of long
  flows (see Flow shape).
- **detail**: `side`, `label` (16 px semibold caps on the column), `lines` (1–3;
  a line is a str, or `{"str", "weight": "semibold"}` for a name line — Text
  rules, Names), `size` (largest tier that fits); no per-screen x
  nudges — a detail sits on its column, a chain screen composes itself.
  `side` defaults to the opposite of the previous detail in the segment,
  the first on the left; `pages` (two or more pages of 1–3 lines at that one
  `size` — ONE value read in full over pages, the pager `n/m` with it; Text
  rules, Pages) in place of `lines`, which then holds the first page.
- **value**: the value alone, full width — `lines` / `pages` and `size` as a
  detail's, the text centred on x 214 with the full-width budgets
  (Typography, Choosing the size); NO token on the panel: the circle
  leaves — parked off-canvas at `layout.VALUE_PARK_X`, the position spring
  carrying it off the left edge with its followers, and back for the
  next screen. The corner chevrons stay, the pager comes with `pages`. A
  detail without the docked token — it counts as one for the Confirm?
  rule. The hash the user matches (`flows/fingerprint`). `words` (up to
  eight short words) in place of `lines` lays the value on the numbered
  seed-words grid (Text rules, Words) — the key fingerprint
  (`flows/firmware`). A value screen carries no `label`
  (`normalize_screens` rejects one).
- **status**: `bottom` caption; `anim` (default splits on outcome —
  `"qubit"` for done endings, `"resolve"` for cancels
  (`status.default_anim`); `"arrive"` — the resting look arriving on the
  entrance law, for an ending whose work a `lead` film showed; any
  registered animation — the `screens` package adds more), `lead` (a film
  that ends on an empty canvas, played first — `dict(anim="explosion",
  severity="major", busy="UPDATING…")`; Motion, Status animations),
  `result` (`"check"` | `"x"` | `None`, default `"check"`),
  `state` (a `colors.STATE` key, default `"done"`; explicit `color` wins),
  `busy` (optional loading caption), `revs` (whole orbit turns of a qubit
  / explosion film before the spiral — `REVS` (3) stock, `REVS_LONG` (5);
  the film's minimum), `ready` (demo only: the ms at which the work
  answers — the film renders its loop), `live` (set by the bench driver,
  never by a flow: the film loops until `FlowDriver.answer`). Dwell
  defaults to the animation's duration (a live film waits). Unknown names
  raise — no silent fallback. Extra fields ride
  through to the registered animation — the PIN entry's `pin` (the PIN
  the device accepts), `typed` (what the demo dials), `exit` (`"rest"` /
  `"submit"`), `miss` / `match` (the verdict screen dicts it plays after
  the row fades), `labels` (`screens/pin/pin_entering.py`, Input).

## Pre-ship check

Largest fitting tier used · nothing below 16 px · bottom text on the y 128
baseline · addresses unbroken by ellipsis · one primary value per screen ·
text color matches screen state · gradient only on unknown tokens · a chain screen named by `chain=<id>`, never a hand-written mark or caption · the
unknown ramp derived from token identity, never fixed · every screen
answers what left, right, and both holds do · decline reachable until
dispatch · commit screens fill up before their ending (a see-through
film: black over coloured discs, white inside black ones — the glyph stays).
