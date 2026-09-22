# PQ1 — design definition

The canonical spec for the NV3007 wallet UI (428 × 142 landscape, pure black).
Every number here is mirrored by a constant in this package — `layout.py`,
`typography.py`, `colors.py`, `motion.py` — and the code is the source of
truth: if this file and a module ever disagree, fix this file. The
[README](README.md) maps the modules; this file defines the system.

## Canvas & rendering

- 428 × 142 UI pixels, pure black background, 12 px margins.
- Everything draws at 3× supersample and is LANCZOS-downscaled in
  `Canvas.out()`; all APIs take UI pixels.
- Alpha idiom: colours are scaled toward black, which is exact on the pure
  black background. The draw context is RGBA so components that need true
  compositing (pulse rings, badges) get it.
- The NV3007 driver handles rotation to the physical panel.

## Layout grid & anchors

| Anchor | Value |
|---|---|
| Main circle | diameter 60 (r 30), centre y 72 — never resizes |
| Idle / hero circle | centred x 214 |
| Idle sweep range | x 89 – 339 |
| Detail circle columns | x 24 – 123 (centre 74) or x 303 – 402 (centre 352) |
| Detail text centre | x 263 (circle left) / x 163 (circle right), vertical centre y 72.5 |
| Detail text region | 276 × 77 px (x 127 – 402 or x 25 – 300, y 28 – 104); 404 px wide on full-width screens |
| Bottom band | y 105 – 129, all band text baseline-aligned to y 128 |
| Chevron slots | (23.5, 19) and (403.5, 19), hidden on status screens |
| Confirm screen | circle x 291, prompt centre x 175 (the CHAIN nudges) |
| Value screen | text centred x 214 across the full 404 px region; no circle on the panel — the token parks off-canvas at x −60 (`layout.VALUE_PARK_X`) |
| Pager | `n/m` top centre — x 214, baseline y 24, at the **Label size** (16) — a screen with pages, or a hero's position in a sequence of asks (`pager`) |

## Typography

One family, seven sizes, fixed roles, two faces. Aileron Regular for every
value; Aileron SemiBold for the label caps and for a **name** line inside a
value (see Text rules, Names) — no other weight, no italic, no other family,
never below 12 px.

| Role | Size | Spec | Use |
|---|---|---|---|
| Big | 32–36 | Regular, leading = size | Short one-liners: "Unlimited", "on Mainnet" |
| Mid | 28 | Regular, leading 36 | One- or two-liners: "50 gwei / Tip: 1 gwei" |
| Default | 22 | Regular, leading 30 | Multi-line content: addresses, call data, hashes |
| Question | 18 | Caps, +0.5 px tracking | Idle / confirm prompt in the bottom band |
| Label | 16 | SemiBold caps, +1 px tracking | Field name under the circle: SPENDER, MAX FEE |
| Paging | 12 | 80 % white | footnotes — the PIN ghost digits, the `badge()` default. The pager `n/m` rides the **Label** size (16), so the two band-edge annotations read alike (user request, Sep 2026) |

Leading is the stacking rule `line_height(size)` — size for 32/36, size + 8
below (28 → 36, 22 → 30).

**Font resolution** (`typography.font`): `$PQ1_FONT` override → the bundled
copy in `pq1/assets/` (Aileron-Regular/SemiBold.otf, so pq1 is self-contained)
→ system font directories → PIL's built-in default as a last resort. A warning is printed
once if the face that loads is not Aileron, so a missing font can never
silently restyle the UI.

### Choosing the size

Always use the largest tier whose content fits the detail region:

| Tier | Max characters per line | Max lines |
|---|---|---|
| 36 | 12 | 1 |
| 32 | 14 | 1 |
| 28 | 16 | 2 |
| 22 | 21 | 3 (the third line overflows into the text band — info screens only) |

Measure the longest unbreakable run. Fits at 36? Use 36. Otherwise try 32,
then 28 (up to 2 lines), then 22 (up to 3 lines). If it still does not fit,
split the content across two screens — or, when it is ONE value that must
stay whole (a 32-byte hash), page it within its screen (Text rules, Pages)
— never shrink below 22, never truncate, never ellipsize. For full-width screens (no side-docked circle)
multiply the per-line counts by 1.45 (36 → 17, 32 → 20, 28 → 23, 22 → 30).

### Text rules

- **Baseline, not centering.** Any text in the bottom band is
  baseline-aligned to y 128 — never vertically centered in the band.
- **Addresses and hashes.** Default tier, broken into centred lines of ≤ 21
  characters, split mid-string, no ellipsis — the full value must be
  verifiable on screen.
- **Pages.** A value that overflows its tier's three lines yet must be read
  in full — a 32-byte hash, 66 characters — stays ONE value on ONE screen
  and turns pages: `pages` in the screen dict, two or more pages of 1–3
  lines at the screen's one `size`, the pager `n/m` (Typography, Paging)
  top centre only then. A hash pages on byte lines: page 1 `0x` + 8 bytes /
  8 bytes, page 2 8 / 8 bytes, at 22
  (`flows/eip1271/personal_counterfactual_hash.py`). Never two screens for
  one value, never an ellipsis where the value must be verified (the DATA
  HASH fingerprint is the one sanctioned shortening). The page turn is the
  swap of § Motion, Page flip; a tap turns the page before it moves the
  screen (§ Input).
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
  address treatment above — two ≤ 21-character lines at 22.
- **Case.** Labels and questions are caps. Detail values are rendered
  exactly as supplied — never re-case, re-punctuate, or reformat a value
  coming from the transaction.
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
| 70 % white | `scale(WHITE, 0.7)` | secondary text |
| 80 % white | `scale(WHITE, 0.8)` | paging |
| Factory blue `#4A9FF0` | `FACTORY_BLUE` 74, 159, 240 | factory screens only — never a state colour, never user-facing wallet UI |

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
(brand art, placeholder ramps, unknown gradients), white inside a black
body (the ETH mono token) — never a paint that hides the glyph.

**The gradient is not decoration.** A gradient disc is reserved for a
token the device does **not** recognize — the unknown-token treatment. Its
hue is one of the placeholder ramps below, resolved deterministically from
the token's identity by `components.token_ramp` (`palette` → `address` →
`symbol` → the screen's `icon` → the neutral grey ramp; crc32-hashed and
case-folded — except a `palette` naming a brand ramp, which is pinned by
name, never hashed; see Brand ramps), so the same unknown token always
wears the same gradient —
and the same ramp supplies its five follower colours. `address` outranks
`symbol` because two tokens can share a ticker but never a contract. There
is no fixed unknown gradient; it is not a blind-signing indicator, and
known tokens never use it.

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

**The mono entry (recognized token with a logo).** The last ramp,
`colors.MONO_RAMP`, is the treatment for a recognized token that shows its
own logo: black body, white ring, white glyph, grey trail (its palette fill
is overridden to black; status-film bodies take the ramp's brightest stop
so they never render black-on-black). The SEND flow pins ETH to it; WETH, ether's ERC-20 wrapper, wears the same
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
ether mark on the mono body for ETH / WETH, otherwise the placeholder ramp
hashed from the symbol — one flow serves every token on device. A flow with
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
  beat survives on the device.
- **Named curves are for scripted motion**: `ease` (cubic in-out) and
  `ease_out` serve the non-interruptible sequences — the status film,
  press feedback (120 ms ease-out), hold snap-back. Ambient motion (idle
  sweep, follower chain) keeps the frame-rate-independent τ-chase
  (`motion.tau_chase`).
- **Transition anatomy**: everything moves at once — outgoing text fades
  while the circle travels and the incoming text arrives. A KIOSK leg
  settles in ~700 ms, NAV in ~500 ms; `MOVE_MS + 2*FADE_MS` (1260 ms)
  survives only as the span bound harnesses render into.
- **Dwell**: hero 5000 ms (one full sweep), detail 4100 ms — per page on a
  paged detail; a status screen
  dwells for its animation's duration — loading + resolve + a 2450 ms result
  hold (qubit 8600 ms; the film-less cancel resolve 2850 ms). Dwell counts
  from spring settle.
- **Hold fill (demo loops)**: the demo performs the hold gesture through
  the last 2000 ms (`HOLD_COMMIT_MS`) of a commit screen's dwell before an
  ending — hold-right into a done ending, hold-left into a cancel — the
  disc full exactly as the screen advances. It lives inside the dwell, so
  durations are unchanged (§ Input: the hold fill).
- **Idle sweep** (hero screens by default): centred hold 1000 ms, then a
  5000 ms left-right cycle, amplitude 95 px, the circle chasing the target
  with τ 180 ms. The sweep stays inside x 89 – 339.
- **Follower chain**: 5 links trailing the head, per-link easing τ 60 ms
  (150 ms during the idle sweep, for more separation), consecutive links
  capped at 30 px apart.
- **Chevron hint** (hero screens): starts 1.4 s into the idle and repeats
  every 3.6 s — 350 ms rotate up, 1200 ms bob (−4 px sine), 350 ms return.
- **Confirm band alternation** (confirm screens): once settled, the
  band shows **OR VIEW MORE** with a right-pointing chevron, and **every
  5 s** it fades away and **◂ TO GO BACK** fades in (then back — a
  sequential 300 ms swap, `motion.confirm_band`). The corner chevrons
  rest in the **up** (hold-armed) pose there and point — the hero bob —
  on the same 5 s beat (`motion.chevron_hint` at `BAND_SWAP_MS`).
- **Page flip** (paged details — Text rules, Pages): each page holds one
  detail dwell (`PAGE_SWAP_MS`, 4100 ms). 300 ms before its slot ends the
  showing page fades away on `ease_out`, THEN the next page fades in over
  300 ms on `ease` (`PAGE_FADE_MS`; `motion.page_flip`) — a sequential swap
  on the confirm band's rhythm, never a crossfade; the pager's number
  switches between the two phases. The first page arrives with the screen
  (the transition's own text alpha) and the last leaves with it. On the
  bench a tap starts the same swap.

## Flow shape

- **The mid-flow Confirm? screen.** A flow with **7 or more detail
  screens** takes a `confirm`-kind screen as its **6th screen** — an
  early exit ahead of the remaining details. "Confirm?" sits big in the
  detail region (Big tier, mixed case), the token circle docks right of
  centre (x 291 / prompt centre x 175 — the CHAIN nudges), and the
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
  (canonical id `CHAIN` — `on BASE`, Big tier, the x 291 / x 175 nudges)
  sits **directly after** the `TO` or `AMOUNT` detail it contextualizes —
  the chain qualifies the address or value just shown, never floats
  elsewhere. Enforced with the flow-shape checks.
- **Dwell**: 10 s in demo loops (`motion.CONFIRM_DWELL` — one full band
  cycle, so both messages play); on hardware it idles until input.

## Verdict screens

A **verdict** is a status-kind screen whose animation draws a procedural
icon instead of the resting token: the icon arrives on the circle grid
(cx 214, cy 72 — or the detail grid for detail verdicts like SIG ERROR),
the caption fades onto the y 128 baseline, then the screen rests.
Chevrons are hidden (no input), like every status screen.

When to use which: a **status** screen shows work the device did
resolving (the token loads, then lands on the result) — signing,
broadcasting. A **verdict** states a fact — LOCKED, BACKUP OK, WALLET
WIPED, RNG FAILED, LAST ATTEMPT. No loading: the icon *is* the message.

Anatomy and timing (`pq1/verdict.py`):

    T_HOLD 400 → T_IN 300 (icon: fade + motion.arrive) → T_WAIT 450 → T_TEXT 300
    t_resolve = the phase sum (1450 by default; mechanisms override)
    duration  = t_resolve + RESULT_HOLD_MS — the same law as every
                status animation, so flows dwell correctly for free

Rules:

- The icon colour comes from the screen's `state` (`colors.STATE`) or an
  explicit `color` (factory blue). Never a local hex.
- Icon art comes from `pq1/procedural/` — one module per image; the
  result/notice marks (check, x, exclamation) live in
  `pq1/procedural/marks.py`. Screens compose marks onto art; they never
  redraw them.
- The composite icon's resting-pose optical centre sits on (214, 72).
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
  Screens that rest on the token (the qubit film, a resolve, the idle
  screens, the hold) keep the morph (Sep 2026).
- **Lead films.** A verdict that follows destructive work may open on a
  film that ends on an empty canvas — the screen's `lead`
  (`status.LedAnim`): the lead plays first, the verdict starts when it
  resolves and its black `T_HOLD` runs under the lead's fading tail, so
  the icon pops in as the blast clears; `lead_gap` (ms) holds the screen
  back further, past the tail. Durations add (one screen, one
  dwell). Only a film with `t_tail` set may lead (the explosion); one
  that rests on a look raises. The explosion's `enter` ("left" /
  "right") slides its circle in from off the panel (`VALUE_PARK_X`) on
  the flows' KIOSK spring (`motion.spring_travel`, `ENTER_MS` 800), the
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
the mapping never flips while reading the details. The ask is not a flip
but a **hub**: either tap leads into the details (below). Gesture weight scales with consequence: a tap
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
| Left tap | back one screen (the previous page first on a paged detail); on an ask: into the details | previous character / decrement |
| Left double-tap | — (unbound) | BACK: the cursor to the previous entered character (to fix it) |
| Left hold | decline / cancel the flow → DECLINED | cancel the entry, discard (while it is open) |
| Right tap | forward one screen (the next page first on a paged detail); on an ask: into the details | next character / increment |
| Right double-tap | — (unbound) | NEXT: the cursor forward again over entered characters (moving never takes a dial away) |
| Right hold | sign / complete → CONFIRMED | — (unbound: the PIN submits on its 8th ENTER) |
| Both buttons together | — (unbound) | ENTER the character / accept the step (user decision, Sep 2026: enter on the chord, the double press for navigation, so a fast run of taps always dials); the ENTER of the PIN's 8th digit submits it — checked at once, no hold (user decision, Sep 2026) |

- **Taps are instant.** Acknowledgment on press-down: the pressed-side
  chevron nudges, 120 ms ease-out (`PRESS_FEEDBACK_MS`). The action fires
  on release when the press stayed under 250 ms (`TAP_MAX_MS`).
- **A tap turns the page first.** On a paged detail (Text rules, Pages)
  right tap shows the next page until the last, then the next screen; left
  tap the previous page until the first, then the previous screen — which
  is entered on its LAST page, so left undoes right. The flip is § Motion's
  page swap; the pager tracks the page (`pq1/driver.py`).
- **The ask is the hub.** A hero has no left or right: either tap enters
  the details at their first screen (first page), so the signer never has
  to remember which side leads in. Inside the details the mapping holds —
  left regresses, right progresses: left from the first detail returns to
  the ask, right from the last detail arrives on the returning ask, and
  from either ask any tap starts the details from the beginning again. An
  intro ahead of the ask (`band_chev`) leads on to the ask on either tap;
  the walkthrough never returns to it. A flow with no details (an ask
  straight to its endings) leaves taps unbound on it. In a batch every
  segment's BATCH screen is that segment's hub — either tap enters ITS
  details, hold-right signs ITS ending, and the mid-batch ending plays
  through into the next segment (`layout._segments`). Reference:
  `pq1/driver.py` `_hub_target`.
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
  curve `motion.hold_fill`), full exactly when the hold fires. The liquid
  is a **30 % see-through film** (`HOLD_OVERLAY_ALPHA`), never a paint:
  over a coloured body — brand logo art, a placeholder-ramp solid, an
  unknown token's gradient — it is **black**, rising over the art and the
  glyph, under the ring, so the disc darkens below the surface; inside a
  **black body** (the ETH mono token, any near-black fill) black would be
  invisible, so it is **white**, rising under the ring and the glyph as a
  dark grey that leaves the logo crisp (`components.hold_style` is the one
  resolver, so a new brand family gets it for free). Both holds fill the
  same way; the pressed side is what the
  chevrons say. The press pulls a sweeping circle home; on commit the full
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
- **Presses are never dropped.** Input during any transition retargets from
  the current interpolated pose — never queued, never eaten.
- **Chevron meaning.** `"lr"` = tap navigation available; `"up"` = a hold
  action is armed; `None` = no input. The hero hint cycle (rotate up → bob)
  is the periodic reminder that holds are armed on that screen.
- **Dwell auto-advance is demo-loop behavior only** — on hardware nothing
  moves without a press.
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
  the gradient disc. Ring width 2.4, inset 1.2; inner glyphs crossfade
  during transitions.
- **Glyph resolution**: named icon in the registry → image logo
  (circle-masked) → vector for the symbol (ETH diamond) → monogram of the
  symbol's first letter. Never an empty circle.
- **Chevrons**: corner slots only; `"lr"` points out (tap navigation
  available), `"up"` points up (a hold action is armed), `None` hidden (no
  input — status screens). The one exception: a `band_chev` hero — the
  intro ahead of an ask (`flows/erc7730/`) — moves its chevron into the
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
  2000 ms period, stroked at the system ring weight (`TOKEN_RING_W`, 2.4 px).
- **Hold fill** (`hold_flood` / `hold_style`, drawn by `token()`): the
  hold gesture's progress — the disc filling from the bottom up on
  `motion.hold_fill` with a 30 % see-through film: black over a coloured
  body (art and glyph, under the ring); white inside a black body (under
  ring and glyph). The glyph is never hidden. See Input.
- **Pills / badges**: rounded chips on a faint white tint
  (`(255, 255, 255, 26)`), badge text 12 px.
- **Status animations** (`status.py` registry): every status screen loads
  with a named choreography and resolves to the shared resting look — black
  disc, state-coloured ring, result glyph, caption on the y 128 baseline —
  unless the screen brands it with a `resting` override (see Color).
  The default splits on outcome (`status.default_anim`): a done ending
  plays `"qubit"` — **the film, the depiction of work**: the token
  splits into two qubits that orbit (metaball merge), spiral in, flash
  and resolve green under the check. A cancel ending (any non-done
  state) plays `"resolve"` — **no film**: the arrived token resolves in
  place over one flash beat — the token glyph hands off, disc and ring
  crossfade into the resting look, the flash ring fires in the state
  colour, and the X and caption land on the film's own resolve timing
  (400 ms + the shared result hold). There is no other cancel or failure
  choreography — the old orbit spinner is gone from the project and must
  not come back. The film follows the screen's token palette; an
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
  (`motion.arrive`, 300 ms), a beat, then the caption; 1450 ms to
  resolve. The firmware endings (`flows/firmware`): the major explosion
  under "RECONNECTING…", then the WHITE disc + black check (the family's
  own disc resolved, the FIRMWARE VERIFIED look); the minor
  explosion, then the red disc + black X. The `screens` package registers
  further animations (verdicts, explosion).

## Screen schema

A screen is a plain dict (see `layout.py` for the full contract):

- Common: `id`, `kind` (`"hero"` | `"detail"` | `"value"` | `"confirm"` | `"status"`), `icon`
  (+ optional `icon_color` — vector-mark colour override; image logos keep
  their own art — the SAFE family pins it black),
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
  (`flows/erc7730/`).
- **confirm**: `bottom` (default `"Confirm?"` — the 36 px prompt),
  `commit` defaults True, corner chevrons up (hold-armed) with a 5 s
  pointing bob. The alternating band
  (`components.confirm_band`: OR VIEW MORE ▸ / ◂ TO GO BACK, 5 s swap)
  comes with the kind; inserted automatically as the 6th screen of long
  flows (see Flow shape).
- **detail**: `side`, `label` (16 px semibold caps on the column), `lines` (1–3;
  a line is a str, or `{"str", "weight": "semibold"}` for a name line — Text
  rules, Names), `size` (largest tier that fits), optional `circle_x` /
  `text_x` nudges; `pages` (two or more pages of 1–3 lines at that one
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
  seed-words grid (Text rules, Words), an optional `label` on the bottom
  baseline — the key fingerprint (`flows/firmware`).
- **status**: `bottom` caption; `anim` (default splits on outcome —
  `"qubit"` for done endings, `"resolve"` for cancels
  (`status.default_anim`); `"arrive"` — the resting look arriving on the
  entrance law, for an ending whose work a `lead` film showed; any
  registered animation — the `screens` package adds more), `lead` (a film
  that ends on an empty canvas, played first — `dict(anim="explosion",
  severity="major", busy="RECONNECTING…")`; Motion, Status animations),
  `result` (`"check"` | `"x"` | `None`, default `"check"`),
  `state` (a `colors.STATE` key, default `"done"`; explicit `color` wins),
  `busy` (optional loading caption). Dwell defaults to the animation's
  duration. Unknown names raise — no silent fallback. Extra fields ride
  through to the registered animation — the PIN entry's `pin` (the PIN
  the device accepts), `typed` (what the demo dials), `exit` (`"rest"` /
  `"submit"`), `miss` / `match` (the verdict screen dicts it plays after
  the row fades), `labels` (`screens/pin/pin_entering.py`, Input).

## Pre-ship check

Largest fitting tier used · nothing below 12 px · bottom text on the y 128
baseline · addresses unbroken by ellipsis · one primary value per screen ·
text color matches screen state · gradient only on unknown tokens · the
unknown ramp derived from token identity, never fixed · every screen
answers what left, right, and both holds do · decline reachable until
dispatch · commit screens fill up before their ending (a see-through
film: black over coloured discs, white inside black ones — the glyph stays).
