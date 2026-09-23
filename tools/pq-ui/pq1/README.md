# pq1 — the PQ1 design system

Screen-agnostic layout, color, typography, motion and components for the
NV3007 wallet UI (428 × 142). Every current and future screen renders through
these modules so the UI stays consistent by construction. The design rules
themselves — grid anchors, type scale, color semantics, motion timing, screen
schema — are defined in [DESIGN.md](DESIGN.md); this README maps the code.
One file per design aspect:

| module          | owns                                                                 |
|-----------------|----------------------------------------------------------------------|
| `layout.py`     | the grid (canvas size, circle columns, bottom band, chevron slots), `layout_of()`, and the **screen-dict schema** — the canonical spec |
| `colors.py`     | solid palette + semantic states (awaiting/done/failed/warning); 14 placeholder ramps (`PLACEHOLDER_GRADIENTS`, index 13 = `MONO_RAMP`, the logo look) — an **unknown token** hashes onto one, a known token **without an image** picks one; named ramps pinned by name, never hashed (`BRAND_GRADIENTS`: SAFE, COWSWAP, ROTATE, ERC7730, FINGERPRINT, FIRMWARE, USDC, USDT, DAI) |
| `typography.py` | Aileron loader (Regular + SemiBold from `pq1/assets/`, `$PQ1_FONT` overrides; warns if it falls back), the PQ1 type scale 36/32/28/22/18/16/12 (label caps render SemiBold), letter-spacing constants |
| `motion.py`     | easing curves, `Spring` (Apple response/damping parameterization) + the `NAV`/`KIOSK` profiles (one pace for travel, morph and text alpha), timing constants, the two-button input-gesture timings (DESIGN.md § Input) + `hold_fill` (the hold-progress curve), `FollowerChain`, chevron hint envelope |
| `canvas.py`     | the 3× supersampled drawing surface (`Canvas`), LANCZOS downscale in `out()` |
| `components.py` | token circle (solid / unknown variants), glyph registry with image → vector → monogram fallback, `circle_image`, chevrons, caption band, streak trails, pulse ring, the hold fill (`hold_flood` / `hold_style` — the disc filling bottom-up with a 30 % see-through film: black over coloured art, white inside a black body), pills/badges |
| `loading.py`    | the qubit sequence's pose math + drawing (`draw_status`) — the one loading film; its loop region (`QubitCfg.loop`, `loop_ms`) with `film_time` / `wraps_for`, the open-ended film's clock, and the `REVS` / `REVS_LONG` / `TURN_MS` turn tokens |
| `status.py`     | the status-screen engine: one resting look (black disc, state-coloured ring stroke + result glyph — brand families fill the disc instead, `branded_resting`), pluggable animations with the default split on outcome (`default_anim`: `"qubit"` — the film — for done endings; the film-less `"resolve"` for cancels, which land the red X in place with no loading; a failure the host reports after dispatch names the film — `anim="qubit"` + X), the loop / latch contract (`StatusAnim.loops` / `resolve` / `outcome` / `pending`, `t_resolve` a property, `live` / `ready`), the `anim` / `result` / `state` / `busy` / `resting` screen fields; the registry is shared — importing the repo-root `screens` package registers the whole screen library into it |
| `flow.py`       | `Sim(screens)` — drives any list of screen dicts with the PQ1 motion (spring transitions, retargetable mid-flight) and the hold gesture (`hold_begin` / `hold_release` / `hold_commit`; demo loops perform the hold themselves before an ending) — plus `render_flow` / `save_gif` |
| `driver.py`     | `FlowDriver` — the reference implementation of DESIGN.md § Input: taps navigate, holds commit, the hold fill drawn live by the Sim; on an entry (the PIN row, `StatusAnim.interactive`) taps tick, double-taps commit / delete, holds submit / cancel, and the outcome routes (a miss to the next attempt, a match on); on a loading film `answer(now, ok)` — the host's word, the bench's `y` / `n`; the bench player's grammar (`tools/panel/play_flow.py`), not device firmware |
| `verdict.py`    | `VerdictAnim` — the icon-verdict choreography (hold → icon pops in → caption; DESIGN.md § Verdict screens); concrete verdicts live in `screens/verdict/` and register into `status.ANIMS` |
| `gradients.py`  | the forward-facing surface for gradient/ramp material (re-exports the colors.py data) + ramp helpers: `mix`, `brightness_trail`, `band_mask`, `TEAL_RAMP` |
| `procedural/`   | generative icon art, one module per image — `marks` (check / x / exclamation — the marks' home), `shield`, `warning_triangle`, `brush`, `padlock`, `gear`, `heart`, `die3d`, `digit_reel`, `pin_slots`, `pin_pill`, `burst`, `eth` (the mainnet badge), `blind`, `dev`, `download`, `fingerprint`, `rotate` (traced from the SVGs in `assets/`), shared `geometry`; lazy package (import submodules directly) |
| `render.py`     | the standalone-screen harness — `frames_of` + `run` (the shared `-o/--fps/--at/--frames/--scale/--loops` CLI); `python -m screens` renders through it |
| `assets/`       | the bundled faces `Aileron-Regular/SemiBold.otf` (+ `OFL.txt`) so typography is self-contained; token logos (`ETH/USDC/DAI/Tether.svg`, their PNGs, `eth-logo.png`); brand marks (`safe.png`, `cowswap.png`); the icon sources the procedural marks are traced from (`blind_icon`, `dev_icon`, `download_icon`, `rotate_icon`, `fingerprint` SVGs) |

## Using it in a screen

```python
# run from the repo root (or put it on sys.path)
from pq1 import components, layout
from pq1.canvas import Canvas

screen = dict(kind="detail", side="left", icon="eth", label="TO",
              lines=["0x78D8…"], size=22, chev="lr")

cv = Canvas()
L = layout.layout_of(screen)
for t in L["texts"]:
    components.draw_text(cv, t)
c = L["circle"]
components.trail_static(cv, c["cx"], c["cy"], c["r"])
components.token_from_spec(cv, c["cx"], c["cy"], c["r"], screen,
                           glyph_a=c["icon"], glyph_b=c["icon"])
cv.out().save("renders/screens/to.png")
```

Animating needs no new code — describe the screens as a flow in `flows/`
(or drive `pq1.flow.Sim` directly).

## The spring, defined

`motion.Spring` is a damped harmonic oscillator — the classical model
`m·ẍ = −k·(x − target) − c·ẋ` — advanced each frame with the closed-form
solution of that ODE over the frame's `dt`, restarted from the live
position and velocity. Because the solution is exact over any `dt`, the
14 fps panel and a 30 fps preview trace the same curve.

The four physical quantities, and how PQ1 uses them:

| quantity | role in the physics | in PQ1 |
|---|---|---|
| **mass** `m` | inertia: resistance to changes in motion — heavier is slower to pick up speed and carries through farther | fixed at 1 by convention. Only the ratios `k/m` and `c/m` shape the motion, so mass is normalized away; a "heavier" feel is simply a longer `response` |
| **stiffness** `k` | the pull toward the target — stiffer means stronger acceleration and a higher natural frequency `ω = √(k/m)` | never set directly: folded into `response` (seconds) via `ω = 2π / response`, i.e. `k = (2π / response)²`. Profiles: `NAV` 0.40 s (hardware button pace), `KIOSK` 0.55 s (demo loops) |
| **damping** `c` | friction that bleeds off velocity. The *ratio* `ζ = c / (2√(k·m))` sets the character: `ζ < 1` overshoots and rings, `ζ = 1` is critically damped (fastest approach that never overshoots), `ζ > 1` is sluggish | the `damping` argument IS the ratio `ζ`. It is 1.0 everywhere (DESIGN.md § Motion: two buttons carry no momentum, navigation never overshoots) and clamped to ≤ 1.0 — overdamped is never wanted in UI |
| **velocity** `ẋ` | the state the spring carries between frames | `Spring.velocity` (units per second) survives `retarget()`: a press mid-transition redirects the motion from its live speed instead of restarting it — § Input's "presses are never dropped". It is also half the settle test: at the target with ~zero velocity, the spring snaps exactly onto it and sleeps until the next retarget |

So instead of exposing `(mass, stiffness, damping coefficient)`, `Spring`
takes Apple's designer pair — `response` ("how long a settle feels") and
`damping` ("does it overshoot") — which pin down the same physics with two
numbers a designer can reason about.

## Known vs unknown tokens

Solid colors are the primary language. A screen opts into the treatments via
the optional `"token"` field:

```python
dict(..., token=dict(variant="solid", fill=[0, 0, 0], ring=[255, 255, 255]))
```

`variant="solid"` is the default. `variant="unknown"` draws a gradient
disc — reserved for tokens the device does **not** recognize; it is not a
blind-signing indicator. The disc's hue is one of the placeholder ramps,
resolved deterministically from the token's identity, so the same unknown
token always wears the same gradient:

```python
dict(..., token=dict(variant="unknown", address="0x78D8…c081e"))
dict(..., token=dict(variant="unknown", symbol="XYZ"))   # address outranks symbol
```

Without an identity the ramp falls back to the screen's `icon`, then the
neutral grey ramp (`components.token_ramp` is the one resolver; the trail
takes the same ramp). A recognized token that shows its own logo takes the
mono entry — black body, white ring, grey trail:

```python
dict(..., token=dict(palette=colors.MONO_RAMP))   # the SEND flow's ETH
```

A known token that has **no image** uses a placeholder ramp instead:

```python
dict(..., token=dict(palette="USDC"))   # or palette=3 — a ramp index
```

The token fills with the ramp's last stop and its five followers take the
5th → 1st stops (nearest → farthest), so the trail darkens away from the
circle. `palette` implies `variant="solid"`; `colors.ramp_palette(components.token_ramp(spec))`
gives the same `(fill, trail)` for hand-drawn screens (it also reads brand
names — `placeholder_palette` only hashes). A brand name (`palette="SAFE"`)
pins that brand ramp instead of hashing — see DESIGN.md § Color.
