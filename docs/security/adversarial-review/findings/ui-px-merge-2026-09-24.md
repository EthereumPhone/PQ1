# ui-px pixel trusted UI — merge review (2026-09-24)

Merging `origin/ui-px-evt` (mhaas's pixel trusted display + Safe display
refactor) into `feat/pq1-board-target`. Reviewed incoming tip `5c27782e`
against base `77a0fe10`; 5 conflicts resolved.

**Both reviewers said block.** GPT-6 Astra opened with "I would block this
merge"; the 75-agent audit workflow (9.9M tokens, 43 min) produced 22 SURVIVED
and 10 CONTESTED findings. Three fix commits landed on the merge branch. The
branch is **not landed on master**.

| File | What |
|---|---|
| `findings.md` | The full audit — scope, conflict resolutions, findings 1–5, all 22 SURVIVED + 10 CONTESTED |
| `astra-review.md` | GPT-6 Astra's independent review, with its own reproductions |

## Fixed on the merge branch

| Commit | What |
|---|---|
| `7e7a8900` | Atlas fail-open, carried-over chord, unpainted confirm, `Font::tier_at` panic, + 1 |
| `f1fde83a` | Scroll-to-end consent ON — every screen must be viewed before signing |
| `1ab9c248` | Pin the atlas base to the NS boot base (#540 divergence guard) |

The two that mattered most:

**Atlas fail-open (HIGH, found independently by three audit dimensions and by
Astra).** `assets::atlas()` cached the *verdict*, not the bytes: after the first
call it re-parsed live NS flash with no hash check, and `verify_atlas()` never
wrote `BOOT_STATE`, so a failure could not demote a cached pass. Worse,
`ui::lcd::Display::flush` routes every legacy 16x4 page — the consent pages
included — through `px::lcd::paint_legacy`, which used that cached view. So
tampering the NS atlas made `verify_atlas()` fail, which made
`px_confirm_plain()` fall back to the legacy paint, which rendered the consent
screen with the *tampered* glyphs. Now `atlas_verified()` re-hashes on every
call, `atlas_film_frame()` is the only cached path (film only), and
`verify_atlas_inner()` latches both outcomes.

I initially called this unreachable because ITNS is never written. That was
wrong and the audit refuted it: NS does not need to preempt the secure world —
it tampers during ordinary execution, then calls the gateway.

**Consent gate (owner decision).** The pixel path shipped with
`PX_COMMIT_REQUIRES_SEEN_LAST = false`, so the opening hero was commit-armed and
one chord click could sign without any detail screen ever being displayed. The
owner's decision — "all screens should be viewed before the user can sign" —
reversed it to `true`, restoring the legacy scroll-to-end gate on the pixel
route.

## Still open

* **FINDING 1 — the ship-shaped image does not fit, by ~68 KB.** Pre-existing,
  not caused by the merge. This is what the flash-geometry v7 engagement exists
  to solve; see `flash-geometry-v7-2026-09-24.md`.
* **FINDING 3 — two production ship-fence tests fail on the merged tree.**
  `fsbl-tests/tests/rollback_ship_fences.rs` at `:294` and `:443`, one root
  cause: `rng-consumer-audit` sees a raw `rng::fill` in `secure/src/main.rs:1091`
  inside the `se-lcd-diag` screen. The gate scans source TEXT, so a `#[cfg]`-gated
  dev-only call still trips it. Arrived via `435ec6a5` on the `pq1-evt-dfu`
  ancestry, not the pixel work. Fix: allowlist the call site with the
  justification that `se-lcd-diag` is in `PROD_FORBIDDEN`, or route it through
  the reviewed accessor.
* **FINDING 5 — CONFIRMED 2026-09-24, WYSIWYS break on the pixel route.** See
  below.
* `seen_last` is a plain `bool` on the pixel path where the legacy path uses
  `FihBool` — same class as #470.

## FINDING 5, confirmed: the pixel adapter drops rows by matching their text

Astra reported it and flagged that it had not verified reachability; I then
reduced it to the adapter and it reproduces.

`erc7730_screens::is_nav_row` classifies a row by its **text**: anything
beginning `"> "` is taken for the legacy navigation vocabulary, and the field
loop drops it (`erc7730_screens.rs:333`). The proven page keeps that row and the
signature commits to it. So a rendered **value** that begins with a chevron is a
row the user signs but never sees.

Demonstrated by
`a_data_row_beginning_with_a_chevron_is_dropped_from_the_pixel_transcript` in
`secure/src/display_under_test/structured_screens_render_pure_tests.rs`, which
drives the adapter directly: a body page of `NAME` / `> Alice` lifts to a
transcript with no `Alice` anywhere.

Why the existing gates miss it: the render-faithfulness differential checks
every hex run >= 8 and every decimal run >= 2 of the legacy pages against the
screen text. `"> Alice"` is neither, so alphabetic content is unchecked.

A second consequence of the same textual test: `is_confirm_page` is "every row
empty or nav", so a page whose only content row is `"> Alice"` classifies as a
**confirm page**.

**Toward a fix.** Every chevron-prefixed navigation row in the tree is written
to **row index 3** (`erc20_known.rs`, `erc20_unknown.rs`, `value_transfer.rs`,
`erc8213.rs`, `forced_blind.rs` — all `pages.buf[p][3]`). So position is a far
better discriminator than text. The principled fix is structural: the renderer
knows which rows it emitted as navigation, and the adapter should be told rather
than guess. The minimum honest fix is to refuse rather than silently drop — a
display adapter that decides what to show by pattern-matching the text it is
showing is wrong regardless of which calldata can reach it today.
