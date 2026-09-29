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
* **FINDING 3 (#754) — two production ship-fence tests fail on the merged tree.**
  `fsbl-tests/tests/rollback_ship_fences.rs` at `:294` and `:443`, one root
  cause: `rng-consumer-audit` sees a raw `rng::fill` in `secure/src/main.rs:1091`
  inside the `se-lcd-diag` screen. The gate scans source TEXT, so a `#[cfg]`-gated
  dev-only call still trips it. Arrived via `435ec6a5` on the `pq1-evt-dfu`
  ancestry, not the pixel work. Fix: allowlist the call site with the
  justification that `se-lcd-diag` is in `PROD_FORBIDDEN`, or route it through
  the reviewed accessor.
* **FINDING 5 (#751) — CONFIRMED end-to-end 2026-09-24, WYSIWYS break on the
  pixel route.** See below.
* `seen_last` is a plain `bool` on the pixel path where the legacy path uses
  `FihBool` — same class as #470, recorded there as a comment. It became
  load-bearing when `f1fde83a` turned the consent gate ON: a single-fault flip
  of that bool now buys exactly the bypass the gate was turned on to prevent.

## FINDING 5 (#751), confirmed end-to-end: the pixel adapter drops rows by text

Astra reported it and flagged that it had **not** verified reachability. Both
halves now reproduce.

`erc7730_screens::is_nav_row` classifies a row by its **text**: anything
matching the legacy navigation vocabulary is dropped by the field loop
(`erc7730_screens.rs:333`). The proven page keeps that row and the signature
commits to it. The vocabulary is not reserved, so a rendered **value** that
collides with it is a row the user signs but never sees.

**Reachable today, with the shipped corpus.** `calldata-celo_accounts.json`
(Celo Accounts, chain 42220) admits `setName(string name)` with
`format: "raw"`, `visible: always` — the attacker's string goes straight onto a
row. `setName("> Alice")` renders:

```
NAME

7 bytes
```

The name is gone. `setName("> Alice")` and `setName("> Carol")` differ on the
trusted display in **exactly one place**, measured by diffing the transcripts:

```
-0xae284c3e3e2d0a4a1f5032b0ca416b78e50f09f2b5cc00bd08981918faef54a6
+0x88a23209505ecf8de0964aa0db846733e6afdc189a289cfa3ec8513bfc5707b3
```

That is the ERC-8213 calldata digest. Everything else is byte-identical, so the
only thing separating two different signed operands on the device is a hash the
user would have to recompute off-device — blind signing with extra steps, inside
the flow whose whole purpose is that it is not.

**Wider than the chevron.** Measured: `"vote > next"`, `"ok > sign"`,
`"R=Confirm"` and `"to confirm"` are all signed and never displayed.

**Why nothing caught it.** The render-faithfulness differential checks every hex
run >= 8 and decimal run >= 2 of the legacy pages against the screen text.
`"> Alice"` is neither, so alphabetic content is unchecked. Second consequence of
the same textual test: `is_confirm_page` is "every row empty or nav", so a page
whose only content row is `"> Alice"` classifies as a **confirm page**.

**Evidence** — `7099dc48` on `merge/ui-px-evt`, in
`secure/src/display_under_test/structured_screens_render_pure_tests.rs`. Two
controls first, without which a failure proves nothing:
`control_an_ordinary_field_value_reaches_the_pixel_transcript` (the hand-built
page shape lifts at all) and `control_celo_set_name_reaches_the_pixel_transcript`
(`setName("Alice")` renders end-to-end through the real descriptor, decoder and
renderer). Both pass, so the only variable left in the probes is the value's
text. `measured_two_chevron_names_differ_only_by_the_erc8213_digest` asserts the
**broken** behaviour, pinning the finding before a fix exists. The four probes
themselves are `#[ignore]`d so the branch is not red.

**Toward a fix.** Every chevron-prefixed nav row in the tree is written to **row
index 3** (`erc20_known.rs`, `erc20_unknown.rs`, `value_transfer.rs`,
`erc8213.rs`, `forced_blind.rs` — all `pages.buf[p][3]`), so position
discriminates better than text. But position alone is **not** sufficient: the
confirm-page vocabulary spans several rows and a body page's row 3 can hold
data. In order of durability: (1) structural — the renderer knows which rows it
emitted as navigation, so carry that out of the page painter instead of
re-deriving it downstream; (2) until then, **refuse** rather than silently drop,
matching the codebase's hard-refuse discipline; (3) widen the differential from
hex/decimal runs to all non-nav text, which catches the class rather than the
instance.

**Caveat.** The harness renders the leaf with the `! DEV BUILD / Unattested
descriptor` banner, because `synth_bundle` synthesises the attestation. The
field-rendering path is the same one an attested descriptor takes — the control
proves an ordinary value renders through it — but reachability on a
production-attested corpus should be confirmed before severity is finalised.
