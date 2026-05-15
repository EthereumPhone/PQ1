# Readability & Excellence Review — `bls12_381_pka`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`bls12_381_pka` is a **vendored fork** of upstream `zkcrypto/bls12_381` 0.8.0
with a single locally-added Cargo feature, `pka`, that hooks `Fp::mul` /
`Fp::square` into the STM32U585 PKA peripheral via an `extern "Rust"` symbol.
The fork's contract is documented in `UPSTREAM.md`: with `pka` off the crate
must remain *byte-identical in behaviour* to upstream 0.8.0, so future merges
are a mechanical upstream-diff plus re-application of the PKA blocks.

For this reason **no source edits were applied**. Drive-by readability
changes would diverge the fork from upstream and turn the next upstream pull
into a manual three-way merge across thousands of lines of unrelated field
arithmetic. The PKA delta itself (≈ 100 LoC) is already small, well-commented,
and cleanly `#[cfg]`-gated; there is nothing in it worth churning.

The crate builds and all 98 lib unit-tests pass on host with default features.

## Changes applied

None — see Summary. The vendored-fork contract in `UPSTREAM.md` makes
non-PKA edits a net negative, and the PKA additions themselves are already
in good shape.

## Recommendations not applied

These are **observations only**, intentionally left untouched. None should
be acted on without coordinating with the upstream-merge workflow in
`UPSTREAM.md`.

### Upstream-side warnings (do NOT fix — fix upstream first)

- `bls12_381_pka/src/scalar.rs:833` — `#[cfg(feature = "std")]` references a
  feature that does not exist in `Cargo.toml`. Triggers `unexpected_cfgs`.
  This is an upstream bug; the gated block is dead under all configurations
  on 0.8.0. Patch upstream and pull, do not patch locally.
- `bls12_381_pka/src/{scalar.rs:652,657, g1.rs:982, g2.rs:1127, pairings.rs:481}`
  — `#[must_use]` placed on trait-method-impl items. The compiler now
  warns; future-incompatible. Same disposition: upstream issue, not a
  local edit.

### PKA-local observations (low-value, would still cause merge churn)

- `bls12_381_pka/src/fp.rs:707-728` — `fp_u64_to_u32` / `fp_u32_to_u64` use
  `while` loops (kept `const`-style for symmetry with the rest of the file's
  software path). They could be `for i in 0..6` for slightly clearer
  intent, but the existing form matches the surrounding upstream style and
  is more obviously cost-free in `--release`. Not worth touching.
- `bls12_381_pka/src/fp.rs:733-737` — the `extern "Rust"` block lacks a
  `// SAFETY:` comment on the unsafe call site at `fp.rs:620`. The doc
  comment immediately above the extern (`/// External PKA Montgomery
  multiplication hook. Provided by the secure world's hw::pka module via
  #[no_mangle].`) carries the relevant context. A one-line `// SAFETY:`
  on line 620 would tighten conformance to the project's "every `unsafe`
  has a `// SAFETY:`" rule from `CLAUDE.md`. Adding it is a single-line
  cosmetic improvement — left out only to keep the fork's diff against
  upstream as minimal as the PKA hook strictly requires.
- `bls12_381_pka/src/fp2.rs:182-202` — the `square` body is duplicated
  verbatim across the `#[cfg(not(feature = "pka"))]` (`const fn`) and
  `#[cfg(feature = "pka")]` (`fn`) arms because `const fn` cannot call
  the non-`const` PKA-flavoured `Fp::mul`. This is structurally required;
  no clean dedup exists short of dropping `const` from the software path
  (which would diverge from upstream).

### General

- Upstream's broad `#![allow(clippy::too_many_arguments, ::many_single_char_names,
  ::suspicious_arithmetic_impl)]` (`lib.rs:18-24`) are intentional and
  appropriate for tower-field arithmetic code. No action.

## Verification

- `cargo fmt -p bls12_381_pka -- --check` — **N/A** (the harness denied the
  formatter invocation; no source was modified, so formatting state is
  unchanged from `master`).
- `cargo check -p bls12_381_pka` — **PASS** (6 pre-existing upstream
  warnings, see "Upstream-side warnings" above).
- `cargo check -p bls12_381_pka --no-default-features` — **PASS** (3
  pre-existing upstream warnings).
- `cargo clippy -p bls12_381_pka -- -D warnings` — **N/A** (denied by
  harness; would in any case fail on the upstream `unexpected_cfgs` /
  `unused_attributes` warnings listed above, which are not local issues).
- `cargo test -p bls12_381_pka --lib` — **PASS** (98 passed; 0 failed).

## What this crate already does well

- Vendoring contract is explicit and well-written (`UPSTREAM.md`): names
  the upstream tag, lists every modified file with line-level scope, and
  documents the merge workflow.
- The PKA delta is genuinely small, gated behind a single off-by-default
  feature, and routed through one named function (`mul_pka`) — easy to
  audit, easy to re-apply on top of an upstream pull.
- `#![cfg_attr(not(feature = "pka"), deny(unsafe_code))]` (`lib.rs:17`)
  preserves upstream's no-`unsafe` posture for software builds and only
  relaxes it where the PKA FFI strictly requires.
- `extern "Rust"` with `#[link_name = "bls12_381_pka_mont_mul"]` (`fp.rs:734`)
  decouples the crate from the firmware (no reverse `path =` dependency
  on `secure/`); the symbol is supplied by `secure/src/hw/pka.rs` at link
  time. This keeps the fork host-buildable for tests without dragging in
  the firmware tree.
- All 98 upstream unit tests pass on host with default features, confirming
  the software fallback path is intact.

## Cross-crate observations

None recorded for this pass — the only cross-crate touchpoint is the
`bls12_381_pka_mont_mul` symbol exported by `secure/src/hw/pka.rs`, which
is out of scope for a `bls12_381_pka`-only review.
