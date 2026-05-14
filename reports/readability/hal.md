# Readability & Excellence Review — `hal`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-hal` is a small, single-file trait-only crate (≈300 LOC) that
serves as the architectural specification for future driver impl crates
(`hal-stm32u5`, `hal-mock`). Quality was already high — clear module
banners, `no_std`, zero deps, well-named traits — so the audit produced a
focused polish pass rather than a refactor. Headline changes: removed
PR-anecdote / phase-history narrative from doc comments and `Cargo.toml`;
fixed a `Platform::sha256` signature inconsistency (returned `Self::Sha256`
by value while every other accessor returned `&mut Self::Foo`); added a
small set of `#[must_use]`, `#[non_exhaustive]`, and missing-derive
hygiene fixes; tightened `BootStage::ALL` to `Self`; documented the
`SpiBus::xfer` length contract. No public ABI consumed by other crates
(none exists yet — this crate is spec-only) was meaningfully changed.

## Changes applied

- `hal/Cargo.toml` — replaced the multi-paragraph "Phase 6 PR 1 of the
  modularity refactor — PR 2 (`hal-stm32u5/`…), PR 3 (`hal-mock/`…),
  PR 4 (`secure/src/platform.rs` selects between the two)" narrative
  with a two-line statement of what the crate is. Refactor sequencing
  belongs in `docs/handoff-modularity-refactor.md`, not in package
  manifests where it rots.
- `hal/src/lib.rs:1–16` — same cleanup in the crate-level rustdoc:
  dropped Phase 6 / Phase 7 PR-history references and the
  "until that move lands…" hedge, kept the actual statement of
  intent (trait-only spec, drivers must match signatures verbatim).
- `hal/src/lib.rs` `HalError` — added `#[non_exhaustive]`. New error
  variants are inevitable as drivers come online (e.g. `Provisioning`,
  `RollbackProtected`); the attribute lets us add them without a
  semver bump and forces consumers to keep a wildcard arm.
- `hal/src/lib.rs` `Sha256` doctring — removed
  "the `pqsigner-c10` crate's `pqsigner_sha256_*` extern fns are
  shimmed onto this trait by `hal-stm32u5` once Phase 6 PR 2 lands"
  PR-anecdote sentence. The trait's purpose is self-evident.
- `hal/src/lib.rs` `KeySelector` — added `#[derive(Clone, Copy)]` (all
  variants are trivially copyable; lets callers thread the selector
  without `match`-rebinding) and an explicit `// Intentionally NOT
  Debug` comment so a future contributor doesn't "fix" the missing
  derive and start logging key bytes.
- `hal/src/lib.rs` `BootStateData` — added `Debug, PartialEq, Eq`
  derives. The struct is a 32-byte opaque blob already; no secrecy
  concern, and tests will want the equality / formatting impls.
- `hal/src/lib.rs` `BootState::read`, `Tamp::check`, `Buttons::poll`
  — added `#[must_use]` (return values are the entire point of the
  call; ignoring them is a bug).
- `hal/src/lib.rs` `Buttonset` — added `Debug, PartialEq, Eq`. Same
  rationale as `BootStateData`.
- `hal/src/lib.rs` `SpiBus::xfer` — added a one-line doc clarifying
  that the trait is full-duplex and impls require
  `w.len() == r.len()`. Previously the reader had to infer this from
  the `&[u8]` / `&mut [u8]` pair.
- `hal/src/lib.rs` `Platform::sha256` — fixed signature
  `fn sha256(&mut self) -> Self::Sha256` (return-by-value) to
  `fn sha256(&mut self) -> &mut Self::Sha256`. Every other accessor
  on the trait returns `&mut Self::T`; `Sha256` was the lone outlier
  and the only readable interpretation of the inconsistency is a
  typo. `Sha256` is a stateful streaming digester (`init` / `update`
  / `finalize`), so by-value would also force every call site to
  re-init a fresh hasher per use, defeating the trait's streaming
  shape. Safe to fix now because no code currently implements or
  consumes the trait — all future driver impls will match the
  corrected spec from the start.
- `hal/src/lib.rs` `BootStage` — `pub const ALL: [BootStage; 6]`
  rewritten using `Self` for the array element type and each variant,
  and the doctring's brittle `secure/src/main.rs:356–605` line-range
  reference + Phase-10-PR-C anecdote replaced with a generic "secure
  world entry can drive bring-up as `for stage in BootStage::ALL { … }`"
  sentence.

## Recommendations not applied

- **`OtpRange::Reserved(u8)` / `TamperCause::Other(u8)` escape hatches.**
  Both enums already carry an open variant, which makes
  `#[non_exhaustive]` partially redundant and would force a wildcard
  arm even though `Reserved` / `Other` already serve that role. Left
  as-is — adding `#[non_exhaustive]` here would be churn without
  clear benefit. (`hal/src/lib.rs:126`, `:165`.)
- **Constant-time wrappers on `Sha256` output / `Saes` outputs.** The
  trait surface returns `[u8; 32]` / `&mut [u8; 16]` directly. A
  future hardening pass could wrap secret outputs in newtypes that
  zeroize on drop, but doing so here without a driver to validate
  against risks getting the API shape wrong. Defer to the impl-crate
  PR (Phase 6 PR 2). (`hal/src/lib.rs:69`, `:92`.)
- **Splitting `lib.rs` into per-trait modules** (`error.rs`, `rng.rs`,
  …). At ~300 LOC with banner-separated sections the single-file
  layout is still readable and `git blame`-friendly. Splitting would
  add 12+ files for marginal benefit; revisit only if the trait
  surface grows substantially (e.g. when impl crates add associated
  types or methods).
- **`Platform`-aggregate ergonomics.** Each accessor returns a single
  `&mut Self::T`, which is the right pattern but means callers can
  only borrow one peripheral at a time. A `split` helper that returns
  `(&mut Rng, &mut Sha256, …)` tuples would help for cases that need
  e.g. `rng + saes` simultaneously. Best designed once a real driver
  reveals the borrow-pattern needs; deferred.

## Verification

- `cargo check -p pqsigner-hal` — **PASS** (clean build, no warnings).
- `cargo check -p pqsigner-hal --tests` — **PASS** (no test targets in
  this crate; trivially clean).
- `cargo fmt -p pqsigner-hal --check` — **N/A** (sandbox denied
  `cargo fmt`; matched the convention used by the existing
  `proto.md` / `shared.md` reports). All edits preserve the prior
  4-space / banner-comment style; no whitespace reflow done.
- `cargo clippy -p pqsigner-hal -- -D warnings` — **N/A** (same
  sandbox restriction). The edits are derive additions, attribute
  additions, doc-comment cleanup, and a single signature change —
  none of these patterns are clippy lint targets.
- `cargo test -p pqsigner-hal` — **N/A** (no tests; this is a
  trait-only spec crate with no executable behaviour to assert).

## What this crate already does well

- **Single-responsibility, zero-dep, `no_std`.** The crate boundary
  is a literal trait surface; the `[dependencies]` block is empty
  and proudly so.
- **Banner comments** segment the file by peripheral (`// ---- SHA-256
  accelerator ----`) and make navigation trivial without a TOC.
- **Trait granularity matches drivers.** `Rng`, `Sha256`, `Saes`,
  `Flash`, `Otp`, `BootState`, `Tamp`, `ConsumptionMask`, `I2cBus`,
  `SpiBus`, `Buttons`, `Uart` map 1:1 to peripherals in
  `secure/src/hw/*`, so the eventual impl-crate move is mechanical.
- **`HalError` is intentionally narrow.** Five variants (BusFault /
  Timeout / BadParam / Unsupported / Corrupt) — drivers map richer
  errors down at the trait edge so callers can have one uniform
  `NscStatus::InternalError` mapping. This is the right boundary
  for a HAL.
- **`KeySelector::Software` is gated behind a borrow.** The
  `&'a [u8; 32]` lifetime ensures the secure-world caller can keep
  its key on-stack and zeroize it on scope exit; the trait surface
  never copies it into impl-owned state.

## Cross-crate observations

- `secure/src/hw/*` files don't yet implement the `pqsigner-hal`
  traits. That's tracked as Phase 6 PR 2 in
  `docs/handoff-modularity-refactor.md` §4.2 and is out of scope
  here. Once the impl crates land, the `// Intentionally NOT Debug`
  comment on `KeySelector` should propagate to the impl crate's
  internal types so the no-Debug-on-secrets rule is enforced
  consistently.
- The trait names overlap with `core::hash::Hasher` and the wider
  ecosystem's `embedded_hal::*` traits. Worth noting in the impl
  crates' module docs that `pqsigner-hal` is an internal HAL, not
  an `embedded-hal` impl, so contributors don't reach for the
  `embedded-hal-async` shape by mistake.
