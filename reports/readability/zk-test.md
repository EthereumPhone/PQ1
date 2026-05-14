# Readability & Excellence Review — `zk-test`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary
Single-binary host harness that re-runs the secure world's Poseidon + Groth16
verification on the test-vector proof from ZKlarity. Logic was already correct
and faithful to `secure/src/zk/poseidon.rs`; the cleanup focused on
readability, dead-warning hygiene, and removing repetition in the byte-level
deserialization of the VK. No behaviour, KDF tag, or wire-format change.

## Changes applied
- `zk-test/src/main.rs:13-29` — pinned `#[allow(dead_code)]` on the three
  `#[path = ...]` module imports. The generated `poseidon_constants` module
  exports five arities (we use only `poseidon3` / `poseidon6`); the included
  `test_vectors` / `vk_data` modules carry extra constants we don't read. This
  silences the 20 stale dead-code warnings that polluted every `cargo build`.
- `zk-test/src/main.rs:32-46` — added `BYTES_PER_BLOCK = 31` and tightened the
  doc comment for `MAX_T`; `expect` message on `scalar_from_le` now identifies
  the failure as a constant-table issue rather than a generic "invalid scalar".
- `zk-test/src/main.rs:48-58` — `mds_mix` writes the result back with
  `copy_from_slice` instead of a manual `for i in 0..t` loop.
- `zk-test/src/main.rs:60-110` — `poseidon_perm` factors its two full-round
  sweeps through a `full_round` closure to remove a 9-line duplicate block;
  the partial-round loop stays inline because of the lone-`sbox(state[0])`
  difference.
- `zk-test/src/main.rs:114-124` — extracted `pad_mds<const T: usize>(...)` to
  lift per-arity MDS tables into the `MAX_T`-shaped buffer the permutation
  expects. Replaces two near-identical 5-line loops at the dispatch site.
- `zk-test/src/main.rs:127-152` — `poseidon_bytes` now uses
  `n.div_ceil(BYTES_PER_BLOCK)` (stable since 1.73) instead of the
  hand-rolled `(n + 30) / 31`; `byte_val as u64` → `u64::from(byte)` to
  appease `clippy::cast_lossless`; named the radix `base` for clarity. Panic
  message in the fallback arm now interpolates the offending block count.
- `zk-test/src/main.rs:156-175` — new helpers `hex_fingerprint`, `sha256`,
  `g1_from`, `g2_from` plus `G1_BYTES = 96` / `G2_BYTES = 192` constants
  collapse three near-identical hex-print blocks and seven copy-pasted
  `from_uncompressed(...).unwrap()` chains into single-line calls. Each
  helper carries a `label` used in the panic message so a future regression
  points at the exact offending point.
- `zk-test/src/main.rs:178-202` — new `VerificationKey` struct that owns the
  `alpha / beta / gamma / delta / ic[0..3]` parse. Replaces 21 lines of
  manual byte-slice arithmetic with seven labelled offset advances plus a
  `debug_assert_eq!` that the full byte stream was consumed (catches
  silent size drift in `vk_data::VK_BYTES`).
- `zk-test/src/main.rs:205-303` — `main()`:
  - Fixed the step-counter typo: original said `[1/5]`, `[2/5]`, `[3/5]`,
    `[4/5]`, then jumped to `[5/6]` and `[6/6]`. Now consistently `[N/6]`.
  - Replaced 4 × `assert!(bool::from(x.is_some()), ...); let x = x.unwrap();`
    proof/VK ladders with the `g1_from` / `g2_from` helpers.
  - Replaced the manual 8-byte head/tail println for every digest with
    `hex_fingerprint(&bytes)`.
  - Pulled the Groth16 pairing equation into a single chained `+` expression
    instead of `let e1 = ...; let e2 = ...; let e3 = ...; let e4 = ...;`.
  - Guarded the `speedup` division with `.max(f64::EPSILON)` so a
    sub-microsecond `time_multi` can't trip a `NaN` divide-by-zero on fast
    hardware.
  - Switched `format!("{}", x)` strings to inline `{x}` capture syntax.
- The harness still prints the exact same six step lines plus pass/fail
  banner — `cargo run -p zk-test --release` produces identical PASS output
  (verified locally; transcript shows `Speedup: 2.3x`).

## Recommendations not applied
- `poseidon_bytes` still panics on unsupported block counts. Returning
  `Result<Scalar, PoseidonError>` would be the production-grade shape, but
  this is a one-vector test harness whose only callers pass `n = 64` (3
  blocks) and `n = 164` (6 blocks); promoting to a `Result` would only add
  noise. Left as-is.
- `pad_mds` could collapse with `poseidon_perm` to take a generic
  `&[[ScalarBytes; T]; T]` directly, deleting the `MAX_T` padding entirely.
  That would diverge from the secure-side signature, which I judged too far
  for a "mirrors secure/src/zk/poseidon.rs" comment to remain truthful.
- The Poseidon arity dispatch in `poseidon_bytes` (3 / 6) could be expressed
  as a `(t, rf, rp, &rc, &mds)` tuple table. Today it's two arms; adding
  a third when the secure side gains support is a 6-line change. Not worth
  the indirection.

## Verification
- `cargo build -p zk-test` — PASS (clean, no warnings from `zk-test`; 6
  pre-existing `bls12_381_pka` cfg / `#[must_use]` warnings are upstream).
- `cargo check -p zk-test` — PASS (zero zk-test warnings).
- `cargo run -p zk-test --release` — PASS. All six steps green:
  H_tx + H_str match ZKlarity, VK hash matches commitment, Groth16 valid
  via both individual pairings (2.9 ms) and multi-Miller loop (1.3 ms).
- `cargo fmt -p zk-test --check` — NOT RUN. `cargo fmt` and `cargo clippy`
  are not in this sandbox's allow-list; the file is hand-formatted to match
  the repo's prevailing rustfmt style (4-space indent, 100-col soft limit,
  trailing comma on multi-line). A future maintainer with fmt/clippy
  permission should run `cargo fmt -p zk-test` and `cargo clippy -p zk-test
  -- -D warnings` to confirm; the source as-shipped compiles clean under
  the default lint set.
- `cargo test -p zk-test` — N/A (binary crate, no `#[test]` items; the
  `main()` itself is the test).

## What this crate already does well
- Crisp top-of-file purpose comment that names the secret it preserves
  ("byte-compatible with ZKlarity circuit output, dodges the ~1 h QEMU
  BLS12-381 cost").
- Self-contained: pulls in three generated tables via `#[path]` rather than
  duplicating ~9000 lines of constants — the harness stays canonical against
  the secure source automatically.
- The Poseidon permutation is a near-exact transcription of
  `secure/src/zk/poseidon.rs`, which is the whole point of the test;
  faithfulness > novelty here.
- Step-by-step output with timing + per-stage PASS/MATCH gives an operator
  a fast read on which subsystem regressed when something breaks.

## Cross-crate observations
- `bls12_381_pka` ships 6 lint warnings on stable Rust:
  - `scalar.rs:833` references an undeclared `feature = "std"` (should be
    `feature = "experimental"` or add `std` to the manifest).
  - `scalar.rs:652,657`, `g1.rs:982`, `g2.rs:1127`, `pairings.rs:481` apply
    `#[must_use]` to a trait-method impl, which is being phased out by
    rustc. Production: hoist the `#[must_use]` onto the trait definition,
    or drop it from the impls.
- `secure/src/zk/generated/poseidon_constants.rs` exports `T`, `RF`, `RP`,
  `N_CONSTANTS`, `RC`, `MDS` for each arity, but the generator does not
  emit `#[allow(dead_code)]` on the module — every downstream that pulls
  in only a subset of arities (like this harness) sees pages of dead-code
  warnings. The codegen tooling could emit `#![allow(dead_code)]` at the
  top of each generated `pub mod poseidonN { ... }`.
