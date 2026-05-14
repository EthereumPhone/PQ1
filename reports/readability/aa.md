# Readability & Excellence Review — `aa`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-aa` is a small, well-scoped, `no_std` crate that already
follows the project's conventions: zero `unsafe`, no heap, fixed-size
stack buffers, documented wire formats, and parity tests against
hand-encoded ABI references. The bulk of the review work was to
shave ad-hoc offset arithmetic and repeated "right-align u64 into a
32-byte ABI word" idioms into a few named helpers (`WORD`,
`SELECTOR_LEN`, `write_u64_in_word_be`, `u64_to_word_be`,
`read_array<N>`), unify hash-finalization style on the
`Digest::digest(...).into()` idiom, drop a stale PR-history comment,
and add `#[must_use]` to pure-compute functions. All 35 tests still
pass byte-for-byte against the existing cross-validated ABI vectors,
so on-wire output is provably unchanged.

## Changes applied

- `aa/src/userop.rs:64` — removed the 7-line "Phase 5 PR 5.2 deleted
  the local consts" PR-archeology block; the `pub use`s below speak
  for themselves.
- `aa/src/userop.rs:64` — added module-private `WORD = 32` and
  `SELECTOR_LEN = 4` constants and small ABI helpers
  `write_u64_in_word_be`, `u64_to_word_be`, `read_array::<N>` so the
  three encoders stop spelling out magic offsets.
- `aa/src/userop.rs:123` (`reconstruct_execute_calldata`) — rewrote
  the body around a single advancing cursor `p` plus
  `write_u64_in_word_be`. The arithmetic that used to be
  `4 + 96 + 12` / `4 + 160 + 24` etc. is now explicit
  `SELECTOR_LEN + n * WORD` steps that match the docstring's layout
  sketch one-for-one.
- `aa/src/userop.rs:238` (`reconstruct_execute_batch_calldata`) —
  same cleanup; the five head words are now driven by a small
  `[u64; 5]` table so the per-slot index arithmetic only appears
  once; targets/values/datas writes use `write_u64_in_word_be`
  instead of slicing `[off + 24..off + 32]` by hand.
- `aa/src/userop.rs:380` (`compute_user_op_hash`) — replaced the ten
  hand-numbered offsets (`buf[64..96]`, `buf[96..128]`, …) with a
  small `[&[u8]; 10]` row table and a right-alignment loop, removing
  ~25 lines of repetitive arithmetic. Switched the final keccak to
  `Keccak256::digest(outer).into()` for parity with the rest of the
  crate.
- `aa/src/userop.rs:430` (`parse_header`) — replaced four repeated
  `let mut x = [0u8; N]; x.copy_from_slice(&buf[p..p+N]); p += N;`
  blocks with a single `read_array::<N>` helper. Also dropped the
  separate `read_u256` (its only caller is `parse_header`); turbofish
  reads now flow into `U256(read_array(buf, &mut p))`. Removes
  `&buf` reborrow at every call site.
- `aa/src/userop.rs:572` (`compute_sphincs_digest_v06`) — collapsed
  the imperative `let mut h = …; h.update(…); …; out.copy_from_slice`
  into a chained `Sha256::new().chain_update(…).…finalize().into()`;
  chainId word now goes through `u64_to_word_be`. Net −8 lines, no
  intermediate buffer.
- `aa/src/userop.rs:597` (`sha256_bytes`) — collapsed to
  `Sha256::digest(data).into()`.
- `aa/src/userop.rs` — added `#[must_use]` to `ExecuteCallData::as_slice`,
  `ExecuteBatchCallData::as_slice`, `compute_user_op_hash`,
  `compute_sphincs_digest_v06`, `sha256_bytes`. (Discarding any of
  these is always a bug.)
- `aa/src/eip1271.rs` — added `#[must_use]` to `proxy_address`,
  `domain_separator`, `personal_sign_prefixed_hash`,
  `personal_sign_replay_safe_hash`.
- `aa/src/eip6492.rs:42` — fixed the doc-comment that claimed "All
  slots are filled — there is no need to pre-zero `out`" while the
  body unconditionally `out.fill(0)`s for the factoryCalldata
  padding. The new wording matches reality.
- `aa/src/eip6492.rs:129` (`write_be_u256_small`) — replaced the
  `for b in &mut slot[..24] { *b = 0; }` loop with `slot[..24].fill(0)`.
- `aa/src/eip6492.rs:139` — `#[must_use]` on `has_magic_suffix`.

## Recommendations not applied

- **Split `userop.rs` into submodules.** It's 1226 lines (~600 of
  prod code, ~620 of tests), and conceptually four concerns live in
  one file: single-tx encode, batch encode, wire parse, and the two
  hashing functions. A `userop/{execute, execute_batch, hash, wire}`
  split would aid navigation but is mechanical churn that risks
  cross-references and would push the diff well past the ~300-line
  budget called for in the prompt. Worth doing in a dedicated PR.
- **Tighten `ExecuteCallData.{buf,len}` / `ExecuteBatchCallData.{buf,len}`
  to `pub(crate)`.** Downstream callers (`secure/src/nsc/cmd_sign_userop*.rs`)
  only use `.as_slice()` and the field-direct accesses live inside
  the crate's own tests, so this is safe in principle. Skipped to
  avoid touching the public surface area in the same PR as the
  refactor; if a follow-up shows the fields are still unused
  externally, this is a one-liner.
- **`AaError` / `BatchAaError` / `WireParseError` are not
  `core::error::Error`.** Stable since 1.81 and the crate is
  `no_std`-compatible. Adding the impls is two lines apiece and
  would let host-side reference signers fold the errors into
  anyhow/thiserror chains. Skipped because no caller asks for it
  yet and impl'ing `core::error::Error` would lock in the MSRV.
- **`decimal_str` in `eip1271.rs:153`** could be replaced by an
  `itoa`-style direct write. The current digit-then-reverse code is
  readable and correct; rewriting would be churn for no readability
  win.

## Verification

- `cargo check -p pqsigner-aa` — PASS
- `cargo check --target thumbv8m.main-none-eabi -p pqsigner-aa` — PASS (no_std consumer compiles)
- `cargo test -p pqsigner-aa` — PASS (35/35; the byte-exact ABI
  cross-validation vectors in `test_reconstruct_cross_validate` and
  `test_batch_cross_validate_n1` are the binding evidence that no
  on-wire output changed)
- `cargo clippy -p pqsigner-aa -- -D warnings` — **N/A in this
  session**: the local sandbox blocks `cargo clippy` invocations;
  ran `cargo check` (above) instead, which catches the same
  compiler-level errors. No new `#[allow]`s introduced; helpers added
  follow standard `#[inline]` / `#[must_use]` annotations.
- `cargo fmt -p pqsigner-aa --check` — **N/A**: blocked in the same
  way. Edits follow rustfmt defaults (4-space, 100-col-ish) by hand.

## What this crate already does well

- Zero `unsafe`, zero heap; everything sits on the stack with
  fixed-size buffers wired to `pqsigner-proto` constants — invariant #4 (`CLAUDE.md`)
  preserved by construction.
- The on-wire ABI for `executeWithOffchainCount` and
  `executeBatchWithOffchainCount` has docstrings that *show* the
  byte layout, and tests that cross-validate against a hand-encoded
  reference (`test_reconstruct_cross_validate`,
  `test_batch_cross_validate_n1`). That's exactly the right shape
  for code whose output is a frozen on-chain target.
- `eip1271.rs` keeps `PERSONAL_SIGN_TYPEHASH`,
  `EIP712_DOMAIN_TYPEHASH`, `NAME_HASH`, `VERSION_HASH` as compile-time
  constants and *also* has unit tests that re-derive each from the
  original keccak preimage — so a typo in any constant is a build-time
  test failure, not a silent on-chain mismatch.
- Public surface is split cleanly: `userop` (chain-side), `eip1271`
  (off-chain PersonalSign), `eip6492` (counterfactual). Re-exports
  from `pqsigner-proto` keep the Solidity/Rust constants in lockstep.
- No `unwrap`/`expect` in production paths; all error paths surface
  through `AaError` / `BatchAaError` / `WireParseError`.

## Cross-crate observations

- `secure/src/aa/mod.rs:42-44` is a perfect candidate for
  `pub use pqsigner_aa::{eip1271, eip6492, userop};` on a single
  line; the current three-line form is harmless but the surrounding
  docstring still mentions "an `init_code` helper" that was removed —
  that mention could be trimmed.
- `secure/src/nsc/cmd_sign_userop.rs:75` and
  `secure/src/nsc/cmd_sign_userop_batch.rs:54` both import the same
  five symbols from `aa::userop`. If the secure crate ever grows a
  shared `nsc/aa_imports.rs` for these (and the `compute_*` /
  `reconstruct_*` pair), the duplicate `use` blocks would collapse.
- `fuzz/fuzz_targets/aa_userop_parse_header.rs` is correctly
  parameter-less and pulls `pqsigner_aa::userop` directly — no
  action needed, just nice to confirm the public symbol is still
  reachable after this PR.
