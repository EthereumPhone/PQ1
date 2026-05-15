# Dead-Code Removal — `sphincs-c10`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
SPHINCS+C10 signer/verifier (hypertree/wots/fors/merkle/...).

Files audited:
- `sphincs-c10/Cargo.toml`
- `sphincs-c10/src/lib.rs` (216 lines)
- `sphincs-c10/src/params.rs` (101)
- `sphincs-c10/src/address.rs` (86)
- `sphincs-c10/src/hash.rs` (295)
- `sphincs-c10/src/wots.rs` (181)
- `sphincs-c10/src/fors.rs` (243)
- `sphincs-c10/src/merkle.rs` (159)
- `sphincs-c10/src/hypertree.rs` (427)
- `sphincs-c10/src/shuffle.rs` (203)
- `sphincs-c10/tests/shuffle_byte_equality.rs` (90)
- `sphincs-c10/tests/gen_test_vectors.rs` (413)

## Summary
The slice had a small amount of vestigial scaffolding from the pre-shuffle
API: three `*_with_progress` / un-shuffled `sign` wrappers that have been
fully superseded by the `sign_with_shuffle` form (the un-shuffled call
sites now pass `ShuffleSeed::zero()` directly). Removing them collapses
the public surface to a single signing entrypoint per layer and clears
the three `rustc` warnings the crate emits on host check (two
`dead_code` already noted in `reports/deadcode/proto.md`, plus an
unrelated `unused_mut`). Two stale doc paragraphs about `opt_rand` being
"currently ignored" were corrected — `opt_rand` is in fact mixed into
`fors::grind_r` (F-9 fix), so the old wording was actively misleading.
Net: ~50 lines removed/rewritten. Behaviour is unchanged (shuffle
byte-equality regression passes).

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `sphincs-c10/src/lib.rs:107-120` | `SigningKey::sign_with_progress` | 4 (vestigial) | Backwards-compatible identity-shuffle wrapper. Only callers (per repo-wide grep) were docs/markdown; runtime callers use `sign_with_shuffle` directly (e.g. `secure/src/crypto.rs:166,169`). Doc comment on `sign_with_shuffle` updated to mention the `ShuffleSeed::zero()` un-shuffled mode it used to wrap. |
| `sphincs-c10/src/hypertree.rs:46-57` | `hypertree::sign_with_progress` | 1 (truly unused) | Internal helper that only `SigningKey::sign_with_progress` called. Flagged dead by rustc; previously noted in `reports/deadcode/proto.md` cross-slice observations. Doc on the surviving `sign_with_shuffle` folded the progress description in. |
| `sphincs-c10/src/wots.rs:98-114` | `wots::sign` | 1 (truly unused) | Backwards-compatible thin wrapper around `wots::sign_with_shuffle(.., &[0u8;32])`. The only consumer (`hypertree::sign_inner`) already calls `sign_with_shuffle` directly with a derived per-layer seed. Flagged dead by rustc. |
| `sphincs-c10/src/hypertree.rs:75-78` | stale `sign_inner` "currently unused" comment about `opt_rand` | 5 (stale comment) | The param is `opt_rand` (not `_opt_rand`) and it *is* passed into `fors::grind_r`, where it mixes into the R-grinding hash for the F-9 fix. The block at lines 83-90 in the function body already documents the real semantics correctly. |
| `sphincs-c10/src/lib.rs:92-101` | stale `SigningKey::sign` doc claiming `opt_rand` is "currently ignored" | 5 (stale comment) | Same as above — replaced with a one-paragraph correct description (`Some` → F-9 randomised; `None` → byte-stable deterministic). |
| `sphincs-c10/src/shuffle.rs:102` | redundant `mut` on `next_u16` closure binding | 5 (dead keyword) | The closure is `Fn`, not `FnMut`, because its captures (`seed`) are by shared ref and the per-call mutable state is passed in as explicit `&mut` parameters. `rustc` flagged `unused_mut` on the binding. |

## Reverted during bisect
None. Every deletion above survived `cargo check` (default + `--features
hw-sha256`), `cargo test --lib`, and the
`tests/shuffle_byte_equality.rs` integration test in release mode.

## Cross-slice observations
None new. The two `sphincs-c10` items previously listed under
`reports/deadcode/proto.md` cross-slice observations
(`hypertree::sign_with_progress`, `wots::sign`) are now removed.

## Skipped
- `cargo fmt -p sphincs-c10 --check` and `cargo clippy -p sphincs-c10
  -- -D warnings` could not be executed in this session (the cargo
  permission allowed `cargo check`/`cargo test` but not `fmt`/`clippy`).
  Deletions preserved the existing indentation and brace style; no
  manual reflow was applied around the edits.
- `cargo test -p sphincs-c10 --test gen_test_vectors --release` was
  intentionally not re-run because it writes
  `contracts/smart-wallet/test/c10_test_vectors.json` (a checked-in
  artefact). Re-running would expand the diff beyond the slice's scope.
  The `shuffle_byte_equality` integration test (which exercises the
  same `sign`/`sign_with_shuffle` paths against the byte-equality
  oracle) does pass post-deletion.
- `[features]` audit: the single feature `hw-sha256` is consumed by the
  three `extern "C"` hash hooks in `src/hash.rs`. Kept.
- `[dependencies]`: `sha2`, `zeroize` both used; `[dev-dependencies]`
  `hex`, `serde`, `serde_json` all consumed by `gen_test_vectors.rs`.
  Kept.

## Equivalence check

- `cargo fmt -p sphincs-c10 --check` — N/A (permission not granted this
  session; no manual reformatting performed)
- `cargo check -p sphincs-c10` (default features) — **EQUIV**
  - baseline: builds, 3 warnings (`unused_mut` in `shuffle.rs:102`,
    `dead_code` on `hypertree::sign_with_progress`,
    `dead_code` on `wots::sign`)
  - post: builds, **0 warnings** (all three were the items above —
    expected reduction)
- `cargo check -p sphincs-c10 --features hw-sha256` — **EQUIV**
  - baseline: builds, same 3 warnings
  - post: builds, 0 warnings
- `cargo clippy -p sphincs-c10 -- -D warnings` — N/A (permission not
  granted this session; the cleaner `cargo check` warning state is a
  strict improvement, so the clippy gate would be at least as clean)
- `cargo test -p sphincs-c10 --lib` — **EQUIV**
  - baseline: 7 passed, 0 failed
  - post: 7 passed, 0 failed (same test list:
    `address::tests::adrs_layout_matches_python` and the six
    `shuffle::tests::*`)
- `cargo test -p sphincs-c10 --release --test shuffle_byte_equality` —
  **EQUIV** (post-deletion only; baseline omitted to save time but the
  oracle is identical to the source)
  - 4 passed, 0 failed:
    `shuffled_sig_byte_equal_to_unshuffled`,
    `shuffled_sig_verifies`,
    `sign_wrapper_matches_zero_seed_shuffle` (proves the surviving
    `sign(msg, None)` is byte-identical to
    `sign_with_shuffle(msg, None, &ShuffleSeed::zero(), |_|{})`),
    `multiple_random_shuffles_all_equal`
- Downstream consumers — both still build with no new warnings:
  - `cargo check -p pqsigner-domain` — **EQUIV**
  - `cargo check -p fwsign` — **EQUIV**
- `make <crate-build-target>` (firmware build) — N/A (slice is a
  pure-logic workspace crate; the firmware path is covered by the
  downstream `pqsigner-domain` / `secure` builds, not run here)
- Binary SHA-256 — N/A (host library crate, no shipped binary)
