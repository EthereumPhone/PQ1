# Dead-Code Removal — `zk-test`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Groth16 test harness.

Files audited:
- `zk-test/Cargo.toml` — 10 lines
- `zk-test/src/main.rs` — 332 lines

## Summary
`zk-test` is a single-file host binary that exercises the same Poseidon + Groth16
verification path the secure world runs, against ZKlarity's `proof_supply.json`
vector. Every function (`scalar_from_le`, `sbox`, `mds_mix`, `poseidon_perm`,
`pad_mds`, `poseidon_bytes`, `hex_fingerprint`, `sha256`, `g1_from`, `g2_from`,
`VerificationKey::parse`), every constant (`MAX_T`, `BYTES_PER_BLOCK`, `G1_BYTES`,
`G2_BYTES`), and every included module (`poseidon_constants`, `test_vectors`,
`vk_data`) is reached from `main()`. Both arms of the `poseidon_bytes` match
(`3` and `6`) are exercised by the two call-sites (164-byte calldata → 6 blocks,
64-byte readable → 3 blocks). The three `#[allow(dead_code)]` annotations
exist because the included files (`poseidon_constants.rs`, `test_vectors.rs`,
`vk_data.rs`) live under `secure/src/zk/` and export a superset of items;
removing the `allow` would re-introduce warnings about the unused items
in those out-of-scope files. Both workspace dependencies (`bls12_381`, `sha2`)
are used. No `TODO`/`FIXME`/`deprecated` markers, no commented-out code blocks,
no stale doc references. **Slice is clean — no deletions.**

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_(none — no deletions were attempted)_

## Cross-slice observations
None within review window.

## Skipped
The three `#[path = "../../secure/src/zk/..."]` includes pull in files outside
the `zk-test/` scope. Any dead items inside those files belong to the `secure`
slice and were intentionally left untouched.

## Equivalence check
- `cargo fmt -p zk-test --check` — N/A (sandbox-blocked, consistent with prior slices)
- `cargo check -p zk-test` (default features) — EQUIV (clean compile, 0 warnings, pre & post identical since no source changes)
- `cargo check -p zk-test` (extra feature combos): N/A (crate has no `[features]`)
- `cargo clippy -p zk-test -- -D warnings` — N/A (sandbox-blocked)
- `cargo test -p zk-test` — EQUIV (0 tests; harness is a runnable binary, not a `#[test]` suite — test count baseline 0, post 0)
- (firmware crates) `make <crate-build-target>` — N/A (host-only binary, targets the host triple)
- (firmware crates) binary SHA-256 — N/A
