## Dead-Code Removal — `aa`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
ERC-4337 v0.6 UserOp hash + EIP-1271 PersonalSign + ERC-6492 wrapping.

Files audited:
- `aa/Cargo.toml` (22 lines)
- `aa/src/lib.rs` (47 lines)
- `aa/src/userop.rs` (1243 lines)
- `aa/src/eip1271.rs` (224 lines)
- `aa/src/eip6492.rs` (283 lines)

## Summary

This slice is already clean. The recent readability pass (2026-05-14,
`reports/readability/aa.md`) removed the only PR-archeology block,
shaved repeated ABI-offset arithmetic into named helpers, and verified
byte-exact ABI parity with `cast abi-encode` vectors. After that pass,
nothing in the slice qualifies as removable under the dead-code rules:

- Every internal helper (`read_array`, `write_u64_in_word_be`,
  `u64_to_word_be`, `decimal_str`, `write_be_u256_small`) has a live
  caller inside the crate.
- Every `pub` item the secure crate does not currently import
  (`compute_user_op_hash`, `AaUserOpParams`, `KECCAK_EMPTY`,
  `ENTRY_POINT_V06`, `has_magic_suffix`, `eip1271::{domain_separator,
  personal_sign_prefixed_hash, PERSONAL_SIGN_TYPEHASH,
  EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH}`) is declared
  intentional public surface by an explicit docstring or by
  `Cargo.toml` (`Used by … any future host-side reference signer`),
  and the on-crate keccak-preimage tests (`name_hash_is_keccak_of_pqsmartwallet`,
  etc.) make the four EIP-712 domain constants load-bearing for typo
  detection. Removing any of them is an API-surface change, not a
  dead-code deletion.
- No commented-out code, TODOs, FIXMEs, deprecated paths, or
  `#[allow(dead_code)]` shims remain.
- All four direct dependencies (`pqsigner-proto`, `pqsigner-tx-core`,
  `sha2`, `sha3`) are consumed by the source.
- No unused `[features]` entries (none declared).

So this commit only adds the report.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_None — no deletions attempted._

## Cross-slice observations
- `nonsecure/src/main.rs:255`, `nonsecure/src/bench_key_speed.rs:55`,
  `nonsecure/src/e2e_test.rs:40` each redeclare local
  `KECCAK_EMPTY` / `ENTRY_POINT_V06` constants whose canonical
  definitions already live in `pqsigner_aa::userop`. A future
  `nonsecure` dead-code pass could replace each with a
  `use pqsigner_aa::userop::{KECCAK_EMPTY, ENTRY_POINT_V06};`,
  which would also turn the currently-unimported `aa` constants into
  genuinely-consumed public API. Out of scope here.
- `secure/src/tx/eip712/safe/mod.rs:202` defines its own
  `domain_separator` (different `name`/`version` constants than the
  wallet's `("PQSmartWallet", "1")`, so this is intentional — Safe's
  EIP-712 domain is distinct from the wallet's). No action.

## Skipped
- _No pre-existing breakage carried over from baseline._
- The "Recommendations not applied" items from the readability review
  (split `userop.rs` into submodules, narrow `ExecuteCallData.{buf,len}`
  to `pub(crate)`, add `core::error::Error` impls) are refactors, not
  dead-code removal; intentionally out of scope.

## Equivalence check

Since no source files in scope were modified, the equivalence check
is trivially satisfied. Baseline runs:

- `cargo check -p pqsigner-aa` — PASS (clean) → EQUIV
- `cargo test  -p pqsigner-aa` — 35/35 PASS, 0 ignored → EQUIV (35 baseline / 35 post)
- `cargo fmt --check -p pqsigner-aa` — N/A (sandbox denies this `cargo` subcommand in
  the current permission mode; same gap noted in the readability
  report); no `.rs` files were touched, so format equivalence is
  byte-exact by construction.
- `cargo clippy -p pqsigner-aa --all-targets -- -D warnings` — N/A
  (same sandbox denial); no source changes mean any pre-existing
  clippy state is unchanged.
- Firmware/binary equivalence — N/A (`pqsigner-aa` is host-buildable,
  consumed by `secure` via re-export shim; no firmware artefact is
  produced from this crate alone).
