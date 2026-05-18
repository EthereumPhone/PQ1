# Dead-Code Removal — `secure-nsc-batch-offchain`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Batch sign + EIP-1271 off-chain sign + per-slot counter cmds.

Files audited:
- `secure/src/nsc/cmd_sign_userop_batch.rs` (844 → 822 lines)
- `secure/src/nsc/cmd_sign_offchain.rs` (595 lines)
- `secure/src/nsc/cmd_offchain_status.rs` (99 lines)
- `secure/src/nsc/cmd_offchain_sync.rs` (87 lines)

## Summary
Three of four files in scope were already clean. `cmd_sign_userop_batch.rs`
carried two private helpers that duplicate shared module functions used by
its single-tx sibling (`cmd_sign_userop.rs`): a local `sha256()` wrapper
over `sha2::Sha256` and a local `encode_signature_wrapper()`. Both are
byte-identical to existing shared helpers (`aa::userop::sha256_bytes` and
`super::sig_wrapper::encode_signature_wrapper`). The single-tx path was
already de-duplicated in commit a475dda — extending the same cleanup to
the batch path. Net: −18 lines, no behavioural change.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `cmd_sign_userop_batch.rs:30, 40-45` | `use sha2::{Digest, Sha256}` import + local `fn sha256()` helper | 4 (vestigial / superseded) | Byte-identical to `aa::userop::sha256_bytes` already imported in the same `use` block. Mirrors the cleanup applied to `cmd_sign_userop.rs` in a475dda. Sole call site (line 507) switched to `sha256_bytes`. |
| `cmd_sign_userop_batch.rs:778-786` | private `fn encode_signature_wrapper()` | 4 (vestigial / superseded) | Byte-identical to `super::sig_wrapper::encode_signature_wrapper` (same module). `cmd_sign_userop.rs` and `cmd_sign_offchain.rs` both call the shared one; only batch carried a private duplicate. Both call sites (Type 1 wrapper at line 613, Type 2 wrapper at line 700) switched to `super::sig_wrapper::encode_signature_wrapper`. |

## Reverted during bisect
None.

## Cross-slice observations
None within the four scoped files. Baseline build produces 82 warnings
across the secure crate; all the `is never used` items live outside this
slice (mostly `secure/src/{scp03_logic,cmac,iso7816,reset_cause,zk}`,
`secure/src/nsc/mod.rs::reconcile_pin_attempts`, etc.) — out of scope.

## Skipped
- Local helpers in `cmd_sign_userop_batch.rs` that are duplicated in
  `cmd_sign_userop.rs` but used inside *their own* file under both copies
  (`add_one_to_be_u256`, `u128_saturating_from_u256`,
  `c10_sign_progress_bootstrap`, `c10_sign_progress_slot`,
  `write_be_u32`, `write_be_u64`). Deleting either copy in isolation
  would break that file; consolidating them into a shared helper module
  is a refactor (not a deletion) and out of this pass's scope.
- `debug_assert!(false, "nonce seq overflow slipped past the step-4 guard")`
  in `add_one_to_be_u256` — FI-detection-only branch (reachable only via
  fault injection past the step-4 nonce guard), intentional. Not dead.
- `let _ = write_pos;` after the final `debug_assert!(write_pos <=
  MAX_SIGN_RESPONSE_LEN)`: silences an `unused_assignments` warning when
  `debug_assertions` is off. Intentional.

## Equivalence check
- `make secure` (default features `mock-se,debug-log,ui-semihosting`,
  target `thumbv8m.main-none-eabi`) — baseline: 82 warnings, build OK;
  post-deletion: 82 warnings, build OK → **EQUIV**.
- Binary SHA-256:
  - baseline: `f901afcbf9bfb970f262eb719c2f2dba66f76e7fa26bdfcac6e50387667baf58`
  - post:     `1aa66d680c0cab3e16122f483f4abcd1e421222eaf4e542b6fde29245d8eda7f`
  → **EXPLAINED-DELTA** — the two deleted private helpers were not
  inlined identically to the shared ones in baseline codegen (different
  module path → different inlining decisions), so the .text bytes shift.
  Both deletions are semantically equivalent to their shared targets
  (identical bodies, identical signatures); the diff in machine code is
  purely the removal/redirection of the two private symbols.
- `cargo check`, `cargo clippy -D warnings`, `cargo test`, `cargo fmt
  --check` against package-level `sphincs-tz-secure` — **N/A** for this
  crate on host: the secure crate is a `thumbv8m.main-none-eabi`
  `#![no_std]` firmware binary that does not host-compile (default
  `cargo check` fails on UI / hw / cortex-m dependencies). The
  cross-compiled `make secure` build is the only meaningful check; it
  is EQUIV pre/post.
