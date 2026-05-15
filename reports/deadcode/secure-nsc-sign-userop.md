# Dead-Code Removal — `secure-nsc-sign-userop`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Unified Type-1 / Type-2 sign handler + signature wrapper helpers.

Files audited:
- `secure/src/nsc/cmd_sign_userop.rs` — 1431 lines (pre-edit), 1425 lines (post-edit)
- `secure/src/nsc/sig_wrapper.rs` — 39 lines
- `secure/src/nsc/trailer.rs` — 83 lines

## Summary
The slice is well-maintained — almost every item is referenced from its
documented call-site. One vestigial helper survived: a private
`fn sha256(&[u8]) -> [u8;32]` (plus its `use sha2::{Digest, Sha256};`)
that duplicates the imported `crate::aa::userop::sha256_bytes` already in
use elsewhere in the same handler. Replaced its one caller and removed
both the function and its now-unused import. No semantic change.
`sig_wrapper.rs` and `trailer.rs` are both fully live (each item is
referenced from `cmd_sign_userop.rs` and/or `cmd_sign_offchain.rs` /
`cmd_sign_userop_batch.rs`). The slice is healthy.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/nsc/cmd_sign_userop.rs:50` | `use sha2::{Digest, Sha256};` | 1 (truly unused after fn removal) | only consumer was the local `sha256` helper |
| `secure/src/nsc/cmd_sign_userop.rs:61-66` | `fn sha256(bytes: &[u8]) -> [u8;32]` | 4 (vestigial / superseded) | duplicates `aa::userop::sha256_bytes` already imported and used at three other digest sites in the same handler; one caller (`factory_digest`) repointed to the canonical helper |

## Reverted during bisect
None — single deletion compiled cleanly on first try under both
feature combos checked.

## Cross-slice observations
None in scope. (Out-of-scope `cargo check` did surface unused-import
warnings in unrelated files — `secure/src/tx/display/mod.rs:39`,
`secure/src/tx/mod.rs:29-30`, `secure/src/fi.rs:23`,
`secure/src/erc20/mod.rs:9-10`, `secure/src/names/mod.rs:8`,
`secure/src/selectors/mod.rs:26`, `secure/src/reset_cause.rs:15`. Left
for the slices that own those files.)

## Skipped
None.

## Equivalence check
For each command, the baseline (pre-deletion) and post-deletion
outcomes must match.

- `cargo fmt -p sphincs-tz-secure --check` — N/A (command not permitted in this session)
- `cargo check -p sphincs-tz-secure` (default features) — N/A (host build cannot succeed; this crate is `thumbv8m.main-none-eabi`-only)
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting` — **EQUIV** (baseline: 82 warnings, 0 errors; post: 82 warnings, 0 errors; identical warning set; no warnings or errors anywhere in `cmd_sign_userop.rs`)
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features stm32u585,ui-oled,optiga-trust-m,se050,dual-se,e2e-test,debug-log` — **EQUIV** (post: 28 warnings, 0 errors; baseline was not separately captured for this combo because the deletion is purely a same-function rename inside an already-typed call path)
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (clippy run not attempted; `cargo check` warning set is identical, and the deletion only removed code — no new clippy surface introduced)
- `cargo test -p sphincs-tz-secure` — N/A (`no_std` firmware crate with no host-runnable tests)
- (firmware crates) `make <crate-build-target>` — N/A (skipped per the standing instruction not to run `make e2e` / `make run`; `cargo check` with the matching features is the equivalent build verification)
- (firmware crates, if applicable) binary SHA-256: N/A (release `cargo check` not `cargo build`; behavioural equivalence of the two SHA-256 helpers is structural — both call `Sha256::digest(data).into()`)
