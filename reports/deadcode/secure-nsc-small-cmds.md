# Dead-Code Removal — `secure-nsc-small-cmds`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Small NSC command handlers (unlock, address, init-code, lock, …).

Files audited:
- `secure/src/nsc/cmd_request_unlock.rs` — 167 lines
- `secure/src/nsc/cmd_get_wallet_address.rs` — 144 lines
- `secure/src/nsc/cmd_get_init_code.rs` — 270 lines
- `secure/src/nsc/cmd_get_remaining.rs` — 40 lines
- `secure/src/nsc/cmd_is_unlocked.rs` — 16 lines
- `secure/src/nsc/cmd_lock.rs` — 15 lines
- `secure/src/nsc/cmd_test_pin_lockout.rs` — 236 lines
- `secure/src/nsc/factory_calldata.rs` — 88 lines

Total: 976 lines.

## Summary
This slice is already clean. Every `cmd_*::run` entry-point is dispatched
from `secure/src/nsc/mod.rs` (both the QEMU mailbox path and the CMSE
veneer path). Every internal helper has a live caller in its own file:
`verify_pin_with_chip` and `trigger_lockout_wipe` in
`cmd_request_unlock.rs`; the section-by-section pipeline in
`cmd_get_init_code.rs`; and the single `build` helper in
`factory_calldata.rs` (consumed by both `cmd_get_init_code` and
`cmd_sign_offchain` — its raison d'être). The PIN-lockout test handler
and the `nsc_test_pin_lockout` veneer are bucket-2 dev infrastructure
gated behind `e2e-test`, so they are intentional and out of scope for
deletion. No deletions applied; no source files modified.

## Deletions applied
_(none)_

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

## Reverted during bisect
_(none — no deletions attempted)_

## Cross-slice observations
- `secure/src/nsc/mod.rs` (out-of-scope) has stale module-level docs at
  lines 23–47 referencing modules that no longer exist (`sign_and_emit`,
  `userop_tail`) and pre-cutover command IDs (CMD 3 `GET_PUBKEY`, CMD 5
  `CLEAR_SIGN`). The current dispatch table in this slice's neighbours
  (`cmd_sign_userop`, `cmd_sign_offchain`, etc.) has long since replaced
  these. A `secure-nsc-mod` slice (or a generic doc-sweep slice) should
  trim the stale table — out of scope for `secure-nsc-small-cmds`.
- `cmd_get_init_code.rs:263` labels the final block `── 9. Write output
  …` but the function only has sections 1..7 — section 8 was removed at
  some earlier point. The numbering is a comment-only artefact; leaving
  it alone to avoid churning behaviour-preserving cosmetic edits in a
  dead-code pass.

## Skipped
- `cmd_test_pin_lockout.rs` — bucket-2 dev/e2e infrastructure
  (`#[cfg(feature = "e2e-test")]`); intentional.
- All `secure_log!` macro invocations gated on `debug-log` — bucket-2.
- `cmd_request_unlock.rs:28` exhaustive match arm for
  `PinEntryResult::Mismatch` (unreachable from `enter_pin`, but the
  enum has the variant for `enter_pin_with_confirm`; the arm is
  required for exhaustiveness and is not a dead branch).

## Equivalence check
No source files were modified, so post-deletion outcomes are trivially
identical to baseline. No baseline run was needed.

- `cargo fmt -p sphincs-tz-secure --check` — N/A (no edits)
- `cargo check -p sphincs-tz-secure` — N/A (no edits)
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (no edits)
- `cargo test -p sphincs-tz-secure` — N/A (no edits)
- firmware build / binary SHA-256 — N/A (no edits)
