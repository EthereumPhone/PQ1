# Dead-Code Removal — `pqsigner-fi`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
FI-hardening primitives shared by secure + fsbl.

Files audited:
- `pqsigner-fi/Cargo.toml` (15 lines)
- `pqsigner-fi/src/lib.rs` (255 lines)

## Summary
The crate is a single 255-line `lib.rs` exposing five public items
(`OK_SENTINEL`, `FAIL_SENTINEL`, `wait_random_loop`, `check_true`,
`check_true_into_sentinel`) plus three private helpers (`vread`, `vwrite`,
`halt_on_glitch`). Every public item is consumed by `secure/src/fi.rs`,
`fsbl/src/fi.rs`, and/or the `tools/sca/*` FI-fuzz targets; all private
helpers are used inside `lib.rs`. There are no commented-out code blocks,
no stale TODOs, no unused dependencies, and no `[features]` table to
prune. The `cortex-m` dependency is correctly target-gated to ARM. No
deletions applied — the slice is already clean.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_(none — no deletions attempted)_

## Cross-slice observations
None within the audit window of this slice.

## Skipped
None.

## Equivalence check
No source edits were made; baseline == post-deletion trivially.

- `cargo fmt -p pqsigner-fi --check` — N/A (no edits)
- `cargo check -p pqsigner-fi` (default features) — EQUIV (clean baseline)
- `cargo clippy -p pqsigner-fi -- -D warnings` — N/A (no edits)
- `cargo test -p pqsigner-fi` — EQUIV (test counts: baseline 7, post 7;
  all passing)
- (firmware crates) `make <crate-build-target>` — N/A (pqsigner-fi is a
  pure-logic library reused by `secure` and `fsbl`; firmware-image
  rebuilds aren't required for a no-op change)
- binary SHA-256 — N/A (no source change)
