# Dead-Code Removal — `secure-nsc-fw-update`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Five firmware-update NSC handlers (BEGIN/CHUNK/COMMIT/STATUS/ABORT).

Files audited:
- `secure/src/nsc/cmd_fw_abort.rs` — 31 lines
- `secure/src/nsc/cmd_fw_begin.rs` — 139 lines
- `secure/src/nsc/cmd_fw_chunk.rs` — 124 lines
- `secure/src/nsc/cmd_fw_commit.rs` — 155 lines
- `secure/src/nsc/cmd_fw_status.rs` — 63 lines

Total: ~512 lines.

## Summary
The slice is almost entirely live. Each `cmd_fw_*::run` is dispatched
from `secure/src/nsc/mod.rs` via the FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT
gateway commands; every internal call (NS-pointer validation, manifest
verify, slot erase, chunk write, image rehash, OTP bump, boot-state
write, system reset) has a downstream consumer in `fw_update::*` /
`hw::*`. Three small dead items were removed from `cmd_fw_begin.rs`:
two unused glob-imported names and a vestigial `let _ = m.slot();`
read whose discarded byte is already explained by the comment above
it. The remaining files were already clean. Post-deletion binary is
byte-identical to baseline.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/nsc/cmd_fw_begin.rs:20` | `with_state` import | 1 (truly unused) | Brought in alongside `peek_state` + `FW_UPDATE` but never called in BEGIN. |
| `secure/src/nsc/cmd_fw_begin.rs:25` | `boot_state` import | 1 (truly unused) | Imported from `crate::hw` but BEGIN never touches boot-state — only COMMIT does, via its own import. |
| `secure/src/nsc/cmd_fw_begin.rs:90` | `let _ = m.slot();` | 5 (stale / vestigial) | Pure read of `bytes[OFF_SLOT]` whose result is discarded. The explanatory comment above (kept intact) already documents why the manifest's `slot` byte is informational and unused. |

## Reverted during bisect
_(none — first-pass post-build was already EQUIV)_

## Cross-slice observations
- `secure/src/fw_update/mod.rs` (out of scope) defines
  `SESSION_COUNTER: AtomicU32` and `bump_session() -> u32`. The
  counter is mutated once in `cmd_fw_begin.rs:136`
  (`let _session = fw_update::bump_session();`) and never read
  anywhere else in the workspace. The aspirational use ("by
  CMD_FW_STATUS to let the companion detect a different session")
  is not implemented — STATUS returns `(state, recv_s, recv_ns,
  slot)` only. The `_session` line and the counter could be
  removed together in a `secure-fw-update-mod` slice; left alone
  here because the dead callee lives outside this slice's scope.
- `secure/src/nsc/cmd_fw_chunk.rs:108` —
  `Err(ChunkError::FlashError) => return NscStatus::FwUpdateFlashError`
  inside the `check_chunk` result match is unreachable: `check_chunk`
  in `fw_update/mod.rs` only emits `{TooLarge, BadKind, NonMonotonic,
  OverflowsImage}`, never `FlashError`. Removing the arm requires
  introducing a `Err(_)` catch-all (the enum has `FlashError`, so
  exhaustiveness keeps the arm in scope); the resulting semantic
  shift — a future check_chunk gaining FlashError would map to
  FwUpdateBadChunk instead of FwUpdateFlashError — is a defensive-
  coding judgment call not appropriate for an automated dead-code
  pass. Documented but not deleted.

## Skipped
- All `secure_log!` macro invocations and the FW handlers' early
  `peek_state(|s| s.pin_verified.check_sentinel())` PIN gates —
  load-bearing FI-hardened control flow, not dead.
- `OFF_TRY_ONCE` / `TRY_ONCE_TRIED` / `crc32_ieee` from `fw_manifest`
  in `cmd_fw_commit.rs` — they are part of the frozen FW-update
  preimage / try-once flag layout (see "Do not expand the signed FW-
  update preimage" in CLAUDE.md). Intentional, not dead.

## Equivalence check
- `cargo fmt -p sphincs-tz-secure --check` — N/A on host (the
  secure crate is `thumbv8m.main-none-eabi`/`#![no_std]` and does
  not host-compile; rustfmt-check on the edited file would need to
  be run inside the cross-compile session). Edits were import-line
  shrinks and a single-line removal, all of which preserve existing
  rustfmt-style — no whitespace-only or wrap changes introduced.
- `make secure` (features `mock-se,debug-log,ui-semihosting`, target
  `thumbv8m.main-none-eabi`) — baseline: 82 warnings, build OK; post-
  deletion: 82 warnings, build OK → **EQUIV**.
- Binary SHA-256:
  - baseline: `1aa66d680c0cab3e16122f483f4abcd1e421222eaf4e542b6fde29245d8eda7f`
  - post:     `1aa66d680c0cab3e16122f483f4abcd1e421222eaf4e542b6fde29245d8eda7f`
  → **MATCH** (byte-identical — the deletions were no-ops at the
  codegen level, confirming they were truly dead).
- `cargo check -p sphincs-tz-secure` / `cargo clippy -- -D warnings`
  / `cargo test -p sphincs-tz-secure` (default host) — **N/A**: the
  secure crate is a `thumbv8m` firmware binary and does not host-
  compile; `make secure` is the only meaningful check and is EQUIV.
