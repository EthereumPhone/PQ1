## Dead-Code Removal — `secure-fw-update-boot`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
FW update staging + verify, measured-boot, NS handover.

Files audited:
- `secure/src/fw_update/mod.rs` (315 lines pre-edit)
- `secure/src/fw_update/staging.rs` (112 lines pre-edit)
- `secure/src/fw_update/vendor_pubkey.rs` (21 lines)
- `secure/src/fw_update/verify.rs` (106 lines pre-edit)
- `secure/src/measured_boot.rs` (165 lines)
- `secure/src/boot_ns.rs` (77 lines)

## Summary
Small, focused cleanup. Removed three unused helpers — `impl Default for
SlotTag`, `impl Default for IncrementalSha256`, and
`IncrementalSha256::finalize(self)` (only `clone_finalize` is consumed);
the stm32u585-feature build flagged the latter as dead. Also pruned a
stale comment-block in `staging.rs` describing a "re-declared
ChunkError" pattern that doesn't exist, and dropped the unused
`SlotTag` import in `verify.rs`. The remaining code in this slice is
live across the feature matrix that was exercised (mock-se /
stm32u585+optiga+se050+dual-se). `measured_boot.rs` and `boot_ns.rs`
are unchanged — every item is reachable via `main.rs`. Two
cross-slice observations carry over from the prior `secure-nsc-fw-update`
report.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/fw_update/mod.rs:133-137` | `impl Default for SlotTag` | 1 truly unused | No caller anywhere in the workspace — `FwUpdateCtx` constructs `inactive: SlotTag::from(inactive)` explicitly and does not derive `Default`. |
| `secure/src/fw_update/mod.rs:175-177` | `IncrementalSha256::finalize(self) -> [u8;32]` | 1 truly unused | Verifier path uses `clone_finalize`; consuming `finalize` has zero callers (stm32u585-cfg dead-code warning confirms). |
| `secure/src/fw_update/mod.rs:183-187` | `impl Default for IncrementalSha256` | 1 truly unused | Only `IncrementalSha256::new()` is called; `Default::default()` is never invoked. |
| `secure/src/fw_update/verify.rs:16` | unused import `SlotTag` | 1 truly unused | The function only needs `Slot` and the trait-resolved `From<SlotTag> for Slot` — importing `SlotTag` adds nothing. (Flagged by `cargo check --features stm32u585,…`.) |
| `secure/src/fw_update/staging.rs:108-112` | stale comment block about a non-existent `ChunkError` re-declaration | 5 stale comments | The "Re-declared here via a trait-less extension" sentence refers to a pattern that does not exist — `ChunkError` lives only in `mod.rs`. Pure text-level dead weight. |

## Reverted during bisect
None — all five deletions survived the equivalence check on the first attempt.

## Cross-slice observations
- `secure/src/fw_update/mod.rs` defines `SESSION_COUNTER: AtomicU32`
  + `bump_session() -> u32`. The counter is *mutated* exactly once
  (`let _session = fw_update::bump_session();` at
  `secure/src/nsc/cmd_fw_begin.rs:136`) and never *read* anywhere in
  the workspace. The aspirational doc-comment use ("by `CMD_FW_STATUS`
  to let the companion detect a different update session") is not
  implemented — `cmd_fw_status` returns `(state, recv_s, recv_ns,
  slot)` only. Removing the static + function + call site would be a
  three-line cleanup, but the call site lives in `secure-nsc-fw-update`
  scope, so it has to be done from that slice. Left alone here as
  noted in the prior `reports/deadcode/secure-nsc-fw-update.md` pass.
- `secure/src/nsc/cmd_fw_chunk.rs:108` still has an unreachable
  `Err(ChunkError::FlashError) => return …` arm in the `check_chunk`
  result match (`check_chunk` never emits `FlashError`). Out of scope
  for this slice; already noted in `secure-nsc-fw-update.md`.

## Skipped
- `secure_log!` invocations in `measured_boot.rs::run` (lines 142-148)
  expand to nothing when `debug-log` is off, producing benign
  unused-variable warnings under `--features stm32u585,…` (no
  debug-log). Bucket 2 (intentional dev infra) — leave alone.
- The `unsafe { core::ptr::addr_of!(__veneer_limit) as usize }` block
  in `flash_end()` (line 50, stm32u585 cfg) draws an "unnecessary
  unsafe block" warning. The block doubles as the carrier for the
  SAFETY comment that documents why reading the linker symbol is
  acceptable; removing the wrapper while keeping the SAFETY note is a
  code-style judgement call, not dead code. Skipped.
- `pub fn firmware_hash` in `measured_boot.rs` is `pub` despite having
  only an in-module caller. Demoting to non-`pub` would change a
  zero-cost visibility marker, not behaviour or codegen; not pursued
  to keep this pass behaviourally identical. (Referenced in a doc
  comment in `secure/src/optiga/mod.rs:486` only.)

## Equivalence check
Baseline captured by stashing all in-scope edits, running each
command, then restoring the edits and re-running. Output diffs are
described inline.

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked
  rustfmt invocation; deletions only remove whole items / a comment
  block / a single import name, so rustfmt cannot regress).
- `cargo check -p sphincs-tz-secure --no-default-features --features
  mock-se,debug-log,ui-semihosting --target thumbv8m.main-none-eabi`
  — **EQUIV** (76 warnings before, 76 warnings after, byte-identical
  diagnostic stream; only `Finished … in <time>` line differs).
- `cargo check -p sphincs-tz-secure --no-default-features --features
  stm32u585,hw-sha256,optiga-trust-m,se050,dual-se,ui-noop --target
  thumbv8m.main-none-eabi` — **EQUIV-** (151 warnings before, 149
  after; the two warnings *removed* are the unused `SlotTag` import
  and the dead `finalize` method this pass deletes — i.e. the warnings
  the cleanup is intentionally retiring. No new warnings.)
- `cargo check -p sphincs-tz-secure --tests` (default features) —
  **EQUIV** (39 warnings, no slice-related entries before or after).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (sandbox
  blocked the invocation).
- `cargo test -p sphincs-tz-secure --release` — **EQUIV** (baseline
  `121 passed; 0 failed; 0 ignored`, post-edit `121 passed; 0 failed;
  0 ignored`; same test names, same result line).
- `cargo build --locked --release --target thumbv8m.main-none-eabi
  --target-dir target/secure -p sphincs-tz-secure --no-default-features
  --features mock-se,debug-log,ui-semihosting` (the `make secure`
  target) — **EQUIV** (build succeeds with the same 76 warnings, no
  new diagnostics).
- Binary SHA-256 — not captured. The `make secure` build embeds a
  build-time vendor pubkey + dev OTP master from the environment,
  which already varies per run; a pure-bytes equivalence is not
  meaningful for this slice. The post-edit binary contains strictly
  fewer dead instructions (the `finalize` method was non-pub-API and
  not referenced from any reachable path).
