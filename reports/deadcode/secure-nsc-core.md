# Dead-Code Removal — `secure-nsc-core`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Gateway dispatcher + SecureState singleton + NS-pointer validation.

Files audited:
- `secure/src/nsc/mod.rs` — 949 lines
- `secure/src/nsc/state.rs` — 369 lines
- `secure/src/nsc/ns_ptr.rs` — 269 lines
- `secure/src/nsc/ptr_validate.rs` — 165 lines

## Summary
The slice is materially clean. A whole-workspace grep of every candidate
(`HandlerGuard`, `HANDLER_DEPTH`, `handler_is_busy`, `is_unlocked`,
`unlock_with_master`, `zeroize_sensitive_state`, `set_e2e_unlocked`,
`gated_unlock`, `reconcile_pin_attempts`, `init_gateway`, `poll_gateway`,
the eleven CMSE veneers, `BOOTSTRAP_CACHE_LEN`, `bootstrap_cache_*`,
`SLOT_CACHE`, `FW_UPDATE`, `CachedSlot`, `with_state`, `peek_state`,
`tt_range_is_ns`, `validate_ns_{read,write}_ptr`) returned active call
sites — either in NS / main.rs, cross-file inside `nsc/`, or via
`#[no_mangle]` linkage consumed by `nonsecure/` through the CMSE implib.
The only deletion was the module-doc table at the top of `mod.rs`, which
listed two obsolete command IDs (3 `GET_PUBKEY`, 5 `CLEAR_SIGN` — neither
dispatched anywhere) and two non-existent submodules (`sign_and_emit`,
`userop_tail`). Items that look unused but are intentional are documented
under "Skipped" below.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/nsc/mod.rs:20-47` | Stale module-doc gateway-command table + bullets referencing removed submodules (`sign_and_emit`, `userop_tail`) and commands (`CMD_GET_PUBKEY`, `CMD_CLEAR_SIGN`) that no longer exist | 5 | Doc-comment only; authoritative table is in `CLAUDE.md`. No runtime impact. |

## Reverted during bisect
None.

## Cross-slice observations
- `secure/src/secure_element.rs:215` — `MockSecureElement::macd_all_initialized` is reported as dead by rustc under the `mock-se,debug-log,ui-semihosting` test config. Belongs to the `secure-nsc-small-cmds`/`shared` review surface, not this slice. Left alone.
- Multiple pre-existing `unused_assignments` warnings in `state.rs:259` (`victim_tick` overwrite) are stylistic; leaving alone preserves the explicit "look for empty slot first, else LRU" loop shape that the security-review pass blessed in `docs/security-review-2026-05.md`.

## Skipped
The following items look unused on a casual grep but are **intentional
infrastructure**, documented as such in code or design docs. Per the
task's "bucket 2" rule they were left intact:

- `SecureState::{last_chain_id, last_key_index, last_ots_index, has_signed}` and `{slot_master_entropy, slot_master_derived}` — write-only by current design; per `state.rs:64-68,82-89` and `tools/sca/README.md:1194` ("Follow-up (deferred)") these are F-14 complement-storage placeholders that earn future read sites their FI defense for free. Removing the fields would defeat the documented intent and force the FI work to be redone.
- `secure/src/nsc/ns_ptr.rs` (whole file) — explicitly `#![allow(dead_code)]` and documented at the top of the file as Phase 7 typestate scaffolding adopted incrementally. `docs/handoff-modularity-refactor.md:688-695` notes the host tests are intentionally dormant (the `nsc` module is `#[cfg(not(test))]`-gated). Tools/sca SCA harnesses reference the F-8 fix pattern by name. Touching this file would erase planned future-adoption infrastructure.
- All eleven `nsc_*` CMSE veneers in `mod.rs` — `#[no_mangle]` symbols emitted into the implib that NS links against. They look unreferenced inside the secure crate but are the production transport on stm32u585.

## Equivalence check
- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (no permission granted to run; only doc-comment text changed, fmt cannot regress).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting` — baseline: 82 warnings, 0 errors; post: 82 warnings, 0 errors → **EQUIV**.
- `cargo clippy ... -- -D warnings` — **N/A** (no permission; doc-comment-only edit cannot introduce a lint).
- `cargo test --locked -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting` — baseline: 121 passed / 0 failed; post: 121 passed / 0 failed → **EQUIV**.
- Firmware binary SHA-256 — **N/A** (no rebuild beyond `cargo check`; the diff is doc-comment text and cannot change codegen).
