# Test Suite Added — `secure-nsc-fw-update`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Five firmware-update NSC handlers (BEGIN/CHUNK/COMMIT/STATUS/ABORT).

Source files covered:
- `secure/src/nsc/cmd_fw_abort.rs` — 30 lines
- `secure/src/nsc/cmd_fw_begin.rs` — 138 lines
- `secure/src/nsc/cmd_fw_chunk.rs` — 124 lines
- `secure/src/nsc/cmd_fw_commit.rs` — 155 lines
- `secure/src/nsc/cmd_fw_status.rs` — 63 lines

The five handlers are all `#[cfg(feature = "stm32u585")]`-gated in
`secure/src/nsc/mod.rs` because they consume bank-2 flash + OTP
primitives that only real STM32U585 silicon exposes. The supporting
`fw_update` module is `#[cfg(all(feature = "stm32u585", not(test)))]`
in `secure/src/main.rs`, so neither the handlers nor their direct
helpers can be linked into a host `cargo test` build. Tests therefore
exercise the slice via the established `nsc_*_pure_tests.rs` pattern:
host-runnable pure-logic mirrors + wire-format constant pins +
source-text invariant pins.

## Test files added / extended
- `secure/src/nsc_fw_update_pure_tests.rs` (new) — **34 positive, 37
  negative** tests, organised into 20 numbered sections:
    1. Wire-format constant pins (CMD_FW_* IDs, FW_MAX_CHUNK,
       FW_CHUNK_HEADER_LEN, FW_IMAGE_KIND_*, FW_STATUS_* offsets,
       FW_STATE_*, MANIFEST_SIZE, TRY_ONCE_TRIED, OFF_TRY_ONCE,
       OFF_CRC32, NscStatus::FwUpdate*).
    2. Pure-logic chunk-header parser mirror.
    3. STATUS state-derivation mirror (`idle | receiving | staged`)
       and BE-counter serialisation.
    4-5. `check_chunk` decision-tree mirror covering every
       `ChunkError` arm (TooLarge, BadKind, NonMonotonic with
       both gap + retransmit, OverflowsImage with length + u32
       addition overflow).
    6-7. Wire-format payload bounds (BEGIN's exact-MANIFEST_SIZE
       check; CHUNK's `[HEADER_LEN, HEADER_LEN+FW_MAX_CHUNK]`
       window + `chunk_len == data_len` mismatch).
    8. PIN-verified gating on BEGIN/CHUNK/COMMIT; absence of
       PIN gate on STATUS/ABORT.
    9. NS pointer validation on the three NS-touching handlers
       (BEGIN/CHUNK use `validate_ns_read_ptr`; STATUS uses
       `validate_ns_write_ptr`).
    10. TOCTOU snapshot via byte-by-byte `core::ptr::read_volatile`
       / `write_volatile`.
    11. `HandlerGuard::enter()` acquisition BEFORE `static mut
       FW_UPDATE` deref in CHUNK + COMMIT; ABORT's single-write
       safety.
    12. `FwUpdateCtx` ZeroizeOnDrop guarantee.
    13. BEGIN's verify-before-erase ordering, BelowRollback vs
       BadManifest discrimination, inactive-slot derivation,
       activity-timer reset AFTER ctx seed.
    14. COMMIT ordering: verify_images → confirm_commit →
       otp::bump_to → manifest write → boot_state write →
       sys_reset; user-cancel short-circuit; TRY_ONCE_TRIED +
       CRC recompute; `write_quadword_verified` use; OTP-budget
       error discrimination.
    15. F-7 FI-hardened signature verify in `verify_manifest`
       (`check_true_into_sentinel` + `OK_SENTINEL`) and verify-chain
       step ordering.
    16. CHUNK error discrimination (FlashError vs BadChunk vs
       BadState).
    17. No classical signers (secp256k1, ECDSA, ed25519, P256, RSA,
       FORS_C) anywhere in the slice — invariant #5.
    18. `feature = "stm32u585"` gating on every `cmd_fw_*` module
       declaration + every CMSE veneer in `nsc/mod.rs`.
    19. STATUS sources STATE bytes from `sphincs_tz_shared::FW_STATE_*`
       and offsets from `FW_STATUS_*_OFFSET` (no inlined literals).
    20. ABORT shape: < 50 lines, no `HandlerGuard::enter()`, no NS
       pointer validation, no PIN gate, returns `NscStatus::Ok`
       exactly once.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| positive_cmd_fw_command_ids_pinned | CMD_FW_BEGIN..ABORT = 20..24 | shared proto |
| positive_fw_max_chunk_and_header_len_pinned | 1024 + 8 | shared proto |
| positive_fw_image_kind_byte_values_pinned | 0 = secure, 1 = NS | CHUNK |
| positive_fw_status_response_layout_pinned | 10 B + offsets 0/1/5/9 | STATUS |
| positive_fw_state_byte_values_pinned | IDLE=0, RECEIVING=1, STAGED=2 | STATUS |
| positive_manifest_size_is_one_flash_page | 8192 B | BEGIN |
| positive_try_once_tried_marker_pinned | 0xAA @ OFF_TRY_ONCE=4192 | COMMIT |
| positive_off_crc32_is_at_end_of_manifest | OFF_CRC32 = MANIFEST_SIZE - 4 | COMMIT |
| positive_nsc_status_fw_codes_pinned | FwUpdate* discriminants 10..16, round-trip | all 5 |
| positive_chunk_header_parses_offset_as_big_endian_u32 | parser BE u32 @ 0..4 | CHUNK |
| positive_chunk_header_parses_image_kind_at_offset_4 | byte 4 | CHUNK |
| positive_chunk_header_parses_len_as_big_endian_u16_at_offset_6 | BE u16 @ 6..8 | CHUNK |
| positive_chunk_header_full_round_trip | all fields together | CHUNK |
| positive_status_state_is_idle_when_no_session | None → IDLE,0,0,0 | STATUS |
| positive_status_state_is_receiving_when_partial | recv<expected → RECEIVING | STATUS |
| positive_status_state_is_staged_when_both_halves_complete | recv==expected → STAGED | STATUS |
| positive_status_response_serialises_counters_big_endian | byte-exact response | STATUS |
| positive_check_chunk_accepts_first_secure_block | first chunk OK | CHUNK |
| positive_check_chunk_accepts_first_nonsecure_block | NS image accepted | CHUNK |
| positive_check_chunk_accepts_terminal_chunk_filling_image | end==expected_len OK | CHUNK |
| positive_begin_accepts_exactly_manifest_size | total_len == MANIFEST_SIZE OK | BEGIN |
| positive_chunk_accepts_total_len_at_boundaries | HEADER..HEADER+MAX OK | CHUNK |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| negative_check_chunk_rejects_oversize_chunk | "chunk_len capped at FW_MAX_CHUNK" | feed chunk_len = FW_MAX_CHUNK + 1 | `Err(TooLarge)` |
| negative_check_chunk_rejects_unknown_image_kind | "image_kind ∈ {0, 1}" | feed 2, 3, 0x80, 0xFF | `Err(BadKind)` for each |
| negative_check_chunk_rejects_nonmonotonic_offset_gap | "offset must equal received_*" | offset > received | `Err(NonMonotonic)` |
| negative_check_chunk_rejects_nonmonotonic_offset_retransmit | "no retransmit" | offset < received | `Err(NonMonotonic)` |
| negative_check_chunk_rejects_run_past_expected_image_length | "end ≤ expected_len" | offset + len > expected_len (with len ≤ MAX) | `Err(OverflowsImage)` |
| negative_check_chunk_rejects_u32_addition_overflow | "checked_add on end calc" | offset = u32::MAX - 16, len = 17 | `Err(OverflowsImage)` |
| negative_begin_rejects_total_len_below_manifest_size | "exact MANIFEST_SIZE" | total_len in {0, MANIFEST_SIZE/2, MANIFEST_SIZE - 1} | refused |
| negative_begin_rejects_total_len_above_manifest_size | "secure-stack snap buffer fixed" | total_len > MANIFEST_SIZE | refused |
| negative_chunk_rejects_total_len_below_header_size | "header must fit" | 0..FW_CHUNK_HEADER_LEN | refused |
| negative_chunk_rejects_total_len_above_header_plus_max | "data buffer fixed at FW_MAX_CHUNK" | total_len > HEADER + MAX | refused |
| negative_chunk_rejects_header_len_mismatch_with_payload | "chunk_len == data_len" | header claims 16, payload 32 | mismatch (→ FwUpdateBadChunk) |
| negative_begin_checks_pin_verified_first | "no update on locked device" | source-grep gate | `pin_verified.check_sentinel()` + `NotInitialized` |
| negative_chunk_checks_pin_verified_first | "mid-session lock blocks chunks" | source-grep gate | same |
| negative_commit_checks_pin_verified_first | "OTP bump must never fire on locked device" | source-grep gate | same |
| negative_status_does_not_gate_on_pin_verified | "STATUS is a recovery probe" | source-grep absence | no `pin_verified` reference |
| negative_abort_does_not_gate_on_pin_verified | "ABORT must always work" | source-grep absence | no `pin_verified.check_sentinel()` |
| negative_begin_validates_ns_read_pointer_before_deref | "no deref before validate" | source-grep | `validate_ns_read_ptr(payload_ptr, total_len)` + InvalidPointer |
| negative_chunk_validates_ns_read_pointer_before_deref | same | source-grep | same |
| negative_status_validates_ns_write_pointer_before_deref | "write-side validator for output buffer" | source-grep | `validate_ns_write_ptr(out_ptr, FW_STATUS_RESPONSE_LEN)` |
| negative_begin_copies_manifest_via_byte_read_volatile | "TOCTOU snapshot must use byte read_volatile" | source-grep | `core::ptr::read_volatile(src.add(i))` in BEGIN |
| negative_chunk_copies_payload_via_byte_read_volatile | same for chunk header + data | source-grep | both fixed buffers + read_volatile loop |
| negative_status_emits_response_via_byte_write_volatile | "ordered byte-by-byte writes" | source-grep | `core::ptr::write_volatile(dst.add(i), buf[i])` |
| negative_chunk_holds_handler_guard_before_fw_update_deref | "SysTick must not wipe under handler" | source-position assert | `HandlerGuard::enter()` source-pos < `addr_of_mut!(FW_UPDATE)` source-pos |
| negative_commit_holds_handler_guard_before_fw_update_deref | same | source-position assert | `HandlerGuard::enter()` < `addr_of!(FW_UPDATE)` |
| negative_abort_drops_ctx_via_static_mut_assignment | "ZeroizeOnDrop wipes via assignment" | source-grep | `addr_of_mut!(FW_UPDATE)` + `= None;` |
| negative_fw_update_ctx_uses_zeroize_on_drop | "ctx zeroises on drop" | source-grep | `ZeroizeOnDrop` derive |
| negative_begin_runs_verify_manifest_before_erase | "verify before destructive op" | source-position assert | `verify_manifest` < `flash::erase_slot` |
| negative_begin_distinguishes_rollback_from_bad_manifest | "companion needs discriminated errors" | source-grep | BelowRollback → FwUpdateBadVersion; other → FwUpdateBadManifest |
| negative_begin_picks_inactive_slot_via_read_active_slot | "never erase running slot" | source-grep | `read_active_slot()` + A↔B inversion |
| negative_begin_resets_activity_timer_after_seed | "fresh ctx gets fresh 120 s budget" | source-position assert | ctx seed < `timeout::reset_activity()` |
| negative_commit_runs_verify_images_before_confirm_ui | "confirm bytes must reflect flash" | source-position assert | verify_images < confirm_commit |
| negative_commit_user_cancel_short_circuits_before_destructive_ops | "cancel must not bump OTP" | source-position assert | cancel branch < `otp::bump_to` |
| negative_commit_bumps_otp_before_writing_new_manifest | "rollback-floor anti-replay across reset" | source-position assert | `otp::bump_to` < `write_quadword_verified` |
| negative_commit_writes_manifest_via_write_quadword_verified | "torn write detection" | source-grep | `flash::write_quadword_verified` (no plain `write_quadword`) |
| negative_commit_sets_try_once_tried_and_recomputes_crc | "FSBL can revert + page CRC stays valid" | source-grep + position | `OFF_TRY_ONCE] = TRY_ONCE_TRIED` < `crc32_ieee` |
| negative_commit_writes_boot_state_last_before_reset | "boot pointer flips last" | source-position assert | manifest < boot_state < sys_reset |
| negative_commit_maps_otp_exhaustion_to_distinct_error_code | "companion distinguishes permanent vs transient" | source-grep | `OtpError::OutOfBudget` → `FwUpdateOtpExhausted` |
| negative_verify_manifest_uses_fi_hardened_signature_check | "F-7: single-fault skip must not bypass sig verify" | source-grep | `check_true_into_sentinel` + `OK_SENTINEL` in `fw_update/mod.rs` |
| negative_verify_manifest_runs_full_chain_in_documented_order | "cheap checks first, sig before rollback" | source-position assert across 6 steps | each step appears in declared order |
| negative_chunk_maps_flash_error_distinctly_from_bad_chunk | "companion distinguishes retry vs give-up" | source-grep | `ChunkError::FlashError` → `FwUpdateFlashError` and `BadChunk` |
| negative_chunk_requires_active_session_before_static_mut_deref | "no unwrap-panic on None" | source-grep | `ctx_present` discrimination + `FwUpdateBadState` |
| negative_commit_requires_active_session_before_static_mut_deref | same for COMMIT | source-grep | `FwUpdateBadState` |
| negative_slice_contains_no_classical_signer_mentions | invariant #5 (single C10 signer) | source-grep over all 6 files | none of secp256k1, ECDSA, ed25519, P256, RSA, FORS_C anywhere |
| negative_all_fw_modules_are_stm32u585_gated_in_nsc_mod | "QEMU build must not pull in stub FW handlers" | source-grep | `#[cfg(feature = "stm32u585")]` precedes every `mod cmd_fw_*` |
| negative_all_fw_veneers_are_stm32u585_gated_in_nsc_mod | same for CMSE veneers | source-grep | each `nsc_fw_*` veneer present + stm32u585 cfg present |
| negative_status_emits_proto_state_constants_not_inlined_literals | "proto renumber must propagate to firmware" | source-grep | `FW_STATE_IDLE / RECEIVING / STAGED` used by name |
| negative_status_response_layout_uses_proto_offset_constants | same for layout offsets | source-grep | `FW_STATUS_*_OFFSET` used by name |
| negative_abort_handler_is_intentionally_tiny | "ABORT must not silently grow gates" | line count + source-grep | < 50 lines, no `HandlerGuard::enter()`, no `validate_ns_`, no `pin_verified.check_sentinel()` |
| negative_abort_always_returns_ok | "single Ok return, no error path" | source-grep + count | one `NscStatus::Ok`, no other `NscStatus::` references |

## Production-code bugs surfaced by negative tests

None. Every test passes against the current source. The negative
suite is forward-looking: it pins assumptions the source currently
honours so a future refactor that quietly weakens any one of them
surfaces here rather than at flash time.

## Coverage gaps deliberately left

- **Live execution of the handlers.** The five `cmd_fw_*::run`
  functions can only be exercised on the STM32U585 target
  (`thumbv8m.main-none-eabi`); they pull in `crate::hw::flash`,
  `crate::hw::otp`, `crate::hw::boot_state`, and `crate::ui` which
  have no host-side implementation. Their decision shape is
  mirrored at the source-text level above; an on-target integration
  test (akin to `make e2e-hw`) is the right way to exercise the
  flash/OTP write side. The `fw_update` module itself is gated
  `#[cfg(all(feature = "stm32u585", not(test)))]` so even its
  pure helpers (`check_chunk`, `verify_manifest`) cannot be
  reached from `cargo test` — this is why we use a sibling mirror
  of `check_chunk` in the test file rather than the real one.
- **SAU `tt`-instruction range check.** `validate_ns_read_ptr` /
  `validate_ns_write_ptr` are tested in `nsc_small_cmds_pure_tests`
  for the constant-window bounds; the `tt`-stride check is ARM-only
  and exercised by `make e2e-hw`. The FW slice's negative tests pin
  that the handlers *call* the validators; the validators' own
  correctness is the small-cmds slice's responsibility.
- **`confirm_commit` "stub returns false" behaviour.** The current
  `fw_update::confirm_commit` body returns `false` unless
  `e2e-test` is on (so an accidentally-deployed half-ported UI
  fails closed). The test file pins the ordering of
  `verify_images → confirm_commit → otp::bump_to`; a future pass
  should add a host-runnable wrapper test for the stub's "fails
  closed" contract once the trusted-UI `confirm()` machinery
  reland.
- **OTP-budget arithmetic.** `otp::bump_to` is ARM-only; the
  `FwUpdateOtpExhausted` mapping is pinned via source-text but the
  underlying "out of budget" condition cannot be triggered on host.
  A future pass that extracts the budget arithmetic to a pure-logic
  helper would unlock direct testing.
- **TZIC / GTZC interactions.** The handlers run after SAU
  classification but are not themselves TZIC-aware; the slice does
  not introduce a new TZIC-protected region. No coverage gap.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox refused
  `cargo fmt` and `rustfmt`; the new file follows the same
  rustfmt-default layout as the sibling `nsc_*_pure_tests.rs`
  files in the crate, and `cargo check`/`cargo test` accept it
  unchanged).
- `cargo check -p sphincs-tz-secure --tests` — PASS (no new
  warnings; pre-existing 37 warnings unchanged).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` —
  N/A (sandbox refused; `cargo check --tests` passes cleanly with
  no new lints under `cargo test`).
- `cargo test -p sphincs-tz-secure` — PASS (455 tests, 0 ignored,
  71 of which are the new `nsc_fw_update_pure_tests`).
- (firmware) on-target tests deferred: yes — see "Coverage gaps
  deliberately left" above. The handler decision shape is pinned
  via mirrors + source-text invariants; flash/OTP side effects
  require `make e2e-hw` and are out of scope for this host-only
  pass.
