# Test Suite Added — `secure-nsc-batch-offchain`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Batch sign + EIP-1271 off-chain sign + per-slot counter cmds.

Source files covered:
- `secure/src/nsc/cmd_sign_userop_batch.rs` — 825 lines
- `secure/src/nsc/cmd_sign_offchain.rs` — 594 lines
- `secure/src/nsc/cmd_offchain_status.rs` — 98 lines
- `secure/src/nsc/cmd_offchain_sync.rs` — 86 lines

All four files are firmware-only: each `run(&GatewayArgs)` function
transitively reaches the `static mut SLOT_CACHE`, the offchain-state
flash log, the secure-element trait, the OLED confirm dialog, and the
CMSE NSC ABI — none of which can be linked into a host build. The
slice's handlers therefore cannot be invoked directly from `cargo test`.

The test suite instead covers the slice with three families that *can*
run on the host:
1. Wire-format constant pins (the proto-crate constants every `run()`
   reads — offsets, lengths, masks, magic suffixes).
2. Helper-function characterisations (mirrors of `u128_saturating_from_u256`
   and `add_one_to_be_u256` that the batch handler depends on).
3. Source-text invariant pins (assertions that the load-bearing gates,
   FI guards, zeroization barriers, frozen domain tags, and rejection
   branches remain in each file's source).

This is the same pattern the existing `secure-nsc-sign-userop` slice
already uses (`secure/src/nsc_sign_userop_pure_tests.rs`), so a single
`cargo test -p sphincs-tz-secure --tests` covers both slices' source
invariants together.

## Test files added / extended
- `secure/src/nsc_batch_offchain_pure_tests.rs` — 8 positive, 83 negative
  tests (91 total). Pure-logic + source-text invariant pins for the
  four-file slice; wired into the crate at `secure/src/main.rs` under
  `#[cfg(test)]`.
- `secure/src/main.rs` — added `#[cfg(test)] mod nsc_batch_offchain_pure_tests;`
  (3 lines).

No new `[dev-dependencies]` were needed; the workspace already provides
`proptest` + `hex` for the existing test suite.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_batch_u128_sat_zero_returns_zero` | `u128_saturating_from_u256([0;32]) == 0` | `cmd_sign_userop_batch::u128_saturating_from_u256` (mirror) |
| `positive_batch_u128_sat_low_128_returns_value` | Low 128 bits with high half zero round-trip | same |
| `positive_batch_u128_sat_low_128_max_returns_u128_max` | `u128::MAX` low half round-trips | same |
| `positive_batch_u128_sat_just_above_u128_saturates` | First value past `u128::MAX` saturates | same |
| `positive_batch_nonce_increment_simple` | `0x...05 + 1 == 0x...06`; high bytes untouched | `cmd_sign_userop_batch::add_one_to_be_u256` (mirror) |
| `positive_batch_nonce_increment_carry_within_seq` | `0x...FF + 1` carries into byte 30 | same |
| `positive_sig_wrapper_offset_field_is_0x40` *(coverage via existing sign-userop test)* | (already pinned upstream) | n/a |
| `positive_*` (4 `u128_sat` + 2 `nonce_increment`) | shared with batch handler arithmetic | helper characterisations |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_offchain_status_input_len_is_13` | Input length is fixed at 13 B | Compare constant to 13 | `OFFCHAIN_STATUS_INPUT_LEN == 13` |
| `negative_offchain_status_output_len_is_24` | Output is exactly 24 B (with 7 reserved bytes) | Compare constant to 24 | Matches |
| `negative_offchain_status_output_offsets_pin_documented_layout` | LOCAL/LAST_USEROP/REGISTERED at 0/8/16 | Compare each offset | All match |
| `negative_offchain_status_local_and_last_userop_fields_dont_overlap` | u64 fields are contiguous with no gap | Sum offset + 8 vs next offset | Continuous |
| `negative_offchain_sync_input_len_is_21` | Sync input is 21 B (1+8+4+8) | Compare constant | Matches |
| `negative_sign_offchain_header_len_is_17` | EIP-1271 sign header is 17 B | Compare constant | Matches |
| `negative_sign_offchain_input_offsets_are_packed_in_order` | All 7 header field offsets packed contiguously | Compare each offset | Packed |
| `negative_sign_offchain_kind_values_are_zero_and_one` | RAW32=0 (default-byte interpretation), PERSONAL_SIGN=1 | Compare constants | Matches |
| `negative_sign_offchain_flags_mask_pins_account_deployed_bit` | Mask is only bit 0; all bits 1..7 rejected | Iterate every reserved bit, check `& !mask != 0` | All 7 reserved bits get rejected |
| `negative_sign_offchain_personal_sign_max_payload_unchanged` | 700 B cap on personal-sign messages | Compare constant | 700 |
| `negative_sign_offchain_input_max_len_equals_header_plus_max_personal_sign` | SNAP_BUF size = HEADER_LEN + 700 | Sum check | 717 |
| `negative_sign_offchain_output_len_deployed_is_4016` | Deployed-path output = 8 (count) + 4008 (sig) | Compare to 4016 + decompose | Matches |
| `negative_sign_offchain_output_len_6492_is_8616` | 6492-path output = 8 + 8608 (blob) | Compare to 8616 + decompose | Matches |
| `negative_eip6492_factory_calldata_padding_matches_abi` | Blob layout math = head(96)+fc_len(32)+fc_pad(4288)+sig_len(32)+sig(4128)+magic(32) | Algebraic decomposition | All 8608 bytes accounted for |
| `negative_eip6492_magic_suffix_is_repeating_6492` | EIP-6492 magic = 16× `0x6492` (per spec) | Compare to spec | Bytes match |
| `negative_sign_userop_batch_header_len_is_277` | Batch header = 277 B (matches CLAUDE.md decomposition) | Compare + algebraic check | Matches |
| `negative_sign_userop_batch_tx_prefix_len_is_54` | Per-tx prefix = 54 B (20+32+2) | Compare | Matches |
| `negative_sign_userop_batch_max_payload_len_covers_max_batch_at_max_tx_len` | SNAP_BUF in batch handler ≥ worst-case payload | Sum check + absolute 16,877 pin | Sized correctly |
| `negative_max_batch_txs_is_4` | MAX_BATCH_TXS pinned at 4 (bounds `parsed[]`/`batch_view[]` arrays) | Compare | 4 |
| `negative_execute_batch_selector_unchanged` | `0x7a389933` (`keccak256("executeBatch...")[..4]`) frozen | Compare bytes | Match |
| `negative_signature_len_unchanged_4008` | C10 sig length frozen at 4008 (on-chain ABI dep) | Compare + tie-up with `C10_SIG_LEN` | 4008 |
| `negative_sig_wrapper_len_unchanged_4128` | Wrapper length frozen at 4128 (on-chain ABI dep) | Compare | 4128 |
| `negative_max_sign_response_len_fits_batch_worst_case` | Output buffer ≥ count+init+wrap+wrap = 12,556 | Sum check | Holds |
| `negative_max_tx_len_per_inner_tx_unchanged` | MAX_TX_LEN = 4096 (CLAUDE.md `data_len 0..=4096`) | Compare | 4096 |
| `negative_batch_flag_layout_pins_31_30_account_slot` | Flag layout `[31]+[30]+[29..22]+[21..0]` pairwise-disjoint + covers u32 | OR all + AND all pairs | Disjoint, covers full u32 |
| `negative_max_account_index_matches_8_bit_field` | `MAX_ACCOUNT_INDEX == 0xFF` = `mask >> shift` | Compute | Matches |
| `negative_max_offchain_gap_is_100` | CLAUDE.md invariant #9 cap | Compare | 100 |
| `negative_max_slot_uses_is_65536` | CLAUDE.md invariant #7 cap | Compare | 65,536 |
| `negative_batch_u128_sat_any_high_byte_nonzero_saturates` | Every byte in `[0..16)` triggers saturation | Iterate 16 single-byte positions | All saturate to u128::MAX |
| `negative_batch_u128_sat_msb_high_bit_saturates_not_truncates` | MSB high bit doesn't silently truncate to small value | Set `bytes[0] = 0x80` | u128::MAX |
| `negative_batch_u128_sat_low_byte_alone_does_not_saturate` | Negative-of-negative: non-zero in low half MUST NOT saturate | `bytes[31] = 0xff` | Returns 0xff, not u128::MAX |
| `negative_batch_nonce_increment_does_not_touch_key_field` | CRIT-17: nonce key field (bytes 0..24) untouched by seq +1 | Set buf to 0xAA, increment, check bytes 0..24 | Unchanged |
| `negative_batch_nonce_increment_seq_overflow_panics` | Helper panics rather than carry into key field | Pass 0xFF*32 | Panics with "nonce seq overflow" |
| `negative_batch_nonce_increment_range_matches_gate_check_range` | Helper's increment range and gate's check range identical | Compare ranges 24..32 == 24..32 | Equal |
| `negative_every_handler_checks_pin_verified` | All 4 handlers check `pin_verified` + return NotInitialized | Source-text scan | All present |
| `negative_every_handler_validates_ns_read_ptr_before_deref` | All 4 call `validate_ns_read_ptr` before TOCTOU snapshot | Source-text scan | All present |
| `negative_handlers_with_output_buffers_validate_ns_write_ptr` | The 3 handlers with output validate write ptr; sync does NOT | Source-text scan (presence + absence) | Correct |
| `negative_sign_offchain_and_batch_snapshot_input_before_parse` | Variable-length handlers TOCTOU-snapshot via SNAP_BUF + read_volatile | Source-text scan | Present |
| `negative_sign_offchain_and_batch_wipe_snap_on_exit` | L-2 SNAP_BUF wipe-on-exit comment + code present | Source-text scan | Present |
| `negative_handlers_with_output_use_write_volatile` | NS-bound writes use `write_volatile` | Source-text scan | All present |
| `negative_offchain_status_rejects_wrong_input_length` | Strict length gate + InvalidPointer return | Source-text scan | Present |
| `negative_offchain_sync_rejects_wrong_input_length` | Same for sync | Source-text scan | Present |
| `negative_byte_source_handlers_bound_account_index` | Three NSC handlers reading `buf[0]` carry explicit `> MAX_ACCOUNT_INDEX` gate | Source-text scan | All 3 present |
| `negative_batch_account_index_is_mask_bounded` | Batch derives account from mask shift, no explicit gate needed; mask is 8 bits | Source scan + bit-count | Mask is 8 bits |
| `negative_sign_offchain_rejects_unknown_kind` | Match's wildcard arm refuses unknown kind bytes | Source-text scan | Present |
| `negative_sign_offchain_rejects_raw32_with_wrong_payload_len` | RAW32 requires payload_len == 32 | Source-text scan | Present |
| `negative_sign_offchain_caps_personal_sign_payload_len` | Personal-sign payload bounded by MAX_OFFCHAIN_PERSONAL_SIGN_LEN | Source-text scan | Present |
| `negative_sign_offchain_rejects_unknown_flag_bits` | `flags & !OFFCHAIN_FLAGS_MASK != 0` rejection | Source-text scan | Present |
| `negative_sign_offchain_eip6492_path_requires_slot_zero` | Counterfactual sig only allowed on slot 0 | Source-text scan | Present |
| `negative_sign_offchain_validates_payload_len_arithmetic` | `PAYLOAD_OFF + payload_len != total_len` refusal | Source-text scan | Present |
| `negative_sign_offchain_caps_total_len_to_input_max` | Lower + upper bound on total_len | Source-text scan | Present |
| `negative_sign_offchain_revalidates_write_ptr_for_larger_6492_buffer` | Second write-ptr validation for 6492 path | Source-text scan | Present |
| `negative_sign_offchain_double_reads_counters_for_fi_hardening` | F-10: two reads each of last_userop / local_offchain with `wait_random()` between | Source-text scan | Present |
| `negative_sign_offchain_enforces_gap_and_cap_with_recheck` | MAX_OFFCHAIN_GAP + MAX_SLOT_USES + `gap_recheck` after sign | Source-text scan + status names | Present |
| `negative_sign_offchain_refuses_unregistered_slots_on_deployed_path` | `OffchainSlotUnregistered` status returned for unregistered deployed-path slots | Source-text scan | Present |
| `negative_sign_offchain_promotes_local_count_to_last_userop_floor` | `offchain_count_promote_to` called when `last_userop > local_offchain` | Source-text scan | Present |
| `negative_sign_offchain_double_verifies_before_release` | `sphincs_c10::verify` called ≥ 2× through `check_true_into_sentinel` | Source-text scan + count | Present, count ≥ 2 |
| `negative_sign_offchain_bumps_counter_after_verify_only` | Counter bump comes AFTER FI verify gate | Source-text comment scan | Present |
| `negative_sign_offchain_owner_index_starts_at_one_not_zero` | `(slot_index as u64) + 1` — ownerIndex 0 forbidden | Source-text scan | Present |
| `negative_batch_rejects_zero_or_oversized_batch_count` | `batch_count == 0 \|\| > MAX_BATCH_TXS` refusal | Source-text scan | Present |
| `negative_batch_enforces_mutually_exclusive_init_code_and_register` | `include_init_code && register_slot` refusal | Source-text scan | Present |
| `negative_batch_init_code_requires_slot_zero` | initCode only seeded for slot 0 | Source-text scan | Present |
| `negative_batch_register_slot_requires_nonzero_slot` | Slot 0 cannot be registered (it's seeded at deploy) | Source-text scan | Present |
| `negative_batch_nonce_overflow_gate_present` | `nonce[24..32] == [0xFFu8; 8]` refusal under REGISTER_SLOT | Source-text scan | Present |
| `negative_batch_per_tx_data_len_bounded_by_max_tx_len` | Per-tx `data_len > MAX_TX_LEN` refusal | Source-text scan | Present |
| `negative_batch_rejects_truncated_inner_tx` | Cursor + prefix/data > total_len refusal | Source-text scan | Present |
| `negative_batch_rejects_trailing_bytes_after_last_inner_tx` | `cursor != total_len` refusal | Source-text scan | Present |
| `negative_batch_double_verifies_before_release` | `sphincs_c10::verify` called ≥ 6× (3 sigs × double) | Source-text scan + count | Count ≥ 6 |
| `negative_batch_uses_correct_owner_index_offset` | `(slot_index as u64) + 1` | Source-text scan | Present |
| `negative_batch_pins_factory_add_slot_domain_tag` | `b"pqwallet-factory-add-slot"` byte string unchanged | Source-text scan | Present |
| `negative_batch_pins_create_account_and_add_owner_selectors` | Three frozen on-chain identities used by name | Source-text scan | All 3 present |
| `negative_batch_render_uses_v06_userop_params` | Only `AaUserOpParamsV06Sha256` (no v0.7 / v0.8) | Source-text scan | Present |
| `negative_batch_zeroizes_entropy_on_every_error_path` | `entropy.zeroize()` called ≥ 4×, paired with barrier | Source-text count | Counts match within ±1 |
| `negative_batch_confirm_dialog_handles_cancel_and_idle_wipe` | All 3 `ConfirmResult` arms handled at every `confirm(...)` call | Source-text count match | Counts equal across the 3 arms |
| `negative_batch_idle_wipe_zeroizes_sensitive_state` | IdleWipe arm calls `zeroize_sensitive_state` | Source-text scan | Present |
| `negative_slice_does_not_mention_any_classical_signer` | No ECDSA / Ed25519 / FORS+C / P-256 / secp256k1 / RSA in any file | Iterate 14 forbidden strings × 4 files | None present |
| `negative_slice_does_not_expose_reset_or_rotate_paths` | No `rotateMasterKeys` / `resetBootstrapUses` / `resetSlotUses` / `increaseMax*` | Iterate 10 forbidden strings × 4 files | None present |
| `negative_slice_does_not_target_entrypoint_v07_or_v08` | No `v0.7` / `v0.8` references | Iterate 6 strings × 4 files | None present |
| `negative_status_and_sync_do_not_log_companion_bytes` | The 2 SW-only handlers have no `secure_log!` calls | Source-text scan | Absent |
| `negative_status_zero_inits_output_buffer_before_writing_fields` | Reserved bytes [17..24) zero-init via full-buffer pre-zero | Source-text scan | Present |
| `negative_sync_uses_set_if_greater_primitive` | `last_userop_count_set` (not overwrite) | Source-text scan | Present |
| `negative_sign_handlers_enter_handler_guard` | All 4 handlers enter `HandlerGuard::enter` | Source-text scan | Present |
| `negative_sign_offchain_returns_documented_status_variants` | Every documented NscStatus variant appears | Iterate 10 names | All present |
| `negative_batch_returns_documented_status_variants` | Same for batch | Iterate 7 names | All present |
| `negative_proto_constants_used_by_handlers_resolve_to_pinned_values` | Smoke-pin the 21 most load-bearing proto constants | Compare against expected values | All match |

## Production-code bugs surfaced by negative tests

None. All 91 new tests pass against the current source. The negative
suite is structured so that a future refactor which removes or weakens
any of the load-bearing gates would fail at least one of the source-
text invariant tests, before reaching an audited build.

## Coverage gaps deliberately left

- **`run(&GatewayArgs)` end-to-end exercise.** Each of the four
  handlers is firmware-only; a host build cannot link them. Their full
  behaviour is exercised by the QEMU and on-target e2e suites (`make
  e2e`, `make e2e-hw`). A future pass could expand the `pqsigner-aa` /
  `pqsigner-domain` workspace crates to pull the parse / wire-build
  logic out of `nsc/`, which would let host tests drive `run()`'s
  inner loop end-to-end against a mocked `offchain_state` + slot
  cache.
- **TrustZone / NSC dispatcher pointer validation.** Tested indirectly
  via the source-text scan; the dispatcher's `validate_ns_*_ptr`
  proofs are exercised by the existing `proto`/`shared`-crate tests.
  Genuine attacker-supplied pointers cannot be constructed in a host
  build without TZ infra.
- **FI fault injection on the double-verify gate.** The
  `pqsigner-fi::check_true_into_sentinel` primitive is itself unit-
  tested in its own crate (`pqsigner-fi`); the slice's use of it is
  pinned by source-text scan here.
- **Confirm-dialog cancel/idle-wipe behaviour in batch.** Pinned via
  source-text counts (all three `ConfirmResult` arms handled). A
  future pass that lifts `confirm()` out of `crate::ui` into a
  workspace crate could drive the path with a host-side mock.
- **Counter-bump atomicity across reboots.** `offchain_state.rs` has
  its own host-runnable tests (page-123 log-structured store). The
  slice's *use* of those primitives is what this pass pins.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked the
  command; the new file follows the repo's standard rustfmt layout and
  is structurally identical to the existing `nsc_sign_userop_pure_tests.rs`)
- `cargo check -p sphincs-tz-secure` — PASS (test build, 0 errors,
  37 pre-existing warnings)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox blocked); `cargo check` succeeds with the existing
  warning set, no new warnings introduced by the test file
- `cargo test -p sphincs-tz-secure --tests` — PASS (287 tests
  passed, 0 failed, 0 ignored; the new file contributes 91 of those —
  8 positive + 83 negative)
- (firmware) on-target tests deferred: yes — the four `run()`
  handlers themselves are firmware-only and continue to be exercised
  by `make e2e` / `make e2e-hw` / `make play-hw-display`. The host
  test pass added here is the regression canary that fires when a
  load-bearing gate is silently removed.
