# Test Suite Added — `secure-nsc-small-cmds`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Small NSC command handlers (unlock, address, init-code, lock, etc.) — the
short-form gateway commands that aren't covered by the dedicated
`secure-nsc-sign-userop` and `secure-nsc-batch-offchain` test slices.

Source files covered:
- `secure/src/nsc/cmd_request_unlock.rs` — 168 lines
- `secure/src/nsc/cmd_get_wallet_address.rs` — 145 lines
- `secure/src/nsc/cmd_get_init_code.rs` — 271 lines
- `secure/src/nsc/cmd_get_remaining.rs` — 41 lines
- `secure/src/nsc/cmd_is_unlocked.rs` — 17 lines
- `secure/src/nsc/cmd_lock.rs` — 16 lines
- `secure/src/nsc/cmd_test_pin_lockout.rs` — 237 lines
- `secure/src/nsc/factory_calldata.rs` — 89 lines

All eight transitively reach `static mut crate::SE`, the OLED stack,
flash I/O, FI helpers, or `crate::sign_rate`, so no `run()` function can
be linked into a `cargo test -p sphincs-tz-secure` host build. The
coverage strategy mirrors the existing
`nsc_sign_userop_pure_tests` / `nsc_batch_offchain_pure_tests` files:

1. Pure-logic **mirrors** of the deterministic parts (`CREATE2` address
   derivation, ABI-only half of `factory_calldata::build`).
2. Wire-format / on-chain-ABI **constant pins** for every length,
   selector, embedded address, and domain string the slice reads from
   `pqsigner-proto`.
3. **Source-text invariant pins** — the load-bearing FI / lockout /
   validation / TOCTOU / verify-before-release patterns. A future
   refactor that quietly drops any one of them surfaces here rather
   than at run-time on a bench board.
4. **Cross-cutting policy negatives** sweeping all eight files for
   forbidden symbols (classical signers, `rotate*` / `reset*` paths,
   EntryPoint v0.7 / v0.8, heap allocators, software PRNGs).

## Test files added / extended
- `secure/src/nsc_small_cmds_pure_tests.rs` — 30 positive, 67 negative
  tests (host-runnable; `#![cfg(test)]`). Brand-new file.
- `secure/src/main.rs` — `#[cfg(test)] mod nsc_small_cmds_pure_tests;`
  registration line added next to the existing
  `nsc_sign_userop_pure_tests` / `nsc_batch_offchain_pure_tests` mods.
  No production code change.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_create2_deterministic_for_fixed_input` | repeated derivation gives identical output | `cmd_get_wallet_address` CREATE2 step |
| `positive_create2_uses_low_20_bytes_of_keccak` | address = keccak[12..32] | `cmd_get_wallet_address` |
| `positive_create2_distinct_inputs_yield_distinct_addresses` | distinct (pkSeed, pkRoot) ↦ distinct addresses | `cmd_get_wallet_address` |
| `positive_create2_preimage_first_byte_is_0xff` | source pins `pre[0] = 0xff` | `cmd_get_wallet_address` |
| `positive_factory_calldata_selector_at_offset_zero` | byte [0..4] = `PQ_CREATE_ACCOUNT_SELECTOR` | `factory_calldata::build` |
| `positive_factory_calldata_master_pk_seed_at_offset_4` | byte [4..36] = masterPkSeed | `factory_calldata::build` |
| `positive_factory_calldata_master_pk_root_at_offset_36` | byte [36..68] = masterPkRoot | `factory_calldata::build` |
| `positive_factory_calldata_slot0_seed_at_offset_68` | byte [68..100] = slot0PkSeed | `factory_calldata::build` |
| `positive_factory_calldata_slot0_root_at_offset_100` | byte [100..132] = slot0PkRoot | `factory_calldata::build` |
| `positive_factory_calldata_chain_id_is_left_padded_u256` | chainId is uint64 left-padded into uint256 slot | `factory_calldata::build` |
| `positive_factory_calldata_dynamic_bytes_offset_is_0xc0` | tail offset = 6 × 32 | `factory_calldata::build` |
| `positive_factory_calldata_dynamic_bytes_length_matches_c10_sig_len` | dynamic-bytes len = `C10_SIG_LEN` | `factory_calldata::build` |
| `positive_factory_calldata_total_length_is_eip6492_constant` | total = 4260 = init_code − 20 | `factory_calldata::build` |

## Negative coverage (the important one)

### CREATE2 — invariant #6 (cross-chain address stability)
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_create2_address_is_20_bytes_exact` | address length is exactly 20 B | size check | length = 20 |
| `negative_create2_salt_is_sha256_not_keccak256` | salt uses SHA-256, not keccak | source-text grep for `Sha256::new()` | present |
| `negative_create2_preimage_uses_keccak256_not_sha256` | preimage uses keccak256 (EVM-mandated) | grep `Keccak256::new()` | present |
| `negative_create2_pk_seed_and_pk_root_are_distinct_positions` | (pkSeed, pkRoot) order matters | swap inputs | addresses differ |
| `negative_create2_factory_address_is_pinned` | `PQ_SMART_WALLET_FACTORY` frozen value | compare bytes | exact match to canonical 20-byte address |
| `negative_create2_proxy_init_code_hash_is_pinned` | `PROXY_INIT_CODE_HASH` frozen value | compare bytes | exact match to canonical 32-byte hash |
| `negative_create2_factory_address_not_all_zero` | not silently zeroed | inequality vs `[0; 20]` | non-zero |
| `negative_create2_proxy_init_code_hash_not_all_zero` | not silently zeroed | inequality vs `[0; 32]` | non-zero |

### `factory_calldata::build` — frozen on-chain ABI shape
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_factory_calldata_signature_window_is_padded_to_32` | sig occupies [228..4236], 24 zero pad to 4260 | arithmetic check | exact 24-byte tail |
| `negative_factory_calldata_chain_id_high_24_bytes_must_be_zero` | chainId is left-padded uint64-in-uint256 | provide max u64, inspect upper 24 B | all zero |
| `negative_factory_calldata_does_not_overflow_when_chain_id_is_zero` | chainId == 0 OK | zero input | slot all-zero |
| `negative_factory_calldata_offset_field_high_bytes_zero` | dynamic-bytes offset is 0xC0, upper 31 B zero | inspect bytes | upper 31 zero, byte 195 = 0xC0 |
| `negative_factory_calldata_length_field_high_bytes_zero` | dynamic-bytes length high 30 B zero | inspect bytes | upper 30 zero, low 2 = 4008 |
| `negative_factory_calldata_pk_seed_and_root_layout_order` | seed/root order matters | distinct fixtures | each lands at documented offset |
| `negative_factory_calldata_independent_calls_match_byte_for_byte` | determinism | two identical builds | byte-equal |

### Wire-format / on-chain-ABI constant pins
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_max_attempts_is_ten` | MAX_ATTEMPTS = 10 (CLAUDE.md inv #2) | const equality | == 10 |
| `negative_max_account_index_is_eight_bit_mask` | MAX_ACCOUNT_INDEX = 0xFF | const equality | == 0xFF |
| `negative_pq_init_code_len_is_4280` | initCode length frozen | const equality | == 4280 |
| `negative_eip6492_factory_calldata_len_is_init_code_minus_20` | factory addr is the 20-byte prefix | sum check | matches |
| `negative_c10_sig_len_unchanged_4008` | C10 sig length frozen | const equality | == 4008 |
| `negative_factory_add_slot_domain_unchanged` | domain string frozen | byte/length equality | exact |
| `negative_pq_create_account_selector_unchanged` | factory selector frozen | byte equality | exact |
| `negative_get_init_code_input_len_is_12` | INPUT_LEN = 12 (4+8) | source-text grep | declared exactly |
| `negative_get_wallet_address_output_len_is_20` | ADDR_LEN = 20 | source-text grep | declared exactly |

### `cmd_request_unlock` — three-way lockstep + FI hardening
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_request_unlock_uses_gated_unlock_not_raw_se_unlock` | PIN verify goes through `gated_unlock` (inv #2) | grep presence + absence of `se.unlock(` | gated_unlock called, raw bypass absent |
| `negative_request_unlock_pre_commits_attempt_counter_before_se_call` | pre-commit bump before SE call | grep `Pre-commit` + `pin_attempts_bump` | both present |
| `negative_request_unlock_fail_in_fi_pattern_present` | F-15 sentinel-encoded FAIL-IN | grep sentinel symbols | `check_true_into_sentinel`, `OK_SENTINEL` |
| `negative_request_unlock_double_reads_post_bump_counter` | F-15 double-read with wait_random | grep `pin_attempts_read` + `wait_random` + `if a != b` | all present |
| `negative_request_unlock_zeroizes_pin_buffer_before_return` | PIN bytes wiped from stack | grep `pin_copy.zeroize()` | present |
| `negative_request_unlock_idle_wipe_zeroizes_state` | IdleWipe path zeroizes master_secret | grep `IdleWipe` + `zeroize_sensitive_state` | both present |
| `negative_request_unlock_trigger_lockout_wipe_runs_factory_reset_admin` | 10 wrong PINs ⇒ admin wipe (inv #2) | grep `factory_reset_admin` + `pin_attempts_reset` | both present |
| `negative_request_unlock_uses_handler_guard_to_block_idle_wipe` | HIGH-7 SysTick race fix | grep `HandlerGuard::enter()` | present |
| `negative_request_unlock_last_attempt_message_only_at_one` | UX warning fires at exactly 1 | grep `if remaining_after == 1` | present (not `<= 1` or `< 2`) |
| `negative_request_unlock_does_not_implement_software_pin_compare` | No SW PIN compare (inv #2) | grep absence of `ConstantTimeEq` / `== pin` | both absent |
| `negative_request_unlock_no_classical_signer_mentions` | Inv #5 single-signer | grep absence of 6 forbidden names | all absent |

### `cmd_get_wallet_address`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_get_wallet_address_checks_pin_verified` | unlock gate (inv #2) | grep `pin_verified.check_sentinel` + `NotInitialized` | both present |
| `negative_get_wallet_address_validates_write_ptr_before_deref` | NS-ptr validation precedes deref (inv #4) | source-position check: `validate_ns_write_ptr` before `write_volatile` | order correct |
| `negative_get_wallet_address_rejects_account_index_above_mask` | refuse stale companion that sends index ≥ 256 | grep `account_index > MAX_ACCOUNT_INDEX` | present |
| `negative_get_wallet_address_uses_volatile_writes_to_ns` | volatile NS writes | grep `write_volatile` | present |
| `negative_get_wallet_address_wraps_secrets_in_zeroizing` | stack secrets in `Zeroizing<>` | grep `Zeroizing::new` | present |
| `negative_get_wallet_address_no_rotate_or_reset_paths` | no forbidden APIs in slice | grep absence of 5 forbidden names | all absent |

### `cmd_get_init_code`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_get_init_code_uses_handler_guard` | HIGH-7 (multi-second keygen) | grep `HandlerGuard::enter()` | present |
| `negative_get_init_code_checks_pin_verified` | unlock gate | grep `pin_verified.check_sentinel` + `NotInitialized` | both present |
| `negative_get_init_code_strictly_checks_total_len_against_input_len` | strict `!=` length check | grep `total_len != INPUT_LEN` | present (rejects `>=`/`<` regressions) |
| `negative_get_init_code_validates_both_ns_pointers_before_deref` | TOCTOU (inv #4) | source-position check on both pointers | both validators precede their derefs |
| `negative_get_init_code_snaps_input_into_stack_buffer` | TOCTOU snapshot | grep stack-buffer copy + volatile reads | both present |
| `negative_get_init_code_rejects_account_index_above_mask` | refuse index ≥ 256 | grep | present |
| `negative_get_init_code_emits_pq_init_code_len_bytes` | output is full PQ_INIT_CODE_LEN | grep `for i in 0..PQ_INIT_CODE_LEN` | present |
| `negative_get_init_code_delegates_calldata_layout_to_factory_calldata` | single source of truth | grep `super::factory_calldata::build` | present |
| `negative_get_init_code_first_20_bytes_are_factory_address` | initCode starts with factory addr (inv #6) | grep `ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY)` | present |
| `negative_get_init_code_wraps_secrets_in_zeroizing` | ZeroizeOnDrop for stack secrets | grep `Zeroizing` | present |
| `negative_get_init_code_uses_c10_sign_verified_with_progress` | verify-before-release | grep present + absence of raw `.sign(` | as expected |

### `cmd_get_remaining`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_get_remaining_uses_min_of_mcu_and_se` | MIN-across-counters policy | grep `.min(` | present |
| `negative_get_remaining_uses_saturating_subtract_against_max` | clamp instead of wrap | grep `saturating_sub` | present |
| `negative_get_remaining_persists_value_into_secure_state` | UI display sync | grep `s.remaining_attempts = remaining` | present |

### `cmd_is_unlocked`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_is_unlocked_uses_fi_hardened_read_not_raw_bool` | F-14 FihBool | grep `pin_verified.is_true_fi()` | present |
| `negative_is_unlocked_returns_only_zero_or_one` | only `0`/`1` returns, file stays tiny | grep + line count | < 30 lines |

### `cmd_lock`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_lock_calls_zeroize_sensitive_state` | wipe on demand | grep `zeroize_sensitive_state()` | present |
| `negative_lock_returns_ok_status` | companion-friendly result | grep `NscStatus::Ok` | present |

### `cmd_test_pin_lockout` (e2e-test only)
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_test_pin_lockout_correct_pin_matches_e2e_fastpath_value` | CORRECT_PIN aligns with main.rs e2e provisioning | exact byte-pattern grep | match |
| `negative_test_pin_lockout_wrong_pin_differs_from_correct` | WRONG_PIN ≠ CORRECT_PIN | exact byte-pattern grep | distinct |
| `negative_test_pin_lockout_pass_a_runs_max_minus_one_wrong_pins` | pass A keeps SE050 lifetime budget intact | grep `MAX_ATTEMPTS as usize).saturating_sub(1)` | present |
| `negative_test_pin_lockout_compiled_only_under_e2e_test_feature` | never ships in production | grep mod feature gate | gated |
| `negative_test_pin_lockout_cleanup_restores_unlocked_state` | leaves session healthy | grep `unlock_with_master(master_final)` | present |
| `negative_test_pin_lockout_passes_b_is_stm32u585_only` | MCU page-124 is silicon-only | grep `#[cfg(feature = "stm32u585")]` | present |

### `factory_calldata`
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_factory_calldata_pins_factory_add_slot_domain` | bootstrap-sig domain frozen | grep tag + len assertion | both present |
| `negative_factory_calldata_fills_buffer_before_writing_fields` | tail zero-pad contract | grep `out.fill(0);` | present |
| `negative_factory_calldata_returns_crypto_error_on_sign_failure` | error-code stability for companion | grep `NscStatus::CryptoError` | present |
| `negative_factory_calldata_no_classical_signers` | inv #5 | grep absence of 7 banned names | all absent |

### `nsc/mod.rs::gated_unlock` (shared primitive every slice file relies on)
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_gated_unlock_refuses_when_counter_at_max` | hard cap at MAX_ATTEMPTS | grep `pre_count < MAX_ATTEMPTS` + `PinLocked` | both present |
| `negative_gated_unlock_refuses_on_flash_bump_failure` | refuse without calling SE on flash fault | grep `pin_attempts_bump().is_err()` + `InternalError` | both present |
| `negative_gated_unlock_uses_fi_double_check_on_result` | F-19 triple-read | grep `is_ok_1`/`is_ok_2` + `check_true_into_sentinel` | all present |
| `negative_gated_unlock_resets_counter_only_on_clean_ok` | counter reset gated on sentinel | grep `Ok(master) if verdict == crate::fi::OK_SENTINEL` | present |

### Cross-cutting policy negatives (sweep all 8 slice files)
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_no_slice_file_mentions_a_classical_signer` | inv #5 single-signer | grep 7 banned names across 8 files | all absent |
| `negative_no_slice_file_exposes_reset_or_rotate_paths` | no rotate/reset paths | grep 10 banned names across 8 files | all absent |
| `negative_no_slice_file_targets_entrypoint_v07_or_v08` | EntryPoint v0.6 frozen | grep 6 banned names across 8 files | all absent |
| `negative_no_slice_file_uses_format_or_alloc` | no heap (Code Conventions) | grep 7 alloc/format names across 8 files | all absent |
| `negative_no_slice_file_uses_software_prng` | hardware TRNG only | grep 5 SW-PRNG names across 8 files | all absent |

### NS-pointer validator window sanity
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_ns_sram_window_is_strictly_below_ns_sram_end` | non-empty NS SRAM window | inequality | base < end |
| `negative_ns_flash_window_is_strictly_below_ns_flash_end` | non-empty NS flash window | inequality | base < end |
| `negative_shared_mailbox_lies_inside_ns_sram` | mailbox nests inside NS SRAM | range check | nested |
| `negative_shared_mailbox_window_nonzero` | non-empty mailbox window | inequality | base < end |
| `negative_ns_sram_and_ns_flash_are_disjoint_regions` | validate_ns_read_ptr union math is safe | overlap test | disjoint |

### NscStatus stability
| test name | assumption challenged | how attacked | expected outcome |
|---|---|---|---|
| `negative_nsc_status_codes_pin` | Ok = 0 + every other code distinct/non-zero | enumerate + pairwise compare | invariants hold |

## Production-code bugs surfaced by negative tests
None. Every negative test passed against the current source, which is
the desired baseline — each one is now wired to fail loudly the next
time someone changes the underlying gate.

## Coverage gaps deliberately left
- **Live invocation of `factory_calldata::build`.** The function calls
  into `crate::crypto::c10_sign_verified_with_progress`, which (a)
  requires a real `sphincs_c10::SigningKey` (multi-second keygen), and
  (b) is expensive enough to dominate the host test wall-clock if run
  for every fixture. Tested instead via the ABI-only mirror
  (`mirror_build_calldata_abi_only`) plus source-text invariants. A
  follow-up pass with a fixed mnemonic + cached `SigningKey` could
  byte-compare full output against the real build.
- **NS-pointer validator behaviour under the `TT` instruction.** The
  `tt_range_is_ns()` path is `#[cfg(feature = "stm32u585")]`-gated and
  needs real silicon to exercise — the existing on-target `make e2e-hw`
  suite covers it. Host tests pin only the constant-window math.
- **PIN-lockout-wipe end-to-end.** The full 10-wrong-PINs → admin-wipe
  → page-124-erase sequence runs on real silicon via `make
  pin-gate-wipe-e2e`. Host coverage is necessarily limited to
  source-text pins of the lockout path (`trigger_lockout_wipe`,
  `factory_reset_admin`, `pin_attempts_reset`).
- **HandlerGuard / SysTick race regression.** The `HandlerGuard`
  RAII increment / decrement uses real `AtomicU32` ordering; a true
  race test needs a SysTick IRQ, which is on-target only. Host tests
  pin only the guard's presence at the right handler entry points.
- **Linker-emitted CMSE veneer behaviour.** The `nsc_*` entry-point
  functions are real ARMv8-M `cmse-nonsecure-entry` thunks that only
  the `--cmse-implib` pass emits; cannot be exercised from `x86_64`.
- **`debug-log` / `mock-se` / `e2e-test` production fence.** Already
  enforced by the `compile_error!` block in `nsc/mod.rs`; a `trybuild`
  test would duplicate but not deepen the existing fence (which fires
  at build time for every offending combination).

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox blocked
  the invocation; the file follows the same style as the existing
  `nsc_*_pure_tests.rs` siblings — no tabs, 4-space indent, 100-col
  lines, attribute lists single-spaced).
- `cargo check -p sphincs-tz-secure` — **PASS** (only pre-existing
  unused-import / dead-code warnings; the new test file is
  warning-free).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` —
  **N/A** (sandbox blocked the invocation; `cargo check` is
  warning-free for the new file).
- `cargo test -p sphincs-tz-secure` — **PASS** (384 tests passed, 0
  failed, 0 ignored; 97 of the 384 are new). New file alone:
  `cargo test -p sphincs-tz-secure --tests nsc_small_cmds` →
  `97 passed; 0 failed; 0 ignored`.
- On-target tests deferred: **no** (this pass added only host-runnable
  tests; the firmware-only behaviour listed under "Coverage gaps
  deliberately left" is exercised by existing on-target `make`
  targets).
