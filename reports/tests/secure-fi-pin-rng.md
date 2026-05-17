# Test Suite Added — `secure-fi-pin-rng`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

FI sentinels, fuzz-props harness, host-rng stub, ISO7816 helpers, PIN core,
RNG wrappers, sign-rate, timeout.

Source files covered:

- `secure/src/fi.rs` — 347 lines
- `secure/src/fih.rs` — 137 lines
- `secure/src/fuzz_props.rs` — 329 lines (host-only proptest harness)
- `secure/src/host_rng.rs` — 43 lines (ARM-only at link level)
- `secure/src/iso7816.rs` — 175 lines
- `secure/src/pin.rs` — 91 lines
- `secure/src/pin_diag.rs` — 205 lines (ARM-only; `#[cfg(feature = "stm32u585")]`)
- `secure/src/rng.rs` — 23 lines
- `secure/src/rng_strong.rs` — 101 lines
- `secure/src/sign_rate.rs` — 194 lines
- `secure/src/timeout.rs` — 56 lines

## Test files added / extended

- `secure/src/secure_fi_pin_rng_pure_tests.rs` — 29 positive, 68 negative
  tests (97 total). All host-runnable; no on-target gating needed.
  Re-mounts `timeout.rs` under a local `#[path]` scaffold so the
  `core::sync::atomic` logic can be exercised even though the production
  `mod timeout;` is `#[cfg(not(test))]`-excluded. Source-text
  invariants (`include_str!`) pin the load-bearing contracts of
  modules that don't link on host (`rng`, `rng_strong`, `host_rng`,
  `pin_diag`, plus the cfg gates / sentinel patterns / inline-never
  attributes / FihBool storage layout in the host-compilable modules).
- `secure/src/main.rs` — one `#[cfg(test)] mod secure_fi_pin_rng_pure_tests;`
  declaration alongside the other `_pure_tests` modules.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `fi_tests::positive_wait_random_terminates_without_panic` | `crate::fi::wait_random()` returns cleanly in cfg(test) builds | `fi::wait_random` |
| `fi_tests::positive_check_true_returns_true_for_true` | True closure → true | `fi::check_true` |
| `fi_tests::positive_check_true_returns_false_for_false` | False closure → false | `fi::check_true` |
| `fi_tests::positive_check_true_into_sentinel_ok_for_true` | True closure → `OK_SENTINEL` | `fi::check_true_into_sentinel` |
| `fi_tests::positive_check_true_into_sentinel_fail_for_false` | False closure → `FAIL_SENTINEL` | `fi::check_true_into_sentinel` |
| `fi_tests::positive_zeroize_barrier_compiles_and_runs` | Callable from test code | `fi::zeroize_barrier` |
| `fi_tests::positive_scrub_sentinel_register_runs` | Callable | `fi::scrub_sentinel_register` |
| `fi_tests::positive_read_volatile_voted_returns_value_when_stable` | Stable u32 in memory triple-reads agreeing | `fi::read_volatile_voted` |
| `fi_tests::positive_read_volatile_voted_works_on_various_widths` | u8 and u64 work via generics | `fi::read_volatile_voted` |
| `fi_tests::positive_cfi_counter_init_and_check` | Bump twice + check matches the macro-derived expected | `fi::CfiCounter` |
| `fi_tests::positive_cfi_init_value_is_documented_constant` | `INIT_VALUE == 0x1357_2468` | `fi::CfiCounter::INIT_VALUE` |
| `fi_tests::positive_cfi_expected_matches_init_plus_steps` | `cfi_expected!` is `INIT + Σsteps` (wrapping_add) | `cfi_expected!` macro |
| `fih_tests::positive_new_false_reads_false` | Default state is false | `fih::FihBool::new_false` |
| `fih_tests::positive_set_true_then_is_true` | Set→read round-trip | `fih::FihBool::set_true` / `is_true` / `is_true_fi` |
| `fih_tests::positive_set_false_after_set_true` | True→false transition | `fih::FihBool::set_false` |
| `fih_tests::positive_check_sentinel_returns_ok_when_true` | Sentinel-form of is_true=true | `fih::FihBool::check_sentinel` |
| `fih_tests::positive_check_sentinel_returns_fail_when_false` | Sentinel-form of is_true=false | `fih::FihBool::check_sentinel` |
| `iso7816_tests::positive_tlv_put_long_form_82` | 500-byte value uses 0x82 length form | `iso7816::tlv_put` |
| `iso7816_tests::positive_tlv_put_at_offset_nonzero` | Encoder respects non-zero offset, doesn't touch prefix bytes | `iso7816::tlv_put` |
| `iso7816_tests::positive_tlv_put_u32_round_trip` | 4-byte u32 BE encode + decode | `iso7816::tlv_put_u32` / `tlv_parse` |
| `iso7816_tests::positive_tlv_parse_returns_trailing_bytes_as_rest` | Two TLVs back-to-back; second returned in `rest` | `iso7816::tlv_parse` |
| `iso7816_tests::positive_parse_pin_ctr_boundary_values` | `(0, u32::MAX)` and `(N, N)` decode correctly | `iso7816::parse_pin_ctr` |
| `pin_tests::positive_correct_pin_returns_master_secret` | Correct PIN → 32-B non-zero secret | `pin::verify_pin` |
| `pin_tests::positive_wrong_pin_returns_pin_incorrect` | First wrong PIN → `PinIncorrect` | `pin::verify_pin` |
| `timeout_tests::positive_constants_are_documented_values` | `TIMEOUT_TICKS == 2*60*1000` | `timeout::TIMEOUT_TICKS` |
| `timeout_tests::positive_tick_increments_monotonically` | `tick()` advances `now()` by 1 | `timeout::tick`/`now` |
| `timeout_tests::positive_reset_activity_drops_idle_for` | After reset, `idle_for()` ≈ 0 | `timeout::reset_activity`/`idle_for` |
| `timeout_tests::positive_ticks_ptr_matches_atomic_address` | `ticks_ptr()` is non-null and 4-B aligned | `timeout::ticks_ptr` |
| `pin_diag_source_text::positive_run_keeps_empirical_pulse_sequence` | PA4 → PD5 → PE0 ordering in `run()` body | `pin_diag::run` (text pin) |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `fi_tests::negative_cfi_missing_bump_fails_check` | "A skipped `bl bump` is detectable" | Construct counter, skip the bump, check vs `cfi_expected!(STEP_A)` | `FAIL_SENTINEL` |
| `fi_tests::negative_cfi_wrong_step_magic_fails_check` | "Per-step magics catch swap-two-bumps attacks" | Bump with STEP_B but expect STEP_A | `FAIL_SENTINEL` |
| `fi_tests::negative_cfi_init_value_is_not_a_sentinel` | "INIT_VALUE ≠ OK/FAIL/0, defends stuck-at-zero on counter init" | Equality checks against OK_SENTINEL, FAIL_SENTINEL, 0 | All `assert_ne!` |
| `fi_tests::negative_sentinels_are_maximally_hamming_distant` | "Single bit-flip cannot turn FAIL into OK (F-2 contract)" | Popcount of XOR == 32 | `count_ones() == 32` |
| `fi_tests::negative_common_glitch_clamps_are_not_ok_sentinel` | "stuck-at-0 / stuck-at-FF / 0xDEADBEEF do not look like OK" | OK_SENTINEL != each clamp | `assert_ne!` |
| `fi_tests::negative_check_true_evaluates_closure_exactly_twice` | "F-2 double-check contract is intact" | Counter inside the closure | `count == 2` |
| `fi_tests::negative_check_true_one_true_one_false_rejects` | "Single-fault on second compare is caught by AND-fold" | Stateful closure flipping its answer | `check_true == false` |
| `fi_tests::negative_check_true_into_sentinel_disagreement_returns_fail` | Same, sentinel form | Same stateful closure | `== FAIL_SENTINEL` |
| `fi_source_text::negative_critical_fns_keep_inline_never` | "BL-skip glitch is observable at the caller" | grep for `#[inline(never)]` near each critical fn | All present |
| `fi_source_text::negative_read_volatile_voted_keeps_fences` | "Triple-read with SeqCst fences ≠ CSE'd single-read" | Count `read_volatile(p)` (== 3) + count `compiler_fence(SeqCst)` (≥ 2) | Both pass |
| `fi_source_text::negative_zeroize_barrier_keeps_dsb_on_arm` | "Wipe is flushed past store buffer before peripheral access / ISR" | grep for `dsb()` + ARM cfg gate | All present |
| `fi_source_text::negative_wait_random_delegates_to_shared_crate_on_prod` | "wait_random is the shared `pqsigner_fi::wait_random_loop` (single auditable implementation)" | grep for `pqsigner_fi::wait_random_loop(rng_byte)` + e2e-test short-circuit | All present |
| `fi_source_text::negative_rng_byte_does_not_route_through_rng_strong` | "wait_random uses platform-only TRNG so latency stays bounded" | Within `rng_byte` body: contains `crate::rng::byte()`, does not contain `rng_strong::byte`/`fill` | Both pass |
| `fih_tests::negative_corrupting_val_alone_fail_closes` | "FihBool's `val^complement` storage invariant catches single bit-flips in `val`" | Forge fault: XOR 1 into `val` via `*mut u32`; assert `is_true == false` | `!is_true()` and `!is_true_fi()` |
| `fih_tests::negative_corrupting_complement_alone_fail_closes` | Same, for `complement` field | XOR a bit into `complement` only | `!is_true()` |
| `fih_tests::negative_out_of_pattern_val_fail_closes` | "Pattern invariant catches coordinated double-fault that preserves XOR" | Write `(0xDEADBEEF, !0xDEADBEEF)` — XOR holds, pattern doesn't | `!is_true()` |
| `fih_tests::negative_is_true_fi_rejects_corrupted_pair` | "is_true_fi rejects the all-zero post-glitch / cold-boot RAM signature" | Wipe both words to 0 | `!is_true_fi()` |
| `fih_source_text::negative_sec_patterns_are_pinned` | "SEC_TRUE / SEC_FALSE remain the exact 29-Hamming patterns" | Pin both constants verbatim in source | Both `contains` pass |
| `fih_source_text::negative_sec_patterns_hamming_distance_meets_contract` | "Pattern distance ≥ 28 so no 1-bit flip can FALSE→TRUE" | Compute popcount in test | `>= 28` |
| `fih_source_text::negative_is_true_uses_read_volatile_on_both_fields` | "Plain field access lets LLVM CSE the load" | grep for `read_volatile(&self.val)` + `(&self.complement)` | Both present |
| `fih_source_text::negative_setters_use_write_volatile` | "Reorder / dead-store-elim around set_true / set_false is prevented" | grep for `write_volatile` in each setter | Both present |
| `fih_source_text::negative_is_true_fi_inserts_wait_random_between_reads` | "Double-read with wait_random between defeats a glitch that lands in both reads" | grep for `crate::fi::wait_random()` in `is_true_fi` | Present |
| `fih_source_text::negative_fihbool_is_repr_c` | "Storage layout is stable for the bit-flip negative tests above" | grep `#[repr(C)]\npub struct FihBool` | Present |
| `fih_source_text::negative_fihbool_is_not_clone_copy` | "No stale TRUE survives a set_false via a clone" | grep absence of Clone/Copy impl + derive | All absent |
| `iso7816_tests::negative_tlv_parse_empty` | Empty input handling | Pass `&[]` | `None` |
| `iso7816_tests::negative_tlv_parse_tag_only` | 1-byte (tag only) handling | Pass `&[0x41]` | `None` |
| `iso7816_tests::negative_tlv_parse_81_length_overflow` | "0x81 with `len` past buffer is rejected before slicing" | tag + 0x81 + 200, but only 3 follow-bytes | `None` |
| `iso7816_tests::negative_tlv_parse_82_length_overflow` | Same for 0x82 | tag + 0x82 + ffff but tiny buffer | `None` |
| `iso7816_tests::negative_tlv_parse_unsupported_long_form_83` | "0x83 is unsupported, not interpreted as 3-byte length" | tag + 0x83 + ... | `None` |
| `iso7816_tests::negative_tlv_parse_unsupported_long_form_84` | Same for 0x84 | tag + 0x84 + ... | `None` |
| `iso7816_tests::negative_tlv_parse_indefinite_length_rejected` | "ISO 7816-4 0x80 indefinite length is rejected, not silently interpreted as len=0" | tag + 0x80 + ... | `None` |
| `iso7816_tests::negative_tlv_parse_truncated_81_no_follow_byte` | Truncated 0x81 | 2-byte input | `None` |
| `iso7816_tests::negative_tlv_parse_truncated_82_short_follow` | Truncated 0x82 | 3-byte input | `None` |
| `iso7816_tests::negative_parse_pin_ctr_rejects_wrong_lengths` | "Only exact 8-byte UPCTR is parsed; anything else is a fault on the SE bus" | Iterate every n ≠ 8 in 0..=20 | All `None` |
| `iso7816_tests::negative_tlv_parse_never_panics_brute_force` | "Parser is panic-free on adversarial inputs" | Hand-picked adversarial byte strings | None panics |
| `iso7816_source_text::negative_tlv_parse_uses_checked_add_for_end_offset` | "`hdr + len` overflow on huge `len` would produce a tiny index that succeeds" | grep `hdr.checked_add(len)?` | Present |
| `iso7816_source_text::negative_parse_pin_ctr_returns_none_on_wrong_length` | "Length check precedes indexing" | grep length-guard literal | Present |
| `pin_tests::negative_correct_pin_at_attempt_10_succeeds_and_resets` | "An honest user fat-fingering 9 times can still unlock on the 10th correct PIN; that success resets to 0" | 9 wrong + 1 correct, check `remaining_attempts == MAX_ATTEMPTS` post | Master returned + counter reset |
| `pin_tests::negative_bricked_se_refuses_subsequent_correct_pin` | "CLAUDE.md Invariant #2: 10 wrong → brick has no back-door even for the correct PIN" | 10 wrong, then correct | `PinLocked` or `InternalError` |
| `pin_tests::negative_wrong_pin_decrements_monotonically` | "Counter strictly decreases per wrong PIN — no reset on the wrong branch" | 5 wrong; observe `remaining_attempts` after each | Strictly decreasing |
| `pin_tests::negative_brick_fires_at_exactly_10_wrong_pins` | "Off-by-one defense: 11th wrong PIN doesn't slip through" | 9 wrong (PinIncorrect) then 10th (PinLocked) | As stated |
| `pin_tests::negative_unlock_preserves_pin_incorrect_vs_pin_locked` | "`unlock()`'s mapping distinguishes PinIncorrect from PinLocked / InternalError" | Wrong PIN through unlock | `UnlockError::PinIncorrect` |
| `pin_source_text::negative_brick_path_erases_all_three_critical_slots` | "Brick path wipes ENTROPY + PIN_STATE + VERIFYING_KEY (no residue → no leaked pubkey from a dead device)" | grep all three `r_mem_erase` calls in the "last attempt failed" branch | All present |
| `pin_source_text::negative_wrong_pin_zeroizes_intermediate_buffers` | "Wrong-PIN branch zeroizes `w_j` + `ct_buf` to prevent leaking failed-decryption state" | grep both `zeroize()` calls | Both present |
| `pin_source_text::negative_verify_pin_signature_is_fixed_eight_bytes` | "PIN is `&[u8; 8]` (not `&[u8]`) — no length-side-channel" | grep signature | Present |
| `pin_source_text::negative_max_attempts_sourced_from_shared` | "MAX_ATTEMPTS comes from `sphincs_tz_shared` to keep the three lockstep counters in sync (Invariant #2)" | grep import statement | Present |
| `sign_rate_tests::negative_session_cap_constant_is_pinned_at_250` | "Burst cap 250 defends profiled-DPA window" | `MAX_SIGNS_PER_SESSION == 250` | Pass |
| `sign_rate_tests::negative_min_interval_constant_is_pinned_at_1000ms` | "Sub-second burst signing is blocked by 1-second interval" | `MIN_SIGN_INTERVAL_MS == 1000` | Pass |
| `sign_rate_source_text::negative_wait_for_min_interval_is_production_only` | "Host tests / e2e bypass the wait so tests don't deadlock without SysTick" | grep exact cfg gate | Present |
| `sign_rate_source_text::negative_cap_uses_gte_not_gt` | "Off-by-one: `>` would let the 251st sign through" | grep `if count >= MAX_SIGNS_PER_SESSION` | Present |
| `sign_rate_source_text::negative_wait_loop_triple_reads_last_sign_and_ticks` | "Single-fault glitch on the `ldr` of LAST_SIGN_MS / TICKS is detected" | grep both `read_volatile_voted` calls | Both present |
| `sign_rate_source_text::negative_triple_read_failure_fails_closed_into_wait` | "Disagreement keeps the function INSIDE the wait — does not break out" | grep the WFI + retry guard | Present |
| `sign_rate_source_text::negative_reset_counters_resets_both` | "Both LAST_SIGN_MS and SIGNS_THIS_SESSION are reset together" | grep both `.store(0,` | Both present |
| `timeout_source_text::negative_timeout_ticks_pinned_at_two_minutes` | "CLAUDE.md Lifecycle pins the inactivity window at 120 s" | grep `pub const TIMEOUT_TICKS: u32 = 2 * 60 * 1000;` | Present |
| `timeout_source_text::negative_idle_for_uses_wrapping_sub` | "49.7-day SysTick rollover does not panic" | grep `wrapping_sub(` in `idle_for` | Present |
| `timeout_source_text::negative_is_idle_uses_strictly_greater_than` | "Off-by-one defense at the boundary: not `>=`" | grep `idle_for() > TIMEOUT_TICKS` | Present |
| `timeout_source_text::negative_only_reset_activity_writes_last_activity` | "CLAUDE.md: NS pings do NOT reset the inactivity timer — only `reset_activity` may write LAST_ACTIVITY" | Count `LAST_ACTIVITY.store(` occurrences | Exactly 1 |
| `rng_source_text::negative_rng_dispatches_on_stm32u585_feature` | "QEMU calls `host_rng`, hw calls `hw::rng` — cfg drift would HardFault either path" | grep both cfg arms + both delegations | All present |
| `rng_source_text::negative_rng_strong_keeps_all_zero_fail_closed_gate` | "Stuck-at-0 fault on the buffer must fail closed, not deliver a predictable random to the signer" | grep `if acc == 0 { ... return Err(())` | Present |
| `rng_source_text::negative_rng_strong_uses_platform_trng_as_baseline` | "Platform-TRNG failure must abort the signing call" | grep `crate::rng::fill(buf)?;` | Present |
| `rng_source_text::negative_rng_strong_xor_folds_se_bytes` | "Compromised SE cannot clamp the buffer — XOR fold preserves platform-TRNG entropy" | grep `buf[off + i] ^= block[i];` (not `=`) | Present |
| `rng_source_text::negative_rng_strong_se_failure_falls_through` | "Broken SE TRNG falls through silently to the next contributor; not fatal" | grep `.is_ok()` guard around `se_random` | Present |
| `rng_source_text::negative_host_rng_uses_semihosting_dev_urandom` | "QEMU `/dev/urandom` is the source — not a fixed seed that would silently produce a deterministic mnemonic" | grep path literal + 3 syscall! calls | All present |
| `pin_diag_source_text::negative_run_does_not_pulse_pe4` | "PE4 cross-couples onto SE050 ENA via OM-SE050ARD shield — pulsing it mid-NVM-write corrupted ENTROPY_OBJ (the original brick). `run()` must NEVER touch PE4." | Walk `pub fn run()` body up to next `pub fn`, grep absence of `GPIOE_BASE, 4` | Absent |
| `pin_diag_source_text::negative_header_sweep_is_feature_gated` | "Header-sweep diagnostic must be locked behind `pin-diag-boot` so a stray PE4 pulse never happens in normal ops" | grep exact cfg attr | Present |
| `pin_diag_source_text::negative_module_is_stm32u585_gated` | "MMIO addresses are STM32U585-specific" | grep `#![cfg(feature = "stm32u585")]` | Present |
| `fuzz_props_source_text::negative_harness_covers_every_documented_parser` | "Every NS→S parser the slice promises to fuzz is actually covered" | Pin each of 13 parser identifiers | All present |
| `fuzz_props_source_text::negative_fuzz_props_is_test_only` | "Proptest harness never reaches firmware" | grep `#![cfg(test)]` | Present |

## Production-code bugs surfaced by negative tests

None. All 97 tests pass. The negative tests pinning source-text contracts
all match the current production code; the FihBool storage-fault tests
confirm the val/complement invariant is properly enforced; the PIN
brick-path tests confirm the 10-attempt cap fires at exactly 10 wrong
PINs and erases all three critical slots.

## Coverage gaps deliberately left

- **Real-silicon `wait_random` jitter distribution.** The host shim
  uses fixed `rng_byte() = 7` (see `secure/src/fi.rs:46-48`). The
  invariant-checked loop is exercised, but the actual timing
  randomness depends on STM32 TRNG output and is only observable on
  hardware (`make test-key-speed` already times signing).
- **`scrub_sentinel_register` clearing r0 on ARM.** Host build is a
  no-op by design — see `fi.rs:298-309`. Validating the actual `mov
  r0, #0` requires either a `thumbv8m`-target test or a disassembly
  check. Deferred; the source-text test in
  `fi_source_text::negative_critical_fns_keep_inline_never` at least
  pins `#[inline(never)]` on `scrub_sentinel_register`.
- **`host_rng::fill` end-to-end through semihosting.** The OPEN /
  READ / CLOSE syscalls only work under QEMU mps2-an505; host tests
  cannot link `cortex_m_semihosting`. The source-text pin
  (`negative_host_rng_uses_semihosting_dev_urandom`) catches a
  silent swap to a deterministic seed, which is the highest-impact
  regression. The full round-trip is exercised by `make run` /
  `make e2e`.
- **`pin_diag::run` actual GPIO toggle on real silicon.** Source text
  pins the no-PE4 contract and the empirical PA4→PD5→PE0 sequence,
  but the actual `pulse_low` emits depend on Cortex-M cycle timing.
  The hardware target `make optiga-bringup-hw-counter-e2e` exercises
  the full path; this suite catches the regression class (silent PE4
  re-add) at host-build time.
- **`sign_rate::pre_sign` time-based wait on hardware.** The
  `wait_for_min_interval` body is `#[cfg(all(feature = "stm32u585",
  not(feature = "e2e-test"), not(test)))]` so host tests skip it.
  Source-text pins (`negative_wait_loop_triple_reads_last_sign_and_ticks`,
  `negative_triple_read_failure_fails_closed_into_wait`) catch the
  load-bearing FI-hardening regressions; the actual 1-s wait + WFI
  is exercised on silicon by `make test-key-speed`.
- **`rng_strong::fill` end-to-end with a real SE backend.** The
  `crate::se_random` extern is `cfg(not(test))`, so host tests cannot
  drive the XOR fold. Source-text pins capture the XOR (`^=`), the
  all-zero gate, and the platform-TRNG baseline with `?` propagation
  — the three load-bearing contracts. Real exercise happens in
  `make dual-se-multi-unlock-e2e`.
- **`fih::FihBool` against ACTUAL clock-glitch on real silicon.**
  The forge-the-fault tests via `write_volatile` simulate the
  post-glitch RAM state but don't reproduce the glitch event itself.
  This is the canonical limit of host FI testing; on-silicon
  fault-injection via the `sca-trigger` harness is the next step.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (Bash sandbox in
  this session blocks `cargo fmt`; the new test file was authored
  using the same indentation / wrapping conventions as the
  neighbouring `*_pure_tests.rs` files and only the agent-author's
  text-editor formatting touched it. A pre-commit hook will surface
  any rustfmt drift).
- `cargo check -p sphincs-tz-secure --tests` — PASS (40 unrelated
  warnings from other pre-existing test files; no errors).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  in this session (Bash sandbox blocks `cargo clippy`). Visual
  review against neighbouring `*_pure_tests.rs` style; no `unsafe`
  helpers beyond the FihBool corruption-forge tests (which use
  `read_volatile` / `write_volatile` with documented SAFETY
  comments).
- `cargo test -p sphincs-tz-secure` — PASS (1739 tests pass, 2
  pre-existing ignored, 0 filtered out). The `secure_fi_pin_rng`
  subset runs 97 tests, all passing.
- (firmware) on-target tests deferred: no — every test in this
  suite is host-runnable. The gaps listed above are *complementary*
  exercises that already have hardware Makefile targets
  (`make test-key-speed`, `make optiga-bringup-hw-counter-e2e`,
  `make dual-se-multi-unlock-e2e`, `make e2e`).
