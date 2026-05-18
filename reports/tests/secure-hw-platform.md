# Test Suite Added — `secure-hw-platform`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

Platform peripherals: flash, TAMP, RCC, RNG, PKA, consumption-mask,
boot-state, sca-trigger, boot-pulse.

Source files covered:
- `secure/src/hw/flash.rs:1713` — bank-1 / bank-2 program & erase, PIN
  attempt counter (page 124), off-chain journal (page 123), wipe flag
  (page 125), key page (page 127), slot geometry.
- `secure/src/hw/tamp.rs:387` — TAMP + RTC log-only IRQ harness.
- `secure/src/hw/consumption_mask.rs:270` — TIM2-CH1 PWM power mask on PA5.
- `secure/src/hw/sca_trigger.rs:145` — SCA-rig GPIO sync (dev-only).
- `secure/src/hw/rcc.rs:172` — SYSCLK PLL config @ 160 MHz, HSI48 for RNG.
- `secure/src/hw/rng.rs:140` — STM32U585 hardware TRNG driver.
- `secure/src/hw/pka.rs:244` — PKA accelerator for BLS12-381 Fp Montgomery mul.
- `secure/src/hw/boot_pulse.rs:143` — RDP1 boot-bisection GPIO (dev-only).
- `secure/src/hw/boot_state.rs:140` — FSBL slot-pick redundant page.

All nine files are firmware-only by feature gate (`stm32u585`, `tamp`,
`consumption-mask`, `boot-pulse`, `sca-trigger`, `pka-accel`) and
cannot link on host because they pull in `cortex_m`. The slice
therefore matches the precedent set by the `secure-hw-crypto` slice:
host tests pin the slice via `include_str!` source-text invariants
plus reference re-implementations of the wire-format encoders.

## Test files added / extended

- `secure/src/hw_platform_under_test/mod.rs` — new scaffold module
  (mirrors `secure/src/hw_crypto_under_test/`), gated `#[cfg(test)]`.
- `secure/src/hw_platform_under_test/pure_tests.rs` — **55 positive,
  54 negative tests** (109 total) covering the slice's flash
  geometry, register addresses, wire formats, dev-feature production
  fences, FI guards, monotonicity gates, and forbidden-API exclusion.
- `secure/src/main.rs` — added `#[cfg(test)] mod hw_platform_under_test;`
  next to the existing `hw_crypto_under_test` test scaffold (the only
  non-test edit; pure `cfg(test)` declaration).

No `[dev-dependencies]` additions were needed — `fw_manifest` (CRC32)
and `hex` are already in scope.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_flash_key_page_127` | KEY_PAGE_ADDR=0x0C0F_E000 / KEY_PAGE_NUM=127 | flash.rs key page |
| `positive_flash_admin_page_125` | ADMIN_PAGE_ADDR + WIPE_FLAG_OFFSET=16 + WIPE_FLAG_ARMED=0x00 | flash.rs SE admin page |
| `positive_flash_pin_attempts_page_124` | PIN_ATTEMPTS_PAGE_ADDR + capacity=32 + QW=16 | flash.rs PIN counter |
| `positive_flash_offchain_journal_page_123` | OFFCHAIN page addr/num + CAPACITY=512 + type=0x01/0x02 | flash.rs journal |
| `positive_flash_boot_state_page_6` | BOOT_STATE_ADDR + BOOT_STATE_PAGE | flash.rs boot state |
| `positive_flash_manifest_pages_4_and_5` | manifest A/B page addresses | flash.rs manifest |
| `positive_flash_slot_layout_bank1_secure` | secure slot A/B page ranges + 464 KB cap | flash.rs slot geometry |
| `positive_flash_slot_layout_bank2_ns` | NS slot A/B page ranges + 512 KB cap | flash.rs slot geometry |
| `positive_flash_secure_alias_0x5002_2000` | FLASH controller secure alias | flash.rs MMIO |
| `positive_flash_unlock_key_sequence` | KEY1=0x4567_0123, KEY2=0xCDEF_89AB | flash.rs unlock |
| `positive_flash_seccr_bit_positions` | PG/PER/STRT/LOCK + PNB_SHIFT | flash.rs SECCR layout |
| `positive_flash_secsr_error_mask` | BSY=1<<16, ERR_MASK=0xFA | flash.rs SECSR |
| `positive_flash_bker_bit_for_bank2` | BKER=1<<11 (bank 2 select) | flash.rs NSCR |
| `positive_flash_icache_secure_alias` | ICACHE_BASE=0x5003_0400 | flash.rs ICACHE |
| `positive_rcc_ns_alias_for_clock_setup` | RCC uses NS alias 0x4602_0C00 | rcc.rs |
| `positive_rcc_secure_aliases_for_pwr_flash_icache` | PWR/FLASH/ICACHE secure aliases | rcc.rs |
| `positive_rcc_pll1_dividers_target_160mhz` | PLL1_N=20-1, PLL1_R=2-1<<24 | rcc.rs PLL config |
| `positive_rcc_hsi48_for_rng_clock` | HSI48ON/HSI48RDY pinned | rcc.rs |
| `positive_rcc_flash_latency_4ws_required_for_160mhz` | flash ACR latency=4WS | rcc.rs |
| `positive_rng_peripheral_secure_alias` | RNG=0x520C_0800 | rng.rs |
| `positive_rng_nist_compliant_default_cr` | RNG_CR_NIST_DEFAULT=0x00F0_0D00 | rng.rs |
| `positive_rng_condrst_bit_30` | CONDRST=1<<30 (NOT bit 6) | rng.rs |
| `positive_pka_peripheral_secure_alias` | PKA_BASE=0x520C_2000 | pka.rs |
| `positive_pka_ram_offsets_match_rm0456` | NB_BITS / OP1 / OP2 / RESULT / MODULUS offsets | pka.rs |
| `positive_pka_montgomery_mul_opcode` | MODE_MONTGOMERY_MUL=0x10 | pka.rs |
| `positive_pka_bls12_381_field_size_384_bits` | BLS12_381_BITS=384, N_LIMBS=12 | pka.rs |
| `positive_tamp_secure_alias_and_irqn_2` | TAMP=0x5600_4400, IRQN=2 | tamp.rs |
| `positive_tamp_rcc_pwr_secure_aliases` | RCC/PWR secure aliases for backup domain | tamp.rs |
| `positive_tamp_itamp_enable_bit_positions` | every ITAMP*E bit position | tamp.rs CR1 layout |
| `positive_tamp_reason_from_sr_covers_crypto_fault` | CRYPTO_FAULT / VOLTAGE / LSE_CLOCK / IWDG / SWD strings present | tamp.rs reason labels |
| `positive_tamp_reason_each_bit_maps_to_expected_label` | reference `reason_from_sr` matches per-bit mapping | tamp.rs reason mapping |
| `positive_tamp_reason_zero_is_unknown` | SR=0 → UNKNOWN, not panic | tamp.rs reason mapping |
| `positive_tamp_reason_priority_voltage_over_temperature` | first-match-wins priority order | tamp.rs reason mapping |
| `positive_consumption_mask_pa5_pwm_tim2_ch1` | TIM2=0x5000_0000, GPIOA=0x5202_0000, TIMER_PERIOD=16_000 | consumption_mask.rs |
| `positive_consumption_mask_pwm_mode1` | OC1M=PWM1, OC1PE (preload) | consumption_mask.rs |
| `positive_sca_trigger_pin_pd2` | TRIG_GPIO_PORT_BASE=GPIOD_S, TRIG_PIN=2 | sca_trigger.rs |
| `positive_sca_trigger_off_state_init_is_no_op` | OFF-state init is `#[inline(always)] pub fn init() {}` | sca_trigger.rs |
| `positive_sca_trigger_off_state_trig_high_is_no_op` | OFF-state trig_high / trig_low are inlined no-ops | sca_trigger.rs |
| `positive_sca_trigger_struct_has_drop_for_pairing` | RAII pairing via `impl Drop for Trigger` | sca_trigger.rs |
| `positive_sca_trigger_raise_calls_trig_high_before_returning` | raise() calls trig_high THEN constructs Self | sca_trigger.rs |
| `positive_boot_pulse_pin_pe13` | TARGET_PIN=13, GPIOE_BASE=0x5202_1000 | boot_pulse.rs |
| `positive_boot_state_magic_is_bste` | BSTATE_MAGIC = b"BSTE" | boot_state.rs |
| `positive_boot_state_size_is_one_quadword` | BSTATE_SIZE=16 (atomic write) | boot_state.rs |
| `positive_boot_state_copy_addresses` | copy A at +0, copy B at +0x1000 (anti-torn) | boot_state.rs |
| `positive_boot_state_encode_slot_a_layout` | byte-exact encode_ref output for Slot A | boot_state.rs reference |
| `positive_boot_state_encode_slot_b_byte` | slot B byte = 0x01 | boot_state.rs |
| `positive_boot_state_round_trip_crc_validates` | CRC32-IEEE over bytes [0..12) round-trips | boot_state.rs |
| `positive_entry_qw_layout_is_pinned_in_source` | slot_key/type/count_be packing identical to flash.rs | flash.rs journal |
| `positive_entry_qw_count_packing_is_7_byte_be` | 7-byte BE drops top u64 byte by design | flash.rs journal |
| `positive_entry_qw_min_count_zero` | count=0 packs to expected null buffer | flash.rs journal |
| `positive_entry_qw_distinct_types_diverge` | type 0x01 vs 0x02 yields distinct QWs | flash.rs journal |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_flash_uses_secure_alias_not_ns_alias` | FLASH controller MMIO uses secure-bus alias | source scan rejects NS alias 0x4002_2000 | absent — must use 0x5002_2000 |
| `negative_rng_uses_secure_alias_not_ns_alias` | RNG NS alias (0x420C_0800) bus-faulted at first boot | source scan rejects the NS alias | absent — must use 0x520C_0800 |
| `negative_pka_uses_secure_alias_not_ns_alias` | TZSC blocks PKA NS alias | source scan rejects 0x420C_2000 | absent — must use 0x520C_2000 |
| `negative_tamp_pwr_alias_matches_secure_backup_domain` | backup-domain regs are secure-only | source scan rejects PWR NS alias | absent — must use 0x5602_0800 |
| `negative_consumption_mask_tim2_is_secure_alias` | TZ-default-secure drops NS TIM2 writes | source scan rejects NS TIM2 alias | absent — must use 0x5000_0000 |
| `negative_flash_icache_base_is_correct_off_by_400` | wrong base (off by 0x400) HardFaulted previously | source scan rejects 0x5003_0000 | absent — must use 0x5003_0400 |
| `negative_sca_trigger_module_warns_production_fence` | dev-feature prose warning prevents accidental ship | source must contain "production-fence" + ship warning | both present |
| `negative_boot_pulse_is_module_level_feature_gated` | dev-feature must disappear from prod builds | source must have `#![cfg(feature = "boot-pulse")]` | present at top of file |
| `negative_boot_pulse_module_documents_never_ship_constraint` | prose-pin tells auditor the file is bring-up-only | docstring must explain RDP≥1 purpose | present |
| `negative_consumption_mask_implies_stm32u585` | feature combo prevents QEMU pulling STM32 MMIO | `hw/mod.rs` gate combines both flags | combined gate present |
| `negative_tamp_module_dual_feature_gated` | same for TAMP / stm32u585 combo | hw/mod.rs combined gate | combined gate present |
| `negative_pka_module_gated_on_pka_accel_only` | host bls12_381 fork must reach pka.rs | hw/mod.rs gates pka only on `pka-accel` | matches expected gate |
| `negative_offchain_count_bump_refuses_regression` | invariant #9: monotonic off-chain counter | source has `if new_count <= pre { return Err }` | present |
| `negative_offchain_count_bump_readback_verified` | FI glitch that suppresses program is detected | post-write `read != new_count → Err` + FI sentinel | both present |
| `negative_offchain_count_read_fi_double_scan_halt_on_mismatch` | F-12: forward + reverse scan halt-on-mismatch | source has both scans + `r1 != r2 → u64::MAX` | present, returns sentinel |
| `negative_offchain_count_read_slot_key_input_redundancy` | F-12: stuck-at on slot_key register | sk_a/sk_b double-load + compare | present |
| `negative_pin_attempts_bump_readback_verified_with_fi_sentinel` | FI-glitched bump silently bypasses lockout | post-bump readback + FI sentinel re-check | both present |
| `negative_pin_attempts_read_double_scan_with_fail_closed_sentinel` | F-15.r5: scan mismatch → fail-closed | forward+reverse + `fwd != rev → PIN_ATTEMPTS_CAPACITY` | present |
| `negative_pin_attempts_bump_capacity_check_fails_closed` | wraparound past capacity bypasses lockout | source guards `if (pre as u32) >= CAPACITY { Err }` | present |
| `negative_last_userop_count_set_tolerates_regression_but_logs` | Err on regression bricks slot (witnessed history) | source keeps the "defensive no-op" path | present |
| `negative_no_classical_signer_in_platform_slice` | CLAUDE.md #5: one signature primitive only | grep for ECDSA / Ed25519 / secp256k1 in every slice file | all 9 files clean |
| `negative_no_software_prng_seed_in_rng_module` | CLAUDE.md: no software PRNG seed in TRNG path | grep for StdRng/ChaCha/xorshift in rng.rs | rng.rs clean |
| `negative_consumption_mask_xorshift_seeded_from_hw_trng` | mask predictability would let SCA attacker subtract it | source must call `rng_strong::fill` + zero-seed guard | both present |
| `negative_no_reset_or_increase_max_path_in_flash` | CLAUDE.md "What NOT to do": no rotate/reset paths | grep for rotate_master / reset_bootstrap / etc. | flash.rs clean |
| `negative_flash_unlock_keys_are_st_canonical_not_swapped` | KEY1/KEY2 swap latches OPTLOCK | KEY1 declared before KEY2 (source order) | order preserved |
| `negative_flash_erase_key_page_inside_interrupt_free` | HIGH-12: erase atomicity | function body must contain `cortex_m::interrupt::free` | present |
| `negative_flash_write_quadword_inside_interrupt_free` | HIGH-12: program atomicity | function body must contain interrupt::free | present |
| `negative_flash_erase_secure_page_inside_interrupt_free` | HIGH-12: secure-page erase atomicity | function body must contain interrupt::free | present |
| `negative_flash_erase_ns_page_inside_interrupt_free` | HIGH-12: NS-page erase atomicity | function body must contain interrupt::free | present |
| `negative_flash_pin_attempts_reset_inside_interrupt_free` | HIGH-12: PIN-counter erase atomicity | function body must contain interrupt::free | present |
| `negative_flash_icache_invalidated_after_every_erase` | post-erase reads return stale cached bytes without invalidate | count of `icache_invalidate()` calls ≥ 4 | 4+ found |
| `negative_flash_write_slot_quadword_bank_dispatch_rejects_out_of_range` | mis-dispatch to wrong bank silently writes peripheral | dispatcher has bank range checks + Err return | present |
| `negative_flash_write_quadword_verified_compares_every_byte` | partial torn write undetected if compare loop shortens | for loop bound is `0..16` + Err on mismatch | present |
| `negative_boot_state_parse_rejects_bad_magic` | missing magic check accepts garbage as state | parse_copy compares to BSTATE_MAGIC + returns None | present |
| `negative_boot_state_parse_rejects_unknown_slot_byte` | only 0x00/0x01 are valid; 0xFF / others must reject | match arm `_ => return None` | present |
| `negative_boot_state_parse_rejects_crc_mismatch` | bit-flip in flash misroutes FSBL slot pick | CRC compare + None on mismatch | present |
| `negative_boot_state_read_falls_back_through_both_copies` | torn write may leave only one copy valid | source tries both copies before Unavailable | present |
| `negative_boot_state_write_updates_both_copies` | one-copy update degrades the redundancy invariant | source erases page + writes both copy A AND copy B | present |
| `negative_boot_state_round_trip_preserves_state` | encode/parse bijection across all (slot, version) | exhaustive round-trip on representative space | parses back identical |
| `negative_boot_state_parser_rejects_bit_flip_anywhere` | single-bit flip must be detected by CRC or magic | every (byte, bit) flip combination tested against parser | every flip rejected |
| `negative_boot_state_blank_page_returns_none` | fresh page (all 0xFF) misparses → wrong slot on first boot | parse_ref([0xFF;16]) → None | None |
| `negative_entry_qw_within_2_pow_56_round_trips` | 7-byte BE encoding supports up to 2^56-1 | counts up to 2^56-1 round-trip cleanly | round-trip OK |
| `negative_entry_qw_top_byte_silently_truncated` | refactor expanding to 8 bytes would mis-parse legacy entries | two counts differing only in top byte produce identical QWs | identical (truncation preserved) |
| `negative_journal_blank_qw_is_none_per_parse_entry_contract` | all-blank QW must signal end-of-journal, not garbage | source has `all_blank → None` short-circuit | present |
| `negative_tamp_poll_is_log_only_not_wipe` | bring-up branch invariant: TAMP must NOT wipe | poll body contains `secure_log!` + SCR clear; no `factory_reset` / `trigger_lockout_wipe` / `SCB::sys_reset` | log-only confirmed |
| `negative_tamp_irq_handler_is_log_only_not_wipe` | same invariant on IRQ-mode handler | on_tamp_irq body audit | log-only confirmed |
| `negative_tamp_init_skips_external_pins` | external pin enables (ITAMP4/10 or non-internal CR1 bits) false-trigger on PCB noise | init scope must mention ITAMP1E but NOT ITAMP4E / ITAMP10E | confirmed |
| `negative_pka_bls12_381_modulus_limbs_in_little_endian_order` | limb order swap silently corrupts every Montgomery mul | the 12 limb hex values present in canonical LSB-first order | present |
| `negative_pka_extern_hook_no_mangle_for_bls12_381_fork` | rename breaks bls12_381 fork's PKA lookup | `#[no_mangle]` on `bls12_381_pka_mont_mul` | present |
| `negative_pka_writes_terminator_word_past_operand` | missing N_LIMBS+1 zero terminator → garbage Fp results | write_operand body must have `write_at(N_LIMBS, 0)` | present |
| `negative_rcc_switches_to_hsi16_baseline_before_touching_pll` | PLL config on unstable source deadlocks SWS wait | init switches to HSI16 before any PLL touch | present |
| `negative_rcc_pll_failure_returns_16mhz_keeps_running_on_hsi16` | panic on VOS failure bricks the boot path | source returns 16 on failure (must run) | present |
| `negative_rcc_enables_hsi48_for_rng_in_init` | missing HSI48 → rng::fill silently times out at first boot | init body has HSI48ON + HSI48RDY wait | present |
| `negative_rng_recovers_from_latched_seis_ceis_once` | inert RNG on first transient → permanent boot freeze | source has SEIS/CEIS clear + init() recovery | present |
| `negative_rng_bounded_timeout_returns_err_not_hangs` | RNG deadlock can hang boot if loop is unbounded | source has `timeout > 1_000_000 → Err` | present |
| `negative_rng_byte_helper_panics_on_failure_does_not_return_zero` | returning 0 on RNG failure produces a deterministic stream | byte() uses `.expect(...)` style | present |
| `negative_flash_mutating_apis_stay_unsafe` | safe API would let unaudited callers reset PIN counter | 20 mutating fn signatures audited for `unsafe` marker | all 20 unsafe |
| `negative_flash_pin_attempts_scan_helpers_stay_inline_never` | inlining collapses asymmetric forward/reverse → defeats F-15.r5 | 6 `#[inline(never)]` markers required | all 6 present |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current source, which
means the in-source guards / encodings / fences all remain in place
as documented in the CLAUDE.md invariants and the in-file safety
comments.

## Coverage gaps deliberately left

The slice is firmware-only by feature gate. The host-side cargo-test
pass cannot exercise:

- **Real flash erase/program round-trip.** Atomicity of
  `write_quadword_verified` against a real brown-out window;
  read-back-verified torn-write detection. Requires real STM32U585
  + a controlled brown-out rig. Tested on bench by `make e2e-hw` for
  the happy path; brown-out tolerance is documented in
  `docs/optiga-brick-postmortem.md` rather than tested in CI.
- **RCC PLL lock on real silicon.** `try_pll_160mhz` only fully
  exercises the VOSRDY path on real PWR_VOSR hardware; QEMU never
  enters the PLL loop. `make test-key-speed` is the closest in-suite
  signal (signing times within ≤3 s of expected = PLL locked).
- **RNG entropy quality.** The driver returns bytes — distribution
  / NIST SP-800-90B health checks are deferred to the AIS31 +
  on-chip TRNG self-tests that boot already runs at `rcc::init`'s
  RNG bring-up. Future pass should add a host-side entropy estimator
  on a captured 1 MB sample.
- **PKA Montgomery KAT.** Pinned the modulus limb order + RAM
  layout + extern hook here; the actual `mont_mul` correctness lives
  in the `bls12_381_pka` crate's host KAT suite (`cargo test -p
  bls12_381_pka`) which validates the hook end-to-end.
- **TAMP false-trigger profile.** Polled vs IRQ latency
  characterisation needs an oscilloscope + ITAMP9 inducer (e.g.
  voltage-glitch rig). Documented in `docs/work-todo.md` #26.
- **Consumption-mask PWM duty distribution.** TIM2 CCR1
  randomisation correctness on silicon requires a current probe on
  the supply rail. Not in scope for this pass.
- **SCA trigger pin glitch reproduction.** sca_trigger pin
  electrical edge requires a logic analyzer. Pin choice (PD2) is
  here in source but the actual trace alignment is bench-only.
- **Boot-pulse silicon quirk reproduction.** The decoy-pin priming
  workaround in boot_pulse.rs is documented in
  `pin_diag.rs::run`'s docstring; verifying that workaround works
  needs an LA1010 capture and isn't reducible to a host test.
- **Real GTZC1 TZIC enforcement of NS-vs-S alias mismatch.** Source
  here pins that the secure aliases are used; the actual bus-fault
  on NS access from secure code is QEMU/silicon-only.
- **Compile-fail negative tests via `trybuild`.** Would catch e.g.
  a `Clone` derive accidentally added to a flash-key holder type.
  The slice's secret-handling lives in `secret_keys.rs` (separate
  slice `secure-hw-crypto`) so trybuild here would have nothing to
  guard.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked
  the invocation; new test file follows the existing
  `hw_crypto_under_test` style verbatim — same brace/indent/comment
  conventions). Verify locally before merge.
- `cargo check -p sphincs-tz-secure` — PASS (0 new warnings from
  the test scaffold; pre-existing 36 are unchanged).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox blocked the invocation). The new test code only uses
  `assert!` / `assert_eq!` / `panic!` over `&str` / `[u8; N]`
  primitives — no custom types or unsafe code.
- `cargo test -p sphincs-tz-secure` — PASS (705 tests total, 0
  failed, 1 ignored; this pass added 109 new tests — 55 positive +
  54 negative).
- On-target tests deferred: yes — every test in this slice runs on
  host. The on-silicon equivalents (`make e2e-hw`,
  `make optiga-hw-counter-e2e`, `make pin-gate-hw-counter-e2e`,
  `make pin-gate-wipe-e2e`, `make saes-self-test-hw`,
  `make test-key-speed`) live under existing Makefile targets and
  are exercised by the existing hardware bring-up workflow.
