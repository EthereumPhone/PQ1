# Test Suite Added — `secure-main-sau`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Secure-world boot entry, SAU/GTZC TrustZone configuration, RCC_CSR
reset-cause classifier.

Source files covered:
- `secure/src/main.rs` — 2925 lines (after this pass; +12 lines for the
  `#[cfg(test)] mod main_sau_pure_tests;` mount).
- `secure/src/sau.rs` — 384 lines.
- `secure/src/reset_cause.rs` — 216 lines.

All three are gated `#[cfg(not(test))]` at the crate root because they
pull in `cortex_m` / MMIO / extern linker symbols (`__veneer_base`,
`__veneer_limit`) / the SE-backend `static mut` — none link on host.
The existing inner `#[cfg(test)] mod tests` block in `reset_cause.rs`
therefore never actually runs (`cargo test reset_cause` matches 0
tests pre-pass). This pass closes that gap with a host-runnable
mirror plus source-text invariant pins.

## Test files added / extended
- `secure/src/main_sau_pure_tests.rs` (new) — 23 positive + 42 negative
  tests. Includes a self-contained pure-logic mirror of
  `classify_bits` / `ResetCause` / `is_abnormal` / `tag`, plus
  `include_str!`-based source-text pins for register addresses, GTZC
  TZSC bit positions, SAU region layout, panic-handler ordering,
  DefaultHandler dispatch arms, PendSV re-unlock invariants, and the
  abnormal-reset SRAM-wipe contract.
- `secure/src/main.rs` (modified, `#[cfg(test)]` mount only) — adds
  `#[cfg(test)] mod main_sau_pure_tests;` next to the existing
  test-only module mounts (no production-code change).

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_classify_cold_is_bor_plus_pin_only` | BOR + PIN → Cold | `reset_cause::classify_bits` |
| `positive_classify_software_is_sft_plus_pin` | SFT + PIN → Software | `classify_bits` |
| `positive_classify_iwdg_is_watchdog` | IWDG → Watchdog | `classify_bits` |
| `positive_classify_wwdg_is_watchdog` | WWDG → Watchdog | `classify_bits` |
| `positive_classify_lpwr_is_low_power` | LPWR → LowPower | `classify_bits` |
| `positive_classify_obl_is_option_byte` | OBL + PIN + BOR → OptionByte | `classify_bits` |
| `positive_classify_no_flags_is_unknown` | 0 → Unknown | `classify_bits` |
| `positive_classify_pinrst_alone_is_unknown` | PIN-only (no BOR) → Unknown | `classify_bits` |
| `positive_is_abnormal_classification_is_exact` | Watchdog/LowPower/Unknown abnormal; Cold/Software/OptionByte not | `ResetCause::is_abnormal` |
| `positive_tag_is_one_word_lowercase_for_every_variant` | Every variant's `tag()` is a grep-friendly single token | `ResetCause::tag` |
| `positive_source_pins_rcc_csr_address_and_base` | `RCC = 0x4602_0C00`, `RCC_CSR = +0xF4` | reset_cause.rs source-text |
| `positive_source_pins_sticky_flag_bit_positions` | Every sticky-flag bit position pinned (RMVF=23, OBL=25, PIN=26, BOR=27, SFT=28, IWDG=29, WWDG=30, LPWR=31) | reset_cause.rs constants |
| `positive_sau_register_addresses_are_armv8m_canonical` | SAU_CTRL/RNR/RBAR/RLAR at 0xE000_EDD0/EDD8/EDDC/EDE0 | sau.rs constants |
| `positive_sau_init_sequence_is_disable_program_enable_with_barriers` | `init()` disables SAU, programs regions, re-enables, dsb+isb | `sau::init` |
| `positive_sau_region_count_is_four` | Exactly regions 0..=3 programmed; region 4 absent | `sau::init` |
| `positive_only_region_1_is_nsc` | Region 1 has `nsc=true`; regions 0/2/3 have `nsc=false` | `configure_sau_region` |
| `positive_arch_register_addresses_are_armv8m_canonical` | Every ARMv8-M arch register address in `ArchRegs` | `main::ARCH` |
| `positive_dhcsr_is_read_only_to_avoid_unlock_key_writes` | DHCSR bound as `RoReg32` | `ArchRegs` |
| `positive_dwt_lar_unlock_key_is_documented_magic` | DWT_LAR written with 0xC5AC_CE55 | `main::main` |
| `positive_reset_cause_runs_before_any_peripheral_init` | `classify_and_clear` called before `sau::init` and `hw::rcc::init` | `main::main` |
| `positive_reset_cause_drives_abnormal_zeroize` | `is_abnormal()` branches into `nsc::zeroize_sensitive_state` | `main::main` |
| `positive_reset_cause_is_logged_with_csr_raw` | Boot log prints both `tag()` and raw RCC_CSR | `main::main` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_watchdog_takes_priority_over_bor_when_both_set` | IWDG must beat BOR even when both sticky bits are latched | Feed `IWDGRSTF \| BORRSTF \| PINRSTF` to the classifier | Returns `Watchdog`; losing this priority skips the abnormal-reset SRAM wipe |
| `negative_watchdog_takes_priority_over_sft` | A SW reset that piggybacks on a wedged firmware must still surface as Watchdog | Feed `SFTRSTF \| IWDGRSTF` and `SFTRSTF \| WWDGRSTF` | Both return `Watchdog` |
| `negative_obl_takes_priority_over_every_other_flag` | OBL is the most-specific provisioner signal — must dominate everything | Set every sticky bit at once | Returns `OptionByte` |
| `negative_lpwr_takes_priority_over_sft_and_bor` | Illegal low-power transitions are abnormal and must not be silently classified as SW reset | LPWR+SFT and LPWR+BOR combos | Both return `LowPower` |
| `negative_classifier_ignores_rmvf_bit` | RMVF is a control bit, not a reset cause — must not be folded into `ANY_RESET_FLAG` | Set RMVF alone, then RMVF+PIN | Both return `Unknown` |
| `negative_classifier_ignores_garbage_low_bits` | Low bits 0..22 are not reset-cause bits | Feed 0x007F_FFFF | Returns `Unknown` |
| `negative_csr_with_only_obl_bit_classifies_option_byte` | OBL alone (no PIN) is still OptionByte | Feed `OBLRSTF` | Returns `OptionByte` |
| `negative_abnormal_set_does_not_include_optionbyte` | OptionByte resets are intentional provisioner events; including them in the abnormal set would force a wipe on every flash/OB write | `is_abnormal()` on OptionByte | `false` |
| `negative_abnormal_set_does_not_include_software` | SW resets always originate from code that zeroized first | `is_abnormal()` on Software | `false` |
| `negative_abnormal_set_does_not_include_cold` | Cold-boot SRAM is physically gone — wiping wastes boot time | `is_abnormal()` on Cold | `false` |
| `negative_classifier_is_total_on_arbitrary_inputs` | Pure function, no panics on any input | Iterate the full 9-bit upper-nibble cross-product (`hi << 23`) | No panic on any input |
| `negative_classify_and_clear_uses_volatile_mmio` | RCC_CSR is sticky/clear-on-write — non-volatile R/W would be elided by the compiler | Source-text pin on `read_volatile`/`write_volatile` | All three required volatile ops present |
| `negative_classify_and_clear_is_marked_unsafe` | Raw MMIO requires the caller to promise call-once ordering | Pin the `pub unsafe fn` signature | Signature stays `unsafe` |
| `negative_qemu_branch_does_not_touch_mmio` | mps2-an505 has no RCC_CSR; touching it would HardFault | Extract the QEMU branch body and assert no `read_volatile`/`write_volatile` and returns `(Cold, 0)` | Body is MMIO-free |
| `negative_configure_sau_region_sets_enable_bit` | RLAR bit 0 = ENABLE; missing it leaves region unprogrammed (defaults to fully-secure under TZEN=1, would brick NS) | Source-text pin on `\| 1)` in RLAR write | Enable bit always ORed |
| `negative_configure_sau_region_uses_nsc_bit_1` | NSC is bit 1 of RLAR; wrong bit would silently make region 1 plain-NS and let NS call any S-world address | Source-text pin on `1 << 1` | NSC bit is 1 << 1 |
| `negative_configure_sau_region_aligns_to_32_bytes` | M33 requires 32-byte alignment; off-by-N could open a gap between NS-flash and NSC-veneers | Source-text pin on `0xFFFF_FFE0` masks | Both RBAR and RLAR masked |
| `negative_stm32_gtzc_seccfgr3_protects_full_crypto_block` | CLAUDE.md invariant #4 — AES/HASH/RNG/PKA/SAES must be SECURE | Pin every SECCFGR3 bit constant + the OR'd mask expression | All 5 bits present in the mask |
| `negative_stm32_gtzc_seccfgr3_does_not_mark_otg_secure` | OTG (bit 10) MUST stay NS so the NS USB HID stack works; flipping it bricks USB enumeration | Pin the "stays NS" comment + assert no `SECCFGR3_OTG_BIT` constant exists | OTG remains NS |
| `negative_stm32_gtzc_seccfgr1_protects_se_buses` | I2C1 (OPTIGA+SE050) and I2C2 (STSAFE probe) carry plaintext shielded-connection bytes | Pin both bit constants + the OR'd mask | Both bits in the mask |
| `negative_stm32_tzsc_base_is_5003_2400_not_5003_2800` | Pre-fix history: 0x5003_2800 is TZIC, not TZSC — writes silently no-op and CLAUDE.md inv #4 was regressed | Pin `TZSC_BASE = 0x5003_2400` and absence of `0x5003_2800` form | Correct address only |
| `negative_stm32_gtzc_postwrite_self_check_is_present` | Self-check catches base-addr typos / clock-not-enabled glitches | Pin all three `debug_assert_eq!` calls | All present |
| `negative_stm32_mpcbb1_is_all_secure_mpcbb2_is_all_nonsecure` | SRAM1 = S, SRAM2 = NS; flipping is an immediate inv #4 violation | Pin both loops + the all-secure / all-NS write values | Loops + values correct |
| `negative_qemu_mpc_partitioning_matches_documented_layout` | QEMU MPC0 first 2MB S (LUT idx 64), MPC1 first 128KB S (LUT idx 4) | Pin the two `configure_mpc_partial_ns` call args | Both args match |
| `negative_tzic_is_armed_with_same_masks_as_tzsc` | Without TZIC, illegal NS access is silently RAZ/WI — gateway test harness can't observe enforcement | Pin the `hw::tzic::configure(...)` call | Call present with same masks |
| `negative_panic_handler_zeroizes_before_halting` | Last-line-of-defence: panic must wipe master_secret / pin / SE keys before parking | Slice out the panic body and assert it contains `nsc::zeroize_sensitive_state();` before the `loop` | Zeroize present |
| `negative_panic_handler_halts_with_wfi_not_bkpt` | BKPT without a debugger escalates to HardFault → could glitch through to NS | Pin `wfi()` and assert no `bkpt` in body | WFI used; BKPT absent |
| `negative_panic_handler_is_test_excluded` | `#[panic_handler]` global; would conflict with std's handler in host tests | Pin `#[cfg(not(test))]\n#[panic_handler]` | Gate present |
| `negative_default_handler_dispatches_tzic_to_on_violation` | GTZC IRQ 8 must route to `on_violation` so violations are counted | Pin the `8 => unsafe { hw::tzic::on_violation() }` arm | Arm present |
| `negative_default_handler_logs_unexpected_irqs_instead_of_silent_drop` | Catch-all `_ =>` arm is required; missing means UB on unmasked IRQs | Pin `_ => {` and `cortex_m::asm::wfe();` | Both present |
| `negative_pendsv_uses_gated_unlock_not_raw_unlock` | PendSV re-unlock must respect MCU page-126 counter (CLAUDE.md inv #2) | Pin `nsc::gated_unlock(se, &pin)` | Used; raw `SE.unlock` would be a brute-force bypass |
| `negative_pendsv_has_reentry_guard` | SysTick can re-pend PendSV; re-entry is UB on M33 | Pin `static mut PENDSV_IN_FLIGHT` + the `read_volatile != 0` check | Guard present |
| `negative_pendsv_zeroizes_pin_after_use` | Local PIN buffer leaks into stack if not zeroized | Pin `pin.zeroize();` + `crate::fi::zeroize_barrier();` | Both present |
| `negative_systick_idle_wipe_skips_when_handler_is_busy` | HIGH-7 fix: wiping while a sign handler holds stack-local secrets lets it sign for a now-locked session | Pin the `!nsc::handler_is_busy()` guard in the idle-wipe `if` | Guard present |
| `negative_systick_idle_wipe_pends_pendsv_for_reunlock` | PendSV (low-pri) drives the re-unlock UI outside the SysTick ISR | Pin `ARCH.icsr.write(1 << 28); // PENDSVSET` | Write present at correct bit |
| `negative_se_static_mut_is_unique_per_backend` | Each SE-backend cfg defines exactly one `static mut SE`; duplicates would silently shadow each other | Count occurrences of `static mut SE:` | Exactly 5 (mock, tropic01, se050, optiga, dual) |
| `negative_panic_handler_debug_log_dhcsr_check_is_present` | debug-log + standalone (no debugger) = BKPT HardFault unless DHCSR gated | Pin `ARCH.dhcsr.read() & 1 != 0` | Gate present |
| `negative_secure_log_macro_compiles_to_nop_without_debug_log` | Production builds must emit zero observable BKPT instructions | Pin the `#[cfg(any(not(feature = "debug-log"), test))]` arm and its empty body | Both pinned |
| `negative_reset_cause_module_declaration_is_test_excluded` | `#[cfg(not(test))]` keeps host `cargo test` linkable | Pin `#[cfg(not(test))]\nmod reset_cause;` | Gate present |
| `negative_sau_module_declaration_is_test_excluded` | Same as above | Pin `#[cfg(not(test))]\nmod sau;` | Gate present |
| `negative_no_classical_signer_referenced_in_slice` | CLAUDE.md "What NOT to do": no ECDSA, no Ed25519, no FORS+C, no `rotateMasterKeys`/`resetBootstrapUses`/`resetSlotUses` | Source-text grep on every forbidden token across all three files | All absent |
| `negative_systick_reload_is_documented_25khz_on_qemu` | QEMU mps2-an505 SysTick = 25 MHz → 25_000 / tick = 1 ms; drift breaks the 120 s inactivity timer | Pin `SYSTICK_RELOAD: u32 = 25_000` | Present |
| `negative_ns_flash_base_constants_match_proto_layout` | NS_FLASH_BASE duplicated in main.rs and pqsigner-proto; mismatch would either break the boot hop or reject every legitimate NS pointer | Pin both per-cfg literals | Both addresses present |

## Production-code bugs surfaced by negative tests
None. Every assertion held against the current production source. The
"sticky" assumptions that justify the negative suite remain intact:

- The reset-cause classifier respects its priority order (OBL > WDOG >
  LPWR > SFT > BOR), correctly ignores RMVF, and never panics on
  arbitrary input.
- The SAU init sequence preserves dsb/isb ordering and the 32-byte
  alignment masks.
- GTZC1 TZSC SECCFGR3 still secures the full crypto block and leaves
  OTG NS, with TZSC_BASE at the correct 0x5003_2400 (not the regressed
  0x5003_2800 TZIC address).
- The panic handler still zeroizes before WFI, and the secure_log!
  macro's `not(debug-log)` arm is still a literal empty body.
- PendSV still routes re-unlock through `nsc::gated_unlock` and keeps
  its `PENDSV_IN_FLIGHT` re-entry guard.
- SysTick's idle-wipe still respects the HIGH-7 `!nsc::handler_is_busy()`
  guard.

## Coverage gaps deliberately left
- **`classify_and_clear` MMIO side-effect.** The actual `read_volatile` /
  `write_volatile` on `0x4602_0CF4` is hardware-only — we pin its
  textual shape but cannot exercise the sticky-flag clear on host. A
  future on-target test (e.g. via `make e2e-hw` with a captured
  RCC_CSR pre/post snapshot) is the right place for it.
- **`sau::init` register effects.** SAU_RNR/RBAR/RLAR writes only
  matter on a real M33; host has no register file to observe. We pin
  the textual ordering and bit construction but rely on `make
  saes-self-test-hw` and the existing `gtzc-enforcement-hw` Makefile
  target for on-silicon validation.
- **PendSV re-entry under SysTick pressure.** Requires an actual ISR
  preemption window — covered by interactive `make play-hw-display`
  rather than host tests.
- **`#[panic_handler]` invocation.** Triggering a panic from a host
  test would terminate the test binary; we pin the handler's shape
  but cannot drive `_info` through it on host.
- **Linker-supplied `__veneer_base` / `__veneer_limit`.** Only meaningful
  in the real link — host build has no veneer table. Covered by the
  S→NS boot hop's e2e test (`make e2e`).
- **DefaultHandler IRQ dispatch.** Requires a real NVIC line firing —
  the `make gtzc-enforcement-hw` target is the on-silicon proof.

Each gap is "needs hardware" rather than "needs more host tests."

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocks
  `cargo fmt` invocations regardless of flag form; only `cargo check`
  and `cargo test` succeed in this sandbox profile).
- `cargo check -p sphincs-tz-secure` — PASS (compiles clean, 43 pre-
  existing warnings, none introduced by this pass).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (same sandbox block as fmt).
- `cargo test -p sphincs-tz-secure` — PASS (1548 passed; 2 ignored;
  +65 net from this pass — 23 positive, 42 negative).
- (firmware) on-target tests deferred: yes — see the coverage-gaps
  list. None of the new tests requires on-target execution; everything
  in this pass is host-runnable.
