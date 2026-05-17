# Test Suite Added — `secure-hw-io`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

Bus / IO peripherals: I2C, SPI, USB, UART, buttons + `hw/mod.rs`.

Source files covered:
- `secure/src/hw/i2c.rs:250`        — I2C1 OLED driver (write path, RELOAD chunking).
- `secure/src/hw/i2c_hw.rs:142`     — I2C1 SE050 init (hardware bring-up only, no public data API).
- `secure/src/hw/i2c2_probe.rs:407` — I2C2 bus-scan diagnostic (`stsafe-probe` dev-only).
- `secure/src/hw/spi.rs:253`        — SPI master implementing `embedded_hal::SpiDevice` for TROPIC01.
- `secure/src/hw/spi_hw.rs:224`     — SPI2 / SPI1 init (GPIO + clock + CS) for TROPIC01 bus.
- `secure/src/hw/usb_hw.rs:258`     — USB OTG FS + UCPD1 init (the only IO file that flips GPIO pins to NS).
- `secure/src/hw/uart.rs:187`       — USART1 ST-LINK VCP TX (RDP1 diagnostic via `uart-console`).
- `secure/src/hw/buttons.rs:389`    — PA8 (RIGHT) + PC1 (LEFT) trusted-UI buttons, debounce + long-press + combo.
- `secure/src/hw/mod.rs:135`        — feature gates for every IO module above.

All nine files sit behind hardware-only feature gates (`stm32u585`,
`uart-console`, `gpio-buttons`, `tropic01-se`, `usb`, `stsafe-probe`,
`se050`, `optiga-trust-m`, `ui-oled`) and pull in `cortex_m` MMIO that
does not link on host. The slice therefore matches the precedent set
by `secure-hw-platform` and `secure-hw-crypto`: host tests pin the
slice via `include_str!` source-text invariants — every constant
whose silent regression would matter for security (Secure vs NS
alias, exact pin set flipped to NS by USB init, SWD-pin protection,
ISR / SR / CFG2 bit positions, baud-rate divisor, AF numbers,
debounce / long-press thresholds) is asserted against the file text.

## Test files added / extended

- `secure/src/hw_io_under_test/mod.rs` — new scaffold module
  (mirrors `secure/src/hw_platform_under_test/`), gated `#[cfg(test)]`.
- `secure/src/hw_io_under_test/pure_tests.rs` — **81 positive,
  42 negative tests** (123 total) covering the slice's secure-alias
  enforcement, register layouts, pin assignments, AF numbers, timing
  constants, USB SECCFGR clearance set, SWD-pin protection on the
  button driver, bounded-busy-wait invariants, and public-surface
  minimality.
- `secure/src/main.rs` — added `#[cfg(test)] mod hw_io_under_test;`
  next to the existing `hw_crypto_under_test` / `hw_platform_under_test`
  scaffolds (the only non-test edit; pure `cfg(test)` declaration).

No `[dev-dependencies]` additions were needed.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_i2c_secure_alias_base` | `I2C1 = 0x5000_5400` (Secure alias) | i2c.rs |
| `positive_i2c_rcc_secure_alias` | `RCC_S = 0x5602_0C00` | i2c.rs |
| `positive_i2c_gpiob_secure_alias` | `GPIOB_S = 0x5202_0400` | i2c.rs |
| `positive_i2c_100khz_timing_at_160mhz` | TIMINGR=0x9042_3F4F for SM @ 160 MHz | i2c.rs |
| `positive_i2c_100khz_timing_at_qemu_clock` | TIMINGR=0x0042_3F4F fallback for 16 MHz | i2c.rs |
| `positive_i2c_pin_assignments_pb8_pb9` | PB8/PB9 MODER AF + OTYPER open-drain | i2c.rs |
| `positive_i2c_af4_in_afrh` | AFRH AF4 for PB8/PB9 | i2c.rs |
| `positive_i2c_isr_bit_positions` | TXIS/NACKF/STOPF/TCR/BERR/ARLO/BUSY masks | i2c.rs |
| `positive_i2c_empty_write_returns_true` | `write(_, &[])` no-op fast path | i2c.rs `write()` |
| `positive_i2c_reload_chunk_at_255` | NBYTES-8-bit RELOAD chunking + AUTOEND on last chunk | i2c.rs `write()` |
| `positive_i2c_start_bit_only_on_first_chunk` | START set only when `offset == 0` | i2c.rs `write()` |
| `positive_i2c_hw_secure_alias_base` | I2C1 base 0x5000_5400 in SE050 driver | i2c_hw.rs |
| `positive_i2c_hw_rcc_secure_alias` | RCC_S 0x5602_0C00 | i2c_hw.rs |
| `positive_i2c_hw_gpiob_secure_alias` | GPIOB_S 0x5202_0400 | i2c_hw.rs |
| `positive_i2c_hw_400khz_timing_at_160mhz` | I2C_TIMING_400KHZ = 0x1090_378F | i2c_hw.rs |
| `positive_i2c_hw_pin_mode_af_open_drain_pullup` | PB8/PB9 AF mode + OD + pull-up + AF4 | i2c_hw.rs `init()` |
| `positive_i2c_hw_init_has_no_public_data_path` | exactly 1 `pub fn init`, no `pub fn write/read` | i2c_hw.rs public API |
| `positive_i2c2_probe_secure_alias_base` | `I2C2 = 0x5000_5800` | i2c2_probe.rs |
| `positive_i2c2_probe_gpioh_secure_alias` | GPIOH_S 0x5202_1C00 | i2c2_probe.rs |
| `positive_i2c2_probe_pin_mapping_ph4_ph5_af4` | PH4/PH5 AF mode + AF4 | i2c2_probe.rs |
| `positive_i2c2_probe_stsafe_default_address_0x20` | STSAFE-A110 default address 0x20 | i2c2_probe.rs |
| `positive_i2c2_probe_scan_range_0x08_to_0x77` | reserved-address skip | i2c2_probe.rs `run_probe` |
| `positive_i2c2_probe_halts_after_scan` | `run_probe() -> !` + `wfi()` loop | i2c2_probe.rs |
| `positive_spi_sr_bit_positions` | TXP/RXP/EOT/OVR bit positions | spi.rs |
| `positive_spi_cr1_spe_and_cstart_bits` | SPE bit 0, CSTART bit 9 | spi.rs |
| `positive_spi_ifcr_clear_bits` | EOTC/TXTFC/OVRC clear flags | spi.rs |
| `positive_spi_register_offsets_match_stm32u5_layout` | CR1/CR2/SR/IFCR/TXDR/RXDR offsets | spi.rs `REG` |
| `positive_spi_empty_transfer_is_ok` | `transfer_inplace(&mut [])` → Ok | spi.rs |
| `positive_spi_overrun_returns_err_overrun` | OVR maps to `ErrorKind::Overrun` | spi.rs `SpiError` |
| `positive_spi_disables_pe_on_timeout` | wait_eot timeout force-disables SPE | spi.rs |
| `positive_spi_cs_always_deasserted_at_end_of_transaction` | CS released even on error | spi.rs `SpiDevice::transaction` |
| `positive_spi_hw_default_spi2_base` | SPI2 default base 0x5000_3800 | spi_hw.rs |
| `positive_spi_hw_arduino_spi1_base` | SPI1 base 0x5001_3000 under `spi1-arduino` | spi_hw.rs |
| `positive_spi_hw_rcc_secure_alias` | RCC_S | spi_hw.rs |
| `positive_spi_hw_gpiob_default_gpioe_arduino` | GPIO bases per feature | spi_hw.rs |
| `positive_spi_hw_cs_pin_12` | `CS_PIN = 12` | spi_hw.rs |
| `positive_spi_hw_ssi_high_before_master_mode` | SSI=1 in CR1 before MASTER in CFG2 | spi_hw.rs `init` |
| `positive_spi_hw_cfg1_baud_5mhz_dsize_8bit` | MBR=÷32 → 5 MHz, DSIZE=7 (8-bit) | spi_hw.rs |
| `positive_spi_hw_cfg2_master_software_nss_only` | MASTER+SSM (CPOL/CPHA=0, Mode 0) | spi_hw.rs |
| `positive_spi_hw_no_interrupts` | IER zeroed | spi_hw.rs |
| `positive_spi_hw_cs_asserts_low_via_bsrr_reset` | BSRR BR12 / BS12 atomic asserts | spi_hw.rs `cs_assert/deassert` |
| `positive_spi_hw_af5_for_sck_miso_mosi` | AF5 in AFRH for pins 13/14/15 | spi_hw.rs |
| `positive_usb_rcc_secure_alias` | RCC_S 0x5602_0C00 | usb_hw.rs |
| `positive_usb_pwr_secure_alias` | PWR 0x5602_0800 | usb_hw.rs |
| `positive_usb_gpioa_gpiob_secure_alias` | GPIOA_S/GPIOB_S secure | usb_hw.rs |
| `positive_usb_ucpd1_secure_alias` | UCPD1 0x5000_DC00 | usb_hw.rs |
| `positive_usb_svmcr_usv_bit_28` | PWR_SVMCR.USV = bit 28 | usb_hw.rs |
| `positive_usb_otg_fs_clock_bit_14` | AHB2ENR1 bit 14 + reset | usb_hw.rs |
| `positive_usb_pa11_pa12_af10` | PA11/PA12 AF10 in AFRH | usb_hw.rs |
| `positive_usb_ns_pin_classification_only_usb_and_tcpp03` | SECCFGR clears PA11/12/15 + PB5/15 exactly | usb_hw.rs `init` |
| `positive_usb_tcpp03_pb5_drive_high` | BSRR BS5 to enable TCPP03 | usb_hw.rs |
| `positive_usb_ucpd_sink_mode_with_dead_battery_disabled` | ANAMODE=1, CC1TCDIS+CC2TCDIS=11 | usb_hw.rs `init_ucpd` |
| `positive_usb_ucpd_cfg1_constants` | HBITCLKDIV/IFRGAP/TRANSWIN/UCPDEN values | usb_hw.rs |
| `positive_uart_usart1_secure_alias` | USART1 0x5001_3800 | uart.rs |
| `positive_uart_rcc_secure_alias` | RCC_S | uart.rs |
| `positive_uart_gpioa_secure_alias` | GPIOA 0x5202_0000 | uart.rs |
| `positive_uart_brr_115200_at_160mhz` | BRR=1389 (160e6/115200 ≈ 1389) | uart.rs |
| `positive_uart_usart1_enable_bit_14` | APB2ENR USART1EN = bit 14 | uart.rs |
| `positive_uart_pa9_af7_via_afrh` | PA9 AF mode + AF7 | uart.rs |
| `positive_uart_init_ue_then_te_sequence` | UE before TE per RM0456 | uart.rs `init` |
| `positive_uart_init_bounded_teack_wait` | TEACK loop bounded with 10M timeout | uart.rs |
| `positive_uart_write_hex_8_lowercase` | lowercase hex table for 8-byte fingerprint | uart.rs `write_hex_8` |
| `positive_uart_flush_waits_tc` | flush spins on ISR.TC | uart.rs `flush` |
| `positive_buttons_left_pc1_right_pa8_pin_bits` | LEFT_BIT=1<<1, RIGHT_BIT=1<<8 | buttons.rs |
| `positive_buttons_gpioa_gpioc_secure_alias` | GPIOA_S/GPIOC_S secure | buttons.rs |
| `positive_buttons_rcc_secure_alias` | RCC_S | buttons.rs |
| `positive_buttons_active_low_pressed_reads_zero` | press = pin reads 0 | buttons.rs |
| `positive_buttons_pullup_internal_pupdr_01` | PUPDR 0b01 (internal pull-up) | buttons.rs `init` |
| `positive_buttons_timings` | DEBOUNCE_MS=30, LONG_PRESS_MS=500, POLL_MS=5, COMBO_WINDOW_MS=80 | buttons.rs |
| `positive_buttons_combo_emits_right_long` | chord = `(Button::Right, Press::Long)` | buttons.rs `wait_combo_release` |
| `positive_buttons_idle_check_returns_none` | wait_event returns None on idle | buttons.rs |
| `positive_buttons_gpio_clocks_a_and_c` | RCC enables GPIOAEN + GPIOCEN | buttons.rs |
| `positive_buttons_sysclk_detection_via_cfgr_sws` | PLL1/HSI16/MSI detection | buttons.rs `detect_sysclk_mhz` |
| `positive_buttons_bit_positions_match_pin_numbers` | pin-N → bit-N / MODER-2N consistency | buttons.rs |
| `positive_mod_i2c_oled_gate` | `i2c` gated by `stm32u585 + ui-oled` | hw/mod.rs |
| `positive_mod_i2c_hw_se_gate` | `i2c_hw` gated by `stm32u585 + (se050|optiga-trust-m)` | hw/mod.rs |
| `positive_mod_spi_tropic01_gate` | `spi` + `spi_hw` gated by `stm32u585 + tropic01-se` | hw/mod.rs |
| `positive_mod_usb_gate` | `usb_hw` gated by `stm32u585 + usb` | hw/mod.rs |
| `positive_mod_uart_console_gate` | `uart` gated by `uart-console` | hw/mod.rs |
| `positive_mod_buttons_gate` | `buttons` gated by `gpio-buttons` | hw/mod.rs |
| `positive_mod_i2c2_probe_gate` | `i2c2_probe` gated by `stsafe-probe` | hw/mod.rs |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_i2c_does_not_use_ns_alias_for_i2c1` | I2C1 OLED always uses Secure alias | scans non-comment lines for `0x4000_5400` | fail if any code line references NS base |
| `negative_i2c_hw_does_not_use_ns_alias_for_i2c1` | SE050 I2C1 stays Secure (invariant #3) | non-comment scan for `0x4000_5400` | fail if any code line references NS base |
| `negative_i2c2_probe_does_not_use_ns_alias` | I2C2 STSAFE probe stays Secure | non-comment scan for `0x4000_5800` | fail if any code line references NS base |
| `negative_spi_hw_does_not_use_ns_alias_for_spi2_or_spi1` | TROPIC01 SPI bus stays Secure | non-comment scan for both SPI NS bases | fail if any code line references NS base |
| `negative_usb_hw_does_not_use_ns_rcc_alias` | RCC writes for USB use Secure alias (NS writes silently dropped under TZEN=1) | non-comment scan for `0x4602_0C00` | fail if NS RCC alias used |
| `negative_uart_does_not_use_ns_aliases` | uart RCC + USART1 access via Secure alias | non-comment scan for both NS bases | fail if NS aliases used |
| `negative_buttons_does_not_use_ns_aliases` | buttons GPIO writes via Secure alias | non-comment scan for GPIOA/C NS aliases | fail if NS aliases used |
| `negative_usb_must_not_mark_i2c1_pins_pb8_pb9_ns` | USB SECCFGR clear does not expose SE050 I2C1 or TROPIC01 SPI2 pins | enumerate banned PB pins (8/9/12/13/14) and assert each is absent from `gpiob_seccfgr.clear_bits(...)`; also assert exactly one such call | fail if any extra PB pin flipped to NS |
| `negative_usb_must_not_mark_arbitrary_gpioa_pins_ns` | USB SECCFGR clear does not flip PA8 / PA9 / PA13 / PA14 to NS | enumerate banned PA pins, assert each absent from `gpioa_seccfgr.clear_bits(...)`; also assert exactly one such call | fail if any extra PA pin flipped to NS |
| `negative_buttons_must_not_touch_swd_pins_pa13_pa14` | buttons init does not RMW MODER bits for PA13/PA14 (SWD port) | scan for MODER writes at shift 26 or 28 | fail if SWD pins touched (would brick debug) |
| `negative_buttons_must_not_consume_extra_swd_pins` | GPIOC MODER only touched at PC1 + PC13 shifts | parse each `gpioc_moder.modify(...)` line, allow only `!(0b11 << 2)` or `!(0b11 << 26)` | fail if a stray shift appears |
| `negative_no_classical_signer_referenced_in_hw_io` | no classical signer (invariant #5) leaks into hw IO | substring scan for ecdsa/secp256k1/ed25519/FORS+C across all 9 files | fail if any banned name present |
| `negative_no_software_pin_compare_in_hw_io` | no PIN compare in IO layer (invariant #2 — SE silicon only) | substring scan for enter_pin/verify_pin/compare_pin/ct_eq/PIN_LEN/MAX_ATTEMPTS | fail if PIN-handling shows up |
| `negative_no_heap_types_in_hw_io_sources` | no_std slice has no heap | substring scan for String/Vec/Box/vec!/alloc:: | fail if heap leak |
| `negative_i2c_write_aborts_on_nack` | OLED write returns false on NACK rather than retry | check ICR clears + early return on NACKF/BERR/ARLO | fail if silent retry introduced |
| `negative_i2c_write_aborts_on_busy_stuck` | OLED write attempts PE-cycle on stuck BUSY, then bails | check "Bus stuck busy" recovery comment + code | fail if removed |
| `negative_i2c_write_aborts_on_txis_timeout` | TXIS-wait loop bounded with PE-cycle recovery | check "Abort: disable PE" comment + code | fail if removed |
| `negative_i2c_write_chunk_size_clamped_at_255` | NBYTES (8-bit) clamped at 255 — larger silently truncates | check exact clamp expression | fail if clamp removed/changed |
| `negative_uart_console_documents_rdp_dev_only_usage` | uart.rs documents its RDP1 dev-only purpose so reviewers know it never ships | scan for "RDP1 SAES self-test" + the survives-RDP justification | fail if docstring rationale removed |
| `negative_uart_emits_no_secret_via_write_str` | uart byte-egress doesn't embed secret-bearing label literals | substring scan for master_secret/mnemonic/seed_word | fail if any banned label present |
| `negative_i2c2_probe_module_is_dev_only_gated` | i2c2 bus-scan is dev-only and one-shot | check `stsafe-probe` gate + `run_probe() -> !` divergent return | fail if gate removed or made non-divergent |
| `negative_buttons_run_test_only_under_button_test_feature` | hw button-test harness gated | check `#[cfg(feature = "button-test")]` on `run_test` | fail if ungated |
| `negative_i2c_hw_does_not_reclassify_se_bus_to_ns` | i2c_hw never touches SECCFGR (SE bus stays S) | non-comment scan for `seccfgr`/`SECCFGR` + docstring assertion | fail if any code line touches SECCFGR |
| `negative_spi_hw_does_not_reclassify_tropic01_bus_to_ns` | spi_hw never touches SECCFGR (TROPIC01 bus stays S) | non-comment scan + docstring assertion | fail if any code line touches SECCFGR |
| `negative_i2c_busy_wait_is_bounded` | every poll loop has `t -= 1` countdown | count `t -= 1;` occurrences (≥4) + TIMEOUT constant | fail if any loop becomes unbounded |
| `negative_spi_busy_wait_is_bounded` | EOT-wait bounded by `TIMEOUT_LOOPS` | check constant + for-loop form | fail if `loop {}` introduced |
| `negative_i2c2_probe_busy_wait_is_bounded` | probe loops bounded by 500 K | check constant | fail if removed |
| `negative_i2c_no_raw_volatile_ops` | i2c.rs funnels MMIO via `Reg32`/`RoReg32` | substring scan for `read_volatile`/`write_volatile` | fail if raw volatile call leaks in |
| `negative_i2c_hw_no_raw_volatile_ops` | same for i2c_hw.rs | same | same |
| `negative_spi_hw_no_raw_volatile_ops` | same for spi_hw.rs | same | same |
| `negative_uart_no_raw_volatile_ops` | same for uart.rs | same | same |
| `negative_buttons_no_raw_volatile_ops` | same for buttons.rs | same | same |
| `negative_usb_hw_raw_volatile_only_under_debug_log_diagnostic` | usb_hw allows ≤1 `read_volatile` (debug-log SECCFGR offset probe) only | count + `#[cfg(feature = "debug-log")]` presence | fail if raw write_volatile leaks in or 2nd raw read appears |
| `negative_spi_write_op_clamps_to_300_byte_scratch` | SpiDevice::Write op clamps to 300-byte stack scratch | check `let mut tmp = [0u8; 300];` + `.min(tmp.len())` | fail if scratch grows or clamp removed |
| `negative_spi_transfer_op_uses_min_of_read_write_lens` | SpiDevice::Transfer shrinks to min(read,write) | check `.min(write.len())` | fail if removed |
| `negative_buttons_combo_waits_for_full_release_before_emitting` | combo confirm waits for both fingers released | check `!left_pressed() && !right_pressed()` in wait_combo_release | fail if race introduced |
| `negative_buttons_long_press_threshold_is_500ms` | LONG_PRESS_MS = 500 — load-bearing for trusted-UI confirm | check constant + threshold comparison | fail if regressed |
| `negative_uart_teack_wait_is_bounded_not_unbounded_while` | TEACK while-loop has decrement + early return | check `t -= 1;` presence | fail if unbounded |
| `negative_uart_write_byte_has_no_secret_param` | uart byte-egress doesn't accept wrapped-secret types | check public signatures + scan for Secret/Zeroizing/ZeroizeOnDrop imports | fail if a wrapped-secret API leaks in |
| `negative_i2c_public_surface_only_init_and_write` | OLED driver's public surface is exactly 2 fns | count `pub fn`/`pub unsafe fn` lines | fail if surface grows |
| `negative_i2c_hw_public_surface_only_init` | SE050 hw init has exactly 1 public fn | same | fail if data path API appears |
| `negative_spi_hw_public_surface_only_init_cs` | SPI hw has exactly 3 public fns (init + 2 CS helpers) | same | fail if surface grows |

## Production-code bugs surfaced by negative tests

None. Every negative test passed on first run after fixing the
seven self-inflicted false-positives that were tripped by source
docstrings naming the forbidden patterns (NS aliases / SECCFGR /
`PIN = ...` in a BSP comment). Those false-positives are now
neutralised by a `contains_in_code` helper that scans only the
non-comment portion of each line.

## Coverage gaps deliberately left

- **On-target round-trip tests.** Real OLED ACK over I2C1, real
  SE050 SCP03 handshake, real TROPIC01 SPI frame, real USB
  enumeration on a B-U585I-IOT02A, and real button presses via the
  jumper-wire harness all require `make` targets (`make e2e-hw`,
  `make play-hw-display`, `make button-test-hw`, etc.) and were
  explicitly out of scope per the brief ("Do NOT run `make e2e`,
  `make e2e-hw`, ...").
- **`trybuild` compile-fail negatives** for accidentally enabling
  multiple SE backends or wrong feature combos. The existing crate
  already enforces these via `compile_error!` fences in `nsc/mod.rs`
  and the build.rs ui-mode check; duplicating the contract here
  would be redundant.
- **STM32U585 GTZC TZSC reclassification tests.** Whether USB OTG
  FS actually receives traffic on the NS alias after
  `usb_hw::seccfgr_clear_bits` calls is a hardware-only behaviour
  exercised by `make gtzc-test` and the validation path in
  `secure-hw-platform`.
- **UCPD1 timing values vs PHY spec.** The exact `HBITCLKDIV`,
  `IFRGAP`, `TRANSWIN` values are pinned, but their correspondence
  to USB-PD electrical timing is an on-chip CC voltage measurement,
  not host-checkable.
- **Pin-by-pin SECCFGR enumeration above bit 15.** I assert the
  exact `clear_bits((1 << 11) | (1 << 12) | (1 << 15))` and
  `clear_bits((1 << 5) | (1 << 15))` calls, plus pin-by-pin rejects
  for PA8/PA9/PA13/PA14 and PB8/9/12/13/14. The remaining 16+ pins
  per port are left as "exactly-one-call" enforcement — adding a
  second call would have to clear different bits to even compile,
  and the existing call's literal form is pinned. A future pass
  could turn the test into a full bitmask diff (assert resulting
  SECCFGR mask equals an expected constant) — deferred.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandboxed; rustfmt
  invocations blocked by permission rules in this session).
  Manually-formatted, idiomatic style follows the established pattern
  set by `secure/src/hw_platform_under_test/pure_tests.rs`.
- `cargo check -p sphincs-tz-secure` — PASS (warnings only, all
  pre-existing).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandboxed; clippy invocations blocked by permission rules in
  this session). The 36 pre-existing warnings noted by `cargo check`
  are unchanged by this slice.
- `cargo test -p sphincs-tz-secure` — PASS (828 tests, 1 ignored;
  705 baseline + 123 new = 828 total, matches expected).
- (firmware) on-target tests deferred: yes — every test in this
  suite is a host-runnable source-text pin; on-target validation
  of the actual MMIO writes lives in the `make e2e-hw`,
  `make play-hw-display`, `make button-test-hw`,
  `make optiga-hw-counter-e2e` targets.
