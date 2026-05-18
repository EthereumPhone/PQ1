# Test Suite Added — `hal`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope

Trait-only HAL surface (Rng / Sha256 / Saes / Flash / Otp / BootState /
Tamp / ConsumptionMask / I2cBus / SpiBus / Buttons / Uart) plus the
aggregate `Platform` trait, the public enums/structs that ride the
trait surface (`HalError`, `KeySelector`, `OtpRange`, `BootStateData`,
`TamperCause`, `Buttonset`, `BootStage`), and the boot-ordering
constant `BootStage::ALL`.

The crate has no runtime logic — it is the spec. Tests therefore
target (a) derive contracts, (b) variant identity, (c) stable
constants, (d) compile-time trait coherence, and (e) the few
documented contracts that the trait bodies themselves carry
(`Otp::burn_once` monotonicity, `SpiBus::xfer` length equality,
`Sha256::finalize` output width).

Source files covered:

- `hal/src/lib.rs:295`

## Test files added / extended

- `hal/tests/positive_types.rs` — 21 positive tests covering type
  derives, variant constructors, default values, and `BootStage::ALL`
  shape.
- `hal/tests/positive_mock_platform.rs` — 5 positive tests exercising
  a hand-rolled `MockPlatform` that implements every per-peripheral
  trait. Proves the aggregate trait surface is self-consistent and
  that the documented per-peripheral methods are reachable through
  `&mut impl Platform`.
- `hal/tests/negative_invariants.rs` — 24 negative tests organised
  into 10 families: secret-typed derive bans on `KeySelector`,
  required derives on non-secret types, `Buttonset::default()` /
  `BootStateData::default()` safety, `BootStage::ALL` ordering &
  completeness, pairwise distinctness of error/range/cause variants,
  `KeySelector` size pinning, `Platform` associated-type trait
  bounds, and the `Otp::burn_once` / `SpiBus::xfer` /
  `Sha256::finalize` documented contracts.
- `hal/Cargo.toml` — added `[dev-dependencies] static_assertions = "1.1"`
  so the compile-time `assert_not_impl_any!` / `assert_impl_all!` /
  `const_assert!` macros can enforce derive bans and sizes at build
  time (catching regressions even under `cargo check`, not only
  `cargo test`).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_hal_error_equality_reflexive` | `HalError` `PartialEq` is reflexive on every named variant | `HalError` |
| `positive_hal_error_is_copy` | `HalError` is `Copy` (passable by value) | `HalError` |
| `positive_hal_error_debug_does_not_panic` | `Debug` impl emits the variant name | `HalError` |
| `positive_hal_error_clone_roundtrip` | `Clone` impl is identity | `HalError` |
| `positive_key_selector_all_variants_constructible` | All 4 `KeySelector` variants construct | `KeySelector` |
| `positive_key_selector_is_copy` | `KeySelector` is `Copy` | `KeySelector` |
| `positive_key_selector_software_holds_borrow` | `Software` variant preserves its reference payload | `KeySelector::Software` |
| `positive_otp_range_named_variants_distinct` | Named `OtpRange` variants pairwise differ | `OtpRange` |
| `positive_otp_range_reserved_payload_preserved` | `OtpRange::Reserved(n)` equality is payload-driven | `OtpRange::Reserved` |
| `positive_otp_range_debug_does_not_panic` | `Debug` emits variant + payload | `OtpRange` |
| `positive_boot_state_data_default_is_all_zero` | `BootStateData::default().raw == [0;32]` | `BootStateData::default` |
| `positive_boot_state_data_roundtrip_equality` | `BootStateData` `PartialEq` is byte-precise | `BootStateData` |
| `positive_boot_state_data_distinct_payload_distinct` | Differing-byte payload compares non-equal | `BootStateData` |
| `positive_boot_state_data_is_copy` | `BootStateData` is `Copy` | `BootStateData` |
| `positive_tamper_cause_named_variants_distinct` | Named `TamperCause` variants pairwise differ | `TamperCause` |
| `positive_tamper_cause_other_payload_preserved` | `Other(n)` equality is payload-driven | `TamperCause::Other` |
| `positive_buttonset_default_is_all_false` | `Buttonset::default()` is `{false,false}` | `Buttonset::default` |
| `positive_buttonset_construction_and_equality` | Field-by-field equality | `Buttonset` |
| `positive_boot_stage_all_has_six_entries` | `BootStage::ALL.len() == 6` | `BootStage::ALL` |
| `positive_boot_stage_all_first_is_clocks_last_is_se` | `ALL[0] == Clocks`, `ALL[5] == Se` | `BootStage::ALL` |
| `positive_boot_stage_variants_pairwise_distinct` | No duplicate entries in `ALL` | `BootStage::ALL` |
| `positive_platform_dispatches_to_all_peripherals` | A full `MockPlatform` exercises every accessor + every per-peripheral method | `Platform` (all 12 accessors) + every trait method |
| `positive_rng_propagates_error` | `Rng::fill` can return `Err(HalError::Timeout)` | `Rng` |
| `positive_otp_burn_once_idempotent_for_identical_data` | Re-burning identical bits succeeds | `Otp::burn_once` |
| `positive_spi_zero_length_xfer_ok` | Zero-length `SpiBus::xfer` is well-defined | `SpiBus::xfer` |
| `positive_boot_stage_iter_through_all` | `for s in BootStage::ALL` yields every variant exactly once | `BootStage::ALL` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_key_selector_must_not_impl_debug` | The `Software(&[u8;32])` variant must not be printable — a `Debug` impl would leak an AES-256 key to any `debug!`/`assert_eq!` failure | `static_assertions::assert_not_impl_any!(KeySelector<'static>: Debug)` — compile fails if `Debug` is ever added | Build fails at this line; test passes today |
| `negative_key_selector_must_not_impl_partial_eq` | A derived `PartialEq` on `Software(&k1) == Software(&k2)` is a non-constant-time byte compare → first-differing-byte timing oracle | `assert_not_impl_any!(KeySelector<'static>: PartialEq)` | Test passes today; would break if derive added |
| `negative_key_selector_must_not_impl_eq` | Same rationale as `PartialEq` | `assert_not_impl_any!` | Test passes today |
| `negative_key_selector_must_not_impl_hash` | A `Hash` impl would funnel raw key bytes into `Hasher::write_*` (and through Debug-printed maps) | `assert_not_impl_any!` | Test passes today |
| `negative_key_selector_must_not_impl_display` | `Display` is the user-facing print path; same leak hazard as Debug | `assert_not_impl_any!` | Test passes today |
| `negative_hal_error_must_impl_debug_eq_copy` | Drivers and the secure-world `match err {…}` rely on these derives | `assert_impl_all!` (compile-time) + runtime usage | Holds |
| `negative_otp_range_must_impl_debug_eq_copy` | Same — used in `Otp::read`/`burn_once` matching | `assert_impl_all!` | Holds |
| `negative_tamper_cause_must_impl_debug_eq_copy` | Same — log + branch in `Tamp::check` consumer | `assert_impl_all!` | Holds |
| `negative_buttonset_must_impl_default_debug_eq_copy` | Same — used by trusted-UI confirm | `assert_impl_all!` | Holds |
| `negative_boot_state_data_must_impl_default_debug_eq_copy` | Used as the FSBL handoff blob | `assert_impl_all!` | Holds |
| `negative_boot_stage_must_impl_debug_eq_copy` | `for stage in BootStage::ALL { … }` requires `Copy` | `assert_impl_all!` | Holds |
| `negative_buttonset_default_is_not_pressed` | `Buttonset::default()` returning a pressed button could spoof a trusted-UI confirm before GPIO init (CLAUDE.md invariant #4 / trusted-UI path) | Construct `Buttonset::default()`, assert `!left && !right` with an attacker-citing message | Both false |
| `negative_boot_state_data_default_is_all_zero` | A non-zero default leaks ambient stack/static data into the FSBL handoff | Iterate `raw` and assert every byte is 0 | All zero |
| `negative_boot_stage_all_has_exactly_six_entries` | The boot ordering count is part of the secure-world bring-up contract (CLAUDE.md Lifecycle); adding/dropping a stage must be explicit | `const_assert_eq!(BootStage::ALL.len(), 6)` + runtime assert | Six |
| `negative_boot_stage_all_exact_documented_order` | The order CLAUDE.md pins is Clocks → TrustZone → Crypto → Buses → Ui → Se. Reordering could (e.g.) run the SAES self-test before SAU lockdown | Compare `BootStage::ALL` against a hardcoded expected array, with a failure message naming CLAUDE.md | Exact match |
| `negative_boot_stage_all_covers_every_variant` | Adding a new `BootStage` variant without updating `ALL` would silently skip a bring-up step | Match exhaustively inside the iteration; a future variant addition forces this `match` to grow | All 6 seen, no duplicates |
| `negative_hal_error_pairwise_distinct` | Two `HalError` variants comparing equal would cause `match err { BadParam => … }` to mis-route faults | Iterate all 5 variants, assert pairwise `!=` | All distinct |
| `negative_otp_range_named_distinct_from_reserved` | A fuzzed `Reserved(0)` must never collide with `AntiRollback` (otherwise a future fuse-write could land in the rollback partition) | Compare each named variant against `Reserved(0..=2)` and assert `!=` | All distinct |
| `negative_tamper_cause_other_distinct_from_named` | Same: `Other(0)` ≠ `BackupVoltage` etc. | Pairwise `assert_ne!` | All distinct |
| `negative_key_selector_does_not_inline_software_key` | A refactor that inlines `Software([u8;32])` puts raw key bytes on every Saes call's stack → leak path via panic backtrace or stack-scrubbing miss | `core::mem::size_of::<KeySelector<'static>>()` is ≤ 2× pointer size + discriminant; also `const_assert!(<= 32)` | Size remains ~16 B on 64-bit hosts |
| `negative_platform_associated_types_carry_trait_bounds` | If a future refactor drops `type Rng: Rng` from `Platform`, callers can plug in arbitrary types as `P::Rng` without satisfying the per-peripheral trait | Generic helpers `<P::Rng as Rng>::fill(…)` etc. — fail to compile if the bound is dropped | Compiles; trait bounds retained |
| `negative_otp_burn_once_rejects_disagreeing_rewrite` | The documented `Otp::burn_once` contract: re-burn with disagreeing bits MUST return `HalError::Unsupported` (not `BadParam`, not `Corrupt`) so callers can branch on "already burnt" vs "garbage input" | Hand-rolled trait impl exercises the rule; assert the exact error variant | `Err(Unsupported)` |
| `negative_spi_mismatched_lengths_rejected` | Documented `SpiBus::xfer` contract: impls require `w.len() == r.len()` (clocking mismatched lengths gives undefined bus bytes); pin the rejection signal as `BadParam` | Hand-rolled trait impl rejects, test asserts exact error | `Err(BadParam)` |
| `negative_sha256_finalize_output_is_32_bytes` | `Sha256::finalize` must return exactly 32 bytes — the C10 chain breaks otherwise. Pin both the type-level shape and a `const_assert_eq!` on `size_of::<[u8;32]>()` | Generic helper preserves `[u8;32]` return type + size assertion | Compiles & 32 |

## Production-code bugs surfaced by negative tests

None. Every negative test passes against the current `hal/src/lib.rs`.
The trait surface honours every documented and implied invariant the
tests check.

## Coverage gaps deliberately left

- **Driver-level negatives (`hal-stm32u5`, `hal-mock`).** The HAL is
  trait-only. Contract tests for the documented behaviours
  (`Otp::burn_once` monotonicity, `SpiBus::xfer` length equality,
  `Flash::program` STM32U5 program-to-zero semantics) belong in the
  impl crates once they land (CLAUDE.md "PR 2 / PR 3 deferred").
  Tests here demonstrate the contract is *testable* via the trait
  surface, with a hand-rolled impl, so the impl crates can fold them
  in verbatim.
- **`Tamp::check` post-arm semantics.** The trait spec doesn't pin
  whether `check` may return `Some(_)` on the first poll after
  `arm()`. A future doc clarification could add a negative test here.
- **`I2cBus::xfer` zero-byte read.** Spec says it returns "the number
  of bytes actually read"; a zero-byte read with an empty `r` slice
  could be either `Ok(0)` or an error depending on impl. Left to the
  impl crates.
- **Static layout pinning of `BootStateData::raw`.** Length is
  guaranteed by the type (`[u8; 32]`), but a tagged-field future
  refactor could change byte ordering. Out of scope for this crate
  (no field accessors exist beyond `.raw`).
- **Compile-fail tests via `trybuild`.** Considered, but
  `static_assertions` covers the equivalent "must-not-impl" surface
  at lower infrastructure cost. If a future negative invariant cannot
  be expressed as a trait-bound assertion (e.g. enforcing that
  callers cannot move a `KeySelector::Software` across a function
  boundary), `trybuild` would be the right tool.

## Verification

- `cargo fmt -p pqsigner-hal --check` — N/A (sandbox blocked
  `cargo fmt` invocations; new code is rustfmt-style by inspection,
  rerun locally to confirm)
- `cargo check -p pqsigner-hal` — PASS (also `--tests`)
- `cargo clippy -p pqsigner-hal --tests -- -D warnings` — N/A
  (sandbox blocked `cargo clippy` invocations; rerun locally to
  confirm)
- `cargo test -p pqsigner-hal` — PASS (50 tests, 0 ignored: 21
  positive_types + 5 positive_mock_platform + 24
  negative_invariants + 0 lib unit + 0 doc-tests)
- (firmware) on-target tests deferred: no — `pqsigner-hal` is a pure
  trait crate that builds for both host and `thumbv8m.main-none-eabi`;
  the host-runnable suite is complete.
