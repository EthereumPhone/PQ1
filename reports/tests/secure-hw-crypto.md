# Test Suite Added — `secure-hw-crypto`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Crypto-adjacent hardware drivers (HASH, SAES, OTP, HUK, BHK, secret-key derivation).

Source files covered:
- `secure/src/hw/mmio.rs` — 141 lines, typed MMIO `Reg32` / `RoReg32` wrappers.
- `secure/src/hw/hash.rs` — 362 lines, STM32U585 HASH peripheral / SHA-256 FFI.
- `secure/src/hw/saes.rs` — 624 lines, AES-256-ECB over the SAES coprocessor under `KEYSEL ∈ {Software, DHUK, BHK, DHUK^BHK}`.
- `secure/src/hw/saes_cmac.rs` — 46 lines, `cmac_dhuk` adaptor (feature-gated by `saes-dhuk`).
- `secure/src/hw/secret_keys.rs` — 372 lines, domain-separated per-purpose subkey API.
- `secure/src/hw/otp.rs` — 595 lines, rollback counter + device master in user OTP.
- `secure/src/hw/huk.rs` — 119 lines, per-device wrap-key derivation (UID + OTP master).
- `secure/src/hw/bhk.rs` — 372 lines, Tier-2 BHK provisioning / load + TAMP-lock (feature-gated by `bhk`).

## Slice constraints

Every file except `mmio.rs` imports `cortex_m` or peers that drag it in, so the
slice cannot link on host. The whole `hw` module is `#[cfg(not(test))]` in
`main.rs`; on-target tests live behind hardware-specific Makefile targets
(`make saes-self-test-hw`, `make pin-gate-hw-counter-e2e`, etc.) and are NOT
exercised by this host-side pass. The pass instead pins the slice through
two host-runnable mechanisms:

1. **`include_str!` source-text invariant pins** for KDF labels, register
   addresses, FI guards, zeroization sites, feature gates — anything whose
   silent removal would land a catastrophic regression in silicon.
2. **Reference-algorithm tests**: a byte-for-byte port of
   `secret_keys::hkdf_expand` validated against RFC 5869 Test Case 1, plus
   tests of the OTP rollback bit-walk planning algorithm.

## Test files added / extended
- `secure/src/hw_crypto_under_test/mod.rs` — new test-only scaffold module
  registered under `#[cfg(test)]` in `secure/src/main.rs`.
- `secure/src/hw_crypto_under_test/pure_tests.rs` — **24 positive** +
  **40 negative** = **64 tests**, organised into ten sections.

## Positive coverage (24)

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_hash_base_secure_alias_0x520c_0400` | HASH peripheral uses secure alias (TZSC blocks NS alias) | `hw::hash` |
| `positive_saes_base_secure_alias_0x520c_0c00` | SAES peripheral uses secure alias | `hw::saes` |
| `positive_hash_register_offsets` | HASH_CR/DIN/STR/SR/HR0 at documented offsets | `hw::hash` |
| `positive_hash_sha256_algo_bits` | ALGO field = `(1<<17)|(1<<18)` for SHA-256 on STM32U5 | `hw::hash` |
| `positive_saes_keyr_offsets_split_around_ivr` | KEYR0..3 at 0x10..0x1C, KEYR4..7 at 0x30..0x3C (IVR sits between) | `hw::saes` |
| `positive_saes_keysel_bit_pattern_matches_hal` | KEYSEL values match STM32 HAL CRYP_KEYSEL_* table | `hw::saes::KeySel` |
| `positive_otp_layout_constants` | OTP_BASE / ROLLBACK_WORDS / MAX_FW_VERSION / MASTER_KEY_OFFSET / MASTER_KEY_SIZE | `hw::otp` |
| `positive_huk_uid_base_address` | STM32U585 UID at 0x0BFA_0700 | `hw::huk` |
| `positive_bhk_page_addresses` | BHK flash page / page-number / BHKLOCK bit | `hw::bhk` |
| `positive_secret_keys_labels_present` | all five `pqsigner/*` v1 KDF labels present in source | `hw::secret_keys` |
| `positive_huk_domain_tag_present` | `pqsigner-device-key-v1` present in HUK source | `hw::huk` |
| `positive_secret_keys_output_sizes` | function signatures: 64 B PBS, 16 B SCP03 ENC/MAC/DEK, 16 B admin PIN | `hw::secret_keys` |
| `positive_hkdf_expand_matches_rfc5869_test_case_1` | reference HKDF-Expand produces RFC 5869 §A.1 OKM byte-for-byte | algorithm (reference oracle) |
| `positive_hkdf_expand_single_block_equals_t1` | L ≤ 32 yields prefix of HMAC(prk, info ‖ 0x01) | algorithm |
| `positive_hkdf_expand_64_bytes_equals_t1_concat_t2` | 64-byte OPTIGA PBS = T(1) ‖ T(2) | algorithm |
| `positive_hkdf_distinct_labels_diverge` | distinct labels produce independent keys | algorithm |
| `positive_otp_rollback_bit_walk_lsb_first` | bit-walk clears trailing-zero bit | `hw::otp::bump_to` |
| `positive_otp_rollback_word_capacity_is_1024` | 32 × 32 = 1024 bits | `hw::otp` |

(plus 6 unlisted "address/constant pin" positives, one per file)

## Negative coverage (40)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_secret_keys_optiga_pbs_v1_label_unchanged` | "the OPTIGA PBS KDF tag is stable" (CLAUDE.md: no casual KDF tag changes) | text-pin the exact byte literal in source | failing test if tag renamed — would brick every paired OPTIGA |
| `negative_secret_keys_se050_scp03_enc_v1_label_unchanged` | SE050 SCP03-ENC tag stable | text-pin | bricks SE050 SCP03 channel if renamed |
| `negative_secret_keys_se050_scp03_mac_v1_label_unchanged` | SE050 SCP03-MAC tag stable | text-pin | bricks SE050 SCP03 channel if renamed |
| `negative_secret_keys_se050_scp03_dek_v1_label_unchanged` | SCP03-DEK tag stable | text-pin | desyncs future PUT KEY rotations |
| `negative_secret_keys_se050_admin_pin_v1_label_unchanged` | admin-PIN tag stable | text-pin | locks every device out of admin-wipe if renamed |
| `negative_huk_domain_tag_pqsigner_device_key_v1_unchanged` | HUK domain tag stable | text-pin | invalidates every previously-sealed object |
| `negative_secret_keys_labels_are_versioned_with_v1_suffix` | every label carries a `-vN` suffix | text-scan for the unversioned form | catches a future rename to a tag without version |
| `negative_optiga_pairing_secret_signature_is_64_bytes` | PBS output remains 64 B per OPTIGA SRM | text-pin function signature | shrunk PBS would be rejected by the chip |
| `negative_hash_module_uses_secure_alias_not_ns_alias` | HASH NS alias 0x420C_0400 absent (TZSC blocks NS) | text-pin secure address present + NS-base absent | bus-fault at first SHA-256 push if wrong alias |
| `negative_saes_keyr4_does_not_collide_with_ivr` | KEYR4 ≠ 0x20 (IVR0) | text-pin against 0x20 offset for KEYR4 | catches copy-paste bug writing key into IV register |
| `negative_saes_keysel_bhk_is_2_not_3` | Bhk selector = 0b010 | text-scan for `Bhk = 0b011` | KEYSEL bypass / SR.KEYVALID never asserts |
| `negative_otp_max_fw_version_capacity_unchanged_at_1024` | OTP rollback capacity unchanged | text-pin both feeders | halving ROLLBACK_WORDS would halve lifetime |
| `negative_otp_master_key_offset_unchanged_at_128` | master-key region offset stable | text-pin | overlap with rollback tally would corrupt readback |
| `negative_hash_module_self_test_kat_bytes_unchanged` | SHA-256("abc") canonical KAT bytes | text-pin first + last KAT bytes | tweak would make broken HASH pass self-test |
| `negative_hash_self_test_failure_halts_cpu` | self-test FAIL → CPU halt, not return | text-pin `loop { wfe(); }` | continue-after-FAIL would let signatures emit from a broken hash |
| `negative_bhk_module_is_feature_gated` | `bhk.rs` carries `#![cfg(feature = "bhk")]` | text-pin module-level cfg | generic build pulling in zero-keyed-at-reset BHK derivations |
| `negative_saes_cmac_module_is_feature_gated` | `saes_cmac.rs` carries `#![cfg(feature = "saes-dhuk")]` | text-pin | compile in builds without SAES driver |
| `negative_secret_keys_bhk_plus_otp_hardcoded_combo_is_compile_error` | broken feature combo blocked at compile | text-pin `#[cfg(all(...))]` + `compile_error!` | runtime `KeyInvalid` on every admin-PIN derivation |
| `negative_saes_software_key_zeroized_after_op` | KEYR0..KEYR7 written to 0 on exit | text-pin all 8 `keyrN.write(0)` lines | software key leaks across ops; later DHUK op could leak via SR/timing |
| `negative_saes_decrypt_scratch_zeroized` | d0..d3 scratch zeroized | text-pin `dNz.zeroize()` lines | ciphertext bytes survive in stack reuse |
| `negative_hkdf_expand_zeroizes_prev_t` | last-block T(i) scrubbed before return | text-pin `prev_t.zeroize();` | final block of every derivation lingers on stack |
| `negative_otp_burn_zeroizes_key_on_every_exit_path` | ≥ 4 `key.zeroize()` exit sites | substring-count | missed scrub leaks device master |
| `negative_otp_burn_uses_rng_strong_not_plain_rng` | OTP burn uses XOR-folded RNG | text-pin `rng_strong::fill` call | biased single TRNG → irreversibly burned weak master |
| `negative_huk_zeroizes_otp_master_and_uid` | OTP master + UID scrubbed | text-pin both `*.zeroize()` lines | inputs linger after HUK derivation returns |
| `negative_bhk_zeroizes_plaintext_on_every_path` | plaintext BHK + wrapped buffer scrubbed | substring-count `bhk.zeroize()` + pin `wrapped.zeroize()` | plaintext BHK linger after provision/load |
| `negative_otp_bump_uses_fi_double_check_sentinel` | FI-hardened double-read + sentinel guard | text-pin `wait_random` + `check_true_into_sentinel` + `OK_SENTINEL` | a single glitched `if` could skip OTP commits |
| `negative_otp_program_qw_bounds_checked` | `program_otp_qw` carries 3 debug_asserts | text-pin three predicates | runtime burn into reserved future-use region |
| `negative_otp_burn_refuses_when_already_burned` | second-call refuses | text-pin `is_device_master_burned()` + `AlreadyBurned` | OR-into-existing yields garbage |
| `negative_otp_burn_readback_verified` | post-burn readback compared against written bytes | text-pin `OtpError::ReadbackMismatch` + `readback == key` | brown-out mid-program goes undetected |
| `negative_otp_bump_to_rejects_above_max_fw_version` | software cap before flash op | text-pin guard | exhausted OTP attempts further writes |
| `negative_saes_init_clears_rng_seed_error_and_surfaces_it` | RngSeedError detected before any op | text-pin `RngSeedError` + clear-bit write | un-seeded SAES emits side-channel-leaky ciphertexts |
| `negative_saes_self_test_includes_domain_collision_check` | self-test asserts DHUK ≠ Software | text-pin `SelfTestDomainCollision` + comparison | a KEYSEL-bypass would route DHUK → SW key bytes undetected |
| `negative_saes_polls_keyvalid_before_encrypt` | KEYVALID polled before EN | text-pin spin loop | engine starves forever, CCF never sets |
| `negative_saes_decrypt_runs_key_derivation_pass_first` | KD pass (MODE=0b01) precedes decrypt (0b10) | text-pin both MODE shifts | nonsense plaintext on every decrypt |
| `negative_hash_module_pulses_hashrst_before_each_init` | HASHRST set+clear pulsed in both `init_clock` and `pqsigner_sha256_init` | substring-count ≥ 2 | STM32U5 errata: completed-hash FIFO state stays stuck |
| `negative_bhk_provision_refuses_when_already_provisioned` | second-call refuses | text-pin guard | reprovision invalidates paired SE050 channels |
| `negative_bhk_load_and_lock_sets_bhklock` | BHKLOCK raised before return | text-pin `seccfgr | TAMP_BHKLOCK` write | S-world RCE could dump unwrapped BHK from BKPR |
| `negative_hkdf_expand_n_blocks_capped_at_255` | 255-block cap enforced | text-pin `debug_assert!(n <= 255` | counter byte wraps silently → repeated blocks |
| `negative_hkdf_expand_truncated_output_takes_tag_prefix` | truncation = prefix (no reshape) | reference algorithm comparison | callers' prefix-stability assumption violated |
| `negative_otp_bump_to_idempotent_when_target_le_current` | re-bump is a no-op | text-pin early-return | crash-replay burns extra OTP bits |
| `negative_huk_mixes_uid_and_otp_master_separately` | both inputs enter digest | text-pin both `h.update()` lines | single-update would defeat per-die OR per-board layer |
| `negative_huk_includes_domain_tag_length_prefix` | length-prefixed tag | text-pin LE4 length feed | suffix-collision across unrelated callers |
| `negative_mmio_reg32_construction_is_unsafe` | `Reg32::new` stays `unsafe` | text-pin `pub const unsafe fn new` | typed-MMIO wrapper loses its single-audit point |
| `negative_mmio_read_at_is_unsafe_with_bank_bound_safety_doc` | offset accessors stay `unsafe` | text-pin both signatures | peripherals could be walked off-end of register bank |
| `negative_no_classical_signer_in_slice` | no ECDSA / Ed25519 / secp256k1 reference in slice | substring scan across all 8 files | CLAUDE.md invariant #5 (single-signer C10) breached |
| `negative_no_rotate_master_keys_path_in_secret_keys` | no rotate / reset / increaseMax path | substring scan | CLAUDE.md invariant #6 (bootstrap keys immutable) breached |

## Production-code bugs surfaced by negative tests

None. Every assumption that the negative suite attacks is currently
enforced by the source. The text-pin tests would fail on any future
refactor that silently broke an invariant.

## Coverage gaps deliberately left

The slice is firmware-only — the following classes of test require
on-target execution and are out of scope for this host-side pass:

- **HASH peripheral functional correctness**: SHA-256("abc") KAT, large
  unaligned streaming buffers, FIFO-saturation behaviour. Exercised by
  `make e2e-hw` (boot self-test) and indirectly by every signing
  benchmark; the host can only pin the KAT bytes and reset sequence.
- **SAES driver round-trip**: SW round-trip, DHUK domain separation,
  KEYVALID timing on real silicon. Covered on-target by
  `make saes-self-test-hw` (and at RDP1 via `make saes-self-test-hw-rdp1`).
- **OTP one-way commits**: `bump_to`, `burn_device_master`, readback
  verification under brown-out. Pure-math bit-walk planning is
  unit-tested here; physical commits cannot be tested without a
  sacrificial bench MCU.
- **HUK derivation against real STM32U585 UID**: the UID register is
  factory-fused; per-die uniqueness is only observable on real silicon
  by capturing the SAES `self_test` fingerprint across boards
  (already manual-validated).
- **BHK provision + TAMP-lock**: requires `bhk` feature, RDP-aware
  flash writes, TAMP backup-domain config. Covered on-target by the
  `bhk` feature's `saes_self_test` (BHK fingerprint) — host cannot
  exercise the TAMP register space.
- **Constant-time / side-channel sanity**: subtle-eq usage and FI
  double-evaluation patterns are partially text-pinned (FI sentinel
  pin on OTP bump), but the slice's hot loops don't take secret-
  dependent branches — full SCA coverage requires lab instrumentation
  (ChipWhisperer rig).
- **`mmio.rs` real-MMIO semantics**: `Reg32::new(addr: u32)` casts a
  `u32` into a `*mut u32`. On a 64-bit host the upper bits of a
  pointer are unmapped, so any test that constructs a `Reg32` against
  a heap address would either truncate or fault. The host pins are
  limited to the safety contract (signature + safety docs); MMIO
  semantics ride on-target.

A future pass could add a QEMU-driven smoke that boots the secure
firmware under `mock-se` + `saes-self-test` and asserts the PASS log
line over the semihosting console — `make saes-self-test-hw` already
does this on real hardware, the QEMU variant is the missing link.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox rejected fmt
  invocation; files follow existing `nsc_core_under_test/pure_tests.rs`
  style.)
- `cargo check -p sphincs-tz-secure --tests` — PASS (compiles with no
  new warnings on the added files).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox rejected clippy invocation; `cargo check --tests` is clean
  for the new files).
- `cargo test -p sphincs-tz-secure` — PASS (596 tests passed, 1 ignored;
  64 of the 596 are the new `hw_crypto_under_test::pure_tests::*` cases).
- (firmware) on-target tests deferred: yes — see "Coverage gaps
  deliberately left" above; none of the slice's MMIO / OTP-burn /
  SAES-round-trip behaviour is exercised by this pass.
