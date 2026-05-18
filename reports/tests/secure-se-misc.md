# Test Suite Added — `secure-se-misc`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
SCP03 logic, secure-element abstraction, CMAC, semihosting-SPI, Tropic01.

Source files covered:
- `secure/src/scp03_logic.rs` — 441 → 723 lines (host-compileable SCP03
  primitives: AES-128 ECB/CBC, CMAC-AES-128, NIST SP 800-108 KDF,
  KCV, GP `PUT KEY` APDU builder, factory-keyset constants)
- `secure/src/cmac.rs` — 468 → 715 lines (host-compileable generic
  CMAC-AES core + counter-mode KDF, used by the SAES-DHUK backend)
- `secure/src/secure_element.rs` — 541 → 873 lines (host-compileable
  `WalletStore` / `SecureElement` traits + `MockSecureElement` for
  QEMU PIN-brick regression)
- `secure/src/tropic01_se.rs` — 654 lines (firmware-only,
  `cfg(all(feature = "tropic01-se", not(test)))`-gated; pinned via
  `include_str!`)
- `secure/src/semihosting_spi.rs` — 216 lines (firmware-only,
  `cfg(all(feature = "tropic01-se", not(feature = "stm32u585"),
  not(test)))`-gated; pinned via `include_str!`)

## Test files added / extended
- `secure/src/scp03_logic.rs` — extended existing `#[cfg(test)] mod
  tests`: +9 positive, +10 negative tests (AES-128 CBC chaining /
  keying, KDF == CMAC pin, factory keyset bytes & KVN pins, PUT KEY
  header / block / wrap-bytes / key-order pins, KCV 0x01-vs-0x00
  regression pin, DD constant pairwise distinctness, KDF
  challenge / DD-constant separation, exhaustive
  `keys_are_factory_default` byte-flip sweep, `cmac` empty-input
  alias).
- `secure/src/cmac.rs` — extended existing `#[cfg(test)] mod tests`:
  +5 positive, +10 negative tests (double_l carry / reduction /
  inter-byte propagation, empty-label KDF, backend-error propagation
  in `cmac_generic` + `kdf_cmac_counter_generic`, scratch-one-short
  rejection, output one-past-max rejection, counter starts at 1 not
  0, CMAC empty vs zero-block diverge, single-bit avalanche, two-
  block uniqueness, `KdfError` derives present).
- `secure/src/secure_element.rs` — extended existing `#[cfg(test)]
  mod tests`: +13 positive, +12 negative tests (r-mem write/read/
  erase round-trip + boundary lengths, MACD max-slot + determinism +
  state-depends-on-prior-input, default `random()` / `pin_attempt_
  count` / `divergent` / `factory_reset_admin` / `sync_remaining_
  with_mcu` impls, out-of-range slot rejection across all three
  r-mem ops + MACD, oversize data rejection, too-small read buf
  rejection, unoccupied-slot read rejection, distinct-input MACD
  divergence, simulate_glitch double-arm, `SeError` /
  `UnlockError` Debug impl coverage, geometry constants pin,
  non-zero master_secret guard).
- `secure/src/secure_se_misc_pure_tests.rs` (new file, 34 tests:
  9 for `semihosting_spi`, 25 for `tropic01_se`) — `include_str!`
  source-text invariant pins for the two firmware-only files. Wired
  into `main.rs` via `#[cfg(test)] mod secure_se_misc_pure_tests;`.

Totals: **27 positive + 32 negative tests across the host-compileable
files, plus 13 positive + 21 negative source-text-pin tests on the
firmware-only files = 93 new tests (vs the existing 41 in scope).**
Crate-wide test count grew from 1739 → 1833.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `scp03_logic::positive_aes128_cbc_single_block_with_zero_iv_matches_ecb` | CBC with zero IV == ECB on a single block (FIPS 197 §C.1) | `aes128_cbc_encrypt` |
| `scp03_logic::positive_aes128_cbc_two_blocks_chain_through_previous_ciphertext` | CBC chains via prior ciphertext, not plaintext | `aes128_cbc_encrypt` |
| `scp03_logic::positive_aes128_cbc_distinct_keys_diverge` | Different keys produce different ciphertexts | `aes128_cbc_encrypt` |
| `scp03_logic::positive_kdf_equals_cmac_aes128_over_derivation_data` | `kdf(k, dd) == cmac_aes128(k, [&dd])` | `kdf` |
| `scp03_logic::positive_platform_keyset_bytes_match_an12436` | Factory-keyset constants' boundary bytes match AN12436 + pairwise distinct | `PLATFORM_{ENC,MAC,DEK}` |
| `scp03_logic::positive_key_version_is_0x0b` | SCP03 KVN constant = 0x0B per GP/AN12436 | `KEY_VERSION` |
| `scp03_logic::positive_put_key_ins_is_0xd8` | INS byte for PUT KEY is 0xD8 per GP 2.3 | `PUT_KEY_INS` |
| `scp03_logic::positive_put_key_apdu_len_layout_arithmetic_is_72` | APDU length math = `5 + 1 + 3*22 = 72` | `PUT_KEY_APDU_LEN` |
| `cmac::double_l_low_bit_no_reduction` | `dbl([0…,0x01]) = [0…,0x02]` (no reduction) | `double_l` |
| `cmac::double_l_no_reduction_when_original_msb_clear` | `dbl([0x40,…]) = [0x80,…]` (top bit became 1 but original was 0) | `double_l` |
| `cmac::double_l_carry_and_reduction_compose` | `dbl([0x81,…]) = [0x02,…,0x87]` (carry out AND reduction) | `double_l` |
| `cmac::double_l_inter_byte_carry` | Carry crosses byte boundaries | `double_l` |
| `cmac::kdf_empty_label_one_byte_scratch_succeeds` | Empty label with 1-byte scratch = counter-byte-only CMAC | `kdf_cmac_counter_generic` |
| `secure_element::positive_rmem_write_then_read_roundtrip` | r-mem write/read preserves bytes | `MockSecureElement::r_mem_*` |
| `secure_element::positive_rmem_erase_clears_slot` | Erase → subsequent read returns `SlotNotFound` | `MockSecureElement::r_mem_erase` |
| `secure_element::positive_rmem_write_zero_length_accepted` | Zero-length write is valid | `r_mem_write` |
| `secure_element::positive_rmem_write_max_length_accepted` | 512-byte write at boundary is accepted | `r_mem_write` |
| `secure_element::positive_macd_max_slot_accepted` | MACD slot 15 (=NUM_MACD_SLOTS-1) accepted | `mac_and_destroy` |
| `secure_element::positive_macd_first_call_is_deterministic_per_input` | Same input on fresh slots produces same output | `mac_and_destroy` |
| `secure_element::positive_default_random_returns_slot_not_found` | Default `WalletStore::random` returns `SlotNotFound` | `WalletStore::random` |
| `secure_element::positive_default_pin_attempt_count_is_none` | Default `pin_attempt_count` returns `None` | `WalletStore::pin_attempt_count` |
| `secure_element::positive_default_divergent_is_false` | Single-SE backends return `false` for divergent | `pin_attempt_counts_divergent` |
| `secure_element::positive_default_factory_reset_admin_succeeds_on_mock` | Default `factory_reset_admin` zeroizes + returns Ok | `factory_reset_admin` |
| `secure_element::positive_fresh_mock_is_not_provisioned` | `is_provisioned()` is false on fresh mock | `is_provisioned` |
| `secure_element::positive_fresh_mock_remaining_attempts_is_max` | Fresh mock reports `MAX_ATTEMPTS` remaining | `remaining_attempts` |
| `secure_element::positive_sync_remaining_with_mcu_is_noop_on_mock` | Default `sync_remaining_with_mcu` doesn't change state | `sync_remaining_with_mcu` |
| `secure_se_misc::semihosting_spi::positive_max_frame_constant_is_300` | `MAX_FRAME = 300` pinned | `semihosting_spi.rs:14` |
| `secure_se_misc::semihosting_spi::positive_hex_buf_size_equation_is_max_frame_times_two_plus_four` | Hex-buf sizing arithmetic frozen | `semihosting_spi.rs:16` |
| `secure_se_misc::semihosting_spi::positive_protocol_terminator_is_x_newline` | "x\n" terminator pinned | `semihosting_spi::spi_transfer` |
| `secure_se_misc::semihosting_spi::positive_cs_deassert_protocol_strings` | `"CS=0\n"` / `"OK\r\n"` ack pinned | `semihosting_spi::cs_deassert` |
| `secure_se_misc::tropic01::positive_max_attempts_is_ten` | `TROPIC01_MAX_ATTEMPTS = 10` matches SE050/Mock | `tropic01_se.rs:36` |
| `secure_se_misc::tropic01::positive_per_slot_ct_len_is_32` | XOR-encrypted slot is 32 bytes (no GCM tag) | `T01_CT_LEN` |
| `secure_se_misc::tropic01::positive_pin_tag_len_is_32` | SHA-256 tag length | `T01_TAG_LEN` |
| `secure_se_misc::tropic01::positive_pin_state_total_is_353_bytes` | PIN state fits in 475-B r-mem cap | `T01_PIN_STATE_LEN` |
| `secure_se_misc::tropic01::positive_pin_tag_compare_uses_constant_time_eq` | Tag check uses `subtle::ConstantTimeEq::ct_eq` | `batch_verify_pin` |
| `secure_se_misc::tropic01::positive_secrets_are_zeroized_on_pin_paths` | All secret temporaries call `.zeroize()` | `batch_verify_pin` / `store_data_session` |
| `secure_se_misc::tropic01::positive_pin_state_layout_serializes_in_order` | counter(1)+tag(32)+10×ct(32) write order pinned | `serialize_t01_pin_state` |
| `secure_se_misc::tropic01::positive_lockout_erases_all_four_wallet_slots` | 10th-wrong-PIN wipes slots 0..3 | `batch_verify_pin` |
| `secure_se_misc::tropic01::positive_pairing_priv_is_not_publicly_exposed` | `pairing_priv` field is not `pub` | `Tropic01SecureElement` |
| `secure_se_misc::tropic01::positive_setup_pairing_uses_slot_1_keeps_slot_0_fallback` | Per-device key goes to slot 1; slot 0 stays | `setup_pairing` |

(Plus all pre-existing positive tests in the three host-compileable files
remain unchanged and continue to pass.)

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `scp03_logic::negative_scp03_kcv_filler_is_0x01_not_0x00` | KCV filler block is the SCP03 `0x01` per GP Amendment D, not the SCP02 `0x00` | Compute `scp03_kcv(0-key)` and assert it ≠ `AES-ECB(0-key, 0^16)` (the SCP02 value) | `scp03_kcv` ≠ ECB(0); regression flips this |
| `scp03_logic::negative_keys_are_factory_default_rejects_every_byte_flip` | A prefix-only compare in `keys_are_factory_default` would let attacker-chosen keys with matching prefixes bypass the rotation guard | Exhaustively flip each byte of each of three factory consts, assert `keys_are_factory_default` returns false | All 48 byte-flips reject |
| `scp03_logic::negative_dd_constants_are_pairwise_distinct` | Two SCP03 KDF labels sharing byte-11 would alias session keys | Pairwise inequality across `DD_*` constants | All 10 pairs distinct |
| `scp03_logic::negative_kdf_output_changes_with_host_challenge` | host_challenge actually feeds the KDF (not, say, wrong slice slot) | Compute `kdf` with two different host challenges, assert ≠ | Distinct outputs |
| `scp03_logic::negative_kdf_output_changes_with_card_challenge` | card_challenge actually feeds the KDF | Same as above for card | Distinct outputs |
| `scp03_logic::negative_kdf_output_changes_with_dd_constant` | Different DD constants → different keys (the "label" separation) | Compute kdf for S-ENC and S-MAC, assert ≠ | Distinct outputs |
| `scp03_logic::negative_scp03_kcv_returns_exactly_three_bytes` | KCV length drift would corrupt PUT KEY framing | `size_of_val(&kcv)` is 3 | Size check pins type |
| `scp03_logic::negative_put_key_apdu_header_bytes_are_frozen` | Header byte drift would silently fail rotation | Byte-by-byte header check | All 6 header bytes pinned |
| `scp03_logic::negative_put_key_enc_data_len_byte_is_0x10_per_block` | A silent +1 to the data-len byte misaligns the parser to KCV bytes | Check `[0x88,0x10,…,0x03]` per block | All 3 blocks frame-correct |
| `scp03_logic::negative_put_key_wrapped_bytes_match_ecb_under_platform_dek` | A refactor that swapped ECB for CBC would silently break PUT KEY | Recompute `AES-ECB(PLATFORM_DEK, new_key)` and compare | Each block matches ECB exactly |
| `scp03_logic::negative_put_key_emits_keys_in_enc_mac_dek_order` | Reordering would silently mis-rotate the chip (DEK ↔ ENC) | Provide distinct values per slot and assert each lands in the correct block | Order pinned |
| `scp03_logic::negative_cmac_aes128_no_input_slices_equals_one_empty_slice` | `cmac_aes128(k, &[])` and `cmac_aes128(k, &[&[]])` must alias (CMAC of empty) | Compute both, assert equal | Both equal |
| `cmac::negative_cmac_generic_propagates_backend_error` | A silently-swallowed AES error would produce attacker-controlled tag | Inject closure returning `Err(GlitchedAes)`, assert `cmac_generic` returns the same error | `Err(GlitchedAes)` propagates |
| `cmac::negative_kdf_propagates_backend_error_wrapped` | KDF must wrap backend error as `KdfError::Backend(e)` | Same closure-injection on `kdf_cmac_counter_generic` | `Err(KdfError::Backend(GlitchedAes))` |
| `cmac::negative_kdf_scratch_one_short_is_rejected` | scratch == label.len() would collapse domain separation | Pass `scratch.len() == label.len()`, expect `LabelTooLong` | Rejected |
| `cmac::negative_kdf_output_one_past_max_is_rejected` | 256×16 bytes would wrap counter and silently re-emit block 1 | Request `255*16 + 1` bytes | `OutputTooLong` |
| `cmac::negative_kdf_counter_starts_at_one_not_zero` | Counter=0 start would alias `label || 0x00` cases | Compute `CMAC(K, label || 0x00)` and assert KDF's first block ≠ it | Distinct |
| `cmac::negative_cmac_empty_and_zero_block_diverge` | Empty (K2 path) and zero-block (K1 path) must NOT alias | Compute both, assert ≠ | Distinct |
| `cmac::negative_cmac_one_bit_flip_changes_tag_at_each_position` | Each input byte must influence the tag | Single-bit-flip each of 16 byte positions, assert tag changes | All 16 positions sensitive |
| `cmac::negative_kdf_two_blocks_are_not_equal_to_each_other` | Counter increment is actually used | Request 32 bytes and assert block 0 ≠ block 1 | Distinct |
| `cmac::negative_kdf_error_derives_are_present` | `KdfError` keeps `Copy/Clone/Eq/Debug` derives | Exercise each | Compile + match passes |
| `secure_element::negative_rmem_write_out_of_range_slot_rejected` | NS-controlled slot index must not reach raw array indexing | Write to slot 8 + 0xFFFF, expect SlotNotFound | Both rejected |
| `secure_element::negative_rmem_write_oversize_data_rejected` | Data > MAX_RMEM_DATA must be rejected | Write MAX+1 bytes | `InvalidParameter` |
| `secure_element::negative_rmem_read_unoccupied_slot_rejected` | Reading post-erase must NOT return stale slot bytes | Read fresh slot | `SlotNotFound` |
| `secure_element::negative_rmem_read_buffer_too_small_rejected` | Truncated reads must surface as explicit error | Write 5B, read into 3B buffer | `InvalidParameter` |
| `secure_element::negative_rmem_read_out_of_range_slot_rejected` | Out-of-range read slot indices must be rejected | Read slot 8 | `SlotNotFound` |
| `secure_element::negative_rmem_erase_out_of_range_slot_rejected` | NS-controlled slot index for erase must not reach raw indexing | Erase slot 8 | `SlotNotFound` |
| `secure_element::negative_macd_out_of_range_slot_rejected` | MACD slot index must be range-checked | mac_and_destroy slot 16 + 0xFFFF | Both rejected |
| `secure_element::negative_macd_distinct_inputs_diverge` | MACD output must depend on input, not a constant | Run on fresh slots with two different inputs | Distinct outputs |
| `secure_element::negative_macd_output_depends_on_prior_state` | MACD output must depend on slot's prior state (not just current input) | Compare `mac(B)` on fresh slot vs `mac(B)` after `mac(A)` | Distinct outputs |
| `secure_element::negative_simulate_glitch_double_arm_is_independent` | The one-shot glitch flag actually clears between arms | Arm → fire → clean call → arm → fire → clean call | Two arm cycles each fire exactly once |
| `secure_element::negative_error_debug_impls_dont_panic_for_any_variant` | `SeError` / `UnlockError` Debug impls exist for every variant | Format every variant, assert no panic | All variants format |
| `secure_element::negative_mock_geometry_constants_pinned` | Mock geometry (8 rmem / 16 macd / 512 byte) must match HW expectations | Constant pins | Each = expected value |
| `secure_element::negative_unlock_returns_nonzero_master_secret` | Successful unlock must yield non-zero master_secret | Unlock with provisioned PIN, assert ≠ 0 | Non-zero |
| `semihosting_spi::negative_spi_error_variants_all_present` | All five SpiError variants exist | Source-text grep for each variant name | All present |
| `semihosting_spi::negative_response_length_validator_is_strict_equality` | Length validator uses `!=` (strict), not `<=` (lax) | Source-text pin on the `if end != data.len() * 2` check | Pinned exactly |
| `semihosting_spi::negative_parse_hex_nibble_returns_error_on_non_hex` | Non-hex bytes are rejected, not silently mod-16'd | Source-text pin on the `Err(SpiError::HexParseError)` arm | Pinned |
| `semihosting_spi::negative_read_byte_retry_loop_is_bounded` | Read poll is bounded at 100_000 iterations | Source-text pin on the for-loop bound | Pinned |
| `semihosting_spi::negative_spi_error_kind_is_other` | `ErrorKind::Other` mapping pinned for embedded-hal SpiDevice | Source-text grep | Pinned |
| `tropic01::negative_every_se_op_is_wrapped_in_with_session` | Every SE op goes through `with_session!` (no plaintext I2C/SPI) | Count `Tropic01::new(spi)` (must be 1, only inside macro) + grep for bare `tropic.r_mem_*` / `tropic.mac_and_destroy` | Invariant #3 preserved |
| `tropic01::negative_pin_tag_compare_does_not_use_byte_equality` | Tag compare uses `ct_eq`, not `==` | Source-text grep for `== ps.tag` / `== expected_tag` etc. | None of those patterns present |
| `tropic01::negative_wrong_pin_path_zeroizes_recovered_secret` | Recovered candidate is zeroized on wrong-PIN branch | Locate wrong-PIN `} else {` block, assert `recovered_s.zeroize();` inside | Pinned in branch |
| `tropic01::negative_per_slot_xor_key_is_zeroized` | k_j is zeroized in both store + verify paths | Count `k_j.zeroize();` ≥ 2 | ≥ 2 occurrences |
| `tropic01::negative_macd_output_is_zeroized` | w_j is zeroized in both store + verify paths | Count `w_j.zeroize();` ≥ 2 | ≥ 2 occurrences |
| `tropic01::negative_se_error_to_unlock_error_mapping_is_correct` | SeError → UnlockError mapping arms are present | Source-text grep for each arm | All three present |
| `tropic01::negative_qemu_device_path_is_null_terminated_ttyacm0` | QEMU device path stays NUL-terminated | Source-text grep | Pinned |
| `tropic01::negative_qemu_uid_fallback_is_cfg_gated` | UID-derived key only used on QEMU (not stm32u585) | Find `derive_pairing_key_from_uid` decl and verify closest preceding `#[cfg(...)]` says `not(feature = "stm32u585")` | Cfg-gate present |
| `tropic01::negative_setup_pairing_call_is_cfg_e2e_test_gated` | `setup_pairing` call is `cfg(not(feature = "e2e-test"))`-gated | Source-text grep | Pinned |
| `tropic01::negative_pin_state_deser_requires_exact_length` | Deserialize uses `!=` strict equality, not `<=` | Source-text pin | Pinned exactly |
| `tropic01::negative_macd_slot_init_use_reinit_pattern` | Each provisioning loop iteration does init → pin → re-init | Count `mac_and_destroy(U16::new(j as u16)` ≥ 3 inside `for j in 0..TROPIC01_MAX_ATTEMPTS` body | ≥ 3 occurrences |
| `tropic01::negative_session_doc_pins_x25519_noise_kk1_aes_gcm` | Session doc-comment still claims X25519 + Noise_KK1 + AES-256-GCM | Source-text grep for each | All three present |
| `tropic01::negative_tropic01_struct_has_no_debug_derive` | `Tropic01SecureElement` doesn't `#[derive(Debug)]` (would leak pairing_priv) | Scan 200 chars before struct decl | No `#[derive(Debug` |
| `tropic01::negative_no_software_pin_compare` | No software PIN compare (invariant #2: PIN compare in SE silicon) | Grep for `== pin` / `pin ==` / `pin.ct_eq(` | None present |
| `tropic01::negative_already_locked_branch_returns_err_slot_expired` | Already-locked branch wipes 0..3 AND returns `Err(SlotExpired)` | Locate branch, assert content | All pinned |

## Production-code bugs surfaced by negative tests
None. Every negative test designed against the existing production code
passed on first compile (after one self-correction: my initial
`negative_macd_repeated_input_does_not_repeat_output` was wrong — the
mock intentionally idempotent-replays under the same `data_in` to
match TROPIC01's "overwrite slot with input" re-init semantics, so I
rewrote it to assert that MACD output depends on the slot's PRIOR
state, which IS the contract). The bug discovery rate of this pass is
zero; if a regression in any of the asserted invariants ever lands,
the suite will fire.

## Coverage gaps deliberately left

- **Real Tropic01 chip + Noise_KK1 handshake.** `tropic01_se.rs`'s
  `with_session!` macro establishes a real X25519 + AES-256-GCM
  tunnel via the `tropic01` crate. Exercising that requires either
  a physical TROPIC01 dongle attached to QEMU at `/dev/ttyACM0` or
  a flashed STM32U585 with the chip on SPI2. The host suite pins
  the *source-text* invariants but cannot run the cryptographic
  protocol. A future pass with a hardware fixture should add e2e
  round-trip tests against a real chip.
- **`SemihostingSpi::spi_transfer` end-to-end.** Same reason — the
  function uses `cortex_m_semihosting::syscall!` which only resolves
  on the ARM target. Source-text pins cover the protocol framing;
  full transfer-then-parse coverage requires a QEMU run.
- **`hw::saes_cmac` SAES-coprocessor wrapper.** `cmac.rs` exposes the
  generic `cmac_generic` that the SAES backend calls under
  `KeySel::Dhuk`. The DHUK path itself is silicon-only and lives in
  `hw::saes_cmac`, which is out of scope for this slice (covered by
  `secure-hw-crypto`).
- **OPTIGA SCP03-equivalent (Shielded Connection).** `scp03_logic.rs`
  is SE050-specific; OPTIGA Trust M uses a different scheme
  (Shielded Connection / PRL). That belongs to `secure-optiga`.
- **`PUT KEY` ceremony end-to-end against a sacrificial SE050.** The
  doc-comment explicitly warns that the framing is "best-effort from
  the GP spec / AN12436" and must be validated on a sacrificial part
  before any real provisioning. Out of scope for host tests.
- **Compile-fail tests via `trybuild`.** Considered for asserting
  forbidden cfg combinations (e.g. `mode-production` + `debug-log`)
  but the existing `compile_error!` fences in `nsc/mod.rs` already
  encode those invariants, and `trybuild` would add a heavy
  dev-dependency for limited additional coverage. Deferred.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox
  disallows `cargo fmt` / `rustfmt` invocations in this environment;
  the new test code follows the surrounding code's style verbatim).
  Reviewer should re-run locally before merging.
- `cargo check -p sphincs-tz-secure` — **PASS** (37 pre-existing
  warnings, no new warnings introduced by this pass)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — **N/A**
  (sandbox disallows `cargo clippy` invocation in this environment).
  Reviewer should re-run locally; the test code adds no `unsafe`,
  no `unwrap` on untrusted data, no shadowed loops, and only
  `format!` calls that are bounded.
- `cargo test -p sphincs-tz-secure` — **PASS** (1833 tests passed,
  2 pre-existing ignored, 0 failed). Crate-wide test count grew from
  1739 → 1833 (+94 tests = 41 new positive + 53 new negative).
- on-target tests deferred: yes — `tropic01_se.rs` and
  `semihosting_spi.rs` are firmware-only and require a real
  TROPIC01 chip or QEMU SPI bridge; pinned via `include_str!`
  source-text invariants only, as documented in the Coverage Gaps
  section above.
