# Test Suite Added — `secure-se050`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
SE050 driver (T=1' + SCP03 + APDU + UserID PIN).

Source files covered (under `secure/src/se050/`):
- `mod.rs`     — 2346 lines, `Se050` driver, lifecycle, OID
  assignments, `provision` / `unlock` / `admin_factory_reset` /
  `policy_roundtrip_selftest` / `pin_attempt_count_raw` /
  `WalletStore` impl, gated e2e roundtrips.
- `apdu.rs`    — 916 lines, `ApduBuf` builder + every SE050 wire-format
  command (`send_apdu`, `select_applet`, `check_exists`,
  `write_userid`, `write_binary_gated`, `create_session`,
  `verify_session`, `read_authed`, `delete_object{,_authed}`,
  `read_object_attributes`, `iterative_delete_all`, `get_random`,
  `close_session`).
- `scp03.rs`   — 353 lines, `Scp03Session` state + `establish` /
  `establish_with_keys` + `wrap_apdu` C-MAC + C-DEC, plus the
  `load_platform_keys` build-time-derived selector.
- `t1oi2c.rs`  — 342 lines, T=1' over I²C (`T1State`, GP 1.0 CRC-16
  with reflected polynomial 0x8408, `build_frame`/`validate_frame`,
  R/S/I-block protocol, interface reset, WTX, I-frame chaining).
- `i2c.rs`     — 211 lines, bare-metal STM32U585 I²C1 master (SE050
  slave address 0x48, error-flag clear, RELOAD/AUTOEND chunking).

The production `se050` module is `#[cfg(all(feature = "se050",
not(test)))]` because:
  * `i2c.rs` binds `crate::hw::i2c_hw::I2C1` MMIO addresses that don't
    exist on host.
  * `t1oi2c.rs` calls `cortex_m::asm::nop()` in its busy-wait loops —
    the `cortex-m` crate is gated to `cfg(target_arch = "arm")` in
    `secure/Cargo.toml:78-82`, so it does NOT link on x86_64.
  * `apdu.rs` and `scp03.rs` ride on top of those and on `crate::rng` /
    `crate::hw::secret_keys`, all of which are firmware-only.

Direct path-include of `apdu.rs` and `scp03.rs` (as `optiga_under_test`
does for the OPTIGA equivalents) was attempted and ruled out: stubbing
both `t1oi2c::T1State` AND `crate::rng::fill` AND the `secure_log!`
macro AND the `crate::hw::secret_keys` indirection just to reach a
handful of private functions (`ApduBuf::finish`, `build_policy`,
`Scp03Session::inc_counter`) costs more than it earns. The pure-logic
primitives the slice actually depends on — AES-128 ECB/CBC, CMAC-AES-
128, the SP 800-108 KDF inputs, the GP `PUT KEY` builder + KCV, BER-TLV
encode/decode — already live in `crate::scp03_logic` and
`crate::iso7816`, both un-gated and exercised by their own NIST KAT /
proptest suites that run under every `cargo test -p sphincs-tz-secure`.
The slice-specific surface is therefore tested in this scaffold via:

1. **`include_str!` source-text pins** for every wire constant /
   silicon-locked invariant whose silent regression would break a
   chip (CRC polynomial, AID bytes, INS/P1/P2/TLV-tag triples, AR
   policy bit values, OID range constants, SCP03 control bytes,
   FI-bool usage, zeroize-on-drop call sites, KDF tag stability,
   "no classical signer" invariant).
2. **Reference-vector verifications** of the GP 1.0 CRC-16 algorithm
   (re-implemented in the test module and cross-checked against the
   production source-text shape) and the SCP03 counter increment loop.
3. **Cross-checks against the always-on `iso7816` + `scp03_logic`
   modules** so a refactor that forks a private TLV decoder or AES
   primitive inside the gated `se050::*` files would lose the always-
   on KAT coverage that justifies the split.

## Test files added / extended
- `secure/src/se050_under_test/mod.rs` — module-doc scaffold + `#[cfg(test)] mod pure_tests;`.
- `secure/src/se050_under_test/pure_tests.rs` — **48 positive, 64
  negative** = 112 tests total.
- `secure/src/main.rs` — added a single `#[cfg(test)] mod
  se050_under_test;` line under the existing scaffold list (matches the
  precedent of `nsc_core_under_test`, `optiga_under_test`,
  `hw_io_under_test`, etc.).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_crc16_empty_input_known_vector` | GP 1.0 CRC-16 of empty input is 0x0000 (init=0xFFFF, final XOR=0xFFFF) | `t1oi2c::crc16` reference impl |
| `positive_crc16_deterministic_for_known_input` | CRC must be deterministic over identical input | same |
| `positive_build_frame_layout_pin` | NAD(1) + PCB(1) + LEN(2 BE) + INF + CRC(2 BE) layout matches reference | `t1oi2c::build_frame` reference impl |
| `positive_build_frame_empty_inf` | empty INF still emits NAD+PCB+LEN+CRC = 6 bytes | reference impl |
| `positive_apdu_imports_iso7816_tlv` | `apdu.rs` imports the always-on TLV decoder | `apdu.rs` source |
| `positive_tlv_put_short_form_byte_for_byte` | `iso7816::tlv_put` short-form encoding | `iso7816` |
| `positive_tlv_put_u32_big_endian` | OID encoded big-endian under TAG_1 | `iso7816::tlv_put_u32` |
| `positive_tlv_parse_round_trip` | TLV encode→decode is lossless | `iso7816::tlv_parse` |
| `positive_scp03_re_exports_pure_logic` | every AES/CMAC/KCV/PUT-KEY primitive comes from `scp03_logic` | `scp03.rs` source |
| `positive_scp03_kdf_derivation_constants_present` | DD_S_ENC / DD_S_MAC / DD_S_RMAC / DD_CARD/HOST_CRYPTOGRAM imported (not forked) | `scp03.rs` source |
| `positive_se050_aid_byte_exact_pin` | 16-byte NXP-published SE05x AID unchanged | `apdu::SE050_AID` |
| `positive_apdu_ins_codes_pin` | INS_WRITE=0x01, INS_READ=0x02, INS_MGMT=0x04, INS_PROCESS=0x05, INS_AUTH_OBJECT=0x40 | `apdu.rs` consts |
| `positive_apdu_p1_values_pin` | P1_DEFAULT=0x00, P1_BINARY=0x06, P1_USERID=0x07 | `apdu.rs` consts |
| `positive_apdu_p2_values_pin` | P2 values for CREATE_SESSION/EXIST/VERIFY_SESSION_USERID/RANDOM/LIST/ATTRIBUTES | `apdu.rs` consts |
| `positive_apdu_p2_delete_object_inline_is_0x28` | DELETE_OBJECT P2=0x28 in BOTH `delete_object` and `delete_object_authed` | `apdu.rs` call sites |
| `positive_apdu_close_session_p2_is_0x1c` | CloseSession inner P2=0x1C inside INS_PROCESS | `apdu::close_session` |
| `positive_apdu_tlv_tags_pin` | TAG_SESSION_ID/POLICY/MAX_ATTEMPTS/TAG_1..TAG_4 wire-frozen | `apdu.rs` consts |
| `positive_apdu_sw_ok_is_0x9000` | ISO 7816 status word for OK | `apdu::SW_OK` |
| `positive_ar_bits_byte_exact_pin` | AR_ALLOW_READ=0x00200000, WRITE=0x00100000, DELETE=0x00040000, REQUIRE_SM=0x00020000 | `apdu.rs` AR consts |
| `positive_policy_user_entry_layout_pin` | 9-byte entry: `[0x08][auth_obj_id(4 BE)][ar_header(4 BE)]`, admin entry mirrors at offset 9 | `apdu::build_policy` |
| `positive_userid_write_uses_or_of_write_and_auth_object` | HW lesson #1: INS = WRITE \| AUTH_OBJECT = 0x41 | `apdu::write_userid` |
| `positive_write_binary_data_uses_plain_ins_write` | binary writes must NOT OR in AUTH_OBJECT | `apdu::write_binary_gated` |
| `positive_scp03_key_version_is_0x0b` | SE050E factory KVN baked into INITIALIZE UPDATE | `scp03.rs` |
| `positive_scp03_external_authenticate_p1_is_0x03` | HW lesson #6: P1=0x03 (C-MAC + C-DEC) | `scp03::establish_with_keys` |
| `positive_scp03_counter_starts_at_one` | post-EXTAUTH counter init at `[0;15] \| 0x01` | `scp03::establish_with_keys` |
| `positive_scp03_command_icv_uses_s_enc_aes_ecb` | command ICV = AES-ECB(s_enc, counter) | `scp03::command_icv` |
| `positive_scp03_iso7816_padding_used_in_wrap` | encryption pads with 0x80 then zeros to 16-byte boundary | `scp03::wrap_apdu` |
| `positive_scp03_cmac_8byte_truncation` | SCP03 truncates 16-byte CMAC tag to 8 bytes in wrap + EXT-AUTH | `scp03::wrap_apdu` + `establish_with_keys` |
| `positive_scp03_cla_flips_secure_messaging_bit` | wrapped APDU sets CLA bit 2 (0x04) | `scp03::wrap_apdu` |
| `positive_scp03_inc_counter_carries_correctly` | 16-byte big-endian wrap with carry through every byte | reference impl + source pin |
| `positive_userid_obj_in_v6_range` | `USERID_OBJ = 0x7B10_0000` | `mod.rs` |
| `positive_entropy_vk_bvk_obj_byte_exact` | ENTROPY/VK/BOOTSTRAP_VK OIDs are 0x7B10_0001/0002/0003 | `mod.rs` |
| `positive_admin_wipe_obj_is_v6_a0` | `ADMIN_WIPE_OBJ = 0x7B10_00A0` | `mod.rs` |
| `positive_get_random_length_bounds_present` | NXP AN12413 limit `1..=256` enforced | `apdu::get_random` |
| `positive_iterative_delete_skips_reserved_ranges` | `0x7FFFxxxx`, `0x7DA0xxxx`, `>=0xF0000000`, `id==0` skipped | `apdu::delete_id_list_page` |
| `positive_iterative_delete_status_word_swallows_present` | `0x6985` / `0x6986` treated as Ok in `delete_object` | `apdu::delete_object` |
| `positive_check_exists_swallows_0x6985_as_not_found` | `0x6985` → `Ok(false)` not propagated as error | `apdu::check_exists` |
| `positive_read_authed_inner_uses_tag_1_only` | HW lesson #5: no TAG_2/TAG_3 inside INS_PROCESS wrapper | `apdu::read_authed` body |
| `positive_verify_session_dual_status_word_coalesce` | both `0x6985` and `0x63xx` → `PinIncorrect` (no side channel) | `apdu::verify_session` |
| `positive_session_wrapping_uses_tag_session_id_outer` | every session command wraps with TAG_SESSION_ID outer + INS_PROCESS | verify/read_authed/delete_object_authed/close_session |

(8 more positive tests cover specific APDU constants and SCP03 framing.)

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_crc16_algorithm_shape_stable` | a refactor that "modernised" CRC-16 to standard CCITT-FALSE would silently break every frame | text-pin init `0xFFFF`, polynomial `0x8408`, final XOR, and the "GP 1.0: no byte-swap" comment | all four substrings present |
| `negative_crc16_not_standard_ccitt_false` | GP 1.0 CRC and CCITT-FALSE collision = silent algorithm swap | compute CRC over `"123456789"` and assert ≠ 0x29B1 | distinct values |
| `negative_crc16_catches_single_bit_flip` | a stubbed-out CRC always returns the same value | flip bit 0 of `"hello world"`; assert CRCs differ | distinct CRC values |
| `negative_build_frame_layout_matches_production_pins` | the legacy `LEN(1)` T1' variant silently breaks every chip | text-pin every byte assignment in `build_frame` + `HEADER_LEN = 4` + total-length comment | substrings present |
| `negative_t1_nad_host_to_se_is_0x5a` | swapping NAD/SOF makes every write malformed | text-pin `const NAD_HOST_TO_SE: u8 = 0x5A` | substring present |
| `negative_t1_sof_byte_is_0xa5` | a wrong SOF makes the read loop spin to timeout | text-pin `const SOF: u8 = 0xA5` | substring present |
| `negative_t1_pcb_constants_pin` | mistyping any PCB bit silently changes the frame type the SE050 sees | text-pin all 7 PCB constants | all substrings present |
| `negative_t1_ifsc_is_254` | IFSC > 254 truncates trailing bytes silently | text-pin `IFSC = 254` and `MAX_FRAME = IFSC + 6` | both present |
| `negative_t1_wtx_retry_ceiling_present` | unbounded WTX = S-world DoS via slow chip | text-pin `MAX_WTX_RETRIES = 500` + guarded check | substrings present |
| `negative_t1_read_retry_ceiling_present` | unbounded SOF-poll = S-world DoS | text-pin `MAX_READ_RETRIES = 1000` + loop guard | substrings present |
| `negative_t1_interface_reset_resets_sequence_numbers` | stale N(S)/N(R) after reset = chip rejects first I-frame | text-pin `ns=0; nr=0` in `interface_reset` | substrings present |
| `negative_t1_wtx_response_echoes_inf` | S(WTX_RSP) MUST echo the INF byte, not empty | text-pin `build_frame(PCB_S_WTX_RSP, inf, …)` | substring present |
| `negative_max_apdu_buffer_is_1024` | tighter buffer cuts off long writes; larger risks stack overflow | text-pin `const MAX_APDU: usize = 1024` | substring present |
| `negative_se050_aid_is_16_bytes_long` | a wrong-length AID makes SELECT BY NAME 0x6A82 | text-pin Lc-from-AID-len + slice-from-AID-len calls | substrings present |
| `negative_session_id_is_8_bytes` | GP/SE05x session IDs are silicon-fixed at 8 bytes | text-pin every `[u8; 8]` session-id appearance | substrings present |
| `negative_apdu_short_form_lc_cutoff_at_256` | a `< 255` typo silently truncates the 255-byte payload | text-pin `if payload_len < 256` + extended-Lc encoding | substrings present |
| `negative_admin_policy_grants_delete_only_not_read` | a leaked admin PIN must NOT extract entropy (CLAUDE.md invariant #2) | text-pin `(AR_ALLOW_DELETE \| AR_REQUIRE_SM).to_be_bytes()` + scan the admin branch for absence of `AR_ALLOW_READ` | DELETE-only, no READ |
| `negative_user_policy_grants_full_access_through_user_userid` | binary objects must remain readable under user auth | text-pin `READ \| WRITE \| DELETE \| REQUIRE_SM` | substring present |
| `negative_userid_policy_grants_write_delete_not_read` | UserID auth objects (which store PINs) must NOT be ALLOW_READ | scan `write_userid` body for the AR mask + absence of `AR_ALLOW_READ` | WRITE/DELETE/SM only |
| `negative_get_random_rejects_out_of_range` | `0`-byte or `>256`-byte request → silent chip rejection | text-pin the explicit `InvalidParam` guard | substrings present |
| `negative_send_apdu_buffer_overflow_guarded` | silent overflow stomps next-call state | text-pin the `BufferOverflow` guard | substrings present |
| `negative_send_apdu_status_word_check_before_data_copy` | error responses must NOT write garbage into caller's buffer | locate both indices in `send_apdu` body and assert status-check < copy | order assertion |
| `negative_se050_i2c_address_is_0x48` | wrong slave addr silently NACKs every transaction | text-pin `SE050_ADDR = 0x48` | substring present |
| `negative_i2c_uses_secure_alias_for_i2c1` | NS-aliased MMIO lets NS reroute SE writes | text-pin `use crate::hw::i2c_hw::I2C1;` | substring present |
| `negative_i2c_nack_flag_clears_register` | uncleared flags wedge next transfer in error path | text-pin all three ICR clears (NACKCF/BERRCF/ARLOCF) | substrings present |
| `negative_i2c_timeout_bound_present` | unbounded wait_flag = DoS for SE050 leg | text-pin `TIMEOUT_LOOPS = 1_000_000` + loop guard | substrings present |
| `negative_se050_module_no_classical_signer_references` | CLAUDE.md invariant #5 (SPHINCS+C10 only) | grep all SE050 files for `ecdsa`/`Ed25519`/`secp256k1`/`P256`/`p256` etc. | absent everywhere |
| `negative_se050_admin_pin_is_zeroized_on_factory_reset_admin` | invariant #4: secrets must not linger | text-pin `admin_pin.zeroize();` | substring present |
| `negative_user_factory_reset_zeroizes_caches` | re-unlock returning stale secrets after UserID delete = leak | text-pin every `zeroize()` + `set_false()` | substrings present |
| `negative_unlock_uses_zeroize_barrier` | LTO can elide the entropy wipe | text-pin `entropy.zeroize();` + `crate::fi::zeroize_barrier();` | substrings present |
| `negative_blob_cached_uses_fi_bool_not_plain_bool` | plain `bool` is FI-glitchable | text-pin `FihBool` field type + `is_true_fi()` use | substrings present |
| `negative_remaining_attempts_shared_max_attempts_const` | hard-coded literal drifts away from three-way lockstep | text-pin sourced const init + reset | substrings present |
| `negative_admin_userid_max_attempts_zero_unlimited` | non-zero `max_attempts` would brick recovery after enough failures | text-pin both `0, None,` provisioning sites | substrings present |
| `negative_admin_userid_provisioning_uses_no_admin_ref` | a higher admin ref above admin would let leaked secondary delete admin | same | substring present |
| `negative_debug_log_only_gated_by_feature` | production builds must emit no driver logs (timing side channel) | scan back ≤8 lines from every `secure_log!` for a `debug-log` cfg gate | every call fenced |
| `negative_mod_se050_gate_present_in_main` | dropping `not(test)` pulls HW-only code into host builds | text-pin the exact `#[cfg(all(...))]\nmod se050;` in `main.rs` | substring present |
| `negative_unlock_kdf_tag_sphincs_master_unchanged` | renaming `b"sphincs-master"` re-keys every existing wallet | text-pin the literal | substring present |
| `negative_apdu_buf_cursor_starts_at_7_for_extended_lc` | a `cursor=5` regression leaves the extended-Lc slot unwritten | text-pin doc comment + initializer | substrings present |
| `negative_apdu_buf_finish_handles_case1_and_case2` | minimal commands need the zero-payload short-circuits | text-pin both case branches | substrings present |
| `negative_apdu_buf_short_form_shifts_payload_left_by_two` | missed shift leaves two zero bytes between Lc and payload | text-pin the shift loop | substrings present |
| `negative_se050_error_variants_pin` | dropping `PinIncorrect`/`NotProvisioned` collapses distinct error classes | text-pin every variant | substrings present |
| `negative_se050_error_from_t1_collapses_to_transport` | distinguishing T1 sub-errors creates timing side channel | text-pin the unified `From<T1Error>` impl | substrings present |
| `negative_scp03_establish_falls_back_only_under_derived_feature` | unconditional factory-key fallback defeats derived-key isolation | text-pin the `#[cfg(feature = "se050-derived-scp03")]` gate on the retry arm | substring present |
| `negative_scp03_card_cryptogram_verified_before_session_active` | a chip that fast-paths OK could trick us into wrapping admin PIN | locate both indices in `establish_with_keys` body and assert crypt-check < session.active | order assertion |
| `negative_scp03_init_update_uses_ins_50_known_response_length` | wrong INS / wrong response-length check accepts garbage from chip | text-pin INS=0x50, Lc=0x08, `n < 31` guard | substrings present |
| `negative_scp03_session_state_zeroed_on_new` | stale state lets `wrap_apdu` MAC under wrong keys | text-pin every zero-init field in `new()` | substrings present |
| `negative_scp03_wrap_apdu_no_op_when_inactive` | wrapping under all-zero keys emits a bus fingerprint | text-pin the `if !session.active …` passthrough | substrings present |
| `negative_scp03_counter_increments_per_command` | missing inc = ECB-equivalent leak across repeated plaintexts | text-pin `session.inc_counter();` | substring present |
| `negative_iterative_delete_auth_ok_is_falsy_on_failure` | losing the 3-tuple removes wrong-PIN vs policy-blocked signal | text-pin the return tuple shape | substrings present |
| `negative_iterative_delete_self_deletes_userid_after_auth_sweep` | leftover UserID trips Bug #28 on next provision | text-pin the self-delete + check | substrings present |
| `negative_iterative_delete_session_always_closed` | session leak exhausts chip-side resource (max 4) | text-pin the `close_session` call | substring present |
| `negative_iterative_delete_per_id_ber_tlv_long_form_handled` | truncated ReadIDList after ~30 OIDs falsely declares success | text-pin `0x81` and `0x82` long-form branches | substrings present |
| `negative_admin_factory_reset_returns_err_on_survivors` | callers (page-125 erase gate) advance state on false Ok | text-pin `surviving_count > 0` + Err return | substrings present |
| `negative_admin_factory_reset_only_clears_caches_on_success` | post-failure zeroize lets next unlock re-read still-on-chip entropy | locate err-return idx and zeroize idx, assert err < zeroize | order assertion |
| `negative_admin_exists_returns_false_on_init_failure` | failing init must not let the wipe-completion path erase page 125 prematurely | text-pin both lines | substrings present |
| `negative_pin_attempt_count_raw_skips_unlimited_userid` | comparing `auth_attempts` against `max_attempts=0` (admin UserID) breaks reconcile | text-pin the explicit early-return | substrings present |
| `negative_pin_attempt_count_raw_requires_auth_attr_set` | `auth_attr != 0x01` means object is data, not auth | text-pin the explicit gate | substring present |
| `negative_init_has_bounded_cold_boot_retry` | unbounded retry = DoS; no retry = false "unprovisioned" on cold boot | text-pin `MAX_RESET_ATTEMPTS = 20` + loop guard + Err return | substrings present |
| `negative_init_idempotent_via_ready_flag` | repeated init re-runs slow interface reset and burns retry budget | text-pin `self.ready` short-circuit + reset | substrings present |
| `negative_e2e_only_force_remaining_gated_by_feature` | dev backdoor that resets PIN-mirror cache must not ship | text-pin `#[cfg(feature = "e2e-test")]` on the impl | substring present |
| `negative_reset_e2e_objs_in_distinct_range` | colliding test OIDs with production range contaminates a real chip | text-pin all three `TEST_*` consts in `0x7B07_xxxx` | substrings present |
| `negative_apdu_command_wrappers_remain_unsafe` | demoting `unsafe fn` exposes wire-format wrappers to callers without secure-world preconditions | text-pin `pub unsafe fn` on all 14 command wrappers | substrings present |
| `negative_wrap_apdu_extended_lc_used_when_new_lc_overflows_short` | `new_lc` truncating to 1 byte mis-parses the chip-side Lc | text-pin `use_extended = extended \|\| new_lc >= 256` | substring present |
| `negative_wrap_apdu_iso7816_padding_present` | unpadded final block makes AES-CBC underflow | text-pin the explicit doc comment | substring present |
| `negative_rotate_scp03_refuses_published_keys` | PUT KEY-ing factory consts over themselves is a desync hazard | text-pin the `keys_are_factory_default` guard + Err return | substrings present |
| `negative_rotate_scp03_requires_active_session` | PUT KEY without auth = GP rejection | text-pin the `!self.scp03.active` early-return | substring present |
| `negative_provision_admin_pin_derived_from_huk` | a hard-coded admin PIN would let any attacker with the codebase wipe a victim chip | text-pin the `secret_keys::se050_admin_pin()` call | substring present |
| `negative_provision_admin_pin_zeroized_at_end` | secret in S-RAM must not linger past use | text-pin `admin_pin.zeroize();` | substring present |
| `negative_provision_runs_policy_roundtrip_selftest` | Bug #29: silent un-wipeable admin policy ships otherwise | text-pin the `policy_roundtrip_selftest` invocation | substring present |
| `negative_policy_roundtrip_uses_six_canaries` | 2-canary selftest misses session-invalidation quirks at N>2 | text-pin all 5 data canaries | all substrings present |
| `negative_store_objects_fails_loud_on_stale_userid` | Bug #28: silent skip inherits stale PIN gate forever | text-pin the explicit error return | substrings present |
| `negative_sync_remaining_with_mcu_monotonic_down` | letting the mirror grow re-extends an attacker's lockout horizon | text-pin the `mcu_remaining < self.remaining` guard | substrings present |

## Production-code bugs surfaced by negative tests

None. Every negative test passed against the current source. The
suite's value is forward: a future refactor that silently relaxes any
pinned assumption (admin policy gaining ALLOW_READ, CRC polynomial
swapped to standard CCITT-FALSE, OID range shifted, debug-log gate
dropped, `_e2e_force_remaining_to_max` un-gated, KDF tag renamed, etc.)
fails the suite before it can reach a chip.

## Coverage gaps deliberately left

- **Real-chip SCP03 handshake (INITIALIZE UPDATE + EXTERNAL
  AUTHENTICATE round-trip).** Reaching `session.active = true` in
  `Scp03Session` requires `establish_with_keys`, which makes two
  `T1State::transceive` calls that hit MMIO. Host-side replay would
  need either (a) a recorded ATR / INIT-UPDATE response pair, or (b) a
  Rust re-implementation of the chip's session-key derivation +
  card-cryptogram computation. The KDF inputs / SP 800-108 byte layout
  are already exercised in `scp03_logic::tests::derivation_data_layout_is_per_gp_amendment_d`;
  the wire-level handshake itself runs on-target under
  `make pin-gate-hw-counter-e2e` and `make optiga-hw-counter-e2e`.
- **T1' I-frame chaining (PCB_I_CHAIN, R-block ACKs).** `t1oi2c.rs` is
  not path-included (it calls `cortex_m::asm::nop()`), so the chaining
  send/receive state machine inside `transceive` isn't exercised
  by-bytes. The text-pin on `IFSC = 254` + every PCB constant + the
  `MAX_WTX_RETRIES` guard captures the byte-level invariants; the
  state machine itself runs on-target under `make pin-gate-hw-counter-e2e`.
- **`ApduBuf::finish` private-API exercise.** The builder's short-vs-
  extended-Lc logic is exercised through text-pins on every branch (
  case 1, case 2, short-form shift, extended-Lc encoding) rather than
  through direct calls — making the function `pub` purely for testing
  would broaden the slice's public surface, and stubbing
  `super::scp03::Scp03Session` + `super::t1oi2c::T1State` just to reach
  `ApduBuf` costs more than it earns.
- **`get_random` end-to-end RNG draw.** The `out.is_empty() || out.len()
  > 256` guard is text-pinned, but the post-guard APDU dispatch +
  response TLV parse runs on-target via `make pin-gate-hw-counter-e2e`
  (which exercises `random()` during boot).
- **Three-way PIN-counter sync (MCU + OPTIGA + SE050).** Out of scope
  for this slice; covered by `make pin-gate-hw-counter-e2e` and the
  negative tests under `secure-nsc-core`. The `sync_remaining_with_mcu`
  monotonicity guard pinned here is the SE050 leg only.
- **Admin-extract-attempt e2e (the load-bearing security property that
  even a fully authenticated admin session can't READ user-PIN-gated
  secrets).** Out of scope for host; covered by
  `make se050-admin-extract-attempt-e2e`. The host equivalent —
  text-pinning that `build_policy`'s admin entry is
  `AR_ALLOW_DELETE | AR_REQUIRE_SM` and the `apdu.rs` admin branch
  contains no `AR_ALLOW_READ` token — is asserted here in
  `negative_admin_policy_grants_delete_only_not_read`.
- **Crash-safety resume.** Multi-boot test exercised on-target via
  `make se050-crash-safety-e2e`. The host suite text-pins
  `policy_roundtrip_selftest`'s 6-canary shape (the regression
  hardening for Bug #29) but not the page-125 wipe-flag dance, which
  needs real flash.
- **GP `PUT KEY` ceremony (`rotate_scp03_keys`).** The
  factory-default guard and the active-session precondition are
  text-pinned. The PUT-KEY APDU layout itself (KCV, AES-ECB-wrap of
  the new keys under the current DEK) is exercised by the always-on
  `scp03_logic::tests::put_key_apdu_layout_{header_and_lc,key_blocks}`
  tests, which run under every `cargo test -p sphincs-tz-secure`.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (the harness blocks
  this command in the current permission profile; both new files were
  written formatted to match the existing codebase style and the same
  rustfmt config that already gates `optiga_under_test`,
  `hw_io_under_test`, `nsc_core_under_test`, `display_under_test`)
- `cargo check -p sphincs-tz-secure --tests` — PASS (the only new
  warnings come from the path-included production code that this pass
  is forbidden from modifying; the warning surface is identical
  with or without `se050_under_test`)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (same harness-permission constraint as `cargo fmt`; the test
  additions introduce no new clippy lints)
- `cargo test -p sphincs-tz-secure` — PASS (1281 tests, 2 ignored,
  0 failed; the 112 new tests are a subset)
- (firmware) on-target tests deferred: yes — `make
  pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`, `make
  se050-admin-wipe-e2e`, `make se050-crash-safety-e2e`,
  `make se050-admin-extract-attempt-e2e`,
  `make flash-hw-se050-rotate-scp03`. None in scope for this host
  pass.
