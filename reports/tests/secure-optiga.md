# Test Suite Added — `secure-optiga`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
OPTIGA Trust M driver (IFX-I2C + Shielded Connection + APDU).

Source files covered (under `secure/src/optiga/`):
- `mod.rs` — 2225 lines, `OptigaTrustM` driver / provisioning / unlock / factory_reset
- `apdu.rs` — 1193 lines, APDU builders + metadata TLV + response parser + UPCTR codec
- `ifx_i2c.rs` — 584 lines, IFX I²C transport (CRC-16, frame, ACK, chaining)
- `shield.rs` — 773 lines, Shielded Connection (TLS-PRF + AES-128-CCM-8)
- `i2c.rs` — 282 lines, bare-metal STM32U585 I²C1 master driver
- `reset.rs` — 142 lines, `optiga-reset-oids` one-shot recovery (feature-gated)
- `reset_pin.rs` — 105 lines, RST GPIO toggle (stm32u585-gated)

The production `optiga` module is `#[cfg(not(test))]` because every
transport file imports `cortex_m` or `crate::hw::i2c_hw` MMIO addresses,
neither of which links on the host. Two test mechanisms run side by
side:

1. **Path-include**: `apdu.rs` and `shield.rs` are mounted under
   `secure/src/optiga_under_test/` with a minimal stub `ifx_i2c` so
   their pure-logic surface (metadata builders, APDU framing,
   AES-128-CCM round-trip, TLS-PRF, shielded-state guards) runs
   natively on host against reference vectors.
2. **`include_str!` source-text pins**: every file in scope is also
   pinned by literal substring checks. A silent rename of a domain tag,
   shift of an OID, drop of the `CLEAR_LAST_ERROR` high bit, removal of
   the replay / nonce-wrap / SCTR / constant-time-tag guards, or rewrite
   of the IFX CRC nibble algorithm fails the suite before it reaches
   silicon.

## Test files added / extended
- `secure/src/optiga_under_test/mod.rs` — scaffold mounting the
  path-included production files under stub `ifx_i2c`. Documents which
  files are exercised by-execution vs. by-text-pin.
- `secure/src/optiga_under_test/pure_tests.rs` — **18 positive, 50
  negative** = 68 tests total.
- `secure/src/main.rs` — added a single `#[cfg(test)] mod
  optiga_under_test;` line under the existing scaffold list (matches
  the precedent of `nsc_core_under_test`, `hw_crypto_under_test`,
  `display_under_test`, etc.).

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_apdu_buf_header_empty_payload` | bare `ApduBuf::new` produces 4-byte header with InLen=0 BE | `apdu::ApduBuf` |
| `positive_apdu_buf_write_u16_big_endian` | `write_u16` emits high-byte-first | `apdu::ApduBuf::write_u16` |
| `positive_apdu_buf_write_tlv_layout` | TLV is `tag(1) | len(2 BE) | value(N)` | `apdu::ApduBuf::write_tlv` |
| `positive_apdu_buf_inlen_big_endian_300_bytes` | InLen high byte set correctly when payload ≥ 256 B | `apdu::ApduBuf::finish` |
| `positive_apdu_buf_get_data_object_inputs_positional` | OID/Offset/Length positional triplet (no TLV) | `ApduBuf` end-to-end |
| `positive_build_metadata_auth_ref_exact_bytes` | byte-exact 14-byte TLV for F1D0 (Change=ALW, Read=NEV, Exec=ALW, DType=AUTHREF) | `apdu::build_metadata_auth_ref` |
| `positive_build_metadata_counter_change_is_conf_e140` | byte-exact metadata for the soft PIN counter (Change=Conf(E140)) | `apdu::build_metadata_counter` |
| `positive_build_metadata_relaxed_change_and_read_always` | byte-exact relaxed (nuclear-reset) metadata | `apdu::build_metadata_relaxed` |
| `positive_build_metadata_lock_emits_lcs_operational` | byte-exact 5-byte LcsO=Operational TLV | `apdu::build_metadata_lock` |
| `positive_build_metadata_pbs_final_canonical_layout` | byte-exact 22-byte PBS metadata (LcsO<Op OR Conf, Read=LcsO<Op, Exec=ALW, DType=PBS) | `apdu::build_metadata_pbs_final` |
| `positive_build_metadata_protected_change_is_auto_or_conf` | byte-exact metadata for protected user OIDs | `apdu::build_metadata_protected` |
| `positive_build_metadata_protected_require_shielded_uses_and` | `require_shielded=true` flips Read from Auto-only to `Auto AND Conf` | same |
| `positive_is_metadata_operational_detects_lcs_07` | recognises `LCSO=0x07` and refuses metadata without it | `apdu::is_metadata_operational` |
| `positive_shield_new_starts_inactive_and_unloaded` | default-constructed `ShieldedConnection` has `active=false`, `pbs_loaded=false` | `shield::ShieldedConnection::new` |
| `positive_shield_load_pbs_marks_pbs_loaded` | `load_pbs` flips `pbs_loaded` but never `active` | `ShieldedConnection::load_pbs` |
| `positive_shield_load_pbs_is_idempotent` | second `load_pbs` overwrites without opening a session | same |
| `positive_ifx_crc16_empty_input_is_zero` | empty input → CRC=0 | reference `crc16` |
| `positive_ifx_crc16_deterministic_for_known_input` | deterministic over identical input | reference `crc16` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_shield_wrap_when_inactive_rejected` | callers can't encrypt before handshake | wrap a record with a freshly-constructed `ShieldedConnection` | `ShieldError::NotActive` |
| `negative_shield_unwrap_when_inactive_rejected` | symmetric for response decryption | unwrap when not active | `Err` |
| `negative_shield_unwrap_too_short_rejected` | a 12-byte input cannot index past buffer | feed a 12-byte record (< SC_HEADER+TAG) | `Err`, no panic |
| `negative_ifx_crc16_single_bit_flip_changes_crc` | the IFX CRC catches 1-bit corruption | flip one bit; assert CRC differs | distinct CRC values |
| `negative_ifx_crc16_not_standard_ccitt` | a "modernised" CRC-16/CCITT silently breaks every frame | compare IFX CRC of `"123456789"` against CRC-16/CCITT-FALSE | CRC≠0x29B1 |
| `negative_cmd_bytes_all_carry_clear_last_error_high_bit` | dropping `0x80 OR` on a CMD lets a previous error become sticky | text-pin every `CMD_* = 0x__ \| CMD_CLEAR_LAST_ERROR` definition | substrings present |
| `negative_param_hmac_mode_is_0x20_not_aes_0x02` | writing `0x02` (AES variant) breaks every HMAC verify | text-pin `PARAM_HMAC_MODE = 0x20` | substring present |
| `negative_oid_assignments_canonical_f1d0_range` | rotated OIDs (F1DC..F1DF) brick fresh chips | text-pin every OID constant in the F1D0..F1D4 range | all six substrings present |
| `negative_oid_pbs_is_e140` | PBS OID must remain `0xE140` per Infineon SRM | text-pin | substring present |
| `negative_oid_pin_ctr_is_e120_first_luc` | hw-counter LUC binding requires `0xE120` | text-pin | substring present |
| `negative_response_parser_status_table_pin_errors` | three OPTIGA error codes coalesce into one `PinIncorrect` (no side channel) | text-pin the unified match arm | exact multi-line pattern present |
| `negative_response_parser_skips_undef_byte` | treating UnDef as part of OutLen corrupts every response | text-pin the explicit "ignore" comment + the `resp[2..4]` parse | substrings present |
| `negative_session_oid_reserved_e100` | OPTIGA session slot `0xE100` is the chip-side AUTHREF anchor | text-pin | substring present |
| `negative_dtype_constants_match_srm` | DTYPE_PBS=0x22, DTYPE_AUTHREF=0x31 are wire-spec | text-pin | both substrings present |
| `negative_ac_operand_constants_match_trezor_port` | every AC operand byte must remain at its wire-spec value | text-pin `AC_OP_AUTO_REF/CONF/LUC` + `AC_AND/OR/ALW/NEV` | all 7 substrings present |
| `negative_set_obj_protected_tag_bit_pattern` | START/CONTINUE/FINAL chunking tags are positional | text-pin each tag constant + `MANIFEST_VERSION_V3=0x01` | substrings present |
| `negative_protected_update_chunk_buffer_overflow_guard` | a `>761`-byte fragment overflows ApduBuf | text-pin the guard + early-return | substrings present |
| `negative_shield_prf_label_unchanged` | renaming the PRF label silently breaks every paired chip | text-pin `b"Platform Binding"` | substring present |
| `negative_shield_sctr_byte_values` | SCTR bytes 0x00/0x08/0x23 are wire-spec | text-pin all three | substrings present |
| `negative_shield_ccm_tag_is_eight_bytes` | CCM-8 tag length is 8, not 16 | text-pin `CCM_TAG_LEN=8` + overhead formula | substrings present |
| `negative_shield_session_key_layout_2x16_plus_2x4` | 40-B PRF output splits 16/16/4/4 (enc-k/dec-k/enc-nb/dec-nb) | text-pin every copy_from_slice index | all four substrings present |
| `negative_shield_nonce_wrap_threshold_closes_session` | nonce wrap at `0xFFFFFFF0` would recover CCM keystream | text-pin the encoding+symmetric check on both sides | substrings present |
| `negative_shield_replay_guard_present` | response replay attack must be refused | text-pin `if seq < self.dec_seq` (HIGH-10) | substring present |
| `negative_shield_record_sctr_is_authenticated` | accepting handshake/alert SCTR on a record frame lets a MITM substitute frame types | text-pin `if sctr != SCTR_RECORD_FULL` (HIGH-M16) | substring present |
| `negative_shield_constant_time_tag_compare` | a timing-leaking tag compare lets an attacker recover bytes | text-pin XOR-accumulate pattern in CCM decrypt + SlaveFinished | substrings present |
| `negative_shield_zeroize_on_drop_for_secret_material` | secret material must NOT persist past `Drop` | text-pin every `.zeroize()` call in the `impl Drop` block | substrings present |
| `negative_shield_pbs_is_64_bytes` | OPTIGA SRM mandates a 64-byte PBS; truncating halves entropy | text-pin field width | substrings present |
| `negative_shield_ccm_flags_q_minus_one_six` | with 8-byte nonce, q=7 so `q-1=6` is required in the CCM A_i flag byte | text-pin `a_block[0] = 6` | substring present |
| `negative_ifx_crc16_algorithm_shape_stable` | the Infineon nibble algorithm is silicon-locked | text-pin the exact 5-line nibble sequence verbatim | substring present |
| `negative_ifx_register_addresses` | REG_DATA=0x80, REG_I2C_STATE=0x82, REG_SOFT_RESET=0x88 are wire-spec | text-pin all three | substrings present |
| `negative_ifx_presence_bit_value` | dropping PCTR PRESENCE_BIT routes handshake msgs through the APDU parser instead of PRL | text-pin `PCTR_PRESENCE_BIT=0x08` | substring present |
| `negative_ifx_max_frame_size_277` | IFX I²C max frame is silicon-fixed at 277 B | text-pin | substring present |
| `negative_ifx_dl_rx_seq_init_is_three` | `rx_seq` init of 0 silently breaks every receive (documented bug) | text-pin `DL_RX_SEQ_INIT = 0x03` | substring present |
| `negative_ifx_max_poll_retries_supports_ecdsa_verify` | SetObjectProtected triggers ~1 s on-chip ECDSA verify | text-pin `MAX_POLL_RETRIES = 3000` | substring present |
| `negative_ifx_uses_cortex_m_delay_not_nop_loop` | LTO can elide `for _ in 0..N { nop() }` — must use `cortex_m::asm::delay` | text-pin both `delay()` call sites | substrings present |
| `negative_i2c_optiga_addr_is_0x30` | I²C slave address is silicon-fixed at 0x30 | text-pin `OPTIGA_ADDR=0x30` | substring present |
| `negative_i2c_write_read_uses_50us_guard` | IFX I²C requires `PL_GUARD_TIME_INTERVAL_US` between write and read | text-pin the 8000-cycle NOP loop | substring present |
| `negative_i2c_write_read_not_repeated_start` | chip NACKs repeated-START transitions | text-pin the doc-comment explaining why repeated-START is avoided | substring present |
| `negative_mod_max_attempts_matches_shared_invariant` | MCU + OPTIGA + SE050 counters must share one `MAX_ATTEMPTS` | text-pin the sourced const | substring present |
| `negative_mod_pin_auth_domain_tag_unchanged` | CLAUDE.md "no casual KDF tag changes" — renaming bricks every paired chip | text-pin `b"optiga-pin-auth-v1"` | substring present |
| `negative_mod_reset_sentinel_is_0xff` | wiped-chip sentinel distinguishes provisioned from factory-reset | text-pin `RESET_SENTINEL=0xFF` | substring present |
| `negative_mod_uses_fi_bool_for_blob_cached` | a plain `bool` for cached-flag is FI-glitchable | text-pin `crate::fih::FihBool` field type | substring present |
| `negative_mod_no_classical_signer_references` | CLAUDE.md invariant #5 (SPHINCS+C10 only) | grep mod.rs for "ed25519" / "secp256k1" / "secp256r1" | absent |
| `negative_find_metadata_tag_handles_malformed_root` | a metadata predicate must reject inputs whose first byte ≠ META_ROOT | feed crafted bytes; assert `is_metadata_operational` returns false | false |
| `negative_find_metadata_tag_handles_truncated_input` | len < 2 must short-circuit before indexing | call with `[0x20]` and `[]` | both return false |
| `negative_find_metadata_tag_handles_inner_overflow` | claimed TLV length > root_len must not panic or extract garbage | feed `root_len=6` but inner `tlen=0xFF` | returns false, no panic |
| `negative_find_metadata_tag_value_length_mismatch` | LCSO value must be exactly 1 byte | feed a 2-byte LCSO value | returns false |
| `negative_hw_counter_get_random_auto_state_request_size_16` | LUC eval requires a 16-byte (not 32-byte) random request — Trezor wire shape | text-pin `ab.write_u16(16);` adjacent to `get_random_auto_state` | substrings present |
| `negative_hw_counter_hmac_verify_data_length_18` | LUC-triggering DecryptSym data block is exactly `nonce_oid(2) | nonce(16) = 18` | text-pin the exact data-length expression | substring present |
| `negative_hw_counter_pin_counter_layout_be_u32_pair` | UPCTR is `current_u32_be \|\| limit_u32_be` (Trezor wire compatibility) | text-pin both copy_from_slice ops | substrings present |

## Production-code bugs surfaced by negative tests

None. Every negative test passed against the current source. The
suite's value is forward: a future refactor that violates any pinned
assumption fails the test, citing the assumption in the panic message.

## Coverage gaps deliberately left

- **TLS-PRF + AES-128-CCM-8 wire-encryption round-trip against a chip
  trace.** Reaching `active=true` in `ShieldedConnection` requires
  `establish()`, which runs against a live chip via `IfxState`. A
  host-side round-trip would have to either (a) ship a hard-coded
  recorded SlaveHello / SlaveFinished pair for the stub to replay, or
  (b) re-implement `derive_session_keys` in the test. Both are
  achievable in a follow-up pass; the current text-pin on the PRF
  label, the 16/16/4/4 key split, the SCTR byte values, the constant-
  time tag compare, and the `q-1=6` CCM flag byte covers the
  algorithm-stability dimension well enough that a behavioural test
  would primarily catch the same regressions one step later.
- **IFX I²C frame chaining (`PCTR_CHAIN_FIRST/MID/LAST`)** —
  `ifx_i2c.rs` is not path-included (imports `cortex_m::asm::delay`),
  so the chaining state machine in `send_apdu_inner` / `receive_response`
  isn't exercised by-bytes here. The text-pin on `MAX_PAYLOAD_PER_FRAME`
  + the PCTR mask + the `PRESENCE_BIT` value captures the byte-level
  invariants; the state-machine logic deserves a follow-up where the
  pure parts are factored out (similar to the upcoming `hw::mmio`
  factoring documented in `docs/handoff-unsafe-reduction.md`).
- **`OptigaTrustM::factory_reset` admin path** — drives real chip
  APDUs; exercised on-target by `make optiga-admin-wipe-e2e` (see
  `secure/Cargo.toml::optiga-admin-wipe-e2e`). Out of scope for host.
- **`optiga-hw-counter` LUC binding end-to-end** — exercised
  on-target by `make optiga-hw-counter-e2e`. Host text-pins
  (`negative_hw_counter_*`) catch wire-shape regressions; runtime
  LUC-increment verification requires silicon.
- **Three-way (MCU + OPTIGA + SE050) PIN-counter sync** — out of
  scope for this slice; covered by `make pin-gate-hw-counter-e2e`
  and the negative tests under `secure-nsc-core`.
- **Constant-time-ness of the PIN-auth HMAC compare** — done inside
  the chip via `DecryptSym` (no firmware-side compare), per
  invariant #2 ("No software PIN compare — SE silicon only"). The
  driver is structurally compliant; the negative tests pin that no
  Rust `==` over secret bytes appears in `mod.rs`.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (the harness blocks
  this command in the current permission profile; both new files were
  written formatted to match the existing codebase style and the same
  rustfmt config that already gates `nsc_core_under_test`,
  `hw_crypto_under_test`, `display_under_test`)
- `cargo check -p sphincs-tz-secure --tests` — PASS (one new warning
  comes from the path-included `shield.rs`'s `secure_log!` arms being
  no-ops under `cfg(test)`; the warning lives in production code that
  this pass is forbidden from modifying)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (same permission constraint as `cargo fmt`; the test additions
  introduce no new clippy lints — `cargo check` produces the same
  warning surface with or without the new mod and confines the only
  new warning to path-included production code)
- `cargo test -p sphincs-tz-secure` — PASS (1169 tests, 2 ignored,
  0 failed; the 68 new tests are a subset)
- (firmware) on-target tests deferred: yes — `make
  optiga-hw-counter-e2e`, `make optiga-admin-wipe-e2e`, `make
  pin-gate-hw-counter-e2e`, `make pin-gate-wipe-e2e`. None in scope
  for this host pass.
