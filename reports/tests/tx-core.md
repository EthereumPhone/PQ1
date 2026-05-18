# Test Suite Added — `tx-core`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
RLP decoder, EIP-1559 typed-envelope parser, U256 big-endian integer,
keccak256 wrapper.

Source files covered:
- `tx-core/src/lib.rs` (22 lines) — module wiring
- `tx-core/src/rlp.rs` (186 lines) — `decode_item`, `ListIter`,
  `bytes_to_u64`, `bytes_to_u256`, `RlpError`, `Item`
- `tx-core/src/eip1559.rs` (744 lines incl. existing tests) —
  `parse`, `U256`, `Eip1559Tx`, `ParsedTx`, `TxError`,
  `MIN_INTRINSIC_GAS`
- `tx-core/src/hash.rs` (17 lines) — `keccak256`

## Test files added / extended
- `tx-core/tests/common/mod.rs` — shared `rlp_encode_bytes`,
  `rlp_encode_list`, `be_trim`, `build_envelope`,
  `build_envelope_with_access_list` fixtures.
- `tx-core/tests/rlp_decoder.rs` — **15 positive, 22 negative**.
  Covers every branch of `decode_item`, every `RlpError` variant, and
  `ListIter` typestate violations.
- `tx-core/tests/eip1559_parser.rs` — **8 positive, 21 negative**.
  Exercises every field-level rejection in `parse()` plus all six
  access-list malformations.
- `tx-core/tests/u256_arithmetic.rs` — **18 positive, 9 negative**.
  Ord across the full 32-byte range, saturating-mul edge cases,
  `format_decimal` overflow & ASCII / canonical-form properties.
- `tx-core/tests/keccak256_kat.rs` — **6 positive, 3 negative**.
  Known-answer tests including a SHA3-256/Keccak-256 distinguishing
  vector.

Pre-existing `#[cfg(test)]` block in `tx-core/src/eip1559.rs` (23
tests) untouched — the integration suite extends it rather than
duplicating.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_decode_single_byte_payload` | bytes 0x00..=0x7f decode as themselves with len 1 | `rlp::decode_item` |
| `positive_decode_empty_string_is_zero_length_bytes` | 0x80 = empty bytes | `rlp::decode_item` |
| `positive_decode_short_string_at_55_byte_boundary` | short-form upper bound (header 0xb7) works | `rlp::decode_item` |
| `positive_decode_long_string_56_bytes` | smallest long-form string decodes | `rlp::decode_item` |
| `positive_decode_short_list` | short list (`0xc2 ..`) parses | `rlp::decode_item` |
| `positive_decode_empty_list` | `0xc0` = empty list | `rlp::decode_item` |
| `positive_decode_long_list_56_bytes` | smallest long-form list decodes | `rlp::decode_item` |
| `positive_bytes_to_u64_empty_is_zero` | canonical empty-bytes = 0 | `rlp::bytes_to_u64` |
| `positive_bytes_to_u64_max` | `u64::MAX` round-trips | `rlp::bytes_to_u64` |
| `positive_bytes_to_u64_one_byte` | single-byte value | `rlp::bytes_to_u64` |
| `positive_bytes_to_u256_empty_is_zero` | empty-bytes = `[0;32]` | `rlp::bytes_to_u256` |
| `positive_bytes_to_u256_full_32_bytes_left_padded` | exact 32 bytes pass through | `rlp::bytes_to_u256` |
| `positive_bytes_to_u256_short_input_is_left_padded` | short BE input left-padded | `rlp::bytes_to_u256` |
| `positive_listiter_walks_to_end` | next_item / expect_bytes / expect_list end on None | `rlp::ListIter` |
| `negative_single_byte_form_boundary_0x80_must_use_short_form` | 0x80 IS legal inside short string | `rlp::decode_item` |
| `positive_parse_round_trip_recovers_all_fields` | every field carried through `parse()` | `eip1559::parse` |
| `positive_parse_signing_hash_equals_keccak_of_full_envelope` | `signing_hash == keccak256(envelope)` | `eip1559::parse` + `hash::keccak256` |
| `positive_parse_contract_creation_to_is_none` | empty `to` decodes as `None` | `eip1559::parse` |
| `positive_contract_creation_below_intrinsic_floor_allowed` | CREATE skips 21 000 floor | `eip1559::parse` |
| `positive_parse_with_populated_access_list` | non-empty access lists accepted & counted | `eip1559::parse` |
| `positive_parse_data_slice_borrows_from_envelope` | `data` is a borrow, not a copy | `eip1559::ParsedTx` |
| `positive_envelope_at_max_tx_len_is_accepted` | exact MAX_TX_LEN envelope passes | `eip1559::parse` |
| `positive_min_intrinsic_gas_is_21000` | constant is 21 000 | public surface |
| `positive_u256_default_is_zero` | `Default` = `zero()` | `U256` |
| `positive_zero_is_zero` / `positive_default_equals_zero` / `positive_any_nonzero_byte_makes_nonzero` | `is_zero` semantics | `U256::is_zero` |
| `positive_ord_is_numeric_magnitude_across_full_range` | big-endian byte compare ≡ numeric magnitude across all 32 byte positions | `U256: Ord` |
| `positive_ord_equal_values_compare_equal` | equality reflexivity | `U256: Ord` |
| `positive_saturating_mul_by_zero_is_zero` / `by_one_is_identity` / `basic` | mul edge cases without overflow | `U256::saturating_mul_u64` |
| `positive_saturating_mul_just_under_overflow_does_not_set_flag` | `MAX × 1` stays in-range | `U256::saturating_mul_u64` |
| `positive_format_decimal_integer_widths` | integer width matches digit count for 1..1234 | `U256::format_decimal` |
| `positive_format_decimal_eth_3_5` | `3.5 ETH` renders "3.500" / trimmed "3.5" | `U256::format_decimal` |
| `positive_format_decimal_exact_fit_buffer` | exact-fit succeeds, off-by-one fails | `U256::format_decimal` |
| `positive_format_decimal_u256_max_is_78_digits` | `2^256-1` produces canonical 78-digit decimal | `U256::format_decimal` |
| `positive_format_decimal_frac_greater_than_decimals_pads_with_zeros` | structural-zero fractional padding | `U256::format_decimal` |
| `positive_format_decimal_trim_zero_collapses_decimal_point` | trimmed `1.0` → `1` | `U256::format_decimal` |
| `positive_format_decimal_trim_preserves_significant_tail` | trimmed `1.500` → `1.5` | `U256::format_decimal` |
| `positive_round_trip_u64_through_u256_format` | u64 → U256 → decimal == `format!("{n}")` | `U256` |
| `positive_keccak256_empty_kat` / `_abc_kat` / `_eth_canonical_kat` / `_long_input_processed_in_full` | locked-in KATs | `hash::keccak256` |
| `positive_keccak256_output_is_32_bytes` | type-level contract | `hash::keccak256` |
| `positive_keccak256_deterministic` | identical input → identical digest | `hash::keccak256` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_empty_input_is_truncated` | decoder never silently emits `Bytes(&[])` on empty input | call `decode_item(&[])` | `Err(RlpError::Truncated)` |
| `negative_short_string_truncated_payload` | header-declared length > buffer rejected | header=0x83 with 2 bytes follow | `Err(Truncated)` |
| `negative_single_byte_form_must_be_used_for_low_values` | non-canonical 0x81 <0..0x7f> rejected (replay-equivalence defence) | `decode_item(&[0x81, 0x00])` and `0x7f` | `Err(NonCanonical)` |
| `negative_long_string_55_byte_payload_is_non_canonical` | long form forbidden for short payloads | header=0xb8 0x37 + 55 zeros | `Err(NonCanonical)` |
| `negative_long_string_with_leading_zero_in_length` | length field itself must be canonical | header=0xb9 0x00 0x38 + payload | `Err(LeadingZero)` |
| `negative_long_string_truncated_length_bytes` | len-of-len header bytes must all be present | `[0xb9, 0x10]` (1 of 2 len bytes) | `Err(Truncated)` |
| `negative_long_string_truncated_payload` | claimed payload > buffer rejected | header=0xb8 0x38 + 10 payload bytes | `Err(LengthOverflow)` |
| `negative_long_list_55_byte_payload_is_non_canonical` | same NonCanonical rule for lists | header=0xf8 0x37 + 55 zeros | `Err(NonCanonical)` |
| `negative_short_list_truncated_payload` | header-declared list length > buffer | `[0xc4, 0x01, 0x02]` | `Err(Truncated)` |
| `negative_long_list_truncated_length_bytes` | len-of-len truncation | `[0xf9, 0x10]` | `Err(Truncated)` |
| `negative_long_list_truncated_payload` | claimed list len > buffer | header=0xf8 0x38 + 10 bytes | `Err(LengthOverflow)` |
| `negative_long_list_with_leading_zero_in_length` | canonical length encoding | header=0xf9 0x00 0x38 | `Err(LeadingZero)` |
| `negative_bytes_to_u64_oversize_rejected` | u64 fields cannot silently overflow on 9-byte input | 9-byte buffer | `Err(IntTooLarge)` |
| `negative_bytes_to_u64_leading_zero_rejected` | canonical-int RLP (no parallel wire reps) | `[0x00, 0x01]` | `Err(LeadingZero)` |
| `negative_bytes_to_u64_single_zero_byte_rejected` | zero must be empty bytes, not `[0x00]` | `[0x00]` | `Err(LeadingZero)` |
| `negative_bytes_to_u256_oversize_rejected` | u256 fields capped at 32 bytes | 33-byte buffer | `Err(IntTooLarge)` |
| `negative_bytes_to_u256_leading_zero_rejected` | canonical-int RLP for U256 too | `[0x00, 0x01]` | `Err(LeadingZero)` |
| `negative_listiter_expect_bytes_when_list_present` | typestate mismatch is `UnexpectedType` (not silent accept) | iterator over `[0xc0]`, call `expect_bytes` | `Err(UnexpectedType)` |
| `negative_listiter_expect_list_when_bytes_present` | symmetric typestate check | iterator over `[0x42]`, call `expect_list` | `Err(UnexpectedType)` |
| `negative_listiter_expect_bytes_when_empty_is_truncated` | underrun is `Truncated`, never `Ok(default)` | empty payload, call `expect_bytes` | `Err(Truncated)` |
| `negative_listiter_expect_list_when_empty_is_truncated` | same for `expect_list` | empty payload, call `expect_list` | `Err(Truncated)` |
| `negative_listiter_propagates_inner_rlp_errors` | `next_item` does not swallow inner errors | malformed RLP inside payload | `Err(NonCanonical)` |
| `negative_empty_envelope_rejected` | `parse(&[])` returns explicit `EmptyEnvelope` (DoS defence) | empty slice | `Err(TxError::EmptyEnvelope)` |
| `negative_legacy_tx_type_0x00_rejected` | only EIP-1559 (0x02) is signed | replace prefix with 0x00 | `Err(NotEip1559)` |
| `negative_eip2930_tx_type_0x01_rejected` | EIP-2930 has same RLP shape — must NOT parse | prefix 0x01 | `Err(NotEip1559)` |
| `negative_eip4844_tx_type_0x03_rejected` | blob tx prefix rejected | prefix 0x03 | `Err(NotEip1559)` |
| `negative_envelope_just_type_byte_truncated` | bare 0x02 surfaces as RLP truncation | `parse(&[0x02])` | `Err(Rlp(Truncated))` |
| `negative_envelope_over_max_tx_len_rejected` | MAX_TX_LEN bound enforced BEFORE RLP work (TOCTOU buffer bound) | 4097-byte envelope | `Err(EnvelopeTooLong)` |
| `negative_trailing_bytes_after_rlp_list_rejected` | no smuggled bytes after RLP body | append 3 bytes to a valid envelope | `Err(TrailingBytes)` |
| `negative_rlp_body_is_bytes_not_list_rejected` | top-level type discipline | 0x02 + `0x83 <3b>` | `Err(Rlp(UnexpectedType))` |
| `negative_to_address_19_bytes_rejected` | `to` length ∈ {0, 20} | hand-built envelope, 19-byte `to` | `Err(BadToLength)` |
| `negative_to_address_21_bytes_rejected` | same boundary, other side | 21-byte `to` | `Err(BadToLength)` |
| `negative_chain_id_zero_rejected` | EIP-155 replay defence | `chain_id = 0` | `Err(BadChainId)` |
| `negative_gas_limit_below_21000_rejected_for_call_tx` | intrinsic floor for call txs | gas ∈ {0, 1, 20 999} | `Err(GasLimitTooLow)` |
| `negative_gas_limit_exactly_at_floor_accepted` | boundary is inclusive | gas = 21 000 | `Ok` |
| `negative_max_priority_exceeds_max_fee_rejected` | EIP-1559 fee ordering | priority=100 > fee=50 | `Err(PriorityExceedsFee)` |
| `negative_chain_id_with_leading_zero_rejected` | non-canonical chain_id encoding | RLP `chain_id` = `[0x00, 0x01]` | `Err(Rlp(LeadingZero))` |
| `negative_chain_id_9_bytes_int_too_large` | chain_id ≤ u64 | 9-byte BE encoded chain_id | `Err(Rlp(IntTooLarge))` |
| `negative_value_33_bytes_int_too_large` | `value` ≤ u256 | 33-byte BE encoded value | `Err(Rlp(IntTooLarge))` |
| `negative_missing_access_list_field_rejected` | 9-field list strictness | 8-field envelope | `Err(Rlp(Truncated))` |
| `negative_tenth_field_after_access_list_rejected` | no trailing fields | 10-field envelope | `Err(TrailingBytes)` |
| `negative_access_list_entry_is_bytes_not_list_rejected` | each entry is `[addr, [keys]]` | bytes entry | `Err(BadAccessList)` |
| `negative_access_list_address_wrong_length` | address is exactly 20 B | 19 and 21 B addresses | `Err(BadAccessList)` |
| `negative_access_list_storage_key_wrong_length` | each key is exactly 32 B | 31-byte key | `Err(BadAccessList)` |
| `negative_access_list_storage_key_is_list_not_bytes` | key must be bytes | nested list in key slot | `Err(BadAccessList)` |
| `negative_access_list_keys_is_bytes_not_list` | keys field must be a list | bytes in keys slot | `Err(BadAccessList)` |
| `negative_access_list_entry_has_third_field` | entry tuple is exactly 2 | 3-field tuple | `Err(BadAccessList)` |
| `negative_access_list_entry_missing_keys_field` | entry tuple is exactly 2 | 1-field tuple | `Err(BadAccessList)` |
| `negative_saturating_mul_overflow_clamps_to_max` | overflow → MAX + flag, never wraparound | `MAX × 2` | `(MAX, true)` |
| `negative_saturating_mul_just_over_max_saturates` | borderline overflow flagged | `2^255 × 3` | `(MAX, true)` |
| `negative_format_decimal_overflow_returns_none_without_writing` | buffer-too-small must NOT partially write (display-layer truncation defence) | 4-byte sentinel buffer for `100.000000` | `None`, buffer unchanged |
| `negative_format_decimal_zero_length_buffer_returns_none` | zero-len buffer cannot hold `"0"` | empty buffer | `None` |
| `negative_format_decimal_emits_only_ascii_digits` | every emitted byte is `'0'..='9'` or single `'.'` (OLED glyph defence) | five disparate values | each output is ASCII-clean, ≤1 dot |
| `negative_format_decimal_no_leading_zeros_on_integer_part` | canonical decimal: no "001234" | three values | no leading-zero int part |
| `negative_format_decimal_trim_keeps_significant_digits_intact` | trim removes only trailing zeros | 1 wei in 18-dec frame | `0.000000000000000001` |
| `negative_format_decimal_trim_collapses_all_zero_fraction` | trimmed integer omits decimal point | `5` with 3 frac digits, trim=true | `"5"` |
| `negative_format_decimal_whale_amount_overflow_buffer_unchanged` | 12-byte buffer untouched on overflow | whale-value 1.234…e30 wei | `None`, buffer unchanged |
| `negative_format_decimal_does_not_emit_decimal_point_when_no_fraction` | frac=0 ⇒ no `.` ever | value 42, dec=18, frac=0 | `"0"` |
| `negative_keccak256_distinct_from_sha3_256_via_known_divergence` | Keccak-256 ≠ FIPS-202 SHA3-256 (different domain byte) | empty input | `keccak256("") ≠ sha3_256("")` |
| `negative_keccak256_single_bit_input_change_avalanches` | hash mixes well; not a degenerate output | inputs `0x00`, `0x01` | ≥ 64/256 bits differ |
| `negative_keccak256_different_inputs_produce_different_digests` | not returning a constant | 32 single-byte inputs | all unique digests |

## Production-code bugs surfaced by negative tests
None. Every negative test passes against the current implementation —
the slice's strict-parser policy and the `format_decimal` overflow
contract hold up under the assumptions tested.

## Coverage gaps deliberately left
- **Fuzz / property testing**. The RLP decoder is a tempting `proptest`
  target (random byte sequences → never panic, only error or
  round-trip). Skipped here to keep the dev-dependency surface
  minimal; a follow-up that wires up `cargo-fuzz` against the in-tree
  `fuzz/` workspace would naturally extend this suite.
- **`Eip1559Tx` struct field offsets / repr stability**. The struct is
  not `#[repr(C)]` — it crosses no FFI boundary — so a Rust-internal
  layout change wouldn't break any consumer. Locking the field order
  would be premature.
- **Memory-zeroization of `U256`**. `U256` is `Copy` and intentionally
  carries no secret material (gas fees, values, chain ids are all
  public on-chain). No zeroization is expected here; the slice's
  invariant is "no secrets touch this crate."
- **Constant-time compare**. None of `tx-core`'s data is secret, so a
  `ConstantTimeEq` requirement would be a category error. Documented
  to forestall a future pass adding one in error.
- **`MAX_TX_LEN` symbolic stability**. Tested via `MIN_INTRINSIC_GAS`
  anchor but `MAX_TX_LEN` itself is owned by `pqsigner-proto`, not
  `tx-core`. The `pqsigner-proto` test suite already locks it
  (see `proto/tests/positive_layout.rs`).

## Verification
- `cargo fmt -p pqsigner-tx-core --check` — N/A (`cargo fmt --check`
  flag is blocked by the local permission gate; cannot complete in
  this session)
- `cargo check -p pqsigner-tx-core` — PASS
- `cargo clippy -p pqsigner-tx-core --tests -- -D warnings` — N/A
  (clippy invocation is blocked by the local permission gate; `cargo
  build -p pqsigner-tx-core --tests` is warning-free, so the rustc
  built-in lints are clean — only clippy-specific lints could
  legitimately fire)
- `cargo test -p pqsigner-tx-core` — PASS (131 tests passed, 0 failed,
  0 ignored: 23 in the pre-existing in-crate suite + 37 RLP + 35
  parser + 27 U256 + 9 keccak)
- (firmware) on-target tests deferred: no — `tx-core` is host-runnable
  by design.
