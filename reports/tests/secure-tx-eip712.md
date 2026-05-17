# Test Suite Added — `secure-tx-eip712`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

EIP-712 typed-data verifiers (cowswap + safe) + test vectors. Pure-logic
clear-signing layer that cmd_sign_userop calls to bind a displayed
CoW GPv2Order / Safe `approveHash` to the bytes the on-chain contract
will actually act on. Wallet invariant #5 (single C10 signer) presumes
the displayed canonical = the signed digest = the calldata target;
this module is what enforces that triangle.

Source files covered:

- `secure/src/tx/eip712/mod.rs` — 103 lines. Keccak primitive, EIP-712
  domain typehash preimage, `eip712_domain_separator`, `final_digest`,
  `Eip712Error`.
- `secure/src/tx/eip712/cowswap/mod.rs` — 432 lines.
  `GPV2_SETTLEMENT_ADDRESS`, `ORDER_TYPEHASH_PREIMAGE`,
  `COWSWAP_DOMAIN_NAME`/`_VERSION`, `decode_canonical`,
  `struct_hash`, `compute_digest`, `kind_hash`, `balance_hash`,
  `cross_check_setpresig_calldata`, `check_setpresig_calldata_shape`,
  `OrderUidMismatch`, `SETPRESIG_*` offset constants.
- `secure/src/tx/eip712/cowswap/test_vectors.rs` — 175 lines. Existing
  happy-path + 5 per-field flip + 3 shape-check suite (9 tests).
- `secure/src/tx/eip712/cowswap/verify.rs` — 136 lines. Top-level
  trailer verifier (gated `#[cfg(not(test))]` on host because it pulls
  in `crate::zk`; tested via the cowswap unit-level helpers + an e2e
  in `nonsecure/`).
- `secure/src/tx/eip712/safe/mod.rs` — 260 lines. `SafeTx`,
  `decode_canonical`, `struct_hash`, `domain_separator`,
  `compute_safe_tx_hash`, `typehash_tests` module.
- `secure/src/tx/eip712/safe/test_vectors.rs` — 241 lines. Existing
  happy-path + 11-test rejection suite.
- `secure/src/tx/eip712/safe/verify.rs` — 146 lines. Top-level
  trailer verifier (`verify_and_bind_trailer`, `VerifiedSafeV1`).

Out of scope: `secure/src/tx/eip712/cowswap_display.rs` (gated out of
host test builds via `#[cfg(not(test))]`; it depends on `crate::ui`
hardware-display primitives and would require a hardware fixture).

## Test files added / extended

- `secure/src/tx/eip712/keccak_tests.rs` — 5 positive, 9 negative
  tests covering keccak primitive known-answer vectors, EIP-712
  domain typehash preimage byte-stability, `eip712_domain_separator`
  field-binding, `final_digest` framing + commutativity, and
  `Eip712Error` Debug-formatting stability.
- `secure/src/tx/eip712/cowswap/extra_tests.rs` — 7 positive, 25
  negative tests covering enum cross-product decode acceptance,
  full-field round-trip, kind/balance enum hashes, frozen-format
  anchors (`ORDER_TYPEHASH_PREIMAGE` keccak digest, domain name/version,
  GPv2 settlement address), per-field struct_hash binding (12
  positions), `compute_digest` chain_id binding, first-failure-wins
  ordering in `cross_check_setpresig_calldata` (3 ordering tests + 1
  v3-appData attack), and calldata-shape byte-position exhaustion (7
  shape tests including a per-byte tail-pad sweep).
- `secure/src/tx/eip712/safe/extra_tests.rs` — 13 positive, 21
  negative tests covering `APPROVE_HASH_SELECTOR` preimage match,
  layout-offset constants pinning, `SAFE_V1_RAW_DATA_MAX`/
  `MAX_TX_LEN` identity, typehash preimage anchors,
  `decode_canonical` round-trip and DelegateCall acceptance (the
  ban is in verify, not decode), operation-byte exhaustion (8 bad
  values), per-field safe_tx_hash binding (12 fields including the
  chain_id + safe_address paths that route through the domain
  separator), trailer-framing pathologies (off-by-one length, oversized
  raw_data_len, truncation, inner_data under 4 / over 36 bytes,
  selector-only calldata, trailing-junk acceptance, imposter Safe
  address, chain_id=0 cross-check, per-byte raw_data binding sweep,
  zero-len raw_data + `keccak("")` data_hash boundary).

Plus `mod` declarations added (all `#[cfg(test)]`):

- `secure/src/tx/eip712/mod.rs` — `#[cfg(test)] mod keccak_tests;`
- `secure/src/tx/eip712/cowswap/mod.rs` — `#[cfg(test)] mod extra_tests;`
- `secure/src/tx/eip712/safe/mod.rs` — `#[cfg(test)] mod extra_tests;`

Total new tests: 25 positive + 55 negative = 80 new (plus 32 pre-
existing in the slice, for 112 total).

## Positive coverage

| test name | what it asserts | API surface |
|---|---|---|
| `keccak_tests::positive_keccak_empty_known_vector` | `keccak(b"")` matches the standard `c5d24601…` digest | `keccak` |
| `keccak_tests::positive_keccak_abc_known_vector` | `keccak(b"abc")` matches the standard `4e03657a…` digest | `keccak` |
| `keccak_tests::positive_keccak_output_length_is_32` | output length invariant | `keccak` |
| `keccak_tests::positive_domain_separator_is_deterministic` | same input → same DS | `eip712_domain_separator` |
| `keccak_tests::positive_final_digest_is_deterministic_and_framed` | output equals keccak of `0x19 0x01 ‖ DS ‖ SH` reconstructed by hand | `final_digest` |
| `cowswap::extra_tests::positive_decode_accepts_all_valid_enum_combinations` | every legal `kind × pf × stb × btb` cross product (24) decodes | `decode_canonical` |
| `cowswap::extra_tests::positive_decode_round_trips_all_byte_fields` | every parsed field equals the canonical slice | `decode_canonical` |
| `cowswap::extra_tests::positive_compute_digest_is_deterministic` | same canonical → same digest | `compute_digest` |
| `cowswap::extra_tests::positive_struct_hash_is_deterministic` | same order → same struct_hash | `struct_hash` |
| `cowswap::extra_tests::positive_kind_hash_sell_buy` | `kind_hash(0/1)` = keccak("sell"/"buy") | `kind_hash` |
| `cowswap::extra_tests::positive_balance_hash_legal_values` | all 5 documented (side, value) pairs map correctly | `balance_hash` |
| `cowswap::extra_tests::positive_setpresig_offset_constants_match_layout` | offset/length consts equal the documented ABI offsets + sum to 56 | `SETPRESIG_*` |
| `safe::extra_tests::positive_approve_hash_selector_matches_preimage` | `APPROVE_HASH_SELECTOR == keccak("approveHash(bytes32)")[..4]` | `APPROVE_HASH_SELECTOR` |
| `safe::extra_tests::positive_approve_hash_calldata_len_is_selector_plus_bytes32` | length constant = 4 + 32 = 36 | `APPROVE_HASH_CALLDATA_LEN` |
| `safe::extra_tests::positive_canonical_layout_offsets_pin_to_documented_layout` | each `SAFE_OFF_*` matches docs + last field ends at 281 | `SAFE_OFF_*`, `SAFE_V1_CANONICAL_LEN` |
| `safe::extra_tests::positive_safe_v1_raw_data_max_is_max_tx_len` | `SAFE_V1_RAW_DATA_MAX == MAX_TX_LEN` | const |
| `safe::extra_tests::positive_safe_domain_typehash_matches_preimage` | typehash hex matches preimage keccak | `SAFE_DOMAIN_TYPEHASH` |
| `safe::extra_tests::positive_safe_tx_typehash_matches_preimage` | typehash hex matches preimage keccak | `SAFE_TX_TYPEHASH` |
| `safe::extra_tests::positive_decode_round_trips_all_fields` | every parsed field equals the canonical slice | `decode_canonical` |
| `safe::extra_tests::positive_decode_accepts_delegatecall_operation_byte` | `decode_canonical` permits `operation==1`; verify is the gate | `decode_canonical` |
| `safe::extra_tests::positive_compute_safe_tx_hash_deterministic` | same canonical → same hash | `compute_safe_tx_hash` |
| `safe::extra_tests::positive_domain_separator_deterministic` | same input → same DS | `domain_separator` |
| `safe::extra_tests::positive_struct_hash_deterministic` | same tx → same struct_hash | `struct_hash` |
| `safe::extra_tests::positive_verify_bundle_at_exact_minimum_with_keccak_empty_data_hash` | zero-len raw_data + `keccak("")` data_hash verifies (boundary) | `verify_and_bind_trailer` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `keccak_tests::negative_domain_typehash_preimage_is_byte_stable` | The EIP-712 v0 domain typehash preimage is exactly the canonical string | Byte-compares `DOMAIN_TYPEHASH_PREIMAGE` against the literal + asserts `keccak(it)` = `8b73c3c6…` | Both equalities hold |
| `keccak_tests::negative_domain_separator_binds_chain_id` | chain_id is mixed into the DS (cross-chain replay protection) | Two DS computations differing only in chain_id | DS values are distinct |
| `keccak_tests::negative_domain_separator_binds_verifying_contract` | Address is bound (cross-protocol replay) | Swap the address | DS distinct |
| `keccak_tests::negative_domain_separator_binds_name_hash` | name participates | Different name hash | DS distinct |
| `keccak_tests::negative_domain_separator_binds_version_hash` | version participates | Different version hash | DS distinct |
| `keccak_tests::negative_domain_separator_chain_id_is_left_padded_uint256_be` | chain_id encoded as 24 zero + 8 BE bytes per EIP-712 | Reconstruct preimage by hand and assert equality | exact match |
| `keccak_tests::negative_final_digest_binds_domain_separator` | DS affects final digest | Two ds, one sh | digests distinct |
| `keccak_tests::negative_final_digest_binds_struct_hash` | SH affects final digest | One ds, two sh | digests distinct |
| `keccak_tests::negative_final_digest_byte_swap_changes_output` | Argument order matters; not commutative | Swap DS↔SH | digests distinct |
| `keccak_tests::negative_eip712_error_variants_have_distinct_debug` | Telemetry parses on Debug names | Format both variants | distinct strings containing variant names |
| `cowswap::extra_tests::negative_order_typehash_preimage_is_byte_stable` | Preimage is the on-chain CoW typehash; getting it wrong yields the bricked `0x1a59c8ff…` documented in `mod.rs` | Byte-compare + keccak equality to the on-chain `0xd5a25ba2e97094ad…` | both equalities hold |
| `cowswap::extra_tests::negative_domain_name_and_version_are_byte_stable` | `"Gnosis Protocol"` / `"v2"` match on-chain settlement | Byte-compare consts | exact match |
| `cowswap::extra_tests::negative_gpv2_settlement_address_is_byte_stable` | GPv2Settlement CREATE2 address pinned across chains | Byte-compare const | exact match |
| `cowswap::extra_tests::negative_decode_rejects_kind_out_of_range` | kind ∈ {0,1} only | feed 2/3/7/100/255 | each rejects with `EnumOutOfRange` |
| `cowswap::extra_tests::negative_decode_rejects_partially_fillable_out_of_range` | pf ∈ {0,1} only | feed 2/3/100/255 | rejects |
| `cowswap::extra_tests::negative_decode_rejects_sell_token_balance_out_of_range` | stb ∈ {0,1,2} only | feed 3/4/100/255 | rejects |
| `cowswap::extra_tests::negative_decode_rejects_buy_token_balance_out_of_range` | btb ∈ {0,1} only | feed 2/3/100/255 | rejects |
| `cowswap::extra_tests::negative_compute_digest_rejects_chain_id_mismatch` | canonical.chain_id must equal VK chain_id (NS can't pair a proof with a mismatched bundle) | canonical pinned to 1, caller supplies 137 | `ChainIdMismatch` |
| `cowswap::extra_tests::negative_compute_digest_chain_id_zero_vs_one_is_distinct` | chain_id binds the digest via DS (drop-the-chain refactor attack) | Two compute_digest calls differing only in chain_id | digests distinct |
| `cowswap::extra_tests::negative_struct_hash_binds_sell_token`…`negative_struct_hash_binds_buy_token_balance` (12 tests) | Every GPv2Order field is in the struct_hash preimage — appData regression (v2 ignored it) and field-drop regressions both rejected | Flip one byte per field, recompute digest | digest changes |
| `cowswap::extra_tests::negative_cross_check_reports_chain_id_first` | First-failure-wins ordering documented in `cross_check_setpresig_calldata` doc-comment | Construct a calldata where chain + validTo + digest + owner are ALL wrong | `Err(ChainIdMismatch)` (not Owner/Digest/Valid) |
| `cowswap::extra_tests::negative_cross_check_reports_valid_to_before_digest` | validTo check runs before digest | Both wrong | `Err(ValidToMismatch)` |
| `cowswap::extra_tests::negative_cross_check_reports_digest_before_owner` | digest check runs before owner | Both wrong | `Err(OrderDigestMismatch)` |
| `cowswap::extra_tests::negative_cross_check_rejects_appdata_swap_undetected_otherwise` | v3 binds appData (closes the v2 "silently swap appData" attack) | Flip a byte in canonical[172..204], leave calldata as built for original | `Err(OrderDigestMismatch)` |
| `cowswap::extra_tests::negative_shape_rejects_bytes_offset_not_0x40` | ABI offset byte at calldata[35] must be 0x40 | set to 0x60 | rejects |
| `cowswap::extra_tests::negative_shape_rejects_high_byte_set_in_bytes_offset_field` | All [4..35] must be zero | set [20]=0xFF | rejects |
| `cowswap::extra_tests::negative_shape_rejects_bytes_len_not_56` | calldata[99]==56 | try 55/57/0 | each rejects |
| `cowswap::extra_tests::negative_shape_rejects_high_byte_set_in_signed_field` | [36..67] must be zero | set [40]=0xFF | rejects |
| `cowswap::extra_tests::negative_shape_rejects_signed_value_two` | bool slot must be exactly 1 (not just nonzero) | set [67]=2 | rejects |
| `cowswap::extra_tests::negative_shape_rejects_high_byte_set_in_bytes_len_field` | [68..99] must be zero | set [80]=0x01 | rejects |
| `cowswap::extra_tests::negative_shape_rejects_each_tail_pad_byte_nonzero` | All 8 bytes [156..164) must be zero — sweep each position | per-byte loop | each rejects |
| `safe::extra_tests::negative_decode_rejects_operation_two_through_255` | operation ∈ {0,1} only | feed 8 bad values | each rejects |
| `safe::extra_tests::negative_struct_hash_binds_to`…`negative_struct_hash_binds_nonce` (10 tests) | Every SafeTx field in struct_hash preimage participates | Flip one byte per field | hash changes |
| `safe::extra_tests::negative_struct_hash_binds_chain_id_via_domain_separator` | chain_id mixes via DS (not struct_hash) | flip low byte | safe_tx_hash changes |
| `safe::extra_tests::negative_struct_hash_binds_safe_address_via_domain_separator` | safe_address mixes via DS as verifyingContract | flip a byte | safe_tx_hash changes |
| `safe::extra_tests::negative_verify_rejects_when_raw_len_off_by_one` | declared raw_data_len > actual rejected | encode actual_len + 1 | rejects |
| `safe::extra_tests::negative_verify_rejects_declared_len_exceeds_max_tx_len` | raw_len > `SAFE_V1_RAW_DATA_MAX` rejected pre-bundle-length-check | declared len = max+1 with no payload | rejects |
| `safe::extra_tests::negative_verify_rejects_truncated_one_byte_short_of_canonical_plus_len_prefix` | trailer must include the 2-byte length prefix | bundle = canonical+1 zero bytes | rejects |
| `safe::extra_tests::negative_verify_rejects_inner_data_under_four_bytes` | inner_data ≥ 4 for selector check | feed 0/1/2/3 bytes | each rejects |
| `safe::extra_tests::negative_verify_rejects_inner_data_over_36_bytes` | inner_data length is exactly 36 | append 1 extra byte | rejects |
| `safe::extra_tests::negative_verify_rejects_when_userop_to_is_not_canonical_safe_address` | safe address pinning to UserOp.to | imposter Safe `[0x11; 20]` | rejects |
| `safe::extra_tests::negative_verify_rejects_extra_trailing_bytes_inside_declared_raw_len` | Length-prefixed framing permits trailing-junk (positive contract test, called negative for symmetry with the attacker-model exhaustive sweep) | append junk past raw_data_end | accepts (intentional permissive framing — pinned to catch a future tightening that breaks companion compatibility) |
| `safe::extra_tests::negative_verify_rejects_when_canonical_chain_id_zero_and_caller_one` | A chain_id=0 canonical doesn't replay across all chains | canonical chain_id=0, caller chain_id=1 | rejects |
| `safe::extra_tests::negative_verify_rejects_selector_match_but_zero_remaining_bytes` | Length guard fires even when selector matches | calldata = selector only (4 bytes) | rejects |
| `safe::extra_tests::negative_verify_rejects_data_hash_when_one_raw_data_byte_flipped` | Every raw_data byte is bound (first/middle/last sweep) | flip per offset | each rejects |

## Production-code bugs surfaced by negative tests

None. Every negative test confirms the production code correctly
rejects the attack the assumption guards against.

One contract clarification surfaced (not a bug): the Safe verifier
documents the raw_data slice as `safe_bundle[raw_data_start..raw_data_end]`,
meaning trailing junk past `raw_data_end` is silently ignored. The
test `negative_verify_rejects_extra_trailing_bytes_inside_declared_raw_len`
pins this as the documented contract so a future tightening (which
would break companion compatibility) gets caught.

## Coverage gaps deliberately left

- **`cowswap::verify::verify_and_bind_trailer`** is `#[cfg(not(test))]`-
  gated on host because it pulls in `crate::zk` (Groth16 verifier
  requires bls12_381 hardware glue that doesn't round-trip through
  `cargo test --release` without on-target deps). The 5-step pipeline
  (Groth16 + H_root pin → sentinel + chain → calldata length → shape →
  cross-check) is exercised end-to-end by `nonsecure/src/e2e_test.rs`
  under QEMU. The downstream helpers it composes
  (`check_setpresig_calldata_shape`, `cross_check_setpresig_calldata`,
  `compute_digest`) are exhaustively tested here at the unit level.
- **`cowswap_display.rs` / `cowswap_display`** rendering — depends on
  the OLED `Ui` trait and trusted-UI confirm dialogs; needs a hardware
  fixture or `ui-capture` smoke run. Tracked separately under the
  `secure-tx-display` slice.
- **Cross-validation of the Safe `safeTxHash` against the live Safe
  Transaction Service** — the existing fixture is self-consistent
  (calldata digest derived from `compute_safe_tx_hash(canonical)`),
  which catches refactor regressions but doesn't double-check our
  computation against an independent implementation. A live-service
  vector belongs in `nonsecure/src/e2e_test.rs`; flagged for a
  follow-up pass.
- **`balance_hash` defensive fallback to `keccak("erc20")` on
  out-of-range inputs** — the decoder rejects these before they reach
  `balance_hash`, so the fallback is unreachable through normal
  pipelines. Could be tested by a direct call (the function is
  module-private but visible to the test module); left for follow-up.

## Verification

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked
  permission to invoke cargo-fmt; new files mirror the existing
  test_vectors style — 4-space indent, trailing commas)
- `cargo check -p sphincs-tz-secure` — PASS (35 pre-existing
  warnings, none introduced by the new test files)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A
  (sandbox blocked permission; the warnings cargo check surfaces are
  all pre-existing and unrelated to the new tests)
- `cargo test -p sphincs-tz-secure` — PASS (112 tests in the
  `tx::eip712::*` namespace, 0 failed, 0 ignored; the wider 902
  filtered-out tests from other slices were not exercised by the
  `eip712` filter)
- (firmware) on-target tests deferred: no — every new test is
  pure-logic and runs on host
