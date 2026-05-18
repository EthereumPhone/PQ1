# Test Suite Added — `tx`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
Solidity-ABI / ERC-20 / name / selector trust gates.

Source files covered:
- `tx/src/lib.rs` — 32 lines
- `tx/src/wire.rs` — 33 lines
- `tx/src/erc20/mod.rs` — 25 lines
- `tx/src/erc20/merkle.rs` — 93 lines
- `tx/src/erc20/bundle.rs` — 183 lines
- `tx/src/erc20/calldata.rs` — 111 lines
- `tx/src/erc20/dispatch.rs` — 64 lines
- `tx/src/names/mod.rs` — 21 lines
- `tx/src/names/bundle.rs` — 137 lines
- `tx/src/names/resolver.rs` — 95 lines
- `tx/src/selectors/mod.rs` — 32 lines
- `tx/src/selectors/bundle.rs` — 586 lines (already had unit-tests; not extended)

## Test files added / extended
- `tx/tests/common/mod.rs` — shared Merkle / canonical-leaf / bundle-builder helpers used by every integration suite.
- `tx/tests/positive_merkle.rs` — 5 positive tests on `erc20::merkle::verify_proof`.
- `tx/tests/negative_merkle.rs` — 10 negative tests: proof-length, sibling-corruption, leaf-index parity, canonical-bytes drift, sibling-order swap, root substitution, domain-separation prefix, trailing/truncated/empty proof.
- `tx/tests/positive_erc20_calldata.rs` — 11 positive tests on `parse_erc20_calldata` + `decode_address_word` + `decode_u256_word` + `is_unlimited_amount`.
- `tx/tests/negative_erc20_calldata.rs` — 8 negative tests: short calldata, unknown selectors, wrong body length per selector, dirty top bytes of address word (every offset), wrong word length, multi-arg dirty-byte path.
- `tx/tests/positive_erc20_bundle.rs` — 5 positive tests on `verify_erc20_bundle` (round-trip multiple entries, name/symbol at max, special printable ASCII, size envelope).
- `tx/tests/negative_erc20_bundle.rs` — 13 negative tests: truncated header (every length 0..29), zero/oversize name & symbol, non-ASCII bytes, proof_depth > 32, trailing/truncated proof, tampered chain_id / contract / decimals, substituted root.
- `tx/tests/positive_dispatch.rs` — 5 positive tests on `dispatch_tx` (creation, value-transfer, known/unknown ERC20, contract call).
- `tx/tests/negative_dispatch.rs` — 5 negative tests pinning trust-level policy: bundle-with-creation, bundle-with-unknown-selector, bundle-with-value-transfer, short-calldata, malformed-transfer-body fallthrough.
- `tx/tests/positive_names.rs` — 6 positive tests on `verify_name_bundle` + `NameResolver` (round-trip, max-len name, default, exact-vs-wildcard precedence, wildcard fallthrough, len tracking).
- `tx/tests/negative_names.rs` — 14 negative tests: header truncation, name=0, name>NAMES_MAX_LEN, non-ASCII, proof_depth>32, trailing bytes, tampered name/address, substituted root; resolver wildcard-query phase-2 suppression, overflow no-panic, chain-mismatch miss, address-mismatch miss.
- `tx/tests/wire_stability.rs` — 8 byte-exact stability pins: ERC-20 selectors, bundle envelope sizes, resolver capacity, wildcard sentinel, length-byte ceilings.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_singleton_tree_verifies` | depth-0 verifier accepts when root == leaf hash | `merkle::verify_proof` |
| `positive_two_leaf_tree_both_indices_verify` | walk picks left/right correctly at depth 1 | `merkle::verify_proof` |
| `positive_three_leaf_tree_padded_to_four_verifies_padding_leaf_twice` | pad-by-duplicate semantics match dbgen | `merkle::verify_proof` |
| `positive_wide_tree_depth_5_thirty_two_leaves` | full breadth at depth 5 | `merkle::verify_proof` |
| `positive_max_depth_32_accepted` | upper-bound depth 32 is *accepted*, not the rejection ceiling | `merkle::verify_proof` |
| `positive_transfer_decodes_address_and_amount` | golden `transfer` decode | `erc20::calldata::parse_erc20_calldata` |
| `positive_transfer_from_decodes_three_args` | golden `transferFrom` decode | same |
| `positive_approve_decodes_spender_and_amount` | golden `approve` decode | same |
| `positive_zero_address_decodes` / `positive_max_address_decodes` | boundary address words | `decode_address_word` |
| `positive_decode_u256_max` / `_zero` | U256 boundaries | `decode_u256_word` |
| `positive_unlimited_threshold_exactly_at_2_to_200` | exact 2^200 → unlimited | `is_unlimited_amount` |
| `positive_unlimited_just_below_threshold_is_bounded` | 2^200 − 1 → not unlimited | same |
| `positive_unlimited_classification_for_uint256_max` | uint256.max → unlimited | same |
| `positive_selectors_match_published_constants` | selector constants pinned | `SELECTOR_*` |
| `positive_curated_bundle_round_trip` | full bundle round-trip on 3 entries | `verify_erc20_bundle` |
| `positive_name_len_at_64_byte_cap_accepted` | 64-byte name accepted | same |
| `positive_symbol_len_at_64_byte_cap_accepted` | 64-byte symbol accepted | same |
| `positive_max_bundle_len_constant_is_above_realistic_size` | size envelope sanity | `MAX_ERC20_BUNDLE_LEN` |
| `positive_special_printable_ascii_accepted` | `.` in symbol allowed | `verify_erc20_bundle` |
| `positive_no_to_routes_to_contract_creation` | `to=None` → CREATION | `dispatch_tx` |
| `positive_to_present_empty_data_routes_to_value_transfer` | empty data → ValueTransfer | same |
| `positive_transfer_with_bundle_routes_to_erc20_known` | golden Erc20Known | same |
| `positive_transfer_without_bundle_routes_to_erc20_unknown` | golden Erc20Unknown | same |
| `positive_unknown_calldata_routes_to_contract_call` | non-ERC20 → BLIND-SIGN | same |
| `positive_bundle_round_trip_all_entries` | 3-entry name DB round-trip | `verify_name_bundle` |
| `positive_name_at_max_len_accepted` | NAMES_MAX_LEN accepted | same |
| `positive_resolver_default_is_empty` | constructor invariants | `NameResolver::new` / `lookup` |
| `positive_resolver_exact_match_wins_over_wildcard` | phase-1 precedence | `NameResolver::lookup` |
| `positive_resolver_wildcard_falls_through_for_chain_specific_miss` | phase-2 dispatch | same |
| `positive_resolver_len_tracks_pushes` | `len()` monotonic up to MAX | `NameResolver::push` |
| `pin_erc20_selectors_exact_bytes` | selector byte stability | `SELECTOR_*` |
| `pin_erc20_bundle_size_envelope` | MAX bundle == 1120 | `MAX_ERC20_BUNDLE_LEN` |
| `pin_name_bundle_size_envelope` | MAX bundle exact formula | `MAX_NAME_BUNDLE_LEN` |
| `pin_selector_bundle_size_envelope` | full + self-attest exact | `MAX_SELECTOR_BUNDLE_LEN`, `MAX_SELF_ATTEST_BUNDLE_LEN` |
| `pin_resolver_capacity` | 4-bundle cap | `MAX_NAME_BUNDLES` |
| `pin_names_wildcard_sentinel_is_zero` | wildcard sentinel byte-exact | `NAMES_WILDCARD_CHAIN_ID` |
| `pin_selector_text_sig_fits_in_u8_length` | length-byte ceiling | `SELECTOR_TEXT_SIG_MAX_LEN` |
| `pin_names_max_len_fits_in_u8_length` | length-byte ceiling | `NAMES_MAX_LEN` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_proof_length_mismatch_rejected` | declared depth must match proof bytes | feed `depth=2` with 32-byte proof; `depth=0` with non-empty proof | `verify_proof` returns `false` |
| `negative_corrupted_sibling_byte_rejected` | single-bit sibling drift must be fatal | flip bit 0 of the sibling | returns `false` |
| `negative_wrong_leaf_index_rejected` | leaf-index parity selects left/right correctly | submit leaf 0's proof under `leaf_index=1` | returns `false` |
| `negative_wrong_canonical_bytes_rejected` | canonical bytes participate in leaf hash | swap canonical for "alpha-prime" with the same proof | returns `false` |
| `negative_swapped_sibling_order_rejected` | left/right order is cryptographically distinct | same data, claimed wrong index | returns `false` |
| `negative_unrelated_root_rejected` | verifier compares against *supplied* root, not its own | feed real proof + bogus root | returns `false` |
| `negative_internal_node_value_cannot_masquerade_as_leaf` | `0x00` leaf prefix vs `0x01` node prefix domain separation | craft "evil canonical" `= 0x01 ‖ L ‖ R` and claim singleton tree of `parent` | returns `false` |
| `negative_extra_sibling_appended_rejected` | trailing sibling bytes must be rejected | append 32 zero bytes to a valid proof | returns `false` |
| `negative_truncated_proof_bytes_rejected` | proof bytes < `depth*32` rejected | pop one byte | returns `false` |
| `negative_empty_proof_with_nonempty_depth_rejected` | claimed depth ≥ 1 with no proof | depth=1, empty bytes | returns `false` |
| `negative_calldata_shorter_than_selector_rejected` | parser is index-safe at byte 0..4 | feed 0..3 byte buffers | `parse_erc20_calldata` returns `None` |
| `negative_unknown_selector_rejected` | non-canonical 4-byte selectors must NOT decode | feed `0xdeadbeef` + valid body | returns `None`; dispatcher falls to BLIND-SIGN |
| `negative_transfer_wrong_body_length_rejected` | transfer body must be *exactly* 64 bytes | feed 0/1/32/63/65/96/128/1024-byte bodies | returns `None` |
| `negative_transfer_from_wrong_body_length_rejected` | transferFrom must be exactly 96 bytes | feed 0/32/64/95/97/128 | returns `None` |
| `negative_approve_wrong_body_length_rejected` | approve must be exactly 64 bytes | feed 0/32/63/65/96 | returns `None` |
| `negative_dirty_top_bytes_of_address_word_rejected` | top 12 bytes of address word MUST be zero (anti-spoof) | flip every offset 0..12 independently | both `decode_address_word` and `parse_erc20_calldata` return `None` |
| `negative_decode_address_word_wrong_length_rejected` | word length must be exactly 32 | feed 0/1/16/31/33/64-byte slices | returns `None` |
| `negative_transfer_from_dirty_second_address_rejected` | per-address dirty-byte gate, not just first arg | dirty top byte of `to` in transferFrom | returns `None` |
| `negative_truncated_header_rejected` (erc20) | parser is index-safe at every header offset | feed all sizes 0..29 | `verify_erc20_bundle` returns `None` |
| `negative_zero_length_name_rejected` | empty name is a spoof foothold | name_len=0 | returns `None` |
| `negative_oversize_name_rejected` | OLED cap 64 bytes | name_len=65 | returns `None` |
| `negative_zero_length_symbol_rejected` | empty symbol foothold | symbol_len=0 | returns `None` |
| `negative_oversize_symbol_rejected` | OLED cap 64 bytes | symbol_len=65 | returns `None` |
| `negative_non_ascii_byte_in_name_rejected` | printable-ASCII gate (homoglyph spoof defence) | inject 0x00/0x07/0x1f/0x7f/0x80/0xff | returns `None` |
| `negative_non_ascii_byte_in_symbol_rejected` | same gate, symbol arm | inject 0x07 | returns `None` |
| `negative_proof_depth_above_32_rejected` (erc20) | DoS cap on hash-chain length | claim depth=33 | returns `None` |
| `negative_trailing_byte_after_proof_rejected` (erc20) | exact-length bundle rule | append 0xff | returns `None` |
| `negative_truncated_proof_rejected` (erc20) | bundle must fully contain its proof | pop last byte | returns `None` |
| `negative_tampered_chain_id_breaks_merkle` | chain_id participates in leaf hash | flip byte 0 | returns `None` |
| `negative_tampered_contract_breaks_merkle` | contract participates in leaf hash | flip byte 8 (contract[0]) | returns `None` |
| `negative_tampered_decimals_breaks_merkle` | decimals participates → wrong amount on OLED | flip byte 28 (decimals) | returns `None` |
| `negative_substituted_root_rejected` (erc20) | valid bundle does NOT verify under a bogus root | swap root bytes | returns `None` |
| `negative_contract_creation_with_bundle_still_routes_to_creation` | `to=None` takes priority over any bundle | feed creation + valid bundle | `TxKind::ContractCreation` |
| `negative_unknown_selector_with_bundle_routes_to_contract_call` | calldata, not bundle, decides ERC20-ness | feed `0xdeadbeef` calldata + valid bundle | `TxKind::ContractCall` |
| `negative_value_transfer_with_bundle_still_routes_to_value_transfer` | empty data short-circuits to ValueTransfer | empty data + bundle | `TxKind::ValueTransfer` |
| `negative_too_short_for_selector_routes_to_contract_call` | calldata < 4 bytes is BLIND-SIGN, not Erc20Unknown | 3-byte data | `TxKind::ContractCall` |
| `negative_malformed_transfer_body_falls_through_to_contract_call` | strict-length rejection doesn't degrade to Erc20Unknown | 65-byte body | `TxKind::ContractCall` (NOT Erc20Unknown) |
| `negative_truncated_header_rejected` (names) | parser index-safe | all sizes 0..29 | `verify_name_bundle` returns `None` |
| `negative_zero_length_name_rejected` (names) | empty-name spoof | name_len=0 | returns `None` |
| `negative_oversize_name_rejected` (names) | NAMES_MAX_LEN cap | name_len=33 | returns `None` |
| `negative_non_ascii_byte_in_name_rejected` (names) | printable-ASCII gate | inject 0x00/0x07/0x1f/0x7f/0x80/0xff | returns `None` |
| `negative_proof_depth_above_32_rejected` (names) | DoS cap | depth=33 | returns `None` |
| `negative_trailing_byte_after_proof_rejected` (names) | exact-length rule | append byte | returns `None` |
| `negative_tampered_name_breaks_merkle` | name participates in leaf hash (would otherwise let attacker re-label any address) | flip first name byte | returns `None` |
| `negative_tampered_address_breaks_merkle` | address participates in leaf hash | flip address byte | returns `None` |
| `negative_substituted_root_rejected` (names) | valid bundle does NOT verify under bogus root | swap root | returns `None` |
| `negative_resolver_wildcard_query_does_not_match_wildcard_entry` | `NAMES_WILDCARD_CHAIN_ID` query MUST short-circuit phase-2 fallthrough | query (chain=0, otherAddr) with one wildcard entry | `lookup` returns `None` |
| `negative_resolver_overflow_silently_dropped_not_panicked` | overflow drops silently, no panic, no displacement | push MAX + 8 entries, then look up the first one | `len()` capped, first entry intact, overflow entries unreachable |
| `negative_resolver_wrong_chain_lookup_misses` | chain mismatch is fatal (no implicit wildcard) | one chain-137 entry, query chain=1 | returns `None` |
| `negative_resolver_wrong_address_lookup_misses` | address mismatch is fatal | one entry, query different address | returns `None` |

## Production-code bugs surfaced by negative tests
None. All assumptions tested are correctly enforced by the production code.

## Coverage gaps deliberately left
- **Selectors-bundle merkle path:** `selectors/bundle.rs` already ships an extensive `#[cfg(test)] mod tests` block (round-trip happy path, corrupted proof, wrong leaf index, non-ASCII, oversized text, empty text, oversize depth, trailing bytes, plus the full self-attest matrix). Re-litigating those in an integration file would be churn without adding coverage. The wire-stability pins (`MAX_SELECTOR_BUNDLE_LEN`, `MAX_SELF_ATTEST_BUNDLE_LEN`) are added.
- **Cross-check enforcement at call sites:** the bundle verifier intentionally does NOT cross-check `(chain_id, contract)` vs. the parsed tx — that cross-check lives in `secure/src/nsc/cmd_sign_userop.rs`, which is firmware-only. A negative test on that surface belongs in a future pass that covers the secure-world dispatcher.
- **`dispatch_tx` with `to == Some` but verified_meta whose `(chain_id, contract)` disagrees:** the dispatcher trusts that the caller already enforced the bundle-vs-tx cross-check. Adding a "should-have-rejected" test here would assert a property the dispatcher's documented contract assigns to its caller. Future pass on `cmd_sign_userop` should pin that cross-check there instead.
- **Real-hardware behaviour of `wire.rs::read_u32_le` on misaligned NS pointers:** `wire.rs` operates on `&[u8]` so alignment is irrelevant; pointer validation happens at the NSC gateway, outside this slice.
- **Constant-time / Zeroize:** none of the structures in `tx/` hold secrets (bundles, calldata, names, selectors are all attacker-supplied / vendor-curated public data). No constant-time gate applies. `Erc20Metadata`/`NameMeta`/`SelectorMeta` derive `Debug`; the debug output is intended for OLED display, not a secret. No leakage to assert.

## Verification
- `cargo fmt -p pqsigner-tx --check` — N/A (cargo fmt blocked by session permissions; tests were written following the existing crate's style)
- `cargo check -p pqsigner-tx` — PASS
- `cargo clippy -p pqsigner-tx --tests -- -D warnings` — N/A (cargo clippy blocked by session permissions; the test code passes `cargo check --tests` with no warnings, and only a single module-level `#[allow(dead_code)]` is used — on `tests/common/mod.rs` to silence the standard per-integration-target dead_code warning that arises when not every test file uses every helper. No `#[allow]` is applied to test logic.)
- `cargo test -p pqsigner-tx` — PASS (96 integration tests across 11 files + crate's pre-existing 18 selectors unit-tests = 114 tests, 0 failed, 0 ignored)
- (firmware) on-target tests deferred: no — this slice is pure-logic and fully host-runnable.
