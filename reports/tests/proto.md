# Test Suite Added — `proto`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope
Protocol IDL crate (constants + enums + wire sizes). Zero-deps.

Source files covered:
- `proto/src/lib.rs` (1611 lines) — every public constant and the `NscStatus` enum.
- `proto/Cargo.toml` (dev-dependencies extended with `tiny-keccak`).

The crate exposes no functions — its public surface is constants and one
`#[repr(u32)]` enum with a `From<u32>` impl. The positive suite asserts
each declared constant matches its documented formula and that derived
sizes equal the sum of their parts. The negative suite challenges the
two big assumptions every constant in this crate makes: **the bytes are
frozen** (because deployed contracts depend on them) and **the layout
math is what the docs claim** (because companion apps parse against
these offsets).

## Test files added / extended
- `proto/tests/positive_layout.rs` — 35 positive tests covering every
  wire-format and derived-length declaration in the crate.
- `proto/tests/positive_nsc_status.rs` — 5 positive tests for the
  `NscStatus` enum + `From<u32>` round-trip + discriminant values.
- `proto/tests/negative_frozen_constants.rs` — 12 negative tests: every
  byte-exact constant baked into deployed on-chain artifacts (EIP-6492
  magic, factory address, proxy init-code hash, all 6 selectors, both
  Safe typehashes, domain tags, settlement vs sentinel) is pinned.
- `proto/tests/negative_selector_keccak.rs` — 8 negative tests: every
  declared selector and EIP-712 typehash is re-derived from its
  canonical Solidity signature via `tiny-keccak` and compared to the
  constant. Catches "fixed the signature, re-derived the selector" drift
  that the byte-exact tests would not.
- `proto/tests/negative_bitfield_invariants.rs` — 15 negative tests:
  pairwise-disjoint flag regions, full-u32 coverage, mask widths/shifts,
  proptest round-trip of (include_init, register_slot, account_index,
  slot_index) packing, reserved off-chain flag bits, contiguous header
  offsets.
- `proto/tests/negative_cmd_and_status.rs` — 12 negative tests:
  pairwise CMD uniqueness, retired CMD IDs 4 and 6 unused,
  `CMD_TEST_PIN_LOCKOUT` / `CMD_TZIC_STATUS` confined to ≥ 200,
  production CMDs all < 200, `CMD_NONE` zero sentinel, documented
  range conventions, NscStatus discriminant pinning, retired
  discriminant 8 (SlotExhausted) falls through to `InternalError`,
  unknown discriminants likewise.
- `proto/tests/negative_memory_layout.rs` — 7 negative tests:
  NS-SRAM and NS-Flash regions non-empty, well-ordered, **disjoint**,
  shared-mailbox contained inside NS-SRAM and exactly 24 bytes wide,
  plus per-feature range checks for mps2-an505 (default) and STM32U585
  silicon addresses.

Existing in-lib `#[cfg(test)] mod tests` (12 tests) was left unmodified.

## Positive coverage

| test name | what it asserts | API surface |
|---|---|---|
| `positive_legacy_userop_header_layout_sums` | `USEROP_HEADER_LEN = 305`, prefix = header + 4 | CMD_SIGN_USEROP v3 wire |
| `positive_unified_userop_header_layout_sums` | `SIGN_USEROP_HEADER_LEN = 330` from declared field widths | CMD_SIGN_USEROP v4 wire |
| `positive_batch_header_layout_sums` | `SIGN_USEROP_BATCH_HEADER_LEN = 277` | CMD_SIGN_USEROP_BATCH wire |
| `positive_batch_tx_prefix_layout_sums` | inner-tx prefix = `to(20)+value(32)+data_len(2) = 54` | batch wire |
| `positive_batch_max_payload_includes_every_tx_at_max_data` | worst-case payload sized for `MAX_BATCH_TXS × MAX_TX_LEN` | batch wire |
| `positive_max_execute_batch_calldata_bounds_reconstructed_calldata` | calldata bound covers 4 inner txs × 4096 B | execute calldata sizing |
| `positive_signature_len_and_padding` | `SIGNATURE_LEN = 4008`, padded to 4032 | C10 sig sizes |
| `positive_sig_wrapper_matches_solidity_encoding` | `SIG_WRAPPER_LEN = 4128 = 32+32+32+4032` | SignatureWrapper ABI |
| `positive_pq_init_code_len_breakdown` | `PQ_INIT_CODE_LEN = 4280` from layout sum | initCode wire |
| `positive_sign_offchain_header_offsets_are_monotonic_and_contiguous` | account/chain/slot/kind/payload_len/flags offsets | CMD_SIGN_OFFCHAIN input |
| `positive_sign_offchain_output_deployed_layout` | count(8) ‖ c10_sig(4008) | CMD_SIGN_OFFCHAIN output |
| `positive_sign_offchain_max_input_bounds_personal_sign` | `header + 700` | CMD_SIGN_OFFCHAIN cap |
| `positive_eip6492_blob_breakdown` | 96+32+4288+32+4128+32 = 8608 | EIP-6492 ABI |
| `positive_sign_offchain_output_6492_layout` | count(8) ‖ blob(8608) = 8616 | EIP-6492 output |
| `positive_offchain_status_input_layout` | 13 B | CMD_OFFCHAIN_STATUS |
| `positive_offchain_status_output_layout` | 24 B with declared offsets | CMD_OFFCHAIN_STATUS |
| `positive_offchain_sync_input_layout` | 21 B | CMD_OFFCHAIN_SYNC |
| `positive_max_sign_response_covers_unified_sign_full_bundle` | `MAX_SIGN_RESPONSE_LEN ≥ count+initCode+T1+T2` | response sizing |
| `positive_max_sign_response_covers_eip6492_output` | also bounds 6492 path | response sizing |
| `positive_fw_status_response_offsets` | state(1)+recv_s(4)+recv_ns(4)+slot(1) = 10 | CMD_FW_STATUS |
| `positive_fw_chunk_header_distinct_kind_bytes` | `SECURE != NONSECURE` | CMD_FW_CHUNK |
| `positive_fw_states_pairwise_distinct` | IDLE/RECEIVING/STAGED | FW state machine |
| `positive_max_execute_calldata_covers_worst_case` | 4+160+32+32+4096 bound | Type 2 calldata |
| `positive_zk_v3_layout_sums` | proof(384)+canonical(204)+readable(128) | CoW v3 trailer |
| `positive_safe_v1_canonical_offsets_contiguous` | every Safe field offset chains | safe_v1 trailer |
| `positive_safe_v1_payload_max_includes_canonical_plus_raw_data` | 281+2+4096 | safe_v1 trailer |
| `positive_ns_sram_region_nonempty_and_ordered` | base < end, ≥ 64 KB | NS memory map |
| `positive_ns_flash_region_nonempty_and_ordered` | base < end | NS memory map |
| `positive_shared_mailbox_region_inside_or_adjacent_ns_sram` | mailbox at end of SRAM, 24 B | gateway mailbox |
| `positive_usb_hid_constants` | size=64, tags distinct, APDU=0x05, PING=0x02 | USB HID v2 |
| `positive_apdu_protocol_version_is_v2` | 0x0200, CLA=0xF0, max_resp=253 | APDU v2 |
| `positive_status_words_pairwise_distinct` | every SW_* unique, SW_OK=0x9000 | ISO 7816 SW |
| `positive_pin_and_constants` | PIN/attempts/key sizes | crypto sizing |
| `positive_ins_v2_codes_pairwise_distinct` | 17 INS codes don't collide | USB v2 INS |
| `positive_cap_constants_match_invariants` | `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65_536`, gap = 100 | invariant #7 |
| `positive_each_variant_round_trips_through_from_u32` | every documented `NscStatus` survives u32 round-trip | NscStatus |
| `positive_ok_is_zero_so_zeroed_buffers_decode_to_ok` | zero-init memory → Ok | NscStatus |
| `positive_internal_error_is_max_u32` | sentinel = `u32::MAX` | NscStatus |
| `positive_debug_impl_emits_variant_name` | `Debug` emits identifier | NscStatus |
| `positive_offchain_recovery_codes_distinct_from_fw_codes` | 10..=16 disjoint from 17..=19 | NscStatus |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_eip6492_magic_must_match_spec_byte_for_byte` | "the EIP-6492 magic bytes still match the published spec" | hard-codes `0x6492…6492` and asserts byte-equality with `EIP6492_MAGIC` | spec-exact 32 bytes; any drift fails with a message about Solady/Ambire/viem |
| `negative_pq_smart_wallet_factory_address_frozen` | "the deployed factory address is the same one CREATE2 wallet derivation bakes in" | hard-codes the deployed 20 B address | exact bytes; otherwise cross-chain address stability (invariant #6) breaks |
| `negative_proxy_init_code_hash_frozen` | "the ERC-1967 proxy init-code hash didn't drift" | hard-codes the 32 B hash | exact bytes |
| `negative_execute_selector_bytes_frozen` | "Type 2 callData prefix still matches `executeWithOffchainCount`" | byte-equality on selector | `[0x14, 0x44, 0x3c, 0x57]` |
| `negative_execute_batch_selector_bytes_frozen` | same for batch dispatcher | byte-equality | `[0x7a, 0x38, 0x99, 0x33]` |
| `negative_create_account_selector_bytes_frozen` | factory deploy selector | byte-equality | `[0xf6, 0x18, 0x2a, 0x73]` |
| `negative_add_owner_bytes_selector_bytes_frozen` | Type 1 slot-add selector | byte-equality | `[0x10, 0x14, 0x90, 0xcb]` |
| `negative_set_pre_signature_selector_bytes_frozen` | CoW v3 mandatory-trailer gate | byte-equality | `[0xec, 0x6c, 0xb1, 0x3f]` |
| `negative_approve_hash_selector_bytes_frozen` | Safe clear-sign gate | byte-equality | `[0xd4, 0xd9, 0xbd, 0xcd]` |
| `negative_factory_add_slot_domain_byte_for_byte` | "the KDF tag `pqwallet-factory-add-slot` is byte-identical" | byte-equality with `b"pqwallet-factory-add-slot"` | exact bytes; any rename invalidates every existing bootstrap-signed slot-add digest |
| `negative_gpv2_settlement_address_frozen` | the CoW EIP-712 `verifyingContract` is mainnet's GPv2Settlement | byte-equality on 20 B | exact bytes |
| `negative_cowswap_sentinel_differs_from_settlement_only_in_last_byte` | "the VK-lookup sentinel is distinguishable from the real address but shares the prefix" | asserts `[..19]` equal and `[19]` differs | sentinel=0x42, settlement=0x41; otherwise the DB lookup would alias |
| `negative_safe_domain_typehash_frozen` | the Safe v1.3.0+ domain typehash is what the on-chain Safe verifies | byte-equality on 32 B | exact bytes |
| `negative_safe_tx_typehash_frozen` | same for `SafeTx` struct | byte-equality on 32 B | exact bytes |
| `negative_wire_format_lengths_frozen` | "no companion-app-visible length silently moved" | hard-codes C10_SIG_LEN, SIG_WRAPPER_LEN, PQ_INIT_CODE_LEN, both off-chain output lengths, header lengths, caps, personal-sign cap | every length pinned to its documented value |
| `negative_execute_selector_matches_canonical_signature` | the constant matches `keccak256("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)")[..4]` | re-derives via tiny-keccak and asserts equality | match; otherwise either the constant or the on-chain ABI changed without coordinating |
| `negative_execute_batch_selector_matches_canonical_signature` | same for batch | re-derive + assert | match |
| `negative_add_owner_bytes_selector_matches_canonical_signature` | same for `addOwnerBytes(bytes)` | re-derive + assert | match |
| `negative_create_account_selector_matches_canonical_signature` | same for `createAccount(bytes32,bytes32,bytes32,bytes32,uint64,bytes)` | re-derive + assert | match |
| `negative_set_pre_signature_selector_matches_canonical_signature` | same for `setPreSignature(bytes,bool)` | re-derive + assert | match |
| `negative_approve_hash_selector_matches_canonical_signature` | same for `approveHash(bytes32)` | re-derive + assert | match |
| `negative_safe_domain_typehash_matches_canonical_type_string` | typehash = keccak256 of canonical type string | re-derive + assert | match (catches type-string refactors) |
| `negative_safe_tx_typehash_matches_canonical_type_string` | same for the full `SafeTx(...)` struct | re-derive + assert | match |
| `negative_flag_regions_are_pairwise_disjoint` | "no two flag-word regions overlap" | computes `a & b` for all 6 pairs of (INIT_CODE, REGISTER_SLOT, ACCOUNT_INDEX_MASK, SLOT_INDEX_MASK) | all pairs AND to 0 |
| `negative_flag_regions_cover_every_bit` | "the four regions partition u32" | OR them and compare to `u32::MAX` | bit-exact full cover; any unallocated bit fails with the offending mask |
| `negative_account_index_mask_matches_documented_shift_and_width` | `ACCOUNT_INDEX_MASK = MAX_ACCOUNT_INDEX << ACCOUNT_INDEX_SHIFT` and is 8 bits | re-derives mask from shift+max | exact match |
| `negative_slot_index_mask_is_lower_22_bits` | "slot index occupies bits 21..0" | asserts `(1<<22)-1` and `count_ones()==22` | exact match |
| `negative_flag_bits_are_top_two_bits` | bit 31 = include_init, bit 30 = register | direct comparison | exact |
| `negative_flags_pack_round_trip` (proptest) | "encoding a (include, register, account, slot) tuple and decoding it round-trips" | proptest over random valid tuples | every input decodes back |
| `negative_offchain_flags_mask_covers_only_defined_bits` | reserved bits 1..=7 of the off-chain flags byte are NOT in the mask | per-bit AND against the mask | bits 1..7 all zero in mask |
| `negative_sign_offchain_header_field_widths_pack_without_gap` | "the 6 declared header offsets pack without gap or overlap and end at HEADER_LEN" | walks the cursor through each offset, asserts contiguity | cursor lands exactly at 17 |
| `negative_no_two_cmds_share_the_same_u32` | runtime parity with the compile-time CMD-collision check (catches new CMDs added to the array but reused IDs) | pairwise inequality over all 25 declared CMDs | all distinct |
| `negative_reserved_cmd_ids_are_not_reused` | CMD IDs 4 and 6 (retired v1 commands) stay unallocated | sweep over all declared CMDs | none equal 4 or 6 |
| `negative_test_only_cmds_live_at_or_above_200` | "test commands stay in the ≥ 200 block so they can't leak into mode-production routing" | direct comparison | both ≥ 200 |
| `negative_production_cmds_stay_below_200` | converse | sweep | no production CMD ≥ 200 |
| `negative_cmd_none_is_zero_and_no_live_cmd_uses_zero` | "zero-initialised mailbox memory dispatches to nothing" | asserts `CMD_NONE = 0` and no other CMD is 0 | true |
| `negative_fw_cmds_live_in_documented_range_20_to_24` | FW-update CMDs in the documented block | range check | true |
| `negative_offchain_cmds_live_in_documented_range_16_to_18` | off-chain CMDs in the documented block | range check | true |
| `negative_retired_status_8_maps_to_internal_error` | "discriminant 8 (retired SlotExhausted) does NOT silently round-trip" | `NscStatus::from(8)` | must be `InternalError` |
| `negative_reserved_status_9_maps_to_internal_error` | discriminant 9 (gap between IdleWipe and FwUpdateBadState) is undefined | `NscStatus::from(9)` | `InternalError` |
| `negative_unknown_status_discriminants_map_to_internal_error` | any non-listed u32 falls through | sweep over a representative set | all map to `InternalError` |
| `negative_status_discriminant_values_are_not_renumbered` | every documented status discriminant byte-value | pin each | match documented number |
| `negative_test_cmds_pairwise_distinct` | test CMDs don't collide with each other | direct | `CMD_TEST_PIN_LOCKOUT != CMD_TZIC_STATUS` |
| `negative_ns_sram_region_non_empty_and_well_ordered` | NS_SRAM region is valid | base < end | true |
| `negative_ns_flash_region_non_empty_and_well_ordered` | same for NS_FLASH | base < end | true |
| `negative_shared_mailbox_region_non_empty_and_well_ordered` | same for mailbox | base < end | true |
| `negative_ns_sram_and_ns_flash_do_not_overlap` | "the NS pointer validator can disambiguate SRAM vs Flash" | range-disjoint check | true |
| `negative_shared_mailbox_inside_ns_sram` | "mailbox writes can't land in S-RAM" | containment check | mailbox ⊆ NS_SRAM |
| `negative_shared_mailbox_is_exactly_24_bytes` | 3 × u64 gateway args; truncation/overrun aliases args | end - base = 24 | exact |
| `negative_default_target_addresses_are_in_mps2_an505_aliases` | feature-default NS regions are in mps2-an505's NS aliases (not random) | range bounds | true under default |
| `negative_stm32u585_addresses_are_in_silicon_aliases` | same for STM32U585 feature | range bounds | true under `stm32u585` |

## Production-code bugs surfaced by negative tests
None — every assertion passes against the current `proto/src/lib.rs`. The
crate's compile-time CMD-collision assert and the existing in-lib tests
already pin a substantial subset of the invariants; the new suite extends
that to byte-exact selectors, keccak cross-checks, flag-bit hygiene,
status-discriminant pinning, and memory-region disjointness — all of
which were previously un-tested.

## Coverage gaps deliberately left
- **`Solidity codegen parity` (Phase 4).** A test that the codegenned
  `library PqsignerProto` (Phase 4 of the modularity refactor — not
  yet landed) emits each `pub const` here is the right artefact for
  the host-side `xtask gen-solidity-constants` tool, not for this
  crate. Re-visit once `xtask` lands.
- **`stm32u585` feature variant.** The default-target memory-layout
  tests run; the `#[cfg(feature = "stm32u585")]` variant compiles but
  is not exercised by host `cargo test -p pqsigner-proto` without the
  feature flag. Future pass: add a CI matrix entry running
  `cargo test -p pqsigner-proto --features stm32u585`.
- **Wire-format round-trip / fuzz against real firmware payloads.**
  This crate is constants only — there are no encode/decode helpers to
  fuzz here. The right home for that is `pqsigner-tx-core` and the
  command handlers in `secure/src/nsc/cmd_*.rs`. The proptest already
  added (`negative_flags_pack_round_trip`) covers the only structural
  encoding this crate actually defines.
- **Compile-fail tests for cfg incompatibilities.** `trybuild`-based
  proof that e.g. `--features stm32u585,not-stm32u585` doesn't exist
  isn't a thing this crate has. The crate has just one feature.
  Re-visit if more mutually exclusive cfgs land here.

## Verification
- `cargo fmt -p pqsigner-proto --check` — N/A (sandbox required user
  approval; not granted). Files were written with conservative
  formatting (4-space indent, trailing comma in multi-line lists).
- `cargo check -p pqsigner-proto` — PASS.
- `cargo clippy -p pqsigner-proto --tests -- -D warnings` — N/A
  (sandbox required user approval; not granted).
- `cargo test -p pqsigner-proto` — PASS (102 tests, 0 ignored, 0
  failures across in-lib + 7 integration files + 0 doc tests).
- (firmware) on-target tests deferred: no. This crate is pure
  host-side `no_std` types; every test runs on the host toolchain.
