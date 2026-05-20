//! Positive functional coverage for `pqsigner-proto` constants and
//! wire-format declarations.
//!
//! The crate has no functions — its public surface is constants and the
//! `NscStatus` enum. These tests assert each declared constant and
//! wire-format layout makes sense **as documented**: offsets monotonic,
//! lengths consistent with their formulas, derived sizes equal to the
//! sum of their parts. The negative suites live alongside in
//! `negative_*.rs`.

use pqsigner_proto::*;

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_USEROP (legacy v3) layout
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_legacy_userop_header_layout_sums() {
    // 1 (mode) + 20 (sender) + 20 (entry_point) + 8 (chain_id)
    // + 8 × 32 (nonce, 5×gas, init_code_hash, paymaster_hash) = 305
    let expected = 1 + 20 + 20 + 8 + 8 * 32;
    assert_eq!(
        USEROP_HEADER_LEN, expected,
        "USEROP_HEADER_LEN doc/formula mismatch"
    );
    assert_eq!(USEROP_PREFIX_LEN, USEROP_HEADER_LEN + 4);
}

// ───────────────────────────────────────────────────────────────────────
// Unified CMD_SIGN_USEROP v4 wire format
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_unified_userop_header_layout_sums() {
    // chain_id(8) + flags(4) + sender(20) + ep(20) + nonce(32)
    // + 5×gas(160) + paymaster_hash(32) + to(20) + value(32) + data_len(2)
    let expected = 8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 20 + 32 + 2;
    assert_eq!(SIGN_USEROP_HEADER_LEN, expected);
    assert_eq!(SIGN_USEROP_HEADER_LEN, 330);
}

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_USEROP_BATCH wire format
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_batch_header_layout_sums() {
    // chain_id(8) + flags(4) + sender(20) + ep(20) + nonce(32)
    // + 5×gas(160) + paymaster_hash(32) + wire_version(1) + batch_count(1)
    let expected = 8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 1 + 1;
    assert_eq!(SIGN_USEROP_BATCH_HEADER_LEN, expected);
    assert_eq!(SIGN_USEROP_BATCH_HEADER_LEN, 278);
}

#[test]
fn positive_batch_wire_version_is_two() {
    // Bump v1 → v2 when the TLV trailer list landed (batch-sign parity
    // with single-tx). Firmware refuses any other value.
    assert_eq!(SIGN_USEROP_BATCH_WIRE_VERSION, 2);
}

#[test]
fn positive_batch_tx_prefix_layout_sums() {
    // to(20) + value(32) + data_len(2)
    assert_eq!(SIGN_USEROP_BATCH_TX_PREFIX_LEN, 54);
    assert_eq!(SIGN_USEROP_BATCH_TX_PREFIX_LEN, 20 + 32 + 2);
}

#[test]
fn positive_batch_trailer_record_header_sums() {
    // kind(1) + tx_idx(1) + len(u16 BE, 2)
    assert_eq!(SIGN_USEROP_BATCH_TRAILER_HEADER_LEN, 4);
    assert_eq!(SIGN_USEROP_BATCH_TRAILER_HEADER_LEN, 1 + 1 + 2);
}

#[test]
fn positive_batch_trailer_kind_enum_values_stable() {
    // Pinned: the wire dispatch table on the secure side matches each
    // const by value, so renumbering breaks deployed companions.
    assert_eq!(TRAILER_KIND_ERC20, 1);
    assert_eq!(TRAILER_KIND_ZK_V1, 2);
    assert_eq!(TRAILER_KIND_ZK_V3, 3);
    assert_eq!(TRAILER_KIND_SAFE_V1, 4);
    assert_eq!(TRAILER_KIND_SEL_CURATED, 5);
    assert_eq!(TRAILER_KIND_SEL_SELFATTEST, 6);
    assert_eq!(TRAILER_KIND_ERC7730, 7);
    assert_eq!(TRAILER_KIND_NAME, 8);
    assert_eq!(TRAILER_TX_IDX_BATCH_WIDE, 0xff);
}

#[test]
fn positive_max_trailers_per_batch_covers_worst_case() {
    // Realistic worst case: every inner tx carries six per-tx kinds
    // (ERC-20, ZK_V1, ZK_V3, SAFE_V1, ERC-7730, plus one of
    // SEL_CURATED XOR SEL_SELFATTEST since they're mutually exclusive),
    // plus the four batch-wide name bundles.
    let worst_case = MAX_BATCH_TXS * 6 + 4 /* MAX_NAME_BUNDLES */;
    assert!(
        MAX_TRAILERS_PER_BATCH >= worst_case,
        "MAX_TRAILERS_PER_BATCH ({}) must bound worst case ({})",
        MAX_TRAILERS_PER_BATCH,
        worst_case
    );
}

#[test]
fn positive_batch_max_payload_includes_trailers_budget() {
    // v2 wire: header + N × (tx_prefix + data) + trailer_count(1)
    //         + MAX_TRAILERS_PER_BATCH × per-record-header
    //         + TRAILERS_TOTAL_MAX_LEN.
    let expected = SIGN_USEROP_BATCH_HEADER_LEN
        + MAX_BATCH_TXS * (SIGN_USEROP_BATCH_TX_PREFIX_LEN + MAX_TX_LEN)
        + 1
        + MAX_TRAILERS_PER_BATCH * SIGN_USEROP_BATCH_TRAILER_HEADER_LEN
        + TRAILERS_TOTAL_MAX_LEN;
    assert_eq!(SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN, expected);
}

#[test]
fn positive_trailers_total_max_len_bounded() {
    // 24 KB outer budget. Keeps SNAP_BUF in the ~41 KB range — well
    // inside the secure SRAM budget but generous enough for realistic
    // mixed-trailer batches.
    assert_eq!(TRAILERS_TOTAL_MAX_LEN, 24 * 1024);
    assert!(TRAILERS_TOTAL_MAX_LEN <= 64 * 1024); // sanity: not a runaway
}

#[test]
fn positive_max_execute_batch_calldata_bounds_reconstructed_calldata() {
    // Worst-case 4 inner txs each at 4096 B data:
    //   selector(4) + head(160)
    // + targets[](32 + 4×32) + values[](32 + 4×32) + datas[](32 + 4×32)
    // + 4 × (length(32) + padded_data(4096))
    let computed = 4 + 5 * 32 + (32 + 4 * 32) * 3 + 4 * (32 + 4096);
    assert!(
        MAX_EXECUTE_BATCH_CALLDATA_LEN >= computed,
        "MAX_EXECUTE_BATCH_CALLDATA_LEN ({}) must bound the computed worst-case ({})",
        MAX_EXECUTE_BATCH_CALLDATA_LEN,
        computed
    );
}

// ───────────────────────────────────────────────────────────────────────
// Signature wrapper / Type 1/Type 2 lengths
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_signature_len_and_padding() {
    assert_eq!(SIGNATURE_LEN, 4_008);
    assert_eq!(C10_SIG_LEN, SIGNATURE_LEN);
    let padded = SIGNATURE_LEN.next_multiple_of(32);
    assert_eq!(padded, 4_032);
    assert_eq!(padded % 32, 0);
}

#[test]
fn positive_sig_wrapper_matches_solidity_encoding() {
    // abi.encode(uint256, bytes):
    //   head: ownerIndex(32) + bytes_offset(32) = 64
    //   tail: bytes_length(32) + padded_data(4032) = 4064
    assert_eq!(SIG_WRAPPER_LEN, 4_128);
    assert_eq!(SIG_WRAPPER_LEN, 32 + 32 + 32 + 4_032);
    assert_eq!(SIG_TYPE1_LEN, SIG_WRAPPER_LEN);
    assert_eq!(SIG_TYPE2_LEN, SIG_WRAPPER_LEN);
    assert_eq!(SIG_TYPE2_HEADER_LEN, 96);
}

// ───────────────────────────────────────────────────────────────────────
// initCode (PQ_INIT_CODE_LEN) breakdown
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_pq_init_code_len_breakdown() {
    // factory(20) + selector(4) + 5×bytes32(160) + offset(32)
    // + bytes_length(32) + padded_sig(4032)
    let expected = 20 + 4 + 5 * 32 + 32 + 32 + SIGNATURE_LEN.next_multiple_of(32);
    assert_eq!(PQ_INIT_CODE_LEN, expected);
    assert_eq!(PQ_INIT_CODE_LEN, 4_280);
}

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_OFFCHAIN / EIP-6492 layouts
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_sign_offchain_header_offsets_are_monotonic_and_contiguous() {
    // account(1) | chain(8) | slot(4) | kind(1) | payload_len(2) | flags(1)
    assert_eq!(SIGN_OFFCHAIN_INPUT_ACCOUNT_OFF, 0);
    assert_eq!(SIGN_OFFCHAIN_INPUT_CHAIN_OFF, 1);
    assert_eq!(SIGN_OFFCHAIN_INPUT_SLOT_OFF, 9);
    assert_eq!(SIGN_OFFCHAIN_INPUT_KIND_OFF, 13);
    assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, 14);
    assert_eq!(SIGN_OFFCHAIN_INPUT_FLAGS_OFF, 16);
    assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF, 17);
    assert_eq!(SIGN_OFFCHAIN_HEADER_LEN, 17);
}

#[test]
fn positive_sign_offchain_output_deployed_layout() {
    // [count(8)] [c10_sig(4008)]
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, 0);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_SIG_OFF, 8);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 8 + C10_SIG_LEN);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 4_016);
}

#[test]
fn positive_sign_offchain_max_input_bounds_personal_sign() {
    // Phase 3 (ERC-7730) added an optional EIP-712 typed-data path
    // (MAX_OFFCHAIN_EIP712_TYPED_LEN) plus an attestation trailer.
    // The max-input bound is now the longer of the two payload
    // shapes + the trailer:
    //   header + max(personal_sign, eip712_typed_len_with_trailer).
    assert_eq!(
        SIGN_OFFCHAIN_INPUT_MAX_LEN,
        SIGN_OFFCHAIN_HEADER_LEN
            + core::cmp::max(
                MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
                MAX_OFFCHAIN_EIP712_TYPED_LEN,
            )
    );
    assert_eq!(MAX_OFFCHAIN_PERSONAL_SIGN_LEN, 700);
}

#[test]
fn positive_eip6492_blob_breakdown() {
    // 96 head + 32 fc_len + fc_padded + 32 sig_len + inner_sig + 32 magic
    let computed = 96
        + 32
        + EIP6492_FACTORY_CALLDATA_PADDED
        + 32
        + EIP6492_INNER_WRAPPER_LEN
        + 32;
    assert_eq!(EIP6492_BLOB_LEN, computed);
    assert_eq!(EIP6492_BLOB_LEN, 8_608);
    assert_eq!(
        EIP6492_FACTORY_CALLDATA_LEN,
        PQ_INIT_CODE_LEN - 20,
        "factoryCalldata is initCode minus the 20-byte factory prefix"
    );
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4_260);
    assert_eq!(EIP6492_FACTORY_CALLDATA_PADDED, 4_288);
    assert_eq!(EIP6492_FACTORY_CALLDATA_PADDED % 32, 0);
    assert_eq!(EIP6492_INNER_WRAPPER_LEN, SIG_WRAPPER_LEN);
    assert_eq!(EIP6492_INNER_WRAPPER_LEN % 32, 0);
}

#[test]
fn positive_sign_offchain_output_6492_layout() {
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8 + EIP6492_BLOB_LEN);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8_616);
}

// ───────────────────────────────────────────────────────────────────────
// CMD_OFFCHAIN_STATUS / CMD_OFFCHAIN_SYNC layouts
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_offchain_status_input_layout() {
    // account(1) + chain(8) + slot(4) = 13
    assert_eq!(OFFCHAIN_STATUS_INPUT_LEN, 13);
}

#[test]
fn positive_offchain_status_output_layout() {
    // local(8) + last_userop(8) + registered(1) + reserved(7) = 24
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LEN, 24);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF, 0);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF, 8);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF, 16);
}

#[test]
fn positive_offchain_sync_input_layout() {
    // account(1) + chain(8) + slot(4) + target(8) = 21
    assert_eq!(OFFCHAIN_SYNC_INPUT_LEN, 21);
}

// ───────────────────────────────────────────────────────────────────────
// MAX_SIGN_RESPONSE_LEN — must cover every CMD_SIGN_* response shape
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_max_sign_response_covers_unified_sign_full_bundle() {
    // 8 (count) + 4 + initCode + 4 + type1 + 4 + type2
    let expected = 8 + 4 + PQ_INIT_CODE_LEN + 4 + SIG_TYPE1_LEN + 4 + SIG_TYPE2_LEN;
    assert_eq!(MAX_SIGN_RESPONSE_LEN, expected);
}

#[test]
fn positive_max_sign_response_covers_eip6492_output() {
    assert!(
        MAX_SIGN_RESPONSE_LEN >= SIGN_OFFCHAIN_OUTPUT_LEN_6492,
        "MAX_SIGN_RESPONSE_LEN must also fit the largest CMD_SIGN_OFFCHAIN output"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Firmware-update wire format
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_fw_status_response_offsets() {
    // state(1) + recv_s(4) + recv_ns(4) + slot(1) = 10
    assert_eq!(FW_STATUS_RESPONSE_LEN, 10);
    assert_eq!(FW_STATUS_STATE_OFFSET, 0);
    assert_eq!(FW_STATUS_RECV_S_OFFSET, 1);
    assert_eq!(FW_STATUS_RECV_NS_OFFSET, 5);
    assert_eq!(FW_STATUS_SLOT_OFFSET, 9);
}

#[test]
fn positive_fw_chunk_header_distinct_kind_bytes() {
    assert_eq!(FW_CHUNK_HEADER_LEN, 8);
    assert_ne!(FW_IMAGE_KIND_SECURE, FW_IMAGE_KIND_NONSECURE);
    assert_eq!(FW_IMAGE_KIND_SECURE, 0);
    assert_eq!(FW_IMAGE_KIND_NONSECURE, 1);
}

#[test]
fn positive_fw_states_pairwise_distinct() {
    assert_ne!(FW_STATE_IDLE, FW_STATE_RECEIVING);
    assert_ne!(FW_STATE_RECEIVING, FW_STATE_STAGED);
    assert_ne!(FW_STATE_IDLE, FW_STATE_STAGED);
}

// ───────────────────────────────────────────────────────────────────────
// CMD_SIGN_USEROP execute-calldata bound
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_max_execute_calldata_covers_worst_case() {
    // selector(4) + head(5×32=160) + bytes_offset(32) + bytes_length(32)
    // + padded_data(4096) = 4356
    let worst = 4 + 5 * 32 + 32 + 32 + MAX_TX_LEN;
    assert!(
        MAX_EXECUTE_CALLDATA_LEN >= worst,
        "MAX_EXECUTE_CALLDATA_LEN ({}) must bound the worst case ({})",
        MAX_EXECUTE_CALLDATA_LEN,
        worst
    );
}

// ───────────────────────────────────────────────────────────────────────
// CoW Protocol v3 trailer layout
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_zk_v3_layout_sums() {
    assert_eq!(
        ZK_V3_FIXED_LEN,
        EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN
    );
    assert_eq!(ZK_V3_OFF_CANONICAL, EIP712_PROOF_LEN);
    assert_eq!(
        ZK_V3_OFF_READABLE,
        ZK_V3_OFF_CANONICAL + EIP712_CANONICAL_LEN
    );
    // Spec EIP-712 canonical packed GPv2Order: 204 B
    assert_eq!(EIP712_CANONICAL_LEN, 204);
    // 8×16 readable
    assert_eq!(EIP712_STRING_LEN, 128);
    // Groth16 proof π.A(96)+π.B(192)+π.C(96)
    assert_eq!(EIP712_PROOF_LEN, 384);
    assert_eq!(EIP712_PROOF_LEN, ZK_PROOF_LEN);
}

// ───────────────────────────────────────────────────────────────────────
// Safe v1 canonical layout — offsets contiguous and end at canonical_len
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_safe_v1_canonical_offsets_contiguous() {
    assert_eq!(SAFE_OFF_CHAIN_ID, 0);
    assert_eq!(SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_CHAIN_ID + 8);
    assert_eq!(SAFE_OFF_TO, SAFE_OFF_SAFE_ADDRESS + 20);
    assert_eq!(SAFE_OFF_VALUE, SAFE_OFF_TO + 20);
    assert_eq!(SAFE_OFF_DATA_HASH, SAFE_OFF_VALUE + 32);
    assert_eq!(SAFE_OFF_OPERATION, SAFE_OFF_DATA_HASH + 32);
    assert_eq!(SAFE_OFF_SAFE_TX_GAS, SAFE_OFF_OPERATION + 1);
    assert_eq!(SAFE_OFF_BASE_GAS, SAFE_OFF_SAFE_TX_GAS + 32);
    assert_eq!(SAFE_OFF_GAS_PRICE, SAFE_OFF_BASE_GAS + 32);
    assert_eq!(SAFE_OFF_GAS_TOKEN, SAFE_OFF_GAS_PRICE + 32);
    assert_eq!(SAFE_OFF_REFUND_RECEIVER, SAFE_OFF_GAS_TOKEN + 20);
    assert_eq!(SAFE_OFF_NONCE, SAFE_OFF_REFUND_RECEIVER + 20);
    assert_eq!(SAFE_OFF_NONCE + 32, SAFE_V1_CANONICAL_LEN);
    assert_eq!(SAFE_V1_CANONICAL_LEN, 281);
}

#[test]
fn positive_safe_v1_payload_max_includes_canonical_plus_raw_data() {
    assert_eq!(
        SAFE_V1_PAYLOAD_MAX,
        SAFE_V1_CANONICAL_LEN + 2 + SAFE_V1_RAW_DATA_MAX
    );
    assert_eq!(SAFE_V1_RAW_DATA_MAX, MAX_TX_LEN);
    assert_eq!(APPROVE_HASH_CALLDATA_LEN, 4 + 32);
}

// ───────────────────────────────────────────────────────────────────────
// Memory-layout regions
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_ns_sram_region_nonempty_and_ordered() {
    assert!(NS_SRAM_BASE < NS_SRAM_END);
    assert!(NS_SRAM_END - NS_SRAM_BASE >= 0x10_000); // at least 64 KB
}

#[test]
fn positive_ns_flash_region_nonempty_and_ordered() {
    assert!(NS_FLASH_BASE < NS_FLASH_END);
}

#[test]
fn positive_shared_mailbox_region_inside_or_adjacent_ns_sram() {
    assert!(SHARED_MAILBOX_BASE < SHARED_MAILBOX_END);
    // Mailbox is documented as living "at end of NS SRAM"
    assert!(SHARED_MAILBOX_END <= NS_SRAM_END);
    // 24-byte mailbox (3 × u64 args) per docs
    assert_eq!(SHARED_MAILBOX_END - SHARED_MAILBOX_BASE, 0x18);
}

// ───────────────────────────────────────────────────────────────────────
// USB / APDU surface
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_usb_hid_constants() {
    assert_eq!(HID_REPORT_SIZE, 64); // USB Full-Speed interrupt EP
    assert_ne!(HID_TAG_APDU, HID_TAG_PING);
    assert_eq!(HID_TAG_APDU, 0x05);
    assert_eq!(HID_TAG_PING, 0x02);
}

#[test]
fn positive_apdu_protocol_version_is_v2() {
    assert_eq!(PROTOCOL_VERSION, 0x0200);
    assert_eq!(APDU_CLA_V2, 0xF0);
    assert_eq!(APDU_MAX_RESP, 253);
}

#[test]
fn positive_status_words_pairwise_distinct() {
    let sws: &[u16] = &[
        SW_OK,
        SW_CONDITIONS_NOT_SATISFIED,
        SW_SECURITY_NOT_SATISFIED,
        SW_WRONG_DATA,
        SW_WRONG_LENGTH,
        SW_INS_NOT_SUPPORTED,
        SW_CLA_NOT_SUPPORTED,
        SW_FEATURE_NOT_SUPPORTED,
        SW_INTERNAL_ERROR,
        SW_REFERENCED_DATA_INVALIDATED,
    ];
    for i in 0..sws.len() {
        for j in (i + 1)..sws.len() {
            assert_ne!(
                sws[i], sws[j],
                "status words at index {i} and {j} collide"
            );
        }
    }
    assert_eq!(SW_OK, 0x9000);
}

#[test]
fn positive_pin_and_constants() {
    assert_eq!(PIN_LEN, 8);
    assert_eq!(MAX_ATTEMPTS, 10);
    assert_eq!(TX_HASH_LEN, 32);
    assert_eq!(SIGNING_KEY_LEN, 48); // sk_seed(32) + pk_seed(16)
    assert_eq!(VERIFYING_KEY_LEN, 32); // pk_seed(16) + pk_root(16)
    assert_eq!(OWNER_BYTES_LEN, 64);
}

#[test]
fn positive_ins_v2_codes_pairwise_distinct() {
    let codes: &[u8] = &[
        INS_V2_GET_DEVICE_INFO,
        INS_V2_GET_STATUS,
        INS_V2_UNLOCK,
        INS_V2_LOCK,
        INS_V2_SIGN_USEROP,
        INS_V2_SIGN_USEROP_BATCH,
        INS_V2_GET_WALLET_ADDRESS,
        INS_V2_GET_INIT_CODE,
        INS_V2_SIGN_OFFCHAIN,
        INS_V2_OFFCHAIN_STATUS,
        INS_V2_OFFCHAIN_SYNC,
        INS_V2_FW_BEGIN,
        INS_V2_FW_CHUNK,
        INS_V2_FW_COMMIT,
        INS_V2_FW_STATUS,
        INS_V2_FW_ABORT,
        INS_V2_GET_RESPONSE,
    ];
    for i in 0..codes.len() {
        for j in (i + 1)..codes.len() {
            assert_ne!(
                codes[i], codes[j],
                "INS_V2 codes at index {i} and {j} collide"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// Cap / budget invariants
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_cap_constants_match_invariants() {
    // Invariant #7: per-chain caps are 65,536, monotonic, unresettable.
    assert_eq!(MAX_BOOTSTRAP_USES, 65_536);
    assert_eq!(MAX_SLOT_USES, 65_536);
    // Documented bound on unbacked off-chain sigs.
    assert_eq!(MAX_OFFCHAIN_GAP, 100);
}
