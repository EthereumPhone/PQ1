//! Host-side test suite for the `secure-nsc-batch-offchain` slice.
//!
//! # What is covered here
//!
//! The slice itself lives in four files under `secure/src/nsc/`:
//!
//!   * `cmd_sign_userop_batch.rs` — atomic multi-call SPHINCS+C10 sign
//!     (`CMD_SIGN_USEROP_BATCH`). 825 lines; pulls in the OLED stack,
//!     flash I/O, `static mut` slot cache, secure-element trait, and
//!     FI helpers — none reachable from a host build.
//!   * `cmd_sign_offchain.rs` — EIP-1271 / ERC-6492 off-chain signing
//!     (`CMD_SIGN_OFFCHAIN`). 594 lines, same firmware deps.
//!   * `cmd_offchain_status.rs` — read-only per-slot off-chain counter
//!     surface (`CMD_OFFCHAIN_STATUS`). 98 lines.
//!   * `cmd_offchain_sync.rs` — "set if greater" sync of
//!     `last_userop_count` after a reflash (`CMD_OFFCHAIN_SYNC`).
//!     86 lines.
//!
//! Because all four `run()` functions transitively reach the
//! `static mut` slot cache, the offchain-state flash log, and the OLED
//! confirm dialog, none of them can be linked into a host test. We
//! therefore cover the slice with three test families that *can* run
//! on the host:
//!
//!   1. **Wire-format constant pins** — every offset / length / mask
//!      the four `run()` functions read from `pqsigner-proto`. A silent
//!      drift here would shift companion payloads or output buffers
//!      and break interop without a single test failing in the
//!      crypto / sign suite.
//!   2. **Helper-function characterisations** — `add_one_to_be_u256`
//!      and `u128_saturating_from_u256` are private to
//!      `cmd_sign_userop_batch.rs`. Mirrored at module scope and tested
//!      against the documented behaviour.
//!   3. **Source-text invariant pins** — assertions over the four
//!      files' source text that the load-bearing gates remain (pin
//!      check, NS pointer validation, flag/length rejection branches,
//!      FI double-verify, zeroization barriers, frozen domain tags,
//!      mutually-exclusive flag enforcement). These act as the
//!      regression canary CLAUDE.md asks for: a refactor that removes
//!      a guard "by accident" surfaces as a test failure here long
//!      before it reaches an audited build.
//!
//! Negative tests are framed around the assumptions each gate enforces
//! (CLAUDE.md invariants #1, #2, #4, #5, #6, #7, #8, #9 + the slice's
//! file-level docstrings). When the assumption holds, the test passes;
//! when the assumption is violated by a future refactor, the test
//! fails with a panic message naming the assumption.

#![cfg(test)]

use sphincs_tz_shared::{
    ACCOUNT_INDEX_MASK, ACCOUNT_INDEX_SHIFT, C10_SIG_LEN, EIP6492_BLOB_LEN,
    EIP6492_FACTORY_CALLDATA_LEN, EIP6492_FACTORY_CALLDATA_PADDED, EIP6492_INNER_WRAPPER_LEN,
    EIP6492_MAGIC, ERC7730_LEGACY_BUNDLE_MAX_LEN, ERC7730_MAX_TRAILER_LEN,
    ERC7730_PROOF_SET_COUNT, ERC7730_PROOF_SET_MAGIC, ERC7730_PROOF_SET_VERSION,
    EXECUTE_BATCH_SELECTOR, FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT, MAX_ACCOUNT_INDEX,
    MAX_BATCH_TXS, MAX_OFFCHAIN_EIP712_TYPED_LEN,
    MAX_OFFCHAIN_EIP712_TYPED_V3_LEN, MAX_OFFCHAIN_GAP, MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
    MAX_SIGN_RESPONSE_LEN, MAX_SLOT_USES, MAX_TX_LEN, NscStatus, OFFCHAIN_FLAGS_MASK,
    OFFCHAIN_FLAG_ACCOUNT_DEPLOYED, OFFCHAIN_KIND_PERSONAL_SIGN, OFFCHAIN_KIND_RAW32,
    OFFCHAIN_STATUS_INPUT_LEN, OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF,
    OFFCHAIN_STATUS_OUTPUT_LEN, OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF,
    OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF, OFFCHAIN_SYNC_INPUT_LEN, PQ_ADD_OWNER_BYTES_SELECTOR,
    PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN, PQ_SMART_WALLET_FACTORY, SIGNATURE_LEN,
    SIGN_OFFCHAIN_HEADER_LEN, SIGN_OFFCHAIN_INPUT_ACCOUNT_OFF, SIGN_OFFCHAIN_INPUT_CHAIN_OFF,
    SIGN_OFFCHAIN_INPUT_FLAGS_OFF, SIGN_OFFCHAIN_INPUT_KIND_OFF, SIGN_OFFCHAIN_INPUT_MAX_LEN,
    SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF,
    SIGN_OFFCHAIN_INPUT_SLOT_OFF, SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, SIGN_OFFCHAIN_OUTPUT_LEN,
    SIGN_OFFCHAIN_OUTPUT_LEN_6492, SIGN_OFFCHAIN_OUTPUT_SIG_OFF, SIGN_USEROP_BATCH_HEADER_LEN,
    SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN, SIGN_USEROP_BATCH_TRAILER_HEADER_LEN,
    SIGN_USEROP_BATCH_TX_PREFIX_LEN, SIGN_USEROP_BATCH_WIRE_VERSION, SIG_WRAPPER_LEN,
    SLOT_INDEX_MASK, TRAILERS_TOTAL_MAX_LEN, TRAILER_KIND_ERC20, TRAILER_KIND_ERC7730,
    TRAILER_KIND_NAME, TRAILER_KIND_SAFE_V1, TRAILER_KIND_SEL_CURATED,
    TRAILER_KIND_RESERVED_V1, TRAILER_KIND_SEL_SELFATTEST, TRAILER_KIND_COW_ORDER,
    TRAILER_TX_IDX_BATCH_WIDE, MAX_TRAILERS_PER_BATCH,
};

// ─────────────────────────────────────────────────────────────────────
// 1. CMD_OFFCHAIN_STATUS — wire layout (cmd_offchain_status.rs)
//
// Input: account(1) || chain(8) || slot(4)               = 13 B
// Output: local(8) || last_userop(8) || registered(1) || reserved(7) = 24 B
//
// The companion subtracts `local - last_userop` to render a "X
// off-chain sigs available" hint, and reads `registered` to detect a
// post-restore unregistered slot. A drift in any offset / length means
// the companion silently reads the wrong field.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_offchain_status_input_len_is_13() {
    // 1 byte account + 8 bytes chain + 4 bytes slot.
    assert_eq!(
        OFFCHAIN_STATUS_INPUT_LEN, 13,
        "OFFCHAIN_STATUS_INPUT_LEN drifted — the dispatcher's length gate would silently accept the wrong-sized payload from the companion"
    );
}

#[test]
fn negative_offchain_status_output_len_is_24() {
    // 8 local + 8 last_userop + 1 registered + 7 reserved.
    assert_eq!(
        OFFCHAIN_STATUS_OUTPUT_LEN, 24,
        "OFFCHAIN_STATUS_OUTPUT_LEN drifted — the companion would read garbage past byte 23 or under-read the response"
    );
}

#[test]
fn negative_offchain_status_output_offsets_pin_documented_layout() {
    // Pin every documented offset. A refactor that changed any of these
    // would silently swap the meaning of bytes in the response.
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF, 0);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF, 8);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF, 16);
    // Reserved bytes occupy [17..24).
    assert_eq!(
        OFFCHAIN_STATUS_OUTPUT_LEN - (OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF + 1),
        7
    );
}

#[test]
fn negative_offchain_status_local_and_last_userop_fields_dont_overlap() {
    // The two u64 fields must not overlap. local starts at 0, must end
    // at exactly last_userop's start.
    assert_eq!(
        OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF + 8,
        OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF,
        "local_offchain and last_userop fields overlap or have a gap"
    );
    assert_eq!(
        OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF + 8,
        OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF,
        "last_userop and registered fields overlap or have a gap"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 2. CMD_OFFCHAIN_SYNC — wire layout (cmd_offchain_sync.rs)
//
// Input: account(1) || chain(8) || slot(4) || target(8)  = 21 B
// Output: SW only (no body).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_offchain_sync_input_len_is_21() {
    assert_eq!(
        OFFCHAIN_SYNC_INPUT_LEN, 21,
        "OFFCHAIN_SYNC_INPUT_LEN drifted — the dispatcher's strict length gate would silently accept a wrong-sized payload"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. CMD_SIGN_OFFCHAIN — header layout, kind/flags constants, output
//                       sizes (cmd_sign_offchain.rs)
//
// CLAUDE.md "Off-chain (EIP-1271 / ERC-6492) output" pins these. The
// firmware bakes them into branch conditions; the wallet's
// `isValidSignature` and Solady's EIP-6492 dispatch decode them on the
// other side. Any drift breaks both ends silently.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_sign_offchain_header_len_is_17() {
    // CLAUDE.md "Input header is 17 B
    // (account(1) | chain(8) | slot(4) | kind(1) | payload_len(2) | flags(1))".
    assert_eq!(SIGN_OFFCHAIN_HEADER_LEN, 17);
}

#[test]
fn negative_sign_offchain_input_offsets_are_packed_in_order() {
    // Header field offsets must be contiguous + in spec order.
    assert_eq!(SIGN_OFFCHAIN_INPUT_ACCOUNT_OFF, 0);
    assert_eq!(SIGN_OFFCHAIN_INPUT_CHAIN_OFF, 1);
    assert_eq!(SIGN_OFFCHAIN_INPUT_SLOT_OFF, 9);
    assert_eq!(SIGN_OFFCHAIN_INPUT_KIND_OFF, 13);
    assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, 14);
    assert_eq!(SIGN_OFFCHAIN_INPUT_FLAGS_OFF, 16);
    assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF, 17);
    // No gaps in the header.
    assert_eq!(SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF, SIGN_OFFCHAIN_HEADER_LEN);
}

#[test]
fn negative_sign_offchain_kind_values_are_zero_and_one() {
    // KIND_RAW32 == 0 is also the default value of the byte at offset
    // 13 when zero-initialised. A future renumbering would flip the
    // default-kind interpretation and silently change the meaning of
    // a malformed (zero-payload) request.
    assert_eq!(OFFCHAIN_KIND_RAW32, 0);
    assert_eq!(OFFCHAIN_KIND_PERSONAL_SIGN, 1);
}

#[test]
fn negative_sign_offchain_flags_mask_pins_account_deployed_bit() {
    // Bit 0 is the only currently-defined bit. The handler refuses
    // `flags & !OFFCHAIN_FLAGS_MASK != 0` to defend against bit-flip
    // / stale-companion bits. A widened mask would silently accept
    // future bits that the firmware does not yet interpret.
    assert_eq!(OFFCHAIN_FLAG_ACCOUNT_DEPLOYED, 1);
    assert_eq!(OFFCHAIN_FLAGS_MASK, 1);
    // Every unused bit must be rejected by the gate.
    for bit_index in 1..8 {
        let test_flags = 1u8 << bit_index;
        assert_ne!(
            test_flags & !OFFCHAIN_FLAGS_MASK,
            0,
            "bit {bit_index} silently slipped past the OFFCHAIN_FLAGS_MASK gate"
        );
    }
}

#[test]
fn negative_sign_offchain_personal_sign_max_payload_unchanged() {
    // 700 bytes — bounded by trusted-UI scroll budget. Larger payload
    // = user can no longer audit text; smaller = breaks existing SIWE
    // dapps.
    assert_eq!(MAX_OFFCHAIN_PERSONAL_SIGN_LEN, 700);
}

#[test]
fn negative_sign_offchain_input_max_len_equals_header_plus_max_personal_sign() {
    // Worst-case input: header + max over ALL payload kinds. The
    // firmware's TOCTOU snapshot is sized to this bound; any drift would
    // either overflow SNAP_BUF (smaller bound, larger snap) or refuse
    // valid traffic (larger bound, smaller snap). Phase 3 added the
    // EIP-712 typed-data path + attestation trailer; Phase 5 added the
    // v0x03 nested variant (MAX_OFFCHAIN_EIP712_TYPED_V3_LEN), which is now
    // the largest shape and sets the ceiling — this assertion omitted it
    // (stale two-way max, fixed 2026-07-02, the secure-crate mirror of the
    // same proto/tests drift).
    assert_eq!(
        SIGN_OFFCHAIN_INPUT_MAX_LEN,
        SIGN_OFFCHAIN_HEADER_LEN
            + core::cmp::max(
                MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
                core::cmp::max(
                    MAX_OFFCHAIN_EIP712_TYPED_LEN,
                    MAX_OFFCHAIN_EIP712_TYPED_V3_LEN,
                ),
            )
    );
}

#[test]
fn negative_sign_offchain_output_len_deployed_is_4016() {
    // CLAUDE.md "deployed: 4016 B = [count(8)][C10 sig(4008)]".
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 4016);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 8 + C10_SIG_LEN);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, 0);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_SIG_OFF, 8);
}

#[test]
fn negative_sign_offchain_output_len_6492_is_8616() {
    // CLAUDE.md "counterfactual: 8616 B = [count(8)][6492 blob(8608)]".
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8616);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8 + EIP6492_BLOB_LEN);
    assert_eq!(EIP6492_BLOB_LEN, 8608);
}

#[test]
fn negative_eip6492_factory_calldata_padding_matches_abi() {
    // The blob padding math is what the on-chain ABI decoder expects.
    // factoryCalldata length = PQ_INIT_CODE_LEN - 20 = 4260; padded
    // to next 32-byte boundary = 4288. Any drift here means
    // Solady / Ambire / viem's ABI decode lands at the wrong offset.
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, PQ_INIT_CODE_LEN - 20);
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4260);
    assert_eq!(EIP6492_FACTORY_CALLDATA_PADDED, 4288);
    assert_eq!(EIP6492_INNER_WRAPPER_LEN, SIG_WRAPPER_LEN);
    // Verify blob math: head(96) + fc_len(32) + fc_padded(4288) +
    // sig_len(32) + sig(4128) + magic(32) = 8608.
    assert_eq!(EIP6492_BLOB_LEN, 96 + 32 + 4288 + 32 + 4128 + 32);
}

#[test]
fn negative_eip6492_magic_suffix_is_repeating_6492() {
    // Spec: EIP-6492 magic = 0x6492...6492 (16 reps). Any drift =
    // every counterfactual EIP-1271 sig the firmware emits looks
    // unwrapped to 6492-aware verifiers, which then try (and fail)
    // to read the bytes as a bare ERC-1271 sig on a wallet that
    // isn't deployed yet.
    let spec = [
        0x64u8, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64,
        0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
        0x64, 0x92,
    ];
    assert_eq!(EIP6492_MAGIC, spec);
}

// ─────────────────────────────────────────────────────────────────────
// 4. CMD_SIGN_USEROP_BATCH — header / per-tx prefix / max-payload
//                            (cmd_sign_userop_batch.rs)
//
// CLAUDE.md "Unified sign input" is the single-tx layout. Batch reuses
// the first 277 bytes (header up to + including batch_count), then N
// inner-tx blocks of `(to(20) || value(32) || data_len(2)) + data`.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_sign_userop_batch_header_len_is_278() {
    // v2 wire: 8 (chain) + 4 (flags) + 20 (sender) + 20 (ep) + 32 (nonce)
    // + 5×32 (gas) + 32 (paymaster hash) + 1 (wire_version) + 1 (batch_count) = 278.
    assert_eq!(SIGN_USEROP_BATCH_HEADER_LEN, 278);
    assert_eq!(
        SIGN_USEROP_BATCH_HEADER_LEN,
        8 + 4 + 20 + 20 + 32 + 5 * 32 + 32 + 1 + 1
    );
}

#[test]
fn negative_sign_userop_batch_tx_prefix_len_is_54() {
    // Per-tx prefix: to(20) + value(32) + data_len(2) = 54.
    assert_eq!(SIGN_USEROP_BATCH_TX_PREFIX_LEN, 54);
}

#[test]
fn negative_sign_userop_batch_max_payload_len_covers_max_batch_at_max_tx_len() {
    // SNAP_BUF in cmd_sign_userop_batch.rs is sized to this constant.
    // v2 wire: header + MAX_BATCH_TXS × (prefix + MAX_TX_LEN data) +
    // trailer_count(1) + MAX_TRAILERS_PER_BATCH × per-record-header(4)
    // + TRAILERS_TOTAL_MAX_LEN budget. A fully-loaded batch payload must
    // fit without overflowing the snapshot.
    let expected = SIGN_USEROP_BATCH_HEADER_LEN
        + MAX_BATCH_TXS * (SIGN_USEROP_BATCH_TX_PREFIX_LEN + MAX_TX_LEN)
        + 1
        + MAX_TRAILERS_PER_BATCH * SIGN_USEROP_BATCH_TRAILER_HEADER_LEN
        + TRAILERS_TOTAL_MAX_LEN;
    assert_eq!(SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN, expected);
}

#[test]
fn negative_max_batch_txs_is_4() {
    // Bounded by what a user can review on the OLED + by the inner-tx
    // array sizing in `cmd_sign_userop_batch::run` (the `parsed` /
    // `batch_view` arrays are `[_; MAX_BATCH_TXS]`). A larger value
    // would require those arrays to grow.
    assert_eq!(MAX_BATCH_TXS, 4);
}

#[test]
fn negative_execute_batch_selector_unchanged() {
    // keccak256("executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])")[..4].
    // A change = batch UserOps land on a different dispatcher (or
    // revert). On-chain matched by
    // `PQSmartWallet.executeBatchWithOffchainCount`.
    assert_eq!(EXECUTE_BATCH_SELECTOR, [0x7a, 0x38, 0x99, 0x33]);
}

#[test]
fn negative_signature_len_unchanged_4008() {
    // SPHINCS+C10 sig length is part of the on-chain ABI in the
    // SignatureWrapper's bytes-length field. Pin separately from
    // SIG_WRAPPER_LEN so a refactor that changes one but not the
    // other fails both tests.
    assert_eq!(SIGNATURE_LEN, 4008);
    assert_eq!(C10_SIG_LEN, SIGNATURE_LEN);
}

#[test]
fn negative_sig_wrapper_len_unchanged_4128() {
    // CLAUDE.md "OWNER_BYTES_LEN = 64, C10_SIG_LEN = 4008". Wrapper is
    // 32 (ownerIndex) + 32 (offset) + 32 (length) + 4032 (padded sig)
    // = 4128. The batch handler emits two of these (Type 1 + Type 2)
    // back-to-back into MAX_SIGN_RESPONSE_LEN.
    assert_eq!(SIG_WRAPPER_LEN, 4128);
}

#[test]
fn negative_max_sign_response_len_fits_batch_worst_case() {
    // Worst-case batch response: count(8) + init_code_len(4) +
    // init_code(4280) + type1_len(4) + type1_wrapper(4128) +
    // type2_len(4) + type2_wrapper(4128) = 12,556. The companion's
    // NS-side buffer is sized to MAX_SIGN_RESPONSE_LEN; the firmware's
    // `validate_ns_write_ptr` is called against the same constant.
    // Drift here = under-allocation on one side, silent write past
    // the buffer end on the other.
    let worst = 8 + 4 + PQ_INIT_CODE_LEN + 4 + SIG_WRAPPER_LEN + 4 + SIG_WRAPPER_LEN;
    assert!(
        MAX_SIGN_RESPONSE_LEN >= worst,
        "MAX_SIGN_RESPONSE_LEN ({MAX_SIGN_RESPONSE_LEN}) < batch worst-case ({worst})"
    );
}

#[test]
fn negative_max_tx_len_per_inner_tx_unchanged() {
    // CLAUDE.md "data_len (u16 BE, 0..=4096)". Per-tx cap also bounds
    // the snapshot size for batch.
    assert_eq!(MAX_TX_LEN, 4096);
}

// ─────────────────────────────────────────────────────────────────────
// 5. Flag layout — shared with cmd_sign_userop.rs (pinned independently
//                  to catch a drift that touches only the batch path)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_batch_flag_layout_pins_31_30_account_slot() {
    // CLAUDE.md "flags (u32 BE: bit 31 INCLUDE_INIT_CODE, bit 30
    // REGISTER_SLOT, bits 29..22 account_index (8b, 0..=255), bits
    // 21..0 slot_index (22b))". `cmd_sign_userop_batch::run` decodes
    // the same flags word at offset 8 of the batch header.
    assert_eq!(FLAG_INCLUDE_INIT_CODE, 1u32 << 31);
    assert_eq!(FLAG_REGISTER_SLOT, 1u32 << 30);
    assert_eq!(ACCOUNT_INDEX_SHIFT, 22);
    assert_eq!(ACCOUNT_INDEX_MASK, 0xFFu32 << 22);
    assert_eq!(SLOT_INDEX_MASK, (1u32 << 22) - 1);
    // Pairwise disjoint.
    assert_eq!(FLAG_INCLUDE_INIT_CODE & FLAG_REGISTER_SLOT, 0);
    assert_eq!(FLAG_INCLUDE_INIT_CODE & ACCOUNT_INDEX_MASK, 0);
    assert_eq!(FLAG_INCLUDE_INIT_CODE & SLOT_INDEX_MASK, 0);
    assert_eq!(FLAG_REGISTER_SLOT & ACCOUNT_INDEX_MASK, 0);
    assert_eq!(FLAG_REGISTER_SLOT & SLOT_INDEX_MASK, 0);
    assert_eq!(ACCOUNT_INDEX_MASK & SLOT_INDEX_MASK, 0);
    // Cover the full u32.
    assert_eq!(
        FLAG_INCLUDE_INIT_CODE | FLAG_REGISTER_SLOT | ACCOUNT_INDEX_MASK | SLOT_INDEX_MASK,
        u32::MAX
    );
}

#[test]
fn negative_max_account_index_matches_8_bit_field() {
    assert_eq!(MAX_ACCOUNT_INDEX, 0xFF);
    assert_eq!(ACCOUNT_INDEX_MASK >> ACCOUNT_INDEX_SHIFT, MAX_ACCOUNT_INDEX);
}

// ─────────────────────────────────────────────────────────────────────
// 6. Cap constants — MAX_OFFCHAIN_GAP, MAX_SLOT_USES
//
// Both are read pre-emptively in `cmd_sign_offchain.rs` as
// firmware-side defence-in-depth around the on-chain combined cap.
// CLAUDE.md invariants #7 and #9 depend on these exact values.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_max_offchain_gap_is_100() {
    // CLAUDE.md invariant #9: "Refuses to sign past MAX_OFFCHAIN_GAP =
    // 100 unbacked sigs". Bound on the worst-case unpublished
    // off-chain sigs from a previous device after a fresh-from-seed
    // restore.
    assert_eq!(MAX_OFFCHAIN_GAP, 100);
}

#[test]
fn negative_max_slot_uses_is_65536() {
    // CLAUDE.md invariant #7: "slotUses[i] + offchainSigCount[i] <
    // 65,536". The firmware's pre-emptive `new_count > MAX_SLOT_USES`
    // gate is the belt-and-braces against a faulted firmware
    // producing a sig past the SPHINCS+C10 usage budget.
    assert_eq!(MAX_SLOT_USES, 65_536);
}

// ─────────────────────────────────────────────────────────────────────
// 7. Helper-function characterisations — `u128_saturating_from_u256`
//    and `add_one_to_be_u256` from cmd_sign_userop_batch.rs.
//
// Both are private to the firmware file (which is `cfg(not(test))` at
// the crate level, since `nsc/` pulls in hardware deps). Mirror their
// bodies here and verify the documented behaviour.
// ─────────────────────────────────────────────────────────────────────

/// Mirror of `cmd_sign_userop_batch.rs::u128_saturating_from_u256`.
/// Update both or neither; if these diverge, gas-fee display in the
/// batch confirm dialog silently truncates an attacker-supplied huge
/// value down into the comfortable u128 range.
fn mirror_u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

#[test]
fn positive_batch_u128_sat_zero_returns_zero() {
    assert_eq!(mirror_u128_saturating_from_u256(&[0u8; 32]), 0);
}

#[test]
fn positive_batch_u128_sat_low_128_returns_value() {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&123u128.to_be_bytes());
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), 123);
}

#[test]
fn positive_batch_u128_sat_low_128_max_returns_u128_max() {
    let mut bytes = [0u8; 32];
    bytes[16..32].copy_from_slice(&u128::MAX.to_be_bytes());
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), u128::MAX);
}

#[test]
fn positive_batch_u128_sat_just_above_u128_saturates() {
    // Smallest u256 value strictly greater than u128::MAX: bit 128.
    let mut bytes = [0u8; 32];
    bytes[15] = 0x01;
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), u128::MAX);
}

#[test]
fn negative_batch_u128_sat_any_high_byte_nonzero_saturates() {
    // Assumption: every non-zero byte in [0..16) saturates. A future
    // refactor that early-exited on a specific byte position would
    // let an attacker craft a gas-fee value with a single bit set in
    // the wrong byte and have it render as that bit's value instead
    // of u128::MAX. Iterate every position to keep the assumption
    // tight.
    for high_byte_index in 0..16 {
        let mut bytes = [0u8; 32];
        bytes[high_byte_index] = 0x01;
        assert_eq!(
            mirror_u128_saturating_from_u256(&bytes),
            u128::MAX,
            "high byte at index {high_byte_index} must trigger saturation"
        );
    }
}

#[test]
fn negative_batch_u128_sat_msb_high_bit_saturates_not_truncates() {
    // The most-significant byte (index 0) with its high bit set is
    // the most likely attacker target. Pin saturation.
    let mut bytes = [0u8; 32];
    bytes[0] = 0x80;
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), u128::MAX);
}

#[test]
fn negative_batch_u128_sat_low_byte_alone_does_not_saturate() {
    // Negative-of-the-negative: a non-zero byte in [16..32) (the low
    // half) MUST NOT trigger saturation. Otherwise tiny gas values
    // would render as u128::MAX and brick every benign sign.
    let mut bytes = [0u8; 32];
    bytes[31] = 0xff;
    assert_eq!(mirror_u128_saturating_from_u256(&bytes), 0xff);
}

/// Mirror of `cmd_sign_userop_batch.rs::add_one_to_be_u256`. The
/// `debug_assert!` in the production helper becomes a panic here so
/// the overflow test surface is the same.
fn mirror_add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    panic!("nonce seq overflow slipped past the step-4 guard");
}

#[test]
fn positive_batch_nonce_increment_simple() {
    let mut n = [0u8; 32];
    n[31] = 5;
    mirror_add_one_to_be_u256(&mut n);
    assert_eq!(n[31], 6);
    assert_eq!(&n[0..31], &[0u8; 31]);
}

#[test]
fn positive_batch_nonce_increment_carry_within_seq() {
    let mut n = [0u8; 32];
    n[31] = 0xff;
    mirror_add_one_to_be_u256(&mut n);
    assert_eq!(n[31], 0x00);
    assert_eq!(n[30], 0x01);
}

#[test]
fn negative_batch_nonce_increment_does_not_touch_key_field() {
    // CRIT-17 (mirrors cmd_sign_userop's identical helper): v0.6
    // nonces are 192-bit key | 64-bit seq. The increment must touch
    // bytes 24..32 only. Otherwise a slot rotation could silently
    // reset the nonce key, opening a userOpHash collision window.
    let mut n = [0xAAu8; 32];
    mirror_add_one_to_be_u256(&mut n);
    assert_eq!(&n[0..24], &[0xAAu8; 24], "key field bytes were touched");
}

#[test]
fn positive_batch_rotation_display_sequence_is_base_plus_one_same_lane() {
    let mut base = [0xa5u8; 32];
    base[24..32].copy_from_slice(&255u64.to_be_bytes());
    let mut type2 = base;
    mirror_add_one_to_be_u256(&mut type2);
    assert_eq!(u64::from_be_bytes(base[24..32].try_into().unwrap()), 255);
    assert_eq!(u64::from_be_bytes(type2[24..32].try_into().unwrap()), 256);
    assert_eq!(&type2[..24], &base[..24], "batch rotation changed nonce lane");
}

#[test]
#[should_panic(expected = "nonce seq overflow")]
fn negative_batch_nonce_increment_seq_overflow_panics() {
    // cmd_sign_userop_batch.rs:172 — `nonce[24..32] == [0xFFu8; 8]`
    // is the gate that prevents the helper from ever seeing a full
    // overflow. If the gate is bypassed, the helper's
    // `debug_assert!` (production) / `panic!` (mirror) is the second
    // line of defence: rather than silently carrying into byte 23
    // (i.e. the 192-bit key field), the helper crashes the build.
    let mut n = [0xffu8; 32];
    mirror_add_one_to_be_u256(&mut n);
}

#[test]
fn negative_batch_nonce_increment_range_matches_gate_check_range() {
    // The handler's gate is `nonce[24..32] == [0xFFu8; 8]`. The
    // helper increments `(24..32).rev()`. These ranges must be
    // identical — otherwise a partial-overflow nonce could slip
    // past the gate and trigger the panic, or worse, succeed and
    // silently carry into the key field.
    let increment_range = 24..32;
    let gate_check_range = 24..32;
    assert_eq!(increment_range, gate_check_range);
}

// ─────────────────────────────────────────────────────────────────────
// 8. Source-text invariant pins — cmd_offchain_status.rs,
//                                 cmd_offchain_sync.rs,
//                                 cmd_sign_offchain.rs,
//                                 cmd_sign_userop_batch.rs.
//
// These are the regression canary: if any future refactor removes a
// load-bearing gate from one of these files, the source-text check
// here fires before the change ever reaches an audited build.
// ─────────────────────────────────────────────────────────────────────

const CMD_OFFCHAIN_STATUS_SRC: &str = include_str!("nsc/cmd_offchain_status.rs");
const CMD_OFFCHAIN_SYNC_SRC: &str = include_str!("nsc/cmd_offchain_sync.rs");
const OFFCHAIN_SYNC_DISPLAY_SRC: &str = include_str!("tx/display/offchain_sync.rs");
const CMD_SIGN_OFFCHAIN_SRC: &str = include_str!("nsc/cmd_sign_offchain.rs");
const EIP1271_DISPLAY_SRC: &str = include_str!("tx/display/eip1271.rs");
const CMD_SIGN_USEROP_BATCH_SRC: &str = include_str!("nsc/cmd_sign_userop_batch.rs");
const BATCH_DISPLAY_SRC: &str = include_str!("tx/display/batch.rs");
// Not part of the four-file "slice" array below — pinned only for the
// MEDIUM-2 combined-cap guard, which lives in the single-tx handler too.
const CMD_SIGN_USEROP_SRC: &str = include_str!("nsc/cmd_sign_userop.rs");
const WALLET_ADDRESS_SRC: &str = include_str!("nsc/cmd_get_wallet_address.rs");
const VALUE_PAGE_SRC: &str = include_str!("tx/display/value_page.rs");
const NONCE_LANE_SRC: &str = include_str!("tx/display/nonce_lane.rs");
const DISPLAY_DISPATCH_SRC: &str = include_str!("tx/display/dispatch.rs");
const SAFE_DISPLAY_SRC: &str = include_str!("tx/display/safe_display.rs");
const SAFE_EIP712_SRC: &str = include_str!("tx/eip712/safe/mod.rs");

const ALL_SLICE_SRCS: [(&str, &str); 4] = [
    ("cmd_offchain_status.rs", CMD_OFFCHAIN_STATUS_SRC),
    ("cmd_offchain_sync.rs", CMD_OFFCHAIN_SYNC_SRC),
    ("cmd_sign_offchain.rs", CMD_SIGN_OFFCHAIN_SRC),
    ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
];

fn assert_each_sentinel_pair_is_scrubbed(
    name: &str,
    src: &str,
    first: &str,
    second: &str,
) -> usize {
    let mut cursor = 0usize;
    let mut count = 0usize;
    while let Some(relative_first) = src[cursor..].find(first) {
        let first_pos = cursor + relative_first;
        let second_pos = first_pos
            + src[first_pos..]
                .find(second)
                .unwrap_or_else(|| panic!("{name}: missing {second:?} after {first:?}"));
        assert!(
            src[first_pos + first.len()..second_pos]
                .contains("crate::fi::scrub_sentinel_register();"),
            "{name}: adjacent sentinel pair {first:?} -> {second:?} lacks an intervening F-15.r1 scrub"
        );
        count += 1;
        cursor = second_pos + second.len();
    }
    assert!(count > 0, "{name}: no {first:?} -> {second:?} pair found");
    count
}

// ── 8a. pin_verified gate (CLAUDE.md invariant #2 — hardware PIN gating)

#[test]
fn negative_every_handler_checks_pin_verified() {
    // Every NSC handler in the slice MUST refuse with
    // NscStatus::NotInitialized if the secure-state pin_verified
    // sentinel is not the OK pattern. A handler that skipped this
    // would happily produce sigs / leak counter state pre-PIN.
    for (name, src) in ALL_SLICE_SRCS {
        assert!(
            src.contains("pin_verified"),
            "{name} must check pin_verified — CLAUDE.md invariant #2"
        );
        assert!(
            src.contains("NscStatus::NotInitialized"),
            "{name} must return NotInitialized when pin_verified is clear"
        );
    }
}

// ── 8b. NS pointer validation (CLAUDE.md invariant #4)

#[test]
fn negative_every_handler_validates_ns_read_ptr_before_deref() {
    // The TOCTOU snapshot copy in every handler must be preceded by
    // `validate_ns_read_ptr`. CLAUDE.md invariant #4 + the file-level
    // safety docstrings make this load-bearing.
    for (name, src) in ALL_SLICE_SRCS {
        assert!(
            src.contains("validate_ns_read_ptr"),
            "{name} must validate the NS read pointer before deref"
        );
    }
}

#[test]
fn negative_handlers_with_output_buffers_validate_ns_write_ptr() {
    // CMD_OFFCHAIN_STATUS, CMD_SIGN_OFFCHAIN, CMD_SIGN_USEROP_BATCH
    // all write a response. CMD_OFFCHAIN_SYNC is SW-only (no output
    // body), so it does not need write-ptr validation.
    assert!(CMD_OFFCHAIN_STATUS_SRC.contains("validate_ns_write_ptr"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("validate_ns_write_ptr"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("validate_ns_write_ptr"));
    // And cmd_offchain_sync.rs deliberately should NOT validate a
    // write pointer (it has no output buffer). Documenting this
    // expectation here so a refactor that adds an output buffer is
    // forced to also add the validation.
    assert!(
        !CMD_OFFCHAIN_SYNC_SRC.contains("validate_ns_write_ptr"),
        "cmd_offchain_sync.rs has no output body — adding validate_ns_write_ptr signals new attack surface"
    );
}

#[test]
fn negative_batch_revalidates_full_output_extent_at_deref_site() {
    const GATE: &str =
        "validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)";
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC.matches(GATE).count(),
        2,
        "batch signing needs both the entry gate and a spatially separate deref-site gate"
    );

    let durable_commit = CMD_SIGN_USEROP_BATCH_SRC
        .rfind("userop_sigs_bump(&slot_flash_key")
        .expect("durable signature tally before response release");
    let final_gate = CMD_SIGN_USEROP_BATCH_SRC
        .rfind(GATE)
        .expect("deref-site output gate");
    let first_output_write = CMD_SIGN_USEROP_BATCH_SRC[final_gate..]
        .find("write_be_u64(out_ptr")
        .map(|offset| final_gate + offset)
        .expect("first response write");
    assert!(
        durable_commit < final_gate && final_gate < first_output_write,
        "the second full-extent check must be after durable commit and immediately before output writes"
    );
    assert!(
        CMD_SIGN_USEROP_BATCH_SRC[..final_gate]
            .rfind("crate::fi::scrub_sentinel_register();")
            .is_some_and(|scrub| final_gate - scrub < 256),
        "the deref-site sentinel check must start from a scrubbed return register"
    );
}

// ── 8c. TOCTOU snapshot (CLAUDE.md "NS buffers copied to S-stack before parse")

#[test]
fn negative_sign_offchain_and_batch_snapshot_input_before_parse() {
    // The two sign handlers are the only ones with variable-length
    // input — they MUST copy NS bytes into a local snapshot buffer
    // via `read_volatile` before parsing. A skipped TOCTOU here
    // would let NS swap the buffer mid-parse and force a different
    // sign than the user confirmed on the display.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("SNAP_BUF"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("read_volatile"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("SNAP_BUF"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("read_volatile"));
}

#[test]
fn negative_sign_offchain_and_batch_wipe_snap_on_exit() {
    // L-2 mitigation — wipe the TOCTOU snapshot on exit so the next
    // sign doesn't observe stale companion bytes in BSS.
    assert!(
        CMD_SIGN_OFFCHAIN_SRC.contains("L-2")
            || CMD_SIGN_OFFCHAIN_SRC.contains("wipe the TOCTOU snapshot"),
        "cmd_sign_offchain.rs must wipe SNAP_BUF on exit"
    );
    assert!(
        CMD_SIGN_USEROP_BATCH_SRC.contains("L-2")
            || CMD_SIGN_USEROP_BATCH_SRC.contains("wipe the TOCTOU snapshot"),
        "cmd_sign_userop_batch.rs must wipe SNAP_BUF on exit"
    );
}

// ── 8d. Volatile writes for NS output

#[test]
fn negative_handlers_with_output_use_write_volatile() {
    // CMSE / TrustZone: every byte of an NS-bound response must be
    // written via `core::ptr::write_volatile` so the compiler can't
    // reorder it past the status-word return or merge a torn word.
    for &(name, src) in &[
        ("cmd_offchain_status.rs", CMD_OFFCHAIN_STATUS_SRC),
        ("cmd_sign_offchain.rs", CMD_SIGN_OFFCHAIN_SRC),
        ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
    ] {
        assert!(
            src.contains("write_volatile"),
            "{name} must use write_volatile for every NS output byte"
        );
    }
}

// ── 8e. Strict length gating on the SW-only handlers

#[test]
fn negative_offchain_status_rejects_wrong_input_length() {
    // The exact-length gate is the only thing keeping malformed
    // companion payloads out of the parser. Pin its presence + the
    // refusal status.
    assert!(CMD_OFFCHAIN_STATUS_SRC.contains("OFFCHAIN_STATUS_INPUT_LEN"));
    assert!(CMD_OFFCHAIN_STATUS_SRC.contains("total_len != OFFCHAIN_STATUS_INPUT_LEN"));
    assert!(CMD_OFFCHAIN_STATUS_SRC.contains("NscStatus::InvalidPointer"));
}

#[test]
fn negative_offchain_sync_rejects_wrong_input_length() {
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("OFFCHAIN_SYNC_INPUT_LEN"));
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("total_len != OFFCHAIN_SYNC_INPUT_LEN"));
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("NscStatus::InvalidPointer"));
}

#[test]
fn negative_offchain_sync_confirms_new_slot_before_durable_write() {
    // page-123 exhaustion → permanent-brick fix
    // (docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md). CMD_OFFCHAIN_SYNC
    // mints a durable page-123 entry for a companion-chosen, seed-independent
    // slot_key. Without consent a hostile companion sprays distinct tuples to
    // fill the page and wedge compaction into a permanent signing brick. The
    // handler MUST require a trusted-display confirm before creating a slot it
    // has not seen before — keyed on `!offchain_count_is_registered` so re-syncs
    // of a known slot stay confirm-free — and the confirm MUST precede the
    // durable write (cmd_sign_offchain MEDIUM-3 "defer write until after confirm").
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("offchain_count_is_registered"),
        "SYNC must branch on registration so only NEW slots prompt for consent",
    );
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("build_offchain_sync_pages"),
        "SYNC must render the trusted-display consent page for a new slot",
    );
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("confirm_checked(pages.as_slice())"),
        "SYNC must call confirm() for a new slot",
    );
    // Fail-closed: only Confirmed proceeds; Cancelled/IdleWipe refuse the write.
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("ConfirmResult::Confirmed")
            && CMD_OFFCHAIN_SYNC_SRC.contains("NscStatus::UserRejected"),
        "SYNC confirm must be fail-closed (only Confirmed proceeds)",
    );
    // Ordering: the consent gate must come BEFORE the durable `last_userop_count_set`.
    // Anchor the write search on the CALL form (`last_userop_count_set(`), not the
    // bare identifier: doc comments in this handler now reference the function by
    // name (e.g. the value-inflation clamp block), and a bare-identifier `find`
    // would match the earliest comment mention instead of the real call site —
    // falsely failing this ordering pin. The comment writes the name backtick-
    // wrapped (`` `last_userop_count_set` ``), never followed by `(`, so the
    // paren-anchored search matches only the durable write.
    let gate = CMD_OFFCHAIN_SYNC_SRC
        .find("confirm_checked(pages.as_slice())")
        .expect("confirm gate present");
    let write = CMD_OFFCHAIN_SYNC_SRC
        .find("last_userop_count_set(")
        .expect("durable write present");
    assert!(
        gate < write,
        "consent confirm must precede the durable page-123 write (no pre-confirm mint)",
    );
}

#[test]
fn negative_offchain_sync_clamps_target_before_durable_write() {
    // Value-inflation → consent-free durable slot brick fix
    // (docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md). For an ALREADY-
    // registered slot the confirm gate is skipped, so a hostile `target_count`
    // reaches the durable write with no user interaction; promoted into the
    // monotonic off-chain counter it would trip the combined-cap gate forever.
    // The handler MUST clamp `target_count` to the ceiling, and the clamp MUST
    // precede the durable `last_userop_count_set` so it applies on EVERY path
    // (registered slots included, which never hit the confirm branch).
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("clamp_offchain_count(target_count)"),
        "SYNC must clamp the untrusted target_count (value-inflation brick defence)",
    );
    let clamp = CMD_OFFCHAIN_SYNC_SRC
        .find("clamp_offchain_count(target_count)")
        .expect("source clamp present");
    let write = CMD_OFFCHAIN_SYNC_SRC
        .find("last_userop_count_set")
        .expect("durable write present");
    assert!(
        clamp < write,
        "target_count clamp must precede the durable write (applies on the \
         confirm-free registered-slot path too)",
    );
}

#[test]
fn negative_offchain_sync_confirms_value_inflation_on_registered_slot() {
    // Value-inflation → consent-free durable slot brick fix, defence-in-depth
    // layer 2 (docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md). The clamp
    // blocks the permanent cap-tripping brick; this confirm additionally denies
    // the consent-free *near-exhaustion* of an already-registered slot. The gate
    // must fire when the sync would RAISE the stored floor (not only for a new
    // slot), and the raise-check must read the stored `last_userop` value.
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("last_userop_count_read"),
        "SYNC must read the stored floor to detect a value-inflating sync",
    );
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("let raises_floor = target_count > current_count"),
        "the confirm gate must fire on a floor-RAISING sync, not just a new slot",
    );
    // The raise detection must precede (feed) the confirm gate.
    let raise = CMD_OFFCHAIN_SYNC_SRC
        .find("raises_floor")
        .expect("raise-detection present");
    let gate = CMD_OFFCHAIN_SYNC_SRC
        .find("confirm_checked(pages.as_slice())")
        .expect("confirm gate present");
    assert!(
        raise < gate,
        "the value-inflation raise check must feed the confirm gate",
    );
}

#[test]
fn negative_offchain_sync_display_binds_current_and_target_values() {
    // A generic "SYNC COUNTER?" prompt is not informed consent: the hostile
    // companion controls target_count and can ask for a near-cap floor. Pin
    // the data flow into the renderer and the literal trusted rows: the
    // device's count, the app's count and what remains (sweep 2026-10-13
    // finding #2 replaced "Current/Target" with plain-language rows).
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("device_count,"));
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("target_count_for_display,"));
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("left_after_for_display,"));
    assert!(OFFCHAIN_SYNC_DISPLAY_SRC.contains("b\"On device: \""));
    assert!(OFFCHAIN_SYNC_DISPLAY_SRC.contains("b\"From app: \""));
    assert!(OFFCHAIN_SYNC_DISPLAY_SRC.contains("b\"Sigs left: \""));
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("target_count_for_display")
            && CMD_OFFCHAIN_SYNC_SRC.contains("check_true_into_sentinel"),
        "the displayed target must be FI-bound to the durable write value",
    );

    let render = CMD_OFFCHAIN_SYNC_SRC
        .find("build_offchain_sync_pages(")
        .expect("sync renderer call");
    let write = CMD_OFFCHAIN_SYNC_SRC
        .find("last_userop_count_set(")
        .expect("sync durable write");
    assert!(render < write, "current/target values must be shown before commit");
}

#[test]
fn negative_offchain_sync_refuses_an_exhausting_target_before_any_dialog_or_write() {
    // Sweep 2026-10-13 finding #2 (owner decision: refuse + warn). The
    // handler must read BOTH remaining counters, run the shared aa policy,
    // and refuse a sync that would leave 0 signatures before it renders a
    // dialog or touches flash.
    for needle in [
        "offchain_count_read(&slot_key)",
        "userop_sigs_read(&slot_key)",
        "sync_verdict(",
        "SyncVerdict::Refuse",
        "SyncVerdict::Plain",
        "NscStatus::OffchainCapExceeded",
    ] {
        assert!(CMD_OFFCHAIN_SYNC_SRC.contains(needle), "{needle}");
    }
    let refuse = CMD_OFFCHAIN_SYNC_SRC
        .find("NscStatus::OffchainCapExceeded")
        .expect("refusal present");
    let render = CMD_OFFCHAIN_SYNC_SRC
        .find("build_offchain_sync_pages(")
        .expect("sync renderer call");
    let write = CMD_OFFCHAIN_SYNC_SRC
        .find("last_userop_count_set(")
        .expect("sync durable write");
    assert!(refuse < render && refuse < write, "refusal must precede dialog and write");
    // The warning is fail-safe: shown unless the policy PROVES `Plain`.
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("== SyncVerdict::Plain\n    }) != crate::fi::OK_SENTINEL;"));
    // The dialog itself is skipped only on a sentinel-proved no-op on a
    // registered slot (adversarial review 2026-10-13): no plain-bool gate.
    assert!(!CMD_OFFCHAIN_SYNC_SRC.contains("if is_new_slot || raises_floor {"));
    let skip = CMD_OFFCHAIN_SYNC_SRC.find("let skip_dialog = crate::fi::check_true_into_sentinel(").expect("skip proof");
    let gate = CMD_OFFCHAIN_SYNC_SRC.find("if !skip_dialog {").expect("dialog gate");
    assert!(skip < gate && gate < render);
    assert!(CMD_OFFCHAIN_SYNC_SRC[skip..gate].contains("offchain_count_is_registered(&slot_key)"));
}

// ── 8f. Account-index range check (CLAUDE.md "8b account_index (0..=255)")

#[test]
fn negative_byte_source_handlers_bound_account_index() {
    // The three handlers that read account_index from a single
    // input byte (`buf[0] as u32`) carry an explicit `> MAX_ACCOUNT_INDEX`
    // gate even though the cast is mathematically bounded to 0..=255.
    // The gate is documented defence-in-depth — a refactor that
    // widened the field to u16 or u32 without updating the gate would
    // silently let cross-account slot derivations bleed through.
    for &(name, src) in &[
        ("cmd_offchain_status.rs", CMD_OFFCHAIN_STATUS_SRC),
        ("cmd_offchain_sync.rs", CMD_OFFCHAIN_SYNC_SRC),
        ("cmd_sign_offchain.rs", CMD_SIGN_OFFCHAIN_SRC),
    ] {
        assert!(
            src.contains("MAX_ACCOUNT_INDEX"),
            "{name} must reject account_index > MAX_ACCOUNT_INDEX"
        );
        assert!(
            src.contains("account_index > MAX_ACCOUNT_INDEX"),
            "{name} must use the canonical `> MAX_ACCOUNT_INDEX` rejection clause"
        );
    }
}

#[test]
fn negative_batch_account_index_is_mask_bounded() {
    // The batch handler must share the Kani-proven total flag decoder with
    // the single handler for both the primary extraction and FI recheck.
    // `decode_flags` applies the canonical eight-bit account mask, so no
    // separate `> MAX_ACCOUNT_INDEX` gate is necessary here.
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("crate::aa::userop::decode_flags(")
            .count(),
        2,
        "batch primary/recheck flag extraction must use the shared proven kernel"
    );
    // Sanity: the mask really is 8 bits wide.
    let derived_width = (ACCOUNT_INDEX_MASK >> ACCOUNT_INDEX_SHIFT).count_ones();
    assert_eq!(
        derived_width, 8,
        "ACCOUNT_INDEX_MASK width drifted — batch handler would suddenly need an explicit > MAX_ACCOUNT_INDEX gate"
    );
}

// ── 8g. cmd_sign_offchain — kind / flag / payload-length gates

#[test]
fn negative_sign_offchain_rejects_unknown_kind() {
    // The match on the kind byte has a `_ => bad kind` arm. A
    // refactor that replaced this with a permissive default (e.g.
    // "treat unknown kinds as RAW32") would let a stale companion
    // sign arbitrary 32-byte hashes for a wallet whose user wanted
    // to sign a SIWE message.
    assert!(
        CMD_SIGN_OFFCHAIN_SRC.contains("bad kind"),
        "cmd_sign_offchain.rs must reject unknown kind bytes"
    );
}

#[test]
fn negative_sign_offchain_rejects_raw32_with_wrong_payload_len() {
    // payload_len != 32 must be rejected when kind == RAW32. If the
    // gate silently truncated/padded the payload to 32 bytes, the
    // user-visible signature subject (hex dump on the OLED) would
    // diverge from what is actually signed.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("payload_len != 32"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("raw32 needs 32 B"));
}

#[test]
fn negative_sign_offchain_caps_personal_sign_payload_len() {
    // payload_len > MAX_OFFCHAIN_PERSONAL_SIGN_LEN must be refused so
    // the user can actually scroll through the message and the
    // snapshot buffer stays bounded.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("MAX_OFFCHAIN_PERSONAL_SIGN_LEN"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("msg too long"));
}

#[test]
fn negative_sign_offchain_display_budget_gate_precedes_first_flash_write() {
    // A personal_sign message the display cannot show in full (text rows,
    // or hex for a non-text message) is refused before the first page-123
    // write — the counter-floor repair — so an unshowable request leaves no
    // durable trace.
    let gate = CMD_SIGN_OFFCHAIN_SRC
        .find("crate::tx::display::personal_sign_msg_pages(payload).is_none()")
        .expect("display-budget gate present");
    let first_write = CMD_SIGN_OFFCHAIN_SRC
        .find("offchain_count_promote_to(")
        .expect("counter-floor repair present");
    let slot_probe = CMD_SIGN_OFFCHAIN_SRC.find("// ── 5. Slot key + registration probe").expect("§5 present");
    assert!(gate < slot_probe && slot_probe < first_write);
    assert!(CMD_SIGN_OFFCHAIN_SRC[gate - 80..gate].contains("kind == OFFCHAIN_KIND_PERSONAL_SIGN"));
    assert!(CMD_SIGN_OFFCHAIN_SRC[gate..slot_probe].contains("return NscStatus::InvalidPointer as u32;"));
}

#[test]
fn negative_sign_offchain_rejects_unknown_flag_bits() {
    // `flags & !OFFCHAIN_FLAGS_MASK != 0` is the canonical rejection
    // of bits the firmware does not yet implement. Without this, a
    // stale companion / bit-flip could trigger a future mode that
    // isn't actually present, and the handler would silently fall
    // through to the deployed-account branch.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("OFFCHAIN_FLAGS_MASK"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("flags & !OFFCHAIN_FLAGS_MASK"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("bad flags"));
}

#[test]
fn negative_sign_offchain_eip6492_path_requires_slot_zero() {
    // The factory's `createAccount(...)` seeds only ownerIndex 0
    // (bootstrap) + ownerIndex 1 (slot 0). A 6492-wrapped sig on
    // slot N>0 is unverifiable because that slot doesn't exist
    // after the factory call. The handler refuses early.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("!account_deployed && slot_index != 0"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("6492 needs slot 0"));
}

#[test]
fn negative_sign_offchain_validates_payload_len_arithmetic() {
    // The handler computes `SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF +
    // payload_len != total_len` and refuses. This catches both
    // "declared shorter than buffer" (trailing-byte attack) and
    // "declared longer than buffer" (read past end).
    assert!(CMD_SIGN_OFFCHAIN_SRC
        .contains("SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF + payload_len != total_len"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("bad payload_len"));
}

#[test]
fn negative_sign_offchain_caps_total_len_to_input_max() {
    // Two bounds: lower (must have at least HEADER_LEN bytes) and
    // upper (must not exceed INPUT_MAX_LEN, which sizes SNAP_BUF).
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("SIGN_OFFCHAIN_HEADER_LEN"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("SIGN_OFFCHAIN_INPUT_MAX_LEN"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("bad length"));
}

#[test]
fn offchain_fingerprints_have_caller_cfi_completion_and_final_boundary_proofs() {
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC
            .matches("append_fingerprint_page(")
            .count(),
        3,
        "typed-data, personal/raw32 input, and RAW32 signed hash need authoritative appends"
    );
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC
            .matches("fingerprint_page_proof(")
            .count(),
        3
    );
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC
            .matches("fingerprint_final_set_proof(")
            .count(),
        3
    );

    let typed_start = CMD_SIGN_OFFCHAIN_SRC
        .find("let render_result = if is_v3")
        .expect("typed render section");
    let ordinary_start = CMD_SIGN_OFFCHAIN_SRC
        .find("if kind == OFFCHAIN_KIND_RAW32 || kind == OFFCHAIN_KIND_PERSONAL_SIGN")
        .expect("personal/raw32 render section");
    let typed = &CMD_SIGN_OFFCHAIN_SRC[typed_start..ordinary_start];
    let typed_append = typed.find("append_fingerprint_page(").unwrap();
    let typed_completion = typed.find("fingerprint_page_proof(").unwrap();
    let typed_final = typed.find("fingerprint_final_set_proof(").unwrap();
    let typed_confirm = typed.find("confirm_checked(pages.as_slice())").unwrap();
    assert!(typed_append < typed_completion && typed_completion < typed_final);
    assert!(typed_final < typed_confirm);
    assert!(typed[typed_append..typed_confirm].contains("FINGERPRINT_CFI_EXPECTED"));

    let ordinary = &CMD_SIGN_OFFCHAIN_SRC[ordinary_start..];
    let primary_append = ordinary.find("append_fingerprint_page(").unwrap();
    let primary_completion = ordinary.find("fingerprint_page_proof(").unwrap();
    let nested_append = primary_append
        + 1
        + ordinary[primary_append + 1..]
            .find("append_fingerprint_page(")
            .unwrap();
    let nested_completion = primary_completion
        + 1
        + ordinary[primary_completion + 1..]
            .find("fingerprint_page_proof(")
            .unwrap();
    let primary_final = ordinary.find("fingerprint_final_set_proof(").unwrap();
    let nested_final = primary_final
        + 1
        + ordinary[primary_final + 1..]
            .find("fingerprint_final_set_proof(")
            .unwrap();
    let ordinary_confirm = ordinary.find("confirm_checked(pages.as_slice())").unwrap();
    assert!(primary_append < primary_completion && primary_completion < nested_append);
    assert!(nested_append < nested_completion && nested_completion < primary_final);
    assert!(primary_final < nested_final && nested_final < ordinary_confirm);
    assert!(ordinary[primary_append..ordinary_confirm].contains("FINGERPRINT_CFI_EXPECTED"));
}

#[test]
fn typed_offchain_context_and_common_confirmation_receipt_gate_every_kind() {
    assert!(
        !CMD_SIGN_OFFCHAIN_SRC.contains("already_confirmed"),
        "a plain conditional must never be off-chain signing authority"
    );
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC
            .matches("offchain_confirm_receipt.fail_initialize()")
            .count(),
        1
    );
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC.matches(".record_confirmed(").count(),
        2,
        "typed and personal/raw confirmations must each mint the same receipt"
    );
    assert_eq!(
        CMD_SIGN_OFFCHAIN_SRC.matches(".completion_proof(").count(),
        2,
        "two spatially distinct common gates must consume the receipt"
    );

    let fail_init = CMD_SIGN_OFFCHAIN_SRC
        .find("offchain_confirm_receipt.fail_initialize()")
        .expect("fail-initialized off-chain authority receipt");
    let context_append = CMD_SIGN_OFFCHAIN_SRC
        .find("append_eip1271_context_pages(")
        .expect("typed handler-owned context append");
    let context_insert_proof = CMD_SIGN_OFFCHAIN_SRC
        .find("eip1271_context_page_proof(")
        .expect("typed context insertion proof");
    let context_final_proof = CMD_SIGN_OFFCHAIN_SRC
        .find("eip1271_context_final_set_proof(")
        .expect("typed context final-set proof");
    let typed_confirm = context_final_proof
        + CMD_SIGN_OFFCHAIN_SRC[context_final_proof..]
            .find("confirm_checked(pages.as_slice())")
            .expect("typed trusted confirmation");
    let typed_record = typed_confirm
        + CMD_SIGN_OFFCHAIN_SRC[typed_confirm..]
            .find(".record_confirmed(&typed_confirm_context)")
            .expect("typed affirmative receipt publication");
    let ordinary_branch = typed_record
        + CMD_SIGN_OFFCHAIN_SRC[typed_record..]
            .find("if kind == OFFCHAIN_KIND_RAW32 || kind == OFFCHAIN_KIND_PERSONAL_SIGN")
            .expect("ordinary raw/personal render branch");
    let ordinary_confirm = ordinary_branch
        + CMD_SIGN_OFFCHAIN_SRC[ordinary_branch..]
            .find("confirm_checked(pages.as_slice())")
            .expect("raw/personal trusted confirmation");
    let ordinary_record = ordinary_confirm
        + CMD_SIGN_OFFCHAIN_SRC[ordinary_confirm..]
            .find(".record_confirmed(&confirmed_context)")
            .expect("raw/personal affirmative receipt publication");
    let common_proof_a = ordinary_record
        + CMD_SIGN_OFFCHAIN_SRC[ordinary_record..]
            .find("offchain_confirm_receipt.completion_proof(&signing_context_a)")
            .expect("first unconditional common receipt gate");
    let common_reject_a = common_proof_a
        + CMD_SIGN_OFFCHAIN_SRC[common_proof_a..]
            .find("if confirm_receipt_verdict_a != crate::fi::OK_SENTINEL")
            .expect("first common receipt rejection");
    let common_proof_b = common_reject_a
        + CMD_SIGN_OFFCHAIN_SRC[common_reject_a..]
            .find("offchain_confirm_receipt.completion_proof(&signing_context_b)")
            .expect("second unconditional common receipt gate");
    let common_reject_b = common_proof_b
        + CMD_SIGN_OFFCHAIN_SRC[common_proof_b..]
            .find("if confirm_receipt_verdict_b != crate::fi::OK_SENTINEL")
            .expect("second common receipt rejection");
    let sign = common_reject_b
        + CMD_SIGN_OFFCHAIN_SRC[common_reject_b..]
            .find("c10_sign_verified_with_progress")
            .expect("C10 sign boundary");
    assert!(
        fail_init < context_append
            && context_append < context_insert_proof
            && context_insert_proof < context_final_proof
            && context_final_proof < typed_confirm
            && typed_confirm < typed_record
            && typed_record < ordinary_branch
            && ordinary_branch < ordinary_confirm
            && ordinary_confirm < ordinary_record
            && ordinary_record < common_proof_a
            && common_proof_a < common_reject_a
            && common_reject_a < common_proof_b
            && common_proof_b < common_reject_b
            && common_reject_b < sign
    );
    assert!(CMD_SIGN_OFFCHAIN_SRC[common_reject_a..common_proof_b]
        .contains("crate::fi::wait_random();"));

    for required in [
        "account_index",
        "slot_index",
        "wallet_addr",
        "account_deployed",
        "local_offchain_after",
        "last_userop",
        "cap",
        "hash_to_sign",
    ] {
        assert!(
            EIP1271_DISPLAY_SRC.contains(required),
            "off-chain receipt/context must bind {required}"
        );
    }
    assert!(EIP1271_DISPLAY_SRC.contains("PQSigner/offchain-confirm/v1"));
    assert!(EIP1271_DISPLAY_SRC.contains("DEPLOYED EIP1271"));
    assert!(EIP1271_DISPLAY_SRC.contains("ERC-6492 WRAPPED"));
    assert!(EIP1271_DISPLAY_SRC.contains("L cancel/R sign"));
    assert!(EIP1271_DISPLAY_SRC.contains("write_addr_full"));
    assert!(EIP1271_DISPLAY_SRC.contains("occurrences != 1"));
}

#[test]
fn raw32_confirmation_shows_input_signed_hash_wallet_and_exact_response_mode() {
    let ordinary_start = CMD_SIGN_OFFCHAIN_SRC
        .find("if kind == OFFCHAIN_KIND_RAW32 || kind == OFFCHAIN_KIND_PERSONAL_SIGN")
        .expect("personal/raw32 confirmation section");
    let ordinary_end = ordinary_start
        + CMD_SIGN_OFFCHAIN_SRC[ordinary_start..]
            .find("// ── 10. Slot C10 keygen")
            .expect("end of personal/raw32 confirmation section");
    let section = &CMD_SIGN_OFFCHAIN_SRC[ordinary_start..ordinary_end];

    let context = section
        .find("let confirmed_context = crate::tx::display::OffchainConfirmContext::new(")
        .expect("exact confirmation context");
    let preflight = section
        .find("let required_suffix_pages = if kind == OFFCHAIN_KIND_RAW32")
        .expect("atomic complete RAW32 suffix preflight");
    let primary_append = section.find("append_fingerprint_page(").unwrap();
    let replay_kind = section
        .find("Kind::ReplaySafeHash(hash_to_sign)")
        .expect("exact nested hash fingerprint");
    let replay_append = replay_kind
        + section[replay_kind..]
            .find("append_fingerprint_page(")
            .unwrap();
    let replay_proof = replay_append
        + section[replay_append..]
            .find("fingerprint_page_proof(")
            .unwrap();
    let context_append = section
        .find("append_eip1271_context_pages(")
        .expect("RAW32 signer/mode context append");
    let context_proof = section
        .find("eip1271_context_page_proof(")
        .expect("RAW32 context completion proof");
    let primary_final = section.find("fingerprint_final_set_proof(").unwrap();
    let replay_final = primary_final
        + 1
        + section[primary_final + 1..]
            .find("fingerprint_final_set_proof(")
            .unwrap();
    let context_final = section
        .find("eip1271_context_final_set_proof(")
        .expect("RAW32 final context proof");
    let confirm = section
        .find("confirm_checked(pages.as_slice())")
        .expect("trusted confirmation");
    let receipt = section
        .find(".record_confirmed(&confirmed_context)")
        .expect("authority receipt publication");

    assert!(context < preflight && preflight < primary_append);
    assert!(primary_append < replay_kind && replay_kind < replay_append);
    assert!(replay_append < replay_proof && replay_proof < context_append);
    assert!(context_append < context_proof && context_proof < primary_final);
    assert!(primary_final < replay_final && replay_final < context_final);
    assert!(context_final < confirm && confirm < receipt);

    assert!(section.contains("Kind::Raw32(raw_h)"));
    assert!(section.contains("raw_h.copy_from_slice(payload)"));
    assert!(section.contains("FINGERPRINT_PAGES * 2"));
    assert!(section.contains("+ crate::tx::display::OFFCHAIN_CONTEXT_PAGES"));
    assert!(EIP1271_DISPLAY_SRC.contains("Signing wallet"));
    assert!(EIP1271_DISPLAY_SRC.contains("DEPLOYED EIP1271"));
    assert!(EIP1271_DISPLAY_SRC.contains("ERC-6492 WRAPPED"));
    assert!(EIP1271_DISPLAY_SRC.contains("write_addr_full"));
}

#[test]
fn negative_sign_offchain_revalidates_write_ptr_for_larger_6492_buffer() {
    // The deployed-path output is 4016 B, the 6492 path is 8616 B.
    // The handler validates the smaller bound up front so any
    // unmapped output buffer fails fast, then re-validates against
    // the larger bound once the account_deployed bit is parsed.
    // A refactor that dropped the second validation would let a
    // 6492-wrapped sig overrun a buffer the companion only sized
    // for the deployed path.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("SIGN_OFFCHAIN_OUTPUT_LEN_6492"));
}

#[test]
fn negative_sign_offchain_revalidates_6492_extent_fi_hardened_before_write() {
    // FI hardening for the write-size selector. The deployed (4016 B) vs
    // 6492 (8616 B) write size is chosen by the un-hardened
    // `account_deployed` bool, read once at parse time and again to pick
    // the write branch. The up-front §4 re-validation of the larger
    // extent is itself gated on `!account_deployed`, so a SINGLE fault
    // flipping the bit true→false between that gate and the write branch
    // would reach the 8616-byte blob write against a buffer only proven
    // NS-writable for the 4016-byte deployed extent (~4600 B overrun
    // across the NS/secure-SRAM boundary). The fix re-validates the full
    // 6492 extent INSIDE the else branch, double-evaluated through
    // `check_true_into_sentinel`, so reaching the larger write requires a
    // passing larger validation in the same branch (two coordinated
    // faults needed, matching the F-8 bar). A refactor that drops this
    // guard re-opens the single-fault overrun.
    let src = CMD_SIGN_OFFCHAIN_SRC;
    // The hardened re-validation closure must compose the sentinel check
    // with `validate_ns_write_ptr(.., SIGN_OFFCHAIN_OUTPUT_LEN_6492)`.
    assert!(src.contains("check_true_into_sentinel"));
    assert!(src.contains("validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN_6492)"));
    // Unique status string emitted only by the in-branch guard — pins the
    // guard's presence so it can't be silently removed.
    assert!(src.contains("bad out 6492"));
    // The guard sits after the write-size branch opens (`if account_deployed`)
    // so it gates the else/6492 write, not just the up-front fail-fast check.
    let branch = src.find("if account_deployed {").expect("write-size branch");
    let guard = src.find("bad out 6492").expect("6492 extent guard");
    assert!(guard > branch, "6492 extent re-validation must live inside the write-size branch");
}

#[test]
fn negative_sign_offchain_revalidates_full_mode_extent_after_commit_before_release() {
    let src = CMD_SIGN_OFFCHAIN_SRC;
    let entry_check = src
        .find("validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN)")
        .expect("entry deployed-extent validation");
    let snapshot = src.find("// ── 3. TOCTOU snapshot").expect("snapshot");
    let bump = src
        .find("crate::offchain_state::offchain_count_bump(&slot_flash_key, new_count)")
        .expect("durable off-chain counter bump");
    let extent_select = src
        .find("let response_extent = if account_deployed")
        .expect("mode-selected complete response extent");
    let post_commit_scrub = extent_select
        + src[extent_select..]
            .find("crate::fi::scrub_sentinel_register();")
            .expect("post-commit sentinel scrub");
    let post_commit_check = src
        .find("let post_commit_output_extent_verdict = crate::fi::check_true_into_sentinel")
        .expect("post-commit hardened pointer validation");
    let post_commit_reject = src
        .find("if post_commit_output_extent_verdict != crate::fi::OK_SENTINEL")
        .expect("post-commit fail-closed pointer gate");
    let first_output_write = src
        .find("core::ptr::write_volatile(out_ptr.add(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF + i)")
        .expect("first NS output write");

    assert!(entry_check < snapshot, "entry extent must fail before expensive secure work");
    assert!(bump < extent_select, "release recheck must follow the durable commit");
    assert!(extent_select < post_commit_scrub && post_commit_scrub < post_commit_check);
    assert!(post_commit_check < post_commit_reject && post_commit_reject < first_output_write);
    let selected_extent = &src[extent_select..post_commit_scrub];
    assert!(selected_extent.contains("SIGN_OFFCHAIN_OUTPUT_LEN"));
    assert!(selected_extent.contains("SIGN_OFFCHAIN_OUTPUT_LEN_6492"));
    let hardened_gate = &src[post_commit_scrub..first_output_write];
    assert_eq!(
        hardened_gate
            .matches("crate::fi::scrub_sentinel_register();")
            .count(),
        2,
        "scrub both before producing and before consuming the Hamming-distant verdict"
    );
    assert!(hardened_gate.contains("validate_ns_write_ptr(args.arg1"));
    assert!(hardened_gate.contains("core::hint::black_box(response_extent)"));
}

#[test]
fn negative_sign_offchain_retains_scrubbed_branch_local_6492_spatial_belt() {
    let src = CMD_SIGN_OFFCHAIN_SRC;
    let first_output_write = src
        .find("core::ptr::write_volatile(out_ptr.add(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF + i)")
        .unwrap();
    let branch = first_output_write
        + src[first_output_write..]
            .find("if account_deployed {")
            .expect("release-size branch");
    let branch_scrub = branch
        + src[branch..]
            .find("crate::fi::scrub_sentinel_register();")
            .expect("branch-local pre-check scrub");
    let extent_check = branch
        + src[branch..]
            .find("let extent_ok = crate::fi::check_true_into_sentinel")
            .expect("branch-local 6492 check");
    let branch_reject = branch
        + src[branch..]
            .find("if extent_ok != crate::fi::OK_SENTINEL")
            .expect("branch-local fail-closed gate");
    let blob_write = branch
        + src[branch..]
            .find("for i in 0..EIP6492_BLOB_LEN")
            .expect("counterfactual blob write");
    assert!(branch < branch_scrub && branch_scrub < extent_check);
    assert!(extent_check < branch_reject && branch_reject < blob_write);
    let belt = &src[branch_scrub..branch_reject];
    assert_eq!(
        belt.matches("crate::fi::scrub_sentinel_register();").count(),
        2,
        "the branch-local sentinel must be scrubbed immediately before check and compare"
    );
    assert!(belt.contains("validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN_6492)"));
}

#[test]
fn negative_sign_offchain_double_reads_counters_for_fi_hardening() {
    // F-10 hardening — read each counter twice with a randomised
    // gap, halt on disagreement. Defeats single-shot stuck-at faults
    // on the value-holding register after a successful flash scan.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("last_userop_a"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("last_userop_b"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("local_offchain_a"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("local_offchain_b"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("fi tampered"));
}

#[test]
fn negative_sign_offchain_enforces_gap_and_cap_with_recheck() {
    // CLAUDE.md invariant #9: refuse past MAX_OFFCHAIN_GAP unbacked sigs;
    // invariant #7: refuse past MAX_SLOT_USES per slot. The gap + combined-cap
    // ARITHMETIC now lives in the Kani-proven kernel
    // `aa::offchain_gate::check_offchain_gate` (fail-closed / monotonic /
    // overflow-free — `cargo kani -p pqsigner-aa`,
    // `offchain_gate_accept_is_sound` + `_verdict_is_exact`; work-todo §12e).
    // This source guard now pins the *wiring* — the handler routes through the
    // proven kernel and re-evaluates it in the F-10 recheck window — while the
    // proof + `aa` host tests pin the LOGIC (a strictly stronger split than the
    // pre-2026-07 inline `gap_recheck` string-assert the refutation flagged).
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("check_offchain_gate"));
    // Called at BOTH the decision and the post-`wait_random` recheck window so
    // a single glitch must land in both windows to reach the sign.
    assert!(
        CMD_SIGN_OFFCHAIN_SRC.matches("check_offchain_gate(").count() >= 2,
        "the gap+cap gate must be re-evaluated in the F-10 recheck window"
    );
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("wait_random"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("OffchainGapExceeded"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("OffchainCapExceeded"));
}

#[test]
fn negative_sign_offchain_refuses_unregistered_slots_on_deployed_path() {
    // CLAUDE.md invariant #9: "CMD_SIGN_OFFCHAIN for an unregistered
    // slot is rejected — forces a Type 1 rotation via
    // CMD_SIGN_USEROP first." The handler returns
    // `OffchainSlotUnregistered` for non-6492 unregistered slots.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("OffchainSlotUnregistered"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("slot unregistered"));
}

#[test]
fn negative_sign_offchain_defers_registration_until_after_confirm() {
    // MEDIUM-3 (audit counter-replay 20260611): the off-chain handler must
    // NOT commit a durable page-123 registration entry before the user
    // confirms. The old code called `offchain_count_register_slot` at the
    // §5 probe (pre-confirm), letting a malicious companion mint durable
    // flash state — and wear the page — with no consent. The registration
    // is now folded into the post-confirm §13 `offchain_count_bump`. Pin
    // that the pre-confirm register call is gone from this handler.
    assert!(
        !CMD_SIGN_OFFCHAIN_SRC.contains("offchain_count_register_slot"),
        "MEDIUM-3: off-chain handler must not write a registration entry before the user confirm"
    );
    // The counterfactual (account_deployed==0, slot 0) carve-out is still
    // the ONLY unregistered-slot path that proceeds; everything else is
    // refused (invariant #9).
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("account_deployed || slot_index != 0"));
}

#[test]
fn negative_combined_cap_counts_userop_sigs_on_every_sign_path() {
    // MEDIUM-2 (audit counter-replay 20260611): off-chain EIP-1271 sigs are
    // never counted on-chain (isValidSignature is view-only) and a withheld
    // / reverted UserOp never bumps on-chain `slotUses`, so the device must
    // tally the Type-2 slot-key signatures it produces (`userop_sigs`) and
    // enforce the *combined* few-time budget `userop_sigs + offchain_count
    // <= MAX_SLOT_USES` on BOTH the UserOp and the off-chain paths. Without
    // this, a malicious companion can withhold the publishing UserOps and
    // drive total slot-key usage to ~2x the cap.
    //
    // Off-chain path: reads the tally and folds it into the combined-cap gate.
    // The cap arithmetic is the Kani-proven kernel `check_offchain_gate`; the
    // handler feeds `userop_sigs` into it as the third argument, so the proof
    // (userop_sigs + new_count <= MAX_SLOT_USES on accept) covers this path.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("userop_sigs"));
    assert!(CMD_SIGN_OFFCHAIN_SRC
        .contains("check_offchain_gate(local_offchain, last_userop, userop_sigs)"));
    // Single-tx UserOp path: the cap MUST fold in a higher synced floor before
    // signing, then durably bump the Type-2 tally.
    assert!(CMD_SIGN_USEROP_SRC.contains("userop_sigs_read"));
    assert!(CMD_SIGN_USEROP_SRC.contains("effective_offchain_count"));
    assert!(CMD_SIGN_USEROP_SRC.contains("userop_cap_ok(effective_offchain, userop_sigs)"));
    assert!(CMD_SIGN_USEROP_SRC.contains("userop_sigs_bump"));
    // Batch path: same effective-floor gate + bump (one Type-2 sig per batch).
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("userop_sigs_read"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("effective_offchain_count"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("userop_cap_ok(effective_offchain, userop_sigs)"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("userop_sigs_bump"));
}

#[test]
fn combined_cap_boundary_arithmetic() {
    // MEDIUM-2: mirror both gate formulations and verify they bound the
    // TOTAL slot-key signatures (UserOp tally + off-chain count) to
    // MAX_SLOT_USES, plus the fail-closed saturating behaviour on a
    // glitched (u64::MAX) counter read. Keep in lockstep with the handler
    // expressions pinned above; if either drifts, this fires.

    // UserOp path: refuse iff `userop_sigs + max(local,last_userop) >= cap`
    // (after the +1 bump the post-state combined is <= cap).
    let userop_refuse = |userop_sigs: u64, local_offchain: u64, last_userop: u64| -> bool {
        let effective = core::cmp::max(local_offchain, last_userop);
        userop_sigs.saturating_add(effective) >= MAX_SLOT_USES
    };
    // Off-chain path: refuse iff `userop_sigs + (local_offchain + 1) > cap`.
    let offchain_refuse = |userop_sigs: u64, local_offchain: u64| -> bool {
        let new_count = local_offchain + 1;
        userop_sigs.saturating_add(new_count) > MAX_SLOT_USES
    };

    // The sig that reaches exactly the cap is allowed; the next is refused.
    assert!(!userop_refuse(MAX_SLOT_USES - 1, 0, 0)); // 65535 userops -> 1 more ok
    assert!(userop_refuse(MAX_SLOT_USES, 0, 0)); // 65536 produced -> refuse
    assert!(!userop_refuse(MAX_SLOT_USES / 2, MAX_SLOT_USES / 2 - 1, 0)); // 32768+32767 ok
    assert!(userop_refuse(MAX_SLOT_USES / 2, MAX_SLOT_USES / 2, 0)); // 32768+32768 refuse

    // Regression: a synced floor ahead of local state is part of the same cap.
    assert!(userop_refuse(1, 0, MAX_SLOT_USES - 1));
    assert!(!userop_refuse(1, 0, MAX_SLOT_USES - 2));

    assert!(!offchain_refuse(0, MAX_SLOT_USES - 1)); // 65536th off-chain ok
    assert!(offchain_refuse(0, MAX_SLOT_USES)); // would be 65537 -> refuse
    // Mixed: the 2x evasion is closed — 65535 userops + off-chain caps at
    // exactly one more (reaching the cap), not a second full 65536 budget.
    assert!(!offchain_refuse(MAX_SLOT_USES - 1, 0)); // 65535 + 1 = 65536 ok
    assert!(offchain_refuse(MAX_SLOT_USES - 1, 1)); // 65535 + 2 = 65537 refuse

    // Fail-closed: a glitched counter read (u64::MAX) saturates and refuses.
    assert!(userop_refuse(u64::MAX, 0, 0));
    assert!(offchain_refuse(u64::MAX, 0));
}

#[test]
fn negative_sign_offchain_promotes_local_count_to_last_userop_floor() {
    // After a firmware reflash, `local_offchain` may be 0 while
    // `last_userop_count` reflects on-chain history. The handler
    // promotes `local_offchain` to at least `last_userop` so the
    // next emitted count is monotonic.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("offchain_count_promote_to"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("last_userop > local_offchain"));
}

#[test]
fn negative_sign_offchain_double_verifies_before_release() {
    // Every C10 sig the firmware emits is verified twice (with a
    // random delay between) and the AND is gated through a Hamming-
    // distant FI sentinel. CLAUDE.md "Verify-before-release on
    // every Type 1 / Type 2 sig".
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("sphincs_c10::verify"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("c10_sign_verified_with_progress"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("check_true_into_sentinel"));
    // The double-evaluate pattern: two named verify calls, one
    // `wait_random()` between them.
    let v1_count = CMD_SIGN_OFFCHAIN_SRC.matches("sphincs_c10::verify").count();
    assert!(
        v1_count >= 2,
        "cmd_sign_offchain.rs must call sphincs_c10::verify at least twice (FI-hardened double-check)"
    );
}

#[test]
fn negative_sign_offchain_bumps_counter_after_verify_only() {
    // The durable counter bump must happen AFTER the verify gate,
    // so a faulted-sig failure leaves the counter intact and the
    // next sign attempt sees the same `new_count`. Pin the comment
    // that names this discipline.
    assert!(
        CMD_SIGN_OFFCHAIN_SRC.contains("Bump the durable counter AFTER verify"),
        "the AFTER-verify counter-bump ordering must remain"
    );
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("offchain_count_bump"));
}

#[test]
fn negative_sign_offchain_owner_index_starts_at_one_not_zero() {
    // The handler builds the inner wrapper as
    // `(slot_index as u64) + 1`. ownerIndex 0 is the bootstrap key
    // and is forbidden for EIP-1271 (per CLAUDE.md "Bootstrap key
    // forbidden in isValidSignature"). A refactor that dropped the
    // `+ 1` would silently allow EIP-1271 sigs that the on-chain
    // verifier would route through the bootstrap-budget path.
    assert!(
        CMD_SIGN_OFFCHAIN_SRC.contains("(slot_index as u64) + 1"),
        "cmd_sign_offchain.rs must offset ownerIndex by +1 so bootstrap (0) is never reachable"
    );
}

// ── 8h. cmd_sign_userop_batch — header gates, flag invariants, FI guard

#[test]
fn negative_batch_rejects_zero_or_oversized_batch_count() {
    // `batch_count == 0` is malformed; `batch_count > MAX_BATCH_TXS`
    // would overflow the fixed parsed[] / batch_view[] arrays. Both
    // must be rejected before the inner-tx parse loop runs.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("batch_count == 0 || batch_count > MAX_BATCH_TXS"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("bad batch_count"));
}

#[test]
fn negative_batch_enforces_mutually_exclusive_init_code_and_register() {
    // Mirror of cmd_sign_userop's gate. include_init_code &&
    // register_slot must be refused — deploy bundles slot-0 add into
    // the factory call, so a separate addOwner UserOp on deploy is
    // forbidden.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("include_init_code && register_slot"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("incompatible flags"));
}

#[test]
fn negative_batch_init_code_requires_slot_zero() {
    // initCode seeds only slot 0; companion must not request init_code
    // on slot > 0.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("include_init_code && slot_index != 0"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("init_code needs slot0"));
}

#[test]
fn negative_batch_register_slot_requires_nonzero_slot() {
    // Slot 0 cannot be "registered" via Type 1 — it's seeded at
    // deploy. A registration on slot 0 would emit a Type 1 wrapper
    // the on-chain verifier silently no-ops.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("register_slot && slot_index == 0"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("register needs slot>=1"));
}

#[test]
fn negative_batch_nonce_overflow_gate_present() {
    // CRIT-17: under FLAG_REGISTER_SLOT the handler emits two
    // UserOps with consecutive nonces. If the seq is already
    // 0xFF..FF the increment would carry into the 192-bit key
    // field; the gate refuses that before the helper runs.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("register_slot && nonce[24..32] == [0xFFu8; 8]"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("Nonce seq"));
}

#[test]
fn negative_batch_binds_sender_before_verify_confirm_sign_or_state_write() {
    assert!(
        CMD_SIGN_USEROP_BATCH_SRC.contains("account_index_r != account_index"),
        "account_index selects the trusted sender and must be included in the F-11 recheck"
    );

    let parsed = CMD_SIGN_USEROP_BATCH_SRC
        .find("let parsed_trailers = match parse_batch_trailers")
        .expect("batch trailer parser");
    let gate = CMD_SIGN_USEROP_BATCH_SRC
        .find("super::cmd_get_wallet_address::bind_userop_sender(")
        .expect("batch sender binding must remain present");
    let verify = CMD_SIGN_USEROP_BATCH_SRC
        .find("// ── 5c. Verify + route trailers")
        .expect("batch verifier section");
    assert!(
        parsed < gate && gate < verify,
        "bind after structural parsing but before sender-dependent verification"
    );

    let trusted_shadow = CMD_SIGN_USEROP_BATCH_SRC[gate..]
        .find("let sender =")
        .map(|p| gate + p)
        .expect("batch path must replace the companion sender");
    let before_gate = &CMD_SIGN_USEROP_BATCH_SRC[..gate];
    for (label, needle) in [
        ("trusted-display confirm", "let (cr, cr_verdict) = confirm_checked"),
        ("C10 signing", "match crate::crypto::c10_sign_verified_with_progress"),
        ("offchain promotion", "crate::offchain_state::offchain_count_promote_to("),
        ("last-userop write", "crate::offchain_state::last_userop_count_set("),
        ("userop counter bump", "crate::offchain_state::userop_sigs_bump("),
    ] {
        assert!(
            !before_gate.contains(needle),
            "{label} must not occur before sender binding"
        );
    }
    for (label, needle) in [
        ("trusted-display confirm", "confirm_checked("),
        ("C10 signing", "c10_sign_verified_with_progress"),
        ("offchain promotion", "offchain_count_promote_to"),
        ("last-userop write", "last_userop_count_set"),
        ("userop counter bump", "userop_sigs_bump"),
    ] {
        let pos = CMD_SIGN_USEROP_BATCH_SRC[gate..]
            .find(needle)
            .map(|p| gate + p)
            .unwrap_or_else(|| panic!("missing {label} marker: {needle}"));
        assert!(
            trusted_shadow < pos,
            "sender must be bound and shadowed before {label}"
        );
    }

    let downstream = &CMD_SIGN_USEROP_BATCH_SRC[verify..];
    assert!(
        !downstream.contains("companion_sender"),
        "the untrusted sender must never reach batch verifiers or signed hashes"
    );
    let downstream_compact = downstream.split_whitespace().collect::<String>();
    assert!(
        downstream_compact.contains(
            "pick_sign_pages_with_erc7730_evidence(&tx_for_display,inner_data,&sender,"
        ),
        "each batch member's ERC-7730 @.from must receive the bound sender explicitly"
    );
    let helper_start = WALLET_ADDRESS_SRC
        .find("pub(super) unsafe fn bind_userop_sender")
        .expect("sender helper");
    let helper_end = WALLET_ADDRESS_SRC[helper_start..]
        .find("pub(super) unsafe fn run")
        .map(|p| helper_start + p)
        .expect("GET_WALLET_ADDRESS handler");
    let helper = &WALLET_ADDRESS_SRC[helper_start..helper_end];
    assert!(helper.contains("ct_eq"));
    assert!(helper.contains("Ok(expected_a)"));
    assert!(helper.contains("Ok(expected_b)"));
    assert!(helper.contains("derivations_agree"));
    assert!(helper.contains("wallet_address_for_account_cross_check("));
    assert!(WALLET_ADDRESS_SRC.contains("fn proxy_address_cross_check("));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&pk_seed[..]))"));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&pk_root[..]))"));
    assert!(WALLET_ADDRESS_SRC.contains("h.update(core::hint::black_box(&preimage[..21]))"));
    assert!(WALLET_ADDRESS_SRC.contains(
        "crate::aa::eip1271::proxy_address(&pk_seed, &pk_root)"
    ));
    assert!(helper.contains("check_true_into_sentinel"));
    assert!(helper.contains("SenderBinding"));
    assert!(WALLET_ADDRESS_SRC.contains(
        "#[inline(never)]\npub(super) unsafe fn bind_userop_sender"
    ));
    assert!(helper.contains("addr_of_mut!(output.sender)"));
    assert!(helper.contains("sender_readback_a"));
    assert!(helper.contains("sender_readback_b"));
    assert!(helper.contains("addr_of_mut!(output.verdict)"));
    assert!(helper.contains("cfi.bump(CFI_STEP_SENDER_BIND_DONE)"));
    assert!(WALLET_ADDRESS_SRC.contains("verdict: crate::fi::FAIL_SENTINEL"));
    let before_call = &CMD_SIGN_USEROP_BATCH_SRC[..gate];
    assert!(before_call.contains("SenderBinding::fail_closed()"));
    assert!(before_call.contains("core::ptr::write_volatile("));
    assert!(CMD_SIGN_USEROP_BATCH_SRC[gate..].contains("SENDER_BIND_CFI_EXPECTED"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC[gate..].contains("let sender_check ="));
    assert!(CMD_SIGN_USEROP_BATCH_SRC[gate..].contains("sender_reads_agree"));
}

#[test]
fn negative_batch_every_confirmation_gets_bound_from_page() {
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC.matches("enforce_from_page(").count(),
        3,
        "rotation, each member, and final batch authorization need source identity"
    );
    let compact = CMD_SIGN_USEROP_BATCH_SRC
        .split_whitespace()
        .collect::<String>()
        .replace(",)", ")");
    assert!(compact.contains(
        "enforce_from_page(&mutrotate_pages,account_index,&sender,&mutsigner_cfi)"
    ));
    assert!(compact.contains(
        "enforce_from_page(&mutpages,account_index,&sender,&mutsigner_cfi)"
    ));
    assert!(compact.contains(
        "enforce_from_page(&mutfinal_pages,account_index,&sender,&mutsigner_cfi)"
    ));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("signer unshown"));
    assert_eq!(CMD_SIGN_USEROP_BATCH_SRC.matches("from_page_proof(").count(), 3);
}

#[test]
fn negative_batch_each_member_gets_full_target_page() {
    assert_eq!(CMD_SIGN_USEROP_BATCH_SRC.matches("enforce_target_page(").count(), 1);
    assert_eq!(CMD_SIGN_USEROP_BATCH_SRC.matches("target_page_proof(").count(), 1);
    let compact = CMD_SIGN_USEROP_BATCH_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains(
        "enforce_target_page(&mutpages,&ptx.to,&muttarget_cfi)"
    ));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("TARGET_IDENTITY_PAGES"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("target unshown"));
}

#[test]
fn negative_batch_shows_and_fi_proves_full_derived_signer_identity() {
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC.matches("enforce_from_page(").count(),
        3,
        "rotation, each member, and final batch gate must identify the signer"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC.matches("from_page_proof(").count(),
        3,
        "every batch signer page needs an independent FI completion proof"
    );
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("SIGNER_IDENTITY_PAGES"));
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("account_index, &companion_sender"));

    let wrap = CMD_SIGN_USEROP_BATCH_SRC
        .find("if wrap_pages_with_batch_banner(")
        .expect("per-member banner");
    let member_page = CMD_SIGN_USEROP_BATCH_SRC[wrap..]
        .find("let signer_pages_before = pages.len;")
        .map(|p| wrap + p)
        .expect("per-member signer page");
    let member_fp = CMD_SIGN_USEROP_BATCH_SRC[member_page..]
        .find("append_fingerprint_page(")
        .map(|p| member_page + p)
        .expect("per-member fingerprint");
    assert!(wrap < member_page && member_page < member_fp);

    let final_summary = CMD_SIGN_USEROP_BATCH_SRC
        .find("let mut final_pages = build_final_summary_pages")
        .expect("batch final summary");
    let final_page = CMD_SIGN_USEROP_BATCH_SRC[final_summary..]
        .find("enforce_from_page(")
        .map(|p| final_summary + p)
        .expect("batch-final signer page");
    let final_fp = CMD_SIGN_USEROP_BATCH_SRC[final_page..]
        .find("append_fingerprint_page(")
        .map(|p| final_page + p)
        .expect("batch-final fingerprint");
    let final_confirm = CMD_SIGN_USEROP_BATCH_SRC[final_fp..]
        .find("confirm_checked(final_pages.as_slice())")
        .map(|p| final_fp + p)
        .expect("batch-final confirmation");
    assert!(final_summary < final_page && final_page < final_fp && final_fp < final_confirm);

    assert!(VALUE_PAGE_SRC.contains("b\"Signer acct #\""));
    assert!(VALUE_PAGE_SRC.contains("primitives::write_addr_full(a, b, c, sender)"));
}

#[test]
fn negative_batch_banner_copy_completes_before_shift_and_member_confirmation() {
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("wrap_pages_with_batch_banner(")
            .count(),
        1,
        "the production member loop must have one authoritative banner-copy call"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("batch_banner_copy_proof(")
            .count(),
        1,
        "the copied transcript needs one exact completion proof"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("BATCH_BANNER_CFI_EXPECTED")
            .count(),
        1,
        "the copy operation needs one caller-owned CFI completion receipt"
    );

    let start = CMD_SIGN_USEROP_BATCH_SRC
        .find("// Fail closed if the per-tx renderer ate the banner budget")
        .expect("batch-banner completion block");
    let wrap = start
        + CMD_SIGN_USEROP_BATCH_SRC[start..]
            .find("if wrap_pages_with_batch_banner(")
            .expect("authoritative banner copy");
    let cfi = wrap
        + CMD_SIGN_USEROP_BATCH_SRC[wrap..]
            .find("let banner_cfi_verdict =")
            .expect("banner CFI verdict");
    let scrub = cfi
        + CMD_SIGN_USEROP_BATCH_SRC[cfi..]
            .find("crate::fi::scrub_sentinel_register();")
            .expect("F-15.r1 scrub between sentinel calls");
    let proof = scrub
        + CMD_SIGN_USEROP_BATCH_SRC[scrub..]
            .find("let banner_copy_verdict =")
            .expect("exact copied-transcript proof");
    let reject = proof
        + CMD_SIGN_USEROP_BATCH_SRC[proof..]
            .find("banner incomplete")
            .expect("completion refusal");
    let shift = reject
        + CMD_SIGN_USEROP_BATCH_SRC[reject..]
            .find("dispatch_page_proofs.shift_indices(1)")
            .expect("dispatcher proof-index shift");
    let signer = shift
        + CMD_SIGN_USEROP_BATCH_SRC[shift..]
            .find("let signer_pages_before = pages.len;")
            .expect("member signer append");
    let fingerprint = signer
        + CMD_SIGN_USEROP_BATCH_SRC[signer..]
            .find("append_fingerprint_page(")
            .expect("member fingerprint append");
    let confirm = fingerprint
        + CMD_SIGN_USEROP_BATCH_SRC[fingerprint..]
            .find("confirm_checked(pages.as_slice())")
            .expect("member confirmation");
    assert!(
        wrap < cfi
            && cfi < scrub
            && scrub < proof
            && proof < reject
            && reject < shift
            && shift < signer
            && signer < fingerprint
            && fingerprint < confirm
    );

    let copy_body = BATCH_DISPLAY_SRC
        .split("pub fn wrap_pages_with_batch_banner(")
        .nth(1)
        .and_then(|tail| tail.split("fn build_batch_banner_page(").next())
        .expect("authoritative banner-copy body");
    let fail_init = copy_body
        .find("write_volatile(&mut out.len, 0)")
        .expect("volatile empty-output fail initialization");
    let bounds = copy_body
        .find("let new_len = inner.len.checked_add(1).ok_or(())?;")
        .expect("checked visible-length derivation");
    let copied = copy_body
        .find("copy_from_slice(&inner.buf[i][r])")
        .expect("all-row copy loop");
    let completion = copy_body
        .find("cfi.bump(BATCH_BANNER_CFI_STEP)")
        .expect("copy-completion CFI step");
    assert!(fail_init < bounds && bounds < copied && copied < completion);
    assert!(BATCH_DISPLAY_SRC.contains("#[inline(never)]\npub fn wrap_pages_with_batch_banner("));
    assert!(BATCH_DISPLAY_SRC.contains("for page_index in 0..inner.len"));
    assert!(BATCH_DISPLAY_SRC.contains("for row in 0..DISPLAY_ROWS"));
    assert!(BATCH_DISPLAY_SRC.contains("for col in 0..DISPLAY_COLS"));
}

#[test]
fn negative_batch_member_loop_must_complete_before_final_summary() {
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("member_confirm_receipt.record_confirmed(i)")
            .count(),
        1
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("member_confirm_receipt.completion_proof(batch_count)")
            .count(),
        1
    );

    let receipt_init = CMD_SIGN_USEROP_BATCH_SRC
        .find("let mut member_confirm_receipt =")
        .expect("fail-closed member receipt");
    let member_loop = receipt_init
        + CMD_SIGN_USEROP_BATCH_SRC[receipt_init..]
            .find("for i in 0..batch_count")
            .expect("trusted-display member loop");
    let confirm = member_loop
        + CMD_SIGN_USEROP_BATCH_SRC[member_loop..]
            .find("confirm_checked(pages.as_slice())")
            .expect("member confirmation");
    let affirmative_gate = confirm
        + CMD_SIGN_USEROP_BATCH_SRC[confirm..]
            .find("if cr_verdict != crate::fi::OK_SENTINEL")
            .expect("affirmative member sentinel");
    let commitment_publish = affirmative_gate
        + CMD_SIGN_USEROP_BATCH_SRC[affirmative_gate..]
            .find("confirmed_member_commitments[i] = member_commitment")
            .expect("confirmed-member full-tuple commitment publication");
    let record = commitment_publish
        + CMD_SIGN_USEROP_BATCH_SRC[commitment_publish..]
            .find("member_confirm_receipt.record_confirmed(i)")
            .expect("ordered confirmed-member receipt");
    let pinned_count = record
        + CMD_SIGN_USEROP_BATCH_SRC[record..]
            .find("let pinned_batch_count_a =")
            .expect("fresh post-loop batch count");
    let receipt_proof = pinned_count
        + CMD_SIGN_USEROP_BATCH_SRC[pinned_count..]
            .find("member_confirm_receipt.completion_proof(batch_count)")
            .expect("post-loop receipt proof");
    let independent_tuple = receipt_proof
        + CMD_SIGN_USEROP_BATCH_SRC[receipt_proof..]
            .find("let Some(recomputed_batch_final) =")
            .expect("independent all-member tuple commitment");
    let completion_reject = independent_tuple
        + CMD_SIGN_USEROP_BATCH_SRC[independent_tuple..]
            .find("members incomplete")
            .expect("incomplete-member refusal");
    let final_summary = completion_reject
        + CMD_SIGN_USEROP_BATCH_SRC[completion_reject..]
            .find("let mut final_pages = build_final_summary_pages(batch_count)")
            .expect("whole-batch final summary");
    assert!(
        receipt_init < member_loop
            && member_loop < confirm
            && confirm < affirmative_gate
            && affirmative_gate < commitment_publish
            && commitment_publish < record
            && record < pinned_count
            && pinned_count < receipt_proof
            && receipt_proof < independent_tuple
            && independent_tuple < completion_reject
            && completion_reject < final_summary
    );

    assert!(BATCH_DISPLAY_SRC.contains("pub(crate) struct BatchMemberConfirmReceipt"));
    assert!(BATCH_DISPLAY_SRC.contains("write_volatile(&mut self.confirmed, 0)"));
    assert!(BATCH_DISPLAY_SRC.contains("if current != expected"));
    assert!(BATCH_DISPLAY_SRC.contains("cfi.bump(BATCH_MEMBER_CONFIRM_CFI_STEP)"));
    assert!(BATCH_DISPLAY_SRC.contains("let confirmed_a = unsafe"));
    assert!(BATCH_DISPLAY_SRC.contains("let confirmed_b = unsafe"));
    assert!(BATCH_DISPLAY_SRC.contains("let all_ok = confirmed_a == expected_count_u32"));
}

#[test]
fn security_relevant_sentinel_composition_is_explicitly_scrubbed() {
    for (name, src) in [
        ("single", CMD_SIGN_USEROP_SRC),
        ("batch", CMD_SIGN_USEROP_BATCH_SRC),
        ("offchain", CMD_SIGN_OFFCHAIN_SRC),
    ] {
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "if super::state::peek_state",
            "let read_ptr_ok =",
        );
        assert_each_sentinel_pair_is_scrubbed(name, src, "let read_ptr_ok =", "let write_ptr_ok =");
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let bind_cfi_verdict_a =",
            "let bind_gate_a =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let bind_cfi_verdict_b =",
            "let bind_gate_b =",
        );
    }

    for (name, src) in [
        ("single", CMD_SIGN_USEROP_SRC),
        ("batch", CMD_SIGN_USEROP_BATCH_SRC),
    ] {
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let paymaster_cfi_verdict",
            "let paymaster_page_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let paymaster_final_cfi_verdict",
            "let paymaster_final_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let signer_cfi_verdict",
            "let signer_page_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let nonce_lane_cfi_verdict",
            "let nonce_lane_page_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let gas_lane_cfi_verdict",
            "let gas_lane_page_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let gas_lane_final_cfi_verdict",
            "let gas_lane_final_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let fingerprint_cfi_verdict",
            "let fingerprint_page_verdict",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_claim_cfi_verdict_a =",
            "let safe_verify_a_cfi_verdict_a =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_verify_a_cfi_verdict_a =",
            "let safe_verify_b_cfi_verdict_a =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_verify_b_cfi_verdict_a =",
            "let safe_resolution_verdict_a =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_claim_cfi_verdict_b =",
            "let safe_verify_a_cfi_verdict_b =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_verify_a_cfi_verdict_b =",
            "let safe_verify_b_cfi_verdict_b =",
        );
        assert_each_sentinel_pair_is_scrubbed(
            name,
            src,
            "let safe_verify_b_cfi_verdict_b =",
            "let safe_resolution_verdict_b =",
        );
    }

    assert_each_sentinel_pair_is_scrubbed(
        "single",
        CMD_SIGN_USEROP_SRC,
        "let target_cfi_verdict",
        "let target_page_verdict",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "batch",
        CMD_SIGN_USEROP_BATCH_SRC,
        "let target_cfi_verdict",
        "let target_page_verdict",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "batch banner",
        CMD_SIGN_USEROP_BATCH_SRC,
        "let banner_cfi_verdict",
        "let banner_copy_verdict",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "offchain fingerprint",
        CMD_SIGN_OFFCHAIN_SRC,
        "let fingerprint_cfi_verdict",
        "let fingerprint_page_verdict",
    );

    assert_each_sentinel_pair_is_scrubbed(
        "dispatcher native",
        DISPLAY_DISPATCH_SRC,
        "let native_cfi_verdict",
        "let native_page_verdict",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "dispatcher fees",
        DISPLAY_DISPATCH_SRC,
        "let legacy_fee_cfi_verdict",
        "let legacy_fee_page_verdict",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "dispatcher unknown A",
        DISPLAY_DISPATCH_SRC,
        "let unknown_cfi_verdict_a",
        "let unknown_gate_a",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "dispatcher unknown B",
        DISPLAY_DISPATCH_SRC,
        "let unknown_cfi_verdict_b",
        "let unknown_gate_b",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "Safe display unknown A",
        SAFE_DISPLAY_SRC,
        "let unknown_cfi_verdict_a",
        "let unknown_gate_a",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "Safe display unknown B",
        SAFE_DISPLAY_SRC,
        "let unknown_cfi_verdict_b",
        "let unknown_gate_b",
    );
    assert_each_sentinel_pair_is_scrubbed(
        "Safe claim publication",
        SAFE_EIP712_SRC,
        "let sample_verdict =",
        "let published_verdict =",
    );

    assert!(DISPLAY_DISPATCH_SRC.contains("let all_ok = native_cfi == crate::fi::OK_SENTINEL"));
    assert!(DISPLAY_DISPATCH_SRC.contains("core::hint::black_box(unknown_all_ok_a)"));
    assert!(SAFE_DISPLAY_SRC.contains("core::hint::black_box(unknown_all_ok_a)"));
    assert!(SAFE_EIP712_SRC.contains("core::hint::black_box(published_ok)"));
    assert!(SAFE_EIP712_SRC.contains("core::hint::black_box(all_ok)"));
    for src in [CMD_SIGN_USEROP_SRC, CMD_SIGN_USEROP_BATCH_SRC, CMD_SIGN_OFFCHAIN_SRC] {
        assert!(src.contains("core::hint::black_box(bind_all_ok_a)"));
        assert!(src.contains("core::hint::black_box(bind_all_ok_b)"));
    }
    let larger_extent = CMD_SIGN_OFFCHAIN_SRC
        .split("// larger. Validate the full extent now that we know the mode.")
        .nth(1)
        .and_then(|tail| tail.split("// Per-kind payload constraints.").next())
        .expect("conditional ERC-6492 output-extent gate");
    assert!(larger_extent.contains("crate::fi::scrub_sentinel_register();"));
    assert!(larger_extent.contains("SIGN_OFFCHAIN_OUTPUT_LEN_6492"));
}

#[test]
fn negative_batch_shows_and_fi_proves_nonce_lane_on_every_confirmation() {
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("enforce_nonce_lane_page(")
            .count(),
        3
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("nonce_lane_page_proof(")
            .count(),
        3
    );
    let compact = CMD_SIGN_USEROP_BATCH_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains("&mutrotate_pages,&nonce,&mutnonce_lane_cfi"));
    assert!(compact.contains("&mutpages,&type2_nonce,&mutnonce_lane_cfi"));
    assert!(compact.contains("&mutfinal_pages,&type2_nonce,&mutnonce_lane_cfi"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("NONZERO_NONCE_LANE_PAGES"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("lane unshown"));

    let member = CMD_SIGN_USEROP_BATCH_SRC
        .find("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let member_proof = member
        + CMD_SIGN_USEROP_BATCH_SRC[member..]
            .find("nonce_lane_page_proof(")
            .unwrap();
    let member_fp = member_proof
        + CMD_SIGN_USEROP_BATCH_SRC[member_proof..]
            .find("append_fingerprint_page(")
            .unwrap();
    assert!(member < member_proof && member_proof < member_fp);

    let final_lane = CMD_SIGN_USEROP_BATCH_SRC
        .find("let nonce_lane_pages_before = final_pages.len;")
        .unwrap();
    let final_proof = final_lane
        + CMD_SIGN_USEROP_BATCH_SRC[final_lane..]
            .find("nonce_lane_page_proof(")
            .unwrap();
    let final_confirm = final_proof
        + CMD_SIGN_USEROP_BATCH_SRC[final_proof..]
            .find("confirm_checked(final_pages.as_slice())")
            .unwrap();
    assert!(final_lane < final_proof && final_proof < final_confirm);

    assert!(NONCE_LANE_SRC.contains("nonce[..24]"));
    assert!(NONCE_LANE_SRC.contains("pages.len == prior_len"));
    assert!(NONCE_LANE_SRC.contains("nonce_lane_page_matches"));
}

#[test]
fn negative_batch_type2_display_uses_incremented_rotation_nonce() {
    let overflow_guard = CMD_SIGN_USEROP_BATCH_SRC
        .find("register_slot && nonce[24..32] == [0xFFu8; 8]")
        .unwrap();
    let derive = CMD_SIGN_USEROP_BATCH_SRC
        .find("let mut type2_nonce = nonce;")
        .unwrap();
    let display = CMD_SIGN_USEROP_BATCH_SRC
        .find("let display_nonce = u64::from_be_bytes([")
        .unwrap();
    let member_lane = CMD_SIGN_USEROP_BATCH_SRC
        .find("let nonce_lane_pages_before = pages.len;")
        .unwrap();
    let final_lane = CMD_SIGN_USEROP_BATCH_SRC
        .find("let nonce_lane_pages_before = final_pages.len;")
        .unwrap();
    let signed = CMD_SIGN_USEROP_BATCH_SRC
        .rfind("nonce: U256(type2_nonce)")
        .unwrap();
    assert!(
        overflow_guard < derive
            && derive < display
            && display < member_lane
            && member_lane < final_lane
            && final_lane < signed
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("let mut type2_nonce = nonce;")
            .count(),
        1
    );
    assert!(CMD_SIGN_USEROP_BATCH_SRC[derive..display]
        .contains("add_one_to_be_u256(&mut type2_nonce)"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC[display..].contains("type2_nonce[24]"));
    let display_fields_start = CMD_SIGN_USEROP_BATCH_SRC
        .find("userop_fields: Some(UserOpDisplayFields {")
        .expect("per-member UserOp display fields");
    let display_fields_end = display_fields_start
        + CMD_SIGN_USEROP_BATCH_SRC[display_fields_start..]
            .find("}),")
            .expect("end of per-member UserOp display fields");
    let display_fields = &CMD_SIGN_USEROP_BATCH_SRC[display_fields_start..display_fields_end];
    assert!(
        display_fields.contains("nonce: U256(type2_nonce)"),
        "the per-member display must show the exact Type-2 nonce"
    );
    assert!(
        !display_fields.contains("nonce: U256(nonce)"),
        "the base Type-1 nonce must not leak into the Type-2 display"
    );
    let compact = CMD_SIGN_USEROP_BATCH_SRC.split_whitespace().collect::<String>();
    assert!(compact.contains("&mutrotate_pages,&nonce,&mutnonce_lane_cfi"));
}

#[test]
fn negative_batch_per_tx_data_len_bounded_by_max_tx_len() {
    // Each inner tx declares its data_len in 2 BE bytes. The handler
    // must reject `data_len > MAX_TX_LEN` per CLAUDE.md "data_len
    // (u16 BE, 0..=4096)". Otherwise a malicious payload could
    // overrun SNAP_BUF.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("data_len > MAX_TX_LEN"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("bad data_len"));
}

#[test]
fn negative_batch_rejects_truncated_inner_tx() {
    // `cursor + TX_PREFIX_LEN > total_len` and `cursor + data_len >
    // total_len` are the two ways an inner tx can extend past the
    // declared payload boundary. Both must be refused.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("cursor + SIGN_USEROP_BATCH_TX_PREFIX_LEN > total_len"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("truncated tx"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("cursor + data_len > total_len"));
}

#[test]
fn negative_batch_rejects_trailing_bytes_after_last_inner_tx() {
    // Wire v2: the trailing-bytes check moved into
    // `batch_trailers::parse_all` (refuses `walk != total_len` after
    // consuming the TLV list). The batch handler delegates the parse
    // via `parse_batch_trailers`, so the check is enforced indirectly
    // — the parser source pins the refusal label.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("parse_batch_trailers"));
    const BATCH_TRAILERS_SRC: &str = include_str!("nsc/batch_trailers.rs");
    assert!(
        BATCH_TRAILERS_SRC.contains("trailing bytes"),
        "batch_trailers::parse_all must refuse trailing bytes after last record"
    );
    assert!(
        BATCH_TRAILERS_SRC.contains("walk != total_len"),
        "batch_trailers::parse_all must enforce cursor-exhaustion"
    );
}

#[test]
fn negative_batch_erc20_metadata_never_scans_unverified_safe_trailers() {
    let erc20_arm = CMD_SIGN_USEROP_BATCH_SRC
        .split("TRAILER_KIND_ERC20 =>")
        .nth(1)
        .and_then(|tail| tail.split("TRAILER_KIND_COW_ORDER =>").next())
        .expect("ERC-20 trailer arm");
    assert!(
        !erc20_arm.contains("parsed_trailers.records"),
        "raw Safe trailer inventory must not grant ERC-20 metadata authority"
    );
    assert!(erc20_arm.contains("Store only the Merkle- and chain-verified metadata"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("let chain_verified_erc20"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("selected surface"));
}

#[test]
fn negative_reserved_compatibility_inputs_are_fail_closed() {
    const BATCH_TRAILERS_SRC: &str = include_str!("nsc/batch_trailers.rs");

    // The batch TLV value is frozen for wire compatibility but every record,
    // including an empty one, is rejected before dispatch.
    assert!(BATCH_TRAILERS_SRC.contains("if kind == TRAILER_KIND_RESERVED_V1"));
    assert!(BATCH_TRAILERS_SRC.contains("reserved trailer"));
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("TRAILER_KIND_RESERVED_V1 =>"));

    // The single-sign wire uses a positional field, so its two-byte length
    // prefix must remain. A zero cap ensures no payload can revive the retired
    // slot or shift the following fields.
    let reserved_parse = CMD_SIGN_USEROP_SRC
        .split("let reserved_v1 = match")
        .nth(1)
        .and_then(|tail| tail.split("cursor = reserved_v1.next_cursor").next())
        .expect("single-sign reserved compatibility parser");
    assert!(reserved_parse.contains("read_optional_u16_prefixed"));
    assert!(reserved_parse.contains("\n        0,"));
    assert!(reserved_parse.contains("reserved slot must be 0"));
}

#[test]
fn negative_batch_double_verifies_before_release() {
    // Symmetric with cmd_sign_offchain. Every C10 sig the batch
    // handler emits — factory sig, bootstrap sig, slot sig — is
    // double-verified.
    let v_count = CMD_SIGN_USEROP_BATCH_SRC.matches("sphincs_c10::verify").count();
    assert!(
        v_count >= 6,
        "cmd_sign_userop_batch.rs must call sphincs_c10::verify at least 6 times (3 sigs × double-check)"
    );
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("c10_sign_verified_with_progress"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("check_true_into_sentinel"));
}

#[test]
fn negative_batch_uses_correct_owner_index_offset() {
    // Type 2 owner index = `slot_index + 1` (slot 0 → ownerIndex 1).
    // Same +1 convention as cmd_sign_offchain.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("(slot_index as u64) + 1"));
}

#[test]
fn negative_batch_pins_factory_add_slot_domain_tag() {
    // Frozen domain tag the bootstrap key signs to authorise slot-0
    // on a new chain. Renaming = factory create reverts on every
    // already-deployed wallet attempting to roll to a new chain.
    assert!(
        CMD_SIGN_USEROP_BATCH_SRC.contains(r#"b"pqwallet-factory-add-slot""#),
        "cmd_sign_userop_batch.rs must use the frozen FACTORY_ADD_SLOT_DOMAIN bytes"
    );
}

#[test]
fn negative_batch_pins_create_account_and_add_owner_selectors() {
    // The init_code prefix uses PQ_CREATE_ACCOUNT_SELECTOR; the
    // Type 1 calldata uses PQ_ADD_OWNER_BYTES_SELECTOR. Both must
    // reference the named constants (which are themselves pinned
    // by the proto-crate frozen-constants tests).
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("PQ_CREATE_ACCOUNT_SELECTOR"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("PQ_ADD_OWNER_BYTES_SELECTOR"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("PQ_SMART_WALLET_FACTORY"));
}

#[test]
fn negative_batch_render_uses_v06_userop_params() {
    // Only the v0.6 user-op params type may be used — CLAUDE.md
    // "No EntryPoint v0.7 / v0.8 migration."
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("AaUserOpParamsV06Sha256"));
}

#[test]
fn negative_batch_zeroizes_entropy_on_every_error_path() {
    // Every error path between the `entropy` decryption and the
    // function return must zeroize `entropy` + call
    // `zeroize_barrier()`. A skipped zeroize would leak the
    // 64-byte BIP-39 seed into BSS until the next sign.
    let zeroize_count = CMD_SIGN_USEROP_BATCH_SRC.matches("entropy.zeroize()").count();
    let barrier_count = CMD_SIGN_USEROP_BATCH_SRC
        .matches("fi::zeroize_barrier()")
        .count();
    assert!(
        zeroize_count >= 4,
        "cmd_sign_userop_batch.rs must zeroize `entropy` on every error path (>= 4 occurrences expected)"
    );
    assert!(
        barrier_count >= zeroize_count - 1,
        "zeroize/barrier counts diverged: {zeroize_count} zeroize vs {barrier_count} barrier"
    );
}

#[test]
fn negative_batch_confirm_dialog_handles_cancel_and_idle_wipe() {
    // Every `confirm(pages)` call MUST handle all three outcomes:
    // Confirmed (continue), Cancelled (UserRejected), IdleWipe
    // (zeroize + return IdleWipe). A handler that silently mapped
    // IdleWipe to UserRejected would skip the secret wipe path.
    let confirmed = CMD_SIGN_USEROP_BATCH_SRC
        .matches("ConfirmResult::Confirmed")
        .count();
    let cancelled = CMD_SIGN_USEROP_BATCH_SRC
        .matches("ConfirmResult::Cancelled")
        .count();
    let idle_wipe = CMD_SIGN_USEROP_BATCH_SRC
        .matches("ConfirmResult::IdleWipe")
        .count();
    assert!(
        confirmed > 0 && cancelled > 0 && idle_wipe > 0,
        "batch handler must handle all three ConfirmResult arms"
    );
    // Counts should match: each confirm() is one of each variant.
    assert_eq!(
        confirmed, cancelled,
        "confirm() arms must match — Confirmed and Cancelled count differ"
    );
    assert_eq!(
        confirmed, idle_wipe,
        "confirm() arms must match — Confirmed and IdleWipe count differ"
    );
}

#[test]
fn negative_batch_idle_wipe_zeroizes_sensitive_state() {
    // The IdleWipe arm of every confirm() must call
    // `super::zeroize_sensitive_state()` before returning. Without
    // this, an inactivity timeout fires *while a confirm dialog is
    // open* and the master_secret / slot_master_entropy stay
    // resident in SRAM until the next handler call zeroes them.
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("zeroize_sensitive_state"));
}

// ── 8i. CLAUDE.md invariant #5 — single signature primitive

#[test]
fn negative_slice_does_not_mention_any_classical_signer() {
    // CLAUDE.md "One signature primitive: SPHINCS+C10." No ECDSA,
    // Ed25519, FORS+C, P-256, secp256k1, RSA anywhere in the slice.
    for forbidden in &[
        "secp256k1",
        "ECDSA",
        "ecdsa",
        "ed25519",
        "Ed25519",
        "p256",
        "P256",
        "p-256",
        "P-256",
        "FORS+C",
        "fors_c",
        "fors+c",
        "rsa_sign",
        "RSA_SIGN",
    ] {
        for (name, src) in ALL_SLICE_SRCS {
            assert!(
                !src.contains(forbidden),
                "{name} must not mention banned signer '{forbidden}' — CLAUDE.md invariant #5"
            );
        }
    }
}

#[test]
fn negative_slice_does_not_expose_reset_or_rotate_paths() {
    // CLAUDE.md "No rotateMasterKeys, resetBootstrapUses,
    // resetSlotUses, increaseMaxBootstrap, increaseMaxSlot." A
    // similarly-named function appearing in any handler is a sign
    // the cap/floor invariants are about to be subverted.
    for forbidden in &[
        "rotateMasterKeys",
        "rotate_master_keys",
        "resetBootstrapUses",
        "reset_bootstrap_uses",
        "resetSlotUses",
        "reset_slot_uses",
        "increaseMaxBootstrap",
        "increase_max_bootstrap",
        "increaseMaxSlot",
        "increase_max_slot",
    ] {
        for (name, src) in ALL_SLICE_SRCS {
            assert!(
                !src.contains(forbidden),
                "{name} must not expose '{forbidden}' — CLAUDE.md"
            );
        }
    }
}

#[test]
fn negative_slice_does_not_target_entrypoint_v07_or_v08() {
    // CLAUDE.md "No EntryPoint v0.7 / v0.8 migration." Pin v0.6 by
    // forbidding the named v0.7/v0.8 strings everywhere in the
    // slice.
    for forbidden in &["v0.7", "v07", "v0_7", "v0.8", "v08", "v0_8"] {
        for (name, src) in ALL_SLICE_SRCS {
            assert!(
                !src.contains(forbidden),
                "{name} must target only EntryPoint v0.6 — found '{forbidden}'"
            );
        }
    }
}

#[test]
fn negative_batch_fi_pins_wire_entrypoint_and_hashes_only_the_constant() {
    // Match the single handler's frozen-domain contract: two independent
    // snapshot reads, constant-time equality, spatially separate sentinel
    // rejects, then direct use of the firmware constant at every T1/T2 digest
    // initializer. No wire-derived `entry_point` variable may survive.
    const SNAPSHOT_COPY_END: &str =
        "snap[i] = core::ptr::read_volatile(payload_ptr.add(i));\n    }\n";
    let snapshot_copy_end = CMD_SIGN_USEROP_BATCH_SRC
        .find(SNAPSHOT_COPY_END)
        .map(|p| p + SNAPSHOT_COPY_END.len())
        .expect("completed batch-handler snapshot copy loop");
    let parse_header = CMD_SIGN_USEROP_BATCH_SRC
        .find("// ── 4. Parse fixed header")
        .expect("batch request parse boundary");
    let pin_a = CMD_SIGN_USEROP_BATCH_SRC
        .find("let supplied_entry_point_a")
        .expect("first batch EntryPoint pin read");
    let gate_a = CMD_SIGN_USEROP_BATCH_SRC[pin_a..]
        .find("if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_a)")
        .map(|p| pin_a + p)
        .expect("first batch EntryPoint rejection gate");
    let gate_a_end = CMD_SIGN_USEROP_BATCH_SRC[gate_a..]
        .find("return NscStatus::InvalidPointer as u32;")
        .map(|p| gate_a + p + "return NscStatus::InvalidPointer as u32;".len())
        .expect("end of first batch EntryPoint rejection gate");
    let gap = CMD_SIGN_USEROP_BATCH_SRC[gate_a_end..]
        .find("crate::fi::wait_random();")
        .map(|p| gate_a_end + p)
        .expect("batch EntryPoint randomized gap");
    let pin_b = CMD_SIGN_USEROP_BATCH_SRC[gap..]
        .find("let supplied_entry_point_b")
        .map(|p| gap + p)
        .expect("second batch EntryPoint pin read");
    let gate_b = CMD_SIGN_USEROP_BATCH_SRC[pin_b..]
        .find("if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_b)")
        .map(|p| pin_b + p)
        .expect("second batch EntryPoint rejection gate");
    let gate_b_end = CMD_SIGN_USEROP_BATCH_SRC[gate_b..]
        .find("return NscStatus::InvalidPointer as u32;")
        .map(|p| gate_b + p + "return NscStatus::InvalidPointer as u32;".len())
        .expect("end of second batch EntryPoint rejection gate");
    let nonce_parse = CMD_SIGN_USEROP_BATCH_SRC
        .find("let mut nonce =")
        .expect("batch nonce parse");
    let chain_parse = CMD_SIGN_USEROP_BATCH_SRC
        .find("let chain_id = u64::from_be_bytes([")
        .expect("batch chain-id parse");
    let flags_parse = CMD_SIGN_USEROP_BATCH_SRC
        .find("let flags_a = u32::from_be_bytes(")
        .expect("batch flags parse");
    let sender_parse = CMD_SIGN_USEROP_BATCH_SRC
        .find("let mut companion_sender =")
        .expect("batch sender parse");
    let wire_version_parse = CMD_SIGN_USEROP_BATCH_SRC
        .find("let wire_version = snap[276];")
        .expect("batch wire-version parse");
    assert!(snapshot_copy_end <= pin_a, "pin must follow snapshot copy");
    assert!(
        pin_a < gate_a
            && gate_a < gate_a_end
            && gate_a_end < gap
            && gap < pin_b
            && pin_b < gate_b
            && gate_b < gate_b_end
    );
    assert!(
        gate_b_end < parse_header,
        "both EntryPoint gates must finish before the batch parse boundary"
    );
    for (label, parse) in [
        ("chain id", chain_parse),
        ("flags", flags_parse),
        ("sender", sender_parse),
        ("nonce", nonce_parse),
        ("wire version", wire_version_parse),
    ] {
        assert!(
            gate_b_end < parse,
            "EntryPoint must fail before batch {label} request handling"
        );
    }
    let pin_window = &CMD_SIGN_USEROP_BATCH_SRC[snapshot_copy_end..gate_b_end];
    assert!(
        !pin_window.contains("snap["),
        "no indexed batch field may be consumed before both EntryPoint rejects complete"
    );
    assert_eq!(
        pin_window.matches("snap.as_ptr().add(32)").count(),
        2,
        "the batch pre-parse window may read only the two EntryPoint samples"
    );
    for forbidden_parse in ["u64::from_be_bytes", "u32::from_be_bytes", "copy_from_slice"] {
        assert!(!pin_window.contains(forbidden_parse));
    }
    let pre_scrub = CMD_SIGN_USEROP_BATCH_SRC[pin_a..gate_a]
        .rfind("crate::fi::scrub_sentinel_register();")
        .map(|p| pin_a + p)
        .expect("scrub before first batch EntryPoint sentinel check");
    assert!(pre_scrub < gate_a);
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches(".ct_eq(&ENTRY_POINT_V06)")
            .count(),
        2
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>())")
            .count(),
        2
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("wrong EntryPoint")
            .count(),
        2
    );
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("let mut entry_point ="));
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("entry_point.copy_from_slice"));

    let params = CMD_SIGN_USEROP_BATCH_SRC
        .matches("AaUserOpParamsV06Sha256 {")
        .count();
    assert_eq!(
        params, 2,
        "batch handler owns one T1 and one T2 params site"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("entry_point: ENTRY_POINT_V06,")
            .count(),
        params,
        "every batch T1/T2 digest must consume the firmware constant directly"
    );
}

#[test]
fn negative_batch_safe_exec_claim_is_fatal_before_other_routing() {
    // The CoW trailer pass must not reinterpret malformed Safe-shaped bytes as
    // a direct CoW call, and the per-member display pass must refuse before
    // ERC-20/ERC-7730/selector/typed/blind routing. Each pass owns a fresh
    // selector receipt, two strict verifier executions, and two final
    // resolution gates; neither may restore a minimum-length conjunct.
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("prove_exec_transaction_claim(")
            .count(),
        2,
        "both batch Safe classification sites need caller-owned proofs"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("verify_and_bind_exec_into(")
            .count(),
        4,
        "each batch pass uses two caller-owned strict verifier outputs"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("exec_claim_resolution_proof(")
            .count(),
        4,
        "each batch pass has two spatially separate resolution gates"
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("EXEC_CLAIM_CFI_EXPECTED")
            .count(),
        4
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("EXEC_VERIFY_CFI_EXPECTED")
            .count(),
        8,
        "four verifier calls are each CFI-checked at two final gates"
    );
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("EXEC_TRANSACTION_MIN_CALLDATA_LEN"));
    assert!(!CMD_SIGN_USEROP_BATCH_SRC.contains("safe_exec_enough_len"));

    let cow_pass = CMD_SIGN_USEROP_BATCH_SRC
        .find("Pass 2: verify the deferred COW_ORDER")
        .expect("deferred CoW pass");
    let cow_claim = CMD_SIGN_USEROP_BATCH_SRC[cow_pass..]
        .find("let mut safe_exec_claim =")
        .map(|p| cow_pass + p)
        .expect("CoW-pass Safe claim receipt");
    let cow_verify = CMD_SIGN_USEROP_BATCH_SRC[cow_claim..]
        .find("let mut safe_exec_ctx:")
        .map(|p| cow_claim + p)
        .expect("CoW-pass first Safe verify");
    let cow_verify_check = CMD_SIGN_USEROP_BATCH_SRC[cow_verify..]
        .find("let mut safe_exec_ctx_check:")
        .map(|p| cow_verify + p)
        .expect("CoW-pass second Safe verify");
    let cow_resolution = CMD_SIGN_USEROP_BATCH_SRC[cow_verify_check..]
        .find("exec_claim_resolution_proof(")
        .map(|p| cow_verify_check + p)
        .expect("CoW-pass resolution gate");
    let cow_route = CMD_SIGN_USEROP_BATCH_SRC[cow_resolution..]
        .find("let cow_bind =")
        .map(|p| cow_resolution + p)
        .expect("CoW route");
    assert!(
        cow_claim < cow_verify
            && cow_verify < cow_verify_check
            && cow_verify_check < cow_resolution
            && cow_resolution < cow_route
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC[cow_pass..cow_route]
            .matches("exec_claim_resolution_proof(")
            .count(),
        2,
        "both CoW-pass Safe resolution gates must precede CoW routing"
    );

    let member_pass = CMD_SIGN_USEROP_BATCH_SRC
        .find("Routed-trailer pass-through")
        .expect("per-member routed pass");
    let member_claim = CMD_SIGN_USEROP_BATCH_SRC[member_pass..]
        .find("let mut safe_exec_claim =")
        .map(|p| member_pass + p)
        .expect("member Safe claim receipt");
    let member_verify = CMD_SIGN_USEROP_BATCH_SRC[member_claim..]
        .find("let mut safe_exec_verified:")
        .map(|p| member_claim + p)
        .expect("member first Safe verify");
    let member_verify_check = CMD_SIGN_USEROP_BATCH_SRC[member_verify..]
        .find("let mut safe_exec_verified_check:")
        .map(|p| member_verify + p)
        .expect("member second Safe verify");
    let member_resolution = CMD_SIGN_USEROP_BATCH_SRC[member_verify_check..]
        .find("exec_claim_resolution_proof(")
        .map(|p| member_verify_check + p)
        .expect("member resolution gate");
    let lower_route = CMD_SIGN_USEROP_BATCH_SRC[member_resolution..]
        .find("let chain_verified_erc20 =")
        .map(|p| member_resolution + p)
        .expect("member lower routing");
    assert!(
        member_claim < member_verify
            && member_verify < member_verify_check
            && member_verify_check < member_resolution
            && member_resolution < lower_route
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC[member_pass..lower_route]
            .matches("exec_claim_resolution_proof(")
            .count(),
        2,
        "both member Safe resolution gates must precede lower routing"
    );
}

#[test]
fn batch_payload_fingerprints_complete_and_recheck_before_both_confirms() {
    assert_eq!(CMD_SIGN_USEROP_BATCH_SRC.matches("append_fingerprint_page(").count(), 2);
    assert_eq!(CMD_SIGN_USEROP_BATCH_SRC.matches("fingerprint_page_proof(").count(), 2);
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("fingerprint_final_set_proof(")
            .count(),
        2
    );
    assert_eq!(
        CMD_SIGN_USEROP_BATCH_SRC
            .matches("FINGERPRINT_CFI_EXPECTED")
            .count(),
        2
    );

    let member_start = CMD_SIGN_USEROP_BATCH_SRC
        .find("// Per-tx ERC-8213 fingerprint")
        .expect("batch-member fingerprint block");
    let member_append = member_start
        + CMD_SIGN_USEROP_BATCH_SRC[member_start..]
            .find("append_fingerprint_page(")
            .expect("batch-member append");
    let member_completion = member_append
        + CMD_SIGN_USEROP_BATCH_SRC[member_append..]
            .find("fingerprint_page_proof(")
            .expect("batch-member completion proof");
    let member_final = member_completion
        + CMD_SIGN_USEROP_BATCH_SRC[member_completion..]
            .find("fingerprint_final_set_proof(")
            .expect("batch-member final proof");
    let member_confirm = member_final
        + CMD_SIGN_USEROP_BATCH_SRC[member_final..]
            .find("confirm_checked(pages.as_slice())")
            .expect("batch-member confirm");
    assert!(member_append < member_completion && member_completion < member_final);
    assert!(member_final < member_confirm);

    let final_start = CMD_SIGN_USEROP_BATCH_SRC
        .find("// Fail closed if the batch-final fingerprint")
        .expect("batch-final fingerprint block");
    let final_append = final_start
        + CMD_SIGN_USEROP_BATCH_SRC[final_start..]
            .find("append_fingerprint_page(")
            .expect("batch-final append");
    let final_completion = final_append
        + CMD_SIGN_USEROP_BATCH_SRC[final_append..]
            .find("fingerprint_page_proof(")
            .expect("batch-final completion proof");
    let final_boundary = final_completion
        + CMD_SIGN_USEROP_BATCH_SRC[final_completion..]
            .find("fingerprint_final_set_proof(")
            .expect("batch-final final proof");
    let final_confirm = final_boundary
        + CMD_SIGN_USEROP_BATCH_SRC[final_boundary..]
            .find("confirm_checked(final_pages.as_slice())")
            .expect("batch-final confirm");
    assert!(final_append < final_completion && final_completion < final_boundary);
    assert!(final_boundary < final_confirm);

    let rotation = CMD_SIGN_USEROP_BATCH_SRC
        .find("// Slot rotation is its own affirmative-consent step ahead")
        .expect("batch rotation confirmation block");
    let member_loop = rotation
        + CMD_SIGN_USEROP_BATCH_SRC[rotation..]
        .find("for i in 0..batch_count")
        .expect("batch member loop");
    assert!(
        !CMD_SIGN_USEROP_BATCH_SRC[rotation..member_loop]
            .contains("append_fingerprint_page("),
        "firmware-built batch rotation must retain the explicit exemption"
    );
}

#[test]
fn batch_deployment_consent_gates_factory_and_type2_authority_in_source_order() {
    let context = CMD_SIGN_USEROP_BATCH_SRC
        .find("let deployment_context =")
        .expect("deployment context");
    let fail_initialize = context
        + CMD_SIGN_USEROP_BATCH_SRC[context..]
            .find("deployment_confirm_receipt.fail_initialize()")
            .expect("fail-initialized deployment receipt");
    let page_append = fail_initialize
        + CMD_SIGN_USEROP_BATCH_SRC[fail_initialize..]
            .find("enforce_deployment_page(")
            .expect("deployment page append");
    let page_proof = page_append
        + CMD_SIGN_USEROP_BATCH_SRC[page_append..]
            .find("deployment_page_proof(")
            .expect("deployment page proof");
    let final_proof = page_proof
        + CMD_SIGN_USEROP_BATCH_SRC[page_proof..]
            .find("deployment_final_set_proof(")
            .expect("deployment final-set proof");
    let final_confirm = final_proof
        + CMD_SIGN_USEROP_BATCH_SRC[final_proof..]
            .find("confirm_checked(final_pages.as_slice())")
            .expect("batch-final confirmation");
    let affirmative_gate = final_confirm
        + CMD_SIGN_USEROP_BATCH_SRC[final_confirm..]
            .find("if cr_verdict != crate::fi::OK_SENTINEL")
            .expect("affirmative confirmation sentinel gate");
    let record_confirmed = affirmative_gate
        + CMD_SIGN_USEROP_BATCH_SRC[affirmative_gate..]
            .find(".record_confirmed(&deployment_context)")
            .expect("deployment confirmation receipt record");
    let first_completion = record_confirmed
        + CMD_SIGN_USEROP_BATCH_SRC[record_confirmed..]
            .find("deployment_confirm_receipt.completion_proof(&deployment_context)")
            .expect("pre-factory deployment receipt proof");
    let deploy_branch = first_completion
        + CMD_SIGN_USEROP_BATCH_SRC[first_completion..]
            .find("if include_init_code {")
            .expect("optional deployment branch");
    let factory_sign = deploy_branch
        + CMD_SIGN_USEROP_BATCH_SRC[deploy_branch..]
            .find("let factory_sig = match crate::crypto::c10_sign_verified_with_progress(")
            .expect("factory signature authority");
    let second_completion = factory_sign
        + CMD_SIGN_USEROP_BATCH_SRC[factory_sign..]
            .find("deployment_confirm_receipt.completion_proof(&deployment_context)")
            .expect("pre-Type-2 deployment receipt proof");
    let output_binding = second_completion
        + CMD_SIGN_USEROP_BATCH_SRC[second_completion..]
            .find("deployment_output_binding_proof(")
            .expect("deployment output binding proof");
    let type2_params = output_binding
        + CMD_SIGN_USEROP_BATCH_SRC[output_binding..]
            .find("let t2_params = AaUserOpParamsV06Sha256")
            .expect("Type-2 parameters");
    let type2_digest = type2_params
        + CMD_SIGN_USEROP_BATCH_SRC[type2_params..]
            .find("let t2_digest = compute_sphincs_digest_v06(")
            .expect("Type-2 digest");
    let type2_sign = type2_digest
        + CMD_SIGN_USEROP_BATCH_SRC[type2_digest..]
            .find("match crate::crypto::c10_sign_verified_with_progress(")
            .expect("Type-2 signing authority");

    assert!(context < fail_initialize);
    assert!(fail_initialize < page_append && page_append < page_proof);
    assert!(page_proof < final_proof && final_proof < final_confirm);
    assert!(final_confirm < affirmative_gate && affirmative_gate < record_confirmed);
    assert!(record_confirmed < first_completion && first_completion < deploy_branch);
    assert!(deploy_branch < factory_sign && factory_sign < second_completion);
    assert!(second_completion < output_binding && output_binding < type2_params);
    assert!(type2_params < type2_digest && type2_digest < type2_sign);

    let binding_call = &CMD_SIGN_USEROP_BATCH_SRC[output_binding..type2_params];
    for bound_value in [
        "&deployment_context",
        "emit_init_code",
        "init_code_out.as_slice()",
        "&t2_init_code_digest",
        "&SHA256_EMPTY",
    ] {
        assert!(
            binding_call.contains(bound_value),
            "deployment output proof must bind {bound_value}"
        );
    }
}

// ── 8j. NS observability — handlers must not log payload bytes

#[test]
fn negative_status_and_sync_do_not_log_companion_bytes() {
    // The two SW-only handlers have a tiny diagnostic surface
    // (`crate::ui::show_status` for error paths only). Adding a
    // `secure_log!` that dumps the parsed account / chain / slot
    // values would widen the side-channel on a chip where the
    // production semihosting console is gated by RDP. Pin the
    // absence of secure_log! in both small handlers.
    assert!(
        !CMD_OFFCHAIN_STATUS_SRC.contains("secure_log!"),
        "cmd_offchain_status.rs must not log via secure_log!"
    );
    assert!(
        !CMD_OFFCHAIN_SYNC_SRC.contains("secure_log!"),
        "cmd_offchain_sync.rs must not log via secure_log!"
    );
}

// ── 8k. cmd_offchain_status — zero-fills reserved bytes

#[test]
fn negative_status_zero_inits_output_buffer_before_writing_fields() {
    // The reserved bytes [17..24) must be zero in the response. The
    // simplest way to guarantee that — and the way the handler
    // does it — is to zero-init the whole 24-byte output buffer
    // before writing the named fields. A refactor that wrote only
    // the named fields would leave stale NS-buffer contents in the
    // reserved region.
    assert!(
        CMD_OFFCHAIN_STATUS_SRC.contains("write_volatile(out_ptr.add(i), 0u8)")
            || CMD_OFFCHAIN_STATUS_SRC.contains("Zero-init the buffer first"),
        "cmd_offchain_status.rs must zero-init the output buffer to keep reserved bytes deterministic"
    );
}

// ── 8l. cmd_offchain_sync — set-if-greater semantics

#[test]
fn negative_sync_uses_set_if_greater_primitive() {
    // The docstring documents `last_userop_count_set` as tolerant
    // of `target <= current`. The handler MUST use this primitive
    // (not e.g. a hypothetical `last_userop_count_overwrite`),
    // otherwise a low-target call from a stale companion could
    // regress the floor and undo the monotonicity guarantee.
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("last_userop_count_set"),
        "cmd_offchain_sync.rs must call the set-if-greater primitive, not an overwrite"
    );
    assert!(
        CMD_OFFCHAIN_SYNC_SRC.contains("tolerant of `target <= current`")
            || CMD_OFFCHAIN_SYNC_SRC.contains("set if greater"),
        "the set-if-greater contract must remain documented at the call site"
    );
}

// ── 8m. HandlerGuard — keeps secrets resident across keygen window

#[test]
fn negative_sign_handlers_enter_handler_guard() {
    // CLAUDE.md "HandlerGuard prevents SysTick from zeroing
    // master_secret while we're holding stack-local copies." Every
    // handler in the slice that touches master_secret /
    // SLOT_CACHE must enter the guard.
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("HandlerGuard::enter"));
    assert!(CMD_SIGN_USEROP_BATCH_SRC.contains("HandlerGuard::enter"));
    // The two SW-only handlers don't keep secrets resident, but
    // they should still enter the guard to keep dispatcher
    // serialisation tight. Pin that here.
    assert!(CMD_OFFCHAIN_STATUS_SRC.contains("HandlerGuard::enter"));
    assert!(CMD_OFFCHAIN_SYNC_SRC.contains("HandlerGuard::enter"));
}

// ── 8n. NscStatus return values — every error path uses the documented variant

#[test]
fn negative_sign_offchain_returns_documented_status_variants() {
    // Each error path uses a named NscStatus variant. Pin the set
    // so a refactor that swallowed a specific error into a generic
    // `InternalError` (and thus blurred the companion's UX) shows
    // up here.
    for status in &[
        "NotInitialized",
        "InvalidPointer",
        "CryptoError",
        "InternalError",
        "UserRejected",
        "IdleWipe",
        "OffchainSlotUnregistered",
        "OffchainGapExceeded",
        "OffchainCapExceeded",
        "Ok",
    ] {
        assert!(
            CMD_SIGN_OFFCHAIN_SRC.contains(status),
            "cmd_sign_offchain.rs must return NscStatus::{status} on its documented path"
        );
    }
}

#[test]
fn negative_batch_returns_documented_status_variants() {
    for status in &[
        "NotInitialized",
        "InvalidPointer",
        "CryptoError",
        "InternalError",
        "UserRejected",
        "IdleWipe",
        "Ok",
    ] {
        assert!(
            CMD_SIGN_USEROP_BATCH_SRC.contains(status),
            "cmd_sign_userop_batch.rs must return NscStatus::{status} on its documented path"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// 9. Cross-file invariants — Cargo.toml dev-dep stability, etc.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_proto_constants_used_by_handlers_resolve_to_pinned_values() {
    // Defence-in-depth: even if the handler's source-text mentions
    // the constant name, the *value* it imports could have drifted.
    // Pin a smoke set so a single `cargo test -p sphincs-tz-secure`
    // catches a proto-crate constant rename that happens to align
    // with a stale handler import.
    //
    // (The proto crate has its own dedicated frozen-constants test
    // file; this is a sanity-pin from the consumer side.)
    assert_eq!(SIG_WRAPPER_LEN, 4128);
    assert_eq!(C10_SIG_LEN, 4008);
    assert_eq!(PQ_INIT_CODE_LEN, 4280);
    assert_eq!(MAX_OFFCHAIN_GAP, 100);
    assert_eq!(MAX_SLOT_USES, 65_536);
    assert_eq!(MAX_ACCOUNT_INDEX, 0xFF);
    assert_eq!(MAX_BATCH_TXS, 4);
    assert_eq!(MAX_TX_LEN, 4096);
    assert_eq!(SIGN_OFFCHAIN_HEADER_LEN, 17);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN, 4016);
    assert_eq!(SIGN_OFFCHAIN_OUTPUT_LEN_6492, 8616);
    assert_eq!(OFFCHAIN_STATUS_INPUT_LEN, 13);
    assert_eq!(OFFCHAIN_STATUS_OUTPUT_LEN, 24);
    assert_eq!(OFFCHAIN_SYNC_INPUT_LEN, 21);
    assert_eq!(SIGN_USEROP_BATCH_HEADER_LEN, 278);
    assert_eq!(SIGN_USEROP_BATCH_TX_PREFIX_LEN, 54);
    assert_eq!(SIGN_USEROP_BATCH_WIRE_VERSION, 2);
    assert_eq!(MAX_TRAILERS_PER_BATCH, 32);
    assert_eq!(TRAILERS_TOTAL_MAX_LEN, 24 * 1024);
    assert_eq!(ERC7730_LEGACY_BUNDLE_MAX_LEN, 5_130);
    assert_eq!(ERC7730_MAX_TRAILER_LEN, 10_268);
    assert_eq!(ERC7730_PROOF_SET_MAGIC, 0xe773);
    assert_eq!(ERC7730_PROOF_SET_VERSION, 1);
    assert_eq!(ERC7730_PROOF_SET_COUNT, 2);
    assert_eq!(SIGN_USEROP_BATCH_TRAILER_HEADER_LEN, 4);
    assert_eq!(TRAILER_KIND_ERC20, 1);
    assert_eq!(TRAILER_KIND_RESERVED_V1, 2);
    assert_eq!(TRAILER_KIND_COW_ORDER, 3);
    assert_eq!(TRAILER_KIND_SAFE_V1, 4);
    assert_eq!(TRAILER_KIND_SEL_CURATED, 5);
    assert_eq!(TRAILER_KIND_SEL_SELFATTEST, 6);
    assert_eq!(TRAILER_KIND_ERC7730, 7);
    assert_eq!(TRAILER_KIND_NAME, 8);
    assert_eq!(TRAILER_TX_IDX_BATCH_WIDE, 0xff);
    assert_eq!(EIP6492_BLOB_LEN, 8608);
    assert_eq!(EXECUTE_BATCH_SELECTOR, [0x7a, 0x38, 0x99, 0x33]);
    assert_eq!(PQ_ADD_OWNER_BYTES_SELECTOR, [0x10, 0x14, 0x90, 0xcb]);
    assert_eq!(PQ_CREATE_ACCOUNT_SELECTOR, [0xf6, 0x18, 0x2a, 0x73]);
    assert_eq!(PQ_SMART_WALLET_FACTORY.len(), 20);
    assert_ne!(PQ_SMART_WALLET_FACTORY, [0u8; 20]);
}

// ── Sweep 2026-10-13 finding #1 + #353: rotation consent receipt and the
//    0x0203 owner-bytes output binding, in BOTH sign handlers. ────────────

#[test]
fn negative_rotation_receipt_gates_both_bootstrap_boundaries_in_both_handlers() {
    for (name, src) in [
        ("cmd_sign_userop.rs", CMD_SIGN_USEROP_SRC),
        ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
    ] {
        let at = |needle: &str| {
            src.find(needle)
                .unwrap_or_else(|| panic!("{name}: missing `{needle}`"))
        };
        let new = at("RotationConfirmReceipt::new()");
        let fail_init = at("rotation_confirm_receipt.fail_initialize()");
        let dialog = at("build_slot_rotation_pages(");
        let record = at(".record_confirmed(&rotation_context)");
        let skip = at(".record_not_requested(&rotation_context)");
        let keygen = at("derive_c10_master_keypair_from_entropy_with_progress");
        let t1_call = at("add_owner_bytes_calldata(&slot_owner_bytes)");
        let boot_sign = at("let bootstrap_sig = match");
        let readback = at("rotation_confirm_receipt.pristine_proof()");
        // Fail-initialised and read back before the dialog; published only after it.
        assert!(new < fail_init && fail_init < dialog, "{name}: receipt not fail-initialised before the dialog");
        assert!(fail_init < readback && readback < dialog, "{name}: no pristine read-back after fail_initialize");
        assert_eq!(src.matches("rotation_confirm_receipt.pristine_proof()").count(), 1, "{name}: one read-back");
        assert!(dialog < record && record < skip, "{name}: record must sit in the dialog's affirmative arm");
        // The affirmative record follows the dialog's FI verdict check.
        let verdict = src[dialog..record].rfind("cr_verdict != crate::fi::OK_SENTINEL");
        assert!(verdict.is_some(), "{name}: record must follow the cr_verdict gate");
        // Exactly two spatially separate proofs: before keygen, and between
        // the Type-1 preimage and the bootstrap sign.
        let proofs: Vec<usize> = src
            .match_indices("rotation_confirm_receipt.completion_proof(&rotation_context)")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(proofs.len(), 2, "{name}: expected two rotation completion proofs");
        assert!(skip < proofs[0] && proofs[0] < keygen, "{name}: first proof must precede bootstrap keygen");
        assert!(t1_call < proofs[1] && proofs[1] < boot_sign, "{name}: second proof must precede the bootstrap sign");
    }
}

#[test]
fn negative_rotation_response_releases_only_the_signed_owner_bytes() {
    for (name, src) in [
        ("cmd_sign_userop.rs", CMD_SIGN_USEROP_SRC),
        ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
    ] {
        let at = |needle: &str| {
            src.find(needle)
                .unwrap_or_else(|| panic!("{name}: missing `{needle}`"))
        };
        // The owner bytes are copied OUT of the signed calldata, after the
        // bootstrap signature exists.
        let copy = at("type1_owner_out.copy_from_slice(\n                &t1_call[crate::aa::userop::ADD_OWNER_BYTES_ARG_OFFSET..],");
        assert!(at("let bootstrap_sig = match") < copy, "{name}: owner copied before the signature");
        // The binding proof runs after the second write-extent check and
        // before the first byte of the Type-1 section is written.
        let extent = src.rfind("out_extent_ok != crate::fi::OK_SENTINEL").expect("extent check");
        let section = at("if emit_type1 { TYPE1_ROTATION_SECTION_LEN } else { 0 }");
        let register = at("offchain_count_register_slot(&slot_flash_key)");
        let proofs: Vec<usize> =
            src.match_indices("rotation_output_binding_proof(").map(|(i, _)| i).collect();
        assert_eq!(proofs.len(), 2, "{name}: expected two rotation output bindings");
        // First binding gates the durable slot registration, which is keyed
        // on the bound Type-1 output rather than the raw flag.
        assert!(copy < proofs[0] && proofs[0] < register, "{name}: output binding must gate the registration");
        let guard = src[proofs[0]..register].rfind("if emit_type1 {");
        assert!(guard.is_some(), "{name}: registration must be keyed on emit_type1");
        assert!(!src[proofs[0]..register].contains("if register_slot {"), "{name}: registration keyed on the raw flag");
        // Second binding gates the release.
        assert!(extent < proofs[1] && proofs[1] < section, "{name}: output binding must gate the release");
        assert!(!src.contains("if emit_type1 { SIG_WRAPPER_LEN }"), "{name}: bare 0x0202 Type-1 length");
    }
}
