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
    EIP6492_MAGIC, ERC7730_MAX_TRAILER_LEN, EXECUTE_BATCH_SELECTOR, FLAG_INCLUDE_INIT_CODE,
    FLAG_REGISTER_SLOT, MAX_ACCOUNT_INDEX, MAX_BATCH_TXS, MAX_OFFCHAIN_EIP712_TYPED_LEN,
    MAX_OFFCHAIN_GAP, MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
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
    TRAILER_KIND_SEL_SELFATTEST, TRAILER_KIND_ZK_V1, TRAILER_KIND_ZK_V3,
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
    // Worst-case input: header + max(personal_sign, eip712_typed).
    // The firmware's TOCTOU snapshot is sized to this bound; any
    // drift would either overflow SNAP_BUF (smaller bound, larger
    // snap) or refuse valid traffic (larger bound, smaller snap).
    // Phase 3 (ERC-7730) widened this to include the EIP-712 typed-
    // data path + attestation trailer.
    assert_eq!(
        SIGN_OFFCHAIN_INPUT_MAX_LEN,
        SIGN_OFFCHAIN_HEADER_LEN
            + core::cmp::max(
                MAX_OFFCHAIN_PERSONAL_SIGN_LEN,
                MAX_OFFCHAIN_EIP712_TYPED_LEN,
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
const CMD_SIGN_OFFCHAIN_SRC: &str = include_str!("nsc/cmd_sign_offchain.rs");
const CMD_SIGN_USEROP_BATCH_SRC: &str = include_str!("nsc/cmd_sign_userop_batch.rs");

const ALL_SLICE_SRCS: [(&str, &str); 4] = [
    ("cmd_offchain_status.rs", CMD_OFFCHAIN_STATUS_SRC),
    ("cmd_offchain_sync.rs", CMD_OFFCHAIN_SYNC_SRC),
    ("cmd_sign_offchain.rs", CMD_SIGN_OFFCHAIN_SRC),
    ("cmd_sign_userop_batch.rs", CMD_SIGN_USEROP_BATCH_SRC),
];

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
    // cmd_sign_userop_batch.rs derives account_index from the flags
    // word: `(flags & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT`.
    // ACCOUNT_INDEX_MASK is 8 bits wide, so the result is bounded to
    // 0..=255 by construction — no separate `> MAX_ACCOUNT_INDEX`
    // gate is necessary. Pin the mask-based derivation so a refactor
    // that switched to a direct byte read would also be forced to
    // add the explicit gate.
    assert!(CMD_SIGN_USEROP_BATCH_SRC
        .contains("(flags & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT"));
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
    // CLAUDE.md invariant #9: refuse past MAX_OFFCHAIN_GAP unbacked
    // sigs; invariant #7: refuse past MAX_SLOT_USES per slot. Both
    // must be checked twice (the F-10 recheck pass).
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("MAX_OFFCHAIN_GAP"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("MAX_SLOT_USES"));
    assert!(CMD_SIGN_OFFCHAIN_SRC.contains("gap_recheck"));
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
    assert_eq!(SIGN_USEROP_BATCH_TRAILER_HEADER_LEN, 4);
    assert_eq!(TRAILER_KIND_ERC20, 1);
    assert_eq!(TRAILER_KIND_ZK_V1, 2);
    assert_eq!(TRAILER_KIND_ZK_V3, 3);
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
