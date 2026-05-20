//! Extension suite for the Safe v1.3.0+ clear-sign pipeline.
//!
//! The existing `test_vectors.rs` proves the happy path verifies and
//! that selector / calldata-length / chain / safe-address / operation /
//! data_hash / safeTxHash failures all reject. This module rounds out
//! the adversarial story:
//!
//!   * **Frozen-format anchors** — `APPROVE_HASH_SELECTOR` matches the
//!     keccak of its preimage; the canonical layout offsets are pinned
//!     against the documented values; `SAFE_V1_CANONICAL_LEN` matches
//!     the layout sum.
//!   * **Decode-vs-verify split** — decode permits operation 0 OR 1
//!     (the verify pipeline is what bans DelegateCall), and decode
//!     rejects every other operation byte. Decoupling these surfaces
//!     a future refactor that accidentally rejected DelegateCall at
//!     decode time (which would let raw-canonical consumers silently
//!     drop the verify guard).
//!   * **Struct-hash field binding** — flipping a byte in any field
//!     covered by the struct_hash preimage must change
//!     `compute_safe_tx_hash`. Belt-and-braces against a refactor
//!     that dropped a field.
//!   * **Trailer-framing pathological cases** — truncation, oversized
//!     length, exact-boundary `raw_data_len == SAFE_V1_RAW_DATA_MAX`,
//!     length-prefix off by one, and zero raw_data with a matching
//!     `keccak(empty)` data_hash.

extern crate alloc;

use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, MAX_TX_LEN, SAFE_DOMAIN_TYPEHASH,
    SAFE_OFF_BASE_GAS, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH, SAFE_OFF_GAS_PRICE,
    SAFE_OFF_GAS_TOKEN, SAFE_OFF_NONCE, SAFE_OFF_OPERATION, SAFE_OFF_REFUND_RECEIVER,
    SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_SAFE_TX_GAS, SAFE_OFF_TO, SAFE_OFF_VALUE, SAFE_TX_TYPEHASH,
    SAFE_V1_CANONICAL_LEN, SAFE_V1_RAW_DATA_MAX,
};

use super::{
    compute_safe_tx_hash, decode_canonical, domain_separator, struct_hash, verify_and_bind_trailer,
};
use crate::tx::eip712::keccak;

// ---------------------------------------------------------------------------
// Local fixtures (self-contained; mirror those in `test_vectors.rs`)
// ---------------------------------------------------------------------------

const FIXTURE_CHAIN_ID: u64 = 1;
const FIXTURE_SAFE_ADDRESS: [u8; 20] = [
    0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
];
const FIXTURE_TO: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];

fn fixture_raw_data() -> [u8; 68] {
    let mut d = [0u8; 68];
    d[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    for (i, b) in d[16..36].iter_mut().enumerate() {
        *b = 0xabu8.wrapping_add(i as u8);
    }
    d[60..68].copy_from_slice(&250_000_000u64.to_be_bytes());
    d
}

fn fixture_canonical() -> [u8; SAFE_V1_CANONICAL_LEN] {
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&FIXTURE_CHAIN_ID.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&FIXTURE_SAFE_ADDRESS);
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&FIXTURE_TO);
    let raw = fixture_raw_data();
    let dh = keccak(&raw);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&dh);
    c[SAFE_OFF_OPERATION] = 0;
    let mut n = [0u8; 32];
    n[31] = 42;
    c[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32].copy_from_slice(&n);
    c
}

fn fixture_calldata() -> [u8; APPROVE_HASH_CALLDATA_LEN] {
    let c = fixture_canonical();
    let h = compute_safe_tx_hash(&c).unwrap();
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    cd
}

fn fixture_bundle() -> alloc::vec::Vec<u8> {
    let c = fixture_canonical();
    let raw = fixture_raw_data();
    let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(&c);
    b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    b.extend_from_slice(&raw);
    b
}

// ===========================================================================
// Positive — frozen-format anchors
// ===========================================================================

#[test]
fn positive_approve_hash_selector_matches_preimage() {
    // ASSUMPTION: the selector equals `keccak256("approveHash(bytes32)")[..4]`.
    let h = keccak(b"approveHash(bytes32)");
    assert_eq!(&h[..4], &APPROVE_HASH_SELECTOR);
    assert_eq!(APPROVE_HASH_SELECTOR, [0xd4, 0xd9, 0xbd, 0xcd]);
}

#[test]
fn positive_approve_hash_calldata_len_is_selector_plus_bytes32() {
    assert_eq!(APPROVE_HASH_CALLDATA_LEN, 4 + 32);
    assert_eq!(APPROVE_HASH_CALLDATA_LEN, 36);
}

#[test]
fn positive_canonical_layout_offsets_pin_to_documented_layout() {
    // The doc-comment on `SAFE_V1_CANONICAL_LEN` is authoritative. Pin
    // each offset to the value the byte-layout requires; a refactor
    // that renumbered them silently would shift every field in the
    // packed buffer.
    assert_eq!(SAFE_OFF_CHAIN_ID, 0);
    assert_eq!(SAFE_OFF_SAFE_ADDRESS, 8);
    assert_eq!(SAFE_OFF_TO, 28);
    assert_eq!(SAFE_OFF_VALUE, 48);
    assert_eq!(SAFE_OFF_DATA_HASH, 80);
    assert_eq!(SAFE_OFF_OPERATION, 112);
    assert_eq!(SAFE_OFF_SAFE_TX_GAS, 113);
    assert_eq!(SAFE_OFF_BASE_GAS, 145);
    assert_eq!(SAFE_OFF_GAS_PRICE, 177);
    assert_eq!(SAFE_OFF_GAS_TOKEN, 209);
    assert_eq!(SAFE_OFF_REFUND_RECEIVER, 229);
    assert_eq!(SAFE_OFF_NONCE, 249);
    // Total length sanity:
    assert_eq!(SAFE_V1_CANONICAL_LEN, 281);
    assert_eq!(SAFE_OFF_NONCE + 32, SAFE_V1_CANONICAL_LEN);
}

#[test]
fn positive_safe_v1_raw_data_max_is_max_tx_len() {
    assert_eq!(SAFE_V1_RAW_DATA_MAX, MAX_TX_LEN);
}

#[test]
fn positive_safe_domain_typehash_matches_preimage() {
    // Duplicate of the existing `typehash_tests` assertion; included
    // here so this file is self-sufficient if the parent module's
    // typehash_tests is ever removed or relocated.
    assert_eq!(
        keccak(b"EIP712Domain(uint256 chainId,address verifyingContract)"),
        SAFE_DOMAIN_TYPEHASH
    );
}

#[test]
fn positive_safe_tx_typehash_matches_preimage() {
    let preimage: &[u8] = b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
    assert_eq!(keccak(preimage), SAFE_TX_TYPEHASH);
}

// ===========================================================================
// Positive — round-trip + determinism
// ===========================================================================

#[test]
fn positive_decode_round_trips_all_fields() {
    let c = fixture_canonical();
    let tx = decode_canonical(&c).unwrap();
    assert_eq!(tx.chain_id, FIXTURE_CHAIN_ID);
    assert_eq!(tx.safe_address, FIXTURE_SAFE_ADDRESS);
    assert_eq!(tx.to, FIXTURE_TO);
    assert_eq!(&tx.value, &[0u8; 32]);
    assert_eq!(&tx.data_hash, &keccak(&fixture_raw_data()));
    assert_eq!(tx.operation, 0);
    assert_eq!(tx.nonce[31], 42);
}

#[test]
fn positive_decode_accepts_delegatecall_operation_byte() {
    // ASSUMPTION: decode is permissive (operation ∈ {0,1}) and the
    // verify pipeline is what bans DelegateCall. If a refactor moves
    // the DelegateCall rejection into decode, raw-canonical consumers
    // (display path) would silently drop the verify guard.
    let mut c = fixture_canonical();
    c[SAFE_OFF_OPERATION] = 1;
    let tx = decode_canonical(&c).expect("decode must accept operation=1 (DelegateCall)");
    assert_eq!(tx.operation, 1);
}

#[test]
fn positive_compute_safe_tx_hash_deterministic() {
    let c = fixture_canonical();
    let a = compute_safe_tx_hash(&c).unwrap();
    let b = compute_safe_tx_hash(&c).unwrap();
    assert_eq!(a, b);
}

#[test]
fn positive_domain_separator_deterministic() {
    let a = domain_separator(1, &FIXTURE_SAFE_ADDRESS);
    let b = domain_separator(1, &FIXTURE_SAFE_ADDRESS);
    assert_eq!(a, b);
}

#[test]
fn positive_struct_hash_deterministic() {
    let tx = decode_canonical(&fixture_canonical()).unwrap();
    assert_eq!(struct_hash(&tx), struct_hash(&tx));
}

#[test]
fn positive_verify_bundle_at_exact_minimum_with_keccak_empty_data_hash() {
    // SAFE allows a canonical with no inline raw_data when the data_hash
    // equals keccak(""). Build that and assert verify accepts.
    let mut c = fixture_canonical();
    let empty_hash = keccak(b"");
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&empty_hash);
    // The struct_hash changed so we must recompute the calldata digest.
    let h = compute_safe_tx_hash(&c).unwrap();
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    // Bundle with raw_data_len = 0.
    let mut bundle = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2);
    bundle.extend_from_slice(&c);
    bundle.extend_from_slice(&0u16.to_be_bytes());
    let v = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS);
    assert!(
        v.is_some(),
        "zero-len raw_data with keccak('') data_hash must verify"
    );
    assert_eq!(v.unwrap().raw_data.len(), 0);
}

// ===========================================================================
// Negative — decode enum-range exhaustion
// ===========================================================================

#[test]
fn negative_decode_rejects_operation_two_through_255() {
    let mut c = fixture_canonical();
    for bad in [2u8, 3, 16, 127, 128, 200, 254, 255] {
        c[SAFE_OFF_OPERATION] = bad;
        assert!(
            decode_canonical(&c).is_err(),
            "operation={bad} must reject (only 0 and 1 are valid SafeOp)"
        );
    }
}

// ===========================================================================
// Negative — struct_hash field binding
// ===========================================================================

fn flip_changes_safe_tx_hash(field: &str, offset: usize) {
    let mut c = fixture_canonical();
    let d0 = compute_safe_tx_hash(&c).unwrap();
    c[offset] ^= 0xFF;
    let d1 = compute_safe_tx_hash(&c).unwrap();
    assert_ne!(
        d0, d1,
        "flipping {field} (offset {offset}) MUST change safeTxHash"
    );
}

#[test]
fn negative_struct_hash_binds_to() {
    flip_changes_safe_tx_hash("to", SAFE_OFF_TO);
}

#[test]
fn negative_struct_hash_binds_value() {
    // pick a byte in the middle of the value slot
    flip_changes_safe_tx_hash("value", SAFE_OFF_VALUE + 16);
}

#[test]
fn negative_struct_hash_binds_data_hash() {
    flip_changes_safe_tx_hash("data_hash", SAFE_OFF_DATA_HASH);
}

#[test]
fn negative_struct_hash_binds_operation() {
    let mut c = fixture_canonical();
    let d0 = compute_safe_tx_hash(&c).unwrap();
    c[SAFE_OFF_OPERATION] = 1;
    let d1 = compute_safe_tx_hash(&c).unwrap();
    assert_ne!(d0, d1, "operation must be bound into safeTxHash");
}

#[test]
fn negative_struct_hash_binds_safe_tx_gas() {
    flip_changes_safe_tx_hash("safe_tx_gas", SAFE_OFF_SAFE_TX_GAS + 16);
}

#[test]
fn negative_struct_hash_binds_base_gas() {
    flip_changes_safe_tx_hash("base_gas", SAFE_OFF_BASE_GAS + 16);
}

#[test]
fn negative_struct_hash_binds_gas_price() {
    flip_changes_safe_tx_hash("gas_price", SAFE_OFF_GAS_PRICE + 16);
}

#[test]
fn negative_struct_hash_binds_gas_token() {
    flip_changes_safe_tx_hash("gas_token", SAFE_OFF_GAS_TOKEN);
}

#[test]
fn negative_struct_hash_binds_refund_receiver() {
    flip_changes_safe_tx_hash("refund_receiver", SAFE_OFF_REFUND_RECEIVER);
}

#[test]
fn negative_struct_hash_binds_nonce() {
    flip_changes_safe_tx_hash("nonce", SAFE_OFF_NONCE + 16);
}

#[test]
fn negative_struct_hash_binds_chain_id_via_domain_separator() {
    // chain_id is NOT part of struct_hash; it's bound via the domain
    // separator. Either way, compute_safe_tx_hash MUST surface the
    // change.
    let mut c = fixture_canonical();
    let d0 = compute_safe_tx_hash(&c).unwrap();
    c[SAFE_OFF_CHAIN_ID + 7] = 137; // change low byte
    let d1 = compute_safe_tx_hash(&c).unwrap();
    assert_ne!(d0, d1, "chain_id must affect safeTxHash via the domain separator");
}

#[test]
fn negative_struct_hash_binds_safe_address_via_domain_separator() {
    // safe_address goes into the DS as verifyingContract, not into the
    // struct_hash preimage. Flipping must still propagate to safeTxHash.
    let mut c = fixture_canonical();
    let d0 = compute_safe_tx_hash(&c).unwrap();
    c[SAFE_OFF_SAFE_ADDRESS] ^= 0xFF;
    let d1 = compute_safe_tx_hash(&c).unwrap();
    assert_ne!(
        d0, d1,
        "safe_address (verifyingContract) must affect safeTxHash via DS"
    );
}

// ===========================================================================
// Negative — verify trailer framing pathologies
// ===========================================================================

#[test]
fn negative_verify_rejects_when_raw_len_off_by_one() {
    // Declared raw_data_len = actual + 1 → declared end exceeds bundle.
    let c = fixture_canonical();
    let raw = fixture_raw_data();
    let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(&c);
    b.extend_from_slice(&((raw.len() as u16) + 1).to_be_bytes());
    b.extend_from_slice(&raw);
    let cd = fixture_calldata();
    assert!(
        verify_and_bind_trailer(&b, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "off-by-one declared length must reject"
    );
}

#[test]
fn negative_verify_rejects_declared_len_exceeds_max_tx_len() {
    // raw_len_field > SAFE_V1_RAW_DATA_MAX is rejected even before the
    // bundle-length check, so test it isolated.
    let c = fixture_canonical();
    let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2);
    b.extend_from_slice(&c);
    b.extend_from_slice(&((SAFE_V1_RAW_DATA_MAX as u16).wrapping_add(1)).to_be_bytes());
    // Don't supply any bytes; the raw_len > cap path should reject without
    // looking at remaining bytes.
    let cd = fixture_calldata();
    assert!(
        verify_and_bind_trailer(&b, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "raw_len > SAFE_V1_RAW_DATA_MAX must reject"
    );
}

#[test]
fn negative_verify_rejects_truncated_one_byte_short_of_canonical_plus_len_prefix() {
    let short: [u8; SAFE_V1_CANONICAL_LEN + 1] = [0u8; SAFE_V1_CANONICAL_LEN + 1];
    let cd = fixture_calldata();
    assert!(
        verify_and_bind_trailer(&short, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none()
    );
}

#[test]
fn negative_verify_rejects_inner_data_under_four_bytes() {
    // Selector check requires `inner_data.len() >= 4`. Pass shorter
    // slices and confirm None.
    let bundle = fixture_bundle();
    for short_len in [0usize, 1, 2, 3] {
        let cd: alloc::vec::Vec<u8> = (0..short_len).map(|i| i as u8).collect();
        assert!(
            verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
                .is_none(),
            "inner_data of {short_len} bytes must reject (selector requires ≥4)"
        );
    }
}

#[test]
fn negative_verify_rejects_inner_data_over_36_bytes() {
    let bundle = fixture_bundle();
    let mut cd = alloc::vec::Vec::from(fixture_calldata());
    cd.push(0xAA);
    assert!(
        verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "calldata of 37 bytes must reject (selector matches but length is wrong)"
    );
}

#[test]
fn negative_verify_rejects_when_userop_to_is_not_canonical_safe_address() {
    // The doc says `tx.safe_address == userop_to` is required: a
    // UserOp's `to` that doesn't match the Safe whose hash we're
    // approving is a category error. The existing test flips a byte of
    // userop_to; here we use a completely different but valid-looking
    // address.
    let bundle = fixture_bundle();
    let cd = fixture_calldata();
    let imposter_safe: [u8; 20] = [0x11; 20];
    assert!(
        verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &imposter_safe).is_none()
    );
}

#[test]
fn negative_verify_rejects_extra_trailing_bytes_inside_declared_raw_len() {
    // Declared raw_data_len = actual_len, but we extend the bundle
    // with junk past raw_data_end. The verifier should still accept
    // because the doc says the slice is `safe_bundle[raw_data_start..
    // raw_data_end]`. (Documenting: this is NOT a rejection — sanity
    // check the contract.)
    let mut bundle = fixture_bundle();
    bundle.extend_from_slice(&[0xCC; 16]);
    let cd = fixture_calldata();
    assert!(
        verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_some(),
        "trailing junk past raw_data_end is permitted (length-prefixed framing)"
    );
}

#[test]
fn negative_verify_rejects_when_canonical_chain_id_zero_and_caller_one() {
    // ASSUMPTION: chain pinning catches a canonical that claims a
    // different chain than the UserOp header. ATTACK: an attacker
    // crafts an EIP-712 with chain_id=0 hoping it would replay on
    // every chain.
    let mut c = fixture_canonical();
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&0u64.to_be_bytes());
    let h = compute_safe_tx_hash(&c).unwrap();
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    let raw = fixture_raw_data();
    let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(&c);
    b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    b.extend_from_slice(&raw);
    assert!(
        verify_and_bind_trailer(&b, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "chain_id=0 canonical must reject when UserOp claims chain 1"
    );
}

#[test]
fn negative_verify_rejects_selector_match_but_zero_remaining_bytes() {
    // Calldata is exactly 4 bytes (selector only). The selector check
    // passes but the length check rejects. Distinguishes the two
    // guards.
    let bundle = fixture_bundle();
    let cd = APPROVE_HASH_SELECTOR;
    assert!(
        verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "selector-only calldata must reject on length check"
    );
}

#[test]
fn negative_verify_rejects_data_hash_when_one_raw_data_byte_flipped() {
    // Already covered in test_vectors.rs but we add a stronger sweep:
    // every byte position of raw_data is bound, including the first
    // and last.
    let canonical = fixture_canonical();
    let raw = fixture_raw_data();
    let cd = fixture_calldata();
    for offset in [0usize, 4, raw.len() - 1] {
        let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
        b.extend_from_slice(&canonical);
        b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        b.extend_from_slice(&raw);
        let raw_off = SAFE_V1_CANONICAL_LEN + 2 + offset;
        b[raw_off] ^= 0xFF;
        assert!(
            verify_and_bind_trailer(&b, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
            "flipping raw_data byte at offset {offset} must break data_hash bind"
        );
    }
}

// ===========================================================================
// Safe-mgmt inner-tx integration
// ===========================================================================
//
// Build a canonical SafeTx that self-calls (to == safe_address) with each
// of the supported Safe-mgmt selectors, run it through the full verify
// pipeline, and assert the classifier picks the right variant. The
// renderer is `#[cfg(not(test))]`-gated (it pulls in `Pages` and the
// non-test UI), so we don't unit-test the page strings here — see the
// renderer's own tests in `tx::display::safe_mgmt::tests` for that.

use super::mgmt_decode::{classify_safe_mgmt, SafeMgmtOp, ThresholdValue};

/// Build a self-call canonical SafeTx that targets `safe_address` (the
/// fixture's Safe contract) with the supplied inner calldata. Returns
/// the canonical + matching `approveHash` calldata for the verifier.
fn build_self_call(
    raw_data: &[u8],
) -> ([u8; SAFE_V1_CANONICAL_LEN], [u8; APPROVE_HASH_CALLDATA_LEN]) {
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&FIXTURE_CHAIN_ID.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&FIXTURE_SAFE_ADDRESS);
    // Self-call: to = safe_address. This is the trigger for Safe-mgmt
    // routing in `safe_display::render_safe_v1_pages`.
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&FIXTURE_SAFE_ADDRESS);
    let dh = keccak(raw_data);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&dh);
    c[SAFE_OFF_OPERATION] = 0;

    let h = compute_safe_tx_hash(&c).unwrap();
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    (c, cd)
}

fn bundle_with_raw(canonical: &[u8; SAFE_V1_CANONICAL_LEN], raw: &[u8]) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(canonical);
    b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    b.extend_from_slice(raw);
    b
}

fn calldata_add_owner_with_threshold(new_owner: [u8; 20], threshold: u64) -> [u8; 68] {
    let mut out = [0u8; 68];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD);
    out[4 + 12..4 + 32].copy_from_slice(&new_owner);
    out[4 + 32 + 24..4 + 32 + 32].copy_from_slice(&threshold.to_be_bytes());
    out
}

fn calldata_change_threshold(threshold: u64) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD);
    out[4 + 24..4 + 32].copy_from_slice(&threshold.to_be_bytes());
    out
}

fn calldata_set_guard(guard: [u8; 20]) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_SET_GUARD);
    out[4 + 12..4 + 32].copy_from_slice(&guard);
    out
}

fn calldata_enable_module(module: [u8; 20]) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_ENABLE_MODULE);
    out[4 + 12..4 + 32].copy_from_slice(&module);
    out
}

#[test]
fn safe_mgmt_add_owner_e2e_bind_and_classify() {
    let new_owner = FIXTURE_TO; // any address
    let raw = calldata_add_owner_with_threshold(new_owner, 3);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    // Verifier accepts the self-call (it doesn't care that to ==
    // safe_address; that's a renderer-level routing signal).
    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("self-call SafeTx with valid bind must pass verify");

    // The classifier sees the same bytes the renderer would.
    let op = classify_safe_mgmt(verified.raw_data).expect("addOwnerWithThreshold decodes");
    assert!(matches!(
        op,
        SafeMgmtOp::AddOwnerWithThreshold {
            new_owner: o,
            new_threshold: ThresholdValue::Fits(3),
        } if o == new_owner
    ));
}

#[test]
fn safe_mgmt_change_threshold_n1_e2e() {
    // Lowering the threshold to 1 — the renderer flags this with
    // `! MULTISIG OFF`. Here we just verify the bind+classify chain.
    let raw = calldata_change_threshold(1);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("changeThreshold SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("changeThreshold decodes");
    assert!(matches!(
        op,
        SafeMgmtOp::ChangeThreshold {
            new_threshold: ThresholdValue::Fits(1)
        }
    ));
}

#[test]
fn safe_mgmt_set_guard_zero_is_removal_e2e() {
    // setGuard(0x0) — the renderer surfaces this as "REMOVING GUARD".
    let raw = calldata_set_guard([0u8; 20]);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("setGuard SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("setGuard decodes");
    match op {
        SafeMgmtOp::SetGuard { guard } => assert_eq!(guard, [0u8; 20]),
        _ => panic!("expected SetGuard(0x00..00)"),
    }
}

#[test]
fn safe_mgmt_enable_module_e2e() {
    let module = FIXTURE_TO;
    let raw = calldata_enable_module(module);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("enableModule SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("enableModule decodes");
    assert!(matches!(op, SafeMgmtOp::EnableModule { module: m } if m == module));
}

#[test]
fn safe_mgmt_unknown_selector_self_call_passes_bind_but_classify_returns_none() {
    // A self-call whose first 4 bytes don't match any of the eight
    // recognised Safe-mgmt selectors. The verify pipeline doesn't care
    // (it only binds the hash chain), but the classifier rejects so the
    // renderer falls into the loud `UnknownSafeSelf` branch.
    let mut raw = [0u8; 68];
    raw[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    // Plausibly-shaped tail so the length matches one of the known
    // calldatas (68 = addOwnerWithThreshold); ensures we're testing
    // "unknown selector at known length" not "wrong length".
    raw[4 + 12..4 + 32].copy_from_slice(&FIXTURE_TO);
    raw[4 + 32 + 31] = 2;
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("unknown-selector self-call still binds successfully");
    assert!(
        classify_safe_mgmt(verified.raw_data).is_none(),
        "unknown selector must not classify as a known Safe-mgmt op"
    );
}

fn calldata_remove_owner(prev: [u8; 20], owner: [u8; 20], threshold: u64) -> [u8; 100] {
    let mut out = [0u8; 100];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_REMOVE_OWNER);
    out[4 + 12..4 + 32].copy_from_slice(&prev);
    out[4 + 32 + 12..4 + 32 + 32].copy_from_slice(&owner);
    out[4 + 64 + 24..4 + 64 + 32].copy_from_slice(&threshold.to_be_bytes());
    out
}

fn calldata_swap_owner(prev: [u8; 20], old: [u8; 20], new: [u8; 20]) -> [u8; 100] {
    let mut out = [0u8; 100];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_SWAP_OWNER);
    out[4 + 12..4 + 32].copy_from_slice(&prev);
    out[4 + 32 + 12..4 + 32 + 32].copy_from_slice(&old);
    out[4 + 64 + 12..4 + 64 + 32].copy_from_slice(&new);
    out
}

fn calldata_disable_module(prev: [u8; 20], module: [u8; 20]) -> [u8; 68] {
    let mut out = [0u8; 68];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_DISABLE_MODULE);
    out[4 + 12..4 + 32].copy_from_slice(&prev);
    out[4 + 32 + 12..4 + 32 + 32].copy_from_slice(&module);
    out
}

fn calldata_set_fallback_handler(handler: [u8; 20]) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[0..4].copy_from_slice(&sphincs_tz_shared::SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER);
    out[4 + 12..4 + 32].copy_from_slice(&handler);
    out
}

#[test]
fn safe_mgmt_remove_owner_e2e() {
    // Sentinel as prev_owner (removing the first owner in the list).
    let mut sentinel = [0u8; 20];
    sentinel[19] = 0x01;
    let raw = calldata_remove_owner(sentinel, FIXTURE_TO, 2);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("removeOwner SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("removeOwner decodes");
    match op {
        SafeMgmtOp::RemoveOwner {
            prev_owner,
            owner,
            new_threshold,
        } => {
            assert_eq!(prev_owner, sentinel);
            assert_eq!(owner, FIXTURE_TO);
            assert_eq!(new_threshold, ThresholdValue::Fits(2));
        }
        _ => panic!("expected RemoveOwner"),
    }
}

#[test]
fn safe_mgmt_swap_owner_e2e() {
    let prev = FIXTURE_TO;
    let old = FIXTURE_SAFE_ADDRESS;
    let new = [
        0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0, 0x12, 0x34, 0x56, 0x78,
    ];
    let raw = calldata_swap_owner(prev, old, new);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("swapOwner SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("swapOwner decodes");
    match op {
        SafeMgmtOp::SwapOwner {
            prev_owner,
            old_owner,
            new_owner,
        } => {
            assert_eq!(prev_owner, prev);
            assert_eq!(old_owner, old);
            assert_eq!(new_owner, new);
        }
        _ => panic!("expected SwapOwner"),
    }
}

#[test]
fn safe_mgmt_disable_module_e2e() {
    let mut sentinel = [0u8; 20];
    sentinel[19] = 0x01;
    let module = FIXTURE_TO;
    let raw = calldata_disable_module(sentinel, module);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);

    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("disableModule SafeTx with valid bind must pass verify");
    let op = classify_safe_mgmt(verified.raw_data).expect("disableModule decodes");
    match op {
        SafeMgmtOp::DisableModule {
            prev_module,
            module: m,
        } => {
            assert_eq!(prev_module, sentinel);
            assert_eq!(m, module);
        }
        _ => panic!("expected DisableModule"),
    }
}

#[test]
fn safe_mgmt_set_fallback_handler_e2e_install_and_removal() {
    // Installation
    let raw = calldata_set_fallback_handler(FIXTURE_TO);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);
    let verified = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
        .expect("setFallbackHandler SafeTx with valid bind must pass verify");
    match classify_safe_mgmt(verified.raw_data).expect("setFallbackHandler decodes") {
        SafeMgmtOp::SetFallbackHandler { handler } => assert_eq!(handler, FIXTURE_TO),
        _ => panic!("expected SetFallbackHandler"),
    }

    // Removal — handler = 0x0
    let raw0 = calldata_set_fallback_handler([0u8; 20]);
    let (canonical0, cd0) = build_self_call(&raw0);
    let bundle0 = bundle_with_raw(&canonical0, &raw0);
    let verified0 =
        verify_and_bind_trailer(&bundle0, &cd0, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS)
            .expect("setFallbackHandler(0) SafeTx with valid bind must pass verify");
    match classify_safe_mgmt(verified0.raw_data).expect("setFallbackHandler(0) decodes") {
        SafeMgmtOp::SetFallbackHandler { handler } => assert_eq!(handler, [0u8; 20]),
        _ => panic!(),
    }
}

#[test]
fn safe_mgmt_delegate_call_with_safe_mgmt_calldata_still_rejected() {
    // Build a canonical that says operation=1 (DelegateCall) but whose
    // inner calldata is a perfectly-shaped addOwnerWithThreshold. The
    // verifier must still reject because the operation gate fires
    // BEFORE the inner-calldata classifier ever sees the bytes — this
    // is the load-bearing pre-condition for "MultiSend not yet
    // supported".
    let raw = calldata_add_owner_with_threshold(FIXTURE_TO, 3);
    let (mut canonical, _stale_cd) = build_self_call(&raw);
    // Flip operation 0 -> 1, then recompute safeTxHash so the bind
    // would *otherwise* pass — this isolates the operation-gate test
    // from the safeTxHash mismatch path.
    canonical[SAFE_OFF_OPERATION] = 1;
    let new_hash = compute_safe_tx_hash(&canonical).expect("recompute with op=1");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&new_hash);
    let bundle = bundle_with_raw(&canonical, &raw);
    assert!(
        verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none(),
        "operation=1 (DelegateCall) must be rejected even when the rest of the bind chain would have passed"
    );
}

#[test]
fn safe_mgmt_chain_mismatch_with_safe_mgmt_calldata_still_rejected() {
    // The canonical says chain_id = mainnet, but we hand the verifier
    // a userop chain_id of polygon. Even though the inner calldata is
    // a valid addOwnerWithThreshold and would otherwise classify
    // cleanly, the chain-pinning gate must fire first.
    let raw = calldata_add_owner_with_threshold(FIXTURE_TO, 3);
    let (canonical, cd) = build_self_call(&raw);
    let bundle = bundle_with_raw(&canonical, &raw);
    let polygon: u64 = 137;
    assert!(
        verify_and_bind_trailer(&bundle, &cd, polygon, &FIXTURE_SAFE_ADDRESS).is_none(),
        "chain_id mismatch must reject even with a recognised Safe-mgmt inner op"
    );
}

#[test]
fn safe_mgmt_to_not_safe_is_not_a_safe_mgmt_op() {
    // Even with a Safe-mgmt-shaped calldata, if canonical.to is some
    // other address (e.g. a normal contract), the renderer must NOT
    // route through the Safe-mgmt classifier. Here we don't run the
    // renderer (cfg-gated) but we check the routing gate by hand: the
    // classifier itself doesn't look at `to`, so this test documents
    // that the to-equality check lives in safe_display.
    //
    // In other words: classify_safe_mgmt decodes the calldata
    // regardless of where it's pointed; the safe_address gate is
    // enforced by safe_display::render_safe_v1_pages. This test exists
    // to prevent a future refactor from moving the gate inside the
    // classifier without thinking it through.
    let raw = calldata_change_threshold(2);
    let op = classify_safe_mgmt(&raw).expect("classifier ignores `to`");
    assert!(matches!(
        op,
        SafeMgmtOp::ChangeThreshold {
            new_threshold: ThresholdValue::Fits(2)
        }
    ));
}
