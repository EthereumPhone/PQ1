//! Test vectors + regression tests for the `safe_v1` Safe-multisig
//! clear-sign trailer.
//!
//! The fixture builds a synthetic Safe-v1.3.0 transaction that calls
//! `IERC20.transfer(0xRECIPIENT…, 250_000_000)` (250 USDC) on Safe
//! `0xSAFE…` from a wallet on chain id 1, then exercises the full
//! `verify_and_bind_trailer` pipeline plus eight per-field corruptions
//! to confirm every load-bearing check rejects.
//!
//! The `safeTxHash` in `fixture_calldata` is *self-consistent* — it's
//! whatever `compute_safe_tx_hash(fixture_canonical())` returns. The
//! external cross-validation lives in the typehash unit tests in the
//! parent module (which prove our `SAFE_TX_TYPEHASH` /
//! `SAFE_DOMAIN_TYPEHASH` byte arrays equal `keccak(preimage)`) and
//! in the e2e test path under `nonsecure/src/e2e_test.rs` (which can
//! later be wired to compare against a real Safe Transaction Service
//! response).

use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
    SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_V1_CANONICAL_LEN,
};

use super::{compute_safe_tx_hash, verify_and_bind_trailer};
use crate::tx::eip712::keccak;

const FIXTURE_CHAIN_ID: u64 = 1;

const FIXTURE_SAFE_ADDRESS: [u8; 20] = [
    0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Real USDC contract on mainnet — used as `to` so the inner-tx
/// renderer can resolve it via the ERC-20 metadata bundle in the e2e
/// flow.
const FIXTURE_TO_USDC: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
    0xce, 0x36, 0x06, 0xeb, 0x48,
];

const FIXTURE_RECIPIENT: [u8; 20] = [
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab,
];

/// `transfer(0xRECIPIENT…, 250_000_000)` — 250 USDC at 6 decimals.
fn fixture_raw_data() -> [u8; 4 + 32 + 32] {
    let mut d = [0u8; 4 + 32 + 32];
    // selector: keccak256("transfer(address,uint256)")[..4] = 0xa9059cbb
    d[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    // address (left-padded to 32)
    d[16..36].copy_from_slice(&FIXTURE_RECIPIENT);
    // uint256 = 250_000_000 (BE; high bytes zero, low bytes carry the value)
    let amount: u64 = 250_000_000;
    let amt_be = amount.to_be_bytes();
    d[68 - 8..68].copy_from_slice(&amt_be);
    d
}

/// Build the 281-byte canonical SafeTx for the fixture. Every field
/// is exercised so per-field corruption tests can flip arbitrary
/// bytes.
fn fixture_canonical() -> [u8; SAFE_V1_CANONICAL_LEN] {
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    // chain_id (u64 BE, 8 B)
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&FIXTURE_CHAIN_ID.to_be_bytes());
    // safe_address (20 B)
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&FIXTURE_SAFE_ADDRESS);
    // to (20 B)
    c[28..48].copy_from_slice(&FIXTURE_TO_USDC);
    // value (uint256 BE) — Safe call carrying ERC-20, so 0
    // (leave as zeros).
    // data_hash = keccak(raw_data)
    let raw = fixture_raw_data();
    let dh = keccak(&raw);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&dh);
    // operation = 0 (Call)
    c[SAFE_OFF_OPERATION] = 0;
    // safe_tx_gas, base_gas, gas_price stay zero (typical for relayer-less Safe txs).
    // gas_token, refund_receiver stay zero.
    // nonce = 42
    let mut n = [0u8; 32];
    n[31] = 42;
    c[249..281].copy_from_slice(&n);
    c
}

/// `approveHash(safeTxHash)` calldata for the fixture.
fn fixture_calldata() -> [u8; APPROVE_HASH_CALLDATA_LEN] {
    let canonical = fixture_canonical();
    let hash = compute_safe_tx_hash(&canonical).expect("fixture canonical decodes");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&hash);
    cd
}

/// Pack a full `safe_v1` trailer: canonical || u16 raw_data_len || raw_data.
fn fixture_bundle() -> alloc::vec::Vec<u8> {
    let canonical = fixture_canonical();
    let raw = fixture_raw_data();
    let mut buf = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    buf.extend_from_slice(&canonical);
    buf.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    buf.extend_from_slice(&raw);
    buf
}

extern crate alloc;

#[test]
fn happy_path_verifies() {
    let bundle = fixture_bundle();
    let cd = fixture_calldata();
    let v = verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS);
    assert!(v.is_some(), "happy path must verify");
    let v = v.unwrap();
    assert_eq!(&v.canonical[..], &fixture_canonical()[..]);
    assert_eq!(v.raw_data, &fixture_raw_data()[..]);
}

#[test]
fn rejects_wrong_selector() {
    let bundle = fixture_bundle();
    let mut cd = fixture_calldata();
    cd[0] ^= 0xff; // corrupt selector
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_wrong_calldata_length() {
    let bundle = fixture_bundle();
    let cd = [0xd4u8, 0xd9, 0xbd, 0xcd]; // selector only, no hash
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_chain_id_mismatch() {
    let bundle = fixture_bundle();
    let cd = fixture_calldata();
    // pass the wrong chain id to the verify call (mainnet canonical, but
    // a UserOp claiming Optimism)
    assert!(verify_and_bind_trailer(&bundle, &cd, 10, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_safe_address_mismatch() {
    let bundle = fixture_bundle();
    let cd = fixture_calldata();
    let mut wrong_safe = FIXTURE_SAFE_ADDRESS;
    wrong_safe[0] ^= 0xff;
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &wrong_safe).is_none());
}

#[test]
fn rejects_delegatecall() {
    // Build a canonical with operation = 1 (DelegateCall).
    let mut canonical = fixture_canonical();
    canonical[SAFE_OFF_OPERATION] = 1;
    // Recompute the matching safeTxHash so this isn't *also* failing
    // the safeTxHash bind — we want to see DelegateCall rejected on
    // its own merits.
    let hash = compute_safe_tx_hash(&canonical).expect("delegatecall canonical decodes");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&hash);

    let raw = fixture_raw_data();
    let mut bundle = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    bundle.extend_from_slice(&canonical);
    bundle.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    bundle.extend_from_slice(&raw);

    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_data_hash_mismatch() {
    let bundle = fixture_bundle();
    let cd = fixture_calldata();
    // Corrupt one byte of raw_data inside the bundle (the canonical
    // still claims the original keccak so the bind fails).
    let mut tampered = bundle.clone();
    let raw_data_off = SAFE_V1_CANONICAL_LEN + 2;
    tampered[raw_data_off + 5] ^= 0xff;
    assert!(verify_and_bind_trailer(&tampered, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_safe_tx_hash_mismatch() {
    let bundle = fixture_bundle();
    let mut cd = fixture_calldata();
    // Flip a byte deep inside the safeTxHash so the bind fails but
    // selector + length are still fine.
    cd[20] ^= 0xff;
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_truncated_bundle() {
    // Bundle shorter than canonical + 2-byte length prefix is malformed.
    let short: [u8; SAFE_V1_CANONICAL_LEN + 1] = [0u8; SAFE_V1_CANONICAL_LEN + 1];
    let cd = fixture_calldata();
    assert!(verify_and_bind_trailer(&short, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_oversized_raw_data_len() {
    // Declared raw_data_len exceeds the bundle's actual remaining bytes.
    let canonical = fixture_canonical();
    let mut bundle = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + 100);
    bundle.extend_from_slice(&canonical);
    // Claim 5_000 bytes of raw_data but only supply 100.
    bundle.extend_from_slice(&(5_000u16).to_be_bytes());
    bundle.extend_from_slice(&[0u8; 100]);
    let cd = fixture_calldata();
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

#[test]
fn rejects_zero_raw_data_when_canonical_has_data_hash() {
    // A canonical with a non-zero data_hash but a zero-length raw_data
    // would have keccak(empty) != data_hash → bind fails.
    let canonical = fixture_canonical();
    let mut bundle = alloc::vec::Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2);
    bundle.extend_from_slice(&canonical);
    bundle.extend_from_slice(&0u16.to_be_bytes());
    let cd = fixture_calldata();
    assert!(verify_and_bind_trailer(&bundle, &cd, FIXTURE_CHAIN_ID, &FIXTURE_SAFE_ADDRESS).is_none());
}

/// Sanity: `decode_canonical` rejects an out-of-range operation byte
/// (anything other than 0 or 1) before the digest pipeline runs.
#[test]
fn decode_rejects_bad_operation() {
    let mut canonical = fixture_canonical();
    canonical[SAFE_OFF_OPERATION] = 2;
    assert!(super::decode_canonical(&canonical).is_err());
}
