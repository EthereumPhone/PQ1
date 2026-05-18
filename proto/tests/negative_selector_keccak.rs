//! Negative tests: every declared on-chain selector / typehash matches
//! the keccak256 of its canonical Solidity signature.
//!
//! **What's being attacked.** The byte-exact tests in
//! `negative_frozen_constants.rs` would catch a `let x = [0x14, …]` →
//! `let x = [0x15, …]` typo. But they would NOT catch a refactor that
//! "fixes" the canonical signature string (e.g. drops a parameter,
//! reorders args, changes `uint256` → `uint`) and re-derives a
//! consistent-but-different selector. These tests close that gap by
//! re-deriving each selector from its canonical signature string and
//! asserting equality with the constant.
//!
//! A selector mismatch here means either:
//!   * the constant drifted from what the on-chain ABI expects, OR
//!   * someone changed the function signature on-chain without
//!     updating the firmware constant.
//! Either way, deployed wallets stop interoperating with deployed
//! contracts.

use pqsigner_proto::*;
use tiny_keccak::{Hasher, Keccak};

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(input);
    k.finalize(&mut out);
    out
}

fn selector(sig: &str) -> [u8; 4] {
    let h = keccak256(sig.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

// ───────────────────────────────────────────────────────────────────────
// PQSmartWallet entry-point selectors
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_execute_selector_matches_canonical_signature() {
    let sig = "executeWithOffchainCount(uint256,uint256,address,uint256,bytes)";
    assert_eq!(
        EXECUTE_SELECTOR,
        selector(sig),
        "EXECUTE_SELECTOR no longer matches keccak256({sig})[..4] — either the constant drifted or the on-chain function signature was changed without updating firmware"
    );
}

#[test]
fn negative_execute_batch_selector_matches_canonical_signature() {
    let sig =
        "executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])";
    assert_eq!(
        EXECUTE_BATCH_SELECTOR,
        selector(sig),
        "EXECUTE_BATCH_SELECTOR no longer matches keccak256({sig})[..4]"
    );
}

#[test]
fn negative_add_owner_bytes_selector_matches_canonical_signature() {
    let sig = "addOwnerBytes(bytes)";
    assert_eq!(
        PQ_ADD_OWNER_BYTES_SELECTOR,
        selector(sig),
        "PQ_ADD_OWNER_BYTES_SELECTOR no longer matches keccak256({sig})[..4]"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Factory selector
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_create_account_selector_matches_canonical_signature() {
    let sig = "createAccount(bytes32,bytes32,bytes32,bytes32,uint64,bytes)";
    assert_eq!(
        PQ_CREATE_ACCOUNT_SELECTOR,
        selector(sig),
        "PQ_CREATE_ACCOUNT_SELECTOR no longer matches keccak256({sig})[..4]"
    );
}

// ───────────────────────────────────────────────────────────────────────
// External-protocol selectors
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_set_pre_signature_selector_matches_canonical_signature() {
    let sig = "setPreSignature(bytes,bool)";
    assert_eq!(
        SET_PRE_SIGNATURE_SELECTOR,
        selector(sig),
        "SET_PRE_SIGNATURE_SELECTOR no longer matches keccak256({sig})[..4]"
    );
}

#[test]
fn negative_approve_hash_selector_matches_canonical_signature() {
    let sig = "approveHash(bytes32)";
    assert_eq!(
        APPROVE_HASH_SELECTOR,
        selector(sig),
        "APPROVE_HASH_SELECTOR no longer matches keccak256({sig})[..4]"
    );
}

// ───────────────────────────────────────────────────────────────────────
// EIP-712 typehashes (full 32-byte keccak of the canonical type string)
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_safe_domain_typehash_matches_canonical_type_string() {
    let ty = "EIP712Domain(uint256 chainId,address verifyingContract)";
    assert_eq!(
        SAFE_DOMAIN_TYPEHASH,
        keccak256(ty.as_bytes()),
        "SAFE_DOMAIN_TYPEHASH no longer matches keccak256({ty}) — Safe v1.3.0+ approveHash cross-check would compute a different domain separator"
    );
}

#[test]
fn negative_safe_tx_typehash_matches_canonical_type_string() {
    // Safe v1.3.0+ SafeTx struct. Field order and types are part of the
    // EIP-712 typehash preimage — any rename here is a hard fork from
    // what the Safe verifies on-chain.
    let ty = "SafeTx(address to,uint256 value,bytes data,uint8 operation,\
                uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,\
                address refundReceiver,uint256 nonce)";
    assert_eq!(
        SAFE_TX_TYPEHASH,
        keccak256(ty.as_bytes()),
        "SAFE_TX_TYPEHASH no longer matches keccak256({ty})"
    );
}
