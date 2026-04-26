//! Shared EIP-712 primitives used by the CoW v3 setPreSignature
//! cross-check.
//!
//! The firmware does not expose a standalone EIP-712 typed-data
//! signing command; the only consumer is `cmd_sign_userop`, which
//! re-derives the GPv2Order EIP-712 digest from the v3 trailer's
//! canonical buffer to byte-compare it against the orderUid in the
//! UserOp's `setPreSignature` calldata.
//!
//! This module provides the protocol-agnostic keccak primitives —
//! `keccak`, `eip712_domain_separator`, `final_digest` — plus the
//! shared `Eip712Error` enum. The CoW-specific `decode_canonical`,
//! `struct_hash`, `compute_digest`, and the cross-check helpers all
//! live in [`cowswap`].

use sha3::{Digest, Keccak256};

pub mod cowswap;
pub mod safe;
// cowswap_display / safe_display pull in `crate::ui` (hardware display
// primitives), so they're gated out of host test builds. Pure EIP-712
// logic (`cowswap`, `safe`, keccak primitives above) is always compiled
// so its cross-check invariants can be unit-tested on the host.
#[cfg(not(test))]
pub mod cowswap_display;

// ---------------------------------------------------------------------------
// Keccak primitive
// ---------------------------------------------------------------------------

/// Keccak-256 of a single byte slice. Internal helper used by both
/// `eip712_domain_separator` and the per-protocol struct hashers.
#[inline]
pub fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

// ---------------------------------------------------------------------------
// EIP-712 domain separator
// ---------------------------------------------------------------------------

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
const DOMAIN_TYPEHASH_PREIMAGE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Compute an EIP-712 domain separator from precomputed `name` /
/// `version` keccak hashes plus chain id and verifying contract.
///
/// Pre-hashing `name` and `version` lets each protocol module declare
/// its (constant) values once at module scope and skip the keccak on
/// every signing request.
pub fn eip712_domain_separator(
    name_hash: &[u8; 32],
    version_hash: &[u8; 32],
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> [u8; 32] {
    let domain_typehash = keccak(DOMAIN_TYPEHASH_PREIMAGE);

    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(&domain_typehash);
    buf[32..64].copy_from_slice(name_hash);
    buf[64..96].copy_from_slice(version_hash);
    // chainId as uint256: 24 zero bytes, then 8 BE bytes.
    buf[96 + 24..96 + 32].copy_from_slice(&chain_id.to_be_bytes());
    // verifyingContract as address (left-padded to 32 bytes).
    buf[128 + 12..128 + 32].copy_from_slice(verifying_contract);

    keccak(&buf)
}

/// Final EIP-712 digest:
/// `keccak256( 0x19 ‖ 0x01 ‖ domain_separator ‖ struct_hash )`.
pub fn final_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain_separator);
    buf[34..66].copy_from_slice(struct_hash);
    keccak(&buf)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that the protocol-specific decoder can return.
#[derive(Debug)]
pub enum Eip712Error {
    /// One of the byte-encoded enum fields was outside its valid range.
    EnumOutOfRange,
    /// The `chain_id` bound inside the canonical buffer does not
    /// match the `chain_id` from the verified VK bundle. Prevents NS
    /// from pairing a legitimate cross-chain proof with a mismatched
    /// domain-separator bundle.
    ChainIdMismatch,
}
