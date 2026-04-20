//! Generic EIP-712 typed-data clear signing.
//!
//! This module provides the protocol-agnostic plumbing for the
//! `cmd_clear_sign_msg` gateway command:
//!
//!   1. A small set of keccak primitives that every EIP-712 protocol
//!      implementation needs (`keccak`, `eip712_domain_separator`,
//!      `final_digest`).
//!   2. A `Eip712Protocol` trait that each protocol implements to
//!      describe how its 164-byte canonical buffer maps onto an
//!      EIP-712 message digest.
//!   3. A `dispatch_for_sentinel` function that the `nsc.rs` handler
//!      calls with the sentinel address pulled out of the verified
//!      VK bundle. The dispatch is a tiny static table — adding a
//!      new EIP-712 protocol means: write a new submodule under
//!      `secure/src/tx/eip712/`, implement `Eip712Protocol`, append
//!      it to `PROTOCOLS`, and add a matching VK row in
//!      `secure/data/vks.json`. No change to `nsc.rs` is required.
//!
//! Why a sentinel address: the VK DB is keyed on
//! `(chain_id, contract)`, but most EIP-712 protocols sign over
//! contracts that ALSO have a calldata-bound clear-sign protocol
//! (e.g. CowSwap GPv2Settlement is the verifying contract for both
//! the EIP-712 GPv2Order flow and the on-chain `setPreSignature`
//! flow). To keep the lookup key unique without bumping the on-disk
//! `VK_DB_VERSION`, every EIP-712 protocol declares a sentinel
//! address that differs from the real verifying contract. The
//! sentinel never makes it onto Ethereum — it is a pure DB key. The
//! protocol module is responsible for hardcoding the REAL
//! verifying contract when it builds the EIP-712 domain separator.
//!
//! Canonical layout: every protocol that goes through this module
//! shares the same 164-byte canonical slot (so they all reuse the
//! firmware's existing `poseidon6` Poseidon-bytes instance). The
//! protocol module owns the byte → field decoding and the keccak
//! struct hash; this module only provides the surrounding glue.

use sha3::{Digest, Keccak256};

pub mod cowswap;
// cowswap_display pulls in `crate::ui` (hardware display primitives),
// so it's gated out of host test builds. Pure EIP-712 logic
// (`cowswap`, keccak primitives above) is always compiled so its
// cross-check invariants can be unit-tested on the host.
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
// Protocol trait + dispatch
// ---------------------------------------------------------------------------

/// Errors that the protocol-specific decoder can return.
#[derive(Debug)]
pub enum Eip712Error {
    /// One of the byte-encoded enum fields was outside its valid range.
    EnumOutOfRange,
    /// The verified VK bundle's contract field did not match any
    /// known EIP-712 protocol sentinel.
    UnknownSentinel,
    /// The `chain_id` bound inside the canonical buffer does not
    /// match the `chain_id` from the verified VK bundle. Prevents NS
    /// from pairing a legitimate cross-chain proof with a mismatched
    /// domain-separator bundle.
    ChainIdMismatch,
}

/// One protocol's contribution to the EIP-712 dispatcher.
///
/// `name` is for human-readable status logging. `sentinel` is what
/// the VK bundle's `contract` field is matched against. `compute`
/// takes the 204-byte canonical buffer (already verified by the
/// Groth16 proof) and the chain id (also verified by the bundle)
/// and returns the EIP-712 digest the wallet should sign.
pub struct Eip712ProtocolEntry {
    pub name: &'static str,
    pub sentinel: [u8; 20],
    pub compute: fn(canonical: &[u8; 204], chain_id: u64) -> Result<[u8; 32], Eip712Error>,
}

/// Static dispatch table. Add a new protocol by writing a sibling
/// submodule under `secure/src/tx/eip712/` that exports `SENTINEL` +
/// a `compute_digest` function, then appending an entry here.
pub static PROTOCOLS: &[Eip712ProtocolEntry] = &[Eip712ProtocolEntry {
    name: "cowswap-eip712-order-v1",
    sentinel: cowswap::SENTINEL,
    compute: cowswap::compute_digest,
}];

/// Look up a protocol by sentinel address and run its digest
/// computation. Returns `Err(UnknownSentinel)` if no entry matches.
pub fn dispatch_for_sentinel(
    sentinel: &[u8; 20],
    canonical: &[u8; 204],
    chain_id: u64,
) -> Result<[u8; 32], Eip712Error> {
    for p in PROTOCOLS {
        if &p.sentinel == sentinel {
            return (p.compute)(canonical, chain_id);
        }
    }
    Err(Eip712Error::UnknownSentinel)
}

/// Returns true if `sentinel` matches any registered EIP-712
/// protocol. Used by `nsc.rs` to reject VK bundles that the
/// dispatcher will not understand BEFORE running Groth16.
pub fn is_known_sentinel(sentinel: &[u8; 20]) -> bool {
    PROTOCOLS.iter().any(|p| &p.sentinel == sentinel)
}
