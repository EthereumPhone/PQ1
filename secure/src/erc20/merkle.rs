//! Merkle proof verifier shared between the ERC20 metadata DB and the
//! ZK clear-signing VK DB.
//!
//! Both DBs use the same scheme:
//!
//! - Leaf hash:     `sha256(0x00 || canonical_entry_bytes)`
//! - Internal node: `sha256(0x01 || left || right)`
//! - Padding:       last leaf duplicated until count is a power of 2
//! - Direction:     bit `i` of `leaf_index` selects left/right at level `i`
//!
//! The `0x00` / `0x01` domain separation prefix prevents an attacker
//! who controls the entry encoding from crafting bytes that look like
//! an internal-node concatenation, which would otherwise break
//! second-preimage resistance for the tree.
//!
//! The verifier here is the secure-world side of the trust gate.
//! `dbgen::merkle::verify_proof` is the host-side mirror used by the
//! round-trip tests; the two implementations MUST stay in lock-step
//! (the `dbgen` round-trip test catches any drift the moment dbgen
//! runs).

use sha2::{Digest, Sha256};

/// Verify that `canonical` is a leaf in the Merkle tree whose root
/// is `expected_root`, walking the supplied sibling hashes.
///
/// Returns `true` only if `proof.len()` equals `proof_depth` (the
/// caller is expected to read this from the DB header) AND the walk
/// terminates at `expected_root`.
///
/// The proof is supplied as a flat byte slice — `proof_bytes.len() ==
/// proof_depth * 32`. This avoids needing a `Vec` in the secure
/// `#![no_std]` world; the bytes are read 32 at a time directly from
/// the gateway buffer.
pub fn verify_proof(
    canonical: &[u8],
    leaf_index: usize,
    proof_bytes: &[u8],
    proof_depth: usize,
    expected_root: &[u8; 32],
) -> bool {
    if proof_bytes.len() != proof_depth * 32 {
        return false;
    }

    // 1. Hash the canonical leaf bytes with the 0x00 domain prefix.
    let mut h = leaf_hash(canonical);

    // 2. Walk up the tree, picking left/right at each level by
    //    bit `i` of `leaf_index`.
    let mut idx = leaf_index;
    for level in 0..proof_depth {
        let sib_off = level * 32;
        let sib: &[u8; 32] = match proof_bytes[sib_off..sib_off + 32].try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        h = if idx & 1 == 0 {
            node_hash(&h, sib)
        } else {
            node_hash(sib, &h)
        };
        idx >>= 1;
    }

    // 3. After `proof_depth` steps the path must collapse exactly
    //    to the root. We do not check `idx == 0` because both 0 and
    //    1 are legal root indices in a tree padded to power-of-2.
    &h == expected_root
}

#[inline]
fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(canonical);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[inline]
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}
