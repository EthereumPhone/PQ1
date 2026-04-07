//! Merkle tree construction for the ERC20 + VK databases.
//!
//! Both DBs use the same scheme:
//!
//! - Leaves are sorted by `(chain_id, contract)` (the same order used
//!   for the on-disk entry array).
//! - Each leaf hash is `sha256(0x00 || canonical_entry_bytes)`.
//! - Each internal node is `sha256(0x01 || left || right)`.
//! - The leaf count is padded to the next power of two by duplicating
//!   the last real leaf hash. Bitcoin-style. Unreachable via valid
//!   `(chain_id, contract)` lookups.
//!
//! The Merkle proof for entry at index `i` is the list of sibling
//! hashes encountered while walking from leaf `i` up to the root. The
//! direction at each level is implicit from the bits of `i`: bit `0`
//! is the leaf-level direction (`0` = our leaf is the left child,
//! `1` = right). The verifier mirrors this exactly.
//!
//! ## Domain separation
//!
//! The `0x00` / `0x01` prefix bytes are critical: without them, an
//! attacker who controls the entry encoding could craft a "leaf" whose
//! bytes happen to look like an internal-node concatenation, breaking
//! second-preimage resistance for the tree.

use sha2::{Digest, Sha256};

/// Hash a leaf's canonical bytes into the Merkle leaf node.
pub fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(canonical);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Combine two child hashes into their parent node.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// All levels of the Merkle tree, indexed bottom-up:
///   levels[0] = leaves (padded to power of 2)
///   levels[1] = parents of leaves
///   ...
///   levels[depth] = single root
pub struct MerkleTree {
    pub levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of leaf hashes. The input may
    /// have any non-zero length; it is padded by duplicating the last
    /// element until the length is a power of two. A single-leaf tree
    /// has depth 0 and the leaf itself is the root.
    pub fn build(mut leaves: Vec<[u8; 32]>) -> Self {
        assert!(!leaves.is_empty(), "Merkle tree requires at least one leaf");
        let target = leaves.len().next_power_of_two();
        while leaves.len() < target {
            let last = *leaves.last().unwrap();
            leaves.push(last);
        }

        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            levels.push(next);
        }

        Self { levels }
    }

    /// Root of the tree (single 32-byte hash). For a single-leaf
    /// tree, this is the leaf itself.
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    /// Number of sibling hashes in any proof from this tree (the
    /// tree's depth, equal to `log2(padded_leaf_count)`).
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Build the proof for the leaf at the given index. The result is
    /// a list of `depth` sibling hashes, ordered leaf-up. The verifier
    /// reads bit `i` of `index` to know whether the sibling at level
    /// `i` is on the left or the right.
    pub fn proof(&self, mut index: usize) -> Vec<[u8; 32]> {
        let mut out = Vec::with_capacity(self.depth());
        for level in &self.levels[..self.depth()] {
            let sib_idx = index ^ 1;
            out.push(level[sib_idx]);
            index >>= 1;
        }
        out
    }
}

/// Verify a Merkle proof. Mirror of the secure-world verifier in
/// `secure/src/erc20/merkle.rs`. Lives here so dbgen's round-trip
/// tests can self-check the proofs it just generated without pulling
/// the secure crate as a dev-dependency.
pub fn verify_proof(
    leaf_canonical: &[u8],
    mut index: usize,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    let mut h = leaf_hash(leaf_canonical);
    for sib in proof {
        if index & 1 == 0 {
            h = node_hash(&h, sib);
        } else {
            h = node_hash(sib, &h);
        }
        index >>= 1;
    }
    &h == expected_root
}
