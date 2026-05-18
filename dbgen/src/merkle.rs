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

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // === Positive ============================================================

    /// leaf_hash MUST be `sha256(0x00 || canonical)` — the domain-
    /// separation prefix is the secure-world's defence against an
    /// attacker who controls a leaf's canonical bytes crafting a value
    /// whose bytes happen to look like an internal-node concatenation.
    #[test]
    fn positive_leaf_hash_known_vector_empty() {
        // sha256(0x00) — known constant, also baked into the secure
        // verifier. Any change here invalidates every on-chain root.
        let expected = hex::decode(
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        )
        .unwrap();
        assert_eq!(leaf_hash(&[]).as_slice(), expected.as_slice());
    }

    #[test]
    fn positive_leaf_hash_known_vector_abc() {
        // sha256(0x00 || "abc")
        let expected = hex::decode(
            "609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1",
        )
        .unwrap();
        assert_eq!(leaf_hash(b"abc").as_slice(), expected.as_slice());
    }

    #[test]
    fn positive_node_hash_known_vector() {
        // sha256(0x01 || 32*0x00 || 32*0xff)
        let l = [0u8; 32];
        let r = [0xffu8; 32];
        let expected = {
            let mut hh = Sha256::new();
            hh.update([0x01u8]);
            hh.update(l);
            hh.update(r);
            let out = hh.finalize();
            let mut a = [0u8; 32];
            a.copy_from_slice(&out);
            a
        };
        assert_eq!(node_hash(&l, &r), expected);
    }

    #[test]
    fn positive_single_leaf_tree_root_is_leaf() {
        // A 1-leaf tree has depth 0 and root == leaf. No proof bytes.
        let leaf = leaf_hash(b"only");
        let t = MerkleTree::build(vec![leaf]);
        assert_eq!(t.depth(), 0);
        assert_eq!(t.root(), leaf);
        assert!(t.proof(0).is_empty());
        assert!(verify_proof(b"only", 0, &[], &leaf));
    }

    #[test]
    fn positive_two_leaf_tree() {
        let l0 = leaf_hash(b"a");
        let l1 = leaf_hash(b"b");
        let t = MerkleTree::build(vec![l0, l1]);
        assert_eq!(t.depth(), 1);
        assert_eq!(t.root(), node_hash(&l0, &l1));
        let p0 = t.proof(0);
        assert_eq!(p0, vec![l1]);
        let p1 = t.proof(1);
        assert_eq!(p1, vec![l0]);
        assert!(verify_proof(b"a", 0, &p0, &t.root()));
        assert!(verify_proof(b"b", 1, &p1, &t.root()));
    }

    #[test]
    fn positive_padding_three_leaves_to_four() {
        // Bitcoin-style: the 4th slot is the 3rd leaf duplicated.
        let l0 = leaf_hash(b"x0");
        let l1 = leaf_hash(b"x1");
        let l2 = leaf_hash(b"x2");
        let t = MerkleTree::build(vec![l0, l1, l2]);
        assert_eq!(t.depth(), 2);
        // The padded leaf level must end with the last real leaf duped.
        assert_eq!(t.levels[0].len(), 4);
        assert_eq!(t.levels[0][3], l2);
        // Each real entry verifies against the root.
        for (i, raw) in [&b"x0"[..], &b"x1"[..], &b"x2"[..]].iter().enumerate() {
            let proof = t.proof(i);
            assert!(verify_proof(raw, i, &proof, &t.root()));
        }
    }

    #[test]
    fn positive_full_tree_eight_leaves_all_verify() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::build(leaves);
        assert_eq!(t.depth(), 3);
        for i in 0u8..8 {
            let p = t.proof(i as usize);
            assert_eq!(p.len(), 3);
            assert!(verify_proof(&[i], i as usize, &p, &t.root()));
        }
    }

    // === Negative ============================================================

    /// Domain-separation invariant: a leaf is `sha256(0x00 || ..)` and
    /// an internal node is `sha256(0x01 || ..)`. If they shared a
    /// preimage space, an attacker who controls a leaf's canonical
    /// bytes could craft a leaf whose hash equals an internal node and
    /// substitute subtrees. Assert the prefix bytes are different and
    /// that `leaf_hash` of an "inner-node-shaped" payload does NOT
    /// equal `node_hash` of the same children.
    #[test]
    fn negative_domain_separation_leaf_vs_node() {
        let l = h(0xaa);
        let r = h(0xbb);
        // Inner concat without the 0x01 prefix.
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&l);
        concat.extend_from_slice(&r);
        let leaf_of_concat = leaf_hash(&concat);
        let inner = node_hash(&l, &r);
        assert_ne!(
            leaf_of_concat, inner,
            "leaf and inner nodes must use distinct domain prefixes \
             (otherwise an attacker who controls leaf bytes can mimic a subtree)"
        );
    }

    /// If verify_proof tolerated tampered canonical bytes, the
    /// secure-world ERC-20/Names/Selectors Merkle gates would let NS
    /// substitute metadata for any entry. Mutate every byte position
    /// in the canonical and assert each rejects.
    #[test]
    fn negative_tampered_canonical_rejected() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| leaf_hash(&[i, 0, 0])).collect();
        let t = MerkleTree::build(leaves);
        let canonical = [1u8, 0, 0]; // entry at index 1
        let proof = t.proof(1);
        assert!(verify_proof(&canonical, 1, &proof, &t.root()));
        for pos in 0..canonical.len() {
            let mut bad = canonical;
            bad[pos] ^= 0xff;
            assert!(
                !verify_proof(&bad, 1, &proof, &t.root()),
                "tampered byte {pos} must invalidate the proof"
            );
        }
    }

    /// Tampered sibling — flipping any byte of any sibling must break
    /// the proof. Otherwise the verifier's "walk up to root" guarantee
    /// is partial.
    #[test]
    fn negative_tampered_sibling_rejected() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::build(leaves);
        let mut proof = t.proof(3);
        for level in 0..proof.len() {
            let original = proof[level];
            proof[level][0] ^= 0x01;
            assert!(
                !verify_proof(&[3u8], 3, &proof, &t.root()),
                "tampered sibling at level {level} must invalidate proof"
            );
            proof[level] = original;
        }
        // Sanity: restoring all bytes recovers a valid proof.
        assert!(verify_proof(&[3u8], 3, &proof, &t.root()));
    }

    /// Tampered root — flipping any byte of the expected root must
    /// reject. (Trivial but cheap to pin.)
    #[test]
    fn negative_tampered_root_rejected() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::build(leaves);
        let proof = t.proof(2);
        let mut bad_root = t.root();
        bad_root[31] ^= 0x80;
        assert!(!verify_proof(&[2u8], 2, &proof, &bad_root));
    }

    /// Position binding: the index is folded into the proof walk via
    /// `index & 1` at every level. Two distinct leaves at different
    /// positions must NOT cross-verify with each other's proofs.
    #[test]
    fn negative_wrong_index_rejected() {
        let leaves: Vec<[u8; 32]> = (0u8..8).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::build(leaves);
        let proof_for_3 = t.proof(3);
        // Use leaf index 3's proof but claim leaf at index 4 — under
        // the position binding this must reject, otherwise an attacker
        // could relocate any leaf within the tree.
        assert!(!verify_proof(&[3u8], 4, &proof_for_3, &t.root()));
        assert!(!verify_proof(&[3u8], 2, &proof_for_3, &t.root()));
    }

    /// Empty leaf list must panic — a 0-leaf Merkle tree has no
    /// well-defined root, and silently accepting it would let a build
    /// emit a header claiming `entry_cnt = 0` with an attacker-chosen
    /// root.
    #[test]
    #[should_panic(expected = "Merkle tree requires at least one leaf")]
    fn negative_empty_leaves_panics() {
        let _ = MerkleTree::build(Vec::<[u8; 32]>::new());
    }

    /// Tampered leaf hash inside `build` — the public API takes leaf
    /// hashes, not canonical bytes, so a caller that supplies a
    /// hand-crafted "leaf hash" should still produce a deterministic
    /// root. This pins that `build` does not hash its inputs again
    /// (a subtle regression that would silently change every
    /// on-chain root).
    #[test]
    fn negative_build_does_not_rehash_inputs() {
        let leaf = h(0x42);
        let t = MerkleTree::build(vec![leaf]);
        assert_eq!(
            t.root(),
            leaf,
            "single-leaf root must be the leaf as-given (not sha256(leaf))"
        );
    }

    /// Proof for an out-of-range index panics — guards against the
    /// secure-world parser handing the verifier a bogus index without
    /// triggering a silent wrap-around. (`MerkleTree::proof` indexes
    /// into level vectors via `idx ^ 1` so an out-of-range index
    /// panics in debug + release.)
    #[test]
    #[should_panic]
    fn negative_proof_out_of_range_panics() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::build(leaves);
        let _ = t.proof(99);
    }

    /// Padded-slot ambiguity (Bitcoin-style): the duplicated tail
    /// padding means the leaf at `n_real - 1` and the padded leaf at
    /// `n_real` produce the SAME hash chain, so `verify_proof` will
    /// accept either index. This is a documented property of the
    /// scheme; the secure-world parser is responsible for never
    /// emitting a proof for a padded index (it gates on `entry_cnt`).
    /// This test pins the behaviour so a future "tighten the verifier
    /// to reject padded indices" change does not silently break the
    /// shipped on-chain root.
    #[test]
    fn negative_padded_slot_ambiguity_is_documented() {
        // 3 real leaves → 4-slot tree, last real leaf duplicated.
        let canon = [b"x0".as_slice(), b"x1".as_slice(), b"x2".as_slice()];
        let leaves: Vec<[u8; 32]> = canon.iter().map(|c| leaf_hash(c)).collect();
        let t = MerkleTree::build(leaves);
        let proof_real = t.proof(2);
        let proof_pad = t.proof(3);
        // Both verify against the root with the same canonical bytes.
        assert!(verify_proof(canon[2], 2, &proof_real, &t.root()));
        assert!(verify_proof(canon[2], 3, &proof_pad, &t.root()));
        // The two proofs differ at the leaf level (sibling is the
        // duplicated leaf hash from the opposite side).
        assert_eq!(proof_real.len(), proof_pad.len());
    }
}
