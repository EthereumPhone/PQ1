//! Negative: `tx::erc20::merkle::verify_proof` adversarial inputs.
//!
//! The DB Merkle root rides in firmware rodata and is signed end-to-end.
//! Every byte of the proof — sibling order, length, domain prefix — is
//! load-bearing. Any silent acceptance of a "close enough" proof would
//! let a malicious NS substitute a forged metadata row for a real one,
//! and the trusted UI would render attacker-supplied bytes without ever
//! flagging it. These tests pin each rejection path.

mod common;

use common::{build_tree, flatten_proof, leaf_hash, node_hash};
use pqsigner_tx::erc20::merkle::verify_proof;

fn two_leaf_setup() -> (Vec<u8>, [u8; 32]) {
    let canon_a = b"alpha".to_vec();
    let canon_b = b"beta".to_vec();
    let leaves = vec![leaf_hash(&canon_a), leaf_hash(&canon_b)];
    let (root, proofs) = build_tree(leaves);
    let p = flatten_proof(&proofs[0]);
    (p, root)
}

#[test]
fn negative_proof_length_mismatch_rejected() {
    // Assumption attacked: a proof whose declared depth doesn't match its
    // length must never verify. An attacker who could shrink the
    // declared depth would land at an internal node and call it the root.
    let (proof, root) = two_leaf_setup();
    assert!(!verify_proof(b"alpha", 0, &proof, 2, &root),
        "proof_bytes.len() (32) != proof_depth*32 (64) MUST be rejected");
    assert!(!verify_proof(b"alpha", 0, &proof, 0, &root),
        "claiming depth=0 with non-empty proof MUST be rejected");
}

#[test]
fn negative_corrupted_sibling_byte_rejected() {
    // Flip one bit of the sibling — the walk collapses to a different
    // root. Without this guard, a malicious NS could substitute leaves.
    let (mut proof, root) = two_leaf_setup();
    proof[0] ^= 0x01;
    assert!(!verify_proof(b"alpha", 0, &proof, 1, &root),
        "any sibling-byte flip must invalidate the proof");
}

#[test]
fn negative_wrong_leaf_index_rejected() {
    // Same canonical bytes, wrong index → bit-0 picks the wrong side at
    // level 0 → walk lands on the wrong root.
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta")];
    let (root, proofs) = build_tree(leaves);
    let p = flatten_proof(&proofs[0]);
    assert!(!verify_proof(b"alpha", 1, &p, 1, &root),
        "wrong leaf_index must invalidate the proof");
}

#[test]
fn negative_wrong_canonical_bytes_rejected() {
    // Same proof, different canonical bytes → leaf hash diverges → walk
    // hits a different root. Pins that the canonical bytes participate
    // in the leaf hash (i.e. the 0x00 prefix isn't being applied to the
    // wrong input by accident).
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta")];
    let (root, proofs) = build_tree(leaves);
    let p = flatten_proof(&proofs[0]);
    assert!(!verify_proof(b"alpha-prime", 0, &p, 1, &root),
        "any canonical-bytes change must invalidate the proof");
}

#[test]
fn negative_swapped_sibling_order_rejected() {
    // Two-leaf tree, leaf 0 → sibling is leaf 1's hash. If we mis-order
    // the sibling as if we were at index 1, the walk lands at
    // node_hash(sib, h) = node_hash(leaf1, leaf0) ≠ root.
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta")];
    let (root, proofs) = build_tree(leaves);
    let p = flatten_proof(&proofs[0]);
    // Tell the verifier we're at index 1 but supply leaf 0's sibling.
    assert!(!verify_proof(b"alpha", 1, &p, 1, &root),
        "left/right swap (leaf_index parity) must be cryptographically distinct");
}

#[test]
fn negative_unrelated_root_rejected() {
    // Real proof, wrong root → walk completes but final compare fails.
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta")];
    let (_real_root, proofs) = build_tree(leaves);
    let p = flatten_proof(&proofs[0]);
    let bogus_root = [0xffu8; 32];
    assert!(!verify_proof(b"alpha", 0, &p, 1, &bogus_root),
        "verifier MUST compare against the supplied root, not its computed value");
}

#[test]
fn negative_internal_node_value_cannot_masquerade_as_leaf() {
    // Domain separation attack: an attacker controls a candidate
    // canonical leaf and tries to forge a proof where the leaf-hash
    // input is the bytes of an internal node concatenation
    // `0x01 || L || R`. Without the `0x00` leaf prefix the two domains
    // would collide. We assert: hashing those bytes as a leaf does NOT
    // equal hashing them as an internal node, even though the bytes
    // match. Concretely: build a 2-leaf tree, then craft an "evil leaf"
    // whose canonical bytes are `0x01 || left_leaf || right_leaf` and
    // try to verify it under a singleton tree whose root claims to be
    // the parent node. The verifier must reject because leaf_hash adds
    // 0x00 and the internal hash adds 0x01.
    let l = leaf_hash(b"alpha");
    let r = leaf_hash(b"beta");
    let parent = node_hash(&l, &r);

    let mut evil_canonical = Vec::with_capacity(1 + 32 + 32);
    evil_canonical.push(0x01);
    evil_canonical.extend_from_slice(&l);
    evil_canonical.extend_from_slice(&r);

    // Singleton tree: depth 0, empty proof, root claimed = `parent`.
    let empty: [u8; 0] = [];
    assert!(
        !verify_proof(&evil_canonical, 0, &empty, 0, &parent),
        "leaf-vs-internal domain separation must hold: 0x00 || x != node_hash(L, R)"
    );
}

#[test]
fn negative_extra_sibling_appended_rejected() {
    // Real proof + one extra sibling byte chunk. Length check must fire
    // even if the first `depth` siblings would otherwise verify.
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta")];
    let (root, proofs) = build_tree(leaves);
    let mut p = flatten_proof(&proofs[0]);
    p.extend_from_slice(&[0u8; 32]);
    assert!(
        !verify_proof(b"alpha", 0, &p, 1, &root),
        "trailing sibling bytes (length > depth*32) must be rejected"
    );
}

#[test]
fn negative_truncated_proof_bytes_rejected() {
    let leaves = vec![leaf_hash(b"alpha"), leaf_hash(b"beta"), leaf_hash(b"c")];
    let (root, proofs) = build_tree(leaves);
    let mut p = flatten_proof(&proofs[0]);
    p.pop(); // 63 bytes — short by 1
    assert!(
        !verify_proof(b"alpha", 0, &p, 2, &root),
        "truncated proof (length < depth*32) must be rejected"
    );
}

#[test]
fn negative_empty_proof_with_nonempty_depth_rejected() {
    let any_root = [0u8; 32];
    let empty: [u8; 0] = [];
    assert!(
        !verify_proof(b"x", 0, &empty, 1, &any_root),
        "depth=1 with zero-byte proof must be rejected"
    );
}
