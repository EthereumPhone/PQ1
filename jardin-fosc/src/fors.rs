//! FORS+C implementation for JARDIN parameters.
//!
//! k=26 trees, a=5 height (32 leaves/tree). The last tree (tree 25) has
//! its index forced to 0 via counter grinding, saving one auth path.

use crate::address::make_adrs;
use crate::hash::{fors_secret, jardin_h_msg, th, th_multi, th_pair};
use crate::params::*;

/// Build a single FORS tree and return its root.
///
/// Iterative treehash: O(A) stack depth, processes 2^A = 32 leaves.
/// Stack: `[[u8; 32]; A+1]` = 192 bytes.
pub fn build_fors_tree(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    q: u32,
    tree_idx: u32,
) -> [u8; 32] {
    let n_leaves = FORS_LEAVES; // 32

    // Treehash stack: at most A+1 = 6 entries
    let mut stack = [[0u8; 32]; A + 1];
    let mut heights = [0u32; A + 1];
    let mut sp: usize = 0;

    for j in 0..n_leaves {
        // Leaf: hash the FORS secret
        let secret = fors_secret(sk_seed, q, tree_idx, j as u32);
        let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, 0, j as u32);
        let mut node = th(seed, &adrs, &secret);
        let mut node_height: u32 = 0;

        // Merge with stack while heights match
        while sp > 0 && heights[sp - 1] == node_height {
            sp -= 1;
            let left = stack[sp];
            let parent_idx = j >> (node_height + 1);
            let adrs = make_adrs(
                ADRS_FORS_TREE,
                tree_idx,
                q,
                node_height + 1,
                parent_idx as u32,
            );
            node = th_pair(seed, &adrs, &left, &node);
            node_height += 1;
        }

        stack[sp] = node;
        heights[sp] = node_height;
        sp += 1;
    }

    debug_assert_eq!(sp, 1);
    stack[0]
}

/// Sign one FORS tree: return (secret, auth_path).
///
/// Rebuilds the tree while extracting the authentication path for `leaf_idx`.
pub fn sign_fors_tree(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    q: u32,
    tree_idx: u32,
    leaf_idx: u32,
) -> ([u8; 32], [[u8; 32]; A]) {
    let n_leaves = FORS_LEAVES; // 32
    let mut auth_path = [[0u8; 32]; A];

    // Build the full tree level by level to extract auth path.
    // Level 0: leaves
    let mut nodes = [[0u8; 32]; FORS_LEAVES]; // 32 * 32 = 1024 bytes
    for j in 0..n_leaves {
        let secret = fors_secret(sk_seed, q, tree_idx, j as u32);
        let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, 0, j as u32);
        nodes[j] = th(seed, &adrs, &secret);
    }

    // Extract the revealed secret
    let secret = fors_secret(sk_seed, q, tree_idx, leaf_idx);

    // Walk levels, extracting siblings
    let mut path_idx = leaf_idx as usize;
    let mut width = n_leaves;
    for h in 0..A {
        // Sibling is the node at path_idx ^ 1
        let sibling_idx = path_idx ^ 1;
        auth_path[h] = nodes[sibling_idx];

        // Build next level
        width >>= 1;
        let mut next_nodes = [[0u8; 32]; FORS_LEAVES / 2];
        for idx in 0..width {
            let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, (h + 1) as u32, idx as u32);
            next_nodes[idx] = th_pair(seed, &adrs, &nodes[idx * 2], &nodes[idx * 2 + 1]);
        }

        // Copy back (reuse nodes array prefix)
        for idx in 0..width {
            nodes[idx] = next_nodes[idx];
        }
        path_idx >>= 1;
    }

    (secret, auth_path)
}

/// Compute FORS+C public key for a given q.
///
/// Builds all K=26 trees, hashes tree 25's root as a leaf (forced-zero
/// optimization), then compresses 26 roots via `th_multi`.
pub fn compute_forsc_pk(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    q: u32,
) -> [u8; 32] {
    let mut roots = [[0u8; 32]; K];

    for t in 0..K {
        roots[t] = build_fors_tree(seed, sk_seed, q, t as u32);
    }

    // Last tree: hash root as leaf (forced-zero — index is always 0)
    let last_adrs = make_adrs(ADRS_FORS_TREE, (K - 1) as u32, q, 0, 0);
    roots[K - 1] = th(seed, &last_adrs, &roots[K - 1]);

    let roots_adrs = make_adrs(ADRS_FORS_ROOTS, 0, q, 0, 0);
    th_multi(seed, &roots_adrs, &roots)
}

/// Grind counter until the forced-zero constraint is satisfied.
///
/// Returns (counter, digest) where `digest` has tree 25's index == 0.
/// Expected iterations: ~2^A = 32.
pub fn grind_counter(
    seed: &[u8; 32],
    root: &[u8; 32],
    r: &[u8; 32],
    message: &[u8; 32],
) -> (u32, [u8; 32]) {
    for counter in 0..10_000_000u32 {
        let digest = jardin_h_msg(seed, root, r, message, counter);
        let indices = crate::hash::extract_fors_indices(&digest);
        if indices[K - 1] == 0 {
            return (counter, digest);
        }
    }
    panic!("JARDIN counter grinding failed after 10M iterations");
}

/// Verify a FORS+C opening: reconstruct the tree root from a secret and
/// auth path, then compare against the expected root.
pub fn verify_fors_opening(
    seed: &[u8; 32],
    q: u32,
    tree_idx: u32,
    leaf_idx: u32,
    secret: &[u8; 32],
    auth_path: &[[u8; 32]; A],
) -> [u8; 32] {
    // Hash secret to leaf
    let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, 0, leaf_idx);
    let mut node = th(seed, &adrs, secret);

    // Walk auth path
    let mut path_idx = leaf_idx;
    for h in 0..A {
        let parent_idx = path_idx >> 1;
        let adrs = make_adrs(ADRS_FORS_TREE, tree_idx, q, (h + 1) as u32, parent_idx);
        if path_idx & 1 == 0 {
            node = th_pair(seed, &adrs, &node, &auth_path[h]);
        } else {
            node = th_pair(seed, &adrs, &auth_path[h], &node);
        }
        path_idx >>= 1;
    }

    node
}
