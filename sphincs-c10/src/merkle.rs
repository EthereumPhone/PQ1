//! Merkle tree operations for XMSS subtrees in the hypertree.
//!
//! Uses the Treehash algorithm for O(h) stack usage instead of O(2^h),
//! which is critical for the Cortex-M33 target (256 KB secure SRAM).

use crate::address::make_adrs;
use crate::hash::{pad16, th_pair};
use crate::params::*;
use crate::wots;

/// Compute the root of an XMSS subtree at a given hypertree position.
///
/// Builds all 2^SUBTREE_H WOTS public keys as leaves, then computes
/// the Merkle tree root using iterative Treehash.
///
/// Stack usage: O(SUBTREE_H * N) = O(192) bytes for the Treehash stack.
pub fn compute_subtree_root(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
) -> [u8; N] {
    let n_leaves = SUBTREE_LEAVES; // 512
    let mut stack = [[0u8; N]; SUBTREE_H + 1]; // 13 entries = 208 bytes
    let mut stack_heights = [0u32; SUBTREE_H + 1];
    let mut sp: usize = 0;

    for kp in 0..n_leaves {
        let mut node = wots::keygen_pk(seed, sk_seed, layer, tree, kp as u32);
        let mut node_h = 0u32;

        while sp > 0 && stack_heights[sp - 1] == node_h {
            sp -= 1;
            let sibling = stack[sp];
            let parent_idx = (kp >> (node_h + 1)) as u32;
            let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, node_h + 1, parent_idx);
            node = th_pair(seed, &adrs, &pad16(&sibling), &pad16(&node));
            node_h += 1;
        }

        stack[sp] = node;
        stack_heights[sp] = node_h;
        sp += 1;
    }

    debug_assert_eq!(sp, 1);
    debug_assert_eq!(stack_heights[0], SUBTREE_H as u32);
    stack[0]
}

/// Build an XMSS subtree and extract the authentication path for a
/// specific leaf, plus the WOTS secret keys for that leaf.
///
/// Returns `(auth_path, subtree_root)`.
///
/// The WOTS signing for the target leaf is done by the caller using the
/// secret keys derived from `wots::wots_secret()`.
///
/// This uses Treehash with auth-path extraction: during the left-to-right
/// leaf processing, we identify which completed subtree nodes are siblings
/// of our target path and capture them.
pub fn build_subtree_with_auth(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    target_leaf: u32,
) -> ([[u8; N]; SUBTREE_H], [u8; N]) {
    let n_leaves = SUBTREE_LEAVES;
    let mut auth_path = [[0u8; N]; SUBTREE_H];
    let mut stack = [[0u8; N]; SUBTREE_H + 1];
    let mut stack_heights = [0u32; SUBTREE_H + 1];
    let mut sp: usize = 0;

    // For auth path extraction, we track "completed subtree roots" that
    // are siblings of our target path. At height h, the sibling of our
    // target is at index (target_leaf >> h) ^ 1.
    //
    // We use the "keep" array: for each height h, the node that covers
    // the sibling's subtree is saved when it's completed.
    let mut keep = [[0u8; N]; SUBTREE_H];
    let mut keep_set = [false; SUBTREE_H];

    for kp in 0..n_leaves {
        let mut node = wots::keygen_pk(seed, sk_seed, layer, tree, kp as u32);
        let mut node_h = 0u32;

        while sp > 0 && stack_heights[sp - 1] == node_h {
            sp -= 1;
            let left = stack[sp];

            // Before merging, check if either child is the auth sibling we need
            let h = node_h as usize;
            if !keep_set[h] {
                let target_at_h = target_leaf >> node_h;
                let sibling_at_h = target_at_h ^ 1;
                // The left child covers leaf range [left_start, left_start + 2^h)
                // The right child (current node) covers [right_start, right_start + 2^h)
                let pair_start = (kp >> (node_h + 1)) << (node_h + 1);
                let left_idx = (pair_start >> node_h) as u32;
                let right_idx = left_idx + 1;

                if left_idx == sibling_at_h {
                    keep[h] = left;
                    keep_set[h] = true;
                } else if right_idx == sibling_at_h {
                    keep[h] = node;
                    keep_set[h] = true;
                }
            }

            let parent_idx = (kp >> (node_h + 1)) as u32;
            let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, node_h + 1, parent_idx);
            node = th_pair(seed, &adrs, &pad16(&left), &pad16(&node));
            node_h += 1;
        }

        stack[sp] = node;
        stack_heights[sp] = node_h;
        sp += 1;
    }

    debug_assert_eq!(sp, 1);
    let root = stack[0];

    // Copy the authentication path from the keep array
    for h in 0..SUBTREE_H {
        debug_assert!(keep_set[h], "Auth path node at height {} not found", h);
        auth_path[h] = keep[h];
    }

    (auth_path, root)
}

/// Verify a Merkle authentication path: reconstruct the root from a
/// leaf node and its auth path.
pub fn verify_auth_path(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    leaf_node: &[u8; N],
    leaf_idx: u32,
    auth_path: &[[u8; N]; SUBTREE_H],
) -> [u8; N] {
    let mut node = *leaf_node;
    let mut idx = leaf_idx;
    for h in 0..SUBTREE_H {
        let parent_idx = idx >> 1;
        let adrs = make_adrs(layer, tree, ADRS_TREE, 0, 0, (h + 1) as u32, parent_idx);
        let sibling = &auth_path[h];
        if idx & 1 == 0 {
            node = th_pair(seed, &adrs, &pad16(&node), &pad16(sibling));
        } else {
            node = th_pair(seed, &adrs, &pad16(sibling), &pad16(&node));
        }
        idx >>= 1;
    }
    node
}
