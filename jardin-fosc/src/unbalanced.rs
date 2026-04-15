//! Left-spine unbalanced Merkle tree for JARDIN FORS+C.
//!
//! The tree connects Q_MAX FORS public keys in a left-spine structure:
//!
//! ```text
//! depth 0:  pk_root = H(spine[0], fors_pks[0])     <- q=1 leaf
//! depth 1:  spine[0] = H(spine[1], fors_pks[1])    <- q=2 leaf
//! ...
//! depth 93: spine[92] = H(spine[93], fors_pks[93])  <- q=94 leaf
//! depth 94: spine[93] = H(sentinel, fors_pks[94])   <- q=95 leaf
//! ```
//!
//! Each spine node is `th_pair(seed, adrs{atype=6, cp=depth}, left, right)`.

use crate::address::make_adrs;
use crate::hash::th_pair;
use crate::params::*;

/// Build the unbalanced tree from Q_MAX FORS public keys and a sentinel.
///
/// Returns (pk_root, spine) where spine has Q_MAX-1 = 94 nodes.
pub fn build_unbalanced_tree(
    seed: &[u8; 32],
    sentinel: &[u8; 32],
    fors_pks: &[[u8; 32]; Q_MAX],
) -> ([u8; 32], [[u8; 32]; Q_MAX - 1]) {
    let d = Q_MAX; // 95
    let mut spine = [[0u8; 32]; Q_MAX - 1]; // 94 nodes

    // Bottom: sentinel || fors_pks[Q_MAX-1] at depth d-1 = 94
    let adrs = make_adrs(ADRS_UNBALANCED, 0, 0, (d - 1) as u32, 0);
    spine[d - 2] = th_pair(seed, &adrs, sentinel, &fors_pks[d - 1]);

    // Build spine upward: spine[i] = H(spine[i+1], fors_pks[i+1]) at depth i+1
    for i in (0..d - 2).rev() {
        let adrs = make_adrs(ADRS_UNBALANCED, 0, 0, (i + 1) as u32, 0);
        spine[i] = th_pair(seed, &adrs, &spine[i + 1], &fors_pks[i + 1]);
    }

    // Root: spine[0] || fors_pks[0] at depth 0
    let adrs = make_adrs(ADRS_UNBALANCED, 0, 0, 0, 0);
    let pk_root = th_pair(seed, &adrs, &spine[0], &fors_pks[0]);

    (pk_root, spine)
}

/// Get the unbalanced tree auth path for leaf q (1-indexed).
///
/// Returns exactly `q` auth nodes. The path is written into `out[0..q]`.
///
/// - q=1: `[spine[0]]`
/// - q=2: `[spine[1], fors_pks[0]]`
/// - q=k: `[spine[k-1], fors_pks[k-2], ..., fors_pks[0]]`
/// - q=Q_MAX: `[sentinel, fors_pks[Q_MAX-2], ..., fors_pks[0]]`
pub fn get_auth_path(
    sentinel: &[u8; 32],
    spine: &[[u8; 32]; Q_MAX - 1],
    fors_pks: &[[u8; 32]; Q_MAX],
    q: u32,
    out: &mut [[u8; 32]; Q_MAX],
) -> usize {
    let qi = q as usize;
    let i = qi - 1; // 0-indexed
    let d = Q_MAX;

    // First auth node: spine sibling or sentinel
    if i == 0 {
        out[0] = spine[0];
    } else if i >= d - 1 {
        out[0] = *sentinel;
    } else {
        out[0] = spine[i];
    }

    // Remaining: previous FORS public keys (walking up the spine)
    let mut pos = 1usize;
    // j goes from i-1 down to 0
    if i > 0 {
        for j in (0..i).rev() {
            out[pos] = fors_pks[j];
            pos += 1;
        }
    }

    debug_assert_eq!(pos, qi);
    qi
}

/// Verify the unbalanced tree auth path.
///
/// Reconstructs the root from `fors_pk` at position `q` using the auth path,
/// and compares against `pk_root`.
///
/// Verification steps match the Solidity verifier:
/// ```text
/// // Step 0: auth[0] is LEFT, forsPk is RIGHT
/// node = H(auth[0], forsPk) at cp=q-1
///
/// // Steps 1..q-1: node is LEFT, auth[j] is RIGHT
/// for j in 1..q:
///     node = H(node, auth[j]) at cp=q-1-j
/// ```
pub fn verify_unbalanced(
    seed: &[u8; 32],
    pk_root: &[u8; 32],
    q: u32,
    fors_pk: &[u8; 32],
    auth_path: &[u8],
) -> bool {
    let q_usize = q as usize;
    if auth_path.len() != q_usize * 32 {
        return false;
    }

    // Step 0: auth[0] is LEFT, forsPk is RIGHT
    let mut auth0 = [0u8; 32];
    auth0.copy_from_slice(&auth_path[0..32]);
    let adrs = make_adrs(ADRS_UNBALANCED, 0, 0, q - 1, 0);
    let mut node = th_pair(seed, &adrs, &auth0, fors_pk);

    // Steps 1..q-1: node is LEFT, auth[j] is RIGHT
    for j in 1..q_usize {
        let mut auth_j = [0u8; 32];
        auth_j.copy_from_slice(&auth_path[j * 32..(j + 1) * 32]);
        let depth = q - 1 - j as u32;
        let adrs = make_adrs(ADRS_UNBALANCED, 0, 0, depth, 0);
        node = th_pair(seed, &adrs, &node, &auth_j);
    }

    node == *pk_root
}
