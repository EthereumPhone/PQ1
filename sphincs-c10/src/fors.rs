//! FORS+C: Forest of Random Subsets with forced-zero Constraint.
//!
//! FORS consists of K=13 independent Merkle trees, each of height A=11.
//! The message digest selects one leaf per tree (via A-bit indices).
//! The last tree's index is **forced to zero** by R-grinding, which
//! means we only emit the tree root (no authentication path needed),
//! saving (A * N) = 176 bytes per signature.

use crate::address::make_adrs;
use crate::hash::{fors_secret, h_msg, pad16, sha256_parts, th, th_multi, th_pair, truncate};
use crate::params::*;

/// Read `num_bits` (≤ 57) starting at logical bit `bit_offset` from a
/// 256-bit big-endian digest. Bit 0 is the LSB of `digest[31]`.
///
/// Reads enough underlying bytes (`(num_bits + bit_offset%8 + 7) / 8`,
/// at most 8) to cover the requested span, returning the extracted value
/// right-aligned and masked to `num_bits`.
fn read_bits_le(digest: &[u8; 32], bit_offset: usize, num_bits: usize) -> u64 {
    debug_assert!(num_bits > 0 && num_bits <= 57);
    let byte_start = 31 - (bit_offset / 8);
    let bit_in_byte = bit_offset % 8;
    let bytes_needed = (num_bits + bit_in_byte + 7) / 8;

    let mut val: u64 = 0;
    for b in 0..bytes_needed {
        let idx = byte_start.wrapping_sub(b);
        if idx < 32 {
            val |= u64::from(digest[idx]) << (b * 8);
        }
    }
    let mask = (1u64 << num_bits) - 1;
    (val >> bit_in_byte) & mask
}

/// Extract K FORS indices from the H_msg digest.
///
/// Each index is A bits wide, extracted from the least significant bits
/// upward: `index[i] = (digest >> (i * A)) & ((1 << A) - 1)`.
///
/// Matches Python: `indices = [(digest >> (i * a)) & a_mask for i in range(k)]`
pub fn extract_fors_indices(digest: &[u8; 32]) -> [u32; K] {
    let mut indices = [0u32; K];
    for i in 0..K {
        indices[i] = read_bits_le(digest, i * A, A) as u32;
    }
    indices
}

/// Extract the hypertree index from the H_msg digest.
///
/// `htIdx = (digest >> (K * A)) & ((1 << H) - 1)`
///
/// With C10 (K=13, A=11, H=18): starts at bit 143, extracts 18 bits.
///
/// Matches Solidity `SPHINCsC10Asm.sol`:
///   `let htIdx := and(shr(143, digest), 0x3FFFF)`
pub fn extract_ht_index(digest: &[u8; 32]) -> u32 {
    read_bits_le(digest, K * A, H) as u32
}

/// R-grinding: find a randomizer R such that the last FORS index is zero.
///
/// The forced-zero constraint eliminates the need for an authentication
/// path for the last FORS tree, saving `A*N = 11*16 = 176` bytes.
///
/// # R derivation (secret-keyed, message-bound — hardened 2026-06-13)
///
/// ```text
/// R = sha256(sk_seed || "R_grind" || [opt_rand] || message || nonce_be32)[0..N]
/// ```
///
/// Two independent properties, both load-bearing:
///
/// * **`sk_seed` + `message` binding** makes R (and hence
///   `ht_idx = bits[143..161] of h_msg(pk_seed, pk_root, R, message)`)
///   **unpredictable to anyone who does not hold the secret key**, for any
///   chosen message — even under a biased or fully-predictable TRNG. This
///   closes the chosen-message FORS-saturation avenue (upstream SPHINCS-
///   `docs/SECURITY-ANALYSIS.md` §2 "Avenue B"): without a secret-keyed R an
///   attacker who can compute the public `message ↦ ht_idx` map offline can
///   craft many messages that collide on one hypertree leaf, concentrating
///   the few-time FORS budget on a single instance and lowering the forgery
///   bound. With sk_seed in the preimage that map is not attacker-computable.
///   This mirrors FIPS 205's `PRF_msg` keying R on a secret (`SK.prf`).
/// * **`opt_rand`** (when `Some`) additionally randomises the R series per
///   call, so the iteration count at which the forced-zero constraint hits
///   depends on fresh randomness rather than just `(sk_seed, message)` —
///   closing the F-9 transparent-leak channel (the msg-dependent iteration
///   count that is TVLA-detectable post-F-16). Production firmware always
///   supplies fresh TRNG `opt_rand`; the `None` path is deterministic given
///   `(sk_seed, message)` and exists only for byte-stable test vectors.
///
/// The verifier never recomputes R (it reads R from the signature), so this
/// is a pure signer-side change: the on-chain Yul verifier and the deployed
/// contracts are unaffected, but signature *bytes* change for a given input,
/// so all pinned vectors must be regenerated together.
pub fn grind_r(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    message: &[u8; 32],
    opt_rand: Option<&[u8; N]>,
) -> ([u8; N], [u8; 32]) {
    let seed_b32 = pad16(pk_seed);
    let root_b32 = pad16(pk_root);
    let last_shift = (K - 1) * A; // bit offset of the last FORS index

    let mut nonce = 0u32;
    while nonce < 10_000_000 {
        let mut nonce_b32 = [0u8; 32];
        nonce_b32[28..32].copy_from_slice(&nonce.to_be_bytes());
        // Preserve the streaming calls, including the absence of an OptRand
        // update in deterministic mode. The shared backend makes the exact
        // preimage visible to extraction without copying it into a buffer.
        let r_full = match opt_rand {
            Some(rand) => sha256_parts(&[sk_seed, b"R_grind", rand, message, &nonce_b32]),
            None => sha256_parts(&[sk_seed, b"R_grind", message, &nonce_b32]),
        };
        let r = truncate(&r_full);

        let r_b32 = pad16(&r);
        let digest = h_msg(&seed_b32, &root_b32, &r_b32, message);

        if read_bits_le(&digest, last_shift, A) == 0 {
            return (r, digest);
        }
        nonce += 1;
    }
    panic!("R grinding failed after 10M iterations");
}

/// Compute a FORS tree root via iterative bottom-up Treehash.
///
/// Uses O(A) = O(16) stack nodes = 256 bytes, not O(2^A) = 1 MB.
pub fn compute_fors_root(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    ht_idx: u32,
    tree_idx: u32,
) -> [u8; N] {
    // Treehash: process 2^A leaves left-to-right with a stack.
    let n_leaves = FORS_LEAVES; // 2048
    let mut stack = [[0u8; N]; A + 1]; // 17 entries, 272 bytes
    let mut stack_heights = [0u32; A + 1];
    let mut sp: usize = 0;

    for j in 0..n_leaves {
        // Compute leaf: th(seed, leaf_adrs, secret)
        let secret = fors_secret(sk_seed, ht_idx, tree_idx, j as u32);
        let leaf_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, tree_idx, 0, 0, j as u32);
        let mut node = th(seed, &leaf_adrs, &pad16(&secret));
        let mut node_h = 0u32;

        // Merge with stack while heights match
        while sp > 0 && stack_heights[sp - 1] == node_h {
            sp -= 1;
            let sibling = stack[sp];
            let parent_idx = (j >> (node_h + 1)) as u32;
            let adrs = make_adrs(
                0,
                u64::from(ht_idx),
                ADRS_FORS_TREE,
                tree_idx,
                0,
                node_h + 1,
                parent_idx,
            );
            // Left child was pushed first (lower index)
            node = th_pair(seed, &adrs, &pad16(&sibling), &pad16(&node));
            node_h += 1;
        }

        stack[sp] = node;
        stack_heights[sp] = node_h;
        sp += 1;
    }

    debug_assert_eq!(sp, 1);
    debug_assert_eq!(stack_heights[0], A as u32);
    stack[0]
}

/// Sign one FORS tree: return (secret, auth_path).
///
/// Uses iterative Treehash with O(A) stack to compute the authentication
/// path without materializing the full 2^A-leaf tree.
pub fn sign_fors_tree(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    ht_idx: u32,
    tree_idx: u32,
    leaf_idx: u32,
) -> ([u8; N], [[u8; N]; A]) {
    let secret = fors_secret(sk_seed, ht_idx, tree_idx, leaf_idx);

    // Build the tree and extract the auth path via Treehash.
    // For each level h, we need the sibling of our path node at that level.
    let n_leaves = FORS_LEAVES;
    let mut auth_path = [[0u8; N]; A];
    let mut stack = [[0u8; N]; A + 1];
    let mut stack_heights = [0u32; A + 1];
    let mut sp: usize = 0;

    // Track which nodes on the authentication path we've found
    let target_idx = leaf_idx;

    for j in 0..n_leaves {
        let s = fors_secret(sk_seed, ht_idx, tree_idx, j as u32);
        let leaf_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, tree_idx, 0, 0, j as u32);
        let mut node = th(seed, &leaf_adrs, &pad16(&s));
        let mut node_h = 0u32;

        while sp > 0 && stack_heights[sp - 1] == node_h {
            sp -= 1;
            let sibling = stack[sp];
            let parent_idx = (j >> (node_h + 1)) as u32;
            let adrs = make_adrs(
                0,
                u64::from(ht_idx),
                ADRS_FORS_TREE,
                tree_idx,
                0,
                node_h + 1,
                parent_idx,
            );

            // Check if either child is the auth path sibling we need
            let target_at_h = target_idx >> node_h;
            let sibling_idx = target_at_h ^ 1;
            let left_leaf_start = (j >> (node_h + 1)) << (node_h + 1);
            let right_leaf_start = left_leaf_start + (1 << node_h);

            // The sibling we just popped covers leaves starting at left_leaf_start
            // The current node covers leaves starting at right_leaf_start
            // We need the sibling of our target at height node_h
            if sibling_idx & 1 == 0 {
                // Sibling is on the left — that's the popped node
                if (sibling_idx << node_h) == (left_leaf_start as u32) {
                    auth_path[node_h as usize] = sibling;
                }
            } else {
                // Sibling is on the right — that's the current node
                if (sibling_idx << node_h) == (right_leaf_start as u32) {
                    auth_path[node_h as usize] = node;
                }
            }

            // Merge: left is always the popped (earlier) node
            node = th_pair(seed, &adrs, &pad16(&sibling), &pad16(&node));
            node_h += 1;
        }

        stack[sp] = node;
        stack_heights[sp] = node_h;
        sp += 1;
    }

    (secret, auth_path)
}

/// Compute the FORS public key from all K tree roots.
///
/// `fors_pk = th_multi(seed, fors_roots_adrs, roots[0..K])`
pub fn compute_fors_pk(seed: &[u8; 32], ht_idx: u32, roots: &[[u8; N]; K]) -> [u8; N] {
    let roots_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_ROOTS, 0, 0, 0, 0);
    th_multi(seed, &roots_adrs, roots)
}
