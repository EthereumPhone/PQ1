//! Hypertree: the top-level structure combining FORS+C and a D=2 layer
//! XMSS hypertree.
//!
//! Signing flow:
//! 1. R-grind to find a randomizer that forces the last FORS index to 0
//! 2. Sign FORS+C (K=8 trees)
//! 3. For each of D=2 hypertree layers: WOTS+C sign + Merkle auth path
//!
//! Verification:
//! 1. Reconstruct FORS PK from sig
//! 2. For each HT layer: reconstruct WOTS PK from sig, walk auth path
//! 3. Compare final root against pk_root

use crate::fors;
use crate::hash::pad16;
use crate::merkle;
use crate::params::*;
use crate::shuffle::{self, ShuffleSeed};
use crate::wots;

/// Compute `pk_root` by building the top-layer subtree.
///
/// Builds all 2^SUBTREE_H = 512 WOTS keys at layer 1, tree 0. Called
/// once at provisioning.
///
/// Matches Python: `_build_hypertree_d2(seed, sk_seed, subtree_h, cfg)`.
pub fn compute_pk_root(sk_seed: &[u8; 32], pk_seed: &[u8; N]) -> [u8; N] {
    let seed = pad16(pk_seed);
    // Build subtree at top layer (layer=1, tree=0)
    merkle::compute_subtree_root(&seed, sk_seed, 1, 0)
}

/// Full SPHINCS+C10 signing.
///
/// Produces a 4,008-byte signature: R || FORS || HT_layer0 || HT_layer1.
pub fn sign(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    opt_rand: Option<&[u8; N]>,
) -> [u8; SIGNATURE_LEN] {
    sign_inner(sk_seed, pk_seed, pk_root, msg_hash, opt_rand, None, &ShuffleSeed::zero())
}

/// Like [`sign`] but calls `progress(percent)` at each major phase
/// so the caller can update a UI indicator (0-100).
pub fn sign_with_progress(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    opt_rand: Option<&[u8; N]>,
    progress: fn(u8),
) -> [u8; SIGNATURE_LEN] {
    sign_inner(sk_seed, pk_seed, pk_root, msg_hash, opt_rand, Some(progress), &ShuffleSeed::zero())
}

/// Like [`sign_with_progress`] but the per-signature shuffle seed
/// randomises the COMPUTATION order of WOTS chains and FORS trees.
/// Output is byte-identical to the un-shuffled path; the shuffle is
/// purely a DPA-trace-misalignment defence (see `shuffle.rs`).
pub fn sign_with_shuffle(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    opt_rand: Option<&[u8; N]>,
    shuffle: &ShuffleSeed,
    progress: fn(u8),
) -> [u8; SIGNATURE_LEN] {
    sign_inner(sk_seed, pk_seed, pk_root, msg_hash, opt_rand, Some(progress), shuffle)
}

fn sign_inner(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    _opt_rand: Option<&[u8; N]>,
    progress: Option<fn(u8)>,
    shuffle: &ShuffleSeed,
) -> [u8; SIGNATURE_LEN] {
    let report = |pct: u8| { if let Some(f) = progress { f(pct); } };

    let seed = pad16(pk_seed);
    let mut sig = [0u8; SIGNATURE_LEN];
    let mut offset = 0;

    // 1. R-grind: find R such that the last FORS index is 0
    report(0);
    let (r, digest) = fors::grind_r(pk_seed, pk_root, msg_hash);

    // Write R (16 bytes)
    sig[offset..offset + N].copy_from_slice(&r);
    offset += N;

    // 2. Extract FORS indices and HT index from digest
    let fors_indices = fors::extract_fors_indices(&digest);
    let ht_idx = fors::extract_ht_index(&digest);

    // Verify forced-zero constraint
    debug_assert_eq!(fors_indices[K - 1], 0, "Last FORS index must be 0 after R-grinding");

    report(5);

    // 3. Sign FORS+C: K trees
    //
    // Signature layout (matching Python signer + Solidity verifier):
    //   ALL K secrets first, THEN all K-1 auth paths.
    //   NOT interleaved (secret[i], auth[i]) pairs.
    let mut fors_roots = [[0u8; N]; K];
    let mut fors_secrets = [[0u8; N]; K];
    let mut fors_auth_paths = [[[0u8; N]; A]; K]; // only first K-1 used

    // **F-16 (DPA-defence) shuffle.** Derive a per-call permutation
    // of `[0..K-1]` from the shuffle seed and process the trees in
    // that order. Each iteration WRITES to `fors_secrets[t]` etc.
    // using the natural tree index `t`, so the output byte layout
    // is unchanged — only the computation order shifts. The last
    // (forced-zero) tree at index K-1 is special and stays outside
    // the shuffle.
    let fors_shuffle_seed = shuffle.derive(b"fors");
    let mut fors_order = [0u8; K - 1];
    shuffle::fisher_yates(&fors_shuffle_seed, K - 1, &mut fors_order);

    for step in 0..(K - 1) {
        let t = fors_order[step] as usize;
        let (secret, auth_path) =
            fors::sign_fors_tree(&seed, sk_seed, t as u32, fors_indices[t]);
        fors_secrets[t] = secret;
        fors_auth_paths[t] = auth_path;
        fors_roots[t] = reconstruct_fors_root(
            &seed,
            t as u32,
            fors_indices[t],
            &secret,
            &auth_path,
        );
        // FORS trees span 5%-30%, each tree ~2%. Report by step
        // (monotone) rather than by tree index (shuffled), so the
        // progress bar stays smooth regardless of shuffle.
        report((5 + ((step as u32 + 1) * 25) / (K as u32 - 1)) as u8);
    }

    // Last tree (forced-zero): the "secret" is the tree root
    let last_root = fors::compute_fors_root(&seed, sk_seed, (K - 1) as u32);
    fors_secrets[K - 1] = last_root;
    let last_leaf_adrs =
        crate::address::make_adrs(0, 0, ADRS_FORS_TREE, (K - 1) as u32, 0, 0, 0);
    fors_roots[K - 1] = crate::hash::th(&seed, &last_leaf_adrs, &pad16(&last_root));

    report(32);

    // Write ALL secrets (K * N bytes)
    for t in 0..K {
        sig[offset..offset + N].copy_from_slice(&fors_secrets[t]);
        offset += N;
    }

    // Write auth paths for first K-1 trees ((K-1) * A * N bytes)
    for t in 0..(K - 1) {
        for h in 0..A {
            sig[offset..offset + N].copy_from_slice(&fors_auth_paths[t][h]);
            offset += N;
        }
    }

    debug_assert_eq!(offset, SIG_FORS_TOTAL);

    // Compute FORS public key
    let fors_pk = fors::compute_fors_pk(&seed, &fors_roots);

    // 4. Sign hypertree: D=2 layers
    let mut current_node = fors_pk;
    let mut idx_tree = ht_idx;

    for layer in 0..(D as u32) {
        let idx_leaf = idx_tree & ((1u32 << SUBTREE_H) - 1);
        idx_tree >>= SUBTREE_H;

        // Build the subtree and get the auth path
        let (auth_path, _subtree_root) =
            merkle::build_subtree_with_auth(&seed, sk_seed, layer, idx_tree as u64, idx_leaf);

        // HT layers: layer 0 = 32%-65%, layer 1 = 65%-98%
        report((32 + (layer + 1) * 33) as u8);

        // **F-16 (DPA-defence) shuffle.** Per-layer WOTS chain
        // permutation. Each layer gets its own sub-derivation so a
        // glitch leaking the layer-0 order doesn't help an attacker
        // predict layer-1.
        let wots_label: [u8; 7] = match layer {
            0 => *b"wots-0\0",
            _ => *b"wots-1\0",
        };
        let wots_shuffle_seed = shuffle.derive(&wots_label);

        // WOTS+C sign the current node
        let (wots_sigma, count) = wots::sign_with_shuffle(
            &seed, sk_seed, layer, idx_tree as u64, idx_leaf, &current_node,
            &wots_shuffle_seed,
        );

        // Write WOTS chain values (L * N bytes)
        for i in 0..L {
            sig[offset..offset + N].copy_from_slice(&wots_sigma[i]);
            offset += N;
        }

        // Write count (4 bytes, big-endian)
        sig[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
        offset += 4;

        // Write auth path (SUBTREE_H * N bytes)
        for h in 0..SUBTREE_H {
            sig[offset..offset + N].copy_from_slice(&auth_path[h]);
            offset += N;
        }

        // Compute the reconstructed root for the next layer
        let wots_pk = wots::pk_from_sig(
            &seed,
            layer,
            idx_tree as u64,
            idx_leaf,
            &current_node,
            &wots_sigma,
            count,
        );
        current_node = merkle::verify_auth_path(
            &seed,
            layer,
            idx_tree as u64,
            &wots_pk,
            idx_leaf,
            &auth_path,
        );
    }
    report(100);

    debug_assert_eq!(offset, SIGNATURE_LEN);

    // Sanity check: the reconstructed root should match pk_root
    debug_assert_eq!(
        &current_node, pk_root,
        "Signing self-verification failed: root mismatch"
    );

    sig
}

/// Verify a SPHINCS+C10 signature.
pub fn verify(
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    let seed = pad16(pk_seed);
    let root = pad16(pk_root);
    let mut offset = 0;

    // 1. Parse R
    let mut r = [0u8; N];
    r.copy_from_slice(&sig[offset..offset + N]);
    offset += N;

    // 2. Compute H_msg digest
    let r_b32 = pad16(&r);
    let digest = crate::hash::h_msg(&seed, &root, &r_b32, msg_hash);

    // 3. Extract FORS indices and HT index
    let fors_indices = fors::extract_fors_indices(&digest);
    let ht_idx = fors::extract_ht_index(&digest);

    // Check forced-zero constraint
    if fors_indices[K - 1] != 0 {
        return false;
    }

    // 4. Reconstruct FORS public key
    //
    // Signature layout: ALL K secrets first, THEN all K-1 auth paths.
    let mut fors_secrets = [[0u8; N]; K];
    let mut fors_roots = [[0u8; N]; K];

    // Read ALL K secrets
    for t in 0..K {
        fors_secrets[t].copy_from_slice(&sig[offset..offset + N]);
        offset += N;
    }

    // Read auth paths for first K-1 trees
    let mut auth_paths = [[[0u8; N]; A]; K]; // only K-1 used
    for t in 0..(K - 1) {
        for h in 0..A {
            auth_paths[t][h].copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }
    }

    // Reconstruct first K-1 roots from secret + auth path
    for t in 0..(K - 1) {
        fors_roots[t] = reconstruct_fors_root(
            &seed,
            t as u32,
            fors_indices[t],
            &fors_secrets[t],
            &auth_paths[t],
        );
    }

    // Last tree (forced-zero): secret IS the root
    let last_adrs = crate::address::make_adrs(0, 0, ADRS_FORS_TREE, (K - 1) as u32, 0, 0, 0);
    fors_roots[K - 1] =
        crate::hash::th(&seed, &last_adrs, &pad16(&fors_secrets[K - 1]));

    let fors_pk = fors::compute_fors_pk(&seed, &fors_roots);

    // 5. Verify hypertree
    let mut current_node = fors_pk;
    let mut idx_tree = ht_idx;

    for layer in 0..(D as u32) {
        let idx_leaf = idx_tree & ((1u32 << SUBTREE_H) - 1);
        idx_tree >>= SUBTREE_H;

        // Parse WOTS chain values
        let mut wots_sigma = [[0u8; N]; L];
        for i in 0..L {
            wots_sigma[i].copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }

        // Parse count
        let count = u32::from_be_bytes([
            sig[offset],
            sig[offset + 1],
            sig[offset + 2],
            sig[offset + 3],
        ]);
        offset += 4;

        // Parse auth path
        let mut auth_path = [[0u8; N]; SUBTREE_H];
        for h in 0..SUBTREE_H {
            auth_path[h].copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }

        // Reconstruct WOTS public key
        let wots_pk = wots::pk_from_sig(
            &seed,
            layer,
            idx_tree as u64,
            idx_leaf,
            &current_node,
            &wots_sigma,
            count,
        );

        // Walk auth path to root
        current_node = merkle::verify_auth_path(
            &seed,
            layer,
            idx_tree as u64,
            &wots_pk,
            idx_leaf,
            &auth_path,
        );
    }

    debug_assert_eq!(offset, SIGNATURE_LEN);

    // 6. Compare reconstructed root with pk_root
    current_node == *pk_root
}

/// Reconstruct a FORS tree root from a leaf secret and auth path.
fn reconstruct_fors_root(
    seed: &[u8; 32],
    tree_idx: u32,
    leaf_idx: u32,
    secret: &[u8; N],
    auth_path: &[[u8; N]; A],
) -> [u8; N] {
    let leaf_adrs = crate::address::make_adrs(0, 0, ADRS_FORS_TREE, tree_idx, 0, 0, leaf_idx);
    let mut node = crate::hash::th(seed, &leaf_adrs, &pad16(secret));
    let mut path_idx = leaf_idx;

    for h in 0..A {
        let parent_idx = path_idx >> 1;
        let adrs = crate::address::make_adrs(
            0,
            0,
            ADRS_FORS_TREE,
            tree_idx,
            0,
            (h + 1) as u32,
            parent_idx,
        );
        let sibling = &auth_path[h];
        if path_idx & 1 == 0 {
            node = crate::hash::th_pair(seed, &adrs, &pad16(&node), &pad16(sibling));
        } else {
            node = crate::hash::th_pair(seed, &adrs, &pad16(sibling), &pad16(&node));
        }
        path_idx >>= 1;
    }
    node
}
