//! TEST-ONLY near-miss signature generator (KAT coverage for the +C gates).
//!
//! ## Why this exists
//!
//! The two distinguishing constraints of the **+C** variant of SPHINCS+ —
//! the WOTS+C digit-sum gate (`Spec/Wots.lean:63`, `sphincs-c10/src/wots.rs`
//! `pk_from_sig` `sum != TARGET_SUM`) and the FORS+C forced-zero gate
//! (`Spec/Fors.lean:82`, `sphincs-c10/src/hypertree.rs` `verify`
//! `fors_indices[K-1] != 0`) — were, before this module existed, only
//! *proof*-guarded. Removing either gate from the verifier left
//! `lake exe verify-test-vectors` at 10/10: the existing KAT corpus has no
//! signature that exercises a gate in isolation, so the KAT could not *see*
//! a gate's removal.
//!
//! ## The near-miss construction
//!
//! The +C signer GRINDS — it searches a randomizer `R` (FORS) and a `count`
//! (WOTS, per hypertree layer) so that (a) the last FORS index is 0 and
//! (b) every WOTS digit sum equals `TARGET_SUM = 205`. A signature that is
//! otherwise byte-correct but produced WITHOUT the relevant grind still
//! reconstructs the correct `pk_root` under standard WOTS + hypertree
//! verification — it is rejected by the deployed verifier *only* because of
//! the +C gate. That is exactly a "near-miss" vector.
//!
//! Two crucial facts make these vectors well-defined:
//!
//! * **WOTS pk reconstruction is `count`-independent.** `pk_from_sig`
//!   computes `endpoint[i] = chain_hash(seed, adrs, sigma[i], digit[i],
//!   (W-1) - digit[i])`. With `sigma[i] = chain_hash(seed, adrs, sk_i, 0,
//!   digit[i])`, the endpoint is `chain_hash(seed, adrs, sk_i, 0, W-1)`
//!   regardless of `count`/`digit[i]`. So the recovered WOTS public key — and
//!   hence the Merkle root — is identical to keygen for ANY count, as long as
//!   `sigma[i]` is the chain prefix matching that count's `digit[i]`.
//!   ⇒ a non-205 count yields the correct root; only the `sum == 205` gate
//!   rejects.  (NM1)
//!
//! * **The verifier's last-FORS-tree handling is index-independent.** For the
//!   forced-zero (last) tree the verifier does NOT walk an auth path: it takes
//!   `secret[K-1]` and hashes it once at leaf-0 ADRS to get the root
//!   (`hypertree.rs` lines ~411-414). The signer emits the full computed FORS
//!   tree root there (`hypertree.rs` lines ~223-228). Neither side reads the
//!   *value* of the last FORS index for reconstruction. So a digest whose last
//!   FORS index is non-zero still reconstructs the correct `fors_pk` (and root)
//!   when trees `0..K-2` are signed honestly at the digest's indices and the
//!   last tree emits its true root; only the `index[K-1] == 0` gate rejects.
//!   (NM2)
//!
//! ## Scope
//!
//! `#[cfg(feature = "near-miss-gen")]` — off by default, NEVER shipped. The
//! production signer ([`crate::SigningKey::sign`]) is unchanged: grinding stays
//! on. This module reuses the SAME tweakable-hash / WOTS / merkle / FORS
//! primitives as the production path, so the only difference between a real
//! signature and a near-miss one is the single grind that is deliberately
//! skipped.

use crate::address::{make_adrs, set_chain_index};
use crate::fors;
use crate::hash::{chain_hash, h_msg, pad16, sha256_bytes, th, wots_digest, wots_secret};
use crate::merkle;
use crate::params::*;
use crate::wots;

/// Which +C gate the produced signature is engineered to fail (and ONLY that
/// gate). Both kinds reconstruct the correct `pk_root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// NM1: a non-grinded WOTS `count` at hypertree layer 0 so the layer-0
    /// digit sum is `!= TARGET_SUM` (205). Reconstruction → correct root.
    WotsDigitSum,
    /// NM2: a non-grinded `R` so the last FORS index is `!= 0`.
    /// Reconstruction → correct root.
    ForsForcedZero,
}

/// Sign one WOTS+C node at an EXPLICIT `count` (no grinding), returning the
/// L chain values. Mirrors `wots::sign_with_shuffle` but takes the count from
/// the caller instead of `find_count`-ing to `TARGET_SUM`.
fn wots_sign_at_count(
    seed: &[u8; 32],
    sk_seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    count: u32,
) -> [[u8; N]; L] {
    let padded = pad16(msg_hash);
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let d = wots_digest(seed, &wots_adrs, &padded, count);
    let digits = wots::extract_digits(&d);

    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut sigma = [[0u8; N]; L];
    for i in 0..L {
        let sk_i = wots_secret(sk_seed, layer, tree, kp, i as u32);
        let chain_adrs = set_chain_index(&base_adrs, i as u32);
        sigma[i] = chain_hash(seed, &chain_adrs, &sk_i, 0, digits[i] as u32);
    }
    sigma
}

/// The base-w digit sum of the WOTS digest at `(layer, tree, kp, msg, count)`.
/// Used to PICK a count whose sum `!= TARGET_SUM` for NM1.
fn wots_digit_sum(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    count: u32,
) -> usize {
    let padded = pad16(msg_hash);
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let d = wots_digest(seed, &wots_adrs, &padded, count);
    let digits = wots::extract_digits(&d);
    digits.iter().map(|&x| x as usize).sum()
}

/// Find the lowest `count` whose WOTS digit sum is NOT `TARGET_SUM`
/// (NM1's "off-target" witness — the overwhelming majority of counts qualify).
fn find_offtarget_count(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
) -> u32 {
    for count in 0..10_000u32 {
        if wots_digit_sum(seed, layer, tree, kp, msg_hash, count) != TARGET_SUM {
            return count;
        }
    }
    panic!("no off-target WOTS count found in 10k tries (statistically impossible)");
}

/// Derive a candidate `R` from a nonce (test-only; any value works because the
/// verifier reads R straight from the signature). Distinct from the production
/// `grind_r` keying so these vectors can never collide with a real signature.
fn candidate_r(nonce: u32) -> [u8; N] {
    const LABEL: &[u8; 32] = b"PQSigner near-miss R nonce.....!";
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(LABEL);
    buf[32..36].copy_from_slice(&nonce.to_be_bytes());
    let full = sha256_bytes(&buf);
    let mut r = [0u8; N];
    r.copy_from_slice(&full[..N]);
    r
}

/// Find an `R` whose H_msg digest has a NON-zero last FORS index (NM2's witness
/// — again the overwhelming majority of randomizers qualify).
fn find_nonzero_last_index_r(
    seed_b32: &[u8; 32],
    root_b32: &[u8; 32],
    msg_hash: &[u8; 32],
) -> ([u8; N], [u8; 32]) {
    for nonce in 0..10_000u32 {
        let r = candidate_r(nonce);
        let r_b32 = pad16(&r);
        let digest = h_msg(seed_b32, root_b32, &r_b32, msg_hash);
        let indices = fors::extract_fors_indices(&digest);
        if indices[K - 1] != 0 {
            return (r, digest);
        }
    }
    panic!("no non-zero-last-index R found in 10k tries (statistically impossible)");
}

/// Produce a near-miss SPHINCS+C10 signature.
///
/// The returned signature:
/// * reconstructs the SAME `pk_root` under standard WOTS + hypertree
///   verification (i.e. it would VERIFY if the targeted +C gate were removed);
/// * is rejected by the unmodified verifier ONLY because of the +C gate named
///   by `kind`.
///
/// Same `[u8; SIGNATURE_LEN]` wire layout as a real signature.
#[must_use]
pub fn sign_near_miss(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    kind: Kind,
) -> [u8; SIGNATURE_LEN] {
    let seed = pad16(pk_seed);
    let root = pad16(pk_root);
    let mut sig = [0u8; SIGNATURE_LEN];
    let mut offset = 0;

    // 1. Choose R + digest.
    //    NM1: keep the forced-zero property (so ONLY the WOTS gate breaks) —
    //         reuse the production grind.
    //    NM2: deliberately pick an R whose last FORS index is NON-zero.
    let (r, digest) = match kind {
        Kind::WotsDigitSum => fors::grind_r(sk_seed, pk_seed, pk_root, msg_hash, None),
        Kind::ForsForcedZero => find_nonzero_last_index_r(&seed, &root, msg_hash),
    };

    sig[offset..offset + N].copy_from_slice(&r);
    offset += N;

    let fors_indices = fors::extract_fors_indices(&digest);
    let ht_idx = fors::extract_ht_index(&digest);

    // 2. Sign FORS+C honestly (trees 0..K-2 at the digest's indices; the last
    //    tree emits its true root). This is identical to the production path —
    //    note the last-tree handling never reads `fors_indices[K-1]`, so NM2's
    //    non-zero last index does not change the reconstructed fors_pk.
    let mut fors_roots = [[0u8; N]; K];
    let mut fors_secrets = [[0u8; N]; K];
    let mut fors_auth_paths = [[[0u8; N]; A]; K - 1];

    for t in 0..(K - 1) {
        let (secret, auth_path) =
            fors::sign_fors_tree(&seed, sk_seed, ht_idx, t as u32, fors_indices[t]);
        fors_secrets[t] = secret;
        fors_auth_paths[t] = auth_path;
        fors_roots[t] =
            reconstruct_fors_root(&seed, ht_idx, t as u32, fors_indices[t], &secret, &auth_path);
    }

    // Last (forced-zero-style) tree: secret = full tree root, root = leaf-0 hash.
    let last_root = fors::compute_fors_root(&seed, sk_seed, ht_idx, (K - 1) as u32);
    fors_secrets[K - 1] = last_root;
    let last_leaf_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, (K - 1) as u32, 0, 0, 0);
    fors_roots[K - 1] = th(&seed, &last_leaf_adrs, &pad16(&last_root));

    // Write all K secrets.
    for secret in &fors_secrets {
        sig[offset..offset + N].copy_from_slice(secret);
        offset += N;
    }
    // Write K-1 auth paths.
    for auth in &fors_auth_paths {
        for node in auth {
            sig[offset..offset + N].copy_from_slice(node);
            offset += N;
        }
    }
    debug_assert_eq!(offset, SIG_FORS_TOTAL);

    let fors_pk = fors::compute_fors_pk(&seed, ht_idx, &fors_roots);

    // 3. Sign the hypertree. Layer 0 of NM1 uses an OFF-TARGET count; every
    //    other WOTS layer is grinded to TARGET_SUM (so ONLY one gate breaks).
    let mut current_node = fors_pk;
    let mut idx_tree = ht_idx;

    for layer in 0..(D as u32) {
        let idx_leaf = idx_tree & ((1u32 << SUBTREE_H) - 1);
        idx_tree >>= SUBTREE_H;

        let (auth_path, _subtree_root) =
            merkle::build_subtree_with_auth(
                &seed,
                sk_seed,
                layer,
                idx_tree as u64,
                idx_leaf,
                &crate::hypertree::progress_none(),
                0,
                0,
            );

        // Pick the count for this layer.
        let count = if kind == Kind::WotsDigitSum && layer == 0 {
            find_offtarget_count(&seed, layer, idx_tree as u64, idx_leaf, &current_node)
        } else {
            wots::find_count(
                &seed,
                layer,
                idx_tree as u64,
                idx_leaf,
                &pad16(&current_node),
                &crate::hypertree::progress_none(),
                0,
            )
            .0
        };

        let wots_sigma = wots_sign_at_count(
            &seed,
            sk_seed,
            layer,
            idx_tree as u64,
            idx_leaf,
            &current_node,
            count,
        );

        // Write WOTS chains.
        for chain in &wots_sigma {
            sig[offset..offset + N].copy_from_slice(chain);
            offset += N;
        }
        // Write count (BE).
        sig[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
        offset += 4;
        // Write auth path.
        for node in &auth_path {
            sig[offset..offset + N].copy_from_slice(node);
            offset += N;
        }

        // Advance to the next layer's node via the SAME reconstruction the
        // verifier uses. `wots::pk_from_sig` is gated on the digit sum — when
        // the count is off-target it returns the all-zero pk, which would
        // propagate the wrong root. So we reconstruct the WOTS pk DIRECTLY from
        // the chain endpoints (count-independent), mirroring what
        // `pk_from_sig` WOULD compute with the gate removed.
        let wots_pk = wots_pk_from_sigma_ungated(
            &seed,
            layer,
            idx_tree as u64,
            idx_leaf,
            &current_node,
            &wots_sigma,
            count,
        );
        current_node =
            merkle::verify_auth_path(&seed, layer, idx_tree as u64, &wots_pk, idx_leaf, &auth_path);
    }

    debug_assert_eq!(offset, SIGNATURE_LEN);

    // The reconstructed root MUST equal pk_root — that is what makes this a
    // near-miss (correct reconstruction) rather than a plain garbage negative.
    // This is `assert_eq!` (not `debug_assert_eq!`) so the property is enforced
    // even in `--release`, where these vectors are generated. Test-only code,
    // so the cost is irrelevant.
    assert_eq!(
        &current_node, pk_root,
        "near-miss self-reconstruction failed: root mismatch (kind={kind:?})"
    );

    sig
}

/// Reproduce the deployed verifier MINUS the targeted +C gate, returning
/// `true` iff the reconstructed root matches `pk_root`. Used by tests to prove
/// a near-miss vector is a *clean* near-miss: the production [`crate::verify`]
/// rejects it, but `verify_with_gate_removed(sig, kind)` ACCEPTS it — so the
/// ONLY thing rejecting it is `kind`'s gate.
///
/// * `Kind::WotsDigitSum`  — skips the `digitSum == TARGET_SUM` check.
/// * `Kind::ForsForcedZero` — skips the `last FORS index == 0` check.
///
/// All other reconstruction is byte-identical to `hypertree::verify`.
#[must_use]
pub fn verify_with_gate_removed(
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    sig: &[u8; SIGNATURE_LEN],
    kind: Kind,
) -> bool {
    let seed = pad16(pk_seed);
    let root = pad16(pk_root);
    let mut offset = 0;

    let mut r = [0u8; N];
    r.copy_from_slice(&sig[offset..offset + N]);
    offset += N;

    let r_b32 = pad16(&r);
    let digest = h_msg(&seed, &root, &r_b32, msg_hash);

    let fors_indices = fors::extract_fors_indices(&digest);
    let ht_idx = fors::extract_ht_index(&digest);

    // FORS forced-zero gate — skipped only for ForsForcedZero.
    if kind != Kind::ForsForcedZero && fors_indices[K - 1] != 0 {
        return false;
    }

    // Read K secrets.
    let mut fors_secrets = [[0u8; N]; K];
    for s in &mut fors_secrets {
        s.copy_from_slice(&sig[offset..offset + N]);
        offset += N;
    }
    // Read K-1 auth paths.
    let mut auth_paths = [[[0u8; N]; A]; K - 1];
    for t in 0..(K - 1) {
        for h in 0..A {
            auth_paths[t][h].copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }
    }

    let mut fors_roots = [[0u8; N]; K];
    for t in 0..(K - 1) {
        fors_roots[t] = reconstruct_fors_root(
            &seed,
            ht_idx,
            t as u32,
            fors_indices[t],
            &fors_secrets[t],
            &auth_paths[t],
        );
    }
    let last_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, (K - 1) as u32, 0, 0, 0);
    fors_roots[K - 1] = th(&seed, &last_adrs, &pad16(&fors_secrets[K - 1]));

    let fors_pk = fors::compute_fors_pk(&seed, ht_idx, &fors_roots);

    let mut current_node = fors_pk;
    let mut idx_tree = ht_idx;
    for layer in 0..(D as u32) {
        let idx_leaf = idx_tree & ((1u32 << SUBTREE_H) - 1);
        idx_tree >>= SUBTREE_H;

        let mut wots_sigma = [[0u8; N]; L];
        for s in &mut wots_sigma {
            s.copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }
        let count = u32::from_be_bytes([
            sig[offset],
            sig[offset + 1],
            sig[offset + 2],
            sig[offset + 3],
        ]);
        offset += 4;
        let mut auth_path = [[0u8; N]; SUBTREE_H];
        for a in &mut auth_path {
            a.copy_from_slice(&sig[offset..offset + N]);
            offset += N;
        }

        // WOTS digit-sum gate — skipped only for WotsDigitSum. When skipped we
        // reconstruct the pk directly from chain endpoints (count-independent).
        let wots_pk = if kind == Kind::WotsDigitSum {
            wots_pk_from_sigma_ungated(
                &seed,
                layer,
                idx_tree as u64,
                idx_leaf,
                &current_node,
                &wots_sigma,
                count,
            )
        } else {
            match wots_pk_from_sig_gated(
                &seed,
                layer,
                idx_tree as u64,
                idx_leaf,
                &current_node,
                &wots_sigma,
                count,
            ) {
                Some(pk) => pk,
                None => return false,
            }
        };
        current_node =
            merkle::verify_auth_path(&seed, layer, idx_tree as u64, &wots_pk, idx_leaf, &auth_path);
    }

    current_node == *pk_root
}

/// WOTS pk recovery WITH the digit-sum gate (returns `None` on `sum != 205`),
/// for the layers `verify_with_gate_removed` does NOT exempt.
fn wots_pk_from_sig_gated(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    sigma: &[[u8; N]; L],
    count: u32,
) -> Option<[u8; N]> {
    let padded = pad16(msg_hash);
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let d = wots_digest(seed, &wots_adrs, &padded, count);
    let digits = wots::extract_digits(&d);
    let sum: usize = digits.iter().map(|&x| x as usize).sum();
    if sum != TARGET_SUM {
        return None;
    }
    Some(wots_pk_from_sigma_ungated(
        seed, layer, tree, kp, msg_hash, sigma, count,
    ))
}

/// Recover a WOTS public key from sigma + count WITHOUT the digit-sum gate.
/// Identical math to `wots::pk_from_sig` minus the `sum == TARGET_SUM` early
/// return — i.e. what the verifier would compute if the gate were removed.
fn wots_pk_from_sigma_ungated(
    seed: &[u8; 32],
    layer: u32,
    tree: u64,
    kp: u32,
    msg_hash: &[u8; N],
    sigma: &[[u8; N]; L],
    count: u32,
) -> [u8; N] {
    let padded = pad16(msg_hash);
    let wots_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let d = wots_digest(seed, &wots_adrs, &padded, count);
    let digits = wots::extract_digits(&d);

    let base_adrs = make_adrs(layer, tree, ADRS_WOTS, kp, 0, 0, 0);
    let mut pk_elements = [[0u8; N]; L];
    for i in 0..L {
        let chain_adrs = set_chain_index(&base_adrs, i as u32);
        let remaining = (W - 1) as u32 - digits[i] as u32;
        pk_elements[i] = chain_hash(seed, &chain_adrs, &sigma[i], digits[i] as u32, remaining);
    }
    let pk_adrs = make_adrs(layer, tree, ADRS_WOTS_PK, kp, 0, 0, 0);
    crate::hash::th_multi(seed, &pk_adrs, &pk_elements)
}

/// Local copy of `hypertree::reconstruct_fors_root` (that fn is private to the
/// hypertree module). Identical math.
fn reconstruct_fors_root(
    seed: &[u8; 32],
    ht_idx: u32,
    tree_idx: u32,
    leaf_idx: u32,
    secret: &[u8; N],
    auth_path: &[[u8; N]; A],
) -> [u8; N] {
    let leaf_adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, tree_idx, 0, 0, leaf_idx);
    let mut node = th(seed, &leaf_adrs, &pad16(secret));
    let mut path_idx = leaf_idx;
    for h in 0..A {
        let parent_idx = path_idx >> 1;
        let adrs = make_adrs(
            0,
            u64::from(ht_idx),
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
