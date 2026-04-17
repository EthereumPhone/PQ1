//! JARDIN FORS+C compact post-quantum signature scheme.
//!
//! Parameters (Variant 2): k=26 trees, a=5 height (32 leaves/tree),
//! n=16 bytes (128-bit security), Q_MAX=95 signatures per slot.
//!
//! # Architecture
//!
//! JARDIN uses a two-tier on-chain model:
//!
//! - **Type 1 (register):** A full SPHINCS+C10 proof registers a new slot
//!   on-chain: `slots[H(r)] = H(subPkSeed || subPkRoot)`.
//!
//! - **Type 2 (compact):** A FORS+C proof signs transactions cheaply using
//!   the registered sub-key.
//!
//! Each slot supports Q_MAX=95 compact signatures before rotation is needed.
//!
//! # Signature layout
//!
//! ```text
//! [0..32)      R (randomizer, full 32 bytes)
//! [32..36)     counter (grinding result, big-endian u32)
//! [36..2436)   25 FORS openings (each: secret(16) + auth(5*16=80) = 96B)
//! [2436..2452) lastRoot (tree 25 root, forced-zero optimization)
//! [2452..)     unbalanced tree auth path (q * 16 bytes)
//! ```
//!
//! Total: 2452 + q*16 bytes (2468 for q=1, 3972 for q=95).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod address;
pub mod fors;
pub mod hash;
pub mod params;
pub mod unbalanced;

use params::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Precomputed JARDIN slot state.
///
/// Created by [`keygen`] and used for up to Q_MAX=95 compact signatures.
/// Total size: ~3,125 bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JardinSlot {
    /// Sub-key public seed (N bytes left-aligned in 32-byte word).
    #[zeroize(skip)]
    pub pk_seed: [u8; 32],

    /// Sub-key secret seed. ZeroizeOnDrop.
    sk_seed: [u8; 32],

    /// Unbalanced tree root = sub-key public key.
    #[zeroize(skip)]
    pub pk_root: [u8; 32],

    /// FORS public keys for q=1..Q_MAX.
    #[zeroize(skip)]
    pub fors_pks: [[u8; 32]; Q_MAX],

    /// Unbalanced tree spine nodes (Q_MAX-1 = 94 nodes).
    spine: [[u8; 32]; Q_MAX - 1],

    /// Sentinel value (left child of deepest spine node).
    sentinel: [u8; 32],

    /// Next leaf to use (1-indexed, starts at 1).
    pub next_q: u32,
}

/// JARDIN FORS+C signature.
///
/// Variable-length: 2452 + q*16 bytes. The `data` buffer is sized for
/// the maximum possible signature (q=Q_MAX=95).
///
/// `ZeroizeOnDrop` so any early-return or error path that drops the
/// signature before the caller writes it to NS does not leave the
/// bytes on the stack. The fields themselves are public bytes (no
/// secret is derivable from `(data, len)` alone) but leaving the
/// value of a previous signature in stack SRAM violates the secure-
/// world discipline that every secret-adjacent type carries its own
/// wipe on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct JardinSignature {
    /// Raw signature bytes.
    pub data: [u8; SIG_MAX],
    /// Actual signature length: `FORSC_BODY + q * N`.
    pub len: usize,
}

impl JardinSlot {
    /// Build a new JARDIN slot from slot entropy.
    ///
    /// This is the expensive operation (~235K sha256 hashes). It builds
    /// all Q_MAX FORS trees and the unbalanced Merkle tree.
    pub fn keygen(entropy: [u8; 32]) -> Self {
        Self::keygen_with_progress(entropy, |_| {})
    }

    /// Like [`keygen`] but calls `progress(percent)` periodically (0-100).
    ///
    /// Use this on firmware to drive a progress bar during the ~20 s keygen.
    pub fn keygen_with_progress(entropy: [u8; 32], progress: impl Fn(u8)) -> Self {
        let (pk_seed, sk_seed) = hash::jardin_derive_keys(&entropy);
        let sentinel = hash::jardin_sentinel(&pk_seed, &sk_seed);

        progress(0);

        // Compute all Q_MAX FORS public keys (q is 1-indexed).
        // This is ~95% of the keygen cost, so map i=0..95 to 0..95%.
        let mut fors_pks = [[0u8; 32]; Q_MAX];
        for i in 0..Q_MAX {
            fors_pks[i] = fors::compute_forsc_pk(&pk_seed, &sk_seed, (i + 1) as u32);
            // Report every 5th tree to avoid flooding I2C OLED writes
            if (i + 1) % 5 == 0 || i == Q_MAX - 1 {
                let pct = ((i + 1) * 95 / Q_MAX) as u8;
                progress(pct);
            }
        }

        // Build unbalanced tree (~5% of cost)
        let (pk_root, spine) =
            unbalanced::build_unbalanced_tree(&pk_seed, &sentinel, &fors_pks);

        progress(100);

        JardinSlot {
            pk_seed,
            sk_seed,
            pk_root,
            fors_pks,
            spine,
            sentinel,
            next_q: 1,
        }
    }

    /// Sign a message using the next available leaf.
    ///
    /// Returns the variable-length FORS+C signature, or an error if
    /// the slot is exhausted.
    ///
    /// Cost: ~1,670 sha256 hashes (25 FORS tree rebuilds + ~32 grinding).
    pub fn sign(&mut self, message: &[u8; 32]) -> Result<JardinSignature, &'static str> {
        let q = self.next_q;
        if q as usize > Q_MAX {
            return Err("slot exhausted - rotate keys");
        }

        let seed = &self.pk_seed;
        let sk_seed = &self.sk_seed;
        let root = &self.pk_root;

        // Step 1: Deterministic R
        let r = hash::derive_r(sk_seed, message, q);

        // Step 2: Grind counter until forced-zero
        let (counter, digest) = fors::grind_counter(seed, root, &r, message);

        // Step 3: Extract FORS indices
        let indices = hash::extract_fors_indices(&digest);
        // indices[K-1] == 0 guaranteed by the grind

        // Step 4: Build signature
        let mut sig = JardinSignature {
            data: [0u8; SIG_MAX],
            len: 0,
        };

        // R (32 bytes)
        sig.data[0..32].copy_from_slice(&r);
        // counter (4 bytes BE)
        sig.data[32..36].copy_from_slice(&counter.to_be_bytes());
        let mut off = 36;

        // 25 FORS tree openings (trees 0..24)
        for t in 0..(K - 1) {
            let (secret, auth_path) =
                fors::sign_fors_tree(seed, sk_seed, q, t as u32, indices[t]);

            // Secret (N = 16 bytes, top half of 32-byte value)
            sig.data[off..off + N].copy_from_slice(&secret[..N]);
            off += N;

            // Auth path: A=5 siblings, each N=16 bytes
            for h in 0..A {
                sig.data[off..off + N].copy_from_slice(&auth_path[h][..N]);
                off += N;
            }
        }

        // Step 5: Last tree root (tree 25, forced-zero)
        let last_root = fors::build_fors_tree(seed, sk_seed, q, (K - 1) as u32);
        sig.data[off..off + N].copy_from_slice(&last_root[..N]);
        off += N;

        debug_assert_eq!(off, FORSC_BODY); // 2452

        // Step 6: Unbalanced tree auth path (q * N bytes)
        let mut auth_buf = [[0u8; 32]; Q_MAX];
        let auth_len =
            unbalanced::get_auth_path(&self.sentinel, &self.spine, &self.fors_pks, q, &mut auth_buf);
        for i in 0..auth_len {
            sig.data[off..off + N].copy_from_slice(&auth_buf[i][..N]);
            off += N;
        }

        sig.len = off; // 2452 + q * 16
        debug_assert_eq!(sig.len, FORSC_BODY + q as usize * N);

        // Advance counter
        self.next_q = q + 1;

        Ok(sig)
    }

    /// Number of remaining signatures in this slot.
    pub fn remaining(&self) -> u8 {
        if self.next_q as usize > Q_MAX {
            0
        } else {
            (Q_MAX + 1 - self.next_q as usize) as u8
        }
    }

    /// Whether the slot is exhausted (no more signatures available).
    pub fn is_exhausted(&self) -> bool {
        self.next_q as usize > Q_MAX
    }

    /// Sub-key verifying key hash: `sha256(subPkSeed[..16] || subPkRoot[..16])`.
    pub fn sub_vk_hash(&self) -> [u8; 32] {
        let mut buf = [0u8; 32]; // N + N = 32
        buf[..N].copy_from_slice(&self.pk_seed[..N]);
        buf[N..32].copy_from_slice(&self.pk_root[..N]);
        hash::sha256(&buf)
    }
}

/// Verify a JARDIN FORS+C signature.
///
/// The signature is variable-length: 2452 + q*16 bytes.
/// `q` is derived from the signature length.
pub fn verify(
    pk_seed: &[u8; 32],
    pk_root: &[u8; 32],
    message: &[u8; 32],
    sig: &[u8],
) -> bool {
    // Validate signature length
    if sig.len() < SIG_MIN {
        return false;
    }
    let auth_bytes = sig.len() - FORSC_BODY;
    if auth_bytes % N != 0 {
        return false;
    }
    let q = (auth_bytes / N) as u32;
    if q < 1 || q as usize > Q_MAX {
        return false;
    }

    // Parse R (32 bytes, full — not masked)
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[0..32]);

    // Parse counter (4 bytes BE)
    let counter = u32::from_be_bytes([sig[32], sig[33], sig[34], sig[35]]);

    // Compute H_msg digest
    let digest = hash::jardin_h_msg(pk_seed, pk_root, &r, message, counter);

    // Extract FORS indices
    let indices = hash::extract_fors_indices(&digest);

    // Forced-zero check: tree 25 index must be 0
    if indices[K - 1] != 0 {
        return false;
    }

    // Reconstruct FORS roots
    let mut roots = [[0u8; 32]; K];
    let mut off = 36usize;

    // 25 normal trees (0..24)
    for t in 0..(K - 1) {
        // Parse secret (N bytes, left-aligned in 32-byte word)
        let mut secret = [0u8; 32];
        secret[..N].copy_from_slice(&sig[off..off + N]);
        off += N;

        // Parse auth path (A * N bytes)
        let mut auth_path = [[0u8; 32]; A];
        for h in 0..A {
            auth_path[h][..N].copy_from_slice(&sig[off..off + N]);
            off += N;
        }

        // Reconstruct root from opening
        roots[t] = fors::verify_fors_opening(
            pk_seed,
            q,
            t as u32,
            indices[t],
            &secret,
            &auth_path,
        );
    }

    // Last tree (tree 25, forced-zero): hash root as leaf
    let mut last_root = [0u8; 32];
    last_root[..N].copy_from_slice(&sig[off..off + N]);
    off += N;

    let last_adrs = address::make_adrs(ADRS_FORS_TREE, (K - 1) as u32, q, 0, 0);
    roots[K - 1] = hash::th(pk_seed, &last_adrs, &last_root);

    debug_assert_eq!(off, FORSC_BODY);

    // Compress 26 roots into forsPk
    let roots_adrs = address::make_adrs(ADRS_FORS_ROOTS, 0, q, 0, 0);
    let fors_pk = hash::th_multi(pk_seed, &roots_adrs, &roots);

    // Verify unbalanced tree auth path
    let auth_path_bytes = &sig[FORSC_BODY..];
    // Expand N-byte values to 32-byte words for verification
    let mut auth_expanded = [0u8; Q_MAX * 32];
    for i in 0..q as usize {
        auth_expanded[i * 32..i * 32 + N]
            .copy_from_slice(&auth_path_bytes[i * N..i * N + N]);
    }

    unbalanced::verify_unbalanced(
        pk_seed,
        pk_root,
        q,
        &fors_pk,
        &auth_expanded[..q as usize * 32],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_produces_valid_slot() {
        let entropy = [0x42u8; 32];
        let slot = JardinSlot::keygen(entropy);
        assert_eq!(slot.next_q, 1);
        assert_eq!(slot.remaining(), 95);
        assert!(!slot.is_exhausted());
        // pk_seed should be N-masked (bytes 16..32 are zero)
        assert!(slot.pk_seed[N..].iter().all(|&b| b == 0));
        // pk_root should be N-masked
        assert!(slot.pk_root[N..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sign_verify_q1() {
        let entropy = [0x01u8; 32];
        let mut slot = JardinSlot::keygen(entropy);
        let msg = [0xABu8; 32];

        let sig = slot.sign(&msg).unwrap();
        assert_eq!(sig.len, FORSC_BODY + N); // 2468
        assert_eq!(slot.next_q, 2);

        assert!(verify(&slot.pk_seed, &slot.pk_root, &msg, &sig.data[..sig.len]));
    }

    #[test]
    fn test_sign_verify_all_q() {
        let entropy = [0x77u8; 32];
        let mut slot = JardinSlot::keygen(entropy);
        let pk_seed = slot.pk_seed;
        let pk_root = slot.pk_root;

        for q in 1..=Q_MAX {
            let msg = {
                let mut m = [0u8; 32];
                m[0..4].copy_from_slice(&(q as u32).to_be_bytes());
                m
            };
            let sig = slot.sign(&msg).unwrap();
            assert_eq!(sig.len, FORSC_BODY + q * N, "wrong sig len at q={}", q);
            assert!(
                verify(&pk_seed, &pk_root, &msg, &sig.data[..sig.len]),
                "verify failed at q={}",
                q
            );
        }

        // Slot should now be exhausted
        assert!(slot.is_exhausted());
        assert_eq!(slot.remaining(), 0);
        assert!(slot.sign(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_wrong_message_fails() {
        let entropy = [0x02u8; 32];
        let mut slot = JardinSlot::keygen(entropy);
        let msg = [0xCDu8; 32];
        let wrong_msg = [0xEFu8; 32];

        let sig = slot.sign(&msg).unwrap();
        assert!(!verify(
            &slot.pk_seed,
            &slot.pk_root,
            &wrong_msg,
            &sig.data[..sig.len]
        ));
    }

    #[test]
    fn test_wrong_key_fails() {
        let entropy = [0x03u8; 32];
        let mut slot = JardinSlot::keygen(entropy);
        let msg = [0x11u8; 32];

        let sig = slot.sign(&msg).unwrap();

        // Wrong pk_seed
        let mut bad_seed = slot.pk_seed;
        bad_seed[0] ^= 0xFF;
        assert!(!verify(&bad_seed, &slot.pk_root, &msg, &sig.data[..sig.len]));

        // Wrong pk_root
        let mut bad_root = slot.pk_root;
        bad_root[0] ^= 0xFF;
        assert!(!verify(&slot.pk_seed, &bad_root, &msg, &sig.data[..sig.len]));
    }

    #[test]
    fn test_signature_length_invariant() {
        let entropy = [0x04u8; 32];
        let mut slot = JardinSlot::keygen(entropy);

        for q in 1..=5u32 {
            let msg = [q as u8; 32];
            let sig = slot.sign(&msg).unwrap();
            assert_eq!(sig.len, FORSC_BODY + q as usize * N);
        }
    }

    #[test]
    fn test_invalid_signature_lengths() {
        let pk_seed = [0u8; 32];
        let pk_root = [0u8; 32];
        let msg = [0u8; 32];

        // Too short
        assert!(!verify(&pk_seed, &pk_root, &msg, &[0u8; 100]));
        // Not aligned to N after FORSC_BODY
        assert!(!verify(&pk_seed, &pk_root, &msg, &[0u8; FORSC_BODY + 7]));
        // Exactly FORSC_BODY (q=0 invalid)
        assert!(!verify(&pk_seed, &pk_root, &msg, &[0u8; FORSC_BODY]));
    }

    #[test]
    fn test_deterministic_keygen() {
        let entropy = [0x55u8; 32];
        let slot1 = JardinSlot::keygen(entropy);
        let slot2 = JardinSlot::keygen(entropy);
        assert_eq!(slot1.pk_seed, slot2.pk_seed);
        assert_eq!(slot1.pk_root, slot2.pk_root);
    }

    #[test]
    fn test_deterministic_signing() {
        let entropy = [0x66u8; 32];
        let mut slot1 = JardinSlot::keygen(entropy);
        let mut slot2 = JardinSlot::keygen(entropy);
        let msg = [0xBBu8; 32];

        let sig1 = slot1.sign(&msg).unwrap();
        let sig2 = slot2.sign(&msg).unwrap();
        assert_eq!(sig1.len, sig2.len);
        assert_eq!(&sig1.data[..sig1.len], &sig2.data[..sig2.len]);
    }

    #[test]
    fn test_slot_entropy_derivation() {
        let master = [0xAAu8; 32];
        let e1 = hash::jardin_slot_entropy(&master, 0);
        let e2 = hash::jardin_slot_entropy(&master, 1);
        assert_ne!(e1, e2);

        // Deterministic
        let e1b = hash::jardin_slot_entropy(&master, 0);
        assert_eq!(e1, e1b);
    }

    #[test]
    fn test_sub_vk_hash() {
        let entropy = [0x88u8; 32];
        let slot = JardinSlot::keygen(entropy);
        let h = slot.sub_vk_hash();
        // Should be sha256(pk_seed[..16] || pk_root[..16])
        let mut buf = [0u8; 32];
        buf[..N].copy_from_slice(&slot.pk_seed[..N]);
        buf[N..32].copy_from_slice(&slot.pk_root[..N]);
        let expected = hash::sha256(&buf);
        assert_eq!(h, expected);
    }
}
