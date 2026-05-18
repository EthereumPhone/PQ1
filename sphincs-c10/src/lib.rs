//! SPHINCS+C10 — SHA-256-based post-quantum hash-based signatures.
//!
//! Parameter set C10: `W+C_F+C  h=18  d=2  a=11  k=13  w=8  l=43  sig=4008`
//!
//! C10 is the **only** signature primitive in the PQSigner OS wallet.
//! The bootstrap (master) identity signs Type 1 slot registrations, and
//! every per-slot sub-key signs Type 2 user transactions — both through
//! the same stateless 4008-byte signature.
//!
//! This is a `#![no_std]`, zero-allocation implementation targeting
//! Cortex-M33 (STM32U585). All buffers are stack-allocated.
//!
//! The algorithm matches the Solidity verifier `SPHINCsC10Asm.sol` and
//! the Python reference signer (adapted from
//! <https://github.com/nconsigny/SPHINCs->).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod params;

// Internal building blocks. Not part of the public API — external callers
// should use [`SigningKey`], [`VerifyingKey`], and [`verify`] only.
pub(crate) mod address;
pub(crate) mod fors;
pub(crate) mod hash;
pub(crate) mod hypertree;
pub(crate) mod merkle;
pub(crate) mod wots;

// Public: F-16 shuffle seed type is part of the SCA-defence API —
// `crate::crypto::c10_sign_verified_with_progress` and the SCA target
// crates construct `ShuffleSeed` values to drive `sign_with_shuffle`.
pub mod shuffle;

use zeroize::{Zeroize, ZeroizeOnDrop};

use params::{N, SIGNATURE_LEN, VERIFYING_KEY_LEN};

/// SPHINCS+C10 signing key.
///
/// Contains the secret seed and public key material needed for signing.
/// Zeroized on drop. NOT `Copy` or `Clone` to prevent silent duplication.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    /// Secret seed (32 bytes). All WOTS and FORS secrets derive from this.
    sk_seed: [u8; 32],
    /// Public seed (16 bytes). Used in all tweakable hash calls.
    pk_seed: [u8; N],
    /// Hypertree root commitment (16 bytes). Computed at keygen time.
    pk_root: [u8; N],
}

impl SigningKey {
    /// Construct a signing key from raw components.
    ///
    /// `pk_root` must have been computed by building the full hypertree
    /// from `(sk_seed, pk_seed)`. Use [`Self::keygen`] for the normal path.
    #[must_use]
    pub fn from_parts(sk_seed: [u8; 32], pk_seed: [u8; N], pk_root: [u8; N]) -> Self {
        Self {
            sk_seed,
            pk_seed,
            pk_root,
        }
    }

    /// Derive the signing key by building the full hypertree.
    ///
    /// Computes `2^SUBTREE_H = 512` WOTS public keys + Merkle tree at the
    /// top layer. On Cortex-M33 this takes ~2-3 seconds. Call once at
    /// provisioning time, not on every sign.
    #[must_use]
    pub fn keygen(sk_seed: [u8; 32], pk_seed: [u8; N]) -> Self {
        let pk_root = hypertree::compute_pk_root(&sk_seed, &pk_seed);
        Self {
            sk_seed,
            pk_seed,
            pk_root,
        }
    }

    /// Return the corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            pk_seed: self.pk_seed,
            pk_root: self.pk_root,
        }
    }

    /// Sign a 32-byte message hash.
    ///
    /// `opt_rand` is mixed into the R-grinding hash when `Some` (see
    /// [`fors::grind_r`](crate) for the F-9 rationale); when `None` the
    /// path is deterministic and byte-stable with the pre-F-9-fix
    /// behaviour. Returns a 4,008-byte signature that verifies under
    /// the Solidity `SPHINCsC10Asm` verifier and the Rust [`verify`]
    /// function.
    #[must_use]
    pub fn sign(&self, msg_hash: &[u8; 32], opt_rand: Option<&[u8; N]>) -> [u8; SIGNATURE_LEN] {
        hypertree::sign(&self.sk_seed, &self.pk_seed, &self.pk_root, msg_hash, opt_rand)
    }

    /// Sign with a fresh per-call shuffle seed that randomises the
    /// per-signature COMPUTATION order of WOTS chains and FORS
    /// trees, invoking `progress(percent)` (`0..=100`) at each major
    /// signing phase so the caller can update a UI indicator during the
    /// multi-second operation. The produced signature bytes are
    /// byte-identical to the un-shuffled path; the shuffle is purely a
    /// side-channel defence against profiled DPA's trace-alignment
    /// premise.
    ///
    /// Pass `ShuffleSeed::zero()` to get the un-shuffled
    /// (deterministic-order) behaviour — useful for regression
    /// testing the byte-equality oracle.
    #[must_use]
    pub fn sign_with_shuffle(
        &self,
        msg_hash: &[u8; 32],
        opt_rand: Option<&[u8; N]>,
        shuffle: &shuffle::ShuffleSeed,
        progress: fn(u8),
    ) -> [u8; SIGNATURE_LEN] {
        hypertree::sign_with_shuffle(
            &self.sk_seed,
            &self.pk_seed,
            &self.pk_root,
            msg_hash,
            opt_rand,
            shuffle,
            progress,
        )
    }

    /// Read-only access to the secret seed (for KDF purposes within
    /// the secure world only).
    #[must_use]
    pub fn sk_seed(&self) -> &[u8; 32] {
        &self.sk_seed
    }

    /// Read-only access to the public seed (16 bytes).
    #[must_use]
    pub fn pk_seed(&self) -> &[u8; N] {
        &self.pk_seed
    }

    /// Read-only access to the hypertree root commitment (16 bytes).
    #[must_use]
    pub fn pk_root(&self) -> &[u8; N] {
        &self.pk_root
    }
}

/// SPHINCS+C10 verifying key (public key).
///
/// 32 bytes: `pk_seed(16) || pk_root(16)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

impl VerifyingKey {
    /// Deserialize from 32 bytes: `pk_seed[16] || pk_root[16]`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        let mut pk_seed = [0u8; N];
        let mut pk_root = [0u8; N];
        pk_seed.copy_from_slice(&bytes[..N]);
        pk_root.copy_from_slice(&bytes[N..]);
        Self { pk_seed, pk_root }
    }

    /// Serialize to 32 bytes: `pk_seed[16] || pk_root[16]`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        let mut out = [0u8; VERIFYING_KEY_LEN];
        out[..N].copy_from_slice(&self.pk_seed);
        out[N..].copy_from_slice(&self.pk_root);
        out
    }

    /// Verify a signature over a 32-byte message hash.
    #[must_use]
    pub fn verify(&self, msg_hash: &[u8; 32], sig: &[u8; SIGNATURE_LEN]) -> bool {
        hypertree::verify(&self.pk_seed, &self.pk_root, msg_hash, sig)
    }
}

/// Standalone verify function for SPHINCS+C10.
#[must_use]
pub fn verify(
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    hypertree::verify(pk_seed, pk_root, msg_hash, sig)
}
