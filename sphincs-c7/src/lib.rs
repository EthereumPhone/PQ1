//! SPHINCS+C7 — keccak256-based post-quantum hash-based signatures.
//!
//! Parameter set C7: `W+C_F+C  h=24  d=2  a=16  k=8  w=8  l=43  sig=3704`
//!
//! This is a `#![no_std]`, zero-allocation implementation targeting
//! Cortex-M33 (STM32U585). All buffers are stack-allocated.
//!
//! The algorithm matches the Solidity verifier `SphincsC7Asm.sol` and
//! the Python reference signer `signer_c7.py` (adapted from
//! <https://github.com/nconsigny/SPHINCs->).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod params;
pub mod address;
pub mod hash;
pub mod wots;
pub mod fors;
pub mod merkle;
pub mod hypertree;

use zeroize::{Zeroize, ZeroizeOnDrop};

use params::{N, SIGNATURE_LEN, VERIFYING_KEY_LEN};

/// SPHINCS+C7 signing key.
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
    /// from `(sk_seed, pk_seed)`. Use [`keygen`] for the normal path.
    pub fn from_parts(sk_seed: [u8; 32], pk_seed: [u8; N], pk_root: [u8; N]) -> Self {
        Self {
            sk_seed,
            pk_seed,
            pk_root,
        }
    }

    /// Derive the signing key by building the full hypertree.
    ///
    /// **Expensive**: computes 4096 WOTS public keys + Merkle tree at the
    /// top layer. On Cortex-M33 this takes ~10-15 seconds. Call once at
    /// provisioning time, not on every sign.
    pub fn keygen(sk_seed: [u8; 32], pk_seed: [u8; N]) -> Self {
        let pk_root = hypertree::compute_pk_root(&sk_seed, &pk_seed);
        Self {
            sk_seed,
            pk_seed,
            pk_root,
        }
    }

    /// Return the corresponding verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            pk_seed: self.pk_seed,
            pk_root: self.pk_root,
        }
    }

    /// Sign a 32-byte message hash.
    ///
    /// `opt_rand` is an optional 16-byte randomizer mixed into the R
    /// derivation for hedged signing. If `None`, the R is derived purely
    /// from `(sk_seed, message)`.
    ///
    /// Returns a 3,704-byte signature that verifies under [`SphincsC7Asm.sol`]
    /// and the Rust [`verify`] function.
    pub fn sign(&self, msg_hash: &[u8; 32], opt_rand: Option<&[u8; N]>) -> [u8; SIGNATURE_LEN] {
        hypertree::sign(&self.sk_seed, &self.pk_seed, &self.pk_root, msg_hash, opt_rand)
    }

    /// Read-only access to the secret seed (for KDF purposes within
    /// the secure world only).
    pub fn sk_seed(&self) -> &[u8; 32] {
        &self.sk_seed
    }

    pub fn pk_seed(&self) -> &[u8; N] {
        &self.pk_seed
    }

    pub fn pk_root(&self) -> &[u8; N] {
        &self.pk_root
    }
}

/// SPHINCS+C7 verifying key (public key).
///
/// 32 bytes: `pk_seed(16) || pk_root(16)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub pk_seed: [u8; N],
    pub pk_root: [u8; N],
}

impl VerifyingKey {
    /// Deserialize from 32 bytes: `pk_seed[16] || pk_root[16]`.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_LEN]) -> Self {
        let mut pk_seed = [0u8; N];
        let mut pk_root = [0u8; N];
        pk_seed.copy_from_slice(&bytes[..N]);
        pk_root.copy_from_slice(&bytes[N..]);
        Self { pk_seed, pk_root }
    }

    /// Serialize to 32 bytes: `pk_seed[16] || pk_root[16]`.
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_LEN] {
        let mut out = [0u8; VERIFYING_KEY_LEN];
        out[..N].copy_from_slice(&self.pk_seed);
        out[N..].copy_from_slice(&self.pk_root);
        out
    }

    /// Verify a signature over a 32-byte message hash.
    pub fn verify(&self, msg_hash: &[u8; 32], sig: &[u8; SIGNATURE_LEN]) -> bool {
        hypertree::verify(&self.pk_seed, &self.pk_root, msg_hash, sig)
    }
}

/// Standalone verify function.
pub fn verify(
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    msg_hash: &[u8; 32],
    sig: &[u8; SIGNATURE_LEN],
) -> bool {
    hypertree::verify(pk_seed, pk_root, msg_hash, sig)
}
