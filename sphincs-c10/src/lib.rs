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
//!
//! Credit: the C10 parameter set, the reference Python signer, and the Yul
//! on-chain verifier this crate is byte-compatible with are the work of
//! Nicolas Consigny (`nconsigny`, <nicolas@ethereum.org>), MIT-licensed.

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

/// TEST-ONLY +C-gate near-miss vector generator. Gated behind the
/// `near-miss-gen` feature (off by default, NEVER shipped). Produces
/// signatures that reconstruct the correct `pk_root` under standard WOTS +
/// hypertree verification but are rejected by the deployed verifier ONLY
/// because of the WOTS+C digit-sum gate (NM1) or the FORS+C forced-zero gate
/// (NM2). Used by `tests/gen_test_vectors.rs` to add gate-isolating negatives
/// so the Lean KAT can SEE a gate's removal. The production signer is
/// unchanged. See the module docs for the construction's correctness argument.
#[cfg(feature = "near-miss-gen")]
pub mod near_miss;

// Measurement-only (work-todo §18 SCA step a): per-category hash-call
// counters. Re-exported at the crate root so integration tests can read
// the secret-touching (PRF) vs public (tree/chain) breakdown per sign.
// Gated entirely out without the feature.
#[cfg(feature = "hash-counters")]
pub use hash::counters;

/// Internals exposed **only** for the security-regression harnesses in
/// `tests/` — gated behind the `sim-internals` feature (off by default,
/// never shipped). These re-export functions that are otherwise
/// `pub(crate)`:
///
/// * `h_msg`, `pad16`, `extract_fors_indices`, `extract_ht_index` —
///   take only **public** inputs (`pk_seed`, `pk_root`, `R`, message).
///   They model exactly what a passive on-chain observer can compute, so
///   the FORS shared-forest forgery simulator
///   (`tests/fors_forgery_resistance.rs`) can interpret harvested
///   signatures without a secret key.
/// * `fors_secret`, `compute_fors_root`, `compute_fors_pk`,
///   `sign_fors_tree`, `make_adrs`, `th*` — let the position-binding
///   property test (`tests/fors_position_binding.rs`) assert that the
///   post-`fcee705a` `ht_idx` fold makes every hypertree position an
///   independent FORS forest (CWE-347 regression guard).
///
/// This widens the public surface of a security-critical crate, which is
/// why it is feature-gated and `#[doc(hidden)]`. Do not depend on it from
/// production code.
#[cfg(feature = "sim-internals")]
#[doc(hidden)]
pub mod sim_internals {
    pub use crate::address::make_adrs;
    pub use crate::wots::extract_digits;
    pub use crate::fors::{
        compute_fors_pk, compute_fors_root, extract_fors_indices, extract_ht_index, sign_fors_tree,
    };
    pub use crate::hash::{
        chain_hash, fors_secret, h_msg, pad16, th, th_multi, th_pair, wots_digest, wots_secret,
    };
}

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
    pub fn from_parts(mut sk_seed: [u8; 32], pk_seed: [u8; N], pk_root: [u8; N]) -> Self {
        let key = Self {
            sk_seed,
            pk_seed,
            pk_root,
        };
        // See `keygen`: `sk_seed` is `Copy`, so the struct field above is a
        // *copy* and this parameter's stack slot still holds the secret seed.
        // Scrub the frame copy (the stored field is wiped via ZeroizeOnDrop).
        // (secret-lifecycle audit 2026-07-01)
        sk_seed.zeroize();
        key
    }

    /// Derive the signing key by building the full hypertree.
    ///
    /// Computes `2^SUBTREE_H = 512` WOTS public keys + Merkle tree at the
    /// top layer. On Cortex-M33 this takes ~2-3 seconds. Call once at
    /// provisioning time, not on every sign.
    #[must_use]
    pub fn keygen(mut sk_seed: [u8; 32], pk_seed: [u8; N]) -> Self {
        let pk_root = hypertree::compute_pk_root(&sk_seed, &pk_seed);
        let key = Self {
            sk_seed,
            pk_seed,
            pk_root,
        };
        // `sk_seed` is `Copy`: the struct field above is a *copy*, so this
        // parameter's stack slot still holds the secret seed after keygen
        // returns. Scrub it — otherwise a caller's own `sk_seed.zeroize()`
        // (e.g. `pqsigner-domain::derive_signing_key`) is defeated by the
        // residue in this frame. The stored field is wiped via ZeroizeOnDrop.
        // (secret-lifecycle audit 2026-07-01)
        sk_seed.zeroize();
        key
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
    /// Absent under `--cfg lean_extract` (work-todo §33 P0): the
    /// `fn(u8)` progress parameter is an arrow type the Aeneas Lean
    /// extraction cannot represent. Extraction-shape callers (and the
    /// byte-equality test oracle) use [`Self::sign_with_shuffle_silent`].
    #[cfg(not(lean_extract))]
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

    /// [`Self::sign_with_shuffle`] without a progress callback.
    /// Arrow-free signature, present in BOTH cfg shapes.
    #[must_use]
    pub fn sign_with_shuffle_silent(
        &self,
        msg_hash: &[u8; 32],
        opt_rand: Option<&[u8; N]>,
        shuffle: &shuffle::ShuffleSeed,
    ) -> [u8; SIGNATURE_LEN] {
        hypertree::sign_with_shuffle_silent(
            &self.sk_seed,
            &self.pk_seed,
            &self.pk_root,
            msg_hash,
            opt_rand,
            shuffle,
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
