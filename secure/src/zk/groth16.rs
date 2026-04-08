//! Groth16 zero-knowledge proof verifier over BLS12-381.
//!
//! Verification equation:
//!   e(π.A, π.B) · e(-α, β) · e(-vk_x, γ) · e(-π.C, δ) == 1 ∈ GT
//!
//! where vk_x = IC[0] + pub[0]·IC[1] + pub[1]·IC[2]
//!
//! The verification key is NOT hardcoded — it is received at runtime in
//! the NS → S bundle. Each protocol (Aave, CowSwap, etc.) has its own
//! Circom circuit under `circuits/` and its own 960-byte VK in the
//! non-secure VK DB. The wallet authenticates the VK by walking a
//! SHA-256 Merkle proof up to `secure::db_roots::VK_DB_ROOT`, which is
//! anchored by the firmware-signing key. Fully offline — no on-chain
//! governance comparison.
//!
//! Uses the `bls12_381` crate for all elliptic curve and pairing operations.
//! Individual pairings avoid the need for alloc (no multi_miller_loop).

use bls12_381::{miller_loop_4, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use sha2::{Digest, Sha256};

use super::poseidon::poseidon_bytes;
use super::{MAX_CALLDATA, STRING_LEN};

/// A Groth16 proof consisting of three curve points.
pub struct Groth16Proof {
    pub a: G1Affine, // π.A ∈ G1
    pub b: G2Affine, // π.B ∈ G2
    pub c: G1Affine, // π.C ∈ G1
}

/// Groth16 verification key, deserialized from the payload at runtime.
/// Each protocol's ZK clear signing circuit has a unique VK.
pub struct VerificationKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: [G1Affine; 3], // IC[0..2] for 2 public signals
}

/// Serialized VK size: alpha(96) + beta(192) + gamma(192) + delta(192) + 3×IC(288) = 960 bytes.
pub const VK_LEN: usize = 96 + 192 + 192 + 192 + 3 * 96;

impl Groth16Proof {
    /// Deserialize a proof from 384 bytes: π.A (96) || π.B (192) || π.C (96).
    /// Points are in uncompressed big-endian format.
    pub fn from_bytes(bytes: &[u8; 384]) -> Option<Self> {
        let a_bytes: &[u8; 96] = bytes[0..96].try_into().ok()?;
        let b_bytes: &[u8; 192] = bytes[96..288].try_into().ok()?;
        let c_bytes: &[u8; 96] = bytes[288..384].try_into().ok()?;

        let a = Option::from(G1Affine::from_uncompressed(a_bytes))?;
        let b = Option::from(G2Affine::from_uncompressed(b_bytes))?;
        let c = Option::from(G1Affine::from_uncompressed(c_bytes))?;

        Some(Groth16Proof { a, b, c })
    }
}

impl VerificationKey {
    /// Deserialize a VK from 960 bytes.
    ///
    /// Layout:
    ///   [0..96)     alpha_g1  (G1 uncompressed)
    ///   [96..288)   beta_g2   (G2 uncompressed)
    ///   [288..480)  gamma_g2  (G2 uncompressed)
    ///   [480..672)  delta_g2  (G2 uncompressed)
    ///   [672..768)  IC[0]     (G1 uncompressed)
    ///   [768..864)  IC[1]     (G1 uncompressed)
    ///   [864..960)  IC[2]     (G1 uncompressed)
    pub fn from_bytes(bytes: &[u8; VK_LEN]) -> Option<Self> {
        let alpha_g1 = Option::from(G1Affine::from_uncompressed(bytes[0..96].try_into().ok()?))?;
        let beta_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[96..288].try_into().ok()?))?;
        let gamma_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[288..480].try_into().ok()?))?;
        let delta_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[480..672].try_into().ok()?))?;
        let ic0 = Option::from(G1Affine::from_uncompressed(bytes[672..768].try_into().ok()?))?;
        let ic1 = Option::from(G1Affine::from_uncompressed(bytes[768..864].try_into().ok()?))?;
        let ic2 = Option::from(G1Affine::from_uncompressed(bytes[864..960].try_into().ok()?))?;

        Some(VerificationKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: [ic0, ic1, ic2],
        })
    }

    /// Compute SHA-256 hash of the serialized VK. Used by the Merkle
    /// verifier in `vk_bundle` to derive the canonical leaf hash for
    /// proof walking, and by the host-side `zk-test` as a lightweight
    /// integrity check that the committed `vk_data::VK_BYTES` blob
    /// matches `vk_data::VK_HASH`.
    pub fn hash(vk_bytes: &[u8; VK_LEN]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(vk_bytes);
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Verify a Groth16 proof against two public signals using the given VK.
///
/// Computes 4 individual pairings and checks that their product in GT is the
/// identity element. This avoids needing `alloc` for `multi_miller_loop` at
/// the cost of 4 separate final exponentiations instead of 1.
///
/// Returns true if:
///   e(π.A, π.B) · e(-α, β) · e(-vk_x, γ) · e(-π.C, δ) == 1
fn groth16_verify(proof: &Groth16Proof, vk: &VerificationKey, pub0: Scalar, pub1: Scalar) -> bool {
    // Compute vk_x = IC[0] + pub0 · IC[1] + pub1 · IC[2]
    let vk_x: G1Affine = {
        let ic0 = G1Projective::from(vk.ic[0]);
        let ic1 = G1Projective::from(vk.ic[1]);
        let ic2 = G1Projective::from(vk.ic[2]);
        G1Affine::from(ic0 + ic1 * pub0 + ic2 * pub1)
    };

    // Combined Miller loop for all 4 pairs, followed by a single final
    // exponentiation. This is ~2x faster than 4 individual pairing() calls
    // because the expensive final exponentiation runs only once.
    let neg_alpha = -vk.alpha_g1;
    let neg_vk_x = -vk_x;
    let neg_c = -proof.c;

    let result = miller_loop_4([
        (&proof.a, &proof.b),
        (&neg_alpha, &vk.beta_g2),
        (&neg_vk_x, &vk.gamma_g2),
        (&neg_c, &vk.delta_g2),
    ])
    .final_exponentiation();

    // Check if result is the identity element in GT
    result == Gt::identity()
}

/// Verify a Groth16 proof against precomputed public signals.
///
/// Used by the EIP-712 clear-sign path (`cmd_clear_sign_msg`) which
/// supplies its own canonical-bytes Poseidon hash as `pub0` and the
/// readable-string Poseidon hash as `pub1`. The standard ZK clear
/// signing flow goes through `verify_clear_signing_proof` instead,
/// which expects a fixed-size 164-byte calldata buffer.
pub fn verify_with_public_signals(
    proof: &Groth16Proof,
    vk: &VerificationKey,
    pub0: Scalar,
    pub1: Scalar,
) -> bool {
    groth16_verify(proof, vk, pub0, pub1)
}

// ===========================================================================
// 3-public-signal Groth16 (CowSwap EIP-712 v3)
// ===========================================================================
//
// The CowSwap EIP-712 v3 circuit binds a third public input `H_root` —
// the Poseidon Merkle root of the device's ERC20 metadata registry
// (`crate::db_roots::ERC20_POSEIDON_ROOT`). Growing the IC array from
// 3 to 4 slots bumps `VK_LEN` from 960 to 1056 bytes, so we give this
// protocol its own `VerificationKeyV3` type + verifier. Aave v3 and
// CowSwap setPreSignature continue to use the unchanged 2-pub path
// above, so their committed zkeys don't need to be re-run.

/// Size of a 3-public-signal verification key: alpha(96) + beta(192)
/// + gamma(192) + delta(192) + 4·IC(96) = 1056 bytes.
pub const VK_V3_LEN: usize = 96 + 192 + 192 + 192 + 4 * 96;

/// Groth16 verification key for circuits with 3 public signals.
/// Identical structure to `VerificationKey` except for the IC array
/// length. Deserialized at runtime from a VK-bundle slot that was
/// zero-padded to the on-disk `VK_BLOB_LEN` (1056 B).
pub struct VerificationKeyV3 {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: [G1Affine; 4], // IC[0..3] for 3 public signals
}

impl VerificationKeyV3 {
    /// Deserialize a 3-public-signal VK from 1056 bytes.
    ///
    /// Layout:
    ///   [0..96)      alpha_g1  (G1 uncompressed)
    ///   [96..288)    beta_g2   (G2 uncompressed)
    ///   [288..480)   gamma_g2  (G2 uncompressed)
    ///   [480..672)   delta_g2  (G2 uncompressed)
    ///   [672..768)   IC[0]     (G1 uncompressed)
    ///   [768..864)   IC[1]     (G1 uncompressed)
    ///   [864..960)   IC[2]     (G1 uncompressed)
    ///   [960..1056)  IC[3]     (G1 uncompressed)
    pub fn from_bytes(bytes: &[u8; VK_V3_LEN]) -> Option<Self> {
        let alpha_g1 = Option::from(G1Affine::from_uncompressed(bytes[0..96].try_into().ok()?))?;
        let beta_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[96..288].try_into().ok()?))?;
        let gamma_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[288..480].try_into().ok()?))?;
        let delta_g2 =
            Option::from(G2Affine::from_uncompressed(bytes[480..672].try_into().ok()?))?;
        let ic0 = Option::from(G1Affine::from_uncompressed(bytes[672..768].try_into().ok()?))?;
        let ic1 = Option::from(G1Affine::from_uncompressed(bytes[768..864].try_into().ok()?))?;
        let ic2 = Option::from(G1Affine::from_uncompressed(bytes[864..960].try_into().ok()?))?;
        let ic3 = Option::from(G1Affine::from_uncompressed(bytes[960..1056].try_into().ok()?))?;

        Some(VerificationKeyV3 {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic: [ic0, ic1, ic2, ic3],
        })
    }
}

fn groth16_verify_3pub(
    proof: &Groth16Proof,
    vk: &VerificationKeyV3,
    pub0: Scalar,
    pub1: Scalar,
    pub2: Scalar,
) -> bool {
    // vk_x = IC[0] + pub0·IC[1] + pub1·IC[2] + pub2·IC[3]
    let vk_x: G1Affine = {
        let ic0 = G1Projective::from(vk.ic[0]);
        let ic1 = G1Projective::from(vk.ic[1]);
        let ic2 = G1Projective::from(vk.ic[2]);
        let ic3 = G1Projective::from(vk.ic[3]);
        G1Affine::from(ic0 + ic1 * pub0 + ic2 * pub1 + ic3 * pub2)
    };

    let neg_alpha = -vk.alpha_g1;
    let neg_vk_x = -vk_x;
    let neg_c = -proof.c;

    let result = miller_loop_4([
        (&proof.a, &proof.b),
        (&neg_alpha, &vk.beta_g2),
        (&neg_vk_x, &vk.gamma_g2),
        (&neg_c, &vk.delta_g2),
    ])
    .final_exponentiation();

    result == Gt::identity()
}

/// 3-public-signal Groth16 verification entry point. Mirrors
/// `verify_with_public_signals` but for the CowSwap EIP-712 v3
/// circuit. Used by `cmd_clear_sign_msg` when the VK bundle sentinel
/// identifies the EIP-712 protocol.
pub fn verify_with_public_signals_3pub(
    proof: &Groth16Proof,
    vk: &VerificationKeyV3,
    pub0: Scalar,
    pub1: Scalar,
    pub2: Scalar,
) -> bool {
    groth16_verify_3pub(proof, vk, pub0, pub1, pub2)
}

/// Verify a ZK clear signing proof with a dynamically-provided verification key.
///
/// Given raw calldata, a human-readable string, a Groth16 proof, and the
/// protocol's verification key, this function:
///   1. Computes H_tx  = Poseidon(calldata, 164)
///   2. Computes H_str = Poseidon(readable, 64)
///   3. Verifies the Groth16 proof against (H_tx, H_str) using the given VK
///
/// The caller is responsible for authenticating the VK before calling
/// this function (in the firmware flow, that happens via
/// `vk_bundle::verify_vk_bundle`, which walks the Merkle proof up to
/// the embedded `VK_DB_ROOT`). This function only runs the pairing
/// check — it does not re-verify trust in the VK bytes.
///
/// Returns true if the proof is valid — meaning the readable string
/// is a cryptographically verified faithful representation of the calldata.
pub fn verify_clear_signing_proof(
    calldata: &[u8; MAX_CALLDATA],
    readable: &[u8; STRING_LEN],
    proof: &Groth16Proof,
    vk: &VerificationKey,
) -> bool {
    // 1. Compute Poseidon hashes (same as ZKlarity circuit)
    let h_tx = poseidon_bytes(calldata, MAX_CALLDATA);
    let h_str = poseidon_bytes(readable, STRING_LEN);

    // 2. Verify Groth16 proof with computed public signals
    groth16_verify(proof, vk, h_tx, h_str)
}
