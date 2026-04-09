//! Wire format and verifier for the ZK clear-signing VK bundle that
//! the non-secure world attaches to a `CMD_CLEAR_SIGN` request.
//!
//! Same trust model as the ERC20 metadata bundle: the full VK pool
//! lives in non-secure rodata, and the secure world only embeds a
//! 32-byte Merkle root (`crate::db_roots::VK_DB_ROOT`). At sign time
//! the non-secure world looks up `(chain_id, contract)` in its local
//! index, sends the matching 960-byte VK plus a Merkle proof, and the
//! secure world re-derives the leaf hash + walks the proof up to the
//! embedded root before trusting any of the VK bytes for Groth16
//! verification.
//!
//! ## Wire layout
//!
//! ```text
//!   chain_id      u64 LE                  ( 8 B)
//!   contract      [u8; 20]                (20 B)
//!   vk            [u8; 960]               (960 B)
//!   leaf_index    u32 LE                  ( 4 B)
//!   proof_depth   u32 LE                  ( 4 B)
//!   proof         [u8; proof_depth * 32]
//! ```

use crate::db_roots::VK_DB_ROOT;
use crate::erc20::merkle::verify_proof;
use sphincs_tz_shared::db_format::{VK_BLOB_LEN, VK_BLOB_LEN_2PUB, VK_BLOB_LEN_3PUB};

/// Maximum total VK bundle size: header (8 + 20 + 1056 + 4 + 4) +
/// up to 32 levels of Merkle proof (32 levels × 32 bytes = 1024 B).
/// 1092 + 1024 = 2116 B.
pub const MAX_VK_BUNDLE_LEN: usize = 8 + 20 + VK_BLOB_LEN + 4 + 4 + 32 * 32;

/// Decoded + Merkle-verified VK bundle. Borrows the VK bytes from
/// the gateway buffer the bundle was copied into. The VK pool slot
/// is always `VK_BLOB_LEN` (1056 B) wide; callers slice it to the
/// right length based on the protocol sentinel via `vk_as_2pub` /
/// `vk_as_3pub` accessors below.
pub struct VerifiedVk<'a> {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub vk: &'a [u8; VK_BLOB_LEN],
}

impl<'a> VerifiedVk<'a> {
    /// Return the first 960 bytes of the VK slot as a fixed-length
    /// array reference — what `VerificationKey::from_bytes` takes.
    /// Used for 2-public-signal protocols (Aave v3, CowSwap
    /// setPreSignature). The trailing 96 bytes of the slot are the
    /// zero padding written by `dbgen` for 2-pub protocols.
    pub fn vk_as_2pub(&self) -> &'a [u8; VK_BLOB_LEN_2PUB] {
        // SAFETY: &[u8; 1056] trivially projects to &[u8; 960] via a
        // prefix array reference. The padding bytes at [960..1056) are
        // ignored by the 2-pub verifier. Bound of 960 is const.
        let slice: &[u8] = &self.vk[..VK_BLOB_LEN_2PUB];
        slice.try_into().expect("VK_BLOB_LEN_2PUB is a compile-time constant")
    }

    /// Return the full 1056-byte VK slot — what
    /// `VerificationKeyV3::from_bytes` takes. Used by the CowSwap
    /// EIP-712 v3 protocol only.
    pub fn vk_as_3pub(&self) -> &'a [u8; VK_BLOB_LEN_3PUB] {
        let slice: &[u8] = &self.vk[..VK_BLOB_LEN_3PUB];
        slice.try_into().expect("VK_BLOB_LEN_3PUB == VK_BLOB_LEN == compile-time constant")
    }
}

/// Verify a VK bundle copied from the NS gateway buffer. On success,
/// returns the decoded `(chain_id, contract, vk)` triple. The caller
/// (`cmd_clear_sign`) MUST cross-check the returned `chain_id` and
/// `contract` against `parsed.tx.chain_id` and `parsed.tx.to` before
/// using the VK in Groth16 verification — the bundle by itself only
/// proves "this VK is in the firmware DB", not "this VK is the one
/// for the contract being signed".
pub fn verify_vk_bundle(bundle: &[u8]) -> Option<VerifiedVk<'_>> {
    let mut off = 0usize;

    if bundle.len() < off + 8 + 20 + VK_BLOB_LEN + 4 + 4 {
        return None;
    }
    let chain_id = read_u64_le(bundle, off)?;
    off += 8;
    let contract: [u8; 20] = bundle.get(off..off + 20)?.try_into().ok()?;
    off += 20;
    let vk_slice = bundle.get(off..off + VK_BLOB_LEN)?;
    let vk: &[u8; VK_BLOB_LEN] = vk_slice.try_into().ok()?;
    off += VK_BLOB_LEN;

    let leaf_index = read_u32_le(bundle, off)? as usize;
    off += 4;
    let proof_depth = read_u32_le(bundle, off)? as usize;
    off += 4;
    if proof_depth > 32 {
        return None;
    }
    let proof_size = proof_depth * 32;
    if bundle.len() != off + proof_size {
        return None;
    }
    let proof = bundle.get(off..off + proof_size)?;

    // Re-derive the canonical leaf bytes from the supplied fields.
    // MUST match dbgen::vks::canonical_vk_leaf byte-for-byte.
    let mut canonical = [0u8; 8 + 20 + VK_BLOB_LEN];
    canonical[0..8].copy_from_slice(&chain_id.to_le_bytes());
    canonical[8..28].copy_from_slice(&contract);
    canonical[28..28 + VK_BLOB_LEN].copy_from_slice(vk);

    if !verify_proof(&canonical, leaf_index, proof, proof_depth, &VK_DB_ROOT) {
        return None;
    }

    Some(VerifiedVk {
        chain_id,
        contract,
        vk,
    })
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}
