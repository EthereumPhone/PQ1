//! Wire format and verifier for the ERC-7730 descriptor bundle that
//! the non-secure world attaches to a sign request when it has found a
//! matching descriptor for the `(chain_id, contract)` pair (or
//! `(domain_separator, primary_type_hash)` pair for EIP-712).
//!
//! Same trust model as the existing trust DBs: the non-secure world
//! holds the catalogue, sends one specific entry + a Merkle proof, and
//! the secure world re-derives the leaf and walks the proof up to the
//! firmware-pinned `ERC7730_DESCRIPTORS_ROOT`.
//!
//! ## Wire layout
//!
//! ```text
//!   ir_len        u16 BE                  (2 B)
//!   ir            [u8; ir_len]            (≤ MAX_IR_LEN, parsed by `ir::Erc7730Ir::parse`)
//!   leaf_index    u32 BE                  (4 B)
//!   proof_depth   u32 BE                  (4 B)
//!   proof         [u8; proof_depth * 32]
//! ```
//!
//! The leaf hash is `sha256(0x00 || ir_bytes)` — same domain-separation
//! prefix as every other trust DB. The internal-node hash is
//! `sha256(0x01 || left || right)`. The proof walks bit-by-bit through
//! `leaf_index`. See `pqsigner-tx::erc20::merkle::verify_proof` — this
//! crate calls that primitive directly to keep the two DB schemes
//! byte-for-byte locked.
//!
//! ## Caps
//!
//! - `MAX_IR_LEN = 4096` — bounds the on-device walker memory
//! - `MAX_PROOF_DEPTH = 32` — same as every other bundle; 4 G entries
//!   of headroom and bounds the verifier hash chain
//! - `MAX_ERC7730_BUNDLE_LEN = 2 + 4096 + 4 + 4 + 32*32 = 5130` — caller
//!   uses this to size the stack buffer
//!
//! ## Cross-checks the caller MUST run
//!
//! Even after Merkle verification succeeds, the caller MUST cross-check
//! the IR's binding context against the actual sign request:
//!
//! * Contract context: `ir.chain_id == tx.chain_id && ir.contract == tx.to`
//! * EIP-712 context:  `ir.chain_id == domain.chainId
//!                      && ir.contract == domain.verifyingContract
//!                      && ir.domain_separator == computed_domain_sep`
//!
//! Those checks live in `binding.rs` so the bundle stays a pure
//! verifier.

use pqsigner_tx::erc20::merkle::verify_proof;
use sha2::{Digest, Sha256};

use crate::ir::{Erc7730Ir, IrError, MAX_IR_LEN};

/// 2 (ir_len) + IR + 4 (leaf_index) + 4 (proof_depth) + 32 * 32 (proof).
pub const MAX_ERC7730_BUNDLE_LEN: usize = 2 + MAX_IR_LEN + 4 + 4 + 32 * 32;

/// Cap on Merkle depth — same as every other trust-DB bundle.
pub const MAX_PROOF_DEPTH: usize = 32;

/// Errors specific to bundle parsing. IR-internal errors propagate via
/// `BundleError::Ir(IrError)` so the caller can pick a single
/// `ui::show_status` line without branching on the inner cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// Bundle truncated before the declared end.
    Truncated,
    /// Trailing bytes after the declared end.
    TrailingBytes,
    /// IR-internal error.
    Ir(IrError),
    /// Merkle proof failed verification against the pinned root.
    Merkle,
    /// `proof_depth` exceeds `MAX_PROOF_DEPTH`.
    DepthCap,
    /// `ir_len` exceeds `MAX_IR_LEN`.
    IrLenCap,
}

impl From<IrError> for BundleError {
    fn from(e: IrError) -> Self {
        BundleError::Ir(e)
    }
}

/// Verified descriptor handle returned to the caller. Borrows from the
/// bundle's backing buffer; the lifetime is tied to that buffer's
/// stack frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedDescriptor<'a> {
    pub ir: Erc7730Ir<'a>,
}

/// Verify a bundle against the firmware-pinned `root`. On success,
/// returns a parsed + Merkle-bound IR view. On failure, returns a
/// specific error suitable for an on-device status line.
pub fn verify_erc7730_bundle<'a>(
    bundle: &'a [u8],
    root: &[u8; 32],
) -> Result<VerifiedDescriptor<'a>, BundleError> {
    if bundle.len() < 2 {
        return Err(BundleError::Truncated);
    }
    let ir_len = u16::from_be_bytes([bundle[0], bundle[1]]) as usize;
    if ir_len > MAX_IR_LEN {
        return Err(BundleError::IrLenCap);
    }
    if bundle.len() < 2 + ir_len + 4 + 4 {
        return Err(BundleError::Truncated);
    }

    let ir_bytes = &bundle[2..2 + ir_len];
    let ir = Erc7730Ir::parse(ir_bytes)?;

    let mut off = 2 + ir_len;
    let leaf_index = u32::from_be_bytes(
        bundle[off..off + 4]
            .try_into()
            .map_err(|_| BundleError::Truncated)?,
    ) as usize;
    off += 4;

    let proof_depth = u32::from_be_bytes(
        bundle[off..off + 4]
            .try_into()
            .map_err(|_| BundleError::Truncated)?,
    ) as usize;
    off += 4;

    if proof_depth > MAX_PROOF_DEPTH {
        return Err(BundleError::DepthCap);
    }
    let proof_size = proof_depth * 32;

    if off + proof_size > bundle.len() {
        return Err(BundleError::Truncated);
    }
    if off + proof_size != bundle.len() {
        // Reject any trailing bytes — we want exactly the bundle.
        return Err(BundleError::TrailingBytes);
    }
    let proof = &bundle[off..off + proof_size];

    if !verify_proof(ir_bytes, leaf_index, proof, proof_depth, root) {
        return Err(BundleError::Merkle);
    }

    Ok(VerifiedDescriptor { ir })
}

/// Reproduce the leaf hash that the host pipeline computes when
/// building the Merkle tree. Public for the round-trip tests in
/// `dbgen` and any host-side reference verifier.
pub fn leaf_hash(ir_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(ir_bytes);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{CTX_CONTRACT, HEADER_LEN, SCHEMA_VER};

    /// Synthesize the smallest valid IR blob: minimal header + empty
    /// pool + 1-byte formats section (count = 0).
    fn minimal_ir(chain_id: u64, contract: [u8; 20]) -> std::vec::Vec<u8> {
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
        buf[10..30].copy_from_slice(&contract);
        let pool_off = HEADER_LEN as u16;
        buf[126..128].copy_from_slice(&pool_off.to_be_bytes());
        buf[128..130].copy_from_slice(&pool_off.to_be_bytes());
        // pool_len = 0; formats_len = 1.
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.push(0u8); // format count = 0
        buf
    }

    /// Build a bundle for an IR that is the single leaf of a 0-depth
    /// tree (root == leaf_hash(ir)). leaf_index = 0, proof_depth = 0.
    fn bundle_single_leaf(ir: &[u8]) -> (std::vec::Vec<u8>, [u8; 32]) {
        let root = leaf_hash(ir);
        let mut buf = std::vec::Vec::new();
        buf.extend_from_slice(&(ir.len() as u16).to_be_bytes());
        buf.extend_from_slice(ir);
        buf.extend_from_slice(&0u32.to_be_bytes()); // leaf_index
        buf.extend_from_slice(&0u32.to_be_bytes()); // proof_depth
        (buf, root)
    }

    #[test]
    fn happy_path_single_leaf() {
        let ir = minimal_ir(1, [0x11; 20]);
        let (bundle, root) = bundle_single_leaf(&ir);
        let v = verify_erc7730_bundle(&bundle, &root).unwrap();
        assert_eq!(v.ir.chain_id, 1);
        assert_eq!(v.ir.contract, [0x11; 20]);
    }

    #[test]
    fn wrong_root_rejected() {
        let ir = minimal_ir(1, [0x11; 20]);
        let (bundle, _root) = bundle_single_leaf(&ir);
        let bad_root = [0xFFu8; 32];
        assert_eq!(
            verify_erc7730_bundle(&bundle, &bad_root),
            Err(BundleError::Merkle)
        );
    }

    #[test]
    fn truncated_header_rejected() {
        let bundle = std::vec![0u8; 1];
        assert!(matches!(
            verify_erc7730_bundle(&bundle, &[0u8; 32]),
            Err(BundleError::Truncated)
        ));
    }

    #[test]
    fn over_ir_len_cap_rejected() {
        let mut bundle = std::vec::Vec::new();
        bundle.extend_from_slice(&((MAX_IR_LEN + 1) as u16).to_be_bytes());
        assert_eq!(
            verify_erc7730_bundle(&bundle, &[0u8; 32]),
            Err(BundleError::IrLenCap)
        );
    }

    #[test]
    fn over_proof_depth_cap_rejected() {
        let ir = minimal_ir(1, [0x11; 20]);
        let mut bundle = std::vec::Vec::new();
        bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
        bundle.extend_from_slice(&ir);
        bundle.extend_from_slice(&0u32.to_be_bytes()); // leaf_index
        bundle.extend_from_slice(&((MAX_PROOF_DEPTH as u32) + 1).to_be_bytes());
        // No proof bytes — the depth-cap check happens before the
        // length check, which is the right ordering: we don't want to
        // be coerced into reading 4 GiB of "proof" before refusing.
        assert_eq!(
            verify_erc7730_bundle(&bundle, &[0u8; 32]),
            Err(BundleError::DepthCap)
        );
    }

    #[test]
    fn trailing_bytes_rejected() {
        let ir = minimal_ir(1, [0x11; 20]);
        let (mut bundle, root) = bundle_single_leaf(&ir);
        bundle.push(0u8);
        assert_eq!(
            verify_erc7730_bundle(&bundle, &root),
            Err(BundleError::TrailingBytes)
        );
    }

    #[test]
    fn two_leaf_tree_path_walks() {
        // Tree with two leaves L0, L1. Root = node_hash(L0, L1).
        let ir0 = minimal_ir(1, [0x10; 20]);
        let ir1 = minimal_ir(1, [0x20; 20]);
        let l0 = leaf_hash(&ir0);
        let l1 = leaf_hash(&ir1);

        let mut hasher = Sha256::new();
        hasher.update([0x01u8]);
        hasher.update(l0);
        hasher.update(l1);
        let out = hasher.finalize();
        let mut root = [0u8; 32];
        root.copy_from_slice(&out);

        // Build a bundle for leaf 0 with proof = [l1].
        let mut bundle = std::vec::Vec::new();
        bundle.extend_from_slice(&(ir0.len() as u16).to_be_bytes());
        bundle.extend_from_slice(&ir0);
        bundle.extend_from_slice(&0u32.to_be_bytes()); // leaf_index 0
        bundle.extend_from_slice(&1u32.to_be_bytes()); // proof_depth 1
        bundle.extend_from_slice(&l1);

        let v = verify_erc7730_bundle(&bundle, &root).unwrap();
        assert_eq!(v.ir.contract, [0x10; 20]);

        // Build a bundle for leaf 1 with proof = [l0].
        let mut bundle1 = std::vec::Vec::new();
        bundle1.extend_from_slice(&(ir1.len() as u16).to_be_bytes());
        bundle1.extend_from_slice(&ir1);
        bundle1.extend_from_slice(&1u32.to_be_bytes()); // leaf_index 1
        bundle1.extend_from_slice(&1u32.to_be_bytes());
        bundle1.extend_from_slice(&l0);

        let v1 = verify_erc7730_bundle(&bundle1, &root).unwrap();
        assert_eq!(v1.ir.contract, [0x20; 20]);
    }
}
