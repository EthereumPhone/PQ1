//! ZK clear signing verification module.
//!
//! Implements on-device Groth16 proof verification for the ZKlarity clear
//! signing circuit. The circuit proves that a human-readable string is a
//! faithful ABI interpretation of raw Aave v3 calldata.
//!
//! Architecture:
//!   1. Receive (calldata, readable_string, proof) from NS world
//!   2. Compute H_tx  = Poseidon(calldata)  — bind the transaction
//!   3. Compute H_str = Poseidon(readable)  — bind the display string
//!   4. Verify Groth16 proof against (H_tx, H_str) and embedded VK
//!   5. If valid: display readable_string on trusted UI

pub mod groth16;
pub mod poseidon;
/// Generated Poseidon round constants + MDS matrices (BLS12-381 Scalar field).
/// Emitted by `tools/export_poseidon_constants.js` and lives under `generated/`
/// so grep/readers can tell at a glance this is machine-written code.
#[path = "generated/poseidon_constants.rs"]
mod poseidon_constants;
#[cfg(feature = "debug-log")]
pub mod test_vectors;
pub mod vk_bundle;

pub use groth16::{Groth16Proof, VerificationKey, verify_clear_signing_proof};
// Deeper items (`poseidon::poseidon_bytes`, `vk_bundle::{verify_vk_bundle,
// VerifiedVk}`) are imported through their sub-path at the call site so
// the compiler can flag dead code — no flat re-exports.

/// Maximum calldata size (must match ZKlarity circuit MAX_CALLDATA = 164)
pub const MAX_CALLDATA: usize = 164;

/// Human-readable string length (must match ZKlarity circuit STRING_LEN = 64)
pub const STRING_LEN: usize = 64;

/// Groth16 proof size: π.A (96) + π.B (192) + π.C (96) = 384 bytes
pub const PROOF_LEN: usize = 384;

/// Unit-return error indicating the supplied ZK clear-sign bundle did
/// not verify (VK bundle failed Merkle check, Groth16 pairing rejected
/// the proof, or the proof bytes were structurally malformed).
#[derive(Debug, Clone, Copy)]
pub struct ClearSignError;

/// Metadata returned on a successful `verify_clear_sign_proof` — the
/// caller uses these fields to cross-check the proof against the
/// transaction it claims to describe (HIGH-5).
#[derive(Clone, Copy)]
pub struct VerifiedClearSign {
    pub chain_id: u64,
    pub contract: [u8; 20],
}

/// End-to-end verification of a ZK clear-sign bundle supplied as three
/// byte buffers: the 384-byte Groth16 proof, the 164-byte calldata, the
/// 64-byte readable string, and the variable-length VK bundle that
/// proves the verification key is Merkle-committed to the firmware-
/// embedded `VK_DB_ROOT`.
///
/// On success the proof was valid *and* returns the VK's claimed
/// `(chain_id, contract)` pair so the caller can confirm it matches
/// the tx being signed. Without that cross-check, a VK for protocol A
/// on chain A could validate a readable string for protocol B on
/// chain B.
pub fn verify_clear_sign_proof(
    proof_bytes: &[u8; PROOF_LEN],
    calldata: &[u8; MAX_CALLDATA],
    readable: &[u8; STRING_LEN],
    vk_bundle: &[u8],
) -> Result<VerifiedClearSign, ClearSignError> {
    let proof = Groth16Proof::from_bytes(proof_bytes).ok_or(ClearSignError)?;
    let verified_vk = vk_bundle::verify_vk_bundle(vk_bundle).ok_or(ClearSignError)?;
    let vk = VerificationKey::from_bytes(verified_vk.vk_as_2pub()).ok_or(ClearSignError)?;
    if !verify_clear_signing_proof(calldata, readable, &proof, &vk) {
        return Err(ClearSignError);
    }
    Ok(VerifiedClearSign {
        chain_id: verified_vk.chain_id,
        contract: verified_vk.contract,
    })
}

/// Render a trusted-UI confirmation screen for a ZK-verified clear-sign
/// tx. The 64-byte readable string is displayed across the first three
/// rows (12 visible cols × 4 = 48 chars + continuation), followed by a
/// chain / recipient / amount summary and the L/R confirm buttons.
#[cfg(not(test))]
pub fn render_clear_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    readable: &[u8; STRING_LEN],
) -> crate::tx::display::Pages {
    use crate::tx::display::Pages;
    use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

    let mut pages = Pages::empty_with_len(4);

    // Page 0: the ZK-attested readable string. Chunk 16 bytes per row
    // (our row is exactly DISPLAY_COLS) and drop trailing NULs.
    let trimmed_end = {
        let mut end = STRING_LEN;
        while end > 0 && readable[end - 1] == 0 {
            end -= 1;
        }
        end
    };
    let trimmed = &readable[..trimmed_end];
    // Row 0: "✓ Verified"-style header.
    {
        let row = pages.row_mut(0, 0);
        *row = [b' '; DISPLAY_COLS];
        let hdr = b"> Clear-signed";
        let n = core::cmp::min(hdr.len(), DISPLAY_COLS);
        row[..n].copy_from_slice(&hdr[..n]);
    }
    for row_idx in 1..DISPLAY_ROWS {
        let row = pages.row_mut(0, row_idx);
        *row = [b' '; DISPLAY_COLS];
        let start = (row_idx - 1) * DISPLAY_COLS;
        if start >= trimmed.len() {
            break;
        }
        let end = core::cmp::min(start + DISPLAY_COLS, trimmed.len());
        row[..end - start].copy_from_slice(&trimmed[start..end]);
    }

    // Page 1-3: chain / recipient / amount + confirm.
    // Delegate to the normal value-transfer renderer for those pages by
    // calling `render_pages` on the tx and copying the produced pages
    // 1..4 into our pages 1..4. (We already used page 0 for the readable.)
    let base = crate::tx::display::render_pages(tx);
    let base_slice = base.as_slice();
    let copy_count = core::cmp::min(base_slice.len(), 3);
    for i in 0..copy_count {
        let dst = pages.page_mut(1 + i);
        *dst = base_slice[i];
    }

    pages
}
