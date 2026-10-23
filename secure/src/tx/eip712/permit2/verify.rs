//! Verifier for an off-chain Permit2 permit (`SIGN_OFFCHAIN` kind 6).
//!
//! Decodes the packed permit (framing + policy refusals in
//! `pqsigner_tx::permit2::decode_core`), recomputes its digest from pinned
//! constants and decodes each token's metadata on-device: a token whose
//! ERC-20 bundle is missing, fails Merkle verification against
//! `ERC20_DB_ROOT`, or describes another `(contract, chain)` is shown by
//! address with its raw amount — degraded, never refused (the digest binds
//! the token address either way). Same leg decoder as the CoW route.

use pqsigner_tx::permit2::{decode_core, Permit2Core};
use sphincs_tz_shared::{PERMIT2_CORE_MAX_LEN, PERMIT2_MAX_TOKENS};

use crate::tx::eip712::cowswap::verify::decode_leg;
use crate::tx::eip712::cowswap::CowLeg;

/// A permit that passed decode and digest recomputation. Owned, so the
/// snapshot buffer can be dropped before rendering.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedPermit2 {
    /// The packed permit exactly as signed-over (first `packed_len` bytes).
    pub packed: [u8; PERMIT2_CORE_MAX_LEN],
    pub packed_len: usize,
    pub core: Permit2Core,
    /// Per-token metadata; only the first `core.count` are meaningful.
    pub legs: [CowLeg; PERMIT2_MAX_TOKENS],
}

impl VerifiedPermit2 {
    /// The packed bytes.
    pub fn packed(&self) -> &[u8] {
        &self.packed[..self.packed_len]
    }
}

/// Verify an off-chain Permit2 permit and return it with the digest the
/// device recomputed. `Err` carries the trusted-display status line.
pub fn verify_offchain_permit2(
    packed: &[u8],
    erc20: &[&[u8]; PERMIT2_MAX_TOKENS],
    chain_id: u64,
) -> Result<(VerifiedPermit2, [u8; 32]), &'static str> {
    if packed.len() > PERMIT2_CORE_MAX_LEN {
        return Err("permit2 length");
    }
    let core = decode_core(packed).map_err(|e| e.as_str())?;
    let digest = super::compute_digest(&core, chain_id).map_err(|_| "permit2 chain")?;
    let mut legs = [CowLeg::AddrHex; PERMIT2_MAX_TOKENS];
    for (i, e) in core.live().iter().enumerate() {
        legs[i] = decode_leg(Some(erc20[i]).filter(|b| !b.is_empty()), &e.token, core.chain_id);
    }
    let mut buf = [0u8; PERMIT2_CORE_MAX_LEN];
    buf[..packed.len()].copy_from_slice(packed);
    Ok((
        VerifiedPermit2 {
            packed: buf,
            packed_len: packed.len(),
            core,
            legs,
        },
        digest,
    ))
}
