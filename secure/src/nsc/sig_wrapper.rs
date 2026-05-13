//! Encode a `SignatureWrapper(uint256 ownerIndex, bytes innerSig)` —
//! the ABI struct `PQSmartWallet.validateUserOp` /
//! `isValidSignature` decode every signature into.
//!
//! Used by both `cmd_sign_userop` (Type 1 / Type 2 frames in the
//! UserOp bundle) and `cmd_sign_offchain` (the inner sig of an
//! ERC-6492 wrap and, in the non-deployed path, the bare-mode output's
//! companion-side wrap analogue).
//!
//! Layout — Solidity ABI for `(uint256, bytes)`:
//!
//! ```text
//!   [0..32)      ownerIndex (uint256 BE)
//!   [32..64)     offset to bytes = 0x40  (uint256 BE)
//!   [64..96)     length = C10_SIG_LEN    (uint256 BE)
//!   [96..4128)   inner C10 sig, zero-padded up to the next 32-byte boundary
//! ```

use sphincs_tz_shared::{C10_SIG_LEN, SIG_WRAPPER_LEN};

/// Encode a SignatureWrapper into a fresh `out`. The caller must
/// supply `out` zero-initialised (e.g. via `Zeroizing`) — the trailing
/// padding past the sig data is assumed to already be zero.
pub(super) fn encode_signature_wrapper(
    out: &mut [u8; SIG_WRAPPER_LEN],
    owner_index: u64,
    inner_sig: &[u8],
) {
    debug_assert_eq!(inner_sig.len(), C10_SIG_LEN);
    // ownerIndex left-padded to 32 bytes
    out[24..32].copy_from_slice(&owner_index.to_be_bytes());
    // offset = 0x40
    out[32 + 31] = 0x40;
    // length = 4008 = 0x0fa8
    out[64 + 24..64 + 32].copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
    // inner sig
    out[96..96 + C10_SIG_LEN].copy_from_slice(inner_sig);
    // trailing padding already zero.
}
