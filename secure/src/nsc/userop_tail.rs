//! Shared UserOp signing tail used by [`super::cmd_sign_userop`] and
//! [`super::cmd_clear_sign`].
//!
//! After the caller has validated the inner transaction and obtained
//! user confirmation via the trusted UI, the remaining steps are
//! identical for every UserOp signing path:
//!
//!   1. Reconstruct `execute(target, value, data)` callData from the
//!      user-confirmed inner EIP-1559 envelope.
//!   2. Hash the callData with keccak256.
//!   3. Compute the EntryPoint v0.6 `userOpHash` from the AA wrapper
//!      parameters plus the callData hash.
//!   4. Hand the 32-byte `userOpHash` to [`super::sign_and_emit::decrypt_and_sign`].
//!
//! Hoisting this into a single helper means adding a new UserOp-based
//! signing flavour (e.g. a future ZK clear-sign for a new protocol)
//! is a one-line call at the end of the new `cmd_*.rs`.

use crate::aa::userop::{compute_user_op_hash, reconstruct_execute_calldata, AaUserOpParams};
use crate::tx::eip1559::Eip1559Tx;
use crate::tx::hash::keccak256;
use crate::ui;
use sphincs_tz_shared::NscStatus;

use super::sign_and_emit::decrypt_and_sign;
use super::state;

/// Reconstruct callData, compute `userOpHash`, and sign it.
///
/// The caller must have:
///   * verified that the device is unlocked;
///   * validated `sig_ptr` via `validate_ns_write_ptr`;
///   * gotten through trusted-UI confirmation.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `SIGNATURE_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn sign_userop_hash(
    aa: &AaUserOpParams,
    parsed_tx: &Eip1559Tx,
    inner_data: &[u8],
    sig_ptr: *mut u8,
    success_banner: &str,
) -> u32 {
    let exec_call = match reconstruct_execute_calldata(parsed_tx, inner_data) {
        Ok(c) => c,
        Err(_) => {
            ui::show_status("UserOp", "encode fail");
            return NscStatus::CryptoError as u32;
        }
    };
    let call_data_hash = keccak256(exec_call.as_slice());

    let user_op_hash = compute_user_op_hash(aa, &call_data_hash);

    #[cfg(feature = "e2e-test")]
    cortex_m_semihosting::hprintln!(
        "[S][e2e] userop_tail userOpHash[..4] = {:02x}{:02x}{:02x}{:02x}",
        user_op_hash[0],
        user_op_hash[1],
        user_op_hash[2],
        user_op_hash[3]
    );

    ui::show_status("Signing UserOp", "");

    state::peek_state(|s| decrypt_and_sign(s, &user_op_hash, sig_ptr, success_banner))
}
