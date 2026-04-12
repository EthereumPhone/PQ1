//! `CMD_SIGN_BOOTSTRAP` — sign a 32-byte message hash with the bootstrap
//! signer.
//!
//! Used for:
//! - Factory deployment authorization (`keccak256("PQWALLET_INIT_V1" ‖ initialMainSigner)`)
//! - Emergency rotation authorization
//!
//! The bootstrap signer is stateless — no OTS tracking. The user must
//! confirm the operation on the trusted UI because bootstrap operations
//! are high-privilege (can rotate the main signer on any chain).
//!
//! Payload at arg0:
//!   [0..32)  message hash (bytes32 to sign)
//!
//! On success the 17,088-byte SLH-DSA signature is written to sig_ptr.

use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, TX_HASH_LEN};
use zeroize::Zeroize;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state;
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let sig_ptr = args.arg1 as *mut u8;
    let _total_len = args.arg2;

    // Validate pointers
    if !validate_ns_read_ptr(args.arg0, TX_HASH_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGNATURE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // Must be unlocked
    let is_unlocked = state::peek_state(|s| s.pin_verified);
    if !is_unlocked {
        return NscStatus::NotInitialized as u32;
    }

    // Read the message hash into secure memory
    let mut msg_hash = [0u8; 32];
    for i in 0..32 {
        msg_hash[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // Show confirmation on trusted UI — bootstrap operations are admin-level.
    // Build a single-page confirmation dialog.
    {
        use crate::ui::confirm::{confirm, ConfirmResult, Page};
        use crate::ui::DISPLAY_COLS;

        let mut page: Page = [[b' '; DISPLAY_COLS]; crate::ui::DISPLAY_ROWS];
        let line0 = b"Bootstrap sign   ";
        let line1 = b"ADMIN operation  ";
        let line2 = b"Confirm? >       ";
        for i in 0..core::cmp::min(line0.len(), DISPLAY_COLS) { page[0][i] = line0[i]; }
        for i in 0..core::cmp::min(line1.len(), DISPLAY_COLS) { page[1][i] = line1[i]; }
        for i in 0..core::cmp::min(line2.len(), DISPLAY_COLS) { page[2][i] = line2[i]; }

        match confirm(&[page]) {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                crate::ui::show_status("Locked", "(idle)");
                return NscStatus::IdleWipe as u32;
            }
        }
    }

    // Decrypt entropy and derive bootstrap signing key
    let master_secret = state::peek_state(|s| s.master_secret);

    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut entropy_blob) {
            Ok(len) => len,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };

    let mut entropy = match crate::crypto::decrypt_entropy_blob(
        &entropy_blob[..entropy_blob_len],
        &master_secret,
    ) {
        Ok(e) => e,
        Err(_) => {
            entropy_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    entropy_blob.zeroize();

    let signing_key = crate::crypto::derive_bootstrap_key_from_entropy(&entropy);
    entropy.zeroize();

    // Hedged sign with bootstrap key
    let mut rand_buf = [0u8; 16];
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"bootstrap-sign-rand");
        h.update(&master_secret);
        h.update(&msg_hash);
        let r = h.finalize();
        rand_buf.copy_from_slice(&r[..16]);
    }

    use slh_dsa::Sha2_128f;
    use slh_dsa::SigningKey as Sk;
    let sig = match <Sk<Sha2_128f>>::try_sign_with_context(
        &signing_key,
        &msg_hash,
        &[],
        Some(&rand_buf),
    ) {
        Ok(s) => s,
        Err(_) => {
            rand_buf.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };

    // Write signature to NS memory
    let sig_bytes = sig.to_bytes();
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig_bytes[i]);
    }

    rand_buf.zeroize();
    crate::timeout::reset_activity();
    crate::ui::show_status("Signed", "");
    NscStatus::Ok as u32
}
