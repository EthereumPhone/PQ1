//! `CMD_GET_MAIN_PUBKEY` — derive and return the 32-byte main signer's
//! verifying key for a specific chain and key epoch.
//!
//! The main signer VK is NOT stored on the SE — it is derived on-the-fly
//! from the BIP-39 entropy using the per-chain derivation path. This means
//! the device must be unlocked (PIN verified) to derive the key.
//!
//! Payload at arg0:
//!   [0..8)   chain_id   (u64 BE)
//!   [8..12)  key_index  (u32 BE)

use sphincs_tz_shared::{NscStatus, MAIN_PUBKEY_PAYLOAD_LEN, VERIFYING_KEY_LEN};
use zeroize::Zeroize;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state;
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2;

    // Validate output buffer
    if out_len < VERIFYING_KEY_LEN as u32 {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, VERIFYING_KEY_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // Validate input payload
    if !validate_ns_read_ptr(args.arg0, MAIN_PUBKEY_PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // Must be unlocked to derive keys
    let is_unlocked = state::peek_state(|s| s.pin_verified);
    if !is_unlocked {
        return NscStatus::NotInitialized as u32;
    }

    // Read the payload into a secure-side buffer
    let mut payload = [0u8; MAIN_PUBKEY_PAYLOAD_LEN];
    for i in 0..MAIN_PUBKEY_PAYLOAD_LEN {
        payload[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    let mut chain_id_be = [0u8; 8];
    chain_id_be.copy_from_slice(&payload[0..8]);
    let chain_id = u64::from_be_bytes(chain_id_be);

    let mut key_index_be = [0u8; 4];
    key_index_be.copy_from_slice(&payload[8..12]);
    let key_index = u32::from_be_bytes(key_index_be);

    // Decrypt the entropy and derive the per-chain main VK
    let master_secret = state::peek_state(|s| s.master_secret);

    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        #[cfg(feature = "se050")]
        {
            match crate::crypto::se050_read_cached_entropy_blob(&mut entropy_blob) {
                Ok(len) => len,
                Err(_) => return NscStatus::InternalError as u32,
            }
        }
        #[cfg(not(feature = "se050"))]
        {
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            use crate::secure_element::SecureElement;
            match se.r_mem_read(crate::crypto::RMEM_ENCRYPTED_ENTROPY, &mut entropy_blob) {
                Ok(len) => len,
                Err(_) => return NscStatus::InternalError as u32,
            }
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

    let vk = crate::crypto::derive_main_vk_from_entropy(&entropy, chain_id, key_index);
    entropy.zeroize();

    // Write VK to NS buffer
    for i in 0..VERIFYING_KEY_LEN {
        core::ptr::write_volatile(out_ptr.add(i), vk[i]);
    }

    NscStatus::Ok as u32
}
