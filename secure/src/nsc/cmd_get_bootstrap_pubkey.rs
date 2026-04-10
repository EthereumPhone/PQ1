//! `CMD_GET_BOOTSTRAP_PUBKEY` — copy the 32-byte bootstrap signer's
//! verifying key from the secure element out to a pre-validated NS buffer.
//! No unlock is required to read the public key.
//!
//! The bootstrap VK is stored at RMEM_BOOTSTRAP_VK during provisioning.

use sphincs_tz_shared::{NscStatus, VERIFYING_KEY_LEN};

use super::ptr_validate::validate_ns_write_ptr;
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2;

    if out_len < VERIFYING_KEY_LEN as u32 {
        return NscStatus::InvalidPointer as u32;
    }

    if !validate_ns_write_ptr(args.arg1, VERIFYING_KEY_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let mut vk_buf = [0u8; 64];
    let read_result = {
        #[cfg(feature = "se050")]
        {
            // Bootstrap VK is cached after unlock on the SE050 path.
            // For now, re-derive from the cached entropy blob.
            let master_secret = super::state::peek_state(|s| s.master_secret);
            let mut blob = [0u8; 64];
            match crate::crypto::se050_read_cached_entropy_blob(&mut blob) {
                Ok(len) => {
                    match crate::crypto::decrypt_entropy_blob(&blob[..len], &master_secret) {
                        Ok(entropy) => {
                            let bvk = crate::crypto::derive_bootstrap_vk_from_entropy(&entropy);
                            vk_buf[..32].copy_from_slice(&bvk);
                            Ok(32)
                        }
                        Err(_) => Err(crate::secure_element::SeError::InternalError),
                    }
                }
                Err(_) => Err(crate::secure_element::SeError::InternalError),
            }
        }
        #[cfg(not(feature = "se050"))]
        {
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            use crate::secure_element::SecureElement;
            se.r_mem_read(crate::crypto::RMEM_BOOTSTRAP_VK, &mut vk_buf)
        }
    };

    match read_result {
        Ok(vk_len) => {
            let copy_len = core::cmp::min(vk_len, VERIFYING_KEY_LEN);
            for i in 0..copy_len {
                core::ptr::write_volatile(out_ptr.add(i), vk_buf[i]);
            }
            NscStatus::Ok as u32
        }
        Err(_) => NscStatus::NotInitialized as u32,
    }
}
