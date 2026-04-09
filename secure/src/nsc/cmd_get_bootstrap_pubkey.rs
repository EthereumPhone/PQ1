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
    let se = &mut *core::ptr::addr_of_mut!(crate::SE);

    use crate::secure_element::SecureElement;
    let read_result = se.r_mem_read(crate::crypto::RMEM_BOOTSTRAP_VK, &mut vk_buf);

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
