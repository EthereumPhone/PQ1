//! `CMD_GET_PUBKEY` — copy the 32-byte SLH-DSA verifying key from the
//! secure element out to a pre-validated NS buffer. No unlock is
//! required to read the public key.

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
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        se.read_vk(&mut vk_buf)
    };

    match read_result {
        Ok(vk_len) => {
            for i in 0..vk_len {
                core::ptr::write_volatile(out_ptr.add(i), vk_buf[i]);
            }
            NscStatus::Ok as u32
        }
        Err(_) => NscStatus::NotInitialized as u32,
    }
}
