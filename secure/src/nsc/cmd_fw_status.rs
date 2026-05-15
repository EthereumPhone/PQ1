//! CMD_FW_STATUS — report update-session progress.
//!
//! Writes `FW_STATUS_RESPONSE_LEN` bytes to the NS output buffer:
//! `[state:u8 | recv_s:u32 BE | recv_ns:u32 BE | slot:u8]`.

use sphincs_tz_shared::{
    NscStatus, FW_STATE_IDLE, FW_STATE_RECEIVING, FW_STATE_STAGED, FW_STATUS_RESPONSE_LEN,
    FW_STATUS_RECV_NS_OFFSET, FW_STATUS_RECV_S_OFFSET, FW_STATUS_SLOT_OFFSET,
    FW_STATUS_STATE_OFFSET,
};

use super::ptr_validate::validate_ns_write_ptr;
use super::state::FW_UPDATE;
use super::GatewayArgs;

/// # Safety
/// CMSE non-secure-entry handler. The body validates the NS output
/// pointer before deref and reads the `static mut FW_UPDATE` snapshot
/// under the single-threaded dispatcher invariant.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let out_ptr = args.arg1;
    if !validate_ns_write_ptr(out_ptr, FW_STATUS_RESPONSE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let mut buf = [0u8; FW_STATUS_RESPONSE_LEN];
    // SAFETY: category 5 — read-only borrow of `static mut FW_UPDATE`.
    // The non-reentrant gateway dispatcher means no other handler is
    // concurrently mutating this slot.
    let ctx_ref = unsafe { (*core::ptr::addr_of!(FW_UPDATE)).as_ref() };
    let (state, recv_s, recv_ns, slot) = match ctx_ref {
        None => (FW_STATE_IDLE, 0, 0, 0),
        Some(ctx) => {
            let state = if ctx.received_secure == ctx.expected_secure_len
                && ctx.received_nonsecure == ctx.expected_nonsecure_len
            {
                FW_STATE_STAGED
            } else {
                FW_STATE_RECEIVING
            };
            (state, ctx.received_secure, ctx.received_nonsecure, ctx.inactive as u8)
        }
    };
    buf[FW_STATUS_STATE_OFFSET] = state;
    buf[FW_STATUS_RECV_S_OFFSET..FW_STATUS_RECV_S_OFFSET + 4]
        .copy_from_slice(&recv_s.to_be_bytes());
    buf[FW_STATUS_RECV_NS_OFFSET..FW_STATUS_RECV_NS_OFFSET + 4]
        .copy_from_slice(&recv_ns.to_be_bytes());
    buf[FW_STATUS_SLOT_OFFSET] = slot;

    // SAFETY: category 2 — NS pointer deref after `validate_ns_write_ptr`
    // proved `[out_ptr, out_ptr + FW_STATUS_RESPONSE_LEN)` is fully
    // NS-classified and not aliasing the shared mailbox. `write_volatile`
    // forces the compiler to emit one store per byte so the NS observer
    // cannot see a half-written response word.
    unsafe {
        let dst = out_ptr as *mut u8;
        for i in 0..FW_STATUS_RESPONSE_LEN {
            core::ptr::write_volatile(dst.add(i), buf[i]);
        }
    }
    NscStatus::Ok as u32
}
