//! CMD_GET_JARDIN_SLOT_INFO — query the persisted JARDIN slot state.
//!
//! Reads the latest `SlotState` from secure flash and reports it back
//! to the non-secure world. Pure query: no SE access, no crypto.
//!
//! Payload wire format (8 bytes):
//!   [0..8)   chain_id     u64 BE
//!
//! Response wire format (41 bytes):
//!   [0..4)    slot_index   u32 BE
//!   [4..8)    next_q       u32 BE
//!   [8..12)   flags        u32 BE (bit 0 = slot_registered)
//!   [12..13)  active       u8  (1 if a record exists for this chain, else 0)
//!   [13..45)  h_r          32 bytes (all-zero when no record)
//!
//! Total = 4 + 4 + 4 + 1 + 32 = 45.

use sphincs_tz_shared::NscStatus;

use super::jardin_flash;
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 8;
const RESPONSE_LEN: usize = 4 + 4 + 4 + 1 + 32;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2 as usize;

    if out_len < RESPONSE_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, RESPONSE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }
    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);

    let (slot_index, next_q, flags, active, h_r): (u32, u32, u32, u8, [u8; 32]) =
        match jardin_flash::read_latest() {
            Some(s) if s.chain_id == chain_id => {
                (s.slot_index, s.next_q, s.flags, 1u8, s.h_r)
            }
            _ => (0u32, 0u32, 0u32, 0u8, [0u8; 32]),
        };

    let si = slot_index.to_be_bytes();
    let nq = next_q.to_be_bytes();
    let fl = flags.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(i), si[i]);
        core::ptr::write_volatile(out_ptr.add(4 + i), nq[i]);
        core::ptr::write_volatile(out_ptr.add(8 + i), fl[i]);
    }
    core::ptr::write_volatile(out_ptr.add(12), active);
    for i in 0..32 {
        core::ptr::write_volatile(out_ptr.add(13 + i), h_r[i]);
    }

    NscStatus::Ok as u32
}
