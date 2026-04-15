//! CMD_GET_JARDIN_SLOT_INFO — query the current JARDIN slot state.
//!
//! Returns the slot index, next q counter, remaining signatures, and
//! whether the queried (chain_id, slot_index) is currently active in
//! memory.  Pure query: no SE access, no crypto, no entropy derivation.
//!
//! Payload wire format (12 bytes):
//!   [0..8)   chain_id     u64 BE
//!   [8..12)  slot_index   u32 BE
//!
//! Response wire format (7 bytes):
//!   [0..4)   slot_index   u32 BE
//!   [4]      next_q       u8 (1-95, or 0 if not active)
//!   [5]      remaining    u8 (0-95)
//!   [6]      slot_active  u8 (1 if active for this chain+slot, 0 otherwise)

use sphincs_tz_shared::NscStatus;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 8 + 4; // chain_id + slot_index = 12
const RESPONSE_LEN: usize = 4 + 1 + 1 + 1; // slot_index + next_q + remaining + active = 7

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2 as usize;

    // 1. Pointer + length validation
    if out_len < RESPONSE_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, RESPONSE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 2. Check unlock
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // 3. TOCTOU snapshot
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 4. Parse fields
    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let slot_index = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    // 5. Read state
    let (next_q, remaining, active) = super::state::peek_state(|s| {
        if s.jardin_slot_active
            && s.jardin_chain_id == chain_id
            && s.jardin_slot_index == slot_index
        {
            // SAFETY: single-threaded access, state confirms slot is active
            let slot = unsafe { &*core::ptr::addr_of!(super::state::JARDIN_SLOT) };
            match slot {
                Some(ref js) => (js.next_q as u8, js.remaining(), 1u8),
                None => (0u8, 0u8, 0u8),
            }
        } else {
            (0u8, 0u8, 0u8) // not loaded for this chain+slot
        }
    });

    // 6. Write 7-byte response via volatile writes
    let si_bytes = slot_index.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(i), si_bytes[i]);
    }
    core::ptr::write_volatile(out_ptr.add(4), next_q);
    core::ptr::write_volatile(out_ptr.add(5), remaining);
    core::ptr::write_volatile(out_ptr.add(6), active);

    NscStatus::Ok as u32
}
