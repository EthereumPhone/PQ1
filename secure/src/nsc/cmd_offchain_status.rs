//! CMD_OFFCHAIN_STATUS — surface per-slot off-chain signing state to
//! the companion.
//!
//! Wire layout:
//!   * Input (13 bytes): account_index(1) || chain_id(8) || slot_index(4)
//!   * Output (24 bytes):
//!       [ 0.. 8) local_offchain_count (u64 BE)
//!       [ 8..16) last_userop_count    (u64 BE)
//!       [16..17) registered           (u8: 0 = no flash record, 1 = yes)
//!       [17..24) reserved             (zero-filled)
//!
//! The companion uses this for two things:
//!   1. UI hint: "X off-chain sigs available before forced UserOp"
//!      where X = `MAX_OFFCHAIN_GAP - (local - last_userop)`.
//!   2. Recovery probe: a `registered == 0` response after a
//!      seed-restore is the signal to nudge the user toward
//!      registering a fresh slot via CMD_SIGN_USEROP.

use sphincs_tz_shared::{
    NscStatus, MAX_ACCOUNT_INDEX, OFFCHAIN_STATUS_INPUT_LEN, OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF,
    OFFCHAIN_STATUS_OUTPUT_LEN, OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF,
    OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let _busy = super::HandlerGuard::enter();

    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    let in_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len != OFFCHAIN_STATUS_INPUT_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, OFFCHAIN_STATUS_INPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, OFFCHAIN_STATUS_OUTPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let mut buf = [0u8; OFFCHAIN_STATUS_INPUT_LEN];
    for i in 0..OFFCHAIN_STATUS_INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = buf[0] as u32;
    let chain_id = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let slot_index = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    let slot_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);
    let local = crate::offchain_state::offchain_count_read(&slot_key);
    let last_userop = crate::offchain_state::last_userop_count_read(&slot_key);
    let registered = crate::offchain_state::offchain_count_is_registered(&slot_key);

    // Zero-init the buffer first (covers reserved bytes).
    for i in 0..OFFCHAIN_STATUS_OUTPUT_LEN {
        core::ptr::write_volatile(out_ptr.add(i), 0u8);
    }

    let local_be = local.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(
            out_ptr.add(OFFCHAIN_STATUS_OUTPUT_LOCAL_OFF + i),
            local_be[i],
        );
    }
    let userop_be = last_userop.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(
            out_ptr.add(OFFCHAIN_STATUS_OUTPUT_LAST_USEROP_OFF + i),
            userop_be[i],
        );
    }
    core::ptr::write_volatile(
        out_ptr.add(OFFCHAIN_STATUS_OUTPUT_REGISTERED_OFF),
        if registered { 1u8 } else { 0u8 },
    );

    NscStatus::Ok as u32
}
