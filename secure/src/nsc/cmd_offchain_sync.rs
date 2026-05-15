//! CMD_OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
//! companion-supplied target. "Set if greater", idempotent.
//!
//! The repair path in `cmd_sign_userop::run` computes
//! `new_offchain_count = max(local_offchain, last_userop_snapshot)`
//! using firmware-flash state only. After a firmware reflash that
//! wipes the offchain-state flash region, both counters start at
//! zero — but the on-chain `offchainSigCount[ownerIndex]` may still
//! be non-zero (carried over from before the reflash). Without a way
//! to inform the firmware of the on-chain floor, the next userop emits
//! `newOffchainCount = 0` and reverts with
//! `OffchainSigCountNotMonotonic`.
//!
//! Wire layout:
//!   * Input (21 bytes):
//!       [ 0.. 1) account_index (u8)
//!       [ 1.. 9) chain_id      (u64 BE)
//!       [ 9..13) slot_index    (u32 BE)
//!       [13..21) target_count  (u64 BE)
//!   * Output: no body, SW only.
//!
//! Security note: the host is fully trusted to drive slot use already
//! (it picks `account_index` / `slot_index`, signs whatever payload it
//! likes, etc.). Letting it set a floor on `last_userop_count` is no
//! stronger a primitive than the existing slot-rotation flow and
//! cannot exfiltrate state. The on-chain combined-cap check
//! (`slotUses + offchainSigCount <= cap`) still enforces the per-slot
//! budget regardless of what the firmware emits.

use sphincs_tz_shared::{NscStatus, MAX_ACCOUNT_INDEX, OFFCHAIN_SYNC_INPUT_LEN};

use super::ptr_validate::validate_ns_read_ptr;
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let _busy = super::HandlerGuard::enter();

    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    let in_ptr = args.arg0 as *const u8;
    let total_len = args.arg2 as usize;

    if total_len != OFFCHAIN_SYNC_INPUT_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, OFFCHAIN_SYNC_INPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    let mut buf = [0u8; OFFCHAIN_SYNC_INPUT_LEN];
    for i in 0..OFFCHAIN_SYNC_INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = buf[0] as u32;
    let chain_id = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let slot_index = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    let target_count = u64::from_be_bytes([
        buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20],
    ]);
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    let slot_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // `last_userop_count_set` is tolerant of `target <= current` (no-op).
    // The repair branch in `cmd_sign_userop::run` will pick up the new
    // floor via `last_userop_count_read` → `max(local, last_userop)`,
    // and `offchain_count_promote_to` will bump `local_offchain` in turn
    // so subsequent off-chain signs see a consistent base.
    if crate::offchain_state::last_userop_count_set(&slot_key, target_count).is_err() {
        return NscStatus::InternalError as u32;
    }

    NscStatus::Ok as u32
}
