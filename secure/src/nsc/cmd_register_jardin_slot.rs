//! CMD_REGISTER_JARDIN_SLOT — generate JARDIN slot registration parameters.
//!
//! Simplified V1: the firmware derives the slot, computes the public
//! parameters, and returns them to the NS world.  The companion app
//! then builds the `registerJardinSlot(slotKey, subVkHash)` UserOp
//! and submits it via CMD_SIGN_USEROP or CMD_SIGN_MESSAGE.
//!
//! Triggers keygen (~3-4 s on Cortex-M33) if the slot is not already
//! active for this (chain_id, slot_index).
//!
//! Payload wire format (12 bytes):
//!   [0..8)   chain_id     u64 BE
//!   [8..12)  slot_index   u32 BE
//!
//! Response wire format (128 bytes):
//!   [0..32)    slot_key       H(r) — keccak256 of the raw randomizer
//!   [32..64)   sub_vk_hash    keccak256(subPkSeed[..16] || subPkRoot[..16])
//!   [64..80)   sub_pk_seed    16 bytes (raw N, not zero-padded)
//!   [80..96)   sub_pk_root    16 bytes (raw N, not zero-padded)
//!   [96..128)  r              32 bytes (raw randomizer, for companion verification)

use sphincs_tz_shared::NscStatus;

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 8 + 4; // chain_id + slot_index = 12
const RESPONSE_LEN: usize = 32 + 32 + 16 + 16 + 32; // 128

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    crate::ui::show_status("Register slot", "validating...");

    // 1. Check unlock
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // 2. Parse args
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    // 3. Length + pointer validation
    if total_len < PAYLOAD_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, PAYLOAD_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, RESPONSE_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 4. TOCTOU snapshot
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 5. Parse fields
    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let slot_index = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    // 6. Ensure master entropy derived + slot initialized (may trigger keygen)
    let init_status = super::state::with_state(|s| {
        // SAFETY: single-threaded dispatcher invariant
        unsafe { super::sign_and_emit::ensure_jardin_ready(s, chain_id, slot_index) }
    });
    if init_status != NscStatus::Ok as u32 {
        return init_status;
    }

    // 7. Read slot parameters
    //    SAFETY: ensure_jardin_ready guarantees JARDIN_SLOT is Some
    let slot = unsafe {
        match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
            Some(s) => s,
            None => return NscStatus::InternalError as u32,
        }
    };

    // 8. Compute slot key H(r) and raw randomizer r
    let master_entropy = super::state::peek_state(|s| s.jardin_master_entropy);
    let r = jardin_fosc::hash::jardin_slot_r(&master_entropy, slot_index);
    let slot_key = jardin_fosc::hash::keccak256(&r);

    // 9. Compute sub_vk_hash
    let sub_vk_hash = slot.sub_vk_hash();

    // 10. Write 128-byte response via volatile writes
    let mut pos: usize = 0;

    // slot_key (32 bytes)
    for i in 0..32 {
        core::ptr::write_volatile(out_ptr.add(pos + i), slot_key[i]);
    }
    pos += 32;

    // sub_vk_hash (32 bytes)
    for i in 0..32 {
        core::ptr::write_volatile(out_ptr.add(pos + i), sub_vk_hash[i]);
    }
    pos += 32;

    // sub_pk_seed (16 bytes, raw N)
    for i in 0..16 {
        core::ptr::write_volatile(out_ptr.add(pos + i), slot.pk_seed[i]);
    }
    pos += 16;

    // sub_pk_root (16 bytes, raw N)
    for i in 0..16 {
        core::ptr::write_volatile(out_ptr.add(pos + i), slot.pk_root[i]);
    }
    pos += 16;

    // r (32 bytes, raw randomizer)
    for i in 0..32 {
        core::ptr::write_volatile(out_ptr.add(pos + i), r[i]);
    }

    crate::timeout::reset_activity();
    crate::ui::show_status("Slot registered", "");

    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}
