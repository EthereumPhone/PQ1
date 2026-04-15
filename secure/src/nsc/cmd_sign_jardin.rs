//! CMD_SIGN_JARDIN — JARDIN FORS+C compact signing.
//!
//! Signs a 32-byte message hash using the JARDIN compact signature
//! scheme.  The slot is identified by (chain_id, slot_index); if the
//! slot has not been initialised this session, firmware runs keygen
//! (~3-4 s on Cortex-M33).
//!
//! No interactive confirmation — the companion has already confirmed
//! the transaction at the USB APDU layer.  The q counter advances
//! automatically inside the JARDIN slot; no OTS monotonicity check
//! is needed.
//!
//! Payload wire format (44 bytes):
//!   [0..8)   chain_id     u64 BE
//!   [8..12)  slot_index   u32 BE
//!   [12..44) msg_hash     32 bytes
//!
//! Response wire format (variable, max 4073 bytes):
//!   [0..4)   response_len   u32 BE (total bytes including this field)
//!   [4..101) JARDIN wrapper header (97 bytes)
//!   [101..)  raw FORS+C signature (2452 + q*16 bytes)

use sphincs_tz_shared::{
    NscStatus, JARDIN_ROTATION_FLAG, JARDIN_ROTATION_THRESHOLD, JARDIN_WRAPPER_MAX_LEN,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;

const PAYLOAD_LEN: usize = 8 + 4 + 32; // chain_id + slot_index + msg_hash = 44

/// Maximum output buffer: 4-byte length prefix + JARDIN wrapper (header + max sig).
const OUTPUT_MAX_LEN: usize = 4 + JARDIN_WRAPPER_MAX_LEN; // 4073

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    crate::ui::show_status("JARDIN sign", "validating...");

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
    if !validate_ns_write_ptr(args.arg1, OUTPUT_MAX_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // 4. TOCTOU snapshot (volatile read NS → secure stack)
    let mut buf = [0u8; PAYLOAD_LEN];
    for i in 0..PAYLOAD_LEN {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // 5. Parse fields
    let chain_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    let slot_index = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let mut msg_hash = [0u8; 32];
    msg_hash.copy_from_slice(&buf[12..44]);

    // 6. Delegate to the JARDIN signing tail.
    //    sig_ptr is out_ptr + 4 to leave room for the BE length prefix.
    let (status, wrapper_len) = super::state::with_state(|s| {
        // SAFETY: out_ptr validated for OUTPUT_MAX_LEN bytes,
        // out_ptr.add(4) is JARDIN_WRAPPER_MAX_LEN bytes.
        unsafe {
            super::sign_and_emit::decrypt_and_sign_jardin(
                s,
                &msg_hash,
                out_ptr.add(4),
                chain_id,
                slot_index,
                "Signed",
            )
        }
    });

    // 7. On success, write 4-byte BE length prefix.
    //    The prefix value is the total response including the prefix itself.
    //    Bit 31 is set when the slot has fewer than JARDIN_ROTATION_THRESHOLD
    //    signatures remaining, signalling the companion to proactively
    //    register the next slot.  Same bit-31 convention as sign_userop's
    //    OTS trailer flag.
    if status == NscStatus::Ok as u32 {
        let mut response_len = (4 + wrapper_len) as u32;

        // Check remaining signatures on the active slot
        let remaining = unsafe {
            match &*core::ptr::addr_of!(super::state::JARDIN_SLOT) {
                Some(s) => s.remaining(),
                None => 0,
            }
        };
        if remaining < JARDIN_ROTATION_THRESHOLD {
            response_len |= JARDIN_ROTATION_FLAG;
        }

        let len_be = response_len.to_be_bytes();
        for i in 0..4 {
            core::ptr::write_volatile(out_ptr.add(i), len_be[i]);
        }
    }

    status
}
