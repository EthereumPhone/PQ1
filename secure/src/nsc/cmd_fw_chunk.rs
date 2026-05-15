//! CMD_FW_CHUNK — stream one image chunk into the inactive slot.
//!
//! Payload layout (see `sphincs_tz_shared::FW_CHUNK_HEADER_LEN`):
//!
//! ```text
//! offset  size  field
//!    0     4   chunk_offset  u32 BE
//!    4     1   image_kind    0 = secure, 1 = NS
//!    5     1   reserved
//!    6     2   chunk_len     u16 BE, 1..=FW_MAX_CHUNK
//!    8     N   chunk data
//! ```
//!
//! Bounds checks happen in `fw_update::check_chunk`; writes happen in
//! `fw_update::staging::write_chunk`. CHUNK does NOT reset the idle
//! timer — BEGIN already did, and COMMIT will again. If the companion
//! stalls mid-transfer for > 120 s the session expires and the
//! inactive slot stays in an "erased, partially written" state.

use sphincs_tz_shared::{NscStatus, FW_CHUNK_HEADER_LEN, FW_MAX_CHUNK};

use super::ptr_validate::validate_ns_read_ptr;
use super::state::{peek_state, FW_UPDATE};
use super::GatewayArgs;
use crate::fw_update::{self, ChunkError};

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Validates the
/// NS payload pointer before any deref; the static-mut `FW_UPDATE`
/// access is guarded by `HandlerGuard` (no SysTick wipe under us).
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // Critical: hold the busy guard so SysTick's idle-wipe cannot drop
    // FW_UPDATE while we hold a mutable reference into it via
    // `.as_mut().unwrap()` below. Without this, an idle-wipe between the
    // borrow and the chunk write is a use-after-drop on `FwUpdateCtx`.
    let _busy = super::HandlerGuard::enter();

    if !peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    // Validate the NS payload.
    let payload_ptr = args.arg0;
    let total_len = args.arg2 as usize;
    if total_len < FW_CHUNK_HEADER_LEN || total_len > FW_CHUNK_HEADER_LEN + FW_MAX_CHUNK {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(payload_ptr, total_len) {
        return NscStatus::InvalidPointer as u32;
    }

    // Snapshot header + data into secure-stack buffers.
    let mut header = [0u8; FW_CHUNK_HEADER_LEN];
    let mut data = [0u8; FW_MAX_CHUNK];
    let data_len = total_len - FW_CHUNK_HEADER_LEN;
    // SAFETY: category 2 — NS pointer deref after `validate_ns_read_ptr`
    // proved `[payload_ptr, payload_ptr + total_len)` is fully NS
    // (constant-window + per-block ARMv8-M `tt`). Volatile byte-by-byte
    // reads materialise the TOCTOU snapshot into secure-stack `header`
    // / `data`; the NS bytes are never re-read after this point.
    unsafe {
        let src = payload_ptr as *const u8;
        for i in 0..FW_CHUNK_HEADER_LEN {
            header[i] = core::ptr::read_volatile(src.add(i));
        }
        for i in 0..data_len {
            data[i] = core::ptr::read_volatile(src.add(FW_CHUNK_HEADER_LEN + i));
        }
    }

    let chunk_offset = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let image_kind = header[4];
    let chunk_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if chunk_len != data_len {
        return NscStatus::FwUpdateBadChunk as u32;
    }

    // Must have an active session.
    // SAFETY: category 5 — `FW_UPDATE: static mut Option<FwUpdateCtx>`
    // is single-threaded driver state. Non-reentrant dispatcher +
    // `HandlerGuard` block any concurrent mutation; this is a read-
    // only borrow to discriminate `None`/`Some` before we take a
    // mutable reference below.
    let ctx_present = unsafe { (*core::ptr::addr_of!(FW_UPDATE)).is_some() };
    if !ctx_present {
        return NscStatus::FwUpdateBadState as u32;
    }

    // Borrow the context mutably to do the bounds check + write. We
    // go through the raw static-mut address because `with_state`
    // only scopes SecureState, not FW_UPDATE.
    // SAFETY: category 5 — exclusive mutable borrow of the `FW_UPDATE`
    // static mut. The non-reentrant dispatcher guarantees no other
    // handler is active; `_busy = HandlerGuard::enter()` above
    // prevents SysTick's idle-wipe from dropping the `Option` while
    // we hold `ctx`. `unwrap()` is sound: we just observed
    // `ctx_present == true`, and nothing on the path between
    // `ctx_present` and this line mutates `FW_UPDATE`.
    let ctx = unsafe { (*core::ptr::addr_of_mut!(FW_UPDATE)).as_mut().unwrap() };

    match fw_update::check_chunk(ctx, image_kind, chunk_offset, chunk_len as u16) {
        Ok(_) => {}
        Err(ChunkError::TooLarge) | Err(ChunkError::BadKind)
        | Err(ChunkError::NonMonotonic) | Err(ChunkError::OverflowsImage) => {
            return NscStatus::FwUpdateBadChunk as u32;
        }
        Err(ChunkError::FlashError) => return NscStatus::FwUpdateFlashError as u32,
    }

    // SAFETY: `staging::write_chunk` is `unsafe fn` because it
    // programs bank-2 flash. Preconditions: bounds-checked
    // `(image_kind, chunk_offset, chunk_len)` against `ctx` by the
    // `check_chunk` call above, and the destination addresses live in
    // the inactive slot established by BEGIN (the currently-running
    // image is therefore untouched).
    unsafe {
        match fw_update::staging::write_chunk(ctx, image_kind, chunk_offset, &data[..data_len]) {
            Ok(()) => NscStatus::Ok as u32,
            Err(ChunkError::FlashError) => NscStatus::FwUpdateFlashError as u32,
            Err(_) => NscStatus::FwUpdateBadChunk as u32,
        }
    }
}
