//! CMD_FW_ABORT — discard a partial update.
//!
//! Drops the in-SRAM `FwUpdateCtx`. The inactive slot's erased +
//! partially-written pages stay in whatever state they're in —
//! harmless, because FSBL rejects a manifest-less slot as
//! `BadMagic` and falls back to the active slot. A subsequent
//! `CMD_FW_BEGIN` re-erases before re-seeding, so nothing leaks.

use sphincs_tz_shared::NscStatus;

use super::state::FW_UPDATE;

pub(super) unsafe fn run() -> u32 {
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }
    NscStatus::Ok as u32
}
