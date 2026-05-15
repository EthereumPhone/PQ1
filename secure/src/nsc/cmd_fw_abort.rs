//! CMD_FW_ABORT — discard a partial update.
//!
//! Drops the in-SRAM `FwUpdateCtx`. The inactive slot's erased +
//! partially-written pages stay in whatever state they're in —
//! harmless, because FSBL rejects a manifest-less slot as
//! `BadMagic` and falls back to the active slot. A subsequent
//! `CMD_FW_BEGIN` re-erases before re-seeding, so nothing leaks.

use sphincs_tz_shared::NscStatus;

use super::state::FW_UPDATE;

/// # Safety
/// CMSE non-secure-entry handler — caller is the gateway dispatcher
/// (`nsc/mod.rs`) on either the QEMU mailbox path or the STM32U585
/// CMSE veneer. Dispatcher invariants apply: single-threaded,
/// non-reentrant, NS arguments have already been snapshotted.
pub(super) unsafe fn run() -> u32 {
    // SAFETY: `FW_UPDATE` is the secure-world `static mut` that holds
    // the in-flight firmware-update context (category 5: single-
    // threaded driver bookkeeping). Access is serialised by the non-
    // reentrant gateway — no other handler can be running concurrently
    // and SysTick's idle-wipe respects `HandlerGuard`. `addr_of_mut!`
    // is used (rather than `&mut`) to avoid materialising a reference
    // we don't need; the write replaces the slot wholesale.
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = None;
    }
    NscStatus::Ok as u32
}
