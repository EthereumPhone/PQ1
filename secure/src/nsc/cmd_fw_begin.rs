//! CMD_FW_BEGIN — initiate a firmware-update streaming session.
//!
//! NS supplies the 8 KB manifest as the payload. We:
//!   1. Require PIN-verified.
//!   2. Validate the NS pointer, TOCTOU-snapshot the manifest.
//!   3. Run the full verify chain (structural, CRC, digest, vendor
//!      fpr match, rollback floor).
//!   4. Determine inactive slot.
//!   5. Erase inactive slot + target manifest page.
//!   6. Seed a fresh `FwUpdateCtx`, drop any stale one.
//!   7. Reset the idle activity timer (BEGIN counts as user consent).
//!
//! Runtime: dominated by the slot erase (~1 s for 58 + 64 pages on
//! STM32U585). Fine inside the unlock-session idle budget.

use fw_manifest::{ManifestRef, MANIFEST_SIZE};
use sphincs_tz_shared::NscStatus;

use super::ptr_validate::validate_ns_read_ptr;
use super::state::{peek_state, with_state, FW_UPDATE};
use super::GatewayArgs;
use crate::fw_update::{
    self, FwUpdateCtx, IncrementalSha256, SlotTag,
};
use crate::hw::{boot_state, flash, otp};
use crate::timeout;

/// # Safety
/// CMSE non-secure-entry handler — invoked by the gateway dispatcher
/// with NS-supplied `GatewayArgs`. The handler must validate every NS
/// pointer before deref; see the per-step SAFETY comments below.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // Gate: PIN must be verified — updates aren't available on a
    // locked device.
    if peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    // TOCTOU-safe snapshot of the manifest.
    let payload_ptr = args.arg0;
    let total_len = args.arg2 as usize;
    if total_len != MANIFEST_SIZE {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(payload_ptr, total_len) {
        return NscStatus::InvalidPointer as u32;
    }

    // Copy into a secure-stack buffer before parsing so NS can't
    // change the bytes between our verify and our flash-write.
    let mut snap = [0u8; MANIFEST_SIZE];
    // SAFETY: category 2 — NS pointer deref after validation.
    // `validate_ns_read_ptr(payload_ptr, MANIFEST_SIZE)` returned true
    // above, proving the entire `[payload_ptr, payload_ptr + MANIFEST_SIZE)`
    // range is fully NS-classified (constant-window check + ARMv8-M
    // `tt` per byte block). `read_volatile` byte-by-byte is required
    // so the compiler cannot elide or batch the reads — the TOCTOU
    // snapshot semantic depends on capturing the NS bytes once and
    // working from the secure-stack copy thereafter.
    unsafe {
        let src = payload_ptr as *const u8;
        for i in 0..MANIFEST_SIZE {
            snap[i] = core::ptr::read_volatile(src.add(i));
        }
    }

    // Run the verify chain. Rollback floor comes from OTP.
    let m = ManifestRef::new(&snap);
    let floor = otp::rollback_floor();
    match fw_update::verify_manifest(&m, floor) {
        Ok(()) => {}
        Err(fw_manifest::VerifyError::BelowRollback) => {
            return NscStatus::FwUpdateBadVersion as u32
        }
        Err(_) => return NscStatus::FwUpdateBadManifest as u32,
    }

    // Determine inactive slot (the one we're NOT currently running).
    let active = fw_update::read_active_slot();
    let inactive = match active {
        flash::Slot::A => flash::Slot::B,
        flash::Slot::B => flash::Slot::A,
    };

    // Note: the manifest's `slot` byte is *informational* in the
    // v0x02 format — the signed preimage covers only
    // (version, secure_hash, nonsecure_hash), so a single signed
    // release works for either A or B. The secure world picks the
    // inactive slot; the companion doesn't need separate bundles.
    let _ = m.slot();

    // Erase the inactive slot (both secure + NS halves + the target
    // manifest page). This is the only flash-destructive operation
    // in BEGIN; after it completes the device is in a "half written"
    // state that FSBL handles by seeing a blank manifest on the
    // target slot and falling back to the active one.
    // SAFETY: `flash::erase_slot` is `unsafe fn` because it mutates
    // bank-2 flash (irreversible per-page erase). Called only here in
    // the inactive-slot prepare step; we just established `inactive`
    // is the not-currently-running slot via `read_active_slot()` and
    // PIN-verified above, so erasing it cannot brick the live image.
    unsafe {
        if flash::erase_slot(inactive).is_err() {
            return NscStatus::FwUpdateFlashError as u32;
        }
    }

    // Seed a fresh streaming context. If one was already present
    // (earlier BEGIN without a COMMIT/ABORT), it drops here and
    // zeroises.
    let ctx = FwUpdateCtx {
        inactive: SlotTag::from(inactive),
        manifest_bytes: snap,
        received_secure: 0,
        received_nonsecure: 0,
        secure_hasher: IncrementalSha256::new(),
        nonsecure_hasher: IncrementalSha256::new(),
        expected_secure_len: m.secure_len(),
        expected_nonsecure_len: m.nonsecure_len(),
    };
    // SAFETY: category 5 — `FW_UPDATE` is a `static mut` holding the
    // streaming update context. Single-threaded, non-reentrant
    // dispatcher guarantees exclusive access; SysTick respects
    // `HandlerGuard` so no concurrent zeroize can race this write.
    // Any prior value drops here and its `Zeroize`/`ZeroizeOnDrop`
    // impls wipe the previous hashers + manifest copy.
    unsafe {
        *core::ptr::addr_of_mut!(FW_UPDATE) = Some(ctx);
    }

    // Reset the idle activity timer. BEGIN is a user-consented
    // action (the companion asked; the user will confirm on COMMIT),
    // so count it as activity so a slow USB transfer doesn't race
    // the 120 s timer.
    timeout::reset_activity();

    let _session = fw_update::bump_session();
    NscStatus::Ok as u32
}
