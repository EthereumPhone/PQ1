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
use super::state::{peek_state, FW_UPDATE};
use super::GatewayArgs;
use crate::fw_update::{
    self, FwUpdateCtx, IncrementalSha256, SlotTag,
};
use crate::hw::{flash, otp};
use crate::timeout;

/// Verify-failure counter for the glitch-resistance defense (finding B
/// in `docs/usb-fw-update-hardening.md` — modelled on Trezor's repeated-
/// FW-failure → wipe pattern). Incremented on every BEGIN whose manifest
/// is rejected (bad sig / bad version / bad length / etc.); reset to
/// zero on every BEGIN that passes the full verify chain.
///
/// **Layered defense (in-RAM + flash):**
///   * In-RAM `FW_VERIFY_FAIL_COUNT_RAM` (threshold `..._RAM`) catches a
///     high-rate attack within a single power-cycle (a glitch rig that
///     can iterate dozens of times per second).
///   * Flash-backed tally on page 126 (threshold `..._FLASH`) catches a
///     slow-burn attack across many power-cycles (an attacker who
///     power-cycles between attempts to dodge an in-RAM counter).
///
/// On reaching EITHER threshold, we arm the standard admin-wipe flag
/// and `sys_reset` — the boot-time wipe-resume path in `main.rs:1334`
/// completes the SE/storage wipe, matching the response to a 10-wrong-
/// PIN lockout or a TZIC violation. The PIN-verified gate on BEGIN
/// means only an unlocked user session can hit the threshold — a
/// casual buggy host can't trip it without the user's PIN.
static mut FW_VERIFY_FAIL_COUNT_RAM: u32 = 0;

/// In-RAM threshold: bounds the *burst* attack rate within one power
/// cycle. Resets at every reboot.
const FW_VERIFY_FAIL_THRESHOLD_RAM: u32 = 5;

/// Flash threshold: bounds the *lifetime* attack budget across power
/// cycles. Higher than the RAM threshold because legit dev/testing
/// retries accumulate over time, but well below the 512-QW page
/// capacity so a glitch attacker can't fill the page faster than the
/// wipe trigger fires.
const FW_VERIFY_FAIL_THRESHOLD_FLASH: u32 = 20;

/// Trigger the admin wipe + reset. Doesn't return.
#[inline(never)]
fn arm_wipe_and_reset() -> ! {
    // SAFETY: dedicated single-QW idempotent flash write to the
    // wipe-flag slot on page 125. Established pattern (also called
    // from TZIC violation, OPTIGA tamper, SE050 errors).
    #[cfg(feature = "stm32u585")]
    let _ = unsafe { flash::arm_wipe_flag() };
    cortex_m::peripheral::SCB::sys_reset();
}

/// Record a manifest-verify failure. Bumps both the in-RAM and the
/// flash-backed counters; if either hits its threshold, arms the wipe
/// flag and resets — does not return.
#[inline(never)]
fn record_verify_failure_and_maybe_wipe() {
    // ---- In-RAM counter ----
    // SAFETY: single-threaded, non-reentrant gateway path; this is the
    // only writer of `FW_VERIFY_FAIL_COUNT_RAM`. `addr_of_mut!` is used
    // (rather than `&mut`) to side-step the `static_mut_refs` lint.
    let ram_count = unsafe {
        let p = core::ptr::addr_of_mut!(FW_VERIFY_FAIL_COUNT_RAM);
        let cur = core::ptr::read_volatile(p);
        let n = cur.saturating_add(1);
        core::ptr::write_volatile(p, n);
        n
    };

    // ---- Flash-backed counter ----
    // SAFETY: single-QW program on a dedicated page. Stays cheap even
    // on the failure path (~ms; the verify chain itself was already
    // ~1s of SPHINCS+C10 work).
    #[cfg(feature = "stm32u585")]
    let _ = unsafe { flash::fw_fail_bump() };
    #[cfg(feature = "stm32u585")]
    let flash_count = flash::fw_fail_count();
    #[cfg(not(feature = "stm32u585"))]
    let flash_count: u32 = 0;

    secure_log!(
        "[S][fwup] verify failure: ram {}/{} flash {}/{}",
        ram_count,
        FW_VERIFY_FAIL_THRESHOLD_RAM,
        flash_count,
        FW_VERIFY_FAIL_THRESHOLD_FLASH
    );

    if ram_count >= FW_VERIFY_FAIL_THRESHOLD_RAM
        || flash_count >= FW_VERIFY_FAIL_THRESHOLD_FLASH
    {
        secure_log!(
            "[S][fwup] verify-failure threshold reached (ram>={} OR flash>={}) — arming wipe + reset",
            FW_VERIFY_FAIL_THRESHOLD_RAM,
            FW_VERIFY_FAIL_THRESHOLD_FLASH
        );
        arm_wipe_and_reset();
    }
}

/// Reset both the in-RAM and the flash-backed failure tallies after a
/// manifest passes the full verify chain + length bounds. Successful
/// updates don't accumulate failures over a device's lifetime.
#[inline(never)]
fn record_verify_success() {
    // SAFETY: single-threaded, non-reentrant gateway path; sole writer.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(FW_VERIFY_FAIL_COUNT_RAM),
            0,
        );
    }
    // SAFETY: page-erase of the dedicated FW-fail counter page. No
    // other state lives on this page (work-todo #24 freed it from the
    // OPTIGA PBS seal). Failure to erase here is non-fatal — the worst
    // case is one extra latent failure carrying over to the next
    // update attempt, which is still bounded by the threshold.
    #[cfg(feature = "stm32u585")]
    let _ = unsafe { flash::fw_fail_reset() };
}

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
            // Glitch-resistance: count consecutive verify failures so an
            // attacker can't iterate freely on signature/version glitches.
            // See `docs/usb-fw-update-hardening.md` finding B.
            record_verify_failure_and_maybe_wipe();
            return NscStatus::FwUpdateBadVersion as u32;
        }
        Err(_) => {
            record_verify_failure_and_maybe_wipe();
            return NscStatus::FwUpdateBadManifest as u32;
        }
    }

    // Defense-in-depth: the manifest's declared image lengths are signed-
    // over (so a network attacker can't change them), but the verify chain
    // doesn't itself bound them against the actual A/B slot capacity.
    // Without this check, a vendor-signed manifest declaring
    // `secure_len = u32::MAX` would let later CHUNKs walk past the slot
    // until `check_chunk`'s per-chunk `checked_add` on
    // `base_addr + chunk_offset` finally tripped — overwriting the other
    // slot / FSBL pages / etc. in the meantime. (Trezor enforces the
    // analogous bound against `FIRMWARE_MAXSIZE`.) See
    // `docs/usb-fw-update-hardening.md` finding #1.
    if m.secure_len() > flash::SLOT_SECURE_CAPACITY
        || m.nonsecure_len() > flash::SLOT_NS_CAPACITY
    {
        // Treat as a verify failure — a manifest with absurd lengths is
        // a glitch / forgery candidate just like a bad signature.
        record_verify_failure_and_maybe_wipe();
        return NscStatus::FwUpdateBadManifest as u32;
    }

    // Manifest passes the full verify chain (signature, rollback, vendor,
    // structural, length bound) — reset the glitch-defense counter so
    // legit updates don't accumulate failures over the device's lifetime.
    record_verify_success();

    // Trusted-display install confirm BEFORE any destructive flash op
    // (Trezor pattern, finding A in docs/usb-fw-update-hardening.md). A
    // user-cancel here costs zero flash work and leaves the inactive
    // slot untouched. The fingerprint shown is the SIGNED
    // `manifest.secure_hash()`; COMMIT's `verify_images` re-hashes the
    // actually-streamed bytes against the same field and auto-aborts on
    // mismatch (no further user prompt — they've already given consent).
    if !fw_update::confirm_install(&m) {
        return NscStatus::UserRejected as u32;
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
