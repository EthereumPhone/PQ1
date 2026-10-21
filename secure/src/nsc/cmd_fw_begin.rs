//! CMD_FW_BEGIN — initiate a firmware-update streaming session.
//!
//! NS supplies the 8 KB manifest as the payload. We:
//!   1. Require PIN-verified.
//!   2. Validate the NS pointer, TOCTOU-snapshot the manifest.
//!   3. Require a one-shot trusted-UI authorization to invoke the
//!      manifest verifier.
//!   4. Run the full verify chain (structural, CRC, digest, vendor
//!      fpr match, rollback floor).
//!   5. Show the verified release details and require install consent.
//!   6. Determine and erase the inactive slot + target manifest page.
//!   7. Seed a fresh `FwUpdateCtx`, drop any stale one.
//!   8. Reset the idle activity timer (BEGIN counts as user consent).
//!
//! Runtime: dominated by the slot erase (~1 s for 58 + 64 pages on
//! STM32U585). Fine inside the unlock-session idle budget.

use fw_manifest::{ManifestRef, MANIFEST_SIZE};
use sphincs_tz_shared::NscStatus;

use super::ptr_validate::validate_ns_read_ptr;
use super::state::{peek_state, FW_UPDATE};
use super::GatewayArgs;
use crate::fw_update::{self, FwUpdateCtx, IncrementalSha256, SlotTag};
use crate::hw::flash;
use crate::timeout;

/// # Safety
/// CMSE non-secure-entry handler — invoked by the gateway dispatcher
/// with NS-supplied `GatewayArgs`. The handler must validate every NS
/// pointer before deref; see the per-step SAFETY comments below.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // Hold the busy guard for the whole handler. BEGIN's verify-chain
    // (~1-2 s SPHINCS+C10) + inactive-slot erase (~2 s) run with NS
    // blocked in the veneer, so without this guard `handler_is_busy()`
    // would read false for ~3 s — long enough that (a) the SysTick
    // idle-wipe could fire mid-BEGIN, and (b) the `iwdg` watchdog would
    // see no NS heartbeat + no busy handler and approach its stall
    // limit. Holding the guard marks BEGIN as live progress for both.
    let _busy = super::HandlerGuard::enter();

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
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS read
    // pointer (bare `if !validate` is single-fault FAIL-OUT → unvalidated
    // snapshot read of secure memory into the manifest buffer).
    let read_ptr_ok =
        crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(payload_ptr, total_len));
    if read_ptr_ok != crate::fi::OK_SENTINEL {
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

    // A manifest verification is an expensive, fault-injection-sensitive
    // security operation. Bind EACH invocation to a fresh physical action on
    // the trusted display before touching the attacker-controlled bytes with
    // the verifier. The prompt is deliberately static: no unverified host
    // field is rendered as if it were authenticated release metadata.
    //
    // This is the attempt boundary. Invalid transport input must never arm a
    // seed wipe, reset the device, write a persistent failure counter, or wear
    // flash. A retry requires another affirmative physical action.
    //
    // Dev units (`devunit-ab`, owner decision 2026-10-21) skip this ask: an
    // update there is ONE consent, after the verifier (`confirm_install`).
    // What that gives up: on an unlocked dev unit the host can run the
    // verifier without a button press, i.e. repeat it for a glitch rig.
    // Accepted for pre-production units; the production design keeps it.
    use crate::ui::confirm::ConfirmResult;
    #[cfg(not(feature = "devunit-ab"))]
    {
        let (verify_confirm, verify_confirm_sentinel) = fw_update::confirm_verify_request();
        match verify_confirm {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => return NscStatus::UserRejected as u32,
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        if verify_confirm_sentinel != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }

    // Jitter the entry into the verifier after consent. This is defense in
    // depth against a physical timing/glitch rig; the trusted-UI one-shot gate
    // above is the authorization boundary.
    crate::fi::wait_random();

    // Run the verify chain. Rollback floor comes from OTP (dev units: the
    // running release's version, see `fw_update::rollback_floor`).
    let m = ManifestRef::new(&snap);
    let floor = fw_update::rollback_floor();
    match fw_update::verify_manifest(&m, floor) {
        Ok(()) => {}
        Err(fw_manifest::VerifyError::BelowRollback) => {
            return NscStatus::FwUpdateBadVersion as u32;
        }
        Err(_) => {
            return NscStatus::FwUpdateBadManifest as u32;
        }
    }

    // The manifest's declared image lengths are NOT signed-over (the
    // signed preimage covers only `fw_version` and the two image hashes —
    // see `fw-manifest`), and the verify chain doesn't bound them against
    // the actual A/B slot capacity either — this check is the SOLE bound.
    // Without it, a network attacker flipping `secure_len` to `u32::MAX`
    // on an otherwise valid signed manifest would let later CHUNKs walk
    // past the slot until `check_chunk`'s per-chunk `checked_add` on
    // `base_addr + chunk_offset` finally tripped — overwriting the other
    // slot / FSBL pages / etc. in the meantime. (Trezor enforces the
    // analogous bound against `FIRMWARE_MAXSIZE`.) See
    // `docs/security/usb-fw-update-hardening.md` finding #1.
    if m.secure_len() > flash::SLOT_SECURE_CAPACITY || m.nonsecure_len() > flash::SLOT_NS_CAPACITY {
        return NscStatus::FwUpdateBadManifest as u32;
    }

    // Trusted-display install confirm BEFORE any destructive flash op
    // (Trezor pattern, finding A in docs/security/usb-fw-update-hardening.md). A
    // user-cancel here costs zero flash work and leaves the inactive
    // slot untouched. The fingerprint shown is the SIGNED
    // `manifest.secure_hash()`; COMMIT's `verify_images` re-hashes the
    // actually-streamed bytes against the same field and auto-aborts on
    // mismatch (no further user prompt — they've already given consent).
    let (install_confirm, install_confirm_sentinel) = fw_update::confirm_install(&m);
    match install_confirm {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => return NscStatus::UserRejected as u32,
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return NscStatus::IdleWipe as u32;
        }
    }
    if install_confirm_sentinel != crate::fi::OK_SENTINEL {
        super::zeroize_sensitive_state();
        return NscStatus::UserRejected as u32;
    }
    // Replace the confirm screen at once: the erase below and the ~30 s
    // stream that follows would otherwise leave the user looking at a
    // screen that no longer responds (CHUNK advances this one).
    crate::ui::show_progress("INSTALLING", 0);
    super::cmd_fw_chunk::LAST_PCT.store(0, core::sync::atomic::Ordering::Relaxed);

    // Determine the inactive slot (the one we're NOT currently running) from
    // the hardware VTOR, NOT the boot-state page. `read_active_slot()` trusts
    // boot_state, which can diverge from the actually-running slot after an
    // FSBL try-once revert (e.g. a same-version reinstall leaves both slots
    // valid and FSBL reverts to the loser while boot_state still names the
    // winner). In that diverged state, inverting the boot-state slot would
    // select the LIVE slot as the erase target and wipe the running secure
    // image. `running_slot()` reads the VTOR the FSBL set at hand-off, which
    // cannot diverge, so the inverted slot is always genuinely inactive.
    let running = fw_update::running_slot();
    let inactive = match running {
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
    // is the not-currently-running slot via `running_slot()` (the
    // FSBL-set VTOR, which cannot diverge from the live slot) and
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
