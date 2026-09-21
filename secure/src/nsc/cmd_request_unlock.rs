//! `CMD_REQUEST_UNLOCK` — secure UI prompts for the PIN, the PIN
//! never touches NS RAM, and on success the unwrapped master secret
//! is stamped into the shared `SecureState`.

use sphincs_tz_shared::NscStatus;
use zeroize::Zeroize;

use super::state;
use crate::secure_element::UnlockError;
use crate::timeout;
use crate::ui;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. The body drives
/// the trusted-UI PIN dialog and the SE pair; no NS pointer derefs.
/// `static mut SE` access is serialised by the non-reentrant
/// dispatcher.
pub(super) unsafe fn run() -> u32 {
    use crate::ui::pin_entry::{enter_pin, PinEntryResult};

    // Finding F3 — REQUEST_UNLOCK must be idempotent: when the device
    // is already unlocked the requested end state already holds, so
    // respond `Ok` WITHOUT re-popping the trusted-UI PIN dialog.
    // Otherwise a hostile companion can spam INS_V2_UNLOCK to keep
    // unsolicited PIN prompts on the display (prompt-fatigue), where
    // each wrong entry burns one of the lockout attempts. Reads
    // `pin_verified` through the same FI-hardened accessor
    // `cmd_is_unlocked` uses.
    if state::peek_state(|s| s.pin_verified.is_true_fi()) {
        return NscStatus::Ok as u32;
    }

    // HIGH-7 fix: prevent SysTick idle-wipe from racing us while the
    // user is typing the PIN or while we are deriving master_secret.
    let _busy = super::HandlerGuard::enter();

    // Arm a fresh input window before prompting (#713). `enter_pin` samples
    // `timeout::is_idle()` BEFORE waiting and only calls `reset_activity()`
    // after a button event, so entering it with an already-expired deadline —
    // exactly the state after a lock or an idle timeout — makes it return
    // `IdleWipe` instantly, with the PIN screen flashing up and vanishing. The
    // device then could not be unlocked over USB at all; only a power cycle
    // recovered it.
    //
    // This does not weaken "NS does not control the inactivity timer": that
    // invariant exists so NS cannot keep an UNLOCKED session alive by pinging.
    // Here the device is LOCKED with no secret loaded, and the window being
    // armed is for a human to type on the trusted UI. The PendSV re-unlock
    // loop already does exactly this on every pass (`main.rs`, immediately
    // before its own `enter_pin()` call).
    #[cfg(feature = "stm32u585")]
    crate::timeout::reset_activity();

    let mut pin = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        PinEntryResult::Cancelled | PinEntryResult::Mismatch => {
            // Mismatch is unreachable here (only enter_pin_with_confirm
            // can return it), but the match must be exhaustive.
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        PinEntryResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return NscStatus::IdleWipe as u32;
        }
    };

    ui::show_status("Verifying...", "");

    let result = verify_pin_with_chip(&pin);

    // X17-TUI2 / UI9: zeroize the ORIGINAL binding. Zeroizing a
    // duplicate of the array left the live `[u8; 8]` PIN on the stack.
    pin.zeroize();

    result
}

/// # Safety
/// Called only from `run` above; relies on the dispatcher's single-
/// threaded invariant to access `static mut crate::SE`.
unsafe fn verify_pin_with_chip(pin: &[u8; 8]) -> u32 {
    use sphincs_tz_shared::MAX_ATTEMPTS;

    // §18 P1 — entry jitter at the USB-triggered PIN-verify path. This
    // is the closest point to the external trigger (the NS-world
    // `CMD_REQUEST_UNLOCK` veneer call), so jittering here desyncs the
    // whole gate from USB arrival. Layers with the second
    // `wait_random()` at `gated_unlock`'s entry below. See that
    // function's comment for the threat-model bound (~0..19 µs;
    // uncalibrated-single-fault only).
    crate::fi::wait_random();

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);

    // `super::gated_unlock` handles the MCU-side counter (page 124):
    // pre-commit bump before SE verify, reset on success, refuse
    // on flash fault. See its docstring for the full Trezor-style
    // gating rationale.
    match super::gated_unlock(se, pin) {
        Ok(master) => {
            let unlocked = super::unlock_after_verified_pin(master);
            // Permission-bearing success is the explicit exact-sentinel arm;
            // a failed forced-attempt arm already zeroized the session.
            if unlocked == crate::fi::OK_SENTINEL {
                state::with_state(|s| s.remaining_attempts = MAX_ATTEMPTS);
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                return NscStatus::Ok as u32;
            }
            NscStatus::InternalError as u32
        }
        Err(UnlockError::PinIncorrect) => {
            // F-15 hardening: double-read the post-bump counter to
            // defend a value-fault on the load register; halt-to-wipe
            // (fail-closed) on mismatch.
            #[cfg(feature = "stm32u585")]
            let count = {
                let a = crate::hw::flash::pin_attempts_read();
                crate::fi::wait_random();
                let b = crate::hw::flash::pin_attempts_read();
                if a != b {
                    return trigger_lockout_wipe();
                }
                a
            };
            #[cfg(not(feature = "stm32u585"))]
            let count: u8 = 0; // QEMU: no counter, UI-only display

            let remaining_after = MAX_ATTEMPTS.saturating_sub(count);
            state::with_state(|s| s.remaining_attempts = remaining_after);

            // FAIL-IN pattern (F-15): the *secure default* (trigger
            // wipe) is the fall-through. The *attacker-bypass-target*
            // (continue without wiping) is the explicit conditional.
            // A single-fault that skips the conditional triggers wipe
            // instead of bypassing it — exactly opposite to the
            // previous FAIL-OUT shape `if remaining_after == 0 { wipe }`
            // where skipping the `cbz` falls through to "Wrong PIN"
            // and the attacker keeps brute-forcing past the cap.
            //
            // The Hamming-distant sentinel (`check_true_into_sentinel`)
            // additionally defends a value-fault on the comparison
            // register: a glitched return value is overwhelmingly
            // unlikely to coincide with OK_SENTINEL.
            let safe_to_continue = crate::fi::check_true_into_sentinel(
                || remaining_after != 0,
            );
            if safe_to_continue != crate::fi::OK_SENTINEL {
                return trigger_lockout_wipe();
            }
            if remaining_after == 1 {
                ui::show_status("LAST ATTEMPT", "wallet wipes on fail");
            } else {
                ui::show_status("Wrong PIN", "");
            }
            NscStatus::PinIncorrect as u32
        }
        Err(UnlockError::PinLocked) => {
            // Either the MCU counter hit MAX inside gated_unlock, or
            // one of the SEs surfaced its own lockout. Either way, wipe.
            state::with_state(|s| s.remaining_attempts = 0);
            trigger_lockout_wipe()
        }
        Err(UnlockError::InternalError) => {
            // Covers the "flash bump failed" fault-injection refusal
            // from gated_unlock (MCU counter not bumped, SE never
            // called) and the F17/SCAFI-5 "post-success reset failed"
            // refusal (SE verify succeeded but page 124 stayed
            // charged — fail-closed, user retries). Attack surface
            // bounded.
            NscStatus::InternalError as u32
        }
    }
}

/// Handle PIN lockout: factory-reset both SEs, zeroize SRAM state, then
/// return `PinLocked` so the NS side reboots into the first-boot wizard.
///
/// Runs unconditionally — SE050 silicon has already locked the UserID,
/// so further PIN attempts would be pointless. The wipe flag is armed
/// inside `factory_reset_admin` before any destructive work, so a power
/// loss mid-wipe is recoverable on the next boot.
///
/// # Safety
/// Called only from `verify_pin_with_chip` above; accesses
/// `static mut crate::SE` under the single-threaded dispatcher
/// invariant, then mutates secure-flash (page 124) via the `flash`
/// driver and zeroizes the in-RAM secrets.
unsafe fn trigger_lockout_wipe() -> u32 {
    use crate::secure_element::WalletStore;

    ui::show_status("WIPING", "do not power off");

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let _ = se.factory_reset_admin();

    // Reset the MCU-side attempt counter now that both SEs have been
    // wiped. Otherwise the next boot would read a full counter + an
    // unprovisioned chip, trigger the boot-time lockout check, and
    // loop. Erasing here makes the device ready for a fresh first-
    // boot wizard.
    #[cfg(feature = "stm32u585")]
    let _ = crate::hw::flash::pin_attempts_reset();

    // Zeroize every TrustZone-side secret.
    super::zeroize_sensitive_state();

    ui::show_status("WALLET WIPED", "restore from seed");
    NscStatus::PinLocked as u32
}
