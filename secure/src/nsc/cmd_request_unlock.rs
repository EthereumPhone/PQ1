//! `CMD_REQUEST_UNLOCK` — secure UI prompts for the PIN, the PIN
//! never touches NS RAM, and on success the unwrapped master secret
//! is stamped into the shared `SecureState`.

use sphincs_tz_shared::NscStatus;
use zeroize::Zeroize;

use super::state;
use crate::secure_element::UnlockError;
use crate::timeout;
use crate::ui;

pub(super) unsafe fn run() -> u32 {
    use crate::ui::pin_entry::{enter_pin, PinEntryResult};

    // HIGH-7 fix: prevent SysTick idle-wipe from racing us while the
    // user is typing the PIN or while we are deriving master_secret.
    let _busy = super::HandlerGuard::enter();

    let pin = match enter_pin() {
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

    let mut pin_copy = pin;
    pin_copy.zeroize();

    result
}

unsafe fn verify_pin_with_chip(pin: &[u8; 8]) -> u32 {
    use sphincs_tz_shared::MAX_ATTEMPTS;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);

    // `super::gated_unlock` handles the MCU-side counter (page 126):
    // pre-commit bump before SE verify, reset on success, refuse
    // on flash fault. See its docstring for the full Trezor-style
    // gating rationale.
    match super::gated_unlock(se, pin) {
        Ok(master) => {
            state::with_state(|s| {
                s.mark_unlocked(master);
                s.remaining_attempts = MAX_ATTEMPTS;
            });
            timeout::reset_activity();
            ui::show_status("Unlocked", "");
            NscStatus::Ok as u32
        }
        Err(UnlockError::PinIncorrect) => {
            // MCU counter advanced inside gated_unlock. Read the fresh
            // count to compute remaining — authoritative regardless of
            // what the SE-side counters report.
            #[cfg(feature = "stm32u585")]
            let count = crate::hw::flash::pin_attempts_read();
            #[cfg(not(feature = "stm32u585"))]
            let count: u8 = 0; // QEMU: no counter, UI-only display

            let remaining_after = MAX_ATTEMPTS.saturating_sub(count);
            state::with_state(|s| s.remaining_attempts = remaining_after);

            if remaining_after == 0 {
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
            // Includes the "flash bump failed" fault-injection refusal
            // from gated_unlock. MCU counter is not bumped in that
            // case — neither is SE counter, because we never called
            // the chip. Attack surface bounded.
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
