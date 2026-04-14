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
            ui::show_status("Locked", "(idle wipe)");
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
    use crate::secure_element::WalletStore;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    match se.unlock(pin) {
        Ok(master) => {
            state::with_state(|s| s.mark_unlocked(master));
            timeout::reset_activity();
            ui::show_status("Unlocked", "");
            NscStatus::Ok as u32
        }
        Err(UnlockError::PinIncorrect) => {
            let new_remaining = state::with_state(|s| {
                if s.remaining_attempts > 0 {
                    s.remaining_attempts -= 1;
                }
                s.remaining_attempts
            });
            if new_remaining == 0 {
                // Last attempt just failed — the SE has blocked itself.
                // Fall through to the lockout handler below.
                return trigger_lockout_wipe();
            }
            if new_remaining == 1 {
                ui::show_status("LAST ATTEMPT", "wallet wipes on fail");
            } else {
                ui::show_status("Wrong PIN", "");
            }
            NscStatus::PinIncorrect as u32
        }
        Err(UnlockError::PinLocked) => {
            state::with_state(|s| s.remaining_attempts = 0);
            trigger_lockout_wipe()
        }
        Err(UnlockError::InternalError) => {
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

    // Zeroize every TrustZone-side secret.
    super::zeroize_sensitive_state();

    ui::show_status("WALLET WIPED", "restore from seed");
    NscStatus::PinLocked as u32
}
