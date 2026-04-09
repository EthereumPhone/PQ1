//! `CMD_REQUEST_UNLOCK` — secure UI prompts for the PIN, the PIN
//! never touches NS RAM, and on success the unwrapped master secret
//! is stamped into the shared `SecureState`.

use sphincs_tz_shared::{NscStatus, MAX_ATTEMPTS};
use zeroize::Zeroize;

use super::state;
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
    #[cfg(feature = "tropic01-se")]
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.batch_verify_pin(pin, MAX_ATTEMPTS) {
            Ok(master) => {
                state::with_state(|s| s.mark_unlocked(master));
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                NscStatus::Ok as u32
            }
            Err(crate::secure_element::SeError::SlotExpired) => {
                state::with_state(|s| s.remaining_attempts = 0);
                ui::show_status("PIN locked", "");
                NscStatus::PinLocked as u32
            }
            Err(crate::secure_element::SeError::InvalidParameter) => {
                state::with_state(|s| {
                    if s.remaining_attempts > 0 {
                        s.remaining_attempts -= 1;
                    }
                });
                ui::show_status("Wrong PIN", "");
                NscStatus::PinIncorrect as u32
            }
            Err(_) => NscStatus::InternalError as u32,
        }
    }
    #[cfg(not(feature = "tropic01-se"))]
    {
        let _ = MAX_ATTEMPTS;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match crate::pin::verify_pin(se, pin) {
            Ok(master) => {
                state::with_state(|s| s.mark_unlocked(master));
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                NscStatus::Ok as u32
            }
            Err(NscStatus::PinIncorrect) => {
                state::with_state(|s| {
                    if s.remaining_attempts > 0 {
                        s.remaining_attempts -= 1;
                    }
                });
                ui::show_status("Wrong PIN", "");
                NscStatus::PinIncorrect as u32
            }
            Err(NscStatus::PinLocked) => {
                ui::show_status("PIN locked", "");
                NscStatus::PinLocked as u32
            }
            Err(status) => status as u32,
        }
    }
}
