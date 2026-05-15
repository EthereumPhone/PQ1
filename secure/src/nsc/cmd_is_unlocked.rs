//! `CMD_IS_UNLOCKED` — return 1 if the device is PIN-unlocked, 0 otherwise.
//!
//! Used by the v2 `GET_STATUS` USB command to report lock state without
//! attempting a signing operation.

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Reads only
/// `SecureState.pin_verified` via `peek_state`, which takes the
/// closure-scoped lock; no NS pointer derefs.
pub(super) unsafe fn run() -> u32 {
    if super::state::peek_state(|s| s.pin_verified.is_true_fi()) {
        1
    } else {
        0
    }
}
