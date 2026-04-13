//! `CMD_IS_UNLOCKED` — return 1 if the device is PIN-unlocked, 0 otherwise.
//!
//! Used by the v2 `GET_STATUS` USB command to report lock state without
//! attempting a signing operation.

pub(super) unsafe fn run() -> u32 {
    if super::state::peek_state(|s| s.pin_verified) {
        1
    } else {
        0
    }
}
