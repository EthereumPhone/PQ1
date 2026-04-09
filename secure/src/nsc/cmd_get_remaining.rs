//! `CMD_GET_REMAINING` — return how many PIN attempts are still
//! available in the current lockout window.
//!
//! On the mock backend this is just the cached counter in
//! `SecureState::remaining_attempts`. On a real TROPIC01 secure
//! element the count is re-read from the chip's monotonic MAC slot
//! on every call so a host-side reboot can't desync the view.

use sphincs_tz_shared::MAX_ATTEMPTS;

use super::state;

pub(super) unsafe fn run() -> u32 {
    #[cfg(feature = "tropic01-se")]
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.batch_read_pin_state() {
            Ok(next_index) => {
                let remaining = if next_index >= MAX_ATTEMPTS {
                    0
                } else {
                    MAX_ATTEMPTS - next_index
                };
                state::with_state(|s| s.remaining_attempts = remaining);
                remaining as u32
            }
            Err(_) => state::peek_state(|s| s.remaining_attempts as u32),
        }
    }
    #[cfg(not(feature = "tropic01-se"))]
    {
        let _ = MAX_ATTEMPTS;
        state::peek_state(|s| s.remaining_attempts as u32)
    }
}
