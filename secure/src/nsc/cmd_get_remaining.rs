//! `CMD_GET_REMAINING` — return how many PIN attempts are still
//! available in the current lockout window.
//!
//! Each backend reports via its `WalletStore::remaining_attempts()`
//! implementation: Mock reads from r-mem, Tropic01 queries the chip,
//! SE050 returns a cached counter.

use super::state;

pub(super) unsafe fn run() -> u32 {
    use crate::secure_element::WalletStore;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let remaining = se.remaining_attempts();
    state::with_state(|s| s.remaining_attempts = remaining);
    remaining as u32
}
