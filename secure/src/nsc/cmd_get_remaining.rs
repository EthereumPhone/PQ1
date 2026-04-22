//! `CMD_GET_REMAINING` — return how many PIN attempts are still
//! available in the current lockout window.
//!
//! Authoritative value is the MIN across all three counters:
//!   - MCU page-124 (tightest gate in production, fires first at
//!     `MAX_ATTEMPTS = 10`)
//!   - OPTIGA E120 LUC (hardware-enforced, lives in silicon)
//!   - SE050 UserID remaining (reported via `WalletStore`; for the
//!     Dual backend this is already `min(optiga, se050)`).
//!
//! Why MIN: in healthy lockstep, the MCU count dominates and MIN is
//! redundant. The value of MIN is in failure modes — e.g., flash
//! corruption that resets page-124 while silicon counters retain their
//! real state — when the displayed remaining must track the *lowest*
//! real count or the user gets a surprise lockout.

use super::state;

pub(super) unsafe fn run() -> u32 {
    use crate::secure_element::WalletStore;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let se_remaining = se.remaining_attempts();

    #[cfg(feature = "stm32u585")]
    let mcu_remaining = {
        let used = crate::hw::flash::pin_attempts_read();
        sphincs_tz_shared::MAX_ATTEMPTS.saturating_sub(used)
    };
    #[cfg(not(feature = "stm32u585"))]
    let mcu_remaining: u8 = sphincs_tz_shared::MAX_ATTEMPTS;

    let remaining = mcu_remaining.min(se_remaining);
    state::with_state(|s| s.remaining_attempts = remaining);
    remaining as u32
}
