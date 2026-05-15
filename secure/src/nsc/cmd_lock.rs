//! `CMD_LOCK` — explicitly lock the device by zeroizing all cached secrets.
//!
//! Called from the v2 `LOCK` USB command. Equivalent to what happens on
//! inactivity timeout, but triggered by the companion app.

use sphincs_tz_shared::NscStatus;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Zeroizes the
/// secure-world `SecureState` and SE caches; no NS pointer derefs.
pub(super) unsafe fn run() -> u32 {
    super::zeroize_sensitive_state();
    crate::ui::show_status("Locked", "");
    NscStatus::Ok as u32
}
