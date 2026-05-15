//! Signing rate limiter — SCA defense.
//!
//! **Threat.** Profiled DPA / template attacks against the
//! non-hardened STM32U585 HASH peripheral need many traces (typically
//! ~hundreds to ~thousands of signatures). Without a rate limit, an
//! unlocked wallet under USB / NSC control can be made to sign as
//! fast as the firmware can produce sigs (~1 s/sign with HW SHA, so
//! ~3600 sigs/hour). That gives an attacker a few hours to collect
//! enough traces for a profiled-DPA attack against the WOTS chain
//! seeds or FORS leaf secrets.
//!
//! The F-16 shuffling defense raises the per-trace cost by a factor
//! of ~10^52 (the permutation space) — but a determined adversary
//! with enough traces can still try to crack the shuffle pattern.
//! Rate limiting stretches the attack window further: from hours to
//! months.
//!
//! **Two limits enforced per signing call:**
//!
//!   - **Minimum 1-second interval** between consecutive signs.
//!     Sub-second burst signing (e.g., 100 sigs/sec via USB) is
//!     blocked: the firmware busy-waits until the interval elapses.
//!
//!   - **Per-unlock-session burst cap of 250 sigs.** After the cap,
//!     further signs are refused (`Err(())`). The user must re-unlock
//!     (PIN entry) to reset the counter. Combined with SE-side PIN
//!     attempt rate-limiting (10 attempts max before SE wipes), this
//!     bounds the long-term sign rate to ~1 sig/sec sustained.
//!
//! **State is SRAM-only** (lost on lock / idle-wipe / reset). The
//! reset-on-unlock semantic is acceptable because:
//!   - PIN unlock itself is rate-limited by the SE silicon counter.
//!   - For a determined attacker who knows the PIN, the unlock+sign
//!     cycle is bottlenecked by PIN entry (~5 s per cold unlock).
//!
//! **Future hardening** (tracked in `docs/work-todo.md §18b`): a
//! flash-persistent daily-quota (500/day) would defeat the
//! power-cycle-bypass-burst-cap attack class. Deferred because flash
//! writes on every sign add wear; out of scope for this commit.

use core::sync::atomic::{AtomicU32, Ordering};

/// Minimum interval between sign calls, in ms. Enforced via busy-wait
/// against the SysTick-driven `crate::timeout::now()` counter.
pub const MIN_SIGN_INTERVAL_MS: u32 = 1000;

/// Max sigs per unlock session. After this count, the firmware
/// refuses further signs until the next successful PIN unlock.
pub const MAX_SIGNS_PER_SESSION: u32 = 250;

static LAST_SIGN_MS: AtomicU32 = AtomicU32::new(0);
static SIGNS_THIS_SESSION: AtomicU32 = AtomicU32::new(0);

/// Reset the rate-limit counters. Called from
/// `SecureState::mark_unlocked` (fresh session, full burst budget)
/// AND from `SecureState::zeroize_sensitive` (lock / idle-wipe —
/// stale counters serve no purpose).
pub fn reset_counters() {
    LAST_SIGN_MS.store(0, Ordering::Relaxed);
    SIGNS_THIS_SESSION.store(0, Ordering::Relaxed);
}

/// Check whether a sign is permitted right now. Called at the top of
/// `crypto::c10_sign_verified_with_progress`, ONCE per output
/// signature (the F-13 double-compute inside that wrapper counts as
/// one rate-limit charge — same SK budget cost as a single sig).
///
/// Returns `Err(())` if the session cap is hit (caller refuses with
/// `NscStatus::CryptoError`). Otherwise registers the sign and
/// returns `Ok(())`, having busy-waited until the minimum interval
/// since the last sign has elapsed.
///
/// On `e2e-test` builds the time-based wait is skipped (the QEMU
/// e2e runner does ~30 signs back-to-back; a 1-sec wait per sign
/// would stretch the test runtime from seconds to a minute+ with no
/// security benefit on QEMU). The session cap is still enforced so
/// the cap-tripping path can be reached in tests.
pub fn pre_sign() -> Result<(), ()> {
    let count = SIGNS_THIS_SESSION.load(Ordering::Relaxed);
    if count >= MAX_SIGNS_PER_SESSION {
        return Err(());
    }

    // Time-based wait: production-hardware path only.
    #[cfg(all(feature = "stm32u585", not(feature = "e2e-test"), not(test)))]
    wait_for_min_interval();

    // Register this sign. Under non-stm32u585 (QEMU) and host tests,
    // `crate::timeout::now()` is effectively constant (no SysTick) —
    // we still store it (typically 0) so the LAST_SIGN_MS state
    // mirrors the production semantic.
    #[cfg(all(not(test), feature = "stm32u585"))]
    LAST_SIGN_MS.store(crate::timeout::now(), Ordering::Relaxed);
    SIGNS_THIS_SESSION.store(count + 1, Ordering::Relaxed);

    Ok(())
}

#[cfg(all(feature = "stm32u585", not(feature = "e2e-test"), not(test)))]
fn wait_for_min_interval() {
    let last = LAST_SIGN_MS.load(Ordering::Relaxed);
    if last == 0 {
        // First sign of the session: no prior; nothing to wait for.
        return;
    }
    // Busy-wait via WFI (low power; wakes on every SysTick at 1 ms
    // resolution). Wrapping-aware compare handles the (very rare)
    // 49.7-day TICKS rollover.
    loop {
        let now = crate::timeout::now();
        if now.wrapping_sub(last) >= MIN_SIGN_INTERVAL_MS {
            break;
        }
        cortex_m::asm::wfi();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First sign of a session always passes.
    #[test]
    fn first_sign_ok() {
        reset_counters();
        assert!(pre_sign().is_ok());
    }

    /// Session cap is enforced — past MAX_SIGNS_PER_SESSION, sign is
    /// refused.
    #[test]
    fn session_cap_refuses() {
        reset_counters();
        for _ in 0..MAX_SIGNS_PER_SESSION {
            assert!(pre_sign().is_ok());
        }
        assert!(pre_sign().is_err(), "sign #{} should refuse",
            MAX_SIGNS_PER_SESSION + 1);
    }

    /// `reset_counters` re-arms the session.
    #[test]
    fn reset_re_arms() {
        reset_counters();
        for _ in 0..MAX_SIGNS_PER_SESSION {
            assert!(pre_sign().is_ok());
        }
        assert!(pre_sign().is_err());
        reset_counters();
        assert!(pre_sign().is_ok(), "post-reset sign should pass");
    }
}
