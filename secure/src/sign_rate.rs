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
//! **Future hardening** (tracked in `docs/archive/work-todo-retired-2026-07-19.md §18b`): a
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

/// Maximum number of wakeups the forced preflight will tolerate while
/// completing the current minimum-sign interval.  On production hardware
/// `wfi` wakes on the 1 ms SysTick; the small allowance covers unrelated
/// interrupts without turning a corrupt/frozen clock into an unbounded wait.
#[cfg(all(
    feature = "erc7730-forced-blind",
    feature = "stm32u585",
    not(feature = "e2e-test"),
    not(test),
))]
const FORCED_RATE_MAX_WAKEUPS: u32 = MIN_SIGN_INTERVAL_MS * 16;

/// Request-bound, read-only evidence that the forced request reached the
/// session-cap boundary before the severe warning and that the current
/// minimum-sign interval had already elapsed.
///
/// The fields are private so callers cannot mint or rewrite the observation.
/// C3 retains one receipt across both confirmations, independently rechecks it
/// immediately before signing, and passes it to the sole charging operation.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ForcedRateReceipt {
    request_digest: [u8; 32],
    signs_this_session: u32,
    last_sign_ms: u32,
}

/// Fail-closed forced-rate preflight outcomes.  The handler maps every variant
/// to the existing refusal path; these names exist for focused evidence only.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForcedRateError {
    SessionCap,
    IntervalNotReady,
    StateDisagreement,
    TickFault,
    WaitBudgetExceeded,
    RequestMismatch,
    ChargeDisagreement,
}

/// Pure constructor shared by production and exact 249/250 boundary tests.
/// It performs no counter or timestamp write.
#[cfg(any(feature = "erc7730-forced-blind", test))]
fn forced_rate_receipt_from_observation(
    request_digest: &[u8; 32],
    count: u32,
    last_sign_ms: u32,
    now_ms: u32,
) -> Result<ForcedRateReceipt, ForcedRateError> {
    if count >= MAX_SIGNS_PER_SESSION {
        return Err(ForcedRateError::SessionCap);
    }
    // Reset publishes both words as zero; every charged sign advances the
    // count and, on production hardware, records a non-zero tick. A mixed
    // zero/non-zero pair is not a first-sign sentinel and must not skip the
    // interval. (The exact tick-wrap-to-zero instant remains fail-closed.)
    if (count == 0) != (last_sign_ms == 0) {
        return Err(ForcedRateError::StateDisagreement);
    }
    if last_sign_ms != 0 && now_ms.wrapping_sub(last_sign_ms) < MIN_SIGN_INTERVAL_MS {
        return Err(ForcedRateError::IntervalNotReady);
    }
    Ok(ForcedRateReceipt {
        request_digest: *request_digest,
        signs_this_session: count,
        last_sign_ms,
    })
}

/// Complete the existing minimum-sign-interval wait without charging a sign,
/// then freeze the current session count and rate timestamp into a receipt
/// bound to one forced request.
///
/// This helper is deliberately unavailable to host unit builds, whose secure
/// crate omits the production `timeout` module.  The pure observation kernel
/// above carries its boundary tests; Cortex-M feature-on links exercise this
/// exact wrapper.
#[cfg(all(feature = "erc7730-forced-blind", not(test)))]
#[inline(never)]
pub(crate) fn forced_rate_preflight(
    request_digest: &[u8; 32],
) -> Result<ForcedRateReceipt, ForcedRateError> {
    let count_addr = SIGNS_THIS_SESSION.as_ptr() as *const u32;
    let last_addr = LAST_SIGN_MS.as_ptr() as *const u32;
    let count_a = crate::fi::read_volatile_voted(count_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    let last_a = crate::fi::read_volatile_voted(last_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    if count_a >= MAX_SIGNS_PER_SESSION {
        return Err(ForcedRateError::SessionCap);
    }

    #[cfg(all(feature = "stm32u585", not(feature = "e2e-test")))]
    let now_ms = {
        let mut wakeups = 0u32;
        loop {
            let now =
                crate::timeout::snapshot_verified().map_err(|_| ForcedRateError::TickFault)?;
            if last_a == 0 || now.wrapping_sub(last_a) >= MIN_SIGN_INTERVAL_MS {
                break now;
            }
            if wakeups >= FORCED_RATE_MAX_WAKEUPS {
                return Err(ForcedRateError::WaitBudgetExceeded);
            }
            wakeups = wakeups.wrapping_add(1);
            cortex_m::asm::wfi();
        }
    };

    // QEMU/e2e configurations preserve the existing no-wait behavior but
    // still require a valid tick/complement snapshot and the 250-sign cap.
    #[cfg(any(not(feature = "stm32u585"), feature = "e2e-test"))]
    let now_ms = crate::timeout::snapshot_verified().map_err(|_| ForcedRateError::TickFault)?;

    crate::fi::wait_random();
    let count_b = crate::fi::read_volatile_voted(count_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    let last_b = crate::fi::read_volatile_voted(last_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    if count_a != count_b || last_a != last_b {
        return Err(ForcedRateError::StateDisagreement);
    }
    forced_rate_receipt_from_observation(request_digest, count_b, last_b, now_ms)
}

/// Non-blocking independent receipt recheck for the post-consent boundary.
/// Any changed counter/timestamp, request mismatch, unelapsed interval, or bad
/// tick pair is fatal; this helper never introduces a predictable wait after
/// the warning and never charges the counter.
#[cfg(all(feature = "erc7730-forced-blind", not(test)))]
#[inline(never)]
pub(crate) fn forced_rate_recheck(
    receipt: &ForcedRateReceipt,
    request_digest: &[u8; 32],
) -> Result<(), ForcedRateError> {
    if receipt.request_digest != *request_digest {
        return Err(ForcedRateError::RequestMismatch);
    }
    let count = crate::fi::read_volatile_voted(SIGNS_THIS_SESSION.as_ptr() as *const u32)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    let last = crate::fi::read_volatile_voted(LAST_SIGN_MS.as_ptr() as *const u32)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    let now = crate::timeout::snapshot_verified().map_err(|_| ForcedRateError::TickFault)?;
    let current = forced_rate_receipt_from_observation(request_digest, count, last, now)?;
    if current != *receipt {
        return Err(ForcedRateError::StateDisagreement);
    }
    Ok(())
}

/// Reset the rate-limit counters. Called from
/// `SecureState::mark_unlocked` (fresh session, full burst budget)
/// AND from `SecureState::zeroize_sensitive` (lock / idle-wipe —
/// stale counters serve no purpose).
pub fn reset_counters() {
    LAST_SIGN_MS.store(0, Ordering::Relaxed);
    SIGNS_THIS_SESSION.store(0, Ordering::Relaxed);
}

/// Number of signs registered in the current unlock session. Exposed
/// for the X17-FI2 verified-success read-back in
/// `crypto::c10_sign_verified_with_progress`: a glitch that skips
/// `bl pre_sign` leaves this counter un-advanced, so the caller can
/// require the +1 postcondition before stamping the CFI step instead
/// of trusting the fallible call's return register.
pub fn signs_this_session() -> u32 {
    SIGNS_THIS_SESSION.load(Ordering::Relaxed)
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

/// Check the production forced-charge timestamp against verified tick samples
/// taken immediately before and after [`pre_sign`].
///
/// The forced preflight has already completed the one-second interval, so the
/// charging call must not spend another interval in the generic wait.  The
/// charged timestamp must be a non-zero tick inside this short verified window;
/// zero at the exact 32-bit wrap instant is deliberately refused rather than
/// recreating the first-sign sentinel with a non-zero count.
#[cfg(any(feature = "erc7730-forced-blind", test))]
#[inline]
fn forced_charge_postcondition(
    count_before: u32,
    tick_before: u32,
    count_after: u32,
    charged_ms: u32,
    tick_after: u32,
) -> bool {
    let Some(expected_count) = count_before.checked_add(1) else {
        return false;
    };
    let tick_span = tick_after.wrapping_sub(tick_before);
    let charge_offset = charged_ms.wrapping_sub(tick_before);
    expected_count <= MAX_SIGNS_PER_SESSION
        && count_after == expected_count
        && charged_ms != 0
        && tick_span < MIN_SIGN_INTERVAL_MS
        && charge_offset <= tick_span
}

/// Forced-flow rate charge.
///
/// This is deliberately a wrapper around the existing [`pre_sign`] primitive,
/// not a second counter writer.  It first reproduces the frozen request-bound
/// observation without waiting, invokes `pre_sign` exactly once as the sole
/// charge, and independently proves the counter advanced by exactly one.  On
/// production silicon it additionally brackets the stored timestamp with two
/// verified value/complement tick snapshots.  The caller must still bind this
/// verified step into the crypto CFI transcript before any key use.
#[cfg(all(feature = "erc7730-forced-blind", not(test)))]
#[inline(never)]
pub(crate) fn pre_sign_forced(
    receipt: &ForcedRateReceipt,
    request_digest: &[u8; 32],
) -> Result<(), ForcedRateError> {
    forced_rate_recheck(receipt, request_digest)?;

    let count_addr = SIGNS_THIS_SESSION.as_ptr() as *const u32;
    let last_addr = LAST_SIGN_MS.as_ptr() as *const u32;
    let count_before = crate::fi::read_volatile_voted(count_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    let last_before = crate::fi::read_volatile_voted(last_addr)
        .map_err(|()| ForcedRateError::StateDisagreement)?;
    if count_before != receipt.signs_this_session || last_before != receipt.last_sign_ms {
        return Err(ForcedRateError::StateDisagreement);
    }

    #[cfg(all(feature = "stm32u585", not(feature = "e2e-test")))]
    let tick_before =
        crate::timeout::snapshot_verified().map_err(|_| ForcedRateError::TickFault)?;

    // Sole counter/timestamp charge.  The immediately preceding receipt recheck
    // proved the minimum interval elapsed, so the generic production wait exits
    // on its first observation and introduces no post-warning rate delay.
    pre_sign().map_err(|()| ForcedRateError::SessionCap)?;

    let count_after = crate::fi::read_volatile_voted(count_addr)
        .map_err(|()| ForcedRateError::ChargeDisagreement)?;
    let expected_count = count_before
        .checked_add(1)
        .ok_or(ForcedRateError::ChargeDisagreement)?;
    let count_charged = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(count_after) == core::hint::black_box(expected_count)
            && core::hint::black_box(expected_count) <= MAX_SIGNS_PER_SESSION
    });
    if count_charged != crate::fi::OK_SENTINEL {
        return Err(ForcedRateError::ChargeDisagreement);
    }

    #[cfg(all(feature = "stm32u585", not(feature = "e2e-test")))]
    {
        let charged_ms = crate::fi::read_volatile_voted(last_addr)
            .map_err(|()| ForcedRateError::ChargeDisagreement)?;
        let tick_after =
            crate::timeout::snapshot_verified().map_err(|_| ForcedRateError::TickFault)?;
        let timestamp_charged = crate::fi::check_true_into_sentinel(|| {
            forced_charge_postcondition(
                core::hint::black_box(count_before),
                core::hint::black_box(tick_before),
                core::hint::black_box(count_after),
                core::hint::black_box(charged_ms),
                core::hint::black_box(tick_after),
            )
        });
        if timestamp_charged != crate::fi::OK_SENTINEL {
            return Err(ForcedRateError::ChargeDisagreement);
        }
    }

    Ok(())
}

#[cfg(all(feature = "stm32u585", not(feature = "e2e-test"), not(test)))]
fn wait_for_min_interval() {
    // F-19: redundant volatile reads on the rate-limit reference
    // value. `LAST_SIGN_MS` is a plain `AtomicU32` whose `Relaxed`
    // load is one `ldr` instruction — a glitch on that load could
    // clamp `last` to 0 (the "no prior sign" sentinel), causing the
    // first-sign fast-path below to fire and bypass the rate limit.
    // Triple-read the underlying word via `read_volatile_voted`
    // (Err on any disagreement → fail-CLOSED to "skip the wait
    // entirely" is unsafe, so instead we treat disagreement as
    // "no last-sign info available, proceed cautiously" — refuse to
    // break out of the wait until we get a clean read).
    let last_addr = LAST_SIGN_MS.as_ptr() as *const u32;
    let last = match crate::fi::read_volatile_voted(last_addr) {
        Ok(v) => v,
        // Triple-read disagreed → glitch suspected on the load.
        // Fail-CLOSED: stay in the wait loop until the disagreement
        // resolves (or the FI sweep ends). Treat the value as
        // u32::MAX-ish so the wait condition can't fire.
        Err(()) => {
            // Force the loop to spin until a stable read agrees.
            // Use `pre_sign`'s session cap (250) as the ultimate
            // backstop — if we spin too long, the outer caller
            // eventually catches up.
            loop {
                cortex_m::asm::wfi();
                if crate::fi::read_volatile_voted(last_addr).is_ok() {
                    return;
                }
            }
        }
    };
    if last == 0 {
        // First sign of the session: no prior; nothing to wait for.
        return;
    }
    // Busy-wait via WFI (low power; wakes on every SysTick at 1 ms
    // resolution). Wrapping-aware compare handles the (very rare)
    // 49.7-day TICKS rollover.
    //
    // F-19: triple-read `now()` on each iteration too — a glitch on
    // the TICKS atomic load could fake a huge time delta and exit
    // the wait early. Triple-read with agreement defends single-fault
    // on that load.
    loop {
        let now_addr = crate::timeout::ticks_ptr();
        let now = match crate::fi::read_volatile_voted(now_addr) {
            Ok(v) => v,
            Err(()) => {
                // Disagreement → stay in the wait. Sleep and retry.
                cortex_m::asm::wfi();
                continue;
            }
        };
        if now.wrapping_sub(last) >= MIN_SIGN_INTERVAL_MS {
            break;
        }
        cortex_m::asm::wfi();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests share the production module's session counters. Keep each
    // reset-and-sign scenario atomic with respect to the other host tests.
    static COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// First sign of a session always passes.
    #[test]
    fn first_sign_ok() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        reset_counters();
        assert_eq!(signs_this_session(), 0);
        assert!(pre_sign().is_ok());
        assert_eq!(
            signs_this_session(),
            1,
            "pre_sign must advance the session counter by exactly one \
             (the X17-FI2 read-back postcondition crypto.rs relies on)"
        );
    }

    /// Session cap is enforced — past MAX_SIGNS_PER_SESSION, sign is
    /// refused.
    #[test]
    fn session_cap_refuses() {
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
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
        let _guard = COUNTER_TEST_LOCK.lock().unwrap();
        reset_counters();
        for _ in 0..MAX_SIGNS_PER_SESSION {
            assert!(pre_sign().is_ok());
        }
        assert!(pre_sign().is_err());
        reset_counters();
        assert!(pre_sign().is_ok(), "post-reset sign should pass");
    }

    #[test]
    fn forced_preflight_boundary_is_exactly_249_250_and_read_only() {
        let request = [0x42; 32];
        let receipt =
            forced_rate_receipt_from_observation(&request, MAX_SIGNS_PER_SESSION - 1, 1_000, 2_000)
                .expect("count 249 with an elapsed interval must pass");
        assert_eq!(receipt.request_digest, request);
        assert_eq!(receipt.signs_this_session, 249);
        assert_eq!(receipt.last_sign_ms, 1_000);
        assert_eq!(
            forced_rate_receipt_from_observation(&request, MAX_SIGNS_PER_SESSION, 1_000, 2_000,),
            Err(ForcedRateError::SessionCap),
        );
    }

    #[test]
    fn forced_preflight_interval_boundary_is_exact_and_wrapping_safe() {
        let request = [0x24; 32];
        let start = u32::MAX - 400;
        assert_eq!(
            forced_rate_receipt_from_observation(
                &request,
                1,
                start,
                start.wrapping_add(MIN_SIGN_INTERVAL_MS - 1),
            ),
            Err(ForcedRateError::IntervalNotReady),
        );
        assert!(forced_rate_receipt_from_observation(
            &request,
            1,
            start,
            start.wrapping_add(MIN_SIGN_INTERVAL_MS),
        )
        .is_ok());
        assert!(forced_rate_receipt_from_observation(&request, 0, 0, 0).is_ok());
        assert_eq!(
            forced_rate_receipt_from_observation(&request, 1, 0, 2_000),
            Err(ForcedRateError::StateDisagreement),
        );
        assert_eq!(
            forced_rate_receipt_from_observation(&request, 0, 1, 2_000),
            Err(ForcedRateError::StateDisagreement),
        );
    }

    #[test]
    fn forced_receipts_are_request_and_observation_bound() {
        let a = forced_rate_receipt_from_observation(&[0x11; 32], 7, 500, 1_500).unwrap();
        let b = forced_rate_receipt_from_observation(&[0x22; 32], 7, 500, 1_500).unwrap();
        let c = forced_rate_receipt_from_observation(&[0x11; 32], 8, 500, 1_500).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn forced_charge_postcondition_binds_count_timestamp_and_short_tick_window() {
        assert!(forced_charge_postcondition(
            249, 10_000, 250, 10_001, 10_002
        ));
        assert!(!forced_charge_postcondition(
            249, 10_000, 249, 10_001, 10_002
        ));
        assert!(!forced_charge_postcondition(
            249, 10_000, 250, 9_000, 10_002
        ));
        assert!(!forced_charge_postcondition(
            249, 10_000, 250, 10_003, 10_002
        ));
        assert!(!forced_charge_postcondition(249, 10_000, 250, 0, 10_002));
        assert!(!forced_charge_postcondition(
            249, 10_000, 250, 11_000, 11_000,
        ));

        let before = u32::MAX - 2;
        assert!(forced_charge_postcondition(
            0,
            before,
            1,
            u32::MAX,
            before.wrapping_add(3),
        ));
        assert!(!forced_charge_postcondition(0, u32::MAX, 1, 0, 0,));
    }
}
