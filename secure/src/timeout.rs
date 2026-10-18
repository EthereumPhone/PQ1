//! Inactivity timeout / activity tracking.
//!
//! [`tick_verified`] is called first on every SysTick (~1 ms). It advances an
//! exact value/complement pair and publishes completion only after reading the
//! pair back. `reset_activity()` is called whenever real user input occurs
//! (button press, successful PIN entry, confirmed sign). `is_idle()` returns
//! true after [`TIMEOUT_TICKS`] ticks have elapsed without activity, and is
//! checked from any blocking dialog so it can interrupt them and trigger a
//! wipe.
//!
//! Trusted confirmation dialogs also expose a scoped
//! [`TrustedUiWaitGuard`]. The secure watchdog uses that signal to distinguish
//! a healthy handler deliberately waiting for a physical button from a
//! handler wedged in crypto / parsing / flash. The signal never resets the
//! inactivity timer: once [`is_idle`] becomes true, the watchdog resumes its
//! ordinary bounded-stall policy even if a broken input backend failed to
//! return from the dialog.
//!
//! Background NS gateway commands (GET_REMAINING, GET_PUBKEY) intentionally
//! do NOT count as activity — only physical user input does, matching the
//! Ledger model.

use core::sync::atomic::{AtomicU32, Ordering};

/// 2 minutes at ~1 ms tick. The actual SysTick reload is configured in
/// `main::setup_systick()`.
pub const TIMEOUT_TICKS: u32 = 2 * 60 * 1000;

static TICKS: AtomicU32 = AtomicU32::new(0);
static TICKS_INV: AtomicU32 = AtomicU32::new(!0);
static LAST_ACTIVITY: AtomicU32 = AtomicU32::new(0);

// Host tests share this remounted module's globals across parallel test
// threads, while production has one non-reentrant SysTick writer. Keep tests
// that exercise the live pair serialized without adding production state.
#[cfg(test)]
static TIMEOUT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TIMEOUT_TEST_LOCK
        .lock()
        .expect("timeout test lock poisoned")
}

/// Exact forced-flow limit selected by the owner. Physical activity never
/// extends this deadline.
pub const FORCED_FLOW_DEADLINE_MS: u32 = 300_000;

/// Time reserved for the fixed forced-response publication after its final
/// pre-write authorization gate.
pub const FORCED_RELEASE_RESERVE_MS: u32 = 1_000;

/// Latest elapsed tick at which the irreversible forced-response write may
/// begin. The gate is strict: elapsed must be `< 299_000`.
pub const FORCED_RELEASE_LATEST_MS: u32 = FORCED_FLOW_DEADLINE_MS - FORCED_RELEASE_RESERVE_MS;

#[inline]
fn forced_deadline_expired_at(start_ms: u32, now_ms: u32) -> bool {
    now_ms.wrapping_sub(start_ms) >= FORCED_FLOW_DEADLINE_MS
}

#[inline]
fn forced_release_window_open_at(start_ms: u32, now_ms: u32) -> bool {
    now_ms.wrapping_sub(start_ms) < FORCED_RELEASE_LATEST_MS
}

/// Completion code written by [`tick_verified`] only after an exact pair was
/// published and independently read back. It is deliberately distinct from
/// the ordinary FI success sentinel so SysTick must validate two independent
/// caller-owned slots before the watchdog may reload.
pub const TICK_CFI_COMPLETE: u32 = 0x39C6_C639;

const SNAPSHOT_ATTEMPTS: usize = 3;

/// A verified tick snapshot could not be obtained within the fixed retry
/// budget. Forced callers treat every variant as fatal.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TickSnapshotError {
    UnstableOrInvalid,
}

#[derive(Copy, Clone)]
struct TickSample {
    ticks: u32,
    ticks_inv: u32,
}

impl TickSample {
    #[inline]
    fn is_valid(self) -> bool {
        self.ticks_inv == !self.ticks
    }
}

#[inline]
fn read_sample(ticks: &AtomicU32, ticks_inv: &AtomicU32) -> TickSample {
    TickSample {
        ticks: ticks.load(Ordering::SeqCst),
        ticks_inv: ticks_inv.load(Ordering::SeqCst),
    }
}

#[inline]
fn accept_snapshot_samples(samples: [TickSample; 3]) -> Option<u32> {
    if !samples[0].is_valid() || !samples[1].is_valid() || !samples[2].is_valid() {
        return None;
    }
    let delta_01 = samples[1].ticks.wrapping_sub(samples[0].ticks);
    let delta_12 = samples[2].ticks.wrapping_sub(samples[1].ticks);
    if delta_01 > 1 || delta_12 > 1 {
        return None;
    }
    Some(samples[2].ticks)
}

#[inline(never)]
fn snapshot_pair_verified(
    ticks: &AtomicU32,
    ticks_inv: &AtomicU32,
) -> Result<u32, TickSnapshotError> {
    for _ in 0..SNAPSHOT_ATTEMPTS {
        let samples = [
            read_sample(ticks, ticks_inv),
            read_sample(ticks, ticks_inv),
            read_sample(ticks, ticks_inv),
        ];
        if let Some(snapshot) = accept_snapshot_samples(samples) {
            return Ok(snapshot);
        }
    }
    Err(TickSnapshotError::UnstableOrInvalid)
}

/// Retry-safe thread-mode snapshot of the exact tick/complement pair.
///
/// Each of at most three attempts takes three pair-valid samples and accepts
/// only wrapping-monotone progress of zero or one tick between samples. A
/// legitimate SysTick interleave can therefore cause a bounded retry but not
/// a false fatal mismatch; backward movement, a jump, or an invalid pair
/// fails closed.
#[inline(never)]
pub fn snapshot_verified() -> Result<u32, TickSnapshotError> {
    snapshot_pair_verified(&TICKS, &TICKS_INV)
}

/// Non-cloneable marker for the absolute forced-flow deadline. Creation takes
/// a verified pair snapshot; callers create it immediately after charging the
/// one-per-PIN forced attempt.
pub struct ForcedDeadline {
    start_ms: u32,
}

impl ForcedDeadline {
    #[inline(never)]
    pub fn start_verified() -> Result<Self, TickSnapshotError> {
        Ok(Self {
            start_ms: snapshot_verified()?,
        })
    }

    #[inline(never)]
    pub fn elapsed_verified(&self) -> Result<u32, TickSnapshotError> {
        Ok(snapshot_verified()?.wrapping_sub(self.start_ms))
    }

    #[inline(never)]
    pub fn expired_verified(&self) -> Result<bool, TickSnapshotError> {
        Ok(forced_deadline_expired_at(
            self.start_ms,
            snapshot_verified()?,
        ))
    }

    /// Final pre-write window for the fixed forced response. `false` at the
    /// exact 299,000 ms boundary, as required by the owner architecture.
    #[inline(never)]
    pub fn release_window_open_verified(&self) -> Result<bool, TickSnapshotError> {
        Ok(forced_release_window_open_at(
            self.start_ms,
            snapshot_verified()?,
        ))
    }
}

/// Nesting depth of secure trusted-UI button waits.
///
/// Only secure UI code can acquire this guard; NS has no writer. A depth
/// counter rather than a boolean makes nested trusted dialogs fail-safe: an
/// inner guard dropping cannot accidentally clear an outer wait. This state
/// is watchdog bookkeeping only and grants no signing/update authority.
static TRUSTED_UI_WAIT_DEPTH: AtomicU32 = AtomicU32::new(0);

/// RAII marker for the narrow interval in which trusted UI is blocked waiting
/// for a physical button event.
///
/// Keep the guard around the input wait only, not rendering, parsing, crypto,
/// or flash. Those noninteractive operations remain subject to the watchdog's
/// normal busy-handler deadline.
pub struct TrustedUiWaitGuard;

impl TrustedUiWaitGuard {
    #[must_use]
    pub fn enter() -> Self {
        TRUSTED_UI_WAIT_DEPTH.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for TrustedUiWaitGuard {
    fn drop(&mut self) {
        // Saturating CAS mirrors HandlerGuard: underflow is impossible in safe
        // Rust, but must never wrap into an effectively permanent UI-wait
        // authorization if the implementation changes later.
        let mut cur = TRUSTED_UI_WAIT_DEPTH.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match TRUSTED_UI_WAIT_DEPTH.compare_exchange_weak(
                cur,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Whether secure code is currently blocked on a trusted physical input.
///
/// The watchdog additionally requires `!is_idle()` before treating this as
/// progress, so a leaked/wedged wait is still bounded.
#[inline]
pub fn trusted_ui_is_waiting() -> bool {
    TRUSTED_UI_WAIT_DEPTH.load(Ordering::SeqCst) > 0
}

/// Clear any outstanding trusted-UI marker during lock / panic / tamper
/// zeroization.
///
/// Firmware uses panic=abort, so RAII destructors do not run on those paths.
/// Clearing explicitly prevents a panic inside `wait_button` from extending
/// watchdog feeding until the inactivity deadline. Later guard drops use a
/// saturating decrement and therefore remain safe after this emergency clear.
#[inline]
pub fn clear_trusted_ui_wait() {
    TRUSTED_UI_WAIT_DEPTH.store(0, Ordering::SeqCst);
}

#[inline]
pub fn now() -> u32 {
    TICKS.load(Ordering::Relaxed)
}

/// Raw pointer to the underlying `TICKS` word. Used by callers that
/// want to apply `fi::read_volatile_voted` against the same word —
/// triple-read with fences to defend a single-fault glitch on the
/// `ldr` instruction that would otherwise return an attacker-clamped
/// value. The `AtomicU32` API doesn't expose the underlying address
/// directly, so we surface it explicitly here.
#[inline]
pub fn ticks_ptr() -> *const u32 {
    TICKS.as_ptr() as *const u32
}

/// Advance the exact tick pair and publish caller-owned completion receipts.
///
/// The caller must volatile-initialize `health_out` and `cfi_out` to failure
/// values before calling. Invalid old state is never repaired. Completion is
/// published only after the exact next pair has been stored and read back;
/// skipping this whole non-inlined call therefore leaves both caller slots in
/// their fail-initialized state.
#[inline(never)]
fn tick_pair_verified(
    ticks: &AtomicU32,
    ticks_inv: &AtomicU32,
    health_out: &mut u32,
    cfi_out: &mut u32,
) {
    let old = ticks.load(Ordering::SeqCst);
    let old_inv = ticks_inv.load(Ordering::SeqCst);
    if old_inv != !old {
        return;
    }

    let next = old.wrapping_add(1);
    let next_inv = !next;
    ticks.store(next, Ordering::SeqCst);
    ticks_inv.store(next_inv, Ordering::SeqCst);
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    let readback = ticks.load(Ordering::SeqCst);
    let readback_inv = ticks_inv.load(Ordering::SeqCst);
    if readback != next || readback_inv != next_inv || readback_inv != !readback {
        return;
    }

    // SAFETY: both pointers come from unique mutable references owned by the
    // SysTick caller. Volatile publication prevents LLVM from replacing the
    // caller's independent readback with these local SSA values.
    unsafe {
        core::ptr::write_volatile(health_out, crate::fi::OK_SENTINEL);
        core::ptr::write_volatile(cfi_out, TICK_CFI_COMPLETE);
    }
}

#[inline(never)]
pub fn tick_verified(health_out: &mut u32, cfi_out: &mut u32) {
    tick_pair_verified(&TICKS, &TICKS_INV, health_out, cfi_out);
}

#[inline]
pub fn reset_activity() {
    LAST_ACTIVITY.store(now(), Ordering::Relaxed);
}

#[inline]
pub fn idle_for() -> u32 {
    now().wrapping_sub(LAST_ACTIVITY.load(Ordering::Relaxed))
}

#[inline]
pub fn is_idle() -> bool {
    idle_for() > TIMEOUT_TICKS
}

// ---- Bounded idle-wipe deferral (#981) ----
//
// The SysTick idle wipe skips while a gateway handler is busy (HIGH-7: the
// handler holds stack copies of the secrets, and zeroing the BSS copy under it
// would leave it signing for a session the user no longer has). A healthy
// handler reaches its own idle check point and returns within milliseconds of
// the deadline, so the deferral is short. A non-secure exception that
// preempts the handler and parks keeps it "busy" for as long as it likes: on
// EVT-3D21 (2026-10-18, DVT row 13.10) that held an unlocked session 206 s
// past the 120 s deadline. The IWDG busy cap (`hw::iwdg`) bounds that on
// `iwdg` builds, but only through the watchdog, only after the trusted-UI
// exception has run out, and only for as long as nothing fakes its inputs.
// This bound is the idle wipe's own: once the deferral runs past its limit the
// SysTick handler zeroizes and resets the core instead of waiting. A reset
// never returns to the parked handler, so the HIGH-7 aliasing hazard does not
// arise, and the handler's own stack frames are cleared by the reset path
// (`zero-init-ram`, the `SRAM_RST` option bit, and the Software-reset scrub in
// `reset_cause`).

/// Deferral limit while no trusted dialog is waiting: the same ~30 s as the
/// IWDG busy cap, above any legitimate non-interactive handler that can
/// straddle the idle deadline (the longest is one cold first sign, 12-17 s on
/// pq1, and it can only straddle if it began without a button press).
pub const WIPE_DEFER_LIMIT_TICKS: u32 = 30_000;

/// Deferral limit while a trusted dialog is (supposedly) waiting for a button.
/// A dialog that is actually running polls [`is_idle`] in its wait loop and
/// returns as soon as the deadline passes, so one still "waiting" 5 s later has
/// been preempted or is wedged. Without this shorter limit a dialog parked by
/// a non-secure exception would hold the wipe off for the full 30 s above,
/// after the 120 s that the IWDG's trusted-UI exception already allows.
pub const WIPE_DEFER_UI_LIMIT_TICKS: u32 = 5_000;

const _: () = assert!(
    WIPE_DEFER_UI_LIMIT_TICKS < WIPE_DEFER_LIMIT_TICKS && WIPE_DEFER_LIMIT_TICKS <= 30_000,
    "the idle-wipe deferral bound must stay short (#981)"
);

/// Consecutive SysTicks on which the idle wipe was due but deferred because a
/// handler was busy. Sole writer: the non-reentrant SysTick handler. Read over
/// SWD by `tools/dvt/idle_hold.py`.
static WIPE_DEFER_TICKS: AtomicU32 = AtomicU32::new(0);

/// Pure limit test, separated for the host tests.
#[inline]
#[must_use]
pub fn wipe_defer_expired(deferred_ticks: u32, ui_waiting: bool) -> bool {
    let limit = if ui_waiting { WIPE_DEFER_UI_LIMIT_TICKS } else { WIPE_DEFER_LIMIT_TICKS };
    deferred_ticks >= limit
}

/// One SysTick of the deferral bound. `deferred` is "the idle wipe is due and
/// a busy handler is the only thing stopping it" (`is_idle() &&
/// handler_is_busy() && !is_definitely_locked()`); any tick on which it is
/// false restarts the count. Returns `true` once the deferral has run past its
/// limit: the caller must then zeroize and reset, and never return to the
/// handler.
///
/// Evaluated every tick on purpose, like the wipe itself: suppressing the
/// reset means faulting every tick of the window, not one.
#[inline(never)]
pub fn wipe_defer_step(deferred: bool, ui_waiting: bool) -> bool {
    if !deferred {
        WIPE_DEFER_TICKS.store(0, Ordering::SeqCst);
        return false;
    }
    let n = WIPE_DEFER_TICKS.load(Ordering::SeqCst).saturating_add(1);
    WIPE_DEFER_TICKS.store(n, Ordering::SeqCst);
    wipe_defer_expired(n, ui_waiting)
}

/// Current deferral count (host tests only; on silicon read the static over
/// SWD).
#[cfg(test)]
pub fn wipe_defer_ticks() -> u32 {
    WIPE_DEFER_TICKS.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_slots() -> (u32, u32) {
        (crate::fi::FAIL_SENTINEL, crate::fi::FAIL_SENTINEL)
    }

    #[test]
    fn tick_publishes_exact_pair_then_both_completion_slots() {
        let ticks = AtomicU32::new(41);
        let ticks_inv = AtomicU32::new(!41);
        let (mut health, mut cfi) = fail_slots();
        tick_pair_verified(&ticks, &ticks_inv, &mut health, &mut cfi);
        assert_eq!(ticks.load(Ordering::SeqCst), 42);
        assert_eq!(ticks_inv.load(Ordering::SeqCst), !42);
        assert_eq!(health, crate::fi::OK_SENTINEL);
        assert_eq!(cfi, TICK_CFI_COMPLETE);
    }

    #[test]
    fn invalid_primary_or_check_bit_is_sticky_and_never_publishes_success() {
        for (old, old_inv) in [(9u32 ^ 1, !9u32), (9u32, (!9u32) ^ 1)] {
            let ticks = AtomicU32::new(old);
            let ticks_inv = AtomicU32::new(old_inv);
            let (mut health, mut cfi) = fail_slots();
            tick_pair_verified(&ticks, &ticks_inv, &mut health, &mut cfi);
            assert_eq!(ticks.load(Ordering::SeqCst), old);
            assert_eq!(ticks_inv.load(Ordering::SeqCst), old_inv);
            assert_eq!(health, crate::fi::FAIL_SENTINEL);
            assert_eq!(cfi, crate::fi::FAIL_SENTINEL);
        }
    }

    #[test]
    fn skipped_tick_call_leaves_fail_slots_and_frozen_pair() {
        let ticks = AtomicU32::new(77);
        let ticks_inv = AtomicU32::new(!77);
        let (health, cfi) = fail_slots();
        assert_eq!(ticks.load(Ordering::SeqCst), 77);
        assert_eq!(ticks_inv.load(Ordering::SeqCst), !77);
        assert_eq!(health, crate::fi::FAIL_SENTINEL);
        assert_eq!(cfi, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn tick_pair_wraps_exactly() {
        let ticks = AtomicU32::new(u32::MAX);
        let ticks_inv = AtomicU32::new(!u32::MAX);
        let (mut health, mut cfi) = fail_slots();
        tick_pair_verified(&ticks, &ticks_inv, &mut health, &mut cfi);
        assert_eq!(ticks.load(Ordering::SeqCst), 0);
        assert_eq!(ticks_inv.load(Ordering::SeqCst), !0);
        assert_eq!(health, crate::fi::OK_SENTINEL);
        assert_eq!(cfi, TICK_CFI_COMPLETE);
    }

    fn sample(ticks: u32) -> TickSample {
        TickSample {
            ticks,
            ticks_inv: !ticks,
        }
    }

    #[test]
    fn snapshot_accepts_stable_single_advance_and_wraparound() {
        assert_eq!(
            accept_snapshot_samples([sample(5), sample(5), sample(6)]),
            Some(6)
        );
        assert_eq!(
            accept_snapshot_samples([sample(u32::MAX), sample(0), sample(0)]),
            Some(0)
        );
    }

    #[test]
    fn snapshot_rejects_invalid_backward_and_multi_tick_samples() {
        let invalid = TickSample {
            ticks: 5,
            ticks_inv: !5 ^ 1,
        };
        assert_eq!(
            accept_snapshot_samples([sample(5), invalid, sample(5)]),
            None
        );
        assert_eq!(
            accept_snapshot_samples([sample(5), sample(4), sample(4)]),
            None
        );
        assert_eq!(
            accept_snapshot_samples([sample(5), sample(7), sample(7)]),
            None
        );
    }

    #[test]
    fn snapshot_pair_is_bounded_and_accepts_stable_pair() {
        let ticks = AtomicU32::new(123);
        let ticks_inv = AtomicU32::new(!123);
        assert_eq!(snapshot_pair_verified(&ticks, &ticks_inv), Ok(123));

        let bad_inv = AtomicU32::new(!123 ^ 1);
        assert_eq!(
            snapshot_pair_verified(&ticks, &bad_inv),
            Err(TickSnapshotError::UnstableOrInvalid)
        );
    }

    #[test]
    fn forced_deadline_and_release_boundaries_are_exact_and_wrapping() {
        let start = u32::MAX - 20;
        assert!(forced_release_window_open_at(
            start,
            start.wrapping_add(298_999)
        ));
        assert!(!forced_release_window_open_at(
            start,
            start.wrapping_add(299_000)
        ));
        assert!(!forced_deadline_expired_at(
            start,
            start.wrapping_add(299_999)
        ));
        assert!(forced_deadline_expired_at(
            start,
            start.wrapping_add(300_000)
        ));
    }

    #[test]
    fn forced_deadline_public_api_starts_verified_and_is_initially_open() {
        let _guard = test_lock();
        let deadline = ForcedDeadline::start_verified().unwrap();
        assert!(deadline.elapsed_verified().unwrap() < FORCED_FLOW_DEADLINE_MS);
        assert!(!deadline.expired_verified().unwrap());
        assert!(deadline.release_window_open_verified().unwrap());
    }
}
