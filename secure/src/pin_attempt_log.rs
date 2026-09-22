//! Why each PIN attempt was consumed.
//!
//! ## Why this exists
//!
//! On 2026-09-21 a pq1 unit showed "PIN locked" after the operator entered the
//! **correct** PIN once (#715). Ten attempts had been spent, and nothing
//! recorded how: the shipping image omits `debug-log` (semihosting `BKPT`
//! hard-faults with no debugger attached, and a sealed unit has none), so the
//! only evidence was the counter's final value. The root cause remains
//! unidentified, and a field report of the same thing would be equally
//! unfalsifiable.
//!
//! `gated_unlock` **pre-charges** page 124 before the secure element judges the
//! PIN, so a burn on its own says nothing about why. What distinguishes a
//! legitimate wrong-PIN burn from a fault is the *outcome path* that follows,
//! which is exactly what this records.
//!
//! ## What it is not
//!
//! **RAM-resident.** It answers "why did this device just lock out" while the
//! device is still powered — the state today's investigation lost by
//! power-cycling before asking. It does NOT survive a reset, so it cannot yet
//! answer "why did this unit come back from a customer locked". Persisting the
//! ring at lockout (the one moment already exceptional enough to justify a
//! flash write) is the follow-up; it needs a page decision, and CLAUDE.md is
//! deliberately restrictive about new flash state.
//!
//! ## Disclosure
//!
//! Reason codes and the pre-attempt counter value. No secret, no PIN material,
//! nothing derived from one.
//!
//! **This ships in production and is readable WITHOUT the PIN on a locked
//! device** — deliberately, because a log that disappears in production cannot
//! explain a shipped unit's lockout, which is its entire purpose. The exposure
//! is an owner decision tracked in #719; do not gate or ungate it here without
//! that decision.
//!
//! The failure-class discrimination it exposes is already public: every
//! `UNLOCK` returns a distinct status word per class (`PinIncorrect` ->
//! `SW_SECURITY_NOT_SATISFIED`, `PinLocked` -> `SW_CONDITIONS_NOT_SATISFIED`,
//! `InternalError` -> `SW_INTERNAL_ERROR`), per attempt and in real time, and
//! the trusted UI shows the same split on screen. So this grants an attacker
//! no new oracle — a status word beats a log for tuning a glitch.
//!
//! What IS new is *history*: a powered, locked device will tell an
//! unauthenticated peer roughly "unlocked three times recently, one wrong
//! PIN". That is an activity signal about the owner, not a key-recovery aid,
//! and being RAM-resident a seized powered-off device yields nothing.
//!
//! The ring logic is pure and lives here rather than beside the hardware so it
//! is exercised by host tests; a `#[cfg(test)]` module inside a target-only
//! file never runs (#708).

/// Why one `gated_unlock` call ended, from the attempt counter's point of view.
///
/// Values are a wire format — a returned unit's log is decoded by a host tool,
/// so they are assigned explicitly and must not be renumbered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AttemptReason {
    /// PIN correct, counter reset: net zero attempts consumed.
    OkReset = 0x01,
    /// PIN correct but `pin_attempts_reset` failed, so the pre-charged attempt
    /// stays burned. A repeat of this alone walks the counter to the lockout
    /// with the user entering the right PIN every time.
    OkResetFailed = 0x02,
    /// The secure element judged the PIN and rejected it. The burn is what the
    /// budget is for.
    PinIncorrect = 0x03,
    /// Short-circuited because the counter was already at `MAX_ATTEMPTS`.
    /// Nothing was burned and nothing was wiped on this path.
    AlreadyAtMax = 0x04,
    /// The pre-charge bump itself failed verification; the burn may or may not
    /// have landed.
    PrechargeFailed = 0x05,
    /// The SE leg failed before producing any verdict — transport, session, or
    /// a failed FI gate. The attempt is burned fail-closed even though the PIN
    /// was never judged, which is the drain path #715 capped.
    NoVerdict = 0x06,
    /// The two reads of the attempt counter disagreed (FI).
    CounterUnstable = 0x07,
    /// A duress PIN triggered the configured wipe.
    DuressWipe = 0x08,
}

/// One recorded outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub reason: AttemptReason,
    /// Counter value observed *before* this attempt, so a reader can see the
    /// budget being walked down rather than inferring it.
    pub pre_count: u8,
}

/// Entries retained. Sized above `MAX_ATTEMPTS` so a full lockout sequence
/// fits without the oldest — the most interesting — entry rotating out.
pub const LOG_CAPACITY: usize = 16;

const _: () = assert!(
    LOG_CAPACITY > sphincs_tz_shared::MAX_ATTEMPTS as usize,
    "a whole lockout sequence must fit, or the first cause is lost"
);

/// Serialised size: header + entries.
pub const SERIALISED_LEN: usize = 4 + LOG_CAPACITY * 2;

/// Fixed-capacity ring. Oldest entries drop first, and the number dropped is
/// reported so a reader never mistakes a truncated log for a complete one.
pub struct AttemptLog {
    entries: [Option<Entry>; LOG_CAPACITY],
    next: usize,
    len: usize,
    dropped: u16,
}

impl Default for AttemptLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AttemptLog {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [None; LOG_CAPACITY],
            next: 0,
            len: 0,
            dropped: 0,
        }
    }

    pub fn record(&mut self, reason: AttemptReason, pre_count: u8) {
        if self.entries[self.next].is_some() {
            self.dropped = self.dropped.saturating_add(1);
        } else {
            self.len += 1;
        }
        self.entries[self.next] = Some(Entry { reason, pre_count });
        self.next = (self.next + 1) % LOG_CAPACITY;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn dropped(&self) -> u16 {
        self.dropped
    }

    /// Entries oldest-first. A cause is only readable in order.
    pub fn iter_oldest_first(&self) -> impl Iterator<Item = Entry> + '_ {
        let start = if self.len < LOG_CAPACITY {
            0
        } else {
            self.next
        };
        (0..self.len).filter_map(move |i| self.entries[(start + i) % LOG_CAPACITY])
    }

    /// `[version, count, dropped_be16, (reason, pre_count) * count]`, zero
    /// padded to [`SERIALISED_LEN`] so the response is fixed-size.
    pub fn serialise(&self, out: &mut [u8; SERIALISED_LEN]) {
        *out = [0u8; SERIALISED_LEN];
        out[0] = 1; // format version
        out[1] = self.len as u8;
        out[2..4].copy_from_slice(&self.dropped.to_be_bytes());
        for (i, e) in self.iter_oldest_first().enumerate() {
            out[4 + i * 2] = e.reason as u8;
            out[4 + i * 2 + 1] = e.pre_count;
        }
    }
}

/// Process-wide log. Single-threaded secure world, same category as the other
/// `static mut` driver bookkeeping in the unsafe taxonomy.
static mut ATTEMPT_LOG: AttemptLog = AttemptLog::new();

/// Counter value seen by the in-flight attempt's pre-charge, so the outcome
/// arms — which run after the SE verdict and no longer have it in scope — can
/// record the value the budget actually stood at.
static mut PENDING_PRE_COUNT: u8 = 0;

/// Note the pre-charge counter for the attempt now in flight.
pub fn note_precharge(pre_count: u8) {
    // SAFETY: single-threaded secure world, not touched from an ISR.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDING_PRE_COUNT), pre_count);
    }
}

/// Record an outcome for the in-flight attempt, using the noted pre-charge.
pub fn record_outcome(reason: AttemptReason) {
    // SAFETY: as in `note_precharge`.
    let pre = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PENDING_PRE_COUNT)) };
    record(reason, pre);
}

/// Record why one `gated_unlock` call ended.
pub fn record(reason: AttemptReason, pre_count: u8) {
    // SAFETY: secure world is single-threaded and this is not touched from an
    // ISR; `addr_of_mut!` avoids forming a reference to the static.
    unsafe {
        (*core::ptr::addr_of_mut!(ATTEMPT_LOG)).record(reason, pre_count);
    }
}

/// Serialise the log for the read-only gateway command.
pub fn snapshot(out: &mut [u8; SERIALISED_LEN]) {
    // SAFETY: as in `record`; read-only access.
    unsafe {
        (*core::ptr::addr_of!(ATTEMPT_LOG)).serialise(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_records_in_order_with_the_counter_value() {
        let mut log = AttemptLog::new();
        log.record(AttemptReason::NoVerdict, 0);
        log.record(AttemptReason::NoVerdict, 1);
        log.record(AttemptReason::OkReset, 2);
        let mut got = [None; 4];
        for (i, e) in log.iter_oldest_first().enumerate() {
            got[i] = Some(e);
        }
        assert_eq!(log.len(), 3);
        assert_eq!(got[0].expect("first").reason, AttemptReason::NoVerdict);
        assert_eq!(got[0].expect("first").pre_count, 0);
        assert_eq!(got[2].expect("third").reason, AttemptReason::OkReset);
        assert_eq!(got[2].expect("third").pre_count, 2);
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn positive_a_full_lockout_sequence_fits_without_dropping() {
        // The whole point: if the ring were <= MAX_ATTEMPTS the FIRST burn —
        // the one that says what started it — would rotate out exactly when a
        // lockout makes it worth reading.
        let mut log = AttemptLog::new();
        for i in 0..sphincs_tz_shared::MAX_ATTEMPTS {
            log.record(AttemptReason::NoVerdict, i);
        }
        assert_eq!(log.dropped(), 0, "a full lockout must not lose its first cause");
        let first = log.iter_oldest_first().next().expect("entry");
        assert_eq!(first.pre_count, 0);
    }

    #[test]
    fn positive_overflow_reports_how_many_were_dropped() {
        let mut log = AttemptLog::new();
        for i in 0..(LOG_CAPACITY + 3) {
            log.record(AttemptReason::PinIncorrect, i as u8);
        }
        assert_eq!(log.len(), LOG_CAPACITY);
        assert_eq!(log.dropped(), 3, "a truncated log must say so");
        // Oldest retained is entry #3, not #0.
        assert_eq!(log.iter_oldest_first().next().expect("entry").pre_count, 3);
    }

    #[test]
    fn positive_serialised_layout_is_stable() {
        let mut log = AttemptLog::new();
        log.record(AttemptReason::OkResetFailed, 7);
        let mut out = [0u8; SERIALISED_LEN];
        log.serialise(&mut out);
        assert_eq!(out[0], 1, "format version");
        assert_eq!(out[1], 1, "count");
        assert_eq!(&out[2..4], &[0, 0], "dropped");
        assert_eq!(out[4], AttemptReason::OkResetFailed as u8);
        assert_eq!(out[5], 7, "pre-count travels with the reason");
        assert!(out[6..].iter().all(|&b| b == 0), "tail must be zero padded");
    }

    #[test]
    fn positive_reason_codes_are_a_stable_wire_format() {
        // A returned unit's log is decoded by a host tool. Renumbering these
        // silently re-labels every historical receipt.
        assert_eq!(AttemptReason::OkReset as u8, 0x01);
        assert_eq!(AttemptReason::OkResetFailed as u8, 0x02);
        assert_eq!(AttemptReason::PinIncorrect as u8, 0x03);
        assert_eq!(AttemptReason::AlreadyAtMax as u8, 0x04);
        assert_eq!(AttemptReason::PrechargeFailed as u8, 0x05);
        assert_eq!(AttemptReason::NoVerdict as u8, 0x06);
        assert_eq!(AttemptReason::CounterUnstable as u8, 0x07);
        assert_eq!(AttemptReason::DuressWipe as u8, 0x08);
    }
}
