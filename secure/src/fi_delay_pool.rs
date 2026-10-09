//! Pre-drawn fresh-TRNG pool for FI delay lengths (#832).
//!
//! # Why this exists
//!
//! `fi::wait_random()` is the separation between a receipt check and its
//! recheck throughout `hw::rng::fill_bound` — `if take_a == 0 { return }` /
//! `wait_random()` / `if take_b == 0 { return }` and six more of the same
//! shape. Its randomness is what turns "fault one check" into "fault two
//! checks at an unpredictable offset".
//!
//! `DriverGuard::try_acquire()?` is the first statement of `fill_bound`, so
//! every `wait_random` *inside* a fill used to lose the non-blocking race,
//! return `Err`, and replay `FI_DELAY_LAST_GOOD`. Each replay stored the same
//! byte back and no other context can win while thread mode holds the guard,
//! so all of them were provably the SAME length. Measured on silicon
//! (2026-10-09, #805): 32 calls and 31 fallbacks per top-level delay, which
//! made the burst self-revealing — measure the first delay, know the other
//! thirty — and the separation a known constant, in the function that produces
//! BIP-39 entropy, SE handshake keys and OptRand.
//!
//! # Why a pool rather than a DRBG
//!
//! The expensive part was never the TRNG, it was the recursion. `fill_bound`
//! already holds the guard with the peripheral live, so it can draw a handful
//! of extra words up front and let the inner delays consume those. Every byte
//! here is fresh hardware TRNG output: this is NOT a software PRNG and needs no
//! part of `CLAUDE.md`'s countermeasure-timing carve-out (#805).
//!
//! # Why it refills inside the loop
//!
//! The fan-out scales with the fill length — roughly three delays before the
//! per-word loop plus ~28 inside it — and `rng_strong::fill` passes the
//! caller's whole buffer straight through, so no fixed pool can cover every
//! call. [`replenish`] is therefore called once per output word as well as on
//! entry. It is idempotent and cheap: a top-up is a few `DR` reads against the
//! ~25 delay loops it serves: measured at 89 us of TRNG against 3.2 ms of
//! delay loops for a 64-byte fill, i.e. 2.7 %.
//!
//! # Failure direction
//!
//! Unarmed is the old behaviour, exactly. If the TRNG refuses (latched
//! seed/clock error) the pool simply never arms, `take` returns `None`, and
//! the caller falls back to `rng::byte_nonsecret` as before — no new failure
//! mode, no panic on a path whose whole rationale is availability. A `take`
//! that finds an ARMED pool empty is the one genuinely new degradation, and it
//! is counted in [`MISSES`] so the sizing can be measured rather than assumed
//! (`CLAUDE.md` condition (d): bounded, loud, documented, measured).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering::Relaxed};

/// Delays one pass of `fill_bound`'s per-output-word loop actually draws.
///
/// MEASURED on silicon, 2026-10-09, `evt-images/px832sweep`, by sweeping the
/// fill length and reading the largest single-fill pool draw:
///
/// ```text
///   len  1 B -> 31 draws        len 64 B -> 406 draws
///   =>   K(len) = 6 + 25 * ceil(len / 4)      (two-point fit)
/// ```
///
/// It could not be obtained by reading: the sites sit behind six helper
/// validators and three nested loops. The first version of this module put
/// `REFILL_BELOW` at 32 from an eyeball estimate of "~28", which left a margin
/// of 7 bytes — and had the estimate erred the other way, the pool would have
/// missed on every long fill and quietly degraded to the pre-#832 constant
/// separation on exactly the fills that produce secrets. [`MISSES`] would have
/// caught it, but the margin was luck. Hence a measured constant and a
/// deliberate multiple of it below.
pub const MEASURED_PER_WORD_FANOUT: usize = 25;

/// Bytes held at most.
pub const POOL_LEN: usize = 128;

/// Top up when fewer than this many bytes remain.
///
/// A top-up refills to [`POOL_LEN`], so the pool can only run dry if ONE loop
/// iteration consumes more than this threshold. That makes
/// `REFILL_BELOW >= MEASURED_PER_WORD_FANOUT` the correctness condition, and
/// the margin above it is the headroom for paths the sweep did not exercise —
/// the CRNGT `compare_exchange_weak` retry, a rejected word, an `init_locked`
/// recovery — each of which adds delays to a single iteration.
pub const REFILL_BELOW: usize = 64;

const _: () = assert!(
    REFILL_BELOW < POOL_LEN,
    "a refill threshold at or above the pool size would top up on every take"
);
const _: () = assert!(
    REFILL_BELOW >= 2 * MEASURED_PER_WORD_FANOUT,
    "the pool runs dry whenever one loop iteration draws more than REFILL_BELOW;      keep at least 2x the measured per-word fan-out so a retry path inside a      single iteration cannot silently reinstate the #832 constant separation"
);

static POOL: [AtomicU8; POOL_LEN] = [const { AtomicU8::new(0) }; POOL_LEN];

/// Valid bytes, consumed from the back. Also the sole concurrency control:
/// `take` claims a slot with one atomic decrement.
static AVAIL: AtomicUsize = AtomicUsize::new(0);

/// Set only while a holder of `DriverGuard` has words in the pool. Keeps a
/// top-level draw (pool not armed) distinguishable from an exhausted inner one.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Inner delays served a fresh pre-drawn TRNG byte.
pub static HITS: AtomicU32 = AtomicU32::new(0);

/// Inner delays that found the pool armed but empty, i.e. the per-output-word
/// top-up schedule did not keep up. Counted whether or not the in-place
/// top-up then recovered, so this stays a true sizing signal. Expected 0.
pub static MISSES: AtomicU32 = AtomicU32::new(0);

/// Run `f` with interrupts masked, so a refill cannot interleave with an
/// exception-context `take`.
#[inline]
fn critical<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(target_arch = "arm")]
    {
        cortex_m::interrupt::free(|_| f())
    }
    #[cfg(not(target_arch = "arm"))]
    {
        f()
    }
}

/// Take one fresh pre-drawn byte, or `None` to use the ordinary path.
///
/// `None` while unarmed is the normal top-level case and is not counted: the
/// caller is about to enter the fill that arms the pool.
pub fn take() -> Option<u8> {
    if !ARMED.load(Relaxed) {
        return None;
    }
    // One atomic claim. `checked_sub` makes an empty pool an `Err` rather than
    // a wrapped index, so a losing racer cannot read slot `usize::MAX`.
    match AVAIL.fetch_update(Relaxed, Relaxed, |n| n.checked_sub(1)) {
        Ok(n) => {
            HITS.fetch_add(1, Relaxed);
            // Clear on read: a consumed length never lingers in SRAM, and a
            // double-take would surface as a zero-length delay rather than a
            // silently reused one.
            Some(POOL[n - 1].swap(0, Relaxed))
        }
        Err(_) => {
            // Armed means a `DriverGuard` is held, which means the peripheral
            // is ours and live — so draw more right here rather than reporting
            // a shortfall. Without this, a sizing error or an unexpected retry
            // path inside one loop iteration would reach the #833 refusal and
            // halt the device over a shortage we can simply fix. Counted
            // either way, because a top-up here means the per-output-word
            // schedule did not keep up.
            MISSES.fetch_add(1, Relaxed);
            if refill_in_place() {
                if let Ok(n) = AVAIL.fetch_update(Relaxed, Relaxed, |n| n.checked_sub(1)) {
                    HITS.fetch_add(1, Relaxed);
                    return Some(POOL[n - 1].swap(0, Relaxed));
                }
            }
            None
        }
    }
}

/// Fill the pool from `word` if it has run low. Idempotent; call on entry to a
/// fill and once per output word.
///
/// `word` must not itself call [`crate::fi::wait_random`] — that is the
/// recursion this module exists to break.
pub fn replenish(mut word: impl FnMut() -> Option<u32>) {
    if ARMED.load(Relaxed) && AVAIL.load(Relaxed) >= REFILL_BELOW {
        return;
    }
    critical(|| {
        let mut n = AVAIL.load(Relaxed).min(POOL_LEN);
        while n + 4 <= POOL_LEN {
            let Some(w) = word() else { break };
            for b in w.to_le_bytes() {
                POOL[n].store(b, Relaxed);
                n += 1;
            }
        }
        AVAIL.store(n, Relaxed);
        if n > 0 {
            ARMED.store(true, Relaxed);
        }
    });
}

/// Last-resort top-up from inside [`take`], using the platform word source
/// directly. Safe because `ARMED` implies a held `DriverGuard`.
#[inline]
fn refill_in_place() -> bool {
    #[cfg(feature = "stm32u585")]
    {
        replenish(crate::hw::rng::delay_pool_word);
        AVAIL.load(Relaxed) > 0
    }
    #[cfg(not(feature = "stm32u585"))]
    {
        false
    }
}

/// Disarm and wipe. Called from `DriverGuard::drop`, before the busy flag is
/// released, so the pool is never armed outside a guard's lifetime.
pub fn disarm() {
    critical(|| {
        ARMED.store(false, Relaxed);
        AVAIL.store(0, Relaxed);
        for slot in &POOL {
            slot.store(0, Relaxed);
        }
    });
}

/// Test-only view of the pool state.
#[cfg(test)]
pub fn state_for_test() -> (bool, usize) {
    (ARMED.load(Relaxed), AVAIL.load(Relaxed))
}

/// Test-only view of the raw bytes, independent of `AVAIL`.
///
/// Needed because `ARMED`/`AVAIL`/`take()` all behave correctly while the
/// bytes are still sitting in SRAM — a mutation control proved the wipe was
/// unobservable without this.
#[cfg(test)]
pub fn raw_slots_for_test() -> [u8; POOL_LEN] {
    let mut out = [0u8; POOL_LEN];
    for (o, slot) in out.iter_mut().zip(POOL.iter()) {
        *o = slot.load(Relaxed);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool is process-global, and `cargo test` runs these concurrently.
    /// Without this every assertion below would race every other one, and the
    /// suite would be flaky in a way that reads as a real defect.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        disarm();
        HITS.store(0, Relaxed);
        MISSES.store(0, Relaxed);
        g
    }

    #[test]
    fn positive_an_unarmed_pool_defers_to_the_ordinary_path_without_counting_a_miss() {
        let _serial = reset();
        assert_eq!(take(), None, "an unarmed pool must defer");
        assert_eq!(
            MISSES.load(Relaxed),
            0,
            "a top-level draw is not a degradation and must not be counted as one"
        );
    }

    #[test]
    fn positive_every_byte_a_full_fan_out_needs_is_served_fresh_and_distinct_slots() {
        let _serial = reset();
        // 16 distinct words -> 64 distinct bytes.
        let mut next = 0u32;
        replenish(|| {
            next += 1;
            Some(u32::from_le_bytes([
                next as u8,
                (next as u8).wrapping_add(64),
                (next as u8).wrapping_add(128),
                (next as u8).wrapping_add(192),
            ]))
        });
        let (armed, avail) = state_for_test();
        assert!(armed, "words were supplied, so the pool must arm");
        assert_eq!(avail, POOL_LEN, "a full refill must fill the pool");

        // 31 is the measured per-top-level-delay fan-out (#805).
        let mut seen = [0u8; 31];
        for slot in &mut seen {
            *slot = take().expect("a replenished pool must serve the whole fan-out");
        }
        assert_eq!(HITS.load(Relaxed), 31);
        assert_eq!(MISSES.load(Relaxed), 0, "no miss within the pool's capacity");

        // THE defect this fixes: the old path returned one value 31 times.
        let first = seen[0];
        assert!(
            seen.iter().any(|&b| b != first),
            "all {} delays came back identical — that is exactly the constant \
             separation #832 is about, so the pool is not actually being drawn from",
            seen.len()
        );
    }

    #[test]
    fn negative_an_armed_but_empty_pool_counts_a_miss_and_defers() {
        let _serial = reset();
        let mut once = Some(0x0403_0201u32);
        replenish(|| once.take());
        for _ in 0..4 {
            assert!(take().is_some());
        }
        assert_eq!(take(), None, "an exhausted pool must defer, not wrap");
        assert_eq!(
            MISSES.load(Relaxed),
            1,
            "exhaustion is the one new degradation and must be loud"
        );
    }

    #[test]
    fn negative_a_refusing_trng_leaves_the_pool_unarmed_so_behaviour_is_unchanged() {
        let _serial = reset();
        replenish(|| None);
        let (armed, avail) = state_for_test();
        assert!(!armed, "no words means no arm — the old path must stay in force");
        assert_eq!(avail, 0);
        assert_eq!(take(), None);
        assert_eq!(
            MISSES.load(Relaxed),
            0,
            "a TRNG that refuses is not pool exhaustion and must not be counted as it"
        );
    }

    #[test]
    fn negative_disarm_wipes_the_pool_so_no_length_outlives_its_guard() {
        let _serial = reset();
        replenish(|| Some(0xDEAD_BEEF));
        assert!(
            raw_slots_for_test().iter().any(|&b| b != 0),
            "precondition: the pool must hold bytes before disarm is interesting"
        );
        disarm();
        let (armed, avail) = state_for_test();
        assert!(!armed);
        assert_eq!(avail, 0);
        assert_eq!(take(), None, "a disarmed pool must not serve");
        // The flags above all read correctly while the bytes are still in
        // SRAM, so assert on the bytes themselves.
        assert_eq!(
            raw_slots_for_test(),
            [0u8; POOL_LEN],
            "disarm left delay lengths in SRAM past their guard's lifetime"
        );
    }

    #[test]
    fn positive_replenish_tops_up_only_once_the_pool_has_run_low() {
        let _serial = reset();
        replenish(|| Some(0x0403_0201));

        // Probe strictly BETWEEN the threshold and capacity. A mutation
        // control showed that testing at full capacity proves nothing: the
        // `while n + 4 <= POOL_LEN` bound already blocks a draw there, so
        // deleting the early return left every test green. Here the bound
        // would happily draw, and only the threshold check stops it.
        let probe_at = REFILL_BELOW + 4;
        assert!(probe_at < POOL_LEN, "the probe must sit below capacity");
        for _ in 0..(POOL_LEN - probe_at) {
            assert!(take().is_some());
        }
        assert_eq!(state_for_test().1, probe_at);

        let mut calls = 0usize;
        replenish(|| {
            calls += 1;
            Some(0x0807_0605)
        });
        assert_eq!(
            calls, 0,
            "a pool still above the threshold must not re-draw — the top-up \
             runs once per output word and has to stay cheap"
        );

        for _ in 0..(probe_at - REFILL_BELOW + 1) {
            assert!(take().is_some());
        }
        replenish(|| {
            calls += 1;
            Some(0x0807_0605)
        });
        assert!(calls > 0, "below the threshold a top-up must actually happen");
    }
}
