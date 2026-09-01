//! Pure xorshift32 PRNG + reseed windowing for [`crate::hw::consumption_mask`].
//!
//! Split out of `hw/consumption_mask.rs` because that driver is target-only
//! (TIM2/PA5 MMIO), while this state machine is pure logic the host test
//! suite can — and must — exercise directly. Same pattern as
//! [`crate::rng_strong_fold`]. No MMIO and no `crate::rng` here: the caller
//! (SysTick ISR context) supplies the optional fresh seed, keeping the bus
//! rules (`rng_strong` is forbidden in ISR) at the call site.
//!
//! # Why xorshift32 is acceptable here
//!
//! The output physically drives the observable PA5 PWM duty; the goal is
//! only to decorrelate the power signature from die-internal crypto work.
//! Cryptographic strength is not required (see the `consumption_mask`
//! module header). Xorshift32 has period 2^32 − 1 and uniform output —
//! plenty for a duty-cycle jitter. Zero is never a valid state (the
//! sequence would stick at zero); [`Xorshift32::seed`] rejects it and
//! [`Xorshift32::advance`] skips an all-zero reseed.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// STATUS (2026-09-01): this module has NO production caller in the committed
// tree, so its tests below do NOT cover the PRNG the firmware actually runs.
// ---------------------------------------------------------------------------
//
// `hw/consumption_mask.rs` still carries its own inline `static mut PRNG_STATE`
// and a duplicate xorshift. The two implementations look equivalent, but the
// assurance is false: deleting the reseed or corrupting the shift in the LIVE
// driver leaves every test in this file green.
//
// How it got this way, since the state is odd on purpose: this file is a
// concurrent session's refactor. It was committed alone in e537e7cf because
// `main.rs` already declared `mod consumption_mask_prng;` and the branch could
// not build from a clean checkout without it; 4dee0b65 then reconstructed
// `hw/consumption_mask.rs` from HEAD's inline version so that commit would
// carry only its own board-port hunks. Net effect: the module is in, the call
// is not.
//
// Resolve by landing the driver side of that refactor (making the driver call
// `seed`/`advance` here) and deleting the inline duplicate — one commit, both
// halves. Until then, read these tests as covering a reference implementation,
// not the shipped one.

/// sca-1 (Trezor-port): re-seed period, in SysTick ticks (~1 s at 1 kHz).
pub(crate) const RESEED_PERIOD_TICKS: u32 = 1024;

/// The reseedable xorshift32 state machine, as a value so host tests can
/// run independent instances in parallel. Firmware uses the single static
/// [`PRNG`] via the free functions below. `Copy` so the free `advance` can
/// run the caller's seed closure with no `&mut` to the static outstanding.
#[derive(Copy, Clone)]
pub(crate) struct Xorshift32 {
    state: u32,
    reseed_ticks: u32,
}

impl Xorshift32 {
    pub(crate) const fn new() -> Self {
        Self {
            state: 0,
            reseed_ticks: 0,
        }
    }

    /// Seed the PRNG. Rejects 0 (xorshift would lock at zero; an all-zero
    /// TRNG draw is itself an RNG fault — finding F12).
    pub(crate) fn seed(&mut self, seed: u32) -> Result<(), ()> {
        if seed == 0 {
            return Err(());
        }
        self.state = seed;
        self.reseed_ticks = 0;
        Ok(())
    }

    /// One SysTick tick: window the reseed, then step the generator and
    /// return the fresh state.
    ///
    /// `reseed` is consulted only when the ~1 s window opens; it returns
    /// `Some(seed)` from the platform TRNG or `None` on a transient RNG
    /// error (fail-OPEN: keep the current state and retry next window —
    /// a transient TRNG error must never kill signing mid-run). An
    /// all-zero offer is skipped (xorshift must not seed to 0).
    pub(crate) fn advance(&mut self, mut reseed: impl FnMut() -> Option<u32>) -> u32 {
        self.reseed_ticks = self.reseed_ticks.wrapping_add(1);
        if self.reseed_ticks >= RESEED_PERIOD_TICKS {
            self.reseed_ticks = 0;
            if let Some(s) = reseed() {
                if s != 0 {
                    self.state = s;
                }
            }
        }
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }
}

/// Firmware's single PRNG instance. Seeded once at boot by
/// `consumption_mask::init`; advanced by `consumption_mask::randomize`
/// from the SysTick handler.
///
/// SAFETY protocol (unchanged from the pre-split driver): `init` is the
/// sole pre-`randomize` writer and runs single-threaded at boot; SysTick is
/// the sole `advance` caller in normal operation. A future additional caller
/// must ensure mutual exclusion — reentrancy is PROHIBITED (see `advance`).
static mut PRNG: Xorshift32 = Xorshift32::new();

/// Seed [`PRNG`]; see [`Xorshift32::seed`].
pub(crate) fn seed(seed: u32) -> Result<(), ()> {
    // SAFETY: sole pre-`advance` writer, single-threaded at boot; the
    // `&mut` never spans a caller-provided closure.
    unsafe { (*core::ptr::addr_of_mut!(PRNG)).seed(seed) }
}

/// Advance [`PRNG`] one tick; see [`Xorshift32::advance`].
pub(crate) fn advance(reseed: impl FnMut() -> Option<u32>) -> u32 {
    // SAFETY: SysTick is the sole caller in normal operation, and the
    // caller's seed closure is required NOT to re-enter this module
    // (the driver draws from `crate::rng::fill`, which never calls back).
    // The state is copied OUT before the closure runs, so even a prohibited
    // re-entrant call cannot alias a live `&mut` to the static: it would
    // only overwrite — and then be overwritten by — this call's stale
    // copy, i.e. a torn duty sequence, never `&mut` aliasing UB.
    let mut local = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PRNG)) };
    let x = local.advance(reseed);
    // SAFETY: sole writer in normal operation; volatile write-back keeps
    // the publication visible to the SysTick context.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(PRNG), local) };
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn xorshift_step(mut x: u32) -> u32 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    }

    #[test]
    fn positive_deterministic_sequence_from_seed() {
        let mut p = Xorshift32::new();
        p.seed(42).unwrap();
        let mut expect = 42u32;
        for _ in 0..64 {
            expect = xorshift_step(expect);
            assert_eq!(p.advance(|| None), expect);
        }
    }

    #[test]
    fn negative_zero_seed_rejected_and_state_kept() {
        let mut p = Xorshift32::new();
        p.seed(7).unwrap();
        assert!(p.seed(0).is_err());
        assert_eq!(p.advance(|| None), xorshift_step(7));
    }

    #[test]
    fn negative_advance_from_unseeded_state_stays_zero() {
        // Boot-failure posture is a caller-side panic (init); the generator
        // itself simply sticks at zero rather than inventing entropy.
        let mut p = Xorshift32::new();
        assert_eq!(p.advance(|| None), 0);
    }

    #[test]
    fn positive_reseed_fires_exactly_at_period() {
        let mut p = Xorshift32::new();
        p.seed(1).unwrap();
        let mut offers = 0u32;
        let mut window_return = 0u32;
        for tick in 1..=RESEED_PERIOD_TICKS {
            let r = p.advance(|| {
                offers += 1;
                Some(0xDEAD_BEEF)
            });
            if tick < RESEED_PERIOD_TICKS {
                assert_eq!(offers, 0, "reseed must not fire before the window");
            } else {
                window_return = r;
            }
        }
        assert_eq!(offers, 1, "reseed fires once at the window");
        // The fresh seed lands before the same tick's xorshift step.
        assert_eq!(window_return, xorshift_step(0xDEAD_BEEF));
        assert_eq!(p.advance(|| None), xorshift_step(window_return));
    }

    #[test]
    fn positive_transient_reseed_failure_keeps_state_and_retries_next_window() {
        let mut p = Xorshift32::new();
        p.seed(9).unwrap();
        let mut expect = 9u32;
        // A full period with the offer failing: pure stepping throughout
        // (the window at the end of it consumes the failed offer).
        for _ in 0..RESEED_PERIOD_TICKS {
            expect = xorshift_step(expect);
            assert_eq!(p.advance(|| None), expect);
        }
        // The next offer fires one full period later and lands before that
        // tick's step.
        for _ in 0..RESEED_PERIOD_TICKS - 1 {
            expect = xorshift_step(expect);
            assert_eq!(p.advance(|| None), expect);
        }
        let landed = p.advance(|| Some(1234));
        assert_eq!(landed, xorshift_step(1234));
        assert_eq!(p.advance(|| None), xorshift_step(landed));
    }

    #[test]
    fn negative_all_zero_reseed_offer_skipped() {
        let mut p = Xorshift32::new();
        p.seed(3).unwrap();
        let mut expect = 3u32;
        for _ in 0..RESEED_PERIOD_TICKS {
            expect = xorshift_step(expect);
            assert_eq!(p.advance(|| Some(0)), expect, "zero offer must not stick the state");
        }
    }

    #[test]
    fn positive_static_instance_seed_and_advance() {
        // Exercise the `static mut` wrapper protocol itself (this is the
        // only statics-touching test, so there is no intra-module race).
        seed(0xC0FF_EE01).unwrap();
        let first = advance(|| None);
        assert_eq!(first, xorshift_step(0xC0FF_EE01));
        assert!(seed(0).is_err());
        let second = advance(|| None);
        assert_eq!(second, xorshift_step(first));
        assert_ne!(first, second);
    }

    #[test]
    fn positive_seed_resets_the_reseed_window() {
        // A mid-period re-seed (e.g. a future re-init) must restart the
        // ~1 s window, not fire early on the stale tick count.
        let mut p = Xorshift32::new();
        p.seed(1).unwrap();
        for _ in 0..500 {
            p.advance(|| None);
        }
        p.seed(5).unwrap();
        let mut offers = 0u32;
        for _ in 0..RESEED_PERIOD_TICKS - 1 {
            p.advance(|| {
                offers += 1;
                Some(9)
            });
        }
        assert_eq!(offers, 0, "window must restart at re-seed, not inherit stale ticks");
        p.advance(|| {
            offers += 1;
            Some(9)
        });
        assert_eq!(offers, 1);
    }

    #[test]
    fn positive_reseed_fires_every_period_repeatedly() {
        let mut p = Xorshift32::new();
        p.seed(2).unwrap();
        let mut offers = 0u32;
        for _ in 0..3 * RESEED_PERIOD_TICKS {
            p.advance(|| {
                offers += 1;
                Some(0xAB)
            });
        }
        assert_eq!(offers, 3, "windows must recur every period, not latch");
    }

    #[test]
    fn positive_reseed_ticks_wrapping_add_from_max_does_not_fire() {
        // u32 wrap of the tick counter must roll to 0 (young), not fire a
        // spurious window — the counter is never reset by uptime alone.
        let mut p = Xorshift32 {
            state: 1,
            reseed_ticks: u32::MAX,
        };
        let mut offers = 0u32;
        let r = p.advance(|| {
            offers += 1;
            Some(9)
        });
        assert_eq!(offers, 0, "wrap must not manufacture a reseed window");
        assert_eq!(r, xorshift_step(1));
    }
}
