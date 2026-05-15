//! FSBL-side fault-injection hardening — thin shim over the shared
//! `pqsigner-fi` crate.
//!
//! Mirrors the pattern `secure/src/fi.rs` uses. The only meaningful
//! difference is the RNG source: secure-world has a TRNG (`crate::rng::byte`);
//! FSBL doesn't currently initialise the TRNG, so [`wait_random`] uses a
//! fixed loop length. This weakens the *attacker-retiming* defence — an
//! attacker who can produce one precisely-timed fault can produce a second
//! at the same relative offset without any new effort — but the *invariant
//! check inside the loop* still catches mid-loop glitches the same way.
//!
//! The overall bar for bypassing the FSBL gate stays at **2 coordinated
//! faults**: one on the inner verify, one on the caller's `!= OK_SENTINEL`
//! cmp+branch — same as the secure-world `verify_manifest` gate. Without
//! `wait_random` randomness, those two faults can share a single setup;
//! with TRNG (future), they need independent precise timing.
//!
//! Future: when FSBL initialises the STM32U585 TRNG peripheral, swap
//! [`rng_byte`] for a real TRNG read and the FSBL gate matches secure-world
//! exactly. Tracked: TRNG init is currently in `secure/src/hw/rng.rs` and
//! depends on RCC + the peripheral being clocked, which FSBL doesn't yet
//! do.

pub use pqsigner_fi::OK_SENTINEL;

/// FSBL has no TRNG online; return a non-zero fixed byte. The invariant
/// loop's per-iteration sanity check (`i + j == wait`) still defends
/// against mid-loop glitches; only attacker retiming is unaffected by the
/// constant.
#[inline(always)]
fn rng_byte() -> u8 {
    0x42
}

#[inline(never)]
fn wait_random() {
    pqsigner_fi::wait_random_loop(rng_byte);
}

/// Like `secure::fi::check_true_into_sentinel` — see `pqsigner-fi/src/lib.rs`
/// for the full hardening rationale and Finding F-5 in `tools/sca/README.md`
/// for the residual-fault analysis.
#[inline(never)]
pub fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}
