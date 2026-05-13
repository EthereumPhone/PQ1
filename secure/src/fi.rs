//! Fault-injection countermeasures — secure-world bindings of the shared
//! `pqsigner-fi` crate.
//!
//! The actual hardening primitives (sentinels, double-check-with-volatile,
//! wait-random invariant loop) live in `pqsigner-fi`. This file is a thin
//! shim that supplies the secure-world's RNG (the STM32 TRNG) to the
//! generic `pqsigner_fi::wait_random_loop` and re-exports the same API the
//! rest of the secure crate has been calling: `OK_SENTINEL`, `FAIL_SENTINEL`,
//! `wait_random`, `check_true`, `check_true_into_sentinel`.
//!
//! Why a separate crate. FSBL (`fsbl/src/main.rs::filter_valid`) wants the
//! same hardening around its own `verify_signature` call (the F-7
//! defense-in-depth gap documented in `tools/sca/README.md` §F-7). FSBL is
//! a separate workspace member with its own deps; it can't pull in the
//! whole `secure` crate. Shared FI primitives → shared crate.
//!
//! See `pqsigner-fi/src/lib.rs` for the full hardening rationale.

#![allow(dead_code)]

// Re-export the sentinel constants verbatim (same numeric values; existing
// `crate::fi::OK_SENTINEL` etc. call sites keep working).
pub use pqsigner_fi::{FAIL_SENTINEL, OK_SENTINEL};

/// Returns one TRNG byte (production) or a fixed value (test / e2e-test).
/// The `pqsigner_fi::wait_random_loop` calls this to set its loop length.
#[inline(always)]
fn rng_byte() -> u8 {
    #[cfg(not(test))]
    {
        crate::rng::byte()
    }
    #[cfg(test)]
    {
        7
    }
}

/// Trezor's `wait_random()` (port of
/// `core/embed/sec/random_delays/stm32/random_delays.c:186-202`), specialized
/// to the secure-world TRNG. On `e2e-test` builds: no-op so test timings
/// don't drift.
///
/// `#[inline(never)]` so a glitch that skips the CALL is observable at the
/// caller; this remains true through the shim because we never inline this
/// fn into a caller AND `pqsigner_fi::wait_random_loop` is itself
/// `#[inline(never)]`.
#[inline(never)]
pub fn wait_random() {
    #[cfg(feature = "e2e-test")]
    {
        return;
    }
    #[cfg(not(feature = "e2e-test"))]
    {
        pqsigner_fi::wait_random_loop(rng_byte);
    }
}

/// Evaluate `cond` twice with a `wait_random()` delay between, commit the
/// verdict to a volatile sentinel, and re-check. See `pqsigner_fi::check_true`
/// for the full hardening rationale.
///
/// **Prefer [`check_true_into_sentinel`]** at sites that gate something
/// security-relevant: a `bool` return at the caller's `if !verdict { … }` is
/// only a stuck-at (or skip of the `movne`/branch) away from truthy. See
/// Finding F-5 in `tools/sca/README.md`.
#[inline(never)]
pub fn check_true<F: FnMut() -> bool>(cond: F) -> bool {
    pqsigner_fi::check_true(cond, wait_random)
}

/// Like [`check_true`] but returns [`OK_SENTINEL`] / [`FAIL_SENTINEL`]
/// instead of a `bool`. The caller compares `result != OK_SENTINEL` — a
/// garbage register value almost certainly takes the error path. See
/// `pqsigner_fi::check_true_into_sentinel` for full rationale.
#[inline(never)]
pub fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_random_terminates_without_panic() {
        wait_random();
    }

    #[test]
    fn check_true_returns_true_for_true_conditions() {
        assert!(check_true(|| true));
    }

    #[test]
    fn check_true_returns_false_for_false_conditions() {
        assert!(!check_true(|| false));
    }

    #[test]
    fn check_true_double_evaluates() {
        let mut count = 0;
        let result = check_true(|| {
            count += 1;
            true
        });
        assert!(result);
        assert_eq!(count, 2, "check_true must evaluate closure exactly twice");
    }

    #[test]
    fn sentinels_are_hamming_distant() {
        let distance = (OK_SENTINEL ^ FAIL_SENTINEL).count_ones();
        assert_eq!(distance, 32);
    }
}
