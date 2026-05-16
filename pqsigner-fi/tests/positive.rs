//! Positive coverage for `pqsigner-fi` — golden-path behaviour of the
//! three public functions and the two sentinel constants.
//!
//! These tests live alongside the inline `#[cfg(test)] mod tests` at the
//! bottom of `src/lib.rs`. The inline suite already covers the most
//! basic golden paths (`TT → ok`, `FF → fail`, double-eval on
//! `check_true`, hamming distance). This file extends positive coverage
//! to the gaps: boundary RNG values, exhaustive RNG sweep, call-count
//! observation on the closures of both `check_true*` functions, and
//! exact-byte assertions on the sentinel constants.

use core::cell::Cell;
use pqsigner_fi::{OK_SENTINEL, FAIL_SENTINEL, check_true, check_true_into_sentinel, wait_random_loop};

/// A no-op wait. The `wait` closure passed to `check_true*` is allowed
/// to be any `FnMut()`, including one that does nothing — only the
/// sentinel/double-eval protocol matters for the function's contract.
fn noop_wait() {}

#[test]
fn positive_wait_random_loop_terminates_with_rng_zero() {
    // wait = 0 → loop body never executes; post-loop invariant
    // (i == 0, j == 0) trivially holds.
    wait_random_loop(|| 0);
}

#[test]
fn positive_wait_random_loop_terminates_with_rng_max() {
    // wait = 255 — the maximum possible loop length given the
    // documented "0..=255 inclusive" range. Catches any future change
    // that accidentally treats the rng byte as `i8` (would go negative
    // and the i < wait condition would behave oddly).
    wait_random_loop(|| 255);
}

#[test]
fn positive_wait_random_loop_exhaustive_rng_sweep() {
    // Every possible RNG byte must terminate without halting. This is
    // the strongest demonstration that the loop invariant
    // (`i + j == wait`) holds across the full input domain.
    for byte in 0u8..=255 {
        wait_random_loop(|| byte);
    }
}

#[test]
fn positive_wait_random_loop_consumes_exactly_one_rng_byte() {
    // wait_random_loop is documented to use ONE rng byte to choose the
    // loop length. Callers (secure-world TRNG, FSBL stub) wire this up
    // assuming a single byte is consumed per call — any future change
    // that consumes more would shift downstream RNG state.
    let count = Cell::new(0u32);
    wait_random_loop(|| {
        count.set(count.get() + 1);
        13
    });
    assert_eq!(count.get(), 1, "wait_random_loop must call rng_byte exactly once");
}

#[test]
fn positive_check_true_invokes_wait_twice() {
    // The Trezor invariant is "evaluate, delay, evaluate, delay, commit
    // sentinel, verify sentinel". Two wait() calls are the source of
    // the inter-check delay that defeats coordinated retiming. If a
    // refactor reduces this to one or zero calls the FI hardening
    // collapses.
    let wait_calls = Cell::new(0u32);
    let _ = check_true(|| true, || wait_calls.set(wait_calls.get() + 1));
    assert_eq!(wait_calls.get(), 2, "check_true must call wait exactly twice");
}

#[test]
fn positive_check_true_into_sentinel_invokes_wait_twice() {
    let wait_calls = Cell::new(0u32);
    let _ = check_true_into_sentinel(|| true, || wait_calls.set(wait_calls.get() + 1));
    assert_eq!(
        wait_calls.get(),
        2,
        "check_true_into_sentinel must call wait exactly twice"
    );
}

#[test]
fn positive_check_true_into_sentinel_double_evaluates() {
    // Parallel to the inline `check_true_double_evaluates` test, but
    // for the sentinel-returning variant. The body of
    // `check_true_into_sentinel` is intentionally a near-copy of
    // `check_true` (see the lib doc-comment on why a wrapper would
    // weaken the FI guarantee), so we want to lock in that the copy
    // preserves the double-eval property.
    let count = Cell::new(0u32);
    let result = check_true_into_sentinel(
        || {
            count.set(count.get() + 1);
            true
        },
        noop_wait,
    );
    assert_eq!(result, OK_SENTINEL);
    assert_eq!(
        count.get(),
        2,
        "check_true_into_sentinel must evaluate closure exactly twice"
    );
}

#[test]
fn positive_ok_sentinel_exact_value() {
    // `OK_SENTINEL` is observed by callers and possibly by hardware-
    // side assembly elsewhere. Pin the exact value so any rename or
    // re-derivation fails loudly.
    assert_eq!(OK_SENTINEL, 0xA5A5_A5A5_u32);
}

#[test]
fn positive_fail_sentinel_exact_value() {
    assert_eq!(FAIL_SENTINEL, 0x5A5A_5A5A_u32);
}

#[test]
fn positive_sentinel_bytes_little_endian() {
    // Spell out the byte layout so a future change to a hypothetical
    // big-endian / packed-struct serialization can't silently change
    // what bytes actually appear in memory.
    assert_eq!(OK_SENTINEL.to_le_bytes(), [0xA5, 0xA5, 0xA5, 0xA5]);
    assert_eq!(FAIL_SENTINEL.to_le_bytes(), [0x5A, 0x5A, 0x5A, 0x5A]);
}

#[test]
fn positive_check_true_with_noop_wait() {
    // The contract on `wait` is "any FnMut() — typically the random
    // wait loop, but doesn't have to be." Document that a no-op wait
    // is permissible and yields the same TT/FF semantics.
    assert!(check_true(|| true, noop_wait));
    assert!(!check_true(|| false, noop_wait));
}

#[test]
fn positive_check_true_into_sentinel_with_noop_wait() {
    assert_eq!(check_true_into_sentinel(|| true, noop_wait), OK_SENTINEL);
    assert_eq!(check_true_into_sentinel(|| false, noop_wait), FAIL_SENTINEL);
}
