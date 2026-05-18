//! Negative coverage for `pqsigner-fi` — adversarial tests that lock
//! down the assumptions the FI-hardening primitives depend on.
//!
//! The whole point of this module is to **catch what a single glitch
//! can't**. Every test here names the assumption being attacked. If a
//! refactor breaks any one of these properties, the FI hardening is
//! silently weakened — and breakage of FI hardening doesn't show up in
//! a happy-path positive test, by construction. Read each test name
//! as: "the system must reject / refuse / prove ...".
//!
//! Families:
//!  - Boolean-pattern fuzz (TF / FT): one glitch on either evaluation
//!    of `cond` must produce the FAIL path, not the OK path.
//!  - No-short-circuit: even when `v1 == false`, the second evaluation
//!    AND both waits AND the sentinel write/read must still execute,
//!    so that a glitch on the first eval doesn't bypass the rest of
//!    the protocol.
//!  - Sentinel single-fault resistance: no single bit-flip on either
//!    sentinel can produce the other sentinel.
//!  - Sentinel stuck-at safety: common stuck-at register patterns
//!    (`0`, `0xFFFF_FFFF`, etc.) must NOT match `OK_SENTINEL`.
//!  - `wait_random_loop` invariant: exhaustive sweep over the rng-byte
//!    domain terminates without halting. Any future implementation
//!    change that breaks the `i + j == wait` invariant for some byte
//!    value would trip `halt_on_glitch`, which on host is a `panic!`,
//!    which would fail the test loudly.

use core::cell::Cell;
use pqsigner_fi::{OK_SENTINEL, FAIL_SENTINEL, check_true, check_true_into_sentinel, wait_random_loop};

fn noop_wait() {}

/// Builds a `cond` closure that returns the bools from `pattern` in
/// order. Panics if called more than `pattern.len()` times — a useful
/// negative property in its own right: `check_true*` must call `cond`
/// exactly twice, never more.
fn cond_sequence(pattern: &'static [bool]) -> impl FnMut() -> bool {
    let idx = Cell::new(0usize);
    move || {
        let i = idx.get();
        assert!(i < pattern.len(), "cond called more times than the pattern allows");
        idx.set(i + 1);
        pattern[i]
    }
}

// =========================================================================
// Boolean pattern fuzz — TF and FT must both be rejected.
//
// The whole point of double-evaluating `cond` is so that a glitch which
// flips ONE of the two evaluations is caught. Tests below simulate that
// glitch by having the cond closure deliberately return different
// values on its two calls.
// =========================================================================

#[test]
fn negative_check_true_tf_returns_false() {
    // Glitch model: first eval was true (correct), a fault flipped the
    // second eval to false. `check_true` MUST take the FAIL path
    // because v1 && v2 is false. This is the single most important
    // negative test in this file — it directly verifies the FI guard.
    let result = check_true(cond_sequence(&[true, false]), noop_wait);
    assert!(
        !result,
        "FI guard violation: check_true returned true when the two cond \
         evaluations disagreed (T then F). A glitch that flips one eval \
         must be caught — see pqsigner-fi/src/lib.rs check_true."
    );
}

#[test]
fn negative_check_true_ft_returns_false() {
    // Mirror image: first eval was glitched-to-false, second eval
    // recovered. Still must FAIL.
    let result = check_true(cond_sequence(&[false, true]), noop_wait);
    assert!(
        !result,
        "FI guard violation: check_true returned true when the two cond \
         evaluations disagreed (F then T)."
    );
}

#[test]
fn negative_check_true_into_sentinel_tf_returns_fail() {
    let result = check_true_into_sentinel(cond_sequence(&[true, false]), noop_wait);
    assert_eq!(
        result, FAIL_SENTINEL,
        "FI guard violation: check_true_into_sentinel returned OK_SENTINEL \
         when the two cond evaluations disagreed (T then F)."
    );
}

#[test]
fn negative_check_true_into_sentinel_ft_returns_fail() {
    let result = check_true_into_sentinel(cond_sequence(&[false, true]), noop_wait);
    assert_eq!(
        result, FAIL_SENTINEL,
        "FI guard violation: check_true_into_sentinel returned OK_SENTINEL \
         when the two cond evaluations disagreed (F then T)."
    );
}

// =========================================================================
// No-short-circuit on the first false.
//
// If a future refactor accidentally short-circuits — e.g. `if !v1 { return
// false; }` after the first eval — then a glitch that briefly causes
// v1=false would skip the second eval AND both waits AND the sentinel
// write/read, weakening the FI guarantee. Lock this in.
// =========================================================================

#[test]
fn negative_check_true_does_not_short_circuit_on_first_false() {
    let cond_calls = Cell::new(0u32);
    let wait_calls = Cell::new(0u32);
    let result = check_true(
        || {
            cond_calls.set(cond_calls.get() + 1);
            false
        },
        || wait_calls.set(wait_calls.get() + 1),
    );
    assert!(!result);
    assert_eq!(
        cond_calls.get(),
        2,
        "check_true must NOT short-circuit on first-false — both cond \
         evaluations must run so a glitch on either is caught."
    );
    assert_eq!(
        wait_calls.get(),
        2,
        "check_true must NOT short-circuit on first-false — both wait() \
         calls must run."
    );
}

#[test]
fn negative_check_true_into_sentinel_does_not_short_circuit_on_first_false() {
    let cond_calls = Cell::new(0u32);
    let wait_calls = Cell::new(0u32);
    let result = check_true_into_sentinel(
        || {
            cond_calls.set(cond_calls.get() + 1);
            false
        },
        || wait_calls.set(wait_calls.get() + 1),
    );
    assert_eq!(result, FAIL_SENTINEL);
    assert_eq!(
        cond_calls.get(),
        2,
        "check_true_into_sentinel must NOT short-circuit on first-false."
    );
    assert_eq!(
        wait_calls.get(),
        2,
        "check_true_into_sentinel must NOT short-circuit on first-false."
    );
}

// =========================================================================
// Sentinel single-fault resistance.
//
// The whole point of choosing 0xA5A5_A5A5 vs 0x5A5A_5A5A is that the
// hamming distance is 32, so no single-bit fault on a register holding
// one can produce the other. Prove it exhaustively.
// =========================================================================

#[test]
fn negative_no_single_bit_flip_of_ok_yields_fail() {
    for bit in 0..32 {
        let flipped = OK_SENTINEL ^ (1u32 << bit);
        assert_ne!(
            flipped, FAIL_SENTINEL,
            "Single-bit fault at position {bit} on OK_SENTINEL produced \
             FAIL_SENTINEL — sentinel hamming distance is broken."
        );
    }
}

#[test]
fn negative_no_single_bit_flip_of_fail_yields_ok() {
    for bit in 0..32 {
        let flipped = FAIL_SENTINEL ^ (1u32 << bit);
        assert_ne!(
            flipped, OK_SENTINEL,
            "Single-bit fault at position {bit} on FAIL_SENTINEL produced \
             OK_SENTINEL — sentinel hamming distance is broken."
        );
    }
}

#[test]
fn negative_no_single_bit_flip_of_ok_is_self() {
    // Trivially true (flipping any bit changes the value), but assert
    // it anyway to make the symmetry between OK and FAIL explicit.
    for bit in 0..32 {
        let flipped = OK_SENTINEL ^ (1u32 << bit);
        assert_ne!(flipped, OK_SENTINEL);
    }
}

#[test]
fn negative_no_two_bit_flip_collision_within_same_byte_lane() {
    // Stronger property: even a coordinated two-bit fault within a
    // single 8-bit lane cannot convert OK to FAIL. Since the bytes are
    // 0xA5 (1010_0101) vs 0x5A (0101_1010), every bit differs — two
    // flips inside one lane can move at most 2 of those 8 differing
    // bits, so the lane still differs in at least 6 bits, and the
    // resulting 32-bit value still differs from FAIL_SENTINEL.
    for lane in 0..4 {
        for bit_a in 0..8 {
            for bit_b in (bit_a + 1)..8 {
                let mask = (1u32 << (lane * 8 + bit_a)) | (1u32 << (lane * 8 + bit_b));
                assert_ne!(
                    OK_SENTINEL ^ mask,
                    FAIL_SENTINEL,
                    "Two-bit fault inside one byte lane converted OK to FAIL"
                );
            }
        }
    }
}

// =========================================================================
// Sentinel stuck-at safety.
//
// On a fault that drives a register to 0 (most common stuck-at), to
// all-ones, or to a recognisable RAM-init pattern, the caller's
// `if verdict != OK_SENTINEL { ... }` must still take the error path.
// =========================================================================

#[test]
fn negative_ok_sentinel_is_not_zero() {
    // Zero is the natural stuck-at value AND the contents of a register
    // a caller may have forgotten to initialise. If OK_SENTINEL were 0,
    // uninitialised callers would silently appear "verified".
    assert_ne!(OK_SENTINEL, 0);
    assert_ne!(FAIL_SENTINEL, 0);
}

#[test]
fn negative_ok_sentinel_is_not_all_ones() {
    // 0xFFFF_FFFF is the natural stuck-at-1 on a faulty bus, and also
    // the all-set ones-complement of zero. If OK_SENTINEL were
    // 0xFFFF_FFFF then a stuck-at-1 fault would impersonate OK.
    assert_ne!(OK_SENTINEL, 0xFFFF_FFFF);
    assert_ne!(FAIL_SENTINEL, 0xFFFF_FFFF);
}

#[test]
fn negative_ok_sentinel_is_not_common_uninit_patterns() {
    // Common debug-fill patterns that a tooling-introduced
    // uninitialised-memory read might surface. None of them should
    // equal OK_SENTINEL.
    for pattern in [
        0xDEAD_BEEF_u32,
        0xCAFE_BABE_u32,
        0xBAAD_F00D_u32,
        0xFEED_FACE_u32,
        0xABAB_ABAB_u32, // gcc heap-uninit fill
        0xCDCD_CDCD_u32, // MSVC heap-uninit fill
        0xCCCC_CCCC_u32, // MSVC stack-uninit fill
        0x0BAD_BAD0_u32,
    ] {
        assert_ne!(
            pattern, OK_SENTINEL,
            "OK_SENTINEL collides with common debug-fill pattern 0x{pattern:08X}"
        );
    }
}

#[test]
fn negative_sentinels_are_distinct() {
    // Belt-and-braces. If anyone ever defines FAIL == OK, the entire
    // sentinel protocol degenerates to "always OK".
    assert_ne!(OK_SENTINEL, FAIL_SENTINEL);
}

// =========================================================================
// wait_random_loop invariant.
//
// `halt_on_glitch` is a `panic!` on host builds, so any rng byte that
// violated the `i + j == wait` invariant or the post-loop sanity check
// would manifest as a test panic. Exhaustive sweep proves the loop is
// invariant-safe across the entire input domain.
// =========================================================================

#[test]
fn negative_wait_random_loop_invariant_holds_for_all_rng_bytes() {
    for byte in 0u8..=255 {
        // If any byte trips `halt_on_glitch`, the host build panics
        // with "fi: glitch sentinel tripped" and the test fails.
        wait_random_loop(|| byte);
    }
}

#[test]
fn negative_wait_random_loop_does_not_consume_extra_rng_bytes() {
    // Defensive: if a future refactor calls rng_byte() more than once
    // per call (e.g. "let me grab another byte for a second random
    // wait"), downstream RNG state assumptions in the secure-world
    // TRNG flow break. Lock the call count at exactly 1.
    let count = Cell::new(0u32);
    wait_random_loop(|| {
        count.set(count.get() + 1);
        42
    });
    assert_eq!(
        count.get(),
        1,
        "wait_random_loop consumed more than one rng byte — \
         downstream RNG-state assumptions may break."
    );
}

// =========================================================================
// Output domain of check_true_into_sentinel.
//
// The caller's contract is "compare against OK_SENTINEL; anything else
// is failure." A future bug that returns some third value would still
// fail at the caller (because != OK_SENTINEL), but would weaken the
// claim made in the docstring. Lock it in: only the two declared
// constants are ever returned.
// =========================================================================

#[test]
fn negative_check_true_into_sentinel_returns_only_declared_sentinels() {
    // Exhaust the four boolean-pattern inputs and assert the output is
    // exactly OK_SENTINEL or FAIL_SENTINEL — never any other value.
    for pattern in [
        &[true, true][..],
        &[true, false][..],
        &[false, true][..],
        &[false, false][..],
    ] {
        let owned: [bool; 2] = [pattern[0], pattern[1]];
        let idx = Cell::new(0usize);
        let cond = || {
            let i = idx.get();
            idx.set(i + 1);
            owned[i]
        };
        let result = check_true_into_sentinel(cond, noop_wait);
        assert!(
            result == OK_SENTINEL || result == FAIL_SENTINEL,
            "check_true_into_sentinel returned 0x{result:08X} — not a \
             declared sentinel. Caller's `if verdict != OK_SENTINEL` would \
             still reject this, but the docstring guarantees one of two \
             values."
        );
    }
}
