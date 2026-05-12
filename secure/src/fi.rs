//! Fault-injection countermeasures.
//!
//! Ported from Trezor's `core/embed/sec/random_delays/stm32/random_delays.c`
//! (the `wait_random()` double-invariant glitch sentinel) and the
//! `core/embed/sec/fwutils/` verify-then-check-sentinel pattern.
//!
//! ## What this module protects against
//!
//! A *single* clock/voltage glitch is the canonical low-cost FI attack on
//! an embedded secure boundary: slip past one `if`, one `return`, one
//! `memzero` call, and the rest of a signing/verify/zeroize flow runs
//! on stale or attacker-controlled state. Our first-line defences are:
//!
//! 1. **Double-check booleans with a sentinel.** `check_true_or_halt` evaluates
//!    the same condition twice and commits the answer to a `volatile` sentinel
//!    word. A glitch that skips one of the three check sites (first compare,
//!    second compare, sentinel verify) lands in the halt branch.
//! 2. **Random-length volatile loops at decision points.** `wait_random`
//!    is the exact Trezor `i + j == wait` invariant loop. A glitch that
//!    shifts `i` or `j` mid-loop is caught on the next iteration; a glitch
//!    that short-circuits the loop is caught on exit. See
//!    `/home/nicola/repos/trezor-firmware/core/embed/sec/random_delays/stm32/random_delays.c:186-202`.
//! 3. **Sentinel-word state machines.** `ok_sentinel` / `fail_sentinel` are
//!    fixed constants with maximally-hamming-distant bit patterns so a flipped
//!    bit can't silently turn FAIL into OK.
//!
//! ## Not-yet-implemented (Trezor has, PQSigner doesn't — yet)
//!
//! - Systimer-driven periodic RDI (random delay injection) between
//!   interrupt-exit and the next decision point. Trezor's
//!   `random_delays_start_rdi()` / `rdi_handler`; see same source file
//!   `:140-179`. Requires a systimer abstraction we don't have; track in a
//!   follow-up.
//! - DRBG reseed every N calls from HW RNG; we currently pull one
//!   random byte per `wait_random()` call directly from the TRNG, which
//!   is simpler but slower. Good enough for our call rate.
//! - consumption_mask PWM (power side-channel). Tracked separately.
//!
//! ## Calling convention
//!
//! Every public fn in this module is `#[inline(never)]` so a glitch
//! that skips the CALL instruction can be detected at the caller by
//! observing the return value / sentinel; inlining would fuse the check
//! into the caller and defeat that. The `#[cfg(feature = "e2e-test")]`
//! gate short-circuits `wait_random` to a deterministic no-op so
//! `make e2e` runs are stable — the FI hardening is only active on
//! production builds.

#![allow(dead_code)]

use zeroize::Zeroize;

/// A maximally-hamming-distant OK sentinel (binary `1010_0101_...`).
/// Paired with `FAIL_SENTINEL` — a single bit-flip cannot convert one
/// into the other.
pub const OK_SENTINEL: u32 = 0xA5A5_A5A5;

/// FAIL sentinel. Any value other than [`OK_SENTINEL`] is treated as
/// "abort"; this specific value is what we *set* on a detected failure
/// so that a subsequent check for OK matches cleanly on zero-filled RAM
/// (which would read 0 and also trip the halt).
pub const FAIL_SENTINEL: u32 = 0x5A5A_5A5A;

/// Volatile read barrier — forces the compiler to treat the value as if
/// it could change between reads, preventing fusion of adjacent checks.
#[inline(always)]
fn vread<T: Copy>(p: *const T) -> T {
    // SAFETY: caller provides a valid pointer to a stack-local `T`.
    unsafe { core::ptr::read_volatile(p) }
}

#[inline(always)]
fn vwrite<T>(p: *mut T, v: T) {
    // SAFETY: caller provides a valid pointer to a stack-local `T`.
    unsafe { core::ptr::write_volatile(p, v) }
}

/// Trezor's `wait_random()`, port of
/// `core/embed/sec/random_delays/stm32/random_delays.c:186-202`.
///
/// Generates a random-length volatile loop whose per-iteration invariant
/// (`i + j == wait`) is checked every cycle. Any glitch that skews `i`
/// or `j` by even one is caught before the loop exits; any glitch that
/// skips the loop entirely fails the post-loop `i == wait && j == 0`
/// check.
///
/// On the `e2e-test` feature (deterministic CI / QEMU), this is a no-op
/// so test timings don't drift. FI hardening is a production-build
/// concern; we're still bringing up the stack.
///
/// On panic / glitch detection: enters an infinite WFE loop. No return.
#[inline(never)]
pub fn wait_random() {
    #[cfg(feature = "e2e-test")]
    {
        return;
    }
    #[cfg(not(feature = "e2e-test"))]
    {
        // Pull a single random byte (0..=255) as the loop count.
        // Matches Trezor's `drbg_random8()`; we go straight to the
        // hardware TRNG for simplicity.
        #[cfg(not(test))]
        let wait = crate::rng::byte() as i32;
        #[cfg(test)]
        let wait: i32 = 7; // fixed under host tests

        let mut i_storage: i32 = 0;
        let mut j_storage: i32 = wait;

        let i_ptr = &mut i_storage as *mut i32;
        let j_ptr = &mut j_storage as *mut i32;

        loop {
            let i = vread(i_ptr);
            let j = vread(j_ptr);
            if i >= wait {
                break;
            }
            if i.wrapping_add(j) != wait {
                halt_on_glitch();
            }
            vwrite(i_ptr, i + 1);
            vwrite(j_ptr, j - 1);
        }

        // Double-check loop completion — catches a glitch that short-
        // circuits the `while` condition.
        if vread(i_ptr) != wait || vread(j_ptr) != 0 {
            halt_on_glitch();
        }
    }
}

/// Evaluate `cond` twice with a `wait_random()` delay between evaluations,
/// commit the verdict to a volatile sentinel, and compare the sentinel a
/// third time before returning.
///
/// **What this buys you (and what it doesn't).** It raises the cost of
/// flipping a `false` verdict into a `true` return from *one* instruction
/// skip to *several coordinated* faults — empirically (see
/// `tools/sca/fault_sweep_fi.py`): no single instruction-skip flips it, and
/// the `[skip,skip]` pair sweep (`--two-fault`) shows the only two-skip
/// route that lives *inside* this function is corrupting the result/return
/// path (the final `mov` of the verdict register / the fail-path zeroing) —
/// so the caller should also guard the *call site* (e.g. compare a
/// sentinel-encoded return rather than a bare `bool`, and double the
/// `if !verdict { err }` branch). The other two-skip routes all corrupt
/// **`cond` itself** (both evaluations) — this function does **not** protect
/// the computation that produces the boolean; that's the caller's `cond`
/// (in production a real `bl sphincs_c10::verify(...)` whose return is not
/// trivially forceable). A `stuck-at` on the return register likewise
/// defeats any `bool`-returning fn — the same residual.
///
/// Prefer [`check_true_into_sentinel`] at call sites that gate something
/// security-relevant: a `bool` return is one-skip / one-stuck-at away from
/// truthy at the *caller's* `if !verdict { … }` (skip the `bl`, the branch,
/// or stuck-at the return register); a `u32` sentinel return means a garbage
/// register is overwhelmingly `!= OK_SENTINEL`, so the caller's
/// `if verdict != OK_SENTINEL { … }` still takes the error path.
///
/// Typical use at a verify-before-release site:
///
/// ```ignore
/// if fi::check_true_into_sentinel(|| sphincs_c10::verify(pk, root, &msg, &sig))
///     != fi::OK_SENTINEL
/// {
///     return NscStatus::CryptoError as u32;
/// }
/// ```
///
/// The caller is still responsible for the zeroize / error branch; these fns
/// just make the `true` path expensive for an attacker to reach.
///
/// Returns the final verdict as a `bool`.
///
/// **Prefer [`check_true_into_sentinel`]** at sites that gate something
/// security-relevant: a `bool` return at the *caller's* `if !verdict { … }` is
/// only a stuck-at (or a skip of the `movne`/branch) away from truthy, whereas a
/// `u32` sentinel return means a garbage register is overwhelmingly
/// `!= OK_SENTINEL`, so the caller's `if verdict != OK_SENTINEL { … }` still
/// takes the error path. (We keep `check_true` standalone — not a wrapper over
/// `check_true_into_sentinel` — because the `== OK_SENTINEL → bool` reduction a
/// wrapper would add is itself a one-skip-to-truthy step.)
#[inline(never)]
pub fn check_true<F: FnMut() -> bool>(mut cond: F) -> bool {
    let v1 = cond();
    wait_random();
    let v2 = cond();
    let mut sentinel_storage: u32 = if v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    let sentinel_ptr = &mut sentinel_storage as *mut u32;
    wait_random();
    let s = vread(sentinel_ptr);
    // Hamming-safe triple: sentinel is OK AND both booleans were true.
    let result = s == OK_SENTINEL && v1 && v2;
    // Destructor scrub — prevents a stale sentinel from leaking to the
    // next stack frame.
    sentinel_storage.zeroize();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    result
}

/// Like [`check_true`] but returns the hamming-distant sentinel
/// [`OK_SENTINEL`] (verdict held) / [`FAIL_SENTINEL`] (otherwise) instead of a
/// `bool`. The caller compares `result != OK_SENTINEL` — a single fault on the
/// call (`bl`), the caller's branch, or a stuck-at on the return register then
/// almost certainly leaves a value `!= OK_SENTINEL` and so takes the error
/// path, rather than a 50/50-truthy `bool`. (Faults *inside* this fn — and
/// faults that corrupt `cond` itself, which this does not protect — still follow
/// the analysis in `tools/sca/fault_sweep_fi.py`: ~2 coordinated faults; see
/// Finding F-5 in `tools/sca/README.md`. Body is intentionally a near-copy of
/// [`check_true`] rather than a wrapper either way round — see that fn's note.)
#[inline(never)]
pub fn check_true_into_sentinel<F: FnMut() -> bool>(mut cond: F) -> u32 {
    let v1 = cond();
    wait_random();
    let v2 = cond();
    let mut sentinel_storage: u32 = if v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    let sentinel_ptr = &mut sentinel_storage as *mut u32;
    wait_random();
    let s = vread(sentinel_ptr);
    // Hamming-safe triple: sentinel is OK AND both booleans were true.
    let verdict = if s == OK_SENTINEL && v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    // Destructor scrub — prevents a stale sentinel from leaking to the
    // next stack frame.
    sentinel_storage.zeroize();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    verdict
}

/// Halt the CPU in a WFE loop. No return, no panic unwinding.
///
/// Called from the `wait_random` glitch paths. Do NOT print — a glitch
/// that corrupted state may produce misleading output. Just stop.
#[inline(never)]
fn halt_on_glitch() -> ! {
    #[cfg(not(test))]
    loop {
        cortex_m::asm::wfe();
    }
    #[cfg(test)]
    panic!("fi: glitch sentinel tripped (test-build panic)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_random_terminates_without_panic() {
        // Loop count is fixed at 7 in test builds; just verify it
        // completes without hitting the glitch halt.
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
        // 0xA5A5A5A5 ^ 0x5A5A5A5A = 0xFFFFFFFF → 32 bits flipped.
        // Guarantees no single-bit fault can convert OK into FAIL.
        assert_eq!(distance, 32);
    }
}
