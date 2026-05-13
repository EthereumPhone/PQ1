//! Fault-injection (FI) hardening primitives — shared by `secure` and `fsbl`.
//!
//! Ported from Trezor's `core/embed/sec/random_delays/stm32/random_delays.c`
//! (the `wait_random()` double-invariant glitch sentinel) and the
//! `core/embed/sec/fwutils/` verify-then-check-sentinel pattern. Originally
//! lived as `secure/src/fi.rs`; extracted here so FSBL can use the same gate
//! around its own `verify_signature` call (closes the F-7 defense-in-depth
//! gap — see `tools/sca/README.md` §F-7 "Scope of the fix").
//!
//! ## What this module protects against
//!
//! A *single* clock/voltage glitch is the canonical low-cost FI attack on an
//! embedded secure boundary: slip past one `if`, one `return`, one `memzero`
//! call, and the rest of a signing/verify/zeroize flow runs on stale or
//! attacker-controlled state. First-line defences:
//!
//! 1. **Double-check booleans with a sentinel.** [`check_true_into_sentinel`]
//!    evaluates the same condition twice and commits the answer to a
//!    `volatile` sentinel word. A glitch that skips one of the three check
//!    sites (first compare, second compare, sentinel verify) lands in the
//!    halt branch.
//! 2. **Random-length volatile loops at decision points.** [`wait_random_loop`]
//!    is the exact Trezor `i + j == wait` invariant loop. A glitch that
//!    shifts `i` or `j` mid-loop is caught on the next iteration; a glitch
//!    that short-circuits the loop is caught on exit.
//! 3. **Sentinel-word state machines.** [`OK_SENTINEL`] / [`FAIL_SENTINEL`]
//!    are fixed constants with maximally-hamming-distant bit patterns so a
//!    flipped bit can't silently turn FAIL into OK.
//!
//! ## RNG dependency
//!
//! The wait-random loop needs a per-iteration byte. Production secure-world
//! uses the STM32 TRNG; FSBL doesn't have a TRNG online and currently uses
//! a deterministic fixed value. Either way the *invariant-checked loop*
//! catches glitches the same way; randomness only affects *attacker
//! retiming*. The closure-parametrized API ([`wait_random_loop`] takes
//! `FnMut() -> u8`) keeps both worlds working with a single shared
//! implementation.
//!
//! ## Calling convention
//!
//! Every public fn here is `#[inline(never)]` so a glitch that skips the
//! CALL instruction can be detected at the caller by observing the return
//! value / sentinel; inlining would fuse the check into the caller and
//! defeat that. Caller-side shims (e.g. `secure::fi::check_true_into_sentinel`)
//! that wrap these functions should also be `#[inline(never)]` for the same
//! reason.

#![no_std]
#![allow(dead_code)]

use zeroize::Zeroize;

/// A maximally-hamming-distant OK sentinel (binary `1010_0101_...`).
/// Paired with [`FAIL_SENTINEL`] — a single bit-flip cannot convert one
/// into the other.
pub const OK_SENTINEL: u32 = 0xA5A5_A5A5;

/// FAIL sentinel. Any value other than [`OK_SENTINEL`] is treated as
/// "abort"; this specific value is what we *set* on a detected failure
/// so that a subsequent check for OK matches cleanly on zero-filled RAM
/// (which would read 0 and also trip the halt).
pub const FAIL_SENTINEL: u32 = 0x5A5A_5A5A;

/// Volatile read barrier — forces the compiler to treat the value as if it
/// could change between reads, preventing fusion of adjacent checks.
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
/// (`i + j == wait`) is checked every cycle. Any glitch that skews `i` or
/// `j` by even one is caught before the loop exits; any glitch that skips
/// the loop entirely fails the post-loop `i == wait && j == 0` check.
///
/// The `rng_byte` callable supplies the loop length (0..=255 inclusive).
/// Production secure-world passes a TRNG-backed RNG; FSBL passes a
/// deterministic stub (the invariant check still works — only attacker
/// retiming benefits from randomness, and FSBL is small enough that the
/// retiming surface is much narrower than secure-world's signing flow).
///
/// On glitch detection: calls [`halt_on_glitch`] which enters an infinite
/// WFE loop. No return.
#[inline(never)]
pub fn wait_random_loop<R: FnMut() -> u8>(mut rng_byte: R) {
    let wait = rng_byte() as i32;
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

    // Double-check loop completion — catches a glitch that short-circuits
    // the `while` condition.
    if vread(i_ptr) != wait || vread(j_ptr) != 0 {
        halt_on_glitch();
    }
}

/// Evaluate `cond` twice with a `wait()` delay between evaluations, commit
/// the verdict to a volatile sentinel, and compare the sentinel a third
/// time before returning a `bool`.
///
/// **Prefer [`check_true_into_sentinel`]** at sites that gate something
/// security-relevant: a `bool` return is one-skip / one-stuck-at away from
/// truthy at the *caller's* `if !verdict { … }`; a `u32` sentinel return
/// means a garbage register is overwhelmingly `!= OK_SENTINEL`, so the
/// caller's `if verdict != OK_SENTINEL { … }` still takes the error path.
///
/// `wait` is typically [`wait_random_loop`] closed over the caller's RNG.
#[inline(never)]
pub fn check_true<F: FnMut() -> bool, W: FnMut()>(mut cond: F, mut wait: W) -> bool {
    let v1 = cond();
    wait();
    let v2 = cond();
    let mut sentinel_storage: u32 = if v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    let sentinel_ptr = &mut sentinel_storage as *mut u32;
    wait();
    let s = vread(sentinel_ptr);
    // Hamming-safe triple: sentinel is OK AND both booleans were true.
    let result = s == OK_SENTINEL && v1 && v2;
    sentinel_storage.zeroize();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    result
}

/// Like [`check_true`] but returns the hamming-distant sentinel
/// [`OK_SENTINEL`] / [`FAIL_SENTINEL`] instead of a `bool`. The caller
/// compares `result != OK_SENTINEL` — a single fault on the call (`bl`),
/// the caller's branch, or a stuck-at on the return register then almost
/// certainly leaves a value `!= OK_SENTINEL` and so takes the error path,
/// rather than a 50/50-truthy `bool`.
///
/// (Faults *inside* this fn — and faults that corrupt `cond` itself, which
/// this does not protect — still follow the analysis in
/// `tools/sca/fault_sweep_fi.py`: ~2 coordinated faults; see Finding F-5 in
/// `tools/sca/README.md`. Body is intentionally a near-copy of
/// [`check_true`] rather than a wrapper either way round — the
/// `== OK_SENTINEL → bool` reduction a wrapper would add is itself a
/// one-skip-to-truthy step.)
#[inline(never)]
pub fn check_true_into_sentinel<F: FnMut() -> bool, W: FnMut()>(mut cond: F, mut wait: W) -> u32 {
    let v1 = cond();
    wait();
    let v2 = cond();
    let mut sentinel_storage: u32 = if v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    let sentinel_ptr = &mut sentinel_storage as *mut u32;
    wait();
    let s = vread(sentinel_ptr);
    let verdict = if s == OK_SENTINEL && v1 && v2 { OK_SENTINEL } else { FAIL_SENTINEL };
    sentinel_storage.zeroize();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    verdict
}

/// Halt the CPU in a WFE loop. No return, no panic unwinding.
///
/// Called from the `wait_random_loop` glitch paths. Do NOT print — a glitch
/// that corrupted state may produce misleading output. Just stop.
#[inline(never)]
fn halt_on_glitch() -> ! {
    // cfg(target_arch = "arm") not cfg(test): downstream crates (secure,
    // fsbl) test against this module's host build, where `cfg(test)` is
    // set on the testing crate, NOT here. Cortex-M WFE is only available
    // when the build target is ARM.
    #[cfg(target_arch = "arm")]
    loop {
        cortex_m::asm::wfe();
    }
    #[cfg(not(target_arch = "arm"))]
    panic!("fi: glitch sentinel tripped (non-arm test-build panic)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_wait() {
        // wait_random_loop with a fixed RNG value — exercises the
        // invariant check without any nondeterminism.
        wait_random_loop(|| 7);
    }

    #[test]
    fn wait_random_terminates_without_panic() {
        fixed_wait();
    }

    #[test]
    fn check_true_returns_true_for_true_conditions() {
        assert!(check_true(|| true, fixed_wait));
    }

    #[test]
    fn check_true_returns_false_for_false_conditions() {
        assert!(!check_true(|| false, fixed_wait));
    }

    #[test]
    fn check_true_double_evaluates() {
        let mut count = 0;
        let result = check_true(
            || {
                count += 1;
                true
            },
            fixed_wait,
        );
        assert!(result);
        assert_eq!(count, 2, "check_true must evaluate closure exactly twice");
    }

    #[test]
    fn check_true_into_sentinel_returns_OK_for_true() {
        assert_eq!(check_true_into_sentinel(|| true, fixed_wait), OK_SENTINEL);
    }

    #[test]
    fn check_true_into_sentinel_returns_FAIL_for_false() {
        assert_eq!(check_true_into_sentinel(|| false, fixed_wait), FAIL_SENTINEL);
    }

    #[test]
    fn sentinels_are_hamming_distant() {
        let distance = (OK_SENTINEL ^ FAIL_SENTINEL).count_ones();
        // 0xA5A5A5A5 ^ 0x5A5A5A5A = 0xFFFFFFFF → 32 bits flipped.
        // Guarantees no single-bit fault can convert OK into FAIL.
        assert_eq!(distance, 32);
    }
}
