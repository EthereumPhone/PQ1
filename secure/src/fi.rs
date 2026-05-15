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

/// Belt-and-braces memory barrier after a `zeroize()` of a secret
/// buffer. Issue a `compiler_fence(SeqCst)` (forbids LLVM from
/// reordering loads/stores across the boundary) and an `asm::dsb()`
/// (forces the CPU to commit pending stores from the store buffer
/// to memory before subsequent operations).
///
/// **Why both.** The `zeroize` crate's `Zeroize::zeroize()` already
/// uses `write_volatile` (prevents dead-store elimination) and
/// `compiler_fence(SeqCst)` internally — so on a single-core
/// in-order CPU with no other bus masters, that's already
/// sufficient. The extra `dsb()` matters for two specific cases on
/// STM32U585:
///
///   1. **Subsequent peripheral access.** If the wiped buffer was
///      just consumed by the SHA / SAES / PKA accelerator (separate
///      AHB master), the next peripheral write needs to be ordered
///      after the zeroize commits. Without dsb, the store buffer
///      could hold the wiped bytes in flight while a peripheral
///      reads the still-non-zero memory.
///
///   2. **Asynchronous wipe interruption.** Idle-wipe runs from a
///      timer ISR; a panic handler runs after a fault. Either can
///      observe the secret state mid-function. dsb ensures every
///      preceding wipe is committed before the ISR / panic handler
///      runs.
///
/// **Cost.** `compiler_fence` emits zero instructions (it's a
/// compile-time barrier only). `dsb` is a single-cycle instruction
/// on Cortex-M33. Total: ~1 cycle per call site, ~53 sites in the
/// secret-path → ~53 cycles total per signing pass.
///
/// Use after every `zeroize()` of `master_secret`, `entropy`,
/// `half_o` / `half_e` / `full_entropy`, `pin`, `opt_rand_buf`,
/// `slot_master_entropy`, or any other 32-byte cryptographic
/// secret.
#[inline(always)]
pub fn zeroize_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    #[cfg(all(target_arch = "arm", not(test)))]
    cortex_m::asm::dsb();
}

/// **F-15.r1 defence.** Scrub the AAPCS return register (`r0` on
/// Cortex-M) to a known non-sentinel value, with a `wait_random()` to
/// frustrate clock-aligned glitch placement.
///
/// **The attack.** When two `check_true_into_sentinel` calls happen
/// in close succession with no intervening function call that returns
/// a value (e.g. when the closure body is fully inlined), `r0`
/// retains the `OK_SENTINEL` from the first call across to the
/// second. If the attacker skips the second `bl
/// check_true_into_sentinel` with a branch-skip glitch, the caller's
/// `cmp r0, #OK_SENTINEL` sees the *stale* `OK_SENTINEL` and the
/// gate is bypassed without any glitch on the sentinel function
/// itself.
///
/// **The fix.** Place this between paired sentinel callsites in the
/// same function:
///
/// ```ignore
/// if check_true_into_sentinel(|| cond_a()) != OK_SENTINEL { ... }
/// crate::fi::scrub_sentinel_register();
/// if check_true_into_sentinel(|| cond_b()) != OK_SENTINEL { ... }
/// ```
///
/// After this call, `r0` holds `0` (not `OK_SENTINEL`). A skip of
/// the next `bl` then sees `r0 == 0`, the `cmp` fails, the gate
/// rejects.
///
/// On host tests / non-ARM builds the call is a no-op (the stale-r0
/// attack is meaningless without ARM AAPCS register conventions).
#[inline(never)]
pub fn scrub_sentinel_register() {
    wait_random();
    #[cfg(all(target_arch = "arm", not(test)))]
    unsafe {
        // SAFETY: zero-clobber on the ARM AAPCS return register.
        // `out("r0") _` tells the compiler we're scribbling r0;
        // `nomem`/`nostack` are sound because we touch neither.
        core::arch::asm!("mov r0, #0", out("r0") _, options(nomem, nostack));
    }
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
