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

/// Read `*p` via three independent `read_volatile`s separated by
/// `compiler_fence(SeqCst)` barriers, and require all three to agree.
///
/// **Threat model.** A single-fault glitch on the load instruction
/// that brings `*p` into a register could clamp it to 0 / 0xFF /
/// some other attacker-chosen pattern. Reading three times with
/// fences between forces the attacker to glitch the same load
/// identically three times in succession — single-fault primitive
/// doesn't reach.
///
/// **Return semantics (fail-in).** `Ok(v)` iff all three reads
/// returned the same value (no glitch detected). `Err(())` if any
/// pair disagrees (glitch suspected; caller fail-closes).
///
/// **OR-based fail-in pattern.** When the caller uses the result to
/// gate "permission to proceed," the natural compose is:
///
/// ```ignore
/// match read_volatile_voted(p) {
///     Ok(v) if v.is_safe_value() => proceed,
///     _ => reject,  // disagreement OR unsafe value → fail closed
/// }
/// ```
///
/// **Why this is distinct from F-14's FihBool.** FihBool defends a
/// stored boolean via complement-pair *at rest*. This helper defends
/// any `Copy + Eq` value (u32, u64, address, …) via repeated *load*.
/// They compose: e.g., `read_volatile_voted` on a FihBool's `val`
/// field gives both the storage and load-register defenses.
///
/// `T: Copy + Eq` so the values can be compared after copy-by-value.
/// The pointer is `*const T` (read-only) — no concurrent writer
/// expected (the secure world is single-threaded and non-reentrant).
#[inline(never)]
pub fn read_volatile_voted<T: Copy + Eq>(p: *const T) -> Result<T, ()> {
    // SAFETY: caller provides a valid `T`-aligned pointer to memory
    // not being written by another context (the secure world is
    // single-threaded and non-reentrant — even ISRs that touch state
    // are gated by `HandlerGuard`).
    unsafe {
        let r1 = core::ptr::read_volatile(p);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let r2 = core::ptr::read_volatile(p);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let r3 = core::ptr::read_volatile(p);
        if r1 == r2 && r2 == r3 {
            Ok(r1)
        } else {
            Err(())
        }
    }
}

/// Control-flow-integrity step counter (§18 P0).
///
/// Each critical-path function bumps a running `u32` with a unique
/// per-step magic constant. At the end the function compares the
/// running total against the expected final value (computed at
/// compile time via [`cfi_expected!`] from the step magics).
///
/// **What it defends.** A glitch that skips one critical step (the
/// function call OR the `bump` that follows it) leaves the counter
/// short by exactly that magic. The final check fails. This catches
/// the "skip an entire function call" attack class — which the
/// existing F-2 sentinel pattern doesn't reach (F-2 hardens the
/// `if-branch` AFTER a function returns; CFI hardens the function
/// call itself being skipped).
///
/// **What it doesn't defend.** A multi-fault attack that writes the
/// expected value directly to the stack-resident counter (knowing
/// the stack layout and the compile-time expected constant) would
/// bypass — but that's a 2-fault primitive minimum.
///
/// **Composition.** [`check_into_sentinel`] returns a Hamming-distant
/// `OK_SENTINEL` or `FAIL_SENTINEL` so callers can use the same
/// `if cfi.check_into_sentinel(...) != OK_SENTINEL { reject }`
/// pattern as the rest of the F-2 sentinel-encoded gates. Volatile
/// reads/writes on the running accumulator prevent the compiler from
/// constant-folding the sum (which would defeat the check at the
/// IR level).
pub struct CfiCounter {
    accum: u32,
}

impl CfiCounter {
    /// Non-zero non-sentinel start value. Defends a stuck-at-zero
    /// fault on the counter initialisation — if `accum` reads back
    /// as 0 right after `new()`, the final check fails.
    pub const INIT_VALUE: u32 = 0x1357_2468;

    pub const fn new() -> Self {
        Self {
            accum: Self::INIT_VALUE,
        }
    }

    /// Add a per-step magic to the running counter. Volatile so LLVM
    /// can't constant-fold the sum at the IR level.
    #[inline(never)]
    pub fn bump(&mut self, magic: u32) {
        // SAFETY: `self` is a unique mutable borrow.
        unsafe {
            let cur = core::ptr::read_volatile(&self.accum);
            core::ptr::write_volatile(&mut self.accum, cur.wrapping_add(magic));
        }
    }

    /// Compare the running counter against the expected final value
    /// (compile-time sum of `INIT_VALUE` + every step magic). Returns
    /// `OK_SENTINEL` iff equal, `FAIL_SENTINEL` otherwise. Composes
    /// with the F-2 sentinel-comparison idiom at the caller.
    #[inline(never)]
    pub fn check_into_sentinel(&self, expected: u32) -> u32 {
        // SAFETY: `self` is a valid borrow.
        let cur = unsafe { core::ptr::read_volatile(&self.accum) };
        check_true_into_sentinel(|| cur == expected)
    }
}

impl Default for CfiCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile-time helper: sum the step magics with `wrapping_add` so
/// the result matches what [`CfiCounter::bump`]s will produce.
///
/// ```ignore
/// const STEP_A: u32 = 0xAA00_0001;
/// const STEP_B: u32 = 0xBB00_0002;
/// const EXPECTED: u32 = cfi_expected!(STEP_A, STEP_B);
/// ```
#[macro_export]
macro_rules! cfi_expected {
    ($($step:expr),+ $(,)?) => {
        $crate::fi::CfiCounter::INIT_VALUE
            $(.wrapping_add($step))+
    };
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
