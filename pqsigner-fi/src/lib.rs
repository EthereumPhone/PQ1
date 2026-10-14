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

/// Branchless map of a boolean verdict to the Hamming-distant sentinels:
/// `true → OK_SENTINEL`, `false → FAIL_SENTINEL`.
///
/// **F-29 hardening.** The obvious `if pass { OK_SENTINEL } else { FAIL_SENTINEL }`
/// compiles to a conditional/unconditional branch selecting between the two
/// constants — and an exhaustive `tools/sca` sweep showed a **single
/// instruction-skip of that branch flips a `false` verdict to `OK_SENTINEL`**
/// (the dangerous false→OK direction), defeating every value-gate that reads
/// the result. This form has **no branch**: the verdict is assembled from two
/// **independently** black-boxed masks, AND-ed for the OK term and OR-ed
/// (via De Morgan) for the FAIL term, so producing `OK_SENTINEL` from a
/// `false` input requires *both* masks to be all-ones — which a single fault
/// (skip of one mask compute → stale all-ones, or corruption of one mask)
/// cannot achieve, because the other mask is `0` and zeroes the OK term while
/// forcing the FAIL term. A glitch yields garbage that is `!= OK_SENTINEL`,
/// not a clean flip. (It does NOT make boolean→sentinel *unconditionally*
/// single-fault-proof — a stale-register coincidence on the final compose is
/// still possible; secret-RELEASE gates should additionally publish a
/// fail-initialized receipt from duplicated independent recomputation and
/// re-check it twice through volatile reads — the F-28-rework pattern, see
/// `tools/sca/README.md` §F-28. The legacy *infective-mask* pattern that
/// §F-28 once recommended was itself attacker-invertible — XOR-garbling with a
/// public mask returns `Ok` on a forgery and the attacker pre-complements the
/// payload — so it was removed 2026-08-03. But select_sentinel removes the
/// clean single-branch flip that was F-29's root.)
#[inline(always)]
fn select_sentinel(pass: bool) -> u32 {
    // Two independent recomputes of the all-ones/zero mask. `black_box` stops
    // LLVM from proving them equal and folding the AND/OR back into a branch.
    let m1 = (core::hint::black_box(pass) as u32).wrapping_neg(); // 0xFFFF_FFFF iff pass
    let m2 = (core::hint::black_box(pass) as u32).wrapping_neg();
    (m1 & m2 & OK_SENTINEL) | ((!m1 | !m2) & FAIL_SENTINEL)
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
#[must_use]
pub fn check_true<F: FnMut() -> bool, W: FnMut()>(mut cond: F, mut wait: W) -> bool {
    let v1 = cond();
    wait();
    let v2 = cond();
    // F-29: branchless verdict select (no skippable `if pass { OK } else { FAIL }`).
    let mut sentinel_storage: u32 = select_sentinel(v1 & v2);
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
#[must_use]
pub fn check_true_into_sentinel<F: FnMut() -> bool, W: FnMut()>(mut cond: F, mut wait: W) -> u32 {
    let v1 = cond();
    wait();
    let v2 = cond();
    // F-29: branchless verdict select (no skippable `if pass { OK } else { FAIL }`).
    let mut sentinel_storage: u32 = select_sentinel(v1 & v2);
    let sentinel_ptr = &mut sentinel_storage as *mut u32;
    wait();
    let s = vread(sentinel_ptr);
    let verdict = select_sentinel((s == OK_SENTINEL) & v1 & v2);
    sentinel_storage.zeroize();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    verdict
}

/// FI-hardened `min(a, b)` for length-clamping at security-critical
/// boundaries (USB control-transfer length checks, APDU reassembly,
/// HID frame size limits).
///
/// **Threat model.** Colin O'Flynn's USENIX WOOT 2019 EMFI attack
/// (`fault.io/ches2018.pdf` and follow-up WOOT'19) showed that a
/// single voltage/EM glitch on the conditional-branch instruction
/// of a `min(a, b)` can clamp the result to whichever input the
/// attacker chooses — effectively letting a hostile host punch
/// through a length cap and overflow a downstream buffer.
///
/// **Mitigation.** Compute `min` via the standard path, then verify
/// the result satisfies `r <= a && r <= b`. If the verification
/// trips (the glitched result exceeded one of the inputs), recompute
/// via the OTHER inequality — a glitch on the first branch can't
/// land identically on the second.
///
/// Per `docs/security/production-security.md` §2.4 "USB stack hardening
/// patterns" — same body as the reference implementation there.
#[inline]
#[must_use]
pub fn fi_min(a: usize, b: usize) -> usize {
    let r = if a < b { a } else { b };
    if r > a || r > b {
        // Single-fault glitch detected. Recompute via the *opposite*
        // branch direction so an attacker who landed the first fault
        // would also need to land an identically-shaped fault on this
        // recompute. The two inequalities are intentionally not the
        // same comparison: `a < b` vs `b <= a`.
        return if b <= a { b } else { a };
    }
    r
}

/// Halt the CPU in a WFE loop. No return, no panic unwinding.
///
/// Called from the `wait_random_loop` glitch paths. Do NOT print — a glitch
/// that corrupted state may produce misleading output. Just stop.
///
/// This silence is the DELIBERATE exception to the firmware's fatal-screen
/// policy (EthereumPhone/PQ1 #484: the secure-world `#[panic_handler]` draws
/// a best-effort RSOD after zeroizing). A glitch halt must not touch any
/// peripheral an attacker may control — the glitch that tripped the sentinel
/// may also own the display/SPI bus, so even the panic screen is too much
/// surface here. Just stop.
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

/// Pure decision table for the fixed-delay exemption (EthereumPhone/PQ1 #835).
///
/// `fi::wait_random` normally needs a fresh TRNG byte, but the RNG's own
/// conditioning sequence calls it while holding the driver lock during a reset
/// where no word can exist. That window is the one place a FIXED length is
/// permitted, and this is who may use it.
///
/// It lives in this crate rather than beside the state it reads, because that
/// state is in `secure/src/hw/rng.rs` (`stm32u585`-only, never compiled
/// host-side) and `secure/src/rng.rs` (`#[cfg(not(test))]`, excluded from host
/// test builds) — so branches kept in either could only be "tested" by
/// grepping their source text. Three tests written in those files during #835
/// silently never ran. This is the security-relevant logic, so it goes where
/// tests execute.
#[must_use]
pub fn fixed_delay_decision(
    init_done: bool,
    conditioning: bool,
    ctx_matches: bool,
    used: u32,
    cap: u32,
) -> bool {
    // Pre-init: no RNG exists yet, and no secret either. Every caller is
    // covered, including an interrupt — refusing here would halt the device
    // inside its own RNG bring-up.
    if !init_done {
        return true;
    }
    // Outside a conditioning window there is no excuse at all.
    if !conditioning {
        return false;
    }
    // CALLER CONFINEMENT: only the context that OPENED the window. A
    // preempting handler's delays have nothing to do with conditioning the
    // RNG, so it must not inherit the exemption and should poison its own
    // operation instead of running a known-constant gap.
    if !ctx_matches {
        return false;
    }
    // AND bounded by construction, not by observation. The measured "4 per
    // window" was a clean-path reading; the CRNGT publish loop adds delays per
    // failed compare-exchange, and Cortex-M clears the exclusive monitor
    // across exceptions.
    used < cap
}

/// Pure reading of the FI-hardened "RNG init completed" receipt (#835).
///
/// **Fail-closed in the direction that CLOSES the exemption.** The dangerous
/// reading is "init has not completed", because that keeps the fixed-delay
/// window open forever — so anything other than the exact intact PENDING
/// codeword counts as completed. A plain `AtomicBool` had the opposite
/// failure: a skipped publication left the window wide open while `init`
/// reported success.
#[must_use]
pub fn init_receipt_says_completed(val: u32, complement: u32, pending: u32) -> bool {
    !(val == pending && complement == !pending)
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
    fn check_true_into_sentinel_returns_ok_for_true() {
        assert_eq!(check_true_into_sentinel(|| true, fixed_wait), OK_SENTINEL);
    }

    #[test]
    fn check_true_into_sentinel_returns_fail_for_false() {
        assert_eq!(check_true_into_sentinel(|| false, fixed_wait), FAIL_SENTINEL);
    }

    #[test]
    fn sentinels_are_hamming_distant() {
        let distance = (OK_SENTINEL ^ FAIL_SENTINEL).count_ones();
        // 0xA5A5A5A5 ^ 0x5A5A5A5A = 0xFFFFFFFF → 32 bits flipped.
        // Guarantees no single-bit fault can convert OK into FAIL.
        assert_eq!(distance, 32);
    }

    #[test]
    fn fi_min_picks_smaller() {
        assert_eq!(fi_min(3, 7), 3);
        assert_eq!(fi_min(7, 3), 3);
        assert_eq!(fi_min(5, 5), 5);
        assert_eq!(fi_min(0, 100), 0);
        assert_eq!(fi_min(100, 0), 0);
    }

    #[test]
    fn fi_min_handles_extremes() {
        assert_eq!(fi_min(usize::MAX, 1), 1);
        assert_eq!(fi_min(1, usize::MAX), 1);
        assert_eq!(fi_min(usize::MAX, usize::MAX), usize::MAX);
    }
}

#[cfg(test)]
mod fixed_delay_tests {
    use super::{fixed_delay_decision, init_receipt_says_completed};

    const PENDING: u32 = 0x1555_5555;
    const DONE: u32 = 0x1AAA_AAAA;

    #[test]
    fn positive_the_exemption_table_is_exhaustively_as_specified() {
        // A LITERAL truth table over the whole boolean space, not a handful of
        // hand-picked rows. The first version of this test listed rows and
        // omitted the (true, true, false) one, so deleting the caller-
        // confinement branch left it GREEN — a test named "exhaustively" that
        // was not. Caught by a mutation control, not by reading it.
        //
        // The expectations are written out rather than computed, because an
        // expected-value formula here would just be a second copy of the
        // implementation and would agree with any change to it.
        const TABLE: &[(bool, bool, bool, bool)] = &[
            // init_done, conditioning, ctx_matches  ->  permitted (used < cap)
            (false, false, false, true), // pre-init covers everyone:
            (false, false, true, true),  //   no RNG exists yet, and refusing
            (false, true, false, true),  //   would halt the device inside its
            (false, true, true, true),   //   own bring-up
            (true, false, false, false), // post-init, no window: never
            (true, false, true, false),
            (true, true, false, false), // WRONG CONTEXT: never. A preempting
            //                             handler must not inherit it.
            (true, true, true, true), // the one permitted case
        ];
        for &(init_done, cond, ctx, expect) in TABLE {
            for &used in &[0u32, 1, 31] {
                assert_eq!(
                    fixed_delay_decision(init_done, cond, ctx, used, 32),
                    expect,
                    "row (init_done={init_done}, conditioning={cond}, \
                     ctx_matches={ctx}, used={used})"
                );
            }
        }

        // And the cap binds on the one row that is otherwise permitted.
        assert!(fixed_delay_decision(true, true, true, 31, 32));
        assert!(
            !fixed_delay_decision(true, true, true, 32, 32),
            "the cap must BIND: 'four per window' was an observation, and the \
             CRNGT publish loop can add delays per failed compare-exchange"
        );
        assert!(!fixed_delay_decision(true, true, true, 9999, 32));
    }

    #[test]
    fn negative_a_preempting_handler_cannot_inherit_the_exemption() {
        // The concrete trace from the review: thread mode opens a recovery
        // window, PendSV fires, and its `is_unlocked()` reaches wait_random.
        // Before confinement that handler got the fixed length for a delay
        // protecting PIN handling rather than RNG conditioning.
        assert!(
            !fixed_delay_decision(true, true, false, 0, 32),
            "a different context must refuse, so it poisons its own operation"
        );
    }

    #[test]
    fn negative_every_single_bit_corruption_of_the_receipt_closes_the_window() {
        // Intact PENDING is the ONLY state that keeps the exemption open.
        assert!(!init_receipt_says_completed(PENDING, !PENDING, PENDING));
        assert!(init_receipt_says_completed(DONE, !DONE, PENDING));

        for bit in 0..32 {
            let m = 1u32 << bit;
            assert!(
                init_receipt_says_completed(PENDING ^ m, !PENDING, PENDING),
                "a flipped value bit must CLOSE the window, never open it"
            );
            assert!(
                init_receipt_says_completed(PENDING, !PENDING ^ m, PENDING),
                "a flipped complement bit must CLOSE the window"
            );
        }
        // The exact failure the review named: a skipped publication.
        assert!(
            init_receipt_says_completed(DONE, !PENDING, PENDING),
            "value stored, complement skipped -> closed"
        );
        assert!(
            init_receipt_says_completed(PENDING, !DONE, PENDING),
            "complement stored, value skipped -> closed"
        );
    }
}
