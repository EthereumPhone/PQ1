//! Host-side positive + negative test suite for the `secure-fi-pin-rng`
//! slice.
//!
//! # Scope
//!
//! Eleven production files:
//!   * `secure/src/fi.rs`         — FI sentinels shim, `read_volatile_voted`,
//!                                  `CfiCounter`, `zeroize_barrier`,
//!                                  `scrub_sentinel_register`.
//!   * `secure/src/fih.rs`        — `FihBool` (val+complement, SEC_TRUE /
//!                                  SEC_FALSE Hamming-distant patterns,
//!                                  `is_true_fi`, `check_sentinel`).
//!   * `secure/src/fuzz_props.rs` — proptest harness for every NS→S
//!                                  parser (host-only).
//!   * `secure/src/host_rng.rs`   — semihosting `/dev/urandom` fill
//!                                  (QEMU-only; ARM-host-only at link
//!                                  level).
//!   * `secure/src/iso7816.rs`    — BER-TLV encode/decode + UPCTR
//!                                  `(current, limit)` parse.
//!   * `secure/src/pin.rs`        — MAC-and-Destroy PIN verify (used by
//!                                  the Mock backend; SE050 / OPTIGA
//!                                  PIN compare in silicon).
//!   * `secure/src/pin_diag.rs`   — GPIO pulse helper for OPTIGA
//!                                  hard-reset (ARM-only).
//!   * `secure/src/rng.rs`        — platform-agnostic TRNG facade.
//!   * `secure/src/rng_strong.rs` — multi-source TRNG fold with fail-
//!                                  closed all-zero acceptance gate.
//!   * `secure/src/sign_rate.rs`  — per-session sign rate limiter +
//!                                  burst cap (SCA defense).
//!   * `secure/src/timeout.rs`    — inactivity-timeout ticks /
//!                                  `is_idle` (S-only TIM).
//!
//! # Why this slice's negative tests matter
//!
//! Every file here either (a) defends a single fault-injection glitch
//! at a security gate, (b) is the *only* code that hashes user PIN
//! input into the brick path (`pin::verify_pin` on Mock backend), or
//! (c) is the only host-fuzzable defence against malformed NS-world
//! bytes reaching a parser. Silent regressions in any of these turn
//! "single-fault adversary needs hours of glitching" into "single-
//! fault adversary walks straight in." The negative coverage below
//! cites the assumption being defended in the failure message.
//!
//! ## Mounting strategy
//!
//! `fi`, `fih`, `iso7816`, `pin`, `sign_rate`, `fuzz_props` are
//! always-on or test-only at the crate root and need no remount. The
//! remaining five files are `#[cfg(not(test))]`-excluded because they
//! depend on hardware crates (`cortex_m`, `cortex_m_semihosting`) or
//! ARM-only externs (`crate::se_random`). For those we:
//!
//!   1. Re-mount `timeout.rs` under a local `#[path]` scaffold — it
//!      depends only on `core::sync::atomic` so it compiles on host
//!      and we can exercise the increment + idle-after-N-ticks paths
//!      with no production-code modification.
//!   2. Pin `rng`, `rng_strong`, `host_rng`, `pin_diag` via
//!      `include_str!` source-text invariants — the same pattern used
//!      by `main_sau_pure_tests.rs` and `fw_update_boot_pure_tests.rs`
//!      elsewhere in this crate. The pins encode the load-bearing
//!      contracts (delegation to the right backend per cfg, all-zero
//!      fail-closed gate in `rng_strong::fill`, no PE4 pulses in
//!      `pin_diag::run`, etc.) so a silent removal trips the suite.
//!
//! ## What the negative suite covers
//!
//! Each negative test names the assumption attacked + the security
//! property whose silent removal it would otherwise enable. Families
//! exercised here:
//!
//!   * **FI sentinel integrity** — Hamming distance, init non-zero,
//!     stale-bit-flip ≠ flip-to-OK, `check_true_into_sentinel`
//!     returns `FAIL_SENTINEL` on false.
//!   * **FihBool storage invariants** — bit-flipping `val` alone,
//!     bit-flipping `complement` alone, setting `val` to an out-of-
//!     pattern value all fail-close to `false`.
//!   * **ISO 7816-4 TLV parser robustness** — truncated long-form,
//!     unsupported `0x83`/`0x84` lengths, indefinite `0x80`, single-
//!     byte input, length-overflow attempts.
//!   * **PIN brick gating** — exactly-10-wrong wipes entropy,
//!     bricked-state re-entry returns `PinLocked`, correct PIN at
//!     attempt 9 resets the counter to 0 (not 10).
//!   * **Sign-rate cap monotonicity** — past-cap refuses, cap
//!     constants frozen, reset re-arms.
//!   * **Timeout monotonicity + wrap** — `tick` is monotonic on the
//!     same observer thread, `idle_for` handles the 49.7-day overflow.
//!   * **Source-text pins** — `rng_strong::fill` keeps the all-zero
//!     acceptance gate, `pin_diag::run` does NOT pulse PE4 (SE050
//!     ENA cross-coupling regression guard from the brick post-
//!     mortem), `rng` delegates by cfg, `host_rng` uses semihosting.

#![cfg(test)]

// ═════════════════════════════════════════════════════════════════════
// 0. Source-text fixtures for files that don't link on host.
// ═════════════════════════════════════════════════════════════════════

const FI_SRC: &str = include_str!("fi.rs");
const FIH_SRC: &str = include_str!("fih.rs");
const ISO7816_SRC: &str = include_str!("iso7816.rs");
const PIN_SRC: &str = include_str!("pin.rs");
const SIGN_RATE_SRC: &str = include_str!("sign_rate.rs");
const FUZZ_PROPS_SRC: &str = include_str!("fuzz_props.rs");
const HOST_RNG_SRC: &str = include_str!("host_rng.rs");
const RNG_SRC: &str = include_str!("rng.rs");
const RNG_STRONG_SRC: &str = include_str!("rng_strong.rs");
const PIN_DIAG_SRC: &str = include_str!("pin_diag.rs");
const TIMEOUT_SRC: &str = include_str!("timeout.rs");

// ═════════════════════════════════════════════════════════════════════
// 1. Re-mount `timeout.rs` under a host-test scaffold.
//
// Production `mod timeout` is `#[cfg(not(test))]`-excluded because
// `crate::timeout::tick()` is called from a SysTick ISR that doesn't
// exist on host. The module body itself is pure `core::sync::atomic`,
// so re-mounting it under `cfg(test)` is sound — and gives us a real
// instance to exercise `tick`/`reset_activity`/`is_idle` against.
//
// The scaffold's `TICKS` / `LAST_ACTIVITY` are *distinct* from any
// production globals: production never sees this remount because the
// remount is `#[cfg(test)]`.
// ═════════════════════════════════════════════════════════════════════

#[path = "timeout.rs"]
mod timeout_under_test;

// ═════════════════════════════════════════════════════════════════════
// 2. fi.rs — FI sentinels, CFI counter, voted volatile reads.
// ═════════════════════════════════════════════════════════════════════

mod fi_tests {
    use crate::fi::{
        check_true, check_true_into_sentinel, read_volatile_voted, scrub_sentinel_register,
        wait_random, zeroize_barrier, CfiCounter, FAIL_SENTINEL, OK_SENTINEL,
    };

    // ── positive coverage ────────────────────────────────────────────

    #[test]
    fn positive_wait_random_terminates_without_panic() {
        // wait_random in the secure shim uses fixed rng_byte()=7 in test
        // builds (the cfg-test arm in `secure/src/fi.rs`). It must
        // terminate every time without panicking — this is the
        // top-of-loop invariant that defends every later sentinel.
        wait_random();
    }

    #[test]
    fn positive_check_true_returns_true_for_true() {
        assert!(check_true(|| true));
    }

    #[test]
    fn positive_check_true_returns_false_for_false() {
        assert!(!check_true(|| false));
    }

    #[test]
    fn positive_check_true_into_sentinel_ok_for_true() {
        assert_eq!(check_true_into_sentinel(|| true), OK_SENTINEL);
    }

    #[test]
    fn positive_check_true_into_sentinel_fail_for_false() {
        assert_eq!(check_true_into_sentinel(|| false), FAIL_SENTINEL);
    }

    #[test]
    fn positive_zeroize_barrier_compiles_and_runs() {
        // Sanity — the barrier is a `compiler_fence` on host + a `dsb`
        // on ARM. It must be callable from test code without ICE.
        zeroize_barrier();
    }

    #[test]
    fn positive_scrub_sentinel_register_runs() {
        // No-op on non-ARM, but must still execute the wait_random()
        // inside it (which itself contains the invariant-checked loop).
        scrub_sentinel_register();
    }

    #[test]
    fn positive_read_volatile_voted_returns_value_when_stable() {
        let v: u32 = 0xDEAD_BEEF;
        let p: *const u32 = &v;
        match read_volatile_voted(p) {
            Ok(got) => assert_eq!(got, 0xDEAD_BEEF),
            Err(()) => panic!("stable in-memory value must triple-read agreeing"),
        }
    }

    #[test]
    fn positive_read_volatile_voted_works_on_various_widths() {
        let v8: u8 = 0xA5;
        assert_eq!(read_volatile_voted(&v8 as *const u8), Ok(0xA5));
        let v64: u64 = 0x0123_4567_89AB_CDEF;
        assert_eq!(
            read_volatile_voted(&v64 as *const u64),
            Ok(0x0123_4567_89AB_CDEF)
        );
    }

    #[test]
    fn positive_cfi_counter_init_and_check() {
        const STEP_A: u32 = 0xAA00_0001;
        const STEP_B: u32 = 0xBB00_0002;
        let mut cfi = CfiCounter::new();
        cfi.bump(STEP_A);
        cfi.bump(STEP_B);
        let expected = crate::cfi_expected!(STEP_A, STEP_B);
        assert_eq!(cfi.check_into_sentinel(expected), OK_SENTINEL);
    }

    #[test]
    fn positive_cfi_init_value_is_documented_constant() {
        // Defends the public contract that `INIT_VALUE` is non-zero
        // and not a sentinel — see fi.rs:182 (`Non-zero non-sentinel
        // start value. Defends a stuck-at-zero fault on the counter
        // initialisation`).
        assert_eq!(CfiCounter::INIT_VALUE, 0x1357_2468);
    }

    #[test]
    fn positive_cfi_expected_matches_init_plus_steps() {
        const STEP_A: u32 = 0x1111_2222;
        const STEP_B: u32 = 0x3333_4444;
        const STEP_C: u32 = 0x5555_6666;
        let expected = crate::cfi_expected!(STEP_A, STEP_B, STEP_C);
        let manual = CfiCounter::INIT_VALUE
            .wrapping_add(STEP_A)
            .wrapping_add(STEP_B)
            .wrapping_add(STEP_C);
        assert_eq!(expected, manual);
    }

    // ── negative coverage ────────────────────────────────────────────

    /// CFI counter without any bumps must NOT equal the expected
    /// value for a single bump. A glitch that skips the bl-to-`bump`
    /// for a critical step leaves the accumulator short — that's the
    /// whole point of CFI.
    #[test]
    fn negative_cfi_missing_bump_fails_check() {
        const STEP_A: u32 = 0xAA00_0001;
        let cfi = CfiCounter::new();
        // No bump call — simulates a glitch that skipped the BL.
        let expected = crate::cfi_expected!(STEP_A);
        assert_eq!(
            cfi.check_into_sentinel(expected),
            FAIL_SENTINEL,
            "CFI counter without the expected bump must FAIL: \
             if check_into_sentinel returned OK_SENTINEL here, a glitch \
             skipping a critical-path BL would be undetected (defeats §18 P0)."
        );
    }

    /// CFI counter with the WRONG step magic must fail — magics are
    /// per-step unique so the wrong-step-bumped case is detectable
    /// (defends a glitch that swaps two bumps).
    #[test]
    fn negative_cfi_wrong_step_magic_fails_check() {
        const STEP_A: u32 = 0xAA00_0001;
        const STEP_B: u32 = 0xBB00_0002;
        let mut cfi = CfiCounter::new();
        // Caller meant to bump A, glitch caused them to bump B instead.
        cfi.bump(STEP_B);
        let expected = crate::cfi_expected!(STEP_A);
        assert_eq!(
            cfi.check_into_sentinel(expected),
            FAIL_SENTINEL,
            "CFI counter with a wrong-step bump must fail — distinct \
             per-step magics defend against the swap-two-bumps attack."
        );
    }

    /// `INIT_VALUE` must not equal `OK_SENTINEL` or `FAIL_SENTINEL`
    /// to defend the "fresh-counter check before any bump" class of
    /// glitch. If `INIT_VALUE == OK_SENTINEL` then a counter that had
    /// every bump skipped would round-trip through
    /// `check_into_sentinel` as OK_SENTINEL even with `expected == 0`.
    #[test]
    fn negative_cfi_init_value_is_not_a_sentinel() {
        assert_ne!(
            CfiCounter::INIT_VALUE,
            OK_SENTINEL,
            "CFI INIT_VALUE coinciding with OK_SENTINEL would let a \
             skip-all-bumps glitch survive `check_into_sentinel`."
        );
        assert_ne!(
            CfiCounter::INIT_VALUE,
            FAIL_SENTINEL,
            "CFI INIT_VALUE coinciding with FAIL_SENTINEL would mask the \
             zero-init detection."
        );
        assert_ne!(
            CfiCounter::INIT_VALUE,
            0,
            "CFI INIT_VALUE must be non-zero to defend stuck-at-zero on \
             the field — see fi.rs:182."
        );
    }

    /// `OK_SENTINEL` and `FAIL_SENTINEL` must differ in every bit.
    /// This is the foundation of the F-2 sentinel pattern — a single
    /// bit-flip on a stored sentinel cannot turn FAIL into OK.
    #[test]
    fn negative_sentinels_are_maximally_hamming_distant() {
        let distance = (OK_SENTINEL ^ FAIL_SENTINEL).count_ones();
        assert_eq!(
            distance, 32,
            "OK and FAIL sentinels must differ in ALL 32 bits — a single \
             bit-flip must not turn FAIL into OK (this is the entire F-2 \
             contract)."
        );
    }

    /// Common attacker-clamp values (0 / 0xFFFF_FFFF) must NOT equal
    /// `OK_SENTINEL` — a stuck-at-zero or stuck-at-one on the return
    /// register must fall into the FAIL bucket at the caller.
    #[test]
    fn negative_common_glitch_clamps_are_not_ok_sentinel() {
        assert_ne!(OK_SENTINEL, 0, "stuck-at-0 must not look like OK");
        assert_ne!(
            OK_SENTINEL, 0xFFFF_FFFF,
            "stuck-at-FF must not look like OK"
        );
        assert_ne!(OK_SENTINEL, 0xDEAD_BEEF, "common debug pattern is not OK");
    }

    /// `check_true` evaluates its closure exactly twice — the F-2
    /// "double-check booleans" contract. A glitch on either evaluation
    /// is caught by the disagreement.
    #[test]
    fn negative_check_true_evaluates_closure_exactly_twice() {
        let mut count = 0u32;
        let _ = check_true(|| {
            count += 1;
            true
        });
        assert_eq!(
            count, 2,
            "check_true must double-evaluate — anything less and the \
             single-fault FI defense degrades to single-check (F-2)."
        );
    }

    /// `check_true` rejects when only ONE of the two evaluations is
    /// true (simulates a glitch that flips the second compare). The
    /// rejection happens via the AND-fold inside `pqsigner_fi::check_true`.
    #[test]
    fn negative_check_true_one_true_one_false_rejects() {
        let mut iter = 0;
        let result = check_true(|| {
            iter += 1;
            iter == 1 // true on first call, false on second
        });
        assert!(
            !result,
            "check_true must reject when its two evaluations disagree — \
             that disagreement IS the glitch-detection signal."
        );
    }

    /// `check_true_into_sentinel` returns `FAIL_SENTINEL` on
    /// disagreement (same single-fault test as above, sentinel form).
    #[test]
    fn negative_check_true_into_sentinel_disagreement_returns_fail() {
        let mut iter = 0;
        let s = check_true_into_sentinel(|| {
            iter += 1;
            iter == 1
        });
        assert_eq!(
            s, FAIL_SENTINEL,
            "check_true_into_sentinel must return FAIL_SENTINEL when the \
             two compares disagree — otherwise a glitch on either compare \
             slips through with OK_SENTINEL."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 3. fi.rs — source-text invariants (no host way to assert
//    `#[inline(never)]` survives the build).
// ═════════════════════════════════════════════════════════════════════

mod fi_source_text {
    use super::FI_SRC;

    /// `check_true`, `check_true_into_sentinel`, `read_volatile_voted`,
    /// `CfiCounter::bump`, `CfiCounter::check_into_sentinel`,
    /// `scrub_sentinel_register` MUST be `#[inline(never)]` so a glitch
    /// that skips the `bl` instruction is observable at the caller. If
    /// LLVM inlined these into callers, the BL-skip class is gone.
    #[test]
    fn negative_critical_fns_keep_inline_never() {
        let must_be_inline_never = [
            "pub fn check_true<",
            "pub fn check_true_into_sentinel<",
            "pub fn read_volatile_voted<",
            "pub fn bump(",
            "pub fn check_into_sentinel(",
            "pub fn scrub_sentinel_register()",
        ];
        for sig in must_be_inline_never {
            let pos = FI_SRC
                .find(sig)
                .unwrap_or_else(|| panic!("signature `{sig}` not found in fi.rs"));
            // Walk back ~200 bytes from the signature to find the
            // attributes attached to it.
            let start = pos.saturating_sub(300);
            let window = &FI_SRC[start..pos];
            assert!(
                window.contains("#[inline(never)]"),
                "`{sig}` must carry `#[inline(never)]` — inlining defeats \
                 the BL-skip detection that all caller-side FI checks rely on."
            );
        }
    }

    /// `read_volatile_voted` must triple-read the same pointer with
    /// `compiler_fence(SeqCst)` between the reads (otherwise LLVM can
    /// CSE the loads and the triple-read becomes a single read).
    #[test]
    fn negative_read_volatile_voted_keeps_fences() {
        let body_start = FI_SRC
            .find("pub fn read_volatile_voted<")
            .expect("read_volatile_voted not found");
        let body = &FI_SRC[body_start..body_start + 1200];
        let reads = body.matches("read_volatile(p)").count();
        assert_eq!(
            reads, 3,
            "read_volatile_voted must perform exactly 3 reads to detect \
             single-fault glitches on the load instruction (anything <3 \
             is statistically unable to detect a single glitch)."
        );
        let fences = body
            .matches("compiler_fence(core::sync::atomic::Ordering::SeqCst)")
            .count();
        assert!(
            fences >= 2,
            "read_volatile_voted must place SeqCst fences between the \
             three reads — without fences LLVM can CSE adjacent volatile \
             loads despite the volatile marker on the pointer."
        );
    }

    /// `zeroize_barrier` must include the ARM-only `dsb` so a wipe
    /// before a peripheral DMA or before a panic-handler ISR commits
    /// the zeroed bytes from the store buffer to memory.
    #[test]
    fn negative_zeroize_barrier_keeps_dsb_on_arm() {
        let pos = FI_SRC
            .find("pub fn zeroize_barrier()")
            .expect("zeroize_barrier not found");
        let body = &FI_SRC[pos..pos + 500];
        assert!(
            body.contains("compiler_fence(core::sync::atomic::Ordering::SeqCst)"),
            "zeroize_barrier must use SeqCst compiler_fence (host + ARM)"
        );
        assert!(
            body.contains("cortex_m::asm::dsb()"),
            "zeroize_barrier must emit a `dsb` on ARM to flush the store \
             buffer before a subsequent peripheral access or ISR — see \
             fi.rs:240 for the threat model."
        );
        // The cfg gate prevents the dsb from compiling on host.
        assert!(
            body.contains("cfg(all(target_arch = \"arm\", not(test)))"),
            "zeroize_barrier's `dsb` must be ARM-only (otherwise host \
             builds fail to compile)."
        );
    }

    /// `wait_random` is the central FI delay — it MUST be a no-op on
    /// `e2e-test` builds (otherwise the QEMU e2e harness's ~30 signs
    /// take a minute+ instead of seconds) and MUST call the shared
    /// `pqsigner_fi::wait_random_loop` on production builds.
    #[test]
    fn negative_wait_random_delegates_to_shared_crate_on_prod() {
        let pos = FI_SRC
            .find("pub fn wait_random()")
            .expect("wait_random not found");
        let body = &FI_SRC[pos..pos + 500];
        assert!(
            body.contains("cfg(feature = \"e2e-test\")"),
            "wait_random must short-circuit on e2e-test builds (timing-only \
             skip, no security impact under e2e since the chip is not under \
             attack)."
        );
        assert!(
            body.contains("pqsigner_fi::wait_random_loop(rng_byte)"),
            "production wait_random must delegate to the shared `pqsigner_fi` \
             crate's loop — that's the same invariant-checked loop FSBL \
             uses, and it must stay singular to be auditable."
        );
    }

    /// `rng_byte` must use `crate::rng::byte()` (platform-only TRNG),
    /// NOT `rng_strong::byte()`. wait_random is called ~thousands per
    /// signature; routing through `rng_strong` would add ~1000+ SE
    /// round-trips per sign and stretch latency from ~1.5s to minutes.
    /// See fi.rs:30-37 for the rationale.
    #[test]
    fn negative_rng_byte_does_not_route_through_rng_strong() {
        // Focus on the production-code arm of rng_byte() — comments
        // elsewhere in fi.rs MAY mention rng_strong by name (as the
        // rationale block does), so we restrict the check to the
        // function body.
        let pos = FI_SRC.find("fn rng_byte() -> u8").expect("rng_byte not found");
        let end = FI_SRC[pos..]
            .find("\n}\n")
            .map(|i| pos + i + 2)
            .unwrap_or(FI_SRC.len());
        let body = &FI_SRC[pos..end.min(FI_SRC.len())];
        assert!(
            body.contains("crate::rng::byte()"),
            "fi::rng_byte body must call platform-only `crate::rng::byte()` \
             — see fi.rs:30-37 for why rng_strong would explode sign latency."
        );
        assert!(
            !body.contains("rng_strong::byte") && !body.contains("rng_strong::fill"),
            "fi::rng_byte body must NOT route through rng_strong (sign-\
             latency cliff: see fi.rs:30-37)."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 4. fih.rs — FihBool storage + pattern invariants.
// ═════════════════════════════════════════════════════════════════════

mod fih_tests {
    use crate::fi::{FAIL_SENTINEL, OK_SENTINEL};
    use crate::fih::FihBool;

    // ── positive coverage ────────────────────────────────────────────

    #[test]
    fn positive_new_false_reads_false() {
        let f = FihBool::new_false();
        assert!(!f.is_true());
        assert!(!f.is_true_fi());
    }

    #[test]
    fn positive_set_true_then_is_true() {
        let mut f = FihBool::new_false();
        f.set_true();
        assert!(f.is_true());
        assert!(f.is_true_fi());
    }

    #[test]
    fn positive_set_false_after_set_true() {
        let mut f = FihBool::new_false();
        f.set_true();
        f.set_false();
        assert!(!f.is_true());
        assert!(!f.is_true_fi());
    }

    #[test]
    fn positive_check_sentinel_returns_ok_when_true() {
        let mut f = FihBool::new_false();
        f.set_true();
        assert_eq!(f.check_sentinel(), OK_SENTINEL);
    }

    #[test]
    fn positive_check_sentinel_returns_fail_when_false() {
        let f = FihBool::new_false();
        assert_eq!(f.check_sentinel(), FAIL_SENTINEL);
    }

    // ── negative coverage: forge storage faults ──────────────────────

    /// FihBool's storage invariant is `val ^ complement == 0xFFFFFFFF`.
    /// A single bit-flip in `val` (without a matching flip in
    /// `complement`) MUST be detected. Forge that fault by transmuting
    /// the struct into its raw `[u32; 2]` layout and flipping one bit
    /// in `val`, then assert `is_true` returns false.
    #[test]
    fn negative_corrupting_val_alone_fail_closes() {
        let mut f = FihBool::new_false();
        f.set_true();
        assert!(f.is_true(), "precondition: must read true");

        // SAFETY: FihBool is `#[repr(C)]` { val: u32, complement: u32 },
        // and we hold &mut. Flip the LSB of `val`.
        let raw: *mut u32 = (&mut f) as *mut FihBool as *mut u32;
        unsafe {
            let v = core::ptr::read_volatile(raw);
            core::ptr::write_volatile(raw, v ^ 1);
        }

        assert!(
            !f.is_true(),
            "FihBool::is_true must return false when val^complement \
             invariant is broken — otherwise a single bit-flip in SRAM \
             on the `val` word silently turns FALSE-stored values into \
             TRUE at the caller (defeats FI defense class 1)."
        );
        assert!(
            !f.is_true_fi(),
            "is_true_fi must also detect storage corruption (it composes \
             two is_true calls; if one returned true on a broken \
             invariant, the whole gate is bypassed)."
        );
    }

    /// Same attack on the `complement` field — a single bit-flip in
    /// `complement` alone must trip the invariant check.
    #[test]
    fn negative_corrupting_complement_alone_fail_closes() {
        let mut f = FihBool::new_false();
        f.set_true();
        assert!(f.is_true());

        let raw: *mut u32 = (&mut f) as *mut FihBool as *mut u32;
        // SAFETY: as above; offset 1 (one u32) for `complement`.
        unsafe {
            let c_ptr = raw.add(1);
            let c = core::ptr::read_volatile(c_ptr);
            core::ptr::write_volatile(c_ptr, c ^ 0x4000_0000);
        }

        assert!(
            !f.is_true(),
            "FihBool::is_true must return false when `complement` is \
             corrupted independently of `val`."
        );
    }

    /// Setting `val` to a value other than SEC_TRUE / SEC_FALSE (with
    /// `complement` chosen to maintain the XOR invariant) MUST still
    /// fail-close to false — the pattern invariant catches it. This
    /// defends a fault that lands a non-sentinel pattern in `val` while
    /// somehow preserving the XOR (e.g., a coordinated double-fault on
    /// both words — the storage-invariant check would pass, but the
    /// pattern check still rejects).
    #[test]
    fn negative_out_of_pattern_val_fail_closes() {
        let mut f = FihBool::new_false();
        f.set_true();

        let raw: *mut u32 = (&mut f) as *mut FihBool as *mut u32;
        // SAFETY: as above. Plant a "neither pattern" value with a
        // matching complement so the XOR invariant survives.
        unsafe {
            let bad_val: u32 = 0xDEAD_BEEF;
            core::ptr::write_volatile(raw, bad_val);
            core::ptr::write_volatile(raw.add(1), !bad_val);
        }

        assert!(
            !f.is_true(),
            "FihBool::is_true must reject non-SEC_TRUE / non-SEC_FALSE \
             patterns even when the XOR invariant holds — otherwise a \
             coordinated double-fault that survived the storage check \
             could plant an arbitrary value and have it read as true."
        );
    }

    /// `is_true_fi` reads the pair twice with `wait_random()` between.
    /// Defends a glitch landing inside one read's invariant check.
    /// Pattern: any random value other than SEC_TRUE must read false
    /// via `is_true_fi` even if some adversary clamps reads.
    #[test]
    fn negative_is_true_fi_rejects_corrupted_pair() {
        let mut f = FihBool::new_false();
        f.set_true();

        // Wipe to all-zero (val=0, complement=0). XOR invariant
        // 0^0==0, not 0xFFFFFFFF → invariant fails → false.
        let raw: *mut u32 = (&mut f) as *mut FihBool as *mut u32;
        // SAFETY: unique &mut, two adjacent u32 we own.
        unsafe {
            core::ptr::write_volatile(raw, 0);
            core::ptr::write_volatile(raw.add(1), 0);
        }

        assert!(
            !f.is_true_fi(),
            "is_true_fi must reject the all-zero state — that's the \
             post-glitch / post-cold-boot RAM signature that a fault \
             attacker could try to drop the gate into."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 5. fih.rs — source-text invariants on the SEC_TRUE / SEC_FALSE
//    patterns (they're private, so we pin the source values).
// ═════════════════════════════════════════════════════════════════════

mod fih_source_text {
    use super::FIH_SRC;

    /// SEC_TRUE and SEC_FALSE must remain the exact documented
    /// patterns. A future "make it prettier" rename would silently
    /// degrade FI defense class 2 (single-bit-flip distance).
    #[test]
    fn negative_sec_patterns_are_pinned() {
        assert!(
            FIH_SRC.contains("const SEC_TRUE: u32 = 0x1AAA_AAAA;"),
            "FihBool::SEC_TRUE must remain 0x1AAA_AAAA — chosen for 29-bit \
             Hamming distance from SEC_FALSE. Any other value risks a \
             1-bit-flip from FALSE → TRUE."
        );
        assert!(
            FIH_SRC.contains("const SEC_FALSE: u32 = 0x1555_5555;"),
            "FihBool::SEC_FALSE must remain 0x1555_5555 (see SEC_TRUE)."
        );
    }

    /// The pattern-distance contract: any two-pattern Hamming distance
    /// less than ~28 starts to risk single-fault TRUE/FALSE flips. The
    /// chosen patterns sit at 29.
    #[test]
    fn negative_sec_patterns_hamming_distance_meets_contract() {
        let sec_true: u32 = 0x1AAA_AAAA;
        let sec_false: u32 = 0x1555_5555;
        let distance = (sec_true ^ sec_false).count_ones();
        assert!(
            distance >= 28,
            "SEC_TRUE / SEC_FALSE pattern distance must be ≥28 to defend \
             single-bit flips — got {}",
            distance
        );
    }

    /// `is_true` MUST use `read_volatile` on both fields. A plain
    /// field access lets LLVM CSE the load (which would defeat the
    /// stuck-at-load defense class 3).
    #[test]
    fn negative_is_true_uses_read_volatile_on_both_fields() {
        let pos = FIH_SRC
            .find("pub fn is_true(&self) -> bool")
            .expect("is_true not found");
        let body = &FIH_SRC[pos..pos + 800];
        assert!(
            body.contains("read_volatile(&self.val)"),
            "is_true must read `val` via read_volatile — plain access lets \
             LLVM CSE/elide the load (defeats stuck-at-load defense)."
        );
        assert!(
            body.contains("read_volatile(&self.complement)"),
            "is_true must read `complement` via read_volatile too."
        );
    }

    /// `set_true` / `set_false` use `write_volatile` so a wipe call
    /// preceding them can't reorder past them.
    #[test]
    fn negative_setters_use_write_volatile() {
        for fname in ["pub fn set_true(", "pub fn set_false("] {
            let pos = FIH_SRC
                .find(fname)
                .unwrap_or_else(|| panic!("{fname} not found"));
            let body = &FIH_SRC[pos..pos + 500];
            assert!(
                body.contains("write_volatile(&mut self.val,"),
                "{fname} must use write_volatile on `val` to defeat reorder + \
                 dead-store elimination",
                fname = fname
            );
            assert!(
                body.contains("write_volatile(&mut self.complement,"),
                "{fname} must use write_volatile on `complement` too",
                fname = fname
            );
        }
    }

    /// `is_true_fi` MUST place a `wait_random()` between the two
    /// `is_true()` calls — that's the glitch-defeat window.
    #[test]
    fn negative_is_true_fi_inserts_wait_random_between_reads() {
        let pos = FIH_SRC
            .find("pub fn is_true_fi(&self)")
            .expect("is_true_fi not found");
        let body = &FIH_SRC[pos..pos + 400];
        assert!(
            body.contains("crate::fi::wait_random()"),
            "is_true_fi must insert wait_random() between the two passes — \
             without it the two reads happen close enough in time that a \
             single glitch lands across both."
        );
    }

    /// `FihBool` must be `#[repr(C)]` so the (val, complement) layout
    /// is stable (the bit-flip negative tests above rely on it).
    #[test]
    fn negative_fihbool_is_repr_c() {
        assert!(
            FIH_SRC.contains("#[repr(C)]\npub struct FihBool"),
            "FihBool must be `#[repr(C)]` — a `repr(Rust)` would let the \
             compiler reorder fields and the storage invariant's wire \
             interpretation would shift."
        );
    }

    /// `FihBool` must NOT implement `Clone` / `Copy`. A clone would
    /// silently duplicate the gate and let a caller hold a stale TRUE
    /// past a `set_false()`.
    #[test]
    fn negative_fihbool_is_not_clone_copy() {
        assert!(
            !FIH_SRC.contains("impl Clone for FihBool"),
            "FihBool must not implement Clone — cloning would let a stale \
             snapshot survive a `set_false` and re-enter a guarded section."
        );
        assert!(
            !FIH_SRC.contains("impl Copy for FihBool"),
            "FihBool must not be Copy — same reasoning as Clone."
        );
        assert!(
            !FIH_SRC.contains("#[derive(Clone"),
            "FihBool's derives must not include Clone."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 6. iso7816.rs — extend the existing coverage with negative cases.
// ═════════════════════════════════════════════════════════════════════

mod iso7816_tests {
    use crate::iso7816::{parse_pin_ctr, tlv_parse, tlv_put, tlv_put_u32};

    // ── positive coverage (extension) ────────────────────────────────

    #[test]
    fn positive_tlv_put_long_form_82() {
        let mut buf = [0u8; 1024];
        let v = [0x7Fu8; 500];
        let n = tlv_put(&mut buf, 0, 0x43, &v);
        // tag(1) + 0x82 + 2 length bytes + 500 value = 504
        assert_eq!(n, 504);
        assert_eq!(buf[0], 0x43);
        assert_eq!(buf[1], 0x82);
        assert_eq!(buf[2], 0x01); // 500 = 0x01F4
        assert_eq!(buf[3], 0xF4);
        assert_eq!(&buf[4..504], &v[..]);
    }

    #[test]
    fn positive_tlv_put_at_offset_nonzero() {
        let mut buf = [0u8; 64];
        buf[0] = 0xFF; // sentinel — must survive
        let n = tlv_put(&mut buf, 1, 0x42, &[1, 2]);
        assert_eq!(n, 5);
        assert_eq!(buf[0], 0xFF, "tlv_put must not touch bytes before offset");
        assert_eq!(&buf[1..5], &[0x42, 0x02, 1, 2]);
    }

    #[test]
    fn positive_tlv_put_u32_round_trip() {
        let mut buf = [0u8; 16];
        let n = tlv_put_u32(&mut buf, 0, 0x44, 0xDEAD_BEEF);
        assert_eq!(n, 6); // tag + 0x04 + 4 bytes
        assert_eq!(&buf[..n], &[0x44, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);

        let (tag, val, rest) = tlv_parse(&buf[..n]).unwrap();
        assert_eq!(tag, 0x44);
        assert_eq!(val, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(rest.is_empty());
    }

    #[test]
    fn positive_tlv_parse_returns_trailing_bytes_as_rest() {
        // Two TLVs back-to-back; first parse must return the second as `rest`.
        let bytes = [0x41, 0x02, 0xAA, 0xBB, 0x42, 0x01, 0xCC];
        let (tag, val, rest) = tlv_parse(&bytes).unwrap();
        assert_eq!(tag, 0x41);
        assert_eq!(val, &[0xAA, 0xBB]);
        assert_eq!(rest, &[0x42, 0x01, 0xCC]);
    }

    #[test]
    fn positive_parse_pin_ctr_boundary_values() {
        // current = 0, limit = u32::MAX (chip just bound to LUC)
        let mut bytes = [0u8; 8];
        bytes[4..].copy_from_slice(&u32::MAX.to_be_bytes());
        let (cur, lim) = parse_pin_ctr(&bytes).unwrap();
        assert_eq!(cur, 0);
        assert_eq!(lim, u32::MAX);

        // current = limit (chip exhausted)
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&42u32.to_be_bytes());
        bytes[4..].copy_from_slice(&42u32.to_be_bytes());
        let (cur, lim) = parse_pin_ctr(&bytes).unwrap();
        assert_eq!(cur, 42);
        assert_eq!(lim, 42);
    }

    // ── negative coverage ────────────────────────────────────────────

    /// Empty input must be `None`, never panic.
    #[test]
    fn negative_tlv_parse_empty() {
        assert!(tlv_parse(&[]).is_none());
    }

    /// 1-byte input has tag but no length — must be `None`.
    #[test]
    fn negative_tlv_parse_tag_only() {
        assert!(tlv_parse(&[0x41]).is_none());
    }

    /// Long-form 0x81 with claimed length running past `data.len()`.
    #[test]
    fn negative_tlv_parse_81_length_overflow() {
        // Tag + 0x81 + length=200 but only 3 follow bytes → reject.
        let mut blob = vec![0x41, 0x81, 200];
        blob.extend(&[0; 3]);
        assert!(
            tlv_parse(&blob).is_none(),
            "tlv_parse must reject a long-form length running past the \
             buffer — otherwise the caller's slice access of `value` \
             would panic in production."
        );
    }

    /// Long-form 0x82 with claimed length exceeding buffer.
    #[test]
    fn negative_tlv_parse_82_length_overflow() {
        let blob = [0x41, 0x82, 0xFF, 0xFF, 0x00, 0x00];
        assert!(
            tlv_parse(&blob).is_none(),
            "tlv_parse must reject 0x82 lengths overflowing the buffer."
        );
    }

    /// 0x83 (3-byte length) is intentionally not supported.
    #[test]
    fn negative_tlv_parse_unsupported_long_form_83() {
        // The decoder is total: it returns None on 0x83.
        // Padding the buffer to ≥ 4 bytes so the test exercises the
        // *length-form* check, not the early-return-on-truncation path.
        assert!(tlv_parse(&[0x41, 0x83, 0, 0, 0, 1, 0xAA]).is_none());
    }

    /// 0x84 (4-byte length) — same rejection.
    #[test]
    fn negative_tlv_parse_unsupported_long_form_84() {
        assert!(tlv_parse(&[0x41, 0x84, 0, 0, 0, 0, 0, 0]).is_none());
    }

    /// 0x80 means indefinite length (ISO 7816-4 §5.2.2.2). We don't
    /// support it — must be rejected, not interpreted as `len = 0`.
    #[test]
    fn negative_tlv_parse_indefinite_length_rejected() {
        // 0x80 is neither < 0x80, nor 0x81 with a follow byte, nor 0x82
        // with two follow bytes. It must fall through to None.
        assert!(
            tlv_parse(&[0x41, 0x80, 0x00, 0x00, 0x00]).is_none(),
            "Indefinite-length (0x80) must NOT be parsed — silently \
             interpreting it as len=0 would let an attacker submit a \
             zero-length TLV that looks legitimate to the caller."
        );
    }

    /// Truncated 0x81 (only 2 bytes total — tag + 0x81 with no
    /// follow byte): None.
    #[test]
    fn negative_tlv_parse_truncated_81_no_follow_byte() {
        assert!(tlv_parse(&[0x41, 0x81]).is_none());
    }

    /// Truncated 0x82 (only 3 bytes total): None.
    #[test]
    fn negative_tlv_parse_truncated_82_short_follow() {
        assert!(tlv_parse(&[0x41, 0x82, 0x00]).is_none());
    }

    /// `parse_pin_ctr` must REJECT every length other than exactly 8.
    #[test]
    fn negative_parse_pin_ctr_rejects_wrong_lengths() {
        for n in 0..=20u8 {
            if n == 8 {
                continue;
            }
            let buf = vec![0u8; n as usize];
            assert!(
                parse_pin_ctr(&buf).is_none(),
                "parse_pin_ctr must reject length {n} (only exact 8 is the \
                 OPTIGA UPCTR wire format — anything else is a fault on \
                 the I2C bus)"
            );
        }
    }

    /// Fuzz-style: tlv_parse never panics on any input up to 256 bytes.
    /// (Belt-and-braces — the proptest harness already covers this with
    /// much more depth; this regression-cements the contract for tools
    /// that don't run proptest.)
    #[test]
    fn negative_tlv_parse_never_panics_brute_force() {
        // Hand-picked adversarial shapes.
        let cases: &[&[u8]] = &[
            &[],
            &[0xFF],
            &[0xFF, 0xFF],
            &[0xFF, 0x80],
            &[0xFF, 0x81],
            &[0xFF, 0x82, 0xFF],
            &[0xFF, 0x82, 0xFF, 0xFF],
            &[0xFF, 0x82, 0xFF, 0xFF, 0x00],
            &[0; 256],
            &[0xFF; 256],
        ];
        for c in cases {
            // Must not panic.
            let _ = tlv_parse(c);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════
// 7. iso7816.rs — source-text invariants.
// ═════════════════════════════════════════════════════════════════════

mod iso7816_source_text {
    use super::ISO7816_SRC;

    /// Both `tlv_parse` and `parse_pin_ctr` must be panic-free for
    /// arbitrary input — they're used to parse SE bus traffic, which
    /// a fault attacker can manipulate. The `checked_add` on the
    /// length-prefix computation is load-bearing.
    #[test]
    fn negative_tlv_parse_uses_checked_add_for_end_offset() {
        let pos = ISO7816_SRC
            .find("pub fn tlv_parse(")
            .expect("tlv_parse not found");
        let body = &ISO7816_SRC[pos..pos + 1000];
        assert!(
            body.contains("hdr.checked_add(len)?"),
            "tlv_parse must compute `end = hdr + len` via `checked_add` — \
             a plain `hdr + len` overflows on `len ≈ usize::MAX` and \
             becomes a tiny offset, letting the slice access succeed on \
             a malformed input."
        );
    }

    /// `parse_pin_ctr` returns `Option<(u32, u32)>`, not a panic on
    /// `data[..]` slicing.
    #[test]
    fn negative_parse_pin_ctr_returns_none_on_wrong_length() {
        let pos = ISO7816_SRC
            .find("pub fn parse_pin_ctr(")
            .expect("parse_pin_ctr not found");
        let body = &ISO7816_SRC[pos..pos + 500];
        assert!(
            body.contains("if data.len() != 8 {\n        return None;"),
            "parse_pin_ctr must return None on len != 8 BEFORE indexing — \
             a permissive impl would slice-index past the buffer on a \
             4-byte truncated chip response."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 8. pin.rs — PIN verify via Mock SE backend.
//
// Goes through `crate::secure_element::MockSecureElement::unlock` →
// `crate::pin::verify_pin`. The wrong-PIN-decrements,
// 10-wrong-PINs-brick paths are already covered in
// `secure_element::tests`. Here we add:
//   * the off-by-one on the brick threshold (9 wrong → 10th must NOT
//     simply wrap)
//   * the "correct PIN after 9 wrong resets the counter" invariant
//     (production guarantee — without it the counter would only ever
//     advance, eventually bricking even an honest user)
//   * the bricked-state re-entry guarantee
// ═════════════════════════════════════════════════════════════════════

mod pin_tests {
    use crate::crypto::provision_from_mnemonic;
    use crate::pin::verify_pin;
    use crate::secure_element::{MockSecureElement, UnlockError, WalletStore};
    use sphincs_tz_bip39::Mnemonic;
    use sphincs_tz_shared::{NscStatus, MAX_ATTEMPTS};

    fn make_provisioned() -> MockSecureElement {
        let mut se = MockSecureElement::new();
        let mnemonic = Mnemonic::from_entropy(&[0u8; 32]);
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        provision_from_mnemonic(&mut se, &mnemonic, &pin, None);
        se
    }

    // ── positive coverage ────────────────────────────────────────────

    #[test]
    fn positive_correct_pin_returns_master_secret() {
        let mut se = make_provisioned();
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        let master = verify_pin(&mut se, &pin).expect("correct PIN must succeed");
        assert_ne!(master, [0u8; 32], "master_secret must be non-zero");
    }

    #[test]
    fn positive_wrong_pin_returns_pin_incorrect() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        let r = verify_pin(&mut se, &bad);
        assert!(
            matches!(r, Err(NscStatus::PinIncorrect)),
            "first wrong PIN must report PinIncorrect, got {:?}",
            r
        );
    }

    // ── negative coverage ────────────────────────────────────────────

    /// 9 wrong PINs leave 1 remaining; a correct PIN at attempt 10
    /// must SUCCEED and reset the counter to 0. Without this, an
    /// honest user who fat-fingers 9 times would be bricked on the
    /// 10th correct entry.
    #[test]
    fn negative_correct_pin_at_attempt_10_succeeds_and_resets() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        let good = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];

        for i in 0..9 {
            assert!(
                matches!(verify_pin(&mut se, &bad), Err(NscStatus::PinIncorrect)),
                "wrong PIN {} must report PinIncorrect",
                i + 1
            );
        }
        assert_eq!(se.remaining_attempts(), 1, "1 attempt must remain");

        let master = verify_pin(&mut se, &good)
            .expect("correct PIN at last attempt must succeed (not be eaten by brick path)");
        assert_ne!(master, [0u8; 32]);
        assert_eq!(
            se.remaining_attempts(),
            MAX_ATTEMPTS,
            "successful PIN at attempt 10 must reset the counter to 0 (full budget restored)"
        );
    }

    /// After bricking (10 wrong PINs), the entropy slot is erased.
    /// A subsequent verify with ANY PIN — including the correct one —
    /// must NOT return a master secret. This is CLAUDE.md Invariant 2
    /// ("10 wrong PINs → brick") seen from the firmware side.
    #[test]
    fn negative_bricked_se_refuses_subsequent_correct_pin() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        for _ in 0..10 {
            let _ = verify_pin(&mut se, &bad);
        }
        let good = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        let r = verify_pin(&mut se, &good);
        assert!(
            matches!(r, Err(NscStatus::PinLocked | NscStatus::InternalError)),
            "post-brick correct PIN must fail (PinLocked or InternalError), \
             got {:?} — Invariant #2 (`10 wrong PINs → brick`) cannot have \
             a back-door even for the correct PIN.",
            r
        );
    }

    /// Wrong-PIN path must MONOTONICALLY decrement `remaining_attempts`.
    /// A bug that resets it on the wrong-PIN branch (instead of the
    /// correct-PIN branch) would let an attacker brute-force the PIN
    /// without ever running down the counter.
    #[test]
    fn negative_wrong_pin_decrements_monotonically() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        let mut last = se.remaining_attempts();
        assert_eq!(last, MAX_ATTEMPTS);
        for _ in 0..5 {
            let _ = verify_pin(&mut se, &bad);
            let now = se.remaining_attempts();
            assert!(
                now < last,
                "remaining_attempts must strictly decrease per wrong PIN — \
                 was {}, now {}",
                last,
                now
            );
            last = now;
        }
    }

    /// The 10th wrong PIN MUST be the brick-trip point, not the 11th.
    /// (Defends an off-by-one that would allow 11 wrong attempts.)
    #[test]
    fn negative_brick_fires_at_exactly_10_wrong_pins() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        for i in 0..9 {
            assert!(
                matches!(verify_pin(&mut se, &bad), Err(NscStatus::PinIncorrect)),
                "attempt {} must report PinIncorrect (not yet bricked)",
                i + 1
            );
        }
        // Attempt 10: brick path. Result is PinLocked (the wrong PIN is
        // the one that tripped the cap).
        let r = verify_pin(&mut se, &bad);
        assert!(
            matches!(r, Err(NscStatus::PinLocked)),
            "10th wrong PIN must report PinLocked (brick has been applied), \
             got {:?}",
            r
        );
    }

    /// The MockSecureElement's `unlock()` is `pin::verify_pin` under the
    /// hood. Its `Err(_)` mapping must preserve the security-critical
    /// distinction between PinIncorrect and PinLocked.
    #[test]
    fn negative_unlock_preserves_pin_incorrect_vs_pin_locked() {
        let mut se = make_provisioned();
        let bad = [0u8; 8];
        let r = se.unlock(&bad);
        assert!(
            matches!(r, Err(UnlockError::PinIncorrect)),
            "first wrong PIN through unlock() must surface as PinIncorrect, \
             not as a generic InternalError that would hide the attempt cost"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 9. pin.rs — source-text invariants.
// ═════════════════════════════════════════════════════════════════════

mod pin_source_text {
    use super::PIN_SRC;

    /// On the wrong-PIN brick branch (the 10th attempt), three slots
    /// MUST be erased: encrypted entropy, PIN state, and verifying
    /// key. Missing any one of them would leave a residue that breaks
    /// the brick guarantee.
    #[test]
    fn negative_brick_path_erases_all_three_critical_slots() {
        // Find the "last attempt failed" branch.
        let pos = PIN_SRC
            .find("// Last attempt failed")
            .expect("brick-path comment not found in pin.rs");
        let body = &PIN_SRC[pos..(pos + 800).min(PIN_SRC.len())];
        assert!(
            body.contains("se.r_mem_erase(RMEM_ENCRYPTED_ENTROPY)"),
            "brick path must erase RMEM_ENCRYPTED_ENTROPY"
        );
        assert!(
            body.contains("se.r_mem_erase(RMEM_PIN_STATE)"),
            "brick path must erase RMEM_PIN_STATE"
        );
        assert!(
            body.contains("se.r_mem_erase(RMEM_VERIFYING_KEY)"),
            "brick path must erase RMEM_VERIFYING_KEY — leaving it would \
             let post-brick GET_PUBKEY still return the wallet's bootstrap \
             vk, leaking a chain-stable identifier from a supposed-dead \
             device."
        );
    }

    /// On the wrong-PIN branch (under the cap), `w_j` and the ciphertext
    /// buffer MUST be zeroized before the function returns the error.
    /// A future refactor that drops the zeroize would leak a MACD output
    /// + a decrypted-but-failed ciphertext into the SE stack frame.
    #[test]
    fn negative_wrong_pin_zeroizes_intermediate_buffers() {
        let pos = PIN_SRC
            .find("// PIN incorrect")
            .expect("wrong-pin branch comment not found");
        let body = &PIN_SRC[pos..pos + 500];
        assert!(
            body.contains("ct_buf.zeroize()"),
            "wrong-PIN branch must zeroize ct_buf — its bytes include a \
             failed-but-attempted decryption keyed to w_j."
        );
        assert!(
            body.contains("w_j.zeroize()"),
            "wrong-PIN branch must zeroize w_j — leaking it lets an \
             attacker correlate a wrong-PIN attempt with the SE's MACD \
             slot state."
        );
    }

    /// `verify_pin` MUST take the PIN as `&[u8; 8]`, not `&[u8]` —
    /// fixed-size enforces caller-side length validation, avoiding a
    /// "PIN length leak" via TLV-style attacks.
    #[test]
    fn negative_verify_pin_signature_is_fixed_eight_bytes() {
        assert!(
            PIN_SRC.contains("pin: &[u8; 8]"),
            "verify_pin must take a fixed-length [u8; 8] PIN — variable \
             slices invite length-side-channel attacks."
        );
    }

    /// `MAX_ATTEMPTS` MUST be sourced from `sphincs_tz_shared` (the
    /// proto crate), NOT redefined locally. The shared constant is the
    /// SOURCE OF TRUTH for SE050 UserID `max_attempts`, OPTIGA E120
    /// LUC threshold, MCU page-124 counter — all three lockstep
    /// counters depend on the same value.
    #[test]
    fn negative_max_attempts_sourced_from_shared() {
        assert!(
            PIN_SRC.contains("use sphincs_tz_shared::{MAX_ATTEMPTS, NscStatus};")
                || PIN_SRC.contains("sphincs_tz_shared::MAX_ATTEMPTS"),
            "pin.rs must import MAX_ATTEMPTS from sphincs_tz_shared — \
             redefining it locally would let the three lockstep counters \
             drift (Invariant #2 violation)."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 10. sign_rate.rs — burst cap + invariants (extension).
//
// The inline tests in sign_rate.rs already cover first-sign-ok,
// session-cap-refuses, reset-re-arms. We add constant pins + a
// monotonicity check to defend against a future refactor that bumps
// MAX_SIGNS_PER_SESSION silently.
// ═════════════════════════════════════════════════════════════════════

mod sign_rate_tests {
    use crate::sign_rate::{MAX_SIGNS_PER_SESSION, MIN_SIGN_INTERVAL_MS};

    /// Both constants are SCA contracts — see sign_rate.rs:43-50.
    #[test]
    fn negative_session_cap_constant_is_pinned_at_250() {
        assert_eq!(
            MAX_SIGNS_PER_SESSION, 250,
            "MAX_SIGNS_PER_SESSION must remain 250 — see sign_rate.rs:49 \
             threat model. Bumping it without a paired SCA review re-opens \
             the profiled-DPA attack window against WOTS chain seeds."
        );
    }

    #[test]
    fn negative_min_interval_constant_is_pinned_at_1000ms() {
        assert_eq!(
            MIN_SIGN_INTERVAL_MS, 1000,
            "MIN_SIGN_INTERVAL_MS must remain 1000 ms — sub-second burst \
             signing is the exact attack class this constant defends (see \
             sign_rate.rs:21-24)."
        );
    }
}

mod sign_rate_source_text {
    use super::SIGN_RATE_SRC;

    /// The rate-limit time-wait MUST be production-only — host tests and
    /// QEMU e2e bypass it. The cfg gate `all(feature = "stm32u585",
    /// not(feature = "e2e-test"), not(test))` is load-bearing: if `test`
    /// were missing, the host test that runs reset_counters() + pre_sign()
    /// in a loop would deadlock on the first iteration (no SysTick).
    #[test]
    fn negative_wait_for_min_interval_is_production_only() {
        assert!(
            SIGN_RATE_SRC.contains(
                "#[cfg(all(feature = \"stm32u585\", not(feature = \"e2e-test\"), not(test)))]\nfn wait_for_min_interval()"
            ),
            "wait_for_min_interval must be cfg-gated on \
             stm32u585 + !e2e-test + !test — otherwise host tests deadlock."
        );
    }

    /// The session-cap check (`>= MAX_SIGNS_PER_SESSION`) must use
    /// `>=`, not `>`. An off-by-one to `>` would let the 251st sign
    /// through.
    #[test]
    fn negative_cap_uses_gte_not_gt() {
        let pos = SIGN_RATE_SRC
            .find("pub fn pre_sign()")
            .expect("pre_sign not found");
        let body = &SIGN_RATE_SRC[pos..pos + 1200];
        assert!(
            body.contains("if count >= MAX_SIGNS_PER_SESSION {"),
            "pre_sign cap check must use `>=` (not `>`) — `>` would let \
             the 251st sign through (off-by-one on a documented hard cap)."
        );
    }

    /// The wait loop on production silicon uses `read_volatile_voted`
    /// on both `LAST_SIGN_MS` and `TICKS` — defends single-fault
    /// glitches on the `ldr` instruction that would otherwise let the
    /// busy-wait short-circuit.
    #[test]
    fn negative_wait_loop_triple_reads_last_sign_and_ticks() {
        // `LAST_SIGN_MS` triple-read.
        assert!(
            SIGN_RATE_SRC.contains("crate::fi::read_volatile_voted(last_addr)"),
            "sign_rate wait loop must triple-read LAST_SIGN_MS via \
             read_volatile_voted — single-fault glitch on the load could \
             clamp `last` to 0 and bypass the wait."
        );
        // `TICKS` triple-read.
        assert!(
            SIGN_RATE_SRC.contains("crate::fi::read_volatile_voted(now_addr)"),
            "sign_rate wait loop must triple-read TICKS — single-fault \
             glitch on the load could fake a huge time delta and break \
             out early."
        );
    }

    /// On Err(()) from the triple-read of `LAST_SIGN_MS`, the code must
    /// fail-CLOSED (stay in the wait loop), not skip the wait.
    #[test]
    fn negative_triple_read_failure_fails_closed_into_wait() {
        // The disagreement branch enters an inner WFI loop.
        assert!(
            SIGN_RATE_SRC.contains("cortex_m::asm::wfi();") &&
            SIGN_RATE_SRC.contains("if crate::fi::read_volatile_voted(last_addr).is_ok() {"),
            "Disagreement on the LAST_SIGN_MS triple-read must keep the \
             function inside the wait until reads agree — silently \
             breaking out would let a glitched read defeat the rate limit."
        );
    }

    /// `reset_counters` MUST zero BOTH `LAST_SIGN_MS` and
    /// `SIGNS_THIS_SESSION`. A partial reset (e.g., only counter, not
    /// timestamp) would leave a stale `last` that artificially extends
    /// the post-unlock wait.
    #[test]
    fn negative_reset_counters_resets_both() {
        let pos = SIGN_RATE_SRC
            .find("pub fn reset_counters()")
            .expect("reset_counters not found");
        let body = &SIGN_RATE_SRC[pos..pos + 300];
        assert!(
            body.contains("LAST_SIGN_MS.store(0,"),
            "reset_counters must zero LAST_SIGN_MS"
        );
        assert!(
            body.contains("SIGNS_THIS_SESSION.store(0,"),
            "reset_counters must zero SIGNS_THIS_SESSION"
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 11. timeout.rs — exercise via the host-test re-mount.
// ═════════════════════════════════════════════════════════════════════

mod timeout_tests {
    use super::timeout_under_test as t;

    #[test]
    fn positive_constants_are_documented_values() {
        // 2 minutes at ~1 ms tick.
        assert_eq!(t::TIMEOUT_TICKS, 2 * 60 * 1000);
    }

    #[test]
    fn positive_tick_increments_monotonically() {
        let before = t::now();
        t::tick();
        let after = t::now();
        // wrapping math: `after - before` is 1 in the common case.
        assert_eq!(after.wrapping_sub(before), 1);
    }

    #[test]
    fn positive_reset_activity_drops_idle_for() {
        // Pile on some ticks so idle_for would be nonzero…
        for _ in 0..100 {
            t::tick();
        }
        t::reset_activity();
        let idle = t::idle_for();
        // The window between `reset_activity` and `idle_for` may see a
        // tick from another test; allow a small slack.
        assert!(
            idle <= 5,
            "right after reset_activity, idle_for should be ~0 (got {})",
            idle
        );
    }

    #[test]
    fn positive_ticks_ptr_matches_atomic_address() {
        // Triple-checking from sign_rate's defense — the pointer surfaced
        // by `ticks_ptr()` must be a valid `*const u32` that other
        // modules can pass to `fi::read_volatile_voted`.
        let p = t::ticks_ptr();
        assert!(!p.is_null());
        // The pointer must be 4-byte aligned (AtomicU32).
        assert_eq!(
            (p as usize) % core::mem::align_of::<u32>(),
            0,
            "ticks_ptr must yield a 4-byte-aligned address"
        );
    }
}

mod timeout_source_text {
    use super::TIMEOUT_SRC;

    /// `TIMEOUT_TICKS = 2 * 60 * 1000` (= 120 000) is the documented
    /// 2-minute inactivity window. CLAUDE.md "Lifecycle" cites this
    /// explicitly.
    #[test]
    fn negative_timeout_ticks_pinned_at_two_minutes() {
        assert!(
            TIMEOUT_SRC.contains("pub const TIMEOUT_TICKS: u32 = 2 * 60 * 1000;"),
            "TIMEOUT_TICKS must remain 2 * 60 * 1000 — CLAUDE.md \
             'Lifecycle' pins it to 120 s. Bumping it without a paired \
             threat-model update silently relaxes the secret-window cap."
        );
    }

    /// `idle_for` uses `wrapping_sub` so the 49.7-day SysTick rollover
    /// doesn't suddenly classify the device as "just-active" again.
    #[test]
    fn negative_idle_for_uses_wrapping_sub() {
        let pos = TIMEOUT_SRC
            .find("pub fn idle_for() -> u32")
            .expect("idle_for not found");
        let body = &TIMEOUT_SRC[pos..(pos + 300).min(TIMEOUT_SRC.len())];
        assert!(
            body.contains("wrapping_sub("),
            "idle_for must use wrapping_sub — a plain subtraction would \
             wrap-panic under debug_assertions every 49.7 days."
        );
    }

    /// `is_idle` uses `>` (strictly greater), so EXACTLY `TIMEOUT_TICKS`
    /// is still considered active. Off-by-one to `>=` would prematurely
    /// idle-wipe at exactly the boundary.
    #[test]
    fn negative_is_idle_uses_strictly_greater_than() {
        let pos = TIMEOUT_SRC
            .find("pub fn is_idle()")
            .expect("is_idle not found");
        let body = &TIMEOUT_SRC[pos..(pos + 200).min(TIMEOUT_SRC.len())];
        assert!(
            body.contains("idle_for() > TIMEOUT_TICKS"),
            "is_idle must use `>` (strictly greater) — relaxing to `>=` \
             premature-fires the idle-wipe by one tick at the boundary."
        );
    }

    /// CLAUDE.md says: "NS pings do NOT reset it [the inactivity
    /// timer]". The only public mutator for `LAST_ACTIVITY` is
    /// `reset_activity`, and it MUST be called only from real user
    /// input paths. This source-text check pins the mutator surface.
    #[test]
    fn negative_only_reset_activity_writes_last_activity() {
        let writes = TIMEOUT_SRC.matches("LAST_ACTIVITY.store(").count();
        assert_eq!(
            writes, 1,
            "LAST_ACTIVITY must have exactly one mutator (reset_activity) — \
             multiple mutators risk an NS-reachable code path slipping in \
             and resetting the inactivity timer, violating the CLAUDE.md \
             contract 'NS pings do NOT reset it'."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 12. rng.rs / rng_strong.rs / host_rng.rs — source-text invariants.
//
// Production-compile only. Host tests can't link the
// `cortex_m_semihosting` syscall macro, so we pin the load-bearing
// contracts by reading the file text.
// ═════════════════════════════════════════════════════════════════════

mod rng_source_text {
    use super::{HOST_RNG_SRC, RNG_SRC, RNG_STRONG_SRC};

    /// `rng::fill` and `rng::byte` MUST delegate based on the
    /// `stm32u585` feature, NOT some other random predicate. If the
    /// cfg gate drifted, a QEMU build could end up calling the HW
    /// register MMIO (HardFault) or a real-silicon build could end up
    /// reading from `/dev/urandom` via a semihosting BKPT — which on
    /// production silicon traps to HardFault.
    #[test]
    fn negative_rng_dispatches_on_stm32u585_feature() {
        assert!(
            RNG_SRC.contains("#[cfg(not(feature = \"stm32u585\"))]")
                && RNG_SRC.contains("#[cfg(feature = \"stm32u585\")]"),
            "rng.rs must dispatch on `feature = \"stm32u585\"` — drifting \
             to another cfg key risks QEMU calling MMIO regs (HardFault) \
             or hardware calling semihosting (BKPT trap)."
        );
        assert!(
            RNG_SRC.contains("host_rng::fill(buf)") && RNG_SRC.contains("hw_rng::fill(buf)"),
            "rng::fill must delegate to host_rng::fill on QEMU and \
             hw_rng::fill on stm32u585."
        );
    }

    /// `rng_strong::fill` MUST keep the all-zero fail-closed gate. Its
    /// removal would let a single-fault stuck-at-0 on the buffer pass
    /// through as a "predictable random" — which crypto callers
    /// (`opt_rand` for SPHINCS+ signing) would consume and produce a
    /// deterministic-but-attacker-known signature stream.
    #[test]
    fn negative_rng_strong_keeps_all_zero_fail_closed_gate() {
        assert!(
            RNG_STRONG_SRC.contains("if acc == 0 {\n        return Err(());"),
            "rng_strong::fill must keep the all-zero acceptance gate — \
             rationale at rng_strong.rs:86-98. Removing it lets a stuck-\
             at-0 fault deliver a predictable 'random' to the signer."
        );
    }

    /// `rng_strong::fill` is the documented entry point for the
    /// multi-source XOR fold. Caller (`c10_sign_verified_with_progress`)
    /// depends on it returning `Err(())` on platform-TRNG failure (so
    /// the F-13 follow-up's fail-closed semantics hold).
    #[test]
    fn negative_rng_strong_uses_platform_trng_as_baseline() {
        assert!(
            RNG_STRONG_SRC.contains("crate::rng::fill(buf)?;"),
            "rng_strong::fill must call `crate::rng::fill(buf)?` as the \
             baseline — the `?` operator propagates Err so a platform-\
             TRNG failure aborts the whole signing call."
        );
    }

    /// `rng_strong::fill` MUST XOR the SE-provided bytes into `buf`,
    /// not REPLACE them. XOR preserves entropy of the platform TRNG
    /// even if the SE is fully compromised. A `=` would let a
    /// compromised SE clamp the buffer.
    #[test]
    fn negative_rng_strong_xor_folds_se_bytes() {
        let pos = RNG_STRONG_SRC
            .find("for i in 0..len {")
            .expect("XOR-fold loop not found");
        let body = &RNG_STRONG_SRC[pos..pos + 200];
        assert!(
            body.contains("buf[off + i] ^= block[i];"),
            "rng_strong must XOR SE bytes into the buffer (^=) — using \
             `=` lets a compromised SE clamp the buffer and defeats the \
             multi-source entropy preservation argument."
        );
    }

    /// SE-side failure MUST fall through silently — only the platform
    /// TRNG failure is fatal. The comment at rng_strong.rs:43-46 spells
    /// out the contract; the `.is_ok()` check is the implementation.
    #[test]
    fn negative_rng_strong_se_failure_falls_through() {
        assert!(
            RNG_STRONG_SRC
                .contains("if unsafe { crate::se_random(&mut block[..len]) }.is_ok() {"),
            "rng_strong must guard the SE call with `.is_ok()` — a broken \
             SE TRNG must fall through, not abort the signing call."
        );
    }

    /// `host_rng::fill` uses the semihosting OPEN/READ/CLOSE sequence
    /// against `/dev/urandom`. Anything else (e.g., a fixed seed) would
    /// silently produce a deterministic mnemonic in QEMU bring-up flows.
    #[test]
    fn negative_host_rng_uses_semihosting_dev_urandom() {
        assert!(
            HOST_RNG_SRC.contains("b\"/dev/urandom\\0\""),
            "host_rng::fill must open `/dev/urandom` — silently using a \
             fixed seed in QEMU would produce a deterministic mnemonic \
             that bench testers might mistake for a real seed."
        );
        assert!(
            HOST_RNG_SRC.contains("syscall!(OPEN,")
                && HOST_RNG_SRC.contains("syscall!(READ,")
                && HOST_RNG_SRC.contains("syscall!(CLOSE,"),
            "host_rng::fill must OPEN / READ / CLOSE via cortex_m_semihosting \
             syscall! — switching to e.g. core::time-derived seeds is a \
             critical regression."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 13. pin_diag.rs — source-text invariants (ARM-only).
//
// The "CRITICALLY NOT pulsed in `run()`" hazard (PE4 → SE050 ENA
// cross-coupling that corrupted ENTROPY_OBJ) deserves a regression
// guard. A silent re-add of PE4 to `run()` would resurrect the
// original brick bug. See `docs/optiga-brick-postmortem.md`.
// ═════════════════════════════════════════════════════════════════════

mod pin_diag_source_text {
    use super::PIN_DIAG_SRC;

    /// CLAUDE.md / pin_diag.rs:36-43 / optiga-brick-postmortem: `run()`
    /// MUST NOT pulse PE4. Pulsing PE4 routes through the OM-SE050ARD
    /// shield onto SE050's ENA line, and a mid-NVM-write power cycle
    /// corrupts ENTROPY_OBJ on the SE050. This was the original brick.
    #[test]
    fn negative_run_does_not_pulse_pe4() {
        let pos = PIN_DIAG_SRC
            .find("pub fn run()")
            .expect("`pub fn run()` not found");
        // Walk forward only until the next top-level `pub fn` (the
        // start of `header_sweep` — which IS allowed to pulse PE4
        // under the diagnostic feature gate).
        let next_fn = PIN_DIAG_SRC[pos + 1..]
            .find("pub fn ")
            .map(|i| pos + 1 + i)
            .unwrap_or(PIN_DIAG_SRC.len());
        let body = &PIN_DIAG_SRC[pos..next_fn];
        assert!(
            !body.contains("GPIOE_BASE, 4"),
            "pin_diag::run() must NOT touch PE4 — that pin cross-couples \
             onto SE050 ENA via the OM-SE050ARD shield and a mid-NVM-write \
             pulse corrupts ENTROPY_OBJ (the original brick — see \
             docs/optiga-brick-postmortem.md)."
        );
    }

    /// `run()` MUST pulse PA4, PD5, PE0 in that order — the empirically
    /// validated sequence that produces a visible OPTIGA RST edge.
    /// Reordering or dropping any of them caused "no visible edge on the
    /// LA" (see pin_diag.rs:113-128).
    #[test]
    fn positive_run_keeps_empirical_pulse_sequence() {
        let pos = PIN_DIAG_SRC
            .find("pub fn run()")
            .expect("`pub fn run()` not found");
        let next_fn = PIN_DIAG_SRC[pos + 1..]
            .find("pub fn ")
            .map(|i| pos + 1 + i)
            .unwrap_or(PIN_DIAG_SRC.len());
        let body = &PIN_DIAG_SRC[pos..next_fn];
        let pa4_pos = body.find("pulse_low(GPIOA_BASE, 4,").expect("PA4 pulse missing");
        let pd5_pos = body.find("pulse_low(GPIOD_BASE, 5,").expect("PD5 pulse missing");
        let pe0_pos = body.find("pulse_low(GPIOE_BASE, 0,").expect("PE0 pulse missing");
        assert!(
            pa4_pos < pd5_pos && pd5_pos < pe0_pos,
            "pulse order must be PA4 → PD5 → PE0 (PE0 is the actual OPTIGA \
             RST wire; PA4/PD5 are empirically-load-bearing preamble decoys)."
        );
    }

    /// `header_sweep` is gated on `pin-diag-boot` so it can NEVER run
    /// in a production build (production gates `debug-log`/`e2e-test`
    /// off, but `pin-diag-boot` is its own non-standard flag).
    #[test]
    fn negative_header_sweep_is_feature_gated() {
        assert!(
            PIN_DIAG_SRC.contains("#[cfg(feature = \"pin-diag-boot\")]\npub fn header_sweep()"),
            "header_sweep() must be gated on `pin-diag-boot` feature — \
             without the gate, a stray PE4 pulse during normal OPTIGA \
             ops would re-create the SE050 ENA cross-coupling bug."
        );
    }

    /// `pin_diag` itself is gated on `stm32u585` at the file level so
    /// it never reaches host builds (the MMIO addresses are
    /// stm32u585-specific).
    #[test]
    fn negative_module_is_stm32u585_gated() {
        assert!(
            PIN_DIAG_SRC.starts_with("//!")
                && PIN_DIAG_SRC.contains("#![cfg(feature = \"stm32u585\")]"),
            "pin_diag.rs must be `#![cfg(feature = \"stm32u585\")]` — the \
             MMIO base addresses are STM32U585-specific."
        );
    }
}

// ═════════════════════════════════════════════════════════════════════
// 14. fuzz_props.rs — source-text invariants on the harness scope.
//
// The proptest blocks themselves run as tests. We pin the cover set
// so a future refactor that drops a parser from the harness is loud.
// ═════════════════════════════════════════════════════════════════════

mod fuzz_props_source_text {
    use super::FUZZ_PROPS_SRC;

    /// Every NS→S parser called out in the slice must appear in the
    /// fuzz harness. Dropping one would silently regress the
    /// "panic-on-arbitrary-input" guard the comment at fuzz_props.rs:10
    /// promises.
    #[test]
    fn negative_harness_covers_every_documented_parser() {
        let required = [
            "crate::tx::eip1559::parse",
            "crate::tx::rlp::decode_item",
            "crate::erc20::bundle::verify_erc20_bundle",
            "crate::erc20::calldata::parse_erc20_calldata",
            "crate::names::verify_name_bundle",
            "crate::aa::userop::parse_header",
            "crate::selectors::bundle::verify_selector_bundle",
            "crate::tx::eip712::safe::decode_canonical",
            "crate::tx::eip712::cowswap::decode_canonical",
            "crate::iso7816::tlv_parse",
            "crate::iso7816::parse_pin_ctr",
            "fw_manifest::ManifestRef::new",
            "crate::aa::userop::reconstruct_execute_calldata",
        ];
        for parser in required {
            assert!(
                FUZZ_PROPS_SRC.contains(parser),
                "fuzz_props.rs must cover `{parser}` — silent drop would \
                 leave a NS→S parser unfuzzed."
            );
        }
    }

    /// The harness is `#![cfg(test)]` so it never ships in firmware.
    #[test]
    fn negative_fuzz_props_is_test_only() {
        assert!(
            FUZZ_PROPS_SRC.contains("#![cfg(test)]"),
            "fuzz_props.rs must be #![cfg(test)] — shipping proptest into \
             a no_std firmware build would not even compile (std-only \
             dep)."
        );
    }
}
