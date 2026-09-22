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
const RNG_STRONG_FOLD_SRC: &str = include_str!("rng_strong_fold.rs");
const PIN_DIAG_SRC: &str = include_str!("pin_diag.rs");
const TIMEOUT_SRC: &str = include_str!("timeout.rs");
const CONFIRM_SRC: &str = include_str!("ui/confirm.rs");
const NSC_MOD_SRC: &str = include_str!("nsc/mod.rs");

// ═════════════════════════════════════════════════════════════════════
// 1. Re-mount `timeout.rs` under a host-test scaffold.
//
// Production `mod timeout` is `#[cfg(not(test))]`-excluded because
// `crate::timeout::tick_verified()` is called from a SysTick ISR that doesn't
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
        let pos = FI_SRC
            .find("fn rng_byte() -> u8")
            .expect("rng_byte not found");
        let end = FI_SRC[pos..]
            .find("\n}\n")
            .map(|i| pos + i + 2)
            .unwrap_or(FI_SRC.len());
        let body = &FI_SRC[pos..end.min(FI_SRC.len())];
        assert!(
            body.contains("crate::rng::byte_nonsecret("),
            "fi::rng_byte body must call the platform-only, non-panicking \
             `crate::rng::byte_nonsecret()` (a transient TRNG error must not \
             panic the signer mid-sign) — NOT rng_strong (sign-latency \
             cliff). See fi.rs:30-44 for the rationale."
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
            SIGN_RATE_SRC.contains("cortex_m::asm::wfi();")
                && SIGN_RATE_SRC.contains("if crate::fi::read_volatile_voted(last_addr).is_ok() {"),
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

    #[test]
    fn forced_rate_preflight_and_recheck_are_read_only() {
        let preflight_start = SIGN_RATE_SRC
            .find("pub(crate) fn forced_rate_preflight(")
            .expect("forced rate preflight missing");
        let recheck_start = SIGN_RATE_SRC
            .find("pub(crate) fn forced_rate_recheck(")
            .expect("forced rate recheck missing");
        let reset_start = SIGN_RATE_SRC[recheck_start..]
            .find("pub fn reset_counters()")
            .map(|offset| recheck_start + offset)
            .expect("counter reset must follow forced helpers");
        let helpers = &SIGN_RATE_SRC[preflight_start..reset_start];
        assert!(helpers.contains("SIGNS_THIS_SESSION.as_ptr()"));
        assert!(helpers.contains("LAST_SIGN_MS.as_ptr()"));
        assert!(helpers.contains("crate::timeout::snapshot_verified()"));
        assert!(helpers.contains("cortex_m::asm::wfi();"));
        assert!(
            !helpers.contains("SIGNS_THIS_SESSION.store(")
                && !helpers.contains("LAST_SIGN_MS.store(")
                && !helpers.contains("pre_sign()"),
            "forced pre-warning helpers must neither charge nor update the rate timestamp",
        );
    }

    #[test]
    fn forced_rate_charge_rechecks_then_uses_the_sole_pre_sign_writer_once() {
        let start = SIGN_RATE_SRC
            .find("pub(crate) fn pre_sign_forced(")
            .expect("forced rate charge wrapper missing");
        let end = SIGN_RATE_SRC[start..]
            .find("fn wait_for_min_interval()")
            .map(|offset| start + offset)
            .expect("forced rate charge wrapper end anchor missing");
        let body = &SIGN_RATE_SRC[start..end];

        let recheck = body
            .find("forced_rate_recheck(receipt, request_digest)?")
            .expect("frozen request-bound receipt must be rechecked");
        let sole_charge = body
            .find("pre_sign().map_err(|()| ForcedRateError::SessionCap)?")
            .expect("existing pre_sign must remain the sole writer");
        let count_readback = body
            .find("let count_after = crate::fi::read_volatile_voted(count_addr)")
            .expect("forced charge must independently read back the counter");
        let timestamp_proof = body
            .find("forced_charge_postcondition(")
            .expect("production timestamp must be bracketed by verified ticks");

        assert!(recheck < sole_charge);
        assert!(sole_charge < count_readback);
        assert!(count_readback < timestamp_proof);
        assert_eq!(
            body.matches("pre_sign().map_err(|()| ForcedRateError::SessionCap)?")
                .count(),
            1,
            "forced charge must invoke the existing writer exactly once",
        );
        assert!(!body.contains("SIGNS_THIS_SESSION.store("));
        assert!(!body.contains("LAST_SIGN_MS.store("));
        assert!(body.matches("crate::timeout::snapshot_verified()").count() >= 2);
    }
}

// ═════════════════════════════════════════════════════════════════════
// 11. timeout.rs — exercise via the host-test re-mount.
// ═════════════════════════════════════════════════════════════════════

mod timeout_tests {
    use super::timeout_under_test as t;

    fn tick_once() {
        let mut health = crate::fi::FAIL_SENTINEL;
        let mut cfi = crate::fi::FAIL_SENTINEL;
        t::tick_verified(&mut health, &mut cfi);
        assert_eq!(health, crate::fi::OK_SENTINEL);
        assert_eq!(cfi, t::TICK_CFI_COMPLETE);
    }

    #[test]
    fn positive_constants_are_documented_values() {
        // 2 minutes at ~1 ms tick.
        assert_eq!(t::TIMEOUT_TICKS, 2 * 60 * 1000);
    }

    #[test]
    fn positive_tick_increments_monotonically() {
        let _guard = t::test_lock();
        let before = t::now();
        tick_once();
        let after = t::now();
        // wrapping math: `after - before` is 1 in the common case.
        assert_eq!(after.wrapping_sub(before), 1);
    }

    #[test]
    fn positive_reset_activity_drops_idle_for() {
        let _guard = t::test_lock();
        // Pile on some ticks so idle_for would be nonzero…
        for _ in 0..100 {
            tick_once();
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

    #[test]
    fn positive_trusted_ui_wait_guard_is_nested_raii() {
        assert!(
            !t::trusted_ui_is_waiting(),
            "trusted-UI wait state must start clear"
        );
        let outer = t::TrustedUiWaitGuard::enter();
        assert!(t::trusted_ui_is_waiting());
        {
            let _inner = t::TrustedUiWaitGuard::enter();
            assert!(t::trusted_ui_is_waiting());
        }
        assert!(
            t::trusted_ui_is_waiting(),
            "dropping an inner guard must not clear the outer wait"
        );
        drop(outer);
        assert!(
            !t::trusted_ui_is_waiting(),
            "dropping the final guard must clear trusted-UI wait state"
        );

        let outer = t::TrustedUiWaitGuard::enter();
        let inner = t::TrustedUiWaitGuard::enter();
        t::clear_trusted_ui_wait();
        assert!(
            !t::trusted_ui_is_waiting(),
            "panic/tamper-style emergency clear must revoke all nested waits"
        );
        drop(inner);
        drop(outer);
        assert!(
            !t::trusted_ui_is_waiting(),
            "post-clear guard drops must saturate at zero rather than underflow"
        );
    }
}

mod timeout_source_text {
    use super::{CONFIRM_SRC, NSC_MOD_SRC, TIMEOUT_SRC};

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

    /// The watchdog exception is valid only while the trusted confirm loop is
    /// actually blocked on secure physical input. Expanding its scope over
    /// rendering / parsing / crypto would let those operations evade the
    /// ordinary 30 s busy-handler bound.
    #[test]
    fn negative_confirm_scopes_trusted_ui_guard_to_wait_button() {
        let block_start = CONFIRM_SRC
            .find("let event = match {")
            .expect("confirm must use an explicit expression scope for the input wait");
        let block_end = CONFIRM_SRC[block_start..]
            .find("} {")
            .map(|n| block_start + n)
            .expect("trusted-UI input scope must close before result matching");
        let block = &CONFIRM_SRC[block_start..block_end];
        assert!(block.contains("timeout::TrustedUiWaitGuard::enter()"));
        assert!(block.contains("input().wait_button(&mut wait_abort)"));
        assert!(
            !block.contains("timeout::reset_activity()"),
            "entering a trusted-UI wait must never refresh inactivity; only a real button event may do so"
        );
    }

    /// A forgotten guard must not feed the watchdog forever. The watchdog's
    /// trusted-UI branch is separately gated on `!is_idle()`; pin the timeout
    /// module's side of that contract here.
    #[test]
    fn negative_trusted_ui_guard_does_not_mutate_last_activity() {
        let guard_impl = TIMEOUT_SRC
            .find("impl TrustedUiWaitGuard")
            .expect("TrustedUiWaitGuard impl missing");
        let observer = TIMEOUT_SRC
            .find("pub fn trusted_ui_is_waiting()")
            .expect("trusted UI observer missing");
        let body = &TIMEOUT_SRC[guard_impl..observer];
        assert!(
            !body.contains("LAST_ACTIVITY.store("),
            "trusted UI wait bookkeeping must not extend the unlock timeout"
        );
    }

    /// panic=abort does not run the guard's Drop implementation. Every global
    /// sensitive-state wipe must therefore revoke the watchdog exception
    /// explicitly before it can enter a halt/reset path.
    #[test]
    fn negative_zeroize_revokes_trusted_ui_wait_marker() {
        let start = NSC_MOD_SRC
            .find("pub fn zeroize_sensitive_state()")
            .expect("zeroize_sensitive_state missing");
        let body = &NSC_MOD_SRC[start..(start + 700).min(NSC_MOD_SRC.len())];
        let clear = body
            .find("crate::timeout::clear_trusted_ui_wait();")
            .expect("zeroize must revoke trusted UI watchdog state");
        let state_wipe = body
            .find("state::with_state(|s| s.zeroize_sensitive());")
            .expect("global state wipe missing");
        assert!(
            clear < state_wipe,
            "trusted UI watchdog state must be revoked before secret-state zeroization"
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
    use super::{HOST_RNG_SRC, RNG_SRC, RNG_STRONG_FOLD_SRC, RNG_STRONG_SRC};

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
            RNG_STRONG_FOLD_SRC.contains("fn verify_nonzero_output_into")
                && RNG_STRONG_FOLD_SRC.contains("pub(crate) fn verify_nonzero_output_twice_into")
                && RNG_STRONG_SRC
                    .contains("verify_nonzero_output_twice_into(buf, &mut output_receipt)")
                && RNG_STRONG_SRC
                    .matches("core::ptr::read_volatile(&output_receipt)")
                    .count()
                    >= 2,
            "rng_strong::fill must keep the all-zero acceptance gate — \
             it requires two exact volatile scans plus two caller-owned \
             receipt gates so one skipped Thumb branch cannot release zero."
        );
    }

    /// `rng_strong::fill` is the documented entry point for the
    /// multi-source XOR fold. Caller (`c10_sign_verified_with_progress`)
    /// depends on it returning `Err(())` on platform-TRNG failure (so
    /// the F-13 follow-up's fail-closed semantics hold).
    #[test]
    fn negative_rng_strong_uses_platform_trng_as_baseline() {
        let start = RNG_STRONG_SRC
            .find("pub(crate) fn fill_with_source_draw(")
            .expect("strict common three-source facade must exist");
        let end = RNG_STRONG_SRC[start..]
            .find("/// Strict three-source fill for a caller")
            .map(|n| start + n)
            .expect("strict common facade boundary must exist");
        let common = &RNG_STRONG_SRC[start..end];
        assert!(
            common.contains("let platform_result = crate::rng::fill(buf);")
                && common.contains("platform_result.is_ok() && platform_nonzero != 0")
                && common.matches("buf.zeroize();").count() >= 3,
            "the strict common rng_strong path must fail and wipe when the platform TRNG fails"
        );
    }

    /// `rng_strong::fill` MUST XOR the SE-provided bytes into `buf`,
    /// not REPLACE them. XOR preserves entropy of the platform TRNG
    /// even if the SE is fully compromised. A `=` would let a
    /// compromised SE clamp the buffer. (The fold itself lives in
    /// `rng_strong_fold.rs`, split out of the `#[cfg(not(test))]`
    /// `rng_strong` module so host tests can exercise it.)
    #[test]
    fn negative_rng_strong_xor_folds_se_bytes() {
        assert!(
            RNG_STRONG_FOLD_SRC.contains("buf[off + i] ^= optiga_block[i];")
                && RNG_STRONG_FOLD_SRC.contains("buf[off + i] ^= se050_block[i];"),
            "rng_strong must XOR SE bytes into the buffer (^=) — using \
             `=` lets a compromised SE clamp the buffer and defeats the \
             multi-source entropy preservation argument."
        );
    }

    /// SE-side failure MUST be fatal on production backends — no
    /// silent fall-through. Under EMFI / I2C glitching of one SE,
    /// degrading entropy to STM32-only without surfacing the failure
    /// is exactly the attack we want to refuse. The dev-only
    /// `mock-se` backend has no TRNG and is allowed to skip the SE
    /// layer (guarded by `#[cfg(feature = "mock-se")]`).
    #[test]
    fn negative_rng_strong_se_failure_is_fatal() {
        // Production path: the fold itself owns receipt promotion and wipes
        // the platform baseline on failure. There must be no caller-side
        // plain-bool promotion branch that a single instruction fault can
        // invert into OK.
        assert!(
            RNG_STRONG_SRC
                .contains("fold_se_sources(buf, source_draw, source_history, &mut fold_receipt);")
                && !RNG_STRONG_SRC.contains("if fold_ok")
                && RNG_STRONG_FOLD_SRC
                    .contains("core::ptr::write_volatile(fold_receipt, crate::fi::OK_SENTINEL)")
                && RNG_STRONG_FOLD_SRC.contains("buf.zeroize();")
                && RNG_STRONG_SRC.contains("if se_ok != crate::fi::OK_SENTINEL")
                && RNG_STRONG_SRC.contains("return Err(());"),
            "rng_strong production branch must propagate SE failure as \
             Err — silent fall-through would let an EMFI attacker \
             degrade entropy unnoticed."
        );
        // Mock-only path: keeps the fold's return value ignored so QEMU
        // dev builds work.
        assert!(
            RNG_STRONG_SRC.contains("feature = \"mock-se\""),
            "rng_strong must retain a `mock-se`-gated branch that \
             tolerates the absent TRNG on the mock backend."
        );
    }

    /// S2-F13 / #442: the production SE-failure gate must use the
    /// codebase's FI-sentinel idiom (`fi::check_true_into_sentinel` +
    /// an `!= crate::fi::OK_SENTINEL` VALUE compare), not a plain
    /// single-skippable `if !bool` branch. SCAFI-6/F18 doctrine:
    /// attacker-bypass-target gates are Hamming-distant sentinels.
    #[test]
    fn negative_rng_strong_se_failure_gate_uses_fi_sentinel() {
        assert!(
            RNG_STRONG_SRC.contains("check_true_into_sentinel"),
            "rng_strong production SE-failure gate must evaluate through \
             fi::check_true_into_sentinel (S2-F13/#442) — a plain `if !bool` \
             is one instruction-skip away from waiving the fatal-SE check"
        );
        assert!(
            RNG_STRONG_SRC.contains("!= crate::fi::OK_SENTINEL"),
            "rng_strong production SE-failure gate must compare the sentinel \
             VALUE against OK_SENTINEL, not branch on a bool (S2-F13/#442)"
        );
        assert!(
            RNG_STRONG_FOLD_SRC
                .matches("core::ptr::read_volatile(&source_receipt)")
                .count()
                >= 2,
            "the fold must retain two independent volatile source-receipt checks; \
             ordinary duplicate comparisons are folded into one branch by LLVM"
        );
    }

    /// Phase-D partial-fold regression: source-presence receipts alone do not
    /// prove that the stateful XOR loop reached every byte or stayed inside the
    /// current chunk. The fold must retain a platform baseline, publish an
    /// exact volatile output-store count, independently read back the exact
    /// P^O^S relation twice, and advance `off` only after all fail-initialized
    /// receipts pass. Otherwise a skipped loop backedge can publish OK after
    /// mixing byte 0, while a skipped decrement can overwrite byte `len` and
    /// let the next chunk adopt that corruption as its platform baseline.
    #[test]
    fn negative_rng_strong_binds_success_to_exact_chunk_completion() {
        let verify_pos = RNG_STRONG_FOLD_SRC
            .find("fn verify_mixed_chunk_into")
            .expect("exact mix verifier missing");
        let fold_pos = RNG_STRONG_FOLD_SRC
            .find("pub(crate) fn fold_se_sources")
            .expect("SE fold missing");
        let verifier = &RNG_STRONG_FOLD_SRC[verify_pos..fold_pos];
        assert!(RNG_STRONG_FOLD_SRC.contains("#[inline(never)]\nfn verify_mixed_chunk_into"));
        for needle in [
            "core::ptr::write_volatile(mix_receipt, crate::fi::FAIL_SENTINEL)",
            "core::ptr::read_volatile(mixed.as_ptr().add(i))",
            "core::ptr::read_volatile(platform.as_ptr().add(i))",
            "core::ptr::read_volatile(optiga.as_ptr().add(i))",
            "core::ptr::read_volatile(se050.as_ptr().add(i))",
            "core::ptr::write_volatile(&mut processed, i as u32 + 1)",
            "core::ptr::read_volatile(&processed)",
            "processed != mixed.len() as u32 || diff != 0",
            "core::ptr::write_volatile(mix_receipt, crate::fi::OK_SENTINEL)",
        ] {
            assert!(verifier.contains(needle), "mix verifier missing {needle}");
        }

        let fold_end = RNG_STRONG_FOLD_SRC[fold_pos..]
            .find("\n#[cfg(test)]")
            .map(|p| p + fold_pos)
            .expect("SE fold test-module boundary missing");
        let fold = &RNG_STRONG_FOLD_SRC[fold_pos..fold_end];
        let baseline = fold
            .find("platform_block[..len].copy_from_slice(&buf[off..off + len]);")
            .expect("platform baseline copy missing");
        let xor = fold
            .find("buf[off + i] ^= optiga_block[i];")
            .expect("OPTIGA fold missing");
        let xor_se050 = fold
            .find("buf[off + i] ^= se050_block[i];")
            .expect("SE050 fold missing");
        let mixer_publish = fold
            .find("core::ptr::write_volatile(&mut mixed_bytes, i + 1)")
            .expect("volatile mixer store-count publication missing");
        let mixer_verify = fold
            .find("verify_exact_completion_into(&mixed_bytes, len, &mut mixer_receipt)")
            .expect("exact mixer store-count proof missing");
        let verify_a = fold
            .find("verify_mixed_chunk_into(")
            .expect("first exact mix proof missing");
        let verify_b = fold[verify_a + 1..]
            .find("verify_mixed_chunk_into(")
            .map(|p| p + verify_a + 1)
            .expect("second exact mix proof missing");
        let advance = fold
            .find("publish_verified_progress_into(")
            .expect("receipt-bound chunk advance missing");
        let promote = fold
            .find("core::ptr::write_volatile(fold_receipt, crate::fi::OK_SENTINEL)")
            .expect("fold success promotion missing");
        assert!(
            baseline < xor
                && xor < xor_se050
                && xor_se050 < mixer_publish
                && mixer_publish < mixer_verify
                && mixer_verify < verify_a
                && verify_a < verify_b
        );
        assert!(verify_b < advance && advance < promote);
        assert!(
            !fold.contains("off += len;"),
            "a raw cursor advance can be hoisted into a stale pre-draw spill"
        );
        assert!(
            fold.matches("core::ptr::read_volatile(&mixer_receipt)")
                .count()
                >= 2,
            "the exact mixer count needs two volatile rejection gates"
        );
        assert!(
            fold.matches("core::ptr::read_volatile(&mix_receipt)")
                .count()
                >= 2,
            "both exact-mix calls need independent volatile receipt gates"
        );
        assert!(
            fold.contains("platform_block.zeroize();"),
            "the retained platform baseline must be wiped"
        );
    }

    /// A verified chunk is still only a prefix of a multi-chunk request. The
    /// outer loop's fall-through must independently prove that the volatile
    /// completed-byte count equals the original buffer length; otherwise a
    /// skipped outer backedge after chunk 1 can still mint fold success.
    #[test]
    fn negative_rng_strong_binds_success_to_exact_total_completion() {
        let exact_pos = RNG_STRONG_FOLD_SRC
            .find("fn verify_exact_completion_into")
            .expect("exact total-completion verifier missing");
        let progress_pos = RNG_STRONG_FOLD_SRC
            .find("fn publish_verified_progress_into")
            .expect("verified progress publisher missing");
        let mix_pos = RNG_STRONG_FOLD_SRC
            .find("fn verify_mixed_chunk_into")
            .expect("exact mix verifier missing");
        let exact = &RNG_STRONG_FOLD_SRC[exact_pos..progress_pos];
        assert!(RNG_STRONG_FOLD_SRC.contains("#[inline(never)]\nfn verify_exact_completion_into"));
        for needle in [
            "core::ptr::write_volatile(completion_receipt, crate::fi::FAIL_SENTINEL)",
            "core::ptr::read_volatile(completed_bytes)",
            "!= expected_bytes",
            "crate::fi::wait_random();",
            "core::ptr::write_volatile(completion_receipt, crate::fi::OK_SENTINEL)",
        ] {
            assert!(
                exact.contains(needle),
                "completion verifier missing {needle}"
            );
        }
        assert!(
            exact
                .matches("core::ptr::read_volatile(completed_bytes)")
                .count()
                >= 2,
            "exact completion must independently read volatile progress twice"
        );

        let progress = &RNG_STRONG_FOLD_SRC[progress_pos..mix_pos];
        assert!(RNG_STRONG_FOLD_SRC.contains("#[inline(never)]\nfn publish_verified_progress_into"));
        for needle in [
            "core::ptr::write_volatile(progress_receipt, crate::fi::FAIL_SENTINEL)",
            "current_a.checked_add(len_a)",
            "completed_a != current_a",
            "current_b.checked_add(len_b)",
            "completed_b != current_b",
            "mixed_a != len_a",
            "mixed_b != len_b",
            "next_b != next_a",
            "core::ptr::write_volatile(completed_ptr_a, next_a)",
            "core::ptr::write_volatile(completed_ptr_b, next_b)",
            "core::ptr::write_volatile(progress_receipt, crate::fi::OK_SENTINEL)",
        ] {
            assert!(
                progress.contains(needle),
                "progress publisher missing {needle}"
            );
        }
        assert!(
            progress
                .matches("core::ptr::read_volatile(completed_ptr")
                .count()
                >= 4,
            "progress publisher needs two cursor proofs and two publication readbacks"
        );
        assert!(progress.contains("completed_bytes: *mut usize"));
        assert!(progress.contains("mixed_bytes: *const usize"));
        assert!(
            progress
                .matches("core::ptr::eq(completed_ptr")
                .count()
                >= 2,
            "fault-created cursor/mixer alias needs two independent rejection checks"
        );
        assert!(
            progress
                .matches("core::ptr::read_volatile(&completed_pointer_slot)")
                .count()
                >= 2
                && progress
                    .matches("core::ptr::read_volatile(&mixed_pointer_slot)")
                    .count()
                    >= 2,
            "both raw pointer identities must be snapshotted twice with volatile loads"
        );

        let fold_pos = RNG_STRONG_FOLD_SRC
            .find("pub(crate) fn fold_se_sources")
            .expect("SE fold missing");
        let fold_end = RNG_STRONG_FOLD_SRC[fold_pos..]
            .find("\n#[cfg(test)]")
            .map(|p| p + fold_pos)
            .expect("SE fold test-module boundary missing");
        let fold = &RNG_STRONG_FOLD_SRC[fold_pos..fold_end];
        let init = fold
            .find("crate::rng_exact::initialize_exact_progress_into(")
            .expect("receipted canonical progress initialization missing");
        let cursor = fold
            .find("let off = unsafe { core::ptr::read_volatile(&completed_bytes) };")
            .expect("canonical volatile loop cursor missing");
        let publish = fold
            .find("publish_verified_progress_into(")
            .expect("verified-prefix publication missing");
        let published_verify = fold
            .find("let mut published_completion_receipt = crate::fi::FAIL_SENTINEL;")
            .expect("post-publication canonical cursor proof missing");
        let verify = fold
            .find("verify_exact_completion_into(&completed_bytes, buf.len(), &mut completion_receipt)")
            .expect("post-loop exact completion proof missing");
        let promote = fold
            .find("core::ptr::write_volatile(fold_receipt, crate::fi::OK_SENTINEL)")
            .expect("fold success promotion missing");
        assert!(
            init < cursor
                && cursor < publish
                && publish < published_verify
                && published_verify < verify
                && verify < promote
        );
        assert!(fold[..cursor].contains("let mut completed_bytes = usize::MAX;"));
        assert!(
            fold[..cursor]
                .matches("core::ptr::read_volatile(&progress_init_receipt)")
                .count()
                >= 2,
            "canonical progress initialization needs two caller receipt gates"
        );
        assert!(fold.contains("core::ptr::addr_of_mut!(completed_bytes),"));
        assert!(fold.contains("core::ptr::addr_of!(mixed_bytes),"));
        assert!(
            !fold.contains("off += len;")
                && !fold.contains("core::ptr::write_volatile(&mut completed_bytes, off)"),
            "final completion must not consume a separately advanced cursor"
        );
        assert!(
            fold.matches("core::ptr::read_volatile(&progress_receipt)")
                .count()
                >= 2,
            "verified progress publication needs two caller receipt gates"
        );
        assert!(
            fold.matches("core::ptr::read_volatile(&completion_receipt)")
                .count()
                >= 2,
            "post-loop completion receipt needs two volatile rejection gates"
        );
        assert!(
            fold.matches("core::ptr::read_volatile(&published_completion_receipt)")
                .count()
                >= 2,
            "each chunk needs two caller gates on the canonical post-publication proof"
        );
    }

    /// Whole-program LTO must not specialize the fold to today's ≤32-byte
    /// callers and erase its documented 33/40/48/65-byte chunking behavior.
    /// The exported, non-inlined selector is also required by the final-ELF
    /// audit, so loss of the artifact boundary becomes a release-gate failure.
    #[test]
    fn negative_rng_strong_retains_generic_chunk_selector_in_linked_artifact() {
        for needle in [
            "#[inline(never)]\n#[export_name = \"pqsigner_rng_source_chunk_len\"]",
            "pub(crate) extern \"C\" fn source_chunk_len",
            "core::ptr::read_volatile(&remaining_live)",
            "let len = source_chunk_len(remaining);",
            "fn validate_source_chunk_len_into",
            "len_a > MAX_SOURCE_BLOCK",
            "len_b > MAX_SOURCE_BLOCK",
            "validate_source_chunk_len_into(remaining, len, &mut chunk_receipt)",
        ] {
            assert!(RNG_STRONG_FOLD_SRC.contains(needle), "missing {needle}");
        }
        assert!(
            RNG_STRONG_FOLD_SRC
                .matches("core::ptr::read_volatile(&chunk_receipt)")
                .count()
                >= 2,
            "the caller must reject an unchecked selector result twice before slicing scratch"
        );
    }

    /// Finding F27: the SE fold must hand the backend a FRESH, zeroed
    /// block per chunk — `DualSecureElement::random` XORs into the
    /// caller's buffer, so reusing the previous chunk's block would
    /// re-fold chunk N's `OPTIGA ⊕ SE050` bytes into chunk N+1 and let
    /// a repeat-stream fault on both SE TRNGs silently cancel the SE
    /// contribution for the tail. The behavioural proof lives in
    /// `rng_strong_fold.rs`'s `tests` module (compiled on host because
    /// the fold is pure and kept out of the `#[cfg(not(test))]`
    /// `rng_strong` module); this pins the load-bearing line against
    /// accidental deletion.
    #[test]
    fn negative_rng_strong_zeroes_block_before_every_se_draw() {
        let pos = RNG_STRONG_FOLD_SRC
            .find("fn fold_se_sources")
            .expect("rng_strong must fold separate SE sources");
        let body = &RNG_STRONG_FOLD_SRC[pos..];
        let zero = body
            .find("optiga_block[..len].fill(0);")
            .expect("OPTIGA zero");
        let zero2 = body
            .find("se050_block[..len].fill(0);")
            .expect("SE050 zero");
        let draw = body.find("draw(SeSource::Optiga").expect("OPTIGA draw");
        let draw2 = body.find("draw(SeSource::Se050").expect("SE050 draw");
        assert!(
            zero < draw && zero2 < draw2,
            "each source block must be zeroed BEFORE its draw"
        );
    }

    #[test]
    fn negative_rng_strong_rejects_replayed_physical_source_responses() {
        for needle in [
            "pub(crate) struct SourceRepeatState",
            "optiga_history_differ",
            "se050_history_differ",
            "history_overlap != 0 && optiga_history_differ == 0",
            "history_overlap != 0 && se050_history_differ == 0",
            "fn commit_source_history_into",
            "fn verify_committed_source_history_into",
            "SOURCE_HISTORY_POISONED",
            "crate::rng_exact::publish_region_pointer_into(",
            "core::ptr::addr_of!(published_history_optiga_source)",
            "core::ptr::addr_of!(published_history_se050_source)",
            "core::ptr::addr_of!(published_history_optiga_destination)",
            "core::ptr::addr_of!(published_history_se050_destination)",
            "core::ptr::write_volatile(&mut processed_a, i + 1)",
            "core::ptr::write_volatile(&mut processed_b, i + 1)",
        ] {
            assert!(RNG_STRONG_FOLD_SRC.contains(needle), "missing {needle}");
        }
        for needle in [
            "static STRONG_RNG_BUSY: AtomicBool",
            "static mut SOURCE_REPEAT_STATE: SourceRepeatState",
            "StrongRngGuard::try_acquire()",
        ] {
            assert!(RNG_STRONG_SRC.contains(needle), "missing {needle}");
        }

        let fold = &RNG_STRONG_FOLD_SRC[RNG_STRONG_FOLD_SRC
            .find("fn fold_se_sources")
            .expect("strong-RNG fold missing")..];
        let caller_poison = fold
            .find("core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);")
            .expect("caller-side history poison missing");
        let first_history_endpoint = fold
            .find("let mut published_history_optiga_source")
            .expect("first fallible history endpoint publication missing");
        let commit = fold
            .find("commit_source_history_into(")
            .expect("history commit call missing");
        assert!(
            caller_poison < first_history_endpoint,
            "history must be poisoned immediately after health acceptance and before any fallible endpoint setup"
        );
        assert!(
            fold[..first_history_endpoint]
                .matches("core::ptr::write_volatile(&mut history.status, SOURCE_HISTORY_POISONED);")
                .count()
                >= 2,
            "caller needs duplicate volatile poison stores before the first fallible endpoint gate"
        );
        let relation = fold[commit..]
            .find("verify_committed_source_history_into(")
            .expect("independent committed-history postcondition missing")
            + commit;
        assert!(
            commit < relation,
            "the committed history must be checked against the live caller blocks"
        );
        assert!(
            fold[relation..]
                .matches("core::ptr::read_volatile(&history_relation_receipt)")
                .count()
                >= 2,
            "the caller must gate on the committed-history relation twice"
        );
    }

    #[test]
    fn negative_rng_strong_requires_independent_optiga_and_se050_receipts() {
        for needle in [
            "optiga_ok",
            "se050_ok",
            "platform_nonzero == 0",
            "optiga_nonzero == 0",
            "se050_nonzero == 0",
            "optiga_se050_differ == 0",
            "platform_optiga_differ == 0",
            "platform_se050_differ == 0",
            "fn verify_source_health_into",
            "core::ptr::write_volatile(&mut processed, i + 1)",
            "processed != platform.len()",
            "SeSource::Optiga",
            "SeSource::Se050",
        ] {
            assert!(RNG_STRONG_FOLD_SRC.contains(needle), "missing {needle}");
        }
        assert!(
            RNG_STRONG_FOLD_SRC
                .matches("verify_source_health_into(")
                .count()
                >= 3,
            "one definition plus two independent full health scans are required"
        );
        assert!(RNG_STRONG_SRC.contains("store.random_optiga(block)"));
        assert!(RNG_STRONG_SRC.contains("store.random_se050(block)"));
    }

    #[test]
    fn negative_rng_backend_receipt_is_cfg_coupled_and_retained() {
        assert!(RNG_SRC.contains("PQ1_RNG_BACKEND=STM32U585_TRNG\\0"));
        assert!(RNG_SRC.contains("PQ1_RNG_BACKEND=HOST_URANDOM\\0"));
        assert!(RNG_SRC.contains("PQ1_STRONG_RNG_SOURCES=STM32U585+OPTIGA_TRUST_M+SE050\\0"));
        assert!(RNG_SRC.contains("PQ1_STRONG_RNG_SOURCES=DEVELOPMENT_OR_INCOMPLETE\\0"));
        assert!(RNG_SRC.contains("#[link_section = \".pqsigner.rng_backend\"]"));
        assert!(RNG_SRC.contains("read_volatile(PQSIGNER_RNG_BACKEND.as_ptr())"));
        assert!(RNG_SRC.contains("read_volatile(PQSIGNER_STRONG_RNG_SOURCES.as_ptr())"));
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
// original brick bug. See `docs/secure-elements/optiga-brick-postmortem.md`.
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
             docs/secure-elements/optiga-brick-postmortem.md)."
        );
    }

    /// `run()` MUST pulse PA4, PD5, PE0 in that order — the empirically
    /// validated sequence that produces a visible OPTIGA RST edge.
    /// Reordering or dropping any of them caused "no visible edge on the
    /// LA" (see pin_diag.rs:113-128). The PE0 leg moved to the
    /// datasheet-bounded `pulse_low_cycles` form (10 µs ≤ t_low ≤ 2.5 ms,
    /// OPTIGA Table 14) in origin commit `2368003a`; the pin therefore
    /// accepts exactly that call shape and rejects a regression to the
    /// old unbounded `pulse_low` form.
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
        let pa4_pos = body
            .find("pulse_low(GPIOA_BASE, 4,")
            .expect("PA4 pulse missing");
        let pd5_pos = body
            .find("pulse_low(GPIOD_BASE, 5,")
            .expect("PD5 pulse missing");
        let pe0_pos = body
            .find("pulse_low_cycles(GPIOE_BASE, 0,")
            .expect("PE0 pulse missing (datasheet-bounded pulse_low_cycles form)");
        assert!(
            pa4_pos < pd5_pos && pd5_pos < pe0_pos,
            "pulse order must be PA4 → PD5 → PE0 (PE0 is the actual OPTIGA \
             RST wire; PA4/PD5 are empirically-load-bearing preamble decoys)."
        );
        assert!(
            !body.contains("pulse_low(GPIOE_BASE, 0,"),
            "PE0 must use the datasheet-bounded pulse_low_cycles form \
             (RST_LOW_CYCLES; OPTIGA Table 14 t_low ≤ 2.5 ms), not the old \
             ~60 ms unbounded pulse_low."
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

/// The TRNG must run ST's AN4230 values for THIS part, not another part's.
///
/// #704: the driver wrote `RNG_HTCR = 0xAAC7` — RM0456 Table 464's generic
/// configuration-C row — and never wrote `RNG_NSCR` at all (the register was
/// not even mapped). `stm32u585xx.h` ships the per-product AN4230 values under
/// "RNG Nist Compliance Values", and `0xAAC7` is what the U535/U545 headers
/// define: the two parts with **no NSCR register**. U575/U585, which have one,
/// use `0xA2B0` + `0x17CBB`. Health-test thresholds are matched to the noise
/// source, so the old pairing ran our health tests against thresholds meant for
/// different noise hardware — the same class of mismatch as #698.
#[test]
fn positive_trng_uses_this_parts_an4230_values() {
    const HW_RNG_SRC: &str = include_str!("hw/rng.rs");

    // The health-test value must be U575/U585's, and the U535/U545 one must be
    // gone — keeping both would let a careless edit reinstate the wrong pair.
    assert!(
        HW_RNG_SRC.contains("const RNG_HTCR_AN4230: u32 = 0x0000_A2B0;"),
        "HTCR must be the AN4230 value for a part that HAS an NSCR"
    );
    assert!(
        !HW_RNG_SRC.contains("0x0000_AAC7"),
        "0xAAC7 belongs to U535/U545, which have no NSCR register"
    );

    // NSCR must be mapped, written, and read back. Never-mapped was the whole
    // defect: the noise oscillators ran at their reset selection.
    assert!(
        HW_RNG_SRC.contains("const RNG_NSCR_AN4230: u32 = 0x0001_7CBB;"),
        "NSCR needs this part's AN4230 value"
    );
    assert!(
        HW_RNG_SRC.contains("nscr: Reg32::new(RNG + 0x0C)"),
        "NSCR must be mapped at offset 0x0C or it cannot be written at all"
    );
    assert!(
        HW_RNG_SRC.contains("REG.nscr.write(RNG_NSCR_AN4230);"),
        "NSCR must actually be written"
    );
    assert!(
        HW_RNG_SRC.contains("if nscr_after != RNG_NSCR_AN4230 {"),
        "a silently-ignored NSCR write must fail closed, like HTCR's"
    );

    // CONFIGLOCK completes E11 Table 2's RNG_CR (0x80F00DXX) and, per RM0456
    // 48.3.4, is what preserves the configuration across the software reset our
    // seed-error recovery performs. It must be the LAST write: locking before
    // the read-backs have passed would freeze a configuration nobody verified.
    assert!(
        HW_RNG_SRC.contains("const CONFIGLOCK: u32 = 1 << 31;"),
        "CONFIGLOCK is bit 31 per RM0456 48.7.1"
    );
    assert!(
        HW_RNG_SRC.contains("if cr_locked & CONFIGLOCK == 0 {"),
        "a lock that did not take must fail closed"
    );
    let htcr_check = HW_RNG_SRC.find("if htcr_after != RNG_HTCR_AN4230 {");
    let nscr_check = HW_RNG_SRC.find("if nscr_after != RNG_NSCR_AN4230 {");
    let lock = HW_RNG_SRC.find("REG.cr.write(RNG_CR_NIST_DEFAULT | RNGEN | CONFIGLOCK);");
    assert!(htcr_check.is_some() && nscr_check.is_some() && lock.is_some());
    assert!(
        htcr_check < lock && nscr_check < lock,
        "CONFIGLOCK must be set AFTER both read-backs, or a bad config gets frozen"
    );

    // Both config writes only take effect while CONDRST=1, so they must sit
    // between entering and leaving the conditioning-reset window.
    let enter = HW_RNG_SRC.find("REG.cr.write(RNG_CR_NIST_DEFAULT | CONDRST);");
    let nscr = HW_RNG_SRC.find("REG.nscr.write(RNG_NSCR_AN4230);");
    let leave = HW_RNG_SRC.find("REG.cr.write(RNG_CR_NIST_DEFAULT);");
    assert!(enter.is_some() && nscr.is_some() && leave.is_some());
    assert!(
        enter < nscr && nscr < leave,
        "NSCR must be written INSIDE the CONDRST window, or the write is ignored"
    );
}

