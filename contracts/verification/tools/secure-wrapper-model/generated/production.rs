use crate::sphincs_c10;
use crate::zeroize::Zeroize;
const CFI_STEP_RATE_LIMIT:  u32 = 0xA1_5A_1357;
const CFI_STEP_OPT_RAND:    u32 = 0xB2_5B_2468;
const CFI_STEP_SHUFFLE:     u32 = 0xC3_5C_3579;
const CFI_STEP_SIGN_A:      u32 = 0xD4_5D_468A;
const CFI_STEP_SIGN_B:      u32 = 0xE5_5E_579B;
const CFI_STEP_CT_EQ:       u32 = 0xF6_5F_68AC;
const CFI_STEP_VERIFY_GATE: u32 = 0x17_60_79BD;

/// Private hand-off proving one caller-side rate charge completed before the
/// shared signing body.  The mode choice stays in the two separate entrypoints;
/// no runtime enum can fault a forced request into the ordinary charge path.
struct VerifiedRateCharge(u32);

pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: ((), ()),
    effects: &mut crate::Effects,
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session(effects);
        crate::sign_rate::pre_sign(effects)?;
        if crate::sign_rate::signs_this_session(effects) != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
        effects,
        VerifiedRateCharge(crate::fi::OK_SENTINEL),
    )
}

/// Forced-flow counterpart to [`c10_sign_verified_with_progress`].
///
/// The cryptographic computation and seven-step CFI transcript are identical;
/// only the rate step differs.  Before any key use, the forced step rechecks
/// and consumes exactly one charge against the frozen request-bound receipt.
#[cfg(feature = "erc7730-forced-blind")]
pub(crate) fn c10_sign_verified_forced_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: ((), ()),
    effects: &mut crate::Effects,
    rate_receipt: &crate::sign_rate::ForcedRateReceipt,
    request_digest: &[u8; 32],
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(test)]
    let _ = (rate_receipt, request_digest);
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session(effects);
        crate::sign_rate::pre_sign_forced(effects, rate_receipt, request_digest).map_err(|_| ())?;
        if crate::sign_rate::signs_this_session(effects) != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
        effects,
        VerifiedRateCharge(crate::fi::OK_SENTINEL),
    )
}

#[inline(never)]
fn c10_sign_verified_with_progress_inner(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: ((), ()),
    effects: &mut crate::Effects,
    verified_rate_charge: VerifiedRateCharge,
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    use crate::subtle::ConstantTimeEq;

    // F-18 (CFI): track that every critical step ran. Final check
    // (`cfi.check_into_sentinel(EXPECTED) != OK_SENTINEL`) fails
    // closed if any one of the 7 steps below was skipped by a glitch.
    // Defends the "skip an entire function call" attack class that
    // F-2's sentinel-encoding doesn't reach.
    const CFI_EXPECTED: u32 = crate::cfi_expected!(
        CFI_STEP_RATE_LIMIT,
        CFI_STEP_OPT_RAND,
        CFI_STEP_SHUFFLE,
        CFI_STEP_SIGN_A,
        CFI_STEP_SIGN_B,
        CFI_STEP_CT_EQ,
        CFI_STEP_VERIFY_GATE,
    );
    let mut cfi = crate::fi::CfiCounter::new(effects);

    // F-17 (SCA defense): signing rate limiter. Enforces
    //   - ≥ 1 second between consecutive signs (busy-wait), and
    //   - ≤ 250 signs per unlock session (refuses past the cap).
    // The double-compute below counts as ONE rate-limit charge —
    // one output sig per call, one budget unit. See `sign_rate.rs`
    // for the full threat-model and cost analysis.
    //
    // On refusal (session cap), the function returns Err(()) which
    // the gateway callers translate to `NscStatus::CryptoError`.
    // The companion can prompt the user to re-unlock; a fresh PIN
    // entry re-arms the session budget via `mark_unlocked`.
    //
    // X17-FI2 (playbook FI11): bind the CFI bump to the step's VERIFIED
    // success, not the fallible call's return register. `pre_sign()?`
    // alone lets a glitch that skips `bl pre_sign` with a stale-Ok
    // register waive the F-17 session budget yet still stamp the step —
    // fail-closure there would be ABI luck, not design. `pre_sign`
    // commits by advancing the session counter by exactly one; require
    // that postcondition before bumping (a skip now needs a second,
    // coordinated fault on this read-back).
    if crate::fi::check_true_into_sentinel(effects, || {
        core::hint::black_box(verified_rate_charge.0) == crate::fi::OK_SENTINEL
    }) != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    cfi.bump(effects, CFI_STEP_RATE_LIMIT);

    // FI-hardening, layer 1 of 2: double-compute (RFC 9814 §A.2 / Genêt
    // TCHES 2023). Verify-after-sign alone is *insufficient*: a fault
    // injected during signing can produce a malformed sig that
    // nonetheless verifies cleanly under the honest pubkey while leaking
    // sk_seed bits across multiple traces (faulted hypertree nodes
    // re-derive bottom-up). Two signs over identical inputs MUST be
    // byte-identical; a divergence is diagnostic of a fault on one of
    // the two signs.
    //
    // Cost: ~2× sign latency (~+1.5 s on HW SHA, ~+12 s on QEMU
    // software SHA). The progress callback runs on the first sign so
    // the user sees a 0..100 ramp; the second sign is silent and
    // visually appears as a stretched "verifying..." window.
    //
    // **Non-deterministic OptRand (work-todo #18 / Trezor parity).**
    // We draw a fresh 16-byte randomiser per signing call via
    // `rng_strong::fill` (STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG,
    // 3-source XOR mirroring Trezor's `rng_fill_buffer_strong`).
    // Defends against:
    //   - the deterministic-PRF-tree class (Genêt TCHES 2023): adding
    //     a fresh randomiser breaks the chain of repeated SK re-use
    //     across signatures.
    //   - any single biased / compromised TRNG: the XOR of the
    //     remaining unbroken sources preserves entropy.
    //   - F-9 transparent leak: a fresh randomiser makes the R-grind
    //     iteration count depend on per-call randomness, not just
    //     (sk_seed, message) — removing the TVLA-detectable
    //     msg-dependent count.
    // NOTE: the *cryptographic* chosen-message FORS-saturation defence
    // (upstream SPHINCS- SECURITY-ANALYSIS.md §2 "Avenue B") does NOT
    // rely on this TRNG: `fors::grind_r` derives R as
    // `sha256(sk_seed ‖ "R_grind" ‖ [opt_rand] ‖ message ‖ nonce)`, so
    // `ht_idx` is unpredictable to anyone without the secret key for any
    // chosen message even if this RNG is biased or predictable. OptRand
    // here is defence-in-depth (SCA + Genêt) layered on top of that
    // secret-keyed, message-bound R.
    // The randomiser is drawn ONCE and fed to both signs — re-drawing
    // per sign would still be cryptographically sound but would
    // produce divergent sigs, breaking the byte-equality FI gate.
    //
    // Under `mock-se` (QEMU/dev only) the strong-RNG uses the platform source.
    // Hardware production is compile-fenced to both source-specific SE calls;
    // either missing/failing/non-contributing chip aborts the signature.
    let mut opt_rand_buf = [0u8; sphincs_c10::params::N];
    #[cfg(not(test))]
    if crate::rng_strong::fill(effects, &mut opt_rand_buf).is_err() {
        // `rng_strong::fill` may have written partial platform-TRNG bytes
        // before the SE XOR-fold failed — scrub before bailing, matching
        // every other Err/Ok path in this function (found by the sca-3
        // adversarial review; the fill-failure early-return was the one
        // path that skipped the wipe).
        opt_rand_buf.zeroize(effects);
        crate::fi::zeroize_barrier(effects);
        return Err(());
    }
    // X17-FI2 (playbook FI11): bind the CFI bump to the draw's VERIFIED
    // success, not the fallible call's return register. A glitch that
    // skips `bl rng_strong::fill` (stale-Ok register) leaves this
    // pre-zeroed buffer all-zero — an all-zero OptRand is the Genêt
    // deterministic-reuse class and must never reach signing with every
    // gate green. `rng_strong::fill`'s own internal all-zero gate
    // cannot catch this (it was skipped along with the call), so the
    // acceptance check is repeated here, outside the call, before the
    // step is stamped. OR-accumulator: no short-circuit, no early-out
    // branch on the scan.
    #[cfg(not(test))]
    {
        let mut acc: u8 = 0;
        for &b in opt_rand_buf.iter() {
            acc |= b;
        }
        if acc == 0 {
            opt_rand_buf.zeroize(effects);
            crate::fi::zeroize_barrier(effects);
            return Err(());
        }
    }
    let opt_rand: Option<&[u8; sphincs_c10::params::N]> = Some(&opt_rand_buf);
    cfi.bump(effects, CFI_STEP_OPT_RAND);

    // **F-16 (DPA-defence) shuffle seeds — one INDEPENDENT seed per
    // double-compute pass.** Each of the two mandatory signs draws its
    // own fresh seed from `rng_strong::fill` (STM32 ⊕ OPTIGA ⊕ SE050
    // XOR-fold). The shuffle randomises only the COMPUTATION ORDER of
    // WOTS chains (43! ≈ 10^52 per layer) and FORS trees (13! ≈ 6×10^9);
    // the produced signature bytes are byte-identical for ANY seed
    // (proven invariant `sphincs-c10/src/shuffle.rs`, regression-tested
    // for two distinct nonzero seeds in `tests/shuffle_byte_equality.rs`
    // `two_distinct_nonzero_shuffles_byte_equal`). So the two 4008-byte
    // signatures stay byte-identical (F-13 ct_eq) and verify-before-
    // release still holds unchanged — this stays fully inside the
    // double-compute → compare → verify countermeasure and does NOT
    // weaken it.
    //
    // Why INDEPENDENT seeds, not one shared seed fed to both passes:
    //   - SCA: a shared seed makes both passes traverse WOTS/FORS in the
    //     SAME order → two perfectly time-aligned traces of the same
    //     secret computation per signature (a free ~√2 profiled-DPA
    //     denoise) on the exact alignment this shuffle exists to deny.
    //     Independent seeds keep the two passes mutually mis-aligned.
    //   - FI: under `hw-sha256` the HW SHA-256 engine is a single point
    //     trusted by BOTH signs and the verify. A *deterministic*,
    //     position-triggered HASH fault would otherwise corrupt sign_a
    //     and sign_b at the SAME computation step → identical faulted
    //     output → slip the ct_eq gate (the Genêt TCHES-2023 grafting
    //     class the double-compute exists to block). Independent order
    //     lands the same fault on DIFFERENT WOTS/FORS positions per pass
    //     → divergent sigs → caught by ct_eq.
    // Failure-mode note: were byte-invariance ever to fail for some
    // (sk, msg, opt_rand), the effect is a false-reject signing DoS
    // (fail-closed), never a forged or leaked signature. (Contrast
    // `opt_rand` above, which IS part of the signature value and is
    // therefore DELIBERATELY shared across both passes.)
    let mut shuffle_seed_a = [0u8; 32];
    let mut shuffle_seed_b = [0u8; 32];
    #[cfg(not(test))]
    if crate::rng_strong::fill(effects, &mut shuffle_seed_a).is_err()
        || crate::rng_strong::fill(effects, &mut shuffle_seed_b).is_err()
    {
        shuffle_seed_a.zeroize(effects);
        shuffle_seed_b.zeroize(effects);
        opt_rand_buf.zeroize(effects);
        crate::fi::zeroize_barrier(effects);
        return Err(());
    }
    // X17-FI2 (playbook FI11): same verified-success binding as the
    // OptRand draw above — a glitch that skips one `bl rng_strong::fill`
    // (stale-Ok register) leaves that seed all-zero, i.e. a known,
    // predictable shuffle order (the F-16 DPA defence gone) with every
    // gate green. Require BOTH seeds nonzero before stamping the step;
    // each seed's own acceptance check inside `fill` was skipped with
    // the call. OR-accumulators: no short-circuit on the scans.
    #[cfg(not(test))]
    {
        let mut acc_a: u8 = 0;
        let mut acc_b: u8 = 0;
        for i in 0..32 {
            acc_a |= shuffle_seed_a[i];
            acc_b |= shuffle_seed_b[i];
        }
        if acc_a == 0 || acc_b == 0 {
            shuffle_seed_a.zeroize(effects);
            shuffle_seed_b.zeroize(effects);
            opt_rand_buf.zeroize(effects);
            crate::fi::zeroize_barrier(effects);
            return Err(());
        }
    }
    let shuffle_a = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_a);
    let shuffle_b = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_b);
    // `[u8; 32]` is `Copy`, so the constructors above copied — wipe the
    // stack locals now that each secret lives inside its `ZeroizeOnDrop`
    // wrapper.
    shuffle_seed_a.zeroize(effects);
    shuffle_seed_b.zeroize(effects);
    crate::fi::zeroize_barrier(effects);
    cfi.bump(effects, CFI_STEP_SHUFFLE);

    let sig_a = sk.sign_with_shuffle(effects, msg_hash, opt_rand, &shuffle_a, progress.0);
    cfi.bump(effects, CFI_STEP_SIGN_A);
    crate::fi::wait_random(effects);
    // The SECOND HALF of the same ramp (#759), so the film keeps moving on the
    // pixel route and the percentage continues upward on the text route rather
    // than restarting at 0. Like `sign_a`'s it returns unit, captures nothing
    // and receives only a percentage, so it cannot touch the CFI chain, the
    // compare, or the verify-before-release gates below.
    let sig_b = sk.sign_with_shuffle(effects, msg_hash, opt_rand, &shuffle_b, progress.1);
    cfi.bump(effects, CFI_STEP_SIGN_B);

    // Constant-time comparison of the 4008-byte signatures.
    // `subtle::ConstantTimeEq` prevents an attacker from learning
    // *where* the two diverge through a timing side-channel, which
    // could leak FORS-leaf bits in conjunction with F-9.
    //
    // Note: this `if !ct_eq { Err }` is itself a single-instruction-
    // skip point — falling through releases `sig_a` even on mismatch.
    // The verify-before-release below is the second gate: a faulted
    // pair that bypasses this compare still has to produce a sig that
    // verifies under the honest pubkey. Compare + verify form a
    // **2-gate chain**; do not remove the verify on the assumption
    // double-compute makes it redundant.
    if !bool::from(sig_a[..].ct_eq(effects, &sig_b[..])) {
        // fi-2 (Trezor-port): a ct_eq mismatch between the two double-compute
        // passes is a CONFIRMED fault — identical inputs + byte-invariant
        // shuffles mean the two sigs MUST be equal, so a divergence is a glitch
        // corrupting one pass (the Genêt grafting class). Escalate past "reject
        // this one sign" to a full RELOCK: wipe the in-SRAM master + slot
        // secrets and clear `pin_verified` (`zeroize_sensitive_state`), so a
        // glitching attacker can't immediately retry against a still-live key —
        // the next sign requires a fresh PIN. RELOCK, not halt (recoverable).
        // CONFIRMED-fault sites ONLY (this ct_eq, the verify gate, the CFI
        // check) — NEVER the rng-fail / rate-limit / parse rejects above, which
        // would be a self-inflicted DoS.
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state(effects);
        opt_rand_buf.zeroize(effects);
        crate::fi::zeroize_barrier(effects);
        return Err(());
    }
    cfi.bump(effects, CFI_STEP_CT_EQ);

    // FI-hardening, layer 2 of 2: verify-before-release.
    //
    // The boolean check is wrapped by `fi::check_true_into_sentinel`
    // (F-2 fix): a glitch that skips the `if` requires cooperating
    // skips of the double-evaluation AND the hamming-distant sentinel
    // compare. `wait_random()` immediately before the verify defeats
    // clock-aligned fault bursts that time their glitch to the
    // verify's fixed-shape control flow.
    //
    // `core::hint::black_box(v)` is load-bearing — see F-1 in
    // `tools/sca/README.md`: without it LLVM CSEs the two `cond()`
    // evaluations inside `check_true` into a single load of `v` and
    // collapses the `&& v1 && v2` re-check, leaving one skippable
    // branch.
    crate::fi::wait_random(effects);
    let v = sphincs_c10::verify(effects, sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a);
    if crate::fi::check_true_into_sentinel(effects, || core::hint::black_box(v)) != crate::fi::OK_SENTINEL {
        // fi-2: a released sig that fails verify-before-release is a confirmed
        // fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state(effects);
        opt_rand_buf.zeroize(effects);
        crate::fi::zeroize_barrier(effects);
        return Err(());
    }
    cfi.bump(effects, CFI_STEP_VERIFY_GATE);

    // F-18 final CFI check: every critical step bumped the counter
    // with its unique magic; the running total must match the
    // compile-time `CFI_EXPECTED`. A glitch that skipped any one
    // step's `bump` leaves the counter short by exactly that step's
    // magic → fail closed. The three fallible steps (rate limit,
    // OptRand draw, shuffle-seed draws) gate their bumps on VERIFIED
    // step success (X17-FI2): a single-instruction skip of the
    // fallible `bl` alone no longer reaches the bump on a stale
    // return register. The remaining steps are infallible and
    // downstream-gated (a skipped sign diverges at ct_eq). Routed
    // through the F-2 Hamming-distant sentinel idiom so a skip of
    // the verify call itself doesn't bypass.
    if cfi.check_into_sentinel(effects, CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        // fi-2: a short CFI counter means a critical step was skipped by a
        // glitch → confirmed fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state(effects);
        opt_rand_buf.zeroize(effects);
        crate::fi::zeroize_barrier(effects);
        return Err(());
    }

    opt_rand_buf.zeroize(effects);
    crate::fi::zeroize_barrier(effects);
    Ok(sig_a)
}
