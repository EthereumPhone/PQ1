//! Crypto helpers — secure-side wrapper around [`pqsigner_domain`].
//!
//! The pure-logic primitives (KDFs, AES-GCM wrap/unwrap, BIP-39 ↔
//! SPHINCS+C10 derivation, slot-key derivation, PIN-state encoding) live
//! in [`pqsigner_domain`] so host-side reference signers can reuse them
//! without the secure-world hardware deps.
//!
//! What stays here:
//!
//! * [`c10_sign_verified_with_progress`] — the FI-hardened
//!   verify-before-release wrapper. Depends on [`crate::fi`], whose
//!   hardening primitives are keyed off the secure-world TRNG.
//! * [`provision_from_mnemonic`] / [`store_macd_encrypted`] — the
//!   `WalletStore` + `SecureElement` provisioning entry points used by
//!   the wizard and by the mock backend. These touch the
//!   secure-side `crate::secure_element::*` traits with r-mem
//!   semantics, so they cannot live in the pure-logic crate.
//!
//! Every other public name in [`pqsigner_domain`] is re-exported below.

pub use pqsigner_domain::*;

use crate::secure_element::SecureElement;
use sphincs_tz_bip39::Mnemonic;
use zeroize::Zeroize;

/// Sign a 32-byte message hash with the bootstrap C10 signing key and
/// the (optional) randomiser. Wraps `sphincs_c10::SigningKey::sign`
/// with a verify-before-release fault-injection guard. Reports 0..100
/// signing progress via the supplied callback so the trusted-UI
/// progress bar stays responsive during the multi-second C10
/// signature.
///
/// Produces 4008-byte C10 signatures — see `sphincs-c10/src/params.rs`.
// F-18 (CFI): per-step magic constants for `c10_sign_verified_with_progress`.
//
// Distinct, non-trivial 32-bit values so no subset of skipped steps
// can sum to the same gap as another subset. Hex prefixes are
// mnemonic (0xA1 = "rate-limit", 0xB2 = "opt_rand", etc.) — the
// actual numeric value is what matters for FI defense.
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
    progress: fn(u8),
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session();
        crate::sign_rate::pre_sign()?;
        if crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
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
    progress: fn(u8),
    rate_receipt: &crate::sign_rate::ForcedRateReceipt,
    request_digest: &[u8; 32],
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(test)]
    let _ = (rate_receipt, request_digest);
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session();
        crate::sign_rate::pre_sign_forced(rate_receipt, request_digest).map_err(|_| ())?;
        if crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
        VerifiedRateCharge(crate::fi::OK_SENTINEL),
    )
}

#[inline(never)]
fn c10_sign_verified_with_progress_inner(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: fn(u8),
    verified_rate_charge: VerifiedRateCharge,
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    use subtle::ConstantTimeEq;

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
    let mut cfi = crate::fi::CfiCounter::new();

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
    if crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(verified_rate_charge.0) == crate::fi::OK_SENTINEL
    }) != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    cfi.bump(CFI_STEP_RATE_LIMIT);

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
    if crate::rng_strong::fill(&mut opt_rand_buf).is_err() {
        // `rng_strong::fill` may have written partial platform-TRNG bytes
        // before the SE XOR-fold failed — scrub before bailing, matching
        // every other Err/Ok path in this function (found by the sca-3
        // adversarial review; the fill-failure early-return was the one
        // path that skipped the wipe).
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
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
            opt_rand_buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
    }
    let opt_rand: Option<&[u8; sphincs_c10::params::N]> = Some(&opt_rand_buf);
    cfi.bump(CFI_STEP_OPT_RAND);

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
    if crate::rng_strong::fill(&mut shuffle_seed_a).is_err()
        || crate::rng_strong::fill(&mut shuffle_seed_b).is_err()
    {
        shuffle_seed_a.zeroize();
        shuffle_seed_b.zeroize();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
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
            shuffle_seed_a.zeroize();
            shuffle_seed_b.zeroize();
            opt_rand_buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
    }
    let shuffle_a = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_a);
    let shuffle_b = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_b);
    // `[u8; 32]` is `Copy`, so the constructors above copied — wipe the
    // stack locals now that each secret lives inside its `ZeroizeOnDrop`
    // wrapper.
    shuffle_seed_a.zeroize();
    shuffle_seed_b.zeroize();
    crate::fi::zeroize_barrier();
    cfi.bump(CFI_STEP_SHUFFLE);

    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, progress);
    cfi.bump(CFI_STEP_SIGN_A);
    crate::fi::wait_random();
    // The same opaque `fn(u8)` progress hook as `sign_a`: on the pixel route
    // it paces the signing film through both computations. It returns unit,
    // captures nothing and receives only a percentage, so it cannot touch the
    // CFI chain, the compare, or the verify-before-release gates below.
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, progress);
    cfi.bump(CFI_STEP_SIGN_B);

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
    if !bool::from(sig_a[..].ct_eq(&sig_b[..])) {
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
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    cfi.bump(CFI_STEP_CT_EQ);

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
    crate::fi::wait_random();
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a);
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(v)) != crate::fi::OK_SENTINEL {
        // fi-2: a released sig that fails verify-before-release is a confirmed
        // fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    cfi.bump(CFI_STEP_VERIFY_GATE);

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
    if cfi.check_into_sentinel(CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        // fi-2: a short CFI counter means a critical step was skipped by a
        // glitch → confirmed fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }

    opt_rand_buf.zeroize();
    crate::fi::zeroize_barrier();
    Ok(sig_a)
}

/// Provision a `WalletStore` backend from a user-supplied BIP-39 mnemonic.
///
/// Single entry point for both the "new wallet" and "restore from seed
/// phrase" wizard branches. Handles the shared key derivation (the
/// "recovery contract") and delegates storage to `store.provision()`.
///
/// Determinism: the same `(mnemonic, pin)` pair always produces the
/// same SPHINCS+ keypair on any device running this firmware.
pub fn provision_from_mnemonic(
    store: &mut impl crate::secure_element::WalletStore,
    mnemonic: &Mnemonic,
    pin: &[u8; 8],
    duress_pin: Option<&[u8; 8]>,
) {
    let mut entropy = mnemonic
        .to_entropy()
        .expect("mnemonic was already checksum-verified");

    let mut master_secret: [u8; 32] = kdf(b"sphincs-master", &entropy, 0);

    let (sk, vk_bytes) = derive_keypair_from_entropy(&entropy);
    drop(sk);
    let bootstrap_vk = derive_bootstrap_vk_from_entropy(&entropy);

    if store
        .provision(&entropy, &master_secret, &vk_bytes, &bootstrap_vk, pin)
        .is_err()
    {
        // A provision that fails PART-WAY (e.g. a transient SE050 I²C fault
        // after the UserID object is written but before the entropy object)
        // must not leave the device half-provisioned. `is_provisioned()`
        // keys the SE050 leg on `USERID_OBJ` existence, so a bare panic here
        // would leave `is_provisioned() == true` with no entropy half: the
        // wizard would NEVER re-run, yet every correct-PIN `unlock()` would
        // return `InternalError` (missing `ENTROPY_OBJ`) with no user-
        // discoverable recovery — a soft-brick at first-boot setup.
        //
        // Roll back (best-effort) before halting so the next cold boot
        // restarts the wizard cleanly: `factory_reset_admin` wipes the OPTIGA
        // leg unconditionally, flipping `is_provisioned()` to false (the S-6
        // non-admin-deletable SE050 `USERID_OBJ` may survive, but the AND
        // across both SEs already reads false once OPTIGA is blank). It arms
        // the crash-safe wipe flag first, so a fault mid-rollback is resumed
        // on the following boot. Mirrors the duress-decoy rollback below.
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        master_secret.zeroize();
        crate::fi::zeroize_barrier();
        let _ = store.factory_reset_admin();
        panic!("provisioning failed — rolled back for wizard restart");
    }

    entropy.zeroize();
    crate::fi::zeroize_barrier();
    master_secret.zeroize();
    crate::fi::zeroize_barrier();

    // §32 duress (decoy) wallet. Always provision a decoy — a RANDOM PIN
    // when the user declined (`duress_pin = None`) — so "duress configured
    // vs not" is indistinguishable on-chip (always-provision is load-
    // bearing for deniability). Decoy entropy is a FRESH, fully
    // independent 256-bit random (separate-entropy model), unrelated to
    // the real seed. Done AFTER the real wallet so PBS/shield (OPTIGA) and
    // the admin UserID (SE050) are already live.
    //
    // Atomicity: the real wallet is already on-chip at this point and
    // `is_provisioned()` is real-only, so a half-provisioned decoy would
    // leave the device "provisioned" yet without a decoy AND never re-run
    // the wizard. If the decoy provision fails, wipe BOTH wallets so the
    // next cold boot restarts the wizard cleanly (no stuck state).
    #[cfg(feature = "duress-pin")]
    if provision_duress_wallet(store, duress_pin).is_err() {
        let _ = store.factory_reset_admin();
        panic!("duress provisioning failed — wiped both wallets for wizard restart");
    }

    #[cfg(not(feature = "duress-pin"))]
    let _ = duress_pin;
}

/// §32: generate + store an independent decoy wallet behind the duress
/// credential. See [`provision_from_mnemonic`] for the always-provision
/// rationale. Separate fn so the hot path stays readable and the decoy
/// generation is feature-gated in one place. Returns `Err` (rather than
/// panicking) so the caller can roll back the real wallet atomically.
#[cfg(feature = "duress-pin")]
fn fill_strong_with_store<const N: usize>(
    store: &mut impl crate::secure_element::WalletStore,
    out: &mut [u8; N],
) -> Result<(), crate::secure_element::SeError> {
    // Calling the global entry point while `store` is already borrowed would
    // alias the backend. The explicit-handle API executes the same mandatory
    // STM32 + OPTIGA + SE050 composition without re-entering the global.
    crate::rng_strong::fill_with_store(out, store)
        .map_err(|()| crate::secure_element::SeError::InternalError)
}

#[cfg(feature = "duress-pin")]
fn provision_duress_wallet(
    store: &mut impl crate::secure_element::WalletStore,
    duress_pin: Option<&[u8; 8]>,
) -> Result<(), crate::secure_element::SeError> {
    // Fresh independent decoy entropy: STM32 TRNG XOR the SE-combined TRNG
    // (OPTIGA ⊕ SE050 via the store) — same multi-source quality as the
    // real seed path, no re-entrancy (we are not inside a store method).
    let mut decoy_entropy = [0u8; 32];
    fill_strong_with_store(store, &mut decoy_entropy)?;

    // Resolve the duress PIN: user-chosen, or a fresh random 8 bytes when
    // declined (never entered by anyone → unguessable; the chip can't
    // distinguish a random-byte PIN from a digit PIN).
    let mut random_pin = [0u8; 8];
    let mut actual_duress_pin: [u8; 8] = match duress_pin {
        Some(p) => *p,
        None => {
            if let Err(e) = fill_strong_with_store(store, &mut random_pin) {
                decoy_entropy.zeroize();
                crate::fi::zeroize_barrier();
                return Err(e);
            }
            random_pin
        }
    };

    let mut decoy_master: [u8; 32] = kdf(b"sphincs-master", &decoy_entropy, 0);
    let (sk, decoy_vk) = derive_keypair_from_entropy(&decoy_entropy);
    drop(sk);
    let decoy_bvk = derive_bootstrap_vk_from_entropy(&decoy_entropy);

    let result = store.provision_duress(
        &decoy_entropy, &decoy_master, &decoy_vk, &decoy_bvk, &actual_duress_pin,
    );

    // Zeroize every secret regardless of success/failure.
    decoy_entropy.zeroize();
    crate::fi::zeroize_barrier();
    decoy_master.zeroize();
    crate::fi::zeroize_barrier();
    actual_duress_pin.zeroize();
    random_pin.zeroize();
    crate::fi::zeroize_barrier();

    result
}

/// Store pre-derived entropy, VK, and PIN state via the MACD chain on an
/// r-mem-capable secure element. Used by backends that support the
/// `SecureElement` trait (Mock on the generic path).
///
/// The mnemonic-to-entropy derivation is NOT done here — the caller must
/// pass pre-derived `(entropy, master_secret, vk, bootstrap_vk)`.
pub fn store_macd_encrypted(
    se: &mut impl SecureElement,
    entropy: &[u8; ENTROPY_LEN],
    master_secret: &[u8; 32],
    vk: &[u8; 32],
    bootstrap_vk: &[u8; 32],
    pin: &[u8; 8],
) {
    use sphincs_tz_shared::MAX_ATTEMPTS;
    // 1. Encrypt the entropy under the master-derived wrap key.
    let entropy_blob = encrypt_entropy_blob(entropy, master_secret);

    // 2. Initialize MACD slots and build the per-slot encrypted
    //    master_secret blobs (one per allowed PIN attempt).
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for j in 0..MAX_ATTEMPTS {
        let init_in = macd_init_input(master_secret, j);
        let pin_in = macd_pin_input(pin, j);

        se.mac_and_destroy(j as u16, &init_in).unwrap();
        let mut w_j = se.mac_and_destroy(j as u16, &pin_in).unwrap();
        se.mac_and_destroy(j as u16, &init_in).unwrap();

        let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
        ct_buf[..32].copy_from_slice(master_secret);
        aes_encrypt_inplace(&w_j, &mut ct_buf, 32, j);
        encrypted_secrets[j as usize] = ct_buf;
        w_j.zeroize();
    }

    // 3. Store everything in r-mem.
    se.r_mem_erase(RMEM_ENCRYPTED_ENTROPY).ok();
    se.r_mem_write(RMEM_ENCRYPTED_ENTROPY, &entropy_blob)
        .unwrap();

    let mut pin_state_buf = [0u8; PIN_STATE_MAX_LEN];
    let ps_len = serialize_pin_state(0, &encrypted_secrets, &mut pin_state_buf);
    se.r_mem_erase(RMEM_PIN_STATE).ok();
    se.r_mem_write(RMEM_PIN_STATE, &pin_state_buf[..ps_len])
        .unwrap();

    se.r_mem_erase(RMEM_VERIFYING_KEY).ok();
    se.r_mem_write(RMEM_VERIFYING_KEY, vk).unwrap();

    se.r_mem_erase(RMEM_BOOTSTRAP_VK).ok();
    se.r_mem_write(RMEM_BOOTSTRAP_VK, bootstrap_vk).unwrap();
}
