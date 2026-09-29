# Research Prompt C — SLH-DSA Side-Channel Landscape on Cortex-M33

## Research question

What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. Our design rotates the main signer every ~2^20 signatures. Is
   that already beyond the SCA trace-count threshold for practical
   recovery, or do we need tighter rotation?
5. With the all-C10 parameter choice fixed, which implementation-level
   countermeasures materially improve the SCA posture? Do not reopen a
   SHA2-128f/192f migration or imply that changing parameters alone closes
   leakage.

Deliverables: catalogued threat list with severity + mitigation per
item, plus specific recommendations on per-signer rotation cadence
and whether to route hashing through the HASH peripheral.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant code


### `secure/src/crypto.rs`

```rust
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

/// Build the `(first_half, second_half)` progress pair for `$sink` (#759).
///
/// The FI countermeasure signs TWICE, so a single callback handed to both
/// signs ramps 0..100 and then 0..100 again — on the text route
/// `ui::show_progress` renders a real percentage, so the bar counts to 100,
/// drops to 0 and climbs again, which on a trusted display reads as a
/// failed-and-retrying operation. Handing `|_| {}` to the second sign instead
/// freezes the pixel signing film for seconds, which reads as a hang. The
/// phases are therefore SCALED: sign A into 0..=50, sign B into 50..=100.
///
/// It is a macro rather than a function because
/// `SigningKey::sign_with_shuffle` takes `progress: fn(u8)` — a bare pointer,
/// deliberately: its own doc records that the arrow type is already the limit
/// of what the Aeneas Lean extraction can represent, which is why that method
/// is `#[cfg(not(lean_extract))]`. Widening it to `impl Fn(u8)` would push an
/// active FV boundary further, and a capturing closure cannot coerce to
/// `fn(u8)`. Expanding two `fn` items per call site keeps the scaling
/// compile-time and STATELESS — an earlier attempt routed the sink through a
/// `static mut` and raced under the host test harness, which runs tests on
/// parallel threads even though the device is single-threaded.
#[macro_export]
macro_rules! progress_halves {
    ($sink:path) => {{
        fn first_half(pct: u8) {
            $sink(pct / 2);
        }
        fn second_half(pct: u8) {
            $sink(50 + pct / 2);
        }
        (first_half as fn(u8), second_half as fn(u8))
    }};
}

pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: (fn(u8), fn(u8)),
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
    progress: (fn(u8), fn(u8)),
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
    progress: (fn(u8), fn(u8)),
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

    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, progress.0);
    cfi.bump(CFI_STEP_SIGN_A);
    crate::fi::wait_random();
    // The SECOND HALF of the same ramp (#759), so the film keeps moving on the
    // pixel route and the percentage continues upward on the text route rather
    // than restarting at 0. Like `sign_a`'s it returns unit, captures nothing
    // and receives only a percentage, so it cannot touch the CFI chain, the
    // compare, or the verify-before-release gates below.
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, progress.1);
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

```


### `secure/src/nsc/cmd_sign_userop.rs`

```rust
//! CMD_SIGN_USEROP — Coinbase-Smart-Wallet-style sign command (all SHA-256).
//!
//! After the Coinbase Smart Wallet port, every signature on the wallet is a
//! SPHINCS+C10 sig over a purely-SHA-256 digest (no keccak on the sign path —
//! STM32U585 has HW SHA-256 but no keccak accelerator). The on-chain wallet
//! owns an array of 64-byte C10 owners: owner index 0 is the immutable
//! bootstrap key; owner index 1 is the per-chain slot-0 key (added by the
//! factory on deploy); higher indices are slot keys added by the bootstrap
//! when the previous slot hits its 65,536-sig cap.
//!
//! Three flows, selected by the companion-supplied flags field:
//!
//!   * **Deploy** (`FLAG_INCLUDE_INIT_CODE` only, slot_index = 0)
//!     The wallet doesn't yet exist on this chain. Firmware:
//!       1. Derives slot-0 for `(chain_id, 0)`.
//!       2. Signs `sha256("pqwallet-factory-add-slot" || chain_id ||
//!          slot0PkSeed || slot0PkRoot)` with the bootstrap key — this
//!          is the `factorySig` that unlocks `createAccount` on-chain.
//!       3. Assembles the factory-call `initCode` carrying `factorySig`.
//!       4. Signs the user's single UserOp (with `initCode` attached)
//!          using slot-0.
//!     Output: initCode + Type 2 sig wrapper (`ownerIndex = 1`).
//!
//!   * **Rotation** (`FLAG_REGISTER_SLOT` only, slot_index ≥ 1)
//!     slot N-1 is exhausted / compromised. Firmware:
//!       1. Derives slot-N for `(chain_id, slot_index)`.
//!       2. Builds an internal `addOwnerBytes(slot_N_owner_bytes)` UserOp,
//!          signs its SHA-256 sphincs digest with the bootstrap key.
//!       3. Builds the user's UserOp (nonce = base+1), signs with slot-N.
//!     Output: Type 1 sig wrapper (`ownerIndex = 0`) + Type 2 sig wrapper
//!     (`ownerIndex = slot_index + 1`).
//!
//!   * **Normal** (neither flag)
//!     Slot-N is already registered on-chain. Firmware:
//!       1. Derives (or reuses cached) slot-N.
//!       2. Signs the user's UserOp with slot-N.
//!     Output: Type 2 sig wrapper only.
//!
//! `FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` are mutually exclusive
//! — first deploy cannot simultaneously be a rotation (slot-0 is set by the
//! factory atomically, no separate addOwner needed).
//!
//! Firmware is still stateless: slot keys are derived on demand from
//! `(master_entropy, chain_id, slot_index)` and cached in SRAM across the
//! unlock session. Bootstrap key regen happens only on rotation/deploy paths.
//!
//! Every signature is verified locally before being written to NS
//! (fault-injection guard, double-evaluated).

use sphincs_tz_shared::{
    NscStatus, C10_SIG_LEN, COW_ORDER_TRAILER_MAX_LEN, ERC7730_MAX_TRAILER_LEN,
    FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT, GPV2_SETTLEMENT_ADDRESS, MAX_SIGN_RESPONSE_LEN,
    MAX_TX_LEN, PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SAFE_V1_PAYLOAD_MAX, SET_PRE_SIGNATURE_SELECTOR,
    SIGN_USEROP_HEADER_LEN, SIG_WRAPPER_LEN,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Domain tag the firmware signs when authorising slot-0 on a new chain.
/// MUST match `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use crate::names::{verify_name_bundle, NameResolver, MAX_NAME_BUNDLES, MAX_NAME_BUNDLE_LEN};
use crate::selectors::{
    parse_self_attest_bundle, verify_selector_bundle, SelectorMeta, MAX_SELECTOR_BUNDLE_LEN,
    MAX_SELF_ATTEST_BUNDLE_LEN,
};
use crate::tx::display::pick_sign_pages_with_erc7730_evidence;
use crate::tx::eip1559::{Eip1559Tx, UserOpDisplayFields, U256};
use crate::ui;

/// Reserve enough room to TOCTOU-snapshot the largest valid input the
/// gateway will accept. The trailing `1 + MAX_NAME_BUNDLES * (2 +
/// MAX_NAME_BUNDLE_LEN)` block is the address-name bundle section.
/// Two selector trailers sit between `safe_v1` and the names section
/// (mutually exclusive at parse time): the curated Merkle-bundle slot
/// followed by the self-attest slot.
const SNAP_LEN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2 + MAX_ERC20_BUNDLE_LEN
    + 2 // reserved compatibility length field; must be 0
    + 2 + COW_ORDER_TRAILER_MAX_LEN
    + 2 + SAFE_V1_PAYLOAD_MAX
    + 2 + MAX_SELECTOR_BUNDLE_LEN
    + 2 + MAX_SELF_ATTEST_BUNDLE_LEN
    + 2 + ERC7730_MAX_TRAILER_LEN
    + 1 + MAX_NAME_BUNDLES * (2 + MAX_NAME_BUNDLE_LEN);

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// derefs (TOCTOU snapshot read + signed-response write) happen only
/// after `validate_ns_{read,write}_ptr` proves each range is fully
/// NS-classified. `static mut` driver state (`SE`, `SLOT_CACHE`,
/// `SNAP_BUF`) is touched under the single-threaded dispatcher
/// invariant + `HandlerGuard` (HIGH-7).
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::ui::confirm::{confirm_checked, ConfirmResult};

    // HIGH-7 fix: mark the handler as busy so SysTick's background
    // idle-wipe path cannot zero out `master_secret` while we still
    // hold a stack-local copy of it. Dropped on scope exit.
    let _busy = super::HandlerGuard::enter();

    ui::show_status("Sign", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_USEROP_HEADER_LEN || total_len > SNAP_LEN {
        ui::show_status("Sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): route the NS-pointer gates
    // through the Hamming-distant sentinel (`check_true_into_sentinel`)
    // rather than a bare `if !validate(...)`. A single instruction-skip /
    // stuck-at on a plain reject branch falls through into the handler body
    // with an unvalidated pointer — NS then picks an `out_ptr` into secure
    // SRAM and the response write below becomes an OOB write across the
    // S/NS boundary. The sentinel comparison closes the value / stuck-at-
    // register class (a random faulted value is not `OK_SENTINEL`), but NOT the
    // one-skip-of-the-reject-branch residual on its own (finding F5): a precise
    // skip of the `if != OK_SENTINEL` branch still falls through. That residual
    // is closed by RE-VALIDATING the write extent immediately before the output
    // write (§15 below), so a single glitch must skip two spatially-distant
    // reject branches. Same idiom as the §14 6492 re-validation in
    // cmd_sign_offchain.rs. (The FI-bypass count itself is validated by the
    // deferred rainbow instruction-skip sweep on the real ELF, not in-repo.)
    crate::fi::scrub_sentinel_register();
    let read_ptr_ok =
        crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(args.arg0, total_len));
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    let write_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if write_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // Shared with the sibling sign handlers via `super::SIGN_SNAP_BUF`
    // (one buffer for all three; safe because the dispatcher is
    // non-reentrant — see the buffer's doc comment). The const assert pins
    // this handler's protocol max ≤ the shared buffer so the `..total_len`
    // slice below (with `total_len <= SNAP_LEN`, checked at the header
    // length gate above) can never overrun.
    const _: () = assert!(SNAP_LEN <= super::SIGN_SNAP_BUF_LEN);
    // `ui-px`: the screen transcript overlays the buffer beyond SNAP_LEN.
    #[cfg(feature = "ui-px")]
    const _: () = assert!(super::SIGN_SNAP_BUF_LEN - SNAP_LEN >= pqsigner_ui_px::SCREENS_BYTES);
    // M1 fix: wipe any leftover payload from the PREVIOUS sign before
    // we fill it with this request.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    // The pixel UI (`ui-px`) overlays its screen transcript on the tail of the
    // shared buffer beyond this handler's own snapshot maximum — disjoint
    // bytes, split once here so no two live borrows overlap.
    let (snap_full, px_scratch) =
        (&mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF)).split_at_mut(SNAP_LEN);
    let snap = &mut snap_full[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // The wallet and factory are frozen to the canonical EntryPoint v0.6
    // singleton. Treat the companion field as an assertion, never as signing
    // authority: compare it twice through independent fail-closed sentinel
    // gates before parsing any other request field, then feed only
    // `ENTRY_POINT_V06` into every digest below. Even an instruction skip over
    // one reject cannot turn hostile wire bytes into a signed domain, and the
    // second spatially separate gate still rejects the mismatch under the
    // single-fault model.
    // SAFETY: the validated fixed header contains bytes 32..52 in the local
    // S-world snapshot. Volatile aggregate reads keep the two FI samples
    // independent under LTO instead of allowing common-subexpression folding.
    let supplied_entry_point_a =
        unsafe { core::ptr::read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>()) };
    let entry_point_match_a = supplied_entry_point_a.ct_eq(&ENTRY_POINT_V06).unwrap_u8();
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_a) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "wrong EntryPoint");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    crate::fi::wait_random();
    // SAFETY: same validated snapshot range; deliberately re-read volatile
    // after the randomized gap for an independent second sample.
    let supplied_entry_point_b =
        unsafe { core::ptr::read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>()) };
    let entry_point_match_b = supplied_entry_point_b.ct_eq(&ENTRY_POINT_V06).unwrap_u8();
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_b) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "wrong EntryPoint");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();

    // ── 4. Parse header (big-endian, fixed offsets) ────────────────
    let chain_id = u64::from_be_bytes([
        snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
    ]);
    // F-11 hardening: parse flags from the snapshot twice with a
    // randomised gap between, then halt on mismatch. The snapshot lives
    // in S-world SRAM (no NS races), so a divergence is necessarily a
    // glitch on the register/load path between the two reads. The
    // recheck below — after slot_index / account_index are derived —
    // catches faults that land *between* the parse and the gate.
    let flags_a = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    crate::fi::wait_random();
    let flags_b = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_a != flags_b {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let flags = flags_a;
    // FI structure preserved: `flags` is read twice (above) + rechecked below;
    // this only routes the bitfield EXTRACTION through the Kani-proven
    // `decode_flags` kernel (`#[inline]` → identical codegen under LTO).
    let (include_init_code, register_slot, account_index, slot_index) =
        crate::aa::userop::decode_flags(flags);

    #[cfg(all(feature = "e2e-test", feature = "ui-lcd"))]
    {
        static mut E2E_CALL_NO: u8 = 0;
        // SAFETY: category 5 — `E2E_CALL_NO` is a `static mut` debug-
        // only counter compiled in only under `e2e-test` + `ui-lcd`.
        // Single-threaded non-reentrant dispatcher serialises access;
        // not present in production builds.
        let n = unsafe {
            E2E_CALL_NO = E2E_CALL_NO.wrapping_add(1);
            E2E_CALL_NO
        };
        let title: &str = match n {
            1 => "e2e Sign 1/4",
            2 => "e2e Sign 2/4",
            3 => "e2e Sign 3/4",
            4 => "e2e Sign 4/4",
            _ => "e2e Sign ?",
        };
        let kind = if include_init_code {
            "Deploy"
        } else if register_slot {
            "T1+T2"
        } else {
            "T2 only"
        };
        ui::show_status(title, kind);
    }
    let mut companion_sender = [0u8; 20];
    companion_sender.copy_from_slice(&snap[12..32]);

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&snap[52..84]);
    let mut call_gas_limit = [0u8; 32];
    call_gas_limit.copy_from_slice(&snap[84..116]);
    let mut verification_gas_limit = [0u8; 32];
    verification_gas_limit.copy_from_slice(&snap[116..148]);
    let mut pre_verification_gas = [0u8; 32];
    pre_verification_gas.copy_from_slice(&snap[148..180]);
    let mut max_fee_per_gas = [0u8; 32];
    max_fee_per_gas.copy_from_slice(&snap[180..212]);
    let mut max_priority_fee_per_gas = [0u8; 32];
    max_priority_fee_per_gas.copy_from_slice(&snap[212..244]);
    let mut paymaster_and_data_hash = [0u8; 32];
    paymaster_and_data_hash.copy_from_slice(&snap[244..276]);
    let mut to_address = [0u8; 20];
    to_address.copy_from_slice(&snap[276..296]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&snap[296..328]);
    // Kani-proven `validate_data_len`: keeps the inner-tx data slice
    // `snap[HEADER_LEN..HEADER_LEN+data_len]` (cut below) in bounds + caps it at
    // MAX_TX_LEN, so no companion `data_len` can drive an OOB read.
    let data_len = match crate::aa::userop::validate_data_len(
        total_len,
        u16::from_be_bytes([snap[328], snap[329]]),
    ) {
        Some(d) => d,
        None => {
            ui::show_status("Sign", "bad data_len");
            return NscStatus::InvalidPointer as u32;
        }
    };

    // Flag-combination invariants (post-Coinbase-port):
    //   * INCLUDE_INIT_CODE and REGISTER_SLOT are mutually exclusive —
    //     first-deploy bundles its slot-0 registration into the factory
    //     call, so there is never a separate addOwner UserOp on deploy.
    //   * INCLUDE_INIT_CODE requires slot_index == 0 (the factory can
    //     only pre-register the canonical slot 0).
    //   * REGISTER_SLOT requires slot_index >= 1 (rotation only; slot-0
    //     is already added by the factory on deploy).
    if include_init_code && register_slot {
        ui::show_status("Sign", "incompatible flags");
        return NscStatus::InvalidPointer as u32;
    }
    if include_init_code && slot_index != 0 {
        ui::show_status("Sign", "init_code needs slot0");
        return NscStatus::InvalidPointer as u32;
    }
    if register_slot && slot_index == 0 {
        ui::show_status("Sign", "register needs slot>=1");
        return NscStatus::InvalidPointer as u32;
    }

    // F-11 belt-and-braces: re-derive flags / slot_index from the
    // snapshot and re-run the three sanity gates. A single-shot fault
    // on the derived values would have to land twice (once before each
    // gate) to bypass; an instruction-skip fault on a single conjunct
    // is caught by the second check refreshing the inputs from snap[].
    crate::fi::wait_random();
    let flags_recheck = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_recheck != flags {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    // Same kernel as the first decode (the redundant read + this full-field
    // recheck ARE the F-11 countermeasure). Account index is load-bearing: it
    // selects the mnemonic-derived sender checked below.
    let (include_init_code_r, register_slot_r, account_index_r, slot_index_r) =
        crate::aa::userop::decode_flags(flags_recheck);
    if include_init_code_r != include_init_code
        || register_slot_r != register_slot
        || account_index_r != account_index
        || slot_index_r != slot_index
    {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    if include_init_code_r && register_slot_r {
        ui::show_status("Sign", "fi flag conflict");
        return NscStatus::InternalError as u32;
    }
    if include_init_code_r && slot_index_r != 0 {
        ui::show_status("Sign", "fi init_code slot");
        return NscStatus::InternalError as u32;
    }
    if register_slot_r && slot_index_r == 0 {
        ui::show_status("Sign", "fi register slot");
        return NscStatus::InternalError as u32;
    }

    // CRIT-17: refuse nonce-seq overflow. v0.6 nonces are 192-bit key | 64-bit seq.
    // When REGISTER_SLOT is set, Type 2 nonce = base + 1 — overflowing the
    // seq would carry into the key field and silently change the nonce key.
    if register_slot && nonce[24..32] == [0xFFu8; 8] {
        ui::show_status("Nonce seq", "overflow");
        return NscStatus::InvalidPointer as u32;
    }
    // Derive the exact nonce of the transaction UserOp before rendering.
    // REGISTER_SLOT emits a separate Type-1 UserOp at `nonce`; the displayed
    // and signed Type-2 transaction is at `nonce + 1` within the same lane.
    // The overflow gate above proves this increment cannot carry into key192.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

    let inner_data: &[u8] = &snap[SIGN_USEROP_HEADER_LEN..SIGN_USEROP_HEADER_LEN + data_len];

    // ── 5. Parse optional trailers ─────────────────────────────────
    //
    // Three independently-optional length-prefixed trailers (ERC-20
    // bundle, reserved compatibility slot, native CoW EIP-712), followed by the
    // address-name bundles section. Each uses the same
    // `[u16 BE len][payload]` framing, delegated to the `trailer`
    // helper so bounds-checking and error-label routing stay
    // consistent. Absent trailer == trailer with len == 0.
    let mut cursor = SIGN_USEROP_HEADER_LEN + data_len;

    let erc20 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_ERC20_BUNDLE_LEN,
        "bad erc20 bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = erc20.next_cursor;

    // Reserved compatibility slot. The 2-byte length field is kept for
    // wire-offset stability of the trailers that follow. `max_len = 0`
    // makes the read fail-closed: a non-zero declared length is rejected,
    // and no payload bytes are ever parsed.
    let reserved_v1 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        0,
        "reserved slot must be 0",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = reserved_v1.next_cursor;

    // CoW order trailer: canonical(204) [|| sell_len(2) || sell_bundle
    // || buy_len(2) || buy_bundle]. Companion sends the whole trailer;
    // no NS-side injection: token metadata is decoded on-device from the
    // ERC-20 bundles. Absent is
    // legal for non-CoW tx — the CoW downgrade-mitigation gate below
    // enforces presence when needed.
    //
    // Inlined instead of `trailer::read_optional_u16_prefixed` so the
    // OLED distinguishes the two failure modes (oversized declared
    // length vs. declared length overflowing the payload) — makes
    // companion-vs-NS-router layout disagreements trivial to triage.
    let cow_order = if cursor + 2 > total_len {
        super::trailer::Trailer {
            start: cursor,
            len: 0,
            next_cursor: cursor,
        }
    } else {
        let declared = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        let payload_start = cursor + 2;
        if declared > COW_ORDER_TRAILER_MAX_LEN {
            // Dump four values across the 4-line OLED:
            //   line 1: "Sign v3 len>cap"
            //   line 2: "d=XXXX (data_len)"
            //   line 3: "e=XXXX r=XXXX   "   (erc20 + reserved declared len)
            //   line 4: "v3=XXXX        "
            // Expected happy values for a CoW swap on Base:
            //   d=00a4 (164), e=0000, r=0000, v3=0790 (or 02cc bare).
            const HEX: &[u8] = b"0123456789abcdef";
            let d = data_len as u16;
            let e = erc20.len as u16;
            let r = reserved_v1.len as u16;
            let v = declared as u16;

            let mut line2 = [b' '; 16];
            line2[0] = b'd';
            line2[1] = b'=';
            line2[2] = HEX[((d >> 12) & 0xF) as usize];
            line2[3] = HEX[((d >> 8) & 0xF) as usize];
            line2[4] = HEX[((d >> 4) & 0xF) as usize];
            line2[5] = HEX[(d & 0xF) as usize];

            let mut line3 = [b' '; 16];
            line3[0] = b'e';
            line3[1] = b'=';
            line3[2] = HEX[((e >> 12) & 0xF) as usize];
            line3[3] = HEX[((e >> 8) & 0xF) as usize];
            line3[4] = HEX[((e >> 4) & 0xF) as usize];
            line3[5] = HEX[(e & 0xF) as usize];
            line3[7] = b'r';
            line3[8] = b'=';
            line3[9] = HEX[((r >> 12) & 0xF) as usize];
            line3[10] = HEX[((r >> 8) & 0xF) as usize];
            line3[11] = HEX[((r >> 4) & 0xF) as usize];
            line3[12] = HEX[(r & 0xF) as usize];

            let mut line4 = [b' '; 16];
            line4[0] = b'v';
            line4[1] = b'3';
            line4[2] = b'=';
            line4[3] = HEX[((v >> 12) & 0xF) as usize];
            line4[4] = HEX[((v >> 8) & 0xF) as usize];
            line4[5] = HEX[((v >> 4) & 0xF) as usize];
            line4[6] = HEX[(v & 0xF) as usize];

            let d2 = ui::display();
            d2.clear();
            d2.draw_line(0, "Sign v3 len>cap");
            d2.draw_line(1, core::str::from_utf8(&line2).unwrap_or(""));
            d2.draw_line(2, core::str::from_utf8(&line3).unwrap_or(""));
            d2.draw_line(3, core::str::from_utf8(&line4).unwrap_or(""));
            d2.flush();
            return NscStatus::InvalidPointer as u32;
        }
        if payload_start + declared > total_len {
            ui::show_status("Sign", "v3 len > payload");
            return NscStatus::InvalidPointer as u32;
        }
        super::trailer::Trailer {
            start: payload_start,
            len: declared,
            next_cursor: payload_start + declared,
        }
    };
    cursor = cow_order.next_cursor;

    // 5a-bis. Optional Safe-multisig `approveHash` clear-sign trailer
    // (`safe_v1`). Layout: canonical(281) || u16 raw_data_len ||
    // raw_data. Absence is legal for non-Safe tx; the downgrade gate
    // below mandates presence whenever the inner calldata claims to
    // be `approveHash(bytes32)`.
    let safe_v1 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        SAFE_V1_PAYLOAD_MAX,
        "bad safe bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = safe_v1.next_cursor;

    // 5a-ter. Optional function-selector → text-signature trailer
    // (curated path). Layout is the same `[u16 BE len][bundle]` framing
    // every other trailer uses. The DB itself lives on the host
    // (companion app/stub) — only its 32-byte Merkle root rides in the
    // secure image. Absence is legal — when missing, the calldata may
    // still render typed args via the self-attest trailer below, or
    // fall back to blind-sign. Sits BEFORE the names section so the
    // names `[count:u8]` framing remains the very last thing in the
    // payload.
    let selector_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_SELECTOR_BUNDLE_LEN,
        "bad selector bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = selector_trailer.next_cursor;

    // 5a-quater. Optional self-attest selector trailer. Wire layout:
    // `selector(4) || text_sig_len(1) || text_sig(<=63)`. No Merkle
    // proof — this path is for selectors that the curated DB doesn't
    // cover. The firmware verifies internal consistency only:
    //   (a) `keccak256(text_sig)[..4] == bundle.selector`
    //   (b) `bundle.selector == calldata[..4]` (cross-check below)
    //   (c) the existing strict ABI walker rejects shape mismatch.
    // The trusted UI surfaces the weakened trust on its banner — see
    // `SelectorProvenance::SelfAttest`. Mutual exclusion with the
    // curated trailer is enforced below: companions must pick exactly
    // one path per call.
    let self_attest_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_SELF_ATTEST_BUNDLE_LEN,
        "bad self-attest",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = self_attest_trailer.next_cursor;

    // ── 5a-quinquies. Optional ERC-7730 clear-signing descriptor ───
    //
    // Wire layout: `[u16 BE len][payload]`. The payload is either one exact
    // legacy bundle or the capability-gated versioned proof-set envelope. A
    // proof set retains ordered, zero-copy raw handles for the outer and
    // optional child legacy bundles; the outer remains the top-level
    // descriptor while an authenticated enrolled child may render in scope.
    //
    // Verified inline against the firmware-pinned
    // `ERC7730_DESCRIPTORS_ROOT` (Phase 2 emits this root from the
    // host pipeline). Cross-checked against `(chain_id, to_address)`
    // so a hostile companion cannot pair a USDC descriptor with a
    // transfer to an attacker-controlled contract — see invariant
    // discussion in `pqsigner_erc7730::binding::cross_check_contract`.
    //
    // Sits BEFORE the names section so the names `[count:u8]` framing
    // remains the very last thing in the payload.
    //
    // NOT mutually exclusive with the selector / self-attest trailers
    // — Phase 4's renderer picks the best one per priority ladder.
    let erc7730_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        ERC7730_MAX_TRAILER_LEN,
        "bad erc7730",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = erc7730_trailer.next_cursor;

    // Parse and retain the exact rooted proof set here, but do not grant it
    // display authority yet. The complete contract context (trusted sender,
    // display nonce/value, and signed calldata) exists only after section 6.
    // Section 6a reparses the entire payload twice and re-derives the nested
    // binding around a randomized gap before the set can reach the renderer.
    // A present malformed trailer hard-refuses below; only true absence maps
    // to `None`, where the independently pinned known-call filter still
    // prevents omission downgrade for every registry-known tuple.
    let erc7730_candidate: Option<crate::tx::erc7730::VerifiedProofSet<'_>> = if erc7730_trailer
        .len
        > 0
    {
        let bytes = &snap[erc7730_trailer.start..erc7730_trailer.start + erc7730_trailer.len];
        match crate::tx::erc7730::verify_erc7730_proof_set(
            bytes,
            &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
        ) {
            Ok(v) => Some(v),
            Err(_e) => {
                ui::show_status("Sign", "7730 bundle fail");
                return NscStatus::InvalidPointer as u32;
            }
        }
    } else {
        None
    };

    // ── 5b. Optional address-name bundles ─────────────────────────
    //
    // Zero or more merkle-verified (chain_id, address, name) bundles.
    // The companion emits up to MAX_NAME_BUNDLES entries, one per
    // address it found in its local names DB across the tx's display
    // surface (tx.to, ERC-20 recipient/spender, paymaster, ...). The
    // secure world verifies each bundle against NAMES_DB_ROOT and
    // collects the survivors into a NameResolver for the display
    // layer.
    //
    // Absence of this trailer is legal — legacy callers that never
    // upgrade their NS code still produce a zero-trailer sign request.
    // Framing differs from the three trailers above (1-byte count +
    // variable-count 2-byte-len entries), so it parses inline.
    let names_count = if cursor < total_len {
        snap[cursor] as usize
    } else {
        0
    };
    let names_start;
    if names_count > 0 {
        cursor += 1;
        names_start = cursor;
        if names_count > MAX_NAME_BUNDLES {
            ui::show_status("Sign", "bad names count");
            return NscStatus::InvalidPointer as u32;
        }
        for _ in 0..names_count {
            if cursor + 2 > total_len {
                ui::show_status("Sign", "bad names frame");
                return NscStatus::InvalidPointer as u32;
            }
            let l = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
            cursor += 2;
            if l > MAX_NAME_BUNDLE_LEN || cursor + l > total_len {
                ui::show_status("Sign", "bad names len");
                return NscStatus::InvalidPointer as u32;
            }
            cursor += l;
        }
    } else {
        names_start = cursor;
    }

    if cursor != total_len {
        ui::show_status("Sign", "trailing bytes");
        return NscStatus::InvalidPointer as u32;
    }

    // Bind the untrusted wire sender to the deterministic CREATE2 address for
    // this mnemonic + account index before any sender-dependent verifier or
    // trusted-display confirmation. Downstream code intentionally uses ONLY
    // the published address, never `companion_sender`; even a skipped reject
    // branch therefore cannot produce a signature for an arbitrary wallet.
    let mut sender_binding_slot = super::cmd_get_wallet_address::SenderBinding::fail_closed();
    let mut sender_binding_cfi = crate::fi::CfiCounter::new();
    // Materialize the fail-closed slot even under LTO. If the following `bl`
    // is instruction-skipped, only the materialized fail-closed slot remains.
    // SAFETY: unique local slot; volatile store is deliberately observable.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(sender_binding_slot),
            super::cmd_get_wallet_address::SenderBinding::fail_closed(),
        );
        super::cmd_get_wallet_address::bind_userop_sender(
            account_index,
            &companion_sender,
            &mut sender_binding_slot,
            &mut sender_binding_cfi,
        );
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Read the derived sender twice. A skipped/corrupted aggregate word-load
    // must be detected before the local copy can reach any verifier or hash.
    // SAFETY: the slot is initialized before the call and remains live here.
    let sender =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.sender)) };
    crate::fi::wait_random();
    // SAFETY: same as the first sender read.
    let sender_check =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.sender)) };
    let sender_reads_agree = sender.ct_eq(&sender_check).unwrap_u8();
    // SAFETY: the scalar fields were initialized before the call and the
    // helper publishes them with volatile stores.
    let binding_verdict =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.verdict)) };
    // SAFETY: same initialized caller-owned slot.
    let binding_error =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.error)) };
    if sender_binding_cfi
        .check_into_sentinel(super::cmd_get_wallet_address::SENDER_BIND_CFI_EXPECTED)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(sender_reads_agree) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if binding_verdict != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "wrong wallet");
        return binding_error as u32;
    }

    // ── 6. Build display-time Eip1559Tx shim ───────────────────────
    let display_nonce = u64::from_be_bytes([
        type2_nonce[24],
        type2_nonce[25],
        type2_nonce[26],
        type2_nonce[27],
        type2_nonce[28],
        type2_nonce[29],
        type2_nonce[30],
        type2_nonce[31],
    ]);
    let display_max_fee = U256(max_fee_per_gas);
    let display_max_prio = U256(max_priority_fee_per_gas);
    let call_gas_u128 = u128_saturating_from_u256(&call_gas_limit);
    let ver_gas_u128 = u128_saturating_from_u256(&verification_gas_limit);
    let pre_ver_u128 = u128_saturating_from_u256(&pre_verification_gas);
    let display_gas_limit: u64 = ver_gas_u128
        .saturating_add(call_gas_u128)
        .saturating_add(pre_ver_u128)
        .min(u64::MAX as u128) as u64;

    let tx_for_display = Eip1559Tx {
        chain_id,
        nonce: display_nonce,
        max_priority_fee_per_gas: display_max_prio,
        max_fee_per_gas: display_max_fee,
        gas_limit: display_gas_limit,
        to: Some(to_address),
        value: U256(value),
        data_len,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: Some(UserOpDisplayFields {
            // This display object describes the Type-2 transaction the user
            // is authorizing.  During slot rotation the companion-supplied
            // base nonce belongs to the preceding Type-1 registration, while
            // the transaction is signed at base+1.
            nonce: U256(type2_nonce),
            call_gas_limit: U256(call_gas_limit),
            verification_gas_limit: U256(verification_gas_limit),
            pre_verification_gas: U256(pre_verification_gas),
        }),
    };

    // ── 6a. FI-bind the complete ERC-7730 proof set and nested call ──
    //
    // The initial pure derivation establishes the exact binding the renderer
    // must reproduce. The non-inlined proof then reparses the complete raw
    // legacy/wrapper payload twice, requires the exact same verified set, and
    // independently re-derives that binding around a randomized gap. Both the
    // caller-owned volatile verdict and CFI transcript are consumed twice
    // before the set gains display authority. Any present invalid evidence is
    // a hard refusal; it cannot be erased into a weaker fallback route.
    let (erc7730_verified, erc7730_nested_binding) = if let Some(set) = erc7730_candidate.as_ref() {
        let expected_nested = match crate::tx::erc7730::derive_nested_call(
            &tx_for_display,
            inner_data,
            set,
            &sender,
        ) {
            Ok(binding) => binding,
            Err(_) => {
                ui::show_status("Sign", "7730 binding fail");
                return NscStatus::InvalidPointer as u32;
            }
        };

        let mut bind_verdict_slot = 0u32;
        // SAFETY: unique initialized local; volatile so LTO cannot erase the
        // fail state if the proof call is fault-skipped.
        unsafe {
            core::ptr::write_volatile(&mut bind_verdict_slot, crate::fi::FAIL_SENTINEL);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut bind_cfi = crate::fi::CfiCounter::new();
        crate::tx::erc7730::prove_contract_proof_set_binding(
            set,
            &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
            &tx_for_display,
            inner_data,
            &sender,
            expected_nested.as_ref(),
            &mut bind_verdict_slot,
            &mut bind_cfi,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Gate A consumes independently materialized verdict and CFI proofs.
        // SAFETY: local remains live and the callee borrow ended.
        let bind_verdict_a = unsafe { core::ptr::read_volatile(&bind_verdict_slot) };
        let bind_cfi_verdict_a =
            bind_cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED);
        let bind_all_ok_a = bind_verdict_a == crate::fi::OK_SENTINEL
            && bind_cfi_verdict_a == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        let bind_gate_a =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_all_ok_a));
        crate::fi::scrub_sentinel_register();
        if bind_gate_a != crate::fi::OK_SENTINEL {
            ui::show_status("Sign", "7730 binding fail");
            return NscStatus::InternalError as u32;
        }

        crate::fi::wait_random();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: same live local, independently re-read after the randomized
        // gap instead of trusting gate A's cache.
        let bind_verdict_b = unsafe { core::ptr::read_volatile(&bind_verdict_slot) };
        let bind_cfi_verdict_b =
            bind_cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED);
        let bind_all_ok_b = bind_verdict_b == crate::fi::OK_SENTINEL
            && bind_cfi_verdict_b == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        let bind_gate_b =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_all_ok_b));
        crate::fi::scrub_sentinel_register();
        if bind_gate_b != crate::fi::OK_SENTINEL {
            ui::show_status("Sign", "7730 binding fail");
            return NscStatus::InternalError as u32;
        }

        #[cfg(feature = "debug-log")]
        {
            let c = &set.outer.descriptor.ir.contract;
            secure_log!(
                "[ERC-7730] matched: chain={} contract=0x{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x} ir_len={} nested={}",
                set.outer.descriptor.ir.chain_id,
                c[0], c[1], c[2], c[3],
                c[16], c[17], c[18], c[19],
                set.outer.descriptor.ir.raw.len(),
                expected_nested.is_some(),
            );
        }
        (Some(*set), expected_nested)
    } else {
        (None, None)
    };

    // ── 7. Verify optional trailers ────────────────────────────────

    // 7a. ERC-20 bundle metadata attribution is resolved in §7c-bis-erc20
    // below — AFTER the Safe-context verifications (`safe_v1_verified` /
    // `safe_exec_verified`). The acceptance gate admits a bundle whose
    // token sits inside a Safe-flow multiSend record, and those disjuncts
    // MUST require the corresponding Safe context to have actually verified
    // (not just inspect raw companion trailer bytes — audit 2026-06-28).
    // Computing it here would force the disjuncts to run before the Safe
    // verdicts exist.

    // 7b. Reserved compatibility slot. Aave clear-signing flows through
    // the native ERC-7730 verifier (§7c-quinquies / `erc7730_verified`).
    // The wire slot is parsed as a zero-length field above (`reserved_v1`).

    // 7c. `safe_v1` Safe-multisig `approveHash` cross-check —
    // 8-step native pipeline (length → selector → calldata len →
    // chain pin → safe-address pin → operation gate → data_hash bind
    // → safeTxHash bind). The approveHash digest is in the calldata
    // itself, so the firmware recomputes both
    // keccak chains and byte-compares.
    //
    // Runs BEFORE the v3 CoW verify (7c-ter): a Safe-wrapped CoW
    // presign anchors the v3 binding to the SafeTx's inner raw_data and
    // to the Safe's address, so the CoW verify needs the verified Safe
    // context first. Nothing in between reads `cow_order_verified`.
    let safe_v1_verified = if safe_v1.len > 0 {
        let v = crate::tx::eip712::safe::verify_and_bind_trailer(
            &snap[safe_v1.start..safe_v1.start + safe_v1.len],
            inner_data,
            chain_id,
            &to_address,
        );
        // FI-hardened verdict (audit L-10): mirror the batch dispatcher —
        // double-evaluate the verify result through a Hamming-distant
        // sentinel with `wait_random` between, so a single glitch that
        // flips the bind verdict also has to defeat the sentinel compare.
        // Fail closed to `None`.
        let ok = v.is_some();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
            != crate::fi::OK_SENTINEL
        {
            None
        } else {
            v
        }
    } else {
        None
    };

    // 7c-bis. Safe-multisig `execTransaction(...)` decode — no trailer
    // needed; the SafeTx fields are encoded directly into the function
    // arguments, so the firmware decodes them straight out of
    // `inner_data` once the selector matches. Companion of the
    // approveHash path above for the case where the wallet is the
    // EOA-equivalent actually triggering execution (carrying co-signers'
    // approvals in the `signatures` argument).
    // Reserve the selector under a caller-owned, fail-initialized FI/CFI
    // receipt. The strict verifier runs independently of that classification;
    // two resolution gates accept only {claimed + verified} or {unclaimed +
    // unverified}. A stuck-at-false classifier therefore cannot reinterpret a
    // malformed or disallowed Safe call as an ordinary blind-sign route.
    let mut safe_exec_claim = crate::tx::eip712::safe::ExecClaimReceipt::fail_closed();
    let mut safe_exec_claim_cfi = crate::fi::CfiCounter::new();
    // SAFETY: unique initialized local; volatile materialization makes a
    // skipped non-inlined proof call leave an unusable receipt.
    unsafe {
        core::ptr::write_volatile(
            &mut safe_exec_claim,
            crate::tx::eip712::safe::ExecClaimReceipt::fail_closed(),
        )
    };
    crate::tx::eip712::safe::prove_exec_transaction_claim(
        inner_data,
        &mut safe_exec_claim,
        &mut safe_exec_claim_cfi,
    );
    let mut safe_exec_verified: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
    let mut safe_exec_verified_check: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
    let mut safe_exec_verify_cfi_a = crate::fi::CfiCounter::new();
    let mut safe_exec_verify_cfi_b = crate::fi::CfiCounter::new();
    // SAFETY: distinct initialized caller-owned outputs. A skipped verifier
    // call leaves `None`, and its independent CFI counter remains short.
    unsafe {
        core::ptr::write_volatile(&mut safe_exec_verified, None);
        core::ptr::write_volatile(&mut safe_exec_verified_check, None);
    }
    crate::tx::eip712::safe::verify_and_bind_exec_into(
        inner_data,
        chain_id,
        &to_address,
        &mut safe_exec_verified,
        &mut safe_exec_verify_cfi_a,
    );
    crate::fi::wait_random();
    crate::tx::eip712::safe::verify_and_bind_exec_into(
        inner_data,
        chain_id,
        &to_address,
        &mut safe_exec_verified_check,
        &mut safe_exec_verify_cfi_b,
    );

    crate::fi::scrub_sentinel_register();
    let safe_claim_cfi_verdict_a =
        safe_exec_claim_cfi.check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_a_cfi_verdict_a = safe_exec_verify_cfi_a
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_b_cfi_verdict_a = safe_exec_verify_cfi_b
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_resolution_verdict_a = crate::tx::eip712::safe::exec_claim_resolution_proof(
        &safe_exec_claim,
        safe_exec_verified.as_ref(),
        safe_exec_verified_check.as_ref(),
    );
    if safe_claim_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_verify_a_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_verify_b_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_resolution_verdict_a != crate::fi::OK_SENTINEL
    {
        ui::show_status("Safe sign", "exec parse fail");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    crate::fi::wait_random();
    let safe_claim_cfi_verdict_b =
        safe_exec_claim_cfi.check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_a_cfi_verdict_b = safe_exec_verify_cfi_a
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_b_cfi_verdict_b = safe_exec_verify_cfi_b
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_resolution_verdict_b = crate::tx::eip712::safe::exec_claim_resolution_proof(
        &safe_exec_claim,
        safe_exec_verified.as_ref(),
        safe_exec_verified_check.as_ref(),
    );
    if safe_claim_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_verify_a_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_verify_b_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_resolution_verdict_b != crate::fi::OK_SENTINEL
    {
        ui::show_status("Safe sign", "exec parse fail");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();

    // 7c-bis-erc20. ERC-20 bundle → authenticated display metadata
    // (deferred from §7a).
    //
    // This layer proves only the Merkle leaf and chain. Surface-specific
    // attribution happens after dispatch against signed facts: outer target
    // for a direct ERC-20 call, descriptor-resolved tokenPath for ERC-7730,
    // or a verified Safe direct/MultiSend target. Keeping that decision out of
    // raw trailer routing both closes RT-ERC20-01 and preserves legitimate
    // metadata for direct protocol calls such as `deposit(asset, amount)`.
    let chain_verified_meta: Option<Erc20Metadata<'_>> = if erc20.len > 0 {
        let bundle_slice = &snap[erc20.start..erc20.start + erc20.len];
        match verify_erc20_bundle(bundle_slice) {
            Some(meta) if meta.chain_id == chain_id => Some(meta),
            None => None,
            Some(_) => None,
        }
    } else {
        None
    };

    // 7c-ter. Native CoW EIP-712 pipeline: canonical decode, chain/shape
    // checks, orderUid cross-check, and optional Merkle-verified token
    // metadata for each leg. Returns
    // `None` on any failure; no partial-success fallback. See
    // `tx::eip712::cowswap::verify_and_bind_trailer` for specifics.
    //
    // The binding target depends on the Safe context resolved above:
    // for a direct order the trailer binds to `inner_data` with
    // `uid.owner == sender`; for a Safe-wrapped presign it binds to the
    // SafeTx's inner raw_data with `uid.owner == the Safe` (GPv2's
    // settlement sees the Safe as `msg.sender` at execution). One call
    // site, one resolver — see `safe::cow_binding` for the fail-closed
    // argument.
    let cow_bind = crate::tx::eip712::safe::resolve_cow_binding(
        inner_data,
        &sender,
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
    );
    let cow_order_verified = if cow_order.len > 0 {
        let v = crate::tx::eip712::cowswap::verify_and_bind_trailer(
            &snap[cow_order.start..cow_order.start + cow_order.len],
            cow_bind.calldata,
            chain_id,
            &cow_bind.owner,
        );
        // FI-hardened verdict: same sentinel double-eval as the safe_v1
        // bind above and the batch dispatcher's COW_ORDER arm (this call
        // site historically lacked the envelope — closed for parity).
        // Fail closed to `None`.
        let ok = v.is_some();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
            != crate::fi::OK_SENTINEL
        {
            None
        } else {
            v
        }
    } else {
        None
    };

    // 7c-quater. Selector → text-signature bundle.
    //
    // Two parallel paths, mutually exclusive at the wire level:
    //
    //   * Curated (Phase-1+2): Merkle-verified bundle pulled from the
    //     host-side DB whose root is baked into the firmware image.
    //     One canonical text_sig per selector — adversarial 4byte
    //     collisions are dropped at curation time.
    //   * Self-attest (Phase-2b): companion-supplied (selector, text_sig)
    //     pair. Firmware verifies `keccak256(text_sig)[..4] == selector`
    //     and the existing ABI walker checks shape match. A patient
    //     attacker can find a same-shape colliding text_sig with ~2³²
    //     keccak ops, so the trusted UI uses a louder banner for this
    //     path (see SelectorProvenance::SelfAttest).
    //
    // Both paths run the cross-check `bundle.selector == calldata[..4]`
    // after parsing, so a host that signs a perfectly-valid bundle for
    // selector A while supplying calldata starting with selector B
    // cannot mislead the trusted UI either way.
    //
    // If both trailers are present, we refuse the request. A confused
    // companion sending both is a bug; the alternative ("silently
    // prefer curated") would give an attacker plausible deniability if
    // the user later complains the wrong banner showed.
    if selector_trailer.len > 0 && self_attest_trailer.len > 0 {
        ui::show_status("Sign", "both selector trailers");
        return NscStatus::InvalidPointer as u32;
    }

    let selector_verified: Option<SelectorMeta<'_>> = if selector_trailer.len > 0 {
        let bundle_slice =
            &snap[selector_trailer.start..selector_trailer.start + selector_trailer.len];
        match verify_selector_bundle(bundle_slice) {
            Some(meta) => {
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    Some(meta)
                } else {
                    None
                }
            }
            None => None,
        }
    } else if self_attest_trailer.len > 0 {
        let bundle_slice =
            &snap[self_attest_trailer.start..self_attest_trailer.start + self_attest_trailer.len];
        match parse_self_attest_bundle(bundle_slice) {
            Some(meta) => {
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    Some(meta)
                } else {
                    None
                }
            }
            None => None,
        }
    } else {
        None
    };

    // 7d. Downgrade-mitigation gate.
    //
    // The v1 clear-sign flow only binds the setPreSignature calldata
    // to a static "Pre-sign CowSwap order" string. That's safe — but
    // if an attacker strips the v3 trailer from a CoW UserOp, the
    // user would confirm that static string instead of the rich
    // 8-page v3 display and end up pre-signing an orderUid they never
    // saw the contents of. So: for CoW setPreSignature specifically,
    // require v3 verification. No fallback.
    let cow_selector = inner_data.len() >= 4 && &inner_data[..4] == SET_PRE_SIGNATURE_SELECTOR;
    let cow_target = to_address == GPV2_SETTLEMENT_ADDRESS;
    if cow_selector && cow_target && cow_order_verified.is_none() {
        ui::show_status("CoW sign", "v3 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Safe-wrapped twin of the gate above. `via_safe` is true exactly
    // when a *verified* Safe context's inner call claims setPreSignature
    // on the GPv2 settlement (see `safe::cow_binding`) — in that case a
    // verified v3 trailer is mandatory too. Without this gate a hostile
    // companion could strip the trailer and the order would fall to the
    // generic blind-sign inner page; a user habituated to the rich CoW
    // display might confirm it anyway. Same failure mode covers
    // malformed presign calldata and `signed == false` (revocation is
    // unsupported, exactly like the direct path).
    if cow_bind.via_safe && cow_order_verified.is_none() {
        ui::show_status("CoW sign", "v3 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Direct-path CoW target gate (audit 2026-06-26 — direct-path target
    // unshown). A verified DIRECT (non-Safe-wrapped) v3 order renders via
    // `render_cowswap_pages`, which shows the order but NOT the UserOp call
    // target. The signed `executeWithOffchainCount(...)` forwards
    // `to_address.call{value}(data)` to an arbitrary target, so unless it IS
    // the GPv2 settlement singleton the user would confirm a trusted CoW
    // screen while signing a call (and any `value`) to an attacker-chosen,
    // never-displayed address. The Safe-wrapped path already pins the inner
    // target via `safe_inner_is_cow_presign`; this is its direct-arm twin.
    // A legitimate direct presign always targets GPv2, so this never refuses
    // a well-formed CoW UserOp.
    if !crate::tx::eip712::safe::direct_cow_target_ok(
        cow_order_verified.is_some(),
        cow_bind.via_safe,
        &to_address,
    ) {
        ui::show_status("CoW sign", "bad target");
        return NscStatus::InvalidPointer as u32;
    }

    // Symmetric Safe `approveHash` gate. If the inner calldata claims
    // to be `approveHash(bytes32)`, a `safe_v1` trailer is mandatory.
    // Without this gate a hostile NS could strip the trailer and
    // coerce the user into blind-signing the bytes32 hash with no
    // visibility into what SafeTx it commits to.
    //
    // Keyed on the SELECTOR ALONE (like the CoW `setPreSignature` gate
    // above), NOT an exact calldata length: `Safe.approveHash(bytes32)`
    // ignores trailing calldata on-chain, so the old `len == 36` test was
    // a parser differential — `selector ‖ hash ‖ 0x00` (37 B) skipped the
    // gate AND failed `safe_v1` verify, falling to a generic blind-sign of
    // an approveHash that pre-approves an arbitrary SafeTx (audit
    // 2026-06-28). `is_approve_hash_claim` closes the differential.
    if crate::tx::eip712::safe::is_approve_hash_claim(inner_data) && safe_v1_verified.is_none() {
        ui::show_status("Safe sign", "safe_v1 required");
        return NscStatus::InvalidPointer as u32;
    }

    // MultiSend gate. When a verified Safe context's inner call claims
    // an allowlisted MultiSendCallOnly DELEGATECALL, the payload must
    // pass every hard rule (strict framing, per-record operation == 0,
    // record cap, at most one presign claim) AND fit the trusted-
    // display page budget — a record the user never sees is exactly
    // the attack class this flow closes, so overflow refuses instead
    // of truncating. One shared decision (`multisend_sign_gate`) for
    // this handler and the batch handler. Reserved pages here: the
    // dispatcher's native-value page when the outer UserOp carries
    // ETH, plus the two ERC-8213 fingerprint pages appended below.
    {
        // Native-value page (when outer value != 0) + mandatory full signer
        // and target pages + worst-case non-zero nonce-lane page + the
        // mandatory UserOp gas-triple page (F10) + 2 ERC-8213 fingerprint pages
        // + 2 gas/fee pages (the dispatcher splices the gas pages for the Safe
        // surface — audit 2026-06-19) + the paymaster page when paymasterAndData
        // is non-empty (audit 2026-06-27).
        let reserved = usize::from(value.iter().any(|&b| b != 0))
            + usize::from(paymaster_and_data_hash != SHA256_EMPTY)
            + usize::from(include_init_code) * crate::tx::display::DEPLOYMENT_MODE_PAGES
            + crate::tx::display::SIGNER_IDENTITY_PAGES
            + crate::tx::display::TARGET_IDENTITY_PAGES
            + crate::tx::display::NONZERO_NONCE_LANE_PAGES
            + crate::tx::display::USEROP_GAS_PAGES
            + 2
            + 2;
        match crate::tx::display::multisend_sign_gate(
            safe_v1_verified.as_ref(),
            safe_exec_verified.as_ref(),
            cow_order_verified.as_ref(),
            reserved,
        ) {
            crate::tx::display::MultisendGate::Reject(reason) => {
                ui::show_status("Safe sign", reason);
                return NscStatus::InvalidPointer as u32;
            }
            crate::tx::display::MultisendGate::NotMultiSend
            | crate::tx::display::MultisendGate::Ok => {}
        }
    }

    // 7d-bis. The opt-in forced-blind branch is terminal and exists only for
    // an exact steady-state Type-2 request with a clean, explicit empty
    // ERC-7730 slot. Classification runs only after every existing
    // Safe/CoW/protected-call gate above has completed. A non-candidate resumes
    // the ordinary renderer below unchanged; no terminal failure may downgrade
    // into that path.
    #[cfg(feature = "erc7730-forced-blind")]
    {
        let request = super::cmd_sign_userop_forced::ForcedRequest {
            wire: &snap[..total_len],
            account_index,
            slot_index,
            sender,
            chain_id,
            nonce: type2_nonce,
            call_gas_limit,
            verification_gas_limit,
            pre_verification_gas,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            target: to_address,
            value,
            tx: &tx_for_display,
            calldata: inner_data,
        };
        match super::cmd_sign_userop_forced::classify(&request) {
            super::cmd_sign_userop_forced::ForcedRoute::ContinueOrdinary => {}
            super::cmd_sign_userop_forced::ForcedRoute::Candidate(eligibility) => {
                return unsafe {
                    super::cmd_sign_userop_forced::run(args, eligibility, request)
                };
            }
            super::cmd_sign_userop_forced::ForcedRoute::Fatal => {
                ui::show_status("Sign refused", "forced classify");
                return NscStatus::InternalError as u32;
            }
        }
    }

    // 7e. Address-name bundles.
    //
    // Every bundle crosses the Merkle gate against NAMES_DB_ROOT.
    // Bundles that don't verify are silently dropped — the affected
    // address just renders as 40-hex, which is always safe. A bundle
    // IS verified against the DB but the (chain_id, address) pair in
    // the verified metadata is NOT necessarily the tx chain_id or
    // tx.to; the resolver matches those against the tx-derived values
    // at display time.
    let mut resolver = NameResolver::new();
    {
        let mut walk = names_start;
        for _ in 0..names_count {
            let l = u16::from_be_bytes([snap[walk], snap[walk + 1]]) as usize;
            walk += 2;
            let bundle_slice = &snap[walk..walk + l];
            if let Some(meta) = verify_name_bundle(bundle_slice) {
                resolver.push(meta);
            }
            walk += l;
        }
    }

    // ── 8. Render + confirm ────────────────────────────────────────
    //
    // The priority ladder (CoW → Safe → ERC-7730 → known-call refusal →
    // value/ERC-20/typed/blind) lives in `display::pick_sign_pages`.
    //
    // Slot rotation is its own affirmative-consent step: when
    // `FLAG_REGISTER_SLOT` is set the firmware also emits a Type 1
    // `addOwnerBytes` UserOp that consumes one of the wallet's
    // `MAX_BOOTSTRAP_USES` budget items on chain. Without a separate
    // confirm a hostile companion could silently set the flag on every
    // routine UserOp and drain the bootstrap reserve at twice the rate
    // the user thinks they're authorising. The Type 1 sig is gated by
    // the on-chain monotonic cap regardless; this gate just makes the
    // cost visible to the user.
    if register_slot {
        let mut rotate_pages = crate::tx::display::build_slot_rotation_pages(slot_index);
        let signer_pages_before = rotate_pages.len;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_from_page(
            &mut rotate_pages,
            account_index,
            &sender,
            &mut signer_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let signer_cfi_verdict =
            signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let signer_page_verdict = crate::tx::display::from_page_proof(
            &rotate_pages,
            signer_pages_before,
            account_index,
            &sender,
        );
        if signer_cfi_verdict != crate::fi::OK_SENTINEL
            || signer_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        let nonce_lane_pages_before = rotate_pages.len;
        let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_nonce_lane_page(
            &mut rotate_pages,
            &nonce,
            &mut nonce_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let nonce_lane_cfi_verdict =
            nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let nonce_lane_page_verdict = crate::tx::display::nonce_lane_page_proof(
            &rotate_pages,
            nonce_lane_pages_before,
            &nonce,
        );
        if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        // The rotation consent contributes a Type-1 signature over the same
        // UserOperation gas words. Keep its confirmation boundary subject to
        // the same handler-owned exact gas-page invariant as the Type-2
        // confirmation below and as every batch confirmation.
        let gas_lane_pages_before = rotate_pages.len;
        let mut gas_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_userop_gas_page(
            &mut rotate_pages,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
            &mut gas_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof(
            &rotate_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
            &rotate_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_final_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_final_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "gas conflict");
            return NscStatus::InternalError as u32;
        }
        // Pixel trusted UI (`ui-px`): the rotation consent is re-emitted as
        // design screens (rotation body + the signer / lane / gas trailer
        // twins), bound to the proven `rotate_pages` by the same lift proof.
        let px_rotation_facts = crate::tx::display::TrailerFacts {
            tx: &tx_for_display,
            legacy_fee_required: false,
            paymaster_and_data_hash: &paymaster_and_data_hash,
            account_index,
            sender: &sender,
            target: &to_address,
            nonce: &nonce,
            call_gas: &call_gas_limit,
            verification_gas: &verification_gas_limit,
            pre_verification_gas: &pre_verification_gas,
            fingerprint: crate::tx::display::erc8213::Kind::CalldataDigest(
                pqsigner_tx_core::erc8213::calldata_digest(inner_data),
            ),
            deployment: None,
            set: crate::tx::display::TrailerSet::Rotation,
            fingerprint2: None,
            offchain: None,
        };
        let px_rotation = px_route_rotation(px_scratch, &rotate_pages, chain_id, slot_index, &px_rotation_facts);
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        let px_rotation_route = px_rotation.is_some();
        let (cr, cr_verdict) = match px_rotation {
            Some(Ok(r)) => r,
            Some(Err(reason)) => {
                ui::show_status("Sign refused", reason);
                return NscStatus::InternalError as u32;
            }
            None => confirm_checked(rotate_pages.as_slice()),
        };
        match cr {
            ConfirmResult::Confirmed => {
                #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
                if px_rotation_route {
                    crate::fi::scrub_sentinel_register();
                    if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
                        super::zeroize_sensitive_state();
                        ui::show_status("Sign refused", "px atlas");
                        return NscStatus::InternalError as u32;
                    }
                    crate::fi::scrub_sentinel_register();
                }
            }
            ConfirmResult::Cancelled => {
                #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
                if px_rotation_route {
                    crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Declined);
                    return NscStatus::UserRejected as u32;
                }
                ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        // FI belt (UI1 / work-todo #12c): reach signing ONLY on the affirmative
        // sentinel born at confirm's accept branch. A skipped reject-arm return
        // is caught here; fail closed (zeroize + reject).
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }
    // `include_init_code` changes the released response, the Type-2 digest,
    // and whether the bootstrap key signs a factory authorization. Bind that
    // mode to the exact public deployment context before the cancellable main
    // confirmation; the receipt is published only from its affirmative arm.
    let deployment_context = crate::tx::display::DeploymentConfirmContext::new(
        include_init_code,
        chain_id,
        account_index,
        slot_index,
        sender,
        type2_nonce,
        PQ_SMART_WALLET_FACTORY,
    );
    let mut deployment_confirm_receipt = crate::tx::display::DeploymentConfirmReceipt::new();
    deployment_confirm_receipt.fail_initialize();
    let legacy_fee_pages_required = crate::tx::display::legacy_fee_pages_required(
        cow_order_verified.is_some(),
        safe_v1_verified.is_some(),
        safe_exec_verified.is_some(),
    );
    let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();
    dispatch_page_proofs.fail_initialize();
    let mut pages = match pick_sign_pages_with_erc7730_evidence(
        &tx_for_display,
        inner_data,
        &sender,
        cow_order_verified.as_ref(),
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
        erc7730_verified.as_ref(),
        erc7730_nested_binding.as_ref(),
        chain_verified_meta.as_ref(),
        selector_verified.as_ref(),
        &resolver,
        &mut dispatch_page_proofs,
    ) {
        Ok(p) => p,
        // Fail closed for any mandatory render failure: native-value/gas page
        // budget, Safe accounting, a verified ERC-7730 descriptor that cannot
        // render exactly, or a firmware-known call whose proof was omitted /
        // malformed / mis-bound. None may downgrade to a weaker confirmation.
        Err(()) => {
            ui::show_status("Sign refused", "render refused");
            return NscStatus::InternalError as u32;
        }
    };
    // Paymaster WYSIWYS gate (audit 2026-06-27). `paymaster_and_data_hash` is
    // folded into the signed sphincs digest below, so the signature commits
    // to whatever paymaster the companion chose — but no renderer surfaces
    // it. A companion can route an otherwise-benign UserOp through a
    // token-paymaster the user previously approved, draining ERC-20 as "gas"
    // behind the confirm (the "Worst-case ETH" page actively misdirects). The
    // firmware only has sha256(paymasterAndData) so it cannot show *which*
    // paymaster, but it appends a loud "! PAYMASTER SET" page whenever one is
    // present. FI-hardened (sentinel skip-on-empty) and fails CLOSED on a
    // full buffer — refuse rather than sign a sponsor the user never saw.
    let paymaster_pages_before = pages.len;
    let mut paymaster_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_paymaster_page(
        &mut pages,
        &paymaster_and_data_hash,
        &mut paymaster_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "paymaster unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let paymaster_cfi_verdict =
        paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let paymaster_page_verdict = crate::tx::display::paymaster_page_proof(
        &pages,
        paymaster_pages_before,
        &paymaster_and_data_hash,
    );
    if paymaster_cfi_verdict != crate::fi::OK_SENTINEL
        || paymaster_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "paymaster unshown");
        return NscStatus::InternalError as u32;
    }
    // Account/signer identity is mandatory on every UserOp confirmation.
    // `sender` is the mnemonic-derived, independently cross-checked address,
    // never the companion field. Append-only publication preserves every
    // renderer/paymaster page that has already been built and proved.
    let signer_pages_before = pages.len;
    let mut signer_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_from_page(&mut pages, account_index, &sender, &mut signer_cfi)
        .is_err()
    {
        ui::show_status("Sign refused", "signer unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let signer_cfi_verdict =
        signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let signer_page_verdict =
        crate::tx::display::from_page_proof(&pages, signer_pages_before, account_index, &sender);
    if signer_cfi_verdict != crate::fi::OK_SENTINEL || signer_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "signer unshown");
        return NscStatus::InternalError as u32;
    }
    // The exact outer contract target is mandatory even when the semantic
    // renderer (notably ERC-7730) does not show it itself. Append after the
    // proven signer page and independently prove the full page materialized.
    let target_pages_before = pages.len;
    let mut target_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_target_page(&mut pages, &to_address, &mut target_cfi).is_err() {
        ui::show_status("Sign refused", "target unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let target_cfi_verdict =
        target_cfi.check_into_sentinel(crate::tx::display::TARGET_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let target_page_verdict =
        crate::tx::display::target_page_proof(&pages, target_pages_before, &to_address);
    if target_cfi_verdict != crate::fi::OK_SENTINEL || target_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "target unshown");
        return NscStatus::InternalError as u32;
    }
    // EntryPoint v0.6's high 192 nonce bits select an independently
    // executable lane. Lane zero stays compact; every non-zero lane is shown
    // in full and independently FI-proved so two lane-distinct UserOps cannot
    // hide behind the same low-64 `Nonce:` row.
    let nonce_lane_pages_before = pages.len;
    let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_nonce_lane_page(&mut pages, &type2_nonce, &mut nonce_lane_cfi)
        .is_err()
    {
        ui::show_status("Sign refused", "lane unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let nonce_lane_cfi_verdict =
        nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let nonce_lane_page_verdict =
        crate::tx::display::nonce_lane_page_proof(&pages, nonce_lane_pages_before, &type2_nonce);
    if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
        || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "lane unshown");
        return NscStatus::InternalError as u32;
    }
    // EntryPoint v0.6 commits callGasLimit, verificationGasLimit, and
    // preVerificationGas as three independent, ordered 256-bit words. The
    // generic Safe/CoW envelope only showed their saturated u64 aggregate, so a
    // gas-split permutation with the same sum rendered identically (F10). Bind
    // all three exact values on their own page, independently FI-proved, so no
    // permutation can hide behind the aggregate. The handler is the sole page
    // producer for every render path; the pre/post scans reject any duplicate
    // or conflicting gas-shaped page.
    let gas_lane_pages_before = pages.len;
    let mut gas_lane_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_userop_gas_page(
        &mut pages,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
        &mut gas_lane_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "gas unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let gas_lane_cfi_verdict =
        gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof(
        &pages,
        gas_lane_pages_before,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
    );
    if gas_lane_cfi_verdict != crate::fi::OK_SENTINEL
        || gas_lane_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "gas unshown");
        return NscStatus::InternalError as u32;
    }
    // ERC-8213 fingerprint — show the calldata digest as the last
    // page so a user can cross-check against `cast` / `viem`. Cap is
    // `MAX_PAGES` = 31; `multisend_sign_gate` reserves the full signer and
    // target pages, the conditional nonce-lane page, and these two fingerprint
    // pages. If the buffer is nonetheless full we
    // fail closed (F5): the fingerprint binds the displayed intent to the
    // signed calldata, so dropping it silently and signing anyway breaks that
    // binding.
    let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(inner_data);
    let fingerprint_pages_before = pages.len;
    let fingerprint_kind = crate::tx::display::erc8213::Kind::CalldataDigest(calldata_fingerprint);
    let mut fingerprint_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::erc8213::append_fingerprint_page(
        &mut pages,
        fingerprint_kind,
        &mut fingerprint_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "fp unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let fingerprint_cfi_verdict =
        fingerprint_cfi.check_into_sentinel(crate::tx::display::erc8213::FINGERPRINT_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let fingerprint_page_verdict = crate::tx::display::erc8213::fingerprint_page_proof(
        &pages,
        fingerprint_pages_before,
        fingerprint_kind,
    );
    if fingerprint_cfi_verdict != crate::fi::OK_SENTINEL
        || fingerprint_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fp incomplete");
        return NscStatus::InternalError as u32;
    }
    // Deployment is a UserOp-level mode, so append its exact factory page
    // after the semantic calldata fingerprint and prove the completed-skip
    // path when initCode is absent. A full page budget refuses atomically.
    let deployment_pages_before = pages.len;
    let mut deployment_page_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_deployment_page(
        &mut pages,
        &deployment_context,
        &mut deployment_page_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "deploy unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let deployment_cfi_verdict = deployment_page_cfi
        .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let deployment_page_verdict = crate::tx::display::deployment_page_proof(
        &pages,
        deployment_pages_before,
        &deployment_context,
    );
    if deployment_cfi_verdict != crate::fi::OK_SENTINEL
        || deployment_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "deploy unshown");
        return NscStatus::InternalError as u32;
    }
    // Recompute the canonical gas page and scan the COMPLETE page set after
    // every later append. The insertion-completion proof above establishes the
    // one-page length transition; this final-boundary proof prevents a later
    // duplicate or gas-shaped conflict from reaching confirmation.
    crate::fi::scrub_sentinel_register();
    let gas_lane_final_cfi_verdict =
        gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
        &pages,
        gas_lane_pages_before,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
    );
    if gas_lane_final_cfi_verdict != crate::fi::OK_SENTINEL
        || gas_lane_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "gas conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let paymaster_final_cfi_verdict =
        paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let paymaster_final_verdict = crate::tx::display::paymaster_final_set_proof(
        &pages,
        paymaster_pages_before,
        &paymaster_and_data_hash,
    );
    if paymaster_final_cfi_verdict != crate::fi::OK_SENTINEL
        || paymaster_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "paymaster changed");
        return NscStatus::InternalError as u32;
    }
    // Recheck the dispatcher-owned native/legacy-fee suffix against the
    // complete transcript after paymaster, identity, nonce, exact-gas and
    // fingerprint appends. This also rechecks the caller-owned dispatcher CFI
    // receipts immediately before the pages cross the confirmation boundary.
    crate::fi::scrub_sentinel_register();
    let mut dispatch_final_verdict_slot = 0u32;
    // SAFETY: unique live local. The volatile FAIL state is load-bearing: if
    // the non-inlined final proof is fault-skipped, stale stack/register data
    // cannot authorize the confirmation below.
    unsafe {
        core::ptr::write_volatile(&mut dispatch_final_verdict_slot, crate::fi::FAIL_SENTINEL);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    dispatch_page_proofs.final_set_proof(
        &pages,
        &tx_for_display,
        legacy_fee_pages_required,
        &mut dispatch_final_verdict_slot,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the slot remains live and is not concurrently written.
    let dispatch_final_verdict_a =
        unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
    crate::fi::scrub_sentinel_register();
    let dispatch_final_gate_a = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(dispatch_final_verdict_a == crate::fi::OK_SENTINEL)
    });
    crate::fi::scrub_sentinel_register();
    if dispatch_final_gate_a != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "value/fee conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::wait_random();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: this is a second independent volatile read after a randomized
    // gap; it deliberately does not reuse gate A's cached evidence.
    let dispatch_final_verdict_b =
        unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
    crate::fi::scrub_sentinel_register();
    let dispatch_final_gate_b = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(dispatch_final_verdict_b == crate::fi::OK_SENTINEL)
    });
    crate::fi::scrub_sentinel_register();
    if dispatch_final_gate_b != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "value/fee conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if crate::tx::display::erc8213::fingerprint_final_set_proof(
        &pages,
        fingerprint_pages_before,
        fingerprint_kind,
    ) != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fp changed");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let deployment_final_cfi_verdict = deployment_page_cfi
        .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let deployment_final_verdict = crate::tx::display::deployment_final_set_proof(
        &pages,
        deployment_pages_before,
        &deployment_context,
    );
    if deployment_final_cfi_verdict != crate::fi::OK_SENTINEL
        || deployment_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "deploy changed");
        return NscStatus::InternalError as u32;
    }
    // Pixel trusted UI (`ui-px`): the proven `pages` stay the proof
    // substrate; the Safe route and every single-UserOp route are re-emitted
    // as design screens, bound to them by `px_lift::transcript_proof`, and
    // confirmed through the design's grammar. The structured routes still to
    // be ported (direct CoW, ERC-7730) — and every build without `ui-px` —
    // keep the page dialog.
    // The facts every trailer page above was painted from, for the pixel
    // route's native trailer twins (`tx::display::trailer_screens`): the
    // same values, never the pages and never companion bytes.
    let px_trailer_facts = crate::tx::display::TrailerFacts {
        tx: &tx_for_display,
        legacy_fee_required: legacy_fee_pages_required,
        paymaster_and_data_hash: &paymaster_and_data_hash,
        account_index,
        sender: &sender,
        target: &to_address,
        nonce: &type2_nonce,
        call_gas: &call_gas_limit,
        verification_gas: &verification_gas_limit,
        pre_verification_gas: &pre_verification_gas,
        fingerprint: fingerprint_kind,
        deployment: Some(&deployment_context),
        set: crate::tx::display::TrailerSet::Sign,
        fingerprint2: None,
        offchain: None,
    };
    let px_decision = px_route_confirm(
        px_scratch,
        &pages,
        chain_id,
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
        cow_order_verified.as_ref(),
        chain_verified_meta.as_ref(),
        &resolver,
        &px_trailer_facts,
        &tx_for_display,
        inner_data,
        selector_verified.as_ref(),
        erc7730_verified.is_some(),
    );
    // Whether the pixel UI owns this confirmation (and therefore its ending).
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    let px_route = px_decision.is_some();
    let (cr, cr_verdict) = match px_decision {
        Some(Ok(r)) => r,
        Some(Err(reason)) => {
            ui::show_status("Sign refused", reason);
            return NscStatus::InternalError as u32;
        }
        None => confirm_checked(pages.as_slice()),
    };
    match cr {
        ConfirmResult::Confirmed => {
            // Second, spatially separate re-proof of the NS-resident glyph
            // atlas the pixel dialog just painted with (the first sits in
            // `px_confirm_safe`): the handler does not trust the returned
            // tuple alone, same A/B shape as the dispatch final gates.
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::fi::scrub_sentinel_register();
                if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
                    super::zeroize_sensitive_state();
                    ui::show_status("Sign refused", "px atlas");
                    return NscStatus::InternalError as u32;
                }
                crate::fi::scrub_sentinel_register();
            }
        }
        ConfirmResult::Cancelled => {
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Declined);
                return NscStatus::UserRejected as u32;
            }
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return NscStatus::IdleWipe as u32;
        }
    }
    // FI belt (UI1 / work-todo #12c): reach signing ONLY on the affirmative
    // sentinel born at confirm's accept branch. A skipped reject-arm return is
    // caught here; fail closed (zeroize + reject).
    if cr_verdict != crate::fi::OK_SENTINEL {
        super::zeroize_sensitive_state();
        return NscStatus::UserRejected as u32;
    }
    if deployment_confirm_receipt
        .record_confirmed(&deployment_context)
        .is_err()
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }

    // ── 9. Reconstruct entropy + derive slot master ────────────────
    //
    // HIGH-6: wrap every stack-local secret in Zeroizing.
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|s| s.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut *entropy_blob) {
            Ok(l) => l,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };
    let mut entropy = Zeroizing::new(
        match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &*master_secret,
        ) {
            Ok(e) => e,
            Err(_) => return NscStatus::CryptoError as u32,
        },
    );
    let slot_master_entropy: Zeroizing<[u8; 32]> = Zeroizing::new(
        crate::crypto::slot_master_entropy_from_entropy(&*entropy, account_index),
    );

    // ── 10. Build Type 2 callData: executeWithOffchainCount(...) ───
    //
    // The on-chain wallet's slot-authorised execute path also publishes
    // the firmware's per-slot off-chain sig counter, so the calldata
    // here commits to `(ownerIndex, newOffchainCount, target, value,
    // data)`. `newOffchainCount` is the firmware's local count *for
    // this slot*, read from secure-flash page 123.
    let t2_owner_index = (slot_index as u64) + 1;
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // The on-chain wallet's `_setOffchainSigCount` reverts on
    // non-monotonic input. The firmware's best estimate of the
    // on-chain `offchainSigCount[i]` is `last_userop_count` — the
    // value committed by the previous Type 2 sign for this slot. If
    // the local `offchain_count` view has fallen below that mark
    // (e.g. a partial compaction lost a `COUNT` entry, or this is the
    // first sign after a fresh-from-seed restore that surfaced a
    // stale `USEROP` snapshot from the prior incarnation), promote
    // `new_offchain_count` to the high-water mark and repair the
    // local off-chain counter so cmd_sign_offchain's gap arithmetic
    // and the `slotUses + offchainSigCount <= MAX_SLOT_USES` cap
    // continue to operate on a consistent base. Without this, the
    // sign here would still produce a valid C10 sig but the on-chain
    // verification would revert — wasting the slot's hypertree
    // budget AND surfacing as "Sig commit FAIL" the next time
    // `last_userop_count_set` enforced its old strict-monotonic
    // check.
    // F-10 hardening (audit 2026-06-18 — bring this gate to the off-chain
    // gate's bar, cmd_sign_offchain.rs §6): read each counter TWICE with a
    // randomised delay between and refuse on disagreement, so a single
    // stuck-at fault on the value-holding register after a good flash scan
    // cannot carry a faulted count into the combined-cap check below. The
    // reads forward+reverse-scan internally (F-12), so a glitched scan
    // yields u64::MAX — rejected here and tripped by the saturating cap.
    let local_offchain_a = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let local_offchain_b = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    if local_offchain_a != local_offchain_b || local_offchain_a == u64::MAX {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let local_offchain = local_offchain_a;

    let last_userop_a = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let last_userop_b = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    if last_userop_a != last_userop_b || last_userop_a == u64::MAX {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let last_userop_snapshot = last_userop_a;

    // MEDIUM-2 (audit counter-replay 20260611): enforce the *combined*
    // SPHINCS+ few-time budget on-device. Off-chain EIP-1271 sigs are
    // never counted on-chain (isValidSignature is view-only), and a
    // UserOp this firmware signs but the companion withholds / lets revert
    // never bumps on-chain `slotUses` — so the chain alone cannot bound
    // total slot-key usage. `userop_sigs` is the durable tally of Type-2
    // sigs THIS firmware has produced for the slot; together with
    // `local_offchain` it is the device's view of total slot-key
    // signatures. Refuse before signing if emitting one more would push
    // the combined total past MAX_SLOT_USES. Fail-closed: a glitched read
    // returns u64::MAX, which saturates and trips the gate.
    let userop_sigs_a = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    crate::fi::wait_random();
    let userop_sigs_b = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    if userop_sigs_a != userop_sigs_b {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let userop_sigs = userop_sigs_a;

    // The synced `last_userop` floor can be ahead of the materialised local
    // counter after recovery / CMD_OFFCHAIN_SYNC.  The promotion below becomes
    // durable before this signature is released, so the cap decision must use
    // that same effective value.  Checking bare `local_offchain` here used to
    // admit one Type-2 signature after a high sync even when
    // `userop_sigs + max(local,last)` was already exhausted.
    let effective_offchain =
        crate::aa::offchain_gate::effective_offchain_count(local_offchain, last_userop_snapshot);
    if !crate::aa::offchain_gate::userop_cap_ok(effective_offchain, userop_sigs) {
        ui::show_status("Slot exhausted", "rotate slot");
        return NscStatus::OffchainCapExceeded as u32;
    }
    // F-10 belt-and-braces: independently recompute BOTH the floor-fold and
    // cap after a randomised delay. `black_box` prevents LLVM from CSE-folding
    // this into the first decision, so a single glitch cannot substitute the
    // stale-low local count in both windows.
    crate::fi::wait_random();
    let effective_offchain_recheck = crate::aa::offchain_gate::effective_offchain_count(
        core::hint::black_box(local_offchain),
        core::hint::black_box(last_userop_snapshot),
    );
    if effective_offchain_recheck != core::hint::black_box(effective_offchain)
        || !crate::aa::offchain_gate::userop_cap_ok(
            effective_offchain_recheck,
            core::hint::black_box(userop_sigs),
        )
    {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    secure_log!(
        "[S][sign] slot_key={:02x?} local_offchain={} last_userop={} userop_sigs={}",
        slot_flash_key,
        local_offchain,
        last_userop_snapshot,
        userop_sigs
    );
    let new_offchain_count = effective_offchain;
    if new_offchain_count > local_offchain {
        // Best-effort repair. Even if this write fails (e.g. flash
        // exhausted), we continue: `last_userop_count_set` below is
        // tolerant of an unmoved local counter, and the on-chain
        // monotonicity gate is the authoritative check. Surface a
        // diagnostic on the OLED so operators notice the repair.
        if unsafe {
            crate::offchain_state::offchain_count_promote_to(&slot_flash_key, new_offchain_count)
        }
        .is_err()
        {
            ui::show_status("Sign", "offchain repair");
        }
    }
    let t2_exec = match reconstruct_execute_calldata(
        t2_owner_index,
        new_offchain_count,
        &tx_for_display,
        inner_data,
    ) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 11. Type 2 nonce ───────────────────────────────────────────
    // `type2_nonce` was derived before trusted-display rendering so the
    // sequence/lane shown to the user is byte-identical to this signed nonce.

    // ── 12. Slot C10 keygen (cached by (account_index, chain_id, slot_index)) ──
    //
    // Post-Coinbase-port slot keys are chain-specific. With multi-
    // account derivation they're also account-specific (the master
    // entropy varies per `account_index`). A cache miss on any of the
    // three fields triggers a fresh <1 s keygen.
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded non-reentrant dispatcher: the
        // closure runs synchronously inside `peek_state`'s scope and
        // no other handler can race this read.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        match cached {
            Some(c) => {
                c.account_index != account_index
                    || c.chain_id != chain_id
                    || c.slot_index != slot_index
            }
            None => true,
        }
    });

    if need_keygen {
        ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*slot_master_entropy,
                chain_id,
                slot_index,
                |p| ui::show_progress("Slot keygen", p),
            );
        // SAFETY: category 5 — exclusive write to `static mut
        // SLOT_CACHE`. Non-reentrant dispatcher + `HandlerGuard`
        // mean no concurrent reader or SysTick wipe can race this
        // update. Any displaced prior `CachedSlot` drops here; its
        // `ZeroizeOnDrop` wipes the previous SK.
        unsafe {
            *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
                account_index,
                chain_id,
                slot_index,
                key: slot_sk,
            });
        }
        super::state::with_state(|s| {
            s.slot_master_entropy.zeroize();
            crate::fi::zeroize_barrier();
            s.slot_master_entropy = *slot_master_entropy;
            s.slot_master_derived.set_true();
        });
    }

    // Extract the 32-byte slot pubkey halves. Post-port the on-chain
    // verifier takes `bytes32` pkSeed + pkRoot directly from the 64-byte
    // owner bytes, so the old N-mask truncation to 16 bytes is gone.
    // SAFETY: category 5 — read-only borrow of `static mut SLOT_CACHE`.
    // The cache is guaranteed populated above (we either skipped
    // keygen because of a hit, or just wrote a fresh entry).
    // Non-reentrant dispatcher means no concurrent mutator.
    let (slot_pk_seed_32, slot_pk_root_32) = unsafe {
        match &*core::ptr::addr_of!(super::state::SLOT_CACHE) {
            Some(c) => {
                let mut seed = [0u8; 32];
                let mut root = [0u8; 32];
                seed[..16].copy_from_slice(&c.key.pk_seed()[..16]);
                root[..16].copy_from_slice(&c.key.pk_root()[..16]);
                (seed, root)
            }
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        }
    };

    // Slot-N's 64-byte owner bytes (pkSeed || pkRoot) — injected into the
    // Type 1 addOwnerBytes calldata.
    let mut slot_owner_bytes = [0u8; 64];
    slot_owner_bytes[..32].copy_from_slice(&slot_pk_seed_32);
    slot_owner_bytes[32..].copy_from_slice(&slot_pk_root_32);

    // First spatially separate authority check: no bootstrap-key factory
    // signature may start unless the exact deployment context crossed the
    // affirmative trusted-display branch above.
    crate::fi::scrub_sentinel_register();
    if deployment_confirm_receipt.completion_proof(&deployment_context)
        != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sign refused", "deploy consent");
        return NscStatus::InternalError as u32;
    }

    // ── 13. Build Type 1 (optional) + initCode (optional) ──────────
    //
    // We need the bootstrap C10 key in three cases:
    //   * FLAG_INCLUDE_INIT_CODE — to sign the factorySig for slot-0.
    //   * FLAG_REGISTER_SLOT — to sign the addOwnerBytes UserOp.
    // So regen the bootstrap key (<1 s) once and use as needed.
    //
    // Non-secret outputs:
    //   * `init_code_out` / `emit_init_code` — 4280-byte factory call.
    //   * `type1_wrapper_out` / `emit_type1` — 4128-byte SignatureWrapper.
    let mut init_code_out: Zeroizing<[u8; PQ_INIT_CODE_LEN]> =
        Zeroizing::new([0u8; PQ_INIT_CODE_LEN]);
    let mut type1_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    let mut emit_init_code = false;
    let mut emit_type1 = false;
    let mut t1_init_code_digest = SHA256_EMPTY;

    if include_init_code || register_slot {
        ui::show_progress("C10 keygen", 0);
        let (c10_sk, master_pk_seed_32, master_pk_root_32) =
            crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                &*entropy,
                account_index,
                |p| ui::show_progress("C10 keygen", p),
            );

        // Refresh the bootstrap pubkey cache so the address-picker
        // doesn't have to re-keygen this account on the next look-up.
        super::state::with_state(|s| {
            s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
        });

        // ── 13a. Deploy path: build initCode + factorySig ──────────
        if include_init_code {
            ui::show_status("Factory", "signing slot-0");

            // factorySig message: sha256(DOMAIN || chainId(8) ||
            //                             slot0PkSeed(32) || slot0PkRoot(32))
            let mut factory_msg = [0u8; 25 + 8 + 32 + 32];
            factory_msg[..25].copy_from_slice(FACTORY_ADD_SLOT_DOMAIN);
            factory_msg[25..33].copy_from_slice(&chain_id.to_be_bytes());
            factory_msg[33..65].copy_from_slice(&slot_pk_seed_32);
            factory_msg[65..97].copy_from_slice(&slot_pk_root_32);
            let factory_digest = sha256_bytes(&factory_msg);

            let factory_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &factory_digest,
                crate::progress_halves!(c10_sign_progress_bootstrap),
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    crate::fi::zeroize_barrier();
                    return NscStatus::CryptoError as u32;
                }
            };
            // Outer FI guard, symmetric with the Type 2 release. The sig
            // is already FI-verified inside `c10_sign_verified_*`; this
            // second pass guards the path between sign and the
            // initCode-buffer copy below. A glitch that corrupts
            // `factory_sig` or `factory_digest` post-sign would fail this
            // gate; without it the firmware would happily embed the
            // corrupted sig into the initCode blob.
            let (fv1, fv2) = {
                let v1 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &factory_digest,
                    &factory_sig,
                );
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &factory_digest,
                    &factory_sig,
                );
                (v1, v2)
            };
            // F16: `black_box` each verdict so LLVM cannot CSE-merge the
            // helper's two closure evaluations into one (the F-1 idiom the
            // single-bool gates here already use). The genuinely CSE-proof
            // redundancy is the two `verify()` calls separated by `wait_random`
            // above; this brings the AND-of-two outer gate up to the same bar.
            if crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(fv1) && core::hint::black_box(fv2)
            }) != crate::fi::OK_SENTINEL
            {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("FactorySig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            // Build the initCode blob. Layout:
            //
            //   factory(20)
            //   || selector(4)
            //   || masterPkSeed(32) || masterPkRoot(32)
            //   || slot0PkSeed(32) || slot0PkRoot(32)
            //   || chainId (left-padded to uint256, 32)
            //   || bytes-offset (0xE0 = 224, 32)
            //   || bytes-length (4008, 32)
            //   || factory_sig (4008 bytes, then padded to 4032)
            let ic = &mut *init_code_out;
            ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
            ic[20..24].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
            ic[24..56].copy_from_slice(&master_pk_seed_32);
            ic[56..88].copy_from_slice(&master_pk_root_32);
            ic[88..120].copy_from_slice(&slot_pk_seed_32);
            ic[120..152].copy_from_slice(&slot_pk_root_32);
            // chainId left-padded
            ic[152 + 24..184].copy_from_slice(&chain_id.to_be_bytes());
            // bytes-offset = 0xE0 (= head-args-len: 5 × 32 = 160; plus 32
            // for own offset slot gives 192 — wait, but offset is measured
            // from the start of the abi-encoded args, AFTER the selector.
            // Args start at ic+24. The 5 fixed slots take 5*32 = 160 bytes.
            // The bytes-offset slot itself is at 160..192. So offset value
            // = 192 (= 0xC0). Actually Solidity measures offset from the
            // *first byte of the abi-encoded args*, not from the offset
            // slot; and the offset points to the start of the length field.
            // For (bytes32,bytes32,bytes32,bytes32,uint64,bytes) the head
            // occupies 6×32 = 192 bytes (each head slot is 32), and the
            // length field starts at byte 192. So offset = 0xc0 = 192.
            let offset_field_start = 24 + 5 * 32;
            ic[offset_field_start + 24..offset_field_start + 32]
                .copy_from_slice(&(6 * 32u64).to_be_bytes());
            let length_field_start = offset_field_start + 32;
            ic[length_field_start + 24..length_field_start + 32]
                .copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
            let data_start = length_field_start + 32;
            ic[data_start..data_start + C10_SIG_LEN].copy_from_slice(&factory_sig);
            // Trailing 4032 - 4008 = 24 bytes of zero padding are already zero.

            debug_assert_eq!(data_start + 4032, PQ_INIT_CODE_LEN);
            emit_init_code = true;
            // initCode digest for the Type 2 sphincs sign.
            t1_init_code_digest = sha256_bytes(ic.as_slice());
        }

        // ── 13b. Rotation path: build addOwnerBytes UserOp + Type 1 sig ──
        if register_slot {
            ui::show_status("Slot register", "signing addOwner");

            // addOwnerBytes(bytes) calldata:
            //   selector(4) || offset(32 = 0x20) || length(32 = 0x40)
            //     || data(64 = slot_N_owner_bytes) — already 32-aligned
            let mut t1_call = [0u8; 4 + 32 + 32 + 64];
            t1_call[..4].copy_from_slice(&PQ_ADD_OWNER_BYTES_SELECTOR);
            t1_call[4 + 28..4 + 32].copy_from_slice(&0x20u32.to_be_bytes());
            t1_call[4 + 32 + 28..4 + 32 + 32].copy_from_slice(&64u32.to_be_bytes());
            t1_call[4 + 64..4 + 64 + 64].copy_from_slice(&slot_owner_bytes);
            let t1_call_digest = sha256_bytes(&t1_call);

            // Sphincs digest for the Type 1 UserOp.
            let t1_params = AaUserOpParamsV06Sha256 {
                sender,
                entry_point: ENTRY_POINT_V06,
                chain_id,
                nonce: U256(nonce),
                init_code_digest: SHA256_EMPTY, // rotation never rides initCode
                call_gas_limit: U256(call_gas_limit),
                verification_gas_limit: U256(verification_gas_limit),
                pre_verification_gas: U256(pre_verification_gas),
                max_fee_per_gas: U256(max_fee_per_gas),
                max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
                paymaster_and_data_digest: SHA256_EMPTY,
            };
            let t1_digest = compute_sphincs_digest_v06(&t1_params, &t1_call_digest);

            let bootstrap_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &t1_digest,
                crate::progress_halves!(c10_sign_progress_bootstrap),
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    crate::fi::zeroize_barrier();
                    return NscStatus::CryptoError as u32;
                }
            };
            // Outer FI guard, symmetric with Type 2.
            let (bv1, bv2) = {
                let v1 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &t1_digest,
                    &bootstrap_sig,
                );
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &t1_digest,
                    &bootstrap_sig,
                );
                (v1, v2)
            };
            // F16: black_box each verdict (see the factory-sig gate above).
            if crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(bv1) && core::hint::black_box(bv2)
            }) != crate::fi::OK_SENTINEL
            {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("Type1 sig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            super::sig_wrapper::encode_signature_wrapper(
                &mut *type1_wrapper_out,
                0,
                &bootstrap_sig,
            );
            emit_type1 = true;
        }

        drop(c10_sk); // ZeroizeOnDrop.
    }

    // ── 14. Type 2: slot C10 signs the user's UserOp sphincs digest ──
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_init_code_digest = if include_init_code {
        t1_init_code_digest
    } else {
        SHA256_EMPTY
    };
    // Second authority check, now coupled to the concrete post-confirm output:
    // the Type-2 digest must consume SHA-256 of the exact emitted initCode and
    // that blob must carry the factory shown to the user. Disabled mode proves
    // the opposite: no emitted blob and the canonical empty digest.
    crate::fi::scrub_sentinel_register();
    let deployment_receipt_verdict =
        deployment_confirm_receipt.completion_proof(&deployment_context);
    crate::fi::scrub_sentinel_register();
    let deployment_output_verdict = crate::tx::display::deployment_output_binding_proof(
        &deployment_context,
        emit_init_code,
        init_code_out.as_slice(),
        &t2_init_code_digest,
        &SHA256_EMPTY,
    );
    if deployment_receipt_verdict != crate::fi::OK_SENTINEL
        || deployment_output_verdict != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sign refused", "deploy binding");
        return NscStatus::InternalError as u32;
    }
    // The on-wire `paymaster_and_data_hash` is now the SHA-256 of the
    // paymasterAndData bytes (companion sends SHA256_EMPTY when absent).
    // Staying all-sha256 means zero keccak on the sign path.
    let t2_params = AaUserOpParamsV06Sha256 {
        sender,
        entry_point: ENTRY_POINT_V06,
        chain_id,
        nonce: U256(type2_nonce),
        init_code_digest: t2_init_code_digest,
        call_gas_limit: U256(call_gas_limit),
        verification_gas_limit: U256(verification_gas_limit),
        pre_verification_gas: U256(pre_verification_gas),
        max_fee_per_gas: U256(max_fee_per_gas),
        max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
        paymaster_and_data_digest: paymaster_and_data_hash,
    };
    let t2_digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);

    // The pixel route plays the qubit loading film around the sign (started
    // here, paced by the signer's opaque progress hook, landed at the
    // post-release site below); every other route keeps the progress text.
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if px_route {
        crate::ui::px::lcd::film_start();
    } else {
        ui::show_progress("Slot C10 sign", 0);
    }
    #[cfg(not(all(feature = "ui-px", feature = "ui-lcd")))]
    ui::show_progress("Slot C10 sign", 0);
    let t2_sig = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded dispatcher; the cache was
        // populated above (or already valid) and no concurrent
        // mutator can swap it under us.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        };
        match crate::crypto::c10_sign_verified_with_progress(
            slot_ref,
            &t2_digest,
            crate::progress_halves!(c10_sign_progress_slot),
        ) {
            Ok(s) => s,
            Err(_) => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::CryptoError as u32;
            }
        }
    };

    // Verify-before-release, double-evaluated with FI hardening. A
    // random-length volatile delay separates the two verifies, and
    // `fi::check_true` gates the AND through a hamming-distant
    // sentinel that survives single-bit flips. Defence in depth: the
    // sig was already FI-verified inside
    // `c10_sign_verified_with_progress`; this second pass guards the
    // path between sign and release-to-NS.
    let (v1, v2) = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE` for the FI-hardened verify-before-release.
        // Same single-threaded-dispatcher rationale as the sign block.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        };
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        crate::fi::wait_random();
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        (v1, v2)
    };
    // F16: black_box each verdict (see the factory-sig gate above).
    if crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(v1) && core::hint::black_box(v2)
    }) != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // Wrap the Type 2 sig: ownerIndex = slot_index + 1 (bootstrap is at 0).
    // `t2_owner_index` was bound at step 10 alongside the calldata.
    let mut type2_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    super::sig_wrapper::encode_signature_wrapper(&mut *type2_wrapper_out, t2_owner_index, &t2_sig);

    // ── 14b. Persist the new last_userop_count and (if Type 1) the
    //         registered-slot flag. Done *after* sig verify so a verify
    //         failure does not bake a phantom count into flash.
    if register_slot {
        if unsafe { crate::offchain_state::offchain_count_register_slot(&slot_flash_key) }.is_err()
        {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            secure_log!(
                "[S][slot-register] offchain_count_register_slot FAIL key={:02x?}",
                slot_flash_key
            );
            ui::show_status("Slot register", "FAIL");
            return NscStatus::InternalError as u32;
        }
    }
    if unsafe { crate::offchain_state::last_userop_count_set(&slot_flash_key, new_offchain_count) }
        .is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!(
            "[S][sig-commit] last_userop_count_set FAIL key={:02x?} count={}",
            slot_flash_key,
            new_offchain_count
        );
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }
    // MEDIUM-2: durably tally this Type-2 slot-key signature so the
    // combined-cap gate (§10) accounts for it on the next call. Bumped
    // after sig verify (so a verify failure bakes no phantom count) and
    // before the response is written (so a bump failure refuses the
    // response rather than releasing an uncounted sig). `userop_sigs` was
    // read at §10 and the cap gate proved `userop_sigs < MAX_SLOT_USES`,
    // so `+ 1` cannot overflow.
    if unsafe { crate::offchain_state::userop_sigs_bump(&slot_flash_key, userop_sigs + 1) }.is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!(
            "[S][sig-commit] userop_sigs_bump FAIL key={:02x?} count={}",
            slot_flash_key,
            userop_sigs + 1
        );
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 15. Assemble output bundle ─────────────────────────────────
    //
    // Layout:
    //   [new_offchain_count(8 BE)] -- the value just baked into the
    //                                signed inner-tx calldata, surfaced
    //                                here so the companion does not
    //                                have to ABI-decode `executeWith
    //                                OffchainCount(...)` to find it.
    //   [init_code_len(4 BE)][init_code(0 or 4280)]
    //   [type1_len(4 BE)][type1_wrapper(0 or 4128)]
    //   [type2_len(4 BE)][type2_wrapper(4128)]
    //
    // FI deref-site re-validation (finding F5). The top-of-handler write gate
    // (§2) and these volatile writes are spatially distant, so a single skip of
    // that gate's reject branch would admit an `out_ptr` into secure SRAM
    // straight to the writes below. Re-validate the FULL MAX_SIGN_RESPONSE_LEN
    // write extent now, double-evaluated through the Hamming-distant sentinel,
    // so reaching the write REQUIRES a second passing validation in this branch
    // — two coordinated faults instead of one. A legit sign already passed the
    // identical §2 check, so this never false-rejects.
    let out_extent_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if out_extent_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }
    let mut write_pos: usize = 0;
    write_be_u64(out_ptr, &mut write_pos, new_offchain_count);
    let init_code_len = if emit_init_code { PQ_INIT_CODE_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, init_code_len as u32);
    if emit_init_code {
        for i in 0..PQ_INIT_CODE_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), init_code_out[i]);
        }
        write_pos += PQ_INIT_CODE_LEN;
    }

    let type1_len = if emit_type1 { SIG_WRAPPER_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, type1_len as u32);
    if emit_type1 {
        for i in 0..SIG_WRAPPER_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), type1_wrapper_out[i]);
        }
        write_pos += SIG_WRAPPER_LEN;
    }

    write_be_u32(out_ptr, &mut write_pos, SIG_WRAPPER_LEN as u32);
    for i in 0..SIG_WRAPPER_LEN {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), type2_wrapper_out[i]);
    }
    write_pos += SIG_WRAPPER_LEN;

    debug_assert!(write_pos <= MAX_SIGN_RESPONSE_LEN);
    debug_assert_eq!(
        write_pos - (8 + 4 + init_code_len + 4 + type1_len + 4),
        SIG_WRAPPER_LEN
    );
    let _ = write_pos;

    // ── 16. Zeroise transients ─────────────────────────────────────
    entropy.zeroize();
    crate::fi::zeroize_barrier();
    type1_wrapper_out.zeroize();
    type2_wrapper_out.zeroize();
    init_code_out.zeroize();
    // L-2: wipe the TOCTOU snapshot on exit too. The payload itself is
    // not secret (the NS side sourced it) but it contains user metadata
    // (names, EIP-712 readable text, recipients) that we don't want
    // leaving in BSS until the next sign overwrites it.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
    // The pixel route lands the film: the current orbit turn completes,
    // the pair spirals in, the flash, the check, then the design's
    // RESULT_HOLD_MS — the film's own hold replaces the legacy spin below.
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if px_route {
        crate::ui::px::lcd::film_resolve(pqsigner_ui_px::scene::Ending::Signed);
    } else {
        ui::show_status("Signed", "");
        for _ in 0..3_000_000u32 {
            cortex_m::asm::nop();
        }
    }
    #[cfg(not(all(feature = "ui-px", feature = "ui-lcd")))]
    {
        ui::show_status("Signed", "");
        for _ in 0..3_000_000u32 {
            cortex_m::asm::nop();
        }
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Volatile write of a big-endian u32 to `out_ptr + *write_pos`, advancing the cursor.
///
/// # Safety
/// Category 2 — NS pointer deref. Caller must have already validated
/// `[out_ptr, out_ptr + MAX_SIGN_RESPONSE_LEN)` via
/// `validate_ns_write_ptr` AND must ensure `*write_pos + 4 <=
/// MAX_SIGN_RESPONSE_LEN`. The volatile store keeps NS observers from
/// seeing a torn word.
unsafe fn write_be_u32(out_ptr: *mut u8, write_pos: &mut usize, v: u32) {
    let be = v.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 4;
}

/// Volatile write of a big-endian u64 to `out_ptr + *write_pos`, advancing the cursor.
///
/// # Safety
/// Category 2 — NS pointer deref. Caller must have validated
/// `[out_ptr, out_ptr + MAX_SIGN_RESPONSE_LEN)` via
/// `validate_ns_write_ptr` AND ensured `*write_pos + 8 <=
/// MAX_SIGN_RESPONSE_LEN`.
unsafe fn write_be_u64(out_ptr: *mut u8, write_pos: &mut usize, v: u64) {
    let be = v.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 8;
}

/// Increment the 64-bit sequence portion of an EntryPoint v0.6 nonce
/// (192-bit key | 64-bit seq, stored big-endian in bytes[24..32]).
fn add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    debug_assert!(false, "nonce seq overflow slipped past the step-4b guard");
}

fn c10_sign_progress_bootstrap(percent: u8) {
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if crate::ui::px::lcd::film_live() {
        crate::ui::px::lcd::film_tick(percent);
        return;
    }
    crate::ui::show_progress("C10 sign", percent);
}

fn c10_sign_progress_slot(percent: u8) {
    // On the pixel route the signer's progress hook paces the film (one
    // frame at most per period); the pose is a pure function of the S-only
    // clock, never of `percent`.
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if crate::ui::px::lcd::film_live() {
        crate::ui::px::lcd::film_tick(percent);
        return;
    }
    crate::ui::show_progress("Slot C10 sign", percent);
}

/// Decode a 32-byte BE u256 as `u128`, saturating at `u128::MAX`.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

/// Route a sign confirmation through the pixel UI when `ui-px` is on.
/// `None` means "use the page dialog" (the feature is off);
/// `Some(Err(reason))` is a refusal, never a fall-back.
///
/// The precedence is `dispatch::pick_sign_pages_inner`'s: a verified Safe
/// context wins (the Safe surface, CoW-wrapped or not), then a direct CoW
/// order (its page painter re-run binds the body), then an authenticated
/// ERC-7730 render (laid out from the proven page range itself), and
/// everything below them is a single-UserOp route whose body the lift binds
/// by re-running its page painter.
#[cfg(feature = "ui-px")]
#[allow(clippy::too_many_arguments)]
fn px_route_confirm(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    chain_id: u64,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    cow: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    facts: &crate::tx::display::TrailerFacts<'_>,
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    erc7730_present: bool,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    if safe_v1.is_some() || safe_exec.is_some() {
        return Some(super::px_confirm_safe(scratch, pages, chain_id, safe_v1, safe_exec, cow, erc20, resolver, facts));
    }
    if let Some(v3) = cow {
        return Some(super::px_confirm_cow(scratch, pages, v3, facts));
    }
    if erc7730_present {
        let target = tx.to.unwrap_or([0u8; 20]);
        let family = crate::tx::display::erc7730_screens::family(
            crate::tx::display::erc7730_screens::Surface::Contract,
            &target,
        );
        return Some(super::px_confirm_erc7730(scratch, pages, chain_id, family, facts));
    }
    let body = crate::tx::display::userop_screens::UserOpInputs {
        tx,
        inner_data,
        erc20,
        selector,
        resolver,
    };
    Some(super::px_confirm_userop(scratch, pages, body, facts))
}

/// Route the slot-rotation consent through the pixel UI when `ui-px` is on
/// (`None` = the page dialog).
#[cfg(feature = "ui-px")]
fn px_route_rotation(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    chain_id: u64,
    slot_index: u32,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    Some(super::px_confirm_rotation(scratch, pages, chain_id, slot_index, facts))
}

#[cfg(not(feature = "ui-px"))]
#[inline(always)]
fn px_route_rotation(
    _scratch: &mut [u8],
    _pages: &crate::tx::display::Pages,
    _chain_id: u64,
    _slot_index: u32,
    _facts: &crate::tx::display::TrailerFacts<'_>,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    None
}

#[cfg(not(feature = "ui-px"))]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn px_route_confirm(
    _scratch: &mut [u8],
    _pages: &crate::tx::display::Pages,
    _chain_id: u64,
    _safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    _safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    _cow: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    _erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    _resolver: &crate::names::NameResolver<'_>,
    _facts: &crate::tx::display::TrailerFacts<'_>,
    _tx: &crate::tx::eip1559::Eip1559Tx,
    _inner_data: &[u8],
    _selector: Option<&crate::selectors::SelectorMeta<'_>>,
    _erc7730_present: bool,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    None
}

```


### `secure/Cargo.toml`

```toml
[package]
name = "sphincs-tz-secure"
version = "0.1.0"
edition.workspace = true

[dependencies]
sphincs-tz-shared = { workspace = true }
# Shared STM32U585 drivers (typed MMIO + HASH). `debug-log` mirrors this
# crate's own flag so the semihosting diagnostics keep working here.
pqsigner-hw = { workspace = true }
sphincs-tz-bip39  = { workspace = true, features = ["full-wordlist"] }
fw-manifest       = { workspace = true }
# Frozen §5 flash-geometry registry (Draft 1.1, post-errata-4): the single
# source of truth for bank bases, page size, and page ownership. Only
# constants whose values AGREE with the live legacy bench layout are
# re-pointed at it (Foundation A slice FA-1.1, issue #540); the legacy A/B
# slot/manifest constants stay literal until the cutover slice.
pqsigner-geometry = { path = "../geometry" }
# FI hardening primitives shared with FSBL — `secure/src/fi.rs` is a thin
# shim over this crate, supplying the secure-world's TRNG-backed RNG.
pqsigner-fi       = { workspace = true }
# ML-KEM-1024 + HMAC(HUK) + AES-256-GCM hybrid inner wrap for the dual-SE
# entropy halves (HNDL/CRQC defence). `secure/src/pq_wrap.rs` binds it to
# `hw::secret_keys` + the TRNG. See `docs/security/ml-kem-inner-wrap.md`.
pqsigner-pq-seal  = { workspace = true }
# Pure-logic tx primitives (RLP, EIP-1559 envelope, U256, keccak256).
# Extracted from `secure/src/tx/{rlp,eip1559,hash}.rs` in Phase 5 PR 5.1.
# `secure/src/tx/mod.rs` re-exports through it so existing call sites
# (`crate::tx::eip1559::...`) keep working unchanged.
pqsigner-tx-core  = { workspace = true }
# ERC-4337 v0.6 UserOperation hash + EIP-1271 PersonalSign hash.
# Extracted from `secure/src/aa/` in Phase 5 PR 5.2.
# `secure/src/aa/mod.rs` re-exports through it so existing call sites
# (`crate::aa::userop::...`, `crate::aa::eip1271::...`) keep working
# unchanged.
pqsigner-aa       = { workspace = true }
# Pure-logic key derivation + AES-GCM wrap + BIP-39 ↔ SPHINCS+C10
# bridge + slot-key derivation. Extracted from `secure/src/crypto.rs`
# in Phase 5 PR 5.3. `secure/src/crypto.rs` re-exports through it so
# existing call sites (`crate::crypto::derive_c10_master_*`,
# `crate::crypto::encrypt_entropy_blob`, ...) keep working unchanged.
pqsigner-domain   = { workspace = true }
# Pure-logic ERC-20 / address-name / function-selector trust gates.
# Extracted from `secure/src/{erc20,names,selectors}/` in Phase 5 PR
# 5.4. The secure-side modules (`secure/src/erc20/mod.rs` etc.) now
# re-export from this crate and bake the `db_roots::*` constants into
# thin wrapper functions, so existing call sites
# (`crate::erc20::bundle::verify_erc20_bundle(...)`) keep working
# unchanged.
pqsigner-tx       = { workspace = true }
# ERC-7730 clear-signing descriptor interpreter. Binary IR parser,
# Merkle-bundle verifier, context-binding cross-check. Display
# rendering layer lives in `secure/src/tx/display/erc7730/` and
# depends on this crate.
pqsigner-erc7730  = { workspace = true }
# Pixel trusted-UI substrate (Screen transcript, tier fitter, motion, input,
# rasteriser). Always linked so the host test mounts see it; the `ui-px`
# feature switches the firmware wiring on.
pqsigner-ui-px = { workspace = true }

# Crypto (all no_std, no alloc)
sphincs-c10 = { workspace = true }
# First-order masked SHA-256 building blocks — only linked for the
# `bench-masked-sha` measurement firmware (work-todo §18 SHAKE-vs-SHA2).
masked-sha2 = { workspace = true, optional = true }
aes-gcm = { version = "0.10", default-features = false, features = ["aes"] }
aes = { version = "0.8", default-features = false, features = ["zeroize"] }
cmac = { version = "0.7", default-features = false, features = ["zeroize"] }
sha2 = { version = "0.10", default-features = false }
sha3 = { version = "0.10", default-features = false }
subtle = { version = "2.6", default-features = false }
hmac    = { workspace = true }
zerocopy = { version = "0.8", default-features = false }
zeroize = { workspace = true }

# Fast no_std f32 transcendentals (sin/cos/sqrt/powf/floor/ceil) for the
# `splash-test` animated boot-screen preview only. Pure-Rust approximations —
# accurate enough for a 1-bit dithered splash, never used by crypto. Optional:
# compiled in only under `splash-test`. `num-traits` dep stays off
# (default-features = false).
micromath = { version = "2.1", default-features = false, optional = true }

# Graphics primitives used by the NV3007 LCD font/glyph path.
embedded-graphics = { version = "0.8", default-features = false, optional = true }

# ARM-only: these crates don't compile on x86_64, so they're gated to the
# ARM target. This lets `cargo test -p sphincs-tz-secure` run the
# pure-logic unit tests (aa, tx) on the host without pulling in hardware deps.
[target.'cfg(target_arch = "arm")'.dependencies]
cortex-m = { workspace = true, features = ["critical-section-single-core"] }
cortex-m-rt          = { workspace = true }
cortex-m-semihosting = { workspace = true }

[features]
# No default features. Every consumer (Makefile recipe, Cargo invocation,
# CI job) must declare its build profile explicitly via
# `--no-default-features --features ...`. This is a deliberate inversion
# of the previous "default to QEMU dev" stance: a manual `cargo build -p
# sphincs-tz-secure` now fails with a clear "no SE backend selected /
# no UI backend selected" error from the `compile_error!` fences in
# `secure/src/nsc/mod.rs`, instead of silently producing a dev-mode
# build that could be mistaken for production.
#
# Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md
# Phase 2.
default = []

# ---------------------------------------------------------------------------
# Phase-8 PR 1 — axis aliases (additive, no behaviour change).
#
# Five orthogonal axes consolidate the 50 ad-hoc flags below into a
# clearer surface. Each axis flag is a thin alias over the existing
# legacy names so the Makefile recipes can keep working unchanged
# while new code (and `docs/firmware/feature-flags.md` once written) speaks
# the consolidated vocabulary. PR 2 of Phase 8 (deferred per the
# handoff) flips every Makefile recipe to the new names and deletes
# the legacy aliases — but the cross-axis `compile_error!` enforcement
# only lands in PR 2, so today's builds stay backwards-compatible.
#
# Axes:
#
#   1. platform        — pick exactly one of the MCU targets.
#   2. secure-element  — pick exactly one SE backend.
#   3. ui-mode         — pick exactly one UI backend.
#   4. mode            — pick exactly one of the development profiles.
#   5. accelerators    — any subset of side-channel / hw accelerators.
#
# Reference: `docs/archive/handoff-modularity-refactor.md` §4.4.
# ---------------------------------------------------------------------------

# 1. platform axis (mutually exclusive)
platform-qemu      = []                # mps2-an505 / host targets
platform-stm32u585 = ["stm32u585"]

# 2. secure-element axis (mutually exclusive at top level; `dual`
#    implies both component flags below).
secure-element-mock     = ["mock-se"]
secure-element-optiga   = ["optiga-trust-m"]
secure-element-se050    = ["se050"]
secure-element-dual     = ["dual-se"]

# 3. ui-mode axis (mutually exclusive — enforced by build.rs today,
#    cross-axis compile_error! in Phase 8 PR 2).
ui-mode-semihosting = ["ui-semihosting"]
ui-mode-noop        = ["ui-noop"]
ui-mode-capture     = ["ui-capture"]

# 4. mode axis (development profile)
mode-production = []                                    # no debug-log / no e2e-test / no mock-se
# Opt-in: hard-refuse to run (halt) if the boot-time RDP check finds RDP != Level 2
# under `mode-production`. OFF by default while the intended first-field-boot
# self-lock ordering remains unapproved/unimplemented, so non-production
# rehearsal can observe rather than perform an irreversible transition
# (default = WARN-and-continue; RDP2 disables SWD/JTAG in silicon once an
# separately authorized path sets it). silicon-lockdown SL7.
rdp-enforce-halt = []
mode-bringup    = ["debug-log"]                         # debug-log allowed; production-fence sub-features prohibited
mode-e2e        = ["debug-log", "e2e-test"]             # full e2e suite including skip-* sub-flags
mode-bench      = ["debug-log", "e2e-test"]             # bench harness — e2e minus the skip-* flags

# 5. accelerators axis (composes — pick any subset)
accel-tamp             = ["tamp"]
accel-consumption-mask = ["consumption-mask"]
accel-saes-dhuk        = ["saes-dhuk"]

# ---------------------------------------------------------------------------
# Legacy flag names (still load-bearing — Makefile recipes still use
# these). PR 2 of Phase 8 will delete these aliases after every recipe
# has been flipped.
# ---------------------------------------------------------------------------

# Temporary, explicit acknowledgement that a non-shipping STM32U585 image
# still contains the rejected unary OTP rollback backend.  The flag changes
# no runtime behaviour; it only clears the build-time quarantine for bench
# firmware.  Production and factory-provisioning builds reject it (and reject
# the legacy backend unconditionally) in build.rs + nsc/mod.rs.
#
# Remove this feature only when an exact-digest-approved replacement backend
# replaces the legacy implementation. Draft 1.1 is still a research candidate.
# NEVER ship.
legacy-fw-rollback-unsafe = []

# Current development images independently acknowledge both quarantined
# subsystems: the legacy rollback backend and the dev-unattested ERC-7730
# catalogue. Neither acknowledgement feature implies the other; these
# never-ship development modes deliberately select both. This coupling is
# temporary: the first reviewed `erc8176-verified` root rotation MUST remove
# `erc7730-dev-unattested` from these aliases in the same change, because the
# generated verified-root fence intentionally rejects a stale warning feature.
debug-log = ["legacy-fw-rollback-unsafe", "erc7730-dev-unattested", "pqsigner-hw/debug-log"]
mock-se = ["legacy-fw-rollback-unsafe", "erc7730-dev-unattested"]
ui-semihosting = []
ui-noop = []  # Silent no-op UI for standalone USB operation (no debugger)
# Pixel trusted UI (PQ-UI design system port, pilot = the Safe sign flow).
# Additive over the backend axis: with `ui-lcd` the strip rasteriser paints
# the panel; with `ui-semihosting` the screens print as text for QEMU e2e.
# Mutually exclusive with `ui-oled-bench` (16x4-only bench backend).
ui-px = []
# `ui-px` at SPI ÷4 = 40 MHz (production board without the dev kit's LED on SCK).
ui-px-spi40 = ["ui-px", "ui-lcd"]
# Bench-only: overlay the previous frame's render / blit / period (ms) in the
# top-left of every pixel-UI frame (DWT cycle counter). NEVER ship.
ui-px-frametime = ["ui-px", "ui-lcd"]
# Real STM32U585 hardware target (vs QEMU mps2-an505). Pulls in `hw-sha256`
# because on real silicon we always want the HASH peripheral — the software
# `sha2::Sha256` path would waste ~19x the signing time for no reason.
stm32u585 = ["sphincs-tz-shared/stm32u585", "hw-sha256"]

# ---------------------------------------------------------------------------
# Board axis — which physical board an `stm32u585` image targets.
#
# `secure/src/board/` holds one pin/peripheral map per board and re-exports
# the selected one, so drivers name a constant instead of a port base.
#
#   board-iota2  ST B-U585I-IOT02A dev board, STM32U585AII6 (169-pin BGA).
#   board-pq1    AL_A66_MB_V10 production board, STM32U585CIU6 (48-pin
#                UFQFPN — only PA0-15, PB0-15 and PC13 are bonded).
#
# Naming a board is MANDATORY on every `stm32u585` build: `secure/src/board/
# mod.rs` hard-errors if neither feature is set, and if both are.
#
# This used to read "selection is *opt-in to pq1* ... `board-iota2` therefore
# carries no implications". That model was retracted in a15561b4 and the text
# is preserved here only as a warning, because the belief it encoded is what
# caused the bug: `#[cfg(feature = "board-pq1")] compile_error!` fences are
# SILENT when the feature is absent, so a recipe that omitted the board did not
# fail — it compiled the iota2 pin map and every pq1 fence went quiet. That is
# how `build-hw-prodtest BOARD=pq1` came to compile iota2 pins onto pq1
# silicon. `board-iota2` is load-bearing; treating it as inert is what let
# seven build sites drift.
#
# Use `make <target> BOARD=pq1`, which sets the feature and the probe-rs chip
# name together with `override`, so neither can be detached from the other.
board-iota2 = []
board-pq1 = []

# Bench-only, read-only secure-element address probe (`hw::se_i2c_probe`).
# Answers "does the chip at this address ACK?" and nothing else: every probe
# is a zero-data-byte transfer, so no payload reaches either part. Exists
# because on a production board the OPTIGA is virgin and its lifecycle
# transitions are irreversible — this is the one SE check that is safe to run
# on hardware you cannot replace. NEVER SHIP: it is a diagnostic, and it is
# listed in the Makefile's PROD_FORBIDDEN.
se-i2c-probe = []

# LCD-only secure-element diagnostic for a probe-less board (EVT over DFU):
# after the panel is up, runs TRNG / SE050 init+random / OPTIGA init+pair+
# shield+random / rng_strong one step at a time, shows each result on the
# LCD, then cycles the summary forever. Never reaches the wizard. Performs
# the SAME SE writes the normal first boot performs (OPTIGA E140 pairing),
# nothing more. NEVER SHIP — listed in the Makefile's PROD_FORBIDDEN.
se-lcd-diag = []

# Bench: hold BOTH buttons while powering up → firmware clears nSWBOOT0/nBOOT0
# and reloads option bytes, so the chip comes back in the ROM USB-DFU
# bootloader without a probe or an SBU cable (`hw::dev_dfu`, checked right
# after `rcc::init`, before any UI/SE/USB code). Pair with
# `tools/evt-dev-flash.sh`, which restores the boot option bits.
# NEVER SHIP — listed in the Makefile's PROD_FORBIDDEN.
dev-dfu = []

# `ui-oled-bench` (bench-only SSD1306 over bit-banged I2C) was REMOVED
# 2026-09-23: real NV3007 panels exist now, so the stand-in is not needed.
# It was the last consumer of `embedded-graphics` outside `ui-lcd`.
# Route every SHA-256 call in the signing crates through the STM32U585 HASH
# peripheral (the `pqsigner_sha256_*` extern fns in `secure/src/hw/hash.rs`).
# Without this feature the signing crates use software `sha2::Sha256` — what
# host tests need. Every `stm32u585` build opts in automatically.
hw-sha256 = ["sphincs-c10/hw-sha256"]
# Non-interactive automated end-to-end test mode. Provisions a fixed
# test mnemonic + PIN at boot, marks PIN as verified, and short-circuits
# every confirm() / enter_pin() dialog so no stdin input is needed.
# Logs the chosen TxKind variant on every cmd_sign for assertions.
# NEVER ship in production: it disables every meaningful trust gate.
# E2E images use the generated dev fixture catalogue. Pull in the matching
# trusted-display provenance warning centrally so every E2E target satisfies
# the generated root fence; `mode-production` remains mutually exclusive with
# both `e2e-test` and `erc7730-dev-unattested`.
e2e-test = [
    "legacy-fw-rollback-unsafe",
    "erc7730-dev-unattested",
    "erc7730-nested-calldata-test-fixture",
]
# Reversible firmware anti-rollback test: drives the real fw_update::
# verify_manifest chain with dev-key-signed v1/v2/v3 manifests against
# literal test floors (no OTP burn, no flash, no reboot). Runs early in
# main() and halts. Implies e2e-test (the sanctioned hardware-test opt-in
# that relaxes the release-hardware fence) + debug-log (PASS/FAIL output).
# Fenced out of mode-production by a dedicated compile_error! in nsc/mod.rs.
# See secure/src/fw_rollback_e2e.rs. NEVER ship.
fw-rollback-e2e = ["e2e-test", "debug-log"]
# Over-USB FW-update transport e2e (`make fwup-transport-hw`). The
# host driver sends a dev-signed manifest + chunks + COMMIT over USB
# HID; the device runs the full state machine + verify_manifest +
# verify_images, then STOPS before the OTP rollback-floor bump + boot-
# state write + sys_reset (so the chip stays reflashable). Implies
# e2e-test only (PIN/provisioning short-circuits + fence opt-in).
# Deliberately does NOT imply debug-log: semihosting BKPTs under
# probe-rs run halt the core per log line and break USB enumeration
# timing (this is the same lesson the USB-C enumeration work hit —
# see reference_probe_rs_reset_halts_core memory). The make target
# adds usb/mock-se/ui-noop/stm32u585. Fenced out of mode-production.
# NEVER ship.
fwup-transport-e2e = ["e2e-test"]
usb = []  # Enable USB OTG hardware init (clock, GPIO, GTZC) for host communication
# Independent watchdog (IWDG) USB-path hang detection. Implies
# `stm32u585` (IWDG register layout + 1 ms SysTick cadence are
# hardware-specific). Secure-owned IWDG is attributed by GTZC1 bit 7,
# accessed through its Secure alias, and kicked from SysTick while the
# NS heartbeat advances OR a gateway handler is busy; a sustained
# stall (~4 s) stops the kicks and the ~2 s IWDG resets the chip. MUST
# stay OFF for mode-bringup / mode-e2e — a live watchdog resets the
# device during probe-rs breakpoints / semihosting pauses. Pairs with
# the NS-side `iwdg` feature (heartbeat bump + boot registration).
iwdg = ["stm32u585"]
se050 = []  # NXP SE050 secure element via I2C1 (OM-SE050ARD on Arduino R3 headers)
# STM32U585 TAMP (tamper detection) — backup-domain voltage, LSE clock,
# crypto-peripheral-fault, JTAG/SWD-when-RDP>0 monitoring. Log-only IRQ
# handler (prints reason + WFE halt) so a false ITAMP9 during a probe-rs
# debug session doesn't wipe a bench chip. Implies `stm32u585`. Port of
# Trezor's `core/embed/sec/tamper/stm32u5/tamper.c`; see
# `docs/architecture/trezor-comparison.md §2.5` for the adoption rationale.
tamp = ["stm32u585"]
# Flip TAMP from polled-mode to IRQ-mode. Implies `tamp`. Arms TAMP_IER
# + NVIC.ISER0 bit 2 in `tamp::init()`, and routes `IRQn=2` through a
# `DefaultHandler` dispatcher in `secure/src/main.rs`. Reduces detection
# latency from ~1 ms (SysTick poll) to ~hundreds of cycles. **Does not
# change the trigger response** — the IRQ handler still logs + clears,
# never halts and never wipes. Production hardening will flip the
# trigger response separately (see `docs/archive/production-todo-retired-2026-07-19.md` "TAMP
# escalation"). Off by default while polled-mode soaks; see
# `docs/archive/work-todo-retired-2026-07-19.md` #26 for the flip-when criteria.
tamp-irq = ["tamp"]
# Production escalation for a TAMP tamper event (audit tz-tamper 20260611
# MEDIUM-1). When OFF (bench/dev), `tamp::poll` / `tamp::on_tamp_irq` stay
# log-only so a false ITAMP9 (crypto-peripheral fault) during a glitch-
# sensitive probe-rs session doesn't wipe the bench chip — the exact
# bring-up-safety failure mode the log-only handler was built for. When ON,
# a confirmed internal-tamper flag drives the same zeroize-SRAM + arm-page-
# 125-wipe-flag + reset intrusion response the GTZC1 illegal-access path
# uses (`hw::tzic::trigger_intrusion_wipe`); the next boot's wipe-resume
# path finishes the SE factory_reset + page-124 erase. Implies `tamp` (you
# can't escalate a tamper you don't monitor); pair with `tamp-irq` for
# lowest-latency response. Production CI / `make prod-check` must require
# this ON — enforced by the ship-blocker `compile_error!` in `nsc/mod.rs`
# (mirrors `tzic-wipe` / `consumption-mask`).
tamp-wipe = ["tamp"]
# Production escalation for GTZC1 illegal-access. When OFF, the TZIC
# IRQ handler in `hw::tzic::on_violation` only snapshots SR + bumps a
# counter (the `gtzc-test` validation path uses this — see the
# `gtzc-enforcement-hw` Makefile target). When ON, the IRQ handler
# additionally zeroizes SRAM secrets via
# `nsc::zeroize_sensitive_state`, arms the page-125 wipe flag via
# `hw::flash::arm_wipe_flag`, and triggers `SCB::sys_reset`. The
# next boot's existing wipe-resume path (`main.rs:909`) finishes
# the full SE factory_reset + flash erase under the same control
# flow used by `cmd_request_unlock::trigger_lockout_wipe`. Implies
# `stm32u585` (TZIC is U585-only). Off by default while the IRQ
# wiring soaks; production CI must require this ON (analogous to
# how TAMP will require its log→wipe flip).
tzic-wipe = ["stm32u585"]
# Power-consumption side-channel mask. Drives TIM2 CH1 PWM on PA5 with a
# randomised duty cycle so the mask-pin power draw is uncorrelated with
# the crypto work happening elsewhere on the die. Simpler than Trezor's
# GPDMA linked-list version — callers must invoke
# `hw::consumption_mask::randomize()` periodically (e.g. SysTick IRQ or
# inline between signing rounds). Implies `stm32u585`.
# See `docs/architecture/trezor-comparison.md §3.1`.
consumption-mask = ["stm32u585"]
# Screenshot-hash capture for UI regression testing. Emits a SHA-256
# fingerprint of every displayed frame via `secure_log!` (requires
# `debug-log`). Host-side `tools/ui_fixture.py` parses the stream
# and compares against `tests/ui_fixtures.json`. See
# `docs/architecture/trezor-comparison.md §2.3` for the rationale. NEVER ship in
# production — spams the secure log and is a test-only observability
# hook. Implies `debug-log`.
ui-capture = ["debug-log"]
optiga-trust-m = []  # Infineon OPTIGA Trust M V3 via I2C1 (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers)
# Silicon-enforced OPTIGA PIN counter via the E120 Lifetime Usage
# Counter bound to F1D0's Execute access condition (LUC). Parity with
# Trezor Safe's OPTIGA PIN lockout: each HMAC verify auto-increments
# the counter inside the chip, and the AuthRef refuses auth once the
# counter hits its threshold — immune to Platform Binding Secret
# extraction (unlike the soft F1E1 counter). Firmware resets the
# counter to (0, limit) after every successful PIN via Change=Auto(F1D0)
# on E120.
#
# DESTRUCTIVE on first provisioning: rewrites F1D0 metadata with
# Execute=LUC(E120). If F1D0 is already at LcsO=Operational with the
# non-LUC metadata installed, the ratchet blocks the rewrite — the chip
# cannot be repaired by the retired, mis-targeted `optiga-reset-oids`
# experiment. Stop, preserve the part as evidence, and use only a separately
# specified and reviewed replacement ceremony; none exists today. See
# `docs/secure-elements/optiga-brick-postmortem.md` for the incident record.
#
# Feature is pure-additive against non-`optiga-hw-counter` builds: all
# new code is cfg-gated, no behavioural change without it.
optiga-hw-counter = ["optiga-trust-m"]
# End-to-end validation for `optiga-hw-counter`: provisions the chip
# under the LUC binding, reads E120, drives wrong/right-PIN cycles,
# and asserts E120's `current` value matches what silicon should have
# tracked. DESTRUCTIVE — rewrites F1D0 metadata on first run (the
# LUC variant replaces the legacy non-LUC F1D0 metadata). Fails
# loudly if F1D0 is already at LcsO=Operational with non-LUC metadata
# (the `Status(0xE0)` sentinel).
#
# Uses standalone OPTIGA path (not dual-se) so the test isolates
# OPTIGA behaviour from SE050. Use `make optiga-hw-counter-e2e`.
optiga-hw-counter-e2e = ["optiga-hw-counter"]
# §32 duress-PIN feasibility probe: provisions a SECOND OPTIGA AuthRef
# (F1D8, Execute=ALW / no E120 binding) + a SECOND SE050 UserID
# (max_attempts=0) alongside the real credentials, and asserts
# coexistence + that the duress OPTIGA auth leaves E120 untouched.
# Needs the full dual-SE + hw-counter path. Stays LcsO=Creation (never
# locks). Use `make duress-probe-hw`.
duress-probe-e2e = ["dual-se", "optiga-hw-counter"]
# §32 PRODUCTION duress (decoy) wallet. Provisions a second, fully
# independent decoy wallet behind a second PIN credential (OPTIGA F1D8 +
# E121 matched-LUC, SE050 DURESS_USERID_OBJ unlimited). When ON, the
# wizard ALWAYS provisions a decoy (random PIN if the user declines) so
# "duress configured vs not" is indistinguishable. Implies the matched-LUC
# OPTIGA hw-counter path + dual-SE. The unlock-side dispatch (P3) is built
# separately; with only this feature the decoy is provisioned but never
# consulted, so the real wallet behaves identically.
duress-pin = ["dual-se", "optiga-hw-counter"]
# §32 P2 silicon-validation recipe. Implies duress-pin + adds the read-back
# helpers (`OptigaTrustM::duress_read_half` / `Se050::duress_read_half`)
# and the main.rs validation block: provision real + decoy via the
# PRODUCTION provision/provision_duress path with a KNOWN decoy entropy,
# then re-auth the decoy on both chips, read both decoy halves, and assert
# half_o XOR half_e == the known decoy entropy (mirrors the real unlock
# cross-check). Asserts E121 bumped + E120 untouched, real wallet still
# unlocks. Stays LcsO=Creation. Use `make duress-provision-hw`.
duress-provision-e2e = ["duress-pin"]
# §32 P4/P5 INTERACTIVE UI harness. Compiles ONLY the duress-PIN setup
# dialogs (`collect_duress_pin` / `choose_duress_wipe_mode`) — NOT the
# dual-SE / OPTIGA storage stack — so the wizard dialogs can be driven on
# the real OLED with keyboard-forwarded buttons (`make play-hw-duress-ui`)
# without standing up a full dual-SE provision. main.rs short-circuits
# into a dialog loop at boot. Pure UI; pairs with mock-se + ui-oled.
duress-ui-test = []
# Combined MCU page-124 + OPTIGA E120 + SE050 per-attempt and in-run
# desynchronization/recovery E2E. It exercises ordinary three-way attempt
# consumption plus MCU-, OPTIGA-, and SE050-ahead recovery and simulated
# cache resynchronization. It does not reboot, call `reconcile_pin_attempts`,
# or supply evidence for either directional boot branch. Use
# `make pin-gate-hw-counter-e2e`.
pin-gate-hw-counter-e2e = ["dual-se", "optiga-hw-counter", "e2e-test"]
# Destructive end-to-end: burns 10 wrong PINs through gated_unlock to force
# MCU page-124 to MAX_ATTEMPTS, SE050 UserID to silicon-lock, and OPTIGA
# E120 to 10. Then fires `factory_reset_admin` + `pin_attempts_reset` to
# prove the lockout-wipe dispatch path works end-to-end on both chips
# (admin UserID max_attempts=0 lets the wipe run even after user UserID
# locks). Consumes 10 lifetime SE050 UserID slots — recoverable via
# admin-wipe, which re-creates the UserID in `provision_with_admin`.
# Use `make pin-gate-wipe-e2e`.
pin-gate-wipe-e2e = ["dual-se", "optiga-hw-counter", "e2e-test"]
# One-shot dev-only wipe for provisioning iteration. Runs
# `DualSecureElement::factory_reset_admin` (inherits the Trezor-parity
# E120 transient-auth reset from the `optiga-hw-counter` path), erases
# MCU page 124 (PIN counter) — page 125 is erased by
# `Se050::factory_reset_admin` itself when admin UserID deletion
# succeeds — zeroizes SRAM state, shows "WIPED — power-cycle" on the
# OLED, and halts. Firmware stays resident: the next cold boot enters
# the first-boot wizard with whatever fresh PIN the user enters.
# Explicitly does NOT imply `optiga-lock-operational`: every OID stays
# at `LcsO=Creation` so metadata remains mutable for further dev
# iteration. Use `make wipe-for-wizard`.
wipe-for-wizard = ["dual-se", "optiga-hw-counter", "dev-testkey", "ui-lcd", "gpio-buttons"]
# One-shot diagnostic: at the top of `main()`, fire `pin_diag::run()`
# (a 6-pulse train on PA4/PD5/PE0/PE4/PE5/PB6 with distinct widths)
# and halt. Used to identify which STM32 pin is electrically wired to
# the Arduino D6 header on the B-U585I-IOT02A — the target of the
# OPTIGA RST move off D5 (which cross-couples into SE050 ENA on the
# stacked OM-SE050ARD shield). No secrets, no provisioning, no
# destructive flash writes. Use `make pin-diag-boot-hw`.
pin-diag-boot = ["stm32u585", "optiga-trust-m"]
# Tier 1 of work-todo #7 (three-tier key hierarchy). Compiles
# `secure/src/hw/saes.rs` — the STM32U585 Secure AES coprocessor driver
# with AES-256 ECB primitives under KEYSEL={Software, DHUK, BHK, DHUK^BHK}.
# OFF by default: landing the driver under its own gate lets us bench-test
# it on silicon before `hw::secret_keys::derive_into` flips over to
# `SAES-CMAC(DHUK, label)` (that's task #31). Pure-additive — does not
# change any existing call site.
saes-dhuk = ["stm32u585"]
# Boot-time SAES self-test runner. Under this feature, `main()` runs
# `hw::saes::init` + `hw::saes::self_test` right after the RNG/TRNG
# init and halts with PASS/FAIL on the semihosting console via the
# existing `secure_log!` macro (which requires `debug-log`). Used to
# validate the Tier-1 driver on real silicon before flipping any
# derivation call sites. Results appear only when the target is paired
# with `debug-log` at the make-target level (see `saes-self-test-hw`).
# Use `make saes-self-test-hw`.
saes-self-test = ["saes-dhuk"]
# Boot-time ML-KEM inner-wrap self-test: round-trips a dummy half through
# `pq_wrap::{seal_half_hw, open_half_hw}` (the real HUK-derived keypair +
# TRNG) and logs PASS/FAIL via `secure_log!`. OFF by default — it is what
# pulls ml-kem into the image, so production builds that don't yet wire the
# wrap pay zero size/CT cost. Validates the HUK binding + measures the
# ml-kem flash delta before the provision/reconstruct rewiring lands.
mlkem-self-test = []
# Route the dual-SE provision/reconstruct through the ML-KEM hybrid inner wrap
# (#28 piece 2b-2): each entropy half is sealed before it crosses I²C — the SE
# stores the 32-byte AES-GCM ciphertext (unchanged object size), the 1568-byte
# ML-KEM ct + 16-byte tag live in MCU flash. OFF by default (the validated
# direct-half flow is the default); turning it on is the migration. See
# `docs/security/ml-kem-inner-wrap.md`.
mlkem-inner-wrap = []
# Render-only golden-screenshot harness (#21): a FAST ui-golden gate. At boot,
# renders a curated set of display screens through the production renderers +
# captures [UI-FP] fingerprints, then halts — no C10 keygen/sign (which makes
# the e2e-based `ui-golden` too slow on QEMU software SHA-256). Implies
# `ui-capture` (the fingerprint emitter). Dev-only.
ui-golden-render = ["ui-capture", "erc7730-dev-unattested"]

# Masked-SHA-256 overhead bench (work-todo §18 SHAKE-vs-SHA2 #2
# measurement). Runs once at boot, DWT-times the masked gates +
# HASH-peripheral / sha2 baselines, prints the projected masked-block
# slowdown, then SYS_EXITs. Pairs with hw-sha256 (implied by stm32u585)
# so the HASH-peripheral baseline is real. Use `make bench-masked-sha-hw`.
bench-masked-sha = ["stm32u585", "dep:masked-sha2"]
# F-24 stage E Phase 1 — hardware flicker validation harness for the
# decoy-mnemonic-frame defense. Short-circuits `main()` into a forever-
# loop that renders page 0 of a fixed test mnemonic interleaved with
# 4 fixed decoys at the production 5:1 (200ms:40ms) cadence. No wizard,
# no buttons, no SE access — just OLED rendering. Use `make decoy-
# flicker-hw` to flash a board and stare at the screen to validate
# whether the cadence is visually readable. NEVER ship.
decoy-flicker-test = []
# F-24 stage E Phase 1 — enable decoy-mnemonic-frame rendering in the
# production seed-wizard's show_mnemonic flow. Default OFF: the wizard
# shows the real mnemonic on a stable display so the user can write it
# down. Default ON would only make sense on a display whose pixel
# response time is long enough that briefly-painted decoy frames don't
# fully appear before being overwritten by the next real frame (LCD
# with Tr+Tf > decoy-hold-MS). On bistable displays like the SSD1306
# OLED, decoy frames are FULLY visible and the user sees N+1 mnemonics
# cycling — breaks the wizard UX. Gate this feature on once the
# hardware supports subliminal decoys; bench-validate via the
# `decoy-flicker-test` feature on the same display first.
decoy-frames = []
# SPI LCD backend (ZT165M017AT — 142×428 TFT with NV3007 driver IC).
# Implies `spi1-arduino` because the LCD wiring on B-U585I-IOT02A
# reuses the Arduino-header SPI1 pins: PE12 CS, PE13 SCK, PE15 MOSI.
# DC and RES are additional GPIOs on PE3 + PE1 (configurable in
# `secure/src/hw/lcd_nv3007.rs`). The driver primitives sit in
# `hw::lcd_nv3007`; Display-trait integration is a separate Phase C
# follow-up. The only shipping display backend (the OLED backend was
# removed 2026-06-30 — only the NV3007 LCD is used).
ui-lcd = ["spi1-arduino", "gpio-buttons", "dep:embedded-graphics"]
# Phase-B LCD bring-up: short-circuits `main()` into `lcd_nv3007::lcd_test_loop`
# (green→red→blue fill loop) to validate the NV3007 wiring + init sequence on
# real silicon. Pulls in `ui-lcd` (→ `spi1-arduino`). Build via `make lcd-test-hw`.
lcd-test = ["ui-lcd"]
# `aw99703-ovp-low` and `aw99703-full-brightness` were #705 bench experiments,
# REMOVED 2026-09-23 once they had answered their question. Owner decision: keep
# the shipping OVP at `OVPSEL=001` and the shipping brightness at 0x5FF. Both
# are recoverable from git (`27f38683`, `0a7ceef4`) if the ODM envelope ever
# reopens the question; the measurements they produced are recorded on #705.
# Animated splash-screen preview. Short-circuits `main()` into
# `ui::splash_test::run`, which ports the three `assets/splash-1{6,7,8}-*.html`
# revisions (hyperspace / horizon / nebula) to no_std and cycles them on the
# NV3007 LCD ~12 s each, forever. Pulls in `ui-lcd` (→ `spi1-arduino` +
# `gpio-buttons`) and `micromath` (fast f32 sin/cos/sqrt/powf for the
# animations). Build + flash via `make splash-test-hw`.
splash-test = ["ui-lcd", "dep:micromath"]
# Quarantined legacy factory-provisioning feature. The retained state machine
# documents the rejected provision-then-wipe design, but every STM32U585 build
# with this feature fails `FW_ROLLBACK_FACTORY_BLOCKED` before compilation.
# No factory, flash, OTP, or RDP action is authorized. Historically it:
#
#   1. validates hardware (SAES self-test, BHK lifecycle, OTP master);
#   2. provisions OPTIGA + SE050 infrastructure (PBS, SCP03, admin
#      UserID, F1Dx metadata) via the production `WalletStore::
#      provision` path with deterministic-zero user state;
#   3. immediately wipes the dummy user state via `factory_reset_admin`,
#      leaving SE infrastructure intact for the end-user wizard to
#      fill in later;
#   4. cross-validates the resulting chip looks "factory ready"
#      (admin functional, no user residue);
#   5. halts on a "FACTORY OK — POWER OFF" panel.
#
# On any failure, the LCD would show a numbered step + error code that
# the factory operator can read off the screen and report back. See
# `docs/provisioning/factory-provisioning.md` for the operator manual + error
# code table.
#
# Implies: `dual-se` (both SEs required), `stm32u585` (real
# silicon — no QEMU path), `ui-lcd` (operator needs visual status).
# Mutually exclusive with `e2e-test` (which bypasses real
# provisioning) at the production-fence level.
factory-provisioning = ["dual-se", "stm32u585", "ui-lcd"]
# Legacy rehearsal mode for `factory-provisioning`. It rendered all panels on
# the LCD while skipping the destructive SE calls, but still consumed the
# broken receipt QW. The host treats every value as non-authoritative, and all
# factory profiles are now build-blocked.
# Retained only so historical source/tests remain parseable.
factory-provisioning-rehearsal = ["factory-provisioning"]
# Historical foot-gun acknowledgement. It no longer overrides the rollback
# quarantine: `factory-provisioning` is rejected for every STM32U585 build.
factory-production-irreversible-im-sure = []
# Factory production-line test firmware. Replaces the wizard / unlock
# path with a USB-command server the factory fixture drives to verify
# each hardware component (OLED render, SAES Tier-1, BHK Tier-2, TRNG
# entropy, flash R/W, STM32 UID readout) before flashing the
# factory_provisioning firmware. See `docs/provisioning/factory-prodtest.md`.
#
# Implies: `dual-se` (need both SEs alive for the communication
# tests in Phase C), `stm32u585` (real silicon target), `ui-oled`
# (visual status), `usb` (the command channel).
#
# Mutually exclusive with `factory-provisioning` at the build-target
# level: prodtest runs FIRST in the factory line; factory_provisioning
# runs AFTER a chip passes prodtest. Each is a separate flash cycle.
#
# Same opt-in fence as factory-provisioning for irreversible
# production features (`optiga-lock-operational`, real OTP burn,
# `bhk` without hardcoded key) — prodtest builds default to
# `dev-testkey` for bring-up safety.
prodtest = ["dual-se", "stm32u585", "ui-lcd", "usb", "gpio-buttons"]
# Minimal USART1 → ST-LINK-VCP driver for diagnostic output that
# survives RDP ≥ 1 (where SWD debug — and therefore semihosting — is
# disabled). Pairs with `saes-self-test` for the RDP1 DHUK fingerprint
# capture: the target flashes at RDP0, programs RDP=0xBB, the chip
# re-runs the self-test at RDP1 with the real per-die DHUK, and the
# 8-byte fingerprint is captured over the ST-LINK's USB virtual-COM-
# port (which is an ST-LINK MCU feature independent of target RDP).
# Pure-additive; no effect when inactive. NEVER ship — production
# boards go up to RDP2 and have no debug UART. Implies `stm32u585`.
# Use alongside `make saes-self-test-hw-rdp1` +
# `make saes-self-test-hw-rdp0-regress`.
uart-console = ["stm32u585"]
# Early-boot GPIO bisection diagnostic. Compiles `secure/src/hw/boot_pulse.rs`
# which toggles PE4 (Arduino D5 on the B-U585I-IOT02A — empirically
# verified pin map, see project memory
# `reference_b_u585i_iot02a_arduino_header_mapping.md`) at seven call
# sites in `main()` — N short pulses for stage N. The only diagnostic
# that survives the RDP ≥ 1 + TZEN=1 + no-OEM-keys combo where neither
# SWD halt nor USART output works. Wire an LA1010 channel to D5 +
# GND; a captured trace tells us exactly which boot stage hangs.
# NEVER ship — registered in the production-build `compile_error!`
# fence. Implies `stm32u585`.
boot-pulse = ["stm32u585"]
# `sca-trigger` — compile-time-gated GPIO toggle around security-critical
# primitives (`c10_sign_verified*`, `hw::saes_cmac::cmac_dhuk`,
# `nsc::gated_unlock`). Lets a ChipWhisperer / NewAE Scaffold / crowbar rig
# sync trace captures to the exact instruction we want to analyse. NEVER
# ship — registered in the production-build `compile_error!` fence in
# `secure/src/nsc/mod.rs`. The GPIO pin choice + bank pre-config is in
# `hw::sca_trigger`; rises high on entry to a guarded primitive and falls
# low on exit. Implies `stm32u585` because the trigger pin is a real GPIO.
sca-trigger = ["stm32u585"]
optiga-reset-oids = ["optiga-trust-m"]  # RETIRED evidence-only feature. Unconditionally compile-fenced: it mis-targets the observed type-0x12 E0E3 device-certificate object as a type-0x11 anchor. No runnable profile may enable it.
optiga-no-shield = []  # Dev mode: skip Shielded Connection (PRL) entirely — no setup_pbs_no_handshake, no ensure_shield, no encrypted I2C. PIN HMAC + entropy read/write still work via plaintext APDUs. Use when E140 is unreachable (current bricked test chip). NOT production-safe. See docs/secure-elements/optiga-brick-postmortem.md §7.
optiga-lock-operational = []  # Controlled irreversible-validation primitive for non-E140 OPTIGA object locks (F1D0..F1D4 + F1E1) and separately gated S-2 experiments. Irreversible per OPTIGA SRM §"Life Cycle Status" — LcsO is monotonic, no reverse path exists. Ordinary `pair_for_first_boot` / `setup_pbs_no_handshake` NEVER ratchets E140, even when this feature is present. Work-todo #36 fixes the E140 actor as factory-side but leaves exact timing/order relative to the first-field final PBS rotation OPEN; the E140 ratchet primitive remains intentionally unwired. This feature grants no production authority and is unconditionally incompatible with prodtest. Enable only under an exact owner-authorized sacrificial plan until a reviewed lifecycle flow exists. See docs/archive/production-todo-retired-2026-07-19.md and docs/secure-elements/optiga-brick-postmortem.md §5 + §7.
# Dev/bring-up ONLY: swap the STM32U585 OTP-stored device master key for a
# compile-time fixed 32-byte constant. Lets us exercise the whole hw/otp.rs
# + hw/secret_keys.rs + OPTIGA pairing-secret derivation pipeline on bench
# boards without burning real OTP (OTP is one-way; a mistake costs the
# board). The test pattern is plain ASCII ("PQSIGNER-TEST-OTP-MASTER-DNS-
# v1!") so it cannot be confused for a real key. Guarded against production
# via a compile_error! in secure/src/main.rs that fires unless debug-log or
# e2e-test is also enabled. NEVER ship — a device built with this feature
# shares its pairing secret with every other device built with this feature,
# which would let a logic-analyzer snoop decrypt the Shielded Connection
# across every unit.
otp-hardcoded-master-key = ["legacy-fw-rollback-unsafe", "erc7730-dev-unattested"]
# Tier-2 phase 2A dev fallback: replace the silicon BHK with a compile-
# time fixed 32-byte ASCII test constant ("PQSIGNER-TEST-BHK-DHUK-WRAP-
# v1!!"). Lets us exercise the `secret_keys::derive_into_bhk` path +
# any future BHK callers on bench boards before phase-2B silicon work
# (TRNG burn → DHUK-ECB wrap → flash write → TAMP load + SECCFGR
# lock) lands. Distinct constant from `otp-hardcoded-master-key` so a
# device with both flags has independent (non-equal) DHUK-path and
# BHK-path derivations — preserving the defense-in-depth shape even
# under dev. Like `otp-hardcoded-master-key`: NEVER ship; registered
# in the production-build `compile_error!` fence. Pure-additive (no
# silicon side effects).
bhk-hardcoded-master-key = []
# Tier-2 phase 2B candidate-hardware gate: switch `secret_keys::derive_into_bhk`
# from the dev hardcoded fallback (HKDF over a compile-time constant)
# to the real silicon path — `kdf_cmac_counter_generic` driven by
# `KeySel::Bhk`. Requires `saes-dhuk` (Tier 1) AND the silicon-side
# BHK provisioning + boot-load + TAMP-lock infrastructure that phase
# 2B will land. This deterministic root helper is not the still-open
# fresh-TRNG production-final credential protocol. OFF until that
# infrastructure exists; turning it on
# in a build that hasn't run phase-2B provisioning would produce
# stable-but-zero-keyed derivations on most STM32U5 silicon (BHK
# backup registers are zero at reset).
bhk = ["saes-dhuk"]
# work-todo #36: on the FIRST field boot, self-lock the MCU to RDP Level 2 and
# rotate the SE pairing secrets off the factory-installed *transport* keysets
# to final BHK-/salted-DHUK-rooted secrets, before the seed wizard. Devices
# ship at RDP-0 (batch-uniform, user-verifiable over SWD before first power);
# this feature owns the on-device half. It pulls in `bhk` (the Tier-2 axis the
# rotation provisions) — hence `saes-dhuk` transitively. The RDP burn is
# IRREVERSIBLE, so this must NEVER be in a dev/QEMU/bench image: the
# `nsc/mod.rs` ship fence forces it on for `mode-production` ONLY, and
# incompat fences keep it out of every test/dev feature. Absent from every
# current build target; behaviour with it OFF is byte-identical to today.
rdp2-self-lock = ["bhk"]
# Under `e2e-test`, halt the boot flow right after `provision_from_mnemonic`
# returns, before the ordinary unlock/PRL handshake. Used for the Phase-A
# hardware-validation target (`flash-hw-optiga-bringup-write-only`) to prove
# the PBS write without proceeding into the rest of the session. Ordinary
# unlock does not ratchet E140; that irreversible factory-side step remains
# unwired and OPEN.
# Only meaningful in combination with `e2e-test`.
e2e-skip-unlock = []
# Under `e2e-test`, skip the `crypto::provision_from_mnemonic` call. Used when
# the OPTIGA chip is already provisioned from a prior run and its protected
# user-OID metadata has been locked at LcsO=op — re-running `store_objects` would fail
# on the first `set_metadata` APDU because the target OID is already frozen.
# With this feature set, we jump straight to `SE.unlock(pin)` which triggers
# the PRL handshake against the existing PBS + PIN secret on the chip. Only
# meaningful in combination with `e2e-test`.
e2e-skip-provision = []
# Under `e2e-test`, route the SE050 `WalletStore::provision` impl through the
# simpler single-policy path (the one already used on non-stm32u585 targets).
# Skips `provision_admin` + `policy_roundtrip_selftest` + the two-entry
# `TAG_POLICY` with admin-delete references. Used by the dual-SE hardware e2e
# target (`e2e-hw-dual-se`) so the test does not depend on mutable chip state
# around `ADMIN_WIPE_OBJ` — which can get stuck across firmware revisions
# when the on-chip admin UserID was created by a previous build whose admin
# PIN is no longer in flash (unauthenticated `iterative_wipe` can't delete
# policy-gated objects). Must NOT be enabled for `dual-se-admin-wipe-e2e` —
# that test's whole point is to exercise the admin-wipe install.
# Only meaningful in combination with `e2e-test` + `se050` (or `dual-se`).
e2e-skip-admin-wipe = []
dual-se = ["optiga-trust-m", "se050"]  # Both SEs active: XOR-split entropy across OPTIGA Trust M + SE050
# Use per-device DERIVED SCP03 static keys (secret_keys::se050_scp03_{enc,mac,dek}_key,
# BHK-rooted in a `bhk` build) instead of the published AN12436 factory constants.
# `establish()` probes the derived set first; if that fails the card-cryptogram check it
# can fall back to the published factory keys — but ONLY when `se050-scp03-allow-factory-
# fallback` is ALSO set (see below). Reversible: just code + this flag, no chip writes.
# Necessary for the current deterministic transport-key path, but not
# production-final or sufficient for shipment. The selected shipping model
# requires a fresh-TRNG per-device final rotation plus crash-safe durable public
# state and recovery; that protocol is still OPEN. The existing irreversible
# deterministic PUT KEY mechanism is `se050-rotate-scp03` and is bench/factory
# evidence only. See work-todo #20 and docs/archive/production-todo-retired-2026-07-19.md.
se050-derived-scp03 = ["se050"]
# Permit `establish()` to fall back to the PUBLISHED AN12436 factory SCP03 keys when the
# derived-key handshake fails. This is needed ONLY by the provisioning/rotation tool
# firmware (§29) — it must open a factory-key session to send GP PUT KEY against a chip
# that still holds NXP defaults. The runtime-signing SHIP build talks exclusively to an
# already-rotated deterministic-transport chip, so it MUST omit this flag and
# FAIL CLOSED instead of silently downgrading to attacker-known factory keys (a
# fail-OPEN). This is a necessary current guard, not production-final pairing
# closure. ENFORCED at compile time:
# this flag is in the hardware-release `compile_error!` fence in nsc/mod.rs (alongside
# debug-log / se050-rotate-scp03), so a `stm32u585 + !debug_assertions` image that is not
# an explicit `e2e-test` / `dev-testkey` test build cannot enable it. Nonsensical without
# `se050-derived-scp03` → second compile_error in scp03.rs.
se050-scp03-allow-factory-fallback = ["se050-derived-scp03"]
# IRREVERSIBLE per chip — existing one-shot GP PUT KEY evidence path that
# replaces SCP03 keyset 0x0B in place with deterministic derived transport
# keys, then halts. This is not the required fresh-TRNG production-final
# rotation. NEVER ship; sacrificial bench/factory validation only; never flash
# to a board that still moves RDP around (the RDP1↔RDP0 dance mass-erases
# the BHK page → dead SE050). The PUT KEY APDU framing is best-effort from GP 2.3 / AN12436
# and MUST be validated on sacrificial parts before any real provisioning run. Listed in the
# `compile_error!` fence in nsc/mod.rs. See work-todo #20 Stage B + docs/archive/production-todo-retired-2026-07-19.md.
# Rotation inherently runs against a still-factory chip, so it MUST be able to
# open a factory-key session → pulls in the fallback. (This is enabling it, not
# the forbidden rotate⊕fallback compile_error: the rotation tool legitimately
# needs the fallback; only the runtime-signing image must omit it.)
se050-rotate-scp03 = ["se050-derived-scp03", "se050-scp03-allow-factory-fallback"]
# Which SE050 VARIANT is fitted, and therefore which published factory SCP03
# keyset `scp03_logic::PLATFORM_*` must present. OFF = SE050E2 / OEF `0xA921`
# (the default, because every board we physically have is an E2: the
# `AL_A66_MB_V10` pq1 board per its schematic, and the OM-SE050ARD-E bench
# shield). ON = SE050C2 / OEF `0xA201` (`SE050C2HQ1/Z01SDZ`).
#
# Getting this wrong is NOT subtle and NOT dangerous — it fails closed with
# `[SCP03] Card cryptogram MISMATCH` on every `establish()`, because the static
# keys simply don't match the chip. It is, however, easy to misdiagnose: the
# `admin_factory_reset` recovery path needs SCP03 too, so a wrong keyset locks
# the door and the key in the same motion (observed on pq1 silicon 2026-09-17,
# 11 consecutive mismatches ending in a provisioning panic).
#
# Only affects builds that use the PUBLISHED keys, i.e. those WITHOUT
# `se050-derived-scp03`: every bench HW target (`se050-stress`,
# `pin-gate-hw-*`, any `e2e-test` image). Shipping builds derive per-device
# keys and are unaffected by this flag — EXCEPT the rotation tooling
# (`se050-rotate-scp03`), which must open a factory-key session against a
# still-factory chip and therefore must name the correct part.
#
# A C2 on a plain OM-SE050ARD dev kit is a third case: it presents the separate
# A375 "Development Board" keyset (ENC `35C25645…`), which is not encoded here.
se050-part-c2 = []
se050-factory-reset = ["se050"]  # Wipe all SE050 objects on boot, then halt. Use `make se050-reset`.
se050-reset-e2e = ["se050"]  # Self-contained factory-reset roundtrip test. Use `make se050-reset-e2e`.
se050-admin-wipe-e2e = ["se050"]  # Admin-auth wipe roundtrip test on isolated OID range. Use `make se050-admin-wipe-e2e`.
# Negative security test: prove the admin PIN CANNOT read user-PIN-gated
# secrets (only delete them). Provisions a sentinel under user-PIN gating
# with admin-DELETE in the policy, then asserts admin-auth READ is refused
# while admin-auth DELETE succeeds. PASS = chip enforced read deny.
# Falsifies the load-bearing claim that the two-entry TAG_POLICY is
# silicon-enforced rather than driver-enforced. Use `make se050-admin-extract-attempt-e2e`.
se050-admin-extract-attempt-e2e = ["se050"]
# OPTIGA Trust M admin-wipe e2e: provision → unlock → factory_reset →
# verify sentinel + NotProvisioned. Exercises the `factory_reset` primitive
# NOT the PIN-lockout→wipe integration (that's a separate deferred test).
# Uses real production OIDs (F1D0..F1D4 + F1E1) so running this destroys
# any wallet state on the chip. Deliberately does NOT imply
# `optiga-lock-operational` — the test runs entirely in LcsO=Creation on
# dev bench chips and will NOT ratchet any OID to Operational. Use
# `make optiga-admin-wipe-e2e`.
optiga-admin-wipe-e2e = ["optiga-trust-m"]
# Minimal "nuclear" OPTIGA wipe: no provision-first dance, no shielded
# connection, no OTP/PBS dependency. Relaxes F1E1's Change AC via
# set_metadata (always mutable at LcsO=Creation), then writes
# RESET_SENTINEL to F1E1 via plaintext set_data_object. Used by
# `make optiga-factory-reset-hw` as the recovery path for boards where
# the shielded-connection primitives can't run (e.g. OTP programming
# blocked by chip product state). Requires `optiga-no-shield` so the
# internal apdu helpers traverse plaintext. Use `make optiga-factory-
# reset-hw`.
optiga-nuclear-reset = ["optiga-trust-m", "optiga-no-shield"]
# Dev escape hatch: allow an interactive STM32U585 release build that
# bypasses OTP programming via `otp-hardcoded-master-key` WITHOUT
# enabling `e2e-test` (which would replace the interactive wizard
# with an auto-provision fast-path). Used on bench boards where the
# specific STM32U585 can't program user OTP (see the "STM32 OTP
# master-key burn" pre-production-validation note in
# `docs/archive/production-todo-retired-2026-07-19.md`) but the developer still wants to
# exercise the real first-boot wizard + PIN entry + standalone
# unlock flow. Only meaningful alongside `otp-hardcoded-master-key`.
# Like `otp-hardcoded-master-key`, makes the PBS a compile-time
# constant shared across every dev board built with the feature — a
# logic-analyzer snoop on any such board recovers the pairing secret
# of every other. NEVER enter production with this feature enabled.
# Paired Makefile target: `flash-hw-optiga-oled-standalone-testkey`.
dev-testkey = ["otp-hardcoded-master-key"]
# Dual-SE (OPTIGA + SE050) unlock e2e: pre-clean → provision both halves
# → unlock + XOR-reconstruct master_secret → verify. Exercises
# `DualSecureElement::provision` + `DualSecureElement::unlock` on real
# silicon; the XOR reconstruction is the unique dual-SE value-add not
# covered by either single-SE test. Does NOT test
# `factory_reset_admin` — that integration path is deferred to a
# factory-only target that requires a fresh SE050 (an admin UserID
# whose PIN has drifted out of sync with page-125 flash cannot be
# wiped without admin auth, which is a real production guarantee but
# also means this test on a contaminated bench chip is not meaningful).
# DESTROYS wallet state on BOTH chips (pre-clean wipes before
# re-provisioning under test credentials). Deliberately does NOT
# imply `optiga-lock-operational` — no LcsO advance on OPTIGA; SE050
# has no LcsO concept. Uses current production object ranges on both
# chips (OPTIGA F1D0..F1D4 + F1E1; SE050 0x7B0E_xxxx — v5). Use
# `make dual-se-admin-wipe-e2e`.
dual-se-admin-wipe-e2e = ["dual-se"]
# Multi-unlock / cross-reboot validation. First boot: provision both
# chips with a fixed test mnemonic+PIN, do N unlocks in a row (each one
# re-reads both halves from NVM and re-XORs), verify every reconstruction
# matches the expected master_secret. Subsequent boots: detect already-
# provisioned state, skip provisioning, do N unlocks again. Paired with
# a Makefile target that invokes `probe-rs run` 3× to force 3 cold
# reboots through the same firmware image, proving SE050 NVM survives
# the full provisioning pulse sequence and stays stable across reboots
# — the exact scenario where the old PE4→ENA cross-coupling corrupted
# ENTROPY_OBJ. Use `make dual-se-multi-unlock-e2e`.
dual-se-multi-unlock-e2e = ["dual-se"]
# Direct test of the MCU-side PIN attempt counter (page 124) + the
# `nsc::gated_unlock` pre-commit pattern. Hardcoded right/wrong PINs
# + semihosting PASS/FAIL output; no buttons or PIN UI needed.
# Exercises what the interactive unlock path would — counter
# bump on wrong PIN, counter reset on correct PIN, return-code
# correctness. It does not enable the OPTIGA E120 hardware counter and does
# not exercise boot reconciliation. Use `make pin-gate-e2e`.
pin-gate-e2e = ["dual-se"]
se050-crash-safety-e2e = ["se050"]  # 2-phase test: partial wipe + reset + resume. Use `make se050-crash-safety-e2e`.
# On-silicon SE050 stress-test harness. Catalog-driven runner that boots
# the secure world, runs every registered `stress_test!` against the real
# SE050 (no `mock-se`), and reports PASS/FAIL via `secure_log!` semihosting.
# Adding a new test is one function + one macro invocation in
# `secure/src/se050_stress/tests/*.rs` — no Cargo, main.rs, or Makefile
# edits per test. Stress-test OIDs live in carve-out range `0x7B5F_*`,
# never touch the v6 production range `0x7B10_*`. Use `make se050-stress`
# (Safe tier) / `make se050-stress-destructive` (incl. counter-burning
# tests) / `make se050-stress-only-<name>` (single test) / `make
# se050-stress-list` (host-side catalog).
se050-stress = ["se050"]
spi1-arduino = []  # Use SPI1/PE12-PE15 (Arduino R3 headers) instead of SPI2/PB12-PB15 (NV3007 LCD wiring)
stsafe-probe = ["stm32u585", "mock-se"]  # I2C2 bus scan to detect on-board STSAFE-A110
gpio-buttons = ["stm32u585"]  # GPIO button driver: PI2 (LEFT) + PA15 (RIGHT) on CN14
button-test = ["stm32u585", "mock-se", "gpio-buttons"]  # Flash + run GPIO button test

# ERC-7730 dev provenance warning. This does NOT relax an on-device
# attestation verifier: there is no classical/ERC-8176 verifier in firmware.
# Dbgen records the exact root's provenance in generated `db_roots.rs`; its
# generated compile fences require this feature for a dev-unattested root and
# forbid that root under `mode-production`. When enabled, the trusted display
# adds the "DEV: unattested descriptor" warning page. Canonical Make-driven dev
# builds derive the feature from `secure/data/erc7730.review.txt`; the canonical
# never-ship dev modes above also select it. Other direct Cargo builds must
# select it explicitly when the generated root requires it.
#
# NEVER ship — the dedicated `mode-production` fence in `nsc/mod.rs`, the
# generated root-provenance fence, and `make prod-erc7730-provenance-check`
# all reject it. The rollback quarantine remains independently visible through
# `make prod-check-ship`. Unlike
# secret-leaking debug features, it remains valid on explicitly dev/bring-up
# hardware because that is where the warning is required.
erc7730-dev-unattested = ["pqsigner-erc7730/erc7730-dev-unattested"]
# Compile-time-only synthetic nested-calldata policy row for host/QEMU E2E.
# Default builds keep zero production admissions; mode-production is fenced in
# `nsc/mod.rs` even if this feature is selected directly.
erc7730-nested-calldata-test-fixture = [
    "pqsigner-erc7730/nested-calldata-test-fixture",
    "dbgen/nested-calldata-test-fixture",
]
# Positive, default-off authority for the separately reviewed forced-blind
# ceremony. This flag never aliases from a dev/test mode. The production
# C1 binds the exact P73K artifact; C2 adds the production configuration,
# verified tick/deadline, and trusted-UI/state substrates; C3 alone wires the
# signing handler. Declaring it here does not itself enable signing behavior.
erc7730-forced-blind = []

[build-dependencies]
# Decodes the vendored `assets/font_5x8.png` (embedded-graphics' FONT_5X8
# bitmap) into a flat `[[u8; 5]; 96]` table baked into `OUT_DIR/font_flat.rs`.
# Consumed by `secure/src/ui/secret_text.rs` for the F-24 constant-time
# glyph blit. Build-script only; not linked into the firmware.
png = "0.17"
# Used by `generate_vendor_pubkey` to embed `VENDOR_PK_{SEED,ROOT,FPR}`
# into the secure image at build time. Mirrors `fsbl/build.rs`; both
# must produce identical bytes from the same `FSBL_VENDOR_PUBKEY`
# env var so the secure firmware's BEGIN-time signature check and
# FSBL's boot-time check agree on the trusted vendor.
#
# NOTE: build.rs does NOT pull in sphincs-c10 — cargo's feature
# unification across target and host deps would propagate
# `hw-sha256` (enabled on the target build) into the host build
# script, which then fails to link against the secure-side
# `pqsigner_sha256_*` externs. Instead build.rs requires the caller
# to supply a precomputed 32-byte pubkey file via FSBL_VENDOR_PUBKEY;
# `make dev-pubkey-fixture` generates one for dev builds.
# Also pins the NS-resident pixel-UI atlas: `validate_ui_px_assets`
# recomputes sha256(nonsecure/assets/ui-px/atlas.pq1a) and refuses a stale
# `src/ui/px/atlas_root.rs`.
sha2        = "0.10"

[dev-dependencies]
hex = { workspace = true }
# Property-based testing for host-side parser fuzzing. Runs under
# `cargo test -p sphincs-tz-secure --tests` on host builds only
# (std-backed, not compiled into the no_std firmware). Every parser
# that consumes NS-world bytes (APDU headers, trailer chunks, RLP
# envelopes, ERC-20 / name bundles) must never panic, deadlock, or
# buffer-overrun on arbitrary input. proptest generates random byte
# strings to cover the edge cases a hand-written test suite misses.
#
# This is PQSigner's answer to Trezor's `crypto/fuzzer/` libFuzzer
# harnesses — see `docs/architecture/trezor-comparison.md §2.4`. Proptest is
# ~80% of the value of cargo-fuzz with zero Cargo.toml refactoring
# (cargo-fuzz needs a `[lib]` target which `sphincs-tz-secure`
# currently lacks). Coverage-guided libFuzzer is a follow-up.
proptest = "1"

# Host-side ERC-7730 catalogue compiler. Used by the host renderer
# round-trip tests in `secure/src/display_under_test/erc7730_render_pure_tests.rs`
# to compile the checked-in seed-corpus JSON into the byte-identical IR
# the firmware would see on-wire, so the renderer is exercised against
# real descriptors rather than hand-rolled IR fixtures. Host-only by
# construction (`dbgen` pulls in `serde_json` / `toml` / `std::fs`) and
# never reaches the no_std firmware binary.
dbgen = { path = "../dbgen" }

```
