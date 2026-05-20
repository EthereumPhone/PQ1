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
//!   the wizard and by the mock/Tropic01 backends. These touch the
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

pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: fn(u8),
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
    #[cfg(not(test))]
    crate::sign_rate::pre_sign()?;
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
    // `hw::rng_strong::fill` (STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG,
    // 3-source XOR mirroring Trezor's `rng_fill_buffer_strong`).
    // Defends against:
    //   - the deterministic-PRF-tree class (Genêt TCHES 2023): adding
    //     a fresh randomiser breaks the chain of repeated SK re-use
    //     across signatures.
    //   - any single biased / compromised TRNG: the XOR of the
    //     remaining unbroken sources preserves entropy.
    // The randomiser is drawn ONCE and fed to both signs — re-drawing
    // per sign would still be cryptographically sound but would
    // produce divergent sigs, breaking the byte-equality FI gate.
    //
    // Under `mock-se` (no SE backend) the strong-RNG falls through to
    // STM32 TRNG only. Under any real-SE feature flag the active
    // backend's `random()` is XOR-mixed in.
    let mut opt_rand_buf = [0u8; sphincs_c10::params::N];
    #[cfg(not(test))]
    if crate::rng_strong::fill(&mut opt_rand_buf).is_err() {
        return Err(());
    }
    let opt_rand: Option<&[u8; sphincs_c10::params::N]> = Some(&opt_rand_buf);
    cfi.bump(CFI_STEP_OPT_RAND);

    // **F-16 (DPA-defence) shuffle seed.** Drawn once per signing
    // call via `rng_strong::fill` (STM32 ⊕ OPTIGA ⊕ SE050 XOR-fold)
    // and fed UNCHANGED to both double-compute signs — re-drawing
    // per sign would still be cryptographically sound but would
    // produce different shuffle orders → divergent internal hash
    // streams → divergent register-level state during the
    // double-compute (sig outputs would still be byte-equal per
    // F-16's byte-equality oracle, but the F-13 ct_eq still holds).
    //
    // The shuffle seed randomises the COMPUTATION order of WOTS
    // chains (43! ≈ 10^52 per layer) and FORS trees (13! ≈ 6×10^9).
    // Profiled-DPA averaging relies on the same secret hash landing
    // at the same sample index across traces; the shuffle moves
    // chain-i's hashes to a random sample per signature, breaking
    // alignment. See `sphincs-c10/src/shuffle.rs` for the
    // correctness invariant (byte-identical output across any
    // shuffle seed).
    let mut shuffle_seed_buf = [0u8; 32];
    #[cfg(not(test))]
    if crate::rng_strong::fill(&mut shuffle_seed_buf).is_err() {
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    let shuffle = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_buf);
    // `[u8; 32]` is `Copy`, so the constructor above copied — wipe
    // the stack local now that the secret lives inside the
    // `ZeroizeOnDrop` wrapper.
    shuffle_seed_buf.zeroize();
    crate::fi::zeroize_barrier();
    cfi.bump(CFI_STEP_SHUFFLE);

    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle, progress);
    cfi.bump(CFI_STEP_SIGN_A);
    crate::fi::wait_random();
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle, |_| {});
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
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    cfi.bump(CFI_STEP_VERIFY_GATE);

    // F-18 final CFI check: every critical step bumped the counter
    // with its unique magic; the running total must match the
    // compile-time `CFI_EXPECTED`. A glitch that skipped any one
    // step's `bump` (or skipped the step itself, since the bump
    // follows it directly) leaves the counter short by exactly that
    // step's magic → fail closed. Routed through the F-2 Hamming-
    // distant sentinel idiom so a skip of the verify call itself
    // doesn't bypass.
    if cfi.check_into_sentinel(CFI_EXPECTED) != crate::fi::OK_SENTINEL {
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

    store
        .provision(&entropy, &master_secret, &vk_bytes, &bootstrap_vk, pin)
        .expect("provisioning failed");

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
    #[cfg(feature = "duress-pin")]
    provision_duress_wallet(store, duress_pin);

    #[cfg(not(feature = "duress-pin"))]
    let _ = duress_pin;
}

/// §32: generate + store an independent decoy wallet behind the duress
/// credential. See [`provision_from_mnemonic`] for the always-provision
/// rationale. Separate fn so the hot path stays readable and the decoy
/// generation is feature-gated in one place.
#[cfg(feature = "duress-pin")]
fn provision_duress_wallet(
    store: &mut impl crate::secure_element::WalletStore,
    duress_pin: Option<&[u8; 8]>,
) {
    // Fresh independent decoy entropy: STM32 TRNG XOR the SE-combined TRNG
    // (OPTIGA ⊕ SE050 via the store) — same multi-source quality as the
    // real seed path, no re-entrancy (we are not inside a store method).
    let mut decoy_entropy = [0u8; 32];
    crate::rng::fill(&mut decoy_entropy).expect("TRNG fill failed (decoy entropy)");
    let mut se_buf = [0u8; 32];
    if store.random(&mut se_buf).is_ok() {
        for i in 0..32 {
            decoy_entropy[i] ^= se_buf[i];
        }
    }
    se_buf.zeroize();

    // Resolve the duress PIN: user-chosen, or a fresh random 8 bytes when
    // declined (never entered by anyone → unguessable; the chip can't
    // distinguish a random-byte PIN from a digit PIN).
    let mut random_pin = [0u8; 8];
    let actual_duress_pin: [u8; 8] = match duress_pin {
        Some(p) => *p,
        None => {
            crate::rng::fill(&mut random_pin).expect("TRNG fill failed (decoy PIN)");
            random_pin
        }
    };

    let mut decoy_master: [u8; 32] = kdf(b"sphincs-master", &decoy_entropy, 0);
    let (sk, decoy_vk) = derive_keypair_from_entropy(&decoy_entropy);
    drop(sk);
    let decoy_bvk = derive_bootstrap_vk_from_entropy(&decoy_entropy);

    store
        .provision_duress(&decoy_entropy, &decoy_master, &decoy_vk, &decoy_bvk, &actual_duress_pin)
        .expect("duress provisioning failed");

    decoy_entropy.zeroize();
    crate::fi::zeroize_barrier();
    decoy_master.zeroize();
    crate::fi::zeroize_barrier();
    random_pin.zeroize();
}

/// Store pre-derived entropy, VK, and PIN state via the MACD chain on an
/// r-mem-capable secure element. Used by backends that support the
/// `SecureElement` trait (Mock, Tropic01 on the generic path).
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
