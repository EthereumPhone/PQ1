//! Crypto helpers — secure-side wrapper around `pqsigner-domain`.
//!
//! Phase 5 PR 5.3 of the modularity refactor moved every pure-logic
//! helper (KDFs, AES-GCM wrap/unwrap, BIP-39 → SPHINCS+C10 derivation,
//! slot-key derivation, PIN-state encoding) into the standalone
//! `pqsigner-domain` crate so the same code can power host-side
//! reference signers and any future `fwsign verify-release --simulate`
//! tool.
//!
//! What stays here:
//!
//! * [`c10_sign_verified`] / [`c10_sign_verified_with_progress`] — the
//!   FI-hardened verify-before-release wrapper. Depends on
//!   `crate::fi::{wait_random, check_true}`, which are CPU-glitch
//!   countermeasures keyed off the secure-world TRNG.
//! * [`provision_from_mnemonic`] / [`store_macd_encrypted`] — the
//!   `WalletStore` + `SecureElement` provisioning entry points used by
//!   the wizard and by the mock/Tropic01 backends. They depend on the
//!   secure-side `crate::secure_element::*` traits which themselves
//!   pull in hardware r-mem semantics, so they don't belong in the
//!   pure-logic crate.
//!
//! Every other public name in `pqsigner-domain` is re-exported below
//! so existing call sites (`crate::crypto::derive_c10_master_*`,
//! `crate::crypto::encrypt_entropy_blob`, `crate::crypto::kdf`, ...)
//! compile unchanged.

pub use pqsigner_domain::*;

use crate::secure_element::SecureElement;
use sphincs_tz_bip39::Mnemonic;
use zeroize::Zeroize;

/// Sign a 32-byte message hash with the bootstrap C10 signing key and the
/// (optional) randomiser. Wraps `sphincs_c10::SigningKey::sign` with a
/// verify-before-release fault-injection guard.
///
/// Produces 4008-byte C10 signatures — see `sphincs-c10/src/params.rs`.
pub fn c10_sign_verified(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    c10_sign_verified_with_progress(sk, msg_hash, |_| {})
}

/// Like [`c10_sign_verified`] but reports 0..100 signing progress via the
/// supplied callback so the trusted-UI progress bar stays responsive
/// during the multi-second C10 signature.
pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: fn(u8),
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    use subtle::ConstantTimeEq;

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
    let sig_a = sk.sign_with_progress(msg_hash, opt_rand, progress);
    crate::fi::wait_random();
    let sig_b = sk.sign_with_progress(msg_hash, opt_rand, |_| {});

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
        return Err(());
    }

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
        return Err(());
    }
    opt_rand_buf.zeroize();
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
    master_secret.zeroize();
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
