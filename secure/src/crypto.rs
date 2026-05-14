//! Crypto helpers — secure-side wrapper around [`pqsigner_domain`].
//!
//! The pure-logic primitives (KDFs, AES-GCM wrap/unwrap, BIP-39 ↔
//! SPHINCS+C10 derivation, slot-key derivation, PIN-state encoding) live
//! in [`pqsigner_domain`] so host-side reference signers can reuse them
//! without the secure-world hardware deps.
//!
//! What stays here:
//!
//! * [`c10_sign_verified`] / [`c10_sign_verified_with_progress`] — the
//!   FI-hardened verify-before-release wrapper. Depends on
//!   [`crate::fi`], whose hardening primitives are keyed off the
//!   secure-world TRNG.
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
    let sig = sk.sign_with_progress(msg_hash, None, progress);
    // Verify before release (fault-injection guard).
    //
    // The boolean check is wrapped by `fi::check_true` so a glitch that
    // skips the `if` requires cooperating skips of the double-evaluation
    // AND the hamming-distant sentinel compare. `wait_random()` immediately
    // before the verify defeats clock-aligned fault bursts that time their
    // glitch to the verify's fixed-shape control flow.
    //
    // `core::hint::black_box(v)` is load-bearing: without it LLVM CSEs the
    // two `cond()` evaluations inside `check_true` into a single load of `v`
    // and collapses the `&& v1 && v2` re-check, leaving one skippable branch
    // — `tools/sca/fault_sweep_c10_verify.py` (finding F-1) showed a single
    // instruction-skip then releases an unverified signature. The black_box
    // forces `v` to be re-materialised opaquely on each evaluation, so the
    // double-check survives, at ~zero cost (one extra `ldrb` per check).
    // (The even-stronger option — re-running `sphincs_c10::verify(...)` inside
    // the closure, per `fi::check_true`'s doc example — also defends a data
    // fault on `v`'s storage, at the cost of a second multi-second verify.)
    crate::fi::wait_random();
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig);
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(v)) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(sig)
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
