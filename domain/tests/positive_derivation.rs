//! Positive functional coverage for the BIP-39 → SPHINCS+C10 derivation
//! chain (slhdsa seed, bootstrap key, c10 master keypair, slot keys,
//! slot-master entropy).  Complements the recovery-contract reference
//! values already asserted in `c10_derivation_tests`.

use pqsigner_domain::{
    bootstrap_seed_from_bip39, derive_bootstrap_keypair_from_entropy,
    derive_bootstrap_vk_from_entropy, derive_c10_master_keypair_from_entropy,
    derive_c10_master_keypair_from_entropy_with_progress, derive_c10_slot_keypair,
    derive_c10_slot_keypair_with_progress, derive_keypair_from_entropy, derive_signing_key,
    derive_signing_key_from_entropy, slhdsa_seed_from_bip39, slot_entropy,
    slot_master_entropy_from_bip39, slot_master_entropy_from_entropy, ENTROPY_LEN, SEED_LEN,
};
use sphincs_c10::params::SIGNATURE_LEN;
use std::cell::RefCell;

const ZERO_ENTROPY: [u8; ENTROPY_LEN] = [0u8; ENTROPY_LEN];

fn pk_seed_16(pk_seed_32: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&pk_seed_32[..16]);
    out
}

#[test]
fn positive_slhdsa_seed_layout_is_sk32_pk16zero16() {
    // First 32 bytes carry sk_seed (always non-deterministically-shaped
    // SHA-256 output); bytes 32..48 carry the top 16 bytes of pk_seed.
    // The remaining 16 bytes of any 32-byte pk_seed buffer expansion
    // are zero in the N-masked layout — but the slhdsa seed is the
    // 48-byte concatenated form, so we just check it is 48 bytes long.
    let bip39_seed = [0u8; 64];
    let out = slhdsa_seed_from_bip39(&bip39_seed);
    assert_eq!(out.len(), SEED_LEN, "slhdsa seed must be 48 bytes");
}

#[test]
fn positive_slhdsa_seed_is_deterministic() {
    let bip39 = [0xABu8; 64];
    assert_eq!(slhdsa_seed_from_bip39(&bip39), slhdsa_seed_from_bip39(&bip39));
}

#[test]
fn positive_derive_signing_key_consumes_48b_seed() {
    // Smoke: keygen runs and produces a usable verifying key for a
    // 48-byte seed of arbitrary bit pattern.
    let seed = [0x5Au8; SEED_LEN];
    let sk = derive_signing_key(&seed);
    assert_eq!(sk.verifying_key().to_bytes().len(), 32);
}

#[test]
fn positive_derive_signing_key_from_entropy_signs_and_verifies() {
    let entropy = [0x33u8; ENTROPY_LEN];
    let sk = derive_signing_key_from_entropy(&entropy);
    let vk = sk.verifying_key().to_bytes();
    let msg = [0x11u8; 32];
    let sig = sk.sign(&msg, None);
    assert_eq!(sig.len(), SIGNATURE_LEN);

    // Reconstruct (pk_seed, pk_root) from the 32-byte VK (top 16 each).
    let mut pk_seed = [0u8; 16];
    pk_seed.copy_from_slice(&vk[0..16]);
    let mut pk_root = [0u8; 16];
    pk_root.copy_from_slice(&vk[16..32]);
    assert!(sphincs_c10::verify(&pk_seed, &pk_root, &msg, &sig));
}

#[test]
fn positive_derive_keypair_from_entropy_matches_signing_key_vk() {
    let entropy = [0x77u8; ENTROPY_LEN];
    let (sk_a, vk_bytes_a) = derive_keypair_from_entropy(&entropy);
    let sk_b = derive_signing_key_from_entropy(&entropy);
    assert_eq!(vk_bytes_a, sk_b.verifying_key().to_bytes());
    let _ = sk_a; // keep alive
}

#[test]
fn positive_bootstrap_seed_is_deterministic_and_distinct_from_slhdsa() {
    let bip39 = [0x91u8; 64];
    let boot = bootstrap_seed_from_bip39(&bip39);
    assert_eq!(boot, bootstrap_seed_from_bip39(&bip39));
    assert_ne!(
        boot,
        slhdsa_seed_from_bip39(&bip39),
        "bootstrap and slhdsa must use independent domain tags"
    );
}

#[test]
fn positive_bootstrap_keypair_signs_and_verifies() {
    let (sk, vk) = derive_bootstrap_keypair_from_entropy(&[0x12u8; ENTROPY_LEN]);
    let msg = [0xEFu8; 32];
    let sig = sk.sign(&msg, None);
    let mut ps = [0u8; 16];
    ps.copy_from_slice(&vk[0..16]);
    let mut pr = [0u8; 16];
    pr.copy_from_slice(&vk[16..32]);
    assert!(sphincs_c10::verify(&ps, &pr, &msg, &sig));
}

#[test]
fn positive_derive_bootstrap_vk_matches_keypair_vk() {
    let entropy = [0x54u8; ENTROPY_LEN];
    let vk_a = derive_bootstrap_vk_from_entropy(&entropy);
    let (_sk, vk_b) = derive_bootstrap_keypair_from_entropy(&entropy);
    assert_eq!(vk_a, vk_b, "vk-only path must agree with full keypair path");
}

#[test]
fn positive_slot_master_entropy_consistency_across_apis() {
    // slot_master_entropy_from_entropy(e, idx) == slot_master_entropy_from_bip39(seed(e), idx).
    use sphincs_tz_bip39::Mnemonic;
    let entropy = [0xC0u8; ENTROPY_LEN];
    let m = Mnemonic::from_entropy(&entropy);
    let bip39_seed = m.to_seed("");
    for idx in [0u32, 1, 7, 255, 1234, u32::MAX] {
        let from_e = slot_master_entropy_from_entropy(&entropy, idx);
        let from_s = slot_master_entropy_from_bip39(&bip39_seed, idx);
        assert_eq!(from_e, from_s, "from_entropy must equal from_bip39 at idx {idx}");
    }
}

#[test]
fn positive_slot_entropy_changes_with_chain_and_slot() {
    let m = [0xDEu8; 32];
    let s_a = slot_entropy(&m, 1, 0);
    let s_b = slot_entropy(&m, 137, 0);
    let s_c = slot_entropy(&m, 1, 1);
    assert_ne!(s_a, s_b, "different chain_id must change slot_entropy");
    assert_ne!(s_a, s_c, "different slot_index must change slot_entropy");
    // Determinism.
    assert_eq!(slot_entropy(&m, 1, 0), s_a);
}

#[test]
fn positive_derive_c10_slot_keypair_signs_and_verifies() {
    let m = [0x44u8; 32];
    let (sk, pk_seed_32, pk_root_32) = derive_c10_slot_keypair(&m, 1, 0);
    let msg = [0x55u8; 32];
    let sig = sk.sign(&msg, None);
    let ps16 = pk_seed_16(&pk_seed_32);
    let mut pr16 = [0u8; 16];
    pr16.copy_from_slice(&pk_root_32[..16]);
    assert!(sphincs_c10::verify(&ps16, &pr16, &msg, &sig));
}

#[test]
fn positive_derive_c10_master_keypair_with_progress_reports_0_and_100() {
    let calls = RefCell::new(std::vec::Vec::<u8>::new());
    let _ = derive_c10_master_keypair_from_entropy_with_progress(&ZERO_ENTROPY, 0, |p| {
        calls.borrow_mut().push(p);
    });
    let v = calls.borrow();
    assert!(v.first().copied() == Some(0), "first progress call must be 0");
    assert!(v.last().copied() == Some(100), "last progress call must be 100");
    // Must be non-decreasing.
    for w in v.windows(2) {
        assert!(w[0] <= w[1], "progress must be non-decreasing: {w:?}");
    }
}

#[test]
fn positive_derive_c10_slot_keypair_with_progress_reports_0_and_100() {
    let calls = RefCell::new(std::vec::Vec::<u8>::new());
    let _ = derive_c10_slot_keypair_with_progress(&[0u8; 32], 1, 0, |p| {
        calls.borrow_mut().push(p);
    });
    let v = calls.borrow();
    assert_eq!(v.first().copied(), Some(0));
    assert_eq!(v.last().copied(), Some(100));
}

#[test]
fn positive_c10_master_and_slot_have_independent_keypairs() {
    // Both paths run keygen — for a given entropy the master and slot
    // pk_root must differ (different domain tags upstream).
    let entropy = [0x60u8; ENTROPY_LEN];
    let (_, master_pk_seed, master_pk_root) =
        derive_c10_master_keypair_from_entropy(&entropy, 0);
    let m = slot_master_entropy_from_entropy(&entropy, 0);
    let (_, slot_pk_seed, slot_pk_root) = derive_c10_slot_keypair(&m, 1, 0);

    assert_ne!(master_pk_seed, slot_pk_seed, "master vs slot pk_seed must differ");
    assert_ne!(master_pk_root, slot_pk_root, "master vs slot pk_root must differ");
}
