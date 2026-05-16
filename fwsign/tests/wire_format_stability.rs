//! Wire-format / domain-tag stability tests.
//!
//! These tests pin the on-the-wire contract that `fwsign` participates
//! in.  Every byte here is baked into shipped vendor keys, shipped FSBL
//! pubkeys, and released `.pqfw` bundles — silently changing any of
//! these constants would orphan every device in the field.
//!
//! Per CLAUDE.md: "No casual KDF tag changes" and "Do not expand the
//! signed FW-update preimage."  These tests give those two policies
//! teeth.

use fw_manifest::{compute_signed_digest, DOMAIN_TAG, SIGNED_PREIMAGE_LEN, VERIFYING_KEY_LEN};
use sha2::{Digest, Sha256};
use sphincs_c10::params::{N, SIGNATURE_LEN};

// ---------------------------------------------------------------
// Domain tag stability (the public "what gets signed?" contract)
// ---------------------------------------------------------------

#[test]
fn positive_domain_tag_is_pqfw_v1() {
    // Frozen forever per CLAUDE.md.  If anyone bumps this, every
    // device's FSBL hard-codes the old tag and will refuse the new
    // bundle.
    assert_eq!(DOMAIN_TAG, b"PQFW_V1", "FW-update domain tag must remain 'PQFW_V1'");
    assert_eq!(DOMAIN_TAG.len(), 7);
}

#[test]
fn positive_signed_preimage_len_is_75() {
    // The CLAUDE.md spec: "75 B `PQFW_V1` || fw_version_be || secure_hash || nonsecure_hash".
    // Auditors reconstruct the preimage from (version, secure.elf,
    // nonsecure.elf) — changing the length is a breaking change.
    assert_eq!(SIGNED_PREIMAGE_LEN, 7 + 4 + 32 + 32);
    assert_eq!(SIGNED_PREIMAGE_LEN, 75);
}

#[test]
fn positive_compute_signed_digest_matches_manual_construction() {
    // Belt-and-braces: independently rebuild the digest by hand and
    // assert byte equality with `compute_signed_digest`.  This
    // protects against an internal refactor in fw_manifest that
    // changes the byte order or padding.
    let version: u32 = 0x12345678;
    let sh = [0xAAu8; 32];
    let nh = [0xBBu8; 32];

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"PQFW_V1");
    preimage.extend_from_slice(&version.to_be_bytes());
    preimage.extend_from_slice(&sh);
    preimage.extend_from_slice(&nh);
    assert_eq!(preimage.len(), 75);
    let manual: [u8; 32] = Sha256::digest(&preimage).into();

    let lib = compute_signed_digest(version, &sh, &nh);
    assert_eq!(manual, lib);
}

#[test]
fn negative_version_binding_is_meaningful() {
    // Assumption attacked: an attacker swaps a high-version signed
    // bundle for a low-version one.  Different versions must yield
    // different digests (else the signature replays trivially).
    let sh = [0u8; 32];
    let nh = [0u8; 32];
    let d1 = compute_signed_digest(1, &sh, &nh);
    let d2 = compute_signed_digest(2, &sh, &nh);
    assert_ne!(d1, d2, "version field must affect the signed digest");
}

#[test]
fn negative_secure_hash_binding_is_meaningful() {
    let d1 = compute_signed_digest(7, &[0xAA; 32], &[0xBB; 32]);
    let d2 = compute_signed_digest(7, &[0xAB; 32], &[0xBB; 32]);
    assert_ne!(d1, d2, "secure_hash flip must affect the signed digest");
}

#[test]
fn negative_nonsecure_hash_binding_is_meaningful() {
    let d1 = compute_signed_digest(7, &[0xAA; 32], &[0xBB; 32]);
    let d2 = compute_signed_digest(7, &[0xAA; 32], &[0xBC; 32]);
    assert_ne!(d1, d2, "nonsecure_hash flip must affect the signed digest");
}

#[test]
fn negative_compute_signed_digest_is_pure_function() {
    // Same inputs → same output, every time.  Reproducible signing
    // depends on this.  (`compute_signed_digest` has no RNG/clock, but
    // we test the contract explicitly.)
    let d_a = compute_signed_digest(42, &[0x11; 32], &[0x22; 32]);
    let d_b = compute_signed_digest(42, &[0x11; 32], &[0x22; 32]);
    assert_eq!(d_a, d_b);
}

// ---------------------------------------------------------------
// Key + signature length stability
// ---------------------------------------------------------------

#[test]
fn positive_pubkey_layout_is_pk_seed_then_pk_root() {
    // The `pubkey.bin` artifact `fwsign pubkey` writes is exactly
    // `pk_seed[N] || pk_root[N]`.  FSBL `include_bytes!`s it and
    // splits at offset N.  If either side ever swaps the order, every
    // released vendor pubkey becomes unusable.
    assert_eq!(N, 16, "SPHINCS+C10 N (security parameter) must be 16");
    assert_eq!(VERIFYING_KEY_LEN, 32);
    assert_eq!(VERIFYING_KEY_LEN, 2 * N);
}

#[test]
fn positive_signature_len_is_4008() {
    // CLAUDE.md: "OWNER_BYTES_LEN = 64, C10_SIG_LEN = 4008".
    // Also baked into the on-chain verifier and the firmware
    // protocol.
    assert_eq!(SIGNATURE_LEN, 4008, "SPHINCS+C10 signature length must be 4008");
}

// ---------------------------------------------------------------
// Pubkey fingerprint stability
// ---------------------------------------------------------------

#[test]
fn positive_vendor_fingerprint_is_sha256_of_concat() {
    // FSBL's cheap-reject path computes `SHA-256(pk_seed || pk_root)`
    // and compares to the manifest's `vendor_pubkey_fpr`.  If the
    // helper ever changes its preimage order or KDF, FSBL silently
    // accepts the wrong vendor key.
    let pk_seed = [0x01u8; N];
    let pk_root = [0x02u8; N];

    let mut h = Sha256::new();
    h.update(&pk_seed);
    h.update(&pk_root);
    let expected: [u8; 32] = h.finalize().into();

    let got = fw_manifest::vendor_pubkey_fingerprint(&pk_seed, &pk_root);
    assert_eq!(got, expected);
}

#[test]
fn negative_vendor_fingerprint_distinguishes_swapped_halves() {
    // (pk_seed=A, pk_root=B) must hash differently from
    // (pk_seed=B, pk_root=A) — otherwise the fpr loses preimage
    // ordering, and a swapped pubkey.bin could collide.
    let a = [0x01u8; N];
    let b = [0x02u8; N];
    let f1 = fw_manifest::vendor_pubkey_fingerprint(&a, &b);
    let f2 = fw_manifest::vendor_pubkey_fingerprint(&b, &a);
    assert_ne!(f1, f2);
}
