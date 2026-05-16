//! Positive + negative tests for the SPHINCS+C10 signature path of
//! `fw-manifest`.
//!
//! Designed as a single integration-test binary so the multi-second
//! `SigningKey::keygen` only runs ONCE — every test borrows shared
//! keys from a `OnceLock`. Without this discipline, a 10-test file
//! would do 10 keygens × ~1 s each in release mode.

use fw_manifest::{
    compute_signed_digest, crc32_ieee, vendor_pubkey_fingerprint, ManifestBuilder, ManifestRef,
    VerifyError, OFF_CRC32, OFF_MANIFEST_DIGEST, OFF_SIGNATURE, SIGNATURE_LEN, SLOT_A,
};
use sphincs_c10::{params::N, SigningKey};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Shared fixtures — keygen runs at most once per integration-test binary
// ---------------------------------------------------------------------------

const SK_SEED_A: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const PK_SEED_A: [u8; N] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

const SK_SEED_B: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];
const PK_SEED_B: [u8; N] = [
    0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0xaa, 0xaa,
];

fn sk_a() -> &'static SigningKey {
    static SK: OnceLock<SigningKey> = OnceLock::new();
    SK.get_or_init(|| SigningKey::keygen(SK_SEED_A, PK_SEED_A))
}

fn sk_b() -> &'static SigningKey {
    static SK: OnceLock<SigningKey> = OnceLock::new();
    SK.get_or_init(|| SigningKey::keygen(SK_SEED_B, PK_SEED_B))
}

/// Build a fully-finalized signed manifest using vendor key A. Returns
/// `(bytes, digest)` so tests can pivot the digest without rebuilding.
fn signed_manifest_with(key: &SigningKey, fw_version: u32) -> ([u8; 8192], [u8; 32]) {
    let fpr = vendor_pubkey_fingerprint(key.pk_seed(), key.pk_root());
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(fw_version)
        .secure_image(&[0xAA; 32], 0x100)
        .nonsecure_image(&[0xBB; 32], 0x200)
        .vendor_pubkey_fpr(&fpr)
        .build_id(&[0xDE; 32]);
    let digest = b.finalize_preimage();
    let sig = key.sign(&digest, None);
    b.set_signature(&sig);
    (b.finalize(), digest)
}

fn rewrite_crc(bytes: &mut [u8]) {
    let crc = crc32_ieee(&bytes[..OFF_CRC32]);
    bytes[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&crc.to_be_bytes());
}

// ===========================================================================
// POSITIVE: full chain (structural + CRC + digest + vendor fpr + signature)
// ===========================================================================

#[test]
fn positive_full_verifier_chain_accepts_freshly_signed_manifest() {
    let key = sk_a();
    let (bytes, _digest) = signed_manifest_with(key, 100);
    let m = ManifestRef::new(&bytes);
    m.verify_structural().unwrap();
    m.verify_crc().unwrap();
    m.verify_digest().unwrap();
    m.verify_vendor_fpr(key.pk_seed(), key.pk_root()).unwrap();
    m.verify_signature(key.pk_seed(), key.pk_root()).unwrap();
    m.verify_rollback(50).unwrap();
}

#[test]
fn positive_signature_verifies_for_multiple_versions_under_same_key() {
    let key = sk_a();
    for v in [1u32, 100, 0x1234_5678] {
        let (bytes, _) = signed_manifest_with(key, v);
        ManifestRef::new(&bytes)
            .verify_signature(key.pk_seed(), key.pk_root())
            .unwrap();
    }
}

#[test]
fn positive_signature_byte_stable_across_rebuilds() {
    // Given fixed inputs, the manifest bytes (including the C10 sig
    // produced with opt_rand = None) are byte-deterministic. This is
    // what lets fwsign produce a release whose hash auditors can
    // reproduce.
    let key = sk_a();
    let (a, _) = signed_manifest_with(key, 7);
    let (b, _) = signed_manifest_with(key, 7);
    assert_eq!(a, b);
}

// ===========================================================================
// NEGATIVE: every attack the on-chain verifier (and FSBL) must refuse
// ===========================================================================

#[test]
fn negative_verify_signature_rejects_wrong_vendor_key() {
    // Most fundamental: a signature produced by key A must not verify
    // under key B's public material. This is the entire point of the
    // FSBL-compiled vendor pubkey — if this assertion held, anyone
    // could ship arbitrary firmware.
    let key_a = sk_a();
    let key_b = sk_b();
    let (bytes, _) = signed_manifest_with(key_a, 7);
    assert_eq!(
        ManifestRef::new(&bytes).verify_signature(key_b.pk_seed(), key_b.pk_root()),
        Err(VerifyError::BadSignature),
        "C10 signature by vendor A must not verify under vendor B",
    );
}

#[test]
fn negative_verify_signature_rejects_zeroed_signature() {
    // An attacker who can write to the signature region (e.g. by
    // forging a `.pqfw` envelope) MUST not be accepted after zeroing
    // the sig. The C10 verifier must refuse the all-zero forgery.
    let key = sk_a();
    let (mut bytes, _) = signed_manifest_with(key, 7);
    bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN].fill(0);
    rewrite_crc(&mut bytes);
    assert_eq!(
        ManifestRef::new(&bytes).verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
    );
}

#[test]
fn negative_verify_signature_rejects_all_ones_signature() {
    let key = sk_a();
    let (mut bytes, _) = signed_manifest_with(key, 7);
    bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN].fill(0xFF);
    rewrite_crc(&mut bytes);
    assert_eq!(
        ManifestRef::new(&bytes).verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
    );
}

#[test]
fn negative_verify_signature_rejects_single_byte_tamper() {
    // C10's hash-tree structure means most single-byte tampers in the
    // signature surface as a verify failure. Cover three positions:
    // start (FORS region), middle (hypertree layer 0), end (last
    // hypertree authentication node).
    let key = sk_a();
    let (base, _) = signed_manifest_with(key, 7);

    for sig_byte_off in [0usize, 1500, SIGNATURE_LEN - 1] {
        let mut bytes = base;
        bytes[OFF_SIGNATURE + sig_byte_off] ^= 0x01;
        rewrite_crc(&mut bytes);
        assert_eq!(
            ManifestRef::new(&bytes).verify_signature(key.pk_seed(), key.pk_root()),
            Err(VerifyError::BadSignature),
            "single-bit tamper at signature offset {sig_byte_off} must trip verify",
        );
    }
}

#[test]
fn negative_verify_signature_rejects_signature_for_different_digest() {
    // Build manifest M1 (digest D1, sig S1 = sign(D1)). Build manifest
    // M2 (digest D2). Splice S1 into M2's signature region. Since
    // verify_signature uses M2's stored manifest_digest, S1 will be
    // checked against D2 ≠ D1 → BadSignature.
    let key = sk_a();
    let (m1_bytes, d1) = signed_manifest_with(key, 7);
    let (mut m2_bytes, d2) = signed_manifest_with(key, 8);
    assert_ne!(d1, d2);

    // Copy M1's signature into M2 (overwriting M2's own sig).
    let m1_sig = &m1_bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN];
    m2_bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(m1_sig);
    rewrite_crc(&mut m2_bytes);

    let m2 = ManifestRef::new(&m2_bytes);
    // verify_digest still passes (M2's digest field matches its
    // version+hashes), but verify_signature fails (S1 doesn't sign D2).
    m2.verify_digest().unwrap();
    assert_eq!(
        m2.verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
        "signature cross-pollination (sign(D1) in manifest with digest D2) must fail",
    );
}

#[test]
fn negative_verify_signature_rejects_manifest_digest_swap() {
    // Inverse of the previous attack: keep the signature, overwrite
    // the stored manifest_digest with an unrelated value (e.g. all
    // zeros). C10 verifies sig against the stored digest, which is
    // now the attacker's choice. Must fail.
    let key = sk_a();
    let (mut bytes, original_digest) = signed_manifest_with(key, 7);
    bytes[OFF_MANIFEST_DIGEST..OFF_MANIFEST_DIGEST + 32].fill(0);
    rewrite_crc(&mut bytes);

    let m = ManifestRef::new(&bytes);
    assert_ne!(m.manifest_digest(), &original_digest);
    assert_eq!(
        m.verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
    );
}

#[test]
fn negative_verify_signature_rejects_signature_under_swapped_seed_root() {
    // Even within the same vendor's key material, swapping pk_seed and
    // pk_root must fail — they have distinct roles in the WOTS+/FORS
    // hash chains and are not interchangeable.
    let key = sk_a();
    let (bytes, _) = signed_manifest_with(key, 7);
    let m = ManifestRef::new(&bytes);
    assert_eq!(
        m.verify_signature(key.pk_root(), key.pk_seed()),
        Err(VerifyError::BadSignature),
        "swapping pk_seed and pk_root must fail — they're not interchangeable in C10",
    );
}

#[test]
fn negative_verify_signature_rejects_after_tampered_signed_field_and_digest_repaired() {
    // The "smart attacker" flow: tamper a signed field (e.g. fw_version
    // to a higher value), recompute the manifest_digest so verify_digest
    // passes, recompute the CRC so verify_crc passes — but the
    // signature still binds the ORIGINAL digest. C10 verify must catch.
    let key = sk_a();
    let (mut bytes, _) = signed_manifest_with(key, 7);

    // Bump fw_version 7 → 99.
    bytes[fw_manifest::OFF_FW_VERSION..fw_manifest::OFF_FW_VERSION + 4]
        .copy_from_slice(&99u32.to_be_bytes());

    // Recompute the in-buffer manifest_digest to match the tampered
    // preimage.
    let new_digest = compute_signed_digest(99, &[0xAA; 32], &[0xBB; 32]);
    bytes[OFF_MANIFEST_DIGEST..OFF_MANIFEST_DIGEST + 32].copy_from_slice(&new_digest);
    rewrite_crc(&mut bytes);

    let m = ManifestRef::new(&bytes);
    m.verify_crc().unwrap();
    m.verify_digest().unwrap();
    assert_eq!(
        m.verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
        "tampering fw_version then patching digest+CRC must still fail signature verify — \
         otherwise an attacker could roll forward any signed release to any version",
    );
}

#[test]
fn negative_verify_vendor_fpr_blocks_wrong_key_before_signature_verify() {
    // The FSBL verify chain is: structural → CRC → digest → vendor fpr
    // → signature. The vendor-fpr check is the cheap fast-reject. If it
    // passes erroneously under a wrong key, we waste the expensive C10
    // verify; if it fails when it should pass, no release ever boots.
    let key_a = sk_a();
    let key_b = sk_b();
    let (bytes, _) = signed_manifest_with(key_a, 7);

    // Wrong key fails vendor fpr.
    assert_eq!(
        ManifestRef::new(&bytes).verify_vendor_fpr(key_b.pk_seed(), key_b.pk_root()),
        Err(VerifyError::WrongVendor),
    );
    // Right key passes.
    ManifestRef::new(&bytes)
        .verify_vendor_fpr(key_a.pk_seed(), key_a.pk_root())
        .unwrap();
}

#[test]
fn negative_attacker_swap_signature_between_versions_blocked() {
    // Sign two versions (v=7 and v=99) with the SAME vendor key. Take
    // the v=99 signature and try to install it into the v=7 manifest.
    // Result: stored manifest_digest now refers to v=7, but sig binds
    // v=99 → BadSignature. This is the rollback / replay attack the
    // signed-version binding exists to prevent.
    let key = sk_a();
    let (mut v7_bytes, _) = signed_manifest_with(key, 7);
    let (v99_bytes, _) = signed_manifest_with(key, 99);

    v7_bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN]
        .copy_from_slice(&v99_bytes[OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE_LEN]);
    rewrite_crc(&mut v7_bytes);

    let m = ManifestRef::new(&v7_bytes);
    m.verify_digest().unwrap();
    assert_eq!(
        m.verify_signature(key.pk_seed(), key.pk_root()),
        Err(VerifyError::BadSignature),
        "splicing a v=99 signature into a v=7 manifest must fail — version is signed",
    );
}
