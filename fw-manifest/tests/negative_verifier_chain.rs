//! Negative tests against the verifier chain — digest, CRC over signed
//! vs unsigned fields, vendor fingerprint, and rollback floor.
//!
//! The wallet's release-signing model says:
//!
//!   * `secure_hash`, `nonsecure_hash`, `fw_version`, and `DOMAIN_TAG`
//!     are signed.  Tampering them must fail `verify_digest` (and then
//!     also `verify_signature`, if the digest was repaired).
//!   * `vendor_pubkey_fpr`, `build_id`, `slot`, `secure_len`,
//!     `nonsecure_len`, `boot_counter_snap`, `try_once_flag` are
//!     unsigned. Tampering them must NOT change the signed digest, but
//!     MUST trip the CRC if the CRC isn't repaired.
//!
//! These tests fix each property in turn.

use fw_manifest::{
    compute_signed_digest, crc32_ieee, vendor_pubkey_fingerprint, ManifestBuilder, ManifestRef,
    VerifyError, DOMAIN_TAG, OFF_BOOT_CTR_SNAP, OFF_BUILD_ID, OFF_CRC32, OFF_FW_VERSION,
    OFF_MANIFEST_DIGEST, OFF_NONSECURE_HASH, OFF_NONSECURE_LEN, OFF_SECURE_HASH, OFF_SECURE_LEN,
    OFF_SIGNATURE, OFF_TRY_ONCE, OFF_VENDOR_FPR, SIGNATURE_LEN, SLOT_A,
};
use sha2::{Digest, Sha256};

fn baseline() -> ManifestBuilder {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(0x1000)
        .secure_image(&[0xAA; 32], 0x100)
        .nonsecure_image(&[0xBB; 32], 0x200)
        .vendor_pubkey_fpr(&[0x33; 32])
        .build_id(&[0x44; 32])
        .boot_counter_snap(7);
    b.finalize_preimage();
    b.set_signature(&[0x55; SIGNATURE_LEN]);
    b
}

fn rewrite_crc(bytes: &mut [u8]) {
    let crc = crc32_ieee(&bytes[..OFF_CRC32]);
    bytes[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&crc.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Domain-tag separation
// ---------------------------------------------------------------------------

#[test]
fn negative_signed_digest_includes_domain_tag() {
    // Without the domain tag, a SPHINCS+C10 signature over any
    // 32-byte hash could be repurposed as a firmware-release signature.
    // Confirm the wallet's actual digest is NOT equal to the digest
    // someone would naively compute without the tag.
    let v = 1u32;
    let sh = [0xAA; 32];
    let nh = [0xBB; 32];

    let with_tag = compute_signed_digest(v, &sh, &nh);
    let without_tag: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(v.to_be_bytes());
        h.update(sh);
        h.update(nh);
        h.finalize().into()
    };
    assert_ne!(
        with_tag, without_tag,
        "missing DOMAIN_TAG must change the digest — otherwise a UserOp sig over the same \
         32-byte hash could be replayed as a firmware-release signature"
    );

    // Sanity: the *with-tag* digest IS what you'd compute when you
    // include the tag.
    let with_tag_explicit: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(DOMAIN_TAG);
        h.update(v.to_be_bytes());
        h.update(sh);
        h.update(nh);
        h.finalize().into()
    };
    assert_eq!(with_tag, with_tag_explicit);
}

#[test]
fn negative_signed_digest_binds_version_strictly() {
    let sh = [0xAA; 32];
    let nh = [0xBB; 32];
    // Off-by-one in version must produce a different digest — prevents
    // replay of an old signature with a higher version claim.
    assert_ne!(
        compute_signed_digest(1, &sh, &nh),
        compute_signed_digest(2, &sh, &nh),
    );
    // Far-apart versions must also differ.
    assert_ne!(
        compute_signed_digest(0, &sh, &nh),
        compute_signed_digest(u32::MAX, &sh, &nh),
    );
}

#[test]
fn negative_signed_digest_binds_image_hashes() {
    let v = 1u32;
    // Bit-flip in secure_hash → different digest.
    let mut sh = [0u8; 32];
    sh[0] = 0x01;
    assert_ne!(
        compute_signed_digest(v, &[0; 32], &[0; 32]),
        compute_signed_digest(v, &sh, &[0; 32]),
    );
    // Bit-flip in nonsecure_hash → different digest.
    assert_ne!(
        compute_signed_digest(v, &[0; 32], &[0; 32]),
        compute_signed_digest(v, &[0; 32], &sh),
    );
}

#[test]
fn negative_signed_digest_binds_image_hash_order() {
    // Swapping secure_hash and nonsecure_hash MUST produce a different
    // digest. An attacker who can swap the two binaries (e.g. by
    // tampering the .pqfw envelope) must not get away with a verifiable
    // signature.
    let v = 1u32;
    let a = [0xAA; 32];
    let b = [0xBB; 32];
    assert_ne!(
        compute_signed_digest(v, &a, &b),
        compute_signed_digest(v, &b, &a),
    );
}

// ---------------------------------------------------------------------------
// Tamper detection on signed fields → BadDigest after CRC repair
// ---------------------------------------------------------------------------

#[test]
fn negative_tampered_fw_version_then_crc_repaired_gives_bad_digest() {
    let mut bytes = baseline().finalize();
    bytes[OFF_FW_VERSION] ^= 0x01;
    rewrite_crc(&mut bytes);

    let m = ManifestRef::new(&bytes);
    m.verify_crc().unwrap();
    assert_eq!(m.verify_digest(), Err(VerifyError::BadDigest));
}

#[test]
fn negative_tampered_secure_hash_then_crc_repaired_gives_bad_digest() {
    let mut bytes = baseline().finalize();
    bytes[OFF_SECURE_HASH] ^= 0xFF;
    rewrite_crc(&mut bytes);

    let m = ManifestRef::new(&bytes);
    m.verify_crc().unwrap();
    assert_eq!(m.verify_digest(), Err(VerifyError::BadDigest));
}

#[test]
fn negative_tampered_nonsecure_hash_then_crc_repaired_gives_bad_digest() {
    let mut bytes = baseline().finalize();
    bytes[OFF_NONSECURE_HASH + 31] ^= 0xFF;
    rewrite_crc(&mut bytes);

    let m = ManifestRef::new(&bytes);
    m.verify_crc().unwrap();
    assert_eq!(m.verify_digest(), Err(VerifyError::BadDigest));
}

#[test]
fn negative_corrupted_manifest_digest_field_gives_bad_digest() {
    // Direct tamper of the stored digest also fails verify_digest
    // (because recomputed digest != stored digest).
    let mut bytes = baseline().finalize();
    bytes[OFF_MANIFEST_DIGEST] ^= 0x80;
    rewrite_crc(&mut bytes);

    assert_eq!(
        ManifestRef::new(&bytes).verify_digest(),
        Err(VerifyError::BadDigest),
    );
}

// ---------------------------------------------------------------------------
// Unsigned fields: tamper produces BadCrc (not BadDigest), and tamper +
// CRC repair produces NO error from verify_digest — because the
// tampered field isn't covered by the signed preimage.
// ---------------------------------------------------------------------------

#[test]
fn negative_tampered_vendor_fpr_does_not_invalidate_digest_only_crc() {
    let mut bytes = baseline().finalize();
    bytes[OFF_VENDOR_FPR] ^= 0xFF;

    // CRC alone catches the tamper.
    assert_eq!(
        ManifestRef::new(&bytes).verify_crc(),
        Err(VerifyError::BadCrc),
    );

    // After CRC repair, verify_digest still passes — vendor_pubkey_fpr
    // is *unsigned* metadata. That's the documented design: a vendor
    // fingerprint mismatch is caught by verify_vendor_fpr, not
    // verify_digest.
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn negative_tampered_build_id_does_not_invalidate_digest() {
    let mut bytes = baseline().finalize();
    bytes[OFF_BUILD_ID + 5] ^= 0x80;
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn negative_tampered_secure_len_does_not_invalidate_digest() {
    // secure_len and nonsecure_len are informational only — verifier
    // doesn't bind them into the signed digest. Confirm so any future
    // change to "make them signed" must update both this test and the
    // CLAUDE.md documentation.
    let mut bytes = baseline().finalize();
    bytes[OFF_SECURE_LEN + 3] ^= 0xFF;
    bytes[OFF_NONSECURE_LEN + 3] ^= 0xFF;
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn negative_tampered_boot_counter_snap_does_not_invalidate_digest() {
    // Post-sign field; documented as not covered by the signature.
    let mut bytes = baseline().finalize();
    bytes[OFF_BOOT_CTR_SNAP] ^= 0x55;
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn negative_tampered_try_once_flag_does_not_invalidate_digest() {
    // Try-once flag is updated by the device after signing; it cannot
    // be part of the signature.
    let mut bytes = baseline().finalize();
    bytes[OFF_TRY_ONCE] ^= 0xFF;
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn negative_any_unsigned_field_tamper_without_crc_repair_fails_crc() {
    // Every unsigned metadata field tamper at least catches the CRC
    // (so the FSBL refuses the manifest even before realising the
    // tamper was 'unsigned' anyway). Iterate each documented unsigned
    // field offset.
    let unsigned_offsets = [
        OFF_VENDOR_FPR,
        OFF_BUILD_ID,
        OFF_SECURE_LEN,
        OFF_NONSECURE_LEN,
        OFF_BOOT_CTR_SNAP,
        OFF_TRY_ONCE,
    ];
    for off in unsigned_offsets {
        let mut bytes = baseline().finalize();
        bytes[off] ^= 0xFF;
        assert_eq!(
            ManifestRef::new(&bytes).verify_crc(),
            Err(VerifyError::BadCrc),
            "tamper of unsigned field at offset {off} must trip CRC",
        );
    }
}

// ---------------------------------------------------------------------------
// vendor_pubkey_fpr — fast-reject before SPHINCS+C10 verify
// ---------------------------------------------------------------------------

#[test]
fn negative_verify_vendor_fpr_rejects_wrong_seed() {
    let real_seed = [0xAA; 16];
    let real_root = [0xBB; 16];
    let fpr = vendor_pubkey_fingerprint(&real_seed, &real_root);

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(1).vendor_pubkey_fpr(&fpr);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();

    let mut wrong_seed = real_seed;
    wrong_seed[0] ^= 1;
    assert_eq!(
        ManifestRef::new(&bytes).verify_vendor_fpr(&wrong_seed, &real_root),
        Err(VerifyError::WrongVendor),
    );
}

#[test]
fn negative_verify_vendor_fpr_rejects_wrong_root() {
    let real_seed = [0xAA; 16];
    let real_root = [0xBB; 16];
    let fpr = vendor_pubkey_fingerprint(&real_seed, &real_root);

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(1).vendor_pubkey_fpr(&fpr);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();

    let mut wrong_root = real_root;
    wrong_root[15] ^= 1;
    assert_eq!(
        ManifestRef::new(&bytes).verify_vendor_fpr(&real_seed, &wrong_root),
        Err(VerifyError::WrongVendor),
    );
}

#[test]
fn negative_verify_vendor_fpr_rejects_zeroed_stored_fpr() {
    // A manifest with vendor_pubkey_fpr field = all zeros must be
    // rejected when compared against the real vendor key. An FSBL that
    // skipped this check could be tricked into running the C10 verify
    // against the attacker-supplied key embedded somewhere in the
    // signature region.
    let real_seed = [0xAA; 16];
    let real_root = [0xBB; 16];

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(1).vendor_pubkey_fpr(&[0u8; 32]);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();

    assert_eq!(
        ManifestRef::new(&bytes).verify_vendor_fpr(&real_seed, &real_root),
        Err(VerifyError::WrongVendor),
    );
}

// ---------------------------------------------------------------------------
// Rollback floor — strict greater-than
// ---------------------------------------------------------------------------

#[test]
fn negative_verify_rollback_rejects_equal_floor() {
    // CLAUDE.md: monotonic per-chain caps, "no reset path". For FW
    // version specifically the check must be strict `>` — a manifest
    // whose version equals the OTP floor must be REJECTED so that
    // re-flashing the same release twice doesn't bypass the rollback
    // guard.
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(5);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();

    assert_eq!(
        ManifestRef::new(&bytes).verify_rollback(5),
        Err(VerifyError::BelowRollback),
        "fw_version == rollback_floor must fail — check must be strict >",
    );
}

#[test]
fn negative_verify_rollback_rejects_lower_version() {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(2);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();
    assert_eq!(
        ManifestRef::new(&bytes).verify_rollback(3),
        Err(VerifyError::BelowRollback),
    );
}

#[test]
fn negative_verify_rollback_floor_u32_max_rejects_everything_finite() {
    // CLAUDE.md "No 'reset rollback floor' path. OTP is one-way by
    // design". A device whose OTP floor has reached u32::MAX must
    // reject every conceivable fw_version including u32::MAX itself
    // (because the check is strict >). The slot freezes forever.
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(u32::MAX);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();
    assert_eq!(
        ManifestRef::new(&bytes).verify_rollback(u32::MAX),
        Err(VerifyError::BelowRollback),
    );
}

#[test]
fn negative_verify_rollback_floor_zero_rejects_version_zero() {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(0);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();
    assert_eq!(
        ManifestRef::new(&bytes).verify_rollback(0),
        Err(VerifyError::BelowRollback),
    );
}

// ---------------------------------------------------------------------------
// CRC vs digest separation: tamper inside the signature region trips
// CRC but does not trip verify_digest (signature region is not part of
// the signed preimage; that's why we have a separate signature check).
// ---------------------------------------------------------------------------

#[test]
fn negative_tamper_inside_signature_region_trips_crc_not_digest() {
    let mut bytes = baseline().finalize();
    bytes[OFF_SIGNATURE + 1000] ^= 0xFF;

    let m = ManifestRef::new(&bytes);
    assert_eq!(m.verify_crc(), Err(VerifyError::BadCrc));

    // After CRC repair, digest still verifies — sig region isn't in
    // the signed preimage. The mismatch will surface later as
    // VerifyError::BadSignature.
    rewrite_crc(&mut bytes);
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

// ---------------------------------------------------------------------------
// VerifyError trait surface — must be Copy + Eq for FSBL match arms
// ---------------------------------------------------------------------------

#[test]
fn negative_verify_error_supports_copy_and_eq() {
    // FSBL pattern-matches on VerifyError in a tight no_std loop; the
    // enum must stay `Copy + Eq + Debug`. Removing any of these is a
    // breaking API change for FSBL boot-stage handlers.
    fn assert_copy_eq_debug<T: Copy + Eq + core::fmt::Debug>() {}
    assert_copy_eq_debug::<VerifyError>();
}
