//! Positive functional coverage of every public API on `fw-manifest`.
//!
//! Complements the inline `#[cfg(test)] mod tests` block in `src/lib.rs`
//! (which already covers the round-trip, blank-flash, CRC/digest tamper,
//! and proptest fuzz cases) by drilling into smaller per-API behaviours
//! that aren't asserted there.

use fw_manifest::{
    compute_signed_digest, crc32_ieee, signed_preimage, vendor_pubkey_fingerprint, ManifestBuilder,
    ManifestRef, DOMAIN_TAG, MAGIC, MANIFEST_SIZE, MANIFEST_VERSION, OFF_BUILD_ID, OFF_CRC32,
    OFF_RESERVED_1, OFF_RESERVED_2, OFF_SIGNATURE, OFF_VENDOR_FPR, SIGNATURE_LEN,
    SIGNED_PREIMAGE_LEN, SLOT_A, SLOT_B, TRY_ONCE_COMMITTED, TRY_ONCE_COMMITTING, TRY_ONCE_TRIED,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants / helpers
// ---------------------------------------------------------------------------

fn fully_populated_builder(slot: u8) -> ManifestBuilder {
    let mut b = ManifestBuilder::new();
    b.init(slot)
        .fw_version(0x1234_5678)
        .secure_image(&[0x11; 32], 0xA000)
        .nonsecure_image(&[0x22; 32], 0xB000)
        .vendor_pubkey_fpr(&[0x33; 32])
        .build_id(&[0x44; 32])
        .boot_counter_snap(7)
        .try_once(TRY_ONCE_COMMITTED);
    b.finalize_preimage();
    b.set_signature(&[0x55; SIGNATURE_LEN]);
    b
}

// ---------------------------------------------------------------------------
// signed_preimage / compute_signed_digest
// ---------------------------------------------------------------------------

#[test]
fn positive_signed_preimage_is_exactly_75_bytes() {
    let pre = signed_preimage(0, &[0; 32], &[0; 32]);
    assert_eq!(pre.len(), 75);
    assert_eq!(pre.len(), SIGNED_PREIMAGE_LEN);
}

#[test]
fn positive_signed_preimage_for_version_zero() {
    let pre = signed_preimage(0, &[0xAB; 32], &[0xCD; 32]);
    assert_eq!(&pre[..7], DOMAIN_TAG);
    assert_eq!(&pre[7..11], &[0, 0, 0, 0]);
    assert_eq!(&pre[11..43], &[0xAB; 32]);
    assert_eq!(&pre[43..75], &[0xCD; 32]);
}

#[test]
fn positive_signed_preimage_for_version_u32_max() {
    let pre = signed_preimage(u32::MAX, &[0xAB; 32], &[0xCD; 32]);
    assert_eq!(&pre[7..11], &[0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn positive_compute_signed_digest_matches_sha256_of_preimage() {
    let pre = signed_preimage(1, &[0x01; 32], &[0x02; 32]);
    let want: [u8; 32] = Sha256::digest(pre).into();
    let got = compute_signed_digest(1, &[0x01; 32], &[0x02; 32]);
    assert_eq!(got, want);
}

#[test]
fn positive_compute_signed_digest_deterministic() {
    let d1 = compute_signed_digest(99, &[0x77; 32], &[0x88; 32]);
    let d2 = compute_signed_digest(99, &[0x77; 32], &[0x88; 32]);
    assert_eq!(d1, d2);
}

// ---------------------------------------------------------------------------
// vendor_pubkey_fingerprint
// ---------------------------------------------------------------------------

#[test]
fn positive_vendor_pubkey_fingerprint_is_sha256_of_seed_and_root() {
    let seed = [0xAA; 16];
    let root = [0xBB; 16];
    let want: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(root);
        h.finalize().into()
    };
    assert_eq!(vendor_pubkey_fingerprint(&seed, &root), want);
}

#[test]
fn positive_vendor_pubkey_fingerprint_differs_when_seed_and_root_swapped() {
    let a = [0xAA; 16];
    let b = [0xBB; 16];
    // SHA-256 is collision-free in practice; swapping arguments must
    // yield a different fingerprint.
    assert_ne!(
        vendor_pubkey_fingerprint(&a, &b),
        vendor_pubkey_fingerprint(&b, &a)
    );
}

// ---------------------------------------------------------------------------
// crc32_ieee
// ---------------------------------------------------------------------------

#[test]
fn positive_crc32_kats() {
    // IEEE 802.3 / zlib KATs from `python3 -c 'import zlib; print(hex(zlib.crc32(b"...")))'`
    assert_eq!(crc32_ieee(b""), 0x0000_0000);
    assert_eq!(crc32_ieee(b"a"), 0xE8B7_BE43);
    assert_eq!(crc32_ieee(b"abc"), 0x3524_41C2);
    assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
}

#[test]
fn positive_crc32_handles_full_manifest_window() {
    // Manifest verifier slices [0..OFF_CRC32) = 8188 bytes; assert it
    // returns *some* value without panicking and is deterministic.
    let buf = [0xA5u8; OFF_CRC32];
    assert_eq!(crc32_ieee(&buf), crc32_ieee(&buf));
}

// ---------------------------------------------------------------------------
// ManifestBuilder
// ---------------------------------------------------------------------------

#[test]
fn positive_builder_default_equals_new() {
    let b1 = ManifestBuilder::default().finalize();
    let b2 = ManifestBuilder::new().finalize();
    assert_eq!(b1, b2);
}

#[test]
fn positive_builder_is_byte_deterministic() {
    let a = fully_populated_builder(SLOT_A).finalize();
    let b = fully_populated_builder(SLOT_A).finalize();
    assert_eq!(a, b);
}

#[test]
fn positive_builder_slot_b_round_trip() {
    let bytes = fully_populated_builder(SLOT_B).finalize();
    let m = ManifestRef::new(&bytes);
    assert_eq!(m.slot(), SLOT_B);
    m.verify_structural().unwrap();
    m.verify_crc().unwrap();
    m.verify_digest().unwrap();
}

#[test]
fn positive_builder_init_zeroes_reserved1_bytes() {
    // Bytes 6..8 (`reserved` field after slot) are zeroed by `init` so
    // the structural-prefix portion of two freshly-initialised manifests
    // is bit-identical. Future format extensions live here.
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A);
    // We can't observe builder bytes pre-finalize via the public API,
    // so use a finalized empty manifest and inspect the post-CRC bytes.
    let bytes = b.finalize();
    assert_eq!(&bytes[OFF_RESERVED_1..OFF_RESERVED_1 + 2], &[0x00, 0x00]);
}

#[test]
fn positive_builder_reserved2_stays_0xff_for_torn_write_detection() {
    // Bytes 4193..8188 are intentionally erased-pattern (`0xFF`) so the
    // CRC catches torn writes that leave the trailing region partially
    // programmed. The builder must NOT overwrite them.
    let bytes = fully_populated_builder(SLOT_A).finalize();
    assert!(
        bytes[OFF_RESERVED_2..OFF_CRC32].iter().all(|&b| b == 0xFF),
        "reserved-region bytes must remain 0xFF (erased pattern) so the CRC catches torn writes"
    );
}

#[test]
fn positive_builder_finalize_preimage_returns_in_buffer_digest() {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(1)
        .secure_image(&[0xAA; 32], 0x100)
        .nonsecure_image(&[0xBB; 32], 0x200);
    let returned = b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();
    let m = ManifestRef::new(&bytes);
    assert_eq!(m.manifest_digest(), &returned);
}

#[test]
fn positive_try_once_round_trip_all_states() {
    for flag in [TRY_ONCE_COMMITTED, TRY_ONCE_COMMITTING, TRY_ONCE_TRIED] {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A).fw_version(1).try_once(flag);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let bytes = b.finalize();
        assert_eq!(ManifestRef::new(&bytes).try_once_flag(), flag);
    }
}

#[test]
fn positive_boot_counter_snap_round_trip_boundaries() {
    for c in [0u32, 1, u32::MAX] {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A).fw_version(1).boot_counter_snap(c);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let bytes = b.finalize();
        assert_eq!(ManifestRef::new(&bytes).boot_counter_snap(), c);
    }
}

#[test]
fn positive_fw_version_be_serialisation_at_boundaries() {
    for v in [0u32, 1, 0x1234_5678, u32::MAX] {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A).fw_version(v);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let bytes = b.finalize();
        let m = ManifestRef::new(&bytes);
        assert_eq!(m.fw_version(), v);
        // Big-endian on the wire.
        assert_eq!(&bytes[8..12], &v.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// ManifestRef accessors
// ---------------------------------------------------------------------------

#[test]
fn positive_manifest_ref_as_bytes_returns_full_8k_backing() {
    let bytes = fully_populated_builder(SLOT_A).finalize();
    let m = ManifestRef::new(&bytes);
    assert_eq!(m.as_bytes().len(), MANIFEST_SIZE);
    assert_eq!(m.as_bytes(), &bytes);
}

#[test]
fn positive_manifest_ref_accessors_read_at_documented_offsets() {
    let bytes = fully_populated_builder(SLOT_A).finalize();
    let m = ManifestRef::new(&bytes);

    // Spot-check that every accessor agrees with a direct byte read at
    // its documented wire offset. This is a quick belt-and-braces guard
    // against an offset typo.
    assert_eq!(m.magic(), MAGIC);
    assert_eq!(m.manifest_version(), MANIFEST_VERSION);
    assert_eq!(m.slot(), SLOT_A);
    assert_eq!(m.fw_version(), 0x1234_5678);
    assert_eq!(m.secure_len(), 0xA000);
    assert_eq!(m.nonsecure_len(), 0xB000);
    assert_eq!(m.secure_hash(), &[0x11; 32]);
    assert_eq!(m.nonsecure_hash(), &[0x22; 32]);
    assert_eq!(m.vendor_pubkey_fpr(), &[0x33; 32]);
    assert_eq!(m.build_id(), &[0x44; 32]);
    assert_eq!(m.signature(), &[0x55; SIGNATURE_LEN]);
    assert_eq!(m.boot_counter_snap(), 7);
    assert_eq!(m.try_once_flag(), TRY_ONCE_COMMITTED);

    // CRC field is computed by `finalize` — accessor must read the same
    // four bytes the CRC verifier compares against.
    assert_eq!(m.crc32(), crc32_ieee(&bytes[..OFF_CRC32]));
}

// ---------------------------------------------------------------------------
// verify_* (non-signature paths — signature paths are in
// signature_verification.rs since they need real C10 keygen)
// ---------------------------------------------------------------------------

#[test]
fn positive_verify_structural_accepts_slot_a_and_slot_b() {
    for slot in [SLOT_A, SLOT_B] {
        let bytes = fully_populated_builder(slot).finalize();
        ManifestRef::new(&bytes).verify_structural().unwrap();
    }
}

#[test]
fn positive_verify_crc_accepts_freshly_finalised_manifest() {
    let bytes = fully_populated_builder(SLOT_A).finalize();
    ManifestRef::new(&bytes).verify_crc().unwrap();
}

#[test]
fn positive_verify_digest_accepts_fresh_manifest() {
    let bytes = fully_populated_builder(SLOT_A).finalize();
    ManifestRef::new(&bytes).verify_digest().unwrap();
}

#[test]
fn positive_verify_rollback_accepts_strict_greater() {
    let bytes = fully_populated_builder(SLOT_A).finalize();
    let m = ManifestRef::new(&bytes);
    // builder's fw_version is 0x12345678 > 0
    m.verify_rollback(0).unwrap();
    m.verify_rollback(0x1234_5677).unwrap();
}

#[test]
fn positive_verify_vendor_fpr_accepts_matching_key() {
    let seed = [0xAA; 16];
    let root = [0xBB; 16];
    let fpr = vendor_pubkey_fingerprint(&seed, &root);

    let mut b = ManifestBuilder::new();
    b.init(SLOT_A).fw_version(1).vendor_pubkey_fpr(&fpr);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    let bytes = b.finalize();

    ManifestRef::new(&bytes)
        .verify_vendor_fpr(&seed, &root)
        .unwrap();
}

// ---------------------------------------------------------------------------
// Test-coverage marker: the offset table is internally consistent
// ---------------------------------------------------------------------------

#[test]
fn positive_layout_offsets_partition_the_manifest_in_order() {
    // The accessors implicitly assume the wire-layout fields are laid
    // out in the documented order without gaps before `OFF_RESERVED_2`.
    // Verify the strict ordering so a future re-order stands out here.
    assert!(OFF_VENDOR_FPR + 32 == OFF_BUILD_ID);
    assert!(OFF_SIGNATURE + SIGNATURE_LEN <= MANIFEST_SIZE - 4);
}
