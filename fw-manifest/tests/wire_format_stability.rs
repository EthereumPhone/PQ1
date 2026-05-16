//! Negative-flavoured tests that pin every wire-format constant.
//!
//! These tests fail loudly the moment anyone changes a manifest offset,
//! the magic bytes, the manifest version, the domain tag, or the
//! signature length. Every such change is a wire-format break that
//! invalidates every already-signed release bundle and every FSBL that
//! ships hard-coded vendor pubkeys.
//!
//! CLAUDE.md guidance: "Do not expand the signed FW-update preimage. It
//! is intentionally 75 B `'PQFW_V1' || fw_version_be || secure_hash ||
//! nonsecure_hash` so any auditor can reconstruct from `(version,
//! secure.elf, nonsecure.elf)` alone."

use fw_manifest::{
    DOMAIN_TAG, MAGIC, MANIFEST_SIZE, MANIFEST_VERSION, OFF_BOOT_CTR_SNAP, OFF_BUILD_ID,
    OFF_CRC32, OFF_FW_VERSION, OFF_MAGIC, OFF_MANIFEST_DIGEST, OFF_MANIFEST_VERSION,
    OFF_NONSECURE_HASH, OFF_NONSECURE_LEN, OFF_RESERVED_1, OFF_RESERVED_2, OFF_SECURE_HASH,
    OFF_SECURE_LEN, OFF_SIGNATURE, OFF_SLOT, OFF_TRY_ONCE, OFF_VENDOR_FPR, SIGNATURE_LEN,
    SIGNED_PREIMAGE_LEN, SLOT_A, SLOT_B, TRY_ONCE_COMMITTED, TRY_ONCE_COMMITTING, TRY_ONCE_TRIED,
    VERIFYING_KEY_LEN,
};

// ---------------------------------------------------------------------------
// Sizes and magic identifiers
// ---------------------------------------------------------------------------

#[test]
fn negative_manifest_size_must_be_one_stm32u585_flash_page() {
    assert_eq!(
        MANIFEST_SIZE, 8192,
        "MANIFEST_SIZE must be one STM32U585 flash page (8 KiB) — changing this re-partitions \
         the manifest A/B layout in flash and breaks every shipped FSBL"
    );
}

#[test]
fn negative_magic_is_exactly_pqsf_ascii() {
    assert_eq!(
        MAGIC,
        [b'P', b'Q', b'S', b'F'],
        "MAGIC bytes are part of the signed-region prefix and are baked into FSBL's torn-flash \
         detection — they must stay 'PQSF' (0x50, 0x51, 0x53, 0x46) forever"
    );
}

#[test]
fn negative_manifest_version_is_pinned_to_0x02() {
    assert_eq!(
        MANIFEST_VERSION, 0x02,
        "MANIFEST_VERSION = 0x02 is the on-wire v2 contract; bumping it requires an FSBL \
         migration path because every shipped device has a hard-coded supported version"
    );
}

#[test]
fn negative_domain_tag_is_exactly_pqfw_v1() {
    // CLAUDE.md: "Do not expand the signed FW-update preimage." The
    // domain tag's bytes are part of every release signature; renaming
    // it invalidates every previously-signed release bundle.
    assert_eq!(
        DOMAIN_TAG,
        b"PQFW_V1",
        "DOMAIN_TAG is part of every signed preimage — changing the bytes invalidates every \
         shipped release signature (see CLAUDE.md 'no casual KDF tag changes')"
    );
    assert_eq!(DOMAIN_TAG.len(), 7);
}

#[test]
fn negative_signed_preimage_len_is_exactly_75_bytes() {
    // CLAUDE.md: "It is intentionally 75 B 'PQFW_V1' || fw_version_be
    // || secure_hash || nonsecure_hash". Auditors who reconstruct a
    // release from source rely on this exact length.
    assert_eq!(SIGNED_PREIMAGE_LEN, 75);
    assert_eq!(SIGNED_PREIMAGE_LEN, DOMAIN_TAG.len() + 4 + 32 + 32);
}

#[test]
fn negative_signature_len_is_4008_bytes_c10() {
    assert_eq!(
        SIGNATURE_LEN, 4008,
        "SIGNATURE_LEN is re-exported from sphincs-c10::params and is part of the C10 wire \
         contract; a 4007/4009-byte sig means we've forked the algorithm"
    );
}

#[test]
fn negative_verifying_key_len_is_32_bytes() {
    assert_eq!(VERIFYING_KEY_LEN, 32);
}

// ---------------------------------------------------------------------------
// Constants used by FSBL's try-once state machine
// ---------------------------------------------------------------------------

#[test]
fn negative_slot_values_are_0x00_and_0x01() {
    assert_eq!(SLOT_A, 0x00);
    assert_eq!(SLOT_B, 0x01);
}

#[test]
fn negative_try_once_states_are_pinned() {
    // FSBL distinguishes 'fresh from sign' (0x00), 'mid-commit reboot'
    // (0x55), and 'armed but not confirmed alive' (0xAA). The Hamming
    // distance between these three values is intentional — single
    // bit-flips in the torn-write window are extremely unlikely to map
    // one valid state to another.
    assert_eq!(TRY_ONCE_COMMITTED, 0x00);
    assert_eq!(TRY_ONCE_COMMITTING, 0x55);
    assert_eq!(TRY_ONCE_TRIED, 0xAA);
}

// ---------------------------------------------------------------------------
// Per-field offsets
//
// One assertion per offset so the failure message names the field that
// moved.
// ---------------------------------------------------------------------------

#[test]
fn negative_field_offsets_are_pinned() {
    assert_eq!(OFF_MAGIC, 0);
    assert_eq!(OFF_MANIFEST_VERSION, 4);
    assert_eq!(OFF_SLOT, 5);
    assert_eq!(OFF_RESERVED_1, 6);
    assert_eq!(OFF_FW_VERSION, 8);
    assert_eq!(OFF_SECURE_LEN, 12);
    assert_eq!(OFF_NONSECURE_LEN, 16);
    assert_eq!(OFF_SECURE_HASH, 20);
    assert_eq!(OFF_NONSECURE_HASH, 52);
    assert_eq!(OFF_VENDOR_FPR, 84);
    assert_eq!(OFF_BUILD_ID, 116);
    assert_eq!(OFF_MANIFEST_DIGEST, 148);
    assert_eq!(OFF_SIGNATURE, 180);
    assert_eq!(OFF_BOOT_CTR_SNAP, 4188);
    assert_eq!(OFF_TRY_ONCE, 4192);
    assert_eq!(OFF_RESERVED_2, 4193);
    assert_eq!(OFF_CRC32, 8188);
}

#[test]
fn negative_field_offsets_partition_without_overlap() {
    // The signed-region fields cover offsets [0..OFF_MANIFEST_DIGEST)
    // contiguously. Walk them in order and verify each one starts where
    // the previous one ends. Any future field addition that doesn't
    // update both the offset and the field width will be caught here.
    let fields: &[(usize, usize, &str)] = &[
        (OFF_MAGIC, 4, "magic"),
        (OFF_MANIFEST_VERSION, 1, "manifest_version"),
        (OFF_SLOT, 1, "slot"),
        (OFF_RESERVED_1, 2, "reserved1"),
        (OFF_FW_VERSION, 4, "fw_version"),
        (OFF_SECURE_LEN, 4, "secure_len"),
        (OFF_NONSECURE_LEN, 4, "nonsecure_len"),
        (OFF_SECURE_HASH, 32, "secure_hash"),
        (OFF_NONSECURE_HASH, 32, "nonsecure_hash"),
        (OFF_VENDOR_FPR, 32, "vendor_pubkey_fpr"),
        (OFF_BUILD_ID, 32, "build_id"),
        (OFF_MANIFEST_DIGEST, 32, "manifest_digest"),
        (OFF_SIGNATURE, SIGNATURE_LEN, "signature"),
        (OFF_BOOT_CTR_SNAP, 4, "boot_counter_snap"),
        (OFF_TRY_ONCE, 1, "try_once"),
    ];
    let mut expected = 0usize;
    for (off, size, name) in fields {
        assert_eq!(
            *off, expected,
            "field {name} starts at {off} but previous field ends at {expected}"
        );
        expected = *off + *size;
    }
    // After try_once we expect the long erased-pattern reserved region.
    assert_eq!(expected, OFF_RESERVED_2);
}

#[test]
fn negative_signature_region_does_not_collide_with_post_sign_fields() {
    // The signature (4008 bytes) sits between offset 180 and 4188, with
    // the post-sign boot-counter snapshot starting exactly at 4188.
    assert_eq!(OFF_SIGNATURE + SIGNATURE_LEN, OFF_BOOT_CTR_SNAP);
}

#[test]
fn negative_crc32_field_is_the_trailing_four_bytes() {
    // FSBL relies on the CRC sitting in the *last* 4 bytes of the page
    // so a torn write that leaves the trailing region unprogrammed
    // (`0xFF...0xFF`) produces a CRC of `0xFFFFFFFF` that almost
    // certainly doesn't match the computed CRC over the rest.
    assert_eq!(OFF_CRC32, MANIFEST_SIZE - 4);
}

#[test]
fn negative_reserved2_window_is_3995_bytes() {
    // The trailing-reserved 0xFF region must be exactly large enough to
    // pad the manifest out to one flash page; off-by-one here means
    // either (a) we wrote outside the page or (b) the CRC slid.
    assert_eq!(OFF_CRC32 - OFF_RESERVED_2, 3995);
}
