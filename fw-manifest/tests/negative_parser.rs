//! Negative tests against the structural / parser layer of `ManifestRef`.
//!
//! These tests attack the assumptions the parser makes about the 8 KB
//! blob handed to it by the secure-world `CMD_FW_BEGIN` accumulator.
//! Anyone with a USB cable can drop arbitrary 8 KB on the firmware-
//! update path; every assumption that fails here is a direct DoS or
//! parser-confusion bug.

use fw_manifest::{
    crc32_ieee, ManifestBuilder, ManifestRef, VerifyError, MAGIC, MANIFEST_SIZE,
    MANIFEST_VERSION, OFF_CRC32, OFF_MANIFEST_VERSION, OFF_SLOT, SIGNATURE_LEN, SLOT_A, SLOT_B,
    TRY_ONCE_COMMITTED,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fresh_manifest_bytes() -> [u8; MANIFEST_SIZE] {
    let mut b = ManifestBuilder::new();
    b.init(SLOT_A)
        .fw_version(7)
        .secure_image(&[0xAA; 32], 0x100)
        .nonsecure_image(&[0xBB; 32], 0x200)
        .try_once(TRY_ONCE_COMMITTED);
    b.finalize_preimage();
    b.set_signature(&[0; SIGNATURE_LEN]);
    b.finalize()
}

fn rewrite_crc(bytes: &mut [u8; MANIFEST_SIZE]) {
    let crc = crc32_ieee(&bytes[..OFF_CRC32]);
    bytes[OFF_CRC32..].copy_from_slice(&crc.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Magic / version / slot
// ---------------------------------------------------------------------------

#[test]
fn negative_blank_flash_rejected_as_bad_magic() {
    // CLAUDE.md / wire-format invariant: a freshly erased flash page is
    // all 0xFF. The parser MUST reject this as BadMagic so we never
    // accidentally accept an unprogrammed slot as a valid manifest.
    let blank = [0xFFu8; MANIFEST_SIZE];
    assert_eq!(
        ManifestRef::new(&blank).verify_structural(),
        Err(VerifyError::BadMagic),
        "erased flash (all 0xFF) must be rejected by the magic check"
    );
}

#[test]
fn negative_zeroed_flash_rejected_as_bad_magic() {
    // Symmetric to the 0xFF case: all-zero is also not a valid
    // manifest. A naive "any aligned 8 KB region is a manifest" parser
    // would accept this; we must not.
    let zero = [0u8; MANIFEST_SIZE];
    assert_eq!(
        ManifestRef::new(&zero).verify_structural(),
        Err(VerifyError::BadMagic),
    );
}

#[test]
fn negative_wrong_magic_every_field_position_rejected() {
    // Flipping each individual byte of the magic must produce a
    // BadMagic — none of the four positions may be silently treated as
    // 'close enough'.
    for byte_idx in 0..4 {
        let mut bytes = fresh_manifest_bytes();
        bytes[byte_idx] ^= 0xFF;
        assert_eq!(
            ManifestRef::new(&bytes).verify_structural(),
            Err(VerifyError::BadMagic),
            "magic byte at offset {byte_idx} must be exact",
        );
    }
}

#[test]
fn negative_invalid_manifest_versions_rejected() {
    // The FSBL hard-codes v=0x02 support. Anything else must be
    // rejected as a clear "wrong-version" error rather than silently
    // mis-parsed.
    for bad in [0x00u8, 0x01, 0x03, 0x7F, 0x80, 0xFE, 0xFF] {
        let mut bytes = fresh_manifest_bytes();
        bytes[OFF_MANIFEST_VERSION] = bad;
        assert_eq!(
            ManifestRef::new(&bytes).verify_structural(),
            Err(VerifyError::BadVersion),
            "manifest_version = 0x{bad:02X} must be rejected as BadVersion",
        );
    }
}

#[test]
fn negative_only_pinned_manifest_version_accepted() {
    // Defence-in-depth: prove a structurally-valid manifest stays
    // accepted only at the pinned 0x02 byte.
    let bytes = fresh_manifest_bytes();
    assert_eq!(bytes[OFF_MANIFEST_VERSION], MANIFEST_VERSION);
    ManifestRef::new(&bytes).verify_structural().unwrap();
}

#[test]
fn negative_invalid_slot_values_rejected() {
    // Slot must be SLOT_A (0x00) or SLOT_B (0x01). Every other byte
    // value is a parser-confusion attack — an FSBL that tolerated
    // wild slot values could route execution to an arbitrary address.
    for bad in [0x02u8, 0x10, 0x55, 0x7F, 0x80, 0xAA, 0xFE, 0xFF] {
        let mut bytes = fresh_manifest_bytes();
        bytes[OFF_SLOT] = bad;
        rewrite_crc(&mut bytes); // CRC alone shouldn't make a bad slot pass.
        assert_eq!(
            ManifestRef::new(&bytes).verify_structural(),
            Err(VerifyError::BadSlot),
            "slot = 0x{bad:02X} must be rejected as BadSlot",
        );
    }
}

#[test]
fn negative_verify_structural_order_magic_before_version_before_slot() {
    // The verifier rejects as early as possible. If magic AND version
    // AND slot are all bad, we expect BadMagic — the earliest check.
    // This pins the error ordering so future refactors don't reorder
    // the checks (which could surface as a subtly different boot
    // message and make field debugging harder).
    let mut bytes = [0xFFu8; MANIFEST_SIZE];
    bytes[OFF_MANIFEST_VERSION] = 0xFF;
    bytes[OFF_SLOT] = 0xFF;
    assert_eq!(
        ManifestRef::new(&bytes).verify_structural(),
        Err(VerifyError::BadMagic),
    );

    // Now fix magic, leave version+slot bad → expect BadVersion before BadSlot.
    bytes[..4].copy_from_slice(&MAGIC);
    assert_eq!(
        ManifestRef::new(&bytes).verify_structural(),
        Err(VerifyError::BadVersion),
    );
}

// ---------------------------------------------------------------------------
// CRC integrity
// ---------------------------------------------------------------------------

#[test]
fn negative_zero_crc_field_rejected() {
    // A manifest whose CRC field is just zeros must not pass — this is
    // a torn-write or attacker-zeroed page.
    let mut bytes = fresh_manifest_bytes();
    bytes[OFF_CRC32..].copy_from_slice(&[0u8; 4]);
    assert_eq!(
        ManifestRef::new(&bytes).verify_crc(),
        Err(VerifyError::BadCrc),
    );
}

#[test]
fn negative_all_ff_crc_field_rejected() {
    // An unprogrammed CRC region (still in erased state, 0xFF) is the
    // classic torn-write signature. Must not be accepted.
    let mut bytes = fresh_manifest_bytes();
    bytes[OFF_CRC32..].copy_from_slice(&[0xFFu8; 4]);
    assert_eq!(
        ManifestRef::new(&bytes).verify_crc(),
        Err(VerifyError::BadCrc),
    );
}

#[test]
fn negative_crc_bit_flip_in_field_detected() {
    for bit in 0u8..32 {
        let mut bytes = fresh_manifest_bytes();
        let byte = (bit / 8) as usize;
        bytes[OFF_CRC32 + byte] ^= 1 << (bit % 8);
        assert_eq!(
            ManifestRef::new(&bytes).verify_crc(),
            Err(VerifyError::BadCrc),
            "single-bit flip in CRC field bit {bit} must be detected",
        );
    }
}

#[test]
fn negative_truncated_to_blank_trailing_bytes_rejected() {
    // Simulates a torn write that left the last N bytes (including the
    // CRC) at 0xFF. Must be rejected at the magic check first, but if
    // someone bypassed structural, the CRC check would catch it.
    let mut bytes = fresh_manifest_bytes();
    bytes[OFF_CRC32 - 16..].fill(0xFF);
    assert_eq!(
        ManifestRef::new(&bytes).verify_crc(),
        Err(VerifyError::BadCrc),
    );
}

// ---------------------------------------------------------------------------
// Construction never panics
// ---------------------------------------------------------------------------

#[test]
fn negative_manifest_ref_new_does_not_validate_on_construction() {
    // ManifestRef::new is documented as "cheap, no allocation, no
    // validation". Confirm a wild blob can be wrapped without panic;
    // callers MUST then call verify_* explicitly.
    let blob = [0u8; MANIFEST_SIZE];
    let m = ManifestRef::new(&blob);
    // Reading every accessor on an all-zero blob is bounded and
    // panic-free — the parser holds no implicit "this must be valid"
    // assumption at construction time.
    let _ = m.magic();
    let _ = m.fw_version();
    let _ = m.signature();
    let _ = m.crc32();
}

#[test]
fn negative_alternating_byte_pattern_does_not_pass_structural() {
    let mut bytes = [0u8; MANIFEST_SIZE];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = if i & 1 == 0 { 0x55 } else { 0xAA };
    }
    assert!(matches!(
        ManifestRef::new(&bytes).verify_structural(),
        Err(VerifyError::BadMagic | VerifyError::BadVersion | VerifyError::BadSlot)
    ));
}

#[test]
fn negative_only_slots_a_and_b_pass_structural() {
    // Belt-and-braces: assert SLOT_A and SLOT_B are the *only* two byte
    // values that pass verify_structural's slot check.
    for slot in 0u8..=255 {
        let mut b = ManifestBuilder::new();
        b.init(SLOT_A) // start with a valid prefix
            .fw_version(1);
        b.finalize_preimage();
        b.set_signature(&[0; SIGNATURE_LEN]);
        let mut bytes = b.finalize();
        bytes[OFF_SLOT] = slot;
        rewrite_crc(&mut bytes);

        let result = ManifestRef::new(&bytes).verify_structural();
        if slot == SLOT_A || slot == SLOT_B {
            assert!(
                result.is_ok(),
                "slot 0x{slot:02X} must pass structural check"
            );
        } else {
            assert_eq!(
                result,
                Err(VerifyError::BadSlot),
                "slot 0x{slot:02X} must be rejected — only SLOT_A and SLOT_B are valid",
            );
        }
    }
}
