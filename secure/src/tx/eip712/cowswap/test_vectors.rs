//! CoW GPv2Order cross-check test vectors.
//!
//! Fixtures + regression tests for the v3 security gate. Kept in a
//! `#[cfg(test)]` sibling so the 1000 USDC → WETH byte-array doesn't
//! dilute the production-logic audit surface in `mod.rs`.
//!
//! Coverage (9 tests total):
//!   * happy path — valid canonical + calldata + owner passes all
//!     invariants.
//!   * 5 per-field flips on the failure side: chain_id, validTo,
//!     orderDigest, appData (caught via digest), owner.
//!   * 3 shape-check violations: bad selector, signed=false, nonzero
//!     tail pad.

use super::*;

/// 1000 USDC → ≥ 0.5 WETH fixture — matches companion e2e_vector.
fn fixture_canonical() -> [u8; 204] {
    let mut c = [0u8; 204];
    c[0..8].copy_from_slice(&1u64.to_be_bytes()); // chain_id
    c[8..28].copy_from_slice(&[
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
        0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
    ]); // USDC
    c[28..48].copy_from_slice(&[
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
        0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ]); // WETH
    c[48..68].copy_from_slice(&[
        0x74, 0x2d, 0x35, 0xcc, 0x66, 0x34, 0xc0, 0x53, 0x29, 0x25, 0xa3, 0xb8, 0x44, 0xbc,
        0x45, 0x4e, 0x44, 0x38, 0xf4, 0x4e,
    ]); // receiver
        // sell_amount = 1_000_000_000 at [68..100]
    c[96..100].copy_from_slice(&1_000_000_000u32.to_be_bytes());
    // buy_amount = 0x06F05B59D3B20000 at [100..132]
    c[124..132].copy_from_slice(&0x06F05B59D3B20000u64.to_be_bytes());
    // fee_amount = 0 at [132..164]
    // valid_to = 0x68000000 at [164..168]
    c[164..168].copy_from_slice(&0x68000000u32.to_be_bytes());
    c[168] = 0; // kind = Sell
    c[169] = 0;
    c[170] = 0;
    c[171] = 0;
    c[172..204].copy_from_slice(&[
        0x83, 0xb9, 0xdc, 0xb2, 0x31, 0x6e, 0x54, 0xfc, 0x04, 0xc1, 0x0f, 0x74, 0xc9, 0xa3,
        0xd5, 0xdd, 0x66, 0xa9, 0xe4, 0xc4, 0x3c, 0x04, 0xcc, 0xef, 0xb9, 0xc0, 0xc0, 0x3e,
        0x61, 0xe5, 0xfb, 0x28,
    ]);
    c
}

fn fixture_owner() -> [u8; 20] {
    [0xfb, 0x3c, 0x7e, 0xb9, 0x36, 0xcA, 0xA1, 0x2B, 0x5A, 0x88, 0x4d, 0x61, 0x23, 0x93, 0x96, 0x9A, 0x55, 0x7d, 0x43, 0x07]
}

/// Hand-build a setPreSignature calldata for the fixture owner +
/// canonical. Reuses `compute_digest` for the orderDigest slice.
fn fixture_calldata() -> [u8; 164] {
    let canonical = fixture_canonical();
    let digest = compute_digest(&canonical, 1).unwrap();
    let owner = fixture_owner();
    let mut cd = [0u8; 164];
    cd[0..4].copy_from_slice(&[0xec, 0x6c, 0xb1, 0x3f]);
    cd[35] = 0x40;
    cd[67] = 1;
    cd[99] = 56;
    cd[100..132].copy_from_slice(&digest);
    cd[132..152].copy_from_slice(&owner);
    cd[152..156].copy_from_slice(&canonical[164..168]);
    cd
}

#[test]
fn happy_path_passes() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert!(cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner).is_ok());
    assert!(check_setpresig_calldata_shape(&calldata).is_ok());
}

#[test]
fn chain_id_mismatch_rejected() {
    let canonical = fixture_canonical();
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 137, &owner),
        Err(OrderUidMismatch::ChainIdMismatch)
    );
}

#[test]
fn valid_to_mismatch_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[152] = calldata[152].wrapping_add(1);
    let owner = fixture_owner();
    // The valid_to check runs before the digest check, so this
    // bubbles out as ValidToMismatch (digest would also fail).
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::ValidToMismatch)
    );
}

#[test]
fn order_digest_flip_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[100] ^= 0x01;
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OrderDigestMismatch)
    );
}

#[test]
fn canonical_field_flip_rejected_via_digest() {
    // Flip any single byte of canonical that isn't chain_id or
    // valid_to and the orderDigest will diverge — catching the
    // attack "swap the appData silently behind a verified proof".
    let mut canonical = fixture_canonical();
    canonical[172] ^= 0xFF; // appData MSB
    let calldata = fixture_calldata();
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OrderDigestMismatch)
    );
}

#[test]
fn owner_mismatch_rejected() {
    let canonical = fixture_canonical();
    let mut calldata = fixture_calldata();
    calldata[132] ^= 0x01;
    let owner = fixture_owner();
    assert_eq!(
        cross_check_setpresig_calldata(&canonical, &calldata, 1, &owner),
        Err(OrderUidMismatch::OwnerMismatch)
    );
}

#[test]
fn shape_check_rejects_bad_selector() {
    let mut cd = fixture_calldata();
    cd[0] ^= 0xFF;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}

#[test]
fn shape_check_rejects_signed_false() {
    let mut cd = fixture_calldata();
    cd[67] = 0;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}

#[test]
fn shape_check_rejects_nonzero_tail_padding() {
    let mut cd = fixture_calldata();
    cd[163] = 1;
    assert_eq!(
        check_setpresig_calldata_shape(&cd),
        Err(OrderUidMismatch::CanonicalDecode)
    );
}
