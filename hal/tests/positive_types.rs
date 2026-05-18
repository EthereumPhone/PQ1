//! Positive coverage for the `pqsigner-hal` type surface.
//!
//! Every public enum / struct / associated constant declared in
//! `src/lib.rs` gets a happy-path test here: its derives are exercised
//! (`Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Default`), its
//! variants are constructed, and any `pub const` shape is read.
//!
//! These tests intentionally have no `Platform` impl — that lives in
//! `tests/positive_mock_platform.rs` so a compile failure there does
//! not mask a derive regression here.

use pqsigner_hal::{
    BootStage, BootStateData, Buttonset, HalError, KeySelector, OtpRange, TamperCause,
};

// ---------------------------------------------------------------------------
// HalError — derives Debug + PartialEq + Eq + Clone + Copy + #[non_exhaustive]
// ---------------------------------------------------------------------------

#[test]
fn positive_hal_error_equality_reflexive() {
    assert_eq!(HalError::BusFault, HalError::BusFault);
    assert_eq!(HalError::Timeout, HalError::Timeout);
    assert_eq!(HalError::BadParam, HalError::BadParam);
    assert_eq!(HalError::Unsupported, HalError::Unsupported);
    assert_eq!(HalError::Corrupt, HalError::Corrupt);
}

#[test]
fn positive_hal_error_is_copy() {
    let e = HalError::BadParam;
    let a = e;
    let b = e;
    assert_eq!(a, b);
    assert_eq!(a, HalError::BadParam);
}

#[test]
fn positive_hal_error_debug_does_not_panic() {
    // Debug is documented; this just exercises the impl.
    let s = format!("{:?}", HalError::Corrupt);
    assert!(s.contains("Corrupt"));
}

#[test]
fn positive_hal_error_clone_roundtrip() {
    let e = HalError::Unsupported;
    #[allow(clippy::clone_on_copy)]
    let c = e.clone();
    assert_eq!(e, c);
}

// ---------------------------------------------------------------------------
// KeySelector — Clone + Copy ONLY (NOT Debug, NOT PartialEq — see negative_invariants.rs)
// ---------------------------------------------------------------------------

#[test]
fn positive_key_selector_all_variants_constructible() {
    let sw_key = [0xAAu8; 32];
    let _sw = KeySelector::Software(&sw_key);
    let _dhuk = KeySelector::Dhuk;
    let _bhk = KeySelector::Bhk;
    let _xor = KeySelector::DhukXorBhk;
}

#[test]
fn positive_key_selector_is_copy() {
    let sel = KeySelector::Dhuk;
    let a = sel;
    let b = sel;
    // Use them so the move/copy is actually exercised.
    let _ = (a, b);
}

#[test]
fn positive_key_selector_software_holds_borrow() {
    let key = [0x11u8; 32];
    let sel = KeySelector::Software(&key);
    // Match exhaustively to assert the variant payload is preserved.
    match sel {
        KeySelector::Software(k) => assert_eq!(k, &[0x11u8; 32]),
        _ => panic!("expected Software variant"),
    }
}

// ---------------------------------------------------------------------------
// OtpRange — Debug + PartialEq + Eq + Clone + Copy. `Reserved(u8)` carries payload.
// ---------------------------------------------------------------------------

#[test]
fn positive_otp_range_named_variants_distinct() {
    assert_eq!(OtpRange::AntiRollback, OtpRange::AntiRollback);
    assert_eq!(OtpRange::MasterKey, OtpRange::MasterKey);
    assert_eq!(OtpRange::BhkProvisioned, OtpRange::BhkProvisioned);
    assert_ne!(OtpRange::AntiRollback, OtpRange::MasterKey);
    assert_ne!(OtpRange::MasterKey, OtpRange::BhkProvisioned);
    assert_ne!(OtpRange::BhkProvisioned, OtpRange::AntiRollback);
}

#[test]
fn positive_otp_range_reserved_payload_preserved() {
    assert_eq!(OtpRange::Reserved(7), OtpRange::Reserved(7));
    assert_eq!(OtpRange::Reserved(0), OtpRange::Reserved(0));
    assert_eq!(OtpRange::Reserved(255), OtpRange::Reserved(255));
}

#[test]
fn positive_otp_range_debug_does_not_panic() {
    let s = format!("{:?}", OtpRange::Reserved(0x42));
    assert!(s.contains("Reserved"));
    assert!(s.contains("66")); // 0x42 == 66 decimal
}

// ---------------------------------------------------------------------------
// BootStateData — Default + Clone + Copy + Debug + PartialEq + Eq, `pub raw: [u8; 32]`
// ---------------------------------------------------------------------------

#[test]
fn positive_boot_state_data_default_is_all_zero() {
    let d = BootStateData::default();
    assert_eq!(d.raw, [0u8; 32]);
}

#[test]
fn positive_boot_state_data_roundtrip_equality() {
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let a = BootStateData { raw };
    let b = BootStateData { raw };
    assert_eq!(a, b);
    assert_eq!(a.raw, raw);
}

#[test]
fn positive_boot_state_data_distinct_payload_distinct() {
    let a = BootStateData { raw: [0u8; 32] };
    let mut b_raw = [0u8; 32];
    b_raw[31] = 1;
    let b = BootStateData { raw: b_raw };
    assert_ne!(a, b);
}

#[test]
fn positive_boot_state_data_is_copy() {
    let d = BootStateData { raw: [9u8; 32] };
    let copy1 = d;
    let copy2 = d;
    assert_eq!(copy1, copy2);
}

// ---------------------------------------------------------------------------
// TamperCause — Debug + PartialEq + Eq + Clone + Copy. `Other(u8)` carries payload.
// ---------------------------------------------------------------------------

#[test]
fn positive_tamper_cause_named_variants_distinct() {
    assert_ne!(TamperCause::BackupVoltage, TamperCause::LseClock);
    assert_ne!(TamperCause::LseClock, TamperCause::CryptoFault);
    assert_ne!(TamperCause::CryptoFault, TamperCause::DebugWhileLocked);
}

#[test]
fn positive_tamper_cause_other_payload_preserved() {
    assert_eq!(TamperCause::Other(0), TamperCause::Other(0));
    assert_eq!(TamperCause::Other(254), TamperCause::Other(254));
}

// ---------------------------------------------------------------------------
// Buttonset — Default + Clone + Copy + Debug + PartialEq + Eq, `pub left/right: bool`
// ---------------------------------------------------------------------------

#[test]
fn positive_buttonset_default_is_all_false() {
    let b = Buttonset::default();
    assert!(!b.left);
    assert!(!b.right);
    assert_eq!(b, Buttonset { left: false, right: false });
}

#[test]
fn positive_buttonset_construction_and_equality() {
    let b = Buttonset { left: true, right: false };
    assert_eq!(b, Buttonset { left: true, right: false });
    assert_ne!(b, Buttonset { left: false, right: true });
    assert_ne!(b, Buttonset { left: true, right: true });
}

// ---------------------------------------------------------------------------
// BootStage — Debug + PartialEq + Eq + Clone + Copy + `pub const ALL: [Self; 6]`
// ---------------------------------------------------------------------------

#[test]
fn positive_boot_stage_all_has_six_entries() {
    assert_eq!(BootStage::ALL.len(), 6);
}

#[test]
fn positive_boot_stage_all_first_is_clocks_last_is_se() {
    assert_eq!(BootStage::ALL[0], BootStage::Clocks);
    assert_eq!(BootStage::ALL[5], BootStage::Se);
}

#[test]
fn positive_boot_stage_variants_pairwise_distinct() {
    let stages = BootStage::ALL;
    for i in 0..stages.len() {
        for j in (i + 1)..stages.len() {
            assert_ne!(
                stages[i], stages[j],
                "BootStage::ALL contains duplicate variant at {i} and {j}",
            );
        }
    }
}
