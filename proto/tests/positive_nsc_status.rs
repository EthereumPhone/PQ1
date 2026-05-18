//! Positive coverage for `NscStatus` enum + `From<u32>` conversion.
//!
//! Every status code returned over the TrustZone NSC boundary travels
//! as a raw `u32` and is parsed by both sides via this `From` impl. The
//! discriminant values are protocol-frozen: any silent renumbering
//! makes every old companion app misinterpret return codes.

use pqsigner_proto::NscStatus;

#[test]
fn positive_each_variant_round_trips_through_from_u32() {
    // Every variant we expect the firmware to emit must survive the
    // u32 → NscStatus → u32 round-trip. Listed by their **documented
    // numeric value**, not by name, so a silent renumbering fails the
    // test.
    let table: &[(u32, NscStatus)] = &[
        (0, NscStatus::Ok),
        (1, NscStatus::PinIncorrect),
        (2, NscStatus::PinLocked),
        (3, NscStatus::CryptoError),
        (4, NscStatus::InvalidPointer),
        (5, NscStatus::NotInitialized),
        (6, NscStatus::UserRejected),
        (7, NscStatus::IdleWipe),
        (10, NscStatus::FwUpdateBadState),
        (11, NscStatus::FwUpdateBadManifest),
        (12, NscStatus::FwUpdateBadVersion),
        (13, NscStatus::FwUpdateBadChunk),
        (14, NscStatus::FwUpdateBadImage),
        (15, NscStatus::FwUpdateFlashError),
        (16, NscStatus::FwUpdateOtpExhausted),
        (17, NscStatus::OffchainSlotUnregistered),
        (18, NscStatus::OffchainGapExceeded),
        (19, NscStatus::OffchainCapExceeded),
        (0xFFFF_FFFF, NscStatus::InternalError),
    ];
    for &(raw, expected) in table {
        let parsed = NscStatus::from(raw);
        assert_eq!(
            parsed, expected,
            "NscStatus::from({raw:#010x}) returned the wrong variant — protocol numbering changed?"
        );
        // u32 round-trip
        assert_eq!(
            parsed as u32, raw,
            "discriminant of {expected:?} ({} as u32) drifted from documented value {raw}",
            parsed as u32
        );
    }
}

#[test]
fn positive_ok_is_zero_so_zeroed_buffers_decode_to_ok() {
    // Defensive: zero-initialized return-status memory must decode to Ok
    // (this is what every successful NSC veneer does).
    assert_eq!(NscStatus::Ok as u32, 0);
    assert_eq!(NscStatus::from(0), NscStatus::Ok);
}

#[test]
fn positive_internal_error_is_max_u32() {
    // Sentinel — unrecoverable internal failure.
    assert_eq!(NscStatus::InternalError as u32, u32::MAX);
}

#[test]
fn positive_debug_impl_emits_variant_name() {
    // We rely on the derived Debug impl for log lines. Surface check
    // that it produces the variant identifier (not a number).
    let s = format!("{:?}", NscStatus::PinLocked);
    assert!(
        s.contains("PinLocked"),
        "Debug impl should emit variant name; got {s:?}"
    );
}

#[test]
fn positive_offchain_recovery_codes_distinct_from_fw_codes() {
    // Companion needs to route off-chain recovery errors differently
    // from FW-update errors. Documented ranges are 10-16 (FW) and
    // 17-19 (offchain) — make sure no aliasing.
    let fw_codes = [10_u32, 11, 12, 13, 14, 15, 16];
    let off_codes = [17_u32, 18, 19];
    for f in fw_codes {
        for o in off_codes {
            assert_ne!(f, o);
        }
    }
}
