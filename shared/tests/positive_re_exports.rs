//! Positive: re-export shim integrity.
//!
//! `shared/src/lib.rs` is documented as a thin `pub use pqsigner_proto::*;`
//! shim. ~67 source files import protocol constants through
//! `sphincs_tz_shared::CMD_*` etc. Any change that drops a symbol from the
//! re-export path breaks those call sites silently — the type system would
//! catch it at the call site, but a contract test here pins the surface
//! down with a clear failure message.

use sphincs_tz_shared as shared;

#[test]
fn positive_apdu_constants_reach_through_shim() {
    // Protocol-level constants defined in `pqsigner-proto` must reach
    // call sites through `sphincs_tz_shared::*` per the lib.rs contract.
    let _: u8 = shared::APDU_CLA_V2;
    let _: u8 = shared::INS_V2_GET_RESPONSE;
    let _: usize = shared::HID_REPORT_SIZE;
    let _: u8 = shared::HID_TAG_APDU;
    let _: u8 = shared::HID_TAG_PING;
    let _: u16 = shared::SW_WRONG_LENGTH;
    let _: u16 = shared::SW_CLA_NOT_SUPPORTED;
    let _: u16 = shared::SW_CONDITIONS_NOT_SATISFIED;
}

#[test]
fn positive_cmd_constants_reach_through_shim() {
    // A representative slice of CMD_* constants from each documented range.
    let _: u32 = shared::CMD_NONE;
    let _: u32 = shared::CMD_GET_REMAINING;
    let _: u32 = shared::CMD_REQUEST_UNLOCK;
}

#[test]
fn positive_modules_reachable() {
    // Implementation modules are documented as living in this crate
    // (not pqsigner-proto), so they must be reachable as
    // `sphincs_tz_shared::apdu_framing::*` and `::db_format::*`.
    let _ = shared::apdu_framing::ChainState::new();
    let _ = shared::apdu_framing::HidFrameAssembler::new();
    let _: u8 = shared::db_format::ERC20_DB_MAGIC[0];
}

#[test]
fn positive_re_exported_values_agree_with_authoritative_crate() {
    // The "single source of truth" claim in lib.rs is only meaningful if
    // re-exported values match the authoritative crate byte-for-byte.
    assert_eq!(shared::APDU_CLA_V2, pqsigner_proto::APDU_CLA_V2);
    assert_eq!(shared::HID_REPORT_SIZE, pqsigner_proto::HID_REPORT_SIZE);
    assert_eq!(shared::SW_WRONG_LENGTH, pqsigner_proto::SW_WRONG_LENGTH);
}
