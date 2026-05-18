//! Negative tests for CMD ID hygiene and `NscStatus` From-u32 behavior.
//!
//! **What's being attacked.**
//!
//! 1. CMD IDs are wire-format values. A re-numbering would make the
//!    NS-world dispatcher and the companion app disagree on what a
//!    given byte means.
//! 2. The block comment at the top of `proto/src/lib.rs` documents
//!    numeric ranges by concern (1..=13 lifecycle, 14..=15 wallet
//!    identity, 16..=18 off-chain, 20..=24 fw-update, 30 batch,
//!    200..=test). Test-only CMDs that drift into the production range
//!    risk being reachable on a `mode-production` build.
//! 3. Retired discriminants (NscStatus 8 was SlotExhausted) MUST NOT
//!    silently round-trip — they must fall through to InternalError so
//!    a misconfigured firmware doesn't replay a stale status code with
//!    a recycled meaning.
//! 4. CMD IDs 4 and 6 are reserved (legacy CMD_SIGN, CMD_CLEAR_SIGN_MSG).
//!    No live CMD constant may reuse them.

use pqsigner_proto::*;

// All currently-defined CMD constants. Kept in sync with the
// compile-time collision check at the bottom of `proto/src/lib.rs`.
const ALL_CMDS: &[(u32, &str)] = &[
    (CMD_NONE, "CMD_NONE"),
    (CMD_GET_REMAINING, "CMD_GET_REMAINING"),
    (CMD_REQUEST_UNLOCK, "CMD_REQUEST_UNLOCK"),
    (CMD_GET_PUBKEY, "CMD_GET_PUBKEY"),
    (CMD_CLEAR_SIGN, "CMD_CLEAR_SIGN"),
    (CMD_SIGN_USEROP, "CMD_SIGN_USEROP"),
    (CMD_GET_BOOTSTRAP_PUBKEY, "CMD_GET_BOOTSTRAP_PUBKEY"),
    (CMD_GET_MAIN_PUBKEY, "CMD_GET_MAIN_PUBKEY"),
    (CMD_SIGN_BOOTSTRAP, "CMD_SIGN_BOOTSTRAP"),
    (CMD_IS_UNLOCKED, "CMD_IS_UNLOCKED"),
    (CMD_LOCK, "CMD_LOCK"),
    (CMD_SIGN_MESSAGE, "CMD_SIGN_MESSAGE"),
    (CMD_GET_WALLET_ADDRESS, "CMD_GET_WALLET_ADDRESS"),
    (CMD_GET_INIT_CODE, "CMD_GET_INIT_CODE"),
    (CMD_SIGN_OFFCHAIN, "CMD_SIGN_OFFCHAIN"),
    (CMD_OFFCHAIN_STATUS, "CMD_OFFCHAIN_STATUS"),
    (CMD_OFFCHAIN_SYNC, "CMD_OFFCHAIN_SYNC"),
    (CMD_FW_BEGIN, "CMD_FW_BEGIN"),
    (CMD_FW_CHUNK, "CMD_FW_CHUNK"),
    (CMD_FW_COMMIT, "CMD_FW_COMMIT"),
    (CMD_FW_STATUS, "CMD_FW_STATUS"),
    (CMD_FW_ABORT, "CMD_FW_ABORT"),
    (CMD_SIGN_USEROP_BATCH, "CMD_SIGN_USEROP_BATCH"),
    (CMD_TEST_PIN_LOCKOUT, "CMD_TEST_PIN_LOCKOUT"),
    (CMD_TZIC_STATUS, "CMD_TZIC_STATUS"),
];

// ───────────────────────────────────────────────────────────────────────
// CMD uniqueness — runtime parity with the compile-time check
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_no_two_cmds_share_the_same_u32() {
    for i in 0..ALL_CMDS.len() {
        for j in (i + 1)..ALL_CMDS.len() {
            assert_ne!(
                ALL_CMDS[i].0, ALL_CMDS[j].0,
                "CMD collision: {} and {} both equal {}",
                ALL_CMDS[i].1, ALL_CMDS[j].1, ALL_CMDS[i].0,
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// Reserved CMD IDs — 4 (legacy CMD_SIGN) and 6 (legacy CMD_CLEAR_SIGN_MSG)
//
// These must NOT be reused by any currently-defined CMD. Reuse would
// have a deployed companion app silently dispatch into the wrong
// handler if it sent a stale v1 byte.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_reserved_cmd_ids_are_not_reused() {
    for &reserved in &[4_u32, 6] {
        for &(cmd, name) in ALL_CMDS {
            assert_ne!(
                cmd, reserved,
                "{name} = {reserved} collides with retired legacy CMD ID — old companion apps would dispatch into the wrong handler"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// Test-only CMDs must live in the documented test block (≥ 200)
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_test_only_cmds_live_at_or_above_200() {
    // CMD_TEST_PIN_LOCKOUT and CMD_TZIC_STATUS are documented to be
    // compiled-out unless `e2e-test` is set. Placing them in the
    // production range (< 200) risks them being reachable on a
    // mis-configured build.
    assert!(
        CMD_TEST_PIN_LOCKOUT >= 200,
        "CMD_TEST_PIN_LOCKOUT = {CMD_TEST_PIN_LOCKOUT} is below the documented test-only range (≥ 200)"
    );
    assert!(
        CMD_TZIC_STATUS >= 200,
        "CMD_TZIC_STATUS = {CMD_TZIC_STATUS} is below the documented test-only range (≥ 200)"
    );
}

#[test]
fn negative_production_cmds_stay_below_200() {
    let test_only: &[u32] = &[CMD_TEST_PIN_LOCKOUT, CMD_TZIC_STATUS];
    for &(cmd, name) in ALL_CMDS {
        if test_only.contains(&cmd) {
            continue;
        }
        assert!(
            cmd < 200,
            "{name} = {cmd} is in the test-only range (≥ 200) but is not declared as a test command"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// CMD_NONE = 0 — uninitialised mailbox memory must NOT decode to a
// live command. Zero is reserved.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_cmd_none_is_zero_and_no_live_cmd_uses_zero() {
    assert_eq!(CMD_NONE, 0);
    for &(cmd, name) in ALL_CMDS {
        if name == "CMD_NONE" {
            continue;
        }
        assert_ne!(
            cmd, 0,
            "{name} = 0 — clashes with CMD_NONE sentinel; a zero-initialised mailbox would dispatch into this handler"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// CMD range conventions documented in the lib.rs block comment
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_fw_cmds_live_in_documented_range_20_to_24() {
    let fw_cmds: &[(u32, &str)] = &[
        (CMD_FW_BEGIN, "CMD_FW_BEGIN"),
        (CMD_FW_CHUNK, "CMD_FW_CHUNK"),
        (CMD_FW_COMMIT, "CMD_FW_COMMIT"),
        (CMD_FW_STATUS, "CMD_FW_STATUS"),
        (CMD_FW_ABORT, "CMD_FW_ABORT"),
    ];
    for &(c, n) in fw_cmds {
        assert!(
            (20..=24).contains(&c),
            "{n} = {c} outside documented fw-update range 20..=24"
        );
    }
}

#[test]
fn negative_offchain_cmds_live_in_documented_range_16_to_18() {
    let off_cmds: &[(u32, &str)] = &[
        (CMD_SIGN_OFFCHAIN, "CMD_SIGN_OFFCHAIN"),
        (CMD_OFFCHAIN_STATUS, "CMD_OFFCHAIN_STATUS"),
        (CMD_OFFCHAIN_SYNC, "CMD_OFFCHAIN_SYNC"),
    ];
    for &(c, n) in off_cmds {
        assert!(
            (16..=18).contains(&c),
            "{n} = {c} outside documented off-chain range 16..=18"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// NscStatus — retired & unknown discriminants MUST map to InternalError
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_retired_status_8_maps_to_internal_error() {
    // Status 8 was SlotExhausted, retired post-C10. A firmware that
    // accidentally emits 8 must NOT be quietly classified as Ok or
    // recycled into a new meaning.
    let parsed = NscStatus::from(8);
    assert_eq!(
        parsed,
        NscStatus::InternalError,
        "NscStatus::from(8) must be InternalError (retired SlotExhausted); got {parsed:?}"
    );
}

#[test]
fn negative_reserved_status_9_maps_to_internal_error() {
    // Documented gap between IdleWipe (7) and FwUpdateBadState (10).
    let parsed = NscStatus::from(9);
    assert_eq!(parsed, NscStatus::InternalError);
}

#[test]
fn negative_unknown_status_discriminants_map_to_internal_error() {
    // Every value outside the documented set must fall through.
    let unknown_values: &[u32] = &[
        20, 21, 100, 0x1000, 0xCAFE_BABE, 0xFFFF_FFFE,
    ];
    for &v in unknown_values {
        let parsed = NscStatus::from(v);
        assert_eq!(
            parsed,
            NscStatus::InternalError,
            "NscStatus::from({v:#010x}) was {parsed:?} — unknown discriminants must NOT silently round-trip into a live variant"
        );
    }
}

#[test]
fn negative_status_discriminant_values_are_not_renumbered() {
    // Pinning the discriminant of every named variant. Firmware emits
    // these as raw u32s; renumbering is a wire-format break.
    assert_eq!(NscStatus::Ok as u32, 0);
    assert_eq!(NscStatus::PinIncorrect as u32, 1);
    assert_eq!(NscStatus::PinLocked as u32, 2);
    assert_eq!(NscStatus::CryptoError as u32, 3);
    assert_eq!(NscStatus::InvalidPointer as u32, 4);
    assert_eq!(NscStatus::NotInitialized as u32, 5);
    assert_eq!(NscStatus::UserRejected as u32, 6);
    assert_eq!(NscStatus::IdleWipe as u32, 7);
    assert_eq!(NscStatus::FwUpdateBadState as u32, 10);
    assert_eq!(NscStatus::FwUpdateBadManifest as u32, 11);
    assert_eq!(NscStatus::FwUpdateBadVersion as u32, 12);
    assert_eq!(NscStatus::FwUpdateBadChunk as u32, 13);
    assert_eq!(NscStatus::FwUpdateBadImage as u32, 14);
    assert_eq!(NscStatus::FwUpdateFlashError as u32, 15);
    assert_eq!(NscStatus::FwUpdateOtpExhausted as u32, 16);
    assert_eq!(NscStatus::OffchainSlotUnregistered as u32, 17);
    assert_eq!(NscStatus::OffchainGapExceeded as u32, 18);
    assert_eq!(NscStatus::OffchainCapExceeded as u32, 19);
    assert_eq!(NscStatus::InternalError as u32, u32::MAX);
}

// ───────────────────────────────────────────────────────────────────────
// CMD_TZIC_STATUS — documented to NOT require PIN unlock. Test that it
// is *numerically distinct* from any unlock-required CMD so the
// firmware dispatcher can route on the ID alone. (Pure structural
// negative: an aliasing CMD would route a no-auth command into an
// auth-required handler or vice-versa.)
// ───────────────────────────────────────────────────────────────────────

#[test]
fn negative_test_cmds_pairwise_distinct() {
    assert_ne!(CMD_TEST_PIN_LOCKOUT, CMD_TZIC_STATUS);
}
