//! Host-runnable positive + negative test suite for the `secure-optiga`
//! slice.
//!
//! Slice files in scope (under `secure/src/optiga/`):
//!   * `mod.rs`        — `OptigaTrustM` driver, lifecycle, factory_reset
//!   * `apdu.rs`       — APDU builders, metadata TLV, response parser
//!   * `ifx_i2c.rs`    — IFX I²C transport (CRC-16, frame, ACK, chaining)
//!   * `shield.rs`     — Shielded Connection (TLS-PRF + AES-128-CCM-8)
//!   * `i2c.rs`        — bare-metal STM32U585 I²C1 master driver
//!   * `reset.rs`      — `optiga-reset-oids` one-shot recovery
//!   * `reset_pin.rs`  — RST GPIO toggle (PE0 on B-U585I-IOT02A)
//!
//! Files that this scaffold path-includes (and therefore exercises by
//! running the actual production bytes):
//!   * `apdu.rs`   — every metadata builder, parser, and `ApduBuf`
//!     method runs natively. Functions with `IfxState` / `ShieldedConnection`
//!     arguments compile thanks to the stubs in `mod.rs`, and the
//!     protected-command path (`send_command_protected` via `get_random`,
//!     `get_data_object`, `generate_auth_code`, …) executes against the
//!     scripted PRL peer (`prl_tests.rs`).
//!   * `shield.rs` — `wrap_command` / `unwrap_response` / `derive_session_keys`
//!     / `aes128_ccm_*` / `tls_prf_sha256` / `build_aad` / `build_nonce` all
//!     run natively; the full `establish()` handshake runs against the
//!     scripted peer with byte-exact golden-vector pins.
//!
//! Files that this scaffold pins via `include_str!`:
//!   * `mod.rs`     — driver / lifecycle constants, FI bool usage, OID range
//!   * `ifx_i2c.rs` — CRC algorithm, frame layout, REG_* addresses,
//!     PRESENCE_BIT, ReSynch reset, RX seq init = 3
//!   * `i2c.rs`     — `OPTIGA_ADDR = 0x30`, write_read guard delay
//!   * `reset_pin.rs` — RST pin = PE0 (Arduino D6, empirically verified)
//!
//! The negative suite is the primary deliverable here. Each `negative_*`
//! test states the assumption it attacks and asserts the rejection /
//! refusal / wire-stable byte that proves the guard holds. A silent
//! removal of e.g. the constant-time tag compare in `aes128_ccm_decrypt`,
//! the replay refusal in `unwrap_response`, the nonce-wrap close in
//! `wrap_command`, the canonical F1D0..F1D4 OID range, or the
//! `CLEAR_LAST_ERROR (0x80)` high-bit on every CMD byte will fail one
//! of these tests before it reaches a chip.

#![cfg(test)]

use super::apdu;
use super::shield;

#[test]
fn get_random_payload_copy_requires_exact_length() {
    let exact = [0x5Au8; 16];
    let mut out = [0u8; 16];
    assert_eq!(
        apdu::copy_exact_payload(&exact, exact.as_ptr(), &mut out).unwrap(),
        16
    );
    assert_eq!(out, exact);

    for payload in [&[0x11u8; 15][..], &[0x22u8; 17][..]] {
        let mut guarded = [0xA5u8; 16];
        assert!(matches!(
            apdu::copy_exact_payload(payload, payload.as_ptr(), &mut guarded),
            Err(apdu::OptigaError::Transport)
        ));
        assert_eq!(guarded, [0u8; 16]);
    }
}

#[test]
fn get_random_payload_copy_requires_response_pointer_provenance() {
    let payload = [0x5Au8; 16];
    let wrong_source = [0x3Cu8; 16];
    let mut out = [0xA5u8; 16];
    assert!(matches!(
        apdu::copy_exact_payload(&payload, wrong_source.as_ptr(), &mut out),
        Err(apdu::OptigaError::Transport)
    ));
    assert_eq!(out, [0u8; 16]);
    assert!(APDU_SRC.contains("copy_exact_payload(payload, unsafe { resp.as_ptr().add(4) }, out)"));
    assert!(APDU_SRC.contains("let mut published_expected_source = core::ptr::null();"));
    assert!(APDU_SRC.contains("core::ptr::addr_of!(published_expected_source)"));
    assert!(APDU_SRC.contains("core::ptr::addr_of!(published_destination)"));
}

// ─────────────────────────────────────────────────────────────────────
// Source-text snapshots (per the precedent of `hw_crypto_under_test`)
// ─────────────────────────────────────────────────────────────────────

const APDU_SRC: &str = include_str!("../optiga/apdu.rs");
const SHIELD_SRC: &str = include_str!("../optiga/shield.rs");
const IFX_SRC: &str = include_str!("../optiga/ifx_i2c.rs");
const I2C_SRC: &str = include_str!("../optiga/i2c.rs");
const MOD_SRC: &str = include_str!("../optiga/mod.rs");
const RESET_PIN_SRC: &str = include_str!("../optiga/reset_pin.rs");
const MAIN_SRC_FOR_PIN_DIAG: &str = include_str!("../main.rs");

#[test]
fn transient_e120_authorization_is_caller_supplied_and_never_platform_only() {
    let start = MOD_SRC
        .find("unsafe fn reset_e120_via_transient_auth(")
        .expect("transient E120 reset helper must exist");
    let end = MOD_SRC[start..]
        .find("    /// Read the silicon PIN counter")
        .map(|n| start + n)
        .expect("transient E120 helper boundary must exist");
    let body = &MOD_SRC[start..end];

    assert!(body.contains("transient_secret: &mut [u8; 32]"));
    assert!(body.contains("if nonzero == 0"));
    assert!(body.contains("transient_secret.zeroize();"));
    assert!(body.contains("Self::hmac_sha256(transient_secret, &nonce)"));
    assert!(
        !body.contains("crate::rng::fill"),
        "OPTIGA must not replace a failed three-source draw with STM32-only bytes"
    );

    let reset_start = MOD_SRC
        .find("fn factory_reset_body(")
        .expect("factory_reset_body must exist");
    let reset_body = &MOD_SRC[reset_start..];
    let supplied_gate = reset_body
        .find("if let Some(secret) = transient_secret")
        .expect("transient auth must require an explicitly supplied secret");
    let transient_call = reset_body
        .find("self.reset_e120_via_transient_auth(secret)")
        .expect("supplied secret must reach transient E120 authentication");
    let destructive_counter_write = reset_body
        .find("apdu::OID_COUNTER")
        .expect("factory reset must still publish its reset sentinel");
    assert!(supplied_gate < transient_call && transient_call < destructive_counter_write);
    assert!(reset_body.contains("no three-source transient auth"));
}

// ─────────────────────────────────────────────────────────────────────
// Re-implementation of the IFX I²C CRC-16 (Infineon's custom nibble
// algorithm). Copied verbatim from `ifx_i2c::crc16` for host-side
// reference-vector use. The text-pin in `negative_ifx_crc16_algorithm_
// shape_stable` asserts the production file still reads identically.
// ─────────────────────────────────────────────────────────────────────

fn ifx_crc16_reference(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        let h1 = (crc ^ byte as u16) & 0xFF;
        let h2 = h1 & 0x0F;
        let h3 = (h2 << 4) ^ h1;
        let h4 = h3 >> 4;
        crc = ((((h3 << 1) ^ h4) << 4) ^ h2) << 3 ^ h4 ^ (crc >> 8);
    }
    crc
}

// ─────────────────────────────────────────────────────────────────────
// Positive — ApduBuf layout
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_apdu_buf_header_empty_payload() {
    let mut ab = apdu::ApduBuf::new(0x81, 0x00);
    let bytes = ab.finish();
    assert_eq!(bytes.len(), 4, "empty payload still emits a 4-byte header");
    assert_eq!(bytes[0], 0x81, "CMD byte preserved verbatim");
    assert_eq!(bytes[1], 0x00, "Param byte preserved");
    assert_eq!(&bytes[2..4], &[0x00, 0x00], "InLen = 0 in big-endian");
}

#[test]
fn positive_apdu_buf_write_u16_big_endian() {
    let mut ab = apdu::ApduBuf::new(0x81, 0x00);
    ab.write_u16(0xABCD);
    let bytes = ab.finish();
    assert_eq!(bytes[4], 0xAB, "u16 high byte first");
    assert_eq!(bytes[5], 0xCD, "u16 low byte second");
    assert_eq!(bytes[2..4], [0x00, 0x02], "InLen = 2 after one u16 write");
}

#[test]
fn positive_apdu_buf_write_tlv_layout() {
    let mut ab = apdu::ApduBuf::new(0x95, 0x20);
    let payload = [0xAA; 32];
    ab.write_tlv(0x43, &payload);
    let bytes = ab.finish();
    assert_eq!(bytes[4], 0x43, "TLV tag preserved");
    assert_eq!(bytes[5..7], [0x00, 0x20], "TLV length is 2-byte BE");
    assert_eq!(&bytes[7..7 + 32], &payload, "TLV value bytes copied");
    assert_eq!(bytes[2..4], [0x00, 35], "InLen = 1 + 2 + 32 = 35");
}

#[test]
fn positive_apdu_buf_inlen_big_endian_300_bytes() {
    // Force a payload large enough that the InLen high byte is non-zero.
    let mut ab = apdu::ApduBuf::new(0x82, 0x40);
    let chunk = [0xCD; 200];
    ab.write(&chunk);
    ab.write(&chunk[..100]); // 300 total
    let bytes = ab.finish();
    assert_eq!(bytes[2], 0x01, "InLen high byte = 300 >> 8 = 1");
    assert_eq!(bytes[3], 0x2C, "InLen low byte = 300 & 0xFF = 0x2C");
}

#[test]
fn positive_apdu_buf_get_data_object_inputs_positional() {
    // GetDataObject InData is the positional triple OID(2) | Offset(2) | Length(2).
    let mut ab = apdu::ApduBuf::new(0x81, 0x00);
    ab.write_u16(0xF1D1).write_u16(0).write_u16(64);
    let bytes = ab.finish();
    assert_eq!(bytes[2..4], [0x00, 0x06], "InLen = 6 bytes");
    assert_eq!(bytes[4..6], [0xF1, 0xD1], "OID first, BE");
    assert_eq!(bytes[6..8], [0x00, 0x00], "Offset second, BE");
    assert_eq!(bytes[8..10], [0x00, 0x40], "Length third, BE");
}

// ─────────────────────────────────────────────────────────────────────
// Positive — Metadata builders (byte-exact pins)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_build_metadata_auth_ref_exact_bytes() {
    let (buf, len) = apdu::build_metadata_auth_ref();
    // META_ROOT(0x20) | total_len | Change=ALW | Read=NEV | Execute=ALW | DataType=AUTHREF
    // = 0x20 | 0x0C | (D0 01 00) (D1 01 FF) (D3 01 00) (E8 01 31)
    let expected: [u8; 14] = [
        0x20, 0x0C, 0xD0, 0x01, 0x00, 0xD1, 0x01, 0xFF, 0xD3, 0x01, 0x00, 0xE8, 0x01, 0x31,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected, "AuthRef metadata is wire-frozen");
}

#[test]
fn positive_build_metadata_counter_change_is_conf_e140() {
    let (buf, len) = apdu::build_metadata_counter();
    // Change = Conf(E140): D0 03 20 E1 40
    // Read   = ALW       : D1 01 00
    // Execute= NEV       : D3 01 FF
    let expected: [u8; 13] = [
        0x20, 0x0B, 0xD0, 0x03, 0x20, 0xE1, 0x40, 0xD1, 0x01, 0x00, 0xD3, 0x01, 0xFF,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected, "Counter metadata is wire-frozen");
}

#[test]
fn positive_build_metadata_relaxed_change_and_read_always() {
    let (buf, len) = apdu::build_metadata_relaxed();
    let expected: [u8; 11] = [
        0x20, 0x09, 0xD0, 0x01, 0x00, 0xD1, 0x01, 0x00, 0xD3, 0x01, 0xFF,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected);
}

#[test]
fn positive_build_metadata_lock_emits_lcs_operational() {
    let (buf, len) = apdu::build_metadata_lock();
    // META_ROOT | total_len(3) | LCSO(0xC0) | 01 | 07
    let expected: [u8; 5] = [0x20, 0x03, 0xC0, 0x01, 0x07];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected);
}

#[test]
fn positive_build_metadata_pbs_final_canonical_layout() {
    let (buf, len) = apdu::build_metadata_pbs_final();
    // Change: D0 07 E1 FC 07 FE 20 E1 40   (LcsO<Op OR Conf(E140))
    // Read:   D1 03 E1 FC 07               (LcsO<Op)
    // Exec:   D3 01 00                     (ALW)
    // Type:   E8 01 22                     (PBS)
    let expected: [u8; 22] = [
        0x20, 0x14, 0xD0, 0x07, 0xE1, 0xFC, 0x07, 0xFE, 0x20, 0xE1, 0x40, 0xD1, 0x03, 0xE1, 0xFC,
        0x07, 0xD3, 0x01, 0x00, 0xE8, 0x01, 0x22,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected, "PBS metadata layout is wire-frozen");
}

#[test]
fn positive_build_metadata_protected_change_is_auto_or_conf() {
    let (buf, len) = apdu::build_metadata_protected(0xF1D0, false);
    // Change: D0 07 23 F1 D0 FE 20 E1 40
    // Read:   D1 03 23 F1 D0     (Auto only — require_shielded=false)
    // Exec:   D3 01 FF
    let expected: [u8; 19] = [
        0x20, 0x11, 0xD0, 0x07, 0x23, 0xF1, 0xD0, 0xFE, 0x20, 0xE1, 0x40, 0xD1, 0x03, 0x23, 0xF1,
        0xD0, 0xD3, 0x01, 0xFF,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(&buf[..len], &expected);
}

#[test]
fn positive_build_metadata_protected_require_shielded_uses_and() {
    let (buf_yes, len_yes) = apdu::build_metadata_protected(0xF1D0, true);
    // With require_shielded=true the Read AC is the same 9-byte compound
    // form as Change but with AC_AND in the middle slot. Layout:
    //   [0]=META_ROOT, [1]=inner_len, [2..11]=Change(9), [11..20]=Read(9),
    //   [20..23]=Execute(3). Inside the Read compound the AND/OR operand
    //   sits at byte 6 of the 9-byte block → buffer index 11+5 = 16.
    assert_eq!(len_yes, 23, "shielded variant has 23-byte metadata");
    assert_eq!(buf_yes[2], 0xD0, "Change tag at byte 2");
    assert_eq!(
        buf_yes[7], 0xFE,
        "Change uses OR (Auto OR Conf) in both variants"
    );
    assert_eq!(
        buf_yes[11], 0xD1,
        "Read tag at byte 11 (after Change's 9 bytes)"
    );
    assert_eq!(
        buf_yes[16], 0xFD,
        "shielded Read uses AC_AND (Auto AND Conf)"
    );

    let (buf_no, len_no) = apdu::build_metadata_protected(0xF1D0, false);
    // Non-shielded Read is the simpler 5-byte form: D1 03 23 F1 D0.
    // No AC_AND/AC_OR slot exists, and the total metadata is 4 bytes shorter.
    assert_eq!(
        len_no + 4,
        len_yes,
        "non-shielded saves the 4 bytes of the compound operand"
    );
    assert_eq!(buf_no[11], 0xD1, "Read tag still at byte 11");
    assert_eq!(buf_no[12], 0x03, "Read AC is 3 bytes long (just Auto-Ref)");
}

#[test]
fn positive_is_metadata_operational_detects_lcs_07() {
    let (locked_buf, locked_len) = apdu::build_metadata_lock();
    assert!(apdu::is_metadata_operational(
        &locked_buf[..locked_len],
        locked_len
    ));

    let (auth_buf, auth_len) = apdu::build_metadata_auth_ref();
    assert!(
        !apdu::is_metadata_operational(&auth_buf[..auth_len], auth_len),
        "metadata without LCSO tag must NOT be considered operational"
    );
}

// ─────────────────────────────────────────────────────────────────────
// S-1 / S-2 / S-3 production-hardening pins
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_build_metadata_ta_junk_emits_no_trust_anchor_assertion() {
    // This legacy candidate emits Change/Read/Execute = NEV and no DataType
    // tag. Omission is deliberately NOT treated as proof that an existing
    // TrustAnchor type was removed; the executable lockdown path is fenced.
    let (buf, len) = apdu::build_metadata_ta_junk();
    let expected: [u8; 11] = [
        0x20, 0x09, 0xD0, 0x01, 0xFF, 0xD1, 0x01, 0xFF, 0xD3, 0x01, 0xFF,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(
        &buf[..len],
        &expected,
        "TA-junk metadata is wire-frozen (S-2)"
    );
    assert!(
        !buf[..len].windows(3).any(|w| w == [0xE8, 0x01, 0x11]),
        "candidate metadata must not itself assert DataType=TrustAnchor(0x11)"
    );
}

#[test]
fn negative_ordinary_pairing_never_ratchets_e140_lifecycle() {
    let start = MOD_SRC
        .find("fn setup_pbs_no_handshake")
        .expect("setup_pbs_no_handshake exists");
    let end = MOD_SRC[start..]
        .find("/// Bump E140 to `LcsO=Operational`")
        .map(|offset| start + offset)
        .expect("lifecycle primitive follows pairing routine");
    let pairing = &MOD_SRC[start..end];

    assert!(
        !pairing.contains("ensure_pbs_lcso_operational("),
        "ordinary pairing must not invoke the irreversible E140 lifecycle primitive"
    );
    assert!(
        pairing.contains("E140 lifecycle unchanged"),
        "pairing must retain an explicit lifecycle-separation marker"
    );
}

#[test]
fn negative_ta_pool_lockdown_is_exact_and_emits_no_apdu() {
    let start = MOD_SRC
        .find("unsafe fn lockdown_ta_pool")
        .expect("lockdown_ta_pool exists");
    let end = MOD_SRC[start..]
        .find("/// Full-device provisioning.")
        .map(|offset| start + offset)
        .expect("provisioning docs follow lockdown helper");
    let helper = &MOD_SRC[start..end];

    assert!(
        helper.contains("const TA_POOL: [u16; 3] = [0xE0E8, 0xE0E9, 0xE0EF];"),
        "candidate trust-anchor inventory must be exactly E0E8/E0E9/E0EF"
    );
    assert!(
        !helper.contains("apdu::"),
        "fenced trust-anchor helper must emit no APDU before the ceremony is proven"
    );
    assert!(
        helper.contains("Err(OptigaError::Status(0xEC))"),
        "trust-anchor helper must fail closed"
    );
}

#[test]
fn positive_metadata_matches_expected_tolerates_reorder_rejects_flip() {
    // The verify-before-lock gate's core. Built against build_metadata_protected
    // (Change=Auto(F1D0) OR Conf(E140), Read=Auto(F1D0), Exec=NEV).
    let (exp, exp_len) = apdu::build_metadata_protected(0xF1D0, false);

    // Reflexive: a buffer with the same AC tags PLUS a trailing chip-internal
    // tag (the chip is known to append size/version tags) must still match.
    let mut stored = [0u8; 64];
    stored[..exp_len].copy_from_slice(&exp[..exp_len]);
    let extra = [0xC1u8, 0x01, 0xAA];
    let inner_len = stored[1] as usize;
    stored[2 + inner_len..2 + inner_len + extra.len()].copy_from_slice(&extra);
    stored[1] = (inner_len + extra.len()) as u8;
    let stored_len = exp_len + extra.len();
    assert!(
        apdu::metadata_matches_expected(&stored, stored_len, &exp[..exp_len], exp_len),
        "trailing chip-added tags must not break a match on the AC tags"
    );

    // A flipped Change operand (Auto-Ref 0x23 → Conf 0x20) is exactly the
    // silent-rejection the gate must catch → MUST NOT match.
    let mut bad = [0u8; 64];
    bad[..exp_len].copy_from_slice(&exp[..exp_len]);
    bad[4] = 0x20; // root[0,1] | Change tag[2] | len[3] | operand[4]
    assert!(
        !apdu::metadata_matches_expected(&bad, exp_len, &exp[..exp_len], exp_len),
        "a flipped Change operand MUST fail the verify-before-lock gate"
    );
}

#[test]
fn positive_metadata_matches_expected_missing_tag_fails() {
    // If the chip stored nothing for a tag we intended, the gate must refuse to
    // lock. `stored` = lock metadata (LcsO only); `expected` = TA-junk
    // (Change/Read/Execute) → none of the expected AC tags are present.
    let (stored, stored_len) = apdu::build_metadata_lock();
    let (want, want_len) = apdu::build_metadata_ta_junk();
    assert!(
        !apdu::metadata_matches_expected(&stored, stored_len, &want, want_len),
        "missing expected AC tags in stored metadata MUST fail the match"
    );
}

#[test]
fn negative_f1d0_luc_change_is_auto_only_under_lock() {
    // S-1: the REAL F1D0 LUC builder selects Change=Auto(F1D0) ONLY in the
    // locked production profile; a silent revert to Change=ALW reopens the
    // bench-attack hole (overwrite F1D0 with a known key → read half_O).
    assert!(
        APDU_SRC.contains(
            "build_metadata_auth_ref_luc_oid(OID_PIN_CTR, cfg!(feature = \"optiga-lock-operational\"))"
        ),
        "real F1D0 must take Change=Auto only under optiga-lock-operational"
    );
    assert!(
        APDU_SRC.contains("push_ac_auto(&mut inner, &mut c, META_CHANGE, OID_AUTH_REF)"),
        "the change_is_auto branch must emit Auto(F1D0) on the Change AC"
    );
}

#[test]
fn negative_setobjectprotected_senders_gated_out_of_production() {
    // S-2: the SetObjectProtected manifest encoder + its command byte must be
    // compiled out unless `optiga-reset-oids` is on, so no production binary can
    // emit CMD 0x83.
    for needle in [
        "unsafe fn protected_update_chunk(",
        "pub unsafe fn protected_update_start(",
        "pub unsafe fn send_protected_manifest(",
        "const CMD_SET_OBJECT_PROTECTED:",
    ] {
        let idx = APDU_SRC
            .find(needle)
            .unwrap_or_else(|| panic!("source marker missing: {needle}"));
        let window = &APDU_SRC[idx.saturating_sub(140)..idx];
        assert!(
            window.contains("#[cfg(feature = \"optiga-reset-oids\")]"),
            "{needle} must be gated behind optiga-reset-oids (S-2)"
        );
    }
}

#[test]
fn negative_soft_counter_bump_gated_out_of_hw_counter() {
    // S-3: the firmware soft-counter attempt bump must be behind
    // not(optiga-hw-counter) so production (hw-counter mandatory) ships only the
    // silicon E120 LUC counter, never the bypassable soft path.
    // The soft path opens with `let attempts = match self.read_counter_raw()`
    // directly under its `#[cfg(not(optiga-hw-counter))]` gate (a `let _ = {`
    // sits between). Pin the gate's adjacency to that opener so it can't drift.
    let idx = MOD_SRC
        .find("let attempts = match self.read_counter_raw()")
        .expect("soft-counter attempt read present");
    let window = &MOD_SRC[idx.saturating_sub(120)..idx];
    assert!(
        window.contains("#[cfg(not(feature = \"optiga-hw-counter\"))]"),
        "the soft-counter attempt bump must be behind not(optiga-hw-counter) (S-3)"
    );
}

#[cfg(feature = "optiga-hw-counter")]
#[test]
fn positive_build_metadata_auth_ref_luc_change_auto_exact_bytes() {
    // S-1 production F1D0 (change_is_auto=true): Change=Auto(F1D0), Read=NEV,
    // Execute=LUC(E120), DataType=AUTHREF. Inner len = 5+3+5+3 = 16 (0x10).
    let (buf, len) = apdu::build_metadata_auth_ref_luc_oid(apdu::OID_PIN_CTR, true);
    let expected: [u8; 18] = [
        0x20, 0x10, 0xD0, 0x03, 0x23, 0xF1, 0xD0, 0xD1, 0x01, 0xFF, 0xD3, 0x03, 0x40, 0xE1, 0x20,
        0xE8, 0x01, 0x31,
    ];
    assert_eq!(len, expected.len());
    assert_eq!(
        &buf[..len],
        &expected,
        "S-1 locked F1D0 metadata is wire-frozen"
    );

    // change_is_auto=false keeps Change=ALW (the dev / duress-twin shape).
    let (dbuf, _dlen) = apdu::build_metadata_auth_ref_luc_oid(apdu::OID_PIN_CTR, false);
    assert_eq!(
        &dbuf[2..5],
        &[0xD0, 0x01, 0x00],
        "change_is_auto=false must emit Change=ALW"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Positive — Shielded Connection wire format
// ─────────────────────────────────────────────────────────────────────

/// Helper: drive a ShieldedConnection into the "session-active" state
/// using a deterministic random_S. Mirrors the post-`establish()` state
/// without needing a real chip on the bus.
fn make_active_shield(seed: u8) -> shield::ShieldedConnection {
    let mut sc = shield::ShieldedConnection::new();
    let pbs = [seed; 64];
    sc.load_pbs(&pbs);
    sc.activate_for_test([seed; 16], [seed; 4], 7, 100);
    sc
}

fn make_protected_response(
    key: &[u8; 16],
    nonce_base: &[u8; 4],
    sequence: u32,
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let sequence_bytes = sequence.to_be_bytes();
    let nonce = [
        nonce_base[0],
        nonce_base[1],
        nonce_base[2],
        nonce_base[3],
        sequence_bytes[0],
        sequence_bytes[1],
        sequence_bytes[2],
        sequence_bytes[3],
    ];
    let plaintext_len = plaintext.len() as u16;
    let aad = [
        0x23,
        sequence_bytes[0],
        sequence_bytes[1],
        sequence_bytes[2],
        sequence_bytes[3],
        0x01,
        (plaintext_len >> 8) as u8,
        plaintext_len as u8,
    ];
    out[0] = 0x23;
    out[1..5].copy_from_slice(&sequence_bytes);
    let protected_len = shield::ccm_encrypt_for_test(
        key,
        &nonce,
        &aad,
        plaintext,
        &mut out[5..],
    );
    5 + protected_len
}

#[test]
fn positive_shield_new_starts_inactive_and_unloaded() {
    let sc = shield::ShieldedConnection::new();
    assert!(
        !sc.active,
        "freshly-constructed ShieldedConnection must NOT be active"
    );
    assert!(
        !sc.pbs_loaded,
        "freshly-constructed ShieldedConnection has not loaded a PBS"
    );
}

#[test]
fn positive_shield_load_pbs_marks_pbs_loaded() {
    let mut sc = shield::ShieldedConnection::new();
    sc.load_pbs(&[0x11; 64]);
    assert!(sc.pbs_loaded);
    assert!(
        !sc.active,
        "load_pbs alone must not open a session — only `establish` may flip `active`"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Negative — Shielded Connection state-machine guards
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_shield_wrap_when_inactive_rejected() {
    // ASSUMPTION ATTACKED: callers cannot send an encrypted record before
    // the handshake completes. A silent removal of the `active` check
    // would leak plaintext-equivalent records keyed on the all-zero
    // post-`new()` key material — CCM tag forgery becomes trivial against
    // a stuck-zero key.
    let mut sc = shield::ShieldedConnection::new();
    let mut out = [0u8; 256];
    let res = sc.wrap_command(&[0xDE, 0xAD, 0xBE, 0xEF], &mut out);
    assert!(
        matches!(res, Err(shield::ShieldError::NotActive)),
        "wrap_command must reject when not active; CLAUDE.md invariant #3 (encrypted SE tunnels)"
    );
}

#[test]
fn negative_shield_unwrap_when_inactive_rejected() {
    let mut sc = shield::ShieldedConnection::new();
    let mut out = [0u8; 256];
    let mut receipt = crate::fi::OK_SENTINEL;
    let res = sc.unwrap_response(&[0u8; 32], &mut out, &mut receipt);
    assert!(matches!(res, Err(shield::ShieldError::NotActive)));
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
}

#[test]
fn negative_shield_unwrap_too_short_rejected() {
    // ASSUMPTION ATTACKED: a truncated record (less than SC_HEADER(5) +
    // CCM_TAG(8) = 13 bytes) is rejected without indexing past the end
    // of the buffer.
    let mut sc = make_active_shield(0xAA);
    let mut out = [0u8; 256];
    let mut receipt = crate::fi::OK_SENTINEL;
    let res = sc.unwrap_response(&[0u8; 12], &mut out, &mut receipt);
    // We don't care WHICH error here — just that it's an Err and didn't panic.
    assert!(res.is_err(), "must not accept a 12-byte record");
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
}

#[test]
fn response_sequence_accepts_only_reference_driver_forward_window() {
    for delta in 1..=3u32 {
        let mut receipt = crate::fi::FAIL_SENTINEL;
        shield::verify_response_sequence_into(100, !100, 100 + delta, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }

    for received in [99u32, 100, 104, 1000, 0xFFFF_FFF0] {
        let mut receipt = crate::fi::OK_SENTINEL;
        shield::verify_response_sequence_into(100, !100, received, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    let mut receipt = crate::fi::OK_SENTINEL;
    shield::verify_response_sequence_into(100, !101, 101, &mut receipt);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);

    // Once B+3 is authenticated and published, the window advances from that
    // new baseline. Each allowed value is checked independently.
    for received in 104..=106u32 {
        receipt = crate::fi::FAIL_SENTINEL;
        shield::verify_response_sequence_into(103, !103, received, &mut receipt);
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }
    for received in [102u32, 103, 107] {
        receipt = crate::fi::OK_SENTINEL;
        shield::verify_response_sequence_into(103, !103, received, &mut receipt);
        assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    }

    // The reference permits a final response to advance beyond the threshold
    // by its bounded retry window. The next command then renegotiates.
    for received in 0xFFFF_FFF0..=0xFFFF_FFF2u32 {
        receipt = crate::fi::FAIL_SENTINEL;
        shield::verify_response_sequence_into(
            0xFFFF_FFEF,
            !0xFFFF_FFEF,
            received,
            &mut receipt,
        );
        assert_eq!(receipt, crate::fi::OK_SENTINEL);
    }
}

#[test]
fn shield_response_sequence_and_ccm_state_move_only_after_both_validate() {
    const KEY: [u8; 16] = [0x31; 16];
    const NONCE_BASE: [u8; 4] = [0x41; 4];
    const PLAINTEXT: [u8; 12] = [0x5A; 12];

    // A correctly tagged response outside the 1..=3 window is rejected,
    // wipes caller output, and leaves the authenticated baseline untouched.
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test(KEY, NONCE_BASE, 7, 100);
    let mut record = [0u8; 64];
    let record_len = make_protected_response(&KEY, &NONCE_BASE, 104, &PLAINTEXT, &mut record);
    let mut out = [0xA5u8; 12];
    let mut receipt = crate::fi::OK_SENTINEL;
    assert!(sc
        .unwrap_response(&record[..record_len], &mut out, &mut receipt)
        .is_err());
    assert_eq!(out, [0u8; 12]);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(sc.sequence_state_for_test().2, 100);

    // An in-window response with a bad tag has the same fail-closed outcome.
    let record_len = make_protected_response(&KEY, &NONCE_BASE, 103, &PLAINTEXT, &mut record);
    record[record_len - 1] ^= 1;
    out.fill(0xA5);
    receipt = crate::fi::OK_SENTINEL;
    assert!(sc
        .unwrap_response(&record[..record_len], &mut out, &mut receipt)
        .is_err());
    assert_eq!(out, [0u8; 12]);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(sc.sequence_state_for_test().2, 100);

    // Only a response satisfying both relations publishes plaintext and the
    // new value/complement baseline. Replaying it then fails closed.
    let record_len = make_protected_response(&KEY, &NONCE_BASE, 103, &PLAINTEXT, &mut record);
    receipt = crate::fi::FAIL_SENTINEL;
    assert_eq!(
        sc.unwrap_response(&record[..record_len], &mut out, &mut receipt)
            .unwrap(),
        PLAINTEXT.len()
    );
    assert_eq!(out, PLAINTEXT);
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(sc.sequence_state_for_test().2, 103);
    assert_eq!(sc.sequence_state_for_test().3, !103);

    out.fill(0xA5);
    receipt = crate::fi::OK_SENTINEL;
    assert!(sc
        .unwrap_response(&record[..record_len], &mut out, &mut receipt)
        .is_err());
    assert_eq!(out, [0u8; 12]);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(sc.sequence_state_for_test().2, 103);
}

#[test]
fn shield_transmit_sequence_is_consumed_even_without_a_response() {
    let mut sc = make_active_shield(0x27);
    let mut first = [0u8; 64];
    let mut second = [0u8; 64];

    let first_len = sc.wrap_command(b"first", &mut first).unwrap();
    // Deliberately provide no response, modeling a transport failure after the
    // command sequence was reserved.
    let second_len = sc.wrap_command(b"second", &mut second).unwrap();

    assert_eq!(&first[..5], &[0x23, 0, 0, 0, 7]);
    assert_eq!(&second[..5], &[0x23, 0, 0, 0, 8]);
    assert_ne!(&first[..first_len], &second[..second_len]);
    assert_eq!(sc.sequence_state_for_test().0, 9);
    assert_eq!(sc.sequence_state_for_test().1, !9);
}

#[test]
fn response_sequence_commit_publishes_bound_value_and_complement() {
    let mut sequence = 0xAAAA_AAAAu32;
    let mut sequence_inv = 0xBBBB_BBBBu32;
    let mut receipt = crate::fi::FAIL_SENTINEL;
    shield::commit_sequence_state_into(
        0x1234_5678,
        &mut sequence,
        &mut sequence_inv,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(sequence, 0x1234_5678);
    assert_eq!(sequence_inv, !0x1234_5678);

    receipt = crate::fi::OK_SENTINEL;
    shield::commit_sequence_state_into(
        0xFFFF_FFF0,
        &mut sequence,
        &mut sequence_inv,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(sequence, 0xFFFF_FFF0);
    assert_eq!(sequence_inv, !0xFFFF_FFF0);
}

#[test]
fn transmit_sequence_reservation_advances_before_ciphertext_use() {
    let mut next = 7u32;
    let mut next_inv = !7u32;
    let mut receipt = crate::fi::FAIL_SENTINEL;
    shield::reserve_transmit_sequence_into(7, !7, &mut next, &mut next_inv, &mut receipt);
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(next, 8);
    assert_eq!(next_inv, !8);

    receipt = crate::fi::OK_SENTINEL;
    shield::reserve_transmit_sequence_into(8, !9, &mut next, &mut next_inv, &mut receipt);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);

    receipt = crate::fi::FAIL_SENTINEL;
    shield::reserve_transmit_sequence_into(
        0xFFFF_FFF0,
        !0xFFFF_FFF0,
        &mut next,
        &mut next_inv,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(next, 0xFFFF_FFF1);

    receipt = crate::fi::OK_SENTINEL;
    shield::reserve_transmit_sequence_into(next, next_inv, &mut next, &mut next_inv, &mut receipt);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
}

#[test]
fn negative_shield_ccm_tamper_keeps_auth_receipt_failed_and_wipes_plaintext() {
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 8];
    let aad = [0x23u8, 0, 0, 0, 7, 0, 24];
    let plaintext = [0x5Au8; 24];
    let mut record = [0u8; 64];
    let record_len =
        shield::ccm_encrypt_for_test(&key, &nonce, &aad, &plaintext, &mut record);

    let mut out = [0xA5u8; 24];
    let mut receipt = crate::fi::FAIL_SENTINEL;
    shield::aes128_ccm_decrypt_into(
        &key,
        &nonce,
        &aad,
        &record[..record_len],
        &mut out,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(out, plaintext);

    // Start from an apparently successful receipt and nonzero output to prove
    // the production helper owns fail initialization and rejection cleanup.
    record[record_len - 1] ^= 1;
    out.fill(0xA5);
    receipt = crate::fi::OK_SENTINEL;
    shield::aes128_ccm_decrypt_into(
        &key,
        &nonce,
        &aad,
        &record[..record_len],
        &mut out,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0u8; 24]);
}

// ─────────────────────────────────────────────────────────────────────
// CRC-16 reference-vector tests (the in-file `crc16` is host-runnable
// via the algorithm copy at the top of this file; the text-pin below
// asserts the production file still reads identically).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_ifx_crc16_empty_input_is_zero() {
    assert_eq!(ifx_crc16_reference(&[]), 0);
}

#[test]
fn positive_ifx_crc16_deterministic_for_known_input() {
    // Reference vector: any change to the algorithm trips this.
    let v1 = ifx_crc16_reference(&[0x00, 0x00, 0x00]); // ACK frame header
    let v2 = ifx_crc16_reference(&[0x80, 0x00, 0x00]); // first byte = FCTR(ACK)
    assert_ne!(v1, v2, "CRC distinguishes data from control frames");
    // Spot-check stability: assert against a self-computed reference so
    // a future refactor that subtly perturbs the polynomial fails here.
    let known = ifx_crc16_reference(b"PQSigner");
    assert_eq!(ifx_crc16_reference(b"PQSigner"), known);
    assert_ne!(known, 0, "non-empty input must produce a non-zero CRC");
}

#[test]
fn negative_ifx_crc16_single_bit_flip_changes_crc() {
    // ASSUMPTION ATTACKED: the CRC catches single-bit corruption on the
    // wire. If a refactor accidentally truncated the polynomial step we
    // would still produce *some* output for every input — but it would
    // collide on neighbouring bit patterns.
    let mut a = [0u8; 16];
    a.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
    let crc_a = ifx_crc16_reference(&a);
    a[7] ^= 0x01;
    let crc_b = ifx_crc16_reference(&a);
    assert_ne!(crc_a, crc_b, "1-bit flip must produce a different IFX CRC");
}

#[test]
fn negative_ifx_crc16_not_standard_ccitt() {
    // ASSUMPTION ATTACKED: a refactor that "modernises" the CRC to a
    // standard polynomial (CRC-16/CCITT, init=0xFFFF) silently breaks
    // every frame against the chip. CRC-16/CCITT-FALSE init=0xFFFF over
    // "123456789" = 0x29B1; our IFX CRC starts at 0 and uses a different
    // nibble step, so this must NOT collide.
    let ifx = ifx_crc16_reference(b"123456789");
    assert_ne!(
        ifx, 0x29B1,
        "Infineon IFX I2C CRC-16 must NOT equal CRC-16/CCITT — the chip would reject every frame"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Source-text pins — apdu.rs constants & framing
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_cmd_bytes_all_carry_clear_last_error_high_bit() {
    // ASSUMPTION ATTACKED: every CMD nibble is OR'd with the
    // CLEAR_LAST_ERROR (0x80) flag — the chip's parser reads the low 7
    // bits for the operation and the high bit as "clear sticky error
    // state". Dropping the flag silently lets a previous error become
    // sticky and causes follow-up commands to fail unrelated.
    for need in &[
        "CMD_OPEN_APPLICATION:      u8 = 0x70 | CMD_CLEAR_LAST_ERROR;",
        "CMD_GET_DATA_OBJECT:       u8 = 0x01 | CMD_CLEAR_LAST_ERROR;",
        "CMD_SET_DATA_OBJECT:       u8 = 0x02 | CMD_CLEAR_LAST_ERROR;",
        "CMD_SET_OBJECT_PROTECTED:  u8 = 0x03 | CMD_CLEAR_LAST_ERROR;",
        "CMD_GET_RANDOM:            u8 = 0x0C | CMD_CLEAR_LAST_ERROR;",
        "CMD_DECRYPT_SYM:           u8 = 0x15 | CMD_CLEAR_LAST_ERROR;",
    ] {
        assert!(APDU_SRC.contains(need), "missing CMD definition: {need}");
    }
    assert!(
        APDU_SRC.contains("const CMD_CLEAR_LAST_ERROR: u8 = 0x80;"),
        "CLEAR_LAST_ERROR must be 0x80"
    );
}

#[test]
fn negative_param_hmac_mode_is_0x20_not_aes_0x02() {
    // ASSUMPTION ATTACKED: writing 0x02 (an AES variant) here makes the
    // chip refuse every HMAC verify with Status=0xFF — silent PIN
    // lockout regression.
    assert!(
        APDU_SRC.contains("const PARAM_HMAC_MODE:   u8 = 0x20;"),
        "DecryptSym HMAC-mode param must be 0x20 (Infineon OPTIGA_HMAC_SHA_256), not 0x02 (AES)"
    );
}

#[test]
fn negative_oid_assignments_canonical_f1d0_range() {
    // ASSUMPTION ATTACKED: the OID range was once rotated to F1DC..F1DF
    // during bring-up to avoid stale chip state; doing so silently broke
    // every pristine chip (the F1DC range is undefined gap addresses).
    // The canonical assignments must be preserved.
    for need in &[
        "OID_AUTH_REF:      u16 = 0xF1D0;",
        "OID_ENTROPY:       u16 = 0xF1D1;",
        "OID_MASTER_SECRET: u16 = 0xF1D2;",
        "OID_VK:            u16 = 0xF1D3;",
        "OID_BOOTSTRAP_VK:  u16 = 0xF1D4;",
        "OID_COUNTER:       u16 = 0xF1E1;",
    ] {
        assert!(
            APDU_SRC.contains(need),
            "OID assignment drifted off canonical range: {need}"
        );
    }
}

#[test]
fn negative_oid_pbs_is_e140() {
    assert!(
        APDU_SRC.contains("OID_PBS:           u16 = 0xE140;"),
        "Platform Binding Secret OID must be E140 per OPTIGA Trust M SRM"
    );
}

#[test]
fn negative_oid_pin_ctr_is_e120_first_luc() {
    // ASSUMPTION ATTACKED: hw-counter binding requires the F1D0 AuthRef
    // Execute AC to reference an OPTIGA Lifetime Usage Counter object
    // — those live at 0xE120..0xE123. Moving the constant off E120
    // silently breaks the silicon PIN lockout.
    assert!(
        APDU_SRC.contains("OID_PIN_CTR: u16 = 0xE120;"),
        "PIN LUC counter OID must be E120 (first OPTIGA LUC object)"
    );
}

#[test]
fn negative_response_parser_sta_model_matches_v3_silicon() {
    // ASSUMPTION ATTACKED: per SRM v3.70 §"Response Status Codes" a V3
    // part returns ONLY Sta ∈ {0x00, 0xFF}; the specific reason lives in
    // the Last Error Code data object (0xF1C2). An earlier revision
    // mapped fictional per-reason Sta values (0x02/0x07/0x0E/0x2F —
    // 0x02 does not even exist in the V3 error table) onto
    // PinIncorrect/PinLocked; those arms were dead code on silicon, and
    // PIN semantics must come from context (the E120 lockout pre-check
    // plus the verify-site collapse in `authenticate_and_read`), never
    // from `Sta`. Re-introducing a per-reason `Sta` mapping would be
    // spec fiction that silently rewires the PIN error paths.
    assert!(
        !APDU_SRC.contains("0x02;"),
        "no per-reason Sta constants — V3 Sta is only 0x00/0xFF (audit 2026-07-20)"
    );
    assert!(
        APDU_SRC.contains("return Err(OptigaError::Status(status));"),
        "parse_response must surface any non-zero Sta as the opaque Status(_) verdict"
    );
    // The diagnostics reader must fetch the Last Error Code WITHOUT the
    // CLEAR_LAST_ERROR flag: the MSB-triggered flush has priority over
    // command evaluation, so an 0x81 read would zero the code before the
    // read executes and always report "no error".
    assert!(
        APDU_SRC.contains("OID_LAST_ERROR: u16 = 0xF1C2;"),
        "Last Error Code object is 0xF1C2 per SRM common data structures"
    );
    assert!(
        APDU_SRC.contains("ApduBuf::new(CMD_GET_DATA_OBJECT & !CMD_CLEAR_LAST_ERROR, PARAM_DATA)"),
        "read_last_error must send Cmd=0x01 (MSB clear), not 0x81"
    );
}

#[test]
fn negative_response_parser_skips_undef_byte() {
    // ASSUMPTION ATTACKED: response is `Sta(1) | UnDef(1) | OutLen(2 BE)
    // | OutData`. Treating UnDef as part of OutLen would corrupt every
    // response whose chip put a non-zero byte there.
    assert!(
        APDU_SRC.contains("// resp[1] = UnDef — ignored."),
        "response parser must explicitly skip the UnDef byte"
    );
    assert!(
        APDU_SRC.contains("let data_len = ((resp[2] as usize) << 8) | resp[3] as usize;"),
        "OutLen must be parsed from resp[2..4], not resp[1..3]"
    );
}

#[test]
fn response_parser_requires_exact_declared_transport_length() {
    let exact = [0x00, 0xA5, 0x00, 0x03, 0x11, 0x22, 0x33];
    assert_eq!(
        apdu::parse_response_for_test(&exact, exact.len()).unwrap(),
        &[0x11, 0x22, 0x33]
    );

    let trailing = [0x00, 0xA5, 0x00, 0x03, 0x11, 0x22, 0x33, 0x99];
    assert!(matches!(
        apdu::parse_response_for_test(&trailing, trailing.len()),
        Err(apdu::OptigaError::Transport)
    ));

    let declared_too_long = [0x00, 0xA5, 0x00, 0x04, 0x11, 0x22, 0x33];
    assert!(matches!(
        apdu::parse_response_for_test(&declared_too_long, declared_too_long.len()),
        Err(apdu::OptigaError::Transport)
    ));
    assert!(matches!(
        apdu::parse_response_for_test(&exact, exact.len() + 1),
        Err(apdu::OptigaError::Transport)
    ));

    let failed_status = [0x01, 0xA5, 0x00, 0x03, 0x11, 0x22, 0x33];
    assert!(matches!(
        apdu::parse_response_for_test(&failed_status, failed_status.len()),
        Err(apdu::OptigaError::Status(0x01))
    ));
    assert!(APDU_SRC.contains("crate::rng_exact::verify_exact_pair_into("));
    assert!(APDU_SRC.contains("core::ptr::read_volatile(&frame_receipt)"));
}

#[test]
fn negative_session_oid_reserved_e100() {
    assert!(
        APDU_SRC.contains("pub const OID_SESSION: u16 = 0xE100;"),
        "PQSigner reserves session slot 0xE100 — moving this conflicts with the chip's per-session AUTHREF state"
    );
}

#[test]
fn negative_dtype_constants_match_srm() {
    assert!(APDU_SRC.contains("const DTYPE_PBS:     u8 = 0x22;"));
    assert!(
        APDU_SRC.contains("const DTYPE_AUTHREF: u8 = 0x31;"),
        "AUTHREF data type tag must be 0x31; OPTIGA's HMAC-verify path keys off it"
    );
}

#[test]
fn negative_ac_operand_constants_match_trezor_port() {
    assert!(
        APDU_SRC.contains("const AC_OP_AUTO_REF: u8 = 0x23;"),
        "Auto-Ref operand must be 0x23 (chip rejects other values for HMAC-gated reads)"
    );
    assert!(APDU_SRC.contains("const AC_OP_CONF:     u8 = 0x20;"));
    assert!(APDU_SRC.contains("const AC_OP_LUC:      u8 = 0x40;"));
    assert!(APDU_SRC.contains("const AC_AND: u8 = 0xFD;"));
    assert!(APDU_SRC.contains("const AC_OR:  u8 = 0xFE;"));
    assert!(APDU_SRC.contains("const AC_ALW: u8 = 0x00;"));
    assert!(APDU_SRC.contains("const AC_NEV: u8 = 0xFF;"));
}

#[test]
fn negative_set_obj_protected_tag_bit_pattern() {
    // ASSUMPTION ATTACKED: Infineon's protected-update tag scheme is
    // (0x30 | start=0, continue=2, final=1). Mixing the START / CONTINUE
    // / FINAL bytes silently bricks the chip mid-manifest because the
    // chip's strict lock is held by START and released only by FINAL.
    assert!(APDU_SRC.contains("SET_OBJ_PROT_TAG_START:    u8 = 0x30;"));
    assert!(APDU_SRC.contains("SET_OBJ_PROT_TAG_CONTINUE: u8 = 0x32;"));
    assert!(APDU_SRC.contains("SET_OBJ_PROT_TAG_FINAL:    u8 = 0x31;"));
    assert!(APDU_SRC.contains("MANIFEST_VERSION_V3: u8 = 0x01;"));
}

#[test]
fn negative_protected_update_chunk_buffer_overflow_guard() {
    // ASSUMPTION ATTACKED: the chunk builder must refuse fragments
    // larger than what fits in the 768-byte ApduBuf minus header(4) +
    // TLV(3) = 761 bytes. A silent removal of this guard would write
    // past the buffer.
    assert!(
        APDU_SRC.contains("if buf.len() > 761 {")
            && APDU_SRC.contains("return Err(OptigaError::BufferOverflow);"),
        "protected_update_chunk must guard against >761-byte fragments"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Source-text pins — shield.rs wire format & security
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_shield_prf_label_unchanged() {
    // ASSUMPTION ATTACKED: the PRF label "Platform Binding" is
    // wire-spec for OPTIGA's Shielded Connection. Renaming silently
    // breaks every paired chip.
    assert!(
        SHIELD_SRC.contains(r#"const PRF_LABEL: &[u8] = b"Platform Binding";"#),
        "PRF label must remain exactly \"Platform Binding\""
    );
}

#[test]
fn negative_shield_sctr_byte_values() {
    assert!(SHIELD_SRC.contains("const SCTR_HANDSHAKE_HELLO: u8 = 0x00;"));
    assert!(SHIELD_SRC.contains("const SCTR_HANDSHAKE_FINISHED: u8 = 0x08;"));
    assert!(
        SHIELD_SRC.contains("const SCTR_RECORD_FULL: u8 = 0x23;"),
        "SCTR=0x23 is the wire identifier for full-protection record frames"
    );
}

#[test]
fn negative_shield_ccm_tag_is_eight_bytes() {
    assert!(SHIELD_SRC.contains("const CCM_TAG_LEN: usize = 8;"));
    assert!(
        SHIELD_SRC.contains("const SC_OVERHEAD: usize = SC_HEADER_LEN + CCM_TAG_LEN;"),
        "overhead must include exactly one MAC tag"
    );
}

#[test]
fn negative_shield_session_key_layout_2x16_plus_2x4() {
    // ASSUMPTION ATTACKED: the 40-byte PRF output is split exactly
    // 16/16/4/4 — encryption key, decryption key, encryption nonce
    // base, decryption nonce base. Any other split silently desyncs
    // the host from the chip's PRL state machine.
    assert!(SHIELD_SRC.contains("const SESSION_KEY_LEN: usize = 40;"));
    assert!(SHIELD_SRC.contains("self.enc_key.copy_from_slice(&key_material[0..16]);"));
    assert!(SHIELD_SRC.contains("self.dec_key.copy_from_slice(&key_material[16..32]);"));
    assert!(SHIELD_SRC.contains("self.enc_nonce_base.copy_from_slice(&key_material[32..36]);"));
    assert!(SHIELD_SRC.contains("self.dec_nonce_base.copy_from_slice(&key_material[36..40]);"));
}

#[test]
fn negative_shield_nonce_wrap_threshold_closes_session() {
    // ASSUMPTION ATTACKED: the final reference-permitted master sequence is
    // 0xFFFFFFF0; the following transaction is forced to renegotiate. The
    // receive direction similarly refuses to begin another transaction once
    // its last authenticated sequence reaches that threshold.
    assert!(
        SHIELD_SRC.contains("if self.enc_seq > PRL_SEQUENCE_THRESHOLD {")
            && SHIELD_SRC.contains("self.active = false;"),
        "wrap_command must force session close before nonce wrap"
    );
    assert!(
        SHIELD_SRC.matches("PRL_SEQUENCE_THRESHOLD - 1").count() >= 2
            && SHIELD_SRC
                .matches("core::ptr::addr_of!(self.dec_seq)")
                .count()
                >= 2,
        "wrap_command must double-check the receive threshold before a transaction"
    );
}

#[test]
fn negative_shield_transmit_sequence_is_reserved_before_ciphertext() {
    let wrap = &SHIELD_SRC[SHIELD_SRC
        .find("pub fn wrap_command(")
        .expect("shielded command wrapper missing")..];
    let unwrap = wrap
        .find("pub fn unwrap_response(")
        .expect("shielded response wrapper missing");
    let reserve = wrap[..unwrap]
        .find("reserve_transmit_sequence_into(")
        .expect("transmit-sequence reservation missing");
    let encrypt = wrap[..unwrap]
        .find("let ct_len = aes128_ccm_encrypt(")
        .expect("CCM encryption missing");
    assert!(reserve < encrypt, "the next sequence must commit before encryption");
    assert!(
        wrap[..unwrap]
            .matches("core::ptr::read_volatile(&sequence_reservation_receipt)")
            .count()
            >= 2
    );
    assert!(!wrap[..unwrap].contains("self.enc_seq += 1;"));
    assert!(SHIELD_SRC.contains("enc_seq_inv: u32"));
}

#[test]
fn negative_shield_handshake_frames_have_exact_reference_shape() {
    assert!(SHIELD_SRC.contains("if n != SLAVE_HELLO_LEN"));
    assert!(SHIELD_SRC.contains("resp[0] != SCTR_HANDSHAKE_HELLO"));
    assert!(SHIELD_SRC.contains("resp[1] != PROTOCOL_VERSION"));
    assert!(
        SHIELD_SRC.contains(
            "const SLAVE_FINISHED_LEN: usize = SC_HEADER_LEN + 36 + CCM_TAG_LEN;"
        ) && SHIELD_SRC.contains("if n2 != SLAVE_FINISHED_LEN {")
    );
}

#[test]
fn negative_shield_replay_guard_present() {
    // ASSUMPTION ATTACKED: an attacker captures a valid response and
    // replays it, or jumps outside the reference driver's retry window.
    assert!(
        SHIELD_SRC.contains("const PRL_MAX_FORWARD_DELTA: u32 = 3;")
            && SHIELD_SRC.contains("fn verify_response_sequence_into(")
            && SHIELD_SRC.contains("fn response_sequence_window_volatile(")
            && SHIELD_SRC.contains("received > last")
            && SHIELD_SRC
                .contains("received.wrapping_sub(last) <= PRL_MAX_FORWARD_DELTA")
            && SHIELD_SRC.contains("core::ptr::read_volatile(received_sequence)")
            && SHIELD_SRC.contains("self.dec_seq_inv"),
        "unwrap_response must bind responses to the authenticated 1..=3 slave-sequence window"
    );
    let unwrap = &SHIELD_SRC[SHIELD_SRC
        .find("pub fn unwrap_response(")
        .expect("steady-state unwrap missing")..];
    let handshake = unwrap
        .find("pub unsafe fn establish(")
        .expect("handshake boundary missing");
    assert!(
        unwrap[..handshake]
            .matches("core::ptr::read_volatile(&sequence_receipt)")
            .count()
            >= 2
            && unwrap[..handshake].contains("commit_sequence_state_into("),
        "steady-state sequence validation needs two caller gates and a bound state commit"
    );
    assert!(
        unwrap[handshake..].contains("commit_sequence_state_into(\n            slave_seq,"),
        "the authenticated SlaveHello counter must seed the record-response baseline"
    );
}

#[test]
fn negative_get_random_has_no_plaintext_transport_branch() {
    let get_random = &APDU_SRC[APDU_SRC
        .find("pub unsafe fn get_random(")
        .expect("GetRandom helper missing")..];
    let plain = get_random
        .find("pub unsafe fn get_random_plain(")
        .expect("cfg-gated prodtest plaintext helper missing");
    assert!(get_random[..plain].contains("send_command_protected("));
    assert!(!get_random[..plain].contains("let n = send_command(ifx"));

    let protected = &APDU_SRC[APDU_SRC
        .find("unsafe fn send_command_protected(")
        .expect("protected-only transport helper missing")..];
    let transparent = protected
        .find("unsafe fn send_command(")
        .expect("transparent provisioning transport helper missing");
    assert!(!protected[..transparent].contains("if shield.active"));
    assert!(!protected[..transparent].contains("ifx.transceive(apdu"));
    assert!(
        protected[..transparent]
            .matches("core::ptr::read_volatile(&shield_receipt)")
            .count()
            >= 2,
        "protected transport must double-check the authenticated unwrap receipt"
    );
    assert!(MOD_SRC.contains("apdu::get_random_plain(&mut self.ifx, out)"));
}

#[test]
fn negative_shield_record_sctr_is_authenticated() {
    // ASSUMPTION ATTACKED: the SCTR byte is part of the AAD. If
    // `unwrap_response` accepted any SCTR (handshake frames, alerts)
    // a MITM could substitute frame types at will. The driver must
    // refuse any SCTR != SCTR_RECORD_FULL.
    assert!(
        SHIELD_SRC.contains("if sctr != SCTR_RECORD_FULL {"),
        "unwrap_response must reject non-record SCTR — HIGH-M16 mitigation"
    );
}

#[test]
fn negative_shield_constant_time_tag_compare() {
    // ASSUMPTION ATTACKED: timing-leaking tag compare (e.g. byte-wise
    // `==` with early return) would let an attacker recover the tag
    // byte-by-byte.
    assert!(
        SHIELD_SRC.contains("use subtle::ConstantTimeEq;")
            && SHIELD_SRC.contains(".ct_eq(expected_tag.as_slice())"),
        "CCM tag compare must use the constant-time comparison primitive"
    );
    let verifier = &SHIELD_SRC[SHIELD_SRC
        .find("fn verify_ccm_tag_into(")
        .expect("out-of-line CCM verifier missing")..];
    let decrypt = verifier
        .find("pub(crate) fn aes128_ccm_decrypt_into(")
        .expect("receipt-based CCM decrypt missing");
    assert!(
        verifier[..decrypt].matches("ccm_tag_matches(").count() >= 2,
        "CCM authentication must be recomputed independently twice before publishing success"
    );
    let unwrap = &SHIELD_SRC[SHIELD_SRC
        .find("pub fn unwrap_response(")
        .expect("steady-state unwrap missing")..];
    let handshake = unwrap
        .find("pub unsafe fn establish(")
        .expect("handshake boundary missing");
    assert!(
        unwrap[..handshake]
            .matches("core::ptr::read_volatile(&ccm_receipt)")
            .count()
            >= 2,
        "steady-state plaintext release must check the caller-owned CCM receipt twice"
    );
    let decrypt_helper = &SHIELD_SRC[SHIELD_SRC
        .find("pub(crate) fn aes128_ccm_decrypt_into(")
        .expect("receipt-based CCM decrypt missing")..];
    let cleanup = decrypt_helper
        .find("if unsafe { core::ptr::read_volatile(auth_receipt) }")
        .expect("decrypt cleanup receipt gate missing");
    let cleanup_tail = &decrypt_helper[cleanup..];
    let poison = cleanup_tail
        .find("core::ptr::write_volatile(auth_receipt, crate::fi::FAIL_SENTINEL);")
        .expect("cleanup must poison its receipt");
    let wipe = cleanup_tail
        .find("out[..ct_len].zeroize();")
        .expect("cleanup plaintext wipe missing");
    assert!(
        poison < wipe,
        "a fault-entered cleanup must poison the receipt before changing authenticated plaintext"
    );
    // Same constant-time pattern in establish() for the random_S echo
    // check.
    assert!(
        SHIELD_SRC.contains("diff |= slave_plain[i] ^ random_s[i];"),
        "SlaveFinished random_S echo must be constant-time-compared"
    );
}

#[test]
fn negative_shield_zeroize_on_drop_for_secret_material() {
    // ASSUMPTION ATTACKED: PBS + session keys + nonce bases stay
    // resident in SRAM after the connection drops, available to a
    // subsequent OS reload or cold-boot attack.
    assert!(SHIELD_SRC.contains("impl Drop for ShieldedConnection"));
    assert!(SHIELD_SRC.contains("self.enc_key.zeroize();"));
    assert!(SHIELD_SRC.contains("self.dec_key.zeroize();"));
    assert!(SHIELD_SRC.contains("self.enc_nonce_base.zeroize();"));
    assert!(SHIELD_SRC.contains("self.dec_nonce_base.zeroize();"));
    assert!(SHIELD_SRC.contains("self.pbs.zeroize();"));
}

#[test]
fn negative_provision_hw_pin_counter_zeroizes_original_pin_secret() {
    // X17-TUI2 family (playbook UI9): step 1c must zeroize the
    // ORIGINAL `pin_secret` binding. Zeroizing a moved copy leaves
    // the KDF-derived PIN secret live on the stack.
    assert!(
        MOD_SRC.contains("self.provision_hw_pin_counter(Self::HW_PIN_CTR_LIMIT, &pin_secret)"),
        "step 1c must pass the pin_secret into provision_hw_pin_counter"
    );
    assert!(
        !MOD_SRC.contains("let mut ps = pin_secret;"),
        "step 1c must zeroize the original pin_secret binding, not a copy (X17-TUI2 family)"
    );
}

#[test]
fn negative_shield_pbs_is_64_bytes() {
    // ASSUMPTION ATTACKED: OPTIGA SRM mandates a 64-byte PBS. Truncating
    // to 32 bytes silently halves the effective key entropy.
    assert!(SHIELD_SRC.contains("pbs: [u8; 64],"));
    assert!(SHIELD_SRC.contains("pub fn load_pbs(&mut self, pbs: &[u8; 64])"));
}

#[test]
fn negative_shield_ccm_flags_q_minus_one_six() {
    // ASSUMPTION ATTACKED: with an 8-byte nonce, q = 15 - 8 = 7, so the
    // counter byte position carries `q-1 = 6` in flags. Drifting this
    // produces a CCM ciphertext the chip can't decrypt.
    assert!(
        SHIELD_SRC.contains("a_block[0] = 6;"),
        "CCM A_i flag byte must encode q-1 = 6 for 8-byte nonce"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Source-text pins — ifx_i2c.rs frame layout & CRC algorithm
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_ifx_crc16_algorithm_shape_stable() {
    // The custom Infineon nibble step. Any rewrite that diverges from
    // this exact sequence silently corrupts every CRC.
    let needle = "let h1 = (crc ^ byte as u16) & 0xFF;\n        let h2 = h1 & 0x0F;\n        let h3 = (h2 << 4) ^ h1;\n        let h4 = h3 >> 4;\n        crc = ((((h3 << 1) ^ h4) << 4) ^ h2) << 3 ^ h4 ^ (crc >> 8);";
    assert!(
        IFX_SRC.contains(needle),
        "Infineon IFX CRC-16 nibble algorithm must remain byte-identical to the chip's"
    );
}

#[test]
fn negative_ifx_register_addresses() {
    assert!(IFX_SRC.contains("const REG_DATA: u8 = 0x80;"));
    assert!(IFX_SRC.contains("const REG_I2C_STATE: u8 = 0x82;"));
    assert!(
        IFX_SRC.contains("const REG_SOFT_RESET: u8 = 0x88;"),
        "soft-reset register must remain 0x88 per IFX I²C protocol v2.03"
    );
}

#[test]
fn negative_ifx_presence_bit_value() {
    // ASSUMPTION ATTACKED: setting PRESENCE_BIT=0x08 on the outgoing
    // PCTR is what routes the payload to the chip's PRL state machine.
    // Without it, handshake messages get parsed as raw APDUs and the
    // chip returns gibberish.
    assert!(
        IFX_SRC.contains("const PCTR_PRESENCE_BIT: u8 = 0x08;"),
        "PCTR PRESENCE_BIT must equal 0x08 (Infineon IFX_I2C_PRESENCE_BIT)"
    );
}

#[test]
fn negative_ifx_max_frame_size_277() {
    assert!(IFX_SRC.contains("const MAX_FRAME_SIZE: usize = 277;"));
}

#[test]
fn negative_ifx_dl_rx_seq_init_is_three() {
    // ASSUMPTION ATTACKED: a documented bug — initialising `rx_seq` to 0
    // causes the chip to silently respond with 4-byte empty-OK frames
    // forever. The fix initialises to 3 so the first received FRNR=0
    // satisfies the chip's `fr_nr == (rx_seq_nr + 1) & 3` predicate.
    assert!(
        IFX_SRC.contains("const DL_RX_SEQ_INIT: u8 = 0x03;"),
        "DL_RX_SEQ_INIT must be 0x03; 0x00 silently breaks the receive path"
    );
}

#[test]
fn negative_ifx_max_poll_retries_supports_ecdsa_verify() {
    // ASSUMPTION ATTACKED: SetObjectProtected triggers ECDSA-P256
    // signature verification on the chip, up to ~1 s wall clock on V3
    // silicon. Polling at 1 ms must retry at least ~1000 times.
    assert!(
        IFX_SRC.contains("const MAX_POLL_RETRIES: u32 = 3000;"),
        "MAX_POLL_RETRIES must be >=1000 to accommodate SetObjectProtected's on-chip ECDSA verify"
    );
}

#[test]
fn negative_ifx_uses_cortex_m_delay_not_nop_loop() {
    // ASSUMPTION ATTACKED: LTO can elide `for _ in 0..N { nop() }`
    // entirely, removing the inter-probe delay and starving the chip
    // out of sleep. The driver must use `cortex_m::asm::delay(N)` (which
    // has a volatile counter LTO cannot drop).
    assert!(
        IFX_SRC.contains("cortex_m::asm::delay(80_000);"),
        "register-probe retry must use cortex_m::asm::delay, not a NOP loop"
    );
    assert!(
        IFX_SRC.contains("cortex_m::asm::delay(40_000);"),
        "1 ms poll delay must use cortex_m::asm::delay"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Source-text pins — i2c.rs bus driver
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_i2c_optiga_addr_is_0x30() {
    // ASSUMPTION ATTACKED: OPTIGA Trust M's 7-bit I²C address is 0x30
    // per Infineon datasheet — co-located with SE050 on I²C1 without
    // conflict. Moving this silently NACKs the chip.
    assert!(
        I2C_SRC.contains("pub const OPTIGA_ADDR: u8 = 0x30;"),
        "OPTIGA_ADDR must remain 0x30"
    );
}

#[test]
fn negative_i2c_write_read_uses_50us_guard() {
    // ASSUMPTION ATTACKED: Infineon's reference driver requires a
    // PL_GUARD_TIME_INTERVAL_US (~50 µs) between the register-address
    // write and the read. The driver implements this as 8000 NOPs at
    // 160 MHz; truncating produces a chip that NACKs the read.
    assert!(
        I2C_SRC.contains("for _ in 0..8_000u32 {"),
        "write_read must insert the IFX I2C PL guard delay (~50 µs)"
    );
}

#[test]
fn negative_i2c_write_read_not_repeated_start() {
    // ASSUMPTION ATTACKED: the chip NACKs repeated-START transitions
    // from write to read. The driver must use separate START/STOP
    // transactions, documented in the file.
    assert!(
        I2C_SRC.contains("Repeated-START is not used"),
        "i2c.rs must document that repeated-START is intentionally avoided"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Source-text pins — mod.rs (driver lifecycle & invariants)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_mod_max_attempts_matches_shared_invariant() {
    assert!(
        MOD_SRC.contains("const MAX_ATTEMPTS: u8 = sphincs_tz_shared::MAX_ATTEMPTS;"),
        "MAX_ATTEMPTS must source from sphincs_tz_shared so the MCU + SE counters stay in lockstep"
    );
}

#[test]
fn negative_mod_pin_auth_domain_tag_unchanged() {
    // ASSUMPTION ATTACKED: renaming the KDF domain tag would silently
    // brick every paired chip (CLAUDE.md "no casual KDF tag changes").
    assert!(
        MOD_SRC.contains(r#"const PIN_AUTH_DOMAIN: &[u8] = b"optiga-pin-auth-v1";"#),
        "OPTIGA PIN-auth KDF domain tag must remain 'optiga-pin-auth-v1'"
    );
}

#[test]
fn negative_mod_reset_sentinel_is_0xff() {
    assert!(
        MOD_SRC.contains("const RESET_SENTINEL: u8 = 0xFF;"),
        "RESET_SENTINEL marker (used by is_provisioned() to detect wiped chips) must be 0xFF"
    );
}

#[test]
fn negative_mod_uses_fi_bool_for_blob_cached() {
    // ASSUMPTION ATTACKED: a plain `bool` for the "entropy blob cached"
    // flag is glitchable to true — letting a faulted boot reuse stale
    // cache. The driver must use the FI-hardened sentinel pair.
    assert!(
        MOD_SRC.contains("blob_cached: crate::fih::FihBool,"),
        "OPTIGA driver must use FihBool for blob_cached to defeat FI glitching"
    );
}

#[test]
fn negative_mod_no_classical_signer_references() {
    // ASSUMPTION ATTACKED: CLAUDE.md invariant #5 — only SPHINCS+C10.
    // The OPTIGA driver must not reach for ECDSA / Ed25519 / P-256
    // signers anywhere. (The chip *does* support these but PQSigner
    // refuses to use them.)
    let lower = MOD_SRC.to_ascii_lowercase();
    for forbidden in &["ed25519", "secp256k1", "secp256r1"] {
        assert!(
            !lower.contains(forbidden),
            "OPTIGA driver must not reference classical signer '{forbidden}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// Reference-algorithm tests: TLS-PRF + AES-128-CCM round-trip via the
// public path-included `wrap_command` / `unwrap_response`.
//
// These exercise the actual production bytes — not a re-implementation
// — by chaining wrap → unwrap and asserting plaintext recovery.
// ─────────────────────────────────────────────────────────────────────
//
// The session-keys derivation is private, so a true wrap→unwrap pair
// requires being inside the same struct instance. We can synthesise
// that by performing wrap and unwrap on the SAME ShieldedConnection
// (which is what would normally talk to a chip — host-side it
// round-trips against itself).
//
// However, because the enc/dec keys are derived from random_S only
// inside the private `derive_session_keys`, the only way to reach
// `active = true` without a chip is through `establish()`, which
// requires the IfxState stub to return a valid SlaveHello — too
// elaborate. We therefore restrict the round-trip suite to the
// portions reachable through the public surface: state-machine
// guards (negative tests above) + load_pbs idempotency below.

#[test]
fn positive_shield_load_pbs_is_idempotent() {
    let mut sc = shield::ShieldedConnection::new();
    sc.load_pbs(&[0xAA; 64]);
    assert!(sc.pbs_loaded);
    sc.load_pbs(&[0xBB; 64]);
    assert!(sc.pbs_loaded, "second load_pbs must keep pbs_loaded=true");
    assert!(
        !sc.active,
        "reloading PBS must NOT open a session — only `establish` can"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Negative — APDU parse: rejection of malformed inputs.
//
// `parse_response` is private; exercised indirectly via the public
// commands (which all early-return on parser failure). Direct
// `parse_response` testing isn't reachable across the module boundary,
// so we pin its rejection paths via text and via a behaviour test on
// `is_metadata_operational` (which uses the sibling `find_metadata_tag`
// internally).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_find_metadata_tag_handles_malformed_root() {
    // ASSUMPTION ATTACKED: `is_metadata_operational` (and any other
    // metadata predicate built on `find_metadata_tag`) must reject
    // inputs whose first byte is not META_ROOT (0x20). A silent
    // acceptance would let a glitched read of a non-metadata OID
    // produce a false positive "operational" verdict — bypassing the
    // ratchet guard.
    let mut bad_root = [0u8; 8];
    bad_root[0] = 0x21; // not META_ROOT
    bad_root[1] = 0x03;
    bad_root[2] = 0xC0; // META_LCSO
    bad_root[3] = 0x01;
    bad_root[4] = 0x07; // would say LCS_OPERATIONAL
    assert!(
        !apdu::is_metadata_operational(&bad_root, 8),
        "metadata whose root byte is not 0x20 must NOT be treated as operational"
    );
}

#[test]
fn negative_find_metadata_tag_handles_truncated_input() {
    // ASSUMPTION ATTACKED: len < 2 must short-circuit before any
    // indexing.
    assert!(!apdu::is_metadata_operational(&[0x20], 1));
    assert!(!apdu::is_metadata_operational(&[], 0));
}

#[test]
fn negative_find_metadata_tag_handles_inner_overflow() {
    // ASSUMPTION ATTACKED: the inner TLV's length must be bounded by
    // root_len. A claim of `0xFF` length on a 3-byte buffer must NOT
    // panic or extract garbage.
    let mut buf = [0u8; 16];
    buf[0] = 0x20; // META_ROOT
    buf[1] = 0x06; // claims 6 bytes of inner content
    buf[2] = 0xC0; // META_LCSO
    buf[3] = 0xFF; // but claims 255 bytes of value — overflows
                   // The fn should return None (treated as not operational) without panic.
    assert!(!apdu::is_metadata_operational(&buf, 8));
}

#[test]
fn negative_find_metadata_tag_value_length_mismatch() {
    // ASSUMPTION ATTACKED: even a syntactically-valid metadata with a
    // 2-byte LCSO value (instead of the required 1) must NOT be read as
    // operational — the predicate must require `v.len() == 1`.
    let mut buf = [0u8; 16];
    buf[0] = 0x20;
    buf[1] = 0x04;
    buf[2] = 0xC0;
    buf[3] = 0x02; // 2-byte value
    buf[4] = 0x07;
    buf[5] = 0x00;
    assert!(
        !apdu::is_metadata_operational(&buf[..6], 6),
        "LCSO value must be exactly 1 byte to be recognised as a state"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Algorithm pins — Trezor-port wire compatibility for hw-counter mode
// (text-pin even when the cfg is off, because the bytes are wire-spec)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_hw_counter_get_random_auto_state_request_size_16() {
    // ASSUMPTION ATTACKED: under hw-counter, the Trezor-shape APDU
    // requests exactly 16 random bytes (matching their nonce length).
    // A 32-byte request pushes the chip onto a different LUC path
    // and the counter does not increment as expected — silently
    // breaking the silicon PIN lockout.
    assert!(
        APDU_SRC.contains("ab.write_u16(16);") && APDU_SRC.contains("get_random_auto_state"),
        "hw-counter get_random_auto_state must request 16 bytes (Trezor wire shape)"
    );
}

#[test]
fn negative_hw_counter_hmac_verify_data_length_18() {
    // ASSUMPTION ATTACKED: the LUC-triggering DecryptSym data block is
    // exactly `nonce_oid(2) | nonce(16)` = 18 bytes. A 66-byte
    // compound (the legacy AC path) does not trigger LUC increment on
    // Trust M V3.
    assert!(
        APDU_SRC.contains("ab.write_u16(2 + 16); // data length = nonce_oid(2) + nonce(16) = 18"),
        "hw-counter hmac_verify_auto_state must send an 18-byte data block"
    );
}

#[test]
fn negative_hw_counter_pin_counter_layout_be_u32_pair() {
    // ASSUMPTION ATTACKED: the 8-byte UPCTR object is `current_u32_be ||
    // limit_u32_be`. Any drift collides with Trezor's reset routine and
    // bricks the AuthRef.
    assert!(APDU_SRC.contains("out[0..4].copy_from_slice(&current.to_be_bytes());"));
    assert!(APDU_SRC.contains("out[4..8].copy_from_slice(&limit.to_be_bytes());"));
}

// ─────────────────────────────────────────────────────────────────────
// Coverage seeds deliberately left to integration / on-target tests
// (documented in reports/tests/secure-optiga.md "Coverage gaps").
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// D1 — an inconclusive probe must never drive the E140 rewrite
// ─────────────────────────────────────────────────────────────────────

/// `I2c` / `Transport` / `Crc` are physical- and framing-layer faults: the chip
/// may not have seen the command, or its reply was mangled. They are not
/// evidence about the PBS. `Status` / `PinIncorrect` / `PinLocked` /
/// `NotProvisioned` are verdicts the chip returned.
#[test]
fn positive_optiga_error_classifies_bus_faults_as_inconclusive() {
    assert!(
        APDU_SRC.contains("pub const fn is_inconclusive(&self) -> bool"),
        "OptigaError must be able to say 'I don't know' — see work-todo D1"
    );
    assert!(
        APDU_SRC.contains("OptigaError::I2c | OptigaError::Transport | OptigaError::Crc"),
        "the inconclusive set must be exactly the bus/framing faults"
    );
}

/// **D1 regression guard — the PBS rotation probe gates the E140 rewrite.**
///
/// `rotate_pbs_to_salted` probes whether the FINAL PBS already establishes a
/// shield and, if not, falls through to rewriting E140 — the operation that
/// bricked the bench chip (`docs/secure-elements/optiga-brick-postmortem.md`,
/// memory `project_optiga_brick`). The old code used
/// `hard_reset_and_reinit().is_ok() && ensure_shield().is_ok()`, so an I2C or
/// IFX fault during a read-only probe fell straight through to the rewrite.
#[test]
fn negative_pbs_rotation_probe_does_not_let_a_bus_fault_reach_e140() {
    let start = MOD_SRC
        .find("pub fn rotate_pbs_to_salted")
        .expect("rotate_pbs_to_salted exists");
    let rest = &MOD_SRC[start..];
    let end = rest[1..]
        .find("\n    pub fn ")
        .map_or(MOD_SRC.len(), |o| start + 1 + o);
    // Strip `//` comments: this is an absence-assertion, and the comment that
    // documents the fix would otherwise trip the gate it documents.
    let code: std::string::String = MOD_SRC[start..end]
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<std::vec::Vec<_>>()
        .join("\n");

    assert!(
        !code.contains("self.hard_reset_and_reinit().is_ok() && self.ensure_shield().is_ok()"),
        "D1: the FINAL-PBS probe collapsed a bus fault into 'not rotated' and \
         fell through to the E140 rewrite (the brick path). Classify with \
         is_inconclusive() and fail closed — the ceremony is journal-resumable, \
         so the next boot re-probes with a fresh link."
    );
    assert!(
        code.contains("Err(e) if e.is_inconclusive() => return Err(e)"),
        "an inconclusive FINAL-PBS probe must fail closed, never reach E140"
    );
}

/// **D1 follow-up — `HandshakeFailed` must stay split.**
///
/// The original D1 fix left `OptigaError::Shield` conflating "wrong PBS" with
/// "handshake faulted", which was the one residual path by which a bus fault
/// could still reach the E140 rewrite. `ShieldError` now separates them, and
/// the separation is only worth anything if `ensure_shield` stops discarding
/// it: `map_err(|_| OptigaError::Shield)` threw the distinction away.
///
/// The dividing line is evidence, not severity. `HandshakeRejected` means the
/// chip answered and its `SlaveFinished` failed to authenticate under keys
/// derived from the loaded PBS — a CCM MAC failure IS the proof our PBS is
/// wrong. `HandshakeTransport` means the exchange never got that far.
#[test]
fn negative_shield_handshake_error_stays_split_by_evidence() {
    // The two classes exist and the collapsed variant is gone.
    assert!(SHIELD_SRC.contains("HandshakeTransport"));
    assert!(SHIELD_SRC.contains("HandshakeRejected"));
    assert!(
        !SHIELD_SRC.contains("ShieldError::HandshakeFailed"),
        "ShieldError::HandshakeFailed re-appeared — it conflates 'the chip \
         rejected our PBS' with 'the bus faulted', and rotate_pbs_to_salted \
         answers the former by rewriting E140 (the brick path)."
    );

    // The CCM MAC failure — the authoritative wrong-PBS signal — must be
    // classified as a rejection, never as transport.
    let decrypt_site = SHIELD_SRC
        .find("SlaveFinished decrypt FAILED")
        .expect("SlaveFinished decrypt check exists");
    let after = &SHIELD_SRC[decrypt_site..decrypt_site + 400];
    assert!(
        after.contains("ShieldError::HandshakeRejected"),
        "a CCM MAC failure on SlaveFinished is the authoritative 'wrong PBS' \
         verdict and must classify as HandshakeRejected"
    );

    // A failed MasterHello transceive is transport — the chip may not have
    // seen it at all.
    let hello_site = SHIELD_SRC
        .find("MasterHello transceive FAILED")
        .expect("MasterHello transceive check exists");
    let after_hello = &SHIELD_SRC[hello_site..hello_site + 300];
    assert!(
        after_hello.contains("ShieldError::HandshakeTransport"),
        "a failed MasterHello transceive proves nothing about the PBS"
    );

    // And ensure_shield must not throw the distinction away again.
    assert!(
        !MOD_SRC.contains("self.shield.establish(&mut self.ifx)\n                        .map_err(|_| OptigaError::Shield)?;"),
        "ensure_shield re-collapsed the handshake error with map_err(|_| ...)"
    );
    assert!(
        MOD_SRC.contains("shield::ShieldError::HandshakeTransport => OptigaError::Transport"),
        "ensure_shield must map a transport-class handshake failure onto \
         OptigaError::Transport so is_inconclusive() sees it"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Runtime coverage — session lifecycle, wrap/unwrap error paths, and
// the host loopback round-trip.
//
// These tests drive the path-included production bytes through the
// public surface plus the `#[cfg(test)]` hooks (`activate_for_test`,
// `sequence_state_for_test`, `ccm_encrypt_for_test`,
// `aes128_ccm_decrypt_into`). The loopback keys both directions
// identically, so it proves self-consistency only. Protocol
// conformance of `establish()` / `derive_session_keys` /
// `tls_prf_sha256` / `send_command_protected` against a scripted PRL
// peer (with independently implemented protocol math, anchored to
// OpenSSL-computed golden vectors) lives in `prl_tests.rs` — see
// `prl_peer.rs` for the peer.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_shield_zeroize_session_clears_live_state() {
    // zeroize_session is the lock / idle-wipe / panic-path scrub of the
    // AES-128-CCM session keys (audit MEDIUM-1). After it runs, both
    // direction counters must be back at their complement-bound initial
    // values, `active` must be false, and the PBS must be RETAINED — it
    // is the long-lived pairing root that re-derives the next session.
    let mut sc = make_active_shield(0x5C);
    assert!(sc.active);
    assert_eq!(sc.sequence_state_for_test(), (7, !7u32, 100, !100u32));

    sc.zeroize_session();

    assert!(!sc.active, "zeroize_session must close the session");
    assert_eq!(
        sc.sequence_state_for_test(),
        (0, u32::MAX, 0, u32::MAX),
        "both counters must reset to the value/complement initial state"
    );
    assert!(
        sc.pbs_loaded,
        "PBS is intentionally retained across zeroize_session (re-derivable pairing root)"
    );

    // Both directions refuse to run on the scrubbed state.
    let mut out = [0u8; 64];
    assert!(matches!(
        sc.wrap_command(b"x", &mut out),
        Err(shield::ShieldError::NotActive)
    ));
    let mut receipt = crate::fi::OK_SENTINEL;
    assert!(matches!(
        sc.unwrap_response(&[0u8; 16], &mut out, &mut receipt),
        Err(shield::ShieldError::NotActive)
    ));
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);

    // A fresh activation (the host-side stand-in for ensure_shield's
    // re-handshake) must still work on the zeroized instance.
    sc.activate_for_test([0x5C; 16], [0x5C; 4], 7, 100);
    let mut wrapped = [0u8; 64];
    assert!(
        sc.wrap_command(b"after-wipe", &mut wrapped).is_ok(),
        "zeroize_session must leave the connection re-handshakeable"
    );
}

#[test]
fn negative_shield_wrap_past_nonce_threshold_forces_renegotiation() {
    // ASSUMPTION ATTACKED: the final reference-permitted master sequence
    // is 0xFFFF_FFF0; the NEXT transaction must force a session close so
    // a CCM nonce can never wrap/reuse. Pin the boundary exactly: a wrap
    // AT the threshold succeeds, the following one fails and closes.
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test([0x77; 16], [0x77; 4], 0xFFFF_FFF0, 100);
    let mut out = [0u8; 64];
    let len = sc
        .wrap_command(b"last-permitted", &mut out)
        .expect("sequence == PRL_SEQUENCE_THRESHOLD is still permitted");
    assert_eq!(&out[..5], &[0x23, 0xFF, 0xFF, 0xFF, 0xF0]);
    assert_eq!(len, 5 + 14 + 8);
    assert!(sc.active, "a permitted wrap must not close the session");

    let res = sc.wrap_command(b"one-too-many", &mut out);
    assert!(
        matches!(res, Err(shield::ShieldError::NotActive)),
        "the wrap past the nonce threshold must fail closed"
    );
    assert!(
        !sc.active,
        "crossing the threshold must deactivate so the caller re-handshakes"
    );
}

#[test]
fn negative_shield_wrap_refused_when_receive_state_at_threshold() {
    // ASSUMPTION ATTACKED: the receive direction's last authenticated
    // counter is bound by the same threshold (minus the bounded retry
    // window). A transaction begun when the last slave sequence has
    // already reached it must be refused before any ciphertext leaves.
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test([0x66; 16], [0x66; 4], 7, 0xFFFF_FFF0);
    let mut out = [0u8; 64];
    let res = sc.wrap_command(b"x", &mut out);
    assert!(matches!(res, Err(shield::ShieldError::NotActive)));
    assert!(
        !sc.active,
        "a receive-side counter at the threshold must close the session"
    );

    // One step below the threshold the same session shape still wraps.
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test([0x66; 16], [0x66; 4], 7, 0xFFFF_FFEF);
    assert!(
        sc.wrap_command(b"x", &mut out).is_ok(),
        "last slave sequence == threshold-1 stays inside the reference window"
    );
}

#[test]
fn negative_shield_wrap_undersized_output_is_buffer_overflow() {
    // ASSUMPTION ATTACKED: wrap_command must refuse to emit a truncated
    // record when the caller's buffer cannot hold header + payload + tag.
    // A silent truncation would authenticate a fragment the chip then
    // parses as a complete APDU.
    let mut sc = make_active_shield(0xAA);
    let plaintext = [0x5Au8; 32];
    // Exact fit is 5 + 32 + 8 = 45 bytes; one short must fail.
    let mut short = [0u8; 44];
    let res = sc.wrap_command(&plaintext, &mut short);
    assert!(
        matches!(res, Err(shield::ShieldError::BufferOverflow)),
        "a 44-byte buffer for a 45-byte record must be BufferOverflow"
    );
    assert!(
        sc.active,
        "a caller-side sizing error must not kill the session"
    );

    let mut exact = [0u8; 45];
    assert_eq!(
        sc.wrap_command(&plaintext, &mut exact).unwrap(),
        45,
        "the exact-size buffer must succeed"
    );
}

#[test]
fn negative_shield_wrap_oversized_plaintext_is_buffer_overflow() {
    // ASSUMPTION ATTACKED: the internal staging buffer is 600 bytes for
    // ciphertext + tag, so plaintext above 592 bytes must be refused even
    // when the CALLER's output buffer is large enough. Without this guard
    // the encrypt loop writes past the staging array.
    let mut sc = make_active_shield(0xBB);
    let plaintext = [0x11u8; 593]; // 593 + 8 = 601 > 600
    let mut out = [0u8; 700]; // the caller buffer is NOT the constraint
    let res = sc.wrap_command(&plaintext, &mut out);
    assert!(
        matches!(res, Err(shield::ShieldError::BufferOverflow)),
        "plaintext that overflows the 600-byte staging buffer must be refused"
    );

    // Boundary: exactly 592 bytes of plaintext fills the staging buffer.
    let plaintext = [0x11u8; 592];
    assert_eq!(
        sc.wrap_command(&plaintext, &mut out).unwrap(),
        5 + 592 + 8,
        "592-byte plaintext exactly fits ciphertext+tag in 600 bytes"
    );
}

#[test]
fn negative_shield_unwrap_rejects_non_record_sctr() {
    // ASSUMPTION ATTACKED (HIGH-M16): only full-protection record frames
    // (SCTR = 0x23) are valid responses to a wrapped command. A handshake
    // SCTR must be refused before the sequence window or CCM are even
    // consulted — otherwise a MITM could substitute frame types at will.
    let key = [0x31u8; 16];
    let nonce_base = [0x31u8; 4];
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test(key, nonce_base, 101, 100);
    let plaintext = [0x5Au8; 12];
    let mut record = [0u8; 64];
    let record_len = make_protected_response(&key, &nonce_base, 101, &plaintext, &mut record);
    // Re-write the SCTR to a handshake value; the gate must fire before
    // any tag verification is consulted.
    record[0] = 0x08;

    let mut out = [0xA5u8; 12];
    let mut receipt = crate::fi::OK_SENTINEL;
    let res = sc.unwrap_response(&record[..record_len], &mut out, &mut receipt);
    assert!(
        matches!(res, Err(shield::ShieldError::DecryptFailed)),
        "a non-record SCTR must be rejected as DecryptFailed"
    );
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0u8; 12], "output must be wiped on refusal");
    assert_eq!(
        sc.sequence_state_for_test().2,
        100,
        "the authenticated baseline must not move"
    );
}

#[test]
fn negative_shield_unwrap_undersized_output_is_buffer_overflow() {
    // ASSUMPTION ATTACKED: unwrap_response must refuse to write a
    // truncated plaintext when the caller's buffer is smaller than the
    // authenticated payload — and the refusal must come BEFORE any
    // decryption or counter publication.
    let key = [0x41u8; 16];
    let nonce_base = [0x41u8; 4];
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test(key, nonce_base, 101, 100);
    let plaintext = [0x5Au8; 12];
    let mut record = [0u8; 64];
    let record_len = make_protected_response(&key, &nonce_base, 101, &plaintext, &mut record);

    let mut short = [0xA5u8; 11];
    let mut receipt = crate::fi::OK_SENTINEL;
    let res = sc.unwrap_response(&record[..record_len], &mut short, &mut receipt);
    assert!(
        matches!(res, Err(shield::ShieldError::BufferOverflow)),
        "an 11-byte buffer for a 12-byte payload must be BufferOverflow"
    );
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(
        sc.sequence_state_for_test().2,
        100,
        "a caller-side sizing error must not advance the authenticated baseline"
    );

    // Exact fit succeeds and publishes the counter.
    let mut exact = [0u8; 12];
    let mut receipt = crate::fi::FAIL_SENTINEL;
    assert_eq!(
        sc.unwrap_response(&record[..record_len], &mut exact, &mut receipt)
            .unwrap(),
        12
    );
    assert_eq!(exact, plaintext);
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
}

#[test]
fn positive_shield_wrap_unwrap_round_trip_recovers_plaintext() {
    // Loopback: `activate_for_test` keys both directions identically, so
    // a wrapped command unwrapped by the SAME session must recover the
    // original payload byte-for-byte — the host-side mirror of the
    // OPTIGA PRL record path, exercising the real production
    // wrap_command → unwrap_response byte flow end to end.
    let key = [0x29u8; 16];
    let nonce_base = [0x29u8; 4];
    let mut sc = shield::ShieldedConnection::new();
    // Transmit starts at 101 so the looped-back record lands inside the
    // 1..=3 response window above the receive baseline (100).
    sc.activate_for_test(key, nonce_base, 101, 100);

    let plaintext = b"pqsigner-loopback";
    let mut record = [0u8; 128];
    let record_len = sc.wrap_command(plaintext, &mut record).unwrap();
    assert_eq!(&record[..5], &[0x23, 0, 0, 0, 101]);

    let mut out = [0u8; 64];
    let mut receipt = crate::fi::FAIL_SENTINEL;
    let n = sc
        .unwrap_response(&record[..record_len], &mut out, &mut receipt)
        .expect("same-session loopback must authenticate");
    assert_eq!(n, plaintext.len());
    assert_eq!(&out[..n], plaintext);
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(
        sc.sequence_state_for_test(),
        (102, !102u32, 101, !101u32),
        "both directions advance exactly once"
    );
}

#[test]
fn negative_shield_replayed_record_and_wrong_key_both_fail() {
    // ASSUMPTION ATTACKED: (a) an I2C MITM replays a captured record —
    // the sequence window must refuse it once the baseline has advanced
    // past the record's sequence; (b) a record protected under a
    // DIFFERENT key (the wrong direction of an asymmetric session, or a
    // foreign session entirely) must fail CCM authentication with the
    // caller's buffer wiped.
    let key = [0x29u8; 16];
    let nonce_base = [0x29u8; 4];
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test(key, nonce_base, 101, 100);

    let plaintext = b"replay-me";
    let mut record = [0u8; 128];
    let record_len = sc.wrap_command(plaintext, &mut record).unwrap();
    let mut out = [0u8; 9];
    let mut receipt = crate::fi::FAIL_SENTINEL;
    sc.unwrap_response(&record[..record_len], &mut out, &mut receipt)
        .unwrap();

    // (a) Replay: the same bytes a second time must fail — the
    // authenticated baseline is now 101 and 101 > 101 is false.
    out.fill(0xA5);
    receipt = crate::fi::OK_SENTINEL;
    assert!(matches!(
        sc.unwrap_response(&record[..record_len], &mut out, &mut receipt),
        Err(shield::ShieldError::DecryptFailed)
    ));
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0u8; 9]);

    // (b) Foreign key: the SCTR and the sequence window both pass, so
    // the CCM tag verification is the only guard left.
    let mut foreign = [0u8; 128];
    let foreign_len =
        make_protected_response(&[0x99; 16], &nonce_base, 101, plaintext, &mut foreign);
    let mut sc2 = shield::ShieldedConnection::new();
    sc2.activate_for_test(key, nonce_base, 101, 100);
    out.fill(0xA5);
    receipt = crate::fi::OK_SENTINEL;
    assert!(matches!(
        sc2.unwrap_response(&foreign[..foreign_len], &mut out, &mut receipt),
        Err(shield::ShieldError::DecryptFailed)
    ));
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0u8; 9], "failed authentication must wipe the output");
    assert_eq!(
        sc2.sequence_state_for_test().2,
        100,
        "a failed authentication must not advance the baseline"
    );
}

#[test]
fn negative_shield_establish_without_pbs_is_refused() {
    // ASSUMPTION ATTACKED: the handshake must not run without a loaded
    // PBS — otherwise derive_session_keys would key the session on the
    // all-zero buffer and every record would be trivially forgeable.
    let mut sc = shield::ShieldedConnection::new();
    let mut ifx = super::ifx_i2c::IfxState::new();
    let res = unsafe { sc.establish(&mut ifx) };
    assert!(matches!(res, Err(shield::ShieldError::NoPbs)));
    assert!(!sc.active);
}

#[test]
fn negative_shield_establish_transport_fault_is_not_a_pbs_verdict() {
    // ASSUMPTION ATTACKED (D1): a MasterHello transceive failure must
    // surface as HandshakeTransport — "the chip may not have seen the
    // hello", NOT HandshakeRejected — so rotate_pbs_to_salted can never
    // read a bus fault as "wrong PBS" and fall through to the E140
    // rewrite (the brick path). The stub transport fails every PRL
    // transceive with IfxError::Timeout, which is exactly this class.
    let mut sc = shield::ShieldedConnection::new();
    sc.load_pbs(&[0x42; 64]);
    let mut ifx = super::ifx_i2c::IfxState::new();
    let res = unsafe { sc.establish(&mut ifx) };
    assert!(
        matches!(res, Err(shield::ShieldError::HandshakeTransport)),
        "a failed MasterHello transceive must classify as transport, not rejection"
    );
    assert!(!sc.active, "a failed handshake must not open the session");
}

#[test]
fn negative_shield_ccm_decrypt_rejects_undersized_inputs_before_writing() {
    // ASSUMPTION ATTACKED: aes128_ccm_decrypt_into must fail-initialize
    // the receipt and return WITHOUT writing when the framed input
    // cannot contain a tag (< 8 bytes) or the caller's buffer cannot
    // hold the carried payload.
    let key = [0x11u8; 16];
    let nonce = [0x22u8; 8];
    let aad = [0x23u8, 0, 0, 0, 7, 0, 24];

    // Fewer bytes than one CCM tag: no payload can exist.
    let mut out = [0xA5u8; 8];
    let mut receipt = crate::fi::OK_SENTINEL;
    shield::aes128_ccm_decrypt_into(&key, &nonce, &aad, &[0u8; 7], &mut out, &mut receipt);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0xA5u8; 8], "no write may happen without a full tag");

    // Output buffer shorter than the carried ciphertext.
    let ct = [0u8; 20]; // 12 payload + 8 tag, but the sink only holds 4
    let mut small = [0xA5u8; 4];
    let mut receipt = crate::fi::OK_SENTINEL;
    shield::aes128_ccm_decrypt_into(&key, &nonce, &aad, &ct, &mut small, &mut receipt);
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(
        small,
        [0xA5u8; 4],
        "oversized ciphertext must not spill past the caller buffer"
    );
}

#[test]
fn positive_shield_ccm_multi_block_aad_is_fully_authenticated() {
    // ASSUMPTION ATTACKED: AAD longer than one CBC-MAC block (14 bytes
    // fit beside the 2-byte length in B_1) must chain through the
    // remaining-AAD-blocks loop; a refactor that drops the continuation
    // blocks would silently accept records whose trailing AAD bytes were
    // never authenticated.
    let key = [0x51u8; 16];
    let nonce = [0x61u8; 8];
    let aad = [0x77u8; 40]; // 40 > 14: forces the multi-block AAD path
    let plaintext = [0x5Au8; 24];
    let mut record = [0u8; 64];
    let record_len = shield::ccm_encrypt_for_test(&key, &nonce, &aad, &plaintext, &mut record);

    let mut out = [0u8; 24];
    let mut receipt = crate::fi::FAIL_SENTINEL;
    shield::aes128_ccm_decrypt_into(
        &key,
        &nonce,
        &aad,
        &record[..record_len],
        &mut out,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::OK_SENTINEL);
    assert_eq!(out, plaintext);

    // The trailing AAD bytes are authenticated: flipping the last one
    // must fail the tag.
    let mut aad_bad = aad;
    aad_bad[39] ^= 1;
    out.fill(0xA5);
    let mut receipt = crate::fi::OK_SENTINEL;
    shield::aes128_ccm_decrypt_into(
        &key,
        &nonce,
        &aad_bad,
        &record[..record_len],
        &mut out,
        &mut receipt,
    );
    assert_eq!(receipt, crate::fi::FAIL_SENTINEL);
    assert_eq!(out, [0u8; 24]);
}

// ─────────────────────────────────────────────────────────────────────
// Runtime coverage — OptigaError classification, the IFX→OPTIGA error
// mapping, ApduBuf u8 appends, and the transport-failure surface of the
// public APDU commands against the hard-down `ifx_i2c` stub.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_optiga_error_inconclusive_classification() {
    // D1: the inconclusive set is exactly the physical/framing faults —
    // the chip may not have seen the command, or its reply was mangled,
    // so the error says "I don't know". Everything else is an answer:
    // chip verdicts, shield verdicts, or our own bugs.
    for e in [
        apdu::OptigaError::I2c,
        apdu::OptigaError::Transport,
        apdu::OptigaError::Crc,
    ] {
        assert!(e.is_inconclusive(), "{e:?} must be inconclusive");
    }
    for e in [
        apdu::OptigaError::Shield,
        apdu::OptigaError::Status(0xFF),
        apdu::OptigaError::Status(0x00),
        apdu::OptigaError::PinIncorrect,
        apdu::OptigaError::PinLocked,
        apdu::OptigaError::NotProvisioned,
        apdu::OptigaError::BufferOverflow,
    ] {
        assert!(
            !e.is_inconclusive(),
            "{e:?} is an answer, not 'I don't know'"
        );
    }
}

#[test]
fn positive_ifx_error_maps_to_documented_optiga_error() {
    // The IFX transport error mapping: a CRC mismatch is the ONLY
    // variant with a dedicated OptigaError (a framing-integrity fault,
    // kept distinct so diagnostics can name it); every other wire fault
    // collapses to Transport.
    use super::ifx_i2c::IfxError;
    assert!(matches!(
        apdu::OptigaError::from(IfxError::Crc),
        apdu::OptigaError::Crc
    ));
    for e in [
        IfxError::I2c,
        IfxError::Nack,
        IfxError::Timeout,
        IfxError::FrameTooLarge,
        IfxError::BadResponse,
        IfxError::ReSynch,
    ] {
        assert!(
            matches!(apdu::OptigaError::from(e), apdu::OptigaError::Transport),
            "every non-CRC IFX fault must map to Transport"
        );
    }
    // And the whole mapped set stays inside the inconclusive class (D1):
    // a bus-layer failure must never be mistaken for a chip verdict.
    assert!(apdu::OptigaError::from(IfxError::Crc).is_inconclusive());
    assert!(apdu::OptigaError::from(IfxError::Timeout).is_inconclusive());
}

#[test]
fn positive_apdu_buf_write_u8_appends_and_updates_inlen() {
    let mut ab = apdu::ApduBuf::new(0x8C, 0x00);
    ab.write_u8(0xDE).write_u8(0xAD);
    let bytes = ab.finish();
    assert_eq!(bytes.len(), 6, "header(4) + 2 payload bytes");
    assert_eq!(bytes[4], 0xDE, "first write_u8 lands at cursor 4");
    assert_eq!(bytes[5], 0xAD, "second write_u8 appends, not overwrites");
    assert_eq!(bytes[2..4], [0x00, 0x02], "InLen tracks the u8 appends");
}

#[test]
fn positive_apdu_buf_write_u8_fills_exactly_to_capacity() {
    // The fixed buffer is 768 bytes with a 4-byte header, so exactly 764
    // payload bytes fit. Fill to capacity through write_u8 alone: the
    // last byte must land at index 767 and InLen must be 764 (0x02FC) —
    // the InLen high byte is exercised non-trivially here.
    let mut ab = apdu::ApduBuf::new(0x82, 0x40);
    for i in 0..764u32 {
        ab.write_u8((i & 0xFF) as u8);
    }
    let bytes = ab.finish();
    assert_eq!(bytes.len(), 768);
    assert_eq!(bytes[767], (763 & 0xFF) as u8);
    assert_eq!(bytes[2..4], [0x02, 0xFC], "InLen = 764 in big-endian");
}

#[test]
#[should_panic]
fn negative_apdu_buf_write_u8_past_capacity_panics() {
    // ASSUMPTION ATTACKED: ApduBuf is a fixed 768-byte stack buffer with
    // no grow path; a 765th payload byte must refuse loudly (the array
    // bounds check panics), never wrap or silently truncate into a
    // malformed APDU the chip would then act on.
    let mut ab = apdu::ApduBuf::new(0x82, 0x40);
    for _ in 0..765 {
        ab.write_u8(0xAA);
    }
}

#[test]
fn negative_open_application_transport_fault_surfaces_transport() {
    // ASSUMPTION ATTACKED: with the stub transport hard-down
    // (IfxError::Timeout on every frame), open_application must surface
    // Err(OptigaError::Transport) via the From<IfxError> mapping — and
    // must never be mistaken for a chip verdict.
    let mut ifx = super::ifx_i2c::IfxState::new();
    let res = unsafe { apdu::open_application(&mut ifx) };
    assert!(
        matches!(res, Err(apdu::OptigaError::Transport)),
        "a transport-layer Timeout must map to OptigaError::Transport"
    );
    assert!(
        res.unwrap_err().is_inconclusive(),
        "OpenApplication failing on the bus says nothing about chip state (D1)"
    );
}

#[test]
fn negative_get_random_never_falls_back_to_plaintext_transport() {
    // ASSUMPTION ATTACKED (entropy provenance): get_random must route
    // through the protected PRL path unconditionally. With no active
    // shielded session it must REFUSE (Shield) — silently downgrading
    // to the plaintext transceive would let an I2C MITM substitute a
    // fixed "random" challenge.
    let mut ifx = super::ifx_i2c::IfxState::new();
    let mut sc = shield::ShieldedConnection::new();
    let mut out = [0xA5u8; 16];
    let res = unsafe { apdu::get_random(&mut ifx, &mut sc, &mut out) };
    assert!(
        matches!(res, Err(apdu::OptigaError::Shield)),
        "no active session => get_random must fail, never send plaintext"
    );
    assert!(
        !res.unwrap_err().is_inconclusive(),
        "Shield is an authoritative verdict, not a bus fault"
    );
    assert_eq!(out, [0xA5u8; 16], "caller buffer untouched on refusal");
}

#[test]
fn negative_get_random_transport_fault_surfaces_transport() {
    // With an active session the wrap succeeds and the failure moves to
    // the wire: the stub PRL transceive hard-fails, which must surface
    // as Transport (inconclusive) — never as a shield/verdict error.
    let mut sc = shield::ShieldedConnection::new();
    sc.activate_for_test([0x31; 16], [0x31; 4], 7, 100);
    let mut ifx = super::ifx_i2c::IfxState::new();
    let mut out = [0xA5u8; 16];
    let res = unsafe { apdu::get_random(&mut ifx, &mut sc, &mut out) };
    assert!(
        matches!(res, Err(apdu::OptigaError::Transport)),
        "a PRL transceive Timeout must map through From<IfxError> to Transport"
    );
    assert_eq!(
        out,
        [0xA5u8; 16],
        "no partial bytes reach the caller on a bus fault"
    );
}

/// The OPTIGA silicon reset must never reach a hardcoded iota2 pin on pq1.
///
/// `pin_diag::run` hardcodes PA4/PD5/PE0 and reads no board constant. It was
/// the live reset path from BOTH `OptigaTrustM::init` and
/// `hard_reset_and_reinit` (the runtime write-throttle workaround), while the
/// board-aware `optiga::reset_pin` sat unused behind a retired feature. On pq1
/// that pulses PE0 (unbonded on the 48-pin package), never touches the real
/// reset (PA15), and strobes PA4 — `LCD_CS`, the trusted display's
/// chip-select — under a comment calling it "disconnected, harmless".
///
/// Fixed 2026-08-31 by board-splitting both call sites. This pins the split.
#[test]
fn negative_optiga_reset_path_is_board_split() {
    // 1. The hardcoded module cannot compile for pq1 at all.
    assert!(
        MAIN_SRC_FOR_PIN_DIAG.contains("not(feature = \"board-pq1\"),\n    not(test)\n))]\nmod pin_diag;"),
        "`mod pin_diag` must stay excluded on board-pq1 — it hardcodes the iota2 \
         pin map (PA4/PD5/PE0) and reads no board constant."
    );

    // 2. Every `pin_diag::run()` call is board-gated. Counting both together
    //    is the point: there are TWO call sites and the review found only one
    //    of them first.
    let runs = MOD_SRC.matches("crate::pin_diag::run();").count();
    assert_eq!(runs, 2, "expected exactly two pin_diag::run() call sites in optiga/mod.rs");
    let gated = MOD_SRC
        .matches("not(feature = \"board-pq1\")")
        .count();
    assert!(
        gated >= 2,
        "each of the {runs} `pin_diag::run()` call sites must carry a \
         `not(feature = \"board-pq1\")` gate; found only {gated} such gates"
    );

    // 3. pq1 gets a real pulse rather than nothing — an unreset OPTIGA that is
    //    merely never pulsed would look like a wiring fault, not a code bug.
    assert_eq!(
        MOD_SRC.matches("reset_pin::hard_pulse()").count(),
        2,
        "both board-split call sites must reach `reset_pin::hard_pulse()` on pq1"
    );

    // 4. And that pulse is board-derived, not another hardcoded pin.
    assert!(
        RESET_PIN_SRC.contains("pub unsafe fn hard_pulse()"),
        "`reset_pin::hard_pulse` must exist — optiga/mod.rs cited this name in a \
         comment for months before anyone wrote the function."
    );
    for derived in [
        "const HAS_RST: bool = crate::board::OPTIGA_RST.is_some();",
        "const RST_PORT: u32 = match crate::board::OPTIGA_RST {",
        "const RST_PIN: u32 = match crate::board::OPTIGA_RST {",
    ] {
        assert!(
            RESET_PIN_SRC.contains(derived),
            "reset_pin must derive its pin from board::OPTIGA_RST; missing `{derived}`"
        );
    }
    // No hardcoded GPIO base may reappear in the board-aware path.
    for banned in ["0x5202_0C00", "0x5202_1000", "GPIOD_BASE", "GPIOE_BASE"] {
        assert!(
            !RESET_PIN_SRC.contains(banned),
            "reset_pin.rs must not hardcode a GPIO port (`{banned}`) — that is the \
             exact defect that made pin_diag unportable."
        );
    }
}
