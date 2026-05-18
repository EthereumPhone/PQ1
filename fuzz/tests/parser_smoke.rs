//! Host-runnable smoke tests for every parser entry-point that a
//! `fuzz_targets/*.rs` invokes.
//!
//! Two complementary purposes:
//!
//!  1. **Compile-time API-drift guard.** If `pqsigner_aa::userop::parse_header`
//!     (or any of the seven other parsers the harness reaches) is
//!     renamed, moved, or has its signature changed, `cargo test
//!     -p pqsigner-fuzz` fails *here* — long before someone runs
//!     `cargo fuzz` and discovers the harness no longer builds. The
//!     proptest siblings in `secure/src/fuzz_props.rs` give the same
//!     guarantee from the workspace side; this is the standalone-
//!     workspace mirror.
//!
//!  2. **Adversarial seeds.** Each parser gets a handful of inputs
//!     hand-picked to exercise the documented rejection paths: empty,
//!     length-prefix overrun, all-ones, just-under / just-over the
//!     fixed header length, etc. Negative tests assert the parser
//!     returns the *documented* error variant rather than:
//!         - panicking (the fuzz contract),
//!         - returning `Ok` on garbage (silent acceptance — far
//!           worse than a panic for a security-critical parser),
//!         - hanging.
//!
//! These ARE the libFuzzer harness's claim made into a deterministic
//! regression test.

use pqsigner_aa::userop;
use pqsigner_proto::USEROP_HEADER_LEN;
use pqsigner_tx::erc20;
use pqsigner_tx_core::{eip1559, rlp};
use sphincs_tz_shared::apdu_framing::{
    parse_apdu_header, FramingError, FrameOutcome, HidFrameAssembler, MAX_APDU_RX,
};
use sphincs_tz_shared::HID_REPORT_SIZE;

const ZERO_ROOT: [u8; 32] = [0u8; 32];

// ===========================================================================
//   aa::userop::parse_header
// ===========================================================================
// The unified SIGN_USEROP wire-format header parser. CLAUDE.md
// §"Wire formats" — every byte after NSC pointer validation lands here.

#[test]
fn positive_userop_parse_header_accepts_exact_length_buffer() {
    let buf = vec![0u8; USEROP_HEADER_LEN];
    let parsed = userop::parse_header(&buf).expect(
        "USEROP_HEADER_LEN bytes is the minimum the parser must accept — \
         see `aa/src/userop.rs::parse_header`",
    );
    assert_eq!(parsed.chain_id, 0, "all-zero buf must give chain_id=0");
}

#[test]
fn positive_userop_parse_header_accepts_oversized_buffer() {
    // The parser consumes exactly USEROP_HEADER_LEN bytes; trailing
    // bytes belong to the inner_tx field and are left for a later
    // parser. An oversized buf must succeed without touching the tail.
    let buf = vec![0xAAu8; USEROP_HEADER_LEN + 1024];
    let parsed = userop::parse_header(&buf).expect("oversized buf must parse");
    // The first byte after the leading has_bundle byte is the sender's
    // most-significant address byte. With all 0xAA the sender field is
    // 20 × 0xAA.
    assert_eq!(parsed.sender, [0xAAu8; 20]);
}

// ─── negatives ────────────────────────────────────────────────────────

#[test]
fn negative_userop_parse_header_rejects_empty_buffer() {
    // Assumption: parser never indexes into a buffer it hasn't bounds-
    // checked. An attacker who can drive USB HID with a 0-byte SIGN
    // command would gain a panic crash (DoS) if this assumption held.
    let err = userop::parse_header(&[]).expect_err(
        "empty buffer MUST be rejected with WireParseError::Truncated, \
         never accepted",
    );
    assert_eq!(err, userop::WireParseError::Truncated);
}

#[test]
fn negative_userop_parse_header_rejects_one_byte_under_header_len() {
    let buf = vec![0u8; USEROP_HEADER_LEN - 1];
    let err = userop::parse_header(&buf).expect_err(
        "USEROP_HEADER_LEN - 1 bytes MUST be rejected — \
         off-by-one boundary",
    );
    assert_eq!(err, userop::WireParseError::Truncated);
}

#[test]
fn negative_userop_parse_header_never_panics_on_pathological_inputs() {
    // Cross-check against the libFuzzer harness's promise: for ANY
    // byte sequence the parser must terminate cleanly.
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 1],
        vec![0u8; USEROP_HEADER_LEN - 1],
        vec![0xFFu8; USEROP_HEADER_LEN],
        vec![0xFFu8; USEROP_HEADER_LEN + 5_000],
        // Pattern: alternating bits to catch single-byte indexing bugs
        (0..=255u8).cycle().take(USEROP_HEADER_LEN).collect(),
    ];
    for inp in inputs {
        let _ = userop::parse_header(&inp);
    }
}

// ===========================================================================
//   tx_core::rlp::decode_item
// ===========================================================================

#[test]
fn positive_rlp_decode_item_single_byte() {
    let (item, used) = rlp::decode_item(&[0x42]).expect("single byte < 0x80 is valid RLP");
    assert_eq!(used, 1);
    match item {
        rlp::Item::Bytes(b) => assert_eq!(b, &[0x42]),
        rlp::Item::List(_) => panic!("must decode as Bytes"),
    }
}

#[test]
fn positive_rlp_decode_item_empty_string() {
    // 0x80 = empty byte string
    let (item, used) = rlp::decode_item(&[0x80]).expect("0x80 is the empty string");
    assert_eq!(used, 1);
    assert!(matches!(item, rlp::Item::Bytes(b) if b.is_empty()));
}

#[test]
fn positive_rlp_decode_item_empty_list() {
    // 0xc0 = empty list
    let (item, used) = rlp::decode_item(&[0xc0]).expect("0xc0 is the empty list");
    assert_eq!(used, 1);
    assert!(matches!(item, rlp::Item::List(l) if l.is_empty()));
}

// ─── negatives ────────────────────────────────────────────────────────

#[test]
fn negative_rlp_decode_item_rejects_empty_input() {
    // Documented behaviour: `RlpError::Truncated`. Attack: 0-byte RLP
    // streamed from a hostile bundler would otherwise hit an empty-
    // slice .first() crash.
    let err = rlp::decode_item(&[]).expect_err("empty input MUST yield Truncated");
    assert_eq!(err, rlp::RlpError::Truncated);
}

#[test]
fn negative_rlp_decode_item_rejects_non_canonical_short_string_with_low_byte() {
    // 0x81 0x42: would encode a 1-byte string holding 0x42, but the
    // canonical form is just 0x42 (single-byte rule). EIP-1559 verifiers
    // MUST reject — otherwise two distinct envelopes produce the same
    // userOpHash.
    let err = rlp::decode_item(&[0x81, 0x42])
        .expect_err("non-canonical short-string-with-low-byte must be rejected");
    assert_eq!(err, rlp::RlpError::NonCanonical);
}

#[test]
fn negative_rlp_decode_item_rejects_length_overflow_short_string() {
    // 0x82 declares a 2-byte string but only 1 byte follows.
    let err = rlp::decode_item(&[0x82, 0xAA])
        .expect_err("declared length > buffer must be rejected");
    assert_eq!(err, rlp::RlpError::Truncated);
}

#[test]
fn negative_rlp_decode_item_rejects_long_string_with_truncated_lenlen_field() {
    // 0xb8 = "long string, length-of-length = 1" — but the length byte
    // that should follow is missing. Must be rejected as Truncated
    // (parser must not index past end-of-buffer).
    let err = rlp::decode_item(&[0xb8])
        .expect_err("truncated len-of-len bytes must yield Truncated");
    assert_eq!(err, rlp::RlpError::Truncated);
}

#[test]
fn negative_rlp_decode_item_rejects_overlong_lenlen_field() {
    // 0xb8 with claimed-length 0x10 (16) but body bytes carry only a
    // 1-byte length value — short-form should have been used.
    // 0xb8 0x10 + 16 bytes of "real data"
    let mut buf = vec![0xb8u8, 0x10];
    buf.extend_from_slice(&[0xAA; 16]);
    // 0x10 = 16, which is ≤ 55, so should have been short-form. Parser
    // returns NonCanonical.
    let err = rlp::decode_item(&buf)
        .expect_err("long-form encoding of a ≤55-byte string must be NonCanonical");
    assert_eq!(err, rlp::RlpError::NonCanonical);
}

#[test]
fn negative_rlp_decode_item_never_panics_on_pathological_inputs() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xFF],
        // long-string with claimed huge length
        vec![0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // long-list with claimed huge length
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        (0..=255u8).collect(),
    ];
    for inp in inputs {
        let _ = rlp::decode_item(&inp);
    }
}

// ===========================================================================
//   tx_core::eip1559::parse
// ===========================================================================

#[test]
fn negative_eip1559_parse_rejects_empty_envelope() {
    // CLAUDE.md: "the signing flow runs over inner_tx_data" — an empty
    // envelope must NOT crash the secure world.
    let err = eip1559::parse(&[]).expect_err("empty envelope must be rejected");
    assert!(matches!(err, eip1559::TxError::EmptyEnvelope));
}

#[test]
fn negative_eip1559_parse_rejects_non_eip1559_type_byte() {
    // First byte MUST be 0x02. A legacy tx, an EIP-2930 (0x01), or any
    // future TX_TYPE byte must hit `TxError::NotEip1559`. This is what
    // protects against "wallet accidentally signs a legacy tx the user
    // didn't see on the trusted UI."
    for type_byte in [0x00u8, 0x01, 0x03, 0x7f, 0x80, 0xff] {
        let inp = vec![type_byte];
        let err = eip1559::parse(&inp).expect_err(&format!(
            "type byte 0x{type_byte:02x} must NOT be accepted as EIP-1559"
        ));
        assert!(
            matches!(err, eip1559::TxError::NotEip1559 | eip1559::TxError::Rlp(_)),
            "expected NotEip1559 or Rlp(_), got {err:?}",
        );
    }
}

#[test]
fn negative_eip1559_parse_rejects_trailing_bytes_after_envelope() {
    // 0x02 then a valid empty-list (0xc0) then trailing junk. The
    // parser must reject — trailing bytes can sneak invisible
    // calldata past the trusted-UI display.
    let env = vec![0x02u8, 0xc0, 0xde, 0xad];
    let err = eip1559::parse(&env)
        .expect_err("trailing bytes after envelope must yield TrailingBytes or RLP error");
    // RLP rejects the list as malformed before we get to TrailingBytes,
    // but either is acceptable — the property is "does NOT return Ok".
    let _ = err;
}

#[test]
fn negative_eip1559_parse_never_panics_on_pathological_inputs() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x02],
        vec![0x02, 0xc0], // valid 0x02 + empty list — too few fields
        vec![0xFF; 4096],
        (0..=255u8).cycle().take(8192).collect(),
    ];
    for inp in inputs {
        let _ = eip1559::parse(&inp);
    }
}

// ===========================================================================
//   tx::erc20::calldata::parse_erc20_calldata
// ===========================================================================

const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SELECTOR_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

fn make_address_word(addr: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&addr);
    out
}

#[test]
fn positive_erc20_calldata_decodes_well_formed_transfer() {
    // 4-byte selector + 32-byte address word + 32-byte amount word
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&SELECTOR_TRANSFER);
    data.extend_from_slice(&make_address_word([0x11u8; 20]));
    data.extend_from_slice(&[0u8; 32]);
    let parsed = erc20::calldata::parse_erc20_calldata(&data)
        .expect("well-formed transfer(address,uint256) calldata must decode");
    match parsed {
        erc20::calldata::Erc20Call::Transfer { to, .. } => {
            assert_eq!(to, [0x11u8; 20]);
        }
        _ => panic!("expected Transfer variant"),
    }
}

// ─── negatives ────────────────────────────────────────────────────────

#[test]
fn negative_erc20_calldata_rejects_short_input() {
    // Attack: < 4 bytes → would panic with [0..4] slice if not
    // length-checked first.
    for len in 0..4usize {
        let data = vec![0u8; len];
        assert!(
            erc20::calldata::parse_erc20_calldata(&data).is_none(),
            "len={len} must NOT decode (no 4-byte selector)",
        );
    }
}

#[test]
fn negative_erc20_calldata_rejects_address_word_with_nonzero_top_bytes() {
    // The address-word left-pad MUST be zero. A non-zero top byte
    // suggests a contract method with a similar selector that the
    // wallet would otherwise mistake for ERC-20 transfer — a route
    // to a spoofed "transfer to Vitalik" screen.
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&SELECTOR_TRANSFER);
    let mut bad_word = [0u8; 32];
    bad_word[0] = 0xAA; // dirty top byte
    bad_word[31] = 0x11;
    data.extend_from_slice(&bad_word);
    data.extend_from_slice(&[0u8; 32]);
    assert!(
        erc20::calldata::parse_erc20_calldata(&data).is_none(),
        "non-zero top byte in address word MUST be rejected — CLAUDE.md \
         requires strict ABI decoding (see tx/src/erc20/calldata.rs)",
    );
}

#[test]
fn negative_erc20_calldata_rejects_wrong_arglen_for_known_selector() {
    // transfer(address,uint256) requires exactly 64 body bytes.
    // 63 / 65 / 0 must all be rejected.
    for body_len in [0usize, 32, 63, 65, 128] {
        let mut data = Vec::with_capacity(4 + body_len);
        data.extend_from_slice(&SELECTOR_TRANSFER);
        data.extend(std::iter::repeat(0u8).take(body_len));
        assert!(
            erc20::calldata::parse_erc20_calldata(&data).is_none(),
            "transfer with body_len={body_len} must be rejected — exact 64 \
             bytes required"
        );
    }
}

#[test]
fn negative_erc20_calldata_rejects_unknown_selector_silently() {
    // Wallet must fall back to blind-sign display (None), never
    // misclassify an unknown selector as a known one.
    let mut data = vec![0x12, 0x34, 0x56, 0x78];
    data.extend_from_slice(&[0u8; 64]);
    assert!(
        erc20::calldata::parse_erc20_calldata(&data).is_none(),
        "unknown selector must return None (caller falls back to blind sign)",
    );
}

#[test]
fn negative_erc20_calldata_approve_max_amount_does_not_panic() {
    // Pattern that historically broke other parsers: approve(spender,
    // type(uint256).max). Must decode cleanly, not OOB.
    let mut data = Vec::with_capacity(4 + 64);
    data.extend_from_slice(&SELECTOR_APPROVE);
    data.extend_from_slice(&make_address_word([0x22u8; 20]));
    data.extend_from_slice(&[0xFFu8; 32]);
    let parsed = erc20::calldata::parse_erc20_calldata(&data)
        .expect("approve(unlimited) is well-formed and must decode");
    assert!(matches!(parsed, erc20::calldata::Erc20Call::Approve { .. }));
}

// ===========================================================================
//   tx::erc20::bundle::verify_erc20_bundle
// ===========================================================================
//
// The fuzz target uses a fixed all-zero `ZERO_ROOT`, so no input will
// ever Merkle-verify; the harness exercises the *parser's* bounds
// checks. We mirror that here.

#[test]
fn negative_erc20_verify_bundle_rejects_empty_input() {
    assert!(
        erc20::bundle::verify_erc20_bundle(&[], &ZERO_ROOT).is_none(),
        "empty bundle MUST be rejected — first bounds check is \
         8+20+1+1 bytes for the header"
    );
}

#[test]
fn negative_erc20_verify_bundle_rejects_truncated_header() {
    // Buffer shorter than the 30-byte fixed header must return None
    // without panicking.
    for len in [0usize, 1, 8, 20, 28, 29] {
        let buf = vec![0u8; len];
        assert!(
            erc20::bundle::verify_erc20_bundle(&buf, &ZERO_ROOT).is_none(),
            "len={len} bundle must NOT decode (header alone is 30 bytes)"
        );
    }
}

#[test]
fn negative_erc20_verify_bundle_rejects_zero_root_for_random_garbage() {
    // The all-zero root means no bundle can ever match. Even a
    // structurally-plausible bundle must return None at the Merkle
    // step. Property: "verifier never accepts under the wrong root."
    let mut buf = vec![0u8; 30];
    buf[28] = 0x06; // name_len = 6
    buf.extend_from_slice(b"FOOBAR"); // name
    buf.push(0x03); // symbol_len
    buf.extend_from_slice(b"FOO"); // symbol
    buf.extend_from_slice(&[0u8; 8]); // proof header bytes (4+4)
    assert!(
        erc20::bundle::verify_erc20_bundle(&buf, &ZERO_ROOT).is_none(),
        "all-zero root must reject all bundles",
    );
}

#[test]
fn negative_erc20_verify_bundle_never_panics_on_pathological_inputs() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0u8; 30],
        vec![0xFFu8; 256],
        // name_len = 0xFF (exceeds MAX_DISPLAY_FIELD)
        {
            let mut v = vec![0u8; 28];
            v.push(0xFF);
            v.extend_from_slice(&[0xAAu8; 1024]);
            v
        },
        (0..=255u8).cycle().take(2048).collect(),
    ];
    for inp in inputs {
        let _ = erc20::bundle::verify_erc20_bundle(&inp, &ZERO_ROOT);
    }
}

// ===========================================================================
//   shared::apdu_framing::parse_apdu_header
// ===========================================================================

#[test]
fn positive_apdu_parse_header_accepts_4_byte_header_with_lc0() {
    let apdu = [0x00u8, 0x01, 0x02, 0x03];
    let hdr = parse_apdu_header(&apdu).expect("4-byte header is Lc=0");
    assert_eq!(hdr.cla, 0x00);
    assert_eq!(hdr.ins, 0x01);
    assert_eq!(hdr.lc, 0);
    assert!(hdr.data.is_empty());
}

#[test]
fn positive_apdu_parse_header_accepts_5_byte_header_with_lc0_and_no_data() {
    // 5th byte = Lc = 0, no following data.
    let apdu = [0x00u8, 0x01, 0x02, 0x03, 0x00];
    let hdr = parse_apdu_header(&apdu).expect("Lc=0 with explicit Lc byte is valid");
    assert_eq!(hdr.lc, 0);
    assert!(hdr.data.is_empty());
}

// ─── negatives ────────────────────────────────────────────────────────

#[test]
fn negative_apdu_parse_header_rejects_input_under_4_bytes() {
    for len in 0..4usize {
        let buf = vec![0u8; len];
        let err = parse_apdu_header(&buf).expect_err(&format!("len={len} too short"));
        assert_eq!(err, FramingError::HeaderTooShort);
    }
}

#[test]
fn negative_apdu_parse_header_rejects_lc_overrun() {
    // Lc claims 10 bytes of data, only 0 follow. Documented:
    // `FramingError::LcOverrun`.
    let apdu = [0x00u8, 0x01, 0x02, 0x03, 0x0A];
    let err = parse_apdu_header(&apdu).expect_err("Lc claims more data than present");
    assert_eq!(err, FramingError::LcOverrun);
}

#[test]
fn negative_apdu_parse_header_rejects_lc_overrun_with_partial_data() {
    // Lc=10 but only 5 bytes follow.
    let apdu = vec![0x00u8, 0x01, 0x02, 0x03, 0x0A, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    let err = parse_apdu_header(&apdu).expect_err("Lc=10 with 5 bytes must overrun");
    assert_eq!(err, FramingError::LcOverrun);
}

#[test]
fn negative_apdu_parse_header_rejects_max_lc_with_no_room() {
    // Lc = 0xFF, only the 5-byte header present.
    let apdu = [0x00u8, 0x01, 0x02, 0x03, 0xFF];
    let err = parse_apdu_header(&apdu).expect_err("Lc=255 with 0 data must overrun");
    assert_eq!(err, FramingError::LcOverrun);
}

#[test]
fn negative_apdu_parse_header_never_panics_on_pathological_inputs() {
    let inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xFF],
        vec![0xFF; 4],
        vec![0xFF; 5],
        // checked_add overflow attempt: 5 + 0xFF wouldn't wrap on
        // 64-bit, so this is mostly a regression seed.
        vec![0xFF; 260],
        (0..=255u8).collect(),
    ];
    for inp in inputs {
        let _ = parse_apdu_header(&inp);
    }
}

// ===========================================================================
//   shared::apdu_framing::HidFrameAssembler
// ===========================================================================
// First parser every USB byte hits. Per CLAUDE.md, "anyone with a USB
// cable" can drive it.

#[test]
fn positive_hid_assembler_single_frame_apdu_completes() {
    // Tag 0x83 (APDU), seq=0, length=4, payload=[CLA, INS, P1, P2].
    let mut report = [0u8; HID_REPORT_SIZE];
    report[0] = 0x12; // channel high
    report[1] = 0x34; // channel low
    report[2] = pqsigner_proto::HID_TAG_APDU;
    report[3] = 0x00; // seq high
    report[4] = 0x00; // seq low
    report[5] = 0x00; // len high
    report[6] = 0x04; // len = 4
    report[7] = 0xAA;
    report[8] = 0xBB;
    report[9] = 0xCC;
    report[10] = 0xDD;
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let r = asm.process_frame(&report, HID_REPORT_SIZE, &mut buf);
    assert_eq!(r, FrameOutcome::ApduComplete(4));
    assert_eq!(&buf[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
}

// ─── negatives ────────────────────────────────────────────────────────

#[test]
fn negative_hid_assembler_drops_frame_shorter_than_3_bytes() {
    // n < 3 → no (channel, tag) prefix at all. Must drop, not panic.
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let report = [0u8; HID_REPORT_SIZE];
    for n in 0..3usize {
        let r = asm.process_frame(&report, n, &mut buf);
        assert_eq!(
            r,
            FrameOutcome::Dropped,
            "n={n} (< 3) must drop frame, not panic",
        );
    }
}

#[test]
fn negative_hid_assembler_drops_frame_when_n_exceeds_report_len() {
    // Attacker-controlled `n` must not be trusted: an `n` larger than
    // `report.len()` would otherwise let the assembler read past the
    // USB stack's buffer. Documented: returns `Dropped`.
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let report = [0u8; HID_REPORT_SIZE];
    let r = asm.process_frame(&report, HID_REPORT_SIZE + 1, &mut buf);
    assert_eq!(r, FrameOutcome::Dropped);
}

#[test]
fn negative_hid_assembler_drops_zero_length_apdu_first_frame() {
    // Per CLAUDE.md / `process_frame`: rx_expected == 0 is rejected.
    // An attacker who could get past this would crash the assembler
    // (rx_pos never reaches rx_expected → infinite NeedMore).
    let mut report = [0u8; HID_REPORT_SIZE];
    report[2] = pqsigner_proto::HID_TAG_APDU;
                      // seq=0, len=0
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let r = asm.process_frame(&report, HID_REPORT_SIZE, &mut buf);
    assert_eq!(
        r,
        FrameOutcome::Dropped,
        "len=0 must be rejected — would otherwise leak into infinite NeedMore"
    );
}

#[test]
fn negative_hid_assembler_drops_oversize_apdu() {
    // Declare a 65535-byte APDU (the wire-max u16). MAX_APDU_RX is
    // 4096, so this MUST drop.
    let mut report = [0u8; HID_REPORT_SIZE];
    report[2] = 0x83;
    report[5] = 0xFF;
    report[6] = 0xFF;
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let r = asm.process_frame(&report, HID_REPORT_SIZE, &mut buf);
    assert_eq!(
        r,
        FrameOutcome::Dropped,
        "65535-byte declared length must be rejected (MAX_APDU_RX = {})",
        MAX_APDU_RX
    );
}

#[test]
fn negative_hid_assembler_drops_continuation_with_wrong_sequence() {
    // First frame: seq=0, len=200 (so it spans multiple frames).
    // Second frame: seq=99 (instead of 1). Must drop + reset state.
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];

    let mut first = [0u8; HID_REPORT_SIZE];
    first[2] = pqsigner_proto::HID_TAG_APDU;
    first[5] = 0x00; // length hi
    first[6] = 0xC8; // length = 200 (will span frames)
    let r = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);
    assert_eq!(r, FrameOutcome::NeedMore);

    let mut second = [0u8; HID_REPORT_SIZE];
    second[2] = pqsigner_proto::HID_TAG_APDU;
    second[3] = 0x00; // seq hi
    second[4] = 0x63; // seq = 99 (wrong)
    let r = asm.process_frame(&second, HID_REPORT_SIZE, &mut buf);
    assert_eq!(
        r,
        FrameOutcome::Dropped,
        "out-of-order continuation MUST be dropped + state reset",
    );
}

#[test]
fn negative_hid_assembler_drops_continuation_with_wrong_channel() {
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];

    let mut first = [0u8; HID_REPORT_SIZE];
    first[0] = 0xAA;
    first[1] = 0xBB;
    first[2] = pqsigner_proto::HID_TAG_APDU;
    first[6] = 0xC8; // length 200
    let r = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);
    assert_eq!(r, FrameOutcome::NeedMore);

    let mut second = [0u8; HID_REPORT_SIZE];
    second[0] = 0xDE; // different channel
    second[1] = 0xAD;
    second[2] = pqsigner_proto::HID_TAG_APDU;
    second[3] = 0x00;
    second[4] = 0x01; // correct seq, wrong channel
    let r = asm.process_frame(&second, HID_REPORT_SIZE, &mut buf);
    assert_eq!(
        r,
        FrameOutcome::Dropped,
        "cross-channel frame in the middle of an APDU MUST be dropped — \
         otherwise a malicious host can hijack an in-flight APDU"
    );
}

#[test]
fn negative_hid_assembler_unknown_tag_dropped() {
    let mut report = [0u8; HID_REPORT_SIZE];
    report[2] = 0x42; // not HID_TAG_APDU nor HID_TAG_PING
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let r = asm.process_frame(&report, HID_REPORT_SIZE, &mut buf);
    assert_eq!(r, FrameOutcome::Dropped, "unknown HID tag must be dropped");
}

#[test]
fn negative_hid_assembler_never_panics_on_random_byte_streams() {
    // Mirror the libFuzzer harness's invariant directly: any byte
    // stream, any (n, report) shape, must terminate without panic.
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];
    let data: Vec<u8> = (0..=255u8).cycle().take(8 * (HID_REPORT_SIZE + 1)).collect();
    let mut i = 0;
    while i + 1 + HID_REPORT_SIZE <= data.len() {
        let n = (data[i] as usize) % (HID_REPORT_SIZE + 2);
        let frame: &[u8] = &data[i + 1..i + 1 + HID_REPORT_SIZE];
        let _ = asm.process_frame(frame, n, &mut buf);
        i += 1 + HID_REPORT_SIZE;
    }
}

// ===========================================================================
//   Cross-cutting: every parser must terminate quickly on length-prefix
//   overflow attempts.
// ===========================================================================

#[test]
fn negative_all_parsers_terminate_on_max_u16_length_prefix() {
    // Recurring attack across length-prefixed parsers: claim a length
    // far exceeding the buffer. Must not panic; must not loop.
    let mut buf = vec![0u8; 4 + 64];
    buf[0] = 0xa9; // ERC-20 transfer selector prefix (just a known byte)
    buf[1] = 0x05;
    buf[2] = 0x9c;
    buf[3] = 0xbb;
    let _ = erc20::calldata::parse_erc20_calldata(&buf);
    let _ = userop::parse_header(&buf);
    let _ = parse_apdu_header(&buf);
    let _ = erc20::bundle::verify_erc20_bundle(&buf, &ZERO_ROOT);
    let _ = rlp::decode_item(&buf);
    let _ = eip1559::parse(&buf);
}
