//! Negative: adversarial tests against the wire-format parsers and the
//! HID reassembly state machine.
//!
//! These parsers are the **first thing every USB byte sees** (per the
//! `apdu_framing` module doc): a panic, OOB write, or hung state machine
//! here is a path from "anyone with a USB cable" to "compute in the
//! secure world". The proptests in-module prove "no panic for any input";
//! these tests pin down *specific* hostile shapes and the exact rejection
//! that proves the parser refuses them.

use sphincs_tz_shared::apdu_framing::*;
use sphincs_tz_shared::{APDU_CLA_V2, HID_REPORT_SIZE, HID_TAG_APDU};

// ─── parse_apdu_header — header-too-short ─────────────────────────────────

#[test]
fn negative_parse_apdu_header_empty_input() {
    // Assumption attacked: parser must reject any input shorter than the
    // 4-byte header rather than reading uninitialised memory.
    assert_eq!(
        parse_apdu_header(&[]).unwrap_err(),
        FramingError::HeaderTooShort
    );
}

#[test]
fn negative_parse_apdu_header_1_2_3_bytes() {
    for len in 1..=3 {
        let buf = vec![0u8; len];
        assert_eq!(
            parse_apdu_header(&buf).unwrap_err(),
            FramingError::HeaderTooShort,
            "len={len} must be rejected"
        );
    }
}

// ─── parse_apdu_header — Lc overrun ───────────────────────────────────────

#[test]
fn negative_parse_apdu_header_lc_with_no_data() {
    // 5-byte APDU declaring Lc=1 but supplying zero data bytes.
    let buf = [APDU_CLA_V2, 0x01, 0, 0, 1];
    assert_eq!(
        parse_apdu_header(&buf).unwrap_err(),
        FramingError::LcOverrun,
        "Lc must NOT consume bytes that aren't there"
    );
}

#[test]
fn negative_parse_apdu_header_lc_off_by_one() {
    // Lc=2 but only one data byte present.
    let buf = [APDU_CLA_V2, 0x01, 0, 0, 2, 0xAA];
    assert_eq!(
        parse_apdu_header(&buf).unwrap_err(),
        FramingError::LcOverrun
    );
}

#[test]
fn negative_parse_apdu_header_lc_max_short_off_by_one() {
    // Lc=255 but only 254 data bytes — must reject without reading past
    // the buffer.
    let mut buf = vec![0u8; 5 + 254];
    buf[0] = APDU_CLA_V2;
    buf[4] = 0xFF;
    assert_eq!(
        parse_apdu_header(&buf).unwrap_err(),
        FramingError::LcOverrun
    );
}

// ─── route_v2 — wrong CLA ────────────────────────────────────────────────

#[test]
fn negative_route_v2_rejects_every_wrong_cla_for_non_get_response() {
    // For any INS != GET_RESPONSE, only CLA == APDU_CLA_V2 (0xF0) is
    // accepted. A regression that accepts CLA=0x00 ("ISO 7816-4 default")
    // would re-introduce v1 protocol confusion across the wire.
    for cla in 0u8..=0xFFu8 {
        if cla == APDU_CLA_V2 {
            continue;
        }
        let h = ApduHeader {
            cla,
            ins: 0x42, // NOT INS_V2_GET_RESPONSE
            p1: 0,
            p2: 0,
            lc: 0,
            data: &[],
        };
        assert_eq!(
            route_v2(&h).unwrap_err(),
            RoutingError::ClassUnsupported,
            "CLA 0x{cla:02X} must be rejected — only 0xF0 is the v2 class"
        );
    }
}

#[test]
fn negative_framing_error_sw_is_wire_correct_6700() {
    // Pin the SW value: 0x6700 is what the companion already special-
    // cases as "retry with case-2 form". A silent change would break the
    // companion's recovery.
    assert_eq!(FramingError::HeaderTooShort.to_sw(), 0x6700);
    assert_eq!(FramingError::LcOverrun.to_sw(), 0x6700);
}

#[test]
fn negative_routing_error_sw_is_wire_correct_6e00() {
    assert_eq!(RoutingError::ClassUnsupported.to_sw(), 0x6E00);
}

// ─── ChainState — protocol violations ─────────────────────────────────────

#[test]
fn negative_chain_state_ins_swap_mid_chain_resets() {
    // Assumption: switching INS mid-chain is a protocol error, and the
    // assembler must NOT carry the partial buffer over to the new INS.
    let mut s = ChainState::new();
    let _ = s.step(0x30, 0x80, 50, 4096);
    assert_eq!(s.active_ins(), 0x30);
    assert_eq!(s.pos(), 50);

    let outcome = s.step(0x40 /* different INS */, 0x80, 50, 4096);
    assert_eq!(outcome, ChainStepOutcome::ProtocolError);
    assert_eq!(
        s.active_ins(),
        0,
        "state must reset on INS swap — otherwise host can splice two INSs"
    );
    assert_eq!(s.pos(), 0);
}

#[test]
fn negative_chain_state_overflow_lc_rejected() {
    // checked_add(pos, lc) overflow — a hostile lc near usize::MAX must
    // be rejected without advancing pos.
    let mut s = ChainState::new();
    let outcome = s.step(0x30, 0x80, usize::MAX, 4096);
    assert_eq!(outcome, ChainStepOutcome::WrongLength);
    assert_eq!(s.pos(), 0);
    assert_eq!(s.active_ins(), 0);
}

#[test]
fn negative_chain_state_pos_plus_lc_exceeds_capacity() {
    // Common attack: ratchet `pos` past `cap` over multiple frames.
    let mut s = ChainState::new();
    let _ = s.step(0x30, 0x80, 900, 1024);
    assert_eq!(s.pos(), 900);
    let outcome = s.step(0x30, 0x80, 200, 1024); // 900+200=1100 > 1024
    assert_eq!(outcome, ChainStepOutcome::WrongLength);
    assert_eq!(
        s.pos(),
        0,
        "WrongLength must reset state — leaving pos=900 would allow a retry to land mid-buffer"
    );
}

#[test]
fn negative_chain_state_zero_capacity_rejects_any_data() {
    // cap=0 must reject any lc>0 immediately.
    let mut s = ChainState::new();
    let outcome = s.step(0x30, 0x80, 1, 0);
    assert_eq!(outcome, ChainStepOutcome::WrongLength);
    assert_eq!(s.pos(), 0);
}

#[test]
fn negative_chain_state_pos_never_exceeds_cap_after_protocol_error() {
    // After ProtocolError the state machine is back to "no chain in
    // progress" — the next step is the new chain's first frame.
    let mut s = ChainState::new();
    let _ = s.step(0x30, 0x80, 100, 1024);
    let _ = s.step(0x40, 0x80, 100, 1024); // ProtocolError → reset
    let outcome = s.step(0x40, 0x80, 50, 1024); // fresh start
    assert!(matches!(
        outcome,
        ChainStepOutcome::Appended { write_at: 0, lc: 50 }
    ));
    assert_eq!(s.pos(), 50);
}

// ─── HidFrameAssembler — malformed and out-of-range ───────────────────────

fn fresh_buf() -> [u8; MAX_APDU_RX] {
    [0u8; MAX_APDU_RX]
}

#[test]
fn negative_hid_short_n_dropped() {
    // n < 3 → can't even read (channel, tag) — must drop, not panic.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let frame = [0u8; HID_REPORT_SIZE];
    for n in 0..3 {
        assert_eq!(
            asm.process_frame(&frame, n, &mut buf),
            FrameOutcome::Dropped,
            "n={n} must drop"
        );
    }
}

#[test]
fn negative_hid_n_greater_than_report_dropped() {
    // n > report.len() — host claims more bytes than the buffer holds.
    // MUST drop without writing.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let frame = [0u8; HID_REPORT_SIZE];
    assert_eq!(
        asm.process_frame(&frame, HID_REPORT_SIZE + 1, &mut buf),
        FrameOutcome::Dropped
    );
}

#[test]
fn negative_hid_unknown_tag_dropped() {
    // Any tag that isn't PING or APDU must be dropped — silently
    // dispatching to APDU on an unknown tag would let a host fake a
    // PING-style channel-zero frame.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    for bad_tag in 0u8..=0xFFu8 {
        if bad_tag == HID_TAG_APDU || bad_tag == 0x02 /* PING */ {
            continue;
        }
        frame[2] = bad_tag;
        assert_eq!(
            asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf),
            FrameOutcome::Dropped,
            "tag 0x{bad_tag:02X} must drop"
        );
    }
}

#[test]
fn negative_hid_apdu_frame_too_short_for_seq() {
    // tag=APDU but n < 5 → can't even read seq.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[2] = HID_TAG_APDU;
    for n in 3..5 {
        assert_eq!(
            asm.process_frame(&frame, n, &mut buf),
            FrameOutcome::Dropped,
            "n={n} (APDU tag, no seq) must drop"
        );
    }
}

#[test]
fn negative_hid_first_frame_too_short_for_expected_len() {
    // seq==0 but n < 7 → can't read the 2-byte expected length. Drop.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[2] = HID_TAG_APDU;
    // seq = 0
    frame[3] = 0;
    frame[4] = 0;
    for n in 5..7 {
        assert_eq!(
            asm.process_frame(&frame, n, &mut buf),
            FrameOutcome::Dropped,
            "first frame n={n} must drop"
        );
    }
}

#[test]
fn negative_hid_first_frame_zero_expected_dropped() {
    // expected==0 is nonsensical — the assembler must drop, not loop or
    // immediately emit ApduComplete(0) which would feed an empty APDU
    // upward.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    frame[2] = HID_TAG_APDU;
    frame[3] = 0;
    frame[4] = 0;
    frame[5..7].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf),
        FrameOutcome::Dropped
    );
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn negative_hid_first_frame_oversize_expected_dropped() {
    // expected > MAX_APDU_RX must be dropped — a host that claims 65535
    // bytes must NOT be allowed to scrub the assembler into a state where
    // a later copy walks past the caller's buffer end.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[2] = HID_TAG_APDU;
    frame[3] = 0;
    frame[4] = 0;
    // expected = 0xFFFF (>> MAX_APDU_RX = 4096)
    frame[5..7].copy_from_slice(&0xFFFFu16.to_be_bytes());
    assert_eq!(
        asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf),
        FrameOutcome::Dropped
    );
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn negative_hid_first_frame_expected_larger_than_caller_buf_dropped() {
    // Defence-in-depth: even if expected ≤ MAX_APDU_RX, if the caller's
    // buffer is smaller, the assembler must drop rather than corrupting
    // memory.
    let mut small_buf = [0u8; 16];
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[2] = HID_TAG_APDU;
    frame[3] = 0;
    frame[4] = 0;
    frame[5..7].copy_from_slice(&100u16.to_be_bytes()); // 100 > 16
    assert_eq!(
        asm.process_frame(&frame, HID_REPORT_SIZE, &mut small_buf),
        FrameOutcome::Dropped
    );
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn negative_hid_continuation_wrong_channel_dropped() {
    // After a valid first frame, a continuation with a DIFFERENT channel
    // id must be dropped and the assembler reset. A host that hijacks
    // mid-reassembly is precisely the threat this guards against.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();

    let payload = [0xAA; 80];
    let first = {
        let mut f = [0u8; HID_REPORT_SIZE];
        f[0..2].copy_from_slice(&0x1111u16.to_be_bytes());
        f[2] = HID_TAG_APDU;
        f[3] = 0;
        f[4] = 0;
        f[5..7].copy_from_slice(&80u16.to_be_bytes());
        f[7..7 + 57].copy_from_slice(&payload[..57]);
        f
    };
    let out1 = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);
    assert_eq!(out1, FrameOutcome::NeedMore);
    assert_eq!(asm.channel_id(), 0x1111);

    let mut cont = [0u8; HID_REPORT_SIZE];
    cont[0..2].copy_from_slice(&0x2222u16.to_be_bytes()); // wrong channel
    cont[2] = HID_TAG_APDU;
    cont[3] = 0;
    cont[4] = 1;
    let out2 = asm.process_frame(&cont, HID_REPORT_SIZE, &mut buf);
    assert_eq!(out2, FrameOutcome::Dropped);
    assert_eq!(asm.rx_expected(), 0, "must reset on channel mismatch");
}

#[test]
fn negative_hid_continuation_wrong_seq_dropped() {
    // Continuation with the right channel but wrong seq must be dropped
    // and the assembler reset.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();

    let mut first = [0u8; HID_REPORT_SIZE];
    first[0..2].copy_from_slice(&0x3333u16.to_be_bytes());
    first[2] = HID_TAG_APDU;
    first[3] = 0;
    first[4] = 0;
    first[5..7].copy_from_slice(&80u16.to_be_bytes());
    let _ = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);

    let mut cont = [0u8; HID_REPORT_SIZE];
    cont[0..2].copy_from_slice(&0x3333u16.to_be_bytes());
    cont[2] = HID_TAG_APDU;
    cont[3] = 0;
    cont[4] = 7; // expected seq is 1
    let out = asm.process_frame(&cont, HID_REPORT_SIZE, &mut buf);
    assert_eq!(out, FrameOutcome::Dropped);
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn negative_hid_continuation_before_first_dropped() {
    // A fresh assembler has channel_id=0 and rx_seq=0; any non-seq-0
    // first frame from a non-zero channel must be dropped (it can't
    // match the empty in-flight state).
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();
    let mut cont = [0u8; HID_REPORT_SIZE];
    cont[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
    cont[2] = HID_TAG_APDU;
    cont[3] = 0;
    cont[4] = 1;
    assert_eq!(
        asm.process_frame(&cont, HID_REPORT_SIZE, &mut buf),
        FrameOutcome::Dropped
    );
}

#[test]
fn negative_hid_state_resets_after_dropped() {
    // After Dropped (any cause), the assembler must be re-usable as if
    // it were brand new. Tested by completing a fresh APDU after a
    // dropped continuation.
    let mut buf = fresh_buf();
    let mut asm = HidFrameAssembler::new();

    // Trigger a Dropped via continuation-before-first.
    let mut bad = [0u8; HID_REPORT_SIZE];
    bad[0..2].copy_from_slice(&0xAAAAu16.to_be_bytes());
    bad[2] = HID_TAG_APDU;
    bad[4] = 5;
    let _ = asm.process_frame(&bad, HID_REPORT_SIZE, &mut buf);

    // Now drive a clean single-frame APDU through.
    let mut first = [0u8; HID_REPORT_SIZE];
    first[0..2].copy_from_slice(&0xBBBBu16.to_be_bytes());
    first[2] = HID_TAG_APDU;
    first[3] = 0;
    first[4] = 0;
    first[5..7].copy_from_slice(&8u16.to_be_bytes());
    first[7..15].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let outcome = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);
    assert_eq!(outcome, FrameOutcome::ApduComplete(8));
    assert_eq!(&buf[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

// ─── ChainStepOutcome — variant discrimination ────────────────────────────

#[test]
fn negative_chain_step_outcome_variants_distinct() {
    // A refactor that accidentally collapses two variants into the same
    // SW value would let one error class masquerade as another to the
    // companion's retry logic. Pin both helpers to different values.
    assert_ne!(
        ChainStepOutcome::protocol_error_sw(),
        ChainStepOutcome::wrong_length_sw(),
        "ProtocolError and WrongLength must map to distinct SWs"
    );
}
