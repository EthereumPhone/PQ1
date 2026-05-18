//! Positive: `apdu_framing` API surface beyond what the in-module
//! regression block already covers.

use sphincs_tz_shared::apdu_framing::*;
use sphincs_tz_shared::{
    APDU_CLA_V2, HID_REPORT_SIZE, HID_TAG_APDU, HID_TAG_PING,
    INS_V2_GET_RESPONSE, SW_CLA_NOT_SUPPORTED, SW_CONDITIONS_NOT_SATISFIED,
    SW_WRONG_LENGTH,
};

// ─── Framing error → SW mapping ───────────────────────────────────────────

#[test]
fn positive_framing_error_to_sw_both_variants() {
    assert_eq!(FramingError::HeaderTooShort.to_sw(), SW_WRONG_LENGTH);
    assert_eq!(FramingError::LcOverrun.to_sw(), SW_WRONG_LENGTH);
}

#[test]
fn positive_routing_error_to_sw() {
    assert_eq!(RoutingError::ClassUnsupported.to_sw(), SW_CLA_NOT_SUPPORTED);
}

#[test]
fn positive_chain_step_outcome_sw_helpers() {
    assert_eq!(
        ChainStepOutcome::protocol_error_sw(),
        SW_CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(ChainStepOutcome::wrong_length_sw(), SW_WRONG_LENGTH);
}

// ─── p1_more_follows ──────────────────────────────────────────────────────

#[test]
fn positive_p1_more_follows_bit7() {
    assert!(p1_more_follows(0x80));
    assert!(p1_more_follows(0xFF));
    assert!(!p1_more_follows(0x00));
    assert!(!p1_more_follows(0x7F));
    assert!(!p1_more_follows(0x01));
}

// ─── parse_apdu_header — additional boundaries ────────────────────────────

#[test]
fn positive_parse_apdu_header_4_byte_exactly() {
    let h = parse_apdu_header(&[APDU_CLA_V2, 0xAB, 0x01, 0x02]).unwrap();
    assert_eq!(h.cla, APDU_CLA_V2);
    assert_eq!(h.ins, 0xAB);
    assert_eq!(h.p1, 0x01);
    assert_eq!(h.p2, 0x02);
    assert_eq!(h.lc, 0);
    assert!(h.data.is_empty());
}

#[test]
fn positive_parse_apdu_header_lc1_one_byte_data() {
    let h = parse_apdu_header(&[APDU_CLA_V2, 0x01, 0, 0, 1, 0xAA]).unwrap();
    assert_eq!(h.lc, 1);
    assert_eq!(h.data, &[0xAA]);
}

#[test]
fn positive_parse_apdu_header_trailing_bytes_after_lc_are_ignored() {
    // ISO 7816-4 short-form `Lc` is followed by Le bytes; the parser
    // returns the data slice and leaves trailing bytes for the caller.
    let buf = [APDU_CLA_V2, 0x01, 0, 0, 2, 0xAA, 0xBB, 0xCC, 0xDD];
    let h = parse_apdu_header(&buf).unwrap();
    assert_eq!(h.lc, 2);
    assert_eq!(h.data, &[0xAA, 0xBB]);
}

// ─── route_v2 happy paths ─────────────────────────────────────────────────

#[test]
fn positive_route_v2_accepts_correct_cla() {
    let h = ApduHeader {
        cla: APDU_CLA_V2,
        ins: 0x42,
        p1: 0,
        p2: 0,
        lc: 0,
        data: &[],
    };
    assert!(route_v2(&h).is_ok());
}

#[test]
fn positive_route_v2_get_response_with_correct_cla() {
    let h = ApduHeader {
        cla: APDU_CLA_V2,
        ins: INS_V2_GET_RESPONSE,
        p1: 0,
        p2: 0,
        lc: 0,
        data: &[],
    };
    assert!(route_v2(&h).is_ok());
}

// ─── ChainState ───────────────────────────────────────────────────────────

#[test]
fn positive_chain_state_default_equals_new() {
    let a = ChainState::default();
    let b = ChainState::new();
    assert_eq!(a.active_ins(), b.active_ins());
    assert_eq!(a.pos(), b.pos());
    assert_eq!(a.active_ins(), 0);
    assert_eq!(a.pos(), 0);
}

#[test]
fn positive_chain_state_single_frame_execute() {
    // First and only frame: more=0.
    let mut s = ChainState::new();
    let outcome = s.step(0x30, 0x00, 64, 4096);
    match outcome {
        ChainStepOutcome::Execute {
            ins,
            final_len,
            write_at,
            lc,
        } => {
            assert_eq!(ins, 0x30);
            assert_eq!(final_len, 64);
            assert_eq!(write_at, 0);
            assert_eq!(lc, 64);
        }
        other => panic!("expected Execute, got {other:?}"),
    }
    // State reset after Execute.
    assert_eq!(s.active_ins(), 0);
    assert_eq!(s.pos(), 0);
}

#[test]
fn positive_chain_state_lc_zero_in_chain() {
    // Some clients legitimately send an empty trailing chunk (more=0,
    // lc=0) to "commit" the buffer accumulated so far.
    let mut s = ChainState::new();
    let _ = s.step(0x30, 0x80, 100, 4096);
    let outcome = s.step(0x30, 0x00, 0, 4096);
    match outcome {
        ChainStepOutcome::Execute { final_len, .. } => assert_eq!(final_len, 100),
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn positive_chain_state_reset_idempotent() {
    let mut s = ChainState::new();
    s.reset();
    s.reset();
    assert_eq!(s.active_ins(), 0);
    assert_eq!(s.pos(), 0);
}

// ─── HidFrameAssembler ────────────────────────────────────────────────────

const fn first_data_max() -> usize {
    // Mirror of HID_REPORT_SIZE - 7.
    HID_REPORT_SIZE - 7
}

fn make_first_frame(channel: u16, expected: u16, payload: &[u8]) -> [u8; 64] {
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[0..2].copy_from_slice(&channel.to_be_bytes());
    frame[2] = HID_TAG_APDU;
    frame[3] = 0; // seq high
    frame[4] = 0; // seq low (= 0)
    frame[5..7].copy_from_slice(&expected.to_be_bytes());
    let n = core::cmp::min(payload.len(), first_data_max());
    frame[7..7 + n].copy_from_slice(&payload[..n]);
    frame
}

fn make_cont_frame(channel: u16, seq: u16, payload: &[u8]) -> [u8; 64] {
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[0..2].copy_from_slice(&channel.to_be_bytes());
    frame[2] = HID_TAG_APDU;
    frame[3..5].copy_from_slice(&seq.to_be_bytes());
    let n = core::cmp::min(payload.len(), HID_REPORT_SIZE - 5);
    frame[5..5 + n].copy_from_slice(&payload[..n]);
    frame
}

#[test]
fn positive_hid_default_equals_new() {
    let a = HidFrameAssembler::default();
    let b = HidFrameAssembler::new();
    assert_eq!(a.channel_id(), b.channel_id());
    assert_eq!(a.rx_expected(), b.rx_expected());
    assert_eq!(a.channel_id(), 0);
    assert_eq!(a.rx_expected(), 0);
}

#[test]
fn positive_hid_complete_single_frame() {
    // expected ≤ HID_FIRST_DATA → assembler completes in one frame.
    let mut buf = [0u8; MAX_APDU_RX];
    let mut asm = HidFrameAssembler::new();
    let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0xAA, 0xBB, 0xCC];
    let frame = make_first_frame(0x1234, payload.len() as u16, &payload);
    let outcome = asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf);
    assert_eq!(outcome, FrameOutcome::ApduComplete(payload.len()));
    assert_eq!(&buf[..payload.len()], &payload[..]);
    // State must reset after completion.
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn positive_hid_ping_echo() {
    let mut buf = [0u8; MAX_APDU_RX];
    let mut asm = HidFrameAssembler::new();
    let mut frame = [0u8; HID_REPORT_SIZE];
    frame[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    frame[2] = HID_TAG_PING;
    let outcome = asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf);
    assert_eq!(outcome, FrameOutcome::PingEcho);
}

#[test]
fn positive_hid_multi_frame_reassembly() {
    let mut buf = [0u8; MAX_APDU_RX];
    let mut asm = HidFrameAssembler::new();

    // Total payload: first_data_max() + 10 bytes — needs exactly 2 frames.
    let total = first_data_max() + 10;
    let mut payload = [0u8; 256];
    for (i, b) in payload.iter_mut().enumerate().take(total) {
        *b = (i & 0xFF) as u8;
    }

    let first = make_first_frame(0x5566, total as u16, &payload[..first_data_max()]);
    let out1 = asm.process_frame(&first, HID_REPORT_SIZE, &mut buf);
    assert_eq!(out1, FrameOutcome::NeedMore);
    assert_eq!(asm.channel_id(), 0x5566);
    assert_eq!(asm.rx_expected(), total);

    let cont = make_cont_frame(0x5566, 1, &payload[first_data_max()..total]);
    let out2 = asm.process_frame(&cont, HID_REPORT_SIZE, &mut buf);
    assert_eq!(out2, FrameOutcome::ApduComplete(total));
    assert_eq!(&buf[..total], &payload[..total]);
    // Reset after completion.
    assert_eq!(asm.rx_expected(), 0);
}

#[test]
fn positive_hid_reset_clears_state() {
    let mut buf = [0u8; MAX_APDU_RX];
    let mut asm = HidFrameAssembler::new();
    let payload = [0xAA; 8];
    let frame = make_first_frame(0x77, 200, &payload); // claim more than fits in one frame
    let _ = asm.process_frame(&frame, HID_REPORT_SIZE, &mut buf);
    assert_ne!(asm.rx_expected(), 0);
    asm.reset();
    assert_eq!(asm.rx_expected(), 0);
}

// ─── Stable derived constants ─────────────────────────────────────────────

#[test]
fn positive_hid_first_data_and_cont_data_consistent() {
    // The two per-frame data widths are derived from HID_REPORT_SIZE.
    // Pin them so a refactor that hard-codes 57/59 elsewhere can be
    // caught by changing one source of truth here.
    assert_eq!(HID_FIRST_DATA, HID_REPORT_SIZE - 7);
    assert_eq!(HID_CONT_DATA, HID_REPORT_SIZE - 5);
    assert_eq!(HID_FIRST_DATA, 57);
    assert_eq!(HID_CONT_DATA, 59);
}

#[test]
fn positive_max_apdu_rx_is_4kib() {
    assert_eq!(MAX_APDU_RX, 4096);
}
