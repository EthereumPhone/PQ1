//! libFuzzer harness for `HidFrameAssembler::process_frame` — the
//! state machine that reassembles 64-byte USB-HID reports into
//! APDUs. This is the first parser every USB byte hits, before any
//! NSC pointer validation. A panic / OOB / state corruption here is
//! a direct path from "anyone with a USB cable" to firmware DoS.
//!
//! Mirrors the proptest sibling in
//! `shared/src/apdu_framing.rs::fuzz_props::hid_frame_random_input_
//! never_panics`. This is the coverage-guided libFuzzer variant.
//!
//! Input encoding: the raw fuzz bytes are chopped into 64-byte
//! reports and fed to a single assembler instance, so a single
//! corpus entry covers a multi-frame sequence (channel/seq state
//! must survive across frames). The first byte controls the
//! reported `n` for each frame so the fuzzer can drive short / long
//! / oversize `n` values too.

#![no_main]
use libfuzzer_sys::fuzz_target;
use sphincs_tz_shared::apdu_framing::{HidFrameAssembler, MAX_APDU_RX};
use sphincs_tz_shared::HID_REPORT_SIZE;

fuzz_target!(|data: &[u8]| {
    let mut asm = HidFrameAssembler::new();
    let mut buf = [0u8; MAX_APDU_RX];

    // Walk the input as a sequence of (n_byte, 64-byte report) pairs.
    let mut i = 0;
    while i + 1 + HID_REPORT_SIZE <= data.len() {
        let n = (data[i] as usize) % (HID_REPORT_SIZE + 2); // 0..=65, exercises edges
        let frame = &data[i + 1..i + 1 + HID_REPORT_SIZE];
        let _ = asm.process_frame(frame, n, &mut buf);
        i += 1 + HID_REPORT_SIZE;
    }
    // Trailing partial bytes: pad to one report so a short corpus
    // entry still gets a single process_frame call exercised.
    if i < data.len() {
        let mut padded = [0u8; HID_REPORT_SIZE];
        let copy = core::cmp::min(data.len() - i, HID_REPORT_SIZE);
        padded[..copy].copy_from_slice(&data[i..i + copy]);
        let _ = asm.process_frame(&padded, copy, &mut buf);
    }
});
