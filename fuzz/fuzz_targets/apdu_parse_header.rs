//! libFuzzer harness for `parse_apdu_header` — the APDU-layer
//! header parser sitting immediately above the HID frame assembler.
//! Every byte reassembled from USB lands here before any command
//! dispatch. A panic / OOB / lc-overrun here is a direct DoS path
//! from any host with a USB cable.
//!
//! Mirrors the proptest sibling in
//! `shared/src/apdu_framing.rs::fuzz_props::parse_apdu_header_
//! never_panics`. Coverage-guided libFuzzer variant.

#![no_main]
use libfuzzer_sys::fuzz_target;
use sphincs_tz_shared::apdu_framing::parse_apdu_header;

fuzz_target!(|data: &[u8]| {
    let _ = parse_apdu_header(data);
});
