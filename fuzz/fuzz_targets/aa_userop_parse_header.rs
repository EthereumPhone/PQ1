//! libFuzzer harness for `pqsigner_aa::userop::parse_header` — the
//! parser for the unified SIGN_USEROP / CLEAR_SIGN wire format (the
//! 330+ B blob CLAUDE.md §"Wire formats" describes). Every byte after
//! the NSC pointer-validation boundary lands here; a panic / OOB /
//! infinite loop in this function is a direct DoS surface against the
//! secure world from any attacker who can drive USB HID.
//!
//! Property exercised: `parse_header` MUST terminate in bounded time
//! and return a well-typed `Result<AaUserOpParams, WireParseError>`
//! for any input slice — no panic, no OOB read, no UB. Already
//! covered by `secure/src/fuzz_props.rs::aa_userop_parse_header_
//! never_panics` (proptest); this is the coverage-guided libFuzzer
//! cross-check (trezor-comparison §2.4).

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_aa::userop;

fuzz_target!(|data: &[u8]| {
    let _ = userop::parse_header(data);
});
