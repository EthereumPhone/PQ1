//! libFuzzer harness for `pqsigner_tx_core::eip1559::parse` — the
//! EIP-1559 typed-transaction envelope decoder. This is what the
//! signing flow runs over `inner_tx_data` to identify the value /
//! recipient / calldata for the trusted-UI confirm screen. A panic
//! here would crash the secure world on any malformed envelope an
//! attacker can submit via `CMD_SIGN_USEROP`.
//!
//! Property: must terminate + return `Result<ParsedTx, TxError>` for
//! any input slice. Counterpart proptest:
//! `fuzz_props::eip1559_parse_never_panics`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_tx_core::eip1559;

fuzz_target!(|data: &[u8]| {
    let _ = eip1559::parse(data);
});
