//! libFuzzer harness for `pqsigner_tx_core::rlp::decode_item` — the
//! foundational RLP decoder used by the EIP-1559 envelope parser and
//! the EIP-712 typed-data verifiers. Every Ethereum tx that flows
//! through the trusted-UI clear-sign path is parsed via this.
//!
//! Property: must terminate + return `Result<(Item, usize), RlpError>`
//! for any input. Length-prefixes can claim sizes well beyond the
//! buffer end and the decoder must reject without panicking. Already
//! covered by `secure/src/fuzz_props.rs::rlp_decode_item_never_panics`
//! (proptest); this is the libFuzzer cross-check.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_tx_core::rlp;

fuzz_target!(|data: &[u8]| {
    let _ = rlp::decode_item(data);
});
