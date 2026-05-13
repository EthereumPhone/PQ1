//! libFuzzer harness for `pqsigner_tx::erc20::calldata::parse_erc20_calldata`
//! — the Solidity-ABI decoder that identifies known ERC-20 method
//! selectors (`transfer`, `transferFrom`, `approve`) and extracts
//! their arguments for the trusted-UI clear-sign screen. Reached on
//! every UserOp that targets a known ERC-20.
//!
//! Property: must terminate + return `Option<Erc20Call>` for any
//! input. Counterpart proptest:
//! `fuzz_props::parse_erc20_calldata_never_panics`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_tx::erc20;

fuzz_target!(|data: &[u8]| {
    let _ = erc20::calldata::parse_erc20_calldata(data);
});
