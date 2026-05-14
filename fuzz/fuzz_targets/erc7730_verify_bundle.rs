//! libFuzzer harness for `pqsigner_erc7730::bundle::verify_erc7730_bundle`
//! — the trailer verifier consumed by `cmd_sign_userop` /
//! `cmd_sign_userop_batch` / `cmd_sign_offchain` on every clear-signing
//! request. Same model as `tx_erc20_verify_bundle`: a zero root so the
//! Merkle walk always rejects, exercising every code path that runs
//! before the final root compare (length prefixes, IR header parse,
//! pool / formats bounds, proof-depth cap, trailing-bytes check).
//!
//! Property: must terminate + return `Result<VerifiedDescriptor,
//! BundleError>` without panicking for any input.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;

const ZERO_ROOT: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = verify_erc7730_bundle(data, &ZERO_ROOT);
});
