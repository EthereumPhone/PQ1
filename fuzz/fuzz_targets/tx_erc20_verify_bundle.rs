//! libFuzzer harness for `pqsigner_tx::erc20::bundle::verify_erc20_bundle`
//! — the Merkle-bundle verifier that runs over the address-name +
//! ERC-20 metadata trust bundle. The bundle is compiled-in
//! (`db_roots::ERC20_ROOT`) but the *bytes* it walks come from
//! firmware flash; a malformed-bundle bug would let a future
//! firmware update corrupt the parser's bounds checks.
//!
//! Property: must terminate + return `Option<Erc20Metadata>` for any
//! input. Counterpart proptest:
//! `fuzz_props::verify_erc20_bundle_never_panics` (which uses the
//! production `db_roots` root; here we use a fixed all-zero root, so
//! the bundle will never *match* — that's intentional, this fuzzer
//! exercises the parser's bounds-checking + the Merkle-walk logic,
//! not the root-check at the end).

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_tx::erc20;

const ZERO_ROOT: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = erc20::bundle::verify_erc20_bundle(data, &ZERO_ROOT);
});
