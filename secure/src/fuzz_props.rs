//! Property-based fuzz tests for every parser that consumes bytes
//! crossing the NS→S trust boundary.
//!
//! # What this exists to catch
//!
//! Every parser below reads a `&[u8]` that originated in the non-secure
//! world (USB host payload, NSC gateway input, TOCTOU-snapshotted NS
//! buffer). A panic — or a buffer-overrun, an infinite loop, or a
//! heap-like unbounded allocation — in any of these on hostile input
//! is a direct path from "anyone who can plug into the USB port" to
//! "secure-world DoS at minimum, arbitrary secure-world compute at
//! worst." These property tests assert one invariant: **the parser
//! terminates in bounded time and returns a well-typed result for
//! any input.**
//!
//! This is PQSigner's narrower, lighter-weight answer to Trezor's
//! `crypto/fuzzer/` libFuzzer harnesses. See
//! `docs/trezor-comparison.md §2.4` for the rationale. proptest is
//! a compile-in test dependency — the `#[cfg(test)]` gate keeps it
//! out of every firmware build. A coverage-guided cargo-fuzz setup
//! would need a `[lib]` target on `sphincs-tz-secure`; adding that is
//! a bigger refactor and tracked for later.
//!
//! # How to extend
//!
//! For every new pure-function parser that takes `&[u8]`, add one
//! `proptest!` block here. Inputs `prop::collection::vec(any::<u8>(),
//! 0..=MAX_LEN)` with a generous `MAX_LEN` are almost always the
//! right shape — we want the parser to handle truncation, overflow,
//! impossible length prefixes, and non-UTF-8 noise alike.
//!
//! # What this does NOT test
//!
//! - NSC pointer validation (`nsc::ptr_validate`) — that relies on
//!   hardware SAU state, not a pure-function signature. Hardware
//!   integration tests cover it.
//! - The `cmd_sign_userop_handler` entry point itself — it takes a
//!   `GatewayArgs` struct with raw NS pointers, unsafe to invoke
//!   from a host fuzz target. The pure sub-parsers below are the
//!   fuzzable slice.

#![cfg(test)]

use proptest::prelude::*;

/// Max input length used for most byte-slice parsers. Well past the
/// largest legitimate input the gateway accepts (see `SIGN_USEROP_HEADER_LEN`
/// and friends in `sphincs_tz_shared`); wide enough to expose overflow
/// in length-prefix fields without blowing test runtime.
const MAX_FUZZ_INPUT: usize = 8192;

/// Smaller cap for parsers whose legitimate inputs are ≤ a few hundred
/// bytes (RLP items, calldata selectors). Keeps the test suite fast.
const SMALL_FUZZ_INPUT: usize = 1024;

proptest! {
    // ─────────────────────────────────────────────────────────────
    // EIP-1559 envelope parser
    //
    // Inputs: raw u8 bytes representing an RLP envelope prefixed
    // with 0x02. Expected to reject malformed input via `TxError`
    // without panicking or looping.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn eip1559_parse_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let _ = crate::tx::eip1559::parse(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // RLP item decoder
    //
    // The deepest-nested parser in the stack. A malformed length
    // prefix can trigger integer overflow if bounds aren't checked.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn rlp_decode_item_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=SMALL_FUZZ_INPUT)
    ) {
        let _ = crate::tx::rlp::decode_item(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // ERC-20 trailer bundle verifier
    //
    // Companion-supplied ERC-20 metadata attached to a user-op for
    // on-device rendering. Signed bundle format; must reject any
    // shape that doesn't carry a valid signature, and must not
    // panic on truncated / overlong input.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn verify_erc20_bundle_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let _ = crate::erc20::bundle::verify_erc20_bundle(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // ERC-20 calldata decoder (`transfer`, `transferFrom`, `approve`)
    //
    // Parses the inner-tx `data` field of a user-op for ERC-20
    // function-selector matching and arg extraction. Must reject
    // unknown selectors without panicking.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn parse_erc20_calldata_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=SMALL_FUZZ_INPUT)
    ) {
        let _ = crate::erc20::calldata::parse_erc20_calldata(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // Address-name trailer bundle verifier
    //
    // Companion-supplied (address → human-readable name) mapping
    // attached to a user-op. Ignored on bad signature; panicking
    // here would be a DoS.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn verify_name_bundle_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let _ = crate::names::verify_name_bundle(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // UserOp header parser
    //
    // The first thing `cmd_sign_userop_handler` parses out of its
    // snapshot of the NS buffer. Fixed-shape layout; the parser
    // should reject any buf shorter than `USEROP_HEADER_LEN` and
    // accept every longer buf identically (trailing bytes are not
    // consumed here — that's a later parser's job).
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn aa_userop_parse_header_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let _ = crate::aa::userop::parse_header(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // Cross-cutting: the parser pipeline order the handler uses.
    //
    // A glitch in how `parse_header` advances the cursor might
    // leave a bad `p` state that later propagates into `rlp` or
    // `verify_erc20_bundle`. This property test calls the parsers
    // in the handler's order to exercise the composed pipeline —
    // still asserting "no panic, any input".
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn composed_pipeline_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let header_ok = crate::aa::userop::parse_header(&input).is_ok();
        if header_ok {
            // Treat everything after the header as potential trailer
            // bytes — the handler dispatches to sub-parsers based on
            // length-prefix fields we're not reconstructing here.
            let tail_start = core::cmp::min(
                sphincs_tz_shared::USEROP_HEADER_LEN,
                input.len(),
            );
            let tail = &input[tail_start..];
            let _ = crate::erc20::bundle::verify_erc20_bundle(tail);
            let _ = crate::names::verify_name_bundle(tail);
        }
    }
}
