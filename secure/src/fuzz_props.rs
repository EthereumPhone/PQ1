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
            let _ = crate::selectors::bundle::verify_selector_bundle(tail);
            // ZK VK bundle verifier is gated behind the `zk` module
            // (BLS12-381 pairing crate is heavy + ARM-only); see the
            // "Coverage NOT exercised here" note at the bottom.
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 4byte selector trailer bundle verifier
    //
    // The companion attaches a Merkle-proof-bound selector→signature
    // mapping so the trusted UI can render "Aggregate(uint256[])"
    // instead of the raw 4-byte selector. Same shape as the
    // ERC-20 / names bundles; same panic-resistance requirement.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn verify_selector_bundle_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        let _ = crate::selectors::bundle::verify_selector_bundle(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // EIP-712 Safe v1 canonical decoder
    //
    // The `safe_v1` clear-sign trailer carries a fixed-length
    // canonical buffer of `(to, value, data_hash, operation, ...,
    // nonce)`. In production the parser only sees well-shaped
    // 281-byte slices, but we still want to prove it's robust to
    // every byte combination — a fault-injected glitch on the bus
    // could feed it anything.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn safe_decode_canonical_never_panics(
        input in any::<[u8; sphincs_tz_shared::SAFE_V1_CANONICAL_LEN]>()
    ) {
        let _ = crate::tx::eip712::safe::decode_canonical(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // EIP-712 CoW order canonical decoder
    //
    // CoW Protocol GPv2 order: 204 bytes of canonical
    // `(sellToken, buyToken, sellAmount, buyAmount, ...)`. Fixed
    // length, parsed once per ZK clear-sign v3, must never panic
    // on fuzz input.
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn cowswap_decode_canonical_never_panics(
        input in any::<[u8; 204]>()
    ) {
        let _ = crate::tx::eip712::cowswap::decode_canonical(&input);
    }

    // ─────────────────────────────────────────────────────────────
    // Firmware manifest verifier (defence-in-depth — fw-manifest
    // already runs its own proptest harness; this exercises the
    // secure-side import surface so a reorganisation of
    // `verify_manifest`'s dependencies doesn't silently regress
    // panic-resistance from a parser the host fuzzer can't see).
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn manifest_ref_chain_never_panics(
        blob in prop::collection::vec(any::<u8>(), fw_manifest::MANIFEST_SIZE..=fw_manifest::MANIFEST_SIZE),
    ) {
        let mut bytes = [0u8; fw_manifest::MANIFEST_SIZE];
        bytes.copy_from_slice(&blob);
        let m = fw_manifest::ManifestRef::new(&bytes);

        let _ = m.verify_structural();
        let _ = m.verify_crc();
        let _ = m.verify_digest();
        let _ = m.verify_rollback(0);
    }

    // ─────────────────────────────────────────────────────────────
    // Reconstruct execute() calldata from a fuzz-derived EIP-1559
    // envelope. This tests the *post-parse* arm of the userop
    // pipeline — once `eip1559::parse` accepts an input, can the
    // ABI re-encoding step still misbehave?
    // ─────────────────────────────────────────────────────────────
    #[test]
    fn reconstruct_execute_calldata_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FUZZ_INPUT)
    ) {
        if let Ok(parsed) = crate::tx::eip1559::parse(&input) {
            let _ = crate::aa::userop::reconstruct_execute_calldata(
                1,        // ownerIndex (typical slot)
                0,        // newOffchainCount (typical first publish)
                &parsed.tx,
                parsed.data,
            );
        }
    }
}

// =============================================================================
//  ISO 7816-4 BER-TLV parsers — extracted to the always-on
//  `crate::iso7816` module so they're host-fuzzable. Both the SE050
//  driver (`se050::apdu`) and the OPTIGA Trust M PIN-counter path
//  (`optiga::apdu::parse_pin_ctr`) delegate to these.
// =============================================================================
proptest! {
    /// SE050 + GP card spec BER-TLV decoder. Defence in depth — a
    /// fault attacker probing the I2C bus could smuggle bogus TLV
    /// bytes into the SE050 response stream. Our decoder must
    /// terminate without panic for any input.
    #[test]
    fn iso7816_tlv_parse_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=SMALL_FUZZ_INPUT)
    ) {
        let _ = crate::iso7816::tlv_parse(&input);
    }

    /// Repeatedly decoding TLVs from the same buffer (walking the
    /// `rest` slice on each iteration) must terminate. Catches a
    /// hypothetical bug where `rest` could ever equal `data` and
    /// loop forever.
    #[test]
    fn iso7816_tlv_parse_iter_terminates(
        input in prop::collection::vec(any::<u8>(), 0..=SMALL_FUZZ_INPUT)
    ) {
        let mut cursor: &[u8] = &input;
        for _ in 0..256 {
            match crate::iso7816::tlv_parse(cursor) {
                Some((_, _, rest)) => {
                    // Each step must consume at least one byte.
                    prop_assert!(rest.len() < cursor.len());
                    cursor = rest;
                }
                None => break,
            }
        }
    }

    /// OPTIGA UPCTR `(current, limit)` parser — 8 bytes BE × 2.
    /// Fault on the OPTIGA I2C bus can deliver any 8 bytes; parser
    /// must never panic.
    #[test]
    fn iso7816_parse_pin_ctr_never_panics(
        input in prop::collection::vec(any::<u8>(), 0..=SMALL_FUZZ_INPUT)
    ) {
        let _ = crate::iso7816::parse_pin_ctr(&input);
    }
}

// =============================================================================
//  Coverage NOT exercised here
//
//  These parsers also consume bytes that originate outside the secure
//  world but are gated out of the host test build (their owning modules
//  pull in hardware-only crates):
//
//      * `zk::vk_bundle::verify_vk_bundle`   — ZK clear-sign VK verifier
//      * `fw_update::check_chunk`            — FW_CHUNK bounds checker
//
//  When the gating is loosened (or these parsers are extracted into a
//  pure-function submodule that compiles on host), add the proptest
//  blocks here. Until then, hardware integration tests in
//  `make pin-gate-hw-counter-e2e` / `make test-update-hw` exercise
//  them on real silicon.
// =============================================================================
