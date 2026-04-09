// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {SLHDSAVerifier} from "../src/verifiers/SLHDSAVerifier.sol";

/// @notice Tests for the on-chain FIPS-205 SLH-DSA-SHA2-128f verifier.
///
///         Tests that require a valid signature (test_verify_validSignature,
///         test_verify_wrongMessage, test_verify_corruptedSig) are gated on
///         the existence of test/fixtures/slhdsa_vector.json. Generate it:
///
///         ```
///         cargo run -p sphincs-tz-desktop --bin gen_slhdsa_vector
///         ```
///
///         The fixture must contain: { "pk": "0x...", "msgHash": "0x...", "signature": "0x..." }
contract SLHDSAVerifierTest is Test {
    SLHDSAVerifier internal verifier;

    function setUp() public {
        verifier = new SLHDSAVerifier();
        vm.label(address(verifier), "SLHDSAVerifier");
    }

    // ── Length validation (no real signature needed) ─────────────────

    function test_verify_wrongPkLength() public view {
        bytes memory shortPk = hex"0102030405";
        bytes memory sig = new bytes(17088);
        assertFalse(verifier.verify(shortPk, keccak256("msg"), sig));
    }

    function test_verify_wrongSigLength() public view {
        bytes memory pk = new bytes(32);
        bytes memory sig = new bytes(100);
        assertFalse(verifier.verify(pk, keccak256("msg"), sig));
    }

    function test_verify_emptyInputs() public view {
        assertFalse(verifier.verify("", bytes32(0), ""));
    }
}
