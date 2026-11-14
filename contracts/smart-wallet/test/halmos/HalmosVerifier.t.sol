// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

// The deployed reference (Base, codehash 0xfd55…), from its frozen copy: since 2026-11-14
// src/verifiers/SPHINCsC10Asm.sol holds the optimized v1, which is not deployed. A3.1 and this
// discharge stay on the deployed bytecode; a run against the v1 is a deployment-time step.
import {RefSPHINCsC10Asm} from "../ref/RefSPHINCsC10Asm.sol";

/// @notice Halmos symbolic-execution rules for the **input-validation
///         gates** of the deployed SPHINCS+C10 verifier bytecode
///         (`solidityVerifier_compiles_correctly`, A3.1).
///
///         SCOPE / honesty: the verifier's FULL functional behaviour is
///         SHA-256-heavy (thousands of `staticcall(0x02)` over a 4008-byte
///         signature, nested Merkle/WOTS loops) and is NOT symbolically
///         tractable — that part of A3.1 is discharged by the Lean
///         refinement (`Verifier/Equivalence.lean::verifyRefined_eq_spec`,
///         including the FORS htIdx ADRS binding) plus the 10-vector
///         Rust ↔ Solidity ↔ Lean differential (`test_verifyAllKatVectors`).
///         Here Halmos proves, ON THE BYTECODE, the early-return gates that
///         execute BEFORE any hashing — exactly the gates the Lean spec
///         (`verifyRefined`) also enforces:
///           * wrong signature length reverts;
///           * a non-N-masked `pkSeed` / `pkRoot` returns false (not revert).
///
///         Run: `halmos --contract HalmosVerifier`.
contract HalmosVerifier is SymTest, Test {
    // N_MASK = top 16 bytes set, bottom 16 bytes zero.
    bytes32 internal constant NMASKED = bytes32(uint256(0x1234) << 240);

    RefSPHINCsC10Asm internal v;

    function setUp() public {
        v = new RefSPHINCsC10Asm();
    }

    /// **Wrong signature length reverts** ("Invalid sig length"). The check
    /// is the first thing the Yul does, before any hash. Swept over the
    /// boundary lengths {0, 1, 2048, 4007, 4009, 8192} with fully symbolic
    /// content (the gate must be length-only: no byte value at a wrong
    /// length may slip through). The correct length 4008 is exercised by
    /// the two N-mask rules below (which return instead of reverting).
    function check_verify_reverts_on_wrong_length(
        uint256 lenSel,
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 digest
    ) public {
        vm.assume(lenSel < 6);
        bytes memory sig;
        if (lenSel == 0) sig = new bytes(0);
        else if (lenSel == 1) sig = svm.createBytes(1, "vsig1");
        else if (lenSel == 2) sig = svm.createBytes(2048, "vsig2048");
        else if (lenSel == 3) sig = svm.createBytes(4007, "vsig4007");
        else if (lenSel == 4) sig = svm.createBytes(4009, "vsig4009");
        else sig = svm.createBytes(8192, "vsig8192");

        try v.verify(pkSeed, pkRoot, digest, sig) returns (bool) {
            assertTrue(false, "A3.1 bytecode: verifier accepted a non-4008 signature length");
        } catch {
            // expected: revert("Invalid sig length")
        }
    }

    /// **Non-N-masked `pkSeed` returns false** (audit I-2 in-verifier
    /// enforcement). The check sits above the H_msg hash, so this path
    /// never reaches a SHA-256 call. Every other argument fully symbolic:
    /// no pkRoot/digest/signature value may rescue a malformed pkSeed.
    function check_verify_rejects_non_nmasked_pkSeed(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 digest
    ) public {
        // bottom 16 bytes non-zero ⇒ not N-masked.
        vm.assume(uint128(uint256(pkSeed)) != 0);
        bytes memory sig = svm.createBytes(4008, "nmSig");
        bool ok = v.verify(pkSeed, pkRoot, digest, sig);
        assertTrue(!ok, "A3.1 bytecode: verifier accepted a non-N-masked pkSeed");
    }

    /// **Non-N-masked `pkRoot` returns false.** pkSeed constrained to the
    /// N-mask shape (so the pkRoot gate is actually reached); digest and
    /// signature fully symbolic.
    function check_verify_rejects_non_nmasked_pkRoot(
        bytes32 pkSeedHigh,
        bytes32 pkRoot,
        bytes32 digest
    ) public {
        bytes32 pkSeed = pkSeedHigh & ~bytes32(uint256(type(uint128).max)); // N-masked
        vm.assume(uint128(uint256(pkRoot)) != 0);
        bytes memory sig = svm.createBytes(4008, "nmSigR");
        bool ok = v.verify(pkSeed, pkRoot, digest, sig);
        assertTrue(!ok, "A3.1 bytecode: verifier accepted a non-N-masked pkRoot");
    }
}
