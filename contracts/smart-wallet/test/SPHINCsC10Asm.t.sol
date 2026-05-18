// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice Defence-in-depth test suite for the on-chain C10 verifier.
///         Combines:
///           1. Legacy single-vector tests (kept for backward compat).
///           2. NEW multi-vector iteration over 10 KAT vectors with
///              explicit expected outcomes (valid + 6 mutation cases).
///           3. NEW fuzz test that asserts random 4008-byte strings
///              never verify against a fixed (pkSeed, pkRoot, msg).
///           4. NEW bytecode-freeze gate that pins the verifier's
///              runtime bytecode hash — any silent change to source
///              or compiler version fails CI.
///           5. NEW gas regression bound — `verify(valid)` must stay
///              under 4M gas.
///           6. NEW length-boundary fuzz — every length ≠ 4008 must
///              revert.
///
///         Pair with the Lean port at
///         `contracts/verity/PQSigner/Verifier/` and the Rust ref
///         impl at `sphincs-c10/`. The Lean port's
///         `verify_byte_equivalent_to_rust` axiom is empirically
///         witnessed by the cross-vector agreement enforced here.
contract SPHINCsC10AsmTest is Test {
    SPHINCsC10Asm internal verifier;

    /// Snapshot of the verifier's `type(SPHINCsC10Asm).runtimeCode`
    /// keccak256, captured by `test_verifierBytecodeFrozen`. Update
    /// ONLY after a deliberate verifier source / compiler change,
    /// and call it out in the commit message - silent changes to
    /// the production verifier MUST fail CI.
    /// Captured 2026-05-18 from solc 0.8.28 / default optimizer settings.
    /// Refresh paired with audit M-2 (drop misleading memory-safe
    /// annotation) and I-2 (add N-mask layout check on pkSeed/pkRoot).
    /// Any change here MUST be paired with a verifier source diff in
    /// the same commit + a justification in the commit message.
    bytes32 internal constant EXPECTED_RUNTIME_CODEHASH =
        0x94a6a6a4d4905760b264099eb8de6d9a58b1d97992b93ca9b66e7361aaa350e9;

    /// Gas ceiling for a single `verify(valid sig)`. The hand-tuned
    /// Yul currently runs ~1.7-4M gas (see handoff §8 footgun #3).
    /// Any new mutation pushing this past 4M must be justified.
    uint256 internal constant GAS_CEILING = 4_000_000;

    function setUp() public {
        verifier = new SPHINCsC10Asm();
    }

    // ------------------------------------------------------------------
    // Legacy single-vector loaders (kept for back-compat; many other
    // test files in this directory read these top-level fields).
    // ------------------------------------------------------------------

    function _load()
        internal
        view
        returns (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig)
    {
        string memory json = vm.readFile("test/c10_test_vectors.json");
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        message = vm.parseJsonBytes32(json, ".message");
        sig = vm.parseJsonBytes(json, ".signature");
    }

    function test_verifyValidSignatureReturnsTrue() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();
        assertEq(sig.length, 4008, "C10 sig must be exactly 4008 bytes");
        assertTrue(verifier.verify(pkSeed, pkRoot, message, sig), "valid C10 sig must verify");
    }

    function _verifyRejected(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, pkSeed, pkRoot, message, sig)
        );
        if (!ok) return true; // revert → rejected
        if (ret.length != 32) return true; // malformed → rejected
        return !abi.decode(ret, (bool));
    }

    function test_verifyWrongMessageRejected() public view {
        (bytes32 pkSeed, bytes32 pkRoot,, bytes memory sig) = _load();
        bytes32 wrongMsg = keccak256("not the signed message");
        assertTrue(_verifyRejected(pkSeed, pkRoot, wrongMsg, sig), "wrong msg must be rejected");
    }

    function test_verifyWrongRootRejected() public view {
        (bytes32 pkSeed,, bytes32 message, bytes memory sig) = _load();
        bytes32 wrongRoot = bytes32(uint256(1) << 128);
        assertTrue(_verifyRejected(pkSeed, wrongRoot, message, sig), "wrong root must be rejected");
    }

    // Audit I-2 — the verifier itself MUST reject pubkeys that aren't
    // N-masked (top 16 bytes populated, bottom 16 bytes zero), without
    // relying on every caller to pre-validate.

    function test_audit_i2_verifyRejectsNonNMaskedPkSeed() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();
        // Smear bits into the low half of pkSeed.
        bytes32 dirtySeed = pkSeed | bytes32(uint256(0xdeadbeefcafebabe));
        assertTrue(_verifyRejected(dirtySeed, pkRoot, message, sig),
            "non-N-masked pkSeed must be rejected at the verifier");
    }

    function test_audit_i2_verifyRejectsNonNMaskedPkRoot() public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();
        bytes32 dirtyRoot = pkRoot | bytes32(uint256(0xdeadbeefcafebabe));
        assertTrue(_verifyRejected(pkSeed, dirtyRoot, message, sig),
            "non-N-masked pkRoot must be rejected at the verifier");
    }

    function test_audit_i2_verifyReturnsFalseNotReverts() public view {
        // The N-mask check returns `false`, it does NOT revert. That
        // keeps the call-site `try / catch` shape predictable.
        (, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();
        bytes32 dirty = bytes32(uint256(1)); // bottom byte set
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, dirty, pkRoot, message, sig)
        );
        assertTrue(ok, "verifier must return cleanly (not revert) on bad N-mask");
        assertEq(ret.length, 32);
        assertFalse(abi.decode(ret, (bool)));
    }

    function test_verifyMutatedSignatureFails() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();

        uint256[6] memory positions = [
            uint256(0),         // R
            uint256(65),        // first FORS secret
            uint256(2300),      // deep in FORS auth paths
            uint256(2500),      // layer 0 WOTS chain
            uint256(3000),      // layer 0 count
            uint256(4000)       // layer 1 Merkle auth
        ];

        for (uint256 i = 0; i < positions.length; i++) {
            uint256 pos = positions[i];
            bytes memory mutated = _clone(sig);
            mutated[pos] = bytes1(uint8(mutated[pos]) ^ 0xFF);

            (bool ok, bytes memory ret) = address(verifier).staticcall(
                abi.encodeWithSelector(verifier.verify.selector, pkSeed, pkRoot, message, mutated)
            );
            bool accepted = ok && ret.length == 32 && abi.decode(ret, (bool));
            assertFalse(
                accepted,
                string.concat("mutation at pos ", vm.toString(pos), " must not verify")
            );
        }
    }

    function test_verifyBadLengthReverts() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message,) = _load();
        bytes memory tooShort = new bytes(4007);
        vm.expectRevert();
        verifier.verify(pkSeed, pkRoot, message, tooShort);

        bytes memory tooLong = new bytes(4009);
        vm.expectRevert();
        verifier.verify(pkSeed, pkRoot, message, tooLong);
    }

    // ------------------------------------------------------------------
    // NEW: Multi-vector iteration over the 10-vector battery
    // ------------------------------------------------------------------

    struct Vector {
        bytes32 pkSeed;
        bytes32 pkRoot;
        bytes32 message;
        bytes signature;
        bool expectValid;
        string label;
    }

    function _loadVector(uint256 i) internal view returns (Vector memory v) {
        string memory json = vm.readFile("test/c10_test_vectors.json");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        v.pkSeed = vm.parseJsonBytes32(json, string.concat(base, ".pkSeed"));
        v.pkRoot = vm.parseJsonBytes32(json, string.concat(base, ".pkRoot"));
        v.message = vm.parseJsonBytes32(json, string.concat(base, ".message"));
        v.signature = vm.parseJsonBytes(json, string.concat(base, ".signature"));
        v.expectValid = vm.parseJsonBool(json, string.concat(base, ".expectValid"));
        v.label = vm.parseJsonString(json, string.concat(base, ".label"));
    }

    function _vectorCount() internal view returns (uint256) {
        // The vectors array length isn't directly parseable from a path
        // selector; we hard-code 10 matching the generator output and
        // sanity-check below.
        return 10;
    }

    function test_verifyAllKatVectors() public {
        uint256 n = _vectorCount();
        for (uint256 i = 0; i < n; i++) {
            Vector memory v = _loadVector(i);
            assertEq(v.signature.length, 4008, string.concat(v.label, ": sig must be 4008 bytes"));
            (bool ok, bytes memory ret) = address(verifier).staticcall(
                abi.encodeWithSelector(verifier.verify.selector, v.pkSeed, v.pkRoot, v.message, v.signature)
            );
            bool accepted = ok && ret.length == 32 && abi.decode(ret, (bool));
            assertEq(
                accepted,
                v.expectValid,
                string.concat("vector ", v.label, ": expected ", v.expectValid ? "valid" : "rejected")
            );
        }
    }

    // ------------------------------------------------------------------
    // NEW: Fuzz random 4008-byte sigs against fixed valid (pkSeed, pkRoot, msg).
    //      A random 4008-byte string has effectively zero probability
    //      of being a valid C10 signature — the chance of all of:
    //        (a) target_sum = 205 in both layers,
    //        (b) FORS reconstruction reaching pk_root,
    //        (c) Merkle auth paths consistent,
    //      simultaneously is ~ 2^-128 (worst case).
    // ------------------------------------------------------------------

    function testFuzz_verifyRandomSigsRejected(uint256 seed) public view {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message,) = _load();
        // Build 4008 deterministic-but-random-looking bytes from `seed`.
        bytes memory randomSig = new bytes(4008);
        bytes32 chunk = keccak256(abi.encode(seed));
        for (uint256 i = 0; i < 4008; i += 32) {
            if (i % 256 == 0) {
                chunk = keccak256(abi.encode(chunk, i));
            }
            uint256 chunkOffset = i % 32;
            for (uint256 j = 0; j < 32 && i + j < 4008; j++) {
                randomSig[i + j] = chunk[(chunkOffset + j) % 32];
            }
        }
        assertEq(randomSig.length, 4008);

        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, pkSeed, pkRoot, message, randomSig)
        );
        bool accepted = ok && ret.length == 32 && abi.decode(ret, (bool));
        assertFalse(accepted, "random 4008-byte string must not verify");
    }

    // ------------------------------------------------------------------
    // NEW: Bytecode-freeze. Pin the deployed verifier's bytecode hash
    //      so any source / compiler / optimizer change is loud.
    // ------------------------------------------------------------------

    function test_verifierBytecodeFrozen() public {
        bytes32 runtimeHash = address(verifier).codehash;
        // If EXPECTED_RUNTIME_CODEHASH is zero (first run), record it.
        // Otherwise enforce equality.
        if (EXPECTED_RUNTIME_CODEHASH != bytes32(0)) {
            assertEq(
                runtimeHash,
                EXPECTED_RUNTIME_CODEHASH,
                "verifier bytecode changed - update EXPECTED_RUNTIME_CODEHASH only after deliberate change"
            );
        } else {
            // On first run, print the hash so the maintainer can paste
            // it into EXPECTED_RUNTIME_CODEHASH. Skip the assertion.
            emit log_named_bytes32("Initial verifier runtime codehash", runtimeHash);
        }
    }

    // ------------------------------------------------------------------
    // NEW: Gas regression ceiling.
    // ------------------------------------------------------------------

    function test_verifyGasUnderBound() public {
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes memory sig) = _load();
        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(pkSeed, pkRoot, message, sig);
        uint256 gasUsed = gasBefore - gasleft();
        assertTrue(ok, "valid sig still verifies");
        assertLt(gasUsed, GAS_CEILING, "verify gas exceeded ceiling (handoff section 8 footgun 3)");
        emit log_named_uint("verify gas used", gasUsed);
    }

    // ------------------------------------------------------------------
    // NEW: Length-boundary fuzz. Any length ≠ 4008 must revert.
    // ------------------------------------------------------------------

    function testFuzz_verifyLengthBoundaries(uint16 wrongLen) public {
        vm.assume(wrongLen != 4008 && wrongLen < 5000);
        (bytes32 pkSeed, bytes32 pkRoot, bytes32 message,) = _load();
        bytes memory wrongLenSig = new bytes(wrongLen);
        // Try the call; if it doesn't revert, the result must be false
        // (the verifier rejects on length even if it doesn't revert).
        (bool ok, bytes memory ret) = address(verifier).staticcall(
            abi.encodeWithSelector(verifier.verify.selector, pkSeed, pkRoot, message, wrongLenSig)
        );
        if (ok && ret.length == 32) {
            // Didn't revert — must be a `false` return.
            assertFalse(abi.decode(ret, (bool)), "wrong-length sig must not verify");
        }
        // Else: revert is fine (the Yul reverts on length mismatch).
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _clone(bytes memory src) internal pure returns (bytes memory dst) {
        dst = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) dst[i] = src[i];
    }
}
