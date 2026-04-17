// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice End-to-end test for the on-chain C10 verifier using Rust-generated
///         test vectors (see `sphincs-c10/tests/gen_test_vectors.rs`).
///         Re-run that generator whenever the signing stack changes.
contract SPHINCsC10AsmTest is Test {
    SPHINCsC10Asm internal verifier;

    function setUp() public {
        verifier = new SPHINCsC10Asm();
    }

    /// Load the single-vector fixture.
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

    /// @dev "Rejected" means either a clean `false` return OR a revert.
    ///      The C10 verifier reverts eagerly on structural invariants it
    ///      can detect without completing the hypertree walk (forced-zero
    ///      FORS index, WOTS digit-sum mismatch), and returns `false`
    ///      only when the final reconstructed root mismatches. Both count
    ///      as rejection for validation purposes — the wallet contract
    ///      wraps `verify` in a `try/catch` and treats every non-true
    ///      outcome as `SIG_VALIDATION_FAILED`.
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

    /// @notice Flipping any byte of the signature must cause verification to
    ///         fail. We check a spread of byte positions rather than every
    ///         one (forge will time out). Each mutation can fail *either* via
    ///         a clean `false` return *or* by reverting (count-grind sum
    ///         check, forced-zero fail, etc.); both count as "rejected".
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

    function _clone(bytes memory src) internal pure returns (bytes memory dst) {
        dst = new bytes(src.length);
        for (uint256 i = 0; i < src.length; i++) dst[i] = src[i];
    }
}
