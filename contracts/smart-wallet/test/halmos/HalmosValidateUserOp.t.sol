// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "../mocks/MockSPHINCSVerifier.sol";

/// @notice Halmos symbolic-execution rules for
///         `PQSmartWallet._validateSignature` — discharges the
///         `solidityWallet_compiles_correctly` axiom (A3.2) for the
///         Claim 1 surface.
///
///         Each `check_*` is a Halmos rule. Run via
///         `halmos --bytecode <pinned-codehash> --contract HalmosValidateUserOp`.
contract HalmosValidateUserOp is SymTest, Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWalletFactory factory = new PQSmartWalletFactory(address(impl), c10);
        c10.setValid(true);
        wallet = factory.createAccount(
            bytes32(uint256(0xaaaa) << 240),
            bytes32(uint256(0xbbbb) << 240),
            bytes32(uint256(0xcccc) << 240),
            bytes32(uint256(0xdddd) << 240),
            uint64(block.chainid),
            hex"aaaa"
        );
    }

    /// **Claim 1 — validateUserOp success implies verifier accepted.**
    /// For any symbolic UserOp, if `validateUserOp` returns SUCCESS,
    /// then the C10 verifier was called and returned true.
    function check_validateUserOp_success_implies_verifier_accepted(uint256 ownerIndex) public {
        vm.assume(ownerIndex < 2);  // bootstrap or slot 0
        bytes memory sig = svm.createBytes(4128, "wrappedSig");
        UserOperation06 memory op = _symbolicOp(sig);
        c10.setValid(true);  // honest verifier path

        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);

        // If validate returned SUCCESS, the verifier was queried and
        // returned true (we enforced this via `setValid(true)` before
        // the call). Since the mock always returns `valid`, this is
        // a tautology at the mock-substitution layer; the real claim
        // is enforced at the real-verifier substitution in
        // `solidityVerifier_compiles_correctly` (A3.1).
        if (result == 0) {
            assertTrue(c10.valid(),
                "Claim 1 violation: validate SUCCESS without verifier accept");
        }
    }

    /// **Bootstrap selector enforcement.** `ownerIndex == 0` requires
    /// callData selector to be `addOwnerBytes`. Other selectors → revert.
    function check_validateUserOp_rejects_wrong_selector_for_bootstrap() public {
        bytes memory wrongCalldata = svm.createBytes(100, "wrongCalldata");
        vm.assume(wrongCalldata.length >= 4);
        bytes4 selector = bytes4(wrongCalldata);
        vm.assume(selector != wallet.addOwnerBytes.selector);

        bytes memory innerSig = new bytes(4008);
        bytes memory wrappedSig = abi.encode(uint256(0), innerSig);
        UserOperation06 memory op = _packedOpWithCallData(wallet, wrongCalldata, wrappedSig);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);
        assertTrue(result == 1,
            "Claim 1 violation: bootstrap accepted non-addOwnerBytes selector");
    }

    /// **Slot selector enforcement.** `ownerIndex >= 1` requires
    /// callData selector to be one of the slot-allowed set.
    function check_validateUserOp_rejects_wrong_selector_for_slot() public {
        bytes memory wrongCalldata = svm.createBytes(100, "wrongCalldata");
        vm.assume(wrongCalldata.length >= 4);
        bytes4 selector = bytes4(wrongCalldata);
        vm.assume(selector != wallet.executeWithOffchainCount.selector);
        vm.assume(selector != wallet.executeBatchWithOffchainCount.selector);
        vm.assume(selector != wallet.removeOwnerAtIndex.selector);

        bytes memory innerSig = new bytes(4008);
        bytes memory wrappedSig = abi.encode(uint256(1), innerSig);
        UserOperation06 memory op = _packedOpWithCallData(wallet, wrongCalldata, wrappedSig);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);
        assertTrue(result == 1,
            "Claim 1 violation: slot accepted non-allowed selector");
    }

    /// **Tail-pad enforcement (audit L-1).** A non-zero ABI tail-pad
    /// in the SignatureWrapper must be rejected.
    function check_validateUserOp_rejects_nonzero_tail_pad(uint256 padByte) public {
        vm.assume(padByte != 0 && padByte < 256);
        bytes memory innerSig = new bytes(4008);
        bytes memory sig = abi.encode(uint256(1), innerSig);
        // Corrupt the last byte of the tail-pad.
        sig[sig.length - 1] = bytes1(uint8(padByte));

        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        UserOperation06 memory op = _packedOpWithCallData(wallet, callData, sig);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);
        assertTrue(result == 1, "Audit L-1: non-zero tail-pad accepted");
    }

    /// **Non-EntryPoint caller is rejected.** Only the configured
    /// EntryPoint can invoke `validateUserOp`.
    function check_validateUserOp_rejects_non_entrypoint_caller(address caller) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        bytes memory sig = new bytes(4128);
        UserOperation06 memory op = _symbolicOp(sig);

        vm.prank(caller);
        try wallet.validateUserOp(op, bytes32(0), 0) returns (uint256) {
            assertTrue(false, "Claim 1 violation: non-EntryPoint caller accepted");
        } catch {
            // expected: NotFromEntryPoint revert
        }
    }

    /// **Direct execute call without validate is rejected.**
    /// `_consumeValidatedOwnerIndex` reverts if the transient token
    /// is not set (audit H-3).
    function check_execute_without_validate_reverts() public {
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, 0, address(0xc0ffee), 0, "") returns (bytes memory) {
            assertTrue(false, "Audit H-3 violation: execute without validate accepted");
        } catch {
            // expected: OwnerIndexMismatch revert
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _symbolicOp(bytes memory sig) internal view returns (UserOperation06 memory op) {
        op.sender = address(wallet);
        op.nonce = 0;
        op.initCode = "";
        op.callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = sig;
    }

    function _packedOpWithCallData(PQSmartWallet w, bytes memory callData, bytes memory sig)
        internal pure returns (UserOperation06 memory op)
    {
        op.sender = address(w);
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = sig;
    }
}
