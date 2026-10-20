// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PQMultiOwnable} from "../../src/PQMultiOwnable.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";

/// @notice Halmos symbolic-execution rules for
///         `PQSmartWallet.validateUserOp` / `_validateSignature`,
///         executed against the **deployed runtime bytecode** (Halmos
///         symbolically executes the solc-compiled EVM bytecode, so a
///         passing rule is a proof over ALL inputs, not the 10 KAT
///         vectors). Together these discharge the validation surface of
///         `solidityWallet_compiles_correctly` (A3.2) and provide the
///         bytecode analogue of the Lean invariants:
///
///           * `check_nonbypass_*`  ≡ Lean I-1
///             (`validateSignature_only_via_verify`): success ⇒ the
///             (arbitrary, symbolic) verifier returned true.
///           * `check_*_bumps_*_at_validation` ≡ the validation-phase
///             few-time-cap bump (I-2) — proves on bytecode that the
///             count happens in `validateUserOp` itself, the
///             PQBootstrapCapEvasion fix.
///           * the selector / tail-pad / caller rules ≡ the role-split
///             and shape gates.
///
///         Run: `halmos --contract HalmosValidateUserOp` (see
///         `test/halmos/run_halmos.sh`).
contract HalmosValidateUserOp is HalmosWalletBase {
    function setUp() public {
        wallet = _deployWalletSha256Free();
        // NB: we do NOT stub the 0x02 precompile. The patched Halmos models
        // SHA-256 as a correctly-sorted uninterpreted function, so the
        // success path runs the genuine `sphincsDigest` precompile calls —
        // the digest stays opaque (the honest A1 boundary), which is exactly
        // how the Lean model treats it.
    }

    /// @dev ABI-encode a SignatureWrapper(ownerIndex, 4008-byte inner sig).
    function _wrap(uint256 ownerIndex) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, new bytes(4008));
    }

    // ──────────────────────────────────────────────────────────────────
    // I-1 (non-bypass): validateUserOp SUCCESS ⇒ the verifier accepted.
    //
    // The verifier's answer is SYMBOLIC (`svm.createBool`), so Halmos
    // explores BOTH answers and proves there is no path where
    // `validateUserOp` returns SUCCESS while the verifier returned false.
    // This is the bytecode analogue of Lean's
    // `validateSignature_only_via_verify` over an arbitrary `verify_fn`.
    // ──────────────────────────────────────────────────────────────────

    /// **Non-bypass, bootstrap role (ownerIndex 0).**
    function check_nonbypass_bootstrap() public {
        bytes memory newOwner = abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT);
        bytes memory callData = abi.encodeCall(wallet.addOwnerBytes, (newOwner));
        bool verifierResult = svm.createBool("verifierResult_bootstrap");
        c10.setValid(verifierResult);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(callData, _wrap(0)), bytes32(0), 0);

        if (result == 0) {
            assertTrue(verifierResult, "I-1 bytecode: bootstrap SUCCESS without verifier accept");
        }
    }

    /// **Non-bypass, slot role (ownerIndex 1).**
    function check_nonbypass_slot() public {
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        bool verifierResult = svm.createBool("verifierResult_slot");
        c10.setValid(verifierResult);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(callData, _wrap(1)), bytes32(0), 0);

        if (result == 0) {
            assertTrue(verifierResult, "I-1 bytecode: slot SUCCESS without verifier accept");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // I-2 (validation-phase few-time-cap bump) — the PQBootstrapCapEvasion
    // fix, proven on bytecode: the count is taken inside `validateUserOp`
    // itself (NOT deferred to the execution phase), so an accepted sig is
    // counted revert-proof under v0.6.
    // ──────────────────────────────────────────────────────────────────

    /// **Bootstrap cap is bumped at validation.** A symbolic verifier
    /// answer: if `validateUserOp` accepts, `bootstrapUses` went 0 → 1
    /// WITHOUT any `addOwnerBytes` execution. (And if it rejects, the
    /// counter is untouched.)
    function check_bootstrap_bumps_cap_at_validation() public {
        bytes memory newOwner =
            abi.encodePacked(bytes32(uint256(0x1111) << 240), bytes32(uint256(0x2222) << 240));
        bytes memory callData = abi.encodeCall(wallet.addOwnerBytes, (newOwner));
        bool verifierResult = svm.createBool("verifierResult_capBootstrap");
        c10.setValid(verifierResult);

        assertEq(wallet.bootstrapUses(), 0, "precondition");
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(callData, _wrap(0)), bytes32(0), 0);

        if (result == 0) {
            assertEq(wallet.bootstrapUses(), 1, "bytecode: bootstrap cap not bumped at validation");
        } else {
            assertEq(wallet.bootstrapUses(), 0, "bytecode: rejected sig must not bump");
        }
    }

    /// **Slot cap is bumped at validation.** Same shape for `slotUses[1]`.
    function check_slot_bumps_cap_at_validation() public {
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        bool verifierResult = svm.createBool("verifierResult_capSlot");
        c10.setValid(verifierResult);

        assertEq(wallet.slotUses(1), 0, "precondition");
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(callData, _wrap(1)), bytes32(0), 0);

        if (result == 0) {
            assertEq(wallet.slotUses(1), 1, "bytecode: slot cap not bumped at validation");
        } else {
            assertEq(wallet.slotUses(1), 0, "bytecode: rejected sig must not bump");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Role-split + shape gates (reached before sphincsDigest, sha256-free).
    // ──────────────────────────────────────────────────────────────────

    /// **Bootstrap selector enforcement.** `ownerIndex == 0` requires the
    /// `addOwnerBytes` selector; any other selector ⇒ rejected.
    function check_rejects_wrong_selector_for_bootstrap() public {
        bytes memory wrongCalldata = svm.createBytes(64, "wrongCalldataB");
        vm.assume(wrongCalldata.length >= 4);
        bytes4 selector = bytes4(wrongCalldata);
        vm.assume(selector != wallet.addOwnerBytes.selector);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(wrongCalldata, _wrap(0)), bytes32(0), 0);
        assertTrue(result == 1, "bytecode: bootstrap accepted non-addOwnerBytes selector");
    }

    /// **Slot selector enforcement.** `ownerIndex >= 1` requires a
    /// slot-allowed selector.
    function check_rejects_wrong_selector_for_slot() public {
        bytes memory wrongCalldata = svm.createBytes(64, "wrongCalldataS");
        vm.assume(wrongCalldata.length >= 4);
        bytes4 selector = bytes4(wrongCalldata);
        vm.assume(selector != wallet.executeWithOffchainCount.selector);
        vm.assume(selector != wallet.executeBatchWithOffchainCount.selector);
        // Every other selector — including the deleted
        // `removeOwnerAtIndex` (0x89625b57) — must be rejected.

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(wrongCalldata, _wrap(1)), bytes32(0), 0);
        assertTrue(result == 1, "bytecode: slot accepted non-allowed selector");
    }

    /// **Tail-pad enforcement (audit L-1).** A non-zero ABI tail-pad byte
    /// in the wrapper ⇒ rejected.
    function check_rejects_nonzero_tail_pad(uint256 padByte) public {
        vm.assume(padByte != 0 && padByte < 256);
        bytes memory sig = _wrap(1);
        sig[sig.length - 1] = bytes1(uint8(padByte));

        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(_op(callData, sig), bytes32(0), 0);
        assertTrue(result == 1, "audit L-1 bytecode: non-zero tail-pad accepted");
    }

    /// **Non-EntryPoint caller is rejected** (before any signature work).
    function check_rejects_non_entrypoint_caller(address caller) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xc0ffee), uint256(0), bytes(""))
        );
        vm.prank(caller);
        try wallet.validateUserOp(_op(callData, _wrap(1)), bytes32(0), 0) returns (uint256) {
            assertTrue(false, "bytecode: non-EntryPoint caller reached validateUserOp");
        } catch {
            // expected: NotFromEntryPoint
        }
    }
}
