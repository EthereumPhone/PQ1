// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";

/// @notice The part of EntryPoint v0.6 these tests actually depend on: it
///         validates and executes **in one transaction**.
///
/// ## Why this exists
///
/// `PQSmartWallet` hands a validated-op credit from the validation phase to
/// the execution phase through **transient storage** (`_stampValidatedCredit`
/// / `_consumeValidatedCredit`). Transient storage is cleared at transaction
/// boundaries, and the guard's whole point is that absence means "no
/// validation stamped this index in the current tx" — the anti-impersonation
/// property.
///
/// A test that calls `validateUserOp(...)` and then `execute…(...)` as two
/// separate top-level calls is therefore not modelling a bundle. Up to forge
/// 1.7.x the harness let transient storage survive between those calls, so
/// such tests passed; from 1.8 it clears them, which is the faithful
/// behaviour. Measured on this tree (forge 1.8.3), two calls made from a test
/// contract see a cleared slot, while two calls made from an intermediate
/// contract inside one top-level call see it intact — so routing both through
/// this contract restores the real shape rather than suppressing the check.
///
/// This matters beyond making tests pass. Under 1.8.3 the invariant handler's
/// execute phase succeeded **0 times in 273 attempts** while the suite still
/// reported green, because its failures were swallowed by a `try/catch`. Six
/// invariants were being proven about an execution path that never ran.
///
/// The wallet refunds `missingAccountFunds` to its caller, so this contract is
/// payable.
contract MockEntryPoint06 {
    receive() external payable {}

    // ── one op ──────────────────────────────────────────────────────

    /// Validate then execute, bubbling an execute revert verbatim so
    /// `vm.expectRevert(Selector)` still matches at the test boundary.
    function validateThenExecute(
        address wallet,
        UserOperation06 calldata op,
        bytes32 opHash,
        uint256 missingAccountFunds,
        bytes calldata execCall
    ) external returns (uint256 validationData) {
        validationData = _validate(wallet, op, opHash, missingAccountFunds);
        _callOrBubble(wallet, execCall);
    }

    /// As above, but the execute outcome is RETURNED rather than bubbled, so a
    /// test can assert on both phases inside the same transaction — needed
    /// wherever the point is "validation rejected it, AND a direct execute
    /// still has no credit".
    function validateThenTryExecute(
        address wallet,
        UserOperation06 calldata op,
        bytes32 opHash,
        uint256 missingAccountFunds,
        bytes calldata execCall
    ) external returns (uint256 validationData, bool ok, bytes memory ret) {
        validationData = _validate(wallet, op, opHash, missingAccountFunds);
        (ok, ret) = wallet.call(execCall);
    }

    /// Validate ONCE, then call the wallet TWICE. The credit is one-shot, so
    /// the second call must fail; both outcomes are returned so the assertion
    /// happens inside the single transaction that makes it meaningful.
    function validateThenExecuteTwice(
        address wallet,
        UserOperation06 calldata op,
        bytes32 opHash,
        bytes calldata execCall
    ) external returns (uint256 validationData, bool firstOk, bool secondOk, bytes memory secondRet) {
        validationData = _validate(wallet, op, opHash, 0);
        (firstOk, ) = wallet.call(execCall);
        (secondOk, secondRet) = wallet.call(execCall);
    }

    /// Execute with NO preceding validation, in one transaction — the
    /// EntryPoint-impersonator case. Returned, not bubbled.
    function tryExecuteOnly(address wallet, bytes calldata execCall)
        external
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = wallet.call(execCall);
    }

    // ── a bundle ────────────────────────────────────────────────────

    /// The real v0.6 order: validate EVERY op, then execute every op. The
    /// co-bundled-credit tests depend on this ordering — a pairwise
    /// validate/execute/validate/execute helper would model the wrong thing.
    function validateAllThenExecuteAll(
        address wallet,
        UserOperation06[] calldata ops,
        bytes32[] calldata opHashes,
        bytes[] calldata execCalls
    ) external returns (uint256[] memory validationData, bool[] memory ok, bytes[] memory rets) {
        validationData = new uint256[](ops.length);
        ok = new bool[](execCalls.length);
        rets = new bytes[](execCalls.length);
        for (uint256 i = 0; i < ops.length; i++) {
            validationData[i] = _validate(wallet, ops[i], opHashes[i], 0);
        }
        for (uint256 i = 0; i < execCalls.length; i++) {
            (ok[i], rets[i]) = wallet.call(execCalls[i]);
        }
    }

    // ── internals ───────────────────────────────────────────────────

    function _validate(
        address wallet,
        UserOperation06 calldata op,
        bytes32 opHash,
        uint256 missingAccountFunds
    ) private returns (uint256 validationData) {
        validationData =
            PQSmartWallet(payable(wallet)).validateUserOp(op, opHash, missingAccountFunds);
    }

    function _callOrBubble(address wallet, bytes calldata execCall) private {
        (bool ok, bytes memory ret) = wallet.call(execCall);
        if (!ok) _bubble(ret);
    }

    function _bubble(bytes memory ret) private pure {
        assembly ("memory-safe") {
            revert(add(ret, 0x20), mload(ret))
        }
    }
}
