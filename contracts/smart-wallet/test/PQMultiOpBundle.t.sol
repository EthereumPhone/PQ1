// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {PQMultiOwnable} from "../src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {MockEntryPoint06} from "./mocks/MockEntryPoint06.sol";

/// @notice Regression suite for the multi-UserOp-per-bundle fix.
///
///         EntryPoint v0.6 `handleOps` runs ALL `validateUserOp`s first,
///         then ALL executions. The previous single transient token
///         (audit M-1/H-3) silently assumed one UserOp per wallet per
///         bundle and broke with 2+: the bootstrap cap under-counted, and
///         all-but-one slot execute reverted.
///
///         The fix replaces the single token with a per-`ownerIndex`
///         transient CREDIT counter and moves the H-3 ownerIndex parity
///         check into validation. These tests drive the exact two-phase
///         order (validate all, then execute all) and assert the fixed
///         behaviour.
contract PQMultiOpBundleTest is Test {
    /// A real contract, because the validated-op credit is TRANSIENT and only
    /// survives inside one transaction. Driving the two phases through `ep` is
    /// what makes this file's "validate all, then execute all" claim true; two
    /// separately pranked calls model a different (and impossible) ordering.
    address internal ENTRY_POINT_ADDR;
    MockEntryPoint06 internal ep;

    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    function setUp() public {
        ep = new MockEntryPoint06();
        ENTRY_POINT_ADDR = address(ep);
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    function _deployWallet() internal returns (PQSmartWallet) {
        c10.setValid(true);
        return factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), hex"aaaa"
        );
    }

    function _op(address sender, bytes memory callData, uint256 ownerIndex)
        internal
        pure
        returns (UserOperation06 memory op)
    {
        op.sender = sender;
        op.callData = callData;
        op.signature = abi.encode(ownerIndex, new bytes(4008));
    }

    /// Two bootstrap registrations in one bundle -> two owners AND the cap
    /// counter advances by two (one per successful registration). Was: 1.
    function test_bootstrapCapCountsEachRegistrationInBundle() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory slotA = abi.encodePacked(bytes32(uint256(0x1111) << 240), bytes32(uint256(0x2222) << 240));
        bytes memory slotB = abi.encodePacked(bytes32(uint256(0x3333) << 240), bytes32(uint256(0x4444) << 240));
        bytes memory cdA = abi.encodeCall(w.addOwnerBytes, (slotA));
        bytes memory cdB = abi.encodeCall(w.addOwnerBytes, (slotB));

        assertEq(w.bootstrapUses(), 0, "precondition");
        assertEq(w.nextOwnerIndex(), 2, "bootstrap@0, slot0@1");

        // handleOps PHASE 1: validate ALL.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_op(address(w), cdA, 0), bytes32(0), 0), 0, "validate A");
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_op(address(w), cdB, 0), bytes32(0), 0), 0, "validate B");

        // handleOps PHASE 2: execute ALL.
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slotA);
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slotB);

        assertEq(w.nextOwnerIndex(), 4, "both owners installed");
        assertTrue(w.isOwnerBytes(slotA), "slotA owner");
        assertTrue(w.isOwnerBytes(slotB), "slotB owner");
        assertEq(w.bootstrapUses(), 2, "FIXED: each registration bumps the cap once");
    }

    /// Two slot-1 transactions in one bundle BOTH execute (was: the second
    /// reverted with OwnerIndexMismatch, burning the nonce + prefund).
    function test_slotPathBothExecuteInBundle() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory cd0 = abi.encodeCall(w.executeWithOffchainCount, (1, 1, address(0xbeef), 0, ""));
        bytes memory cd1 = abi.encodeCall(w.executeWithOffchainCount, (1, 2, address(0xbeef), 0, ""));

        // ONE bundle, real v0.6 order: validate BOTH, then execute BOTH.
        UserOperation06[] memory ops = new UserOperation06[](2);
        ops[0] = _op(address(w), cd0, 1);
        ops[1] = _op(address(w), cd1, 1);
        bytes32[] memory hashes = new bytes32[](2);
        bytes[] memory execs = new bytes[](2);
        execs[0] = cd0;
        execs[1] = cd1;

        (uint256[] memory vd, bool[] memory ok, ) =
            ep.validateAllThenExecuteAll(address(w), ops, hashes, execs);

        assertEq(vd[0], 0, "validate 0");
        assertEq(vd[1], 0, "validate 1");
        assertTrue(ok[0], "execute 0 must succeed");
        assertTrue(ok[1], "execute 1 must succeed - two credits, two executes");
        assertEq(w.slotUses(1), 2, "each validation bumps slotUses once");
        assertEq(w.offchainSigCount(1), 2, "both offchain-count updates landed");
    }

    /// H-3 still holds under bundling: a malicious cross-index op (signs as
    /// slot 1 but its calldata names slot 2) is rejected at VALIDATION, so it
    /// cannot steal a co-bundled slot-2 op's credit or poison slot 2.
    function test_h3_crossIndexCannotStealCoBundledCredit() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Register slot 2 (ownerIndex 2) so there is a victim to target.
        bytes memory slot2 = abi.encodePacked(bytes32(uint256(0x5555) << 240), bytes32(uint256(0x6666) << 240));
        bytes memory addCd = abi.encodeCall(w.addOwnerBytes, (slot2));
        assertEq(
            ep.validateThenExecute(address(w), _op(address(w), addCd, 0), bytes32(0), 0, addCd),
            0
        );

        // Malicious: wrapper ownerIndex 1, calldata names ownerIndex 2 with a
        // poisoning offchain count. Rejected at validation (parity 1 != 2).
        bytes memory evilCd = abi.encodeCall(w.executeWithOffchainCount, (2, 9999, address(0xbeef), 0, ""));
        bytes memory goodCd = abi.encodeCall(w.executeWithOffchainCount, (2, 3, address(0xbeef), 0, ""));

        // CO-BUNDLED, in one transaction — which is the only arrangement in
        // which "steal a co-bundled credit" is even expressible. The evil op
        // is validated alongside the honest one; only the honest op's calldata
        // is executed, because a real EntryPoint executes the callData it
        // validated, not attacker-chosen bytes.
        UserOperation06[] memory ops = new UserOperation06[](2);
        ops[0] = _op(address(w), evilCd, 1);   // wrapper 1, calldata names 2
        ops[1] = _op(address(w), goodCd, 2);   // honest slot-2 op
        bytes32[] memory hashes = new bytes32[](2);
        bytes[] memory execs = new bytes[](1);
        execs[0] = goodCd;

        (uint256[] memory vd, bool[] memory ok, ) =
            ep.validateAllThenExecuteAll(address(w), ops, hashes, execs);

        assertEq(vd[0], 1, "cross-index op rejected at validation");
        assertEq(vd[1], 0, "honest slot-2 validates");
        assertEq(w.slotUses(1), 0, "rejected op did not consume slot 1's budget");
        assertTrue(ok[0], "honest slot-2 execute succeeds");
        assertEq(w.offchainSigCount(2), 3, "slot 2 reflects honest value, not the attacker's 9999");
    }
}
