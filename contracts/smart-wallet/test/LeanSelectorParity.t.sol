// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice Lean selector parity tests — Phase 2C of the
///         contracts/verification discharge plan.
///
///         The Lean model in
///         `contracts/verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean`
///         hard-codes four function selectors used by `_validateSignature`'s
///         role-split enforcer (`bootstrap` ↔ `addOwnerBytes`, `slot` ↔ one
///         of `executeWithOffchainCount` / `executeBatchWithOffchainCount` /
///         `removeOwnerAtIndex`). Any ABI drift between Solidity and Lean
///         would invalidate the `solidityWallet_compiles_correctly`
///         bridge axiom — this test catches such drift at PR time.
///
///         The expected constants are pulled from `forge inspect
///         PQSmartWallet methodIdentifiers` (run at branch-cut time).
contract LeanSelectorParityTest is Test {
    PQSmartWallet internal impl;

    function setUp() public {
        MockSPHINCSVerifier c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(address(0x4337)), c10);
    }

    /// `bytes4(keccak256("addOwnerBytes(bytes)")) = 0x101490cb`.
    /// Mirrors `SphincsCVerify/Wallet/ValidateUserOp.lean::Selector.addOwnerBytes`.
    function test_leanParity_addOwnerBytes_selector() external view {
        assertEq(impl.addOwnerBytes.selector, bytes4(0x101490cb), "Lean selector drifted: addOwnerBytes");
    }

    /// `bytes4(keccak256("executeWithOffchainCount(uint256,uint256,address,uint256,bytes)")) = 0x14443c57`.
    function test_leanParity_executeWithOffchainCount_selector() external view {
        assertEq(impl.executeWithOffchainCount.selector, bytes4(0x14443c57), "Lean selector drifted: executeWithOffchainCount");
    }

    /// `bytes4(keccak256("executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])")) = 0x7a389933`.
    function test_leanParity_executeBatchWithOffchainCount_selector() external view {
        assertEq(impl.executeBatchWithOffchainCount.selector, bytes4(0x7a389933), "Lean selector drifted: executeBatchWithOffchainCount");
    }

    /// `bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)")) = 0x89625b57`.
    function test_leanParity_removeOwnerAtIndex_selector() external view {
        assertEq(impl.removeOwnerAtIndex.selector, bytes4(0x89625b57), "Lean selector drifted: removeOwnerAtIndex");
    }
}
