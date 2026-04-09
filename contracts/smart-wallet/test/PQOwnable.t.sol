// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";

contract PQOwnableTest is Base {
    function test_bootstrapPubKeyHash_matches() public view {
        assertEq(wallet.bootstrapPubKeyHash(), testBootstrapKeyHash);
    }

    function test_isBootstrapKey_true() public view {
        assertTrue(wallet.isBootstrapKey(TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT));
    }

    function test_isBootstrapKey_false() public view {
        bytes32 wrongSeed = bytes32(uint256(0xffff));
        assertFalse(wallet.isBootstrapKey(wrongSeed, TEST_BOOTSTRAP_PK_ROOT));
    }

    function test_currentMainPubKeyHash_matches() public view {
        assertEq(wallet.currentMainPubKeyHash(), testMainKeyHash);
    }

    function test_isMainKey_true() public view {
        assertTrue(wallet.isMainKey(TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT));
    }

    function test_isMainKey_false() public view {
        bytes32 wrongSeed = bytes32(uint256(0xffff));
        assertFalse(wallet.isMainKey(wrongSeed, TEST_MAIN_PK_ROOT));
    }

    function test_currentKeyIndex_initial() public view {
        assertEq(wallet.currentKeyIndex(), 0);
    }

    function test_currentOTSIndex_initial() public view {
        assertEq(wallet.currentOTSIndex(), 0);
    }

    function test_initialize_revert_alreadyInitialized() public {
        bytes32 seed = bytes32(uint256(1));
        bytes32 root = bytes32(uint256(2));
        vm.expectRevert(abi.encodeWithSignature("Initialized()"));
        wallet.initialize(seed, root, seed, root);
    }
}
