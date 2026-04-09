// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";

contract PQOwnableTest is Base {
    function test_bootstrapPubKeyHash_matches() public view {
        assertEq(wallet.bootstrapPubKeyHash(), sha256(TEST_BOOTSTRAP_PK));
    }

    function test_isBootstrapKey_true() public view {
        assertTrue(wallet.isBootstrapKey(TEST_BOOTSTRAP_PK));
    }

    function test_isBootstrapKey_false() public view {
        bytes memory wrongPk = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assertFalse(wallet.isBootstrapKey(wrongPk));
    }

    function test_currentMainPubKeyHash_matches() public view {
        assertEq(wallet.currentMainPubKeyHash(), keccak256(TEST_MAIN_PK));
    }

    function test_isMainKey_true() public view {
        assertTrue(wallet.isMainKey(TEST_MAIN_PK));
    }

    function test_isMainKey_false() public view {
        bytes memory wrongPk = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assertFalse(wallet.isMainKey(wrongPk));
    }

    function test_currentKeyIndex_initial() public view {
        assertEq(wallet.currentKeyIndex(), 0);
    }

    function test_currentOTSIndex_initial() public view {
        assertEq(wallet.currentOTSIndex(), 0);
    }

    function test_initialize_revert_alreadyInitialized() public {
        bytes memory pk = hex"0102030405060708091011121314151617181920212223242526272829303132";
        vm.expectRevert(abi.encodeWithSignature("Initialized()"));
        wallet.initialize(pk, pk);
    }
}
