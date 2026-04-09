// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";

contract PQOwnableTest is Base {
    function test_ownerKeyHash_matches() public view {
        assertEq(wallet.ownerKeyHash(), sha256(TEST_PK));
    }

    function test_isOwnerKey_true() public view {
        assertTrue(wallet.isOwnerKey(TEST_PK));
    }

    function test_isOwnerKey_false() public view {
        bytes memory wrongPk = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assertFalse(wallet.isOwnerKey(wrongPk));
    }

    function test_initialize_revert_alreadyInitialized() public {
        vm.expectRevert(abi.encodeWithSignature("Initialized()"));
        wallet.initialize(bytes32(uint256(99)));
    }
}
