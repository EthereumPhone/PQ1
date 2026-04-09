// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";

contract PQCoinbaseSmartWalletFactoryTest is Base {
    function test_createAccount_deploys() public view {
        assertTrue(address(wallet).code.length > 0);
    }

    function test_createAccount_deterministic() public view {
        address predicted = factory.getAddress(testOwnerKeyHash, 0);
        assertEq(address(wallet), predicted);
    }

    function test_createAccount_initializesOwner() public view {
        assertEq(wallet.ownerKeyHash(), testOwnerKeyHash);
        assertTrue(wallet.isInitialized());
    }

    function test_createAccount_returnExisting() public {
        PQCoinbaseSmartWallet dup = factory.createAccount(testOwnerKeyHash, 0);
        assertEq(address(dup), address(wallet));
    }

    function test_createAccount_revert_zeroHash() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidOwnerKeyHash()"));
        factory.createAccount(bytes32(0), 0);
    }

    function test_createAccount_differentNonce() public {
        PQCoinbaseSmartWallet w2 = factory.createAccount(testOwnerKeyHash, 1);
        assertTrue(address(w2) != address(wallet));
    }
}
