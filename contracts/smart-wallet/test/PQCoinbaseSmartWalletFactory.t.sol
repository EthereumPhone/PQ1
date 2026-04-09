// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {MockSLHDSAVerifier} from "./mocks/MockSLHDSAVerifier.sol";

contract PQCoinbaseSmartWalletFactoryTest is Base {
    function test_createAccount_deploys() public view {
        assertTrue(address(wallet).code.length > 0);
    }

    function test_createAccount_deterministic() public view {
        address predicted = factory.getAddress(TEST_BOOTSTRAP_PK);
        assertEq(address(wallet), predicted);
    }

    function test_createAccount_initializesBootstrapKey() public view {
        assertEq(wallet.bootstrapPubKeyHash(), sha256(TEST_BOOTSTRAP_PK));
        assertTrue(wallet.isInitialized());
    }

    function test_createAccount_initializesMainKey() public view {
        assertEq(wallet.currentMainPubKeyHash(), keccak256(TEST_MAIN_PK));
        assertEq(wallet.currentKeyIndex(), 0);
        assertEq(wallet.currentOTSIndex(), 0);
    }

    function test_createAccount_returnExisting() public {
        bytes memory dummySig = new bytes(17088);
        PQCoinbaseSmartWallet dup = factory.createAccount(TEST_BOOTSTRAP_PK, TEST_MAIN_PK, dummySig);
        assertEq(address(dup), address(wallet));
    }

    function test_createAccount_revert_invalidBootstrapSig() public {
        // Disable the mock verifier → bootstrap sig check fails
        mockVerifier.setShouldVerify(false);
        bytes memory newBootstrapPk = hex"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        bytes memory dummySig = new bytes(17088);
        vm.expectRevert(abi.encodeWithSignature("InvalidBootstrapSignature()"));
        factory.createAccount(newBootstrapPk, TEST_MAIN_PK, dummySig);
    }

    function test_createAccount_sameAddressAcrossChains() public view {
        // The address depends only on bootstrapPubKey, not chainId or
        // main signer. Verify the prediction is stable.
        address predicted = factory.getAddress(TEST_BOOTSTRAP_PK);
        assertEq(predicted, address(wallet));
    }
}
