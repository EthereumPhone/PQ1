// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

contract PQCoinbaseSmartWalletFactoryTest is Base {
    function test_createAccount_deploys() public view {
        assertTrue(address(wallet).code.length > 0);
    }

    function test_createAccount_deterministic() public view {
        address predicted = factory.getAddress(TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT);
        assertEq(address(wallet), predicted);
    }

    function test_createAccount_initializesBootstrapKey() public view {
        assertEq(wallet.bootstrapPubKeyHash(), testBootstrapKeyHash);
        assertTrue(wallet.isInitialized());
    }

    function test_createAccount_initializesMainKey() public view {
        assertEq(wallet.currentMainPubKeyHash(), testMainKeyHash);
        assertEq(wallet.currentKeyIndex(), 0);
        assertEq(wallet.currentOTSIndex(), 0);
    }

    function test_createAccount_returnExisting() public {
        bytes memory dummySig = new bytes(3976);
        PQCoinbaseSmartWallet dup = factory.createAccount(
            TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT,
            TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT,
            dummySig
        );
        assertEq(address(dup), address(wallet));
    }

    function test_createAccount_revert_invalidBootstrapSig() public {
        // Disable the mock verifier -> bootstrap sig check fails
        mockVerifier.setShouldVerify(false);
        bytes32 newSeed = bytes32(uint256(0xeeee));
        bytes32 newRoot = bytes32(uint256(0xdddd));
        bytes memory dummySig = new bytes(3976);
        vm.expectRevert(abi.encodeWithSignature("InvalidBootstrapSignature()"));
        factory.createAccount(newSeed, newRoot, TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT, dummySig);
    }

    function test_createAccount_sameAddressAcrossChains() public view {
        // The address depends only on bootstrap pk, not chainId or main signer.
        address predicted = factory.getAddress(TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT);
        assertEq(predicted, address(wallet));
    }
}
