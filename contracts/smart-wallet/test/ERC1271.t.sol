// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";

contract ERC1271Test is Base {
    function test_replaySafeHash_deterministic() public view {
        bytes32 h = keccak256("test");
        assertEq(wallet.replaySafeHash(h), wallet.replaySafeHash(h));
    }

    function test_replaySafeHash_perAccount() public {
        // Deploy a second wallet with a different bootstrap key
        bytes memory otherBootstrapPk = hex"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        bytes memory dummySig = new bytes(17088);
        PQCoinbaseSmartWallet w2 = factory.createAccount(otherBootstrapPk, TEST_MAIN_PK, dummySig);
        bytes32 h = keccak256("test");
        assertTrue(wallet.replaySafeHash(h) != w2.replaySafeHash(h));
    }

    function test_domainSeparator_nonZero() public view {
        assertTrue(wallet.domainSeparator() != bytes32(0));
    }

    function test_eip712Domain_name() public view {
        (,string memory name, string memory version,,,,) = wallet.eip712Domain();
        assertEq(name, "PQ Coinbase Smart Wallet");
        assertEq(version, "2");
    }

    function test_isValidSignature_mainSigner_magic() public {
        bytes32 h = keccak256("message");
        bytes32 replaySafe = wallet.replaySafeHash(h);
        bytes memory sig = _wrapMainSignature(TEST_MAIN_PK);
        bytes4 result = wallet.isValidSignature(replaySafe, sig);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_bootstrapSigner_magic() public view {
        bytes32 h = keccak256("message");
        bytes32 replaySafe = wallet.replaySafeHash(h);
        bytes memory sig = _wrapBootstrapSignature(TEST_BOOTSTRAP_PK);
        bytes4 result = wallet.isValidSignature(replaySafe, sig);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_failure() public {
        mockVerifier.setShouldVerify(false);
        bytes32 h = keccak256("message");
        bytes32 replaySafe = wallet.replaySafeHash(h);
        bytes memory sig = _wrapMainSignature(TEST_MAIN_PK);
        bytes4 result = wallet.isValidSignature(replaySafe, sig);
        assertEq(result, bytes4(0xffffffff));
    }
}
