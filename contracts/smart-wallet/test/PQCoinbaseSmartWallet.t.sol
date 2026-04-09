// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {MockSLHDSAVerifier} from "./mocks/MockSLHDSAVerifier.sol";

/// @notice Helper target for execute tests.
contract Counter {
    uint256 public count;
    function increment() external payable { count += 1; }
}

contract PQCoinbaseSmartWalletTest is Base {
    Counter internal counter;

    function setUp() public override {
        super.setUp();
        counter = new Counter();
        vm.label(address(counter), "Counter");
    }

    // ── validateUserOp ──────────────────────────────────────────────

    function test_validateUserOp_validSig() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 0); // success
    }

    function test_validateUserOp_invalidSig() public {
        mockVerifier.setShouldVerify(false);
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1); // sig failure
    }

    function test_validateUserOp_wrongOwnerKey() public {
        bytes memory wrongPk = hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = _wrapSignature(wrongPk);
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_wrongPkLength() public {
        bytes memory shortPk = hex"0102030405";
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = _wrapSignature(shortPk);
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_wrongSigLength() public {
        bytes memory dummySig = new bytes(100); // wrong length, should be 17088
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({pk: TEST_PK, signature: dummySig}));
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_revert_notEntryPoint() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        wallet.validateUserOp(op, keccak256("hash"), 0);
    }

    // ── execute ─────────────────────────────────────────────────────

    function test_execute_fromEntryPoint() public {
        vm.prank(ENTRY_POINT);
        wallet.execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));
        assertEq(counter.count(), 1);
    }

    function test_execute_fromSelf() public {
        vm.prank(address(wallet));
        wallet.execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));
        assertEq(counter.count(), 1);
    }

    function test_execute_revert_unauthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        wallet.execute(address(counter), 0, abi.encodeCall(Counter.increment, ()));
    }

    function test_executeBatch() public {
        PQCoinbaseSmartWallet.Call[] memory calls = new PQCoinbaseSmartWallet.Call[](3);
        for (uint256 i; i < 3; i++) {
            calls[i] = PQCoinbaseSmartWallet.Call({
                target: address(counter),
                value: 0,
                data: abi.encodeCall(Counter.increment, ())
            });
        }
        vm.prank(ENTRY_POINT);
        wallet.executeBatch(calls);
        assertEq(counter.count(), 3);
    }

    // ── entryPoint ──────────────────────────────────────────────────

    function test_entryPoint_address() public view {
        assertEq(wallet.entryPoint(), ENTRY_POINT);
    }

    // ── canSkipChainIdValidation ────────────────────────────────────

    function test_canSkipChainIdValidation() public view {
        assertTrue(wallet.canSkipChainIdValidation(UUPSUpgradeable.upgradeToAndCall.selector));
        assertFalse(wallet.canSkipChainIdValidation(bytes4(0xdeadbeef)));
    }

    // ── upgrade ─────────────────────────────────────────────────────

    function test_upgradeToAndCall() public {
        MockSLHDSAVerifier v2 = new MockSLHDSAVerifier(true);
        PQCoinbaseSmartWallet impl2 = new PQCoinbaseSmartWallet(v2);

        vm.prank(address(wallet));
        wallet.upgradeToAndCall(address(impl2), "");
        assertEq(wallet.implementation(), address(impl2));
    }

    function test_upgrade_revert_noCode() public {
        address empty = address(0xbabe);
        vm.prank(address(wallet));
        vm.expectRevert();
        wallet.upgradeToAndCall(empty, "");
    }
}
