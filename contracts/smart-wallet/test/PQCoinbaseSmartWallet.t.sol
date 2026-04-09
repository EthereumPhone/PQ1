// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

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

    // ── validateUserOp (MAIN signer) ───────────────────────────────

    function test_validateUserOp_mainSigner_validSig() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 0); // success
    }

    function test_validateUserOp_mainSigner_incrementsOTS() public {
        assertEq(wallet.currentOTSIndex(), 0);

        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        wallet.validateUserOp(op, keccak256("hash"), 0);

        assertEq(wallet.currentOTSIndex(), 1);
    }

    function test_validateUserOp_mainSigner_secondSigUsesNextOTS() public {
        // First sig
        UserOperation memory op1 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        wallet.validateUserOp(op1, keccak256("hash1"), 0);
        assertEq(wallet.currentOTSIndex(), 1);

        // Second sig — must use otsIndex=1
        UserOperation memory op2 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op2, keccak256("hash2"), 0);
        assertEq(result, 0);
        assertEq(wallet.currentOTSIndex(), 2);
    }

    function test_validateUserOp_mainSigner_wrongOTSIndex() public {
        // Consume OTS 0
        UserOperation memory op1 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.prank(ENTRY_POINT);
        wallet.validateUserOp(op1, keccak256("h1"), 0);

        // Try to replay OTS 0 — should fail
        bytes memory wrongSig = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: 0,
            otsIndex: 0, // already consumed
            pkSeed: TEST_MAIN_PK_SEED,
            pkRoot: TEST_MAIN_PK_ROOT,
            signature: new bytes(3704)
        }));
        UserOperation memory op2 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op2.signature = wrongSig;
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op2, keccak256("h2"), 0);
        assertEq(result, 1); // sig failure
    }

    function test_validateUserOp_mainSigner_invalidSig() public {
        mockVerifier.setShouldVerify(false);
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1); // sig failure
    }

    function test_validateUserOp_mainSigner_wrongPk() public {
        bytes32 wrongSeed = bytes32(uint256(0xaaaa));
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = _wrapMainSignature(wrongSeed, TEST_MAIN_PK_ROOT);
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_mainSigner_wrongKeyIndex() public {
        bytes memory wrongSig = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: 99, // wrong epoch
            otsIndex: 0,
            pkSeed: TEST_MAIN_PK_SEED,
            pkRoot: TEST_MAIN_PK_ROOT,
            signature: new bytes(3704)
        }));
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = wrongSig;
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    function test_validateUserOp_mainSigner_wrongSigLength() public {
        bytes memory wrongSig = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: 0,
            otsIndex: 0,
            pkSeed: TEST_MAIN_PK_SEED,
            pkRoot: TEST_MAIN_PK_ROOT,
            signature: new bytes(100) // wrong length
        }));
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = wrongSig;
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    // ── validateUserOp (BOOTSTRAP signer) ──────────────────────────

    function test_validateUserOp_bootstrapSigner_validSig() public {
        UserOperation memory op = _buildBootstrapUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 0);
    }

    function test_validateUserOp_bootstrapSigner_consumesBootstrapOTS() public {
        assertEq(wallet.bootstrapOTSIndex(), 0);
        assertEq(wallet.currentOTSIndex(), 0);
        UserOperation memory op = _buildBootstrapUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.prank(ENTRY_POINT);
        wallet.validateUserOp(op, keccak256("hash"), 0);
        // Bootstrap consumes its own OTS, not main OTS
        assertEq(wallet.bootstrapOTSIndex(), 1);
        assertEq(wallet.currentOTSIndex(), 0);
    }

    function test_validateUserOp_bootstrapSigner_wrongPk() public {
        bytes32 wrongSeed = bytes32(uint256(0xffff));
        UserOperation memory op = _buildBootstrapUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = _wrapBootstrapSignature(wrongSeed, TEST_BOOTSTRAP_PK_ROOT);
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1);
    }

    // ── rotateMainSigner ───────────────────────────────────────────

    function test_rotateMainSigner() public {
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(wallet));
        wallet.rotateMainSigner(1, newSeed, newRoot);

        assertEq(wallet.currentKeyIndex(), 1);
        assertEq(wallet.currentMainPubKeyHash(), keccak256(abi.encodePacked(newSeed, newRoot)));
        assertEq(wallet.currentOTSIndex(), 0); // reset
    }

    function test_rotateMainSigner_mustBeSequential() public {
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(wallet));
        vm.expectRevert("sequential only");
        wallet.rotateMainSigner(2, newSeed, newRoot); // skip index 1
    }

    function test_rotateMainSigner_onlySelf() public {
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(0xdead));
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        wallet.rotateMainSigner(1, newSeed, newRoot);
    }

    function test_rotateMainSigner_signingWithNewKeyAfterRotation() public {
        // Rotate
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(wallet));
        wallet.rotateMainSigner(1, newSeed, newRoot);

        // Sign with the new key at epoch 1, otsIndex 0
        bytes memory sig = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: 1,
            otsIndex: 0,
            pkSeed: newSeed,
            pkRoot: newRoot,
            signature: new bytes(3704)
        }));
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ())))
        );
        op.signature = sig;
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 0);
        assertEq(wallet.currentOTSIndex(), 1);
    }

    function test_rotateMainSigner_oldKeyRejectedAfterRotation() public {
        // Rotate
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(wallet));
        wallet.rotateMainSigner(1, newSeed, newRoot);

        // Try to sign with the OLD key at old epoch 0
        bytes memory sig = abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: 0,
            otsIndex: 0,
            pkSeed: TEST_MAIN_PK_SEED,
            pkRoot: TEST_MAIN_PK_ROOT,
            signature: new bytes(3704)
        }));
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        op.signature = sig;
        vm.prank(ENTRY_POINT);
        uint256 result = wallet.validateUserOp(op, keccak256("hash"), 0);
        assertEq(result, 1); // rejected
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
        MockSPHINCSVerifier v2 = new MockSPHINCSVerifier(true);
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

    // ── validateUserOp revert ───────────────────────────────────────

    function test_validateUserOp_revert_notEntryPoint() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(counter), 0, ""))
        );
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        wallet.validateUserOp(op, keccak256("hash"), 0);
    }
}
