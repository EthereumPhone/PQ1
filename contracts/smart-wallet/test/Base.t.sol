// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {MockSLHDSAVerifier} from "./mocks/MockSLHDSAVerifier.sol";

/// @notice Shared test fixture. Deploys a mock verifier, implementation,
///         factory, and a single proxy wallet for use by all test files.
abstract contract Base is Test {
    MockSLHDSAVerifier internal mockVerifier;
    PQCoinbaseSmartWallet internal implementation;
    PQCoinbaseSmartWalletFactory internal factory;
    PQCoinbaseSmartWallet internal wallet;

    address internal constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /// @dev Deterministic 32-byte test public key.
    bytes internal constant TEST_PK = hex"0102030405060708091011121314151617181920212223242526272829303132";
    bytes32 internal testOwnerKeyHash;

    function setUp() public virtual {
        testOwnerKeyHash = sha256(TEST_PK);

        mockVerifier = new MockSLHDSAVerifier(true);
        vm.label(address(mockVerifier), "MockVerifier");

        implementation = new PQCoinbaseSmartWallet(mockVerifier);
        vm.label(address(implementation), "Implementation");

        factory = new PQCoinbaseSmartWalletFactory(address(implementation));
        vm.label(address(factory), "Factory");

        wallet = factory.createAccount(testOwnerKeyHash, 0);
        vm.label(address(wallet), "Wallet");

        // Fund the wallet and the EntryPoint for gas prefund.
        vm.deal(address(wallet), 100 ether);
        vm.deal(ENTRY_POINT, 100 ether);
    }

    /// @dev Build an ABI-encoded PQSignatureWrapper with the given pk and
    ///      a dummy 17088-byte signature. Must use struct encoding (single
    ///      top-level tuple) to match `abi.decode(_, (PQSignatureWrapper))`.
    function _wrapSignature(bytes memory pk) internal pure returns (bytes memory) {
        bytes memory dummySig = new bytes(17088);
        // Encode as a struct (single tuple argument), NOT as two separate args.
        // abi.decode(_, (PQSignatureWrapper)) expects the struct wrapping.
        return abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({pk: pk, signature: dummySig}));
    }

    /// @dev Build a minimal UserOperation suitable for validateUserOp.
    function _buildUserOp(bytes memory callData) internal view returns (UserOperation memory op) {
        op.sender = address(wallet);
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.callGasLimit = 100_000;
        op.verificationGasLimit = 200_000;
        op.preVerificationGas = 21_000;
        op.maxFeePerGas = 50 gwei;
        op.maxPriorityFeePerGas = 2 gwei;
        op.paymasterAndData = "";
        op.signature = _wrapSignature(TEST_PK);
    }
}
