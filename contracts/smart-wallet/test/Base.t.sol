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

    /// @dev Deterministic 32-byte test bootstrap public key.
    bytes internal constant TEST_BOOTSTRAP_PK = hex"0102030405060708091011121314151617181920212223242526272829303132";
    /// @dev Deterministic 32-byte test main signer public key.
    bytes internal constant TEST_MAIN_PK = hex"aabbccdd01020304050607080910111213141516171819202122232425262728";

    bytes32 internal testBootstrapKeyHash;
    bytes32 internal testMainKeyHash;

    function setUp() public virtual {
        testBootstrapKeyHash = sha256(TEST_BOOTSTRAP_PK);
        testMainKeyHash = keccak256(TEST_MAIN_PK);

        mockVerifier = new MockSLHDSAVerifier(true);
        vm.label(address(mockVerifier), "MockVerifier");

        implementation = new PQCoinbaseSmartWallet(mockVerifier);
        vm.label(address(implementation), "Implementation");

        factory = new PQCoinbaseSmartWalletFactory(address(implementation), mockVerifier);
        vm.label(address(factory), "Factory");

        // Deploy wallet via factory with bootstrap-sig-gated createAccount
        bytes memory dummySig = new bytes(17088);
        wallet = factory.createAccount(TEST_BOOTSTRAP_PK, TEST_MAIN_PK, dummySig);
        vm.label(address(wallet), "Wallet");

        // Fund the wallet and the EntryPoint for gas prefund.
        vm.deal(address(wallet), 100 ether);
        vm.deal(ENTRY_POINT, 100 ether);
    }

    /// @dev Build an ABI-encoded PQSignatureWrapper for MAIN signer with
    ///      the given pk and a dummy 17088-byte signature. Uses keyIndex=0,
    ///      otsIndex=<current>.
    function _wrapMainSignature(bytes memory pk) internal view returns (bytes memory) {
        bytes memory dummySig = new bytes(17088);
        return abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: wallet.currentKeyIndex(),
            otsIndex: wallet.currentOTSIndex(),
            pk: pk,
            signature: dummySig
        }));
    }

    /// @dev Build an ABI-encoded PQSignatureWrapper for BOOTSTRAP signer.
    function _wrapBootstrapSignature(bytes memory pk) internal pure returns (bytes memory) {
        bytes memory dummySig = new bytes(17088);
        return abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.BOOTSTRAP,
            keyIndex: 0,
            otsIndex: 0,
            pk: pk,
            signature: dummySig
        }));
    }

    /// @dev Build a minimal UserOperation suitable for validateUserOp, using MAIN signer.
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
        op.signature = _wrapMainSignature(TEST_MAIN_PK);
    }

    /// @dev Build a UserOperation using BOOTSTRAP signer.
    function _buildBootstrapUserOp(bytes memory callData) internal pure returns (UserOperation memory op) {
        op.sender = address(0); // will be overridden
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.callGasLimit = 100_000;
        op.verificationGasLimit = 200_000;
        op.preVerificationGas = 21_000;
        op.maxFeePerGas = 50 gwei;
        op.maxPriorityFeePerGas = 2 gwei;
        op.paymasterAndData = "";
        op.signature = _wrapBootstrapSignature(TEST_BOOTSTRAP_PK);
    }
}
