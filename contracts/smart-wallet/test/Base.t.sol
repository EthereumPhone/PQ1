// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {MockJardinVerifier} from "./mocks/MockJardinVerifier.sol";
import {IJardinVerifier} from "../src/verifiers/IJardinVerifier.sol";

/// @notice Shared test fixture. Deploys a mock verifier, implementation,
///         factory, and a single proxy wallet for use by all test files.
abstract contract Base is Test {
    MockSPHINCSVerifier internal mockVerifier;
    MockJardinVerifier internal mockJardinVerifier;
    PQCoinbaseSmartWallet internal implementation;
    PQCoinbaseSmartWalletFactory internal factory;
    PQCoinbaseSmartWallet internal wallet;

    address internal constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /// @dev Deterministic test bootstrap public key (pkSeed, pkRoot).
    bytes32 internal constant TEST_BOOTSTRAP_PK_SEED = bytes32(uint256(0x0102030405060708091011121314151600000000000000000000000000000000));
    bytes32 internal constant TEST_BOOTSTRAP_PK_ROOT = bytes32(uint256(0x1718192021222324252627282930313200000000000000000000000000000000));

    /// @dev Deterministic test main signer public key (pkSeed, pkRoot).
    bytes32 internal constant TEST_MAIN_PK_SEED = bytes32(uint256(0xaabbccdd0102030405060708091011120000000000000000000000000000000));
    bytes32 internal constant TEST_MAIN_PK_ROOT = bytes32(uint256(0x1314151617181920212223242526272800000000000000000000000000000000));

    bytes32 internal testBootstrapKeyHash;
    bytes32 internal testMainKeyHash;

    function setUp() public virtual {
        testBootstrapKeyHash = keccak256(abi.encodePacked(TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT));
        testMainKeyHash = keccak256(abi.encodePacked(TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT));

        mockVerifier = new MockSPHINCSVerifier(true);
        vm.label(address(mockVerifier), "MockVerifier");

        mockJardinVerifier = new MockJardinVerifier(true);
        vm.label(address(mockJardinVerifier), "MockJardinVerifier");

        implementation = new PQCoinbaseSmartWallet(mockVerifier, IJardinVerifier(address(mockJardinVerifier)));
        vm.label(address(implementation), "Implementation");

        factory = new PQCoinbaseSmartWalletFactory(address(implementation), mockVerifier);
        vm.label(address(factory), "Factory");

        // Deploy wallet via factory with bootstrap-sig-gated createAccount
        bytes memory dummySig = new bytes(3976);
        wallet = factory.createAccount(
            TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT,
            TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT,
            dummySig
        );
        vm.label(address(wallet), "Wallet");

        // Fund the wallet and the EntryPoint for gas prefund.
        vm.deal(address(wallet), 100 ether);
        vm.deal(ENTRY_POINT, 100 ether);
    }

    /// @dev Build an ABI-encoded PQSignatureWrapper for MAIN signer with
    ///      the given pk and a dummy 3976-byte signature. Uses keyIndex=current,
    ///      otsIndex=current.
    function _wrapMainSignature(bytes32 pkSeed, bytes32 pkRoot) internal view returns (bytes memory) {
        bytes memory dummySig = new bytes(3976);
        return abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
            keyIndex: wallet.currentKeyIndex(),
            otsIndex: wallet.currentOTSIndex(),
            pkSeed: pkSeed,
            pkRoot: pkRoot,
            slotKey: bytes32(0),
            signature: dummySig
        }));
    }

    /// @dev Build an ABI-encoded PQSignatureWrapper for BOOTSTRAP signer.
    function _wrapBootstrapSignature(bytes32 pkSeed, bytes32 pkRoot) internal view returns (bytes memory) {
        bytes memory dummySig = new bytes(3976);
        return abi.encode(PQCoinbaseSmartWallet.PQSignatureWrapper({
            signerType: PQCoinbaseSmartWallet.SignerType.BOOTSTRAP,
            keyIndex: 0,
            otsIndex: wallet.bootstrapOTSIndex(),
            pkSeed: pkSeed,
            pkRoot: pkRoot,
            slotKey: bytes32(0),
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
        op.signature = _wrapMainSignature(TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT);
    }

    /// @dev Build a UserOperation using BOOTSTRAP signer.
    function _buildBootstrapUserOp(bytes memory callData) internal view returns (UserOperation memory op) {
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
        op.signature = _wrapBootstrapSignature(TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT);
    }
}
