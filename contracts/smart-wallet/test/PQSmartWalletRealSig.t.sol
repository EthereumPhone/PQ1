// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice End-to-end gas benchmark: drive `PQSmartWallet.validateUserOp`
///         with the **real** `SPHINCsC10Asm` verifier and a real C10
///         signature over a real `sphincsDigest(userOp)`. The signature
///         and userOp shape are produced by
///         `sphincs-c10/tests/gen_test_vectors.rs`.
///
///         The factory is wired to the mock verifier so the per-account
///         setup ignores `factorySig` — only the wallet's own validate
///         path uses the real verifier, which is what the bench measures.
contract PQSmartWalletRealSigBench is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);
    address constant TARGET_ADDR = address(0xcafe);

    SPHINCsC10Asm internal realC10;
    MockSPHINCSVerifier internal mockC10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;
    PQSmartWallet internal wallet;

    bytes32 internal pkSeed;
    bytes32 internal pkRoot;
    bytes internal userOpSig;
    bytes32 internal expectedDigest;

    bytes internal callDataFromVec;
    address internal senderFromVec;

    function setUp() public {
        realC10 = new SPHINCsC10Asm();
        mockC10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), ISPHINCSVerifier(address(realC10)));
        factory = new PQSmartWalletFactory(address(impl), mockC10);
        mockC10.setValid(true);

        // Load the userOp test vector.
        string memory json = vm.readFile("test/c10_test_vectors.json");
        pkSeed = vm.parseJsonBytes32(json, ".pkSeed");
        pkRoot = vm.parseJsonBytes32(json, ".pkRoot");
        userOpSig = vm.parseJsonBytes(json, ".userOpBench.signature");
        expectedDigest = vm.parseJsonBytes32(json, ".userOpBench.digest");
        callDataFromVec = vm.parseJsonBytes(json, ".userOpBench.callData");
        senderFromVec = vm.parseJsonAddress(json, ".userOpBench.sender");

        // Bootstrap pubkey is a throwaway (the bench only signs with the
        // slot key at index 1). Slot-0 pubkey == the C10 vector's pubkey
        // so the wallet's `_validateSignature` calls the real verifier
        // with parameters that match `userOpSig`.
        bytes32 dummyBootstrapSeed = bytes32(uint256(0xdead) << 240);
        bytes32 dummyBootstrapRoot = bytes32(uint256(0xbeef) << 240);

        wallet = factory.createAccount(
            dummyBootstrapSeed,
            dummyBootstrapRoot,
            pkSeed,
            pkRoot,
            uint64(block.chainid),
            hex"00" // mock accepts anything when setValid(true)
        );

        // Sanity: confirm the slot-0 pubkey landed where we expect.
        bytes memory slot0 = wallet.ownerAtIndex(1);
        require(slot0.length == 64, "slot0 not installed");
        bytes32 gotSeed;
        bytes32 gotRoot;
        assembly {
            gotSeed := mload(add(slot0, 32))
            gotRoot := mload(add(slot0, 64))
        }
        require(gotSeed == pkSeed && gotRoot == pkRoot, "slot0 pk mismatch");
    }

    function _buildOp() internal view returns (UserOperation06 memory op) {
        op.sender = senderFromVec;
        op.nonce = 0;
        op.initCode = "";
        op.callData = callDataFromVec;
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = abi.encode(uint256(1), userOpSig);
    }

    /// @notice Sanity check: the userOp the test reconstructs must hash to
    ///         the digest the Rust generator signed.
    function test_digestMatches() public view {
        UserOperation06 memory op = _buildOp();
        bytes32 actual = wallet.sphincsDigest(op);
        assertEq(actual, expectedDigest, "Solidity sphincsDigest != Rust digest");
    }

    /// @notice Sanity check: the calldata pre-encoded in the JSON matches
    ///         what `abi.encodeCall(execute, …)` would produce on the fly.
    function test_callDataMatchesEncoder() public view {
        bytes memory expected =
            abi.encodeCall(wallet.execute, (TARGET_ADDR, 0, ""));
        assertEq(
            keccak256(callDataFromVec),
            keccak256(expected),
            "Rust-built callData drifted from abi.encodeCall(execute,...)"
        );
    }

    /// @notice The headline gas number: validateUserOp with real C10 sig.
    function test_validateUserOp_realC10_gas() public {
        UserOperation06 memory op = _buildOp();

        vm.prank(ENTRY_POINT_ADDR);
        uint256 g0 = gasleft();
        uint256 vd = wallet.validateUserOp(op, bytes32(0), 0);
        uint256 used = g0 - gasleft();

        assertEq(vd, 0, "real C10 sig must validate");
        assertEq(wallet.slotUses(1), 1, "slotUses must bump");

        emit log_named_uint("validateUserOp gas (real C10 sig, slot path)", used);
    }

    /// @notice Bench just the verifier in isolation for comparison.
    ///         Materialise everything in memory before the snapshot so the
    ///         measurement excludes storage SLOADs of the 4008-byte sig.
    function test_verifyOnly_realC10_gas() public {
        bytes32 _seed = pkSeed;
        bytes32 _root = pkRoot;
        bytes32 _digest = expectedDigest;
        bytes memory _sig = userOpSig;
        SPHINCsC10Asm _v = realC10;

        uint256 g0 = gasleft();
        bool ok = _v.verify(_seed, _root, _digest, _sig);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        emit log_named_uint("c10Verifier.verify gas (isolated)", used);
    }
}
