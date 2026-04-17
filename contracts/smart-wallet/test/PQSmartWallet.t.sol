// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice End-to-end tests for the Coinbase-derived post-quantum smart
///         wallet + factory. Focuses on dispatch + storage invariants; the
///         real C10 verifier is tested separately by `SPHINCsC10Asm.t.sol`.
contract PQSmartWalletTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    PQSmartWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);

    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    bytes32 internal constant SLOT1_PK_SEED = bytes32(uint256(0xeeee) << 240);
    bytes32 internal constant SLOT1_PK_ROOT = bytes32(uint256(0xffff) << 240);

    bytes internal constant FACTORY_SIG = hex"aaaa"; // mock accepts any bytes when setValid(true)

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        factory = new PQSmartWalletFactory(IEntryPoint(ENTRY_POINT_ADDR), c10);
    }

    // ── helpers ─────────────────────────────────────────────────────

    function _deployWallet() internal returns (PQSmartWallet) {
        c10.setValid(true);
        PQSmartWallet w = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
        return w;
    }

    function _wrapSig(uint256 ownerIndex, bytes memory innerSig) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, innerSig);
    }

    function _fakeC10Sig() internal pure returns (bytes memory) {
        // C10 sig is always exactly 4008 bytes; content doesn't matter for the mock.
        return new bytes(4008);
    }

    function _packedOp(address sender, bytes memory callData, bytes memory sig)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        op.sender = sender;
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.accountGasLimits = bytes32(0);
        op.preVerificationGas = 0;
        op.gasFees = bytes32(0);
        op.paymasterAndData = "";
        op.signature = sig;
    }

    // ── Factory: address determinism ───────────────────────────────

    function test_factoryAddressPerUserStableAcrossChains() public {
        address a = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);

        // Switch chainId, predict again; address must NOT change.
        vm.chainId(42161);
        address b = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        assertEq(a, b, "wallet address must be independent of chainId");
    }

    function test_factoryDifferentMasterKeysDifferAddress() public view {
        address a = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        address b = factory.getAddress(bytes32(uint256(1)), MASTER_PK_ROOT);
        assertTrue(a != b);
    }

    function test_factoryDeployHappyPath() public {
        PQSmartWallet w = _deployWallet();
        assertEq(w.masterPkSeed(), MASTER_PK_SEED);
        assertEq(w.masterPkRoot(), MASTER_PK_ROOT);
        assertEq(w.nextOwnerIndex(), 2, "bootstrap + slot0 must be registered");
        assertEq(w.ownerAtIndex(0).length, 64);
        assertEq(w.ownerAtIndex(1).length, 64);
    }

    function test_factoryIdempotentSecondCall() public {
        PQSmartWallet a = _deployWallet();
        PQSmartWallet b = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
        assertEq(address(a), address(b));
    }

    // ── Factory: squat defence ──────────────────────────────────────

    function test_factoryRejectsBadSignature() public {
        c10.setValid(false);
        vm.expectRevert(PQSmartWalletFactory.InvalidFactorySignature.selector);
        factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
    }

    function test_factoryRejectsWrongChainId() public {
        c10.setValid(true);
        uint64 wrong = uint64(block.chainid) + 1;
        vm.expectRevert(
            abi.encodeWithSelector(PQSmartWalletFactory.WrongChainId.selector, uint64(block.chainid), wrong)
        );
        factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            wrong,
            FACTORY_SIG
        );
    }

    function test_factorySquatAttempt() public {
        // Victim's bootstrap pubkey is public; attacker tries to deploy
        // wallet at victim's address with the attacker's slot0. They do
        // not have the bootstrap sk, so `factorySig` verification fails
        // (mock returns false when setValid(false)).
        c10.setValid(false);

        bytes32 attackerSlot0Seed = bytes32(uint256(0x1111) << 240);
        bytes32 attackerSlot0Root = bytes32(uint256(0x2222) << 240);

        vm.expectRevert(PQSmartWalletFactory.InvalidFactorySignature.selector);
        factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            attackerSlot0Seed, attackerSlot0Root,
            uint64(block.chainid),
            FACTORY_SIG
        );

        // Address isn't squatted — re-running with the real sig works.
        c10.setValid(true);
        PQSmartWallet w = _deployWallet();
        // slot-0 at ownerIndex 1 MUST be the victim's, not the attacker's.
        bytes memory got = w.ownerAtIndex(1);
        bytes memory want = abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT);
        assertEq(keccak256(got), keccak256(want), "slot0 must be victim's, not attacker's");
    }

    // ── Wallet: initialize gating ───────────────────────────────────

    function test_initializeOnlyFactory() public {
        PQSmartWallet w = _deployWallet();
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        vm.expectRevert(PQSmartWallet.NotFromFactory.selector);
        w.initialize(slot1Bytes);
    }

    function test_initializeTwiceReverts() public {
        PQSmartWallet w = _deployWallet();
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        vm.prank(address(factory));
        vm.expectRevert(PQSmartWallet.AlreadyInitialized.selector);
        w.initialize(slot1Bytes);
    }

    // ── Wallet: signature validation & role split ──────────────────

    function test_slotSignValidate() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 0, "slot-0 execute sig must validate");
        assertEq(w.slotUses(1), 1);
        assertEq(w.bootstrapUses(), 0);
    }

    function test_slotCannotCallAddOwner() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory callData = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(1)), 0);
        assertEq(vd, 1, "slot key MUST NOT sign addOwnerBytes");
    }

    function test_bootstrapSignsAddOwner() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory callData = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory sig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(2)), 0);
        assertEq(vd, 0, "bootstrap MUST validate addOwner UserOp");
        assertEq(w.bootstrapUses(), 1);
    }

    function test_bootstrapCannotCallExecute() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(w.execute, (address(0xdead), 0, ""));
        bytes memory sig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(3)), 0);
        assertEq(vd, 1, "bootstrap MUST NOT sign execute");
        assertEq(w.bootstrapUses(), 0);
    }

    function test_c10VerifierFailureReturnsFailed() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(false);
        bytes memory callData = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
        assertEq(w.slotUses(1), 0, "failed verify MUST NOT bump counter");
    }

    function test_wrongInnerSigLengthFails() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory sig = _wrapSig(1, new bytes(4007)); // off-by-one
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
    }

    function test_unknownOwnerIndexFails() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory sig = _wrapSig(99, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
    }

    // ── Rotation flow ───────────────────────────────────────────────

    function test_rotationBootstrapAddsSlot1ThenSlot1Executes() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Bootstrap adds slot1 as ownerIndex 2.
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory addOwnerCall = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(1)), 0),
            0
        );

        // Simulate EntryPoint executing the addOwner self-call.
        vm.prank(address(w));
        w.addOwnerBytes(slot1Bytes);
        assertEq(w.nextOwnerIndex(), 3);

        // Slot1 signs an execute.
        bytes memory execCall = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory slot1Sig = _wrapSig(2, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), execCall, slot1Sig), bytes32(uint256(2)), 0),
            0
        );
        assertEq(w.slotUses(2), 1);
    }

    // ── Use-cap exhaustion ──────────────────────────────────────────

    function test_bootstrapCapExhausts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Write max-1 bootstrap uses directly into storage.
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 slot = bytes32(uint256(base) + 4); // bootstrapUses is field #4 of the struct
        vm.store(address(w), slot, bytes32(uint256(65_535)));

        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory addOwnerCall = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());

        // 65,536th bootstrap use succeeds.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.bootstrapUses(), 65_536);

        // 65,537th is rejected — pre-check guards the verifier.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(2)), 0),
            1
        );
        assertEq(w.bootstrapUses(), 65_536);
    }

    function test_slotCapExhausts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // slotUses is a mapping at field #5. Its slot for key `1` is
        // keccak256(uint256(1) || uint256(base+5)).
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 mapSlot = bytes32(uint256(base) + 5);
        bytes32 entrySlot = keccak256(abi.encode(uint256(1), mapSlot));
        vm.store(address(w), entrySlot, bytes32(uint256(65_535)));

        bytes memory callData = abi.encodeCall(w.execute, (address(0xbeef), 0, ""));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.slotUses(1), 65_536);

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(2)), 0),
            1
        );
    }
}
