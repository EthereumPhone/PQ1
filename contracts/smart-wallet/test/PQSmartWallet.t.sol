// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {PQMultiOwnable} from "../src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice End-to-end tests for the post-quantum smart wallet + proxy
///         factory. The real C10 verifier is tested separately by
///         `SPHINCsC10Asm.t.sol`.
contract PQSmartWalletTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);

    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    bytes32 internal constant SLOT1_PK_SEED = bytes32(uint256(0xeeee) << 240);
    bytes32 internal constant SLOT1_PK_ROOT = bytes32(uint256(0xffff) << 240);

    bytes internal constant FACTORY_SIG = hex"aaaa"; // mock accepts anything when setValid(true)

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    // ── helpers ─────────────────────────────────────────────────────

    function _deployWallet() internal returns (PQSmartWallet) {
        c10.setValid(true);
        return factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
    }

    function _wrapSig(uint256 ownerIndex, bytes memory innerSig) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, innerSig);
    }

    function _fakeC10Sig() internal pure returns (bytes memory) {
        return new bytes(4008);
    }

    function _packedOp(address sender, bytes memory callData, bytes memory sig)
        internal
        pure
        returns (UserOperation06 memory op)
    {
        op.sender = sender;
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = sig;
    }

    // ── Factory: address determinism ───────────────────────────────

    function test_factoryAddressPerUserStableAcrossChains() public {
        address a = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);

        // Chain-switch: address depends only on (factory, impl, salt), all
        // invariant to chainId, so the predicted address must not move.
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

    function test_factoryDeploysProxyNotImpl() public {
        PQSmartWallet w = _deployWallet();
        assertTrue(address(w).code.length > 0 && address(w).code.length < 200,
            "wallet should be a tiny ~55B ERC-1967 proxy, not the full impl");
        assertTrue(address(impl).code.length > 1000,
            "impl should be the full bytecode");
        assertTrue(address(w) != address(impl), "proxy must not be the impl");
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

    function test_implInitializeReverts() public {
        bytes memory b = abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT);
        vm.expectRevert(PQSmartWallet.AlreadyInitialized.selector);
        impl.initialize(b, b);
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
        // Attacker has the victim's public bootstrap key but no sk, so
        // `factorySig` verification fails.
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

        // Real owner can still land on the same address with the real sig.
        c10.setValid(true);
        PQSmartWallet w = _deployWallet();
        bytes memory got = w.ownerAtIndex(1);
        bytes memory want = abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT);
        assertEq(keccak256(got), keccak256(want), "slot0 must be victim's, not attacker's");
    }

    // ── Wallet: signature validation & role split ──────────────────

    function test_slotSignValidate() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
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
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xdead), 0, "")
        );
        bytes memory sig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(3)), 0);
        assertEq(vd, 1, "bootstrap MUST NOT sign execute");
        assertEq(w.bootstrapUses(), 0);
    }

    function test_c10VerifierFailureReturnsFailed() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(false);
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
        assertEq(w.slotUses(1), 0, "failed verify MUST NOT bump counter");
    }

    function test_wrongInnerSigLengthFails() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, new bytes(4007));
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
    }

    function test_unknownOwnerIndexFails() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (99, 0, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(99, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0);
        assertEq(vd, 1);
    }

    // ── Rotation flow ───────────────────────────────────────────────

    function test_rotationBootstrapAddsSlot1ThenSlot1Executes() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory addOwnerCall = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(1)), 0),
            0
        );

        vm.prank(address(w));
        w.addOwnerBytes(slot1Bytes);
        assertEq(w.nextOwnerIndex(), 3);

        bytes memory execCall = abi.encodeCall(
            w.executeWithOffchainCount, (2, 0, address(0xbeef), 0, "")
        );
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

        // bootstrapUses is field #4 of PQMultiOwnableStorage.
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 slot = bytes32(uint256(base) + 4);
        vm.store(address(w), slot, bytes32(uint256(65_535)));

        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory addOwnerCall = abi.encodeCall(w.addOwnerBytes, (slot1Bytes));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.bootstrapUses(), 65_536);

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

        // slotUses is field #5 (mapping). Entry slot for key `1` is
        // keccak256(uint256(1) || uint256(base+5)).
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 mapSlot = bytes32(uint256(base) + 5);
        bytes32 entrySlot = keccak256(abi.encode(uint256(1), mapSlot));
        vm.store(address(w), entrySlot, bytes32(uint256(65_535)));

        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
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

    // ── N-mask layout enforcement ──────────────────────────────────
    //
    // C10 is a 128-bit-security scheme: pkSeed and pkRoot are 16-byte
    // values padded into the TOP half of a bytes32, with the bottom 16
    // bytes required to be zero. The verifier feeds the full 32 bytes
    // into its SHA-256 inputs, so a non-N-masked owner is unsignable.
    // The contract refuses to install one upfront.

    /// @dev A bytes32 with the N-mask convention violated (bottom 16
    ///      bytes set to 0xDEADBEEF... and top 16 bytes also populated).
    bytes32 internal constant DIRTY_SEED =
        bytes32(uint256(0xaaaa) << 240) | bytes32(uint256(0xdeadbeef));

    function test_factoryRejectsNonNMaskedMasterSeed() public {
        c10.setValid(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQMultiOwnable.InvalidNMaskLayout.selector,
                abi.encodePacked(DIRTY_SEED, MASTER_PK_ROOT)
            )
        );
        factory.createAccount(
            DIRTY_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
    }

    function test_factoryRejectsNonNMaskedMasterRoot() public {
        c10.setValid(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQMultiOwnable.InvalidNMaskLayout.selector,
                abi.encodePacked(MASTER_PK_SEED, DIRTY_SEED)
            )
        );
        factory.createAccount(
            MASTER_PK_SEED, DIRTY_SEED,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
    }

    function test_factoryRejectsNonNMaskedSlot0Seed() public {
        c10.setValid(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQMultiOwnable.InvalidNMaskLayout.selector,
                abi.encodePacked(DIRTY_SEED, SLOT0_PK_ROOT)
            )
        );
        factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            DIRTY_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
    }

    function test_addOwnerBytesRejectsNonNMaskedOwner() public {
        PQSmartWallet w = _deployWallet();
        bytes memory dirty = abi.encodePacked(DIRTY_SEED, SLOT1_PK_ROOT);
        vm.prank(address(w));
        vm.expectRevert(
            abi.encodeWithSelector(PQMultiOwnable.InvalidNMaskLayout.selector, dirty)
        );
        w.addOwnerBytes(dirty);
    }

    function test_addOwnerBytesRejectsNonNMaskedRoot() public {
        PQSmartWallet w = _deployWallet();
        bytes memory dirty = abi.encodePacked(SLOT1_PK_SEED, DIRTY_SEED);
        vm.prank(address(w));
        vm.expectRevert(
            abi.encodeWithSelector(PQMultiOwnable.InvalidNMaskLayout.selector, dirty)
        );
        w.addOwnerBytes(dirty);
    }

    // ── Off-chain sig count tracking ────────────────────────────────
    //
    // The slot's signing budget is shared between on-chain Type 2 sigs
    // (`slotUses[i]`) and off-chain (EIP-1271) sigs (`offchainSigCount[i]`).
    // The combined invariant `slotUses + offchainSigCount <= MAX_SLOT_USES`
    // is enforced both by `validateUserOp` (refusing the next Type 2
    // before bumping) and by `executeWithOffchainCount` (refusing a
    // monotonic count update past the cap).

    function test_executeWithOffchainCount_updatesCounter() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Validate + execute a UserOp that publishes offchain count = 17.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 17, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(1)), 0),
            0
        );
        // Then the EntryPoint runs the user's call against the wallet:
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectEmit(true, true, true, true);
        emit PQMultiOwnable.OffchainSigCountUpdated(1, 0, 17);
        w.executeWithOffchainCount(1, 17, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 17);
        assertEq(w.slotUses(1), 1);
    }

    function test_executeWithOffchainCount_idempotentSameValue() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // First publish: 5.
        vm.prank(ENTRY_POINT_ADDR);
        w.executeWithOffchainCount(1, 5, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 5);

        // Re-publish same value: must not revert, must not re-emit.
        vm.prank(ENTRY_POINT_ADDR);
        w.executeWithOffchainCount(1, 5, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 5);
    }

    function test_executeWithOffchainCount_rejectsNonMonotonic() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        vm.prank(ENTRY_POINT_ADDR);
        w.executeWithOffchainCount(1, 10, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 10);

        // Try to publish a lower value: must revert.
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQMultiOwnable.OffchainSigCountNotMonotonic.selector, uint256(1), uint256(10), uint256(9)
            )
        );
        w.executeWithOffchainCount(1, 9, address(0xbeef), 0, "");
    }

    function test_executeWithOffchainCount_rejectsCombinedCapExceeded() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Publish offchain count 65,536 with slotUses=0 → exactly at cap.
        vm.prank(ENTRY_POINT_ADDR);
        w.executeWithOffchainCount(1, 65_536, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 65_536);

        // Now try to publish 65,537 with slotUses=0 → over cap.
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQMultiOwnable.CombinedSlotCapExceeded.selector,
                uint256(1), uint256(0), uint256(65_537), uint256(65_536)
            )
        );
        w.executeWithOffchainCount(1, 65_537, address(0xbeef), 0, "");
    }

    function test_validateUserOp_rejectsType2WhenCombinedCapHit() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Pre-load the offchain counter to 65,535 (one short of cap), with slotUses=0.
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 mapSlot = bytes32(uint256(base) + 6); // offchainSigCount is field #6
        bytes32 entrySlot = keccak256(abi.encode(uint256(1), mapSlot));
        vm.store(address(w), entrySlot, bytes32(uint256(65_535)));

        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 65_535, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());

        // First Type 2: slotUses=0, offchain=65_535, sum=65_535 < cap. PASS.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.slotUses(1), 1);

        // Second Type 2: slotUses=1, offchain=65_535, sum=65_536 == cap. REFUSE.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(2)), 0),
            1
        );
        assertEq(w.slotUses(1), 1, "second Type 2 must NOT bump");
    }

    // ── EIP-1271 ────────────────────────────────────────────────────

    /// @dev Bytes4 EIP-1271 magic value: bytes4(keccak256("isValidSignature(bytes32,bytes)")).
    bytes4 internal constant EIP1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAILURE = 0xffffffff;

    function test_isValidSignature_happyPath() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes32 hash = bytes32(uint256(0x1234));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        bytes4 result = w.isValidSignature(hash, sig);
        assertEq(result, EIP1271_MAGIC, "valid slot sig must return 0x1626ba7e");
    }

    function test_isValidSignature_returnsFailureForBootstrap() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Solady's ERC1271 has an RPC-simulation path that burns gas when
        // `tx.gasprice == 0` to discourage replay outside RPC simulation.
        // Foundry's default gasprice is 0 — set it non-zero so the RPC path
        // is skipped and we exercise the normal on-chain semantics.
        vm.txGasPrice(1);

        bytes32 hash = bytes32(uint256(0x1234));
        bytes memory sig = _wrapSig(0, _fakeC10Sig());
        bytes4 result = w.isValidSignature(hash, sig);
        assertEq(result, EIP1271_FAILURE, "bootstrap sigs MUST NOT verify off-chain");
    }

    function test_isValidSignature_returnsFailureWhenC10Fails() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(false);
        vm.txGasPrice(1); // see comment above.

        bytes32 hash = bytes32(uint256(0x1234));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        bytes4 result = w.isValidSignature(hash, sig);
        assertEq(result, EIP1271_FAILURE);
    }

    function test_isValidSignature_doesNotBumpCounters() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes32 hash = bytes32(uint256(0x1234));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        w.isValidSignature(hash, sig);
        w.isValidSignature(hash, sig);
        w.isValidSignature(hash, sig);

        assertEq(w.slotUses(1), 0, "EIP-1271 must NOT bump slotUses");
        assertEq(w.offchainSigCount(1), 0, "EIP-1271 must NOT bump offchainSigCount");
        assertEq(w.bootstrapUses(), 0, "EIP-1271 must NOT bump bootstrapUses");
    }

    function test_isValidSignature_replayAcrossWalletsBlocked() public {
        // Two wallets with the SAME slot pubkey (same seed → same key in
        // the recovery contract). The mock verifier accepts any sig
        // unconditionally, so the only thing keeping a sig captured
        // against wallet A from validating against wallet B is the
        // EIP-712 nested wrapping that Solady applies — which embeds
        // `verifyingContract = address(this)` into the inner hash.
        //
        // Here we don't call `isValidSignature` (the mock would accept
        // any input hash). Instead we inspect the domain separator
        // surfaced via `eip712Domain()` and confirm it differs across
        // wallets — which is the property that prevents cross-wallet
        // replay.

        PQSmartWallet a = _deployWallet();

        // Deploy a second wallet at a different address by varying the
        // master pubkey (factory salt depends on master).
        c10.setValid(true);
        PQSmartWallet b = factory.createAccount(
            bytes32(uint256(0x5555) << 240), bytes32(uint256(0x6666) << 240),
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
        assertTrue(address(a) != address(b));

        (, , , , address verA, ,) = a.eip712Domain();
        (, , , , address verB, ,) = b.eip712Domain();
        assertEq(verA, address(a));
        assertEq(verB, address(b));
        assertTrue(verA != verB, "domain separator must differ per wallet");
    }
}
