// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {PQMultiOwnable} from "../src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {MockEntryPoint06} from "./mocks/MockEntryPoint06.sol";

/// @notice End-to-end tests for the post-quantum smart wallet + proxy
///         factory. The real C10 verifier is tested separately by
///         `SPHINCsC10Asm.t.sol`.
contract PQSmartWalletTest is Test {
    /// The entry point is now a real contract, not a bare address, because the
    /// wallet's validated-op credit lives in TRANSIENT storage and therefore
    /// only survives when validate and execute happen in ONE transaction.
    /// Driving both through `ep` is what makes these tests model a v0.6
    /// bundle; two separate `vm.prank`ed calls do not. See MockEntryPoint06.
    address internal ENTRY_POINT_ADDR;
    MockEntryPoint06 internal ep;

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
        ep = new MockEntryPoint06();
        ENTRY_POINT_ADDR = address(ep);
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

    /// First four bytes of returned revert data.
    function _selector(bytes memory ret) internal pure returns (bytes4 s) {
        require(ret.length >= 4, "revert data has no selector");
        assembly ("memory-safe") { s := mload(add(ret, 0x20)) }
    }

    /// The execute phase must have reverted with exactly `expected`.
    /// Used where validation legitimately SUCCEEDS and the guard under test
    /// lives at execute time — both phases must be in one transaction for
    /// that distinction to mean anything (see MockEntryPoint06).
    function _assertExecuteReverted(bool ok, bytes memory ret, bytes memory expected) internal {
        assertFalse(ok, "execute phase must revert");
        assertEq(ret, expected, "execute revert data");
    }

    function _assertExecuteRevertedWith(bool ok, bytes memory ret, bytes4 sel) internal {
        assertFalse(ok, "execute phase must revert");
        assertEq(_selector(ret), sel, "execute revert selector");
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

    /// @dev Helper: drive a paired `validateUserOp + executeWithOffchainCount`
    ///      cycle the way EntryPoint v0.6 would in production. After H-3 the
    ///      executed call requires a preceding validate to have stamped the
    ///      transient ownerIndex token; tests that called execute directly
    ///      now use this helper.
    function _validateAndExecute(
        PQSmartWallet w,
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (ownerIndex, newOffchainCount, target, value, data)
        );
        bytes memory sig = _wrapSig(ownerIndex, _fakeC10Sig());
        // ONE transaction: validate then execute, the v0.6 order. The credit
        // is transient, so two separate top-level calls would not carry it.
        require(
            ep.validateThenExecute(
                address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
            ) == 0,
            "validate failed"
        );
    }

    /// @dev Same as `_validateAndExecute` but for the batch variant.
    function _validateAndExecuteBatch(
        PQSmartWallet w,
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory datas
    ) internal {
        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (ownerIndex, newOffchainCount, targets, values, datas)
        );
        bytes memory sig = _wrapSig(ownerIndex, _fakeC10Sig());
        // ONE transaction, as above.
        require(
            ep.validateThenExecute(
                address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
            ) == 0,
            "validate failed"
        );
    }

    /// @dev Stamp the transient ownerIndex token without running real
    ///      validation. Used by tests that want to drive `executeWith*`
    ///      revert paths in isolation (e.g. the `OffchainSigCountNotMonotonic`
    ///      regression) without re-validating between every step.
    function _primeValidatedOwnerIndex(PQSmartWallet w, uint256 ownerIndex) internal {
        c10.setValid(true);
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (ownerIndex, 0, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(ownerIndex, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        require(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(0), 0) == 0,
            "prime: validate failed"
        );
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
        // Bootstrap few-time cap is bumped in the VALIDATION phase (mirrors
        // the slot path) — an accepted Type-1 sig spent a master-key
        // few-time position and is counted revert-proof up front.
        assertEq(w.bootstrapUses(), 1, "bootstrap MUST bump at validation");

        // Drive the execute half of the EntryPoint pair the way v0.6 does:
        // the EntryPoint dispatches `userOp.callData` to the wallet, so the
        // EntryPoint — not the wallet — is `msg.sender` for `addOwnerBytes`.
        // Execution lands the rotation but does NOT bump again (the count
        // already happened at validation).
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slot1Bytes);
        assertEq(w.bootstrapUses(), 1, "execution does not double-count");
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

        vm.prank(ENTRY_POINT_ADDR);
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

        // First validation passes (bootstrapUses=65_535 < cap=65_536) and
        // bumps `bootstrapUses` to the cap of 65_536 in the validation phase.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall, bootstrapSig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.bootstrapUses(), 65_536, "validation bumps to cap");
        // Execution lands the rotation but does not bump again.
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slot1Bytes);
        assertEq(w.bootstrapUses(), 65_536);

        // Now `bootstrapUses == cap`. The second validate is the cap-hit
        // case — it must return `SIG_VALIDATION_FAILED` without bumping.
        // Re-use distinct owner bytes so the AlreadyOwner path doesn't
        // mask the validation failure.
        bytes memory slot2Bytes = abi.encodePacked(
            bytes32(uint256(0x7777) << 240), bytes32(uint256(0x8888) << 240)
        );
        bytes memory addOwnerCall2 = abi.encodeCall(w.addOwnerBytes, (slot2Bytes));
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), addOwnerCall2, bootstrapSig), bytes32(uint256(2)), 0),
            1
        );
        assertEq(w.bootstrapUses(), 65_536, "exhausted cap must stay frozen");
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
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(PQMultiOwnable.InvalidNMaskLayout.selector, dirty)
        );
        w.addOwnerBytes(dirty);
    }

    function test_addOwnerBytesRejectsNonNMaskedRoot() public {
        PQSmartWallet w = _deployWallet();
        bytes memory dirty = abi.encodePacked(SLOT1_PK_SEED, DIRTY_SEED);
        vm.prank(ENTRY_POINT_ADDR);
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
        vm.expectEmit(true, true, true, true);
        emit PQMultiOwnable.OffchainSigCountUpdated(1, 0, 17);
        // One transaction: the EntryPoint validates, then runs the user's call.
        assertEq(
            ep.validateThenExecute(
                address(w), _packedOp(address(w), callData, sig), bytes32(uint256(1)), 0, callData
            ),
            0
        );
        assertEq(w.offchainSigCount(1), 17);
        assertEq(w.slotUses(1), 1);
    }

    function test_executeWithOffchainCount_idempotentSameValue() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // First publish: 5 (paired validate+execute, per EntryPoint v0.6 flow).
        _validateAndExecute(w, 1, 5, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 5);

        // Re-publish same value: must not revert, must not re-emit.
        _validateAndExecute(w, 1, 5, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 5);
    }

    function test_executeWithOffchainCount_rejectsNonMonotonic() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        _validateAndExecute(w, 1, 10, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 10);

        // Try to publish a lower value: must revert.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 9, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 0, "validation passes; monotonicity is an execute-time gate");
        _assertExecuteReverted(ok, ret, abi.encodeWithSelector(
            PQMultiOwnable.OffchainSigCountNotMonotonic.selector, uint256(1), uint256(10), uint256(9)
        ));
    }

    function test_executeWithOffchainCount_rejectsCombinedCapExceeded() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // After H-3 every execute is gated by a paired validate, so the
        // execute-time cap check fires against post-bump `slotUses`.
        // Validation passes (slotUses=0 + offchain=0 < cap) and bumps
        // `slotUses[1]` to 1. The execute then asserts `slotUses(1) +
        // newCount(65_536) = 65_537 > MAX_SLOT_USES`.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 65_536, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 0, "validation passes and bumps slotUses to 1");
        assertEq(w.slotUses(1), 1);
        _assertExecuteReverted(ok, ret, abi.encodeWithSelector(
            PQMultiOwnable.CombinedSlotCapExceeded.selector,
            uint256(1), uint256(1), uint256(65_536), uint256(65_536)
        ));
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

    // ── Batch-sign path ─────────────────────────────────────────────
    //
    // The firmware's `CMD_SIGN_USEROP_BATCH` builds Type 2 callData via
    // `executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])`
    // (selector 0x7a389933). The on-chain `_isSlotAllowedSelector`
    // already accepts that selector alongside `executeWithOffchainCount`,
    // so the wallet validates batch signatures on the same code path
    // that handles single-tx ones. These tests pin down:
    //
    //   * the selector matches what the firmware bakes in
    //     (`shared::EXECUTE_BATCH_SELECTOR`),
    //   * a slot sig over a batch UserOp validates and bumps slotUses,
    //   * the bootstrap key cannot sign batch calldata,
    //   * `executeBatchWithOffchainCount` runs every inner call,
    //   * length-mismatched batch calldata reverts inside execute,
    //   * the off-chain count update + combined-cap enforcement
    //     applies to the batch path identically.
    //
    // Mirrors the per-test-case structure of `test_slotSignValidate`
    // / `test_executeWithOffchainCount_*`.

    /// @dev The firmware-side `EXECUTE_BATCH_SELECTOR` constant must
    ///      match this contract's selector for
    ///      `executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])`.
    function test_executeBatchSelector() public view {
        bytes4 onChain = PQSmartWallet.executeBatchWithOffchainCount.selector;
        bytes4 expected = bytes4(0x7a389933); // mirror sphincs_tz_shared::EXECUTE_BATCH_SELECTOR
        assertEq(onChain, expected, "executeBatchWithOffchainCount selector drifted");
    }

    function test_batchSlotSignValidate() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        address[] memory tos = new address[](2);
        tos[0] = address(0xbeef);
        tos[1] = address(0xfeed);
        uint256[] memory vals = new uint256[](2);
        vals[0] = 0;
        vals[1] = 0;
        bytes[] memory ds = new bytes[](2);
        ds[0] = "";
        ds[1] = "";

        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (1, 0, tos, vals, ds)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(
            _packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0
        );
        assertEq(vd, 0, "slot sig over executeBatch must validate");
        assertEq(w.slotUses(1), 1, "batch sig bumps slotUses by 1");
        assertEq(w.bootstrapUses(), 0);
    }

    function test_batchBootstrapForbidden() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        address[] memory tos = new address[](1);
        tos[0] = address(0xbeef);
        uint256[] memory vals = new uint256[](1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = "";

        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (1, 0, tos, vals, ds)
        );
        // ownerIndex = 0 → bootstrap. Bootstrap is only allowed to call
        // `addOwnerBytes`. Batch (or any non-addOwner selector) under
        // bootstrap MUST fail.
        bytes memory sig = _wrapSig(0, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(
            _packedOp(address(w), callData, sig), bytes32(uint256(0xabc)), 0
        );
        assertEq(vd, 1, "bootstrap MUST NOT sign executeBatch");
        assertEq(w.bootstrapUses(), 0);
    }

    /// Recipient stub used to verify executeBatch dispatched into each
    /// inner target with the right call+value.
    function test_executeBatchWithOffchainCount_runsInnerCalls() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Three throw-away recipient contracts that record what they
        // received. Use simple address-with-payable-receive contracts.
        BatchRecorder r0 = new BatchRecorder();
        BatchRecorder r1 = new BatchRecorder();
        BatchRecorder r2 = new BatchRecorder();

        address[] memory tos = new address[](3);
        tos[0] = address(r0);
        tos[1] = address(r1);
        tos[2] = address(r2);
        uint256[] memory vals = new uint256[](3);
        vals[0] = 0;
        vals[1] = 0;
        vals[2] = 0;
        bytes[] memory ds = new bytes[](3);
        ds[0] = abi.encodeCall(BatchRecorder.bump, (uint256(11)));
        ds[1] = abi.encodeCall(BatchRecorder.bump, (uint256(22)));
        ds[2] = abi.encodeCall(BatchRecorder.bump, (uint256(33)));

        // Paired validate+execute, per EntryPoint v0.6 flow (H-3 gate).
        _validateAndExecuteBatch(w, 1, 5, tos, vals, ds);

        // Each recorder saw its respective bump.
        assertEq(r0.value(), 11, "r0 saw call 0");
        assertEq(r1.value(), 22, "r1 saw call 1");
        assertEq(r2.value(), 33, "r2 saw call 2");
        // Off-chain count published.
        assertEq(w.offchainSigCount(1), 5);
    }

    function test_executeBatchWithOffchainCount_arrayLengthMismatchReverts() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        address[] memory tos = new address[](2);
        uint256[] memory vals = new uint256[](2);
        bytes[] memory ds = new bytes[](1);
        tos[0] = address(0x1); tos[1] = address(0x2);
        vals[0] = 0; vals[1] = 0;
        ds[0] = "";

        // Validate first so `_consumeValidatedOwnerIndex` passes and we
        // exercise the L-3 custom-error path on the length-mismatch arm.
        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (1, 0, tos, vals, ds)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 0, "validation passes; the length check is an execute-time gate");
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.BatchArrayLengthMismatch.selector);
    }

    function test_batch_combinedCapEnforcedByValidate() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Pre-load offchain counter to 65,535 (one short of cap) and
        // slotUses=0 — exactly the same edge condition the single-tx
        // path is checked against in `test_validateUserOp_rejectsType2WhenCombinedCapHit`,
        // but exercised through the batch selector.
        bytes32 base = 0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;
        bytes32 mapSlot = bytes32(uint256(base) + 6); // offchainSigCount
        bytes32 entrySlot = keccak256(abi.encode(uint256(1), mapSlot));
        vm.store(address(w), entrySlot, bytes32(uint256(65_535)));

        address[] memory tos = new address[](1);
        tos[0] = address(0xbeef);
        uint256[] memory vals = new uint256[](1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = "";
        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (1, 65_535, tos, vals, ds)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());

        // First batch: slotUses=0, offchain=65,535, sum=65,535 < cap → PASS
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(1)), 0),
            0
        );
        assertEq(w.slotUses(1), 1);

        // Second batch: slotUses=1, offchain=65,535, sum=65,536 == cap → REFUSE
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(2)), 0),
            1
        );
        assertEq(w.slotUses(1), 1, "second batch must NOT bump");
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

    // ── Audit 2026-05-18 regressions ────────────────────────────────
    //
    // One regression test per finding from
    // `contracts/smart-wallet/AUDIT_2026-05-18.md`. Each test is the
    // reproduction case the audit recommended, adapted to assert the
    // post-fix invariant (so the test passes once the fix lands).

    // H-1 — Factory must NOT strand `msg.value` on already-deployed wallets.

    function test_audit_h1_factoryForwardsValueWhenAlreadyDeployed() public {
        PQSmartWallet w = _deployWallet();
        assertEq(address(w).balance, 0);
        assertEq(address(factory).balance, 0);

        vm.deal(address(this), 1 ether);
        PQSmartWallet w2 = factory.createAccount{value: 1 ether}(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            FACTORY_SIG
        );
        assertEq(address(w), address(w2), "second call hits the same CREATE2");
        assertEq(address(w).balance, 1 ether, "wallet must receive forwarded ETH");
        assertEq(address(factory).balance, 0, "factory must NOT trap ETH");
    }

    function test_audit_h1_factoryAlreadyDeployedSkipsSigCheck() public {
        // First create with a valid sig (mock accepts anything).
        _deployWallet();

        // Second call with the mock flipped to REJECT must still
        // succeed (and forward msg.value) because the squat-defence is
        // skipped when `alreadyDeployed`.
        c10.setValid(false);
        vm.deal(address(this), 0.5 ether);
        PQSmartWallet w2 = factory.createAccount{value: 0.5 ether}(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            hex"00" // any garbage — verifier flipped to false anyway
        );
        assertEq(address(w2).balance, 0.5 ether, "deposit lands on existing wallet");
    }

    // H-2 — Slot key MUST NOT be able to register new owners via the
    // slot-execute path's self-call.

    function test_audit_h2_executeWithOffchainCount_rejectsSelfTarget() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory innerAddOwnerCall = abi.encodeCall(
            w.addOwnerBytes,
            (abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT))
        );

        // Validate first so we exercise the execute-time guard (not the
        // missing-validate guard). The validate side accepts this — the
        // call is `executeWithOffchainCount`, a slot-allowed selector.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(w), 0, innerAddOwnerCall)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 0, "validation passes; the role-split must be enforced at execute time");
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.SelfCallForbidden.selector);

        assertEq(w.nextOwnerIndex(), 2, "slot key MUST NOT mint new owners");
    }

    function test_audit_h2_executeBatch_rejectsSelfTargetAnywhereInArray() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        BatchRecorder recorder = new BatchRecorder();
        address[] memory tos = new address[](3);
        tos[0] = address(recorder);
        tos[1] = address(w);    // ← self in the middle of the batch
        tos[2] = address(recorder);
        uint256[] memory vals = new uint256[](3);
        bytes[] memory ds = new bytes[](3);
        ds[0] = abi.encodeCall(BatchRecorder.bump, (uint256(1)));
        ds[1] = abi.encodeCall(
            w.addOwnerBytes,
            (abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT))
        );
        ds[2] = abi.encodeCall(BatchRecorder.bump, (uint256(2)));

        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (1, 0, tos, vals, ds)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 0, "validation passes; the role-split is an execute-time gate");
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.SelfCallForbidden.selector);

        assertEq(w.nextOwnerIndex(), 2, "no new owner installed via batch self-call");
    }

    // H-3 — `executeWith*` must reject when calldata `ownerIndex`
    // does not match the validated wrapper's ownerIndex.

    function test_audit_h3_rejectsMismatchedOwnerIndex() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Wrapper signs as slot 1, but calldata names `ownerIndex = 99`.
        // The H-3 parity check now fires at VALIDATION: the op is rejected
        // before it can stamp a credit or burn slot 1's budget — which is
        // what stops a co-bundled slot-99 op's credit from being stolen.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (99, 0, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        // ONE transaction. Across two, the execute would revert merely because
        // transient storage was cleared between them, proving nothing about
        // whether the REJECTED validation leaked a credit to index 99. Paired,
        // it proves exactly that.
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 1, "mismatched ownerIndex rejected at validation");
        assertEq(w.slotUses(1), 0, "rejected op must NOT burn slot 1's budget");
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.OwnerIndexMismatch.selector);
        assertEq(w.offchainSigCount(99), 0, "victim slot must NOT be poisoned");
    }

    // SOL6 (adversarial-review on-chain / work-todo #12c) — PINS CURRENT
    // BEHAVIOR, does not ratify it. `removeOwnerAtIndex` is DELIBERATELY exempt
    // from the H-3 ownerIndex-parity check (`selector !=
    // this.removeOwnerAtIndex.selector` in `_validateSignature`), so a slot key
    // at index i can sign a removal of a DIFFERENT non-bootstrap slot j — the
    // mirror of `test_audit_h3_rejectsMismatchedOwnerIndex`, where the same
    // slot-1 signer is REJECTED for `execute(99)`. Impact is intra-wallet
    // AVAILABILITY, not fund theft: the bootstrap owner (index 0) is unremovable
    // and can re-add any pruned slot. This test locks the current design so that
    // binding i==j for the remove selector in future is a DELIBERATE flip (this
    // test then fails and must be updated), never a silent regression. Whether
    // the behavior is DESIRABLE is a threat-model decision — see
    // docs/security/threat-model.md §8.
    function test_sol6_crossSlotRemoveIsAcceptedByDesign() public {
        PQSmartWallet w = _deployWallet(); // owner 0 = bootstrap, owner 1 = slot0
        c10.setValid(true);

        // Bootstrap installs a second removable slot at index 2 (the execute
        // half of an addOwner pair; EntryPoint-gated direct call).
        bytes memory slot1Bytes = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slot1Bytes);
        assertEq(w.ownerAtIndex(2), slot1Bytes, "slot at index 2 installed");

        // Slot key at index 1 signs removal of the UNRELATED slot at index 2:
        // wrapper ownerIndex = 1 (signer), calldata removal index = 2.
        bytes memory callData = abi.encodeCall(w.removeOwnerAtIndex, (2, slot1Bytes));
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd =
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(uint256(0x5016)), 0);
        assertEq(
            vd, 0,
            "SOL6: cross-slot removeOwnerAtIndex is accepted by design (remove is H-3-exempt)"
        );

        // Execute half: the removal actually lands, driven by the slot-1 signer.
        vm.prank(ENTRY_POINT_ADDR);
        w.removeOwnerAtIndex(2, slot1Bytes);
        assertEq(w.ownerAtIndex(2).length, 0, "slot 2 pruned by the slot-1 signer");

        // Recovery holds: the (unremovable) bootstrap owner can re-add the slot.
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slot1Bytes);
        assertEq(
            w.ownerAtIndex(w.nextOwnerIndex() - 1), slot1Bytes,
            "bootstrap re-adds the pruned slot (availability recovery)"
        );
    }

    function test_audit_h3_acceptsMatchingOwnerIndex() public {
        // Regression: the parity check must not block the legitimate
        // case where wrapper and calldata both name slot 1.
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        _validateAndExecute(w, 1, 42, address(0xbeef), 0, "");
        assertEq(w.offchainSigCount(1), 42);
        assertEq(w.slotUses(1), 1);
    }

    function test_audit_h3_executeBatch_rejectsMismatchedOwnerIndex() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        address[] memory tos = new address[](1);
        tos[0] = address(0xbeef);
        uint256[] memory vals = new uint256[](1);
        bytes[] memory ds = new bytes[](1);
        ds[0] = "";

        bytes memory callData = abi.encodeCall(
            w.executeBatchWithOffchainCount, (99, 0, tos, vals, ds)
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        // ONE transaction, for the same reason as the single-call sibling.
        (uint256 vd, bool ok, bytes memory ret) = ep.validateThenTryExecute(
            address(w), _packedOp(address(w), callData, sig), bytes32(0), 0, callData
        );
        assertEq(vd, 1, "mismatched ownerIndex rejected at validation");
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.OwnerIndexMismatch.selector);
    }

    function test_audit_h3_executeFailsIfCalledOutsideValidatedFlow() public {
        // Direct call from EntryPoint without any prior `validateUserOp`
        // — the transient ownerIndex is empty, so parity check fires.
        // (Also defends against a future EntryPoint-impersonator who
        // skips validate.)
        PQSmartWallet w = _deployWallet();
        (bool ok, bytes memory ret) = ep.tryExecuteOnly(
            address(w),
            abi.encodeCall(w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, ""))
        );
        _assertExecuteRevertedWith(ok, ret, PQSmartWallet.OwnerIndexMismatch.selector);
    }

    /// H-3 sibling — one-shot consumption. After a validated execute
    /// runs once, a SECOND execute in the same tx with identical
    /// parameters must revert: the transient ownerIndex token was
    /// consumed by the first execute's `_consumeValidatedOwnerIndex`
    /// (`tstore(0)` clears it regardless of success). Confirms the
    /// "one validate → one execute" semantics, ruling out a replay
    /// attack where an attacker who controls the EntryPoint queues
    /// the same execute twice against one validated bundle.
    function test_audit_h3_validateConsumedByPriorExecute() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        // Validate slot-1 + execute(1, ...) once — both succeed.
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 7, address(0xbeef), 0, "")
        );
        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        // ONE validate, then TWO executes, all inside a single transaction —
        // which is the only setting where "the credit is one-shot" is a
        // meaningful claim. Across separate transactions the second call would
        // fail merely because transient storage was cleared, proving nothing.
        (uint256 vd, bool firstOk, bool secondOk, bytes memory secondRet) =
            ep.validateThenExecuteTwice(
                address(w), _packedOp(address(w), callData, sig), bytes32(0), callData
            );
        assertEq(vd, 0);
        assertTrue(firstOk, "the validated execute must succeed");
        assertEq(w.offchainSigCount(1), 7);

        // Second execute with the SAME parameters must revert — the
        // transient credit was consumed by the first.
        assertFalse(secondOk, "the credit is one-shot");
        assertEq(
            _selector(secondRet),
            PQSmartWallet.OwnerIndexMismatch.selector,
            "second execute must fail for lack of credit"
        );

        // Counter wasn't bumped again (would have failed the monotonic
        // check anyway, but the revert happens before that gate).
        assertEq(w.offchainSigCount(1), 7);
    }

    // Bootstrap budget is counted REVERT-PROOF in the validation phase.
    //
    // History: an earlier "audit M-1" fix DEFERRED the bootstrap bump to
    // `addOwnerBytes`, gated on `_addOwner` succeeding, on the theory that a
    // reverting duplicate-add should not burn a unit. That was a
    // misdiagnosis: an accepted Type-1 signature has already spent a
    // master-key few-time position regardless of whether `_addOwner` lands,
    // and v0.6 swallows the revert — so the deferred bump under-counted the
    // cap toward zero (PQBootstrapCapEvasion). The bump is now done at
    // validation, mirroring the slot path.

    function test_bootstrapBumpCountsEvenWhenAddOwnerReverts() public {
        // A bootstrap-signed `addOwnerBytes(existing bootstrap bytes)`
        // reverts with `AlreadyOwner` in execution — but the accepted
        // signature MUST still count against the few-time cap.
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory existingBootstrap = abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT);
        bytes memory callData = abi.encodeCall(w.addOwnerBytes, (existingBootstrap));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());

        // Validate — passes (selector is `addOwnerBytes`, cap not hit) and
        // counts the accepted signature up front.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, bootstrapSig), bytes32(0), 0),
            0
        );
        assertEq(w.bootstrapUses(), 1, "accepted bootstrap sig counted at validation");

        // Execute via the EntryPoint (v0.6 dispatches `userOp.callData`, so
        // the EntryPoint is `msg.sender`). `_addOwner` reverts on
        // `AlreadyOwner`; the EntryPoint swallows it in production. The count
        // already happened at validation and is unaffected by the revert.
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(
            abi.encodeWithSelector(PQMultiOwnable.AlreadyOwner.selector, existingBootstrap)
        );
        w.addOwnerBytes(existingBootstrap);

        assertEq(w.bootstrapUses(), 1, "count survives the execution-phase revert");
    }

    function test_bootstrapBumpAtValidation_noDoubleCountOnSuccess() public {
        // Happy path: bump at validation; the successful execution lands the
        // rotation but does not bump again.
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory slot1 = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        bytes memory callData = abi.encodeCall(w.addOwnerBytes, (slot1));
        bytes memory bootstrapSig = _wrapSig(0, _fakeC10Sig());

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, bootstrapSig), bytes32(0), 0),
            0
        );
        assertEq(w.bootstrapUses(), 1, "bumped at validation");

        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(slot1);
        assertEq(w.bootstrapUses(), 1, "execution does not double-count");
        assertEq(w.nextOwnerIndex(), 3);
    }

    // L-1 — wrapper tail-pad bytes MUST be zero.

    function test_audit_l1_validateUserOp_rejectsNonZeroWrapperPad() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        assertEq(sig.length, 4128);
        // Flip a tail-pad byte (positions [4104..4128)).
        sig[4104] = 0xAA;

        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(0), 0),
            1,
            "non-zero wrapper pad MUST fail validation"
        );
    }

    function test_audit_l1_validateUserOp_rejectsNonZeroPadAtLastByte() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);

        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        sig[4127] = 0x01; // last byte of the wrapper

        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(0), 0),
            1
        );
    }

    function test_audit_l1_isValidSignature_rejectsNonZeroWrapperPad() public {
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        vm.txGasPrice(1); // skip Solady's RPC-simulation gas burn

        bytes memory sig = _wrapSig(1, _fakeC10Sig());
        sig[4127] = 0xFF;

        bytes4 result = w.isValidSignature(bytes32(uint256(0x1234)), sig);
        assertEq(result, EIP1271_FAILURE, "non-zero wrapper pad MUST fail EIP-1271");
    }

    function test_audit_l1_acceptsZeroPaddedWrapper() public {
        // Regression: the legitimate wrapper (pad is zero by abi.encode)
        // must still validate.
        PQSmartWallet w = _deployWallet();
        c10.setValid(true);
        bytes memory sig = _wrapSig(1, _fakeC10Sig()); // clean abi.encode
        bytes memory callData = abi.encodeCall(
            w.executeWithOffchainCount, (1, 0, address(0xbeef), 0, "")
        );
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), callData, sig), bytes32(0), 0),
            0
        );
    }

    // L-2 — `_erc1271Signer()` must revert loudly.

    function test_audit_l2_erc1271SignerReverts() public {
        // Smoke test: confirm the hook reverts. We use a free-floating
        // function selector and `staticcall` so the test does not
        // require an inheriting child contract.
        PQSmartWallet w = _deployWallet();
        (bool ok, ) = address(w).staticcall(abi.encodeWithSignature("_erc1271Signer()"));
        // `_erc1271Signer` is internal — the staticcall returns success=false
        // because the selector isn't reachable externally. The "revert
        // loudly" property is enforced by source review (see
        // `PQSmartWallet._erc1271Signer`), and the dependent
        // `_erc1271IsValidSignatureNowCalldata` override is exercised
        // by every `isValidSignature` test in this file. Keep this as
        // a documentation-grade smoke check.
        assertFalse(ok);
    }
}

/// @notice Tiny stub used by `test_executeBatchWithOffchainCount_runsInnerCalls`
///         to confirm each inner batch call landed.
contract BatchRecorder {
    uint256 public value;
    function bump(uint256 v) external {
        value = v;
    }
    receive() external payable {}
}
