// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @dev Stateful handler — Foundry fuzzer invokes these public methods
///      in random sequences. The invariants in the test contract are
///      checked after each handler call.
contract WalletInvariantHandler is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    PQSmartWallet public wallet;
    MockSPHINCSVerifier public c10;

    // Track maxima observed so we can assert monotonicity in the invariant.
    uint256 public maxBootstrapUses;
    mapping(uint256 => uint256) public maxSlotUses;
    mapping(uint256 => uint256) public maxOffchainSigCount;

    // Cached pre-state for invariant comparisons.
    bytes32 public initialImplSlotValue;

    constructor(PQSmartWallet w, MockSPHINCSVerifier mock) {
        wallet = w;
        c10 = mock;
        bytes32 IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        initialImplSlotValue = vm.load(address(wallet), IMPL_SLOT);
    }

    // ── Handler functions exposed to the fuzzer ─────────────────────

    /// Drive a slot-keyed UserOp through validate + execute (success path).
    /// `seed` selects the action; we run a single valid execute against a
    /// non-self target.
    function handler_executeOffchainCount(uint256 ownerIndex, uint256 newCount, uint256 value) external {
        // Constrain to a small, valid ownerIndex range.
        ownerIndex = bound(ownerIndex, 1, _activeSlotIndex());
        // newCount must be >= current to not revert.
        uint256 cur = wallet.offchainSigCount(ownerIndex);
        uint256 cap = wallet.MAX_SLOT_USES();
        uint256 slotUsesNow = wallet.slotUses(ownerIndex);
        // Keep newCount within the combined cap.
        uint256 maxNewCount = cap > slotUsesNow + 1 ? cap - slotUsesNow - 1 : cur;
        if (maxNewCount < cur) maxNewCount = cur;
        newCount = bound(newCount, cur, maxNewCount);

        c10.setValid(true);
        bytes memory innerSig = new bytes(4008);
        bytes memory wrappedSig = abi.encode(ownerIndex, innerSig);
        address target = address(0xc0ffee);  // Non-self target.
        bytes memory data = "";
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (ownerIndex, newCount, target, value, data)
        );
        UserOperation06 memory op = _packedOp(address(wallet), callData, wrappedSig);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);
        if (result != 0) return;  // validation failed; skip execution

        vm.deal(ENTRY_POINT_ADDR, value);
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(ownerIndex, newCount, target, value, data) {
            // Success.
            _bumpMonotonic(ownerIndex);
        } catch {
            // Execution-phase revert is acceptable.
        }
    }

    /// Drive a bootstrap-keyed UserOp through validate + addOwnerBytes.
    function handler_addOwner(uint256 newOwnerSeed) external {
        bytes memory ownerBytes = abi.encodePacked(
            bytes16(bytes32(newOwnerSeed)), bytes16(0),
            bytes16(bytes32(newOwnerSeed >> 128)), bytes16(0)
        );

        c10.setValid(true);
        bytes memory innerSig = new bytes(4008);
        bytes memory wrappedSig = abi.encode(uint256(0), innerSig);
        bytes memory callData = abi.encodeCall(wallet.addOwnerBytes, (ownerBytes));
        UserOperation06 memory op = _packedOp(address(wallet), callData, wrappedSig);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 result = wallet.validateUserOp(op, bytes32(0), 0);
        if (result != 0) return;

        vm.prank(address(wallet));
        try wallet.addOwnerBytes(ownerBytes) {
            _bumpMonotonic(0);
        } catch {}
    }

    // ── Helpers ─────────────────────────────────────────────────────

    function _activeSlotIndex() internal view returns (uint256) {
        uint256 n = wallet.nextOwnerIndex();
        return n > 1 ? n - 1 : 1;
    }

    function _bumpMonotonic(uint256 ownerIndex) internal {
        uint256 boot = wallet.bootstrapUses();
        if (boot > maxBootstrapUses) maxBootstrapUses = boot;
        uint256 slot = wallet.slotUses(ownerIndex);
        if (slot > maxSlotUses[ownerIndex]) maxSlotUses[ownerIndex] = slot;
        uint256 off = wallet.offchainSigCount(ownerIndex);
        if (off > maxOffchainSigCount[ownerIndex]) maxOffchainSigCount[ownerIndex] = off;
    }

    function _packedOp(address sender, bytes memory callData, bytes memory sig)
        internal pure returns (UserOperation06 memory op)
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
}

/// @notice Stateful invariant suite for PQSmartWallet.
///         Covers Claim 1, 2, and 3 monotonicity / structural invariants.
contract PQSmartWalletInvariantsTest is StdInvariant, Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);
    bytes32 internal constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;
    PQSmartWallet internal wallet;
    WalletInvariantHandler internal handler;

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);

        c10.setValid(true);
        wallet = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT,
            SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid),
            hex"aaaa"  // mock accepts anything when setValid(true)
        );

        handler = new WalletInvariantHandler(wallet, c10);
        targetContract(address(handler));
    }

    // ─── Claim 2: Owner-set integrity ───────────────────────────────

    /// **inv_bootstrap_owner_present.** Index 0 always has the bootstrap
    /// owner (64-byte pkSeed||pkRoot). Composes I-4 (`cannot_remove_bootstrap`)
    /// with `addOwner_preserves_index0`.
    function invariant_bootstrap_owner_present() external view {
        assertEq(wallet.ownerAtIndex(0).length, 64,
            "Claim 2 violation: bootstrap owner removed/changed");
    }

    /// **inv_nextOwnerIndex_at_least_2.** Post-initialize the wallet
    /// always has at least bootstrap + slot 0 indices. The `initialize`
    /// one-shot guard prevents reset.
    function invariant_nextOwnerIndex_at_least_2() external view {
        assertTrue(wallet.nextOwnerIndex() >= 2,
            "Claim 2 violation: nextOwnerIndex below initialized state");
    }

    /// **inv_impl_slot_unchanged.** The ERC-1967 implementation slot
    /// is never overwritten by any reachable execution path
    /// (`upgrade_path_unreachable`).
    function invariant_impl_slot_unchanged() external view {
        bytes32 current = vm.load(address(wallet), IMPL_SLOT);
        assertEq(current, handler.initialImplSlotValue(),
            "Claim 2 violation: ERC-1967 IMPL slot changed");
    }

    // ─── Claim 2/3: Counter monotonicity ────────────────────────────

    /// **inv_bootstrapUses_monotonic.** `bootstrapUses` never decreases.
    /// Composes I-2 + `bumpBootstrap_monotonic`.
    function invariant_bootstrapUses_monotonic() external view {
        assertTrue(wallet.bootstrapUses() >= handler.maxBootstrapUses(),
            "Claim 2/3 violation: bootstrapUses decreased");
    }

    /// **inv_combined_cap.** For each slot, `slotUses[i] +
    /// offchainSigCount[i] <= MAX_SLOT_USES`. (I-5 inductive invariant.)
    function invariant_combined_cap_slot0() external view {
        uint256 i = 0;
        uint256 sum = wallet.slotUses(i) + wallet.offchainSigCount(i);
        assertTrue(sum <= wallet.MAX_SLOT_USES(),
            "Claim 2/3 violation: combined cap exceeded (slot 0)");
    }

    function invariant_combined_cap_slot1() external view {
        uint256 i = 1;
        uint256 sum = wallet.slotUses(i) + wallet.offchainSigCount(i);
        assertTrue(sum <= wallet.MAX_SLOT_USES(),
            "Claim 2/3 violation: combined cap exceeded (slot 1)");
    }

    /// **inv_bootstrapUses_capped.** Bootstrap cap is never exceeded.
    function invariant_bootstrapUses_capped() external view {
        assertTrue(wallet.bootstrapUses() <= wallet.MAX_BOOTSTRAP_USES(),
            "Claim 2/3 violation: bootstrap cap exceeded");
    }
}
