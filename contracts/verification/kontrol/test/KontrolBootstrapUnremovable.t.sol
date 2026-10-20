// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **First Kontrol (KEVM) proof against the DEPLOYED PQSmartWallet
///          runtime bytecode** — the model-to-bytecode gap (D) explored with
///          a symbolic-execution engine independent of Halmos.
///
///          PROPERTY (owner-set integrity / Lean
///          `Invariants.cannot_remove_bootstrap`): the bootstrap owner at
///          index 0 can NEVER change once the wallet is initialised. Owner
///          removal was deleted before launch (GitHub #131, #213), so the
///          three ways index 0 could move are each closed on the bytecode:
///            1. `addOwnerBytes` (the only owner-table writer) never writes
///               index 0, for ANY argument;
///            2. the former `removeOwnerAtIndex` selector reaches no code,
///               for ANY caller and argument;
///            3. `initialize` cannot run a second time, for ANY arguments.
///
///          WHY THIS IS A GOOD KONTROL TARGET
///          ---------------------------------
///          * NO SHA-256: none of these paths hashes with the `0x02`
///            precompile, so Kontrol never has to interpret it.
///          * NO unbounded loops.
///          * Deployment state is seeded with a real `initialize` (no factory
///            `createAccount`, which would pull `sha256` for the CREATE2 salt
///            + slot-0 squat digest — out of scope, axiom A3.3).
///
///          Mirrors `test/halmos/HalmosMultiOwnable.t.sol` (the add rule's
///          owner-0 frame, `check_removed_selector_does_not_dispatch`,
///          `check_initialize_one_shot`), transposed to the Kontrol/KEVM
///          engine: function arguments are symbolic by default (no `svm.*`).
contract KontrolBootstrapUnremovable is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    // N-mask-shaped owner keys (top 16 bytes set, bottom 16 zero) — the
    // exact shape the firmware emits and the contract's N-mask gate accepts.
    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        // KEVM's default block.chainid is 1 (mainnet); MockSPHINCSVerifier's
        // M14 deploy guard reverts unless chainid ∈ {31337, 1337, 0}. forge
        // defaults to 31337 so this is invisible under `forge test`, but the
        // KEVM symbolic engine needs it set explicitly or `setUp` reverts at
        // the mock's constructor. (Faithful: the mock is local-test-only.)
        vm.chainId(31337);
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        address proxy = LibClone.deployERC1967(address(impl));
        wallet = PQSmartWallet(payable(proxy));
        // Owners installed: index 0 = MASTER (bootstrap), index 1 = SLOT0.
        // nextOwnerIndex = 2. This is byte-identical to the storage the
        // factory's createAccount installs (which we skip — it hashes).
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    /// `bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)"))` — the
    /// selector of the deleted removal function.
    bytes4 internal constant REMOVED_REMOVE_OWNER_SELECTOR = 0x89625b57;

    /// **`addOwnerBytes` never writes index 0 — ∀ 64-byte argument.** The
    /// only owner-table writer appends at `nextOwnerIndex` (2 here), whether
    /// it accepts or rejects. Lean: `MultiOwnable.bootstrap_unremovable`
    /// (addOwner preserves `ownerAtIndex 0` once initialised).
    function prove_bootstrap_unchanged_by_addOwner(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 64);
        bytes memory pre0 = wallet.ownerAtIndex(0);

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {} catch {}

        assertEq(keccak256(wallet.ownerAtIndex(0)), keccak256(pre0), "bootstrap mutated by addOwnerBytes");
    }

    /// **The deleted removal function cannot touch index 0 — ∀ caller
    /// (EntryPoint included), ∀ argument, including the exact installed
    /// bootstrap bytes at index 0.** Its selector reaches no code.
    function prove_bootstrap_removal_selector_does_not_dispatch(address caller, bytes calldata expected) public {
        vm.assume(expected.length == 64);
        bytes memory pre0 = wallet.ownerAtIndex(0);

        vm.prank(caller);
        (bool ok,) = address(wallet).call(abi.encodeWithSelector(REMOVED_REMOVE_OWNER_SELECTOR, uint256(0), expected));
        assertTrue(!ok, "removal selector dispatched");

        vm.prank(caller);
        (ok,) = address(wallet).call(
            abi.encodeWithSelector(
                REMOVED_REMOVE_OWNER_SELECTOR, uint256(0), abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT)
            )
        );
        assertTrue(!ok, "removal selector dispatched (exact bootstrap bytes)");

        assertEq(keccak256(wallet.ownerAtIndex(0)), keccak256(pre0), "bootstrap mutated");
    }

    /// **`initialize` cannot replace the bootstrap — ∀ arguments.** Lean
    /// `Invariants.initialize_called_exactly_once`.
    function prove_bootstrap_reinitialize_rejected(bytes calldata a, bytes calldata b) public {
        vm.assume(a.length == 64);
        vm.assume(b.length == 64);
        bytes memory pre0 = wallet.ownerAtIndex(0);

        vm.expectRevert(PQSmartWallet.AlreadyInitialized.selector);
        wallet.initialize(a, b);

        assertEq(keccak256(wallet.ownerAtIndex(0)), keccak256(pre0), "bootstrap mutated by re-init");
    }
}
