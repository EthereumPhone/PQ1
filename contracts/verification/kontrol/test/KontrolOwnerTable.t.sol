// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../../smart-wallet/src/PQSmartWallet.sol";
import {PQMultiOwnable} from "../../../smart-wallet/src/PQMultiOwnable.sol";
import {MockSPHINCSVerifier} from "../../../smart-wallet/test/mocks/MockSPHINCSVerifier.sol";

/// @notice **A3.4 (owner-table) — Kontrol/KEVM port.** Proves the PQMultiOwnable
///         owner-table mutators + reads pointwise against the Lean
///         `Storage.{addOwner,tryInitialize,ownerAtIndex}` model (owner removal
///         was deleted before launch; Rule 2 proves its selector reaches no code),
///         DIRECTLY on the deployed `PQSmartWallet` runtime bytecode (KEVM
///         symbolic execution) — an engine independent of Halmos, with no
///         hand-written `LeanModel.sol` mirror in the loop. This is the
///         transcription-free discharge of bridge axiom A3.4
///         (`solidityMultiOwnable_compiles_correctly`); it mirrors the rules in
///         `test/halmos/HalmosMultiOwnable.t.sol` rule-for-rule. The
///         bootstrap-unremovable arm lives in `KontrolBootstrapUnremovable.t.sol`.
///
///         SYMBOLIC ENVELOPE: owner CONTENT is a symbolic `bytes calldata` arg
///         (KEVM makes it symbolic by default); we constrain the LENGTH per
///         class via `vm.assume` (a symbolic byte-length explodes the path
///         space — the same engine limit Halmos documents). N-mask layout and
///         duplicate membership stay fully symbolic; callers symbolic in the
///         access-gate rules; counters asserted in the frames.
contract KontrolOwnerTable is Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    /// ERC-7201 base of `PQMultiOwnableStorage`; field +1 is the reserved,
    /// always-zero former `removedOwnersCount`.
    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    /// `bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)"))` — the
    /// selector of the deleted removal function.
    bytes4 internal constant REMOVED_REMOVE_OWNER_SELECTOR = 0x89625b57;

    bytes32 internal constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 internal constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 internal constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 internal constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    MockSPHINCSVerifier internal c10;

    function setUp() public {
        // KEVM default chainid is 1; MockSPHINCSVerifier's M14 deploy guard
        // reverts off a local chain (see KontrolBootstrapUnremovable for the
        // full note). Set the local chainid before any deploy.
        vm.chainId(31337);
        c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        wallet = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));
        // index 0 = MASTER (bootstrap), index 1 = SLOT0; nextOwnerIndex = 2.
        wallet.initialize(
            abi.encodePacked(MASTER_PK_SEED, MASTER_PK_ROOT),
            abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    /// The reserved storage word (former `removedOwnersCount`).
    function _reservedWord() internal view returns (bytes32) {
        return vm.load(address(wallet), bytes32(uint256(PQ_SLOT_BASE) + 1));
    }

    /// Lean `OwnerBytes.hasNMaskLayout` / `Factory.nMasked`: the bottom 128 bits
    /// of each 32-byte word are zero (bytes [16..32) and [48..64)).
    function _nMasked64(bytes memory o) internal pure returns (bool) {
        bytes32 seed;
        bytes32 root;
        assembly ("memory-safe") {
            seed := mload(add(o, 32))
            root := mload(add(o, 64))
        }
        return uint128(uint256(seed)) == 0 && uint128(uint256(root)) == 0;
    }

    // ── Rule 1: addOwnerBytes ≡ Lean addOwner-model (length-64 arm) ──────────

    /// **`addOwnerBytes` pointwise (∀ symbolic 64-byte content).** Accepts iff
    /// the Lean model accepts (N-masked ∧ not already an owner); on accept,
    /// installs verbatim at the pre `nextOwnerIndex` and bumps it; existing
    /// owners + counters unmoved on both arms.
    function prove_addOwner_len64_pointwise(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 64);
        bool wantSuccess = _nMasked64(newOwner) && !wallet.isOwnerBytes(newOwner);

        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preReserved = _reservedWord();
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(wantSuccess, "A3.4 add: bytecode accepted what the Lean model rejects");
            assertEq(keccak256(wallet.ownerAtIndex(preNext)), keccak256(newOwner),
                "A3.4 add: owner not installed verbatim (read parity)");
            assertEq(wallet.nextOwnerIndex(), preNext + 1, "A3.4 add: nextOwnerIndex");
            assertTrue(wallet.isOwnerBytes(newOwner), "A3.4 add: isOwner not set");
        } catch {
            assertTrue(!wantSuccess, "A3.4 add: bytecode rejected what the Lean model accepts");
            assertEq(wallet.nextOwnerIndex(), preNext, "add fail-path: nextOwnerIndex moved");
        }
        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "add frame: owner 0");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "add frame: owner 1");
        assertEq(_reservedWord(), preReserved, "add frame: reserved word written");
    }

    /// **Wrong length is rejected** — the deployed length gate (Lean
    /// `newOwner.size ≠ 64 → none`). Boundary representatives 63 / 65.
    function prove_addOwner_rejects_len63(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 63);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "A3.4 add: accepted a 63-byte owner");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "add len63: nextOwnerIndex moved");
        }
    }

    function prove_addOwner_rejects_len65(bytes calldata newOwner) public {
        vm.assume(newOwner.length == 65);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "A3.4 add: accepted a 65-byte owner");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "add len65: nextOwnerIndex moved");
        }
    }

    // ── Rule 2: the deleted removal function does not dispatch ───────────────

    /// **The former `removeOwnerAtIndex(uint256,bytes)` selector reaches no
    /// code — ∀ caller (EntryPoint included), ∀ index, ∀ 64-byte argument.**
    /// The call reverts and the owner table, `nextOwnerIndex` and the
    /// reserved word are unchanged. The Lean model has no removal operation.
    function prove_removed_selector_does_not_dispatch(address caller, uint256 index, bytes calldata expected)
        public
    {
        vm.assume(expected.length == 64);
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));
        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preReserved = _reservedWord();

        vm.prank(caller);
        (bool ok,) =
            address(wallet).call(abi.encodeWithSelector(REMOVED_REMOVE_OWNER_SELECTOR, index, expected));
        assertTrue(!ok, "removal selector dispatched");

        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "rm: owner 0 changed");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "rm: owner 1 changed");
        assertEq(wallet.nextOwnerIndex(), preNext, "rm: nextOwnerIndex changed");
        assertEq(_reservedWord(), preReserved, "rm: reserved word written");
    }

    // ── Rule 3: initialize one-shot + fresh-install pointwise ────────────────

    /// **`initialize` on an initialised wallet reverts (∀ args)** — Lean
    /// `tryInitialize`'s `if s.nextOwnerIndex ≠ 0 then none` /
    /// `Invariants.initialize_called_exactly_once`.
    function prove_initialize_one_shot(bytes calldata a, bytes calldata b) public {
        vm.assume(a.length == 64);
        vm.assume(b.length == 64);
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        try wallet.initialize(a, b) {
            assertTrue(false, "Claim 2: re-initialize accepted");
        } catch {
            assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "re-init: owner 0 mutated");
            assertEq(wallet.nextOwnerIndex(), 2, "re-init: nextOwnerIndex moved");
        }
    }

    /// **Fresh-proxy `initialize` ≡ gated `tryInitialize`** (∀ symbolic 64-byte
    /// boot/slot0). Succeeds iff both are N-masked and distinct; installs
    /// verbatim at indices 0 and 1.
    function prove_initialize_fresh_pointwise(bytes calldata boot, bytes calldata slot0) public {
        vm.assume(boot.length == 64);
        vm.assume(slot0.length == 64);
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWallet fresh = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));

        bool wantSuccess =
            _nMasked64(boot) && _nMasked64(slot0) && keccak256(boot) != keccak256(slot0);

        try fresh.initialize(boot, slot0) {
            assertTrue(wantSuccess, "init: accepted outside the Lean gates");
            assertEq(keccak256(fresh.ownerAtIndex(0)), keccak256(boot), "init: bootstrap not verbatim");
            assertEq(keccak256(fresh.ownerAtIndex(1)), keccak256(slot0), "init: slot0 not verbatim");
            assertEq(fresh.nextOwnerIndex(), 2, "init: nextOwnerIndex != 2");
        } catch {
            assertTrue(!wantSuccess, "init: rejected inside the Lean gates");
            assertEq(fresh.nextOwnerIndex(), 0, "init fail-path: partial install");
        }
    }

    // ── Rule 4: access gates — EntryPoint-only (∀ non-EP caller) ─────────────

    function prove_addOwner_rejects_non_entrypoint(address caller, bytes calldata newOwner) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        vm.assume(newOwner.length == 64);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(caller);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(false, "gate: non-EntryPoint addOwnerBytes accepted");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "gate add: nextOwnerIndex moved");
        }
    }
}
