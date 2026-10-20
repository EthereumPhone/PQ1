// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";

/// @notice **Owner-table (PQMultiOwnable) bytecode discharge** — replaces
///         the stale Certora artifacts for bridge axiom A3.4
///         (`solidityMultiOwnable_compiles_correctly`) and supplies the
///         bytecode-level witnesses for the Claim-2 owner-set-integrity
///         theorems (`cannot_remove_bootstrap`, owner-install verbatim,
///         `initialize_called_exactly_once`).
///
///         Discharge map:
///           * **A3.4 (read parity)** — every rule below asserts
///             `ownerAtIndex(i)` returns byte-for-byte what the Lean
///             `Storage.ownerAtIndex` holds after the mirrored mutation
///             (verbatim-install / verbatim-survive), with the mutation
///             performed by the REAL deployed mutator bytecode.
///           * **Mutator pointwise equality** — `addOwnerBytes` and
///             `initialize` against the Lean `Storage.addOwner` /
///             `Storage.tryInitialize` (Wallet/Storage.lean), composed with
///             the deployed gates: EntryPoint caller, 64-byte length, N-mask
///             layout, duplicate rejection. (The Lean `Storage.addOwner`
///             core models only the duplicate gate; this harness checks the
///             COMPOSITION, which is what the deployed selector dispatches.)
///           * **No removal** — owner removal was deleted before launch
///             (GitHub #131, #213): the Lean model has no removal operation,
///             and `check_removed_selector_does_not_dispatch` proves the
///             former `removeOwnerAtIndex` selector reaches no code on the
///             bytecode, for every caller and argument. Together with the
///             add-rule frame (owner 0 unchanged on both arms) this is the
///             bytecode side of `cannot_remove_bootstrap`.
///
///         SYMBOLIC ENVELOPE: owner CONTENT fully symbolic at every length
///         class {0, 32, 63, 64, 65}; callers fully symbolic in the
///         access-gate rules; counters untouched (asserted in the frames).
///
///         Run: `make -C contracts/verification verify-bytecode`.
contract HalmosMultiOwnable is HalmosWalletBase {
    /// ERC-7201 base of `PQMultiOwnableStorage`; field +1 is the reserved,
    /// always-zero former `removedOwnersCount`.
    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    /// `bytes4(keccak256("removeOwnerAtIndex(uint256,bytes)"))`, the
    /// selector of the deleted removal function.
    bytes4 internal constant REMOVED_REMOVE_OWNER_SELECTOR = 0x89625b57;

    function setUp() public {
        wallet = _deployWalletSha256Free();
        // Owners installed: index 0 = MASTER (bootstrap), index 1 = SLOT0.
        // nextOwnerIndex = 2; indices >= 2 unset.
    }

    function _ownerSweep(uint256 lenSel, string memory tag) internal view returns (bytes memory) {
        vm.assume(lenSel < 5);
        if (lenSel == 0) return new bytes(0);
        if (lenSel == 1) return svm.createBytes(32, string.concat(tag, "32"));
        if (lenSel == 2) return svm.createBytes(63, string.concat(tag, "63"));
        if (lenSel == 3) return svm.createBytes(64, string.concat(tag, "64"));
        return svm.createBytes(65, string.concat(tag, "65"));
    }

    /// Lean `OwnerBytes.hasNMaskLayout` (Storage.lean:35-38) /
    /// `Factory.nMasked`: bytes [16..32) and [48..64) zero — i.e. the
    /// bottom 128 bits of both words.
    function _nMasked64(bytes memory o) internal pure returns (bool) {
        bytes32 seed;
        bytes32 root;
        assembly ("memory-safe") {
            seed := mload(add(o, 32))
            root := mload(add(o, 64))
        }
        return uint128(uint256(seed)) == 0 && uint128(uint256(root)) == 0;
    }

    /// The reserved storage word (former `removedOwnersCount`); nothing in
    /// the deployed bytecode may write it.
    function _reservedWord(PQSmartWallet w) internal view returns (bytes32) {
        return vm.load(address(w), bytes32(uint256(PQ_SLOT_BASE) + 1));
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 1 — addOwnerBytes pointwise vs the Lean model.
    // ──────────────────────────────────────────────────────────────────

    /// **`addOwnerBytes` ≡ length + N-mask gates ∘ Storage.addOwner**
    /// (caller = EP arm; the caller gate is Rule 4). Lean clauses inline.
    function check_addOwnerBytes_pointwise_equals_lean_model(uint256 lenSel) public {
        bytes memory newOwner = _ownerSweep(lenSel, "ao");

        // Deployed boundary gates composed with Lean `Storage.addOwner`:
        //   if newOwner.size ≠ 64 → none
        //   if ¬nMaskedB o → none
        //   Storage.addOwner: if s.isOwner o → none, else install at
        //   nextOwnerIndex, bump nextOwnerIndex.
        bool wantSuccess = newOwner.length == 64 && _nMasked64(newOwner)
            && !wallet.isOwnerBytes(newOwner);

        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preReserved = _reservedWord(wallet);
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));
        uint256 preBoot = wallet.bootstrapUses();

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.addOwnerBytes(newOwner) {
            assertTrue(wantSuccess, "A3.4 add: bytecode accepted what the Lean model rejects");
            // Lean post-state: installed verbatim at the pre nextOwnerIndex.
            assertEq(
                keccak256(wallet.ownerAtIndex(preNext)),
                keccak256(newOwner),
                "A3.4 add: owner bytes not installed verbatim (read parity)"
            );
            assertEq(wallet.nextOwnerIndex(), preNext + 1, "A3.4 add: nextOwnerIndex");
            assertTrue(wallet.isOwnerBytes(newOwner), "A3.4 add: isOwner not set");
        } catch {
            assertTrue(!wantSuccess, "A3.4 add: bytecode rejected what the Lean model accepts");
            assertEq(wallet.nextOwnerIndex(), preNext, "add fail-path: nextOwnerIndex moved");
        }
        // Frame (both arms): existing owners, reserved word, counters.
        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "add frame: owner 0");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "add frame: owner 1");
        assertEq(_reservedWord(wallet), preReserved, "add frame: reserved word written");
        assertEq(wallet.bootstrapUses(), preBoot, "add frame: bootstrapUses");
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 2 — the deleted removal function does not dispatch.
    // ──────────────────────────────────────────────────────────────────

    /// **The former `removeOwnerAtIndex(uint256,bytes)` selector reaches no
    /// code**, for EVERY caller (including the EntryPoint), EVERY index and
    /// every owner-bytes argument: the call reverts and the owner table,
    /// the reserved word and `nextOwnerIndex` are unchanged. Lean has no
    /// removal operation, so this is the whole of the removal side of
    /// `cannot_remove_bootstrap` on the bytecode.
    function check_removed_selector_does_not_dispatch(address caller, uint256 index, uint256 lenSel) public {
        bytes memory arg = _ownerSweep(lenSel, "rm");
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));
        uint256 preNext = wallet.nextOwnerIndex();
        bytes32 preReserved = _reservedWord(wallet);

        vm.prank(caller);
        (bool ok,) = address(wallet).call(abi.encodeWithSelector(REMOVED_REMOVE_OWNER_SELECTOR, index, arg));
        assertTrue(!ok, "removal selector dispatched");

        assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "rm: owner 0 changed");
        assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "rm: owner 1 changed");
        assertEq(wallet.nextOwnerIndex(), preNext, "rm: nextOwnerIndex changed");
        assertEq(_reservedWord(wallet), preReserved, "rm: reserved word written");
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 3 — initialize: one-shot + gated verbatim install.
    // ──────────────────────────────────────────────────────────────────

    /// **`initialize` on an initialised wallet reverts for ALL arguments**
    /// — Lean `Storage.tryInitialize`'s `if s.nextOwnerIndex ≠ 0 then none`
    /// arm / `Invariants.initialize_called_exactly_once` on the bytecode.
    function check_initialize_one_shot(uint256 lenSelA, uint256 lenSelB) public {
        bytes32 preOwner0 = keccak256(wallet.ownerAtIndex(0));
        try wallet.initialize(_ownerSweep(lenSelA, "i0"), _ownerSweep(lenSelB, "i1")) {
            assertTrue(false, "Claim 2: re-initialize accepted");
        } catch {
            assertEq(keccak256(wallet.ownerAtIndex(0)), preOwner0, "re-init: owner 0 mutated");
            assertEq(wallet.nextOwnerIndex(), 2, "re-init: nextOwnerIndex moved");
        }
    }

    /// **Fresh-proxy `initialize` ≡ gated Storage.tryInitialize** over
    /// fully symbolic 64-byte owner contents: succeeds iff both owners are
    /// N-masked and distinct (the `_initializeOwners` →
    /// `_addOwnerAtIndex` gates; Lean `tryInitialize` refuses
    /// `bootstrap = slot0`), installing verbatim at indices 0 and 1.
    function check_initialize_fresh_pointwise() public {
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWallet fresh = PQSmartWallet(payable(LibClone.deployERC1967(address(impl))));

        bytes memory boot = svm.createBytes(64, "fiBoot");
        bytes memory slot0 = svm.createBytes(64, "fiSlot0");

        // Lean: tryInitialize (nextOwnerIndex = 0 ✓ fresh) + the install
        // gates: nMasked(boot) ∧ nMasked(slot0) ∧ slot0 ≠ boot.
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

    // ──────────────────────────────────────────────────────────────────
    // Rule 4 — access gate: EntryPoint-only, for EVERY caller.
    // ──────────────────────────────────────────────────────────────────

    function check_owner_mutators_reject_non_entrypoint(address caller) public {
        vm.assume(caller != ENTRY_POINT_ADDR);
        uint256 preNext = wallet.nextOwnerIndex();
        vm.prank(caller);
        try wallet.addOwnerBytes(_ownerSweep(3, "ne")) {
            assertTrue(false, "gate: non-EntryPoint addOwnerBytes accepted");
        } catch {
            assertEq(wallet.nextOwnerIndex(), preNext, "gate: nextOwnerIndex moved");
        }
    }
}
