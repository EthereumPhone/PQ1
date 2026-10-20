// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PqsignerProto} from "../../src/generated/PqsignerProto.sol";
import {LeanValidateUserOpModel} from "./LeanValidateUserOpModel.sol";
import {OracleSPHINCSVerifier, RevertingSPHINCSVerifier} from "./OracleSPHINCSVerifier.sol";

/// @notice **Pointwise equivalence of the deployed `PQSmartWallet.validateUserOp`
///         bytecode against the Lean model** — the direct bytecode-level
///         discharge of bridge axiom A3.2 (`solidityWallet_compiles_correctly`),
///         at the equality the axiom actually states (result AND post-state),
///         not merely selected corollaries of it.
///
///         Statement proven, per passing rule (modulo the Halmos+solver TCB):
///
///           ∀ op in the symbolic envelope below, ∀ counter values
///           satisfying the kernel-proven reachable-state invariant,
///           ∀ 64-byte owner contents, ∀ verifier answer functions:
///             wallet.validateUserOp(op) ==
///               LeanValidateUserOpModel.predict(op)     (result), and
///             post-storage == the Lean `bumpForOwner` post-state
///               (bumped field at the decoded index; every probed
///                field/index elsewhere unchanged — the frame).
///
///         SYMBOLIC ENVELOPE (each item universally quantified):
///           * signature: 4128-byte wrappers with bytes [32..4128) (offset
///             word, innerLen word, 4008 sig bytes, 24 pad bytes) fully
///             symbolic in every rule; plus a second rule sweeping wrong
///             total lengths {0,95,96,4127,4129,8192};
///           * the wrapper ownerIndex word [0..32): six CONCRETE class
///             representatives (`_sweepOwnerIndexWord`). This is a genuine
///             engine ceiling, not a modelling choice: `validateUserOp`
///             reads `ownerAtIndex(ownerIndex)`, a `mapping(uint => bytes)`
///             getter, whose DYNAMIC-length return Halmos cannot allocate
///             for a symbolic key (`NotConcreteError`) — so the index must
///             be concrete in any rule that reaches the owner read. The six
///             reps cover every qualitatively distinct treatment (bootstrap
///             idx 0; both installed slots 1, 2; first-unset 3; a deep
///             unset 2^200; the H-3 sentinel uint256.max). Per-index
///             behaviour downstream of the read depends only on
///             `(ownerAtIndex(i), counters at i)`, both symbolic here.
///             NOTE: the EXECUTE path (`HalmosExecuteEquiv`) achieves a
///             genuinely SYMBOLIC ownerIndex, because it reads only
///             word-typed counters/credit, not the bytes getter — so the
///             money-moving surface is ∀-index, and only this
///             validation-read surface carries the concrete-rep residual.
///           * callData: symbolic content at lengths {0,3,4,35,36,68}
///             (covering: no selector; selector w/o H-3 word — incl. both
///             boundary lengths 35/36; full execute-shaped calldata);
///           * initCode / paymasterAndData: symbolic content at lengths
///             {0,32} each (empty exercises the sha256("") path);
///           * sender, nonce, all 5 gas fields, userOpHash,
///             missingAccountFunds: fully symbolic;
///           * storage: bootstrapUses fully symbolic; slotUses[i] /
///             offchainSigCount[i] symbolic at the installed slot indices
///             under `slotUses[i] + offchainSigCount[i] <= MAX_SLOT_USES`
///             (the Lean `combinedCap_inductive` reachable-state invariant —
///             outside it the bytecode reverts on checked-add overflow where
///             the Nat model returns failure: a documented divergence on
///             unreachable states); owner bytes at indices 0/1/2 fully
///             symbolic 64-byte values; indices >= 3 unset. Owner-SET SHAPE
///             (which indices are installed) is concrete; per-index
///             behaviour depends only on (ownerAtIndex(i), counters at i),
///             both of which are symbolic.
///
///         NOT covered (stated honestly): ETH-balance effects of the
///         `missingAccountFunds` prefund transfer (outside the Lean model's
///         `Result × Storage` codomain; EntryPoint accounting is axiom A2);
///         storage states unreachable per the Lean invariants (counter sums
///         above the cap, owner entries of length != 64); the verifier's own
///         function (axiom A3.1 — here it is universally quantified instead,
///         which is strictly more general).
///
///         The verifier is `OracleSPHINCSVerifier`: an UNINTERPRETED
///         function of the full argument tuple. Any path where the wallet
///         hands the verifier different bytes than the model (digest
///         preimage, inner-sig slice) yields distinguishable answers and a
///         counterexample — so a pass also certifies the exact verifier
///         call arguments, byte-for-byte.
///
///         Run: `make -C contracts/verification verify-bytecode`.
contract HalmosValidateUserOpEquiv is SymTest, Test {
    address internal constant ENTRY_POINT_ADDR = address(0x4337);

    /// ERC-7201 base slot for PQMultiOwnableStorage — parity-tested against
    /// the live getters in `_storeSymbolicCounters` (a wrong constant makes
    /// the parity asserts fail with a counterexample, so the stores are
    /// self-certifying). Field offsets per the struct declaration order in
    /// PQMultiOwnable.sol: +0 nextOwnerIndex, +1 removedOwnersCount (reserved,
    /// always zero), +2 ownerAtIndex, +3 isOwner, +4 bootstrapUses,
    /// +5 slotUses, +6 offchainSigCount.
    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    uint256 internal constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;

    PQSmartWallet internal wallet;
    PQSmartWallet internal walletRevertingVerifier;
    OracleSPHINCSVerifier internal oracle;
    LeanValidateUserOpModel internal model;

    function setUp() public {
        oracle = new OracleSPHINCSVerifier();
        wallet = _deployWallet(address(oracle));
        model = new LeanValidateUserOpModel(ENTRY_POINT_ADDR, oracle);

        RevertingSPHINCSVerifier reverting = new RevertingSPHINCSVerifier();
        walletRevertingVerifier = _deployWallet(address(reverting));

        // Lean `Selector.*` literal parity (mirrors LeanSelectorParity.t.sol):
        // the model's hardcoded selectors must be the live ABI's.
        assertEq(model.SEL_ADD_OWNER_BYTES(), wallet.addOwnerBytes.selector);
        assertEq(model.SEL_EXECUTE_WITH_OFFCHAIN_COUNT(), wallet.executeWithOffchainCount.selector);
        assertEq(
            model.SEL_EXECUTE_BATCH_WITH_OFFCHAIN_COUNT(),
            wallet.executeBatchWithOffchainCount.selector
        );
    }

    /// @dev Owner-set bring-up, sha256-free (bare ERC-1967 proxy +
    ///      `initialize`, byte-identical storage to the factory path):
    ///      bootstrap at index 0, slots at indices 1 and 2, every owner's
    ///      64 bytes fully symbolic. Index >= 3 unset.
    function _deployWallet(address verifier) internal returns (PQSmartWallet w) {
        PQSmartWallet impl =
            new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), OracleSPHINCSVerifier(verifier));
        address proxy = LibClone.deployERC1967(address(impl));
        w = PQSmartWallet(payable(proxy));
        w.initialize(svm.createBytes(64, "owner0"), svm.createBytes(64, "owner1"));
        vm.prank(ENTRY_POINT_ADDR);
        w.addOwnerBytes(svm.createBytes(64, "owner2"));
    }

    /// @dev Make the few-time counters symbolic by direct slot writes,
    ///      self-certified by getter parity asserts, constrained to the
    ///      kernel-proven reachable-state invariant
    ///      (`Wallet/Invariants.lean::combinedCap_inductive`):
    ///      slotUses[i] + offchainSigCount[i] <= MAX_SLOT_USES.
    function _storeSymbolicCounters(PQSmartWallet w) internal {
        uint256 base = uint256(PQ_SLOT_BASE);

        uint256 boot = svm.createUint256("bootstrapUses");
        vm.store(address(w), bytes32(base + 4), bytes32(boot));
        assertEq(w.bootstrapUses(), boot, "slot parity: bootstrapUses");

        for (uint256 i = 1; i <= 2; i++) {
            uint256 s = svm.createUint256(i == 1 ? "slotUses1" : "slotUses2");
            uint256 o = svm.createUint256(i == 1 ? "offchain1" : "offchain2");
            vm.assume(s <= MAX_SLOT_USES);
            vm.assume(o <= MAX_SLOT_USES - s); // combined invariant, overflow-free
            vm.store(address(w), keccak256(abi.encode(i, base + 5)), bytes32(s));
            vm.store(address(w), keccak256(abi.encode(i, base + 6)), bytes32(o));
            assertEq(w.slotUses(i), s, "slot parity: slotUses[i]");
            assertEq(w.offchainSigCount(i), o, "slot parity: offchainSigCount[i]");
        }
    }

    /// @dev Symbolic callData over the length sweep. The lengths cover every
    ///      qualitatively distinct class the wallet/model read: {0,3} no
    ///      selector; {4,35} selector but no H-3 word (35 = last sub-36
    ///      boundary); {36} selector + H-3 word boundary; {68} full
    ///      execute-shaped head. Content is symbolic at every length.
    function _sweepCallData(uint256 lenSel) internal view returns (bytes memory) {
        vm.assume(lenSel < 6);
        if (lenSel == 0) return new bytes(0);
        if (lenSel == 1) return svm.createBytes(3, "cd3");
        if (lenSel == 2) return svm.createBytes(4, "cd4");
        if (lenSel == 3) return svm.createBytes(35, "cd35");
        if (lenSel == 4) return svm.createBytes(36, "cd36");
        return svm.createBytes(68, "cd68");
    }

    function _symUserOp(bytes memory callData, bytes memory initCode, bytes memory pm)
        internal
        view
        returns (UserOperation06 memory op)
    {
        op.sender = svm.createAddress("sender");
        op.nonce = svm.createUint256("nonce");
        op.initCode = initCode;
        op.callData = callData;
        op.callGasLimit = svm.createUint256("callGasLimit");
        op.verificationGasLimit = svm.createUint256("verificationGasLimit");
        op.preVerificationGas = svm.createUint256("preVerificationGas");
        op.maxFeePerGas = svm.createUint256("maxFeePerGas");
        op.maxPriorityFeePerGas = svm.createUint256("maxPriorityFeePerGas");
        op.paymasterAndData = pm;
        op.signature = ""; // set by caller
    }

    /// @dev The wrapper's ownerIndex word, materialised CONCRETE per path.
    ///      The class representatives cover every qualitatively distinct
    ///      treatment: the bootstrap index, both installed slot indices, the
    ///      first unset index, a deep unset index, and the H-3 sentinel
    ///      value. All remaining 4096 wrapper bytes (offset word, innerLen
    ///      word, 4008 sig bytes, 24 pad bytes) stay fully symbolic.
    ///      Note {0, 1, 2} is the ENTIRE installed set of this owner-set
    ///      shape — for those indices concrete enumeration IS exhaustive
    ///      coverage, not sampling. The unset reps {3, 2^200, max} cover
    ///      the unset partition (>= 3), on which the wallet's behaviour is
    ///      uniform (owner length 0 != 64 => fail): the boundary, a deep
    ///      value, and the H-3 sentinel. A symbolic sweep of the unset
    ///      partition is NOT possible (the `ownerAtIndex` dynamic-bytes
    ///      getter `NotConcreteError`s on a symbolic non-installed key — a
    ///      disclosed Halmos engine ceiling); see the NOTE above rule 1c.
    ///      Rule 1c does sweep a symbolic index over the INSTALLED slots.
    function _sweepOwnerIndexWord(uint256 idxSel) internal pure returns (bytes32) {
        vm.assume(idxSel < 6);
        if (idxSel == 0) return bytes32(uint256(0));
        if (idxSel == 1) return bytes32(uint256(1));
        if (idxSel == 2) return bytes32(uint256(2));
        if (idxSel == 3) return bytes32(uint256(3));
        if (idxSel == 4) return bytes32(uint256(1) << 200);
        return bytes32(type(uint256).max);
    }

    /// @dev 4128-byte wrapper: concrete ownerIndex word per `idxSel` class,
    ///      everything after byte 32 symbolic.
    function _sweepSig(uint256 idxSel, string memory tailName) internal view returns (bytes memory) {
        return abi.encodePacked(_sweepOwnerIndexWord(idxSel), svm.createBytes(4096, tailName));
    }

    /// @dev 4128-byte wrapper with a caller-supplied (symbolic) ownerIndex
    ///      word; everything after byte 32 symbolic.
    function _sigWithIndexWord(uint256 idxWord, string memory tailName)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(bytes32(idxWord), svm.createBytes(4096, tailName));
    }

    /// @dev Shared body: run model + bytecode on the same op, assert the
    ///      A3.2 equality (result + bumped field) and the frame (probed
    ///      index/fields elsewhere unchanged). Counter frames use a fully
    ///      symbolic probe index (word-typed reads); the owner-set frame
    ///      probes the four concrete index classes (bytes-typed reads need
    ///      concrete lengths under Halmos).
    function _assertEquiv(UserOperation06 memory op, uint256 probeIndex) internal {
        // Pre-state probes for the frame half of the equality.
        uint256 preBoot = wallet.bootstrapUses();
        uint256 preSlotP = wallet.slotUses(probeIndex);
        uint256 preOffP = wallet.offchainSigCount(probeIndex);
        bytes32[4] memory preOwners;
        for (uint256 k = 0; k < 4; k++) {
            preOwners[k] = keccak256(wallet.ownerAtIndex(k));
        }
        uint256 preNext = wallet.nextOwnerIndex();

        LeanValidateUserOpModel.Prediction memory want = model.predict(wallet, op);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 got =
            wallet.validateUserOp(op, svm.createBytes32("userOpHash"), svm.createUint256("missingFunds"));

        assertEq(got, want.result, "A3.2: result != Lean model");

        if (want.result == 0) {
            if (want.ownerIndex == 0) {
                assertEq(
                    wallet.bootstrapUses(),
                    want.postBootstrapUses,
                    "A3.2: bootstrapUses != Lean bumpBootstrap"
                );
                assertEq(wallet.slotUses(probeIndex), preSlotP, "frame: slotUses");
            } else {
                assertEq(
                    wallet.slotUses(want.ownerIndex),
                    want.postSlotUsesAtOwnerIndex,
                    "A3.2: slotUses != Lean bumpSlot"
                );
                assertEq(wallet.bootstrapUses(), preBoot, "frame: bootstrapUses");
                if (probeIndex != want.ownerIndex) {
                    assertEq(wallet.slotUses(probeIndex), preSlotP, "frame: slotUses other");
                }
            }
            assertEq(wallet.offchainSigCount(probeIndex), preOffP, "frame: offchainSigCount");
        } else {
            // Lean failure: (Result.failure, s) — state unchanged.
            assertEq(wallet.bootstrapUses(), preBoot, "A3.2 fail-path: bootstrapUses moved");
            assertEq(wallet.slotUses(probeIndex), preSlotP, "A3.2 fail-path: slotUses moved");
            assertEq(wallet.offchainSigCount(probeIndex), preOffP, "A3.2 fail-path: offchain moved");
        }
        // Validation never touches the owner set, in success or failure.
        for (uint256 k = 0; k < 4; k++) {
            assertEq(keccak256(wallet.ownerAtIndex(k)), preOwners[k], "frame: ownerAtIndex");
        }
        assertEq(wallet.nextOwnerIndex(), preNext, "frame: nextOwnerIndex");
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 1 — the main pointwise equality: every byte of the 4128-byte
    // wrapper symbolic, callData/initCode/paymasterAndData swept over the
    // length classes with symbolic content, all scalar fields symbolic,
    // counters symbolic under the reachable-state invariant.
    // ──────────────────────────────────────────────────────────────────
    function check_validateUserOp_pointwise_equals_lean_model(
        uint256 idxSel,
        uint256 lenSel,
        bool initCodeEmpty,
        bool paymasterEmpty,
        uint256 probeIndex
    ) public {
        _storeSymbolicCounters(wallet);

        bytes memory callData = _sweepCallData(lenSel);
        bytes memory initCode = initCodeEmpty ? new bytes(0) : svm.createBytes(32, "initCode");
        bytes memory pm = paymasterEmpty ? new bytes(0) : svm.createBytes(32, "paymasterAndData");

        UserOperation06 memory op = _symUserOp(callData, initCode, pm);
        op.signature = _sweepSig(idxSel, "wrappedSigTail");

        _assertEquiv(op, probeIndex);
    }

    // ──────────────────────────────────────────────────────────────────
    // NOTE — the UNSET partition (ownerIndex >= 3) is NOT swept
    // symbolically. An attempt (`check_validateUserOp_pointwise_unset_indices`,
    // a symbolic idxWord >= 3) ERRORS under Halmos with the
    // dynamic-bytes-getter `NotConcreteError`: `validateUserOp` reads
    // `ownerAtIndex(ownerIndex)`, a `mapping(uint => bytes)` getter, and
    // for a symbolic key that is NOT statically one of the installed
    // {0,1,2} Halmos cannot resolve the returned bytes' LENGTH (the
    // mapping's default-empty branch is not concretely decidable for a
    // symbolic key), so it cannot allocate the return buffer. This is a
    // hard, disclosed engine ceiling — NOT closed by partitioning. The
    // unset partition is instead covered by the CONCRETE representatives
    // {3, 2^200, uint256.max} in rule 1 (`_sweepOwnerIndexWord` idxSel
    // 3/4/5): the wallet's behaviour on every unset index is uniform
    // (owner length 0 != 64 => SIG_VALIDATION_FAILED, state unchanged),
    // so the reps exercise the boundary (first unset), a deep value, and
    // the H-3 sentinel. Rule 1c below DOES sweep a symbolic index over
    // the INSTALLED partition {1,2} (where the getter length is a
    // concrete 64), a genuine — if modest — strengthening over the two
    // concrete instantiations.
    // ──────────────────────────────────────────────────────────────────

    // ──────────────────────────────────────────────────────────────────
    // Rule 1c — ∀-SYMBOLIC ownerIndex over the INSTALLED slot partition
    // {1, 2}: the full pointwise equality (success arms included) with
    // the index a symbolic word constrained to the partition rather
    // than a concrete singleton. Both installed owners store 64-byte
    // values, so the symbolic-key getter's length resolves uniformly
    // across the partition and the dynamic allocation stays concrete.
    // ──────────────────────────────────────────────────────────────────
    function check_validateUserOp_pointwise_installed_indices(
        uint256 idxWord,
        uint256 lenSel,
        bool initCodeEmpty,
        bool paymasterEmpty,
        uint256 probeIndex
    ) public {
        vm.assume(idxWord == 1 || idxWord == 2);
        _storeSymbolicCounters(wallet);

        bytes memory callData = _sweepCallData(lenSel);
        bytes memory initCode =
            initCodeEmpty ? new bytes(0) : svm.createBytes(32, "initCodeIns");
        bytes memory pm =
            paymasterEmpty ? new bytes(0) : svm.createBytes(32, "pmIns");

        UserOperation06 memory op = _symUserOp(callData, initCode, pm);
        op.signature = _sigWithIndexWord(idxWord, "wrappedSigInsTail");

        _assertEquiv(op, probeIndex);
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 2 — wrong wrapper total lengths: both sides must fail with no
    // state change. Sweep covers empty, the 96-byte head boundary, and
    // off-by-one around 4128.
    // ──────────────────────────────────────────────────────────────────
    function check_validateUserOp_equiv_wrong_sig_lengths(uint256 lenSel, uint256 probeIndex)
        public
    {
        _storeSymbolicCounters(wallet);

        vm.assume(lenSel < 6);
        bytes memory sig;
        if (lenSel == 0) sig = new bytes(0);
        else if (lenSel == 1) sig = svm.createBytes(95, "sig95");
        else if (lenSel == 2) sig = svm.createBytes(96, "sig96");
        else if (lenSel == 3) sig = svm.createBytes(4127, "sig4127");
        else if (lenSel == 4) sig = svm.createBytes(4129, "sig4129");
        else sig = svm.createBytes(8192, "sig8192");

        UserOperation06 memory op =
            _symUserOp(svm.createBytes(68, "cdWL"), new bytes(0), new bytes(0));
        op.signature = sig;

        _assertEquiv(op, probeIndex);
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 3 — reverting verifier: the wallet's try/catch arm. The Lean
    // model is total in `verify_fn`; the deployed bytecode maps a
    // reverting verifier to the `verify_fn ≡ false` interpretation:
    // failure, state unchanged. Proven here on the bytecode for a fully
    // symbolic 4128-byte wrapper.
    // ──────────────────────────────────────────────────────────────────
    function check_validateUserOp_reverting_verifier_is_false_interp(
        uint256 idxSel,
        uint256 probeIndex
    ) public {
        PQSmartWallet w = walletRevertingVerifier;
        _storeSymbolicCounters(w);

        uint256 preBoot = w.bootstrapUses();
        uint256 preSlotP = w.slotUses(probeIndex);
        uint256 preOffP = w.offchainSigCount(probeIndex);

        UserOperation06 memory op =
            _symUserOp(svm.createBytes(68, "cdRV"), new bytes(0), new bytes(0));
        op.signature = _sweepSig(idxSel, "wrappedSigRVTail");

        vm.prank(ENTRY_POINT_ADDR);
        uint256 got =
            w.validateUserOp(op, svm.createBytes32("uoHashRV"), svm.createUint256("fundsRV"));

        assertEq(got, 1, "reverting verifier must map to failure");
        assertEq(w.bootstrapUses(), preBoot, "reverting verifier: bootstrapUses moved");
        assertEq(w.slotUses(probeIndex), preSlotP, "reverting verifier: slotUses moved");
        assertEq(w.offchainSigCount(probeIndex), preOffP, "reverting verifier: offchain moved");
    }
}
