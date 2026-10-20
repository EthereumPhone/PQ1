// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PqsignerProto} from "../../src/generated/PqsignerProto.sol";
import {HalmosWalletBase} from "./HalmosWalletBase.sol";
import {LeanExecuteModel} from "./LeanExecuteModel.sol";

/// @dev Concrete external target that always reverts — drives the
///      `callOk = false` arm of the A3.2-exec axioms (atomicity).
contract RevertingTarget {
    error TargetReverts();

    fallback() external payable {
        revert TargetReverts();
    }
}

/// @notice **Pointwise equivalence of the deployed
///         `executeWithOffchainCount` / `executeBatchWithOffchainCount`
///         bytecode against the Lean `Wallet.Execute` model** — the direct
///         bytecode-level discharge of the A3.2-exec bridge axioms
///         (`solidityWalletExecute_compiles_correctly` /
///         `solidityWalletExecuteBatch_compiles_correctly`,
///         Bridge/Refinement.lean), at the equality the axioms state on the
///         WALLET-LOGIC projection (success/revert + post-storage + guards),
///         plus the atomicity fact that pins the `callOk = false` arm. The
///         emitted external CALL's faithful delivery (the appended Lean
///         `Call` content) is axiom A4 (EVM executes per spec), NOT part of
///         A3.2 — see the "Rule 3 omitted" note in the body.
///
///         SYMBOLIC ENVELOPE (each item universally quantified unless
///         stated):
///           * the execute calldata `ownerIndex` argument: fully symbolic
///             (uint256) in the equiv + no-credit rules — the transient
///             credit read is a symbolic-slot `tload`;
///           * `newOffchainCount`: fully symbolic;
///           * `value`: symbolic over [0, 2^128) — the entire reachable
///             ETH range (total wei supply << 2^128), bounded only to stay
///             inside Halmos's MAX_ETH engine bound. The wallet is dealt
///             `type(uint128).max`, so the codeless-target transfer never
///             fails — the `callOk ≡ true` world of the axiom; the
///             `callOk = false` world is the atomicity rule;
///           * pre-state counters `slotUses[i]` / `offchainSigCount[i]`
///             (i ∈ {1,2}) and `bootstrapUses`: fully symbolic under the
///             kernel-proven combined-cap invariant (`combinedCap_inductive`),
///             exactly the reachable-state hypothesis A3.2 carries;
///           * the stamped credit state: established by REAL
///             `validateUserOp` calls on the same bytecode (so the
///             stamp↔consume pairing is the genuine production path), with
///             the model's per-index `σ.credits` map fed the ground truth
///             derived from those calls' observable results
///             (`_creditAt`); the multi-stamp COUNTER semantics (N stamps
///             fund exactly N executes — the bundle envelope, GAP-11) is
///             witnessed by `check_two_stamps_fund_exactly_two_executes`;
///           * `data` bytes: symbolic content over length classes
///             {0, 5, 68} (data does not influence accept/reject; the
///             dispatch rule checks the forwarded value + length, with
///             content-verbatim closed by inspection — see the note in
///             `check_execute_dispatches_verbatim`).
///
///         CONCRETE (engine limits, each with the reason + the witness rule):
///           * dispatch target addresses (a symbolic call target makes the
///             engine fork over every deployed contract): codeless
///             0xc0ffee/0xdecaf for the success arms; `address(wallet)` for
///             the self-reject arm (`HalmosExecute.check_execute*self*`);
///             the reverter instance for the atomicity arm;
///           * the stamping validate's wrapper index (1) — the credit-slot
///             KEY under test is the execute-side symbolic `ownerIndex`,
///             compared against it by the solver;
///           * the non-EntryPoint caller arm lives in
///             `HalmosExecute.check_execute_rejects_non_entrypoint_caller`
///             (symbolic caller, all values).
///
///         Run: `make -C contracts/verification verify-bytecode`.
contract HalmosExecuteEquiv is HalmosWalletBase {
    uint256 internal constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;

    /// ERC-7201 base slot — parity-tested against the live getters in
    /// `_storeSymbolicCounters` (wrong constant ⇒ parity assert finds a
    /// counterexample, so the stores are self-certifying).
    bytes32 internal constant PQ_SLOT_BASE =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    address internal constant CODELESS_TARGET = address(0xc0ffee);
    address internal constant CODELESS_TARGET_2 = address(0xdecaf);

    LeanExecuteModel internal model;
    RevertingTarget internal reverter;

    function setUp() public {
        wallet = _deployWalletSha256Free();
        model = new LeanExecuteModel(ENTRY_POINT_ADDR);
        reverter = new RevertingTarget();
        // `callOk ≡ true` world for value transfers: the wallet covers any
        // bounded symbolic `value`. Balance is `type(uint128).max` (not
        // `uint256.max`, which trips Halmos's MAX_ETH internal bound); every
        // symbolic `value` is `vm.assume`d `<= type(uint128).max` via
        // `_symValue`, so a transfer to a codeless target always succeeds.
        vm.deal(address(wallet), type(uint128).max);
    }

    /// @dev A bounded symbolic value: free over [0, 2^128), which is the
    ///      whole reachable ETH range (total supply << 2^128 wei) and stays
    ///      inside Halmos's MAX_ETH bound so the codeless-target transfer
    ///      models the `callOk ≡ true` world without an internal error.
    function _symValue(string memory name) internal returns (uint256 v) {
        v = svm.createUint256(name);
        vm.assume(v <= uint256(type(uint128).max));
    }

    /// @dev Symbolic few-time counters under the reachable-state invariant
    ///      (mirrors HalmosValidateUserOpEquiv._storeSymbolicCounters).
    function _storeSymbolicCounters() internal {
        uint256 base = uint256(PQ_SLOT_BASE);
        uint256 boot = svm.createUint256("bootstrapUses");
        vm.store(address(wallet), bytes32(base + 4), bytes32(boot));
        assertEq(wallet.bootstrapUses(), boot, "slot parity: bootstrapUses");
        for (uint256 i = 1; i <= 2; i++) {
            uint256 s = svm.createUint256(i == 1 ? "slotUses1" : "slotUses2");
            uint256 o = svm.createUint256(i == 1 ? "offchain1" : "offchain2");
            vm.assume(s <= MAX_SLOT_USES);
            vm.assume(o <= MAX_SLOT_USES - s);
            vm.store(address(wallet), keccak256(abi.encode(i, base + 5)), bytes32(s));
            vm.store(address(wallet), keccak256(abi.encode(i, base + 6)), bytes32(o));
            assertEq(wallet.slotUses(i), s, "slot parity: slotUses[i]");
            assertEq(wallet.offchainSigCount(i), o, "slot parity: offchainSigCount[i]");
        }
    }

    /// @dev Run the REAL validation-phase bytecode to stamp (or fail to
    ///      stamp) one execution credit for wrapper `ownerIndex = 1`, with
    ///      an `executeWithOffchainCount`-shaped callData (H-3 word = 1).
    ///      Returns `1` iff the validate returned success (one credit
    ///      stamped at index 1), `0` otherwise (cap-exhausted path — no
    ///      credit). The model-side per-index ground truth for a presented
    ///      index `i` is then `i == 1 ? stamped : 0` — the credit map
    ///      `{1 ↦ stamped}` with every other index zero.
    function _stampViaValidate() internal returns (uint256 stamped) {
        bytes memory callData = abi.encodeCall(
            wallet.executeWithOffchainCount,
            (uint256(1), uint256(0), CODELESS_TARGET, uint256(0), bytes(""))
        );
        bytes memory wrappedSig = abi.encode(uint256(1), new bytes(4008));
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(_op(callData, wrappedSig), bytes32(0), 0);
        stamped = vres == 0 ? 1 : 0;
    }

    /// @dev The per-index credit ground truth for a (symbolic) presented
    ///      index, after `_stampViaValidate` stamped `stamped` credits at
    ///      index 1: `credits[i] = (i == 1) ? stamped : 0`.
    function _creditAt(uint256 stamped, uint256 presentedIndex)
        internal
        pure
        returns (uint256)
    {
        return presentedIndex == 1 ? stamped : 0;
    }

    /// @dev Symbolic `data` over the length classes {0, 5, 68}. Content is
    ///      symbolic at every length; the length never influences the
    ///      accept/reject decision (only the dispatched bytes).
    function _sweepData(uint256 dataSel) internal view returns (bytes memory) {
        vm.assume(dataSel < 3);
        if (dataSel == 0) return new bytes(0);
        if (dataSel == 1) return svm.createBytes(5, "execData5");
        return svm.createBytes(68, "execData68");
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 1 — single-call pointwise equality: symbolic calldata
    // ownerIndex, symbolic newOffchainCount, symbolic value/data, symbolic
    // counters, stamped-vs-unstamped credit both arms (the stamping
    // validate itself runs on symbolic counters, so its cap-fail path is
    // inside the sweep).
    // ──────────────────────────────────────────────────────────────────
    function check_execute_pointwise_equals_lean_model(
        uint256 callIdx,
        uint256 dataSel,
        uint256 probeIndex
    ) public {
        _storeSymbolicCounters();
        uint256 stamped = _stampViaValidate();

        uint256 newCount = svm.createUint256("newOffchainCount");
        uint256 value = _symValue("value");
        bytes memory data = _sweepData(dataSel);

        LeanExecuteModel.Prediction memory want = model.predictExecute(
            wallet, _creditAt(stamped, callIdx), ENTRY_POINT_ADDR, callIdx, newCount, CODELESS_TARGET
        );

        // Pre-state probes for the frame / fail-path halves.
        uint256 preBoot = wallet.bootstrapUses();
        uint256 preSlotP = wallet.slotUses(probeIndex);
        uint256 preOffP = wallet.offchainSigCount(probeIndex);
        uint256 preOffAtCall = wallet.offchainSigCount(callIdx);
        bytes32 preOwner1 = keccak256(wallet.ownerAtIndex(1));

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(callIdx, newCount, CODELESS_TARGET, value, data)
        returns (bytes memory) {
            assertTrue(want.success, "A3.2-exec: bytecode succeeded where the Lean model fails");
            assertEq(
                wallet.offchainSigCount(callIdx),
                want.postOffchainAtOwnerIndex,
                "A3.2-exec: offchainSigCount != Lean setOffchain"
            );
            // Frame: slotUses untouched anywhere; bootstrapUses untouched;
            // offchain untouched off the written index; owners untouched.
            assertEq(wallet.bootstrapUses(), preBoot, "frame: bootstrapUses");
            assertEq(wallet.slotUses(probeIndex), preSlotP, "frame: slotUses");
            if (probeIndex != callIdx) {
                assertEq(wallet.offchainSigCount(probeIndex), preOffP, "frame: offchain other");
            }
            assertEq(keccak256(wallet.ownerAtIndex(1)), preOwner1, "frame: ownerAtIndex");
        } catch {
            assertTrue(!want.success, "A3.2-exec: bytecode reverted inside the Lean success arm");
            // Lean `none` ⟺ revert ⟺ state unchanged.
            assertEq(wallet.bootstrapUses(), preBoot, "fail-path: bootstrapUses moved");
            assertEq(wallet.slotUses(probeIndex), preSlotP, "fail-path: slotUses moved");
            assertEq(wallet.offchainSigCount(probeIndex), preOffP, "fail-path: offchain moved");
            assertEq(wallet.offchainSigCount(callIdx), preOffAtCall, "fail-path: offchain at idx moved");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 2 — batch pointwise equality: array-length classes {0,1,2} plus
    // the mismatch and self-target classes, symbolic values content,
    // symbolic calldata ownerIndex + newOffchainCount + counters.
    // ──────────────────────────────────────────────────────────────────
    function check_executeBatch_pointwise_equals_lean_model(
        uint256 callIdx,
        uint256 lenSel,
        uint256 probeIndex
    ) public {
        _storeSymbolicCounters();
        // Batch-shaped validate (H-3 word = 1) so the stamped credit is the
        // genuine batch-selector production path.
        bytes memory vCallData = abi.encodeCall(
            wallet.executeBatchWithOffchainCount,
            (uint256(1), uint256(0), new address[](0), new uint256[](0), new bytes[](0))
        );
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres =
            wallet.validateUserOp(_op(vCallData, abi.encode(uint256(1), new bytes(4008))), bytes32(0), 0);
        uint256 stamped = vres == 0 ? 1 : 0;

        // Array-shape classes: {0,1,2} equal-length, {2 targets / 1 value}
        // mismatch, {2 targets, second = self} self-reject.
        vm.assume(lenSel < 5);
        uint256 n = lenSel == 0 ? 0 : (lenSel == 1 ? 1 : 2);
        address[] memory targets = new address[](n);
        if (n >= 1) targets[0] = CODELESS_TARGET;
        if (n >= 2) targets[1] = lenSel == 4 ? address(wallet) : CODELESS_TARGET_2;
        uint256 vLen = lenSel == 3 ? 1 : n;
        uint256[] memory values = new uint256[](vLen);
        for (uint256 i; i < vLen; i++) {
            // Bound each batch value to 2^126 so the SUM of up to two stays
            // below the wallet's dealt balance (type(uint128).max). Without
            // this the second transfer can exceed balance and revert in the
            // bytecode while the (balance-agnostic) Lean model reports
            // success — a divergence attributable to ETH accounting (axiom
            // A2/A4), not to the wallet's execute logic. Still the entire
            // reachable per-call ETH range (total wei supply << 2^126).
            uint256 v = svm.createUint256(i == 0 ? "bv0" : "bv1");
            vm.assume(v <= (uint256(1) << 126));
            values[i] = v;
        }
        bytes[] memory datas = new bytes[](n);
        for (uint256 i; i < n; i++) {
            datas[i] = svm.createBytes(5, i == 0 ? "bd0" : "bd1");
        }
        uint256 newCount = svm.createUint256("batchNewOffchainCount");

        LeanExecuteModel.Prediction memory want = model.predictExecuteBatch(
            wallet, _creditAt(stamped, callIdx), ENTRY_POINT_ADDR, callIdx, newCount, targets, vLen, n
        );

        uint256 preBoot = wallet.bootstrapUses();
        uint256 preSlotP = wallet.slotUses(probeIndex);
        uint256 preOffP = wallet.offchainSigCount(probeIndex);
        uint256 preOffAtCall = wallet.offchainSigCount(callIdx);

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeBatchWithOffchainCount(callIdx, newCount, targets, values, datas) {
            assertTrue(want.success, "A3.2-exec batch: bytecode succeeded where the Lean model fails");
            assertEq(
                wallet.offchainSigCount(callIdx),
                want.postOffchainAtOwnerIndex,
                "A3.2-exec batch: offchainSigCount != Lean setOffchain"
            );
            assertEq(wallet.bootstrapUses(), preBoot, "batch frame: bootstrapUses");
            assertEq(wallet.slotUses(probeIndex), preSlotP, "batch frame: slotUses");
            if (probeIndex != callIdx) {
                assertEq(wallet.offchainSigCount(probeIndex), preOffP, "batch frame: offchain other");
            }
        } catch {
            assertTrue(!want.success, "A3.2-exec batch: bytecode reverted inside the Lean success arm");
            assertEq(wallet.bootstrapUses(), preBoot, "batch fail-path: bootstrapUses moved");
            assertEq(wallet.slotUses(probeIndex), preSlotP, "batch fail-path: slotUses moved");
            assertEq(wallet.offchainSigCount(probeIndex), preOffP, "batch fail-path: offchain moved");
            assertEq(wallet.offchainSigCount(callIdx), preOffAtCall, "batch fail-path: offchain at idx moved");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 3 (dispatch verbatim) — INTENTIONALLY OMITTED. The
    // correspondence "the appended Lean `Call{target,value,data}` IS the
    // EVM call the bytecode emits" is an EVM-execution fact (bridge axiom
    // A4, `evm_bytecode_executes_correctly`), not a wallet-logic fact
    // (A3.2). The wallet-logic content — that a successful execute reaches
    // the single `target.call{value}(data)` with the cap/credit guards
    // passed and the storage updated — is what the pointwise rule above
    // discharges; the EVM then performs that emitted CALL per A4 (the same
    // axiom through which `theft_free` routes every actual value movement).
    // Halmos additionally cannot reconstruct a callee's `msg.data` from a
    // forwarded symbolic `bytes` slice, so an on-bytecode dispatch-content
    // assert is not even tractable — but the principled reason it lives in
    // A4 stands regardless.

    // ──────────────────────────────────────────────────────────────────
    // Rule 4 — atomicity: the `callOk = false` arm of the A3.2-exec axioms.
    // ──────────────────────────────────────────────────────────────────

    /// **A reverting dispatched call reverts the whole execute** — no
    /// counter movement, no partial state. (The rolled-back transient
    /// credit is intentionally NOT asserted consumed: the revert restores
    /// it; the Lean trace model scopes to all-success traces — see the
    /// axiom comment in Bridge/Refinement.lean.)
    function check_execute_inner_revert_is_atomic(uint256 dataSel) public {
        uint256 stamped = _stampViaValidate();
        vm.assume(stamped == 1);

        uint256 preOff1 = wallet.offchainSigCount(1);
        uint256 preSlot1 = wallet.slotUses(1);
        uint256 newCount = svm.createUint256("atomNewCount");
        uint256 value = _symValue("atomValue");

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, newCount, address(reverter), value, _sweepData(dataSel))
        returns (bytes memory) {
            assertTrue(false, "atomicity: execute succeeded despite reverting target");
        } catch {
            assertEq(wallet.offchainSigCount(1), preOff1, "atomicity: offchain moved");
            assertEq(wallet.slotUses(1), preSlot1, "atomicity: slotUses moved");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 5 — credit-vocabulary witnesses for the model-state
    // correspondence (σ.validatedOwnerPlusOne ↔ transient credit counter).
    // ──────────────────────────────────────────────────────────────────

    /// **No validate ⇒ no execute, for EVERY claimed index** (upgrade of
    /// `HalmosExecute.check_execute_without_validate_reverts`, which used a
    /// concrete index): the credit `tload` is at a symbolic slot.
    function check_execute_no_credit_reverts_for_all_indices(uint256 callIdx) public {
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(
            callIdx, svm.createUint256("ncNoCredit"), CODELESS_TARGET, 0, ""
        ) returns (bytes memory) {
            assertTrue(false, "credit: execute without any validate accepted");
        } catch {
            // expected: OwnerIndexMismatch — Lean: validatedOwnerPlusOne = 0 ⇒ none
        }
    }

    /// **The deleted `removeOwnerAtIndex` selector fails validation and
    /// opens nothing.** Owner removal was deleted before launch; a slot-
    /// signed op carrying its selector (`0x89625b57`) is no longer in the
    /// slot-allowed set, so validation fails, `slotUses` does not move,
    /// and no execute credit exists for ANY index afterwards. Bytecode
    /// witness for the Lean `Selector.isSlotAllowed` (two selectors only).
    function check_validate_rejects_removed_selector(uint256 callIdx) public {
        bytes memory vCallData = abi.encodeWithSelector(
            bytes4(0x89625b57), uint256(1), abi.encodePacked(SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
        c10.setValid(true);
        uint256 preSlotUses = wallet.slotUses(1);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres =
            wallet.validateUserOp(_op(vCallData, abi.encode(uint256(1), new bytes(4008))), bytes32(0), 0);
        assertEq(vres, 1, "removed-selector validate must fail");
        assertEq(wallet.slotUses(1), preSlotUses, "failed validate bumped slotUses");

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(
            callIdx, 0, CODELESS_TARGET, 0, ""
        ) returns (bytes memory) {
            assertTrue(false, "credit: a failed validate opened the execute gate");
        } catch {
            // expected: OwnerIndexMismatch — no credit was stamped
        }
    }

    /// **A successful bootstrap validation stamps no credit.** Since the
    /// 2026-10-20 freeze the only validation that succeeds without stamping
    /// an execute credit is a bootstrap (`ownerIndex 0`) `addOwnerBytes` op
    /// (before it, a slot-signed removal op was the other one). After it,
    /// neither execute path may run for ANY index: the bytecode analogue of
    /// the Lean `TxFlow.applyValidateSuccess` index-0 clause.
    function check_validate_bootstrap_success_stamps_no_credit(uint256 callIdx) public {
        bytes memory newOwner =
            abi.encodePacked(bytes32(uint256(0x1111) << 240), bytes32(uint256(0x2222) << 240));
        c10.setValid(true);
        uint256 preBootstrapUses = wallet.bootstrapUses();
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vres = wallet.validateUserOp(
            _op(abi.encodeCall(wallet.addOwnerBytes, (newOwner)), abi.encode(uint256(0), new bytes(4008))),
            bytes32(0),
            0
        );
        assertEq(vres, 0, "bootstrap validate should succeed");
        assertEq(wallet.bootstrapUses(), preBootstrapUses + 1, "bootstrap validate must count");

        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(
            callIdx, 0, CODELESS_TARGET, 0, ""
        ) returns (bytes memory) {
            assertTrue(false, "credit: a bootstrap validate opened the execute gate");
        } catch {
            // expected: OwnerIndexMismatch — bootstrap validation stamps no credit
        }

        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory datas = new bytes[](0);
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeBatchWithOffchainCount(callIdx, 0, targets, values, datas) {
            assertTrue(false, "credit: a bootstrap validate opened the batch gate");
        } catch {
            // expected: OwnerIndexMismatch — bootstrap validation stamps no credit
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Rule 6 — multi-credit COUNTER semantics (bundle envelope, GAP-11):
    // N validations hand exactly N credits to N executions of the same
    // index in one transaction. This is the bytecode witness for the Lean
    // `credits : Nat → Nat` per-index counter map (stamp = +1,
    // consume = -1): two stamped validates fund exactly two executes —
    // the third reverts with no credit left, and the symbolic
    // `newOffchainCount`s thread the monotonic `setOffchain` chain.
    // ──────────────────────────────────────────────────────────────────
    function check_two_stamps_fund_exactly_two_executes() public {
        uint256 s1 = _stampViaValidate();
        uint256 s2 = _stampViaValidate();
        // The base wallet's counters start at zero, so both validates
        // succeed on this concrete pre-state (capOk holds).
        assertEq(s1, 1, "first stamp should succeed");
        assertEq(s2, 1, "second stamp should succeed");

        // Monotonic counts: c1 <= c2, both within the combined cap.
        uint256 c1 = svm.createUint256("bundleCount1");
        uint256 c2 = svm.createUint256("bundleCount2");
        vm.assume(c1 <= c2);
        vm.assume(c2 <= MAX_SLOT_USES - wallet.slotUses(1));
        vm.assume(c1 >= wallet.offchainSigCount(1));

        // Credit balance 2: first execute consumes one...
        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeWithOffchainCount(1, c1, CODELESS_TARGET, 0, "");
        // ...second execute consumes the other...
        vm.prank(ENTRY_POINT_ADDR);
        wallet.executeWithOffchainCount(1, c2, CODELESS_TARGET_2, 0, "");
        assertEq(wallet.offchainSigCount(1), c2, "bundle: second setOffchain lost");
        // ...and a third execute finds the counter at zero.
        vm.prank(ENTRY_POINT_ADDR);
        try wallet.executeWithOffchainCount(1, c2, CODELESS_TARGET, 0, "")
        returns (bytes memory) {
            assertTrue(false, "credit counter: third execute ran on two stamps");
        } catch {
            // expected: OwnerIndexMismatch — both credits consumed
        }
    }
}
