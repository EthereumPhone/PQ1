// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {PqsignerProto} from "../../src/generated/PqsignerProto.sol";

/// @notice Line-by-line Solidity transcription of the Lean model
///         `SphincsCVerify.Wallet.ValidateUserOp.validateSignature`
///         (contracts/verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean).
///
///         PURPOSE — bridge axiom A3.2 (`solidityWallet_compiles_correctly`)
///         asserts pointwise equality between the deployed
///         `PQSmartWallet.validateUserOp` bytecode and the Lean
///         `validateSignature` function. Halmos cannot consume a Lean term,
///         so this contract IS the Lean term, transcribed clause-for-clause
///         (each block cites the Lean definition it mirrors), and
///         `HalmosValidateUserOpEquiv` proves the deployed wallet bytecode
///         pointwise-equal to THIS contract over a symbolic envelope. The
///         residual transcription gap (this file <-> the Lean file) is a
///         side-by-side syntactic correspondence over ~60 lines of
///         first-order code — auditable by eye, with the selector / cap
///         constants additionally parity-tested in the harness `setUp`.
///
///         Failure cases all return `(failure, unchanged-state)` exactly as
///         the Lean model returns `(Result.failure, s)`; the ORDER of the
///         failure checks differs between the Lean model and the deployed
///         wallet in two places (the wallet checks the tail-pad before the
///         owner lookup; the model decodes everything first) but every
///         failure is observationally identical — the equivalence rule
///         compares only (result, post-state), which is the equality A3.2
///         states.
contract LeanValidateUserOpModel {
    // ── Lean `Selector.*` literals (ValidateUserOp.lean) ───────────────
    //
    // The harness setUp parity-asserts each against the live
    // `PQSmartWallet` function selectors, mirroring LeanSelectorParity.t.sol.
    // (Owner removal was deleted before launch; its selector is in neither
    // the Lean model nor the wallet.)
    bytes4 public constant SEL_ADD_OWNER_BYTES = 0x101490cb;
    bytes4 public constant SEL_EXECUTE_WITH_OFFCHAIN_COUNT = 0x14443c57;
    bytes4 public constant SEL_EXECUTE_BATCH_WITH_OFFCHAIN_COUNT = 0x7a389933;

    // ── Lean `Spec.SignatureLen` / wrapper layout (ValidateUserOp.lean:117-128)
    uint256 public constant SIGNATURE_LEN = PqsignerProto.C10_SIG_LEN; // 4008
    uint256 public constant PADDED_INNER_LEN = ((SIGNATURE_LEN + 31) / 32) * 32; // 4032
    uint256 public constant WRAPPED_LEN = 96 + PADDED_INNER_LEN; // 4128

    // ── Lean `Storage.MaxBootstrapUses` / `MaxSlotUses` ────────────────
    uint256 public constant MAX_BOOTSTRAP_USES = PqsignerProto.MAX_BOOTSTRAP_USES;
    uint256 public constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;

    uint256 public constant OWNER_BYTES_LEN = PqsignerProto.OWNER_BYTES_LEN; // 64

    /// Sentinel mirroring Lean `calldataOwnerIndex`'s `2^256 - 1` fail-closed
    /// value (= Solidity `type(uint256).max`).
    uint256 internal constant CALLDATA_OWNER_INDEX_SENTINEL = type(uint256).max;

    /// @dev Mirrors the Lean model's `entryPoint : ByteVec 20` parameter —
    ///      must be constructed with the SAME address as the wallet under
    ///      test so `sphincsDigestPreimage` is byte-identical.
    address public immutable entryPointAddr;

    /// @dev Mirrors the Lean model's `verify_fn` parameter — the SAME
    ///      verifier instance the wallet under test is wired to.
    ISPHINCSVerifier public immutable verifyFn;

    constructor(address entryPoint_, ISPHINCSVerifier verifyFn_) {
        entryPointAddr = entryPoint_;
        verifyFn = verifyFn_;
    }

    /// The model's output: Lean `Result × Storage`, projected onto the
    /// storage fields `validateSignature` can touch.
    ///
    /// On failure the Lean model returns `(Result.failure, s)` — state
    /// UNCHANGED — so the post fields carry no information beyond the
    /// pre-state and are zeroed; the equivalence rule asserts the
    /// unchanged-state half directly against its own pre-state probes.
    /// They are meaningful only when `result == 0`.
    struct Prediction {
        uint256 result; // Result.toUint256: success = 0, failure = 1
        uint256 ownerIndex; // decoded wrapper ownerIndex (sentinel when undecoded)
        uint256 postBootstrapUses; // success only
        uint256 postSlotUsesAtOwnerIndex; // success only: slotUses[ownerIndex] after
    }

    /// @notice The Lean `validateSignature s op entryPoint chainId verify_fn`,
    ///         with `s` read through the wallet's public storage getters
    ///         (the same symbolic storage the bytecode under test reads) and
    ///         `chainId = block.chainid` (same environment).
    function predict(PQSmartWallet wallet, UserOperation06 calldata op)
        external
        view
        returns (Prediction memory p)
    {
        p.ownerIndex = CALLDATA_OWNER_INDEX_SENTINEL;

        // ── Lean `decodeWrappedSig` (ValidateUserOp.lean) ──────────────
        //
        //   if raw.size ≠ wrappedLen then none
        bytes calldata sig = op.signature;
        if (sig.length != WRAPPED_LEN) return _fail(wallet, p);

        //   let ownerIndex  := readWordBE raw 0
        //   let offsetField := readWordBE raw 32
        //   let innerLen    := readWordBE raw 64
        //   let tailPad     := readWordBE raw 4096 % 2 ^ 192
        uint256 ownerIndex = uint256(bytes32(sig[0:32]));
        uint256 offsetField = uint256(bytes32(sig[32:64]));
        uint256 innerLen = uint256(bytes32(sig[64:96]));
        uint256 tailPad = uint256(bytes32(sig[4096:4128])) & ((uint256(1) << 192) - 1);

        //   if offsetField ≠ 0x40 / innerLen ≠ SignatureLen / tailPad ≠ 0 → none
        if (offsetField != 0x40) return _fail(wallet, p);
        if (innerLen != SIGNATURE_LEN) return _fail(wallet, p);
        if (tailPad != 0) return _fail(wallet, p);

        //   some { ownerIndex, innerSig := extractInnerSig raw 96 }
        bytes calldata innerSig = sig[96:96 + SIGNATURE_LEN];
        p.ownerIndex = ownerIndex;

        // ── Lean `s.ownerAtIndex ownerIndex` (validateSignature step 2) ─
        //
        // Lean `Storage.ownerAtIndex : Nat → Option OwnerBytes` returns
        // `none` exactly when the getter returns bytes of length ≠ 64
        // (`OwnerBytes = ByteVec 64`; the unset default is empty bytes).
        bytes memory ownerBytes = wallet.ownerAtIndex(ownerIndex);
        if (ownerBytes.length != OWNER_BYTES_LEN) return _fail(wallet, p);

        //   pkSeed := owner.raw.take 32 ; pkRoot := owner.raw.drop 32
        bytes32 pkSeed;
        bytes32 pkRoot;
        assembly ("memory-safe") {
            pkSeed := mload(add(ownerBytes, 32))
            pkRoot := mload(add(ownerBytes, 64))
        }

        // ── Lean `capOk s op ownerIndex` ───────────────────────────────
        if (!_capOk(wallet, op, ownerIndex)) return _fail(wallet, p);

        // ── Lean `sphincsDigest op entryPoint chainId` ─────────────────
        bytes32 digest = _sphincsDigest(op);

        // ── Lean `verify_fn pkSeed pkRoot digest innerSig` ─────────────
        if (!verifyFn.verify(pkSeed, pkRoot, digest, innerSig)) {
            return _fail(wallet, p);
        }

        // ── Lean `bumpForOwner s ownerIndex` ───────────────────────────
        //
        // `capOk = true` on this path implies the strict-cap precondition,
        // so `Storage.bumpBootstrap` / `Storage.bumpSlot` is `some` and the
        // post value is pre + 1 at exactly the bumped field/index
        // (`Storage.bump*` modifies nothing else — the Lean monotonicity /
        // preservation lemmas in Wallet/Invariants.lean).
        p.result = 0; // Result.success
        if (ownerIndex == 0) {
            p.postBootstrapUses = wallet.bootstrapUses() + 1;
            p.postSlotUsesAtOwnerIndex = wallet.slotUses(0);
        } else {
            p.postBootstrapUses = wallet.bootstrapUses();
            p.postSlotUsesAtOwnerIndex = wallet.slotUses(ownerIndex) + 1;
        }
    }

    /// Lean `(Result.failure, s)`: result 1, state unchanged (the harness
    /// asserts the unchanged half against its own pre-state probes).
    function _fail(PQSmartWallet, Prediction memory p)
        private
        pure
        returns (Prediction memory)
    {
        p.result = 1; // Result.failure
        p.postBootstrapUses = 0;
        p.postSlotUsesAtOwnerIndex = 0;
        return p;
    }

    /// Lean `UserOperation.selectorOf` (ValidateUserOp.lean:95-101):
    /// first 4 bytes of callData, zero when `size < 4`.
    function _selectorOf(bytes calldata callData) private pure returns (bytes4) {
        if (callData.length < 4) return bytes4(0);
        return bytes4(callData[0:4]);
    }

    /// Lean `Selector.isSlotAllowed` (ValidateUserOp.lean).
    function _isSlotAllowed(bytes4 s) private pure returns (bool) {
        return s == SEL_EXECUTE_WITH_OFFCHAIN_COUNT
            || s == SEL_EXECUTE_BATCH_WITH_OFFCHAIN_COUNT;
    }

    /// Lean `calldataOwnerIndex` (ValidateUserOp.lean): the first ABI word
    /// of the calldata (offset 4); `2^256 - 1` fail-closed when `size < 36`.
    function _calldataOwnerIndex(bytes calldata callData) private pure returns (uint256) {
        if (callData.length < 36) return CALLDATA_OWNER_INDEX_SENTINEL;
        return uint256(bytes32(callData[4:36]));
    }

    /// Lean `capOk` (ValidateUserOp.lean): role-split + H-3 parity + caps.
    function _capOk(PQSmartWallet wallet, UserOperation06 calldata op, uint256 ownerIndex)
        private
        view
        returns (bool)
    {
        bytes4 sel = _selectorOf(op.callData);
        if (ownerIndex == 0) {
            //   decide (op.selectorOf = Selector.addOwnerBytes) &&
            //   decide (s.bootstrapUses < MaxBootstrapUses)
            return sel == SEL_ADD_OWNER_BYTES && wallet.bootstrapUses() < MAX_BOOTSTRAP_USES;
        }
        //   Selector.isSlotAllowed op.selectorOf &&
        //   decide (calldataOwnerIndex op = ownerIndex) &&
        //   decide (s.slotUses i + s.offchainSigCount i < MaxSlotUses)
        //
        // NOTE (reachable-state hypothesis): the Lean conjunct is over Nat
        // and cannot overflow; this uint256 sum can. The equivalence rule
        // assumes the kernel-proven reachable-state invariant
        // `combinedCap_inductive` (slotUses[i] + offchainSigCount[i] ≤
        // MaxSlotUses), under which the sum is ≤ 65536 and the two
        // semantics coincide. Outside that invariant the deployed bytecode
        // REVERTS (checked arithmetic) where the Nat model returns
        // failure — a documented divergence on unreachable states; see
        // AXIOM_STATUS.json A3.2.
        return _isSlotAllowed(sel)
            && _calldataOwnerIndex(op.callData) == ownerIndex
            && wallet.slotUses(ownerIndex) + wallet.offchainSigCount(ownerIndex) < MAX_SLOT_USES;
    }

    /// Lean `sphincsDigestPreimage` + `sphincsDigest`
    /// (ValidateUserOp.lean:232-257): the exact 360-byte
    /// `abi.encodePacked` concatenation, then the outer sha256. Must stay
    /// byte-identical to `PQSmartWallet.sphincsDigest` — under the generic
    /// verifier any preimage divergence is observable, so the equivalence
    /// rule re-proves this identity on every run.
    function _sphincsDigest(UserOperation06 calldata op) private view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                op.sender,
                op.nonce,
                sha256(op.initCode),
                sha256(op.callData),
                op.callGasLimit,
                op.verificationGasLimit,
                op.preVerificationGas,
                op.maxFeePerGas,
                op.maxPriorityFeePerGas,
                sha256(op.paymasterAndData),
                entryPointAddr,
                block.chainid
            )
        );
    }
}
