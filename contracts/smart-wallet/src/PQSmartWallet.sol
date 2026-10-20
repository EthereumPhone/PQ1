// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAccount06} from "account-abstraction/legacy/v06/IAccount06.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {ERC1271} from "solady/accounts/ERC1271.sol";

import {PQMultiOwnable, PQMultiOwnableStorage} from "./PQMultiOwnable.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";
import {PqsignerProto} from "./generated/PqsignerProto.sol";

/// @title PQSmartWallet
///
/// @notice Pure post-quantum ERC-4337 v0.6 account. Forked from Coinbase
///         Smart Wallet's `CoinbaseSmartWallet` (which targets v0.6),
///         stripped of every classical (EOA / P-256) signer path. The only
///         signature primitive is SPHINCS+C10 routed through `c10Verifier`.
///
///         **Deployment model**: this contract is the shared
///         *implementation* behind ERC-1967 proxies. Every user wallet is a
///         61-byte proxy that `DELEGATECALL`s here. The impl is deployed
///         once per chain; per-user deploys cost ~50k gas instead of the
///         ~1.1M a direct-deploy would cost.
///
///         The per-proxy mutable state lives in `PQMultiOwnable`'s ERC-7201
///         storage slot:
///           * `ownerAtIndex[0]` — bootstrap C10 pubkey, immutable per wallet
///           * `ownerAtIndex[i >= 1]` — slot C10 pubkeys, append-only (the
///             bootstrap key adds a new slot to rotate; nothing removes one)
///           * `bootstrapUses` / `slotUses[i]` / `offchainSigCount[i]` —
///             per-chain usage counters
///
///         `entryPoint` and `c10Verifier` are impl-level immutables (they
///         are the same for every wallet on a given chain), so proxies read
///         them straight from the impl bytecode — no per-wallet storage.
///
/// @author PQSigner OS
contract PQSmartWallet is IAccount06, PQMultiOwnable, ERC1271 {
    // ── Structs ─────────────────────────────────────────────────────

    /// @notice ABI-encoded wrapper around a C10 sig: `(ownerIndex, sig)`.
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    // ── Impl-level immutables (chain-level invariants) ─────────────

    IEntryPoint private immutable _entryPoint;
    ISPHINCSVerifier public immutable c10Verifier;

    // ── Config constants ────────────────────────────────────────────
    //
    // Sourced from `pqsigner-proto` (Rust, the single source of truth)
    // via the auto-generated `generated/PqsignerProto.sol` library.
    // CI diffs `cargo run -p pqsigner-xtask -- gen-solidity-constants
    // --check` against the checked-in library so any drift between the
    // firmware and the contract is caught at PR review.
    //
    // The `public` re-export preserves the existing external ABI so
    // off-chain integrations that read `wallet.C10_SIG_LEN()` etc.
    // keep working unchanged.

    /// @notice Exact length (bytes) of a SPHINCS+C10 signature.
    uint256 public constant C10_SIG_LEN = PqsignerProto.C10_SIG_LEN;

    /// @notice Bootstrap (ownerIndex == 0) sig cap, per chain.
    uint256 public constant MAX_BOOTSTRAP_USES = PqsignerProto.MAX_BOOTSTRAP_USES;

    /// @notice Per-slot (ownerIndex >= 1) sig cap.
    uint256 public constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;

    /// @dev ERC-4337 v0.6 sentinel values for `validateUserOp`.
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;

    // ── Transient validated-op credits (EIP-1153) ──────────────────
    //
    // EIP-4337 v0.6 `handleOps` runs ALL `validateUserOp`s first, then
    // ALL executions. To force each executed callData to match the
    // signature that authorised it, `_validateSignature` stamps a
    // transient *credit* for the validated op that the execution phase
    // consumes.
    //
    // The credit is a per-`ownerIndex` COUNTER, not a single shared
    // token. A bundle may legitimately carry several UserOps for the
    // same wallet, so N validations must hand N credits to N executions.
    // The previous single-slot token collapsed under 2+ ops per wallet
    // per bundle: the later validation clobbered the earlier credit and
    // the first execute consumed it, so every later execute reverted
    // (liveness loss).
    //
    // Credits gate ONLY the slot offchain-count execute paths
    // (`ownerIndex >= 1`): each validated `execute*WithOffchainCount`
    // increments credit[ownerIndex]; the matching execute consumes one
    // (anti-impersonation + one-shot replay guard, audit H-3). These two
    // selectors are the only ones a slot key may sign.
    //
    // The bootstrap path (`ownerIndex == 0`) does NOT use a credit. Its
    // few-time-usage cap `bootstrapUses` is bumped directly in the
    // VALIDATION phase (see `_validateSignature`), exactly like the slot
    // path bumps `slotUses` — an accepted Type-1 signature has already
    // spent a position on the master key's SPHINCS+ few-time forest and
    // is public on-chain, so it MUST be counted revert-proof. v0.6's
    // execution phase is revert-tolerant (`handleOps` swallows a
    // reverting `callData` and keeps validation-phase state), so a count
    // done in execution — as the prior credit-gated bump in
    // `addOwnerBytes` did — is lost whenever `_addOwner` reverts (e.g. a
    // forced duplicate-owner), under-counting the cap toward zero and
    // re-opening the few-time forgery surface the cap exists to close.
    //
    // H-3 parity (calldata ownerIndex == signed wrapper ownerIndex) is
    // enforced in `_validateSignature` for every slot op, so a credit is
    // unambiguously owned by the slot that signed it, even when several
    // slots share one bundle.
    //
    // Credits live at `keccak256(ownerIndex, _TS_CREDIT_NAMESPACE)` and
    // auto-clear at end of transaction (EIP-1153 semantics).
    uint256 private constant _TS_CREDIT_NAMESPACE =
        0xb16be5bfba32ddb324f3386598c391a82b15cf64d18acab2fbda19f75b9962d8;

    // ── Errors ──────────────────────────────────────────────────────

    error NotFromEntryPoint();
    error AlreadyInitialized();

    /// @notice An `executeWithOffchainCount` / `executeBatchWithOffchainCount`
    ///         call attempted to target the wallet itself. Blocking this
    ///         closes the bootstrap role-split escape from audit H-2 —
    ///         without it, a slot key could pipe `addOwnerBytes` through
    ///         the slot-execute path's self-call and mint new owners.
    error SelfCallForbidden();

    /// @notice The `ownerIndex` passed in calldata to
    ///         `executeWithOffchainCount` / `executeBatchWithOffchainCount`
    ///         did not match the `ownerIndex` recovered from the validated
    ///         signature wrapper. Closes audit H-3: without parity, a slot
    ///         key could poison a different slot's `offchainSigCount` by
    ///         signing under one index while updating another.
    error OwnerIndexMismatch();

    /// @notice `executeBatchWithOffchainCount` was called with mismatched
    ///         `targets` / `values` / `datas` array lengths. Custom error
    ///         instead of a plain-string revert (audit L-3).
    error BatchArrayLengthMismatch();

    // ── Init ────────────────────────────────────────────────────────

    /// @dev Constructor runs ONLY on the impl contract, not on proxies.
    ///      We seed one dummy owner at index 0 so `initialize` reverts when
    ///      called directly on the impl (proxies have their own storage, so
    ///      `nextOwnerIndex() == 0` for them and they still initialise).
    constructor(IEntryPoint ep, ISPHINCSVerifier c10) {
        _entryPoint = ep;
        c10Verifier = c10;

        bytes[] memory lockOut = new bytes[](1);
        lockOut[0] = abi.encodePacked(bytes32(0), bytes32(0));
        _initializeOwners(lockOut);
    }

    /// @notice Called exactly once, via the factory, right after CREATE2
    ///         of the proxy. The factory has already verified the bootstrap
    ///         C10 signature over `slot0OwnerBytes` before issuing this
    ///         call, so we accept it as-is.
    ///
    ///         The one-shot guard (`nextOwnerIndex() != 0`) is sufficient
    ///         because the factory invokes this atomically in the same tx
    ///         as `LibClone.createDeterministicERC1967`; there is no window
    ///         for a front-runner to call `initialize` first.
    function initialize(bytes calldata bootstrapOwnerBytes, bytes calldata slot0OwnerBytes) external {
        if (nextOwnerIndex() != 0) revert AlreadyInitialized();
        bytes[] memory owners = new bytes[](2);
        owners[0] = bootstrapOwnerBytes;
        owners[1] = slot0OwnerBytes;
        _initializeOwners(owners);
    }

    // ── IAccount ────────────────────────────────────────────────────

    function entryPoint() external view returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Bootstrap pubkey seed (first 32 bytes of `ownerAtIndex(0)`).
    ///         Exposed for companion / off-chain tooling.
    function masterPkSeed() external view returns (bytes32 seed) {
        bytes memory b = ownerAtIndex(0);
        if (b.length < 32) return bytes32(0);
        assembly ("memory-safe") {
            seed := mload(add(b, 32))
        }
    }

    /// @notice Bootstrap pubkey root (bytes 32..64 of `ownerAtIndex(0)`).
    function masterPkRoot() external view returns (bytes32 root) {
        bytes memory b = ownerAtIndex(0);
        if (b.length < 64) return bytes32(0);
        assembly ("memory-safe") {
            root := mload(add(b, 64))
        }
    }

    /// @inheritdoc IAccount06
    function validateUserOp(
        UserOperation06 calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();

        validationData = _validateSignature(userOp, userOpHash);

        if (missingAccountFunds != 0) {
            (bool ok, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            (ok); // EntryPoint handles failure.
        }
    }

    // ── Execution (slot-authorised) ─────────────────────────────────

    /// @notice The single execute entry-point for slot-authorised UserOps.
    ///         Carries the firmware's monotonic per-slot off-chain sig
    ///         count `newOffchainCount`; the contract durably records it
    ///         and enforces the *combined* per-slot cap
    ///         `slotUses[i] + offchainSigCount[i] <= MAX_SLOT_USES`.
    ///
    ///         Note: `slotUses[ownerIndex]` was already bumped by
    ///         `validateUserOp` *before* this call runs (within the same
    ///         transaction), so the combined-cap check here uses the
    ///         post-bump value. That is why the cap test in
    ///         `_validateSignature` uses strict `>=` against
    ///         `MAX_SLOT_USES` (refusing the next sig if combined is
    ///         already at cap), and the test here uses `<=` against the
    ///         cap (the post-bump combined must not have exceeded it).
    function executeWithOffchainCount(
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes memory) {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        if (!_consumeValidatedCredit(ownerIndex)) revert OwnerIndexMismatch();
        if (target == address(this)) revert SelfCallForbidden();
        _setOffchainSigCount(
            ownerIndex,
            newOffchainCount,
            _getStorage().slotUses[ownerIndex],
            MAX_SLOT_USES
        );
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }

    function executeBatchWithOffchainCount(
        uint256 ownerIndex,
        uint256 newOffchainCount,
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        if (!_consumeValidatedCredit(ownerIndex)) revert OwnerIndexMismatch();
        _setOffchainSigCount(
            ownerIndex,
            newOffchainCount,
            _getStorage().slotUses[ownerIndex],
            MAX_SLOT_USES
        );
        uint256 n = targets.length;
        if (values.length != n || datas.length != n) revert BatchArrayLengthMismatch();
        for (uint256 i; i < n; ++i) {
            if (targets[i] == address(this)) revert SelfCallForbidden();
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }

    /// @dev Transient slot for the per-`ownerIndex` validated-op credit,
    ///      namespaced to avoid collision with any future transient use.
    function _creditSlot(uint256 ownerIndex) private pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, ownerIndex)
            mstore(0x20, _TS_CREDIT_NAMESPACE)
            slot := keccak256(0x00, 0x40)
        }
    }

    /// @dev Validation phase: stamp one validated-op credit for `ownerIndex`.
    ///      A per-index COUNTER, so several UserOps for the same wallet in one
    ///      EntryPoint bundle each hand exactly one credit to the execution
    ///      phase (v0.6 validates all ops, then executes all ops).
    function _stampValidatedCredit(uint256 ownerIndex) private {
        bytes32 slot = _creditSlot(ownerIndex);
        assembly ("memory-safe") {
            tstore(slot, add(tload(slot), 1))
        }
    }

    /// @dev Execution phase: consume one validated-op credit for `ownerIndex`.
    ///      Returns whether a credit was present (and decremented). Its
    ///      absence means either no validation stamped this index in the
    ///      current tx (a direct EntryPoint-impersonating call with no
    ///      preceding validate — anti-impersonation) or it was already spent
    ///      (one-shot replay guard). H-3 parity (calldata ownerIndex ==
    ///      wrapper ownerIndex) is enforced in `_validateSignature`, so the
    ///      credit is owned by the slot that signed it.
    function _consumeValidatedCredit(uint256 ownerIndex) private returns (bool had) {
        bytes32 slot = _creditSlot(ownerIndex);
        assembly ("memory-safe") {
            let c := tload(slot)
            had := gt(c, 0)
            if had { tstore(slot, sub(c, 1)) }
        }
    }

    // ── Owner management (EntryPoint-only: a validated UserOp's callData) ──

    /// @notice Add a new slot owner at the next index. Only callable by the
    ///         EntryPoint — i.e. as the `callData` of a UserOp whose
    ///         signature `_validateSignature` accepted against
    ///         `ownerIndex == 0` (bootstrap). In ERC-4337 v0.6 the EntryPoint
    ///         is `msg.sender` when it dispatches `userOp.callData`, so the
    ///         guard is `_entryPoint`, not `address(this)`. The role-split in
    ///         `_validateSignature` is what restricts this selector to the
    ///         bootstrap key; a self-call cannot reach here anyway (every
    ///         `execute*` path rejects `target == address(this)`, audit H-2).
    ///
    ///         The owner set is append-only: there is no removal, so a key
    ///         that was ever installed can never be installed again
    ///         (`AlreadyOwner`), and its per-chain budget can never be reset
    ///         by re-installing it at a fresh index.
    ///
    ///         The bootstrap few-time cap (`bootstrapUses`) is bumped in the
    ///         VALIDATION phase by `_validateSignature`, not here. An accepted
    ///         Type-1 signature has already spent a master-key few-time
    ///         position regardless of whether this `_addOwner` ultimately
    ///         lands (a duplicate-owner revert is swallowed by the EntryPoint
    ///         under v0.6), so counting it in execution would let a
    ///         duplicate-add under-count the cap toward zero. This function
    ///         therefore performs no counter bump — it is pure execution.
    function addOwnerBytes(bytes calldata newOwner) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        _addOwner(newOwner);
    }

    // ── Signature validation ────────────────────────────────────────

    /// @notice Compute the SHA-256 digest that the firmware signs.
    ///
    ///         The EntryPoint-supplied `userOpHash` is keccak256-based, which
    ///         would force the STM32U585 to fall back to a slow software
    ///         keccak implementation (there is no keccak accelerator on the
    ///         chip, only SHA-256 and SAES). By re-hashing the UserOp fields
    ///         under SHA-256 and signing THAT digest, firmware stays on the
    ///         fast path end-to-end.
    function sphincsDigest(UserOperation06 calldata userOp) public view returns (bytes32) {
        return sha256(
            abi.encodePacked(
                userOp.sender,
                userOp.nonce,
                sha256(userOp.initCode),
                sha256(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                sha256(userOp.paymasterAndData),
                address(_entryPoint),
                block.chainid
            )
        );
    }

    function _validateSignature(
        UserOperation06 calldata userOp,
        bytes32 /* userOpHash — keccak-based, ignored in favour of sphincsDigest */
    ) internal returns (uint256) {
        bytes calldata sig = userOp.signature;

        // ── Manual parse of `abi.encode(uint256 ownerIndex, bytes sig)` ──
        //
        //   [0..32)        ownerIndex
        //   [32..64)       offset to bytes (MUST be 0x40)
        //   [64..96)       inner sig length (MUST be C10_SIG_LEN)
        //   [96..96+inner) inner C10 sig (4008 bytes)
        //   [4104..4128)   ABI tail-pad (24 bytes; MUST be zero)
        uint256 paddedInner = ((C10_SIG_LEN + 31) / 32) * 32;
        uint256 expectedLen = 96 + paddedInner;
        if (sig.length != expectedLen) return SIG_VALIDATION_FAILED;

        uint256 ownerIndex;
        uint256 offsetField;
        uint256 innerLen;
        uint256 tailPad;
        assembly ("memory-safe") {
            ownerIndex := calldataload(sig.offset)
            offsetField := calldataload(add(sig.offset, 32))
            innerLen := calldataload(add(sig.offset, 64))
            // Read the last 32 bytes of the wrapper. The bottom 24 bytes
            // of that word are the ABI tail-pad (positions [4104..4128));
            // the top 8 bytes are the last 8 of the authenticated inner
            // sig. Mask the top 8 bytes off so we only check the pad.
            // 0x00..(8 bytes)..0x00 || 0xFF..(24 bytes)..0xFF
            tailPad := and(
                calldataload(add(sig.offset, 4096)),
                0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            )
        }
        if (offsetField != 0x40) return SIG_VALIDATION_FAILED;
        if (innerLen != C10_SIG_LEN) return SIG_VALIDATION_FAILED;
        // Audit L-1: reject non-zero tail-pad — the wrapper keccak must
        // be malleable in zero ways, even though the C10 sig itself
        // authenticates the digest.
        if (tailPad != 0) return SIG_VALIDATION_FAILED;

        bytes calldata innerSig = sig[96:96 + C10_SIG_LEN];

        bytes memory ownerBytes = ownerAtIndex(ownerIndex);
        if (ownerBytes.length != OWNER_BYTES_LEN) return SIG_VALIDATION_FAILED;

        bytes32 pkSeed;
        bytes32 pkRoot;
        assembly ("memory-safe") {
            pkSeed := mload(add(ownerBytes, 32))
            pkRoot := mload(add(ownerBytes, 64))
        }

        // ── Role split ──────────────────────────────────────────────
        bytes4 selector = _selectorOf(userOp.callData);
        if (ownerIndex == 0) {
            if (selector != this.addOwnerBytes.selector) {
                return SIG_VALIDATION_FAILED;
            }
            if (_getStorage().bootstrapUses >= MAX_BOOTSTRAP_USES) {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            if (!_isSlotAllowedSelector(selector)) {
                return SIG_VALIDATION_FAILED;
            }
            // Audit H-3 (enforced at validation): both slot-allowed
            // selectors carry the target slot as their first calldata
            // argument. It MUST equal the signed wrapper `ownerIndex`, so the
            // credit stamped below is unambiguously owned by this slot even
            // when the bundle carries several slots' UserOps. Rejecting here
            // (rather than only at execution) is what keeps the per-index
            // credit from being stolen by a co-bundled victim op.
            if (_calldataOwnerIndex(userOp.callData) != ownerIndex) {
                return SIG_VALIDATION_FAILED;
            }
            // Combined cap: this Type 2 sig will bump `slotUses[i]` by 1,
            // so the post-bump combined total must still be `<= MAX_SLOT_USES`.
            // Equivalently, the pre-bump combined must be `< MAX_SLOT_USES`.
            PQMultiOwnableStorage storage $ = _getStorage();
            if ($.slotUses[ownerIndex] + $.offchainSigCount[ownerIndex] >= MAX_SLOT_USES) {
                return SIG_VALIDATION_FAILED;
            }
        }

        // ── C10 verify against the SHA-256 sphincs digest ──────────
        bytes32 digest = sphincsDigest(userOp);
        try c10Verifier.verify(pkSeed, pkRoot, digest, innerSig) returns (bool ok) {
            if (!ok) return SIG_VALIDATION_FAILED;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        // ── Counter bumps + validated-op credit after successful verify ──
        //
        // Both few-time caps are bumped HERE, in the validation phase, so
        // every accepted signature is counted revert-proof: v0.6's
        // execution phase is revert-tolerant and would lose a count done
        // there.
        //
        //   * ownerIndex 0 (bootstrap): bump `bootstrapUses` directly,
        //     mirroring the slot path. An accepted Type-1 sig has spent a
        //     master-key few-time position and is public on-chain; it must
        //     count even if the subsequent `addOwnerBytes` execution reverts
        //     (a forced duplicate-owner). No execution-phase credit is
        //     stamped — `addOwnerBytes` is pure execution.
        //   * ownerIndex >= 1 (slot): bump `slotUses[ownerIndex]` and stamp
        //     one per-`ownerIndex` credit (audit H-3), consumed by
        //     `execute*WithOffchainCount`. Counted (not a single token), so
        //     2+ ops for this wallet in one bundle are each honoured.
        if (ownerIndex == 0) {
            _bumpBootstrapUses(MAX_BOOTSTRAP_USES);
        } else {
            _bumpSlotUses(ownerIndex, MAX_SLOT_USES);
            _stampValidatedCredit(ownerIndex);
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /// @dev Read the first 4 bytes of `callData` as a selector. Returns
    ///      `0x00000000` when `callData` is shorter than 4 bytes.
    function _selectorOf(bytes calldata callData) private pure returns (bytes4 s) {
        if (callData.length < 4) return bytes4(0);
        assembly {
            s := calldataload(callData.offset)
        }
    }

    /// @dev Read the first ABI word (the `uint256 ownerIndex` argument) of an
    ///      `execute*WithOffchainCount` calldata, used for the H-3 parity
    ///      check in `_validateSignature`. Returns `type(uint256).max` when
    ///      the calldata is too short to carry one — a value no installed
    ///      owner index can equal, so the parity check fails closed.
    function _calldataOwnerIndex(bytes calldata callData) private pure returns (uint256 v) {
        if (callData.length < 36) return type(uint256).max;
        assembly {
            v := calldataload(add(callData.offset, 4))
        }
    }

    function _isSlotAllowedSelector(bytes4 s) private pure returns (bool) {
        return
            s == this.executeWithOffchainCount.selector ||
            s == this.executeBatchWithOffchainCount.selector;
    }

    // ── EIP-1271 (off-chain sig verification, stateless) ───────────
    //
    // Inherits Solady's ERC1271, which provides:
    //   * `isValidSignature(bytes32,bytes)` (the EIP-1271 entry point)
    //     returning the 0x1626ba7e magic on success / 0xffffffff on failure.
    //   * ERC-6492 unwrapping: a signature that ends in the 6492 magic is
    //     reduced to its inner signature. Deploying the counterfactual
    //     wallet first is the job of the ERC-6492-aware verifier calling
    //     us; this contract only strips the wrapper.
    //   * Nested EIP-712 wrapping (TypedDataSign + PersonalSign) so a
    //     captured slot sig over hash H against this wallet on chain X
    //     does NOT verify against a different wallet (same seed, different
    //     `account_index`) or against this wallet on a different chain.
    //
    // We override four hooks and add one entry point:
    //   * `_domainNameAndVersion()` — for the EIP-712 domain.
    //   * `_erc1271IsValidSignature()` — keeps ONLY the nested EIP-712
    //     workflow. Solady also accepts two raw-hash workflows: a call from
    //     its MulticallerWithSigner ("safe caller") and an `eth_call`-only
    //     (`tx.gasprice == 0`) RPC path. Both check the bare `hash` with no
    //     nesting. The firmware never bare-signs anything except UserOp
    //     `sphincsDigest`s, which are public in on-chain calldata, so either
    //     branch let anyone present a public UserOp signature as "this
    //     wallet signed that 32-byte value" (GitHub #691), and the RPC
    //     branch behaved differently per chain. With the override every
    //     accepted signature is over a nested hash bound to this wallet and
    //     chain: PersonalSign (what the firmware signs) or TypedDataSign.
    //   * `_erc1271IsValidSignatureNowCalldata` — does the SPHINCS+C10
    //     verification against the slot pubkey indicated by ownerIndex.
    //   * `_erc1271Signer()` — abstract on Solady's base; we have a
    //     multi-owner model so the single-signer concept does not apply.
    //     We override the only consumer (`_erc1271IsValidSignatureNowCalldata`)
    //     and make `_erc1271Signer()` itself revert as a tripwire
    //     against future refactors that drop the override (audit L-2).
    //   * `isValidSignature(bytes,bytes)` — the legacy EIP-1271 form that
    //     Safe v1.3.0 / v1.4.1 call on a contract owner (GitHub #995). It
    //     hashes `data` and runs the nested check above on that hash.
    //
    // EIP-1271 is `view`-only. It NEVER bumps `slotUses` /
    // `offchainSigCount`. The firmware-side `local_offchain_count`
    // (durably reflected on chain via `executeWithOffchainCount`) is the
    // only path that consumes the slot's signing budget.

    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        return ("PQSmartWallet", "1");
    }

    /// @dev Only the nested EIP-712 workflow (PersonalSign / TypedDataSign,
    ///      both bound to this wallet). Drops Solady's safe-caller and RPC
    ///      raw-hash workflows; see the section comment above.
    function _erc1271IsValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool)
    {
        return _erc1271IsValidSignatureViaNestedEIP712(hash, signature);
    }

    /// @notice Legacy EIP-1271 entry point, `isValidSignature(bytes,bytes)`,
    ///         selector `0x20c13b0b`. Safe v1.3.0 and v1.4.1 call it on a
    ///         contract owner with `data` = the EIP-712 encoding whose
    ///         keccak256 is the SafeTx (or SafeMessage) hash. Runs the same
    ///         nested check as `isValidSignature(bytes32,bytes)` on
    ///         `keccak256(data)`. Unlike that entry it does not unwrap
    ///         ERC-6492 signatures: Safe never sends them, and a
    ///         counterfactual (undeployed) wallet has no code to call.
    /// @return result `0x20c13b0b` if the signature is valid, else `0xffffffff`.
    function isValidSignature(bytes calldata data, bytes calldata signature)
        public
        view
        returns (bytes4 result)
    {
        bool success = _erc1271IsValidSignature(keccak256(data), signature);
        result = success ? bytes4(0x20c13b0b) : bytes4(0xffffffff);
    }

    /// @dev Solady's default `_erc1271IsValidSignatureNowCalldata` would
    ///      `staticcall` the address returned here back into this same
    ///      contract — `address(this) → self → infinite recursion → OOG`.
    ///      Our override below replaces that default body entirely, so
    ///      this hook is never reached in a healthy build. Revert loudly
    ///      to make any future refactor that accidentally drops the
    ///      override fail at the first EIP-1271 call instead of failing
    ///      silently with an unreadable out-of-gas (audit L-2).
    function _erc1271Signer() internal view override returns (address) {
        revert("unreachable: multi-owner -- see _erc1271IsValidSignatureNowCalldata");
    }

    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bool)
    {
        // Decode SignatureWrapper exactly like `_validateSignature`.
        uint256 paddedInner = ((C10_SIG_LEN + 31) / 32) * 32;
        if (signature.length != 96 + paddedInner) return false;

        uint256 ownerIndex;
        uint256 offsetField;
        uint256 innerLen;
        uint256 tailPad;
        assembly ("memory-safe") {
            ownerIndex := calldataload(signature.offset)
            offsetField := calldataload(add(signature.offset, 32))
            innerLen := calldataload(add(signature.offset, 64))
            // Audit L-1: mirror `_validateSignature`'s tail-pad check.
            tailPad := and(
                calldataload(add(signature.offset, 4096)),
                0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            )
        }
        if (offsetField != 0x40) return false;
        if (innerLen != C10_SIG_LEN) return false;
        if (tailPad != 0) return false;

        // Bootstrap key (ownerIndex == 0) is reserved for slot
        // registration. Forbid it for off-chain so the bootstrap budget
        // stays tight.
        if (ownerIndex == 0) return false;

        bytes calldata innerSig = signature[96:96 + C10_SIG_LEN];
        bytes memory ownerBytes = ownerAtIndex(ownerIndex);
        if (ownerBytes.length != OWNER_BYTES_LEN) return false;

        bytes32 pkSeed;
        bytes32 pkRoot;
        assembly ("memory-safe") {
            pkSeed := mload(add(ownerBytes, 32))
            pkRoot := mload(add(ownerBytes, 64))
        }

        try c10Verifier.verify(pkSeed, pkRoot, hash, innerSig) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    // ── Token receiver hooks (ERC-721 / ERC-1155) ──────────────────
    //
    // ERC-721 `safeTransferFrom` / `_safeMint` and every ERC-1155 transfer
    // call these on a contract recipient and revert unless the matching
    // selector comes back, so without them the wallet could not receive
    // ERC-1155 tokens at all, nor ERC-721 tokens sent by a safe transfer.
    // They accept unconditionally and touch no state. Explicit functions
    // rather than Solady's `Receiver`, which would add a payable fallback:
    // calls to unknown selectors still revert.

    /// @notice ERC-721 receiver hook. Returns `0x150b7a02`.
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0x150b7a02;
    }

    /// @notice ERC-1155 receiver hook. Returns `0xf23a6e61`.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xf23a6e61;
    }

    /// @notice ERC-1155 batch receiver hook. Returns `0xbc197c81`.
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external pure returns (bytes4) {
        return 0xbc197c81;
    }

    /// @notice ERC-165. EIP-1155 requires a contract that accepts ERC-1155
    ///         transfers to report the `ERC1155TokenReceiver` interface here.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return
            interfaceId == 0x01ffc9a7 || // ERC-165
            interfaceId == 0x150b7a02 || // ERC-721 token receiver
            interfaceId == 0x4e2312e0; // ERC-1155 token receiver
    }

    receive() external payable {}
}
