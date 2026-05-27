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
///         ~55-byte proxy that `DELEGATECALL`s here. The impl is deployed
///         once per chain; per-user deploys cost ~50k gas instead of the
///         ~1.1M a direct-deploy would cost.
///
///         The per-proxy mutable state lives in `PQMultiOwnable`'s ERC-7201
///         storage slot:
///           * `ownerAtIndex[0]` — bootstrap C10 pubkey, immutable per wallet
///           * `ownerAtIndex[i >= 1]` — slot C10 pubkeys, rotatable
///           * `bootstrapUses` / `slotUses[i]` — per-chain usage counters
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

    // ── Transient storage slots (EIP-1153) ─────────────────────────
    //
    // EIP-4337 v0.6 pairs `validateUserOp` and the executed callData
    // inside the same transaction. We thread two one-shot tokens via
    // transient storage so the executed call is forced to match the
    // signature that authorised it:
    //
    //   * `_TS_VALIDATED_OWNER_INDEX_PLUS_ONE` — the wrapper's
    //     `ownerIndex` from `_validateSignature`, offset by +1 so 0
    //     means "no validation has happened in this tx". Read and
    //     cleared by `executeWithOffchainCount` /
    //     `executeBatchWithOffchainCount` to enforce H-3 parity.
    //   * `_TS_PENDING_BOOTSTRAP_BUMP` — set to 1 whenever a bootstrap
    //     UserOp validates. Read and cleared by `addOwnerBytes`
    //     immediately after `_addOwner` succeeds, gating the actual
    //     bootstrap-budget bump (audit M-1). Bumping in validation
    //     would otherwise burn 1/65536 of the cap for every UserOp
    //     whose execution reverts (e.g. on `AlreadyOwner`).
    //
    // Both slots auto-clear at end of transaction (EIP-1153 semantics).
    uint256 private constant _TS_VALIDATED_OWNER_INDEX_PLUS_ONE = 0;
    uint256 private constant _TS_PENDING_BOOTSTRAP_BUMP = 1;

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
        _consumeValidatedOwnerIndex(ownerIndex);
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
        _consumeValidatedOwnerIndex(ownerIndex);
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

    /// @dev Consume the one-shot ownerIndex token written by
    ///      `_validateSignature` and revert unless it matches the
    ///      `ownerIndex` argument this caller supplied. Forces the
    ///      executed call to operate on the same slot the bundle was
    ///      authorised for (audit H-3) and to follow a validated
    ///      UserOp at all (a direct EntryPoint-impersonating call
    ///      with no preceding validate finds the slot empty).
    function _consumeValidatedOwnerIndex(uint256 ownerIndex) private {
        uint256 expectedPlusOne;
        assembly ("memory-safe") {
            expectedPlusOne := tload(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE)
            tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, 0)
        }
        if (expectedPlusOne == 0 || expectedPlusOne - 1 != ownerIndex) {
            revert OwnerIndexMismatch();
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
    ///         Bootstrap-budget bump is deferred from `_validateSignature`
    ///         to here (audit M-1): consume the transient
    ///         `_TS_PENDING_BOOTSTRAP_BUMP` token AFTER `_addOwner`
    ///         succeeds, so a revert in `_addOwner` (e.g. duplicate owner)
    ///         no longer burns 1/65536 of the bootstrap cap.
    function addOwnerBytes(bytes calldata newOwner) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        _addOwner(newOwner);
        uint256 pending;
        assembly ("memory-safe") {
            pending := tload(_TS_PENDING_BOOTSTRAP_BUMP)
            tstore(_TS_PENDING_BOOTSTRAP_BUMP, 0)
        }
        if (pending == 1) _bumpBootstrapUses(MAX_BOOTSTRAP_USES);
    }

    /// @notice Remove a slot owner. Only callable by the EntryPoint — i.e.
    ///         as the `callData` of a UserOp whose signature was validated
    ///         against `ownerIndex >= 1`. Refuses to remove index 0 (see
    ///         `PQMultiOwnable`).
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external {
        if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
        _removeOwnerAtIndex(index, owner);
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

        // ── Counter bumps after successful verify ───────────────────
        //
        // Audit M-1: the bootstrap-budget bump is deferred to
        //   `addOwnerBytes` so a reverting execution (e.g. `AlreadyOwner`)
        //   doesn't burn a bootstrap unit. We just mark the bump as
        //   pending here and let the execution-phase consume it.
        //
        // Audit H-3: stamp the validated ownerIndex into transient
        //   storage (+1 so the absence sentinel stays 0) so
        //   `executeWithOffchainCount` / `executeBatchWithOffchainCount`
        //   can enforce that the calldata ownerIndex matches.
        if (ownerIndex == 0) {
            assembly ("memory-safe") {
                tstore(_TS_PENDING_BOOTSTRAP_BUMP, 1)
            }
        } else {
            _bumpSlotUses(ownerIndex, MAX_SLOT_USES);
            assembly ("memory-safe") {
                tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, add(ownerIndex, 1))
            }
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

    function _isSlotAllowedSelector(bytes4 s) private pure returns (bool) {
        return
            s == this.executeWithOffchainCount.selector ||
            s == this.executeBatchWithOffchainCount.selector ||
            s == this.removeOwnerAtIndex.selector;
    }

    // ── EIP-1271 (off-chain sig verification, stateless) ───────────
    //
    // Inherits Solady's ERC1271, which provides:
    //   * `isValidSignature` (the EIP-1271 entry point) returning the
    //     0x1626ba7e magic on success / 0xffffffff on failure.
    //   * ERC-6492 unwrap so counterfactual sigs on un-deployed wallets
    //     verify cleanly via static call replication.
    //   * Nested EIP-712 wrapping (TypedDataSign + PersonalSign) so a
    //     captured slot sig over hash H against this wallet on chain X
    //     does NOT verify against a different wallet (same seed, different
    //     `account_index`) or against this wallet on a different chain.
    //
    // We override two hooks:
    //   * `_domainNameAndVersion()` — for the EIP-712 domain.
    //   * `_erc1271IsValidSignatureNowCalldata` — does the SPHINCS+C10
    //     verification against the slot pubkey indicated by ownerIndex.
    //   * `_erc1271Signer()` — abstract on Solady's base; we have a
    //     multi-owner model so the single-signer concept does not apply.
    //     We override the only consumer (`_erc1271IsValidSignatureNowCalldata`)
    //     and make `_erc1271Signer()` itself revert as a tripwire
    //     against future refactors that drop the override (audit L-2).
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

    receive() external payable {}
}
