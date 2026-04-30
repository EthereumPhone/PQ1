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

    // ── Errors ──────────────────────────────────────────────────────

    error NotFromEntryPoint();
    error NotFromSelf();
    error AlreadyInitialized();

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
        _setOffchainSigCount(
            ownerIndex,
            newOffchainCount,
            _getStorage().slotUses[ownerIndex],
            MAX_SLOT_USES
        );
        uint256 n = targets.length;
        require(values.length == n && datas.length == n, "length mismatch");
        for (uint256 i; i < n; ++i) {
            (bool ok, bytes memory ret) = targets[i].call{value: values[i]}(datas[i]);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }

    // ── Owner management (self-only, i.e. via a validated UserOp) ───

    /// @notice Add a new slot owner at the next index. Only callable by
    ///         `this` — i.e. via a UserOp whose signature was validated
    ///         against `ownerIndex == 0` (bootstrap).
    function addOwnerBytes(bytes calldata newOwner) external {
        if (msg.sender != address(this)) revert NotFromSelf();
        _addOwner(newOwner);
    }

    /// @notice Remove a slot owner. Only callable by `this` — i.e. via a
    ///         UserOp whose signature was validated against `ownerIndex >= 1`.
    ///         Refuses to remove index 0 (see `PQMultiOwnable`).
    function removeOwnerAtIndex(uint256 index, bytes calldata owner) external {
        if (msg.sender != address(this)) revert NotFromSelf();
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
        //   [0..32)    ownerIndex
        //   [32..64)   offset to bytes (MUST be 0x40)
        //   [64..96)   inner sig length (MUST be C10_SIG_LEN)
        //   [96..96+padded) inner C10 sig (padded to 32-byte boundary)
        uint256 paddedInner = ((C10_SIG_LEN + 31) / 32) * 32;
        uint256 expectedLen = 96 + paddedInner;
        if (sig.length != expectedLen) return SIG_VALIDATION_FAILED;

        uint256 ownerIndex;
        uint256 offsetField;
        uint256 innerLen;
        assembly ("memory-safe") {
            ownerIndex := calldataload(sig.offset)
            offsetField := calldataload(add(sig.offset, 32))
            innerLen := calldataload(add(sig.offset, 64))
        }
        if (offsetField != 0x40) return SIG_VALIDATION_FAILED;
        if (innerLen != C10_SIG_LEN) return SIG_VALIDATION_FAILED;

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
        if (ownerIndex == 0) {
            _bumpBootstrapUses(MAX_BOOTSTRAP_USES);
        } else {
            _bumpSlotUses(ownerIndex, MAX_SLOT_USES);
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
    //     Returning `address(this)` makes the default impl a no-op (we
    //     override the only consumer of it anyway).
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

    function _erc1271Signer() internal view override returns (address) {
        return address(this);
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
        assembly ("memory-safe") {
            ownerIndex := calldataload(signature.offset)
            offsetField := calldataload(add(signature.offset, 32))
            innerLen := calldataload(add(signature.offset, 64))
        }
        if (offsetField != 0x40) return false;
        if (innerLen != C10_SIG_LEN) return false;

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
