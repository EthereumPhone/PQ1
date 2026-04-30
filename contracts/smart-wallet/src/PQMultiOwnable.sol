// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PqsignerProto} from "./generated/PqsignerProto.sol";

/// @notice Storage layout used by `PQMultiOwnable`.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQMultiOwnable
struct PQMultiOwnableStorage {
    /// @dev Next index to assign to an added owner.
    uint256 nextOwnerIndex;
    /// @dev Number of owners removed (tracked so `ownerCount` stays correct
    ///      without iterating `ownerAtIndex`).
    uint256 removedOwnersCount;
    /// @dev Maps index to owner bytes (always 64 bytes = pkSeed || pkRoot).
    mapping(uint256 index => bytes owner) ownerAtIndex;
    /// @dev Reverse index: owner bytes → bool.
    mapping(bytes owner => bool) isOwner;
    /// @dev Monotonic count of Type 1 (bootstrap / ownerIndex == 0)
    ///      signatures accepted on this chain. Capped at
    ///      `PQSmartWallet.MAX_BOOTSTRAP_USES`.
    uint256 bootstrapUses;
    /// @dev Per-slot monotonic count of Type 2 (slot / ownerIndex >= 1)
    ///      signatures, keyed by owner index. Capped at
    ///      `PQSmartWallet.MAX_SLOT_USES` each.
    mapping(uint256 ownerIndex => uint256) slotUses;
    /// @dev Per-slot monotonic count of off-chain (EIP-1271) signatures
    ///      the firmware reports it has produced on this chain. Updated
    ///      via the signed `executeWithOffchainCount(...)` path. The
    ///      *combined* invariant `slotUses[i] + offchainSigCount[i] <=
    ///      PQSmartWallet.MAX_SLOT_USES` is what bounds total slot-key
    ///      usage; on-chain UserOps and off-chain sigs share the same
    ///      hypertree budget.
    mapping(uint256 ownerIndex => uint256) offchainSigCount;
}

/// @title PQMultiOwnable
///
/// @notice Post-quantum multi-owner auth. Every owner is a
///         SPHINCS+C10 keypair encoded as 64 bytes: `pkSeed (32) || pkRoot (32)`.
///         Both values use the N-mask layout (top 16 bytes populated, bottom
///         16 bytes zero) to match the `sphincs-c10` verifier ABI.
///
///         The contract is deliberately stripped down compared to Coinbase's
///         `MultiOwnable`:
///           * No EOA / address owners (would require ECDSA path).
///           * No WebAuthn / P-256 owners (would require WebAuthn path).
///           * Only 64-byte C10 owner bytes are accepted.
///
///         Owner index 0 is the **bootstrap** key — immutable for the
///         lifetime of the wallet: it cannot be removed, and it is the only
///         owner authorized to add new owners via `addOwnerBytes`.
///         Indices 1..N are **slot** keys — rotatable, each capped at
///         `MAX_SLOT_USES` sigs on this chain. The role split is enforced
///         by `PQSmartWallet._validateSignature`; this contract only holds
///         storage.
///
/// @author PQSigner OS
abstract contract PQMultiOwnable {
    /// @dev ERC-7201 location:
    ///        keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQMultiOwnable")) - 1))
    ///          & ~bytes32(uint256(0xff))
    bytes32 private constant _PQ_MULTI_OWNABLE_STORAGE_LOCATION =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    /// @notice Length (in bytes) of a C10 owner: `pkSeed (32) || pkRoot (32)`.
    /// @dev Sourced from the auto-generated `PqsignerProto.OWNER_BYTES_LEN`
    ///      which mirrors the canonical `pqsigner-proto` Rust constant.
    uint256 internal constant OWNER_BYTES_LEN = PqsignerProto.OWNER_BYTES_LEN;

    // ── Errors ────────────────────────────────────────────────────────

    /// @notice Caller is not authorized.
    error Unauthorized();

    /// @notice Attempted to add an owner already present.
    error AlreadyOwner(bytes owner);

    /// @notice `removeOwnerAtIndex` targeted an empty slot.
    error NoOwnerAtIndex(uint256 index);

    /// @notice `owner` argument in `removeOwnerAtIndex` does not match storage.
    error WrongOwnerAtIndex(uint256 index, bytes expectedOwner, bytes actualOwner);

    /// @notice Owner bytes were not exactly `OWNER_BYTES_LEN` long.
    error InvalidOwnerBytesLength(bytes owner);

    /// @notice Attempt to remove the bootstrap key at index 0.
    error CannotRemoveBootstrap();

    /// @notice Owner bytes do not follow the N-mask layout. SPHINCS+C10 is
    ///         a 128-bit-security scheme; both `pkSeed` and `pkRoot` carry
    ///         their 16-byte values in the TOP half of a `bytes32`, with
    ///         the bottom 16 bytes required to be zero. The on-chain
    ///         verifier feeds the full 32 bytes of each into its SHA-256
    ///         inputs, and the firmware always emits the zero-padded
    ///         shape, so any owner with a non-zero low half is unsignable
    ///         and would just waste a slot index.
    error InvalidNMaskLayout(bytes owner);

    // ── Events ────────────────────────────────────────────────────────

    event AddOwner(uint256 indexed index, bytes owner);
    event RemoveOwner(uint256 indexed index, bytes owner);
    event BootstrapUsed(uint256 indexed newCount);
    event SlotUsed(uint256 indexed ownerIndex, uint256 indexed newCount);
    event OffchainSigCountUpdated(uint256 indexed ownerIndex, uint256 prev, uint256 newCount);

    /// @notice Off-chain count update is non-monotonic (newCount < current).
    error OffchainSigCountNotMonotonic(uint256 ownerIndex, uint256 current, uint256 newCount);

    /// @notice Combined `slotUses + offchainSigCount` would exceed the
    ///         per-slot SPHINCS+ usage cap.
    error CombinedSlotCapExceeded(uint256 ownerIndex, uint256 slotUsesNow, uint256 newOffchainCount, uint256 cap);

    // ── External getters ──────────────────────────────────────────────

    /// @notice Read the owner bytes at `index`.
    function ownerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _getStorage().ownerAtIndex[index];
    }

    /// @notice Next index the factory/wallet will assign to a new owner.
    function nextOwnerIndex() public view virtual returns (uint256) {
        return _getStorage().nextOwnerIndex;
    }

    /// @notice Active owner count (`nextOwnerIndex - removedOwnersCount`).
    function ownerCount() public view virtual returns (uint256) {
        PQMultiOwnableStorage storage $ = _getStorage();
        return $.nextOwnerIndex - $.removedOwnersCount;
    }

    function removedOwnersCount() public view virtual returns (uint256) {
        return _getStorage().removedOwnersCount;
    }

    function isOwnerBytes(bytes memory owner) public view virtual returns (bool) {
        return _getStorage().isOwner[owner];
    }

    /// @notice Monotonic bootstrap-use counter (ownerIndex == 0).
    function bootstrapUses() public view virtual returns (uint256) {
        return _getStorage().bootstrapUses;
    }

    /// @notice Monotonic per-slot use counter (ownerIndex >= 1).
    function slotUses(uint256 ownerIndex) public view virtual returns (uint256) {
        return _getStorage().slotUses[ownerIndex];
    }

    /// @notice Monotonic per-slot off-chain (EIP-1271) sig count last
    ///         reported by the firmware via a signed UserOp.
    function offchainSigCount(uint256 ownerIndex) public view virtual returns (uint256) {
        return _getStorage().offchainSigCount[ownerIndex];
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// @dev Bulk-initialise owners. Used once by the factory-invoked
    ///      `PQSmartWallet.initialize`. Reverts on malformed bytes or dup.
    function _initializeOwners(bytes[] memory owners) internal virtual {
        PQMultiOwnableStorage storage $ = _getStorage();
        uint256 idx = $.nextOwnerIndex;
        for (uint256 i; i < owners.length; i++) {
            if (owners[i].length != OWNER_BYTES_LEN) {
                revert InvalidOwnerBytesLength(owners[i]);
            }
            _addOwnerAtIndex(owners[i], idx++);
        }
        $.nextOwnerIndex = idx;
    }

    /// @dev Append a new owner at `nextOwnerIndex`. Returns the assigned index.
    function _addOwner(bytes memory owner) internal virtual returns (uint256 index) {
        if (owner.length != OWNER_BYTES_LEN) revert InvalidOwnerBytesLength(owner);
        PQMultiOwnableStorage storage $ = _getStorage();
        index = $.nextOwnerIndex;
        _addOwnerAtIndex(owner, index);
        $.nextOwnerIndex = index + 1;
    }

    /// @dev Remove the owner at `index`. Refuses to touch index 0.
    function _removeOwnerAtIndex(uint256 index, bytes calldata owner) internal virtual {
        if (index == 0) revert CannotRemoveBootstrap();
        bytes memory current = ownerAtIndex(index);
        if (current.length == 0) revert NoOwnerAtIndex(index);
        if (keccak256(current) != keccak256(owner)) {
            revert WrongOwnerAtIndex({index: index, expectedOwner: owner, actualOwner: current});
        }
        PQMultiOwnableStorage storage $ = _getStorage();
        delete $.isOwner[owner];
        delete $.ownerAtIndex[index];
        $.removedOwnersCount++;
        emit RemoveOwner(index, owner);
    }

    /// @dev Increment `bootstrapUses`, revert if it would exceed `cap`.
    function _bumpBootstrapUses(uint256 cap) internal returns (uint256 next) {
        PQMultiOwnableStorage storage $ = _getStorage();
        next = $.bootstrapUses + 1;
        require(next <= cap, "bootstrap exhausted");
        $.bootstrapUses = next;
        emit BootstrapUsed(next);
    }

    /// @dev Increment `slotUses[ownerIndex]`, revert if it would exceed `cap`.
    function _bumpSlotUses(uint256 ownerIndex, uint256 cap) internal returns (uint256 next) {
        PQMultiOwnableStorage storage $ = _getStorage();
        next = $.slotUses[ownerIndex] + 1;
        require(next <= cap, "slot exhausted");
        $.slotUses[ownerIndex] = next;
        emit SlotUsed(ownerIndex, next);
    }

    /// @dev Monotonically update `offchainSigCount[ownerIndex]` and enforce
    ///      the *combined* per-slot cap `slotUses + offchainSigCount <= cap`.
    ///      `slotUsesNow` is passed in so the caller does not have to load
    ///      it twice. No-op if `newCount == prev` (idempotent re-publish).
    function _setOffchainSigCount(
        uint256 ownerIndex,
        uint256 newCount,
        uint256 slotUsesNow,
        uint256 cap
    ) internal returns (uint256 prev) {
        PQMultiOwnableStorage storage $ = _getStorage();
        prev = $.offchainSigCount[ownerIndex];
        if (newCount < prev) {
            revert OffchainSigCountNotMonotonic(ownerIndex, prev, newCount);
        }
        if (slotUsesNow + newCount > cap) {
            revert CombinedSlotCapExceeded(ownerIndex, slotUsesNow, newCount, cap);
        }
        if (newCount != prev) {
            $.offchainSigCount[ownerIndex] = newCount;
            emit OffchainSigCountUpdated(ownerIndex, prev, newCount);
        }
    }

    // ── Private ───────────────────────────────────────────────────────

    function _addOwnerAtIndex(bytes memory owner, uint256 index) private {
        if (isOwnerBytes(owner)) revert AlreadyOwner(owner);
        // N-mask enforcement: bottom 128 bits of both pkSeed and pkRoot
        // must be zero. See `InvalidNMaskLayout` doc-comment.
        bytes32 seed;
        bytes32 root;
        assembly ("memory-safe") {
            seed := mload(add(owner, 32))
            root := mload(add(owner, 64))
        }
        if (uint128(uint256(seed)) != 0 || uint128(uint256(root)) != 0) {
            revert InvalidNMaskLayout(owner);
        }
        PQMultiOwnableStorage storage $ = _getStorage();
        $.isOwner[owner] = true;
        $.ownerAtIndex[index] = owner;
        emit AddOwner(index, owner);
    }

    function _getStorage() internal pure returns (PQMultiOwnableStorage storage $) {
        bytes32 slot = _PQ_MULTI_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
