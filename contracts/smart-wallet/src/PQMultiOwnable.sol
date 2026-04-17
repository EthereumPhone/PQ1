// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

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
    uint256 internal constant OWNER_BYTES_LEN = 64;

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

    // ── Events ────────────────────────────────────────────────────────

    event AddOwner(uint256 indexed index, bytes owner);
    event RemoveOwner(uint256 indexed index, bytes owner);
    event BootstrapUsed(uint256 indexed newCount);
    event SlotUsed(uint256 indexed ownerIndex, uint256 indexed newCount);

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

    // ── Private ───────────────────────────────────────────────────────

    function _addOwnerAtIndex(bytes memory owner, uint256 index) private {
        if (isOwnerBytes(owner)) revert AlreadyOwner(owner);
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
