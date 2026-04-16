// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice ERC-7201 storage layout for the JARDÍN-only wallet.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQOwnable
struct PQSignerStorage {
    /// @dev JARDIN FORS+C slot registry: `H(r) => keccak256(subPkSeed || subPkRoot)`.
    ///      Populated by Type 1 signature validation as a side effect; read
    ///      by Type 2 signature validation to look up the registered sub-key.
    mapping(bytes32 => bytes32) jardinSlots;
}

/// @title PQOwnable
///
/// @notice Minimal on-chain slot registry for the JARDÍN-only post-cutover
///         wallet. The entire multi-signer ownership model is gone — every
///         signature on the wallet is validated against the immutable
///         master C11 keypair set at construction time, with JARDIN
///         FORS+C sub-keys registered as pure storage side effects.
///
/// @author PQSigner OS
abstract contract PQOwnable {
    /// @dev Canonical ERC-7201 location:
    ///         keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQOwnable")) - 1))
    ///         & ~bytes32(uint256(0xff))
    ///      Verified with `cast`:
    ///         cast keccak 'pqsigner.storage.PQOwnable'
    ///           → 0xe46f3ef1...59
    ///         cast keccak $(cast abi-encode "f(uint256)" $(prev - 1))
    ///           → 0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd7..
    ///         mask & ~0xff →
    ///           0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700
    ///
    ///      HIGH-14 fix: the previous value was a hand-crafted constant
    ///      with a suspicious "ascending nibbles" pattern that did not
    ///      match the canonical derivation. Any future contract that
    ///      inherits PQOwnable and adds its own ERC-7201 storage would
    ///      have collided with the fabricated slot.
    bytes32 private constant _PQ_OWNABLE_STORAGE_LOCATION =
        0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700;

    /// @notice Emitted when a JARDIN FORS+C slot is registered.
    event JardinSlotRegistered(bytes32 indexed slotKey, bytes32 indexed subVkHash);

    /// @notice Emitted when a JARDIN FORS+C slot is revoked via
    ///         `PQJardinWallet.revokeJardinSlot`. The storage entry
    ///         is cleared to bytes32(0); any future Type 2 signature
    ///         against the revoked slotKey fails with
    ///         SIG_VALIDATION_FAILED.
    event JardinSlotRevoked(bytes32 indexed slotKey, bytes32 indexed previousSubVkHash);

    /// @notice Look up a registered JARDIN sub-key commitment.
    /// @param slotKey The on-chain slot key H(r).
    /// @return The stored sub-VK hash, or bytes32(0) if unregistered.
    function jardinSlot(bytes32 slotKey) public view virtual returns (bytes32) {
        return _getStorage().jardinSlots[slotKey];
    }

    /// @notice Register or idempotently re-confirm a JARDIN slot's sub-key.
    ///
    ///         Called by `validateUserOp` inside `_validateSignature` as a
    ///         side effect of Type 1 verification. Non-re-entrant by virtue
    ///         of EntryPoint's single-entry UserOp dispatch.
    ///
    /// @param slotKey   Keccak256 hash of the slot randomiser `r`.
    /// @param subVkHash Keccak256 hash of `subPkSeed || subPkRoot`.
    function _registerJardinSlot(bytes32 slotKey, bytes32 subVkHash) internal {
        PQSignerStorage storage $ = _getStorage();
        bytes32 prev = $.jardinSlots[slotKey];
        // Idempotent: if the same (r, subKey) pair re-registers, that's a
        // benign retry (e.g. the companion re-submitted a dropped Type 1).
        // A mismatch, however, is a programming or attack error — the
        // wallet must never silently replace a registered sub-key.
        require(prev == bytes32(0) || prev == subVkHash, "slot conflict");
        if (prev == bytes32(0)) {
            $.jardinSlots[slotKey] = subVkHash;
            emit JardinSlotRegistered(slotKey, subVkHash);
        }
    }

    /// @notice Revoke a previously-registered JARDIN FORS+C slot.
    ///
    ///         Clears the `slots[slotKey]` mapping so subsequent Type 2
    ///         signatures against that slotKey are rejected. Used when
    ///         a sub-key has been leaked (side-channel, fault injection,
    ///         ...) before its q counter is exhausted.
    ///
    ///         Callable only from the wallet itself — the UserOp that
    ///         carries the `revokeJardinSlot(slotKey)` calldata must be
    ///         authorised by the master C11 identity (Type 1) OR by a
    ///         live registered slot (Type 2). The public authorisation
    ///         gate is on `PQJardinWallet.revokeJardinSlot`, which
    ///         forwards here.
    /// @param slotKey Slot identifier (`keccak256(r)`) to revoke.
    function _revokeJardinSlot(bytes32 slotKey) internal {
        PQSignerStorage storage $ = _getStorage();
        bytes32 prev = $.jardinSlots[slotKey];
        if (prev != bytes32(0)) {
            delete $.jardinSlots[slotKey];
            emit JardinSlotRevoked(slotKey, prev);
        }
    }

    /// @dev ERC-7201 storage accessor.
    function _getStorage() internal pure returns (PQSignerStorage storage $) {
        bytes32 slot = _PQ_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
