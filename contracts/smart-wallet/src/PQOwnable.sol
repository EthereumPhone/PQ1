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
    /// @dev keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQOwnable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PQ_OWNABLE_STORAGE_LOCATION =
        0xf3a1a4cdfe9d5bd1e7c1f3e3d6c8f7a3b2f6c9d1e2a4b6c8d0e2f4a6b8c0d200;

    /// @notice Emitted when a JARDIN FORS+C slot is registered.
    event JardinSlotRegistered(bytes32 indexed slotKey, bytes32 indexed subVkHash);

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

    /// @dev ERC-7201 storage accessor.
    function _getStorage() internal pure returns (PQSignerStorage storage $) {
        bytes32 slot = _PQ_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
