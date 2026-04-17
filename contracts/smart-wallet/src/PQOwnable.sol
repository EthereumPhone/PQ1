// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice ERC-7201 storage layout for the JARDÍN-only wallet.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQOwnable
struct PQSignerStorage {
    /// @dev JARDIN slot registry: `H(r) => sha256(subPkSeed || subPkRoot)`.
    ///      Populated by Type 1 signature validation as a side effect; read
    ///      by Type 2 signature validation to look up the registered sub-key.
    mapping(bytes32 => bytes32) jardinSlots;

    /// @dev Monotonic count of successful Type 1 (bootstrap C10) signatures
    ///      the wallet has accepted on this chain. Capped at
    ///      `PQJardinWallet.MAX_BOOTSTRAP_USES = 65_536`, well inside the
    ///      C10 hypertree's 2^18 = 262,144 signing positions. Once the cap
    ///      is hit the chain can still run Type 2 transactions against
    ///      already-registered slots (up to `MAX_SLOT_USES` each), but no
    ///      further slot rotations are possible on that chain.
    uint256 bootstrapUses;

    /// @dev Per-slot monotonic count of successful Type 2 (slot C10)
    ///      signatures, keyed by `slotKey = sha256(r)`. Bumped inside
    ///      `_bumpSlotUses` after a successful Type 2 verification.
    ///      Capped at `PQJardinWallet.MAX_SLOT_USES = 65_536`. Exhausting
    ///      a slot makes all future Type 2 sigs for that slotKey return
    ///      `SIG_VALIDATION_FAILED`; the companion rotates to `slot_index
    ///      + 1` via a Type 1 registration to resume signing.
    mapping(bytes32 => uint256) slotUses;
}

/// @title PQOwnable
///
/// @notice Minimal on-chain slot registry for the all-SPHINCS+C10 wallet.
///         The entire multi-signer ownership model is gone — every
///         signature on the wallet is validated against the immutable
///         bootstrap C10 keypair set at construction time (Type 1) or
///         against a slot-C10 sub-key registered on-chain as a pure
///         storage side effect of a prior Type 1 (Type 2).
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

    /// @notice Emitted when a JARDIN slot is registered.
    event JardinSlotRegistered(bytes32 indexed slotKey, bytes32 indexed subVkHash);

    /// @notice Emitted on every successful Type 1 bootstrap C10 signature,
    ///         carrying the post-increment counter value so off-chain tools
    ///         can track exhaustion without re-scanning storage.
    event BootstrapKeyUsed(uint256 indexed newCount);

    /// @notice Emitted on every successful Type 2 slot-C10 signature,
    ///         carrying the post-increment per-slot counter so off-chain
    ///         tools can see how close each slot is to its cap without
    ///         re-scanning storage.
    event SlotKeyUsed(bytes32 indexed slotKey, uint256 indexed newCount);

    /// @notice Emitted when a JARDIN slot is revoked via
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

    /// @notice Number of successful Type 1 bootstrap C10 signatures the
    ///         wallet has accepted on this chain. Read-only view.
    function bootstrapUses() public view virtual returns (uint256) {
        return _getStorage().bootstrapUses;
    }

    /// @notice Number of successful Type 2 signatures this slot has
    ///         produced. Read-only view — the companion uses it to decide
    ///         when to rotate to `slot_index + 1` before the per-slot cap
    ///         is hit.
    /// @param slotKey The on-chain slot key H(r).
    function slotUses(bytes32 slotKey) public view virtual returns (uint256) {
        return _getStorage().slotUses[slotKey];
    }

    /// @notice Register or idempotently re-confirm a JARDIN slot's sub-key.
    ///
    ///         Called by `validateUserOp` inside `_validateSignature` as a
    ///         side effect of Type 1 verification. Non-re-entrant by virtue
    ///         of EntryPoint's single-entry UserOp dispatch.
    ///
    /// @param slotKey   SHA-256 hash of the slot randomiser `r`.
    /// @param subVkHash SHA-256 hash of `subPkSeed || subPkRoot`.
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
    ///         authorised by the bootstrap C10 identity (Type 1) OR by a
    ///         live registered slot (Type 2). The public authorisation
    ///         gate is on `PQJardinWallet.revokeJardinSlot`, which
    ///         forwards here.
    /// @param slotKey Slot identifier (`sha256(r)`) to revoke.
    function _revokeJardinSlot(bytes32 slotKey) internal {
        PQSignerStorage storage $ = _getStorage();
        bytes32 prev = $.jardinSlots[slotKey];
        if (prev != bytes32(0)) {
            delete $.jardinSlots[slotKey];
            emit JardinSlotRevoked(slotKey, prev);
        }
    }

    /// @notice Bump the bootstrap-use counter after a successful Type 1
    ///         signature. Reverts via `require` if the counter would exceed
    ///         `cap`; the caller (`PQJardinWallet`) passes
    ///         `MAX_BOOTSTRAP_USES` so the cap lives as a wallet-level
    ///         invariant and the storage layer remains policy-free.
    /// @param cap Maximum number of Type 1 signatures allowed on this chain.
    /// @return newCount Post-increment counter value.
    function _bumpBootstrapUses(uint256 cap) internal returns (uint256 newCount) {
        PQSignerStorage storage $ = _getStorage();
        uint256 next = $.bootstrapUses + 1;
        require(next <= cap, "bootstrap exhausted");
        $.bootstrapUses = next;
        emit BootstrapKeyUsed(next);
        return next;
    }

    /// @notice Bump the per-slot use counter after a successful Type 2
    ///         slot-C10 signature. Reverts via `require` if the counter
    ///         would exceed `cap`; the caller (`PQJardinWallet`) passes
    ///         `MAX_SLOT_USES` so the cap lives as a wallet-level
    ///         invariant and the storage layer remains policy-free.
    /// @param  slotKey  Slot identifier being bumped.
    /// @param  cap      Maximum number of Type 2 signatures allowed per slot.
    /// @return newCount Post-increment counter value.
    function _bumpSlotUses(bytes32 slotKey, uint256 cap) internal returns (uint256 newCount) {
        PQSignerStorage storage $ = _getStorage();
        uint256 next = $.slotUses[slotKey] + 1;
        require(next <= cap, "slot exhausted");
        $.slotUses[slotKey] = next;
        emit SlotKeyUsed(slotKey, next);
        return next;
    }

    /// @dev ERC-7201 storage accessor.
    function _getStorage() internal pure returns (PQSignerStorage storage $) {
        bytes32 slot = _PQ_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
