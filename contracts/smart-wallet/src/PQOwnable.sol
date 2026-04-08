// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice ERC-7201 storage layout for {PQOwnable}.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQOwnable
struct PQOwnableStorage {
    /// @dev SHA-256 hash of the SLH-DSA-SHA2-128f public key (32 bytes)
    ///      of the *single* owner of this account. Stored as the hash so
    ///      a future verifier upgrade can swap to a different commitment
    ///      scheme without rotating storage layout, and so initial
    ///      deployment calldata stays a fixed 32 bytes regardless of the
    ///      raw key length.
    ///
    ///      We deliberately don't store the raw 32-byte verifying key in
    ///      storage — `validateUserOp` always receives it as part of
    ///      `UserOperation.signature` and re-checks the commitment, so
    ///      the storage slot is the trust root and the key bytes ride
    ///      with the signature.
    bytes32 ownerKeyHash;
    /// @dev `true` once the account has been initialised. We can't use
    ///      "ownerKeyHash != 0" because the SLH-DSA pubkey hash is
    ///      adversarially chosen and could in theory be all-zero.
    bool initialized;
}

/// @title PQOwnable
///
/// @notice Single-owner authentication scheme for the post-quantum
///         smart wallet. Replaces the upstream `MultiOwnable.sol` from
///         coinbase/smart-wallet, which supported a mix of secp256k1
///         EOA and WebAuthn (P-256) owners. Both classical schemes are
///         intentionally removed: a quantum adversary can recover any
///         classical private key from a public key in polynomial time,
///         so accepting a fallback EOA owner would let an adversary
///         drain the wallet regardless of the SPHINCS+ root.
///
///         The single owner is identified by `sha256(pk_slhdsa)` and
///         can never be removed or rotated to a non-PQ scheme. The
///         design choice is "PQ-only or nothing": there is no
///         multi-owner storage, no add/remove path, no fallback to a
///         classical curve, no recovery via guardian addresses.
///
/// @author PQSigner OS
abstract contract PQOwnable {
    /// @dev keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQOwnable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PQ_OWNABLE_STORAGE_LOCATION =
        0xf3a1a4cdfe9d5bd1e7c1f3e3d6c8f7a3b2f6c9d1e2a4b6c8d0e2f4a6b8c0d200;

    /// @notice Thrown when a non-owner attempts a privileged call.
    error Unauthorized();

    /// @notice Thrown when initialize is called more than once.
    error AlreadyInitialized();

    /// @notice Thrown when initialize is called with a zero owner-key hash.
    error InvalidOwnerKeyHash();

    /// @notice Emitted exactly once during {_initializeOwner}.
    event OwnerInitialized(bytes32 indexed ownerKeyHash);

    /// @notice Reverts unless `msg.sender` is the account itself.
    ///
    /// @dev Because the only owner is a SPHINCS+ key — which has no
    ///      Ethereum address — the only way for the owner to call a
    ///      privileged method is via a self-call routed through
    ///      `EntryPoint → validateUserOp → execute(self, …)`. This
    ///      modifier therefore collapses to "msg.sender == address(this)".
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @notice Returns the SHA-256 commitment to the SLH-DSA public key
    ///         that authorises this account.
    ///
    /// @return The 32-byte commitment.
    function ownerKeyHash() public view virtual returns (bytes32) {
        return _getStorage().ownerKeyHash;
    }

    /// @notice Returns whether the wallet has been initialised with an owner.
    function isInitialized() public view virtual returns (bool) {
        return _getStorage().initialized;
    }

    /// @notice Verify that `pk` matches the commitment stored at deploy
    ///         time.
    ///
    /// @param pk The 32-byte SLH-DSA-SHA2-128f verifying key.
    ///
    /// @return `true` if `sha256(pk) == ownerKeyHash`.
    function isOwnerKey(bytes calldata pk) public view virtual returns (bool) {
        return sha256(pk) == _getStorage().ownerKeyHash;
    }

    /// @notice One-shot initialiser. Called by the factory immediately
    ///         after the proxy is deployed.
    ///
    /// @dev Must be called with the SHA-256 hash of the SLH-DSA public
    ///      key, *not* the public key itself. The factory is the trust
    ///      anchor for this commitment — it derives the address of the
    ///      proxy from `keccak256(pkHash, salt)`, so the on-chain
    ///      address is bound to the same commitment.
    function _initializeOwner(bytes32 pkHash) internal virtual {
        PQOwnableStorage storage $ = _getStorage();
        if ($.initialized) revert AlreadyInitialized();
        if (pkHash == bytes32(0)) revert InvalidOwnerKeyHash();
        $.ownerKeyHash = pkHash;
        $.initialized = true;
        emit OwnerInitialized(pkHash);
    }

    /// @notice Reverts unless the caller is the account itself.
    function _checkOwner() internal view virtual {
        if (msg.sender != address(this)) revert Unauthorized();
    }

    /// @dev ERC-7201 storage accessor.
    function _getStorage() internal pure returns (PQOwnableStorage storage $) {
        bytes32 slot = _PQ_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
