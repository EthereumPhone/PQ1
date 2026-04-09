// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice ERC-7201 storage layout for the two-tier PQ signer architecture.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQOwnable
struct PQSignerStorage {
    /// @dev SHA-256 hash of the bootstrap public key (ML-DSA-44 recommended,
    ///      SLH-DSA-SHA2-128f as interim). Set at init, immutable for the
    ///      lifetime of the wallet. The bootstrap key is global (not per-chain)
    ///      and never rotates.
    bytes32 bootstrapPubKeyHash;

    /// @dev Current main signer epoch index. Starts at 0, increments by 1
    ///      on every rotation. Per-chain — each chain's deployed wallet
    ///      tracks its own epoch independently.
    uint32 currentKeyIndex;

    /// @dev Keccak256 hash of the current main signer's public key.
    ///      Updated on every rotation via `rotateMainSigner`.
    bytes32 currentMainPubKeyHash;

    /// @dev Next unused OTS leaf index for the current main key. Incremented
    ///      atomically with each successful main-signer signature validation.
    ///      Reset to 0 on every rotation.
    uint32 currentOTSIndex;

    /// @dev `true` once the account has been initialised.
    bool initialized;
}

/// @title PQOwnable
///
/// @notice Two-tier signer authentication for the post-quantum smart wallet.
///         Replaces the upstream `MultiOwnable.sol` from coinbase/smart-wallet.
///
///         The wallet has two classes of signer, both derived from the same
///         BIP-39 seed:
///
///         - **Bootstrap signer**: a single, stateless PQ keypair used only
///           for administrative operations (initial deployment, emergency
///           rotation). Never rotates. One key for the lifetime of the wallet.
///
///         - **Main signer**: the active signing key for day-to-day transactions.
///           Stateful hash-based, rotates every ~1M signatures. Per-chain
///           and per-epoch.
///
///         Both classical-curve schemes are intentionally removed. A quantum
///         adversary can recover any classical private key from a public key
///         in polynomial time.
///
/// @author PQSigner OS
abstract contract PQOwnable {
    /// @dev keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQOwnable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PQ_OWNABLE_STORAGE_LOCATION =
        0xf3a1a4cdfe9d5bd1e7c1f3e3d6c8f7a3b2f6c9d1e2a4b6c8d0e2f4a6b8c0d200;

    /// @dev Maximum OTS index: 2^20 - 1 = 1,048,575 signatures per keypair.
    uint32 public constant MAX_OTS_INDEX = (1 << 20) - 1;

    /// @notice Thrown when a non-owner attempts a privileged call.
    error Unauthorized();

    /// @notice Thrown when initialize is called more than once.
    error AlreadyInitialized();

    /// @notice Thrown when initialize is called with a zero bootstrap key hash.
    error InvalidBootstrapKeyHash();

    /// @notice Emitted exactly once during initialization.
    event WalletInitialized(
        bytes32 indexed bootstrapPubKeyHash,
        bytes32 indexed initialMainPubKeyHash
    );

    /// @notice Emitted when the main signer is rotated to a new epoch.
    event MainSignerRotated(uint32 indexed newKeyIndex, bytes32 indexed newPubKeyHash);

    /// @notice Emitted on every successful main-signer signature validation.
    event OTSConsumed(uint32 indexed keyIndex, uint32 indexed otsIndex);

    /// @notice Reverts unless `msg.sender` is the account itself.
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @notice Returns the SHA-256 commitment to the bootstrap public key.
    function bootstrapPubKeyHash() public view virtual returns (bytes32) {
        return _getStorage().bootstrapPubKeyHash;
    }

    /// @notice Returns the current main signer epoch index.
    function currentKeyIndex() public view virtual returns (uint32) {
        return _getStorage().currentKeyIndex;
    }

    /// @notice Returns the keccak256 commitment to the current main signer's
    ///         public key.
    function currentMainPubKeyHash() public view virtual returns (bytes32) {
        return _getStorage().currentMainPubKeyHash;
    }

    /// @notice Returns the next unused OTS index for the current main key.
    function currentOTSIndex() public view virtual returns (uint32) {
        return _getStorage().currentOTSIndex;
    }

    /// @notice Returns whether the wallet has been initialised.
    function isInitialized() public view virtual returns (bool) {
        return _getStorage().initialized;
    }

    /// @notice Verify that `pk` matches the bootstrap key commitment.
    function isBootstrapKey(bytes calldata pk) public view virtual returns (bool) {
        return sha256(pk) == _getStorage().bootstrapPubKeyHash;
    }

    /// @notice Verify that `pk` matches the current main signer commitment.
    function isMainKey(bytes calldata pk) public view virtual returns (bool) {
        return keccak256(pk) == _getStorage().currentMainPubKeyHash;
    }

    /// @notice One-shot initialiser. Called by the factory immediately
    ///         after the proxy is deployed.
    ///
    /// @param bootstrapPubKeyHash_ SHA-256 hash of the bootstrap public key.
    /// @param initialMainPubKeyHash_ Keccak256 hash of the initial main signer.
    function _initializeOwner(
        bytes32 bootstrapPubKeyHash_,
        bytes32 initialMainPubKeyHash_
    ) internal virtual {
        PQSignerStorage storage $ = _getStorage();
        if ($.initialized) revert AlreadyInitialized();
        if (bootstrapPubKeyHash_ == bytes32(0)) revert InvalidBootstrapKeyHash();
        $.bootstrapPubKeyHash = bootstrapPubKeyHash_;
        $.currentKeyIndex = 0;
        $.currentMainPubKeyHash = initialMainPubKeyHash_;
        $.currentOTSIndex = 0;
        $.initialized = true;
        emit WalletInitialized(bootstrapPubKeyHash_, initialMainPubKeyHash_);
    }

    /// @notice Rotate the main signer to the next epoch. Called via
    ///         `execute(self, rotateMainSigner(...))` — authorization
    ///         happens in `validateUserOp` (either main or bootstrap path).
    ///
    /// @param newKeyIndex Must be `currentKeyIndex + 1` (sequential only).
    /// @param newMainPubKey The raw public key bytes of the new main signer.
    function _rotateMainSigner(
        uint32 newKeyIndex,
        bytes calldata newMainPubKey
    ) internal virtual {
        PQSignerStorage storage $ = _getStorage();
        require(newKeyIndex == $.currentKeyIndex + 1, "sequential only");

        $.currentKeyIndex = newKeyIndex;
        $.currentMainPubKeyHash = keccak256(newMainPubKey);
        $.currentOTSIndex = 0;

        emit MainSignerRotated(newKeyIndex, $.currentMainPubKeyHash);
    }

    /// @notice Consume an OTS index atomically with signature validation.
    ///         Returns the consumed index for event emission.
    function _consumeOTS(uint32 expectedOTSIndex) internal virtual returns (uint32) {
        PQSignerStorage storage $ = _getStorage();
        require(expectedOTSIndex == $.currentOTSIndex, "wrong ots index");
        require(expectedOTSIndex <= MAX_OTS_INDEX, "key exhausted");

        uint32 consumed = $.currentOTSIndex;
        $.currentOTSIndex = consumed + 1;

        emit OTSConsumed($.currentKeyIndex, consumed);
        return consumed;
    }

    /// @notice Reverts unless the caller is the account itself.
    function _checkOwner() internal view virtual {
        if (msg.sender != address(this)) revert Unauthorized();
    }

    /// @dev ERC-7201 storage accessor.
    function _getStorage() internal pure returns (PQSignerStorage storage $) {
        bytes32 slot = _PQ_OWNABLE_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := slot
        }
    }
}
