// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @notice ERC-7201 storage layout for the two-tier PQ signer architecture.
///
/// @custom:storage-location erc7201:pqsigner.storage.PQOwnable
struct PQSignerStorage {
    /// @dev Keccak256 hash of the bootstrap public key (pkSeed || pkRoot).
    ///      Set at init, immutable for the lifetime of the wallet.
    ///      The bootstrap key is global (not per-chain) and never rotates.
    bytes32 bootstrapPubKeyHash;

    /// @dev Current main signer epoch index. Starts at 0, increments by 1
    ///      on every rotation. Per-chain — each chain's deployed wallet
    ///      tracks its own epoch independently.
    uint32 currentKeyIndex;

    /// @dev Keccak256 hash of the current main signer's public key
    ///      (pkSeed || pkRoot). Updated on every rotation via `rotateMainSigner`.
    bytes32 currentMainPubKeyHash;

    /// @dev Next unused OTS leaf index for the current main key. Incremented
    ///      atomically with each successful main-signer signature validation.
    ///      Reset to 0 on every rotation.
    uint32 currentOTSIndex;

    /// @dev Next unused OTS leaf index for the bootstrap key. Incremented
    ///      atomically with each successful bootstrap-signer UserOp validation.
    ///      Never reset (bootstrap key never rotates).
    uint32 bootstrapOTSIndex;

    /// @dev `true` once the account has been initialised.
    bool initialized;

    /// @dev JARDIN FORS+C slot registry: H(r) => H(subPkSeed || subPkRoot).
    ///      Each slot supports up to 95 compact signatures before rotation.
    mapping(bytes32 => bytes32) jardinSlots;
}

/// @title PQOwnable
///
/// @notice Two-tier signer authentication for the post-quantum smart wallet.
///         Replaces the upstream `MultiOwnable.sol` from coinbase/smart-wallet.
///
///         The wallet has two classes of signer, both derived from the same
///         BIP-39 seed:
///
///         - **Bootstrap signer**: a single, stateful hash-based PQ keypair
///           used for administrative operations (initial deployment, main
///           signer rotation). Never rotates. OTS-tracked per wallet.
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

    /// @notice Emitted on every successful bootstrap-signer UserOp validation.
    event BootstrapOTSConsumed(uint32 indexed otsIndex);

    /// @notice Emitted when a JARDIN FORS+C slot is registered.
    event JardinSlotRegistered(bytes32 indexed slotKey, bytes32 indexed subVkHash);

    /// @notice Reverts unless `msg.sender` is the account itself.
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }

    /// @notice Returns the keccak256 commitment to the bootstrap public key.
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

    /// @notice Returns the next unused OTS index for the bootstrap key.
    function bootstrapOTSIndex() public view virtual returns (uint32) {
        return _getStorage().bootstrapOTSIndex;
    }

    /// @notice Returns whether the wallet has been initialised.
    function isInitialized() public view virtual returns (bool) {
        return _getStorage().initialized;
    }

    /// @notice Verify that (pkSeed, pkRoot) matches the bootstrap key commitment.
    function isBootstrapKey(bytes32 pkSeed, bytes32 pkRoot) public view virtual returns (bool) {
        return keccak256(abi.encodePacked(pkSeed, pkRoot)) == _getStorage().bootstrapPubKeyHash;
    }

    /// @notice Verify that (pkSeed, pkRoot) matches the current main signer commitment.
    function isMainKey(bytes32 pkSeed, bytes32 pkRoot) public view virtual returns (bool) {
        return keccak256(abi.encodePacked(pkSeed, pkRoot)) == _getStorage().currentMainPubKeyHash;
    }

    /// @notice Look up a JARDIN FORS+C slot commitment.
    /// @param slotKey The slot key H(r).
    /// @return The stored sub-VK hash, or bytes32(0) if unregistered.
    function jardinSlot(bytes32 slotKey) public view virtual returns (bytes32) {
        return _getStorage().jardinSlots[slotKey];
    }

    /// @notice One-shot initialiser. Called by the factory immediately
    ///         after the proxy is deployed.
    ///
    /// @param bootstrapPubKeyHash_ Keccak256 hash of the bootstrap public key (pkSeed || pkRoot).
    /// @param initialMainPubKeyHash_ Keccak256 hash of the initial main signer (pkSeed || pkRoot).
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
        $.bootstrapOTSIndex = 0;
        $.initialized = true;
        emit WalletInitialized(bootstrapPubKeyHash_, initialMainPubKeyHash_);
    }

    /// @notice Rotate the main signer to the next epoch. Called via
    ///         `execute(self, rotateMainSigner(...))` — authorization
    ///         happens in `validateUserOp` (either main or bootstrap path).
    ///
    /// @param newKeyIndex Must be `currentKeyIndex + 1` (sequential only).
    /// @param newMainPubKeyHash Keccak256 hash of the new main signer's
    ///        public key (pkSeed || pkRoot).
    function _rotateMainSigner(
        uint32 newKeyIndex,
        bytes32 newMainPubKeyHash
    ) internal virtual {
        PQSignerStorage storage $ = _getStorage();
        require(newKeyIndex == $.currentKeyIndex + 1, "sequential only");

        $.currentKeyIndex = newKeyIndex;
        $.currentMainPubKeyHash = newMainPubKeyHash;
        $.currentOTSIndex = 0;

        emit MainSignerRotated(newKeyIndex, newMainPubKeyHash);
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

    /// @notice Consume a bootstrap OTS index atomically with signature
    ///         validation.
    function _consumeBootstrapOTS(uint32 expectedOTSIndex) internal virtual returns (uint32) {
        PQSignerStorage storage $ = _getStorage();
        require(expectedOTSIndex == $.bootstrapOTSIndex, "wrong bootstrap ots index");
        require(expectedOTSIndex <= MAX_OTS_INDEX, "bootstrap key exhausted");

        uint32 consumed = $.bootstrapOTSIndex;
        $.bootstrapOTSIndex = consumed + 1;

        emit BootstrapOTSConsumed(consumed);
        return consumed;
    }

    /// @notice Register a JARDIN FORS+C slot. Called via
    ///         `execute(self, registerJardinSlot(...))` — authorization
    ///         happens in `validateUserOp` (main or bootstrap path).
    ///
    /// @param slotKey Keccak256 hash of the slot randomizer r.
    /// @param subVkHash Keccak256 hash of (subPkSeed || subPkRoot).
    function _registerJardinSlot(
        bytes32 slotKey,
        bytes32 subVkHash
    ) internal virtual {
        PQSignerStorage storage $ = _getStorage();
        require($.jardinSlots[slotKey] == bytes32(0), "slot exists");
        $.jardinSlots[slotKey] = subVkHash;
        emit JardinSlotRegistered(slotKey, subVkHash);
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
