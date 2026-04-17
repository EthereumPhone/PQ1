// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {LibClone} from "solady/utils/LibClone.sol";

import {PQSmartWallet} from "./PQSmartWallet.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQSmartWalletFactory
///
/// @notice Deterministic ERC-1967 proxy factory for `PQSmartWallet`. The
///         factory CREATE2s a ~55-byte proxy that delegate-calls to the
///         shared `implementation` (deployed once per chain). Per-user
///         deploy cost drops from ~1.1 M gas (direct contract deploy) to
///         ~50 k gas (cheap proxy stub).
///
///         The CREATE2 salt is `sha256(masterPkSeed || masterPkRoot)`, so
///         the same bootstrap keypair maps to the same wallet address on
///         every chain **provided the factory and implementation are
///         deployed at the same addresses on every chain** (achievable via
///         a singleton deployer like Safe's).
///
///         **Front-running defence**: because the bootstrap pubkey is
///         public and the salt depends only on it, an attacker could
///         otherwise squat the victim's address on a chain they have not
///         yet deployed on, installing the attacker's own slot-0 signer.
///         Requiring a bootstrap-key C10 signature over
///         `sha256(DOMAIN || chainId || slot0)` closes that hole — the
///         attacker lacks the bootstrap sk and cannot forge it.
///
/// @author PQSigner OS
contract PQSmartWalletFactory {
    /// @notice The shared `PQSmartWallet` implementation. Every proxy
    ///         delegate-calls to this address.
    address public immutable implementation;

    /// @notice Stateless SPHINCS+C10 verifier used to check `factorySig`.
    ISPHINCSVerifier public immutable c10Verifier;

    /// @notice Domain tag prefixed to the `factorySig` message. Must match
    ///         the firmware's `factory_add_slot0_digest` helper.
    bytes constant FACTORY_ADD_SLOT_DOMAIN = "pqwallet-factory-add-slot";

    event AccountCreated(
        address indexed account,
        bytes32 indexed masterPkSeed,
        bytes32 indexed masterPkRoot,
        uint64 chainId
    );

    error ImplementationUndeployed();
    error WrongChainId(uint64 expected, uint64 supplied);
    error InvalidFactorySignature();

    constructor(address impl, ISPHINCSVerifier c10) {
        if (impl.code.length == 0) revert ImplementationUndeployed();
        implementation = impl;
        c10Verifier = c10;
    }

    /// @notice Deploy the user's wallet proxy at its deterministic CREATE2
    ///         address, or return the existing deployment if already
    ///         populated.
    ///
    /// @param masterPkSeed   Bootstrap pubkey seed (N-mask layout).
    /// @param masterPkRoot   Bootstrap pubkey root (N-mask layout).
    /// @param slot0PkSeed    Slot-0 (ownerIndex 1) pubkey seed.
    /// @param slot0PkRoot    Slot-0 (ownerIndex 1) pubkey root.
    /// @param chainId        Target chain (MUST equal `block.chainid`).
    /// @param factorySig     SPHINCS+C10 sig by `masterPk*` over
    ///                       `sha256(DOMAIN || chainId || slot0PkSeed || slot0PkRoot)`.
    function createAccount(
        bytes32 masterPkSeed,
        bytes32 masterPkRoot,
        bytes32 slot0PkSeed,
        bytes32 slot0PkRoot,
        uint64 chainId,
        bytes calldata factorySig
    ) external payable returns (PQSmartWallet account) {
        if (chainId != block.chainid) revert WrongChainId(uint64(block.chainid), chainId);

        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        address predicted = LibClone.predictDeterministicAddressERC1967(implementation, salt, address(this));

        if (predicted.code.length > 0) {
            return PQSmartWallet(payable(predicted));
        }

        // Squat defence: verify bootstrap authorised this slot-0 on this chain.
        bytes32 digest = addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot);
        bool ok;
        try c10Verifier.verify(masterPkSeed, masterPkRoot, digest, factorySig) returns (bool v) {
            ok = v;
        } catch {
            ok = false;
        }
        if (!ok) revert InvalidFactorySignature();

        // CREATE2 the ERC-1967 proxy stub (always succeeds here — we
        // already handled the `alreadyDeployed` branch above).
        (, address deployed) = LibClone.createDeterministicERC1967(msg.value, implementation, salt);
        account = PQSmartWallet(payable(deployed));

        // Initialise atomically — no front-runner window between
        // CREATE2 and this call.
        bytes memory bootstrapBytes = abi.encodePacked(masterPkSeed, masterPkRoot);
        bytes memory slot0Bytes = abi.encodePacked(slot0PkSeed, slot0PkRoot);
        account.initialize(bootstrapBytes, slot0Bytes);

        emit AccountCreated(deployed, masterPkSeed, masterPkRoot, chainId);
    }

    /// @notice Predict the deterministic wallet address. Chain-independent
    ///         provided the factory + impl are deployed at the same
    ///         addresses on every chain.
    function getAddress(bytes32 masterPkSeed, bytes32 masterPkRoot)
        public
        view
        returns (address)
    {
        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        return LibClone.predictDeterministicAddressERC1967(implementation, salt, address(this));
    }

    /// @notice SHA-256 digest the firmware signs to authorise slot-0 on a
    ///         given chain.
    function addSlot0Digest(uint64 chainId, bytes32 slot0PkSeed, bytes32 slot0PkRoot)
        public
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(FACTORY_ADD_SLOT_DOMAIN, chainId, slot0PkSeed, slot0PkRoot));
    }

    function _salt(bytes32 masterPkSeed, bytes32 masterPkRoot) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(masterPkSeed, masterPkRoot));
    }
}
