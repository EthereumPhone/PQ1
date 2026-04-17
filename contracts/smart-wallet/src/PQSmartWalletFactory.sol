// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {PQSmartWallet} from "./PQSmartWallet.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQSmartWalletFactory
///
/// @notice Deterministic CREATE2 factory for `PQSmartWallet`. The salt is
///         `sha256(masterPkSeed || masterPkRoot)`, so the same 24-word
///         seed maps to the same wallet address on every EVM chain.
///
///         The **front-running defence** is the `factorySig` argument:
///         because the bootstrap pubkey is public (it appears on every
///         UserOp), an attacker could otherwise call this factory on a
///         chain the victim has not yet deployed on, supplying *their
///         own* slot-0 pubkey and capturing the victim's wallet address.
///         Requiring a C10 signature by the bootstrap key over
///         `sha256(DOMAIN || chainId || slot0)` prevents that: the
///         attacker lacks the bootstrap sk and cannot forge the sig.
///
/// @author PQSigner OS
contract PQSmartWalletFactory {
    IEntryPoint public immutable entryPoint;
    ISPHINCSVerifier public immutable c10Verifier;

    /// @notice Domain tag prefixed to the `factorySig` message. Any change
    ///         to this constant MUST be mirrored in the firmware's
    ///         `crypto.rs::factory_add_slot0_digest` helper.
    bytes constant FACTORY_ADD_SLOT_DOMAIN = "pqwallet-factory-add-slot";

    event AccountCreated(
        address indexed account,
        bytes32 indexed masterPkSeed,
        bytes32 indexed masterPkRoot,
        uint64 chainId
    );

    error WrongChainId(uint64 expected, uint64 supplied);
    error InvalidFactorySignature();
    error InvalidSlot0Length(uint256 length);

    constructor(IEntryPoint ep, ISPHINCSVerifier c10) {
        entryPoint = ep;
        c10Verifier = c10;
    }

    /// @notice Deploy the wallet at its deterministic CREATE2 address, or
    ///         return the existing deployment if the address is already
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
    ) external returns (PQSmartWallet account) {
        if (chainId != block.chainid) revert WrongChainId(uint64(block.chainid), chainId);

        address predicted = getAddress(masterPkSeed, masterPkRoot);
        if (predicted.code.length > 0) {
            return PQSmartWallet(payable(predicted));
        }

        // 1) Verify the bootstrap signature authorising slot-0 on THIS chain.
        bytes32 digest = addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot);
        bool ok;
        try c10Verifier.verify(masterPkSeed, masterPkRoot, digest, factorySig) returns (bool v) {
            ok = v;
        } catch {
            ok = false;
        }
        if (!ok) revert InvalidFactorySignature();

        // 2) CREATE2 deploy — address is determined purely by the two
        //    master-key args and this factory's address.
        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        account = new PQSmartWallet{salt: salt}(entryPoint, c10Verifier, masterPkSeed, masterPkRoot);

        // 3) Add slot-0 owner at index 1.
        bytes memory slot0Bytes = abi.encodePacked(slot0PkSeed, slot0PkRoot);
        account.initialize(slot0Bytes);

        emit AccountCreated(address(account), masterPkSeed, masterPkRoot, chainId);
    }

    /// @notice Predict the deterministic address for a bootstrap keypair.
    ///         Slot-0 / chainId do NOT feed into the address.
    function getAddress(bytes32 masterPkSeed, bytes32 masterPkRoot)
        public
        view
        returns (address)
    {
        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(PQSmartWallet).creationCode,
                abi.encode(entryPoint, c10Verifier, masterPkSeed, masterPkRoot)
            )
        );
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash));
        return address(uint160(uint256(h)));
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
