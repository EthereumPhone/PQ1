// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {LibClone} from "solady/utils/LibClone.sol";

import {PQCoinbaseSmartWallet} from "./PQCoinbaseSmartWallet.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQCoinbaseSmartWalletFactory
///
/// @notice ERC-4337 factory that deploys ERC-1967 proxies pointing at a
///         {PQCoinbaseSmartWallet} implementation. The CREATE2 salt is
///         derived solely from the bootstrap public key, so the same
///         bootstrap key produces the same wallet address on every chain.
///
///         Deployment is gated by a bootstrap signature over the initial
///         main signer, preventing front-runners from deploying a wallet
///         with a rogue main signer on a chain the user hasn't touched yet.
///
///         The bootstrap signature is intentionally chain-agnostic (no
///         chainId in the signed message) so the user can produce ONE
///         bootstrap signature and reuse it on every chain.
///
/// @author PQSigner OS (forked from coinbase/smart-wallet)
contract PQCoinbaseSmartWalletFactory {
    /// @notice The implementation contract every proxy delegates to.
    address public immutable implementation;

    /// @notice The shared SPHINCS+C7 verifier used to check bootstrap
    ///         signatures during deployment.
    ISPHINCSVerifier public immutable verifier;

    /// @notice Emitted when a new account is deployed.
    event WalletDeployed(
        address indexed account,
        bytes32 indexed bootstrapPubKeyHash
    );

    /// @notice Thrown when constructor is given an undeployed implementation.
    error ImplementationUndeployed();

    /// @notice Thrown when the bootstrap signature over the initial main
    ///         signer is invalid.
    error InvalidBootstrapSignature();

    constructor(address implementation_, ISPHINCSVerifier verifier_) payable {
        if (implementation_.code.length == 0) revert ImplementationUndeployed();
        implementation = implementation_;
        verifier = verifier_;
    }

    /// @notice Deploy (or fetch the existing) PQ wallet for the given
    ///         bootstrap key.
    ///
    /// @param bootstrapPkSeed   Bootstrap public key seed.
    /// @param bootstrapPkRoot   Bootstrap hypertree root.
    /// @param mainPkSeed        Initial main signer public key seed.
    /// @param mainPkRoot        Initial main signer hypertree root.
    /// @param bootstrapSig      Bootstrap signature over
    ///                          `keccak256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)`.
    ///                          Chain-agnostic — intentionally replayable.
    function createAccount(
        bytes32 bootstrapPkSeed,
        bytes32 bootstrapPkRoot,
        bytes32 mainPkSeed,
        bytes32 mainPkRoot,
        bytes calldata bootstrapSig
    )
        external
        payable
        virtual
        returns (PQCoinbaseSmartWallet account)
    {
        // Verify the bootstrap signature authorizes this initial main signer.
        bytes32 authMsg = keccak256(abi.encodePacked("PQWALLET_INIT_V1", mainPkSeed, mainPkRoot));
        if (!verifier.verify(bootstrapPkSeed, bootstrapPkRoot, authMsg, bootstrapSig)) {
            revert InvalidBootstrapSignature();
        }

        bytes32 salt = keccak256(abi.encodePacked(bootstrapPkSeed, bootstrapPkRoot));
        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, salt);

        account = PQCoinbaseSmartWallet(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(bootstrapPkSeed, bootstrapPkRoot, mainPkSeed, mainPkRoot);
            emit WalletDeployed(
                address(account),
                keccak256(abi.encodePacked(bootstrapPkSeed, bootstrapPkRoot))
            );
        }
    }

    /// @notice CREATE2 address prediction. Same inputs produce the same
    ///         address on every chain where this factory is deployed at the
    ///         same address with the same implementation.
    function getAddress(bytes32 bootstrapPkSeed, bytes32 bootstrapPkRoot) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(bootstrapPkSeed, bootstrapPkRoot));
        return LibClone.predictDeterministicAddress(initCodeHash(), salt, address(this));
    }

    /// @notice ERC-1967 proxy init code hash.
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }
}
