// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {LibClone} from "solady/utils/LibClone.sol";

import {PQCoinbaseSmartWallet} from "./PQCoinbaseSmartWallet.sol";

/// @title PQCoinbaseSmartWalletFactory
///
/// @notice ERC-4337 factory that deploys ERC-1967 proxies pointing at
///         a {PQCoinbaseSmartWallet} implementation. The salt binds the
///         deployed address to the owner's SLH-DSA public-key hash and
///         a caller-supplied nonce, so the same SPHINCS+ key produces
///         the same wallet address on every chain.
///
/// @author PQSigner OS (forked from coinbase/smart-wallet)
contract PQCoinbaseSmartWalletFactory {
    /// @notice The implementation contract every proxy delegates to.
    address public immutable implementation;

    /// @notice Emitted when a new account is deployed.
    event AccountCreated(address indexed account, bytes32 indexed ownerKeyHash, uint256 nonce);

    /// @notice Thrown when constructor is given an undeployed implementation.
    error ImplementationUndeployed();

    /// @notice Thrown when the supplied owner-key hash is zero.
    error InvalidOwnerKeyHash();

    constructor(address implementation_) payable {
        if (implementation_.code.length == 0) revert ImplementationUndeployed();
        implementation = implementation_;
    }

    /// @notice Deploy (or fetch the existing) PQ wallet for the given
    ///         owner key hash and nonce.
    ///
    /// @param ownerKeyHash `sha256(slhdsa_pk)` of the wallet owner.
    /// @param nonce        Caller-defined value that allows the same
    ///                     owner to control multiple distinct wallets.
    function createAccount(bytes32 ownerKeyHash, uint256 nonce)
        external
        payable
        virtual
        returns (PQCoinbaseSmartWallet account)
    {
        if (ownerKeyHash == bytes32(0)) revert InvalidOwnerKeyHash();

        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _salt(ownerKeyHash, nonce));

        account = PQCoinbaseSmartWallet(payable(accountAddress));

        if (!alreadyDeployed) {
            emit AccountCreated(address(account), ownerKeyHash, nonce);
            account.initialize(ownerKeyHash);
        }
    }

    /// @notice CREATE2 prediction.
    function getAddress(bytes32 ownerKeyHash, uint256 nonce) external view returns (address) {
        return LibClone.predictDeterministicAddress(initCodeHash(), _salt(ownerKeyHash, nonce), address(this));
    }

    /// @notice ERC-1967 proxy init code hash.
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    function _salt(bytes32 ownerKeyHash, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(ownerKeyHash, nonce));
    }
}
