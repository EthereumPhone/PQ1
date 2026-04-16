// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {PQJardinWallet} from "./PQJardinWallet.sol";
import {IJardinVerifier} from "./verifiers/IJardinVerifier.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

/// @title PQJardinWalletFactory
///
/// @notice Deterministic CREATE2 factory for `PQJardinWallet` accounts.
///         Same `(masterPkSeed, masterPkRoot)` → same address on every
///         chain. This is the on-chain half of the recovery contract:
///         a user who reinstates their 24-word mnemonic on a new device
///         lands at the same wallet address.
contract PQJardinWalletFactory {
    IEntryPoint public immutable entryPoint;
    ISPHINCSVerifier public immutable c11Verifier;
    IJardinVerifier public immutable forscVerifier;

    event AccountCreated(
        address indexed account,
        bytes32 indexed masterPkSeed,
        bytes32 indexed masterPkRoot
    );

    constructor(IEntryPoint ep, ISPHINCSVerifier c11, IJardinVerifier forsc) {
        entryPoint = ep;
        c11Verifier = c11;
        forscVerifier = forsc;
    }

    /// @notice Deploy the wallet at its deterministic CREATE2 address, or
    ///         return the existing deployment if the address is already
    ///         populated.
    ///
    /// @param masterPkSeed Top 16 bytes populated, bottom 16 zero
    ///                     (matches the N-mask produced by the firmware).
    /// @param masterPkRoot Same N-mask layout.
    function createAccount(bytes32 masterPkSeed, bytes32 masterPkRoot)
        external
        returns (PQJardinWallet)
    {
        address predicted = getAddress(masterPkSeed, masterPkRoot);
        if (predicted.code.length > 0) {
            return PQJardinWallet(payable(predicted));
        }
        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        PQJardinWallet acc = new PQJardinWallet{salt: salt}(
            entryPoint, c11Verifier, forscVerifier, masterPkSeed, masterPkRoot
        );
        emit AccountCreated(address(acc), masterPkSeed, masterPkRoot);
        return acc;
    }

    /// @notice Predict the deterministic address for a given master key.
    function getAddress(bytes32 masterPkSeed, bytes32 masterPkRoot)
        public
        view
        returns (address)
    {
        bytes32 salt = _salt(masterPkSeed, masterPkRoot);
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(PQJardinWallet).creationCode,
                abi.encode(entryPoint, c11Verifier, forscVerifier, masterPkSeed, masterPkRoot)
            )
        );
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash));
        return address(uint160(uint256(h)));
    }

    function _salt(bytes32 masterPkSeed, bytes32 masterPkRoot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(masterPkSeed, masterPkRoot));
    }
}
