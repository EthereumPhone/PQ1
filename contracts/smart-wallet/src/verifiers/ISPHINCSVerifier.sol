// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title ISPHINCSVerifier
/// @notice Interface for SPHINCS+C keccak256-based signature verification.
///         The public key is split into (pkSeed, pkRoot) — two bytes32 values.
///         Signature format and size depend on the variant (C6, C7, etc.).
interface ISPHINCSVerifier {
    /// @param pkSeed The public key seed (top 128 bits used, n=128).
    /// @param pkRoot The hypertree root commitment.
    /// @param message The 32-byte message hash to verify against.
    /// @param sig The raw signature bytes.
    /// @return valid True if the signature is valid.
    function verify(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external view returns (bool valid);
}
