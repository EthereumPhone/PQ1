// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IJardinVerifier
/// @notice Interface for JARDIN FORS+C compact signature verification.
///         The public key is split into (pkSeed, pkRoot) — two bytes32 values
///         where only the top 128 bits are used (n=128-bit security).
///         Signature length is variable: 2452 + q*16 bytes, where q (the leaf
///         index) is derived from the signature length itself.
interface IJardinVerifier {
    /// @param pkSeed The sub-key public seed (top 128 bits used, n=128).
    /// @param pkRoot The unbalanced tree root commitment.
    /// @param message The 32-byte message hash to verify against.
    /// @param sig The raw FORS+C signature bytes (2468..3972 bytes).
    /// @return valid True if the signature is valid.
    function verifyForsCUnbalanced(
        bytes32 pkSeed,
        bytes32 pkRoot,
        bytes32 message,
        bytes calldata sig
    ) external view returns (bool valid);
}
