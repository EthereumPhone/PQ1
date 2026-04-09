// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @title ISLHDSAVerifier
///
/// @notice Pluggable verifier interface for SLH-DSA-SHA2-128f
///         (FIPS-205 stateless hash-based signature scheme, parameter
///         set `SLH-DSA-SHA2-128f`).
///
/// @dev    The interface is intentionally minimal so that the on-chain
///         account does not need to know whether the verifier is the
///         reference Solidity implementation, a precompile (once one
///         lands in an EVM upgrade), or a ZK-wrapped Groth16 verifier
///         that proves an off-chain SLH-DSA verification.
///
///         Implementations MUST be deterministic and side-effect-free.
///         The PQ smart wallet treats a successful return value of
///         `true` as the *only* signal that the signature is valid; any
///         revert is treated as a verification failure.
interface ISLHDSAVerifier {
    /// @notice Verify a SLH-DSA-SHA2-128f signature against `msgHash`.
    ///
    /// @param pk        The 32-byte verifying key.
    /// @param msgHash   The 32-byte message digest the signature was
    ///                  produced over. The wallet always passes the
    ///                  ERC-4337 `userOpHash` here.
    /// @param signature The 17,088-byte SLH-DSA signature.
    ///
    /// @return ok `true` iff the signature verifies.
    function verify(bytes calldata pk, bytes32 msgHash, bytes calldata signature)
        external
        view
        returns (bool ok);
}
