// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";

/// @notice Controllable mock for wallet tests. The real `SPHINCsC11Asm`
///         verifier is tested separately with genuine signature vectors;
///         this mock exists so the wallet dispatcher tests can focus on
///         control flow.
contract MockSPHINCSVerifier is ISPHINCSVerifier {
    bool public valid;

    function setValid(bool v) external {
        valid = v;
    }

    function verify(bytes32, bytes32, bytes32, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        return valid;
    }
}
