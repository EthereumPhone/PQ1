// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";

/// @notice Controllable mock for wallet tests. The real SphincsC7Asm verifier
///         is tested separately with genuine test vectors.
contract MockSPHINCSVerifier is ISPHINCSVerifier {
    bool public shouldVerify;

    constructor(bool shouldVerify_) {
        shouldVerify = shouldVerify_;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }

    function verify(bytes32, bytes32, bytes32, bytes calldata) external view override returns (bool) {
        return shouldVerify;
    }
}
