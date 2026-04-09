// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ISLHDSAVerifier} from "../../src/verifiers/ISLHDSAVerifier.sol";

/// @notice Controllable mock for wallet tests. The real SLHDSAVerifier is
///         tested separately with genuine FIPS-205 test vectors.
contract MockSLHDSAVerifier is ISLHDSAVerifier {
    bool public shouldVerify;

    constructor(bool shouldVerify_) {
        shouldVerify = shouldVerify_;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }

    function verify(bytes calldata, bytes32, bytes calldata) external view override returns (bool) {
        return shouldVerify;
    }
}
