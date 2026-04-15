// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IJardinVerifier} from "../../src/verifiers/IJardinVerifier.sol";

/// @notice Controllable mock for wallet tests. The real JardinForsCVerifier
///         is tested separately with genuine test vectors.
contract MockJardinVerifier is IJardinVerifier {
    bool public shouldVerify;

    constructor(bool shouldVerify_) {
        shouldVerify = shouldVerify_;
    }

    function setShouldVerify(bool v) external {
        shouldVerify = v;
    }

    function verifyForsCUnbalanced(bytes32, bytes32, bytes32, bytes calldata) external view override returns (bool) {
        return shouldVerify;
    }
}
