// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IJardinVerifier} from "../../src/verifiers/IJardinVerifier.sol";

/// @notice Controllable mock for wallet tests. The real
///         `JardinForsCVerifier` is tested separately with genuine
///         signature test vectors; this mock exists so the wallet
///         dispatcher tests can focus on control flow.
contract MockJardinVerifier is IJardinVerifier {
    bool public valid;

    function setValid(bool v) external {
        valid = v;
    }

    function verifyForsCUnbalanced(bytes32, bytes32, bytes32, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        return valid;
    }
}
