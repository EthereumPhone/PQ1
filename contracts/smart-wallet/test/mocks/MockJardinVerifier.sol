// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IJardinVerifier} from "../../src/verifiers/IJardinVerifier.sol";

/// @notice Controllable mock for wallet tests. The real
///         `JardinForsCVerifier` is tested separately with genuine
///         signature test vectors; this mock exists so the wallet
///         dispatcher tests can focus on control flow.
///
///         M14 guard: the constructor reverts on any non-local
///         chain id, so accidentally deploying this mock as a live
///         verifier on mainnet / a real testnet bricks at deploy
///         time rather than silently returning `true` for every
///         signature. Foundry local chain ids (31337, 1337) are
///         permitted.
contract MockJardinVerifier is IJardinVerifier {
    bool public valid;

    error MockNotAllowedOnChain(uint256 chainId);

    constructor() {
        uint256 cid = block.chainid;
        if (cid != 31337 && cid != 1337 && cid != 0) {
            revert MockNotAllowedOnChain(cid);
        }
    }

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
