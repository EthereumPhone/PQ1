// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";

/// @notice Controllable mock for wallet tests. The real `SPHINCsC11Asm`
///         verifier is tested separately with genuine signature vectors;
///         this mock exists so the wallet dispatcher tests can focus on
///         control flow.
///
///         M14 guard: refuse to deploy on any non-local chain so an
///         accidental production use reverts at deploy time instead
///         of silently accepting every signature.
contract MockSPHINCSVerifier is ISPHINCSVerifier {
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

    function verify(bytes32, bytes32, bytes32, bytes calldata)
        external
        view
        override
        returns (bool)
    {
        return valid;
    }
}
