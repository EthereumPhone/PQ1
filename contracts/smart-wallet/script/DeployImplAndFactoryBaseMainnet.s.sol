// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProductionDeploy} from "./ProductionDeploy.sol";

/// @notice Deploy verifier + impl + factory on Base Mainnet (chain id
///         8453). See `ProductionDeploy` for the address checks this
///         runs against the firmware's CREATE2 constants before broadcasting.
///
///         Invoke:
///           FOUNDRY_PROFILE=deploy forge script \
///             script/DeployImplAndFactoryBaseMainnet.s.sol \
///             --rpc-url <rpc> --account <name> --broadcast
///             (the 2026-06 deployer EOA was EIP-7702-delegated; Base then
///             needed --slow)
contract DeployImplAndFactoryBaseMainnet is ProductionDeploy {
    function run() external {
        require(block.chainid == 8453, "not base mainnet");
        _deploySet();
    }
}
