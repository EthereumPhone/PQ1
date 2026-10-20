// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProductionDeploy} from "./ProductionDeploy.sol";

/// @notice Deploy verifier + impl + factory on Base Sepolia (chain id
///         84532). See `ProductionDeploy` for the address checks this
///         runs against the firmware's CREATE2 constants before broadcasting.
///
///         Invoke:
///           FOUNDRY_PROFILE=deploy forge script \
///             script/DeployImplAndFactoryBaseSepolia.s.sol \
///             --rpc-url <rpc> --account <name> --broadcast
contract DeployImplAndFactoryBaseSepolia is ProductionDeploy {
    function run() external {
        require(block.chainid == 84532, "not base sepolia");
        _deploySet();
    }
}
