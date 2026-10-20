// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProductionDeploy} from "./ProductionDeploy.sol";

/// @notice Deploy verifier + impl + factory on Ethereum Mainnet (chain id
///         1). See `ProductionDeploy` for the address checks this
///         runs against the firmware's CREATE2 constants before broadcasting.
///
///         Invoke:
///           FOUNDRY_PROFILE=deploy forge script \
///             script/DeployImplAndFactoryEthMainnet.s.sol \
///             --rpc-url <rpc> --account <name> --broadcast
contract DeployImplAndFactoryEthMainnet is ProductionDeploy {
    function run() external {
        require(block.chainid == 1, "not eth mainnet");
        _deploySet();
    }
}
