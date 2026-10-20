// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ProductionDeploy} from "./ProductionDeploy.sol";

/// @notice Deploy the PQ wallet stack (verifier → impl → factory) on any
///         chain that has EntryPoint v0.6 and the Arachnid CREATE2 deployer.
///         The set lands at the same addresses on every such chain because
///         the addresses depend only on `(0x4e59…, salt 0, keccak256(initCode))`
///         and the init code is byte-identical under `FOUNDRY_PROFILE=deploy`.
///         `ProductionDeploy` refuses to broadcast unless those addresses are
///         the ones compiled into the firmware. Chain-specific scripts
///         (`DeployImplAndFactory*.s.sol`) add a chain-id guard.
///
///         Invoke: `FOUNDRY_PROFILE=deploy forge script \
///                    script/DeployFactory.s.sol \
///                    --rpc-url <rpc> --account <name> --broadcast`
///         Add `--verify` (with an explorer API key) to publish the source;
///         the 2026-06 Base Mainnet set was verified on Basescan.
contract DeployFactory is ProductionDeploy {
    function run() external {
        _deploySet();
    }
}
