// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {console2} from "forge-std/Script.sol";

import {ProductionDeploy} from "./ProductionDeploy.sol";
import {PqsignerDeployment} from "./generated/PqsignerDeployment.sol";

/// @notice Deterministically computes the production deploy addresses and the
///         firmware-baked `PROXY_INIT_CODE_HASH` — with NO RPC and no on-chain
///         deploy. It reproduces exactly where the `Deploy*` scripts land
///         through the Arachnid CREATE2 deployer.
///
///         These values feed the firmware constants in `proto/src/lib.rs`:
///           * Factory address      -> `PQ_SMART_WALLET_FACTORY`
///           * PROXY_INIT_CODE_HASH -> `PROXY_INIT_CODE_HASH`
///
///         BOTH move whenever the impl or verifier code moves, the compiler
///         settings change, or the constructor args change (the impl address
///         is a factory constructor arg, and the proxy init code embeds the
///         impl address). Source comments do not move them: the build sets
///         `bytecode_hash = "none"`. After such a change: run this, update
///         `proto/src/lib.rs` and the two frozen-constant tests, run
///         `cargo run -p pqsigner-xtask -- gen-solidity-constants`, and
///         re-pin `test/DeployedBytecodeReproCheck.t.sol` (CI fails until
///         all of them agree).
///
///         IMPORTANT — run under the SAME profile you deploy with:
///           FOUNDRY_PROFILE=deploy forge script script/PrintProductionAddresses.s.sol
///         The default (test) profile uses different optimizer runs, yields
///         different bytecode, and therefore different addresses.
contract PrintProductionAddresses is ProductionDeploy {
    function run() external pure {
        Predicted memory p = _predict();

        console2.log("chain-independent (Arachnid CREATE2, salt=0):");
        console2.log("  SPHINCsC10Asm verifier :", p.verifier);
        console2.log("  PQSmartWallet impl     :", p.impl);
        console2.log("  PQSmartWalletFactory   :", p.factory);
        console2.log("PROXY_INIT_CODE_HASH (bake into proto/src/lib.rs):");
        console2.logBytes32(p.proxyInitCodeHash);
        console2.log(
            "matches firmware constants (script/generated/PqsignerDeployment.sol):",
            p.factory == PqsignerDeployment.PQ_SMART_WALLET_FACTORY
                && p.proxyInitCodeHash == PqsignerDeployment.PROXY_INIT_CODE_HASH
        );
    }
}
