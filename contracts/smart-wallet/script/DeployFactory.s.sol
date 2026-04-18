// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice Deploy the PQ wallet stack: verifier → impl → factory, with
///         CREATE2 salts so all three land at byte-identical addresses
///         on every chain (the Coinbase-Smart-Wallet cross-chain recipe).
///         EntryPoint v0.9 is assumed to already exist at the canonical
///         address on every target chain; its address feeds into the
///         impl's constructor, so it must match everywhere.
///
///         Foundry routes `new X{salt: S}(args)` through Arachnid's
///         deterministic CREATE2 factory at
///         `0x4e59b44847b379578588920cA78FbF26c0B4956C` (already
///         pre-deployed via Nick's method on every major EVM chain),
///         so the predicted address depends only on
///         `(0x4e59…, salt, keccak256(initCode))`. As long as the
///         bytecode is byte-identical (same solc/via_ir/optimizer/evm
///         version — locked in `foundry.toml`'s `deploy` profile), the
///         addresses are the same on Base, Base Sepolia, mainnet, etc.
///
///         Invoke: `FOUNDRY_PROFILE=deploy forge script \
///                    script/DeployFactory.s.sol \
///                    --rpc-url <rpc> --account <name> --broadcast`
///
///         Do NOT pass `--verify` — deployments are intentionally
///         unpublished.
contract DeployFactory is Script {
    /// @notice Canonical ERC-4337 EntryPoint v0.9 (same address on every
    ///         chain via ERC-2470 singleton).
    address constant ENTRY_POINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    /// @notice CREATE2 salts. Zero is fine and keeps things simple; if
    ///         we ever need to redeploy a fixed contract (e.g. patched
    ///         verifier) we bump the relevant salt.
    bytes32 constant SALT_VERIFIER = bytes32(0);
    bytes32 constant SALT_IMPL     = bytes32(0);
    bytes32 constant SALT_FACTORY  = bytes32(0);

    function run() external {
        require(ENTRY_POINT_V09.code.length > 0, "EntryPoint v0.9 not deployed on this chain");

        vm.startBroadcast();

        SPHINCsC10Asm verifier = new SPHINCsC10Asm{salt: SALT_VERIFIER}();
        PQSmartWallet impl = new PQSmartWallet{salt: SALT_IMPL}(
            IEntryPoint(ENTRY_POINT_V09),
            ISPHINCSVerifier(address(verifier))
        );
        PQSmartWalletFactory factory = new PQSmartWalletFactory{salt: SALT_FACTORY}(
            address(impl),
            ISPHINCSVerifier(address(verifier))
        );

        vm.stopBroadcast();

        console2.log("chain id         ", block.chainid);
        console2.log("EntryPoint v0.9  ", ENTRY_POINT_V09);
        console2.log("SPHINCsC10Asm    ", address(verifier));
        console2.log("PQSmartWallet    ", address(impl));
        console2.log("Factory          ", address(factory));
    }
}
