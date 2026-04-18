// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice Deploy the PQ wallet stack: verifier → impl → factory.
///         EntryPoint v0.9 is assumed to already exist at the canonical
///         address on every target chain.
///
///         Invoke: `forge script script/DeployFactory.s.sol \
///                    --rpc-url <rpc> --account <name> --broadcast`
///
///         Do NOT pass `--verify` — deployments are intentionally
///         unpublished.
contract DeployFactory is Script {
    /// @notice Canonical ERC-4337 EntryPoint v0.9.
    address constant ENTRY_POINT_V09 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    function run() external {
        require(ENTRY_POINT_V09.code.length > 0, "EntryPoint v0.9 not deployed on this chain");

        vm.startBroadcast();

        SPHINCsC10Asm verifier = new SPHINCsC10Asm();
        PQSmartWallet impl = new PQSmartWallet(
            IEntryPoint(ENTRY_POINT_V09),
            ISPHINCSVerifier(address(verifier))
        );
        PQSmartWalletFactory factory = new PQSmartWalletFactory(
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
