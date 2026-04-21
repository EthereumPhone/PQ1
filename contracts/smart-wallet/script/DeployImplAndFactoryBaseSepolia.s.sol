// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";

/// @notice Deploy impl + factory on Base Sepolia, reusing the already
///         on-chain SPHINCsC10Asm verifier at the CREATE2-deterministic
///         address. Same CREATE2 salts as DeployFactory.s.sol so the
///         resulting impl + factory land at the addresses the firmware
///         and companion bake in.
contract DeployImplAndFactoryBaseSepolia is Script {
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant VERIFIER = 0x2f9DA5543957c5933aC326E109e775097f0079d9;

    bytes32 constant SALT_IMPL = bytes32(0);
    bytes32 constant SALT_FACTORY = bytes32(0);

    function run() external {
        require(block.chainid == 84532, "not base sepolia");
        require(ENTRY_POINT_V06.code.length > 0, "EntryPoint v0.6 not deployed");
        require(VERIFIER.code.length > 0, "Verifier not deployed at expected address");

        vm.startBroadcast();

        PQSmartWallet impl = new PQSmartWallet{salt: SALT_IMPL}(
            IEntryPoint(ENTRY_POINT_V06),
            ISPHINCSVerifier(VERIFIER)
        );

        PQSmartWalletFactory factory = new PQSmartWalletFactory{salt: SALT_FACTORY}(
            address(impl),
            ISPHINCSVerifier(VERIFIER)
        );

        vm.stopBroadcast();

        console2.log("chain id         ", block.chainid);
        console2.log("EntryPoint v0.6  ", ENTRY_POINT_V06);
        console2.log("Verifier (reused)", VERIFIER);
        console2.log("PQSmartWallet    ", address(impl));
        console2.log("Factory          ", address(factory));
    }
}
