// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";

/// @notice Deploy verifier + impl + factory on Base Mainnet via the
///         Arachnid CREATE2 factory. Same CREATE2 salts as
///         DeployFactory.s.sol so all three land at byte-identical
///         addresses on every chain (matches the firmware + companion
///         baked-in addresses).
contract DeployImplAndFactoryBaseMainnet is Script {
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    bytes32 constant SALT_VERIFIER = bytes32(0);
    bytes32 constant SALT_IMPL = bytes32(0);
    bytes32 constant SALT_FACTORY = bytes32(0);

    function run() external {
        require(block.chainid == 8453, "not base mainnet");
        require(ENTRY_POINT_V06.code.length > 0, "EntryPoint v0.6 not deployed");

        vm.startBroadcast();

        SPHINCsC10Asm verifier = new SPHINCsC10Asm{salt: SALT_VERIFIER}();

        PQSmartWallet impl = new PQSmartWallet{salt: SALT_IMPL}(
            IEntryPoint(ENTRY_POINT_V06),
            ISPHINCSVerifier(address(verifier))
        );

        PQSmartWalletFactory factory = new PQSmartWalletFactory{salt: SALT_FACTORY}(
            address(impl),
            ISPHINCSVerifier(address(verifier))
        );

        vm.stopBroadcast();

        console2.log("chain id         ", block.chainid);
        console2.log("EntryPoint v0.6  ", ENTRY_POINT_V06);
        console2.log("SPHINCsC10Asm    ", address(verifier));
        console2.log("PQSmartWallet    ", address(impl));
        console2.log("Factory          ", address(factory));
    }
}
