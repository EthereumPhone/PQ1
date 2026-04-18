// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @notice Prints `keccak256(LibClone.initCodeERC1967(impl))` — the
///         build-time constant the firmware bakes in so it can predict
///         the wallet's CREATE2 address without an RPC lookup.
contract PrintProxyInitCodeHash is Script {
    function run() external view {
        address impl = vm.envAddress("IMPL");
        bytes memory initCode = LibClone.initCodeERC1967(impl);
        bytes32 h = keccak256(initCode);
        console2.log("impl:          ", impl);
        console2.log("initCodeLen:   ", initCode.length);
        console2.logBytes32(h);
    }
}
