// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {PqsignerDeployment} from "./generated/PqsignerDeployment.sol";

/// @notice Shared production deploy: verifier → impl → factory through
///         Arachnid's deterministic CREATE2 deployer (salt 0), so the set
///         lands at the same addresses on every chain it is deployed to.
///
///         Before broadcasting it predicts the three addresses and REFUSES
///         to continue unless the predicted factory and the proxy init-code
///         hash equal the CREATE2 constants compiled into the device firmware
///         (`script/generated/PqsignerDeployment.sol`, rendered from
///         `proto/src/lib.rs`). The firmware predicts every wallet address
///         from those constants, so any other deployment is unreachable from
///         the device — the 2026-05 Ethereum-mainnet deployment was exactly
///         that (docs/VULN-eth-mainnet-deployment-divergence.md). A contract
///         already present at its predicted address is the same contract
///         (the CREATE2 address commits to the init code) and is reused, so
///         an interrupted run can simply be run again. After broadcasting it
///         requires every address to hold code and the immutables to point
///         at each other and at the canonical EntryPoint v0.6.
///
///         Run it with `./deploy.sh <base-sepolia|base|eth-mainnet>`, or
///         directly under the production profile, which the address check
///         enforces (any other profile predicts different addresses):
///           FOUNDRY_PROFILE=deploy forge script script/<Script>.s.sol \
///             --rpc-url <rpc> --account <name> [--broadcast] [--verify]
abstract contract ProductionDeploy is Script {
    /// @dev Arachnid's deterministic CREATE2 deployer (Nick's-method
    ///      singleton). Foundry routes `new X{salt: S}(args)` through it.
    address internal constant ARACHNID_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    /// @dev Canonical ERC-4337 EntryPoint v0.6; baked into the impl.
    address internal constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    bytes32 internal constant SALT = bytes32(0);

    struct Predicted {
        address verifier;
        address impl;
        address factory;
        bytes32 proxyInitCodeHash;
    }

    /// @dev `keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:]`.
    function _create2Address(bytes32 initCodeHash) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), ARACHNID_DEPLOYER, SALT, initCodeHash))))
        );
    }

    function _predict() internal pure returns (Predicted memory p) {
        p.verifier = _create2Address(keccak256(type(SPHINCsC10Asm).creationCode));
        p.impl = _create2Address(
            keccak256(abi.encodePacked(type(PQSmartWallet).creationCode, abi.encode(ENTRY_POINT_V06, p.verifier)))
        );
        p.factory = _create2Address(
            keccak256(abi.encodePacked(type(PQSmartWalletFactory).creationCode, abi.encode(p.impl, p.verifier)))
        );
        p.proxyInitCodeHash = keccak256(LibClone.initCodeERC1967(p.impl));
    }

    /// @dev Refuse a deployment the firmware cannot reach.
    function _preflight(Predicted memory p) internal view {
        require(ENTRY_POINT_V06.code.length > 0, "EntryPoint v0.6 not deployed on this chain");
        require(ARACHNID_DEPLOYER.code.length > 0, "Arachnid CREATE2 deployer not on this chain");
        require(
            p.factory == PqsignerDeployment.PQ_SMART_WALLET_FACTORY,
            "predicted factory != firmware PQ_SMART_WALLET_FACTORY (FOUNDRY_PROFILE=deploy? exact foundry.lock libs? proto constants regenerated?)"
        );
        require(
            p.proxyInitCodeHash == PqsignerDeployment.PROXY_INIT_CODE_HASH,
            "predicted proxy init-code hash != firmware PROXY_INIT_CODE_HASH"
        );
    }

    /// @dev One CREATE2 deploy through the Arachnid deployer, as an explicit
    ///      call (calldata = salt ++ initCode; it returns the 20-byte address).
    ///      Not `new X{salt: S}()`: Foundry 1.8 routes that through the
    ///      deployer only when the broadcaster has no code, and executes the
    ///      CREATE2 from an EIP-7702-delegated broadcaster itself — which
    ///      lands at a different address.
    function _arachnidDeploy(bytes memory initCode, address expected) internal {
        (bool ok, bytes memory ret) = ARACHNID_DEPLOYER.call(abi.encodePacked(SALT, initCode));
        require(ok && ret.length == 20, "Arachnid CREATE2 deploy failed");
        require(address(bytes20(ret)) == expected, "Arachnid CREATE2 landed at an unexpected address");
    }

    function _deploySet() internal returns (Predicted memory p) {
        p = _predict();
        _preflight(p);

        vm.startBroadcast();
        if (p.verifier.code.length == 0) {
            _arachnidDeploy(type(SPHINCsC10Asm).creationCode, p.verifier);
        }
        if (p.impl.code.length == 0) {
            _arachnidDeploy(
                abi.encodePacked(type(PQSmartWallet).creationCode, abi.encode(ENTRY_POINT_V06, p.verifier)),
                p.impl
            );
        }
        if (p.factory.code.length == 0) {
            _arachnidDeploy(
                abi.encodePacked(type(PQSmartWalletFactory).creationCode, abi.encode(p.impl, p.verifier)),
                p.factory
            );
        }
        vm.stopBroadcast();

        require(p.verifier.code.length > 0, "verifier missing after deploy");
        require(p.impl.code.length > 0, "impl missing after deploy");
        require(p.factory.code.length > 0, "factory missing after deploy");
        PQSmartWalletFactory factory = PQSmartWalletFactory(p.factory);
        PQSmartWallet impl = PQSmartWallet(payable(p.impl));
        require(factory.implementation() == p.impl, "factory implementation != impl");
        require(address(factory.c10Verifier()) == p.verifier, "factory verifier != verifier");
        require(address(impl.c10Verifier()) == p.verifier, "impl verifier != verifier");
        require(address(impl.entryPoint()) == ENTRY_POINT_V06, "impl EntryPoint != v0.6");

        console2.log("chain id              ", block.chainid);
        console2.log("EntryPoint v0.6       ", ENTRY_POINT_V06);
        console2.log("SPHINCsC10Asm         ", p.verifier);
        console2.log("PQSmartWallet impl    ", p.impl);
        console2.log("PQSmartWalletFactory  ", p.factory);
        console2.log("PROXY_INIT_CODE_HASH (= firmware):");
        console2.logBytes32(p.proxyInitCodeHash);
    }
}
