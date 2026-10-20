// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {PqsignerDeployment} from "../script/generated/PqsignerDeployment.sol";

/// @notice **Production-bytecode reproducibility check (deploy profile).**
///
///         Replays the production deploy — the Arachnid deterministic CREATE2
///         deployer (`0x4e59…`, salt = 0) under the production optimiser
///         profile, on Base's chain id (8453) — and asserts that it lands at
///         the pinned addresses with the pinned runtime codehashes, and that
///         the result matches the CREATE2 constants compiled into the device
///         firmware (`script/generated/PqsignerDeployment.sol`, rendered from
///         `proto/src/lib.rs` by `pqsigner-xtask gen-solidity-constants`).
///         The firmware predicts every wallet address from those constants,
///         so a contract change that is not mirrored there fails here, in CI
///         (`contracts` job, deploy-profile step) — the check that would have
///         caught the 2026-05 Ethereum-mainnet divergence
///         (docs/VULN-eth-mainnet-deployment-divergence.md).
///
///         STATUS 2026-10-20 (Trail of Bits audit freeze): the EXPECTED_*
///         values below are the freeze set, computed deterministically and
///         NOT yet deployed on any chain. The previous set (2026-06-12, Base
///         Mainnet: impl 0x31e4…3590, factory 0xe8CE…d452, verifier
///         0xdDE4…9cbB) is superseded; see deployments/base-mainnet.json.
///         After deploying, `cast codehash <addr>` on the chain must equal
///         these values (the impl hash only on chain 8453: it embeds the
///         chain id in Solady's EIP-712 cache).
///
///         The replay is byte-exact because the lib set is exactly
///         `foundry.lock` (account-abstraction `f54584e` for the v0.6
///         interfaces) and the build sets `bytecode_hash = "none"`, so source
///         comments and extra lib directories cannot move anything.
///
///         DEPLOY-PROFILE ONLY: production contracts are cut from
///         `[profile.deploy]` (runs=999999). Under any other profile the
///         creation code differs, so this test self-skips.
contract DeployedBytecodeReproCheckTest is Test {
    // Arachnid deterministic-deployment proxy (calldata = salt(32) || initcode).
    address constant ARACHNID = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    uint256 constant BASE_CHAIN_ID = 8453;
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    // The 2026-10-20 freeze set (deterministic; deploy pending).
    address constant EXPECTED_VERIFIER = 0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4;
    address constant EXPECTED_IMPL = 0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011;

    bytes32 constant EXPECTED_VERIFIER_CODEHASH =
        0xfd55ec708737970f93a73cec1ce67de95391da4b673e24fa2516f9822bf92989;
    /// On chain 8453 (Solady's EIP-712 cache embeds the chain id).
    bytes32 constant EXPECTED_IMPL_CODEHASH_ON_BASE =
        0x4be66f1681776863f405c0bf6d5f412ffe7248873db7aa3ad6b38664f258b2b6;
    bytes32 constant EXPECTED_FACTORY_CODEHASH =
        0x711dff4be17b368d25e5a24c35d12102f18209cd485392863f009e8a72712d5b;

    function _isDeployProfile() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default"))))
            == keccak256(bytes("deploy"));
    }

    function _create2(bytes memory initcode) internal returns (address a) {
        (bool ok, bytes memory ret) =
            ARACHNID.call(abi.encodePacked(bytes32(0), initcode));
        require(ok, "CREATE2 deploy failed");
        a = address(bytes20(ret));
    }

    /// Replays the production deploy and asserts the pinned addresses and
    /// codehashes, and the firmware's CREATE2 constants, are reproduced
    /// exactly. (Name kept: `check_forge_results.py` pins it.)
    function test_deployed_base_mainnet_bytecode_is_reproducible() external {
        if (!_isDeployProfile()) {
            emit log("SKIP: run under FOUNDRY_PROFILE=deploy (production profile)");
            vm.skip(true);
            return;
        }

        // Deploy on Base's chain id so the EIP-712 immutable cache matches.
        vm.chainId(BASE_CHAIN_ID);
        vm.etch(ARACHNID, ARACHNID_RUNTIME);

        // (1) verifier — no immutables, address-independent.
        address verifier = _create2(type(SPHINCsC10Asm).creationCode);
        assertEq(verifier, EXPECTED_VERIFIER, "verifier address");
        assertEq(verifier.codehash, EXPECTED_VERIFIER_CODEHASH, "verifier codehash");

        // (2) wallet implementation — immutables (_entryPoint, c10Verifier).
        address impl = _create2(
            abi.encodePacked(
                type(PQSmartWallet).creationCode,
                abi.encode(IEntryPoint(ENTRY_POINT_V06), ISPHINCSVerifier(verifier))
            )
        );
        assertEq(impl, EXPECTED_IMPL, "impl address");
        assertEq(impl.codehash, EXPECTED_IMPL_CODEHASH_ON_BASE, "impl codehash");

        // (3) factory — immutables (implementation address, c10Verifier).
        address factory = _create2(
            abi.encodePacked(
                type(PQSmartWalletFactory).creationCode,
                abi.encode(impl, ISPHINCSVerifier(verifier))
            )
        );
        assertEq(factory.codehash, EXPECTED_FACTORY_CODEHASH, "factory codehash");

        // (4) the firmware's CREATE2 constants (proto/src/lib.rs).
        assertEq(
            factory,
            PqsignerDeployment.PQ_SMART_WALLET_FACTORY,
            "factory address != firmware PQ_SMART_WALLET_FACTORY: regenerate proto constants"
        );
        assertEq(
            keccak256(LibClone.initCodeERC1967(impl)),
            PqsignerDeployment.PROXY_INIT_CODE_HASH,
            "proxy init-code hash != firmware PROXY_INIT_CODE_HASH: regenerate proto constants"
        );

        // (5) the firmware's wallet-address formula equals the factory's.
        bytes32 seed = bytes32(uint256(0xaaaa) << 240);
        bytes32 root = bytes32(uint256(0xbbbb) << 240);
        bytes32 salt = sha256(abi.encodePacked(seed, root));
        address firmwarePredicted = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            PqsignerDeployment.PQ_SMART_WALLET_FACTORY,
                            salt,
                            PqsignerDeployment.PROXY_INIT_CODE_HASH
                        )
                    )
                )
            )
        );
        assertEq(
            PQSmartWalletFactory(factory).getAddress(seed, root),
            firmwarePredicted,
            "factory.getAddress != firmware address formula"
        );
    }
}
