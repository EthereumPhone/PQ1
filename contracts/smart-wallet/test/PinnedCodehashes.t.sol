// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice Pinned-codehash test — Phase 2C / Phase 3 of the
///         contracts/verification discharge plan.
///
///         Each `solidity*_compiles_correctly` axiom is bound to a
///         specific runtime codehash (recorded in
///         `contracts/verification/docs/PINNED_CODEHASHES.md`). If the
///         bytecode drifts (compiler bump, source change, optimiser
///         setting change), this test fails and the discharge artifacts
///         must be re-run against the new codehash before the axiom
///         pin is updated.
///
///         The constants below are placeholders for the initial
///         branch-cut; update via the `forge test --match-test
///         test_codehash_print -vv` output below, then re-run the
///         discharge artifacts (Halmos, Certora).
contract PinnedCodehashesTest is Test {
    // ── Codehash freeze constants (pinned at 2026-05-21 branch-cut) ────
    //
    // Re-capture via `forge test --match-test test_codehash_pinned_or_print -vv`
    // and update here when the bytecode legitimately changes (compiler
    // bump / source change). Each update must be accompanied by re-running
    // the discharge artifacts for the affected axiom:
    //   * PQ_SMART_WALLET_CODEHASH    → Halmos (HalmosValidateUserOp + HalmosExecute)
    //   * PQ_SMART_WALLET_FACTORY_CODEHASH → Certora (PQSmartWalletFactory.spec)
    //   * SPHINCS_C10_ASM_CODEHASH    → cross_validation/ Lean ↔ Rust ↔ Solidity
    bytes32 constant PQ_SMART_WALLET_CODEHASH =
        0x4201b2b6933ca9ab4222e25a22616feb61947e03f96e51c8e078a121fc3d006f;
    bytes32 constant PQ_MULTI_OWNABLE_CODEHASH = bytes32(0);  // embedded in PQSmartWallet; no independent deploy
    bytes32 constant PQ_SMART_WALLET_FACTORY_CODEHASH =
        0xe40c9c3bdbacdfde6d98c30dee4437ab0019ec702b8868ad2294a53c052a2270;
    bytes32 constant SPHINCS_C10_ASM_CODEHASH =
        0x94a6a6a4d4905760b264099eb8de6d9a58b1d97992b93ca9b66e7361aaa350e9;

    SPHINCsC10Asm internal sphincs;
    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;

    function setUp() public {
        sphincs = new SPHINCsC10Asm();
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(address(0x4337)), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
    }

    /// **Codehash freeze enforcement.** Only runs when the
    /// `PQ_SMART_WALLET_CODEHASH` constant is non-zero (i.e. has been
    /// pinned). Otherwise prints the current codehashes for capture.
    function test_codehash_pinned_or_print() external view {
        bytes32 walletHash = address(impl).codehash;
        bytes32 factoryHash = address(factory).codehash;
        bytes32 sphincsHash = address(sphincs).codehash;

        // Sanity: deployments produced non-empty bytecode.
        assertTrue(walletHash != bytes32(0), "PQSmartWallet has no bytecode");
        assertTrue(factoryHash != bytes32(0), "PQSmartWalletFactory has no bytecode");
        assertTrue(sphincsHash != bytes32(0), "SPHINCsC10Asm has no bytecode");

        if (PQ_SMART_WALLET_CODEHASH != bytes32(0)) {
            assertEq(walletHash, PQ_SMART_WALLET_CODEHASH,
                "PQSmartWallet codehash drift: re-run Halmos and update pin");
        } else {
            console2.log("[!] PQSmartWallet codehash (capture and pin):");
            console2.logBytes32(walletHash);
        }

        if (PQ_SMART_WALLET_FACTORY_CODEHASH != bytes32(0)) {
            assertEq(factoryHash, PQ_SMART_WALLET_FACTORY_CODEHASH,
                "PQSmartWalletFactory codehash drift: re-run Certora and update pin");
        } else {
            console2.log("[!] PQSmartWalletFactory codehash (capture and pin):");
            console2.logBytes32(factoryHash);
        }

        if (SPHINCS_C10_ASM_CODEHASH != bytes32(0)) {
            assertEq(sphincsHash, SPHINCS_C10_ASM_CODEHASH,
                "SPHINCsC10Asm codehash drift: re-run cross_validation/ and update pin");
        } else {
            console2.log("[!] SPHINCsC10Asm codehash (capture and pin):");
            console2.logBytes32(sphincsHash);
        }
    }

    /// **EVM precompile 0x02 SHA-256 parity test (axiom A1 defense-in-depth).**
    /// Asserts that `staticcall(0x02, "abc")` returns the NIST CAVS expected
    /// SHA-256 digest. This is the empirical Foundry parity test backing
    /// `precompile_0x02_is_FIPS_180_4`.
    function test_sha256_precompile_abc_kat() external view {
        bytes32 expected = 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad;
        bytes32 got = sha256(bytes("abc"));
        assertEq(got, expected, "SHA-256 precompile drift");
    }

    /// **EVM precompile SHA-256("") KAT.**
    function test_sha256_precompile_empty_kat() external view {
        bytes32 expected = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
        bytes32 got = sha256(bytes(""));
        assertEq(got, expected, "SHA-256 precompile drift (empty)");
    }
}
