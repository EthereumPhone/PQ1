// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {SPHINCsC10Asm} from "../src/verifiers/SPHINCsC10Asm.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {PinnedCodehashSelector} from "./PinnedCodehashSelector.sol";

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
contract PinnedCodehashesTest is PinnedCodehashSelector {
    // ── Codehash freeze constants ─────────────────────────────────────
    //
    // Originally pinned at the 2026-05-21 branch-cut; re-pinned 2026-05-27
    // (EntryPoint-guard fix). RE-PINNED 2026-06-10 after the bootstrap
    // few-time-cap fix: `bootstrapUses` is now bumped in the VALIDATION
    // phase of `_validateSignature` (mirroring the slot path) instead of
    // the deferred, credit-gated bump in `addOwnerBytes`. This makes every
    // accepted Type-1 signature counted revert-proof under v0.6 (closes the
    // PQBootstrapCapEvasion under-count). Only `PQSmartWallet.sol` logic
    // changed; the verifier `SPHINCsC10Asm.sol` is untouched (its pin stayed
    // at the fcee705a FORS-htIdx value 0xf1ef…), and the factory's runtime
    // moved only because it imports the edited wallet into its compilation
    // unit (its CREATE2 / squat-defence logic is unchanged).
    //
    // RE-PINNED 2026-10-20 for the Trail of Bits audit freeze. Wallet logic
    // changed: owner removal deleted (#131/#213), legacy EIP-1271
    // `isValidSignature(bytes,bytes)` added (#995), Solady's raw-hash 1271
    // workflows dropped (#691), ERC-721/1155 receiver hooks + ERC-165 added.
    // The build also moved to `bytecode_hash = "none"` (foundry.toml), so the
    // verifier pin moved too although its source and instruction bytes are
    // unchanged (only the CBOR metadata tail shrank to the solc version);
    // from here on comments and source paths no longer move any pin.
    //
    // DISCHARGE STATUS: captured with Foundry v1.8.3 and the exact
    // `foundry.lock` lib set (the CI environment), solc 0.8.28, via_ir, for
    // both profiles. The A3.* bridge axioms are discharged against these
    // exact codehashes by `make -C ../verification verify-bytecode` (which
    // runs this test first to certify the codehashes, then the symbolic
    // rules) and `verify-kontrol`; see AXIOM_STATUS.json for the current
    // receipts. The Lean model in
    // `verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean` is the
    // kernel-checked source of the same properties.
    //
    // Re-capture via `forge test --match-test test_codehash_pinned_or_print -vv`.
    // Each update must be accompanied by re-running the discharge artifact:
    //   * PQ_SMART_WALLET_CODEHASH         → Halmos (HalmosValidateUserOp + HalmosExecute)
    //   * PQ_SMART_WALLET_FACTORY_CODEHASH → Halmos (HalmosFactory) / Certora
    //   * SPHINCS_C10_ASM_CODEHASH         → Halmos (HalmosVerifier gates) + cross_validation/
    //
    // PROFILE-AWARE 2026-06-10: the actual pin constants now live in
    // `PinnedCodehashSelector.sol`, which carries BOTH the default-profile
    // (runs=200) and deploy-profile (runs=999999) codehash sets and picks
    // by `$FOUNDRY_PROFILE`. `make -C ../verification verify-bytecode` runs
    // the symbolic suite under both profiles, so the discharge covers the
    // production build, not just the dev build. The aliases below keep this
    // file's body unchanged.
    bytes32 constant PQ_MULTI_OWNABLE_CODEHASH = bytes32(0);  // embedded in PQSmartWallet; no independent deploy

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

        bytes32 pinWallet = _pinnedWallet();
        bytes32 pinFactory = _pinnedFactory();
        bytes32 pinVerifier = _pinnedVerifier();

        if (pinWallet != bytes32(0)) {
            assertEq(walletHash, pinWallet,
                "PQSmartWallet codehash drift: re-run Halmos and update pin");
        } else {
            console2.log("[!] PQSmartWallet codehash (capture and pin):");
            console2.logBytes32(walletHash);
        }

        if (pinFactory != bytes32(0)) {
            assertEq(factoryHash, pinFactory,
                "PQSmartWalletFactory codehash drift: re-run Halmos/Certora and update pin");
        } else {
            console2.log("[!] PQSmartWalletFactory codehash (capture and pin):");
            console2.logBytes32(factoryHash);
        }

        if (pinVerifier != bytes32(0)) {
            assertEq(sphincsHash, pinVerifier,
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
