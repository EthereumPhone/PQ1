// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// @notice Profile-aware pinned-codehash constants, shared by
///         `PinnedCodehashes.t.sol` (the freeze test) and
///         `PinnedBytecodeImmutableLemma.t.sol` (the immutable-window
///         lemma).
///
///         The compiled runtime depends on the optimiser profile, so each
///         profile gets its own pin set:
///
///           * `default` — foundry.toml main profile (runs=200, via_ir,
///             prague). The fast-iteration build the test suite and the
///             Halmos sessions run against by default.
///           * `deploy`  — [profile.deploy] (runs=999999, via_ir, prague).
///             The bytecode production deployments are cut from.
///             `make -C contracts/verification verify-bytecode` runs the
///             FULL symbolic suite against BOTH profiles, so every
///             discharge holds for the production build too, not just the
///             dev build.
///
///         A zero constant means "not yet pinned": the freeze test prints
///         the live value for capture instead of asserting.
///
///         Since 2026-10-20 the build sets `bytecode_hash = "none"`
///         (foundry.toml), so these hashes depend only on the code and the
///         compiler settings, not on comments, source paths or which lib
///         directories are present.
abstract contract PinnedCodehashSelector is Test {
    // ── default profile (runs=200) — re-pinned 2026-10-20 ─────────────
    bytes32 internal constant WALLET_CODEHASH_DEFAULT =
        0xcebbd91dc5a2cd5869eacc84e2bd82dbd8702c504788017df78a2e1960119a0b;
    bytes32 internal constant FACTORY_CODEHASH_DEFAULT =
        0x318afcbf264cd2f0fa0cc25efa1c26d9ad1799f916a2182ec9a320d4a94e8b46;
    bytes32 internal constant VERIFIER_CODEHASH_DEFAULT =
        0x8fa670d53df0fd63bc64505463f268256ffbb51e57f62d8a5a41f5bcec5cf2eb;

    // ── deploy profile (runs=999999) — re-pinned 2026-10-20 ───────────
    bytes32 internal constant WALLET_CODEHASH_DEPLOY =
        0x1bbd83ba0479a352197328f581b3ee473643996b04e07355ae8e3ebc49d91bea;
    bytes32 internal constant FACTORY_CODEHASH_DEPLOY =
        0x44c3b4f70f5dc5406275cce87be814eda909ab0acab4aacdb9dc3ef24f0f7b21;
    bytes32 internal constant VERIFIER_CODEHASH_DEPLOY =
        0xfd55ec708737970f93a73cec1ce67de95391da4b673e24fa2516f9822bf92989;

    function _isDeployProfile() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default"))))
            == keccak256(bytes("deploy"));
    }

    function _pinnedWallet() internal view returns (bytes32) {
        return _isDeployProfile() ? WALLET_CODEHASH_DEPLOY : WALLET_CODEHASH_DEFAULT;
    }

    function _pinnedFactory() internal view returns (bytes32) {
        return _isDeployProfile() ? FACTORY_CODEHASH_DEPLOY : FACTORY_CODEHASH_DEFAULT;
    }

    function _pinnedVerifier() internal view returns (bytes32) {
        return _isDeployProfile() ? VERIFIER_CODEHASH_DEPLOY : VERIFIER_CODEHASH_DEFAULT;
    }
}
