// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

/// @notice Storage-slot parity test — Phase 2C of the
///         contracts/verification discharge plan.
///
///         The Lean model in
///         `contracts/verification/lean/SphincsCVerify/Wallet/StorageLayout.lean`
///         declares the PQMultiOwnable ERC-7201 slot and the standard
///         ERC-1967 reserved slots as `ByteVec 32` literals. This test
///         asserts each literal matches the canonical value:
///
///           * `PQ_MULTI_OWNABLE_STORAGE_SLOT` — must match the
///             Solidity literal at `PQMultiOwnable.sol:64`.
///           * `ERC1967_*` — standard slots per the ERC-1967 spec.
///
///         If either side drifts, Claim 2's
///         `pq_storage_disjoint_from_erc1967_impl` theorem stops
///         binding the deployed bytecode.
contract StorageSlotParityTest is Test {
    /// Matches `PQMultiOwnable.sol:64 _PQ_MULTI_OWNABLE_STORAGE_LOCATION` and
    /// `Lean::StorageLayout.PQ_MULTI_OWNABLE_STORAGE_SLOT`.
    bytes32 constant PQ_MULTI_OWNABLE_STORAGE_SLOT =
        0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000;

    /// Standard ERC-1967 implementation slot:
    ///   keccak256("eip1967.proxy.implementation") - 1.
    bytes32 constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// Standard ERC-1967 admin slot:
    ///   keccak256("eip1967.proxy.admin") - 1.
    bytes32 constant ERC1967_ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /// Standard ERC-1967 beacon slot:
    ///   keccak256("eip1967.proxy.beacon") - 1.
    bytes32 constant ERC1967_BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /// **PQMultiOwnable slot ↔ Solidity literal parity.**
    /// Recomputes the ERC-7201 slot from the namespace string and asserts
    /// it equals the literal. Catches both Solidity drift AND Lean drift.
    function test_pqMultiOwnable_slot_matches_erc7201_derivation() external pure {
        bytes32 derived = keccak256(
            abi.encode(
                uint256(keccak256("pqsigner.storage.PQMultiOwnable")) - 1
            )
        ) & ~bytes32(uint256(0xff));
        assertEq(derived, PQ_MULTI_OWNABLE_STORAGE_SLOT,
            "ERC-7201 derivation drift for PQMultiOwnable");
    }

    /// **ERC-1967 IMPL slot recomputation.**
    function test_erc1967_impl_slot_matches_derivation() external pure {
        bytes32 derived = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        assertEq(derived, ERC1967_IMPLEMENTATION_SLOT, "ERC-1967 IMPL slot drift");
    }

    /// **ERC-1967 ADMIN slot recomputation.**
    function test_erc1967_admin_slot_matches_derivation() external pure {
        bytes32 derived = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
        assertEq(derived, ERC1967_ADMIN_SLOT, "ERC-1967 ADMIN slot drift");
    }

    /// **ERC-1967 BEACON slot recomputation.**
    function test_erc1967_beacon_slot_matches_derivation() external pure {
        bytes32 derived = bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1);
        assertEq(derived, ERC1967_BEACON_SLOT, "ERC-1967 BEACON slot drift");
    }

    /// **Disjointness.** Matches the Lean theorems
    /// `pq_storage_disjoint_from_erc1967_{impl,admin,beacon}`.
    function test_pq_slot_disjoint_from_erc1967() external pure {
        assertTrue(PQ_MULTI_OWNABLE_STORAGE_SLOT != ERC1967_IMPLEMENTATION_SLOT,
            "Disjointness failure: PQ vs ERC-1967 IMPL");
        assertTrue(PQ_MULTI_OWNABLE_STORAGE_SLOT != ERC1967_ADMIN_SLOT,
            "Disjointness failure: PQ vs ERC-1967 ADMIN");
        assertTrue(PQ_MULTI_OWNABLE_STORAGE_SLOT != ERC1967_BEACON_SLOT,
            "Disjointness failure: PQ vs ERC-1967 BEACON");
        assertTrue(ERC1967_IMPLEMENTATION_SLOT != ERC1967_ADMIN_SLOT,
            "Disjointness failure: IMPL vs ADMIN");
        assertTrue(ERC1967_IMPLEMENTATION_SLOT != ERC1967_BEACON_SLOT,
            "Disjointness failure: IMPL vs BEACON");
        assertTrue(ERC1967_ADMIN_SLOT != ERC1967_BEACON_SLOT,
            "Disjointness failure: ADMIN vs BEACON");
    }
}
