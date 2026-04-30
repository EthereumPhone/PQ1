// SPDX-License-Identifier: MIT
// AUTO-GENERATED — DO NOT EDIT.
// Source of truth: `pqsigner-proto` crate (Rust).
// Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`.
//
// Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md
// Phase 4 of the modularity refactor.
pragma solidity ^0.8.28;

/// @notice Cross-language protocol constants shared by the firmware
///         (Rust, `pqsigner-proto` crate) and the on-chain wallet.
///         The firmware is the source of truth — every constant in
///         this library is generated from a `pub const` in the Rust
///         crate. CI diffs the generated file against
///         `pqsigner-xtask gen-solidity-constants --check` so any
///         drift is caught at PR review.
library PqsignerProto {

    // ─────────────────────────────────────────────
    // Signature sizes
    // ─────────────────────────────────────────────
    uint256 internal constant C10_SIG_LEN = 4008;
    /// @dev abi.encode(uint256 ownerIndex, bytes innerSig) layout: 32 (ownerIndex) + 32 (offset) + 32 (length) + ((C10_SIG_LEN + 31) / 32) * 32
    uint256 internal constant SIG_WRAPPER_LEN = 4128;

    // ─────────────────────────────────────────────
    // Per-chain usage caps
    // ─────────────────────────────────────────────
    uint256 internal constant MAX_BOOTSTRAP_USES = 65536;
    uint256 internal constant MAX_SLOT_USES = 65536;
    uint256 internal constant MAX_OFFCHAIN_GAP = 5;

    // ─────────────────────────────────────────────
    // Wallet storage layout
    // ─────────────────────────────────────────────
    uint256 internal constant OWNER_BYTES_LEN = 64;

    // ─────────────────────────────────────────────
    // Selectors
    // ─────────────────────────────────────────────
    bytes4 internal constant EXECUTE_SELECTOR = 0x14443c57;
    bytes4 internal constant EXECUTE_BATCH_SELECTOR = 0x7a389933;

    // ─────────────────────────────────────────────
    // Domain tags
    // ─────────────────────────────────────────────
    bytes internal constant FACTORY_ADD_SLOT_DOMAIN = "pqwallet-factory-add-slot";
}
