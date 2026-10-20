// SPDX-License-Identifier: MIT
// AUTO-GENERATED — DO NOT EDIT.
// Source of truth: `pqsigner-proto` crate (Rust).
// Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`.
//
// Kept outside `src/`: these values are derived from the compiled
// contracts, so the contracts themselves must not import them.
pragma solidity ^0.8.28;

/// @notice The CREATE2 constants compiled into the device firmware
///         (`proto/src/lib.rs`). The firmware predicts every wallet
///         address from them, so a deployment that does not reproduce
///         them exactly is unreachable from the device.
library PqsignerDeployment {

    // ─────────────────────────────────────────────
    // Firmware CREATE2 constants
    // ─────────────────────────────────────────────
    address internal constant PQ_SMART_WALLET_FACTORY = 0xE3dbA404dCeC30093DE26764965a51689C1607BD;
    bytes32 internal constant PROXY_INIT_CODE_HASH = 0x17ca674095afe9dc82aa6f396ee01bd837449a127b6be59a0d947329f29b2570;
}
