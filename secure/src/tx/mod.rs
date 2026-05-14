//! Ethereum transaction parsing for the secure world.
//!
//! Today only EIP-1559 (typed transaction envelope `0x02 ‖ rlp(...)`) is
//! supported. The unsigned tx envelope is passed across the gateway by NS,
//! copied into a secure stack buffer, parsed here, displayed for user
//! confirmation, and only then hashed + signed.
//!
//! The pure parsing primitives (`rlp`, `eip1559`, `hash`) live in the
//! [`pqsigner_tx_core`] crate so host-side tooling can reuse them; this
//! module exposes them via thin re-export shims. `display`, `eip712`,
//! and `typed_call` still depend on secure-world internals
//! (`crate::ui`, `crate::erc20`, `crate::names`, `crate::selectors`)
//! and stay here.

// display depends on crate::ui (hardware), so it's gated out in host
// test builds. eip1559, eip712 core, hash, rlp, and typed_call (Phase 2
// calldata decoder) are pure logic. eip712 itself is compiled in test
// mode but its `cowswap_display` submodule is gated at the submodule
// level (see eip712/mod.rs); same pattern for typed_call —
// `display::typed_call` is the renderer half (gated), `typed_call`
// here is the parser + ABI walker (always compiled, host-testable).
#[cfg(not(test))]
pub mod display;
pub mod eip712;
pub mod typed_call;

// Pure-logic re-export shims: the bodies live in `pqsigner-tx-core`.
pub use pqsigner_tx_core::eip1559;
pub use pqsigner_tx_core::hash;
pub use pqsigner_tx_core::rlp;
