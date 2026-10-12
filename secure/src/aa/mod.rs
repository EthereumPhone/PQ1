//! ERC-4337 Account Abstraction support for the secure world.
//!
//! Thin re-export shim over the pure-logic [`pqsigner_aa`] crate, which
//! holds the userOp / EIP-1271 / EIP-6492 hashing primitives. Splitting
//! them into a standalone crate lets host-side reference signers (and a
//! future `fwsign verify-release --simulate-userop` tool) consume them
//! without pulling in the rest of `secure/`.
//!
//! ## Trust model
//!
//! The non-secure world is *not* trusted to compute the userOpHash.
//! It is only trusted to:
//!
//!   * Lookup the AA gas parameters and AA nonce from the bundler /
//!     RPC and forward them as opaque big-endian integers.
//!   * Forward the inner unsigned EIP-1559 envelope (which the secure
//!     world parses and dispatches itself).
//!
//! Everything that the EntryPoint actually hashes is *recomputed* in
//! the secure world from primitive inputs — see the `pqsigner-aa`
//! crate docs for the full reasoning.
//!
//! ## On-device initCode construction (deploy path)
//!
//! (Corrected 2026-07-02 — an earlier revision wrongly claimed the
//! firmware never builds initCode; that described a retired factory.)
//! `PQSmartWalletFactory.createAccount` requires a **bootstrap C10
//! signature** over `addSlot0Digest(...)` (squat-defence), so the deploy
//! authorisation is produced in the secure world: `CMD_GET_INIT_CODE`
//! (`cmd_get_init_code.rs`) emits the full 4280-byte `initCode` (factory
//! ‖ ABI-encoded `createAccount` + `factorySig`); a deploy sign
//! (`FLAG_INCLUDE_INIT_CODE`, `slot_index == 0`, mutually exclusive with
//! `FLAG_REGISTER_SLOT`) prepends it and signs a real `init_code_hash`,
//! not `KECCAK_EMPTY`; the counterfactual EIP-6492 path embeds
//! `initCode[20..]` as `factoryCalldata`. See CLAUDE.md "Wire formats".

pub use pqsigner_aa::eip1271;
pub use pqsigner_aa::eip6492;
// Only the gateway handlers use this, and `nsc` is not built under test.
#[cfg(not(test))]
pub use pqsigner_aa::execute_bind;
pub use pqsigner_aa::offchain_gate;
pub use pqsigner_aa::userop;
