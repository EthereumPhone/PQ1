//! `pqsigner-tx-core` — pure-logic Ethereum transaction primitives.
//!
//! - [`rlp`] — strict, no_std RLP decoder for EIP-1559 envelopes.
//! - [`eip1559`] — typed-envelope parser + the shared [`eip1559::U256`]
//!   integer used throughout the display/sign pipeline.
//! - [`hash`] — keccak256 wrapper for the unsigned envelope signing hash.
//! - [`erc8213`] — wallet-signature & calldata-digest fingerprint hashes
//!   the device displays on the final confirm page so a user can cross-
//!   check against `cast` / `viem` / `safe-hash` off-device.
//!
//! Migrated out of `secure/src/tx/{rlp,eip1559,hash}.rs` in Phase 5 PR
//! 5.1 of the modularity refactor. The secure crate keeps a re-export
//! shim at `secure/src/tx/mod.rs` so existing call sites compile
//! unchanged.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod eip1559;
pub mod erc8213;
pub mod hash;
pub mod rlp;
