//! `pqsigner-aa` — ERC-4337 Account Abstraction support for the secure
//! world (and any future host-side reference signer).
//!
//! Owns everything needed to take a user-authorised inner Ethereum
//! transaction (a plain EIP-1559 envelope) and turn it into the
//! EntryPoint-v0.6 `userOpHash` + the firmware-friendly SHA-256 sphincs
//! digest that the SLH-DSA signing key signs.
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
//! the secure world from primitive inputs. Most importantly, the
//! `callData` field of the UserOperation — which controls the actual
//! money flow on chain — is reconstructed by this module from the
//! displayed inner tx (`execute(target, value, data)`), so the bytes
//! the EntryPoint executes are the same bytes the user saw on the
//! trusted UI.
//!
//! ## Layering
//!
//! `userop` exposes the wire-format parsing for the secure-side
//! `cmd_sign_userop` handler and the helpers used by it and the e2e
//! harness. `eip1271` exposes the Solady nested-EIP-712 hash
//! construction the off-chain `CMD_SIGN_OFFCHAIN` workflow signs.
//!
//! Phase 5 PR 5.2 of the modularity refactor extracted this crate from
//! `secure/src/aa/`. The secure crate keeps a re-export shim
//! (`secure/src/aa/mod.rs`) so existing call sites compile unchanged.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod eip1271;
pub mod userop;
