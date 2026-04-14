//! ERC-4337 Account Abstraction support for the secure world.
//!
//! This module owns everything needed to take a user-authorised inner
//! Ethereum transaction (a plain EIP-1559 envelope) and turn it into
//! the EntryPoint-v0.6 `userOpHash` that the trusted UI confirms and
//! the SLH-DSA signing key signs.
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
//! `userop` exposes the wire-format parsing for the
//! [`crate::nsc::cmd_sign_userop`] handler and the helpers used by it
//! and the e2e harness.

pub mod init_code;
pub mod userop;
