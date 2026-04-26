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
//!
//! ## No on-device initCode construction
//!
//! Earlier revisions had an `init_code` helper that built the
//! initCode for first-deployment UserOps against the now-deleted
//! `PQCoinbaseSmartWalletFactory`. The current `PQSmartWalletFactory`
//! takes only `(bytes32 masterPkSeed, bytes32 masterPkRoot)` — no
//! bootstrap signature, no on-device factory call payload — so the
//! wallet is deployed **externally** (by the companion, a relayer, or
//! any anon account with gas) before the firmware ever signs a UserOp
//! against it.
//!
//! Keeping this module purely post-deploy removes the attack surface
//! flagged as CRIT-5: a non-trivial `init_code_hash` bound into the
//! signed `userOpHash` that the trusted UI has no way to display.
//! All sign paths force `init_code_hash = KECCAK_EMPTY`.

pub mod userop;
