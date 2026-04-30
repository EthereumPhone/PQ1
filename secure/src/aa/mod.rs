//! ERC-4337 Account Abstraction support for the secure world.
//!
//! Phase 5 PR 5.2 of the modularity refactor moved the entire `aa/`
//! body into the `pqsigner-aa` crate so host-side reference signers
//! (and the future `fwsign verify-release --simulate-userop` tool) can
//! depend on it without pulling in the rest of `secure/`. This module
//! is now a thin re-export shim: every existing call site
//! (`crate::aa::userop::compute_user_op_hash`,
//! `crate::aa::eip1271::personal_sign_replay_safe_hash`, ...) keeps
//! working unchanged.
//!
//! ## Trust model (unchanged)
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

pub use pqsigner_aa::eip1271;
pub use pqsigner_aa::userop;
