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
//! Keeping this module purely post-deploy means the signed
//! `userOpHash` always carries `init_code_hash = KECCAK_EMPTY`, so the
//! trusted UI never needs to display a factory call payload it cannot
//! meaningfully validate.

pub use pqsigner_aa::eip1271;
pub use pqsigner_aa::eip6492;
pub use pqsigner_aa::userop;
