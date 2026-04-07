//! Secure-world trust gates for ERC20-aware sign confirmation.
//!
//! The full ERC20 metadata DB lives in **non-secure rodata**, signed
//! by the same hybrid firmware-signing key as the rest of the firmware.
//! The secure world embeds only a single 32-byte Merkle root
//! (`crate::db_roots::ERC20_DB_ROOT`).
//!
//! At sign time the non-secure world looks up the contract in its
//! local index, builds a `(canonical_metadata_bytes, merkle_proof,
//! leaf_index)` bundle, and forwards it across the gateway. The
//! secure world re-derives the leaf hash from the supplied metadata
//! and walks the proof up to the embedded root before trusting any
//! of it for trusted-UI display.
//!
//! Public surface:
//!
//! - [`merkle::verify_proof`] — Merkle proof verifier shared by both DBs
//! - [`bundle::verify_erc20_bundle`] — full bundle parser + verifier
//! - [`calldata::parse_erc20_calldata`] — strict ABI decoder for the
//!   `transfer`, `transferFrom`, and `approve` ERC20 selectors
//! - [`dispatch::dispatch_tx`] — picks the trust level for an
//!   already-parsed EIP-1559 envelope, given an optional verified
//!   metadata bundle from the gateway

pub mod bundle;
pub mod calldata;
pub mod dispatch;
pub mod merkle;

pub use bundle::{verify_erc20_bundle, Erc20Metadata};
pub use calldata::{parse_erc20_calldata, Erc20Call};
pub use dispatch::{dispatch_tx, TxKind};
