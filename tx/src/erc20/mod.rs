//! Trust gates for ERC-20-aware sign confirmation.
//!
//! The full ERC-20 metadata DB lives in **non-secure rodata**, signed
//! by the same hybrid firmware-signing key as the rest of the firmware.
//! Only a 32-byte Merkle root is bound into the secure image; bundles
//! that cross the gateway are verified against the supplied root via
//! [`merkle::verify_proof`] before any byte reaches the trusted UI.
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

pub use dispatch::{dispatch_tx, TxKind};
