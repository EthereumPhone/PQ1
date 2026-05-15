//! Secure-world trust gates for ERC20-aware sign confirmation.
//!
//! Thin shim over the pure-logic [`pqsigner_tx::erc20`] crate (calldata
//! decoder, dispatch, Merkle verifier, bundle parser). The local
//! [`bundle`] module adds a wrapper that threads the firmware-embedded
//! [`crate::db_roots::ERC20_DB_ROOT`] into the verifier so callers
//! don't have to.

pub use pqsigner_tx::erc20::{calldata, dispatch, merkle};
pub use pqsigner_tx::erc20::dispatch::{dispatch_tx, TxKind};

/// Local wrapper module: re-exports the metadata struct and length cap
/// from `pqsigner-tx`, but `verify_erc20_bundle` here is a wrapper that
/// passes the firmware-embedded `db_roots::ERC20_DB_ROOT` into the
/// pure-logic verifier so call sites don't need to thread the root.
pub mod bundle {
    pub use pqsigner_tx::erc20::bundle::{Erc20Metadata, MAX_ERC20_BUNDLE_LEN};

    use crate::db_roots::ERC20_DB_ROOT;

    /// Verify a bundle against the firmware-embedded
    /// `ERC20_DB_ROOT`. See [`pqsigner_tx::erc20::bundle::verify_erc20_bundle`]
    /// for the full contract.
    pub fn verify_erc20_bundle<'a>(bundle: &'a [u8]) -> Option<Erc20Metadata<'a>> {
        pqsigner_tx::erc20::bundle::verify_erc20_bundle(bundle, &ERC20_DB_ROOT)
    }
}
