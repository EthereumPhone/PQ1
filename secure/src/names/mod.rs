//! Secure-world address-name lookup.
//!
//! Phase 5 PR 5.4 of the modularity refactor moved the pure-logic
//! bundle verifier + `NameResolver` into `pqsigner-tx`. This module
//! is now a thin shim that re-exports those types and adds the
//! `verify_name_bundle` wrapper which threads the firmware-embedded
//! `db_roots::NAMES_DB_ROOT` into the verifier so existing call sites
//! (`crate::names::verify_name_bundle(...)`,
//! `crate::names::NameResolver`) keep working unchanged.

pub use pqsigner_tx::names::resolver;
pub use pqsigner_tx::names::bundle::{NameMeta, MAX_NAME_BUNDLE_LEN};
pub use pqsigner_tx::names::resolver::{NameResolver, MAX_NAME_BUNDLES};

use crate::db_roots::NAMES_DB_ROOT;

/// Verify a single name bundle against the firmware-embedded
/// `NAMES_DB_ROOT`. See
/// [`pqsigner_tx::names::bundle::verify_name_bundle`] for the full
/// contract.
pub fn verify_name_bundle<'a>(bundle: &'a [u8]) -> Option<NameMeta<'a>> {
    pqsigner_tx::names::bundle::verify_name_bundle(bundle, &NAMES_DB_ROOT)
}
