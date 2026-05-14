//! Secure-world address-name lookup.
//!
//! Thin shim over the pure-logic [`pqsigner_tx::names`] crate. The local
//! [`verify_name_bundle`] wrapper threads the firmware-embedded
//! [`crate::db_roots::NAMES_DB_ROOT`] into the verifier so callers don't
//! have to.

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
