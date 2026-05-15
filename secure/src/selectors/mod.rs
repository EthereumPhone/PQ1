//! Secure-world function-selector → text-signature lookup.
//!
//! Thin shim over the pure-logic [`pqsigner_tx::selectors`] crate. Both
//! [`verify_selector_bundle`] and the nested
//! [`bundle::verify_selector_bundle`] thread the firmware-embedded
//! [`crate::db_roots::SELECTOR_DB_ROOT`] into the underlying verifier.

pub use pqsigner_tx::selectors::bundle::{
    parse_self_attest_bundle, SelectorMeta, SelectorProvenance, MAX_SELECTOR_BUNDLE_LEN,
    MAX_SELF_ATTEST_BUNDLE_LEN,
};

use crate::db_roots::SELECTOR_DB_ROOT;

/// Verify a single selector bundle against the firmware-embedded
/// `SELECTOR_DB_ROOT`.
pub fn verify_selector_bundle<'a>(bundle: &'a [u8]) -> Option<SelectorMeta<'a>> {
    pqsigner_tx::selectors::bundle::verify_selector_bundle(bundle, &SELECTOR_DB_ROOT)
}

/// Backwards-compat alias module: existing imports of
/// `crate::selectors::bundle::verify_selector_bundle(...)` resolve
/// through this nested wrapper to the shim above.
pub mod bundle {
    pub use pqsigner_tx::selectors::bundle::{
        parse_self_attest_bundle, SelectorMeta, SelectorProvenance, MAX_SELECTOR_BUNDLE_LEN,
        MAX_SELF_ATTEST_BUNDLE_LEN,
    };
    use crate::db_roots::SELECTOR_DB_ROOT;

    pub fn verify_selector_bundle<'a>(bundle: &'a [u8]) -> Option<SelectorMeta<'a>> {
        pqsigner_tx::selectors::bundle::verify_selector_bundle(bundle, &SELECTOR_DB_ROOT)
    }
}
