//! Secure-world function-selector → text-signature lookup.
//!
//! Phase 5 PR 5.4 of the modularity refactor moved the pure-logic
//! bundle verifier into `pqsigner-tx`. This module is now a thin shim
//! that re-exports `SelectorMeta` and adds the `verify_selector_bundle`
//! / `crate::selectors::bundle::verify_selector_bundle` wrappers which
//! thread the firmware-embedded `db_roots::SELECTOR_DB_ROOT` into the
//! verifier so existing call sites
//! (`crate::selectors::verify_selector_bundle(...)`,
//! `crate::selectors::bundle::verify_selector_bundle(...)`) keep
//! working unchanged.

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
