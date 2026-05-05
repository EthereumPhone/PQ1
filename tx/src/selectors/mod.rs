//! Secure-world function-selector → text-signature lookup.
//!
//! Parallels [`crate::names`] but for the EVM 4-byte function selector.
//! Whereas the ERC-20 / Names DBs ride NS rodata, the selectors blob
//! lives on the **host** (companion app). Only the 32-byte
//! `db_roots::SELECTOR_DB_ROOT` is bound into the secure image. The
//! companion attaches a `(selector, text_sig, leaf_index, proof)`
//! bundle to `CMD_SIGN_USEROP`; the secure world Merkle-verifies it
//! against the supplied root AND cross-checks
//! `bundle.selector == calldata[0..4]` before any text-sig reaches the
//! trusted UI.
//!
//! The combination of those two checks is what makes the host a pure
//! relay: it cannot forge bundles (Merkle proof fails), it cannot
//! substitute one selector's text-sig onto unrelated calldata
//! (cross-check fails), and adversarial 4byte collisions are filtered
//! out at curation time so the Merkle root only commits to a single
//! canonical signature per selector.
//!
//! Public surface:
//!
//! - [`bundle::verify_selector_bundle`] — bundle parser + Merkle verifier
//! - [`bundle::SelectorMeta`] — verified result threaded into the display
//!   layer alongside the ERC-20 / Names metadata

pub mod bundle;

pub use bundle::{
    parse_self_attest_bundle, verify_selector_bundle, SelectorMeta, SelectorProvenance,
    MAX_SELECTOR_BUNDLE_LEN, MAX_SELF_ATTEST_BUNDLE_LEN,
};
