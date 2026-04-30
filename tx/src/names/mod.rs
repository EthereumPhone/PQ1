//! Secure-world address-name lookup.
//!
//! Parallels [`crate::erc20`] but for the `(chain_id, address) → display
//! name` DB. The non-secure world attaches up to
//! [`resolver::MAX_NAME_BUNDLES`] bundles to a `CMD_SIGN_USEROP`
//! request; each bundle is verified against the supplied
//! `root: &[u8; 32]` (typically `db_roots::NAMES_DB_ROOT`) before any
//! name reaches the trusted UI.
//!
//! Public surface:
//!
//! - [`bundle::verify_name_bundle`] — bundle parser + Merkle verifier
//! - [`resolver::NameResolver`] / [`resolver::NameMeta`] — verified
//!   names passed into the display layer

pub mod bundle;
pub mod resolver;

pub use bundle::{verify_name_bundle, NameMeta, MAX_NAME_BUNDLE_LEN};
pub use resolver::{NameResolver, MAX_NAME_BUNDLES};
