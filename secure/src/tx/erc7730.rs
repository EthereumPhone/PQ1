//! Re-export shim over `pqsigner-erc7730`.
//!
//! Symmetric to `secure/src/tx/mod.rs` re-exporting `pqsigner-tx-core`
//! and `secure/src/erc20/mod.rs` re-exporting `pqsigner-tx::erc20`.
//! Existing call sites (`crate::tx::erc7730::verify_erc7730_bundle`)
//! reach through this shim rather than naming the workspace crate
//! directly, so a future move of the crate's path doesn't ripple
//! into the secure code.
//!
//! The shim also funnels the firmware-pinned Merkle root through a
//! thin wrapper so call sites don't have to reach into `db_roots`
//! every time.

pub use pqsigner_erc7730::binding::{
    cross_check_contract, cross_check_eip712, BindingError,
};
pub use pqsigner_erc7730::bundle::{
    leaf_hash, verify_erc7730_bundle, BundleError, VerifiedDescriptor,
    MAX_ERC7730_BUNDLE_LEN, MAX_PROOF_DEPTH,
};
pub use pqsigner_erc7730::ir::{
    ContextKind, Erc7730Ir, FormatOp, IrError, PathOp, Visibility,
    HEADER_LEN, MAX_FIELDS_PER_FORMAT, MAX_FORMATS, MAX_IR_LEN,
    MAX_NESTING, MAX_POOL_ENTRY_LEN, SCHEMA_VER,
};
