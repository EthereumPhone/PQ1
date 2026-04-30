//! sphincs-tz-shared — thin re-export shim over `pqsigner-proto`.
//!
//! Phase 3 of the modularity refactor moved every protocol-level
//! constant and enum into `pqsigner-proto` so it can be the single
//! source of truth for the firmware ↔ on-chain (Solidity) ↔ companion
//! IDL. This crate stays in the workspace because:
//!
//!   1. ~67 source files import from `sphincs_tz_shared` today.
//!      Re-exporting via `pub use` keeps every one of those imports
//!      working unchanged through the rest of the refactor.
//!   2. The `apdu_framing` and `db_format` modules are *implementation*
//!      (USB protocol parsers + ERC-20 Merkle DB layout), not
//!      *protocol IDL*. They depend on the constants from
//!      `pqsigner-proto` but are too heavy for the constants-only crate.
//!
//! New code should import from `pqsigner-proto` directly. This shim is
//! retained until every call site has been migrated (Phase 11 cleanup).
//!
//! Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md

#![no_std]

// Implementation modules that need a home but aren't pure-IDL.
pub mod apdu_framing;
pub mod db_format;

// Re-export every protocol constant + enum + wire-format size from the
// new authoritative crate. Glob-import so adding constants to
// `pqsigner-proto` automatically becomes visible through this shim.
pub use pqsigner_proto::*;
