//! Test-only scaffold for the `secure-nsc-core` slice.
//!
//! The production `nsc` module is `#[cfg(not(test))]` because most of its
//! files depend on hardware-only crates. This scaffold re-includes the
//! three pure-logic files of the slice (`ptr_validate`, `ns_ptr`,
//! `state`) under a parallel module tree so their `super::*` imports
//! continue to resolve and their inline `#[cfg(test)] mod tests` blocks
//! become live.
//!
//! The cross-file driver `pure_tests` lives here too — a sibling of
//! the included files — so its `super::ptr_validate::*` /
//! `super::state::*` imports inherit the `pub(super)` visibility of the
//! slice's internal items without needing pub-widening re-exports.

#[path = "../nsc/ptr_validate.rs"]
pub mod ptr_validate;

#[path = "../nsc/ns_ptr.rs"]
pub mod ns_ptr;

#[path = "../nsc/state.rs"]
pub mod state;

#[cfg(test)]
mod pure_tests;
