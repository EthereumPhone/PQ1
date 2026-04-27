//! Pure-logic Phase 2 calldata decoder — text-signature parser +
//! Solidity-ABI walker.
//!
//! Lives at the `crate::tx::typed_call` path (not under `display`)
//! because it has no `crate::ui` / no `crate::tx::display` deps —
//! `cargo test -p sphincs-tz-secure` exercises it on the host, in
//! parallel with the rest of the host-testable parsers.
//!
//! The on-screen rendering side lives at
//! [`crate::tx::display::typed_call`]; that one is gated to the
//! firmware-only `cfg(not(test))` path because it does pull in the
//! display primitives.

pub mod abi;
pub mod parser;
