//! STM32U585 peripheral drivers shared between the secure world and the FSBL.
//!
//! Both worlds run in secure state on the same silicon and need the same
//! hardware. Anything in here has EXACTLY ONE definition for that reason — see
//! the crate manifest for why a second copy was rejected.
//!
//! The binary that links this crate must supply one symbol:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn pqsigner_hash_fault() -> ! { /* world-specific */ }
//! ```
//!
//! It is the unrecoverable-HASH-engine posture, and it differs by world: the
//! secure world zeroizes every in-SRAM secret and resets; the FSBL has no
//! secrets yet and halts. Making it a hook rather than a `cfg` keeps the
//! decision at the binary that owns the secrets.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic)]

pub mod hash;
pub mod mmio;
