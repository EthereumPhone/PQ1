//! Re-export shim over [`pqsigner_hw::mmio`].
//!
//! The typed MMIO handles moved to the `pqsigner-hw` workspace crate on
//! 2026-09-28 so the FSBL could share the HASH driver that uses them (#758).
//! Every existing `crate::hw::mmio::{Reg32, RoReg32}` path keeps working.
pub use pqsigner_hw::mmio::{Reg32, RoReg32};
