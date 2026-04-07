//! Hardware peripheral drivers for STM32U585.
//!
//! These modules are only compiled when targeting real hardware
//! (feature `pka-accel` for the PKA crypto accelerator).

#[cfg(feature = "pka-accel")]
pub mod pka;
