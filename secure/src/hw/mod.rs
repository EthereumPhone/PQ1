//! Hardware peripheral drivers for STM32U585.
//!
//! These modules are compiled when targeting real hardware.

#[cfg(feature = "pka-accel")]
pub mod pka;

#[cfg(feature = "stm32u585")]
pub mod rcc;

#[cfg(feature = "stm32u585")]
pub mod rng;

#[cfg(all(feature = "stm32u585", feature = "usb"))]
pub mod usb_hw;

#[cfg(all(feature = "stm32u585", feature = "se050"))]
pub mod i2c_hw;
