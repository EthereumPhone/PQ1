//! Hardware peripheral drivers for STM32U585.
//!
//! These modules are compiled when targeting real hardware.

#[cfg(feature = "pka-accel")]
pub mod pka;

#[cfg(feature = "stm32u585")]
pub mod rcc;

#[cfg(feature = "stm32u585")]
pub mod rng;

#[cfg(all(feature = "stm32u585", feature = "ui-oled"))]
pub mod i2c;

#[cfg(all(feature = "stm32u585", feature = "usb"))]
pub mod usb_hw;

#[cfg(all(feature = "stm32u585", any(feature = "se050", feature = "optiga-trust-m")))]
pub mod i2c_hw;

#[cfg(all(feature = "stm32u585", feature = "tropic01-se"))]
pub mod spi_hw;

#[cfg(all(feature = "stm32u585", feature = "tropic01-se"))]
pub mod spi;

#[cfg(feature = "stm32u585")]
pub mod flash;

/// Device-bound wrap-key derivation (UID + firmware measurement). Only
/// pulled in on real hardware because the QEMU flash backend is a RAM
/// buffer — there's no persistent flash to seal and the QEMU UID is
/// a constant anyway.
#[cfg(feature = "stm32u585")]
pub mod huk;

#[cfg(feature = "stsafe-probe")]
pub mod i2c2_probe;

#[cfg(feature = "gpio-buttons")]
pub mod buttons;
