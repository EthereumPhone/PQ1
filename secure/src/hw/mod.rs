//! Hardware peripheral drivers for STM32U585.
//!
//! These modules are compiled when targeting real hardware.

#[cfg(feature = "pka-accel")]
pub mod pka;

#[cfg(feature = "stm32u585")]
pub mod rcc;

#[cfg(feature = "stm32u585")]
pub mod rng;

#[cfg(all(feature = "stm32u585", feature = "hw-sha256"))]
pub mod hash;

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

/// OTP rollback-counter access for the firmware-update subsystem. Only
/// built on real hardware; the QEMU flash backend doesn't model OTP.
#[cfg(feature = "stm32u585")]
pub mod otp;

/// Boot-state page (try-once / active-slot tracking) for the
/// firmware-update subsystem. Uses flash primitives + CRC from
/// fw-manifest, so it's pulled in on real hardware only.
#[cfg(feature = "stm32u585")]
pub mod boot_state;

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
