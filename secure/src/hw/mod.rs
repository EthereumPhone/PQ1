//! Hardware peripheral drivers for STM32U585.
//!
//! These modules are compiled when targeting real hardware.

/// Typed MMIO register handles — encapsulates `unsafe` volatile
/// accesses behind safe `.read()` / `.write()` / `.modify()` methods,
/// so peripheral drivers don't have to repeat `unsafe` at every touch.
///
/// Always available (no hardware feature gate) so non-`stm32u585` builds
/// — notably the QEMU mps2-an505 boot path in `sau::init` — can also use
/// it for the ARMv8-M architectural peripherals (SAU, SysTick, DWT, ICSR,
/// DHCSR) and the QEMU SSE-200 MPC blocks.
pub mod mmio;

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

/// STM32U585 TAMP (tamper detection) — log-only dev harness. Feature-gated
/// because enabling crypto-peripheral-fault monitoring (ITAMP9) during a
/// probe-rs debug session on a dev board can false-trigger on glitch-sensitive
/// SAES sequences. Port of Trezor's tamper driver; see
/// `docs/trezor-comparison.md §2.5`.
#[cfg(all(feature = "stm32u585", feature = "tamp"))]
pub mod tamp;

/// TIM2-PWM power-consumption mask on PA5. Simplified (no-DMA) port of
/// Trezor's `sec/consumption_mask/`; see `docs/trezor-comparison.md §3.1`.
/// Feature-gated; init() + randomize() are no-ops without the feature.
#[cfg(all(feature = "stm32u585", feature = "consumption-mask"))]
pub mod consumption_mask;

/// OTP rollback-counter access for the firmware-update subsystem. Only
/// built on real hardware; the QEMU flash backend doesn't model OTP.
#[cfg(feature = "stm32u585")]
pub mod otp;

/// Boot-state page (try-once / active-slot tracking) for the
/// firmware-update subsystem. Uses flash primitives + CRC from
/// fw-manifest, so it's pulled in on real hardware only.
#[cfg(feature = "stm32u585")]
pub mod boot_state;

/// Device-bound wrap-key derivation (UID + OTP master). Only pulled
/// in on real hardware because the QEMU flash backend is a RAM
/// buffer and the QEMU UID is a constant.
#[cfg(feature = "stm32u585")]
pub mod huk;

/// STM32U585 Secure AES (SAES) coprocessor driver — AES-256 ECB under
/// KEYSEL={Software, DHUK, BHK, DHUK^BHK}. Tier 1 of the three-tier
/// key hierarchy (work-todo #7). OFF by default; gated behind
/// `saes-dhuk` until bench-validated.
#[cfg(feature = "saes-dhuk")]
pub mod saes;

/// Software CMAC-AES-256 layered on top of `saes::encrypt_ecb_block`
/// with `KeySel::Dhuk`. The derivation primitive for the Tier-1
/// `hw::secret_keys` rewrite (task #31).
#[cfg(feature = "saes-dhuk")]
pub mod saes_cmac;

/// Early-boot GPIO pulse on PE4 (Arduino D5) for RDP1 boot
/// bisection — the only diagnostic that survives both UART silence
/// AND SWD-halt denial at TZEN=1+RDP=1+no-OEM-keys. See module
/// docstring for pulse encoding.
#[cfg(feature = "boot-pulse")]
pub mod boot_pulse;

/// Minimal USART1 driver routed to the B-U585I-IOT02A ST-LINK VCP
/// (PA9 TX). Used under `uart-console` for diagnostic output from
/// builds that can't rely on semihosting — specifically the RDP1
/// SAES self-test target.
#[cfg(feature = "uart-console")]
pub mod uart;

/// Tier-2 BHK (Boot Hardware Key) lifecycle — first-boot TRNG
/// generation + DHUK-ECB wrap + flash write; subsequent-boot unwrap +
/// TAMP backup-register load + `BHKLOCK`. Compiled only under the
/// `bhk` feature (OFF by default — see module docs).
#[cfg(feature = "bhk")]
pub mod bhk;

/// Domain-separated per-purpose subkeys derived from the OTP master
/// (OPTIGA PBS, SE050 SCP03, TROPIC01 pairing, ...). Only compiled on
/// real hardware — the underlying OTP master key lives in STM32U585-
/// specific flash OTP.
#[cfg(feature = "stm32u585")]
pub mod secret_keys;

#[cfg(feature = "stsafe-probe")]
pub mod i2c2_probe;

#[cfg(feature = "gpio-buttons")]
pub mod buttons;
