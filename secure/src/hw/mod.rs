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

#[cfg(feature = "stm32u585")]
pub mod rcc;

// Die identity (DBGMCU_IDCODE). One register read; the decode + SESIP-scope
// rule live in `crate::die_id`, host-tested.
#[cfg(feature = "stm32u585")]
pub mod dbgmcu;

#[cfg(feature = "stm32u585")]
pub mod rng;

#[cfg(all(feature = "stm32u585", feature = "hw-sha256"))]
pub mod hash;

#[cfg(all(feature = "stm32u585", feature = "usb"))]
pub mod usb_hw;

#[cfg(all(feature = "stm32u585", any(feature = "se050", feature = "optiga-trust-m")))]
pub mod i2c_hw;

#[cfg(all(feature = "stm32u585", feature = "ui-lcd"))]
pub mod spi_hw;

#[cfg(feature = "stm32u585")]
pub mod flash;

/// GTZC1 TZIC — TrustZone Illegal-access Controller. Raises NVIC IRQ 8
/// when NS attempts to access a SECURE-marked peripheral. Configured
/// from `sau::stm32::configure_gtzc` and dispatched from
/// `main::DefaultHandler`.
#[cfg(feature = "stm32u585")]
pub mod tzic;

/// STM32U585 TAMP (tamper detection) — log-only dev harness. Feature-gated
/// because enabling crypto-peripheral-fault monitoring (ITAMP9) during a
/// probe-rs debug session on a dev board can false-trigger on glitch-sensitive
/// SAES sequences. Port of Trezor's tamper driver; see
/// `docs/architecture/trezor-comparison.md §2.5`.
#[cfg(all(feature = "stm32u585", feature = "tamp"))]
pub mod tamp;

/// TIM2-PWM power-consumption mask on PA5. Simplified (no-DMA) port of
/// Trezor's `sec/consumption_mask/`; see `docs/architecture/trezor-comparison.md §3.1`.
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

// `sca-trigger` GPIO instrumentation — production-fenced (see the
// `compile_error!` in `nsc/mod.rs`). The module compiles to no-op
// stubs when the feature is OFF, so the `sca_trigger::Trigger::raise()`
// callsites elsewhere in the crate stay buildable on every config.
pub mod sca_trigger;

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
/// (OPTIGA PBS, SE050 SCP03, ...). Only compiled on
/// real hardware — the underlying OTP master key lives in STM32U585-
/// specific flash OTP.
#[cfg(feature = "stm32u585")]
pub mod secret_keys;

#[cfg(feature = "stsafe-probe")]
pub mod i2c2_probe;

#[cfg(feature = "gpio-buttons")]
pub mod buttons;

/// NV3007 SPI LCD driver for the ZT165M017AT module (142×428 TFT,
/// RGB565, 4-line SPI). Phase A: byte-level command/data primitives
/// + the production init sequence + set_window + fill_color +
/// write_pixels. Phase B–D follow once the LCD is physically wired.
/// See module docs for pin mapping + bring-up plan.
#[cfg(feature = "ui-lcd")]
pub mod lcd_nv3007;

/// Independent watchdog (IWDG) — USB-path hang detection. Behind the
/// `iwdg` feature (which implies `stm32u585`); compiles to no-op stubs
/// otherwise, so call sites in `main` stay cfg-free. The off-build's
/// `init` never starts the watchdog, so test builds can't self-reset.
pub mod iwdg;

/// Secure-element supply + enable lines. No-op on boards where the SE rail
/// is unconditionally live (`iota2`); on `pq1` it asserts `LDO2_EN` (PA8),
/// without which **both** secure elements are unpowered and every I2C
/// transaction fails in a way that looks like a bus fault. Must run before
/// `i2c_hw::init`.
#[cfg(all(feature = "stm32u585", any(feature = "se050", feature = "optiga-trust-m")))]
pub mod se_power;

/// Non-destructive secure-element address probe (`se-i2c-probe`). Zero data
/// bytes reach either chip — see the module header before extending it.
/// Bench diagnostic only; in `PROD_FORBIDDEN`.
#[cfg(all(
    feature = "se-i2c-probe",
    feature = "stm32u585",
    any(feature = "se050", feature = "optiga-trust-m")
))]
pub mod se_i2c_probe;

/// Bit-banged I2C for the bench OLED (`ui-oled-bench`). **Display only** —
/// it has none of the hardware peripheral's timing, error reporting or GTZC
/// coverage, so it must never carry secure-element traffic.
#[cfg(all(feature = "ui-oled-bench", feature = "stm32u585"))]
pub mod soft_i2c;
