//! Test-only scaffold for the `secure-hw-io` slice.
//!
//! The production `hw` module is `#[cfg(not(test))]` because the bus /
//! I/O drivers in this slice all sit behind `feature = "stm32u585"`
//! (or `tropic01-se` / `usb` / `gpio-buttons` / ...) and pull in
//! `cortex_m` MMIO machinery that does not link on host. This scaffold
//! hosts the cross-file pure-logic + source-text invariant suite that
//! pins the bus / I/O peripheral layer:
//!
//!   * I2C1 / I2C2 / SPI / UART / USB register addresses — every base
//!     address is the **Secure alias** so the non-secure world cannot
//!     re-route an SE bus or steal frames off the wire. Wrong alias
//!     (NS vs S) would silently break invariant #3 (encrypted-tunnel-
//!     only SE IO) and invariant #4 (secrets stay in S-world).
//!   * Bit fields, timings, pin assignments — wrong AF number, wrong
//!     PUPDR value, wrong TIMINGR for 100 kHz / 400 kHz, or wrong
//!     baudrate-divider would either silently misconfigure the
//!     peripheral or break SE communication.
//!   * Per-pin GTZC security classifications — `usb_hw::init` is the
//!     ONLY hw-IO module that flips GPIO pins from Secure → Non-Secure,
//!     and it must flip exactly the USB-OTG and TCPP03 pins (PA11 /
//!     PA12 / PA15 / PB5 / PB15) and nothing else. Touching PB8 / PB9
//!     (I2C1 SE bus) or PB12-15 (SPI2 TROPIC01 bus) would expose an SE
//!     bus to the NS world.
//!   * SWD-pin protection — `buttons::init` configures PA8 input but
//!     must NOT touch PA13 (SWDIO) or PA14 (SWCLK); a stray RMW on
//!     `MODER` bits 26/27 / 28/29 would brick the SWD debug port.
//!   * Dev-only / never-ship feature gates — `uart-console`,
//!     `stsafe-probe`, `button-test`, `spi1-arduino` carry "NEVER ship"
//!     or dev-only docstring warnings and live behind explicit cargo
//!     features.
//!
//! On-target tests (real OLED ACK, real SE050 SCP03 handshake, real
//! TROPIC01 SPI frame, real USB enumeration, real button press)
//! happen under the corresponding `make` targets and are NOT exercised
//! here. The host-side suite below catches regressions that would
//! either prevent the on-target tests from booting at all or silently
//! degrade the security properties of the bus stack.

#[cfg(test)]
mod pure_tests;
