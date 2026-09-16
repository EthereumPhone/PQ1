//! `iota2` — ST B-U585I-IOT02A dev board, STM32U585AII6 169-pin BGA.
//!
//! LCD pin facts only; see [`super`] for why this is a subset of
//! `secure/src/board/iota2.rs` rather than a move of it. Every `pub const
//! LCD_` line below is asserted verbatim against that file by
//! `fsbl-tests/tests/source_invariants.rs`.
//!
//! The panel is wired to the Arduino R3 headers as a contiguous PE12..PE15
//! run, all in `AFRH`, with DC on PE7 — the pinout every FSBL bench flow has
//! assumed since the display port was written.

use super::{GPIOE_S, SPI1_S};

// ---------------------------------------------------------------------------
// LCD — NV3007 over SPI1 on the Arduino header
// ---------------------------------------------------------------------------

pub const LCD_SPI_BASE: u32 = SPI1_S;
pub const LCD_SPI_PORT: u32 = GPIOE_S;
pub const LCD_SPI_AF: u32 = 5;
pub const LCD_CS_PIN: u32 = 12;
pub const LCD_SCK_PIN: u32 = 13;
/// Routed, and configured as AF5 by `spi1_init`, but the panel is write-only
/// so nothing reads it. `init_dc_res_gpios` then overrides this same pad to a
/// push-pull output for `LCD_RST_PIN` — harmless, and preserved deliberately
/// to keep this board's register sequence byte-identical to the validated one.
pub const LCD_MISO_PIN: Option<u32> = Some(14);
pub const LCD_MOSI_PIN: u32 = 15;

/// `DC` — PE7 (Arduino D4).
pub const LCD_DC_PORT: u32 = GPIOE_S;
pub const LCD_DC_PIN: u32 = 7;

/// `RES` — PE14 (Arduino D12).
///
/// The panel's reset is strapped to 3V3 on this wiring, so this pin is NOT
/// the panel reset: both PE14 and PD15 proved un-drivable at bring-up. The
/// board resets the panel with the `SWRESET` command instead — see
/// [`LCD_RST_IS_DRIVABLE`].
pub const LCD_RST_PORT: u32 = GPIOE_S;
pub const LCD_RST_PIN: u32 = 14;
pub const LCD_RST_IS_DRIVABLE: bool = false;

/// The backlight is hard-wired to 3V3 on this board — nothing to enable.
pub const LCD_BACKLIGHT_EN: Option<(u32, u32)> = None;
