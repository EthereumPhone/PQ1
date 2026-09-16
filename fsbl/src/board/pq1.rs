//! `pq1` — AL_A66_MB_V10, STM32U585CIU6 48-pin UFQFPN.
//!
//! LCD pin facts only; see [`super`] for why this is a subset of
//! `secure/src/board/pq1.rs` rather than a move of it. Every `pub const LCD_`
//! line below is asserted verbatim against that file by
//! `fsbl-tests/tests/source_invariants.rs`.
//!
//! Three properties of this board broke the previous hard-coded driver, and
//! they are the reason the FSBL LCD needed porting at all:
//!
//!   1. The panel is on **port A**, not port E — and port E is not bonded on
//!      a 48-pin part, so the old driver's writes landed on nothing.
//!   2. The SPI pins are **non-contiguous** (4/5/7, PA6 skipped) rather than
//!      iota2's tidy 12..15 run, so a driver deriving pins by offset from CS
//!      is wrong here.
//!   3. They sit **below pin 8**, so their alternate-function nibbles are in
//!      `AFRL`; the old driver wrote `AFRH` unconditionally.
//!
//! DC / RST / backlight are on **port B**, a different port from the SPI, so
//! the driver must clock two GPIO ports rather than one.

use super::{GPIOA_S, GPIOB_S, SPI1_S};

// ---------------------------------------------------------------------------
// LCD — NV3007 over SPI1 on port A, control lines on port B
// ---------------------------------------------------------------------------

pub const LCD_SPI_BASE: u32 = SPI1_S;
pub const LCD_SPI_PORT: u32 = GPIOA_S;
pub const LCD_SPI_AF: u32 = 5;
pub const LCD_CS_PIN: u32 = 4;
pub const LCD_SCK_PIN: u32 = 5;
pub const LCD_MOSI_PIN: u32 = 7;
/// The panel is write-only on this board — MISO is not routed.
pub const LCD_MISO_PIN: Option<u32> = None;

/// `LCM_DC` — PB0.
pub const LCD_DC_PORT: u32 = GPIOB_S;
pub const LCD_DC_PIN: u32 = 0;

/// `LCM_RST` — PB1. Unlike `iota2` this really is driven by the MCU, so the
/// hardware reset pulse is available instead of the SPI `SWRESET`.
pub const LCD_RST_PORT: u32 = GPIOB_S;
pub const LCD_RST_PIN: u32 = 1;
pub const LCD_RST_IS_DRIVABLE: bool = true;

/// `LCM_EN` — PB15, the enable for the AW99703 backlight boost driver.
///
/// **This alone may not light the panel.** The AW99703 is an I2C-controlled
/// LED driver at `0x36` on I2C2 (PB13/PB14); brightness almost certainly
/// has to be programmed over that bus after the enable is asserted. There
/// is no driver for it in the tree yet.
///
/// Consequence for bring-up, worth stating where it will be read: a DARK
/// PANEL IS NOT EVIDENCE THIS PORT FAILED. The FSBL cannot drive I2C2 (no
/// I2C driver at this stage, by design), so the success criterion for the
/// display port is the `stage-marker` page showing `LcdInited` and
/// `RenderFlushed` reached — not visible pixels.
pub const LCD_BACKLIGHT_EN: Option<(u32, u32)> = Some((GPIOB_S, 15));
