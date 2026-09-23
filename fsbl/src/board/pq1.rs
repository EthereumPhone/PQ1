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

/// `LCM_EN` — PB15, the AW99703 backlight driver's `HWEN`.
///
/// **This alone does not light the panel** — settled by experiment, not
/// inference (#705, commit `a3226eca`): a dev build that stalled 5 s before the
/// chip's first register write showed a blank screen for exactly that window.
/// `HWEN` high only reaches *Standby*; the part emits no LED current until
/// `MODE[1:0]` is written to `01` over I2C2, so asserting this pin is
/// necessary and not sufficient.
///
/// The consequence is what #705 exists for: any stage that runs before that
/// I2C write renders onto a dark panel, including this one. A dark panel is
/// therefore NOT evidence that the display port failed, and until the I2C
/// stage lands the success criterion stays the `stage-marker` page reaching
/// `LcdInited` and `RenderFlushed`, not visible pixels.
pub const LCD_BACKLIGHT_EN: Option<(u32, u32)> = Some((GPIOB_S, 15));

// ---------------------------------------------------------------------------
// AW99703 backlight driver — I2C2 transport (#705)
// ---------------------------------------------------------------------------
//
// Copied VERBATIM from `secure/src/board/pq1.rs`; `source_invariants.rs`
// asserts each line appears there unchanged, because two copies of a pin map
// that disagree is how the wrong pins reached silicon once already (PA8 is a
// button on iota2 and the secure-element rail enable here).
//
// The bus is shared with the AW21036 RGB driver at 0x34, which the FSBL never
// talks to — but which can hold SDA after a warm reset mid-transaction, so an
// I2C stage here needs a bus-idle check and clock recovery rather than an
// unconditional START.

/// I2C2 SCL/SDA port — shared bus carrying both LED-driver ICs.
pub const AUX_I2C_PORT: u32 = GPIOB_S;
pub const AUX_I2C_SCL_PIN: u32 = 13;
pub const AUX_I2C_SDA_PIN: u32 = 14;

/// AW99703 backlight boost driver, 7-bit address.
pub const BACKLIGHT_I2C_ADDR: u8 = 0x36;
