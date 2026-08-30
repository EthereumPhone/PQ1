//! Pin map for the **ST B-U585I-IOT02A** dev board (`iota2`).
//!
//! MCU: STM32U585AII6, 169-pin BGA — every GPIO port A..I is bonded.
//!
//! This is the historical bench board: every constant here is the value
//! the driver modules used before the board split, so selecting `iota2`
//! (the default) reproduces the previous behaviour exactly.
//!
//! Empirical notes worth keeping with the pin numbers, because several of
//! these were established by logic-analyser capture rather than from the
//! ST user manual:
//!
//! - The Arduino-header silkscreen is off-by-one against UM2839 — `D5` is
//!   actually PE4 and `D6` is PE0, confirmed with `pin_diag::header_sweep`.
//!   That is why the OPTIGA reset lands on PE0 and not where the board
//!   documentation implies.
//! - The LCD `RES` line is strapped to 3V3 on this wiring, so the NV3007
//!   driver reaches reset over the SPI `SWRESET` (0x01) command instead of
//!   pulsing the pin. `LCD_RST` below is recorded for completeness but the
//!   driver does not rely on it.

#![allow(dead_code)] // Full board inventory; consumed incrementally by drivers.

use super::{
    SeI2cBus, GPIOA_S, GPIOB_S, GPIOC_S, GPIOE_S, I2C1_S, RCC_APB1ENR1_OFF, RCC_APB1RSTR1_OFF,
    RCC_APB2ENR_OFF, RCC_I2C1EN_BIT, RCC_I2C1RST_BIT, RCC_USART1EN_BIT, SPI1_S, USART1_S,
};

/// Human-readable board name, for boot banners and log headers.
pub const BOARD_NAME: &str = "B-U585I-IOT02A (iota2)";

// ---------------------------------------------------------------------------
// Debug console UART
//
// USART1 TX on PA9 (AF7), routed to the on-board ST-LINK's USB virtual COM
// port. The VCP is a feature of the *debugger* MCU, not the target, so it
// keeps forwarding bytes at RDP >= 1 where SWD (and therefore semihosting)
// is gone — this is the channel the RDP1 SAES self-test reports through.
// ---------------------------------------------------------------------------

pub const CONSOLE_UART_BASE: u32 = USART1_S;
/// `USART1EN` lives in `RCC_APB2ENR`.
pub const CONSOLE_UART_RCC_ENR_OFF: u32 = RCC_APB2ENR_OFF;
pub const CONSOLE_UART_RCC_EN_BIT: u32 = RCC_USART1EN_BIT;
pub const CONSOLE_TX_PORT: u32 = GPIOA_S;
pub const CONSOLE_TX_PIN: u32 = 9;
pub const CONSOLE_TX_AF: u32 = 7;

/// 115200 8N1. USART1's default clock source (`CCIPR1[1:0]` = 00) is PCLK2,
/// which `hw::rcc::init` leaves at SYSCLK = 160 MHz (APB2 prescaler /1).
/// With 16x oversampling `BRR = PCLK / baud = 160_000_000 / 115_200 = 1389`
/// (0.064 % error — well inside the framing tolerance).
pub const CONSOLE_BRR: u32 = 1389;

// ---------------------------------------------------------------------------
// LCD — NV3007 over SPI1 on the Arduino header (`spi1-arduino`)
// ---------------------------------------------------------------------------

pub const LCD_SPI_BASE: u32 = SPI1_S;
pub const LCD_SPI_PORT: u32 = GPIOE_S;
pub const LCD_SPI_AF: u32 = 5;
pub const LCD_CS_PIN: u32 = 12;
pub const LCD_SCK_PIN: u32 = 13;
pub const LCD_MISO_PIN: u32 = 14;
pub const LCD_MOSI_PIN: u32 = 15;

/// Data/command select — PE7 (Arduino `D4`).
pub const LCD_DC_PORT: u32 = GPIOE_S;
pub const LCD_DC_PIN: u32 = 7;

/// Reset — PE14. Strapped to 3V3 on this board, so the driver uses the
/// `SWRESET` command instead; see the module note above.
pub const LCD_RST_PORT: u32 = GPIOE_S;
pub const LCD_RST_PIN: u32 = 14;
/// This board drives the panel reset over SPI, not over the pin.
pub const LCD_RST_IS_DRIVABLE: bool = false;

/// No tearing-effect input is wired.
pub const LCD_TE: Option<(u32, u32)> = None;
/// Backlight is unconditional — no enable line and no LED-driver IC.
pub const LCD_BACKLIGHT_EN: Option<(u32, u32)> = None;

// ---------------------------------------------------------------------------
// Secure elements — both share I2C1 on PB8/PB9 (AF4)
// ---------------------------------------------------------------------------

pub const OPTIGA_I2C_BASE: u32 = I2C1_S;
pub const OPTIGA_I2C_PORT: u32 = GPIOB_S;
pub const OPTIGA_I2C_SCL_PIN: u32 = 8;
pub const OPTIGA_I2C_SDA_PIN: u32 = 9;
pub const OPTIGA_I2C_AF: u32 = 4;

/// SE050 shares the OPTIGA bus on this board (`pq1` splits them).
pub const SE050_I2C_BASE: u32 = I2C1_S;
pub const SE050_I2C_PORT: u32 = GPIOB_S;
pub const SE050_I2C_SCL_PIN: u32 = 8;
pub const SE050_I2C_SDA_PIN: u32 = 9;
pub const SE050_I2C_AF: u32 = 4;

/// Bench-only SSD1306 OLED, bit-banged I2C. **`ui-oled-bench` only.**
///
/// The historical pins from before the backend was removed — PB8/PB9, the
/// Arduino-header I2C1 lines. **These are also this board's secure-element
/// bus**, so the bench OLED and a real SE backend cannot coexist here: both
/// would configure the same two pads, one as AF4 open-drain for the I2C1
/// peripheral and one as a GPIO for bit-banging. `hw::soft_i2c` rejects that
/// combination at compile time; use `mock-se` for OLED builds on this board.
///
/// (pq1 bit-bangs on PB3/PA3 instead, which no *secure element* claims — but
/// PB3 there is the SCA scope trigger, so that board has its own exclusivity
/// rule. Both are enforced in `hw::soft_i2c`.)
/// Height in pixels of the SSD1306 wired to this board's bench setup.
///
/// Strictly a property of the **module you plugged in**, not of the board —
/// it lives here because that is where the rest of the bench-OLED wiring is
/// described, and because it must be a compile-time constant (it sizes the
/// framebuffer). The historical bench module (128x32). Four text rows at 8 px pitch.
///
/// Only 32 and 64 are valid: those are the SSD1306 geometries, and both
/// divide evenly by 8 (the page height) and by `DISPLAY_ROWS`. Enforced by a
/// `const assert!` in `ui::oled`.
pub const OLED_HEIGHT_PX: usize = 32;

pub const OLED_SCL: Option<(u32, u32)> = Some((GPIOB_S, 8));
pub const OLED_SDA: Option<(u32, u32)> = Some((GPIOB_S, 9));

/// The SE I2C buses to bring up: exactly one, shared by both chips.
pub const SE_I2C_BUSES: &[SeI2cBus] = &[SeI2cBus {
    name: "I2C1 (OPTIGA 0x30 + SE050 0x48)",
    base: I2C1_S,
    rcc_enr_off: RCC_APB1ENR1_OFF,
    rcc_rstr_off: RCC_APB1RSTR1_OFF,
    rcc_en_bit: RCC_I2C1EN_BIT,
    rcc_rst_bit: RCC_I2C1RST_BIT,
    port: GPIOB_S,
    scl_pin: 8,
    sda_pin: 9,
    af: 4,
    // Both chips share this bus on the dev board; no address conflict.
    probe_addrs: &[(0x30, "OPTIGA Trust M"), (0x48, "SE050")],
}];

/// OPTIGA active-low reset — PE0, i.e. the header pin silkscreened `D6`
/// (UM2839 disagrees; the LA capture wins).
pub const OPTIGA_RST: Option<(u32, u32)> = Some((GPIOE_S, 0));
/// No independent SE050 enable line is wired.
pub const SE050_EN: Option<(u32, u32)> = None;
/// The secure-element supply is not software-gated on this board — both
/// parts are powered whenever the board is.
pub const SE_RAIL_EN: Option<(u32, u32)> = None;

// ---------------------------------------------------------------------------
// Buttons — active-low, internal pull-up
// ---------------------------------------------------------------------------

/// `LEFT` — PC1, Arduino `D8` (CN13 pin 1 jumper).
pub const BTN_LEFT_PORT: u32 = GPIOC_S;
pub const BTN_LEFT_PIN: u32 = 1;
/// `RIGHT` — PA8, Arduino `D9` (CN13 pin 2 jumper).
pub const BTN_RIGHT_PORT: u32 = GPIOA_S;
pub const BTN_RIGHT_PIN: u32 = 8;
/// The blue on-board `USER` (B3) button.
///
/// **Not a UI input.** An earlier version of this comment called it "a genuine
/// third input, which the UI's three-action dialogs rely on" — that was wrong.
/// `hw::buttons::init` configures PC13, but `wait_event` never samples it; the
/// only reads are inside the `button-test` diagnostic, where it just prints a
/// state change. It never constructs a `Button` and never reaches a dialog.
///
/// Kept here because the pin *is* wired on this board and is useful as a
/// bench "is the firmware alive" reference, but nothing in the tree consumes
/// this constant.
pub const BTN_USER: Option<(u32, u32)> = Some((GPIOC_S, 13));
