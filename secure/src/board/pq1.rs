//! Pin map for the **AL_A66_MB_V10** production board (`pq1`).
//!
//! MCU: STM32U585CIU6 (schematic marks it `STM32U585CU6TR`), 48-pin
//! UFQFPN. **Only PA0–PA15, PB0–PB15 and PC13 are bonded** — there is no
//! port D, E, F, G, H or I, and even within port B the package skips PB11.
//!
//! Source of truth, in precedence order:
//!
//! 1. `STM32U585CIU6TR Pin Functions.xls` — the vendor's own pin table,
//!    which carries the **alternate-function numbers**. Authoritative.
//! 2. `AL_A66_MB_V10_20260826_1500.pdf` — the schematic, for net names,
//!    I2C addresses and power topology.
//! 3. `SVD/STM32U585.svd` — every peripheral base, RCC enable bit and
//!    GTZC security bit (see `super`).
//!
//! Where (1) and (2) disagree, (1) wins and the disagreement is recorded:
//!
//! - **Console UART.** The schematic names the PA2/PA3 nets `LPUART1_TX` /
//!   `LPUART1_RX`, but the pin table marks them **AF7**. Both are right
//!   about the silicon: DS13086 Rev 10 Table 28 lists `AF7 = USART2_TX /
//!   USART2_RX` on PA2/PA3, and Table 29 lists `AF8 = LPUART1_TX /
//!   LPUART1_RX` on the same two pads. So this is purely a choice of which
//!   peripheral to drive them with, and USART2 is the better one on three
//!   counts: it is an ordinary USART (`BRR = f_ck / baud`, on APB1) rather
//!   than LPUART1's `BRR = 256 * f_ck / baud` on APB3; it lives in
//!   **GTZC1** alongside every other peripheral `sau.rs` configures,
//!   whereas LPUART1 is governed by GTZC2 — a controller the firmware does
//!   not touch at all; and it keeps the driver a base-address change away
//!   from `iota2`'s USART1 rather than a second baud-rate algorithm.
//! - **RGB LED enable.** The schematic appears to show `RGB_EN` on PB11;
//!   the pin table puts it on **PB12**, and PB11 is not bonded on this
//!   package at all. PB12 it is.
//!
//! ## Things that bite on this board
//!
//! - **PA8 gates the secure elements.** It is `LDO2_EN`, the enable for the
//!   `VDD1_3V3` rail feeding *both* SEs. It must be driven high before any
//!   SE I/O, or the parts are simply unpowered and the bus looks faulty.
//!   On `iota2` PA8 is the `RIGHT` button — the sharpest collision in the
//!   port, and a silent one in both directions.
//! - **PA5 is the LCD clock**, so the `consumption-mask` TIM2_CH1 PWM
//!   cannot live there. PA6, PA10, PC13 are the free pins (PB4 is bonded
//!   but unrouted).
//! - **Two buttons, not three** — `UP`/`DOWN` only. This is NOT a limitation:
//!   the trusted UI is already a two-button design (`(Left|Right)` x
//!   `(Short|Long)`, confirm = `(Right, Long)`), and the dev board's third
//!   button was never a UI input. See `BTN_USER` below.
//! - The pads on `J211` are the debug UART connector, in order
//!   `TX, RX, BOOT0, GND`; `TP101`/`TP102`/`TP103` are test points sitting
//!   on the first three of those nets.

#![allow(dead_code)] // Full board inventory; consumed incrementally by drivers.

use super::{
    SeI2cBus, GPIOA_S, GPIOB_S, GPIOC_S, I2C1_S, I2C4_S, RCC_APB1ENR1_OFF, RCC_APB1ENR2_OFF,
    RCC_APB1RSTR1_OFF, RCC_APB1RSTR2_OFF, RCC_I2C1EN_BIT, RCC_I2C1RST_BIT, RCC_I2C4EN_BIT,
    RCC_I2C4RST_BIT, RCC_USART2EN_BIT, SPI1_S, USART2_S,
};

/// Human-readable board name, for boot banners and log headers.
pub const BOARD_NAME: &str = "AL_A66_MB_V10 (pq1)";

// ---------------------------------------------------------------------------
// Debug console UART — USART2 TX on PA2 (AF7), header J211 pin 1
// ---------------------------------------------------------------------------

pub const CONSOLE_UART_BASE: u32 = USART2_S;
/// `USART2EN` lives in `RCC_APB1ENR1` (bit 17) — a different register from
/// `iota2`'s USART1, which is in `RCC_APB2ENR`.
pub const CONSOLE_UART_RCC_ENR_OFF: u32 = RCC_APB1ENR1_OFF;
pub const CONSOLE_UART_RCC_EN_BIT: u32 = RCC_USART2EN_BIT;
pub const CONSOLE_TX_PORT: u32 = GPIOA_S;
pub const CONSOLE_TX_PIN: u32 = 2;
pub const CONSOLE_TX_AF: u32 = 7;

/// 115200 8N1. USART2's default clock source (`CCIPR1[3:2]` = 00) is
/// PCLK1, which `hw::rcc::init` leaves at SYSCLK = 160 MHz (APB1 prescaler
/// /1) — the same divisor as `iota2`'s PCLK2, so the same BRR.
pub const CONSOLE_BRR: u32 = 1389;

/// RX — PA3 (AF7), `J211` pin 2. The console is TX-only today; recorded so
/// the pin is not accidentally reused.
pub const CONSOLE_RX: Option<(u32, u32)> = Some((GPIOA_S, 3));

// ---------------------------------------------------------------------------
// LCD — NV3007 over SPI1 on port A, control lines on port B
//
// Note the SPI pins are NOT contiguous (4/5/7, with PA6 skipped and no
// MISO), unlike both `iota2` variants which use a tidy 12..15 run. Any
// driver that derives pin numbers by offset from CS will be wrong here.
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

/// `LCM_TE` — PB2, the panel's tearing-effect output (input to us).
pub const LCD_TE: Option<(u32, u32)> = Some((GPIOB_S, 2));

/// `LCM_EN` — PB15, the enable for the AW99703 backlight boost driver.
///
/// **This alone may not light the panel.** The AW99703 is an I2C-controlled
/// LED driver at `0x36` on I2C2 (PB13/PB14); brightness almost certainly
/// has to be programmed over that bus after the enable is asserted. There
/// is no driver for it in the tree yet.
pub const LCD_BACKLIGHT_EN: Option<(u32, u32)> = Some((GPIOB_S, 15));

// ---------------------------------------------------------------------------
// Secure elements — split across two buses on this board
// ---------------------------------------------------------------------------

/// OPTIGA `SLS32AIA010MH` @ `0x30` — I2C1 on PB8/PB9 (AF4).
/// Identical to `iota2`; the only block that ports unchanged.
pub const OPTIGA_I2C_BASE: u32 = I2C1_S;
pub const OPTIGA_I2C_PORT: u32 = GPIOB_S;
pub const OPTIGA_I2C_SCL_PIN: u32 = 8;
pub const OPTIGA_I2C_SDA_PIN: u32 = 9;
pub const OPTIGA_I2C_AF: u32 = 4;

/// SE050 `SE050E2HQ1` @ `0x48` — its own bus, **I2C4** on PB6/PB7 (AF5).
/// Note PB6/PB7 would be I2C1 under AF4; AF5 is what selects I2C4.
pub const SE050_I2C_BASE: u32 = I2C4_S;
pub const SE050_I2C_PORT: u32 = GPIOB_S;
pub const SE050_I2C_SCL_PIN: u32 = 6;
pub const SE050_I2C_SDA_PIN: u32 = 7;
pub const SE050_I2C_AF: u32 = 5;

/// The SE I2C buses to bring up: **two**, one per chip.
///
/// Order matters only for log readability. Both take the same `TIMINGR`
/// because both are clocked from PCLK1 at their reset `*SEL` setting.
pub const SE_I2C_BUSES: &[SeI2cBus] = &[
    SeI2cBus {
        name: "I2C1 (OPTIGA 0x30)",
        base: I2C1_S,
        rcc_enr_off: RCC_APB1ENR1_OFF,
        rcc_rstr_off: RCC_APB1RSTR1_OFF,
        rcc_en_bit: RCC_I2C1EN_BIT,
        rcc_rst_bit: RCC_I2C1RST_BIT,
        port: GPIOB_S,
        scl_pin: 8,
        sda_pin: 9,
        af: 4,
        probe_addrs: &[(0x30, "OPTIGA Trust M")],
    },
    SeI2cBus {
        name: "I2C4 (SE050 0x48)",
        base: I2C4_S,
        // NOTE the different registers: I2C4's enable lives in APB1ENR2,
        // not APB1ENR1, and its reset in APB1RSTR2. Using I2C1's registers
        // here would leave I2C4 unclocked and the bus silent.
        rcc_enr_off: RCC_APB1ENR2_OFF,
        rcc_rstr_off: RCC_APB1RSTR2_OFF,
        rcc_en_bit: RCC_I2C4EN_BIT,
        rcc_rst_bit: RCC_I2C4RST_BIT,
        port: GPIOB_S,
        scl_pin: 6,
        sda_pin: 7,
        // AF5 = I2C4. **AF4 on these same two pins is I2C1** — a typo there
        // does not fail, it silently puts SE050's pins on OPTIGA's bus.
        af: 5,
        probe_addrs: &[(0x48, "SE050")],
    },
];

/// `SE_RST` — PA15, the OPTIGA active-low reset.
///
/// **This pin must be driven high at boot, and `hw::se_power::init` does it.**
///
/// It was first left undriven, on the argument that PA15 would idle high by
/// itself because this die's option bytes have `PA15_PUPEN = 1` (the JTDI
/// pull-up). **Measurement refuted that.** On 2026-08-30 `se_power::init`
/// sampled `IDR` before driving and read PA15 **low**: the OPTIGA sat in
/// reset and NACKed its address on all ten probe attempts, while the SE050 —
/// same rail, separate reset — ACKed on the first. Releasing the reset made
/// the OPTIGA answer on the next run.
///
/// Keep the lesson next to the constant: at the bus level an OPTIGA held in
/// reset is **indistinguishable from an absent one**, so this line is not
/// optional and its level is not something to infer from an option bit.
///
/// `optiga::reset_pin` still owns the reset *pulse* sequence and its silicon
/// write-ordering quirk. `se_power` only establishes the idle level — and it
/// is the only one of the two that runs on the normal boot path, since
/// `reset_pin::init` is reached solely under `optiga-reset-oids`.
pub const OPTIGA_RST: Option<(u32, u32)> = Some((GPIOA_S, 15));
/// `SE1_EN` — PB5, the SE050's own `ENA` line.
pub const SE050_EN: Option<(u32, u32)> = Some((GPIOB_S, 5));
/// `LDO2_EN` — PA8, gating the `VDD1_3V3` rail that powers **both** SEs.
/// Drive this high and let the rail settle before touching either bus.
pub const SE_RAIL_EN: Option<(u32, u32)> = Some((GPIOA_S, 8));

// ---------------------------------------------------------------------------
// Buttons — two only, on the `J`-connector labelled LEFT / RIGHT
// ---------------------------------------------------------------------------

/// `UP_KEY` / `LEFT` — PA0.
pub const BTN_LEFT_PORT: u32 = GPIOA_S;
pub const BTN_LEFT_PIN: u32 = 0;
/// `DOWN_KEY` / `RIGHT` — PA1.
pub const BTN_RIGHT_PORT: u32 = GPIOA_S;
pub const BTN_RIGHT_PIN: u32 = 1;
/// No third button on this board — **and none is needed.**
///
/// An earlier version of this comment claimed dialogs assuming a separate
/// `SELECT` would need "a chord or long-press on this board". That was a false
/// premise on both counts. The trusted UI has always been a two-button design:
/// `ui::Button` has exactly two variants (its own doc says "Two-button input
/// event"), `ui::Press` adds Short/Long, and every dialog matches all four
/// `(Left|Right) x (Short|Long)` arms **with no wildcard** — which is
/// compile-time proof the event space is exactly those four. Confirm is
/// `(Right, Long)`, cancel is `(Left, Long)`. And the both-buttons chord is
/// already implemented too (`hw::buttons::wait_combo_release`), synthesised as
/// `(Right, Long)` with an 80 ms skew window.
///
/// So this constant records a board fact, not a limitation, and it is
/// consumed by nothing.
pub const BTN_USER: Option<(u32, u32)> = None;

// ---------------------------------------------------------------------------
// Board-only peripherals with no `iota2` counterpart
// ---------------------------------------------------------------------------

/// Shared I2C2 (PB13/PB14, AF4) carrying the two LED-driver ICs.
pub const AUX_I2C_PORT: u32 = GPIOB_S;
pub const AUX_I2C_SCL_PIN: u32 = 13;
pub const AUX_I2C_SDA_PIN: u32 = 14;
pub const AUX_I2C_AF: u32 = 4;
/// AW99703 backlight boost driver.
pub const BACKLIGHT_I2C_ADDR: u8 = 0x36;
/// AW21036 RGB LED driver.
pub const RGB_I2C_ADDR: u8 = 0x34;
/// `RGB_EN` — PB12 (the pin table's value; the schematic's PB11 is not
/// bonded on this package).
pub const RGB_EN: Option<(u32, u32)> = Some((GPIOB_S, 12));

/// Height in pixels of the SSD1306 wired to this board's bench setup.
///
/// Strictly a property of the **module you plugged in**, not of the board —
/// it lives here because that is where the rest of the bench-OLED wiring is
/// described, and because it must be a compile-time constant (it sizes the
/// framebuffer). The module actually on the bench (128x64). Four text rows at
/// 16 px pitch.
///
/// Only 32 and 64 are valid: those are the SSD1306 geometries, and both
/// divide evenly by 8 (the page height) and by `DISPLAY_ROWS`. Enforced by a
/// `const assert!` in `ui::oled`.
pub const OLED_HEIGHT_PX: usize = 64;

/// Bench-only SSD1306 OLED, bit-banged I2C. **`ui-oled-bench` only.**
///
/// - `SCL` = **PA2**, the `TX` pad.
/// - `SDA` = **PA3**, the `RX` pad.
///
/// Both are **bare pads**, which is the whole point: they can be reached with
/// a crocodile clip or a test hook, where the 2x5 debug header is 1.27 mm and
/// needs solder. On a board that exposes almost nothing, "can you attach a
/// wire without an iron" is a real selection criterion.
///
/// These are the debug console's pins, so **`ui-oled-bench` and
/// `uart-console` are mutually exclusive** — enforced in `hw::soft_i2c`. That
/// costs nothing in practice: the console and the OLED are two ways of seeing
/// the same 16x4 text, and you would not run both. Semihosting remains
/// available alongside either.
///
/// An earlier revision used PB3 (the `SWO` header pin) for `SCL`. PB3 is
/// electrically fine and still free, but it is a 1.27 mm header pin sitting
/// directly beside `SWCLK` — a clip that bridges the two puts the debugger's
/// clock in contention with firmware. PA2 avoids that entirely, and leaves
/// PB3 to [`SCA_TRIGGER`], removing that collision as well.
///
/// Hardware I2C is still impossible on this pair: PA2/PA3 offer only
/// `USART2` (AF7) and `LPUART1` (AF8), no I2C at all (DS13086 Rev 10,
/// Tables 28/29). Hence software I2C.
pub const OLED_SCL: Option<(u32, u32)> = Some((GPIOA_S, 2));
pub const OLED_SDA: Option<(u32, u32)> = Some((GPIOA_S, 3));

/// GPIOA / GPIOB pins this board's USB front end hands to the NON-SECURE
/// world via `GPIOx_SECCFGR`. Consumed by `hw::usb_hw::init`; checked against
/// this board's reserved lines by the `const assert!`s in `super`.
///
/// **Only USB D-/D+.** iota2 additionally hands over PA15, PB5 and PB15 for
/// its UCPD CC lines and TCPP03 enable. On this board those three pins are
/// `SE_RST`, `SE1_EN` and `LCM_EN` — both secure elements' control lines and
/// the trusted display's backlight — so handing them to NS is a direct
/// invariant #4 breach. There is nothing to remap them to either: the AW35602
/// owns CC and orientation, and no CC line reaches the MCU.
///
/// This is a strict SUBSET of the set iota2 was validated with, on the same
/// die, for the same peripheral — so it cannot introduce a new hazard, only
/// (at worst) fail to enumerate, which is testable.
pub const USB_NS_PINS_A: u32 = (1 << 11) | (1 << 12);
pub const USB_NS_PINS_B: u32 = 0;

/// `FLAGB` — PB10, the AW35602 USB port-protection fault flag (input).
/// Nothing reads it today.
pub const USB_FAULT_FLAG: Option<(u32, u32)> = Some((GPIOB_S, 10));
/// `USB_FS_VBUS` sense — PA9 (AF10). On `iota2` PA9 is the console TX.
pub const USB_VBUS_SENSE: Option<(u32, u32)> = Some((GPIOA_S, 9));

/// Scope / ChipWhisperer sync trigger. `iota2` uses PD2, which does not
/// exist here; PB3 (`SWO`) is the repoint — it is already on the 10-pin
/// debug header, is unused by the firmware, and is dead at RDP-2.
/// Consumption-mask PWM — **PA6, TIM3_CH1, AF2**.
///
/// TIM2_CH1's pins are all taken here: PA0 is `LEFT KEY`, PA5 is the LCD's
/// `SCK`, PA15 is `SE_RST`. PA6 is one of this board's four unclaimed pads
/// (with PA10, PC13, PB4) and is the only one of them on a general-purpose
/// timer channel, so the mask moves to TIM3 — which is why
/// `sau::configure_gtzc` secures TIM3 as well as TIM2.
///
/// **PA6 is `NC` on this board** (vendor pin table, PIN 16), so the PWM drives
/// no external load. That is the same situation as iota2's PA5, which is also
/// unloaded — see the note there. It is NOT a regression introduced by this
/// board, and it is NOT a claim that the mask is effective; that is the open
/// bench item in `docs/hardware/evt-silicon-validation.md` §9.
pub const MASK_PWM_PORT: u32 = GPIOA_S;
pub const MASK_PWM_PIN: u32 = 6;
pub const MASK_PWM_AF: u32 = 2;
pub const MASK_TIM_BASE: u32 = super::TIM3_S;
pub const MASK_TIM_RCC_EN_BIT: u32 = super::RCC_TIM3EN_BIT;

pub const SCA_TRIGGER: Option<(u32, u32)> = Some((GPIOB_S, 3));

/// Board-specific pins that must never reach the non-secure world, beyond the
/// ones `super` derives from the shared pin map.
///
/// Written as references to the existing named constants, never as fresh
/// literals, so this table tracks the pin map instead of duplicating it.
pub const EXTRA_RESERVED_PINS: &[(Option<(u32, u32)>, &str)] = &[
    (RGB_EN, "RGB LED driver enable"),
    (Some((AUX_I2C_PORT, AUX_I2C_SCL_PIN)), "I2C2 SCL (backlight + RGB drivers)"),
    (Some((AUX_I2C_PORT, AUX_I2C_SDA_PIN)), "I2C2 SDA (backlight + RGB drivers)"),
    (USB_FAULT_FLAG, "AW35602 fault flag (FLAGB)"),
    (USB_VBUS_SENSE, "USB VBUS sense"),
    (SCA_TRIGGER, "side-channel scope trigger"),
];

/// Pins bonded but unassigned, available for future use.
/// Unclaimed pads. PA6 LEFT this list on 2026-09-01 when the consumption mask
/// took it (TIM3_CH1/AF2); PB4 was never in it. All of these are `NC` on the
/// board per the vendor pin table, so anything driven here reaches no load.
///
/// NOT a collision guard: nothing folds this list into a `const assert!`, so
/// adding a pin here that a driver already owns fails silently. Check
/// `NS_FORBIDDEN` in `board/mod.rs` and the per-driver guards before claiming
/// a pad.
pub const FREE_PINS: &[(u32, u32)] = &[(GPIOA_S, 10), (GPIOC_S, 13), (GPIOB_S, 4)];
