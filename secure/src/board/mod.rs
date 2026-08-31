//! Board pin / peripheral map, selected at compile time.
//!
//! Every fact that differs between the two physical boards we build for
//! lives in exactly one place: `iota2.rs` or `pq1.rs`. Driver modules
//! (`hw/uart.rs`, `hw/spi_hw.rs`, `hw/i2c_hw.rs`, …) read constants from
//! here instead of hard-coding a port base or a pin number, so a board
//! swap is a feature flip rather than an edit spread across a dozen files.
//!
//! ## The two boards
//!
//! | | `iota2` (default) | `pq1` |
//! |---|---|---|
//! | Board | ST B-U585I-IOT02A dev board | AL_A66_MB_V10 |
//! | MCU | STM32U585AII6, 169-pin BGA | STM32U585CIU6, 48-pin UFQFPN |
//! | Bonded GPIO | ports A..I | **PA0–15, PB0–15, PC13 only** |
//! | probe-rs chip | `STM32U585AIIx` | `STM32U585CIUx` |
//!
//! The dies are otherwise identical (2 MB dual-bank flash, 786 KB SRAM,
//! same peripheral set at the same addresses) — `pq1` simply bonds out
//! fewer pads. That matters: a write to, say, `GPIOE_MODER` on a 48-pin
//! part still *succeeds* (the port logic exists on the die), it just
//! drives nothing. Missing pins therefore fail **silently**, which is why
//! the pin map is centralised here rather than discovered at run time.
//!
//! ## Selection
//!
//! **Every `stm32u585` build must name its board.** `board-pq1` selects pq1,
//! `board-iota2` selects the dev board, neither is a compile error, and both
//! is a compile error.
//!
//! That mandatory-explicit rule replaced an earlier "opt-in to pq1" design in
//! which `board-iota2` was an inert no-op and the *absence* of `board-pq1`
//! meant iota2. The intent was to avoid editing ~200 recipes, and it worked
//! for the recipes that go through `$(FEATURES)`. It failed for four that
//! hardcode their own feature list: `make build-hw-prodtest BOARD=pq1`
//! produced `--features prodtest,dev-testkey,saes-dhuk` — no board — so this
//! module silently selected the **iota2 pin map for pq1 silicon**, and every
//! `#[cfg(feature = "board-pq1")] compile_error!` fence (`hw/usb_hw.rs`,
//! `hw/buttons.rs`, `hw/spi_hw.rs`) went quiet at the same moment, because a
//! fence keyed on a feature cannot fire when that feature is absent.
//!
//! `prodtest` implies `usb`, `ui-lcd` and `gpio-buttons`, and the prodtest
//! boot path calls `hw::usb_hw::init()` — so the *factory* flow was the one
//! that reached the hazard. The lesson is worth keeping: an opt-in selector
//! makes "forgot to choose" indistinguishable from a valid choice, and every
//! guard downstream inherits that blind spot.
//!
//! Build with `make <target> BOARD=pq1`, which sets both the cargo
//! feature and the probe-rs chip name.

#[cfg(all(feature = "board-iota2", feature = "board-pq1"))]
compile_error!(
    "board-iota2 and board-pq1 are mutually exclusive — pick exactly one. \
     Use `make <target> BOARD=iota2|pq1`."
);

// A build that names no board is the dangerous case, not a convenience: it
// silently gets the iota2 pin map AND silences every board-keyed fence at the
// same time. Refuse it.
#[cfg(all(
    feature = "stm32u585",
    not(feature = "board-iota2"),
    not(feature = "board-pq1")
))]
compile_error!(
    "every stm32u585 build must name its board: pass `board-iota2` or `board-pq1`. \
     `make <target> BOARD=iota2|pq1` does this for recipes that build their feature \
     list from $(FEATURES); a recipe with a HARDCODED --features list must append \
     $(BOARD_FEATURE) itself. Without a board this module defaults to the iota2 pin \
     map and every `#[cfg(feature = \"board-pq1\")]` fence goes silent — which is how \
     `build-hw-prodtest BOARD=pq1` used to compile iota2 pins onto pq1 silicon."
);

#[cfg(feature = "board-pq1")]
mod pq1;
#[cfg(feature = "board-pq1")]
pub use pq1::*;

#[cfg(not(feature = "board-pq1"))]
mod iota2;
#[cfg(not(feature = "board-pq1"))]
pub use iota2::*;

// ---------------------------------------------------------------------------
// Facts shared by both boards — same die, same peripheral addresses.
// ---------------------------------------------------------------------------

/// RCC, **secure alias**.
///
/// With `TZEN=1` this is the only alias that can clock-gate peripherals
/// classified secure-by-default. Writing `GPIOAEN` through the NS alias
/// (`0x4602_0C00`) leaves the bit clear — GPIOA stays unclocked, reads
/// return bus junk and writes are silently dropped. See the long note in
/// `hw/uart.rs`, which is where that was diagnosed.
pub const RCC_S: u32 = 0x5602_0C00;

/// `RCC_AHB2ENR1` offset — GPIO port clock enables (`GPIOxEN` = bit x).
pub const RCC_AHB2ENR1_OFF: u32 = 0x8C;
/// `RCC_APB1ENR1` offset — TIM2, USART2, I2C1, I2C2.
pub const RCC_APB1ENR1_OFF: u32 = 0x9C;
/// `RCC_APB1ENR2` offset — I2C4.
pub const RCC_APB1ENR2_OFF: u32 = 0xA0;
/// `RCC_APB2ENR` offset — SPI1, USART1.
pub const RCC_APB2ENR_OFF: u32 = 0xA4;
/// `RCC_APB1RSTR1` offset — peripheral resets matching `APB1ENR1`.
pub const RCC_APB1RSTR1_OFF: u32 = 0x74;
/// `RCC_APB1RSTR2` offset — peripheral resets matching `APB1ENR2`.
pub const RCC_APB1RSTR2_OFF: u32 = 0x78;

/// `I2C1RST` — `RCC_APB1RSTR1` bit 21 (mirrors `I2C1EN`).
pub const RCC_I2C1RST_BIT: u32 = 1 << 21;
/// `I2C4RST` — `RCC_APB1RSTR2` bit 1 (mirrors `I2C4EN`).
pub const RCC_I2C4RST_BIT: u32 = 1 << 1;

/// GPIO port base addresses, **secure alias** (`0x5202_0000 + 0x400 * n`).
///
/// Present on the die for every port regardless of package; only the
/// *pads* differ. `GPIOD_S`/`GPIOE_S` are therefore addressable but inert
/// on `pq1`.
pub const GPIOA_S: u32 = 0x5202_0000;
pub const GPIOB_S: u32 = 0x5202_0400;
pub const GPIOC_S: u32 = 0x5202_0800;
pub const GPIOD_S: u32 = 0x5202_0C00;
pub const GPIOE_S: u32 = 0x5202_1000;

/// `RCC_AHB2ENR1` bit for a GPIO port base — `GPIOAEN` is bit 0, and each
/// subsequent port is the next bit up, matching the 0x400 base stride.
#[must_use]
pub const fn gpio_rcc_bit(port_base: u32) -> u32 {
    1 << ((port_base - GPIOA_S) / 0x400)
}

// ---------------------------------------------------------------------------
// Peripheral base addresses, **secure alias**.
//
// Every value below is transcribed from the vendor SVD shipped with
// STM32CubeProgrammer (`SVD/STM32U585.svd`), which lists the non-secure
// alias; the secure alias is the same address with bit 28 set
// (0x4... -> 0x5...), the aliasing rule the rest of this tree already
// relies on (e.g. `hw/i2c_hw.rs` uses I2C1 at 0x5000_5400 for the SVD's
// 0x4000_5400).
// ---------------------------------------------------------------------------

/// USART1 — `iota2` debug console (SVD: `0x4001_3800`).
pub const USART1_S: u32 = 0x5001_3800;
/// USART2 — `pq1` debug console (SVD: `0x4000_4400`).
pub const USART2_S: u32 = 0x5000_4400;
/// I2C1 — OPTIGA bus on both boards (SVD: `0x4000_5400`).
pub const I2C1_S: u32 = 0x5000_5400;
/// I2C4 — SE050 bus on `pq1` (SVD: `0x4000_8400`).
pub const I2C4_S: u32 = 0x5000_8400;
/// SPI1 (SVD: `0x4001_3000`).
pub const SPI1_S: u32 = 0x5001_3000;
/// SPI2 (SVD: `0x4000_3800`).
pub const SPI2_S: u32 = 0x5000_3800;

/// `USART1EN` — `RCC_APB2ENR` bit 14.
pub const RCC_USART1EN_BIT: u32 = 1 << 14;
/// `USART2EN` — `RCC_APB1ENR1` bit 17.
pub const RCC_USART2EN_BIT: u32 = 1 << 17;
/// `I2C1EN` — `RCC_APB1ENR1` bit 21.
pub const RCC_I2C1EN_BIT: u32 = 1 << 21;
/// `I2C4EN` — `RCC_APB1ENR2` bit 1.
pub const RCC_I2C4EN_BIT: u32 = 1 << 1;
/// `SPI1EN` — `RCC_APB2ENR` bit 12.
pub const RCC_SPI1EN_BIT: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// GTZC1 TZSC security bits, for `sau::configure_gtzc`.
//
// From the same SVD. Note `LPUART1SEC` is deliberately absent: LPUART1 is
// governed by **GTZC2** (`0x4602_3000`), a controller `sau.rs` does not
// configure at all. That asymmetry is one of the reasons the `pq1`
// console is USART2/AF7 (the vendor pin table's own reading) rather than
// LPUART1/AF8 (the schematic net name) — same PA2/PA3 pads either way.
// ---------------------------------------------------------------------------

/// `USART2SEC` — `GTZC1_TZSC_SECCFGR1` bit 9.
pub const TZSC_SECCFGR1_USART2SEC: u32 = 1 << 9;
/// `I2C1SEC` — `GTZC1_TZSC_SECCFGR1` bit 13.
pub const TZSC_SECCFGR1_I2C1SEC: u32 = 1 << 13;
/// `I2C2SEC` — `GTZC1_TZSC_SECCFGR1` bit 14.
pub const TZSC_SECCFGR1_I2C2SEC: u32 = 1 << 14;
/// `I2C4SEC` — `GTZC1_TZSC_SECCFGR1` bit 16.
pub const TZSC_SECCFGR1_I2C4SEC: u32 = 1 << 16;
/// `SPI1SEC` — `GTZC1_TZSC_SECCFGR2` bit 1.
pub const TZSC_SECCFGR2_SPI1SEC: u32 = 1 << 1;
/// `USART1SEC` — `GTZC1_TZSC_SECCFGR2` bit 3.
pub const TZSC_SECCFGR2_USART1SEC: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Secure-element I2C buses
// ---------------------------------------------------------------------------

/// One I2C bus carrying a secure element, described completely enough that
/// `hw::i2c_hw::init` can bring it up without knowing which board it is on.
///
/// `iota2` has exactly one of these (both SEs share I2C1); `pq1` has two
/// (OPTIGA on I2C1, SE050 on its own I2C4). Making the *set* the board
/// variable — rather than adding a second init entry point — is what keeps
/// `i2c_hw` down to a single `pub fn init`, which is itself a pinned gate.
pub struct SeI2cBus {
    /// For logs only.
    pub name: &'static str,
    /// Peripheral base, secure alias.
    pub base: u32,
    /// Offset of the `RCC_APBxENRy` holding this peripheral's enable bit.
    pub rcc_enr_off: u32,
    /// Offset of the matching `RCC_APBxRSTRy`.
    pub rcc_rstr_off: u32,
    /// Enable bit within `rcc_enr_off`.
    pub rcc_en_bit: u32,
    /// Reset bit within `rcc_rstr_off` — same position as the enable bit
    /// on this part, but stated explicitly rather than assumed.
    pub rcc_rst_bit: u32,
    /// GPIO port carrying SCL/SDA, secure alias.
    pub port: u32,
    pub scl_pin: u32,
    pub sda_pin: u32,
    /// Alternate function selecting *this* I2C instance on those pins.
    ///
    /// Getting this wrong is the sharpest silent failure on `pq1`: PB6/PB7
    /// are **I2C4 under AF5 and I2C1 under AF4**. An AF4 typo would not
    /// fail — it would quietly wire the SE050's pins onto the OPTIGA bus.
    pub af: u32,
    /// 7-bit addresses that should answer on this bus, with a label.
    ///
    /// Consumed only by `hw::se_i2c_probe` (feature `se-i2c-probe`), which
    /// address-probes each one. Keeping the expectation here rather than in
    /// the probe means "which chip lives on which bus" stays a single board
    /// fact — and on `iota2`, where both chips share one bus, the list is
    /// two entries long rather than the bus being duplicated.
    pub probe_addrs: &'static [(u8, &'static str)],
}

/// `TIMINGR` for 400 kHz Fast Mode at 160 MHz PCLK1.
///
/// PRESC=1 (÷2 → 12.5 ns), SCLDEL=9 (125 ns ≥ 100 ns FM min), SDADEL=0,
/// SCLH=55 (700 ns ≥ 600 ns), SCLL=143 (1800 ns ≥ 1300 ns).
/// Period = 700+1800 = 2500 ns → 400 kHz.
///
/// Shared by every bus in `SE_I2C_BUSES`: I2C1 and I2C4 both take PCLK1 at
/// their reset clock-source setting (`RCC_CCIPR1` `I2C1SEL`/`I2C4SEL` = 00),
/// and `hw::rcc::init` leaves the APB1 prescaler at /1, so both see 160 MHz.
pub const I2C_TIMING_400KHZ: u32 = 0x1090_378F;
