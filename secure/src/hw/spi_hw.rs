//! SPI hardware initialization for TROPIC01 on STM32U585.
//!
//! Two pin configurations are supported, selected by the `spi1-arduino`
//! cargo feature:
//!
//! ## Default: SPI2 on PB12–PB15 (direct wiring)
//!   PB12 = CS   (GPIO output, active-low)
//!   PB13 = SCK  (SPI2_SCK, AF5)
//!   PB14 = MISO (SPI2_MISO, AF5) — TROPIC01 SPI_SDO
//!   PB15 = MOSI (SPI2_MOSI, AF5) — TROPIC01 SPI_SDI
//!
//! ## `spi1-arduino`: SPI1 on PE12–PE15 (Arduino R3 headers)
//! Used when the TROPIC01 MikroE Clicker is connected via an Arduino
//! shield (e.g. stacked on top of the OM-SE050ARD).
//!   PE12 = CS   (GPIO output, active-low)
//!   PE13 = SCK  (SPI1_SCK, AF5)
//!   PE14 = MISO (SPI1_MISO, AF5) — TROPIC01 SPI_SDO
//!   PE15 = MOSI (SPI1_MOSI, AF5) — TROPIC01 SPI_SDI
//!
//! All configuration runs in the secure world.  The SPI peripheral stays
//! secure (no GTZC/SECCFGR changes) — the non-secure world never touches
//! the TROPIC01 directly.

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC registers (secure alias — TZEN=1)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;

#[cfg(not(feature = "spi1-arduino"))]
const RCC_APB1ENR1: *mut u32 = (RCC_S + 0x9C) as *mut u32;
#[cfg(not(feature = "spi1-arduino"))]
const RCC_APB1RSTR1: *mut u32 = (RCC_S + 0x74) as *mut u32;

#[cfg(feature = "spi1-arduino")]
const RCC_APB2ENR: *mut u32 = (RCC_S + 0xA4) as *mut u32;
#[cfg(feature = "spi1-arduino")]
const RCC_APB2RSTR: *mut u32 = (RCC_S + 0x7C) as *mut u32;

// ---------------------------------------------------------------------------
// GPIO registers (secure alias)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "spi1-arduino"))]
mod gpio {
    // GPIOB for SPI2: PB12-PB15
    const GPIOB_S: u32 = 0x5202_0400;
    pub const MODER: *mut u32 = (GPIOB_S + 0x00) as *mut u32;
    pub const OTYPER: *mut u32 = (GPIOB_S + 0x04) as *mut u32;
    pub const OSPEEDR: *mut u32 = (GPIOB_S + 0x08) as *mut u32;
    pub const BSRR: *mut u32 = (GPIOB_S + 0x18) as *mut u32;
    pub const AFRH: *mut u32 = (GPIOB_S + 0x24) as *mut u32;
    /// AHB2ENR1 bit to enable the GPIO clock.
    pub const GPIO_CLK_BIT: u32 = 1; // GPIOBEN
}

#[cfg(feature = "spi1-arduino")]
mod gpio {
    // GPIOE for SPI1: PE12-PE15
    const GPIOE_S: u32 = 0x5202_1000;
    pub const MODER: *mut u32 = (GPIOE_S + 0x00) as *mut u32;
    pub const OTYPER: *mut u32 = (GPIOE_S + 0x04) as *mut u32;
    pub const OSPEEDR: *mut u32 = (GPIOE_S + 0x08) as *mut u32;
    pub const BSRR: *mut u32 = (GPIOE_S + 0x18) as *mut u32;
    pub const AFRH: *mut u32 = (GPIOE_S + 0x24) as *mut u32;
    /// AHB2ENR1 bit to enable the GPIO clock.
    pub const GPIO_CLK_BIT: u32 = 4; // GPIOEEN
}

// ---------------------------------------------------------------------------
// SPI registers (secure alias)
//
// SPI2: APB1 @ 0x5000_3800   (default, PB12-PB15)
// SPI1: APB2 @ 0x5001_3000   (spi1-arduino, PE12-PE15)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "spi1-arduino"))]
pub const SPI_BASE: u32 = 0x5000_3800; // SPI2

#[cfg(feature = "spi1-arduino")]
pub const SPI_BASE: u32 = 0x5001_3000; // SPI1

pub const SPI_CR1: *mut u32 = (SPI_BASE + 0x00) as *mut u32;
pub const SPI_CR2: *mut u32 = (SPI_BASE + 0x04) as *mut u32;
pub const SPI_CFG1: *mut u32 = (SPI_BASE + 0x08) as *mut u32;
pub const SPI_CFG2: *mut u32 = (SPI_BASE + 0x0C) as *mut u32;
pub const SPI_IER: *mut u32 = (SPI_BASE + 0x10) as *mut u32;
pub const SPI_SR: *const u32 = (SPI_BASE + 0x14) as *const u32;
pub const SPI_IFCR: *mut u32 = (SPI_BASE + 0x18) as *mut u32;
pub const SPI_TXDR: *mut u32 = (SPI_BASE + 0x20) as *mut u32;
pub const SPI_RXDR: *const u32 = (SPI_BASE + 0x30) as *const u32;

/// CS pin = bit 12 in BSRR (PB12 or PE12).
pub const CS_PIN: u32 = 12;

/// Initialize SPI hardware and CS GPIO from the secure world.
///
/// Must be called after `rcc::init()` (clocks running at 160 MHz).
///
/// # Safety
/// Direct register access. Must be called exactly once during boot.
pub unsafe fn init() {
    // ---- 1. Enable GPIO clock (AHB2ENR1) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << gpio::GPIO_CLK_BIT));
    cortex_m::asm::dsb();

    // ---- 2. Enable SPI clock ----
    #[cfg(not(feature = "spi1-arduino"))]
    {
        // SPI2 on APB1: bit 14
        let apb1 = read_volatile(RCC_APB1ENR1);
        write_volatile(RCC_APB1ENR1, apb1 | (1 << 14));
        cortex_m::asm::dsb();
    }
    #[cfg(feature = "spi1-arduino")]
    {
        // SPI1 on APB2: bit 12
        let apb2 = read_volatile(RCC_APB2ENR);
        write_volatile(RCC_APB2ENR, apb2 | (1 << 12));
        cortex_m::asm::dsb();
    }

    // ---- 3. Reset SPI peripheral ----
    #[cfg(not(feature = "spi1-arduino"))]
    {
        let rstr = read_volatile(RCC_APB1RSTR1);
        write_volatile(RCC_APB1RSTR1, rstr | (1 << 14));
        cortex_m::asm::dsb();
        write_volatile(RCC_APB1RSTR1, rstr & !(1 << 14));
        cortex_m::asm::dsb();
    }
    #[cfg(feature = "spi1-arduino")]
    {
        let rstr = read_volatile(RCC_APB2RSTR);
        write_volatile(RCC_APB2RSTR, rstr | (1 << 12));
        cortex_m::asm::dsb();
        write_volatile(RCC_APB2RSTR, rstr & !(1 << 12));
        cortex_m::asm::dsb();
    }

    // ---- 4. Configure pin 12 (CS) as GPIO output, push-pull, high (deasserted) ----
    // MODER: bits [25:24] → 01 (general purpose output)
    let moder = read_volatile(gpio::MODER);
    let moder = (moder & !(0b11 << 24)) | (0b01 << 24);
    write_volatile(gpio::MODER, moder);

    // OTYPER: bit 12 → 0 (push-pull)
    let otyper = read_volatile(gpio::OTYPER);
    write_volatile(gpio::OTYPER, otyper & !(1 << 12));

    // OSPEEDR: bits [25:24] → 11 (very high speed)
    let ospeedr = read_volatile(gpio::OSPEEDR);
    write_volatile(gpio::OSPEEDR, ospeedr | (0b11 << 24));

    // Start with CS high (deasserted)
    write_volatile(gpio::BSRR, 1 << CS_PIN); // BS12 = set

    // ---- 5. Configure pins 13 (SCK), 14 (MISO), 15 (MOSI) as AF5 ----
    // MODER: bits [27:26]=13, [29:28]=14, [31:30]=15 → 10 (AF)
    let moder = read_volatile(gpio::MODER);
    let moder = (moder & !(0b11 << 26) & !(0b11 << 28) & !(0b11 << 30))
        | (0b10 << 26)  // pin 13 AF
        | (0b10 << 28)  // pin 14 AF
        | (0b10 << 30); // pin 15 AF
    write_volatile(gpio::MODER, moder);

    // OTYPER: SCK and MOSI push-pull (bits 13,15 → 0), MISO is input
    let otyper = read_volatile(gpio::OTYPER);
    write_volatile(gpio::OTYPER, otyper & !(1 << 13) & !(1 << 15));

    // OSPEEDR: pins 13, 14, 15 → 11 (very high speed)
    let ospeedr = read_volatile(gpio::OSPEEDR);
    write_volatile(
        gpio::OSPEEDR,
        ospeedr | (0b11 << 26) | (0b11 << 28) | (0b11 << 30),
    );

    // AFRH: pin13 = AF5 (bits [23:20]), pin14 = AF5 (bits [27:24]), pin15 = AF5 (bits [31:28])
    let afrh = read_volatile(gpio::AFRH);
    let afrh = (afrh & !(0xF << 20) & !(0xF << 24) & !(0xF << 28))
        | (5 << 20)   // pin 13 = AF5
        | (5 << 24)   // pin 14 = AF5
        | (5 << 28);  // pin 15 = AF5
    write_volatile(gpio::AFRH, afrh);

    // ---- 6. Configure SPI peripheral ----
    // SSI (bit 12) must be 1 before MASTER mode is set in CFG2, otherwise
    // the peripheral detects a false NSS-low (mode fault) and clears MASTER.
    // SPE (bit 0) = 0 so CFG registers are writable.
    write_volatile(SPI_CR1, 1 << 12); // SSI=1, SPE=0
    cortex_m::asm::dsb();

    // CFG1: 8-bit data size (DSIZE[4:0] = 7), baud rate prescaler
    // PCLK = 160 MHz.  MBR[2:0] in bits [30:28]:
    //   100 = ÷32 → 160/32 = 5 MHz
    // DSIZE[4:0] in bits [4:0] = 0b00111 (8-bit)
    // FTHLV[1:0] in bits [6:5] = 00 (1-data threshold for TXP/RXP)
    write_volatile(SPI_CFG1, (0b100 << 28) | 7);

    // CFG2: Master mode, software NSS management, SSOE disabled
    // MASTER (bit 22) = 1
    // SSM (bit 26) = 1 (software CS management)
    // SSOM (bit 30) = 0
    // SSOE (bit 29) = 0
    // CPOL (bit 25) = 0, CPHA (bit 24) = 0 → SPI Mode 0
    // COMM[1:0] (bits [18:17]) = 00 (full-duplex)
    // MSB first: LSBFRST (bit 23) = 0
    write_volatile(SPI_CFG2, (1 << 22) | (1 << 26));

    // IER: disable all interrupts (polling mode)
    write_volatile(SPI_IER, 0);

    cortex_m::asm::dsb();
}

/// Assert CS (drive pin 12 low).
///
/// # Safety
/// Direct GPIO register access.
#[inline]
pub unsafe fn cs_assert() {
    write_volatile(gpio::BSRR, 1 << (CS_PIN + 16)); // BR12 = reset
}

/// Deassert CS (drive pin 12 high).
///
/// # Safety
/// Direct GPIO register access.
#[inline]
pub unsafe fn cs_deassert() {
    write_volatile(gpio::BSRR, 1 << CS_PIN); // BS12 = set
}
