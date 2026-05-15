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

use crate::hw::mmio::Reg32;

// ---------------------------------------------------------------------------
// RCC registers (secure alias — TZEN=1)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;

// ---------------------------------------------------------------------------
// GPIO base addresses (secure alias)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "spi1-arduino"))]
const GPIO_BASE: u32 = 0x5202_0400; // GPIOB
#[cfg(feature = "spi1-arduino")]
const GPIO_BASE: u32 = 0x5202_1000; // GPIOE

/// AHB2ENR1 bit to enable the GPIO clock.
#[cfg(not(feature = "spi1-arduino"))]
const GPIO_CLK_BIT: u32 = 1; // GPIOBEN
#[cfg(feature = "spi1-arduino")]
const GPIO_CLK_BIT: u32 = 4; // GPIOEEN

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

struct SpiHwRegs {
    rcc_ahb2enr1: Reg32,
    #[cfg(not(feature = "spi1-arduino"))]
    rcc_apb1enr1: Reg32,
    #[cfg(not(feature = "spi1-arduino"))]
    rcc_apb1rstr1: Reg32,
    #[cfg(feature = "spi1-arduino")]
    rcc_apb2enr: Reg32,
    #[cfg(feature = "spi1-arduino")]
    rcc_apb2rstr: Reg32,
    gpio_moder: Reg32,
    gpio_otyper: Reg32,
    gpio_ospeedr: Reg32,
    gpio_bsrr: Reg32,
    gpio_afrh: Reg32,
    spi_cr1: Reg32,
    spi_cfg1: Reg32,
    spi_cfg2: Reg32,
    spi_ier: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register touched
// once during boot by this driver. Shared RCC + GPIO registers are
// accessed via disjoint-bit RMW; `gpio_bsrr` is a write-only atomic-set
// register (BSRR), used here only with single-bit writes.
const REG: SpiHwRegs = unsafe {
    SpiHwRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        #[cfg(not(feature = "spi1-arduino"))]
        rcc_apb1enr1: Reg32::new(RCC_S + 0x9C),
        #[cfg(not(feature = "spi1-arduino"))]
        rcc_apb1rstr1: Reg32::new(RCC_S + 0x74),
        #[cfg(feature = "spi1-arduino")]
        rcc_apb2enr: Reg32::new(RCC_S + 0xA4),
        #[cfg(feature = "spi1-arduino")]
        rcc_apb2rstr: Reg32::new(RCC_S + 0x7C),
        gpio_moder: Reg32::new(GPIO_BASE + 0x00),
        gpio_otyper: Reg32::new(GPIO_BASE + 0x04),
        gpio_ospeedr: Reg32::new(GPIO_BASE + 0x08),
        gpio_bsrr: Reg32::new(GPIO_BASE + 0x18),
        gpio_afrh: Reg32::new(GPIO_BASE + 0x24),
        spi_cr1: Reg32::new(SPI_BASE + 0x00),
        spi_cfg1: Reg32::new(SPI_BASE + 0x08),
        spi_cfg2: Reg32::new(SPI_BASE + 0x0C),
        spi_ier: Reg32::new(SPI_BASE + 0x10),
    }
};

/// CS pin = bit 12 in BSRR (PB12 or PE12).
pub const CS_PIN: u32 = 12;

/// Initialize SPI hardware and CS GPIO from the secure world.
///
/// Must be called after `rcc::init()` (clocks running at 160 MHz).
pub fn init() {
    // ---- 1. Enable GPIO clock (AHB2ENR1) ----
    REG.rcc_ahb2enr1.set_bits(1 << GPIO_CLK_BIT);
    cortex_m::asm::dsb();

    // ---- 2. Enable SPI clock ----
    #[cfg(not(feature = "spi1-arduino"))]
    {
        // SPI2 on APB1: bit 14
        REG.rcc_apb1enr1.set_bits(1 << 14);
        cortex_m::asm::dsb();
    }
    #[cfg(feature = "spi1-arduino")]
    {
        // SPI1 on APB2: bit 12
        REG.rcc_apb2enr.set_bits(1 << 12);
        cortex_m::asm::dsb();
    }

    // ---- 3. Reset SPI peripheral ----
    #[cfg(not(feature = "spi1-arduino"))]
    {
        REG.rcc_apb1rstr1.set_bits(1 << 14);
        cortex_m::asm::dsb();
        REG.rcc_apb1rstr1.clear_bits(1 << 14);
        cortex_m::asm::dsb();
    }
    #[cfg(feature = "spi1-arduino")]
    {
        REG.rcc_apb2rstr.set_bits(1 << 12);
        cortex_m::asm::dsb();
        REG.rcc_apb2rstr.clear_bits(1 << 12);
        cortex_m::asm::dsb();
    }

    // ---- 4. Configure pin 12 (CS) as GPIO output, push-pull, high (deasserted) ----
    // MODER: bits [25:24] → 01 (general purpose output)
    REG.gpio_moder.modify(|v| (v & !(0b11 << 24)) | (0b01 << 24));

    // OTYPER: bit 12 → 0 (push-pull)
    REG.gpio_otyper.clear_bits(1 << 12);

    // OSPEEDR: bits [25:24] → 11 (very high speed)
    REG.gpio_ospeedr.set_bits(0b11 << 24);

    // Start with CS high (deasserted) — BSRR atomic set, BS12.
    REG.gpio_bsrr.write(1 << CS_PIN);

    // ---- 5. Configure pins 13 (SCK), 14 (MISO), 15 (MOSI) as AF5 ----
    // MODER: bits [27:26]=13, [29:28]=14, [31:30]=15 → 10 (AF)
    REG.gpio_moder.modify(|v| {
        (v & !(0b11 << 26) & !(0b11 << 28) & !(0b11 << 30))
            | (0b10 << 26)  // pin 13 AF
            | (0b10 << 28)  // pin 14 AF
            | (0b10 << 30)  // pin 15 AF
    });

    // OTYPER: SCK and MOSI push-pull (bits 13,15 → 0), MISO is input
    REG.gpio_otyper.clear_bits((1 << 13) | (1 << 15));

    // OSPEEDR: pins 13, 14, 15 → 11 (very high speed)
    REG.gpio_ospeedr.set_bits((0b11 << 26) | (0b11 << 28) | (0b11 << 30));

    // AFRH: pin13 = AF5 (bits [23:20]), pin14 = AF5 (bits [27:24]), pin15 = AF5 (bits [31:28])
    REG.gpio_afrh.modify(|v| {
        (v & !(0xF << 20) & !(0xF << 24) & !(0xF << 28))
            | (5 << 20)   // pin 13 = AF5
            | (5 << 24)   // pin 14 = AF5
            | (5 << 28)   // pin 15 = AF5
    });

    // ---- 6. Configure SPI peripheral ----
    // SSI (bit 12) must be 1 before MASTER mode is set in CFG2, otherwise
    // the peripheral detects a false NSS-low (mode fault) and clears MASTER.
    // SPE (bit 0) = 0 so CFG registers are writable.
    REG.spi_cr1.write(1 << 12); // SSI=1, SPE=0
    cortex_m::asm::dsb();

    // CFG1: 8-bit data size (DSIZE[4:0] = 7), baud rate prescaler
    // PCLK = 160 MHz.  MBR[2:0] in bits [30:28]:
    //   100 = ÷32 → 160/32 = 5 MHz
    // DSIZE[4:0] in bits [4:0] = 0b00111 (8-bit)
    // FTHLV[1:0] in bits [6:5] = 00 (1-data threshold for TXP/RXP)
    REG.spi_cfg1.write((0b100 << 28) | 7);

    // CFG2: Master mode, software NSS management, SSOE disabled
    // MASTER (bit 22) = 1
    // SSM (bit 26) = 1 (software CS management)
    // SSOM (bit 30) = 0
    // SSOE (bit 29) = 0
    // CPOL (bit 25) = 0, CPHA (bit 24) = 0 → SPI Mode 0
    // COMM[1:0] (bits [18:17]) = 00 (full-duplex)
    // MSB first: LSBFRST (bit 23) = 0
    REG.spi_cfg2.write((1 << 22) | (1 << 26));

    // IER: disable all interrupts (polling mode)
    REG.spi_ier.write(0);

    cortex_m::asm::dsb();
}

/// Assert CS (drive pin 12 low). BSRR is a write-only atomic-set register;
/// writing `1 << (CS_PIN + 16)` clears bit 12 without disturbing other pins.
#[inline]
pub fn cs_assert() {
    REG.gpio_bsrr.write(1 << (CS_PIN + 16)); // BR12 = reset
}

/// Deassert CS (drive pin 12 high). BSRR atomic-set, BS12.
#[inline]
pub fn cs_deassert() {
    REG.gpio_bsrr.write(1 << CS_PIN); // BS12 = set
}
