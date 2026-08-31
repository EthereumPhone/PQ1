//! SPI hardware initialization for the NV3007 LCD on STM32U585.
//!
//! Two pin configurations are supported, selected by the `spi1-arduino`
//! cargo feature:
//!
//! ## Default: SPI2 on PB12–PB15 (direct wiring)
//!   PB12 = CS   (GPIO output, active-low)
//!   PB13 = SCK  (SPI2_SCK, AF5)
//!   PB14 = MISO (SPI2_MISO, AF5)
//!   PB15 = MOSI (SPI2_MOSI, AF5)
//!
//! ## `spi1-arduino`: SPI1 on PE12–PE15 (Arduino R3 headers)
//! Used for the NV3007 LCD wired to the Arduino headers (e.g. stacked
//! on top of the OM-SE050ARD). `ui-lcd` implies this feature.
//!   PE12 = CS   (GPIO output, active-low)
//!   PE13 = SCK  (SPI1_SCK, AF5)
//!   PE14 = MISO (SPI1_MISO, AF5)
//!   PE15 = MOSI (SPI1_MOSI, AF5)
//!
//! All configuration runs in the secure world.  The SPI peripheral stays
//! secure (no GTZC/SECCFGR changes) — the non-secure world never touches
//! the trusted display's bus.

// ---------------------------------------------------------------------------
// Board fence — this driver is `iota2`-only until the pq1 LCD port lands.
// ---------------------------------------------------------------------------
//
// This file has NO `board::` references: it hardcodes SPI2 on PB12-PB15, or
// SPI1 on PE12-PE15 under `spi1-arduino`. Both are wrong on pq1, and the PB
// variant is actively harmful there — PB12 is `RGB_EN`, PB13/PB14 are the I2C2
// lines to the backlight and RGB LED drivers, and PB15 is `LCM_EN`. Driving
// those as SPI would fight three other peripherals. (The PE variant is merely
// inert: port E is not bonded on the 48-pin package.)
//
// pq1's LCD is SPI1 on PA4 (CS) / PA5 (SCK) / PA7 (MOSI) with no MISO, so the
// pins are neither contiguous nor on the same port as either existing variant
// — see `board::LCD_*`. Porting is a real change, not a base-address swap.
//
// This fence is deliberately added at the same time as the board-selection
// rule in `board/mod.rs` became mandatory-explicit. Before that, `prodtest`
// (which implies `ui-lcd`) never carried `board-pq1`, so this file's hazard
// was hidden behind a build that silently claimed to be iota2. Making the
// board explicit turns that into a compile error here rather than four
// silently-wrong pins on the bench.
#[cfg(feature = "board-pq1")]
compile_error!(
    "hw/spi_hw.rs still uses the iota2 pin map and is unsafe on pq1: its SPI2 variant \
     drives PB12-PB15, which on pq1 are RGB_EN, the I2C2 bus to the backlight/RGB LED \
     drivers, and LCM_EN. pq1's LCD is SPI1 on PA4/PA5/PA7 (no MISO) — see board::LCD_*. \
     Port the pins before enabling `ui-lcd` on pq1."
);

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

    // CFG1: 8-bit data size (DSIZE[4:0] = 7), baud rate prescaler.
    // PCLK = 160 MHz.  SCK = 160 / 2^(MBR+1), MBR[2:0] in bits [30:28].
    // DSIZE[4:0] in bits [4:0] = 0b00111 (8-bit)
    // FTHLV[1:0] in bits [6:5] = 00 (1-data threshold for TXP/RXP)
    //
    // The NV3007 LCD (`ui-lcd`) needs throughput — at ÷32 (5 MHz) a full
    // 121,552-byte RGB565 repaint takes ~200 ms, and while that slowly streams
    // top-to-bottom the panel is scanning out the previous frame, so the two
    // race and produce visible tearing (a moving horizontal seam + per-column
    // shimmer during color transitions; static frames are clean). ÷8 (20 MHz)
    // cuts the repaint to ~65-70 ms (per-byte TXP poll overhead grows with
    // clock), shrinking the tearing window ~4×. 20 MHz has 2.5× margin over the
    // NV3007 10 ns data setup/hold spec (Table 8-3-2; SCK half-period 25 ns) and
    // matches what real NV3007 drivers run (ESPHome 20 MHz, LVGL 40 MHz).
    //
    // Gated on `ui-lcd` so a non-LCD build keeps the conservative ÷32 — the
    // bump is bus-wide, so
    // only raise it where a fast display actually needs it. If striping ever
    // reappears at 20 MHz it means the jumper wiring can't sustain the edges:
    // back off to ÷16 (`0b011`, 10 MHz). DSIZE stays 7; only MBR[30:28] changes.
    // The `splash-test` bench preview streams a full 121 KB frame every frame,
    // so it is SPI-clock-bound: ÷8 (20 MHz) = ~48.6 ms blit, ÷4 (40 MHz) = ~24 ms,
    // ÷2 (80 MHz) = ~13 ms. We run it at ÷2 = 80 MHz. The old wisdom that 80 MHz
    // "starves the polled FIFO and needs DMA" predates the lean byte-wise blit:
    // VALIDATED on the B-U585I dev board 2026-06-16 — blit measured 13.2 ms (the
    // CPU keeps the FIFO fed at the 100 ns/byte rate; ≈ the 12.2 ms clock-out
    // floor), hyperspace 38→68 fps, NO flicker despite the LD2 LED on PE13=SCK
    // (the edge-rounding concern that capped the *trusted UI* at 20 MHz did not
    // materialise for this preview). The trusted-UI `ui-lcd` default stays at the
    // clean 20 MHz below (this faster clock is splash-preview-only).
    #[cfg(feature = "splash-test")]
    const MBR: u32 = 0b000; // ÷2  → 80 MHz (splash preview, ~13 ms full repaint; HW-validated)
    #[cfg(all(feature = "ui-lcd", not(feature = "splash-test")))]
    const MBR: u32 = 0b010; // ÷8  → 20 MHz (NV3007 trusted UI, ~48 ms full repaint)
    #[cfg(not(feature = "ui-lcd"))]
    const MBR: u32 = 0b100; // ÷32 → 5 MHz  (conservative shared-bus default)
    REG.spi_cfg1.write((MBR << 28) | 7);
    // ÷8 = 20 MHz (SCK half-period 25 ns = 2.5× the NV3007 10 ns setup/hold).
    // The raw fill demo ran fine at ÷4 (40 MHz), but the *UI* showed intermittent
    // flicker on the B-U585I dev board, traced to its blue Arduino LED (LD2)
    // being hardwired to PE13 = SPI1_SCK: the LED + series resistor is an extra
    // capacitive load that rounds off the 40 MHz SCK edges (12.5 ns half-period,
    // only ~2.5 ns margin) → occasional misread bits = flicker. ÷8 restores the
    // margin and is plenty for a near-static UI (partial updates < 2 ms; a full
    // repaint ~50 ms happens only on a screen change). A production board with no
    // LED on SCK + proper PCB traces could go back to ÷4 (`0b001`, 40 MHz); ÷16
    // (`0b011`, 10 MHz) is the next step down if 20 MHz still isn't clean. ÷2
    // (80 MHz) would starve the polled FIFO regardless — that needs DMA.

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
