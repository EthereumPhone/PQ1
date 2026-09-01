//! SPI hardware initialization for the NV3007 LCD on STM32U585.
//!
//! Every pin, the peripheral base and the alternate-function number come from
//! [`crate::board`], so the two boards differ only in their pin map:
//!
//! ## `iota2` — SPI1 on the Arduino headers (PE12–PE15)
//!   PE12 = CS   (GPIO output, active-low)
//!   PE13 = SCK  (SPI1_SCK, AF5)
//!   PE14 = MISO (SPI1_MISO, AF5)
//!   PE15 = MOSI (SPI1_MOSI, AF5)
//!
//! ## `pq1` — SPI1 on port A (PA4/PA5/PA7)
//!   PA4  = CS   (GPIO output, active-low)   vendor net "LCM SPI CS"
//!   PA5  = SCK  (SPI1_SCK, AF5)             vendor net "LCM SPI LCK"
//!   PA7  = MOSI (SPI1_MOSI, AF5)            vendor net "LCM SPI MOSI"
//!   (no MISO — PA6, the MISO position of SPI1's pin group, is `NC`)
//!
//! Three things about pq1 that the old hardcoded form could not express, and
//! which are the reason this driver was fenced off that board until now:
//! the pins are **non-contiguous** (5 and 7, PA6 skipped), they sit **below
//! pin 8** so their alternate-function nibbles are in `AFRL` rather than
//! `AFRH`, and there is **no MISO** at all.
//!
//! The panel is write-only on both boards regardless: `lcd_nv3007` discards RX
//! and `MASRX = 0` stops an unread RxFIFO throttling TX (RM0456 §68.8.1), so a
//! floating/absent MISO costs nothing.
//!
//! All configuration runs in the secure world.  The SPI peripheral stays
//! secure (no GTZC/SECCFGR changes) — the non-secure world never touches
//! the trusted display's bus.


use crate::board;
use crate::hw::mmio::Reg32;

// ---------------------------------------------------------------------------
// Everything below comes from `crate::board`
// ---------------------------------------------------------------------------
//
// This file used to hardcode two pin sets behind `spi1-arduino`: SPI2 on
// PB12-PB15, or SPI1 on PE12-PE15. Both are iota2's, and neither survives on
// pq1, whose panel is SPI1 on **PA4 (CS) / PA5 (SCK) / PA7 (MOSI)** with no
// MISO — a non-contiguous group on a different port, below pin 8 (so the
// alternate-function nibbles live in AFRL, not AFRH). Vendor pin table:
// PA4 = "LCM SPI CS", PA5 = "LCM SPI LCK", PA7 = "LCM SPI MOSI", and PA6 —
// the MISO position of SPI1's pin group — is `NC`.
//
// The SPI2 branch is gone rather than ported: `hw/mod.rs` compiles this module
// only under `all(stm32u585, ui-lcd)`, and `ui-lcd = ["spi1-arduino", ...]`,
// so `not(spi1-arduino)` was unreachable here. Same for the `not(ui-lcd)`
// baud-rate arm below.

const RCC_S: u32 = board::RCC_S;

/// SPI1 lives on APB2 on both boards.
const SPI_EN_BIT: u32 = board::RCC_SPI1EN_BIT;
const SPI_RST_BIT: u32 = board::RCC_SPI1RST_BIT;

/// The peripheral base, from the board map.
pub const SPI_BASE: u32 = board::LCD_SPI_BASE;

/// CS pin, from the board map. PE12 on iota2, PA4 on pq1.
pub const CS_PIN: u32 = board::LCD_CS_PIN;

const PORT: u32 = board::LCD_SPI_PORT;
const AF: u32 = board::LCD_SPI_AF;

/// `AFRL` (0x20) for pins 0..7, `AFRH` (0x24) for 8..15 — the pq1 pins are the
/// first in this driver's history to land in the low half.
const fn afr_off(pin: u32) -> u32 {
    if pin < 8 {
        0x20
    } else {
        0x24
    }
}
/// Nibble position of `pin` within its AFR word.
const fn afr_shift(pin: u32) -> u32 {
    (pin % 8) * 4
}

struct SpiHwRegs {
    rcc_ahb2enr1: Reg32,
    rcc_apb2enr: Reg32,
    rcc_apb2rstr: Reg32,
    gpio_moder: Reg32,
    gpio_otyper: Reg32,
    gpio_ospeedr: Reg32,
    gpio_bsrr: Reg32,
    spi_cr1: Reg32,
    spi_cfg1: Reg32,
    spi_cfg2: Reg32,
    spi_ier: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register touched once
// during boot by this driver. Shared RCC + GPIO registers are accessed via
// disjoint-bit RMW; `gpio_bsrr` is a write-only atomic-set register (BSRR),
// used here only with single-bit writes.
const REG: SpiHwRegs = unsafe {
    SpiHwRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + board::RCC_AHB2ENR1_OFF),
        rcc_apb2enr: Reg32::new(RCC_S + board::RCC_APB2ENR_OFF),
        rcc_apb2rstr: Reg32::new(RCC_S + board::RCC_APB2RSTR_OFF),
        gpio_moder: Reg32::new(PORT + 0x00),
        gpio_otyper: Reg32::new(PORT + 0x04),
        gpio_ospeedr: Reg32::new(PORT + 0x08),
        gpio_bsrr: Reg32::new(PORT + 0x18),
        spi_cr1: Reg32::new(SPI_BASE + 0x00),
        spi_cfg1: Reg32::new(SPI_BASE + 0x08),
        spi_cfg2: Reg32::new(SPI_BASE + 0x0C),
        spi_ier: Reg32::new(SPI_BASE + 0x10),
    }
};

/// Put one pin into alternate-function mode at [`AF`], push-pull, very-high
/// speed. Touches only this pin's bits.
fn config_af_pin(pin: u32) {
    let two = pin * 2;
    let field = 0b11u32 << two;
    REG.gpio_moder.modify(|v| (v & !field) | (0b10 << two)); // 10 = AF
    REG.gpio_otyper.clear_bits(1 << pin); // push-pull
    REG.gpio_ospeedr.set_bits(field); // 11 = very high speed
    // SAFETY: `PORT` is a GPIO base from the board map and `afr_off` yields
    // one of that block's two real AFR registers.
    let afr = unsafe { Reg32::new(PORT + afr_off(pin)) };
    let sh = afr_shift(pin);
    afr.modify(|v| (v & !(0xF << sh)) | (AF << sh));
}

/// Initialize SPI hardware and CS GPIO from the secure world.
///
/// Must be called after `rcc::init()` (clocks running at 160 MHz).
pub fn init() {
    // ---- 1. Enable the GPIO port clock (AHB2ENR1) ----
    REG.rcc_ahb2enr1.set_bits(board::gpio_rcc_bit(PORT));
    cortex_m::asm::dsb();

    // ---- 2. Enable the SPI clock (SPI1 on APB2, bit 12) ----
    REG.rcc_apb2enr.set_bits(SPI_EN_BIT);
    cortex_m::asm::dsb();

    // ---- 3. Reset the SPI peripheral ----
    REG.rcc_apb2rstr.set_bits(SPI_RST_BIT);
    cortex_m::asm::dsb();
    REG.rcc_apb2rstr.clear_bits(SPI_RST_BIT);
    cortex_m::asm::dsb();

    // ---- 4. CS as a GPIO output, push-pull, high (deasserted) ----
    // Driven high BEFORE the mode switch so the panel never sees a spurious
    // select while the pad is being configured.
    REG.gpio_bsrr.write(1 << CS_PIN);
    {
        let two = CS_PIN * 2;
        let field = 0b11u32 << two;
        REG.gpio_moder.modify(|v| (v & !field) | (0b01 << two)); // 01 = output
        REG.gpio_otyper.clear_bits(1 << CS_PIN);
        REG.gpio_ospeedr.set_bits(field);
    }
    REG.gpio_bsrr.write(1 << CS_PIN);

    // ---- 5. SCK / MOSI (and MISO where the board routes one) as AF ----
    // Configured per pin rather than as one contiguous run: pq1's are 5 and 7
    // with a gap, and they sit in AFRL while iota2's 13/14/15 sit in AFRH.
    config_af_pin(board::LCD_SCK_PIN);
    config_af_pin(board::LCD_MOSI_PIN);
    if let Some(miso) = board::LCD_MISO_PIN {
        // Only iota2 has one. The panel is write-only either way — the driver
        // discards RX and `MASRX = 0` keeps an unread RxFIFO from throttling
        // TX (RM0456 §68.8.1) — so pq1's absent MISO changes nothing but the
        // pad configuration.
        config_af_pin(miso);
    }

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
    // The `not(ui-lcd)` ÷32 arm that used to sit here was unreachable: this
    // module only compiles under `ui-lcd`.
    #[cfg(not(feature = "splash-test"))]
    const MBR: u32 = 0b010; // ÷8  → 20 MHz (NV3007 trusted UI, ~48 ms full repaint)
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
