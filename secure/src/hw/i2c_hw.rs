//! I2C1 hardware initialization for SE050 on STM32U585.
//!
//! Configures GPIO (PB8 SCL, PB9 SDA as AF4 open-drain) and I2C1
//! peripheral for 400 kHz Fast Mode communication with the NXP SE050
//! secure element on the OM-SE050ARD Arduino shield.
//!
//! All configuration runs in the secure world.  I2C1 stays secure
//! (no GTZC/SECCFGR changes) — the non-secure world never touches
//! the SE050 directly.
//!
//! Pin mapping (OM-SE050ARD defaults J15=3-4, J17=3-4 → Arduino R3):
//!   PB8 = I2C1_SCL (AF4) — Arduino R3 J2:10
//!   PB9 = I2C1_SDA (AF4) — Arduino R3 J2:9

use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// RCC registers (secure alias — TZEN=1)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;

// ---------------------------------------------------------------------------
// GPIOB registers (secure alias)
// ---------------------------------------------------------------------------
const GPIOB_S: u32 = 0x5202_0400;

// ---------------------------------------------------------------------------
// I2C1 registers (secure alias — APB1 peripherals are secure with TZEN=1)
// ---------------------------------------------------------------------------
pub const I2C1: u32 = 0x5000_5400;

// The se050::t1oi2c driver reaches in for the raw register addresses; keep
// the typed handles below as the source of truth.
pub struct I2c1Regs {
    pub cr1: Reg32,
    pub cr2: Reg32,
    pub timingr: Reg32,
    pub isr: RoReg32,
    pub icr: Reg32,
    pub rxdr: RoReg32,
    pub txdr: Reg32,
}

pub struct I2cHwRegs {
    pub rcc_ahb2enr1: Reg32,
    pub rcc_apb1enr1: Reg32,
    pub rcc_apb1rstr1: Reg32,
    pub gpiob_moder: Reg32,
    pub gpiob_otyper: Reg32,
    pub gpiob_ospeedr: Reg32,
    pub gpiob_pupdr: Reg32,
    pub gpiob_afrh: Reg32,
    pub i2c1: I2c1Regs,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register touched
// once during boot by this driver in the single-threaded secure world.
// Shared RCC + GPIOB registers are accessed via disjoint-bit RMW so other
// drivers (i2c.rs, hash.rs) can safely share them.
pub const REG: I2cHwRegs = unsafe {
    I2cHwRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_apb1enr1: Reg32::new(RCC_S + 0x9C),
        rcc_apb1rstr1: Reg32::new(RCC_S + 0x74),
        gpiob_moder: Reg32::new(GPIOB_S + 0x00),
        gpiob_otyper: Reg32::new(GPIOB_S + 0x04),
        gpiob_ospeedr: Reg32::new(GPIOB_S + 0x08),
        gpiob_pupdr: Reg32::new(GPIOB_S + 0x0C),
        gpiob_afrh: Reg32::new(GPIOB_S + 0x24),
        i2c1: I2c1Regs {
            cr1: Reg32::new(I2C1 + 0x00),
            cr2: Reg32::new(I2C1 + 0x04),
            timingr: Reg32::new(I2C1 + 0x10),
            isr: RoReg32::new(I2C1 + 0x18),
            icr: Reg32::new(I2C1 + 0x1C),
            rxdr: RoReg32::new(I2C1 + 0x24),
            txdr: Reg32::new(I2C1 + 0x28),
        },
    }
};

// I2C1 TIMINGR for 400 kHz Fast Mode at 160 MHz PCLK1.
//
// PRESC=1 (÷2 → 12.5 ns), SCLDEL=9 (125 ns ≥ 100 ns FM min),
// SDADEL=0, SCLH=55 (700 ns ≥ 600 ns), SCLL=143 (1800 ns ≥ 1300 ns).
// Period = 700+1800 = 2500 ns → 400 kHz.
const I2C_TIMING_400KHZ: u32 = 0x1090_378F;

/// Initialize I2C1 hardware from the secure world.
///
/// Must be called after `rcc::init()` (clocks running at 160 MHz).
pub fn init() {
    // ---- 1. Enable GPIOB clock (AHB2ENR1 bit 1) ----
    REG.rcc_ahb2enr1.set_bits(1 << 1);
    cortex_m::asm::dsb();

    // ---- 2. Enable I2C1 clock (APB1ENR1 bit 21) ----
    REG.rcc_apb1enr1.set_bits(1 << 21);
    cortex_m::asm::dsb();

    // ---- 3. Reset I2C1 peripheral (APB1RSTR1 bit 21) ----
    REG.rcc_apb1rstr1.set_bits(1 << 21);
    cortex_m::asm::dsb();
    REG.rcc_apb1rstr1.clear_bits(1 << 21);
    cortex_m::asm::dsb();

    // ---- 4. Configure PB8 (SCL) and PB9 (SDA) as AF4, open-drain ----
    // MODER: bits [17:16] for PB8, [19:18] for PB9 → 10 (alternate function)
    REG.gpiob_moder.modify(|v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b10 << 16) | (0b10 << 18)
    });

    // OTYPER: bits 8,9 → 1 (open-drain, required for I2C)
    REG.gpiob_otyper.set_bits((1 << 8) | (1 << 9));

    // OSPEEDR: bits [17:16],[19:18] → 11 (very high speed)
    REG.gpiob_ospeedr.set_bits((0b11 << 16) | (0b11 << 18));

    // PUPDR: bits [17:16],[19:18] → 01 (pull-up — I2C bus pull-ups)
    // Note: the OM-SE050ARD has 3.3kΩ external pull-ups (J37/J38 default),
    // but internal pull-ups don't hurt as additional parallel resistance.
    REG.gpiob_pupdr.modify(|v| {
        (v & !(0b11 << 16) & !(0b11 << 18)) | (0b01 << 16) | (0b01 << 18)
    });

    // AFRH: PB8 = AF4 (bits [3:0]), PB9 = AF4 (bits [7:4])
    REG.gpiob_afrh.modify(|v| {
        (v & !(0xF << 0) & !(0xF << 4)) | (4 << 0) | (4 << 4)
    });

    // ---- 5. Configure I2C1 peripheral ----
    // Ensure PE=0 before writing timing
    REG.i2c1.cr1.write(0);
    cortex_m::asm::dsb();

    // Set timing for 400 kHz FM
    REG.i2c1.timingr.write(I2C_TIMING_400KHZ);

    // Enable analog noise filter (default), no digital filter
    // Enable I2C peripheral (PE=1)
    REG.i2c1.cr1.write(1); // PE = bit 0
    cortex_m::asm::dsb();
}
