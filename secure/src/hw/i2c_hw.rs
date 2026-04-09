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

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC registers (secure alias — TZEN=1)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_APB1ENR1: *mut u32 = (RCC_S + 0x9C) as *mut u32;
const RCC_APB1RSTR1: *mut u32 = (RCC_S + 0x74) as *mut u32;

// ---------------------------------------------------------------------------
// GPIOB registers (secure alias)
// ---------------------------------------------------------------------------
const GPIOB_S: u32 = 0x5202_0400;
const GPIOB_MODER: *mut u32 = (GPIOB_S + 0x00) as *mut u32;
const GPIOB_OTYPER: *mut u32 = (GPIOB_S + 0x04) as *mut u32;
const GPIOB_OSPEEDR: *mut u32 = (GPIOB_S + 0x08) as *mut u32;
const GPIOB_PUPDR: *mut u32 = (GPIOB_S + 0x0C) as *mut u32;
const GPIOB_AFRH: *mut u32 = (GPIOB_S + 0x24) as *mut u32;

// ---------------------------------------------------------------------------
// I2C1 registers (secure alias — APB1 peripherals are secure with TZEN=1)
// ---------------------------------------------------------------------------
pub const I2C1: u32 = 0x5000_5400;
pub const I2C1_CR1: *mut u32 = (I2C1 + 0x00) as *mut u32;
pub const I2C1_CR2: *mut u32 = (I2C1 + 0x04) as *mut u32;
pub const I2C1_TIMINGR: *mut u32 = (I2C1 + 0x10) as *mut u32;
pub const I2C1_ISR: *const u32 = (I2C1 + 0x18) as *const u32;
pub const I2C1_ICR: *mut u32 = (I2C1 + 0x1C) as *mut u32;
pub const I2C1_RXDR: *const u32 = (I2C1 + 0x24) as *const u32;
pub const I2C1_TXDR: *mut u32 = (I2C1 + 0x28) as *mut u32;

// I2C1 TIMINGR for 400 kHz Fast Mode at 160 MHz PCLK1.
//
// PRESC=1 (÷2 → 12.5 ns), SCLDEL=9 (125 ns ≥ 100 ns FM min),
// SDADEL=0, SCLH=55 (700 ns ≥ 600 ns), SCLL=143 (1800 ns ≥ 1300 ns).
// Period = 700+1800 = 2500 ns → 400 kHz.
const I2C_TIMING_400KHZ: u32 = 0x1090_378F;

/// Initialize I2C1 hardware from the secure world.
///
/// Must be called after `rcc::init()` (clocks running at 160 MHz).
///
/// # Safety
/// Direct register access. Must be called exactly once during boot.
pub unsafe fn init() {
    // ---- 1. Enable GPIOB clock (AHB2ENR1 bit 1) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 1));
    cortex_m::asm::dsb();

    // ---- 2. Enable I2C1 clock (APB1ENR1 bit 21) ----
    let apb1 = read_volatile(RCC_APB1ENR1);
    write_volatile(RCC_APB1ENR1, apb1 | (1 << 21));
    cortex_m::asm::dsb();

    // ---- 3. Reset I2C1 peripheral (APB1RSTR1 bit 21) ----
    let rstr = read_volatile(RCC_APB1RSTR1);
    write_volatile(RCC_APB1RSTR1, rstr | (1 << 21));
    cortex_m::asm::dsb();
    write_volatile(RCC_APB1RSTR1, rstr & !(1 << 21));
    cortex_m::asm::dsb();

    // ---- 4. Configure PB8 (SCL) and PB9 (SDA) as AF4, open-drain ----
    // MODER: bits [17:16] for PB8, [19:18] for PB9 → 10 (alternate function)
    let moder = read_volatile(GPIOB_MODER);
    let moder = (moder & !(0b11 << 16) & !(0b11 << 18)) | (0b10 << 16) | (0b10 << 18);
    write_volatile(GPIOB_MODER, moder);

    // OTYPER: bits 8,9 → 1 (open-drain, required for I2C)
    let otyper = read_volatile(GPIOB_OTYPER);
    write_volatile(GPIOB_OTYPER, otyper | (1 << 8) | (1 << 9));

    // OSPEEDR: bits [17:16],[19:18] → 11 (very high speed)
    let ospeedr = read_volatile(GPIOB_OSPEEDR);
    write_volatile(GPIOB_OSPEEDR, ospeedr | (0b11 << 16) | (0b11 << 18));

    // PUPDR: bits [17:16],[19:18] → 01 (pull-up — I2C bus pull-ups)
    // Note: the OM-SE050ARD has 3.3kΩ external pull-ups (J37/J38 default),
    // but internal pull-ups don't hurt as additional parallel resistance.
    let pupdr = read_volatile(GPIOB_PUPDR);
    let pupdr = (pupdr & !(0b11 << 16) & !(0b11 << 18)) | (0b01 << 16) | (0b01 << 18);
    write_volatile(GPIOB_PUPDR, pupdr);

    // AFRH: PB8 = AF4 (bits [3:0]), PB9 = AF4 (bits [7:4])
    let afrh = read_volatile(GPIOB_AFRH);
    let afrh = (afrh & !(0xF << 0) & !(0xF << 4)) | (4 << 0) | (4 << 4);
    write_volatile(GPIOB_AFRH, afrh);

    // ---- 5. Configure I2C1 peripheral ----
    // Ensure PE=0 before writing timing
    write_volatile(I2C1_CR1, 0);
    cortex_m::asm::dsb();

    // Set timing for 400 kHz FM
    write_volatile(I2C1_TIMINGR, I2C_TIMING_400KHZ);

    // Enable analog noise filter (default), no digital filter
    // Enable I2C peripheral (PE=1)
    write_volatile(I2C1_CR1, 1); // PE = bit 0
    cortex_m::asm::dsb();
}
