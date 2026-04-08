//! RCC clock configuration for STM32U585.
//!
//! Switches SYSCLK from the default MSI 4 MHz to HSI16 (16 MHz).
//! Also enables HSI48 for the hardware RNG peripheral.
//!
//! 16 MHz is the maximum safe frequency at VOS Range 4 (the reset default).
//! PLL for 160 MHz requires VOS Range 1, but PWR_VOSR VOS bits are
//! unwritable on STM32U585 Rev W (0x3001) — all VOS change attempts are
//! silently ignored regardless of bus alias, security state, or regulator
//! mode. This is likely a silicon limitation on this revision.

use core::ptr::{read_volatile, write_volatile};

// RCC register base (NS alias — AHB3 bus at 0x46020C00)
const RCC: u32 = 0x4602_0C00;

const RCC_CR: *mut u32 = (RCC + 0x00) as *mut u32;
const RCC_CFGR1: *mut u32 = (RCC + 0x1C) as *mut u32;
const RCC_AHB2ENR1: *mut u32 = (RCC + 0x8C) as *mut u32;
const RCC_AHB3ENR: *mut u32 = (RCC + 0x94) as *mut u32;
const RCC_CCIPR5: *mut u32 = (RCC + 0xE0) as *mut u32;

// RCC_CR bits
const HSION: u32 = 1 << 8;
const HSIRDY: u32 = 1 << 10;
const HSI48ON: u32 = 1 << 12;
const HSI48RDY: u32 = 1 << 13;

// CFGR1 bits (RM0456: 00=MSIS, 01=HSI16, 10=HSE, 11=PLL1)
const SW_HSI16: u32 = 1;
const SWS_HSI16: u32 = 1 << 2;

/// Configure SYSCLK to HSI16 (16 MHz) and enable HSI48 for RNG.
/// Returns the SYSCLK frequency in MHz.
///
/// # Safety
/// Must be called early in boot, before any peripheral that depends on
/// the system clock frequency.
pub unsafe fn init() -> u32 {
    // ---- 1. Enable PWR clock (for completeness, not strictly needed at 16 MHz) ----
    let ahb3 = read_volatile(RCC_AHB3ENR);
    write_volatile(RCC_AHB3ENR, ahb3 | (1 << 2));
    cortex_m::asm::dsb();

    // ---- 2. Enable HSI16 ----
    let cr = read_volatile(RCC_CR);
    write_volatile(RCC_CR, cr | HSION);
    while read_volatile(RCC_CR) & HSIRDY == 0 {}

    // ---- 3. Switch SYSCLK to HSI16 ----
    let cfgr1 = read_volatile(RCC_CFGR1);
    write_volatile(RCC_CFGR1, (cfgr1 & !0x3) | SW_HSI16);
    while read_volatile(RCC_CFGR1) & (0x3 << 2) != SWS_HSI16 {}

    // ---- 4. Enable HSI48 (RNG clock source) ----
    let cr = read_volatile(RCC_CR);
    write_volatile(RCC_CR, cr | HSI48ON);
    while read_volatile(RCC_CR) & HSI48RDY == 0 {}

    // ---- 5. Select HSI48 as RNG clock source ----
    let ccipr5 = read_volatile(RCC_CCIPR5);
    write_volatile(RCC_CCIPR5, ccipr5 & !0x3);

    // ---- 6. Enable RNG peripheral clock (AHB2ENR1 bit 18) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 18));

    16
}
