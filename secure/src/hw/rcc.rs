//! RCC clock configuration for STM32U585.
//!
//! Configures SYSCLK to 160 MHz via PLL1 (HSI16 × 20 / 2).
//! Falls back to HSI16 (16 MHz) if VOS Range 1 cannot be set.
//! Also enables HSI48 for the hardware RNG peripheral.

use crate::hw::mmio::Reg32;

// RCC register base (NS alias — AHB3 bus)
const RCC: u32 = 0x4602_0C00;

// PWR registers (secure alias — PWR is secure by default with TZEN=1,
// writes via NS alias 0x4602_0800 are silently ignored)
const PWR: u32 = 0x5602_0800;

// FLASH registers (secure alias)
const FLASH: u32 = 0x5002_2000;

// ICACHE registers (secure alias)
const ICACHE: u32 = 0x5003_0400;

struct RccRegs {
    cr: Reg32,
    cfgr1: Reg32,
    pll1cfgr: Reg32,
    pll1divr: Reg32,
    ahb2enr1: Reg32,
    ahb3enr: Reg32,
    ccipr5: Reg32,
    pwr_vosr: Reg32,
    flash_acr: Reg32,
    icache_cr: Reg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register
// exclusively owned by RCC clock setup, run once during boot. The secure
// world is single-threaded and non-preemptive — nothing else races us.
const REG: RccRegs = unsafe {
    RccRegs {
        cr: Reg32::new(RCC + 0x00),
        cfgr1: Reg32::new(RCC + 0x1C),
        pll1cfgr: Reg32::new(RCC + 0x28),
        pll1divr: Reg32::new(RCC + 0x34),
        ahb2enr1: Reg32::new(RCC + 0x8C),
        ahb3enr: Reg32::new(RCC + 0x94),
        ccipr5: Reg32::new(RCC + 0xE0),
        pwr_vosr: Reg32::new(PWR + 0x0C),
        flash_acr: Reg32::new(FLASH + 0x00),
        icache_cr: Reg32::new(ICACHE + 0x00),
    }
};

// RCC_CR bits
const HSION: u32 = 1 << 8;
const HSIRDY: u32 = 1 << 10;
const HSI48ON: u32 = 1 << 12;
const HSI48RDY: u32 = 1 << 13;
const PLL1ON: u32 = 1 << 24;
const PLL1RDY: u32 = 1 << 25;

// CFGR1 bits (RM0456: 00=MSIS, 01=HSI16, 10=HSE, 11=PLL1)
const SW_HSI16: u32 = 0b01;
const SWS_HSI16: u32 = 0b01 << 2;
const SW_PLL1: u32 = 0b11;
const SWS_PLL1: u32 = 0b11 << 2;

// PWR_VOSR bits (RM0456)
const VOSR_VOSRDY: u32 = 1 << 15;
const VOSR_VOS_RANGE1: u32 = 0b11 << 16; // bits [17:16] = 11
const VOSR_BOOSTEN: u32 = 1 << 18;

// PLL1CFGR bits
const PLL1SRC_HSI16: u32 = 0b10;          // bits [1:0]
const PLL1RGE_8_16: u32 = 0b11 << 2;      // bits [3:2]
const PLL1REN: u32 = 1 << 18;             // enable DIVR output (SYSCLK path)

// PLL1DIVR: HSI16(16 MHz) / M=1 × N=20 / R=2 = 160 MHz
const PLL1_N_20: u32 = 19;                // bits [8:0], value = N-1
const PLL1_R_2: u32 = 1 << 24;            // bits [30:24], value = R-1

// VOS timeout: ~1 ms at 16 MHz ≈ 16_000 iterations (generous)
const VOS_TIMEOUT: u32 = 100_000;

/// Configure SYSCLK to 160 MHz (PLL1) or 16 MHz (HSI16 fallback).
/// Enables HSI48 for the hardware RNG. Returns SYSCLK in MHz.
///
/// # Safety
/// Must be called early in boot, before any peripheral that depends on
/// the system clock frequency.
pub unsafe fn init() -> u32 {
    // ---- 1. Enable PWR clock ----
    REG.ahb3enr.set_bits(1 << 2);
    cortex_m::asm::dsb();

    // ---- 2. Enable HSI16 ----
    REG.cr.set_bits(HSION);
    while REG.cr.read() & HSIRDY == 0 {}

    // ---- 3. Switch SYSCLK to HSI16 (safe baseline before PLL config) ----
    REG.cfgr1.modify(|v| (v & !0x3) | SW_HSI16);
    while REG.cfgr1.read() & (0x3 << 2) != SWS_HSI16 {}

    // ---- 4. Attempt VOS Range 1 + EPOD booster for 160 MHz ----
    let sysclk = try_pll_160mhz();

    // ---- 5. Enable HSI48 (RNG clock source) ----
    REG.cr.set_bits(HSI48ON);
    while REG.cr.read() & HSI48RDY == 0 {}

    // ---- 6. Select HSI48 as RNG clock source ----
    REG.ccipr5.clear_bits(0x3);

    // ---- 7. Enable RNG peripheral clock (AHB2ENR1 bit 18) ----
    REG.ahb2enr1.set_bits(1 << 18);

    sysclk
}

/// Attempt to switch to VOS Range 1 and configure PLL1 for 160 MHz.
/// Returns 160 on success, or 16 if VOS change fails (stays on HSI16).
fn try_pll_160mhz() -> u32 {
    // Set VOS Range 1 and enable EPOD booster in a single write.
    REG.pwr_vosr.modify(|v| {
        (v & !(VOSR_VOS_RANGE1 | VOSR_BOOSTEN)) | VOSR_VOS_RANGE1 | VOSR_BOOSTEN
    });
    cortex_m::asm::dsb();

    // Wait for VOSRDY with timeout.
    // Note: BOOSTRDY (bit 14) may never set depending on the board's power
    // supply configuration (LDO-only vs SMPS). VOSRDY alone confirms VOS
    // Range 1 is active and stable.
    let mut timeout = VOS_TIMEOUT;
    while REG.pwr_vosr.read() & VOSR_VOSRDY == 0 {
        timeout -= 1;
        if timeout == 0 {
            return 16; // VOS change failed — stay on HSI16 @ 16 MHz
        }
    }

    // Disable ICACHE before changing flash wait states.
    REG.icache_cr.write(0);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    // Set flash latency to 4 wait states (required for 160 MHz @ VOS1).
    REG.flash_acr.modify(|v| (v & !0xF) | 4);
    // Read back to ensure the write took effect.
    while REG.flash_acr.read() & 0xF != 4 {}

    // Make sure PLL1 is off before configuring.
    REG.cr.clear_bits(PLL1ON);
    while REG.cr.read() & PLL1RDY != 0 {}

    // Configure PLL1: HSI16 source, 8-16 MHz input range, M=/1, R output enabled.
    REG.pll1cfgr.write(PLL1SRC_HSI16 | PLL1RGE_8_16 | PLL1REN);

    // Configure PLL1 dividers: N=20, R=2 → 16 MHz × 20 / 2 = 160 MHz.
    REG.pll1divr.write(PLL1_N_20 | PLL1_R_2);

    // Enable PLL1 and wait for lock.
    REG.cr.set_bits(PLL1ON);
    while REG.cr.read() & PLL1RDY == 0 {}

    // Switch SYSCLK to PLL1.
    REG.cfgr1.modify(|v| (v & !0x3) | SW_PLL1);
    while REG.cfgr1.read() & (0x3 << 2) != SWS_PLL1 {}

    // Re-enable ICACHE.
    REG.icache_cr.write(1);

    160
}
