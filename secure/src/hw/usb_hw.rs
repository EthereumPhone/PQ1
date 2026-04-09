//! USB OTG FS hardware initialization for STM32U585.
//!
//! Configures GPIO (PA11/PA12 for D-/D+), enables VDDUSB power supply,
//! and initializes UCPD1 for USB Type-C CC pin detection on the
//! B-U585I-IOT02A discovery board.
//!
//! All configuration is done from the secure world before the non-secure
//! USB stack starts.  The USB OTG peripheral itself is marked non-secure
//! by GTZC TZSC (see sau.rs).

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC registers — SECURE alias required for TZEN=1 (GPIO clock enables
// are secure-only; writes via NS alias 0x4602_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_APB1ENR2: *mut u32 = (RCC_S + 0xA0) as *mut u32;
const RCC_AHB2RSTR1: *mut u32 = (RCC_S + 0x64) as *mut u32;
// Note: USB OTG FS uses ICLK (shared with RNG), already set to HSI48 in rcc.rs.

// ---------------------------------------------------------------------------
// PWR registers (secure alias — NS writes are silently ignored)
// ---------------------------------------------------------------------------
const PWR: u32 = 0x5602_0800;
const PWR_SVMCR: *mut u32 = (PWR + 0x10) as *mut u32;

// PWR_SVMCR bits (from stm32u585xx.h: PWR_SVMCR_USV_Pos = 28)
const USV: u32 = 1 << 28; // VDDUSB supply valid (removes electrical isolation)

// ---------------------------------------------------------------------------
// GPIOA registers (secure alias — GPIOA is secure by default with TZEN=1)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;
const GPIOA_MODER: *mut u32 = (GPIOA_S + 0x00) as *mut u32;
const GPIOA_OSPEEDR: *mut u32 = (GPIOA_S + 0x08) as *mut u32;
const GPIOA_AFRH: *mut u32 = (GPIOA_S + 0x24) as *mut u32;

// GPIOB registers (secure alias)
const GPIOB_S: u32 = 0x5202_0400;
const GPIOB_MODER: *mut u32 = (GPIOB_S + 0x00) as *mut u32;
const GPIOB_OSPEEDR: *mut u32 = (GPIOB_S + 0x08) as *mut u32;
const GPIOB_AFRH: *mut u32 = (GPIOB_S + 0x24) as *mut u32;
const GPIOB_BSRR: *mut u32 = (GPIOB_S + 0x18) as *mut u32;

// GPIOA additional registers
const GPIOA_AFRL: *mut u32 = (GPIOA_S + 0x20) as *mut u32;

// ---------------------------------------------------------------------------
// UCPD1 registers — secure alias (APB1 peripherals are secure with TZEN=1;
// writes via NS alias 0x4000_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const UCPD1: u32 = 0x5000_DC00;
const UCPD1_CFG1: *mut u32 = (UCPD1 + 0x00) as *mut u32;
const UCPD1_CFG2: *mut u32 = (UCPD1 + 0x04) as *mut u32;
const UCPD1_CR: *mut u32 = (UCPD1 + 0x0C) as *mut u32;

/// Initialize USB OTG FS hardware from the secure world.
///
/// This must be called after `rcc::init()` (HSI48 is already running)
/// and after `sau::init()` (GTZC TZSC has marked USB OTG as NS).
///
/// On the B-U585I-IOT02A (MB1551), the USB Type-C connector goes through
/// a **TCPP03-M20** port protection chip (U8) that must be enabled via
/// GPIO PB5 before USB data lines are connected.
///
/// Pin mapping (from UM2839 Table 8 + Table 9):
///   PA11 = USB_OTG_FS_DM (D-)    — direct to CN1
///   PA12 = USB_OTG_FS_DP (D+)    — direct to CN1
///   PA15 = UCPD1_CC1              — through TCPP03 to CN1
///   PB15 = UCPD1_CC2              — through TCPP03 to CN1
///   PB5  = TCPP03 EN (drive HIGH to enable)
///
/// # Safety
/// Direct register access.  Must be called exactly once during boot.
pub unsafe fn init() {
    // ---- 1. Enable GPIO clocks: GPIOA, GPIOB, GPIOE (AHB2ENR1 bits 0,1,4) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 0) | (1 << 1) | (1 << 4));
    cortex_m::asm::dsb();

    // ---- 2. Enable VDDUSB supply monitoring (PWR_SVMCR.USV) ----
    let svmcr = read_volatile(PWR_SVMCR);
    write_volatile(PWR_SVMCR, svmcr | USV);
    cortex_m::asm::dsb();

    // ---- 3. Enable USB OTG FS clock (AHB2ENR1 bit 14) ----
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 14));
    cortex_m::asm::dsb();

    // USB 48 MHz clock: uses ICLK (shared with RNG), already set to HSI48 by rcc::init().

    // ---- 4. Reset USB OTG FS peripheral (AHB2RSTR1 bit 14) ----
    let rstr = read_volatile(RCC_AHB2RSTR1);
    write_volatile(RCC_AHB2RSTR1, rstr | (1 << 14));
    cortex_m::asm::dsb();
    write_volatile(RCC_AHB2RSTR1, rstr & !(1 << 14));
    cortex_m::asm::dsb();

    // ---- 6. Mark USB pins as non-secure (per-pin GPIO security) ----
    // With TZEN=1, all GPIO pins default to secure (SECCFGR = 0xFFFF).
    // The USB OTG FS peripheral runs in NS domain, so it can only drive
    // pins that are marked as non-secure. Clear the security bits for
    // PA11 (D-), PA12 (D+) and PB5 (TCPP03 EN), PB6 (CC1), PB7 (CC2).
    const GPIOA_SECCFGR: *mut u32 = (GPIOA_S + 0x30) as *mut u32;
    const GPIOB_SECCFGR: *mut u32 = (GPIOB_S + 0x30) as *mut u32;
    let a_sec = read_volatile(GPIOA_SECCFGR);
    write_volatile(GPIOA_SECCFGR, a_sec & !(1 << 11) & !(1 << 12) & !(1 << 15)); // PA11,12,15 = NS
    let b_sec = read_volatile(GPIOB_SECCFGR);
    write_volatile(GPIOB_SECCFGR, b_sec & !(1 << 5) & !(1 << 15)); // PB5,15 = NS

    #[cfg(feature = "debug-log")]
    {
        // Comprehensive register dump for USB bring-up debugging
        cortex_m_semihosting::hprintln!(
            "[S][USB] RCC_AHB2ENR1=0x{:08x}",
            read_volatile(RCC_AHB2ENR1)
        );
        cortex_m_semihosting::hprintln!(
            "[S][USB] GPIOA_MODER=0x{:08x} (expect PA11/12=AF=0b10)",
            read_volatile(GPIOA_MODER)
        );
        cortex_m_semihosting::hprintln!(
            "[S][USB] GPIOA_AFRH =0x{:08x} (expect PA11/12=AF10=0xA)",
            read_volatile(GPIOA_AFRH)
        );
        // Read several offsets around 0x30 to find SECCFGR
        for off in [0x28u32, 0x2C, 0x30, 0x34] {
            let addr = GPIOA_S + off;
            let val = read_volatile(addr as *const u32);
            cortex_m_semihosting::hprintln!(
                "[S][USB] GPIOA+0x{:02x}=0x{:08x}", off, val
            );
        }
    }

    // ---- 7. Configure PA11 (D-) and PA12 (D+) as AF10 (USB), very-high speed ----
    let moder = read_volatile(GPIOA_MODER);
    let moder = (moder & !(0b11 << 22) & !(0b11 << 24)) | (0b10 << 22) | (0b10 << 24);
    write_volatile(GPIOA_MODER, moder);

    let ospeedr = read_volatile(GPIOA_OSPEEDR);
    write_volatile(GPIOA_OSPEEDR, ospeedr | (0b11 << 22) | (0b11 << 24));

    // AFRH: PA11 = AF10, PA12 = AF10
    let afrh = read_volatile(GPIOA_AFRH);
    let afrh = (afrh & !(0xF << 12) & !(0xF << 16)) | (10 << 12) | (10 << 16);
    write_volatile(GPIOA_AFRH, afrh);

    #[cfg(feature = "debug-log")]
    {
        cortex_m_semihosting::hprintln!(
            "[S][USB] After GPIO config: MODER=0x{:08x} AFRH=0x{:08x}",
            read_volatile(GPIOA_MODER), read_volatile(GPIOA_AFRH)
        );
    }

    // ---- 8. Enable TCPP03 (PB5 HIGH) ----
    // With JP4 on 5V_UCPD, the TCPP03 controls the VBUS path from the
    // USB-C connector.  Enabling it activates CC routing through the chip.
    enable_tcpp03();

    // ---- 9. UCPD1 CC detection (PA15/PB15) ----
    init_ucpd();
}

/// Drive PB5 HIGH to enable the TCPP03-M20 port protection chip.
unsafe fn enable_tcpp03() {
    // PB5: output, push-pull, very-high speed, no pull
    // MODER bits [11:10] = 01 (output)
    let moder = read_volatile(GPIOB_MODER);
    write_volatile(GPIOB_MODER, (moder & !(0b11 << 10)) | (0b01 << 10));

    // OSPEEDR bits [11:10] = 11 (very high speed)
    let ospeedr = read_volatile(GPIOB_OSPEEDR);
    write_volatile(GPIOB_OSPEEDR, ospeedr | (0b11 << 10));

    // BSRR: set PB5 HIGH
    write_volatile(GPIOB_BSRR, 1 << 5);

    // Small delay for TCPP03 to initialize
    for _ in 0..100_000 {
        cortex_m::asm::nop();
    }
}

/// Initialize UCPD1 for USB Type-C CC detection (sink/device mode).
///
/// On the B-U585I-IOT02A (UM2839 Table 8):
///   PA15 = UCPD1_CC1 (analog)
///   PB15 = UCPD1_CC2 (analog)
///
/// We configure UCPD1 as a sink so the host detects Rd on CC and provides VBUS.
unsafe fn init_ucpd() {
    // Enable UCPD1 clock (APB1ENR2 bit 23)
    let apb1enr2 = read_volatile(RCC_APB1ENR2);
    write_volatile(RCC_APB1ENR2, apb1enr2 | (1 << 23));
    cortex_m::asm::dsb();

    // Configure PA15 as analog (UCPD CC1)
    // MODER bits [31:30] for PA15 = 11 (analog)
    let moder_a = read_volatile(GPIOA_MODER);
    write_volatile(GPIOA_MODER, moder_a | (0b11 << 30));

    // Configure PB15 as analog (UCPD CC2)
    // MODER bits [31:30] for PB15 = 11 (analog)
    let moder_b = read_volatile(GPIOB_MODER);
    write_volatile(GPIOB_MODER, moder_b | (0b11 << 30));

    // UCPD1 CFG1: prescaler and timing for CC detection.
    // Values follow ST's reference configuration for HSI16.
    let cfg1: u32 = (13 << 0)   // HBITCLKDIV
        | (16 << 6)              // IFRGAP
        | (7 << 11)              // TRANSWIN
        | (0b01 << 17)           // PSC_USBPDCLK = /2 (HSI16/2 = 8 MHz)
        | (1 << 31);             // UCPDEN (enable UCPD)
    write_volatile(UCPD1_CFG1, cfg1);
    cortex_m::asm::dsb();

    // UCPD1 CR: enable CC PHYs and connect Rd pull-downs (sink mode).
    // Bit 9:     ANAMODE = 1 (sink → connects 5.1kΩ Rd on CC lines)
    // Bits 11:10 CCENABLE = 11 (both CC1 and CC2 PHYs enabled)
    let cr: u32 = (0b11 << 10)  // CCENABLE: both CC lines enabled
        | (1 << 9);              // ANAMODE: sink (Rd pull-down)
    write_volatile(UCPD1_CR, cr);
    cortex_m::asm::dsb();

    // Settling delay for CC pull-downs
    for _ in 0..50_000 {
        cortex_m::asm::nop();
    }
}
