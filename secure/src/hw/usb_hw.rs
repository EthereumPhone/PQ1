//! USB OTG FS hardware initialization for STM32U585.
//!
//! Configures GPIO (PA11/PA12 for D-/D+), enables VDDUSB power supply,
//! and initializes UCPD1 for USB Type-C CC pin detection on the
//! B-U585I-IOT02A discovery board.
//!
//! All configuration is done from the secure world before the non-secure
//! USB stack starts.  The USB OTG peripheral itself is marked non-secure
//! by GTZC TZSC (see sau.rs).

use crate::hw::mmio::Reg32;

// ---------------------------------------------------------------------------
// RCC registers — SECURE alias required for TZEN=1 (GPIO clock enables
// are secure-only; writes via NS alias 0x4602_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
// Note: USB OTG FS uses ICLK (shared with RNG), already set to HSI48 in rcc.rs.

// ---------------------------------------------------------------------------
// PWR registers (secure alias — NS writes are silently ignored)
// ---------------------------------------------------------------------------
const PWR: u32 = 0x5602_0800;

// PWR_SVMCR bits (from stm32u585xx.h: PWR_SVMCR_USV_Pos = 28)
const USV: u32 = 1 << 28; // VDDUSB supply valid (removes electrical isolation)

// ---------------------------------------------------------------------------
// GPIOA registers (secure alias — GPIOA is secure by default with TZEN=1)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;

// GPIOB registers (secure alias)
const GPIOB_S: u32 = 0x5202_0400;

// ---------------------------------------------------------------------------
// UCPD1 registers — secure alias (APB1 peripherals are secure with TZEN=1;
// writes via NS alias 0x4000_xxxx are silently ignored).
// ---------------------------------------------------------------------------
const UCPD1: u32 = 0x5000_DC00;

struct UsbHwRegs {
    rcc_ahb2enr1: Reg32,
    rcc_apb1enr2: Reg32,
    rcc_ahb2rstr1: Reg32,
    pwr_svmcr: Reg32,
    pwr_ucpdr: Reg32,
    gpioa_moder: Reg32,
    gpioa_ospeedr: Reg32,
    gpioa_afrh: Reg32,
    gpioa_seccfgr: Reg32,
    gpiob_moder: Reg32,
    gpiob_ospeedr: Reg32,
    gpiob_bsrr: Reg32,
    gpiob_seccfgr: Reg32,
    ucpd1_cfg1: Reg32,
    ucpd1_cr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register touched
// once during boot by this driver, in the single-threaded secure world.
// Shared RCC and GPIO registers are accessed via disjoint-bit RMW so
// concurrent (sequential, non-overlapping) edits from other drivers are
// safe. USB endpoint RAM / FIFOs are deliberately NOT wrapped here —
// they require richer types than `Reg32` (see hw::mmio module docs).
const REG: UsbHwRegs = unsafe {
    UsbHwRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_apb1enr2: Reg32::new(RCC_S + 0xA0),
        rcc_ahb2rstr1: Reg32::new(RCC_S + 0x64),
        pwr_svmcr: Reg32::new(PWR + 0x10),
        pwr_ucpdr: Reg32::new(PWR + 0x2C),
        gpioa_moder: Reg32::new(GPIOA_S + 0x00),
        gpioa_ospeedr: Reg32::new(GPIOA_S + 0x08),
        gpioa_afrh: Reg32::new(GPIOA_S + 0x24),
        gpioa_seccfgr: Reg32::new(GPIOA_S + 0x30),
        gpiob_moder: Reg32::new(GPIOB_S + 0x00),
        gpiob_ospeedr: Reg32::new(GPIOB_S + 0x08),
        gpiob_bsrr: Reg32::new(GPIOB_S + 0x18),
        gpiob_seccfgr: Reg32::new(GPIOB_S + 0x30),
        ucpd1_cfg1: Reg32::new(UCPD1 + 0x00),
        ucpd1_cr: Reg32::new(UCPD1 + 0x0C),
    }
};

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
    REG.rcc_ahb2enr1.set_bits((1 << 0) | (1 << 1) | (1 << 4));
    cortex_m::asm::dsb();

    // ---- 2. Enable VDDUSB supply monitoring (PWR_SVMCR.USV) ----
    REG.pwr_svmcr.set_bits(USV);
    cortex_m::asm::dsb();

    // ---- 3. Enable USB OTG FS clock (AHB2ENR1 bit 14) ----
    REG.rcc_ahb2enr1.set_bits(1 << 14);
    cortex_m::asm::dsb();

    // USB 48 MHz clock: uses ICLK (shared with RNG), already set to HSI48 by rcc::init().

    // ---- 4. Reset USB OTG FS peripheral (AHB2RSTR1 bit 14) ----
    REG.rcc_ahb2rstr1.set_bits(1 << 14);
    cortex_m::asm::dsb();
    REG.rcc_ahb2rstr1.clear_bits(1 << 14);
    cortex_m::asm::dsb();

    // ---- 6. Mark USB pins as non-secure (per-pin GPIO security) ----
    // With TZEN=1, all GPIO pins default to secure (SECCFGR = 0xFFFF).
    // The USB OTG FS peripheral runs in NS domain, so it can only drive
    // pins that are marked as non-secure. Clear the security bits for
    // PA11 (D-), PA12 (D+) and PB5 (TCPP03 EN), PB6 (CC1), PB7 (CC2).
    REG.gpioa_seccfgr.clear_bits((1 << 11) | (1 << 12) | (1 << 15)); // PA11,12,15 = NS
    REG.gpiob_seccfgr.clear_bits((1 << 5) | (1 << 15)); // PB5,15 = NS

    #[cfg(feature = "debug-log")]
    {
        // Comprehensive register dump for USB bring-up debugging
        secure_log!(
            "[S][USB] RCC_AHB2ENR1=0x{:08x}",
            REG.rcc_ahb2enr1.read()
        );
        secure_log!(
            "[S][USB] GPIOA_MODER=0x{:08x} (expect PA11/12=AF=0b10)",
            REG.gpioa_moder.read()
        );
        secure_log!(
            "[S][USB] GPIOA_AFRH =0x{:08x} (expect PA11/12=AF10=0xA)",
            REG.gpioa_afrh.read()
        );
        // Read several offsets around 0x30 to find SECCFGR
        for off in [0x28u32, 0x2C, 0x30, 0x34] {
            let addr = GPIOA_S + off;
            // SAFETY: GPIOA register bank, 4-byte-aligned read for debug log.
            let val = unsafe { core::ptr::read_volatile(addr as *const u32) };
            secure_log!(
                "[S][USB] GPIOA+0x{:02x}=0x{:08x}", off, val
            );
        }
    }

    // ---- 7. Configure PA11 (D-) and PA12 (D+) as AF10 (USB), very-high speed ----
    REG.gpioa_moder.modify(|v| {
        (v & !(0b11 << 22) & !(0b11 << 24)) | (0b10 << 22) | (0b10 << 24)
    });

    REG.gpioa_ospeedr.set_bits((0b11 << 22) | (0b11 << 24));

    // AFRH: PA11 = AF10, PA12 = AF10
    REG.gpioa_afrh.modify(|v| {
        (v & !(0xF << 12) & !(0xF << 16)) | (10 << 12) | (10 << 16)
    });

    #[cfg(feature = "debug-log")]
    {
        secure_log!(
            "[S][USB] After GPIO config: MODER=0x{:08x} AFRH=0x{:08x}",
            REG.gpioa_moder.read(), REG.gpioa_afrh.read()
        );
    }

    // ---- 8. Enable TCPP03 (PB5 HIGH) ----
    // The TCPP03-M20 (U8) provides ESD protection and CC routing for the
    // USB-C connector (CN1).  Must be enabled for both USB-A→C and C→C cables.
    enable_tcpp03();

    // ---- 9. UCPD1 CC detection (PA15/PB15) ----
    init_ucpd();
}

/// Drive PB5 HIGH to enable the TCPP03-M20 port protection chip.
fn enable_tcpp03() {
    // PB5: output, push-pull, very-high speed, no pull
    // MODER bits [11:10] = 01 (output)
    REG.gpiob_moder.modify(|v| (v & !(0b11 << 10)) | (0b01 << 10));

    // OSPEEDR bits [11:10] = 11 (very high speed)
    REG.gpiob_ospeedr.set_bits(0b11 << 10);

    // BSRR: set PB5 HIGH. BSRR is atomic-set (write-1-to-set, no read needed).
    REG.gpiob_bsrr.write(1 << 5);

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
fn init_ucpd() {
    // Enable UCPD1 clock (APB1ENR2 bit 23)
    REG.rcc_apb1enr2.set_bits(1 << 23);
    cortex_m::asm::dsb();

    // Configure PA15 as analog (UCPD CC1)
    // MODER bits [31:30] for PA15 = 11 (analog)
    REG.gpioa_moder.set_bits(0b11 << 30);

    // Configure PB15 as analog (UCPD CC2)
    // MODER bits [31:30] for PB15 = 11 (analog)
    REG.gpiob_moder.set_bits(0b11 << 30);

    // UCPD1 CFG1: prescaler and timing for CC detection.
    // Values follow ST's reference configuration for HSI16.
    let cfg1: u32 = (13 << 0)   // HBITCLKDIV
        | (16 << 6)              // IFRGAP
        | (7 << 11)              // TRANSWIN
        | (0b01 << 17)           // PSC_USBPDCLK = /2 (HSI16/2 = 8 MHz)
        | (1 << 31);             // UCPDEN (enable UCPD)
    REG.ucpd1_cfg1.write(cfg1);
    cortex_m::asm::dsb();

    // UCPD1 CR: enable CC PHYs and connect Rd pull-downs (sink mode).
    // Bit 9:     ANAMODE  = 1  (sink → connects 5.1kΩ Rd on CC lines)
    // Bits 11:10 CCENABLE = 11 (both CC1 and CC2 PHYs enabled)
    //
    // IMPORTANT: bits 20/21 are **CC1TCDIS / CC2TCDIS = the Type-C voltage
    // *detector* disables**, NOT a dead-battery control (verified against
    // ST's LL driver: `LL_UCPD_TypeCDetectionCC1Disable() = SET_BIT(
    // CC1TCDIS)`). A prior version set them to 1 — which BLINDED the CC
    // voltage detectors (UCPD_SR.TYPEC_VSTATE stuck at 0, no attach ever
    // detected). We leave them CLEAR so the detectors run.
    let cr: u32 = (0b11 << 10)  // CCENABLE: both CC lines enabled
        | (1 << 9);              // ANAMODE: sink (Rd pull-down)
    REG.ucpd1_cr.write(cr);
    cortex_m::asm::dsb();

    // Disable the DEAD-BATTERY pull-downs the CORRECT way: PWR_UCPDR.
    // UCPD_DBDIS (bit 0). Mirrors `LL_PWR_DisableUCPDDeadBattery()` =
    // `SET_BIT(PWR->UCPDR, PWR_UCPDR_UCPD_DBDIS)` (PWR @ 0x5602_0800,
    // UCPDR @ +0x2C). After reset the dead-battery Rd is engaged (so an
    // unpowered/just-booted sink presents Rd); now that UCPD presents its
    // own Rd (ANAMODE=1) we release the dead-battery so it doesn't sit in
    // PARALLEL with the UCPD Rd and shift the CC voltage the host reads
    // (which is what broke USB-C-to-USB-C detection). Done AFTER the CR
    // config so there is no window with no Rd presented.
    REG.pwr_ucpdr.set_bits(1 << 0); // UCPD_DBDIS
    cortex_m::asm::dsb();

    // Settling delay for CC pull-downs
    for _ in 0..50_000 {
        cortex_m::asm::nop();
    }
}
