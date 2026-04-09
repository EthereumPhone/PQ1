/// SAU and memory-protection configuration.
///
/// On QEMU mps2-an505: configures the MPC (Memory Protection Controller)
/// On real STM32U585:   configures the GTZC MPCBB (block-based SRAM protection)
///
/// SAU region layout is the same structure but with different addresses.

// SAU register addresses (ARMv8-M standard, same on both targets)
const SAU_CTRL: *mut u32 = 0xE000_EDD0 as *mut u32;
const SAU_RNR: *mut u32 = 0xE000_EDD8 as *mut u32;
const SAU_RBAR: *mut u32 = 0xE000_EDDC as *mut u32;
const SAU_RLAR: *mut u32 = 0xE000_EDE0 as *mut u32;

extern "C" {
    static __veneer_base: u32;
    static __veneer_limit: u32;
}

unsafe fn configure_sau_region(region: u32, base: u32, limit: u32, nsc: bool) {
    core::ptr::write_volatile(SAU_RNR, region);
    core::ptr::write_volatile(SAU_RBAR, base & 0xFFFF_FFE0);
    let nsc_bit = if nsc { 1 << 1 } else { 0 };
    core::ptr::write_volatile(SAU_RLAR, (limit & 0xFFFF_FFE0) | nsc_bit | 1);
}

// ---------------------------------------------------------------------------
// QEMU mps2-an505 (SSE-200 IoTKit with MPC)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "stm32u585"))]
mod qemu {
    const MPC0_BASE: u32 = 0x5800_7000; // SSRAM-0 (code, 4MB)
    const MPC1_BASE: u32 = 0x5800_8000; // SSRAM-1 (data, 2MB)

    const MPC_BLK_MAX: u32 = 0x10;
    const MPC_BLK_IDX: u32 = 0x18;
    const MPC_BLK_LUT: u32 = 0x1C;

    pub unsafe fn configure_mpc() {
        // MPC0: SSRAM-0 — first 2MB secure (code), rest NS (NS code + NSC veneers)
        configure_mpc_partial_ns(MPC0_BASE, 64);
        // MPC1: SSRAM-1 — first 128KB secure (stack), rest NS
        configure_mpc_partial_ns(MPC1_BASE, 4);
    }

    unsafe fn configure_mpc_partial_ns(mpc_base: u32, ns_start_lut_idx: u32) {
        let blk_max = core::ptr::read_volatile((mpc_base + MPC_BLK_MAX) as *const u32);
        let blk_idx_reg = (mpc_base + MPC_BLK_IDX) as *mut u32;
        let blk_lut_reg = (mpc_base + MPC_BLK_LUT) as *mut u32;

        for idx in 0..=blk_max {
            core::ptr::write_volatile(blk_idx_reg, idx);
            let val = if idx >= ns_start_lut_idx { 0xFFFF_FFFF } else { 0 };
            core::ptr::write_volatile(blk_lut_reg, val);
        }
    }
}

// ---------------------------------------------------------------------------
// Real STM32U585 (GTZC MPCBB for SRAM, flash watermark via option bytes)
// ---------------------------------------------------------------------------
#[cfg(feature = "stm32u585")]
mod stm32 {
    // RCC AHB1ENR — enable GTZC1 clock (RCC is on AHB3 at 0x56020C00)
    const RCC_AHB1ENR: *mut u32 = (0x5602_0C00 + 0x88) as *mut u32;

    // GTZC1 MPCBB base addresses (S alias, AHB2)
    const MPCBB1_BASE: u32 = 0x5003_2C00; // SRAM1 (192 KB)
    const MPCBB2_BASE: u32 = 0x5003_3000; // SRAM2 (64 KB)

    // MPCBB register offsets
    const MPCBB_CR: u32 = 0x00;
    const MPCBB_SECCFGR0: u32 = 0x100;

    // GTZC1 TZSC base address (S alias, AHB1)
    const TZSC_BASE: u32 = 0x5003_2800;
    const TZSC_SECCFGR1: *mut u32 = (TZSC_BASE + 0x10) as *mut u32;
    const TZSC_SECCFGR2: *mut u32 = (TZSC_BASE + 0x14) as *mut u32;
    const TZSC_SECCFGR3: *mut u32 = (TZSC_BASE + 0x18) as *mut u32;

    pub unsafe fn configure_gtzc() {
        // Enable GTZC1 clock
        let ahb1enr = core::ptr::read_volatile(RCC_AHB1ENR);
        core::ptr::write_volatile(RCC_AHB1ENR, ahb1enr | (1 << 24));
        // Small delay for clock to stabilize
        cortex_m::asm::dsb();

        // MPCBB1 (SRAM1, 192 KB): all secure (default after reset with TZEN=1,
        // but set explicitly for clarity).
        // 192 KB / 256 bytes = 768 blocks, 768 / 32 = 24 config registers.
        core::ptr::write_volatile((MPCBB1_BASE + MPCBB_CR) as *mut u32, 0);
        for i in 0..24u32 {
            core::ptr::write_volatile(
                (MPCBB1_BASE + MPCBB_SECCFGR0 + i * 4) as *mut u32,
                0xFFFF_FFFF, // all blocks secure
            );
        }

        // MPCBB2 (SRAM2, 64 KB): all non-secure.
        // 64 KB / 256 bytes = 256 blocks, 256 / 32 = 8 config registers.
        core::ptr::write_volatile((MPCBB2_BASE + MPCBB_CR) as *mut u32, 0);
        for i in 0..8u32 {
            core::ptr::write_volatile(
                (MPCBB2_BASE + MPCBB_SECCFGR0 + i * 4) as *mut u32,
                0x0000_0000, // all blocks non-secure
            );
        }

        // ---- GTZC1 TZSC: mark USB-related peripherals as NS ----
        //
        // For USB operation, GPIOA (PA11/PA12), GPIOB (PB6/PB7 UCPD CC),
        // USB OTG FS, and UCPD1 must be non-secure.
        //
        // Mark all AHB2 and APB peripherals as NS for now. Production
        // builds should restrict this to only the needed peripherals.
        #[cfg(feature = "usb")]
        {
            core::ptr::write_volatile(TZSC_SECCFGR1, 0x0000_0000);
            core::ptr::write_volatile(TZSC_SECCFGR2, 0x0000_0000);
            core::ptr::write_volatile(TZSC_SECCFGR3, 0x0000_0000);
            cortex_m::asm::dsb();
        }
    }
}

pub fn init() {
    unsafe {
        #[cfg(not(feature = "stm32u585"))]
        qemu::configure_mpc();

        #[cfg(feature = "stm32u585")]
        stm32::configure_gtzc();

        // Disable SAU while configuring
        core::ptr::write_volatile(SAU_CTRL, 0);

        // Region 0: NS code flash
        #[cfg(not(feature = "stm32u585"))]
        configure_sau_region(0, 0x0020_0000, 0x003F_FFFF, false);
        #[cfg(feature = "stm32u585")]
        configure_sau_region(0, 0x0810_0000, 0x081F_FFFF, false); // bank 2 NS

        // Region 1: NSC veneers (placed in secure flash by linker)
        let veneer_base = &__veneer_base as *const u32 as u32;
        let veneer_limit = &__veneer_limit as *const u32 as u32;
        let nsc_end = if veneer_limit > veneer_base {
            ((veneer_limit + 0xFF) & 0xFFFF_FF00) - 1
        } else {
            veneer_base + 0xFF
        };
        configure_sau_region(1, veneer_base, nsc_end, true);

        // Region 2: NS data SRAM
        #[cfg(not(feature = "stm32u585"))]
        configure_sau_region(2, 0x2802_0000, 0x29FF_FFFF, false);
        #[cfg(feature = "stm32u585")]
        configure_sau_region(2, 0x2003_0000, 0x2003_FFFF, false); // SRAM2 NS

        // Region 3: NS peripherals
        configure_sau_region(3, 0x4000_0000, 0x4FFF_FFFF, false);

        // Enable SAU + barriers
        core::ptr::write_volatile(SAU_CTRL, 1);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}
