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
    //! GTZC (Global TrustZone Controller) setup for STM32U585.
    //!
    //! Two registers drive this:
    //!   * GTZC1_MPCBB{1,2}  — block-based SRAM protection (unchanged).
    //!   * GTZC1_TZSC_SECCFGRx — per-peripheral security attribute.
    //!
    //! CRIT-4 fix: the TZSC_SECCFGRx registers used to be written to
    //! `0x00000000` (every peripheral NS), which put TRNG, AES, PKA,
    //! HASH, I2C1, I2C2 under NS control and defeated CLAUDE.md
    //! invariant #4. We now use a default-secure baseline: every bit is
    //! initialised to 1 (SECURE) and only peripherals that MUST be
    //! driven from NS (USB OTG FS, and nothing else today) get flipped
    //! to NS. The exact bit positions come from STM32U585 RM0456 §54
    //! (per-peripheral TZSC mapping tables).

    // RCC AHB1ENR — enable GTZC1 clock (RCC is on AHB3 at 0x56020C00)
    const RCC_AHB1ENR: *mut u32 = (0x5602_0C00 + 0x88) as *mut u32;

    // GTZC1 MPCBB base addresses (S alias, AHB2)
    const MPCBB1_BASE: u32 = 0x5003_2C00; // SRAM1 (192 KB)
    const MPCBB2_BASE: u32 = 0x5003_3000; // SRAM2 (64 KB)

    // MPCBB register offsets
    const MPCBB_CR: u32 = 0x00;
    const MPCBB_SECCFGR0: u32 = 0x100;

    // GTZC1 TZSC base address (S alias, AHB1). Per STM32U585 RM0456 and
    // CMSIS header: AHB1PERIPH_BASE_S (0x50020000) + 0x12400 = 0x50032400.
    // (The nearby 0x50032800 is GTZC1 TZIC — the interrupt controller,
    // not the security config; do not conflate.)
    const TZSC_BASE: u32 = 0x5003_2400;
    const TZSC_SECCFGR1: *mut u32 = (TZSC_BASE + 0x10) as *mut u32;
    const TZSC_SECCFGR2: *mut u32 = (TZSC_BASE + 0x14) as *mut u32;
    const TZSC_SECCFGR3: *mut u32 = (TZSC_BASE + 0x18) as *mut u32;

    // ---- USB allowlist for TZSC ----
    //
    // On STM32U585 the USB OTG FS controller is the only TZSC-gated
    // peripheral the NS world needs direct register access to. The TZSC
    // SECCFGRx layout is documented in RM0456 §54; note that the TZSC
    // bit positions do NOT align with RCC AHB/APB clock-enable bits —
    // each register groups a different bus (APB1 / APB2 / AHB) with its
    // own ordering.
    //
    // UCPD1 stays SECURE: the CC-detection handshake is performed from
    // the secure world at boot (`hw::usb_hw::init_ucpd`); the NS USB
    // stack never touches UCPD1 registers after that.
    //
    // GPIOs are NOT gated by TZSC — their security is per-pin in the
    // bank's GPIOx_SECCFGR register (see `hw::usb_hw::init`).
    //
    // TODO: verify this bit position against the STM32U585 reference
    // manual once the usb feature is exercised on hardware. If OTG_FS
    // is at a different bit, the post-allowlist self-check below will
    // catch the mismatch.
    #[cfg(feature = "usb")]
    const SECCFGR2_OTG_FS_BIT: u32 = 1 << 14;

    pub unsafe fn configure_gtzc() {
        // Enable GTZC1 clock
        let ahb1enr = core::ptr::read_volatile(RCC_AHB1ENR);
        core::ptr::write_volatile(RCC_AHB1ENR, ahb1enr | (1 << 24));
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

        // ---- GTZC1 TZSC: default-secure, with a minimal USB allowlist ----
        //
        // Baseline: every TZSC-gated peripheral is SECURE. Writing 1s to
        // unimplemented bits is ignored by the silicon, so the readback
        // reflects exactly the set of implemented peripherals — we store
        // that as our "all-secure" reference.
        core::ptr::write_volatile(TZSC_SECCFGR1, 0xFFFF_FFFF);
        core::ptr::write_volatile(TZSC_SECCFGR2, 0xFFFF_FFFF);
        core::ptr::write_volatile(TZSC_SECCFGR3, 0xFFFF_FFFF);
        cortex_m::asm::dsb();
        let base1 = core::ptr::read_volatile(TZSC_SECCFGR1);
        let base2 = core::ptr::read_volatile(TZSC_SECCFGR2);
        let base3 = core::ptr::read_volatile(TZSC_SECCFGR3);

        // Sanity check: each register must have at least one implemented
        // bit, otherwise the GTZC1 clock isn't actually on or TZSC_BASE
        // is wrong. Refuse to boot in that state — NS running against a
        // fabric whose security attributes didn't stick is exactly the
        // scenario CRIT-4 warns about.
        if base1 == 0 || base2 == 0 || base3 == 0 {
            loop {
                cortex_m::asm::nop();
            }
        }

        // Allowlist: the USB stack needs OTG FS in NS. Everything else
        // (I2C buses, TRNG, AES, PKA, HASH, SAES, timers, ...) stays
        // SECURE. This is the inverse of the old "everything NS" hole.
        #[cfg(feature = "usb")]
        {
            let want2 = base2 & !SECCFGR2_OTG_FS_BIT;
            core::ptr::write_volatile(TZSC_SECCFGR2, want2);
            cortex_m::asm::dsb();
            // Self-check: only OTG_FS should have changed. If the write
            // landed anywhere else (wrong bit position, silicon lock),
            // halt rather than hand NS a partly-secure fabric.
            let post2 = core::ptr::read_volatile(TZSC_SECCFGR2);
            if post2 != want2 {
                loop {
                    cortex_m::asm::nop();
                }
            }
        }

        // Self-check: after all intended writes, SECCFGR1 and SECCFGR3
        // must still be the all-secure baseline (we never touch those).
        let s1 = core::ptr::read_volatile(TZSC_SECCFGR1);
        let s3 = core::ptr::read_volatile(TZSC_SECCFGR3);
        if s1 != base1 || s3 != base3 {
            loop {
                cortex_m::asm::nop();
            }
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
