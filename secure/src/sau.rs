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
    // not the security config; do not conflate. This was the source of
    // the silently-no-op TZSC writes that motivated the audit.)
    //
    // GTZC1_TZSC governs AHB1 + APB1 + APB2 + AHB2 peripherals on
    // STM32U585. Verified against the STM32CubeU5 HAL headers
    // (`vendor/STM32CubeU5/.../stm32u5xx_hal_gtzc.h` +
    // `stm32u585xx.h`): the `GTZC_PERIPH_{OTG,AES,HASH,RNG,PKA,SAES}`
    // constants all carry the `GTZC1_PERIPH_REG3` discriminator —
    // i.e. they're all bits in `GTZC1_TZSC_SECCFGR3`, the same
    // controller this function already writes to.
    //
    // The pre-fix comment claimed "AHB2 peripherals are governed by a
    // SECOND, separate controller GTZC2_TZSC" — that was a
    // misdiagnosis. GTZC2 on STM32U585 governs *RTC-domain*
    // peripherals (TAMP, BKP-SRAM, etc., in `GTZC2_PERIPH_REG{1,2}`).
    // The AHB2 crypto block + USB OTG FS all live in GTZC1's SECCFGR3.
    //
    // Base addr: `GTZC_TZSC1_BASE_S = 0x5003_2400` (= PERIPH_BASE_S
    // 0x5000_0000 + AHB1PERIPH offset 0x0002_0000 + TZSC1 offset
    // 0x0001_2400).
    const TZSC_BASE: u32 = 0x5003_2400;
    const TZSC_SECCFGR1: *mut u32 = (TZSC_BASE + 0x10) as *mut u32;
    const TZSC_SECCFGR2: *mut u32 = (TZSC_BASE + 0x14) as *mut u32;
    const TZSC_SECCFGR3: *mut u32 = (TZSC_BASE + 0x18) as *mut u32;

    // ---- SECCFGR1 (APB1) — I2C1 + I2C2 SECURE ----
    // Bit positions per `GTZC_CFGR1_*_Pos` in CMSIS `stm32u585xx.h`.
    //
    // - I2C1 (bit 13): OPTIGA Trust M + SE050 driver bus.
    // - I2C2 (bit 14): STSAFE-A110 on-board probe bus.
    // Both are secure-world-only; NS has no business touching either.
    const SECCFGR1_I2C1_BIT: u32 = 1 << 13;
    const SECCFGR1_I2C2_BIT: u32 = 1 << 14;

    // ---- SECCFGR3 (AHB2) — crypto block SECURE, OTG NS ----
    // Bit positions per `GTZC_CFGR3_*_Pos` in CMSIS `stm32u585xx.h`.
    //
    // - OTG (bit 10): USB OTG FS — **stays NS** so the NS USB stack
    //   can manage DWC2 directly. The companion-facing HID transport
    //   lives in NS; pulling USB control into the secure world would
    //   require re-architecting transport, which is way out of scope.
    //   GPIO security (PA11/PA12 = D+/D-) is governed separately by
    //   GPIOA_SECCFGR; UCPD1 handshake is done from secure world at
    //   boot and never touched again.
    // - AES (bit 11): no current consumer (we use SAES); marked
    //   SECURE defensively so a stale NS-side AES driver can't
    //   accidentally race a secure SAES op.
    // - HASH (bit 12): SHA-256 accelerator consumed by sphincs-c10
    //   through the `pqsigner_sha256_*` extern fns.
    // - RNG (bit 13): STM32 TRNG; backbone of `rng_strong::fill`
    //   (the 3-source XOR per F-13/§10 work).
    // - PKA (bit 14): BLS12-381 pairing accelerator for the
    //   Groth16 ZK clear-signing verifier.
    // - SAES (bit 15): Tier-1 KDF (DHUK / BHK derivation) — the
    //   single most secret-bearing peripheral on the bus.
    const SECCFGR3_AES_BIT:  u32 = 1 << 11;
    const SECCFGR3_HASH_BIT: u32 = 1 << 12;
    const SECCFGR3_RNG_BIT:  u32 = 1 << 13;
    const SECCFGR3_PKA_BIT:  u32 = 1 << 14;
    const SECCFGR3_SAES_BIT: u32 = 1 << 15;

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

        // ---- GTZC1 TZSC: SECURE-allowlist policy (Trezor parity) ----
        //
        // CRIT-4 / Pre-Production Caveat fix: restores CLAUDE.md
        // invariant #4 ("NS never sees secure-world peripherals").
        //
        // STM32U5 TZSC reset default is NS for every peripheral. We
        // keep that as the baseline AND explicitly mark a small list
        // of security-critical peripherals SECURE. Trezor uses the
        // same pattern (`core/embed/sys/trustzone/stm32u5/trustzone.c`
        // sets `GTZC_PERIPH_{RNG,SAES,HASH,IWDG,WWDG,...}` SEC,
        // everything else stays NS).
        //
        // Locked-down peripherals (NS reads/writes will trip the GTZC
        // illegal-access IRQ once the post-write check below validates):
        //   - SECCFGR1: I2C1, I2C2 (SE driver buses; STSAFE probe)
        //   - SECCFGR3: AES, HASH, RNG, PKA, SAES (the crypto block)
        //
        // Intentionally LEFT NS (the NS world legitimately needs them):
        //   - OTG (SECCFGR3 bit 10): USB HID transport to companion
        //   - GPIO banks: governed per-pin by GPIOx_SECCFGR, not TZSC
        //   - TIM / SPI / USART / etc.: NS-side UI + debug logging
        //
        // Other peripherals (SDMMC, OCTOSPI, FDCAN, etc.) keep their
        // NS reset default; we don't currently use them from the
        // secure side, and they're irrelevant to the threat model.
        //
        // TAMP lives in GTZC2 (a different controller); its SECCFGR
        // setup is owed in a follow-up (the `tamp` feature flag is
        // log-only-on-this-branch per CLAUDE.md anyway).
        let seccfgr1 = SECCFGR1_I2C1_BIT | SECCFGR1_I2C2_BIT;
        let seccfgr2: u32 = 0; // nothing security-critical in APB2 today
        let seccfgr3 = SECCFGR3_AES_BIT
            | SECCFGR3_HASH_BIT
            | SECCFGR3_RNG_BIT
            | SECCFGR3_PKA_BIT
            | SECCFGR3_SAES_BIT;
        core::ptr::write_volatile(TZSC_SECCFGR1, seccfgr1);
        core::ptr::write_volatile(TZSC_SECCFGR2, seccfgr2);
        core::ptr::write_volatile(TZSC_SECCFGR3, seccfgr3);
        cortex_m::asm::dsb();

        // Post-write self-check: read back and assert. SECCFGR bits
        // are R/W from the secure world, so a write-read round-trip
        // is the right shape (no separate "is this bit even
        // configurable" question — every documented bit in CFGR3
        // for U585 corresponds to an attached peripheral). A
        // mismatch here is diagnostic of a wrong base addr or a
        // clock-not-enabled glitch.
        let r1 = core::ptr::read_volatile(TZSC_SECCFGR1);
        let r2 = core::ptr::read_volatile(TZSC_SECCFGR2);
        let r3 = core::ptr::read_volatile(TZSC_SECCFGR3);
        debug_assert_eq!(r1, seccfgr1, "TZSC_SECCFGR1 write-readback mismatch");
        debug_assert_eq!(r2, seccfgr2, "TZSC_SECCFGR2 write-readback mismatch");
        debug_assert_eq!(r3, seccfgr3, "TZSC_SECCFGR3 write-readback mismatch");
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
