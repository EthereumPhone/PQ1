/// SAU and memory-protection configuration.
///
/// On QEMU mps2-an505: configures the MPC (Memory Protection Controller)
/// On real STM32U585:   configures the GTZC MPCBB (block-based SRAM protection)
///
/// SAU region layout is the same structure but with different addresses.
///
/// All MMIO is funnelled through `hw::mmio::{Reg32, RoReg32}` so the only
/// `unsafe` blocks in this file are the one-shot register-address bindings
/// and the `extern "C"` veneer-symbol address-of taken from the linker.

use crate::hw::mmio::Reg32;
use sphincs_tz_shared::{NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END};

// ---------------------------------------------------------------------------
// SAU NS-region bounds (centralized from the inline literals in `init()` so
// they can be cross-checked at compile time, 2026-06-30).
//
// These are the regions the ARMv8-M SAU marks Non-Secure on this target. END
// is INCLUSIVE here (SAU RLAR semantics).
//
// Item 4 of the 2026-06-29 coverage audit. The NS-pointer validator's
// constant-window check (proto `NS_{SRAM,FLASH}_{BASE,END}`,
// `shared::ns_ptr_validate`) is the load-bearing, host-exercised, Kani-proven
// range gate. The hardware `TT` re-classification layered on top
// (`nsc::ptr_validate::tt_range_is_ns`) is a silicon-only defense-in-depth
// second factor — its host stub returns `true` because there is NO faithful
// host SAU model (SAU Region 1, the NSC carve-out, is a link-time symbol; a
// *discriminating* host model would DIVERGE from silicon, a non-discriminating
// one is a no-op since the windows are subsets of the SAU regions). The one
// drift a host model could catch — the proto NS windows escaping OUTSIDE these
// SAU NS regions, which would let a window-"valid" NS pointer target a SECURE
// byte the real `TT` rejects — is asserted at compile time below instead,
// which is strictly better than a runtime no-op.
#[cfg(not(feature = "stm32u585"))]
const SAU_NS_FLASH_BASE: u32 = 0x0020_0000;
#[cfg(not(feature = "stm32u585"))]
const SAU_NS_FLASH_END: u32 = 0x003F_FFFF;
#[cfg(not(feature = "stm32u585"))]
const SAU_NS_SRAM_BASE: u32 = 0x2802_0000;
#[cfg(not(feature = "stm32u585"))]
const SAU_NS_SRAM_END: u32 = 0x29FF_FFFF;

#[cfg(feature = "stm32u585")]
const SAU_NS_FLASH_BASE: u32 = 0x0810_0000;
#[cfg(feature = "stm32u585")]
const SAU_NS_FLASH_END: u32 = 0x081F_FFFF;
#[cfg(feature = "stm32u585")]
const SAU_NS_SRAM_BASE: u32 = 0x2003_0000;
#[cfg(feature = "stm32u585")]
const SAU_NS_SRAM_END: u32 = 0x2003_FFFF;

// Compile-time SAU/window subset check (per-cfg — each target build evaluates
// its own consts). The proto NS-pointer-validation windows MUST sit inside the
// SAU NS regions; a drift means a window-accepted NS pointer could resolve to a
// SECURE byte on silicon (where the real `TT` would reject it). Window END is
// EXCLUSIVE (proto), SAU END is INCLUSIVE — hence `NS_*_END - 1`.
const _: () = {
    assert!(
        NS_FLASH_BASE >= SAU_NS_FLASH_BASE && NS_FLASH_END - 1 <= SAU_NS_FLASH_END,
        "proto NS_FLASH window escaped the SAU NS-flash region (ptr-validation/SAU drift)"
    );
    assert!(
        NS_SRAM_BASE >= SAU_NS_SRAM_BASE && NS_SRAM_END - 1 <= SAU_NS_SRAM_END,
        "proto NS_SRAM window escaped the SAU NS-SRAM region (ptr-validation/SAU drift)"
    );
};

// SAU register addresses (ARMv8-M standard, same on both targets).
const SAU_CTRL_ADDR: u32 = 0xE000_EDD0;
const SAU_RNR_ADDR: u32 = 0xE000_EDD8;
const SAU_RBAR_ADDR: u32 = 0xE000_EDDC;
const SAU_RLAR_ADDR: u32 = 0xE000_EDE0;

/// SAU registers used during boot. Single-threaded boot path owns them
/// exclusively.
struct SauRegs {
    ctrl: Reg32,
    rnr: Reg32,
    rbar: Reg32,
    rlar: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned ARMv8-M SAU register
// exclusively owned by the boot path (single-threaded). After this
// construction every touch is via safe `.read()` / `.write()`.
const SAU: SauRegs = unsafe {
    SauRegs {
        ctrl: Reg32::new(SAU_CTRL_ADDR),
        rnr: Reg32::new(SAU_RNR_ADDR),
        rbar: Reg32::new(SAU_RBAR_ADDR),
        rlar: Reg32::new(SAU_RLAR_ADDR),
    }
};

extern "C" {
    static __veneer_base: u32;
    static __veneer_limit: u32;
}

/// Program one SAU region.
fn configure_sau_region(region: u32, base: u32, limit: u32, nsc: bool) {
    SAU.rnr.write(region);
    SAU.rbar.write(base & 0xFFFF_FFE0);
    let nsc_bit = if nsc { 1 << 1 } else { 0 };
    SAU.rlar.write((limit & 0xFFFF_FFE0) | nsc_bit | 1);
}

// ---------------------------------------------------------------------------
// QEMU mps2-an505 (SSE-200 IoTKit with MPC)
// ---------------------------------------------------------------------------
#[cfg(not(feature = "stm32u585"))]
mod qemu {
    use crate::hw::mmio::{Reg32, RoReg32};

    const MPC0_BASE: u32 = 0x5800_7000; // SSRAM-0 (code, 4MB)
    const MPC1_BASE: u32 = 0x5800_8000; // SSRAM-1 (data, 2MB)

    const MPC_BLK_MAX: u32 = 0x10;
    const MPC_BLK_IDX: u32 = 0x18;
    const MPC_BLK_LUT: u32 = 0x1C;

    /// Per-MPC instance register handles.
    struct MpcRegs {
        blk_max: RoReg32,
        blk_idx: Reg32,
        blk_lut: Reg32,
    }

    // SAFETY: each MPC block is a real, 4-byte-aligned MMIO peripheral on
    // the QEMU mps2-an505 SSE-200 platform. Boot path owns them exclusively.
    const MPC0: MpcRegs = unsafe {
        MpcRegs {
            blk_max: RoReg32::new(MPC0_BASE + MPC_BLK_MAX),
            blk_idx: Reg32::new(MPC0_BASE + MPC_BLK_IDX),
            blk_lut: Reg32::new(MPC0_BASE + MPC_BLK_LUT),
        }
    };
    const MPC1: MpcRegs = unsafe {
        MpcRegs {
            blk_max: RoReg32::new(MPC1_BASE + MPC_BLK_MAX),
            blk_idx: Reg32::new(MPC1_BASE + MPC_BLK_IDX),
            blk_lut: Reg32::new(MPC1_BASE + MPC_BLK_LUT),
        }
    };

    pub fn configure_mpc() {
        // MPC0: SSRAM-0 — first 2MB secure (code), rest NS (NS code + NSC veneers)
        configure_mpc_partial_ns(&MPC0, 64);
        // MPC1: SSRAM-1 — first 128KB secure (stack), rest NS
        configure_mpc_partial_ns(&MPC1, 4);
    }

    fn configure_mpc_partial_ns(mpc: &MpcRegs, ns_start_lut_idx: u32) {
        let blk_max = mpc.blk_max.read();
        for idx in 0..=blk_max {
            mpc.blk_idx.write(idx);
            let val = if idx >= ns_start_lut_idx { 0xFFFF_FFFF } else { 0 };
            mpc.blk_lut.write(val);
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

    use crate::hw::mmio::Reg32;

    // RCC AHB1ENR — enable GTZC1 clock (RCC is on AHB3 at 0x56020C00)
    const RCC_AHB1ENR_ADDR: u32 = 0x5602_0C00 + 0x88;

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
    // misdiagnosis. GTZC2 on STM32U585 governs the SmartRun-domain
    // peripherals (SPI3, LPUART1, I2C3, LPTIM1/3/4, OPAMP, COMP, ADC4,
    // VREFBUF, DAC1, ADF1 — SVD `GTZC2_TZSC_SECCFGR1`). TAMP and RTC are in
    // neither TZSC; they have their own `*_SECCFGR`.
    // The AHB2 crypto block + USB OTG FS all live in GTZC1's SECCFGR3.
    //
    // Base addr: `GTZC_TZSC1_BASE_S = 0x5003_2400` (= PERIPH_BASE_S
    // 0x5000_0000 + AHB1PERIPH offset 0x0002_0000 + TZSC1 offset
    // 0x0001_2400).
    const TZSC_BASE: u32 = 0x5003_2400;

    /// Bundled GTZC handles. One-time bound below.
    struct GtzcRegs {
        rcc_ahb1enr: Reg32,
        mpcbb1_cr: Reg32,
        mpcbb2_cr: Reg32,
        tzsc_seccfgr1: Reg32,
        tzsc_seccfgr2: Reg32,
        tzsc_seccfgr3: Reg32,
    }

    // SAFETY: each address is a 4-byte-aligned STM32U585 MMIO register
    // owned exclusively by the boot path. The MPCBB1/MPCBB2 SECCFGR banks
    // are accessed by per-index computed addresses below — see
    // `mpcbb_seccfgr` helper for the one-shot `Reg32::new` covering those.
    const GTZC: GtzcRegs = unsafe {
        GtzcRegs {
            rcc_ahb1enr: Reg32::new(RCC_AHB1ENR_ADDR),
            mpcbb1_cr: Reg32::new(MPCBB1_BASE + MPCBB_CR),
            mpcbb2_cr: Reg32::new(MPCBB2_BASE + MPCBB_CR),
            tzsc_seccfgr1: Reg32::new(TZSC_BASE + 0x10),
            tzsc_seccfgr2: Reg32::new(TZSC_BASE + 0x14),
            tzsc_seccfgr3: Reg32::new(TZSC_BASE + 0x18),
        }
    };

    /// Build an MPCBB SECCFGR-bank handle on the fly. The SECCFGR0..N
    /// registers form a contiguous bank at `base + MPCBB_SECCFGR0 + i*4`;
    /// constructing one Reg32 per index keeps the unsafe surface narrow.
    fn mpcbb_seccfgr(base: u32, i: u32) -> Reg32 {
        // SAFETY: `base` is one of MPCBB1_BASE / MPCBB2_BASE — both real
        // MMIO peripherals. `i` is bounded by the caller (24 / 8) so the
        // computed address stays within the 32-register SECCFGR bank.
        unsafe { Reg32::new(base + MPCBB_SECCFGR0 + i * 4) }
    }

    // ---- SECCFGR1 (APB1) — IWDG + I2C1 + I2C2 SECURE ----
    // Bit positions per `GTZC_CFGR1_*_Pos` in CMSIS `stm32u585xx.h`.
    //
    // - IWDG (bit 7): Secure-owned watchdog. Selected only with the `iwdg`
    //   feature, which is mandatory for production and for any production
    //   forced-blind build. Runtime register access uses only 0x5000_3000.
    // - I2C1 (bit 13): OPTIGA Trust M (+ SE050 too, on `iota2`).
    // - I2C2 (bit 14): STSAFE-A110 on-board probe bus (`iota2`); the
    //   AW99703 backlight + AW21036 RGB LED drivers (`pq1`).
    // - I2C4 (bit 16): SE050's dedicated bus — `pq1` only.
    // All selected entries are secure-world-only; NS has no writer.
    #[cfg(feature = "iwdg")]
    const SECCFGR1_IWDG_BIT: u32 = 1 << 7;
    const SECCFGR1_I2C1_BIT: u32 = 1 << 13;
    const SECCFGR1_I2C2_BIT: u32 = 1 << 14;
    // I2C4 (bit 16, `GTZC_CFGR1_I2C4_Pos`): the SE050's OWN bus on `pq1`,
    // which splits the two secure elements across I2C1 and I2C4 instead of
    // sharing one. Unused on `iota2`, where both chips are on I2C1.
    //
    // This bit is the sharpest invariant-#3/#4 hazard in the whole board
    // port, because leaving it clear has **no functional symptom at all**:
    // the SE050 works perfectly from the secure world either way. The only
    // thing that changes is whether the non-secure world can also drive the
    // bus. `configure_gtzc` writes SECCFGR1 absolutely, so a missing bit is
    // actively driven to 0, not merely left at reset.
    #[cfg(feature = "board-pq1")]
    const SECCFGR1_I2C4_BIT: u32 = 1 << 16;

    // UCPD1 (bit 19, `GTZC_CFGR1_UCPD1_Pos` — CMSIS stm32u585xx.h:20063).
    //
    // Secured on BOTH boards, for two different reasons.
    //
    // On `iota2` UCPD1 is driven from the secure world at boot (`hw::usb_hw::
    // init_ucpd`, Type-C CC detection) and never touched again; NS has no
    // business there. That file used to *assert* this was already the case —
    // "APB1 peripherals are secure with TZEN=1; writes via NS alias are
    // silently ignored" — which is false. TZEN=1 secures GPIO by default;
    // APB peripheral attribution is GTZC's, and bit 19 was never set. The
    // comment claimed a guarantee this register did not deliver.
    //
    // On `pq1` it matters more, and in a way no GPIO gate can see. That board
    // routes NO CC line to the MCU, so `init_ucpd` is compiled out — but the
    // pads UCPD1 owns are still physically wired to something: PA15 is
    // `SE_RST`, the OPTIGA's reset, and PB15 is `LCM_EN`, the trusted
    // display's backlight. `board::ns_forbidden_mask` keeps those two pins out
    // of the USB non-secure mask, but that guards `GPIOx_SECCFGR` only. An
    // NS-reachable UCPD1 is a second, independent handle on the same two pads
    // via the CC analog front-end and the dead-battery Rd, underneath the
    // layer that assert protects. ST's HAL also documents `PWR_UCPDR` as
    // secure only when UCPD1 is secure in GTZC, so this bit gates the
    // dead-battery control too.
    //
    // Whether that analog path can pull a secure GPIO output hard enough to
    // actually reset the OPTIGA is NOT established — it needs RM0456 plus a
    // scope on pq1 silicon. This closes the attribution hole regardless,
    // because the cost is one bit and NS has no legitimate use for UCPD1 on
    // either board (`grep -r UCPD nonsecure/` is empty).
    const SECCFGR1_UCPD1_BIT: u32 = 1 << 19;

    // TIM2 (bit 0, `GTZC_CFGR1_TIM2_Pos` — CMSIS stm32u585xx.h:20025).
    //
    // TIM2 CH1 drives the `consumption-mask` PWM, which `nsc/mod.rs` makes
    // MANDATORY for every production hardware build: without it the
    // SPHINCS+C10 keygen/sign window runs with an undiluted power signature
    // and a bench CPA/DPA attacker reads the WOTS/FORS secrets out of it.
    //
    // A countermeasure the non-secure world can switch off is not a
    // countermeasure. With TIM2 unattributed, NS reaches the timer through its
    // own peripheral alias and clears `TIM2_CR1.CEN` — the PWM stops, the mask
    // goes flat, and NOTHING in the secure world notices, because the secure
    // side only ever writes CCR1 and never reads back that the counter is
    // still running. This repo's own audit recorded that trace in
    // `docs/security/audits/tz-tamper-debug-20260611-141459.md:142,154`; it
    // predates the board port and was surfaced again by the 2026-08-31 review.
    //
    // NS has no legitimate use for TIM2 (`grep -rn TIM2 nonsecure/` is empty),
    // so securing it costs nothing and removes the off-switch. As with UCPD1,
    // final exploitability was NOT reproduced on silicon here — the audit
    // above argues it and this closes it either way.
    //
    // TIM3 (bit 1) is secured alongside it. When this comment was written TIM3
    // was unused and explicitly NOT secured, with the note that "if the mask
    // ever moves to TIM3, it must join this image in the same commit, or pq1
    // ships the exact hole this bit closes". It has: pq1 runs the mask on
    // TIM3_CH1/PA6 because every TIM2_CH1 pin is taken there (PA0 LEFT KEY,
    // PA5 the LCD's SCK, PA15 SE_RST).
    //
    // BOTH are secured on BOTH boards rather than one per board. The mask
    // timer differs by board, and a per-board bit would put the whole
    // security property one editing mistake away from silently vanishing on
    // the board whose bit was forgotten — which is exactly what the note above
    // was worried about. Neither timer has a non-secure consumer on either
    // board (`grep -rn "TIM[23]" nonsecure/` is empty), so securing both costs
    // one bit and removes the coupling.
    const SECCFGR1_TIM2_BIT: u32 = crate::board::TZSC_SECCFGR1_TIM2SEC;
    const SECCFGR1_TIM3_BIT: u32 = crate::board::TZSC_SECCFGR1_TIM3SEC;

    // ---- SECCFGR2 (APB2) — SPI1 (trusted display) SECURE (finding F1) ----
    // Bit position per `GTZC_CFGR2_SPI1_Pos` in CMSIS `stm32u585xx.h` (= 1).
    //
    // SPI1 (bit 1): the NV3007 LCD bus under `ui-lcd` (→ `spi1-arduino`) — the
    // trusted-confirmation display, the clear-signing trust root. It is driven
    // EXCLUSIVELY from the secure world (`hw::spi_hw`, `hw::lcd_nv3007`); NS
    // never touches it. Leaving it NS lets a hostile NS image reconfigure,
    // disable, or drive the display used to confirm what is signed — a direct
    // invariant #4 break. Marked only when the SPI1 LCD backend is compiled in.
    //
    // NOTE (F1 is PARTIAL — silicon-validation + two residuals still owed, see
    // the finding): this closes the SPI1 *peripheral* attribution, but the panel
    // GPIOE pins (PE7/12/13/14/15) stay NS (NS could drive the lines directly
    // via GPIOE, bypassing SPI1) and the SPI1 clock-enable is RCC-governed (F3),
    // so full "NS cannot touch the trusted display" needs those closed too.
    #[cfg(feature = "spi1-arduino")]
    const SECCFGR2_SPI1_BIT: u32 = 1 << 1;

    // ---- SECCFGR3 (AHB2) — crypto block SECURE, OTG NS ----
    // Bit positions per `GTZC_CFGR3_*_Pos` in CMSIS `stm32u585xx.h`.
    //
    // - OTG (bit 10): USB OTG FS — **stays NS** so the NS USB stack
    //   can manage DWC2 directly. The companion-facing HID transport
    //   lives in NS; pulling USB control into the secure world would
    //   require re-architecting transport, which is way out of scope.
    //   GPIO security (PA11/PA12 = D+/D-) is governed separately by
    //   GPIOA_SECCFGR. The UCPD1 handshake is done from the secure world at
    //   boot and never touched again — on iota2 only, since pq1 routes no CC
    //   line to the MCU and compiles that path out entirely. UCPD1 itself is
    //   Secure on both boards (bit 19, above); it is only OTG that stays NS.
    // - AES (bit 11): no current consumer (we use SAES); marked
    //   SECURE defensively so a stale NS-side AES driver can't
    //   accidentally race a secure SAES op.
    // - HASH (bit 12): SHA-256 accelerator consumed by sphincs-c10
    //   through the `pqsigner_sha256_*` extern fns.
    // - RNG (bit 13): STM32 TRNG; backbone of `rng_strong::fill`
    //   (the 3-source XOR per F-13/§10 work).
    // - PKA (bit 14): currently unused, but still marked SECURE
    //   defensively so a stale NS driver cannot poke the peripheral.
    // - SAES (bit 15): Tier-1 KDF (DHUK / BHK derivation) — the
    //   single most secret-bearing peripheral on the bus.
    // CRS (SECCFGR1 bit 15, `GTZC_CFGR1_CRS_Pos`): the clock recovery system
    // that trims HSI48 to the host's USB SOF. HSI48 is also the TRNG kernel
    // clock. The secure world enables and owns it (`hw::usb_hw`); NS has no
    // CRS code (`grep -rn CRS nonsecure/src` finds only the gtzc probe).
    const SECCFGR1_CRS_BIT: u32 = 1 << 15;

    const SECCFGR3_AES_BIT:  u32 = 1 << 11;
    const SECCFGR3_HASH_BIT: u32 = 1 << 12;
    const SECCFGR3_RNG_BIT:  u32 = 1 << 13;
    const SECCFGR3_PKA_BIT:  u32 = 1 << 14;
    const SECCFGR3_SAES_BIT: u32 = 1 << 15;
    // The three TZSC-attributable bus MASTERS on U575/585 (RM0456 Table 1,
    // p.129; bit positions from the STM32U585 SVD — the RM text swaps the two
    // SDMMC labels on p.210/p.218). A master made secure-only in TZSC "issues
    // secure transactions" (RM0456 p.158), so only secure code can program it,
    // and its RCC enable/reset bits become secure with it (§11.5.1). Nothing
    // that ships uses them (no SDMMC code; the only DMA2D code is the dev-only
    // `ui-px-dma2d-bench`, fenced out of production), but
    // left NS each one is a DMA engine the non-secure world could point at the
    // OTP and UID, which no flash or MPC option protects (RM0456 Table 71,
    // p.327: OTP is NS-readable by design). #982.
    const SECCFGR3_DMA2D_BIT: u32 = 1 << 5;
    const SECCFGR3_SDMMC1_BIT: u32 = 1 << 17;
    const SECCFGR3_SDMMC2_BIT: u32 = 1 << 18;

    /// Unconditional post-write readback verifier (finding F6).
    ///
    /// Unlike `debug_assert_eq!` — which compiles to nothing under the shipping
    /// `--release` profile (Cargo.toml sets `overflow-checks` but NOT
    /// `debug-assertions`) — this runs in EVERY build, so a skipped or
    /// single-fault-faulted security-config / lock write is caught before NS
    /// boot rather than reaching it undetected. On mismatch it parks the CPU
    /// (fail closed, matching the `hw::hash::init_clock` boot-KAT idiom); this
    /// executes pre-NS-boot, so a halt exposes no secret and is re-flashable
    /// (not a permanent brick). `#[inline(never)]` keeps it a distinct call
    /// site. NOTE: the fail-closed HALT path has not itself been silicon-
    /// exercised — a bench boot (`make play-hw-display` / `make e2e-hw`) must
    /// confirm a correct config does NOT false-trip it before shipping.
    #[inline(never)]
    fn verify_or_halt(actual: u32, expected: u32) {
        if actual != expected {
            loop {
                cortex_m::asm::wfe();
            }
        }
    }

    pub fn configure_gtzc() {
        // Enable GTZC1 clock
        GTZC.rcc_ahb1enr.set_bits(1 << 24);
        cortex_m::asm::dsb();

        // MPCBB1 (SRAM1, 192 KB): all secure (default after reset with TZEN=1,
        // but set explicitly for clarity).
        // 192 KB / 256 bytes = 768 blocks, 768 / 32 = 24 config registers.
        GTZC.mpcbb1_cr.write(0);
        for i in 0..24u32 {
            mpcbb_seccfgr(MPCBB1_BASE, i).write(0xFFFF_FFFF); // all blocks secure
        }

        // MPCBB2 (SRAM2, 64 KB): all non-secure.
        // 64 KB / 256 bytes = 256 blocks, 256 / 32 = 8 config registers.
        GTZC.mpcbb2_cr.write(0);
        for i in 0..8u32 {
            mpcbb_seccfgr(MPCBB2_BASE, i).write(0x0000_0000); // all blocks non-secure
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
        //   - SECCFGR1: IWDG when selected; I2C1, I2C2 (SE buses)
        //   - SECCFGR2: SPI1 (the trusted-display LCD bus, under ui-lcd — F1)
        //   - SECCFGR3: AES, HASH, RNG, PKA, SAES (the crypto block)
        //
        // Intentionally LEFT NS (the NS world legitimately needs them):
        //   - OTG (SECCFGR3 bit 10): USB HID transport to companion
        //   - GPIO banks: governed per-pin by GPIOx_SECCFGR, not TZSC
        //   - USART / etc.: NS-side UI + debug logging. NOT the timers:
        //     TIM2 and TIM3 are SECURED above (they carry the consumption
        //     mask, which production mandates), so this line no longer
        //     covers them. (SPI1 is now
        //     secured above; SPI2 stays NS on the non-LCD Tropic bench build)
        //
        // Bus MASTERS are secured whether or not anything uses them (#982):
        //   - SECCFGR3: DMA2D, SDMMC1, SDMMC2 (the TZSC-attributable masters)
        //   - GPDMA1 / LPDMA1 are not TZSC peripherals; every channel is made
        //     secure + privileged and locked by `secure_dma_masters()` below.
        // Other peripherals (OCTOSPI, FDCAN, etc.) keep their NS reset
        // default; they are slaves only, we don't use them from the secure
        // side, and they're irrelevant to the threat model.
        //
        // RCC, PWR, TAMP, RTC and EXTI are NOT TZSC peripherals: each
        // carries its own `*_SECCFGR`. They are secured separately, by
        // `secure_system_controllers()` below (DVT1 row 3.5).
        // ---- C3: the register image is FEATURE-CONDITIONAL — pin it ----
        //
        // Pinned so a feature-combo change to the TZSC image is a build failure
        // rather than a silent difference between what we test and what we ship.
        // This is the register-image half of roadmap §P1.9 ("exact production
        // register images and feature combinations"), and it composes with the
        // proto-NS-window subset assert at the top of this file: that one pins
        // the SAU intervals, this one pins the peripheral-security image.
        //
        // WHY IT MATTERS HERE, CONCRETELY: `ui-lcd` implies `spi1-arduino`
        // (secure/Cargo.toml), so the SHIPPING image secures SPI1 — the
        // trusted-display bus. `make gtzc-enforcement-hw` builds with
        // `ui-semihosting`, i.e. WITHOUT `spi1-arduino`, so its 7/7 RAZ-fault
        // receipt is taken against `seccfgr2 == 0`: the one bit that keeps NS
        // off the trusted display is NOT covered by the enforcement test that
        // is cited as evidence for it. Recorded as HW-ASSUME-CMSE-SAU's note
        // and work-todo C3; closing it needs the test rebuilt on the shipping
        // combo, which these pins make reviewable in the meantime.
        // The image is two orthogonal choices — IWDG on/off, and which
        // board — so it is built from two independently-cfg'd terms rather
        // than four hand-written totals. The `assert!`s below still pin the
        // FULL expected value for each of the four combinations, by exact
        // equality: a subset test would let a stray extra bit through, and
        // the whole point of this pin is that every secured peripheral was
        // deliberately chosen.
        #[cfg(feature = "iwdg")]
        const SECCFGR1_IWDG_IMAGE: u32 = SECCFGR1_IWDG_BIT;
        #[cfg(not(feature = "iwdg"))]
        const SECCFGR1_IWDG_IMAGE: u32 = 0;

        #[cfg(feature = "board-pq1")]
        const SECCFGR1_BOARD_IMAGE: u32 = SECCFGR1_I2C4_BIT;
        #[cfg(not(feature = "board-pq1"))]
        const SECCFGR1_BOARD_IMAGE: u32 = 0;

        const SECCFGR1_IMAGE: u32 = SECCFGR1_IWDG_IMAGE
            | SECCFGR1_I2C1_BIT
            | SECCFGR1_I2C2_BIT
            | SECCFGR1_BOARD_IMAGE
            | SECCFGR1_UCPD1_BIT
            | SECCFGR1_CRS_BIT
            | SECCFGR1_TIM2_BIT
            | SECCFGR1_TIM3_BIT;

        #[cfg(all(feature = "iwdg", not(feature = "board-pq1")))]
        const _: () = assert!(
            SECCFGR1_IMAGE == (1 << 0) | (1 << 1) | (1 << 7) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 19),
            "TZSC_SECCFGR1 IWDG image drifted — IWDG must be Secure alongside the SE buses. \
             Source closure is not #79 silicon denial evidence."
        );
        #[cfg(all(not(feature = "iwdg"), not(feature = "board-pq1")))]
        const _: () = assert!(
            SECCFGR1_IMAGE == (1 << 0) | (1 << 1) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 19),
            "TZSC_SECCFGR1 image drifted — I2C1+I2C2 are the SE buses (invariant #3). \
             Update the pin ONLY with a matching gtzc-enforcement-hw receipt."
        );
        #[cfg(all(feature = "iwdg", feature = "board-pq1"))]
        const _: () = assert!(
            SECCFGR1_IMAGE == (1 << 0) | (1 << 1) | (1 << 7) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 19),
            "TZSC_SECCFGR1 pq1+IWDG image drifted — on pq1 the SE050 has its OWN bus (I2C4, \
             bit 16) and it MUST be Secure: a clear bit hands the non-secure world the SE050 \
             bus with no functional symptom whatsoever. Update ONLY with a matching \
             gtzc-enforcement-hw receipt taken on pq1 silicon."
        );
        #[cfg(all(not(feature = "iwdg"), feature = "board-pq1"))]
        const _: () = assert!(
            SECCFGR1_IMAGE == (1 << 0) | (1 << 1) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 19),
            "TZSC_SECCFGR1 pq1 image drifted — on pq1 the SE050 has its OWN bus (I2C4, bit 16) \
             and it MUST be Secure: a clear bit hands the non-secure world the SE050 bus with \
             no functional symptom whatsoever. Update ONLY with a matching gtzc-enforcement-hw \
             receipt taken on pq1 silicon."
        );
        // SECCFGR2 is the one that differs between the tested and shipped
        // builds. Both arms are pinned so neither can move unnoticed.
        #[cfg(feature = "spi1-arduino")]
        const _: () = assert!(
            SECCFGR2_SPI1_BIT == 1 << 1,
            "TZSC_SECCFGR2 shipping image drifted (SPI1 = the trusted-display bus)"
        );
        const SECCFGR3_IMAGE: u32 = SECCFGR3_DMA2D_BIT
            | SECCFGR3_AES_BIT
            | SECCFGR3_HASH_BIT
            | SECCFGR3_RNG_BIT
            | SECCFGR3_PKA_BIT
            | SECCFGR3_SAES_BIT
            | SECCFGR3_SDMMC1_BIT
            | SECCFGR3_SDMMC2_BIT;
        const _: () = assert!(
            SECCFGR3_IMAGE
                == (1 << 5) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 17) | (1 << 18),
            "TZSC_SECCFGR3 image drifted — DMA2D/SDMMC1/SDMMC2 (bus masters, #982) and \
             AES/HASH/RNG/PKA/SAES secure, OTG (bit 10) stays NS. AES..SAES are 5 of the 7 \
             peripherals gtzc-enforcement-hw covers."
        );

        let seccfgr1 = SECCFGR1_IMAGE;
        // SPI1 (trusted-display bus) is the only APB2 peripheral we secure
        // (F1), and only in the `spi1-arduino` LCD build.
        #[cfg(feature = "spi1-arduino")]
        let seccfgr2: u32 = SECCFGR2_SPI1_BIT;
        #[cfg(not(feature = "spi1-arduino"))]
        let seccfgr2: u32 = 0; // no APB2 peripheral secured on non-LCD builds
        let seccfgr3 = SECCFGR3_IMAGE;
        GTZC.tzsc_seccfgr1.write(seccfgr1);
        GTZC.tzsc_seccfgr2.write(seccfgr2);
        GTZC.tzsc_seccfgr3.write(seccfgr3);
        cortex_m::asm::dsb();

        // Post-write self-check: read back and verify UNCONDITIONALLY (F6).
        // SECCFGR bits are R/W from the secure world, so a write-read round-trip
        // is the right shape (every documented bit corresponds to an attached
        // peripheral). This MUST run in release too — the previous
        // `debug_assert_eq!` vanished under `--release`, so a skipped/faulted
        // config write reached NS boot undetected. `verify_or_halt` fails closed.
        let r1 = GTZC.tzsc_seccfgr1.read();
        let r2 = GTZC.tzsc_seccfgr2.read();
        let r3 = GTZC.tzsc_seccfgr3.read();
        verify_or_halt(r1, seccfgr1); // TZSC_SECCFGR1
        verify_or_halt(r2, seccfgr2); // TZSC_SECCFGR2
        verify_or_halt(r3, seccfgr3); // TZSC_SECCFGR3

        // Test-only: enable AES/PKA/SAES clocks so the gtzc-test
        // validation driver can prove GTZC enforcement applies to
        // all 7 protected peripherals. Without their clocks, NS
        // reads to AES/PKA/SAES RAZ via the bus-default-no-responder
        // path and TZIC never fires — indistinguishable from a
        // successful block. HASH and RNG are already clocked by
        // boot init (HASH self-test + TRNG init).
        //
        // Compiled out of production builds.
        #[cfg(feature = "e2e-test")]
        crate::hw::tzic::enable_test_target_clocks();

        // Arm GTZC1 TZIC with the same masks. Without this an
        // illegal NS access is silently RAZ/WI'd — the AHB bridge
        // gates the access but no interrupt fires and the secure
        // world never learns the violation happened. TZIC turns
        // that into NVIC IRQ 8, dispatched in
        // `main::DefaultHandler` to `hw::tzic::on_violation()`.
        //
        // IER4 = GPDMA1IE only (#982; was 0 under sweep F8 / TZGW-4).
        // The U585 TZSC bank stops at
        // SECCFGR3 — there is NO SECCFGR4 (CMSIS/PAC
        // `GTZC1_TZSC_TypeDef`: SECCFGR1..3 at 0x10..0x18; 0x1C
        // reserved). TZIC IER4 nonetheless exists and covers the
        // AHB3/memory group: GPDMA1, FLASH(_REG), OTFDEC1/2, TZSC1,
        // TZIC1, OCTOSPI/FSMC memories, BKPSRAM, SRAM1-3 + MPCBB1-3
        // register blocks. Those targets are not TZSC-attributable —
        // they are hardwired secure or self-governed (FLASH via its
        // SECWM watermark, GPDMA per-channel SECCFGR, TZSC/TZIC
        // secure-privileged-only, SRAMs via MPCBB) — so with IER4 = 0
        // an NS probe of them is still blocked by hardware but raises
        // NO violation event: the block never reaches
        // `violation_count`/`LAST_SR`. Accepted instrumentation gap,
        // not an enforcement hole (no AHB3-group peripheral is under
        // our SECCFGR image); if AHB3 forensics become a requirement,
        // set the matching IER4 bits — no TZSC write is possible or
        // needed for that.
        //
        // GPDMA1 is the exception, since #982: `secure_dma_masters()` makes
        // every channel secure, so ANY non-secure access to a channel
        // register is now an attempt to program a DMA engine the non-secure
        // world does not own (NS reads of SECCFGR/PRIVCFGR/RCFGLOCKR stay
        // legal and raise nothing — RM0456 §17.4.14, p.727). The stock NS
        // image has no DMA code at all, so the bit cannot false-fire; under
        // `tzic-wipe` such a probe escalates like a probe of the SE buses.
        // LPDMA1's event is in GTZC2_TZIC (IER2 bit 5), which this branch
        // does not configure; LPDMA1 reaches only SRAM4 and AHB3 anyway.
        crate::hw::tzic::configure(seccfgr1, seccfgr2, seccfgr3, TZIC_IER4_GPDMA1IE);
    }

    /// GTZC1_TZIC_IER4 bit 0, `GPDMA1IE` (STM32U585 SVD; RM0456 p.235).
    const TZIC_IER4_GPDMA1IE: u32 = 1 << 0;

    // ---- System controllers: RCC / PWR / TAMP / RTC / EXTI (DVT1 row 3.5) ----
    //
    // None of these is a TZSC peripheral; each has its own security register,
    // and all five reset to 0 = every function non-secure. Until 2026-10-15
    // nothing wrote them, and the DVT1 run showed non-secure code writing the
    // TRNG oscillator enable, an APB prescaler, the PVD, the backup-domain
    // write enable, the tamper enables and TAMP_BKP0R (the BHK register). By
    // RM0456 the same zeros also left VOS, PLL1 and SYSCLK (software
    // under-volt / over-clock fault injection) and RCC_BDCR.BDRST (backup
    // domain reset) to the non-secure world.
    //
    // The non-secure image needs none of it: `nonsecure/src/usb/mod.rs`
    // `enable()` is empty because `hw::usb_hw::init` clocks OTG, sets
    // VDDUSB and muxes the pins from here; OTG's own clock-enable bit stays
    // NS-writable because OTG is NS in TZSC. Every field is therefore secured.
    // Addresses and field layouts: STM32U585 SVD (CubeProgrammer) / RM0456.
    const RCC_S: u32 = 0x5602_0C00;
    const PWR_S: u32 = 0x5602_0800;
    const TAMP_S: u32 = 0x5600_7C00;
    const RTC_S: u32 = 0x5600_7800;
    const EXTI_S: u32 = 0x5602_2000;

    const RCC_AHB3ENR_PWREN: u32 = 1 << 2; // RCC_AHB3ENR @ +0x94
    const RCC_APB3ENR_RTCAPBEN: u32 = 1 << 21; // RCC_APB3ENR @ +0xA8
    const PWR_DBPR_DBP: u32 = 1 << 0; // PWR_DBPR @ +0x28

    /// RCC_SECCFGR @ +0x110: HSI, HSE, MSI, LSI, LSE, SYSCLK (also guards
    /// PWR_VOSR.VOS), PRESC, PLL1, PLL2, PLL3, ICLK, HSI48, RMVF = bits 0..12.
    const RCC_SECCFGR_IMAGE: u32 = 0x1FFF;
    /// PWR_SECCFGR @ +0x30: WUP1..8 (bits 0..7), LPM (12), VDM (13: PVD,
    /// PVM, VDDUSB), VB (14: backup domain, DBPR), APC (15).
    const PWR_SECCFGR_IMAGE: u32 = 0xF0FF;
    /// RTC_SECCFGR @ +0x20: SEC, INITSEC, CALSEC, TSSEC, WUTSEC, ALRBSEC,
    /// ALRASEC. There is no RTC driver; securing it closes RCC_BDCR to NS.
    const RTC_SECCFGR_IMAGE: u32 = (1 << 15) | (1 << 14) | (1 << 13) | 0xF;
    /// TAMP_SECCFGR @ +0x20: TAMPSEC (31), CNT1SEC (15), and
    /// BKPRWSEC = BKPWSEC = 32 (bits 7:0, 23:16), so all 32 backup registers
    /// are secure read/write (BKP0..7 hold the BHK on `bhk` builds).
    /// BHKLOCK (bit 30) is NOT part of the image: it is `bhk.rs`'s, sticky,
    /// and survives a system reset, so it is masked out of the readback.
    const TAMP_SECCFGR_IMAGE: u32 = (1 << 31) | (1 << 15) | (32 << 16) | 32;
    const TAMP_SECCFGR_BHKLOCK: u32 = 1 << 30;
    /// EXTI_SECCFGR1 @ +0x14: every event line. NS has no EXTI user; with a
    /// line secure, its EXTICR port select is secure too, so NS can no longer
    /// route the secure button pins to an interrupt of its own. The SVD lists
    /// SEC0..SEC25, but the U585 implements lines 0..23 only: on DVT1 a write
    /// of 0x03FF_FFFF reads back 0x00FF_FFFF (2026-10-15), so the exact
    /// readback below would halt every boot with the SVD value.
    const EXTI_SECCFGR1_ALL: u32 = 0x00FF_FFFF;
    /// EXTI_LOCKR @ +0x70: LOCK freezes EXTI_SECCFGR/PRIVCFGR until reset.
    const EXTI_LOCKR_LOCK: u32 = 1 << 0;

    /// Secure RCC, PWR, TAMP, RTC and EXTI (DVT1 row 3.5). Called from
    /// [`super::init`] after the TZSC image and before the lock.
    ///
    /// Every write is read back through the unconditional, fail-closed
    /// [`verify_or_halt`]. Order matters: the TAMP and RTC registers sit in
    /// the backup domain, so their APB clock (RTCAPBEN) and the backup write
    /// enable (DBP) must be on first, or the SECCFGR writes are silently
    /// dropped and the readback halts every boot. DBP stays set (as
    /// `hw::bhk` and `hw::tamp` leave it); with VBSEC it is secure-only.
    pub fn secure_system_controllers() {
        // SAFETY: each address is a 4-byte-aligned security/config register
        // on the secure alias, owned by the single-threaded boot path.
        let rcc_ahb3enr = unsafe { Reg32::new(RCC_S + 0x94) };
        let rcc_apb3enr = unsafe { Reg32::new(RCC_S + 0xA8) };
        let rcc_seccfgr = unsafe { Reg32::new(RCC_S + 0x110) };
        let pwr_dbpr = unsafe { Reg32::new(PWR_S + 0x28) };
        let pwr_seccfgr = unsafe { Reg32::new(PWR_S + 0x30) };
        let rtc_seccfgr = unsafe { Reg32::new(RTC_S + 0x20) };
        let tamp_seccfgr = unsafe { Reg32::new(TAMP_S + 0x20) };
        let exti_seccfgr1 = unsafe { Reg32::new(EXTI_S + 0x14) };
        let exti_lockr = unsafe { Reg32::new(EXTI_S + 0x70) };

        // Prerequisites: PWR bus clock (already on from `rcc::init`, set
        // again so this function stands alone), RTC/TAMP APB clock, and the
        // backup-domain write enable.
        rcc_ahb3enr.set_bits(RCC_AHB3ENR_PWREN);
        rcc_apb3enr.set_bits(RCC_APB3ENR_RTCAPBEN);
        cortex_m::asm::dsb();
        pwr_dbpr.set_bits(PWR_DBPR_DBP);
        cortex_m::asm::dsb();

        rcc_seccfgr.write(RCC_SECCFGR_IMAGE);
        pwr_seccfgr.write(PWR_SECCFGR_IMAGE);
        rtc_seccfgr.write(RTC_SECCFGR_IMAGE);
        // Absolute image, carrying BHKLOCK through: the register survives a
        // system reset, so OR-ing would keep any stale offset field.
        tamp_seccfgr.modify(|v| (v & TAMP_SECCFGR_BHKLOCK) | TAMP_SECCFGR_IMAGE);
        // `set_bits`, not `write`: `hw::lcd_te` may already have claimed its
        // TE line on builds whose `ui::init` runs before SAU.
        exti_seccfgr1.set_bits(EXTI_SECCFGR1_ALL);
        cortex_m::asm::dsb();

        verify_or_halt(rcc_seccfgr.read(), RCC_SECCFGR_IMAGE);
        verify_or_halt(pwr_seccfgr.read(), PWR_SECCFGR_IMAGE);
        verify_or_halt(rtc_seccfgr.read(), RTC_SECCFGR_IMAGE);
        verify_or_halt(tamp_seccfgr.read() & !TAMP_SECCFGR_BHKLOCK, TAMP_SECCFGR_IMAGE);
        verify_or_halt(exti_seccfgr1.read(), EXTI_SECCFGR1_ALL);

        // Freeze the EXTI security attribution only after it reads back.
        exti_lockr.set_bits(EXTI_LOCKR_LOCK);
        cortex_m::asm::dsb();
        verify_or_halt(exti_lockr.read() & EXTI_LOCKR_LOCK, EXTI_LOCKR_LOCK);
    }

    // ---- GPDMA1 / LPDMA1: every channel secure, privileged, locked (#982) ----
    //
    // The SAU filters only the CPU. On EVT-3D21 (2026-10-18, DVT row 3.9) a
    // privileged non-secure GPDMA1 channel read the UID (0x0BFA_0700), the OTP
    // (0x0BFA_0000, which holds the factory transport master at 0x0BFA_0080)
    // and the system ROM verbatim. Nothing in the flash interface or the MPCs
    // can firewall that area (RM0456 Table 71, p.327: OTP reads are allowed
    // to secure and non-secure alike), so the fix is to leave the non-secure
    // world no DMA engine to point at it.
    //
    // RM0456 §17.8.1-17.8.3 / §18.8.1-18.8.3 (p.734-736, p.803-805):
    //   SECCFGR  @ +0x00  SECx: write secure+privileged only, EN=0 only.
    //   PRIVCFGR @ +0x04  PRIVx: once SECx=1, writable by secure only.
    //   RCFGLOCKR@ +0x08  LOCKx (rs): freezes SECx/PRIVx "until a global
    //                     GPDMA reset"; only secure privileged can set it.
    // A non-secure access to a secure channel's registers reads 0 and its
    // writes "have no impact" (§17.4.14, p.727). Once ANY channel is secure,
    // the controller's RCC clock-enable and reset bits become secure too
    // (§3.5.5, p.164; §11.5.1: NS write ignored), so NS cannot pulse
    // GPDMA1RST/LPDMA1RST to clear the lock. The non-secure image has no DMA
    // code (`nonsecure/src` uses DMA only in the DVT probes), so it loses
    // nothing. The secure blit channel (`hw::gpdma`, channel 0) keeps working:
    // it is secure code programming a secure channel.
    const GPDMA1_S: u32 = 0x5002_0000;
    const LPDMA1_S: u32 = 0x5602_5000;
    /// 16 GPDMA1 channels (RM0456 Table 135, p.687): SEC/PRIV/LOCK 0..15.
    const GPDMA1_ALL_CH: u32 = 0xFFFF;
    /// 4 LPDMA1 channels (RM0456 Table 145, p.766): SEC/PRIV/LOCK 0..3.
    const LPDMA1_ALL_CH: u32 = 0xF;
    const RCC_AHB1ENR_GPDMA1EN: u32 = 1 << 0; // RCC_AHB1ENR @ +0x88
    const RCC_AHB3ENR_LPDMA1EN: u32 = 1 << 9; // RCC_AHB3ENR @ +0x94

    const _: () = assert!(
        GPDMA1_ALL_CH == (1 << 16) - 1 && LPDMA1_ALL_CH == (1 << 4) - 1,
        "every DMA channel must be claimed: 16 on GPDMA1, 4 on LPDMA1 (#982)"
    );

    /// Make every GPDMA1 and LPDMA1 channel secure and privileged, lock that
    /// attribution, and verify it (#982). Called from [`super::init`] after
    /// the TZSC image and before the TZSC lock, so it precedes NS boot.
    ///
    /// Order per controller is SEC, then PRIV (writable by secure only once
    /// SEC is set), then LOCK. A channel left enabled would make its SEC write
    /// "read-only when EN=1" and the readback halts the boot (fail closed);
    /// after any reset every channel is disabled, and the only earlier DMA user
    /// (`hw::gpdma` under `ui-px-dma` on non-se050 builds) leaves EN=0 when
    /// its blit completes. Both DMA clocks are left RUNNING, as the SYSCFG
    /// clock is in [`lock_security_config`]: with the clock gated the
    /// controller's registers are not accessible (RM0456 p.553), so the lock
    /// state would read 0 to everyone, and the non-secure RCC alias can no
    /// longer turn it on (the enable bit is secure now). Left on, the
    /// attribution stays readable — NS may read SECCFGR/PRIVCFGR/RCFGLOCKR —
    /// which is what the DVT probe (`nonsecure/src/dma_probe.rs`) checks. An
    /// idle DMA controller's clock draw is negligible.
    pub fn secure_dma_masters() {
        // SAFETY: each address is a 4-byte-aligned RCC / GPDMA1 / LPDMA1
        // register on the secure alias, owned by the single-threaded boot path.
        let rcc_ahb1enr = unsafe { Reg32::new(RCC_S + 0x88) };
        let rcc_ahb3enr = unsafe { Reg32::new(RCC_S + 0x94) };
        let gp_seccfgr = unsafe { Reg32::new(GPDMA1_S + 0x00) };
        let gp_privcfgr = unsafe { Reg32::new(GPDMA1_S + 0x04) };
        let gp_rcfglockr = unsafe { Reg32::new(GPDMA1_S + 0x08) };
        let lp_seccfgr = unsafe { Reg32::new(LPDMA1_S + 0x00) };
        let lp_privcfgr = unsafe { Reg32::new(LPDMA1_S + 0x04) };
        let lp_rcfglockr = unsafe { Reg32::new(LPDMA1_S + 0x08) };

        rcc_ahb1enr.set_bits(RCC_AHB1ENR_GPDMA1EN);
        rcc_ahb3enr.set_bits(RCC_AHB3ENR_LPDMA1EN);
        cortex_m::asm::dsb();

        gp_seccfgr.write(GPDMA1_ALL_CH);
        gp_privcfgr.write(GPDMA1_ALL_CH);
        lp_seccfgr.write(LPDMA1_ALL_CH);
        lp_privcfgr.write(LPDMA1_ALL_CH);
        cortex_m::asm::dsb();
        // Lock only an attribution that reads back: a lock over a wrong
        // image would freeze the hole until reset.
        verify_or_halt(gp_seccfgr.read(), GPDMA1_ALL_CH);
        verify_or_halt(gp_privcfgr.read(), GPDMA1_ALL_CH);
        verify_or_halt(lp_seccfgr.read(), LPDMA1_ALL_CH);
        verify_or_halt(lp_privcfgr.read(), LPDMA1_ALL_CH);

        gp_rcfglockr.write(GPDMA1_ALL_CH);
        lp_rcfglockr.write(LPDMA1_ALL_CH);
        cortex_m::asm::dsb();
        verify_or_halt(gp_rcfglockr.read(), GPDMA1_ALL_CH);
        verify_or_halt(lp_rcfglockr.read(), LPDMA1_ALL_CH);
        // Re-read the attribution under the lock: one faulted check above
        // must not be the only thing standing between NS and a channel.
        verify_or_halt(gp_seccfgr.read() & gp_privcfgr.read(), GPDMA1_ALL_CH);
        verify_or_halt(lp_seccfgr.read() & lp_privcfgr.read(), LPDMA1_ALL_CH);
    }

    // ---- tz-2 (Trezor-port) lock registers ----
    // SYSCFG @ APB3, secure alias: SYSCFG_BASE_S = PERIPH_BASE_S(0x5000_0000)
    // + APB3 offset(0x0600_0000) + 0x0400 = 0x5600_0400; CSLCKR @ +0x10.
    // (CMSIS `stm32u585xx.h`: LOCKSVTAIRCR=bit0, LOCKSAU=bit2.)
    const SYSCFG_CSLCKR_ADDR: u32 = 0x5600_0410;
    const CSLCKR_LOCKSVTAIRCR: u32 = 1 << 0; // freeze secure VTOR + AIRCR sec-cfg
    const CSLCKR_LOCKSAU: u32 = 1 << 2; // freeze SAU regions

    // GTZC1 TZSC control register @ TZSC_BASE + 0x00; LCK = bit 0
    // (CMSIS `GTZC_TZSC_CR_LCK_Msk`).
    const TZSC_CR_ADDR: u32 = TZSC_BASE; // + 0x00
    const TZSC_CR_LCK: u32 = 1 << 0;

    // ARMv8-M SCB AIRCR (core register) security attributes (core_cm33.h).
    const SCB_AIRCR_ADDR: u32 = 0xE000_ED0C;
    const AIRCR_VECTKEY: u32 = 0x05FA << 16; // required on every write
    const AIRCR_VECTKEY_MASK: u32 = 0xFFFF << 16;
    // PRIS is AIRCR bit 14 (CMSIS `core_cm33.h` `SCB_AIRCR_PRIS_Pos 14U`).
    // Bit 10 is PRIGROUP[2]: until the DVT1 run (2026-10-15, checklist row
    // 3.7) this constant was `1 << 10`, so the boot set PRIGROUP=4, never set
    // PRIS, and a non-secure PRIMASK (every `interrupt::free` in the NS USB
    // stack) masked the secure SysTick — the idle wipe and the IWDG kick.
    // Silicon readback with bit 14: AIRCR = 0xFA05_4000.
    const AIRCR_PRIS: u32 = 1 << 14; // NS exception priorities mapped to the lower half
    const AIRCR_PRIGROUP_MASK: u32 = 0x7 << 8; // left at 0: no sub-priority split
    const AIRCR_BFHFNMINS: u32 = 1 << 13; // 0 = BusFault/HardFault/NMI are SECURE
    #[cfg(feature = "mode-production")]
    const AIRCR_SYSRESETREQS: u32 = 1 << 3; // restrict SYSRESETREQ to secure

    /// **tz-2 (Trezor-port `tz_init.c:132-145,410-415`) — freeze the
    /// TrustZone security configuration once it is fully programmed.**
    ///
    /// Called at the very end of [`super::init`], after all four SAU
    /// regions + GTZC are set. Nothing reconfigures SAU/TZSC after boot,
    /// so locking removes the residual "a fault flip or a stray
    /// secure-world write re-classifies secure SRAM as NS / marks SAES NS"
    /// surface — a layer *below* the signing-path FI defense. Universal
    /// Trezor STM32U5 practice, reset-scoped, ~cheap.
    ///
    /// Also fixes the SCB AIRCR security attributes: `PRIS` (secure
    /// interrupts outprioritize NS) and `BFHFNMINS=0` (BusFault/HardFault/
    /// NMI are taken in the SECURE state — this *reinforces* the rr-1
    /// `HardFault` handler, which must run S-side to reach the
    /// secret-zeroize path). `SYSRESETREQS` (restrict `SYSRESETREQ` to
    /// secure) is set ONLY under `mode-production`, so the bench keeps its
    /// NS-initiated `cc_open_then_reset` USB-C warm reset. `LOCKSVTAIRCR`
    /// freezes the AIRCR *security-config* bits, not the reset trigger.
    ///
    /// GTZC2 (SPI3, LPUART1, I2C3, LPTIM1/3/4, ADC4, DAC1, ...) is
    /// intentionally NOT locked: it is not configured on this branch, and
    /// locking an unconfigured controller would freeze its NS reset default.
    /// TAMP/RTC are not GTZC2 peripherals; they are secured through their own
    /// `*_SECCFGR` in [`secure_system_controllers`], as are RCC/PWR/EXTI.
    pub fn lock_security_config() {
        // SAFETY: core + peripheral security registers, 4-byte aligned,
        // owned exclusively by the single-threaded boot path.
        let aircr = unsafe { Reg32::new(SCB_AIRCR_ADDR) };
        let syscfg_cslckr = unsafe { Reg32::new(SYSCFG_CSLCKR_ADDR) };
        let tzsc_cr = unsafe { Reg32::new(TZSC_CR_ADDR) };

        // SYSCFG clock must be ON before any CSLCKR access: RCC_APB3ENR
        // is zero out of reset and nothing else in the boot enables it,
        // so the lock write below was silently dropped (RAZ/WI) on
        // hardware until the F6 readback verify caught it
        // (2026-07-19 bench brick). SYSCFGEN = RCC_APB3ENR bit 1
        // (CMSIS `RCC_APB3ENR_SYSCFGEN`). Left running: the lock bits
        // must stay readable, and the SYSCFG draw is negligible.
        const RCC_APB3ENR_ADDR: u32 = 0x5602_0C00 + 0xA8;
        const RCC_APB3ENR_SYSCFGEN: u32 = 1 << 1;
        let rcc_apb3enr = unsafe { Reg32::new(RCC_APB3ENR_ADDR) };
        rcc_apb3enr.set_bits(RCC_APB3ENR_SYSCFGEN);
        cortex_m::asm::dsb();

        // (1) AIRCR — set the security attributes BEFORE they are frozen
        // by LOCKSVTAIRCR below. VECTKEY must be re-supplied on every
        // write, and the read returns VECTKEYSTAT in the top half, so this
        // is an explicit read-clear-set-write (not `set_bits`).
        let mut v = aircr.read();
        v &= !(AIRCR_VECTKEY_MASK | AIRCR_PRIGROUP_MASK);
        v |= AIRCR_VECTKEY | AIRCR_PRIS;
        v &= !AIRCR_BFHFNMINS;
        #[cfg(feature = "mode-production")]
        {
            v |= AIRCR_SYSRESETREQS;
        }
        aircr.write(v);
        cortex_m::asm::dsb();

        // X17-TZ1 (playbook TZ10): verify the security-config bits we
        // just wrote BEFORE LOCKSVTAIRCR freezes them. The "a read
        // returns VECTKEYSTAT" caveat covers ONLY bits [31:16] — PRIS /
        // BFHFNMINS / SYSRESETREQS sit in the readable low half-word,
        // so an FI'd/skipped store would otherwise sail into the freeze
        // unnoticed (PRIS=0 → an NS IRQ can preempt a secure EXCEPTION
        // handler). PRIS does NOT protect a gateway veneer: a veneer runs
        // in secure THREAD mode, which any exception preempts, banked
        // non-secure SysTick/PendSV included. Nested gateway entry is
        // refused by `nsc::GATEWAY_GATE` instead (#846). Same
        // unconditional fail-closed convention as
        // the lock-bit readback below. Masked to exactly the bits this
        // function owns; comparing against `v`'s masked value verifies
        // both the PRIS/SYSRESETREQS sets AND the BFHFNMINS clear.
        #[cfg(not(feature = "mode-production"))]
        const AIRCR_SECCFG_MASK: u32 = AIRCR_PRIS | AIRCR_BFHFNMINS;
        #[cfg(feature = "mode-production")]
        const AIRCR_SECCFG_MASK: u32 =
            AIRCR_PRIS | AIRCR_BFHFNMINS | AIRCR_SYSRESETREQS;
        verify_or_halt(aircr.read() & AIRCR_SECCFG_MASK, v & AIRCR_SECCFG_MASK);

        // (2) Freeze SAU regions + AIRCR security-config, (3) freeze GTZC1
        // TZSC per-peripheral attributes. Both lock bits are sticky-set.
        syscfg_cslckr.set_bits(CSLCKR_LOCKSAU | CSLCKR_LOCKSVTAIRCR);
        tzsc_cr.set_bits(TZSC_CR_LCK);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // Write-readback self-check, UNCONDITIONAL + fail-closed (F6): the lock
        // bits must read back set before NS boots, in release too (the previous
        // `debug_assert_eq!` was a no-op under `--release`, so a faulted lock
        // write left SAU/TZSC re-writable with nobody noticing). The AIRCR
        // security-config bits were already verified above (X17-TZ1) — only
        // the top-half VECTKEY field is unreadable (reads as VECTKEYSTAT), and
        // the mask there deliberately excludes it.
        let want = CSLCKR_LOCKSAU | CSLCKR_LOCKSVTAIRCR;
        verify_or_halt(syscfg_cslckr.read() & want, want); // SAU/AIRCR lock bits
        verify_or_halt(tzsc_cr.read() & TZSC_CR_LCK, TZSC_CR_LCK); // TZSC CR.LCK
    }
}

pub fn init() {
    #[cfg(not(feature = "stm32u585"))]
    qemu::configure_mpc();

    #[cfg(feature = "stm32u585")]
    stm32::configure_gtzc();

    // RCC / PWR / TAMP / RTC / EXTI carry their own security registers
    // (DVT1 row 3.5); secure them before NS can ever run.
    #[cfg(feature = "stm32u585")]
    stm32::secure_system_controllers();

    // GPDMA1 / LPDMA1 have no TZSC bit; claim and lock every channel so the
    // non-secure world has no DMA master to aim at the OTP/UID (#982).
    #[cfg(feature = "stm32u585")]
    stm32::secure_dma_masters();

    // Disable SAU while configuring.
    SAU.ctrl.write(0);

    // Region 0: NS code flash (bounds centralized above + compile-time
    // subset-checked against the proto NS_FLASH window).
    configure_sau_region(0, SAU_NS_FLASH_BASE, SAU_NS_FLASH_END, false);

    // Region 1: NSC veneers (placed in secure flash by linker).
    // SAFETY: `__veneer_base` / `__veneer_limit` are linker-defined symbols;
    // taking their addresses is safe but the `static` deref reads them
    // through `extern "C"` linkage.
    let (veneer_base, veneer_limit) = unsafe {
        (
            &__veneer_base as *const u32 as u32,
            &__veneer_limit as *const u32 as u32,
        )
    };
    let nsc_end = if veneer_limit > veneer_base {
        ((veneer_limit + 0xFF) & 0xFFFF_FF00) - 1
    } else {
        veneer_base + 0xFF
    };
    configure_sau_region(1, veneer_base, nsc_end, true);

    // Region 2: NS data SRAM (bounds centralized above + compile-time
    // subset-checked against the proto NS_SRAM window).
    configure_sau_region(2, SAU_NS_SRAM_BASE, SAU_NS_SRAM_END, false);

    // Region 3: NS peripherals
    configure_sau_region(3, 0x4000_0000, 0x4FFF_FFFF, false);

    // Enable SAU + barriers
    SAU.ctrl.write(1);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    // tz-2 (Trezor-port): now that SAU + GTZC are fully programmed, freeze
    // the security configuration (SAU + GTZC1 TZSC + AIRCR sec-attrs) so a
    // later fault/stray write cannot rewrite it. See `lock_security_config`.
    // stm32u585 only (QEMU MPC path has no equivalent lock).
    #[cfg(feature = "stm32u585")]
    stm32::lock_security_config();
}
