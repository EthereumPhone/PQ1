//! GTZC1 TZSC + TZIC enforcement validation driver (NS side).
//!
//! Pre-production gate that proves invariant #4 — "all secrets live
//! ONLY in TrustZone secure world" — is actually enforced by the
//! GTZC1 bus master, not just claimed by the code in
//! `secure/src/sau.rs::stm32::configure_gtzc`. Replaces the interactive
//! `main()` when the `gtzc-test` feature is on.
//!
//! ## Protocol
//!
//! For each peripheral the secure-world boot path marked SECURE
//! (I2C1, I2C2 via SECCFGR1; AES, HASH, RNG, PKA, SAES via SECCFGR3):
//!
//!   1. Print a labelled banner via semihosting so the host log
//!      interleaves NS probes with secure-world `[S][TZIC]` lines.
//!   2. `read_volatile` from the NS-aliased peripheral address. By
//!      ARMv8-M + STM32U585 semantics, the AHB bridge gates the
//!      access (read returns 0, no fault propagates to NS) and the
//!      TZIC raises NVIC IRQ 8 in the secure world, which logs the
//!      offender and bumps `hw::tzic::VIOLATION_COUNT`.
//!   3. After all probes, read the TZIC counter via the
//!      `nsc_tzic_status` CMSE veneer. Expected = `PROBES.len()`.
//!   4. Emit a single `[NS][gtzc] === PASS ===` line on success or
//!      `=== FAIL n=<count> ===` on mismatch.
//!
//! The Makefile target `gtzc-enforcement-hw` greps for the PASS/FAIL
//! line and exits 0/1 accordingly.

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};

use crate::nsc_api;

/// One probe: NS-alias address + human label. The address is the
/// NS-alias of a peripheral the secure boot path marked SECURE in
/// `TZSC_SECCFGRx`. Reading it from NS must:
///   * return 0 (AHB bridge gates the access — RAZ semantics), AND
///   * raise GTZC1 IRQ → bump `tzic::VIOLATION_COUNT` by exactly 1.
struct Probe {
    addr: u32,
    label: &'static str,
}

/// Every peripheral marked SECURE in `secure/src/sau.rs`, for THIS board.
///
/// This list and `sau.rs`'s `SECCFGR*_IMAGE` must move together. The pass
/// criterion is `delta == PROBES.len()`, so a peripheral secured in the image
/// but missing here does not weaken the receipt — it makes the receipt SILENT
/// about it while still printing PASS. That has now happened twice (I2C4, then
/// TIM2/TIM3/UCPD1); the const asserts in `sau.rs` carry the instruction
/// "update the pin ONLY with a matching gtzc-enforcement-hw receipt".
/// Order matches the SECCFGR1 → SECCFGR3 ordering in the source file so
/// log scraping is predictable.
///
/// The list is board-conditional because the secured SET is: `pq1` gives the
/// SE050 its own **I2C4** bus (`SECCFGR1` bit 16) where `iota2` has both
/// secure elements on I2C1, so pq1 secures one peripheral more. Keeping the
/// probe list fixed at iota2's seven would leave the one bit that has **no
/// functional symptom either way** — NS reachability of the SE050 bus —
/// permanently unverified, while still reporting PASS.
///
/// NS-alias = SECURE-alias with bit 28 cleared (`0x5...` → `0x4...`).
/// Addresses chosen to hit a benign register on each peripheral:
///   * I2C status / control regs — no side-effect on the bus.
///   * AES/HASH/SAES/PKA/RNG control regs — reading these does not
///     advance any pipeline; they're idempotent.
const PROBES: &[Probe] = &[
    // APB1 — I2C1/I2C2. Base addresses confirmed against
    // `secure/src/hw/i2c.rs:28` (`0x5000_5400`) and
    // `secure/src/hw/i2c2_probe.rs:36` (`0x5000_5800`); NS alias =
    // S alias with bit 28 cleared.
    Probe { addr: 0x4000_5400, label: "I2C1_CR1"  },
    Probe { addr: 0x4000_5800, label: "I2C2_CR1"  },
    // AHB2 crypto block. Base addresses confirmed against
    // `secure/src/hw/{hash,rng,saes}.rs` (S aliases `0x520C_*`); NS
    // alias = S alias with bit 28 cleared.
    Probe { addr: 0x420C_0000, label: "AES_CR"    },
    Probe { addr: 0x420C_0400, label: "HASH_CR"   },
    Probe { addr: 0x420C_0800, label: "RNG_CR"    },
    Probe { addr: 0x420C_2000, label: "PKA_CR"    },
    Probe { addr: 0x420C_0C00, label: "SAES_CR"   },
    // pq1 only: I2C4 is the SE050's dedicated bus. NS alias of the
    // `0x5000_8400` secure alias in `secure/src/board/mod.rs`.
    #[cfg(feature = "board-pq1")]
    Probe { addr: 0x4000_8400, label: "I2C4_CR1"  },
    // APB1 — TIM2, TIM3, UCPD1. Added 2026-09-01 with the commits that put
    // them in the SECCFGR1 image; before that this list covered seven
    // peripherals while the image secured ten, so the receipt printed
    // "7/7 PASS" for a configuration it had never probed. That is the same
    // defect the I2C4 row above was added to fix, re-created three bits later.
    //
    // TIM2/TIM3 carry the `consumption-mask` PWM, which production MANDATES:
    // an NS world that can reach the timer can clear `CR1.CEN` and flat-line
    // the mask with no secure-side symptom. UCPD1 owns PA15/PB15 — `SE_RST`
    // and `LCM_EN` on pq1 — a second handle on those pads underneath the
    // per-pin `GPIOx_SECCFGR` layer. NS aliases = secure alias with bit 28
    // cleared: TIM2_S 0x5000_0000, TIM3_S 0x5000_0400, UCPD1 0x5000_DC00
    // (`secure/src/board/mod.rs`, `secure/src/hw/usb_hw.rs`).
    Probe { addr: 0x4000_0000, label: "TIM2_CR1"  },
    Probe { addr: 0x4000_0400, label: "TIM3_CR1"  },
    Probe { addr: 0x4000_DC00, label: "UCPD1_CFG1" },
    // APB1 — CRS (SECCFGR1 bit 15), secured with the 2026-10-15 CRS fix
    // (DVT1 row 11.2): it trims HSI48, the USB and TRNG kernel clock. NS
    // alias of `0x5000_6000`; the e2e test clocks enable CRSEN for it.
    Probe { addr: 0x4000_6000, label: "CRS_CR" },
];

/// NS-side entry point under `--features gtzc-test`.
#[entry]
fn main() -> ! {
    let _ = hprintln!("[NS][gtzc] === GTZC1 TZSC enforcement validation ===");
    #[cfg(feature = "board-pq1")]
    let _ = hprintln!("[NS][gtzc] target: STM32U585CIU6 AL_A66_MB_V10 (pq1)");
    #[cfg(not(feature = "board-pq1"))]
    let _ = hprintln!("[NS][gtzc] target: STM32U585AII6 B-U585I-IOT02A (iota2)");
    let _ = hprintln!("[NS][gtzc] probes: {}", PROBES.len());

    // Baseline read of the counter before probing. The boot path may
    // legitimately tickle a SECURE peripheral from NS during init
    // (it shouldn't, but a non-zero baseline doesn't invalidate the
    // delta check below).
    let baseline = nsc_api::tzic_status();
    let _ = hprintln!("[NS][gtzc] tzic_status baseline = {}", baseline);

    let mut prev_count = baseline;
    for (i, p) in PROBES.iter().enumerate() {
        let _ = hprintln!(
            "[NS][gtzc] probe {}/{}  addr=0x{:08x} ({})",
            i + 1,
            PROBES.len(),
            p.addr,
            p.label,
        );

        // The actual probe. `read_volatile` keeps the compiler from
        // eliding the access (no observable use of `v` is fine —
        // `volatile` is the contract). The AHB bridge gates the
        // read and RAZ's it; TZIC IRQ fires in the secure world.
        //
        // SAFETY: each addr is a 4-byte-aligned MMIO register on
        // AHB1/AHB2. The TZIC enforcement-under-test means the
        // read never actually touches the peripheral — it's gated
        // at the bridge and returns 0. Even if enforcement is
        // *broken*, reading a control register is side-effect-free
        // on every peripheral in `PROBES`.
        let v: u32 = unsafe { core::ptr::read_volatile(p.addr as *const u32) };

        // Barrier + spin so the TZIC IRQ has time to land before
        // we read the counter below.
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        for _ in 0..1000 {
            cortex_m::asm::nop();
        }

        // Per-probe counter delta — pinpoints which probes the
        // IRQ actually fired for vs which were silently RAZ'd
        // (or not gated at all). Caller logs the secure-side
        // tzic_status return; `prev_count` here is the count
        // *before* this probe.
        let cur = nsc_api::tzic_status();
        let delta_this = cur.wrapping_sub(prev_count);
        let _ = hprintln!(
            "[NS][gtzc]   read=0x{:08x}  tzic_count={}  irqs_for_probe={}",
            v,
            cur,
            delta_this,
        );
        prev_count = cur;
    }

    // Drain barrier — make sure every IRQ has run before we read the
    // counter. Each probe's IRQ runs at higher priority than NS
    // thread mode (banked SECURE exception, default priority 0), so
    // by the time we reach here every IRQ has long since completed.
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    for _ in 0..10_000 {
        cortex_m::asm::nop();
    }

    let final_count = nsc_api::tzic_status();
    let delta = final_count.wrapping_sub(baseline);
    let _ = hprintln!(
        "[NS][gtzc] tzic_status final = {} (delta = {}, expected = {})",
        final_count,
        delta,
        PROBES.len(),
    );

    #[cfg(feature = "gtzc-sys")]
    sys_probe::run();

    if delta == PROBES.len() as u32 {
        let _ = hprintln!("[NS][gtzc] === PASS ===");
        // SYS_EXIT(0) via semihosting — host harness captures the
        // pass line and the QEMU/probe-rs runner returns 0.
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        let _ = hprintln!(
            "[NS][gtzc] === FAIL n={} expected={} ===",
            delta,
            PROBES.len(),
        );
        debug::exit(debug::EXIT_FAILURE);
    }

    // Unreachable on real silicon — `debug::exit` halts on probe-rs.
    // Loop on WFE just in case so we don't fall off into rt's panic.
    loop {
        cortex_m::asm::wfe();
    }
}

/// DVT checklist rows 3.3 / 3.4 / 3.5 / 3.6 (`docs/hardware/dvt-silicon-test-checklist.md`).
///
/// Phase 2, opt-in (`gtzc-sys`), run AFTER the TZSC receipt above so it cannot
/// disturb that count. Each probe is a non-secure read-modify-write of a
/// system register that has no TZSC bit of its own (RCC/PWR/TAMP/EXTI carry
/// their own `*_SECCFGR`), or of a GPIO pad the secure world owns. The NS
/// read-back is printed, but it is NOT the verdict: a secure-only bit may
/// read as zero from NS. The verdict comes from reading the SECURE alias
/// over SWD after the run (the writes are deliberately left in place).
///
/// `GTZC_FAULT_ADDR` (hex, compile-time env) appends one NS read of that
/// address as the very last action: an SAU-secure address must SecureFault
/// (→ secure HardFault → reset), so at most one such probe per run.
#[cfg(feature = "gtzc-sys")]
mod sys_probe {
    use cortex_m_semihosting::hprintln;

    struct W {
        addr: u32,
        label: &'static str,
        /// Bits XOR-toggled by the write. 0 = read only.
        mask: u32,
    }

    const RCC: u32 = 0x4602_0C00;
    const PWR: u32 = 0x4602_0800;
    const TAMP: u32 = 0x4600_7C00;
    const RTC: u32 = 0x4600_7800;
    const EXTI: u32 = 0x4602_2000;
    const TZSC1: u32 = 0x4003_2400;
    const GPIOA: u32 = 0x4202_0000;
    const GPIOB: u32 = 0x4202_0400;

    const PROBES: &[W] = &[
        // Security config registers, read only (record the state).
        W { addr: RCC + 0x110, label: "RCC_SECCFGR", mask: 0 },
        W { addr: PWR + 0x30, label: "PWR_SECCFGR", mask: 0 },
        W { addr: TAMP + 0x20, label: "TAMP_SECCFGR", mask: 0 },
        W { addr: EXTI + 0x14, label: "EXTI_SECCFGR1", mask: 0 },
        W { addr: RTC + 0x20, label: "RTC_SECCFGR", mask: 0 },
        W { addr: EXTI + 0x70, label: "EXTI_LOCKR", mask: 0 },
        W { addr: GPIOA + 0x30, label: "GPIOA_SECCFGR", mask: 0 },
        W { addr: GPIOB + 0x30, label: "GPIOB_SECCFGR", mask: 0 },
        // Bus clocks the gtzc image leaves off: GPIOA/B (AHB2ENR1 bits 0/1)
        // and RTCAPB (APB3ENR bit 21, TAMP/RTC registers). Without these the
        // GPIO/TAMP probes below read garbage and prove nothing; enabling
        // them from NS is itself a probe.
        W { addr: RCC + 0x8C, label: "RCC_AHB2ENR1.GPIOA/B", mask: 0b11 },
        W { addr: RCC + 0xA8, label: "RCC_APB3ENR.RTCAPBEN", mask: 1 << 21 },
        W { addr: GPIOA + 0x30, label: "GPIOA_SECCFGR(clk on)", mask: 0 },
        W { addr: GPIOB + 0x30, label: "GPIOB_SECCFGR(clk on)", mask: 0 },
        W { addr: TAMP + 0x20, label: "TAMP_SECCFGR(clk on)", mask: 0 },
        // RCC: TRNG kernel clock, secure-peripheral clock gate, prescaler.
        W { addr: RCC + 0x00, label: "RCC_CR.HSI48ON", mask: 1 << 12 },
        W { addr: RCC + 0x8C, label: "RCC_AHB2ENR1.RNGEN", mask: 1 << 18 },
        W { addr: RCC + 0x24, label: "RCC_CFGR3.PPRE3", mask: 0b100 << 4 },
        // PWR: voltage monitor + backup-domain write enable.
        W { addr: PWR + 0x10, label: "PWR_SVMCR.PVDE", mask: 1 << 4 },
        W { addr: PWR + 0x28, label: "PWR_DBPR.DBP", mask: 1 << 0 },
        // TAMP (needs DBP=1, probed just above): filter cfg, tamper
        // enables, backup regs (BKP0..7 hold the BHK on `bhk` builds).
        W { addr: TAMP + 0x0C, label: "TAMP_FLTCR", mask: 0x0000_0003 },
        W { addr: TAMP + 0x00, label: "TAMP_CR1.ITAMP5E", mask: 1 << 20 },
        W { addr: TAMP + 0x100, label: "TAMP_BKP0R", mask: 0xA5A5_5A5A },
        W { addr: TAMP + 0x17C, label: "TAMP_BKP31R", mask: 0xA5A5_5A5A },
        // RCC fields the 2026-10-15 fix covers that the first run did not
        // probe. Each is harmless if it moves on this image: MCOSEL (bits
        // 27:24, SYSCLKSEC; no MCO pin is muxed), PLL1FRACR (PLL1SEC; unused
        // while PLL1FRACEN=0), LSCOSEL (BDCR bit 25; backup domain, VBSEC +
        // RTC/TAMP security). BDRST itself is never probed: it would reset
        // the backup domain.
        W { addr: RCC + 0x1C, label: "RCC_CFGR1.MCOSEL", mask: 0b0001 << 24 },
        W { addr: RCC + 0x38, label: "RCC_PLL1FRACR", mask: 0x0000_0008 },
        W { addr: RCC + 0xF0, label: "RCC_BDCR.LSCOSEL", mask: 1 << 25 },
        // EXTI: rising-trigger enable on the button lines 0/1, the port
        // routing of lines 0..3 (EXTICR1), and the attribution itself.
        W { addr: EXTI + 0x00, label: "EXTI_RTSR1.L0L1", mask: 0b11 },
        W { addr: EXTI + 0x60, label: "EXTI_EXTICR1.L0", mask: 0x01 },
        W { addr: EXTI + 0x14, label: "EXTI_SECCFGR1(clr)", mask: 0b11 },
        // RTC attribution (no RTC driver; secured to close RCC_BDCR).
        W { addr: RTC + 0x20, label: "RTC_SECCFGR(clr)", mask: 1 << 15 },
        // GTZC1 TZSC itself: clearing SECCFGR1 would un-secure I2C1/I2C4/TIMs.
        W { addr: TZSC1 + 0x10, label: "TZSC_SECCFGR1", mask: 0xFFFF_FFFF },
        // GPIO pads the secure world owns (pq1): PA8 LDO2_EN, PA15 SE_RST,
        // PA4 LCD CS; PB5 SE1_EN, PB15 LCM_EN. MODER is used rather than
        // ODR so the effect is visible regardless of the current level.
        W { addr: GPIOA + 0x14, label: "GPIOA_ODR.PA4/8/15", mask: (1 << 4) | (1 << 8) | (1 << 15) },
        W { addr: GPIOB + 0x14, label: "GPIOB_ODR.PB5/15", mask: (1 << 5) | (1 << 15) },
        W { addr: GPIOA + 0x00, label: "GPIOA_MODER.PA8", mask: 0b11 << 16 },
        // Positive control: PA11 is NS (USB DM). Its MODER bits MUST move.
        W { addr: GPIOA + 0x00, label: "GPIOA_MODER.PA11(ctl)", mask: 0b11 << 22 },
    ];

    fn spin() {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        for _ in 0..20_000 {
            cortex_m::asm::nop();
        }
    }

    pub(super) fn run() {
        let _ = hprintln!("[NS][gtzc-sys] === phase 2: NS system-register write probes ===");
        for p in PROBES {
            // SAFETY: every address is a 4-byte-aligned register in the NS
            // peripheral alias (SAU region 3 = NS). Reads of these are
            // side-effect free; the writes are the probe under test, on a
            // bench board running a mock-SE image that holds no secret.
            let pre = unsafe { core::ptr::read_volatile(p.addr as *const u32) };
            if p.mask != 0 {
                unsafe { core::ptr::write_volatile(p.addr as *mut u32, pre ^ p.mask) };
            }
            spin();
            let post = unsafe { core::ptr::read_volatile(p.addr as *const u32) };
            let moved = (pre ^ post) & p.mask;
            let _ = hprintln!(
                "[NS][gtzc-sys] {:<22} @0x{:08x} S=0x{:08x} pre=0x{:08x} post=0x{:08x} mask=0x{:08x} moved=0x{:08x} {}",
                p.label,
                p.addr,
                p.addr | 0x1000_0000,
                pre,
                post,
                p.mask,
                moved,
                if p.mask == 0 { "READ" } else if moved != 0 { "NS-WROTE" } else { "ignored" },
            );
        }
        // HSI48ON was cleared above: does the oscillator actually stop?
        let mut rdy_gone_at = None;
        for i in 0..2_000_000u32 {
            // SAFETY: NS-alias RCC_CR read, side-effect free.
            let cr = unsafe { core::ptr::read_volatile(RCC as *const u32) };
            if cr & (1 << 13) == 0 {
                rdy_gone_at = Some(i);
                break;
            }
        }
        let _ = hprintln!("[NS][gtzc-sys] HSI48RDY after NS clear of HSI48ON: dropped at poll {:?}", rdy_gone_at);
        let _ = hprintln!("[NS][gtzc-sys] tzic_status after phase 2 = {}", crate::nsc_api::tzic_status());
        let _ = hprintln!("[NS][gtzc-sys] DONE (writes left in place for SWD read-back)");

        if let Some(s) = option_env!("GTZC_FAULT_ADDR") {
            let a = u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0);
            let _ = hprintln!("[NS][gtzc-sys] fault probe: NS read of 0x{:08x} ...", a);
            for i in 0..4u32 {
                // SAFETY: deliberate — this is the access under test. An
                // SAU-secure address SecureFaults into the secure HardFault
                // handler (zeroize + reset); an NS-mapped one returns data.
                let v = unsafe { core::ptr::read_volatile((a + 4 * i) as *const u32) };
                let _ = hprintln!("[NS][gtzc-sys] FAULT-PROBE READ 0x{:08x} = 0x{:08x}", a + 4 * i, v);
            }
            let _ = hprintln!("[NS][gtzc-sys] FAULT-PROBE SURVIVED (address readable from NS)");
        }
        if option_env!("GTZC_HOLD").is_some() {
            // Park (no semihosting, no WFE) so SWD can read the secure
            // aliases with every probe write still in place.
            let _ = hprintln!("[NS][gtzc-sys] HOLD: parked for SWD read-back");
            loop {
                cortex_m::asm::nop();
            }
        }
    }
}
