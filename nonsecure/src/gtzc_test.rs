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
//!   3. After all 7 probes, read the TZIC counter via the
//!      `nsc_tzic_status` CMSE veneer. Expected = 7.
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
