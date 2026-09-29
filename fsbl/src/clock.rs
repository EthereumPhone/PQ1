//! Minimal clock bring-up: MSIS 4 MHz (reset) → HSI16 16 MHz.
//!
//! The FSBL used to run its whole life on the MSIS reset clock, which the
//! vendor SVD pins at **4 MHz** (`RCC_CFGR1.SW` = 00 selects MSIS;
//! `RCC_CSR.MSISSRANGE` = 4, enumerated as "range 4 around 4 MHz (reset
//! value)"). Measured consequence: a 39.4 s boot, of which 8.6 s was actual
//! computation (`fsbl/src/marker.rs` carries the full budget).
//!
//! Switching to HSI16 is a 4× speedup for every compute term at a cost of
//! about twenty bytes, and it needs **no** voltage-scaling or flash-latency
//! work: `secure/src/hw/rcc.rs` performs exactly this switch as its "safe
//! baseline before PLL config", touching `FLASH_ACR` only later inside
//! `try_pll_160mhz()`. Every boot the secure world has ever done on this
//! silicon therefore demonstrates that 16 MHz is safe at reset VOS and reset
//! flash latency. That was the one real risk in raising the FSBL clock, and it
//! is answered in-tree rather than by assumption.
//!
//! ## Three deliberate properties
//!
//! 1. **Every wait is BOUNDED.** `rcc.rs` spins `while ... == 0 {}` unbounded,
//!    which is fine for an updatable secure world. The FSBL becomes
//!    *permanently unpatchable* once WRP + RDP-2 land (invariant #10), so an
//!    unbounded spin on a clock flag is a potential brick. On timeout this
//!    gives up and leaves the part on MSIS.
//!
//! 2. **[`achieved_hz`] reads the hardware, and holds no state.** It reports
//!    `RCC_CFGR1.SWS` — the clock actually in use — rather than a latched
//!    belief about what the switch managed. That matters twice over:
//!
//!    * *Safety.* `nv3007::delay_ms` is nop-counted, so calibrating it for
//!      16 MHz while running at 4 MHz makes every NV3007 reset / SLPOUT /
//!      DISPON wait **4× SHORT** — the one direction that violates a vendor
//!      minimum. Deriving the figure from `SWS` means a failed switch costs
//!      boot time and nothing else.
//!    * *Image layout.* The first version latched the frequency in a
//!      `static mut` initialised to `MSIS_HZ`. A non-zero initialiser puts it
//!      in `.data`, which becomes a SECOND LOAD segment — and
//!      `scripts/check_fsbl_geometry.py` fails on more than one, because the
//!      physical span and the derived WRP page range are only trustworthy for
//!      a single-segment image. `.bss` would have cost a segment too. A pure
//!      function costs none, which is why there is no state here and why
//!      `fsbl-tests` pins the absence of `static mut` in this file.
//!
//! 3. **Nothing else is reconfigured.** No PLL, no VOS, no flash latency, no
//!    peripheral clocks beyond what the LCD driver already enables. The secure
//!    world re-derives the whole tree in `rcc::init()` immediately after the
//!    branch, so this configuration is transient.

use core::ptr::{read_volatile, write_volatile};

use crate::board;

const RCC_CR: usize = (board::RCC_S + 0x00) as usize;
/// `RCC_CFGR1` — offset 0x1C, per the vendor SVD.
const RCC_CFGR1: usize = (board::RCC_S + 0x1C) as usize;

const HSION: u32 = 1 << 8;
const HSIRDY: u32 = 1 << 10;

/// `CFGR1.SW` = 01 selects HSI16 (00 = MSIS, 10 = HSE, 11 = PLL1).
const SW_HSI16: u32 = 0b01;
const SW_MASK: u32 = 0b11;
/// `CFGR1.SWS` (bits [3:2]) reads back the clock actually in use.
const SWS_HSI16: u32 = 0b01 << 2;
const SWS_MASK: u32 = 0b11 << 2;

/// MSIS reset clock, per the SVD reset values.
pub const MSIS_HZ: u32 = 4_000_000;
/// HSI16, the clock this module tries to reach.
pub const HSI16_HZ: u32 = 16_000_000;

/// Bound on each readiness spin. At 4 MHz this is well under a second, and
/// HSI16 stabilises in microseconds — so reaching the bound means the clock is
/// genuinely broken, not merely slow.
const SPIN_LIMIT: u32 = 200_000;

#[inline(always)]
fn rd(addr: usize) -> u32 {
    // SAFETY: fixed 4-byte-aligned RCC registers in the secure alias; pure
    // read, single-threaded at boot.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn wr(addr: usize, val: u32) {
    // SAFETY: as `rd`. Only this module touches RCC_CR/CFGR1, and it runs once
    // before anything else is initialised.
    unsafe { write_volatile(addr as *mut u32, val) }
}

/// Try to switch SYSCLK to HSI16. Best-effort: on any timeout the part is left
/// on the MSIS reset clock, and [`achieved_hz`] will report that truthfully.
///
/// Call once, first thing in `main`, before any cycle-counted delay and before
/// the `stage-marker` DWT counter starts — so the whole boot is measured in one
/// clock domain.
pub fn init() {
    // 1. Enable HSI16 and wait, BOUNDED, for it to stabilise.
    wr(RCC_CR, rd(RCC_CR) | HSION);
    let mut spins = 0u32;
    while rd(RCC_CR) & HSIRDY == 0 {
        spins += 1;
        if spins > SPIN_LIMIT {
            return; // HSI16 never came up — stay on the reset clock.
        }
        cortex_m::asm::nop();
    }

    // 2. Select it, then confirm via SWS that the switch actually took. A
    //    write to SW is a request; SWS is the acknowledgement.
    wr(RCC_CFGR1, (rd(RCC_CFGR1) & !SW_MASK) | SW_HSI16);
    let mut spins = 0u32;
    while rd(RCC_CFGR1) & SWS_MASK != SWS_HSI16 {
        spins += 1;
        if spins > SPIN_LIMIT {
            return; // Request not honoured — `achieved_hz` reports MSIS.
        }
        cortex_m::asm::nop();
    }

    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

/// The frequency SYSCLK is running at **right now**, read from `CFGR1.SWS`.
///
/// Stateless on purpose — see property 2 in the module header. Anything other
/// than HSI16 is reported as [`MSIS_HZ`], which is conservative: the FSBL
/// never selects HSE or the PLL, and under-reporting the clock only makes
/// nop-counted delays longer, never shorter.
#[must_use]
pub fn achieved_hz() -> u32 {
    if rd(RCC_CFGR1) & SWS_MASK == SWS_HSI16 {
        HSI16_HZ
    } else {
        MSIS_HZ
    }
}
