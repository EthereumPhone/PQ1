//! GTZC isolation on the ship peripheral set, reads AND writes
//! (`gtzc-ship`, DVT row 3.2).
//!
//! Row 3.1 (`gtzc-test`) reads one register of each secured peripheral from
//! the NS alias, on an image without `ui-lcd` and `iwdg`, so it never probes
//! SPI1 (the trusted-display bus) or the IWDG, and never writes. This runner
//! pairs with a secure image that has both (`ui-lcd` secures SPI1 in
//! `GTZC_SECCFGR2`, `iwdg` secures the IWDG in `SECCFGR1`) and, for every
//! TZSC-secured peripheral, does one NS read and then one NS write that
//! XOR-toggles a bit the secure image leaves at 0.
//!
//! Expected: every access is gated at the bridge (reads RAZ, writes
//! ignored) and raises exactly one TZIC event. The NS read-back cannot tell
//! "ignored" from "landed in a secure-only bit", so the host also reads the
//! SECURE alias of each written register over SWD (`tools/dvt/gtzc_ship.py`):
//! the toggled bit must still be 0 there.
//!
//! Nothing is printed: results go to `GTZC_SHIP_RES`, read over SWD. Needs a
//! secure image with `e2e-test` (for the `tzic_status` veneer) and `mock-se`.

use crate::nsc_api;
use core::sync::atomic::{AtomicU32, Ordering};

struct P {
    /// NS-alias register address (secure alias = `addr | 0x1000_0000`).
    addr: u32,
    /// Bits the write XOR-toggles; 0 = the peripheral is only read.
    mask: u32,
}

/// One row per secured peripheral. The write bits are interrupt/DMA
/// enables or similar that the mock-SE `ui-lcd` + `iwdg` image never sets,
/// so a landed write is visible on the secure alias and harmless.
const PROBES: [P; 15] = [
    P { addr: 0x4000_5400, mask: 1 << 12 }, // 0  I2C1_CR1.ANFOFF
    P { addr: 0x4000_5800, mask: 1 << 12 }, // 1  I2C2_CR1.ANFOFF
    P { addr: 0x4000_8400, mask: 1 << 12 }, // 2  I2C4_CR1.ANFOFF (pq1: SE050 bus)
    P { addr: 0x420C_0000, mask: 1 << 1 },  // 3  AES_CR.DATATYPE[0]
    P { addr: 0x420C_0400, mask: 1 << 3 },  // 4  HASH_CR.DMAE
    P { addr: 0x420C_0800, mask: 1 << 3 },  // 5  RNG_CR.IE
    P { addr: 0x420C_2000, mask: 1 << 17 }, // 6  PKA_CR.PROCENDIE
    P { addr: 0x420C_0C00, mask: 1 << 1 },  // 7  SAES_CR.DATATYPE[0]
    P { addr: 0x4000_0000, mask: 1 << 7 },  // 8  TIM2_CR1.ARPE
    P { addr: 0x4000_0400, mask: 1 << 7 },  // 9  TIM3_CR1.ARPE
    P { addr: 0x4000_DC00, mask: 1 << 0 },  // 10 UCPD1_CFG1.HBITCLKDIV[0]
    P { addr: 0x4000_6000, mask: 1 << 3 },  // 11 CRS_CR.ESYNCIE
    P { addr: 0x4001_3010, mask: 1 << 0 },  // 12 SPI1_IER.RXPIE (trusted display)
    P { addr: 0x4000_3004, mask: 0 },       // 13 IWDG_PR (read; KR write is row 5.8)
    P { addr: 0x4001_3008, mask: 0 },       // 14 SPI1_CFG1 (read)
];

/// Per probe: `[read_value, tzic_after_read, ns_pre_write, ns_post_write, tzic_after_write]`.
#[used]
#[no_mangle]
pub static mut GTZC_SHIP_RES: [[u32; 5]; 15] = [[0; 5]; 15];
/// `[magic 0x6752_0302, probes done, tzic baseline, tzic final, unlocked]`.
#[used]
#[no_mangle]
pub static GTZC_SHIP_HDR: [AtomicU32; 5] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

fn settle() {
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    for _ in 0..5_000 {
        cortex_m::asm::nop();
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    GTZC_SHIP_HDR[4].store(u32::from(nsc_api::is_unlocked()), Ordering::Relaxed);
    GTZC_SHIP_HDR[2].store(nsc_api::tzic_status(), Ordering::Relaxed);
    GTZC_SHIP_HDR[0].store(0x6752_0302, Ordering::Relaxed);
    for (i, p) in PROBES.iter().enumerate() {
        // SAFETY: each address is a 4-byte-aligned register of a peripheral
        // in the NS peripheral alias; the access is the probe under test, on
        // a mock-SE bench image that holds no secret.
        let v = unsafe { core::ptr::read_volatile(p.addr as *const u32) };
        settle();
        let t_read = nsc_api::tzic_status();
        let (pre, post) = if p.mask != 0 {
            // SAFETY: as above.
            unsafe {
                let pre = core::ptr::read_volatile(p.addr as *const u32);
                core::ptr::write_volatile(p.addr as *mut u32, pre ^ p.mask);
                settle();
                (pre, core::ptr::read_volatile(p.addr as *const u32))
            }
        } else {
            (0, 0)
        };
        settle();
        let t_write = nsc_api::tzic_status();
        // SAFETY: single-threaded runner; the host reads below the done count.
        unsafe { GTZC_SHIP_RES[i] = [v, t_read, pre, post, t_write] };
        GTZC_SHIP_HDR[1].store(i as u32 + 1, Ordering::Release);
    }
    GTZC_SHIP_HDR[3].store(nsc_api::tzic_status(), Ordering::Release);
    // Park without WFI so SWD can read the secure aliases at any time.
    loop {
        cortex_m::asm::nop();
    }
}
