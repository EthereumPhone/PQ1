//! Non-secure GPDMA isolation probe (`dma-probe`, DVT row 3.9).
//!
//! Programs one GPDMA1 channel from the non-secure alias as a 16-byte
//! memory-to-memory copy (software request) for each case in [`CASES`]:
//! reads from secure SRAM1/SRAM3, secure and NS-alias flash, the OTP, and
//! writes into secure SRAM1 through both aliases, plus NS-to-NS positive
//! controls. For each case it stores the channel status word and the first
//! four destination words in `DMA_PROBE_RES`. Nothing is printed: the host
//! reads the statics over SWD (`tools/dvt/dma_probe.py`), and for the write
//! cases compares the secure target words before and after.
//!
//! Expected: every case that touches secure memory ends with a transfer
//! error (`DTEF`/`USEF`) or copies nothing readable, and no secure word
//! changes. The NS-to-NS controls complete (`TCF`) with the source bytes.
//!
//! The secure image needs nothing from this runner (no gateway call beyond
//! `is_unlocked`). Channel 5 is used so the secure pixel blit (channel 0,
//! `ui-px` only) is never touched.

#![allow(static_mut_refs)]

use core::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" {
    fn nsc_is_unlocked() -> u32;
}

/// GPDMA1, non-secure alias.
const GPDMA1_NS: u32 = 0x4002_0000;
const CH: u32 = 5;
const CFCR: u32 = GPDMA1_NS + 0x5C + 0x80 * CH;
const CSR: u32 = GPDMA1_NS + 0x60 + 0x80 * CH;
const CCR: u32 = GPDMA1_NS + 0x64 + 0x80 * CH;
const CTR1: u32 = GPDMA1_NS + 0x90 + 0x80 * CH;
const CTR2: u32 = GPDMA1_NS + 0x94 + 0x80 * CH;
const CBR1: u32 = GPDMA1_NS + 0x98 + 0x80 * CH;
const CSAR: u32 = GPDMA1_NS + 0x9C + 0x80 * CH;
const CDAR: u32 = GPDMA1_NS + 0xA0 + 0x80 * CH;
const CLLR: u32 = GPDMA1_NS + 0xCC + 0x80 * CH;
/// `RCC_AHB1ENR`, non-secure alias (`GPDMA1EN` is bit 0).
const RCC_AHB1ENR_NS: u32 = 0x4602_0C00 + 0x088;
/// `GPDMA_PRIVCFGR`: bit `CH` makes the channel's bus accesses privileged.
const PRIVCFGR: u32 = GPDMA1_NS + 0x04;

/// Word source and destination, both incrementing (SDW_LOG2 = DDW_LOG2 = 2,
/// SINC, DINC). SSEC/DSEC stay 0: a non-secure channel cannot set them.
const TR1_VAL: u32 = 0x000A_000A;
/// SWREQ: memory-to-memory, no peripheral request.
const TR2_VAL: u32 = 1 << 9;
const FCR_ALL: u32 = 0x0000_7F00;
const SR_IDLEF: u32 = 1 << 0;
const SR_TCF: u32 = 1 << 8;
const SR_ERR: u32 = (1 << 10) | (1 << 11) | (1 << 12); // DTEF | ULEF | USEF
const CR_EN: u32 = 1 << 0;
const CR_RESET: u32 = 1 << 1;
const LEN: u32 = 16;

/// Source pattern for the NS positive controls and the write cases.
#[used]
#[no_mangle]
pub static mut DMA_PROBE_SRC: [u32; 4] = [0xA11C_E001, 0xA11C_E002, 0xA11C_E003, 0xA11C_E004];
/// Destination for the read cases, refilled with this sentinel before each.
#[used]
#[no_mangle]
pub static mut DMA_PROBE_DST: [u32; 4] = [0; 4];
const SENTINEL: u32 = 0x5EE5_5EE5;

/// `(source, destination)` per case; `0` in either slot means "the NS
/// buffer" (`DMA_PROBE_SRC` as source, `DMA_PROBE_DST` as destination).
const CASES: [(u32, u32); 14] = [
    (0, 0),                    // 0  control: NS SRAM2 -> NS SRAM2
    (0x3000_0000, 0),          // 1  secure SRAM1 (secure alias), start
    (0x2000_0000, 0),          // 2  SRAM1 via the NS alias
    (0x3002_FF00, 0),          // 3  secure stack region (secure alias)
    (0x3004_0000, 0),          // 4  SRAM3, secure alias
    (0x2004_0000, 0),          // 5  SRAM3, NS alias
    (0x0C00_0000, 0),          // 6  secure flash (FSBL / secure image)
    (0x0800_0000, 0),          // 7  bank-1 flash, NS alias
    (0x0BFA_0000, 0),          // 8  OTP
    (0, 0x3001_FF00),          // 9  WRITE into secure SRAM1, secure alias
    (0, 0x2001_FF10),          // 10 WRITE into SRAM1 via the NS alias
    (0, 0),                    // 11 control again: the channel still works after the faults
    (0x0BFA_0700, 0),          // 12 device UID (same system area as the OTP, known non-FF value)
    (0x0BFA_01F0, 0),          // 13 last OTP quad-word
];

/// Per case: `[csr_at_end, dst0, dst1, dst2, dst3, spins]`. Pass 0 runs the
/// cases with the channel unprivileged (its reset state), pass 1 privileged.
#[used]
#[no_mangle]
pub static mut DMA_PROBE_RES: [[u32; 6]; 2 * CASES.len()] = [[0; 6]; 2 * CASES.len()];
/// `[magic 0xD3A9_0309, cases done, RCC_AHB1ENR read-back after the NS set,
/// unlocked, GPDMA_PRIVCFGR read-back after the NS set]`.
#[used]
#[no_mangle]
pub static DMA_PROBE_HDR: [AtomicU32; 5] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

fn rd(a: u32) -> u32 {
    // SAFETY: a GPDMA1/RCC non-secure register address from the constants above.
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

fn wr(a: u32, v: u32) {
    // SAFETY: as `rd`.
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}

fn run_case(src: u32, dst: u32) -> [u32; 6] {
    // SAFETY: single-threaded runner; the buffers are only read by the host.
    let (src, dst) = unsafe {
        for w in DMA_PROBE_DST.iter_mut() {
            core::ptr::write_volatile(w, SENTINEL);
        }
        (
            if src == 0 { DMA_PROBE_SRC.as_ptr() as u32 } else { src },
            if dst == 0 { DMA_PROBE_DST.as_mut_ptr() as u32 } else { dst },
        )
    };
    wr(CCR, CR_RESET);
    wr(CFCR, FCR_ALL);
    wr(CLLR, 0);
    wr(CTR1, TR1_VAL);
    wr(CTR2, TR2_VAL);
    wr(CBR1, LEN);
    wr(CSAR, src);
    wr(CDAR, dst);
    cortex_m::asm::dsb();
    wr(CCR, CR_EN);
    let mut spins = 0u32;
    let mut csr = rd(CSR);
    while csr & (SR_TCF | SR_ERR) == 0 && spins < 1_000_000 {
        spins += 1;
        csr = rd(CSR);
    }
    // Let a still-running channel settle, then stop it.
    if csr & SR_IDLEF == 0 {
        wr(CCR, CR_RESET);
    }
    cortex_m::asm::dsb();
    // SAFETY: as above.
    let d = unsafe { [0, 1, 2, 3].map(|i| core::ptr::read_volatile(&DMA_PROBE_DST[i])) };
    wr(CFCR, FCR_ALL);
    [csr, d[0], d[1], d[2], d[3], spins]
}

#[cortex_m_rt::entry]
fn main() -> ! {
    // SAFETY: the veneer is a plain query.
    let unlocked = unsafe { nsc_is_unlocked() };
    DMA_PROBE_HDR[3].store(unlocked, Ordering::Relaxed);
    wr(RCC_AHB1ENR_NS, rd(RCC_AHB1ENR_NS) | 1);
    cortex_m::asm::dsb();
    DMA_PROBE_HDR[2].store(rd(RCC_AHB1ENR_NS), Ordering::Relaxed);
    DMA_PROBE_HDR[0].store(0xD3A9_0309, Ordering::Relaxed);
    for pass in 0..2 {
        if pass == 1 {
            wr(PRIVCFGR, rd(PRIVCFGR) | 1 << CH);
            cortex_m::asm::dsb();
            DMA_PROBE_HDR[4].store(rd(PRIVCFGR), Ordering::Relaxed);
        }
        for (i, &(s, d)) in CASES.iter().enumerate() {
            let n = pass * CASES.len() + i;
            let r = run_case(s, d);
            // SAFETY: single-threaded; the host reads below the done count.
            unsafe { DMA_PROBE_RES[n] = r };
            DMA_PROBE_HDR[1].store(n as u32 + 1, Ordering::Release);
        }
    }
    loop {
        cortex_m::asm::wfi();
    }
}
