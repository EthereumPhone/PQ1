//! DVT row 3.11: can the non-secure world change what is signed by
//! rewriting the caller's buffer while a sign is in flight (TOCTOU)?
//!
//! Four `sign_userop` calls over the same transaction (the one
//! `tools/verify-c10-sig` rebuilds: to `0x11 x 20`, 1e15 wei):
//!
//! 0. baseline, no interference (positive control);
//! 1. ISR: a 1 ms non-secure SysTick flips `to` and `value` in the caller's
//!    payload between the original and an alternate transaction (to
//!    `0xBB x 20`, 2e15 wei) on every tick from [`START_TICKS`] ms into the
//!    call, i.e. after the secure entry copy;
//! 2. DMA: from the same tick, a privileged non-secure GPDMA channel loops
//!    over two linked-list items forever, copying the alternate and then the
//!    original 52 bytes over `to || value`, for the rest of the call. The
//!    SysTick samples the buffer to prove the bytes really move;
//! 3. informational: the same DMA loop started BEFORE the call, so it races
//!    the entry copy itself. That tears the snapshot (the display and the
//!    signature then share the torn bytes), so this response is expected to
//!    verify over neither transaction; it is recorded, not judged.
//!
//! The secure side must sign the transaction it snapshotted at entry, so
//! responses 0-2 must verify over the ORIGINAL transaction and not over the
//! alternate one (`verify-c10-sig` checks both).
//!
//! No semihosting: the probe stays detached; results and the three responses
//! are read over SWD (`tools/dvt/toctou.py`). Pairs with a `mock-se,e2e-test`
//! secure image.

use super::{build_payload, cycles_now, CYC_PER_MS, FOLLOWUP_TO, FOLLOWUP_VALUE_WEI, OUTER_TO, OUTER_VALUE_WEI};
use super::{PAYLOAD_BUF, SIG_BUF};
use crate::nsc_api;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// `to` (20) then `value` (32) inside the unified sign header.
const FIELD_OFF: usize = 276;
const FIELD_LEN: usize = 52;
/// Response length for this transaction (no initCode, no Type-1).
const RESP_LEN: usize = 4148;
const PHASES: usize = 4;
/// Phases 1 and 2 start interfering this many 1 ms ticks into the call. The
/// entry copy runs after a ~41 KB buffer wipe and FI delays, so it can end
/// later than the first tick; 20 ms is well past it.
const START_TICKS: u32 = 20;

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

const GPDMA1_NS: u32 = 0x4002_0000;
const CH: u32 = 6;
const PRIVCFGR: u32 = GPDMA1_NS + 0x04;
const CLBAR: u32 = GPDMA1_NS + 0x50 + 0x80 * CH;
const CFCR: u32 = GPDMA1_NS + 0x5C + 0x80 * CH;
const CSR: u32 = GPDMA1_NS + 0x60 + 0x80 * CH;
const CCR: u32 = GPDMA1_NS + 0x64 + 0x80 * CH;
const CTR1: u32 = GPDMA1_NS + 0x90 + 0x80 * CH;
const CTR2: u32 = GPDMA1_NS + 0x94 + 0x80 * CH;
const CBR1: u32 = GPDMA1_NS + 0x98 + 0x80 * CH;
const CSAR: u32 = GPDMA1_NS + 0x9C + 0x80 * CH;
const CDAR: u32 = GPDMA1_NS + 0xA0 + 0x80 * CH;
const CLLR: u32 = GPDMA1_NS + 0xCC + 0x80 * CH;
const RCC_AHB1ENR_NS: u32 = 0x4602_0C00 + 0x088;
/// Byte beats (the payload is not word aligned), SINC | DINC.
const TR1_BYTES: u32 = (1 << 19) | (1 << 3);
const TR2_SWREQ: u32 = 1 << 9;
/// `CxLLR` update flags: UB1 | USA | UDA | ULL. The LLI then holds, in this
/// order, `CBR1, CSAR, CDAR, CLLR`.
const LLR_UPDATE: u32 = (1 << 29) | (1 << 28) | (1 << 27) | (1 << 16);

#[repr(C, align(4))]
struct Lli([u32; 4]);

static mut LLI_A: Lli = Lli([0; 4]);
static mut LLI_B: Lli = Lli([0; 4]);
static mut ORIG: [u8; FIELD_LEN] = [0; FIELD_LEN];
static mut ALT: [u8; FIELD_LEN] = [0; FIELD_LEN];

/// The three responses, read over SWD.
#[used]
#[no_mangle]
static mut TOCTOU_RESP: [[u8; RESP_LEN]; PHASES] = [[0; RESP_LEN]; PHASES];
/// Per phase: `[status, ms, isr_flips, samples_orig, samples_alt, samples_other, dma_csr_at_stop, ticks]`.
#[used]
#[no_mangle]
static mut TOCTOU_RES: [[u32; 8]; PHASES] = [[0; 8]; PHASES];
/// `[magic 0x70C7_0311, phases done, unlocked, GPDMA PRIVCFGR]`.
#[used]
#[no_mangle]
static TOCTOU_HDR: [AtomicU32; 4] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static PHASE: AtomicU32 = AtomicU32::new(0);
static TICKS: AtomicU32 = AtomicU32::new(0);
static FLIPS: AtomicU32 = AtomicU32::new(0);
static S_ORIG: AtomicU32 = AtomicU32::new(0);
static S_ALT: AtomicU32 = AtomicU32::new(0);
static S_OTHER: AtomicU32 = AtomicU32::new(0);
static DMA_ON: AtomicBool = AtomicBool::new(false);

fn rd(a: u32) -> u32 {
    // SAFETY: a GPDMA1/RCC non-secure register address from the constants above.
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

fn wr(a: u32, v: u32) {
    // SAFETY: as `rd`.
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}

fn field_ptr() -> *mut u8 {
    // SAFETY: in bounds of the 330-byte header buffer.
    unsafe { core::ptr::addr_of_mut!(PAYLOAD_BUF).cast::<u8>().add(FIELD_OFF) }
}

fn write_field(src: &[u8; FIELD_LEN]) {
    for (i, b) in src.iter().enumerate() {
        // SAFETY: FIELD_OFF + FIELD_LEN <= SIGN_USEROP_HEADER_LEN.
        unsafe { core::ptr::write_volatile(field_ptr().add(i), *b) };
    }
}

fn dma_start() {
    // SAFETY: single caller (the SysTick handler, once per phase); the LLIs
    // and patterns are NS statics only this module touches.
    unsafe {
        let dst = field_ptr() as u32;
        let a = core::ptr::addr_of!(LLI_A) as u32;
        let b = core::ptr::addr_of!(LLI_B) as u32;
        let orig = core::ptr::addr_of!(ORIG) as u32;
        let alt = core::ptr::addr_of!(ALT) as u32;
        // A copies ALT then links to B; B copies ORIG then links to A.
        LLI_A.0 = [FIELD_LEN as u32, alt, dst, LLR_UPDATE | (b & 0xFFFC)];
        LLI_B.0 = [FIELD_LEN as u32, orig, dst, LLR_UPDATE | (a & 0xFFFC)];
        cortex_m::asm::dsb();
        wr(CCR, 1 << 1);
        wr(CFCR, 0x7F00);
        wr(CLBAR, a & 0xFFFF_0000);
        wr(CTR1, TR1_BYTES);
        wr(CTR2, TR2_SWREQ);
        wr(CBR1, FIELD_LEN as u32);
        wr(CSAR, alt);
        wr(CDAR, dst);
        wr(CLLR, LLR_UPDATE | (b & 0xFFFC));
        cortex_m::asm::dsb();
        wr(CCR, 1);
    }
}

fn dma_stop() -> u32 {
    let csr = rd(CSR);
    wr(CCR, 1 << 1);
    cortex_m::asm::dsb();
    csr
}

fn sample() {
    // SAFETY: byte read of the payload buffer.
    let b0 = unsafe { core::ptr::read_volatile(field_ptr()) };
    match b0 {
        0x11 => S_ORIG.fetch_add(1, Ordering::Relaxed),
        0xBB => S_ALT.fetch_add(1, Ordering::Relaxed),
        _ => S_OTHER.fetch_add(1, Ordering::Relaxed),
    };
}

#[cortex_m_rt::exception]
fn SysTick() {
    let t = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if !IN_FLIGHT.load(Ordering::SeqCst) {
        return;
    }
    let phase = PHASE.load(Ordering::Relaxed);
    if phase == 3 {
        sample();
        return;
    }
    if t < START_TICKS {
        return;
    }
    match phase {
        1 => {
            let n = FLIPS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the patterns are written once before the phase starts.
            unsafe { write_field(if n % 2 == 0 { &*core::ptr::addr_of!(ALT) } else { &*core::ptr::addr_of!(ORIG) }) };
        }
        2 => {
            if !DMA_ON.swap(true, Ordering::SeqCst) {
                dma_start();
            }
            sample();
        }
        _ => {}
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    TOCTOU_HDR[2].store(u32::from(nsc_api::is_unlocked()), Ordering::Relaxed);
    let mut sender = [0u8; 20];
    if nsc_api::get_wallet_address(&mut sender, 0, 0) != 0 {
        TOCTOU_HDR[0].store(0xE1, Ordering::Relaxed);
        loop {
            cortex_m::asm::nop();
        }
    }
    // SAFETY: single-threaded setup before SysTick starts.
    unsafe {
        build_payload(&mut PAYLOAD_BUF, &sender, &FOLLOWUP_TO, FOLLOWUP_VALUE_WEI);
        ALT.copy_from_slice(&PAYLOAD_BUF[FIELD_OFF..FIELD_OFF + FIELD_LEN]);
        build_payload(&mut PAYLOAD_BUF, &sender, &OUTER_TO, OUTER_VALUE_WEI);
        ORIG.copy_from_slice(&PAYLOAD_BUF[FIELD_OFF..FIELD_OFF + FIELD_LEN]);
    }
    wr(RCC_AHB1ENR_NS, rd(RCC_AHB1ENR_NS) | 1);
    wr(PRIVCFGR, rd(PRIVCFGR) | 1 << CH);
    TOCTOU_HDR[3].store(rd(PRIVCFGR), Ordering::Relaxed);
    TOCTOU_HDR[0].store(0x70C7_0311, Ordering::Relaxed);
    // SAFETY: the non-secure SysTick (banked); 1 ms at 160 MHz.
    unsafe {
        core::ptr::write_volatile(SYST_RVR, CYC_PER_MS - 1);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0b111);
    }

    for phase in 0..PHASES as u32 {
        // SAFETY: SysTick touches the payload only while IN_FLIGHT.
        unsafe { write_field(&*core::ptr::addr_of!(ORIG)) };
        for c in [&FLIPS, &S_ORIG, &S_ALT, &S_OTHER, &TICKS] {
            c.store(0, Ordering::Relaxed);
        }
        DMA_ON.store(false, Ordering::SeqCst);
        PHASE.store(phase, Ordering::Relaxed);
        if phase == 3 {
            DMA_ON.store(true, Ordering::SeqCst);
            dma_start();
        }
        let t0 = cycles_now();
        IN_FLIGHT.store(true, Ordering::SeqCst);
        // SAFETY: the buffers are NS statics; the SysTick/DMA writes to the
        // payload during the call ARE the test.
        let st = unsafe {
            nsc_api::sign_userop(&*core::ptr::addr_of!(PAYLOAD_BUF), &mut *core::ptr::addr_of_mut!(SIG_BUF))
        };
        IN_FLIGHT.store(false, Ordering::SeqCst);
        let ms = cycles_now().wrapping_sub(t0) / CYC_PER_MS;
        let csr = if DMA_ON.load(Ordering::SeqCst) { dma_stop() } else { 0 };
        // SAFETY: single-threaded again (IN_FLIGHT is false).
        unsafe {
            TOCTOU_RESP[phase as usize].copy_from_slice(&SIG_BUF[..RESP_LEN]);
            TOCTOU_RES[phase as usize] = [
                st,
                ms,
                FLIPS.load(Ordering::Relaxed),
                S_ORIG.load(Ordering::Relaxed),
                S_ALT.load(Ordering::Relaxed),
                S_OTHER.load(Ordering::Relaxed),
                csr,
                TICKS.load(Ordering::Relaxed),
            ];
        }
        TOCTOU_HDR[1].store(phase + 1, Ordering::Release);
    }
    loop {
        cortex_m::asm::nop();
    }
}
