//! Stage markers for diagnosing a silent FSBL rejection (`stage-marker`).
//!
//! **Bench diagnostic only — never ships.** This is the only module that makes
//! the FSBL *write* flash, which the production design forbids (invariant #10:
//! the FSBL range is WRP-protected and the FSBL owns no flash or option-byte
//! mutation). The `compile_error!` below keeps it out of any production build,
//! and the feature is default-off so every normal `make fsbl` is byte-identical
//! to before.
//!
//! Why it exists: the FSBL halts SILENTLY when no slot is admissible — it has
//! no logging by construction — and on this bench live core state proved
//! unobservable. The only debug-attach mode that reproduces known-good flash
//! hashes (`mode=UR`) always resets the core, so sampling RCC/VTOR cannot
//! distinguish "parked before admission" from "never ran". So the FSBL records
//! its own progress where a validated reader can see it.
//!
//! Target: one quad-word per stage in the ERASED manifest-B page. That page is
//! inert in the single-candidate bring-up layout — `filter_valid` rejects its
//! contents with `BadMagic`, confirmed on silicon — so markers can never turn
//! into a boot candidate.
//!
//! Read them back with a validated session (control first!):
//! ```text
//! STM32_Programmer_CLI --connect port=SWD mode=UR --read 0x0C00A000 0x80 m.bin
//! ```
//!
//! The register sequence mirrors `secure/src/hw/flash.rs::write_raw`, which is
//! proven on this silicon: it programs bank-1 pages while executing from bank 1,
//! exactly the same-bank case this needs. Two deviations each cost a bring-up
//! cycle, so don't: omitting the ICACHE invalidate makes the readback return
//! STALE CACHED bytes while flash itself is correct, and driving the NS alias of
//! these registers from secure code returns PGSERR.

#![cfg(feature = "stage-marker")]

#[cfg(feature = "mode-production")]
compile_error!(
    "FSBL_STAGE_MARKER_IS_BENCH_ONLY: `stage-marker` gives the FSBL a flash-write \
     path, which invariant #10 forbids in a shipping image. It is a bring-up \
     diagnostic for the silent-rejection bug; never enable it for production."
);

use core::ptr::{read_volatile, write_volatile};

/// Marker page: manifest B (bank-1 page 5), erased in this layout.
const MARKER_PAGE: usize = 0x0C00_A000;

const FLASH_S: usize = 0x5002_2000;
const SECKEYR: usize = FLASH_S + 0x0C;
const SECSR: usize = FLASH_S + 0x24;
const SECCR: usize = FLASH_S + 0x2C;

const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;
const PG: u32 = 1 << 0;
const LOCK: u32 = 1 << 31;
const BSY: u32 = 1 << 16;
const ERR_MASK: u32 = 0xFA;

const ICACHE_CR: usize = 0x5003_0400;
const ICACHE_SR: usize = 0x5003_0404;
const ICACHE_CR_CACHEINV: u32 = 1 << 1;
const ICACHE_SR_BUSYF: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// DWT cycle counter — per-stage timestamps
// ---------------------------------------------------------------------------
//
// Why: the FSBL boot budget was documented as "~3 s", then estimated at ~17 s,
// and is MEASURED at 39.4 s. Deciding whether to raise the FSBL clock or port
// the HASH peripheral on estimates is backwards, so the boot measures itself.
//
// First measurement (pq1, 2026-09-16, MainEntered -> Branching = 39.37 s):
//
//   24.00 s  61%  the fingerprint hold      (delay_ms(3000), PURE WAITING)
//    8.41 s  21%  Lcd::init()               (~6.8 s of it also delay_ms)
//    4.67 s  12%  SHA-256 over the secure image (385,568 B)
//    1.50 s   4%  filter_valid (CRC/digest/fpr/C10 SIGNATURE/rollback)
//    0.70 s   2%  the 16x4 glyph blit
//    0.09 s   0%  SHA-256 over the NS image (7,488 B)
//
// Headline: 30.8 s (78%) is `delay_ms` nop-spinning, only 8.6 s is computation.
// `delay_ms` runs 8x long — 4,000 iterations at 8 cycles/iteration on a 4 MHz
// part is 8 ms per nominal millisecond, where the constant assumed 4 cycles at
// 16 MHz. So the cheap win is the calibration constant, not the clock.
//
// Two independent checks that the 4 MHz clock is real rather than assumed: the
// hold resolves to 8.00 cycles per nop-loop iteration, and software SHA-256 to
// ~3,099 cycles/block. At 16 MHz those would be 32 cycles/iteration (impossible
// for a loop containing one nop) and ~12,400 cycles/block (implausibly slow).
//
// Register sequence mirrors `secure/src/main.rs`, which is validated on this
// silicon. `DSCSR.CDS` is deliberately NOT touched: that is only needed so the
// NON-SECURE world can read DWT on TrustZone parts, and the FSBL is secure
// throughout — one less register poked in the trust root.
//
// At 4 MHz the 32-bit counter wraps after ~1,073 s, far beyond any plausible
// boot, so no wrap handling is needed. If CYCCNT is unavailable the payload
// reads 0, which is distinguishable from a real measurement rather than
// misleading.

const DEMCR: usize = 0xE000_EDFC;
const DEMCR_TRCENA: u32 = 1 << 24;
const DWT_CTRL: usize = 0xE000_1000;
const DWT_CYCCNT: usize = 0xE000_1004;
const DWT_LAR: usize = 0xE000_1FB0;
const DWT_LAR_UNLOCK: u32 = 0xC5AC_CE55;
const DWT_CTRL_CYCCNTENA: u32 = 1 << 0;

/// Parallel timing table inside the same erased page: one quad-word per stage
/// at `TIMING_BASE + 16 * stage`, holding the `CYCCNT` value at the moment the
/// stage was reached.
///
/// Deliberately a SEPARATE table rather than repurposing the payload word: the
/// existing records carry stage-specific context (image hashes, the OTP floor,
/// the tz-1 verdict) and a `!tag` integrity word the reader validates. Both
/// tables fit trivially — 288 B each in an 8 KB page.
const TIMING_BASE: usize = MARKER_PAGE + 0x400;

/// Tag for a timing quad-word — `b"MGT"` so a reader can never confuse the two
/// tables even if it lands on the wrong offset.
const TIMING_TAG_BASE: u32 = 0x5447_4D00;

/// Start the cycle counter. Call once, before the first [`record`], or that
/// stage's timestamp is meaningless.
pub fn init_cycle_counter() {
    wr(DEMCR, rd(DEMCR) | DEMCR_TRCENA);
    wr(DWT_LAR, DWT_LAR_UNLOCK);
    wr(DWT_CYCCNT, 0);
    wr(DWT_CTRL, rd(DWT_CTRL) | DWT_CTRL_CYCCNTENA);
    cortex_m::asm::dsb();
}

#[inline(always)]
fn rd(addr: usize) -> u32 {
    // SAFETY: fixed 4-byte-aligned MMIO in the secure FLASH/ICACHE blocks;
    // pure read, single-threaded at boot.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn wr(addr: usize, val: u32) {
    // SAFETY: as `rd`; these registers are owned solely by this module while
    // it runs (interrupts are masked by the caller).
    unsafe { write_volatile(addr as *mut u32, val) }
}

/// Free-running cycle count, or 0 if the counter never started.
#[inline(always)]
fn cycles() -> u32 {
    rd(DWT_CYCCNT)
}

/// How far the boot path got. Each variant programs one quad-word at
/// `MARKER_PAGE + 16 * n`, so a readback shows exactly where the FSBL stopped.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Stage {
    /// `main()` entered — proves the FSBL executes at all.
    MainEntered = 0,
    /// Manifest pages borrowed and the OTP rollback floor read.
    FloorRead = 1,
    /// `filter_valid` accepted slot A (structure, CRC, digest, fpr, signature,
    /// rollback).
    SlotAAdmitted = 2,
    /// `verify_images` accepted slot A (both image hashes matched).
    SlotAImagesOk = 3,
    /// `pick_slot` chose a slot; about to render the fingerprint.
    SlotPicked = 4,
    /// Render returned; branching into the slot now.
    Branching = 5,
    /// `verify_images` entered; payload = manifest `secure_len`.
    ImgEntered = 6,
    /// Capacity checks passed; payload = manifest `nonsecure_len`.
    ImgLensOk = 7,
    /// Secure region hashed; payload = first 4 bytes of the COMPUTED hash.
    ImgSecureHashed = 8,
    /// NS region hashed; payload = first 4 bytes of the COMPUTED hash.
    ImgNsHashed = 9,
    /// Secure-hash comparison verdict; payload = 1 if equal.
    ImgSecureCmp = 10,
    /// NS-hash comparison verdict; payload = 1 if equal.
    ImgNsCmp = 11,
    /// `sau::init()` returned — the bank-2 NS alias is now readable by the core.
    SauConfigured = 12,
    /// About to consult the tz-1 option-byte tripwire.
    Tz1Entering = 13,
    /// tz-1 verdict; payload = 1 if the option bytes matched (boot continues).
    Tz1Verdict = 14,
    /// `render_fingerprint` entered.
    RenderEntered = 15,
    /// `Lcd::init()` returned — SPI + panel init survived.
    LcdInited = 16,
    /// Fingerprint rows drawn and flushed; only the hold delay remains.
    RenderFlushed = 17,
}

/// Record `stage` with a 32-bit `payload` for context (e.g. the floor value).
///
/// Best-effort and infallible on purpose: a diagnostic must not alter the
/// control flow it measures, so programming errors are swallowed. The readback
/// already distinguishes "not reached" (still `0xFF`) from "reached" (the tag),
/// so no success signal is needed here.
pub fn record(stage: Stage, payload: u32) {
    // FIRST, before any flash work: this timestamps ARRIVAL at the stage, not
    // completion of the programming below. Stage-to-stage deltas therefore
    // still include one flash program plus one ICACHE invalidate each —
    // ms-scale against a multi-second boot, but it is inside the measured
    // window, so do not read a delta as pure compute time.
    let t = cycles();

    let tag: u32 = 0x5247_4D00 | (stage as u32); // b"MGR" | stage
    let qw = [tag, payload, !tag, stage as u32];
    let tqw = [TIMING_TAG_BASE | (stage as u32), t, !t, stage as u32];

    cortex_m::interrupt::free(|_| {
        while rd(SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
        if rd(SECSR) & ERR_MASK != 0 {
            wr(SECSR, rd(SECSR) & ERR_MASK);
        }
        wr(SECKEYR, KEY1);
        wr(SECKEYR, KEY2);

        wr(SECCR, PG);
        let dst = MARKER_PAGE + 16 * (stage as usize);
        for (i, word) in qw.iter().enumerate() {
            // `stage <= 17` bounds the target to the first 288 bytes of the
            // erased 8 KB page, 16-byte aligned as the controller requires.
            wr(dst + i * 4, *word);
        }

        // Second quad-word, same PG window: the controller programs per
        // quad-word, and both targets are 16-byte aligned, so one unlock
        // covers both tables.
        let tdst = TIMING_BASE + 16 * (stage as usize);
        for (i, word) in tqw.iter().enumerate() {
            wr(tdst + i * 4, *word);
        }

        while rd(SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
        wr(SECCR, 0);
        wr(SECCR, LOCK);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        wr(ICACHE_CR, rd(ICACHE_CR) | ICACHE_CR_CACHEINV);
        while rd(ICACHE_SR) & ICACHE_SR_BUSYF != 0 {
            cortex_m::asm::nop();
        }
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    });
}
