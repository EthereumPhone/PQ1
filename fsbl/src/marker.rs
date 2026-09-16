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
}

/// Record `stage` with a 32-bit `payload` for context (e.g. the floor value).
///
/// Best-effort and infallible on purpose: a diagnostic must not alter the
/// control flow it measures, so programming errors are swallowed. The readback
/// already distinguishes "not reached" (still `0xFF`) from "reached" (the tag),
/// so no success signal is needed here.
pub fn record(stage: Stage, payload: u32) {
    let tag: u32 = 0x5247_4D00 | (stage as u32); // b"MGR" | stage
    let qw = [tag, payload, !tag, stage as u32];

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
            // `stage <= 12` bounds the target to the first 208 bytes of the
            // erased 8 KB page, 16-byte aligned as the controller requires.
            wr(dst + i * 4, *word);
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
