//! STM32U585 HASH peripheral driver — SHA-256 only.
//!
//! Used exclusively under the `sha256-hash` feature on `sphincs-tz-secure`
//! to replace the software Keccak-256 in `sphincs-c7` and `jardin-fosc`
//! with hardware-accelerated SHA-256. The HASH peripheral runs at roughly
//! 1 cycle/byte (single-block) vs ~12 cycles/byte for Keccak-asm, which
//! dominates FORS+C signing wall time.
//!
//! Register layout is the STM32U5 HASH v4 (same IP as STM32H5 / WBA55).
//! Confirmed against Linux `drivers/crypto/stm32/stm32-hash.c`.
//!
//! This module provides three extern "C" symbols that `sphincs-c7` and
//! `jardin-fosc` call when compiled with `sha256-hash`:
//!
//!   pqsigner_sha256_init()
//!   pqsigner_sha256_update(ptr, len)
//!   pqsigner_sha256_final(out_ptr)
//!
//! The underlying implementation is single-threaded and uses static state
//! (the peripheral itself, plus a 4-byte merge buffer for non-word-aligned
//! streaming updates). Signing is called from one thread only; the secure
//! world is non-preemptive, so no locking is required.

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register map — STM32U585 HASH @ AHB2 0x520C_0400 (secure alias).
// Base = PERIPH_BASE_S (0x5000_0000) + AHB2 offset (0x0202_0000) + HASH
// offset (0xA_0400). Confirmed against STMicro cmsis-device-u5 header
// (HASH_BASE_NS = 0x420C_0400 / HASH_BASE_S = 0x520C_0400).
// TZSC default-secure blocks NS-alias access to HASH from any state, so
// the secure world must use the S alias.
// ---------------------------------------------------------------------------

const HASH: u32 = 0x520C_0400;
const HASH_CR: *mut u32 = (HASH + 0x00) as *mut u32;
const HASH_DIN: *mut u32 = (HASH + 0x04) as *mut u32;
const HASH_STR: *mut u32 = (HASH + 0x08) as *mut u32;
const HASH_SR: *mut u32 = (HASH + 0x24) as *mut u32;
// HASH_HR0 lives in the HASH_DIGEST block at HASH_BASE + 0x310.
const HASH_HR0: *const u32 = (HASH + 0x310) as *const u32;

// RCC @ RCC_BASE_S = 0x5602_0C00 (AHB3 secure). HASHEN / HASHRST = bit 17
// in AHB2ENR1 / AHB2RSTR1 (confirmed RCC_AHB2ENR1_HASHEN_Pos = 17 in CMSIS).
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_AHB2RSTR1: *mut u32 = (RCC_S + 0x64) as *mut u32;
const RCC_HASHEN: u32 = 1 << 17;
const RCC_HASHRST: u32 = 1 << 17;

// HASH_CR bit positions (confirmed against stm32u585xx.h CMSIS header).
// ALGO is a 2-bit field at bits 17-18 on STM32U5 (NOT the bit-7+17 encoding
// used on STM32MP13). SHA-256 = ALGO=0b11 → bits 17 AND 18.
const CR_INIT: u32 = 1 << 2;
const CR_DATATYPE_8B: u32 = 0b10 << 4; // byte-swap within word -> natural byte order
const CR_ALGO_SHA256: u32 = (1 << 17) | (1 << 18);

// HASH_SR bits
const SR_DINIS: u32 = 1 << 0; // DIN not full
const SR_DCIS: u32 = 1 << 1; // digest calculation complete
const SR_BUSY: u32 = 1 << 3;

// HASH_STR bits
const STR_DCAL: u32 = 1 << 8;

// ---------------------------------------------------------------------------
// Streaming state: 4-byte merge buffer for sub-word updates.
// ---------------------------------------------------------------------------

struct State {
    buf: [u8; 4],
    pending: u8, // 0..=3
}

static mut STATE: State = State {
    buf: [0; 4],
    pending: 0,
};

/// Enable HASH peripheral clock. Call once during boot. Safe to call twice.
pub unsafe fn init_clock() {
    // Enable HASH clock (AHB2ENR1.HASHEN).
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | RCC_HASHEN);
    cortex_m::asm::dsb();
    // Pulse HASHRST to reach a clean state if a previous firmware image
    // left the peripheral mid-hash.
    let rstr = read_volatile(RCC_AHB2RSTR1);
    write_volatile(RCC_AHB2RSTR1, rstr | RCC_HASHRST);
    cortex_m::asm::dsb();
    write_volatile(RCC_AHB2RSTR1, rstr & !RCC_HASHRST);
    cortex_m::asm::dsb();
    // Quick known-answer check: SHA-256("abc"). Halts on failure so a
    // silently-broken HW accel doesn't produce wrong signatures.
    self_test();
}

unsafe fn self_test() {
    pqsigner_sha256_init();
    pqsigner_sha256_update(b"abc".as_ptr(), 3);
    let mut out = [0u8; 32];
    pqsigner_sha256_final(out.as_mut_ptr());
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    if out == expected {
        cortex_m_semihosting::hprintln!("[S] hash: HW SHA-256 self-test PASS");
    } else {
        cortex_m_semihosting::hprintln!("[S] hash: HW SHA-256 self-test FAIL — HALT");
        loop { cortex_m::asm::wfe(); }
    }
}

#[inline]
unsafe fn wait_ready() {
    let mut t = 0u32;
    while read_volatile(HASH_SR) & SR_BUSY != 0 {
        t += 1;
        if t > 10_000_000 {
            cortex_m_semihosting::hprintln!(
                "[S] hash: wait_ready TIMEOUT, SR={:#x}",
                read_volatile(HASH_SR)
            );
            return;
        }
    }
}

#[inline]
unsafe fn write_word(w: u32) {
    // Per Linux stm32-hash.c: push unconditionally. The AHB bus will stall
    // transparently if the internal FIFO is full. Polling DINIS between
    // every word misinterprets "DIN FIFO temporarily saturated" (which is
    // fine — the HASH auto-processes and re-arms) as "don't push".
    write_volatile(HASH_DIN, w);
}

// ---------------------------------------------------------------------------
// Extern symbols — called from `sphincs-c7` and `jardin-fosc`.
// ---------------------------------------------------------------------------

/// Start a new SHA-256 computation.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_init() {
    wait_ready();
    STATE.buf = [0; 4];
    STATE.pending = 0;
    // Pulse HASHRST in RCC before every new hash. Setting INIT=1 in HASH_CR
    // alone is NOT enough on STM32U5: after a completed hash the internal
    // FIFO counters stay in a state where the next block can't be pushed.
    // RSTR wipes the whole peripheral state back to cold-boot values.
    let rstr = read_volatile(RCC_AHB2RSTR1);
    write_volatile(RCC_AHB2RSTR1, rstr | RCC_HASHRST);
    cortex_m::asm::dsb();
    write_volatile(RCC_AHB2RSTR1, rstr & !RCC_HASHRST);
    cortex_m::asm::dsb();
    // HASH mode (MODE=0), 8-bit datatype, SHA-256, INIT=1.
    write_volatile(HASH_CR, CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    cortex_m::asm::dsb();
}

/// Feed `len` bytes from `ptr` into the current SHA-256 computation.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
    let data = core::slice::from_raw_parts(ptr, len);
    let mut i = 0;

    // Fill the pending merge buffer first.
    while STATE.pending != 0 && i < data.len() {
        STATE.buf[STATE.pending as usize] = data[i];
        STATE.pending += 1;
        i += 1;
        if STATE.pending == 4 {
            let w = u32::from_le_bytes(STATE.buf);
            write_word(w);
            STATE.pending = 0;
        }
    }

    // Feed full 32-bit words directly. Data may be unaligned; read byte-wise.
    while data.len() - i >= 4 {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        write_word(w);
        i += 4;
    }

    // Buffer the trailing 0..=3 bytes.
    while i < data.len() {
        STATE.buf[STATE.pending as usize] = data[i];
        STATE.pending += 1;
        i += 1;
    }
}

/// Finalize the current SHA-256 computation and write 32 bytes to `out`.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
    let remaining_bits = (STATE.pending as u32) * 8;
    if STATE.pending != 0 {
        // Pad with zeros in unused bytes of the last word.
        for i in STATE.pending..4 {
            STATE.buf[i as usize] = 0;
        }
        let w = u32::from_le_bytes(STATE.buf);
        write_word(w);
    }
    // Match the STM32 HAL order exactly: set NBLW first (clearing DCAL),
    // THEN set DCAL in a separate write. Some combinations of the U5 HASH
    // IP reportedly latch NBLW incorrectly if DCAL is set in the same cycle.
    write_volatile(HASH_STR, remaining_bits);
    cortex_m::asm::dsb();
    write_volatile(HASH_STR, remaining_bits | STR_DCAL);

    // Wait for digest.
    let mut t = 0u32;
    while read_volatile(HASH_SR) & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            cortex_m_semihosting::hprintln!(
                "[S] hash: DCIS TIMEOUT, SR={:#x} CR={:#x} STR={:#x} remaining_bits={}",
                read_volatile(HASH_SR),
                read_volatile(HASH_CR),
                read_volatile(HASH_STR),
                remaining_bits
            );
            return;
        }
    }

    // Read 8 words from HR[0..8]. Per DATATYPE=10 convention the HR
    // registers hold each 4-byte digest chunk in natural byte order when
    // interpreted via to_be_bytes on the little-endian CPU.
    for i in 0..8 {
        let w = read_volatile(HASH_HR0.add(i));
        let bytes = w.to_be_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i * 4), 4);
    }

    // Clear DCIS (write 0 to bit 1 per STM32U5 RM — SR.DCIS is rc_w0).
    let sr = read_volatile(HASH_SR);
    write_volatile(HASH_SR, sr & !SR_DCIS);

    STATE.pending = 0;
}
