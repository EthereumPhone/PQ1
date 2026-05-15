//! STM32U585 HASH peripheral driver — SHA-256 only.
//!
//! Used under the `hw-sha256` feature on `sphincs-tz-secure` to route
//! every SHA-256 call from `sphincs-c10` through the hardware accelerator.
//! The HASH peripheral runs at roughly 1 cycle/byte (single-block) —
//! significantly faster than the software `sha2::Sha256` fallback that
//! non-firmware builds use, and which dominates C10 signing wall time
//! when software is used.
//!
//! Register layout is the STM32U5 HASH v4 (same IP as STM32H5 / WBA55).
//! Confirmed against Linux `drivers/crypto/stm32/stm32-hash.c`.
//!
//! This module provides three extern "C" symbols that `sphincs-c10` calls
//! when compiled with `hw-sha256`:
//!
//!   pqsigner_sha256_init()
//!   pqsigner_sha256_update(ptr, len)
//!   pqsigner_sha256_final(out_ptr)
//!
//! The underlying implementation is single-threaded and uses static state
//! (the peripheral itself, plus a 4-byte merge buffer for non-word-aligned
//! streaming updates). Signing is called from one thread only; the secure
//! world is non-preemptive, so no locking is required.
//!
//! ## Unsafe surface
//!
//! Only the FFI boundary (`unsafe extern "C"` symbols) and `static mut
//! STATE` access remain unsafe. All MMIO is funnelled through
//! `hw::mmio::{Reg32, RoReg32}`, which encapsulates `read_volatile` /
//! `write_volatile` once per address.

use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Register map — STM32U585 HASH @ AHB2 0x520C_0400 (secure alias).
// Base = PERIPH_BASE_S (0x5000_0000) + AHB2 offset (0x0202_0000) + HASH
// offset (0xA_0400). Confirmed against STMicro cmsis-device-u5 header
// (HASH_BASE_NS = 0x420C_0400 / HASH_BASE_S = 0x520C_0400).
// TZSC default-secure blocks NS-alias access to HASH from any state, so
// the secure world must use the S alias.
// ---------------------------------------------------------------------------

const HASH_BASE: u32 = 0x520C_0400;

// RCC @ RCC_BASE_S = 0x5602_0C00 (AHB3 secure). HASHEN / HASHRST = bit 17
// in AHB2ENR1 / AHB2RSTR1 (confirmed REG.rcc_ahb2enr1_HASHEN_Pos = 17 in CMSIS).
const RCC_S: u32 = 0x5602_0C00;
const RCC_HASHEN: u32 = 1 << 17;
const RCC_HASHRST: u32 = 1 << 17;

/// All MMIO registers this driver owns, bundled so the one-time
/// `unsafe { ... }` for `Reg32::new` happens once at module scope.
struct HashRegs {
    cr: Reg32,
    din: Reg32,
    str_: Reg32,
    sr: Reg32,
    hr0: RoReg32,
    rcc_ahb2enr1: Reg32,
    rcc_ahb2rstr1: Reg32,
    /// DHCSR.C_DEBUGEN — used by `debug_log_safe` to decide whether
    /// semihosting `hprintln!` would BKPT-fault on a debugger-less board.
    dhcsr: RoReg32,
}

// SAFETY: one-time module-scope MMIO register binding. Each address
// below is a real, 4-byte-aligned MMIO register inside the HASH
// peripheral block (or the HASH-clock bit in RCC, or DHCSR for the
// debugger-present probe). All addresses are taken from CMSIS headers
// + datasheet, exclusively owned by this driver, and the secure world
// is single-threaded + non-preemptive — nothing else races us. After
// this one-time construction every register touch is via safe
// `.read()` / `.write()` methods on the `Reg32` / `RoReg32` wrappers.
const REG: HashRegs = unsafe {
    HashRegs {
        cr: Reg32::new(HASH_BASE + 0x00),
        din: Reg32::new(HASH_BASE + 0x04),
        str_: Reg32::new(HASH_BASE + 0x08),
        sr: Reg32::new(HASH_BASE + 0x24),
        // HR0 lives in the HASH_DIGEST block at HASH_BASE + 0x310.
        hr0: RoReg32::new(HASH_BASE + 0x310),
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_ahb2rstr1: Reg32::new(RCC_S + 0x64),
        dhcsr: RoReg32::new(0xE000_EDF0),
    }
};

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
///
/// # Safety
/// Must run after `rcc::init()` and before any call to the
/// `pqsigner_sha256_*` FFI symbols.
pub unsafe fn init_clock() {
    // Enable HASH clock (AHB2ENR1.HASHEN).
    REG.rcc_ahb2enr1.set_bits(RCC_HASHEN);
    cortex_m::asm::dsb();
    // Pulse HASHRST to reach a clean state if a previous firmware image
    // left the peripheral mid-hash.
    REG.rcc_ahb2rstr1.set_bits(RCC_HASHRST);
    cortex_m::asm::dsb();
    REG.rcc_ahb2rstr1.clear_bits(RCC_HASHRST);
    cortex_m::asm::dsb();
    // Quick known-answer check: SHA-256("abc"). Halts on failure so a
    // silently-broken HW accel doesn't produce wrong signatures.
    self_test();
}

/// # Safety
/// Category 5 — touches `static mut STATE` (the 4-byte streaming
/// merge buffer) by calling the FFI hashers below. Must run during
/// boot only (single-threaded; no `sphincs-c10` hash in flight).
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
        debug_log_safe(|| {
            cortex_m_semihosting::hprintln!("[S] hash: HW SHA-256 self-test PASS");
        });
    } else {
        debug_log_safe(|| {
            cortex_m_semihosting::hprintln!("[S] hash: HW SHA-256 self-test FAIL — HALT");
        });
        loop { cortex_m::asm::wfe(); }
    }
}

/// Run `f` only if a debugger is actually attached (DHCSR.C_DEBUGEN=1).
/// Calling `hprintln!` without a debugger issues a BKPT which HardFaults
/// on real hardware — the standalone firmware must never trip that.
#[inline(always)]
fn debug_log_safe(f: impl FnOnce()) {
    if REG.dhcsr.read() & 1 != 0 {
        f();
    }
}

#[inline]
fn wait_ready() {
    let mut t = 0u32;
    while REG.sr.read() & SR_BUSY != 0 {
        t += 1;
        if t > 10_000_000 {
            let sr = REG.sr.read();
            debug_log_safe(|| {
                cortex_m_semihosting::hprintln!(
                    "[S] hash: wait_ready TIMEOUT, SR={:#x}", sr
                );
            });
            return;
        }
    }
}

#[inline]
fn write_word(w: u32) {
    // Per Linux stm32-hash.c: push unconditionally. The AHB bus will stall
    // transparently if the internal FIFO is full. Polling DINIS between
    // every word misinterprets "DIN FIFO temporarily saturated" (which is
    // fine — the HASH auto-processes and re-arms) as "don't push".
    REG.din.write(w);
}

// ---------------------------------------------------------------------------
// Extern symbols — called from `sphincs-c10`.
// ---------------------------------------------------------------------------

/// Start a new SHA-256 computation.
///
/// # Safety
/// Category 3 — FFI symbol consumed by `sphincs-c10` via
/// `extern "C"`. The `unsafe extern "C"` signature is the ABI
/// requirement. Caller (sphincs-c10's hash dispatcher) must
/// serialise calls to `init` / `update` / `final` — only one
/// SHA-256 streaming computation may be in flight at a time
/// because category-5 `static mut STATE` is shared across them.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_init() {
    wait_ready();
    // SAFETY: category 5 — exclusive write to `static mut STATE` (the
    // 4-byte streaming merge buffer). The secure world is single-
    // threaded and non-preemptive, and the FFI contract above forbids
    // two hashes in flight; therefore no concurrent reader/writer.
    unsafe {
        STATE.buf = [0; 4];
        STATE.pending = 0;
    }
    // Pulse HASHRST in RCC before every new hash. Setting INIT=1 in HASH_CR
    // alone is NOT enough on STM32U5: after a completed hash the internal
    // FIFO counters stay in a state where the next block can't be pushed.
    // RSTR wipes the whole peripheral state back to cold-boot values.
    REG.rcc_ahb2rstr1.set_bits(RCC_HASHRST);
    cortex_m::asm::dsb();
    REG.rcc_ahb2rstr1.clear_bits(RCC_HASHRST);
    cortex_m::asm::dsb();
    // HASH mode (MODE=0), 8-bit datatype, SHA-256, INIT=1.
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    cortex_m::asm::dsb();
}

/// Feed `len` bytes from `ptr` into the current SHA-256 computation.
///
/// # Safety
/// Category 3 — FFI symbol. Caller (sphincs-c10) must pass a
/// `(ptr, len)` pair describing a single valid slice (`ptr` non-null
/// and properly aligned for `u8` reads, `ptr..ptr+len` all live
/// readable memory). `pqsigner_sha256_init` must have been called
/// first; no other SHA-256 stream may be interleaved.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
    // SAFETY: category 3 — materialising the FFI `(ptr, len)` pair as
    // a Rust slice. Caller's FFI contract guarantees `ptr..ptr+len`
    // is a valid, live, properly-aligned `[u8]` for the duration of
    // this call.
    let data = unsafe { core::slice::from_raw_parts(ptr, len) };
    let mut i = 0;

    // SAFETY: category 5 — exclusive mutable borrow of `static mut
    // STATE`. Same single-threaded + no-concurrent-hash justification
    // as in `pqsigner_sha256_init`.
    let state: &mut State = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };

    // Fill the pending merge buffer first.
    while state.pending != 0 && i < data.len() {
        state.buf[state.pending as usize] = data[i];
        state.pending += 1;
        i += 1;
        if state.pending == 4 {
            let w = u32::from_le_bytes(state.buf);
            write_word(w);
            state.pending = 0;
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
        state.buf[state.pending as usize] = data[i];
        state.pending += 1;
        i += 1;
    }
}

/// Finalize the current SHA-256 computation and write 32 bytes to `out`.
///
/// # Safety
/// Category 3 — FFI symbol. Caller (sphincs-c10) must pass an `out`
/// pointer that names 32 bytes of valid, live, writable, properly-
/// aligned memory. `pqsigner_sha256_init` (and zero or more
/// `_update` calls) must precede this call; no other SHA-256 stream
/// may be interleaved.
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
    // SAFETY: category 5 — exclusive mutable borrow of `static mut
    // STATE`. Same single-threaded + no-concurrent-hash justification
    // as in `pqsigner_sha256_init`.
    let state: &mut State = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };

    let remaining_bits = (state.pending as u32) * 8;
    if state.pending != 0 {
        // Pad with zeros in unused bytes of the last word.
        for i in state.pending..4 {
            state.buf[i as usize] = 0;
        }
        let w = u32::from_le_bytes(state.buf);
        write_word(w);
    }
    // Match the STM32 HAL order exactly: set NBLW first (clearing DCAL),
    // THEN set DCAL in a separate write. Some combinations of the U5 HASH
    // IP reportedly latch NBLW incorrectly if DCAL is set in the same cycle.
    REG.str_.write(remaining_bits);
    cortex_m::asm::dsb();
    REG.str_.write(remaining_bits | STR_DCAL);

    // Wait for digest.
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            let sr = REG.sr.read();
            let cr = REG.cr.read();
            let str_v = REG.str_.read();
            debug_log_safe(|| {
                cortex_m_semihosting::hprintln!(
                    "[S] hash: DCIS TIMEOUT, SR={:#x} CR={:#x} STR={:#x} remaining_bits={}",
                    sr, cr, str_v, remaining_bits
                );
            });
            return;
        }
    }

    // Read 8 words from HR[0..8]. Per DATATYPE=10 convention the HR
    // registers hold each 4-byte digest chunk in natural byte order when
    // interpreted via to_be_bytes on the little-endian CPU.
    for i in 0..8 {
        // SAFETY: `RoReg32::read_at(i)` is `unsafe fn` because it
        // computes `addr + i * 4` and reads at that offset without
        // bounds-checking against a typed array length. Precondition:
        // `[hr0, hr0 + 32)` (8 contiguous words = the HR0..HR7 digest
        // bank) is real MMIO inside the HASH peripheral block; the
        // datasheet pins HR0..HR7 at offsets 0x310..0x32C. The loop
        // index `i` is statically bounded to 0..8 by the for-range.
        let w = unsafe { REG.hr0.read_at(i) };
        let bytes = w.to_be_bytes();
        // SAFETY: category 3 — FFI output pointer. Caller's contract
        // (documented on `pqsigner_sha256_final`) guarantees
        // `[out, out+32)` is valid + writable; this 4-byte slice
        // write lands at `out + i*4` with `i < 8`, so it stays in
        // range.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out.add(i * 4), 4);
        }
    }

    // Clear DCIS (write 0 to bit 1 per STM32U5 RM — SR.DCIS is rc_w0).
    REG.sr.modify(|sr| sr & !SR_DCIS);

    state.pending = 0;
}
