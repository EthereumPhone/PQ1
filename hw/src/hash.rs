//! STM32U585 HASH peripheral driver — SHA-256 only.
//!
//! MOVED here from `secure/src/hw/hash.rs` on 2026-09-28 so the FSBL can use
//! the same driver instead of carrying a second copy (#758 option (d)). The
//! secure-side file is now a re-export shim.
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

use crate::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Register map — STM32U585 HASH @ AHB2 0x520C_0400 (secure alias).
// Base = PERIPH_BASE_S (0x5000_0000) + AHB2 offset (0x0202_0000) + HASH
// offset (0xA_0400). Confirmed against STMicro cmsis-device-u5 header
// (HASH_BASE_NS = 0x420C_0400 / HASH_BASE_S = 0x520C_0400).
// HASH is a SECURABLE peripheral (RM0456 Rev 7 Table 4, "Securable
// peripherals by TZSC") and securable peripherals are **NONSECURE after
// reset** (RM0456 §3.5 "Securable peripherals are nonsecure after reset";
// GTZC1_TZSC_SECCFGR1 reset value 0x0000_0000). An earlier version of this
// comment claimed the opposite ("TZSC default-secure"), which is wrong.
//
// Using the S alias here is nevertheless correct, because `sau.rs` sets
// GTZC1_TZSC_SECCFGR3 bit 12 (HASHSEC) BEFORE anything hashes — that is what
// makes HASH secure, not a reset default. Any OTHER consumer of this driver
// that runs before `sau.rs` (the FSBL) must set that bit itself; it cannot
// inherit it.
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
    /// DHCSR.C_DEBUGEN — used by `hash_log!` to decide whether semihosting
    /// `hprintln!` would BKPT-fault on a debugger-less board. Read only under
    /// `debug-log`; kept unconditionally so the register bundle is one shape.
    #[cfg_attr(not(feature = "debug-log"), allow(dead_code))]
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

/// Semihosting diagnostic, emitted only when the `debug-log` feature is on
/// AND a debugger is actually attached (DHCSR.C_DEBUGEN = 1).
///
/// Both guards matter. `hprintln!` without a debugger issues a BKPT that
/// HardFaults on real silicon, so the DHCSR probe is a correctness guard, not
/// a tidiness one. The feature is separate because the FSBL links this driver
/// with 2,048 B of headroom and does not want the semihosting machinery at all.
// The `[S]` prefix is DELIBERATE even though this crate is now shared. Only
// the secure world enables `debug-log`, so these lines only ever appear there —
// and CLAUDE.md, plus several docs, instruct the operator to look for the exact
// string "[S] hash: HW SHA-256 self-test PASS" when validating on silicon.
// Renaming it during the extraction broke that marker; do not rename it again
// without updating every consumer.
macro_rules! hash_log {
    ($($t:tt)*) => {{
        #[cfg(feature = "debug-log")]
        if REG.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!($($t)*);
        }
    }};
}

// HASH_CR bit positions (confirmed against stm32u585xx.h CMSIS header).
// ALGO is a 2-bit field at bits 17-18 on STM32U5 (NOT the bit-7+17 encoding
// used on STM32MP13). SHA-256 = ALGO=0b11 → bits 17 AND 18.
const CR_INIT: u32 = 1 << 2;
const CR_DATATYPE_8B: u32 = 0b10 << 4; // byte-swap within word -> natural byte order
const CR_ALGO_SHA256: u32 = (1 << 17) | (1 << 18);

// HASH_SR bits
#[allow(dead_code)] // documents the SR layout; the driver pushes unconditionally
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

// ---------------------------------------------------------------------------
// Dev probe (feature `hash-probe`): where a digest's cycles go.
// ---------------------------------------------------------------------------

/// Cycle sums per digest stage, on `DWT_CYCCNT`. MEASUREMENT ONLY: nothing
/// here arms the counter (the secure world's benches and busy film do), the
/// FSBL never enables the feature, and the secure `nsc/mod.rs` fence keeps it
/// out of a shipping image. The stamps and sums cost cycles of their own,
/// which land in the stages, so compare a probed build's wall time with an
/// unprobed one before trusting the split.
#[cfg(feature = "hash-probe")]
pub mod probe {
    use crate::mmio::RoReg32;

    // SAFETY: DWT_CYCCNT (ARMv8-M core debug block, 0xE000_1004) is a real,
    // aligned register; reading it has no side effect.
    const CYCCNT: RoReg32 = unsafe { RoReg32::new(0xE000_1004) };

    /// The caller's own work: the previous digest's end to this `init` (with
    /// the tick hook, when it runs). Only gaps below [`LONG`] count here.
    pub const GAP: usize = 0;
    /// `init`: the busy wait, the HASHRST pulse, the CR write.
    pub const READY: usize = 1;
    pub const RESET: usize = 2;
    pub const START: usize = 3;
    /// Every `update` of the digest.
    pub const FEED: usize = 4;
    /// `final` to the DCAL write: the last word, NBLW.
    pub const LAST: usize = 5;
    /// DCAL to DCIS: the engine's tail.
    pub const WAIT: usize = 6;
    /// The digest read out and DCIS cleared.
    pub const OUT: usize = 7;
    pub const STAGES: usize = 8;

    /// A gap this long (100 µs at 160 MHz) is other work between digest
    /// streams (a sign's start, the bench's prints), not per-digest overhead.
    pub const LONG: u32 = 16_000;

    #[derive(Clone, Copy)]
    pub struct Probe {
        /// Digests finished.
        pub n: u32,
        /// Cycles per stage, summed.
        pub cyc: [u64; STAGES],
        /// Gaps counted in `cyc[GAP]`.
        pub gaps: u32,
        /// Gaps of [`LONG`] or more: how many, and their cycles.
        pub long: (u32, u64),
        /// By padded message blocks (1, 2, 3, 4 or more): digests, and their
        /// FEED and WAIT cycles.
        pub blocks: [(u32, u64, u64); 4],
    }

    struct Live {
        p: Probe,
        /// The previous digest's end; 0 before the first.
        end: u32,
        /// The latest stage boundary of the digest in flight.
        mark: u32,
        feed: u32,
        bytes: u32,
    }

    static mut LIVE: Live = Live {
        p: Probe { n: 0, cyc: [0; STAGES], gaps: 0, long: (0, 0), blocks: [(0, 0, 0); 4] },
        end: 0,
        mark: 0,
        feed: 0,
        bytes: 0,
    };

    #[inline(always)]
    pub(crate) fn now() -> u32 {
        CYCCNT.read()
    }

    /// `init` entered: file the gap since the previous digest.
    #[inline(always)]
    pub(crate) fn init_entered() {
        let t = now();
        // SAFETY: category 5 — the hash hooks are serialised by their FFI
        // contract and the secure world is single-threaded; nothing else
        // holds a reference to LIVE while this one lives.
        let l = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
        if l.end != 0 {
            let gap = t.wrapping_sub(l.end);
            if gap < LONG {
                l.p.cyc[GAP] += u64::from(gap);
                l.p.gaps = l.p.gaps.saturating_add(1);
            } else {
                l.p.long.0 = l.p.long.0.saturating_add(1);
                l.p.long.1 += u64::from(gap);
            }
        }
        l.mark = t;
        l.feed = 0;
        l.bytes = 0;
    }

    /// Close stage `k` of the digest in flight; returns its cycles.
    #[inline(always)]
    pub(crate) fn stage(k: usize) -> u32 {
        let t = now();
        // SAFETY: as in `init_entered`.
        let l = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
        let d = t.wrapping_sub(l.mark);
        l.p.cyc[k] += u64::from(d);
        l.mark = t;
        d
    }

    /// One `update` of `len` bytes ran from `t0` to now.
    #[inline(always)]
    pub(crate) fn fed(t0: u32, len: usize) {
        let t = now();
        // SAFETY: as in `init_entered`.
        let l = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
        l.feed = l.feed.wrapping_add(t.wrapping_sub(t0));
        l.bytes = l.bytes.wrapping_add(len as u32);
    }

    /// `final` entered.
    #[inline(always)]
    pub(crate) fn final_entered() {
        let t = now();
        // SAFETY: as in `init_entered`.
        unsafe { (*core::ptr::addr_of_mut!(LIVE)).mark = t };
    }

    /// The digest is out (its WAIT took `wait`): file it, report every 2^20
    /// digests, then stamp its end.
    #[inline(never)]
    pub(crate) fn done(wait: u32) {
        stage(OUT);
        // SAFETY: as in `init_entered`.
        let l = unsafe { &mut *core::ptr::addr_of_mut!(LIVE) };
        l.p.cyc[FEED] += u64::from(l.feed);
        // SHA-256 pads with 0x80 and an 8-byte length: (len + 9) rounded up.
        let blocks = (l.bytes as usize + 72) / 64;
        let b = &mut l.p.blocks[blocks.clamp(1, 4) - 1];
        b.0 = b.0.saturating_add(1);
        b.1 += u64::from(l.feed);
        b.2 += u64::from(wait);
        l.p.n = l.p.n.saturating_add(1);
        #[cfg(feature = "debug-log")]
        if l.p.n % (1 << 20) == 0 {
            super::probe_report(&l.p);
        }
        l.end = now();
    }

    /// The sums so far (since boot; the reader takes differences).
    #[must_use]
    pub fn snapshot() -> Probe {
        // SAFETY: as in `init_entered`; a copy, taken outside any hash.
        unsafe { (*core::ptr::addr_of!(LIVE)).p }
    }
}

/// Semihosting print of the probe's means, cycles per digest since boot.
#[cfg(all(feature = "hash-probe", feature = "debug-log"))]
#[inline(never)]
fn probe_report(p: &probe::Probe) {
    let per = |c: u64, n: u32| c / u64::from(n.max(1));
    let c = &p.cyc;
    hash_log!(
        "[S] hash-probe n={} gap={} (n {}) ready={} reset={} start={} feed={} last={} wait={} out={}; long {} x {} cyc",
        p.n,
        per(c[probe::GAP], p.gaps),
        p.gaps,
        per(c[probe::READY], p.n),
        per(c[probe::RESET], p.n),
        per(c[probe::START], p.n),
        per(c[probe::FEED], p.n),
        per(c[probe::LAST], p.n),
        per(c[probe::WAIT], p.n),
        per(c[probe::OUT], p.n),
        p.long.0,
        per(p.long.1, p.long.0)
    );
    for (k, &(n, feed, wait)) in p.blocks.iter().enumerate() {
        hash_log!("[S] hash-probe {}blk n={} feed={} wait={}", k + 1, n, per(feed, n), per(wait, n));
    }
}

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
    // SAFETY: forwarded contract — `init_clock`'s caller guarantees boot-time,
    // single-threaded execution with no hash in flight, which is exactly
    // `self_test`'s requirement.
    unsafe { self_test() };
}

/// # Safety
/// Category 5 — touches `static mut STATE` (the 4-byte streaming
/// merge buffer) by calling the FFI hashers below. Must run during
/// boot only (single-threaded; no `sphincs-c10` hash in flight).
unsafe fn self_test() {
    // SAFETY: forwarded contract — the caller guarantees boot-time,
    // single-threaded execution with no other hash stream in flight, which is
    // the whole precondition these three share. `b"abc"` is a live 3-byte
    // static and `out` is 32 bytes on this frame.
    unsafe {
        pqsigner_sha256_init();
        pqsigner_sha256_update(b"abc".as_ptr(), 3);
    }
    let mut out = [0u8; 32];
    // SAFETY: as above; `out` is valid for 32 bytes of writes.
    unsafe { pqsigner_sha256_final(out.as_mut_ptr()) };
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    if out == expected {
        hash_log!("[S] hash: HW SHA-256 self-test PASS");
    } else {
        hash_log!("[S] hash: HW SHA-256 self-test FAIL — HALT");
        loop { cortex_m::asm::wfe(); }
    }
}


// **H-1 (Trezor-port) — a wedged HASH engine must fail LOUD, not
// silently return a stale digest.**
//
// The STM32U5 HASH peripheral exposes NO hardware fault flag (`HASH_SR`
// carries only DINIS/DCIS/BUSY), so a stuck engine can only be observed
// as a completion-wait that never finishes. The old timeout paths just
// `return`ed — leaving the caller's `out` buffer untouched (stale prior
// digest / stack garbage). `sphincs-c10` would then consume that
// non-digest, and because the same HW engine feeds sign_a, sign_b, AND
// the verify-before-release, all three could ingest the same bad value,
// silently defeating the FI double-compute.
//
// We route the fault to the SAME posture as the `HardFault` handler
// (`main.rs`, rr-1): wipe every in-SRAM secret cache, barrier, then
// `sys_reset()`. A hash that timed out mid-signature has no safe
// continuation, and parking with `wfe` (as the boot KAT does, where no
// secret exists yet) would strand `master_secret` + the cached slot key
// live in SRAM through the idle window — exactly the exposure rr-1
// closes. A reset re-zeroes `.bss` and the legacy bench FSBL re-verifies
// the active slot before any secret is reconstructed from the PIN.
//
// (If the engine is wedged at *boot* — inside the self-test's `init` →
// `wait_ready` — this reset-loops instead of halting; a HASH engine that
// cannot leave BUSY at cold boot is a dead device either way, and a
// reset retry is the right response to a possibly-transient stall.)
extern "C" {
    /// Unrecoverable HASH-engine posture, supplied by the linking binary.
    ///
    /// It is a hook rather than a `cfg` because the right action depends on
    /// what the binary is holding. The secure world zeroizes every in-SRAM
    /// secret and resets (the rr-1 `HardFault` posture). The FSBL runs before
    /// any secret exists and halts. Deciding that here would put the secret
    /// inventory in the wrong crate.
    fn pqsigner_hash_fault() -> !;
}

#[inline(never)]
fn hash_engine_fault() -> ! {
    // SAFETY: FFI to the binary-supplied hook. Diverging by contract; it
    // never returns, so there is no value or aliasing obligation.
    unsafe { pqsigner_hash_fault() }
}

#[inline]
fn wait_ready() {
    let mut t = 0u32;
    while REG.sr.read() & SR_BUSY != 0 {
        t += 1;
        if t > 10_000_000 {
            let sr = REG.sr.read();
            let _ = sr;
            hash_log!("[S] hash: wait_ready TIMEOUT, SR={:#x}", sr);
            // H-1: the engine is wedged BUSY — do NOT continue (the next
            // hash would start on a stuck peripheral). Zeroize + reset.
            hash_engine_fault();
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
    #[cfg(feature = "hash-probe")]
    probe::init_entered();
    wait_ready();
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::READY);
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
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::RESET);
    // HASH mode (MODE=0), 8-bit datatype, SHA-256, INIT=1.
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    cortex_m::asm::dsb();
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::START);
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
    #[cfg(feature = "hash-probe")]
    let t0 = probe::now();
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
    #[cfg(feature = "hash-probe")]
    probe::fed(t0, len);
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
    #[cfg(feature = "hash-probe")]
    probe::final_entered();
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
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::LAST);

    // Wait for digest.
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            let sr = REG.sr.read();
            let cr = REG.cr.read();
            let str_v = REG.str_.read();
            let _ = (sr, cr, str_v);
            hash_log!(
                "[S] hash: DCIS TIMEOUT, SR={:#x} CR={:#x} STR={:#x} remaining_bits={}",
                sr, cr, str_v, remaining_bits
            );
            // H-1: the digest never completed. The OLD behaviour returned
            // here with `out` UNWRITTEN — a stale/garbage 32 bytes that
            // sphincs-c10 would consume as a digest (both FI passes + the
            // verify could ingest the same bad value). Fail loud instead.
            hash_engine_fault();
        }
    }
    #[cfg(feature = "hash-probe")]
    let wait = probe::stage(probe::WAIT);

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
    #[cfg(feature = "hash-probe")]
    probe::done(wait);

    // The digest is out and the engine idle: give the secure world's busy
    // UI its turn (feature `tick-hook`; the FSBL never enables it).
    #[cfg(feature = "tick-hook")]
    // SAFETY: category 3 — FFI call to the secure world's
    // `pqsigner_hash_tick`, which takes no arguments and may run a whole
    // SHA-256 of its own: this hash is finished and `state` is not used
    // after this point.
    unsafe {
        pqsigner_hash_tick();
    }
}

#[cfg(feature = "tick-hook")]
extern "C" {
    /// Defined by the secure world (`tick-hook`): called after every
    /// finished digest, so hash-bound work (signing, keygen) gives a busy
    /// animation a chance to draw far more often than its own progress
    /// reports (~6,000 hashes apart). Must return promptly when it has
    /// nothing to do.
    fn pqsigner_hash_tick();
}
