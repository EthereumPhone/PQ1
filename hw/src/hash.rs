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
//! and, in the secure image (`oneshot`), `pqsigner_sha256_oneshot(ptr, len,
//! out_ptr)`: the three in one call, for a contiguous buffer.
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
    /// `init`: the busy wait, the HASHRST pulse (builds without
    /// `init-restart`; with it the stage is the merge-buffer clear), the CR
    /// write.
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
                // Every long gap is a boundary candidate (a sign's end is
                // one): print the running sums so per-sign deltas can be
                // taken against the bench's own lines.
                #[cfg(feature = "debug-log")]
                super::probe_mark(&l.p);
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

// ---------------------------------------------------------------------------
// Dev crosscheck (feature `hw-sha256-crosscheck`): software SHA-256 beside
// every hardware digest.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "hash-probe", feature = "hw-sha256-crosscheck"))]
compile_error!("`hash-probe` and `hw-sha256-crosscheck` are exclusive: the software hash would land in the probe's stages");

/// True when a dev instrument rides in this driver. The secure world refuses
/// to build `mode-production` with it set: a dependency feature
/// (`--features pqsigner-hw/…`) is invisible to that crate's own `cfg` fence,
/// but not to a constant.
pub const DEV_INSTRUMENTED: bool = cfg!(any(feature = "hash-probe", feature = "hw-sha256-crosscheck"));

/// True when a feature this crate reserves for the secure image is on. The
/// FSBL asserts it false at compile time (`fsbl/src/hash.rs`): its bytes carry
/// the silicon boot proof, and a feature can reach it through a manifest or a
/// recipe that no source pin reads (the workspace dependency line, a
/// `--features pqsigner-hw/…` in a build script). `tick-hook` alone would also
/// fail to link there; the others would link and ship.
pub const SECURE_IMAGE_ONLY: bool = cfg!(any(
    feature = "unrolled-io",
    feature = "inline-barriers",
    feature = "oneshot",
    feature = "init-restart",
    feature = "tick-hook",
    feature = "hash-probe",
    feature = "hw-sha256-crosscheck"
));

#[cfg(feature = "hw-sha256-crosscheck")]
extern "C" {
    /// Software half of the crosscheck, supplied by the linking binary (the
    /// secure world, `secure/src/hw/hash.rs`). SOAK EVIDENCE ONLY: it costs
    /// several hardware digests' worth of cycles, compares in variable time
    /// and keeps a second, unzeroized copy of every preimage (the `sk_seed`
    /// PRFs included). Start a software digest.
    fn pqsigner_xcheck_begin();
    /// Mirror an `update`.
    fn pqsigner_xcheck_feed(ptr: *const u8, len: usize);
    /// Finish the software digest and compare it with the 32 bytes at
    /// `digest`; false on a difference or with no digest started.
    fn pqsigner_xcheck_same(digest: *const u8) -> bool;
}

/// Digests the crosscheck has passed since boot.
#[cfg(feature = "hw-sha256-crosscheck")]
static mut XCHECKED: u32 = 0;

/// Compare the digest just written to `out` with the software one: report
/// every 2^20 digests, take the H-1 fault posture on a difference.
#[cfg(feature = "hw-sha256-crosscheck")]
#[inline(never)]
fn xcheck_digest(out: *const u8) {
    // SAFETY: category 3 — FFI to the binary's software half;
    // `pqsigner_sha256_final` wrote all 32 bytes at `out` (valid by its own
    // FFI contract) before calling this.
    let same = unsafe { pqsigner_xcheck_same(out) };
    // SAFETY: category 5 — the hash hooks are serialised by their FFI
    // contract and the secure world is single-threaded.
    let n = unsafe { &mut *core::ptr::addr_of_mut!(XCHECKED) };
    if !same {
        hash_log!("[S] hash-xcheck MISMATCH after n={} ok — FAULT", *n);
        hash_engine_fault();
    }
    *n = n.wrapping_add(1);
    if *n % (1 << 20) == 0 {
        hash_log!("[S] hash-xcheck n={} ok", *n);
    }
}

/// Semihosting print of the probe's running sums at a long gap: digests,
/// short-gap cycles, driver cycles (every stage), long-gap cycles.
#[cfg(all(feature = "hash-probe", feature = "debug-log"))]
#[inline(never)]
fn probe_mark(p: &probe::Probe) {
    let drv: u64 = p.cyc[probe::READY..].iter().sum();
    hash_log!("[S] hash-probe L n={} gap={} drv={} long={}", p.n, p.cyc[probe::GAP], drv, p.long.1);
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
    // The secure image's unrolled feed gets a vector that reaches all of it;
    // "abc" never leaves the merge buffer. Halts on its own failure.
    #[cfg(feature = "unrolled-io")]
    // SAFETY: forwarded contract, as above.
    unsafe {
        split_self_test();
    }
    // The secure image restarts the engine with INIT alone between digests;
    // its boot vector for that runs here. Halts on its own failure.
    #[cfg(feature = "init-restart")]
    // SAFETY: forwarded contract, as above.
    unsafe {
        restart_self_test();
    }
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

/// SHA-256 of bytes `0, 1, …, 130`, fed as 3 + 62 + 66 from odd offsets:
/// the merge buffer fills across a call, then the sixteen-byte loop, the word
/// loop and the tail all run, and the message ends on a three-byte last word
/// (NBLW = 24) after three blocks. A wrong index or count in `unrolled-io`'s
/// feed changes this digest; "abc" never reaches it.
///
/// # Safety
/// As `self_test`: boot only, single-threaded, no hash stream in flight.
#[cfg(feature = "unrolled-io")]
unsafe fn split_self_test() {
    #[allow(clippy::cast_possible_truncation)] // i < 131
    const MSG: [u8; 131] = {
        let mut m = [0u8; 131];
        let mut i = 0;
        while i < m.len() {
            m[i] = i as u8;
            i += 1;
        }
        m
    };
    let mut out = [0u8; 32];
    // SAFETY: forwarded contract; each `(ptr, len)` names a live sub-slice of
    // the static `MSG`, and `out` is 32 bytes on this frame.
    unsafe {
        pqsigner_sha256_init();
        for part in [&MSG[..3], &MSG[3..65], &MSG[65..]] {
            pqsigner_sha256_update(part.as_ptr(), part.len());
        }
        pqsigner_sha256_final(out.as_mut_ptr());
    }
    // python3 -c "import hashlib; print(hashlib.sha256(bytes(range(131))).hexdigest())"
    let expected: [u8; 32] = [
        0x3a, 0xcc, 0x12, 0x8f, 0xaf, 0x01, 0x07, 0x77,
        0x89, 0x74, 0x6e, 0xdc, 0xfd, 0x10, 0x51, 0xd9,
        0x0b, 0xc1, 0x59, 0x13, 0x42, 0x40, 0x2d, 0x9b,
        0x3c, 0xdd, 0x06, 0xd7, 0x31, 0x57, 0x02, 0xa4,
    ];
    if out != expected {
        hash_log!("[S] hash: HW SHA-256 split self-test FAIL — HALT");
        loop { cortex_m::asm::wfe(); }
    }
}

/// Message lengths of the back-to-back self-test: every shape the signer
/// hashes (48/80-byte PRFs, 96/128/160-byte tweak hashes, `grind_r`'s
/// 119 bytes at NBLW = 24, the 480/1,440-byte compressions) and the padding
/// edges around them. An odd count, so that running the list forward and
/// then reversed with the entry point alternating puts each length through
/// both. The empty message is left out: nothing hashes it, and the Linux
/// driver carries a quirk for it.
#[cfg(feature = "init-restart")]
const RESTART_KAT_LENS: [usize; 23] =
    [3, 1, 2, 4, 48, 55, 56, 63, 64, 65, 68, 80, 96, 103, 119, 120, 127, 128, 129, 131, 160, 480, 1440];

/// The first four bytes of each length's digest, checked digest by digest;
/// a host test recomputes them from the list and message above with
/// software SHA-256.
#[cfg(feature = "init-restart")]
const RESTART_KAT_PREFIX: [u32; 23] = [
    0xde73_c79b, 0xbbee_bd87, 0x9573_16fe, 0x0bc0_bfd8, 0x6d1b_47e9, 0xc5e3_c3e3,
    0xa790_d48a, 0xbbeb_cae4, 0xdd19_841d, 0xc09e_be66, 0x83db_114f, 0x69c4_9e84,
    0xd7be_0585, 0x73a6_5f4d, 0xbfd6_9afd, 0xed63_36a0, 0x3c9b_bdbb, 0x6c8c_35df,
    0x61f2_d40e, 0xa1c0_279e, 0x2ad8_1c36, 0x5087_5667, 0x5c18_81a7,
];

/// The 46 full digests folded (digest `k` XORed in at byte offset `k`), for
/// the bytes the prefixes do not cover. The fold alone can cancel two equal,
/// rotation-invariant errors; the per-digest prefixes cannot. Indexing
/// rather than `rotate_left` keeps `memmove` (1.5 KB) out of the image. A
/// host test recomputes it too.
#[cfg(feature = "init-restart")]
const RESTART_KAT: [u8; 32] = [
    0x40, 0x3b, 0x92, 0x4f, 0x63, 0x85, 0x2e, 0x6e,
    0x70, 0xea, 0x75, 0xb0, 0xb0, 0x02, 0xd7, 0x6d,
    0x3f, 0xc6, 0xbf, 0xd2, 0x19, 0x80, 0x6c, 0x9d,
    0x74, 0x67, 0x45, 0xd9, 0x07, 0x84, 0x4d, 0xea,
];

/// Back-to-back digests with no reset between them (`init-restart`): each
/// starts on INIT alone after the previous shape, through the one-shot and
/// through a two-part streamed digest in turn. A digest that INIT failed to
/// restart cleanly fails its own prefix check.
///
/// # Safety
/// As `self_test`: boot only, single-threaded, no hash stream in flight.
#[cfg(feature = "init-restart")]
#[allow(clippy::cast_possible_truncation)] // the message pattern wraps by design
unsafe fn restart_self_test() {
    let mut msg = [0u8; 1440];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7) ^ 0x5A;
    }
    let mut acc = [0u8; 32];
    let mut prefixes_ok = true;
    let n = RESTART_KAT_LENS.len();
    for k in 0..2 * n {
        let i = if k < n { k } else { 2 * n - 1 - k };
        let len = RESTART_KAT_LENS[i];
        let (head, tail) = msg[..len].split_at(len / 3 + 1);
        let mut d = [0u8; 32];
        // SAFETY: forwarded contract; each `(ptr, len)` names a live
        // sub-slice of `msg`, and `d` is 32 bytes on this frame.
        unsafe {
            if k % 2 == 0 {
                pqsigner_sha256_oneshot(msg.as_ptr(), len, d.as_mut_ptr());
            } else {
                pqsigner_sha256_init();
                pqsigner_sha256_update(head.as_ptr(), head.len());
                pqsigner_sha256_update(tail.as_ptr(), tail.len());
                pqsigner_sha256_final(d.as_mut_ptr());
            }
        }
        prefixes_ok &= u32::from_be_bytes([d[0], d[1], d[2], d[3]]) == RESTART_KAT_PREFIX[i];
        for (j, x) in d.iter().enumerate() {
            acc[(j + k) % 32] ^= x;
        }
    }
    if prefixes_ok && acc == RESTART_KAT {
        hash_log!("[S] hash: back-to-back self-test PASS ({} digests, no reset between)", 2 * RESTART_KAT_LENS.len());
    } else {
        hash_log!("[S] hash: back-to-back self-test FAIL — HALT");
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

#[cfg(not(feature = "init-restart"))]
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

/// `wait_ready`, returning the status word that showed the engine idle, so
/// `init-restart` checks it for a stale DCIS without another bus read.
#[cfg(feature = "init-restart")]
#[inline(always)]
fn wait_ready_sr() -> u32 {
    let mut t = 0u32;
    loop {
        let sr = REG.sr.read();
        if sr & SR_BUSY == 0 {
            return sr;
        }
        t += 1;
        if t > 10_000_000 {
            hash_log!("[S] hash: wait_ready TIMEOUT, SR={:#x}", sr);
            // H-1, as in `wait_ready`.
            hash_engine_fault();
        }
    }
}

/// The per-digest idle check before INIT: under `no-busy-wait` (measurement only) one SR read for
/// the stale-DCIS check, without waiting for BUSY to clear; otherwise `wait_ready_sr`.
#[cfg(feature = "init-restart")]
#[inline(always)]
fn ready_sr_fast() -> u32 {
    #[cfg(feature = "no-busy-wait")]
    return REG.sr.read();
    #[cfg(not(feature = "no-busy-wait"))]
    wait_ready_sr()
}

/// HR0..HR3 as the first 16 digest bytes' words (byte-swapped), read through the documented
/// `HASH_HRA0..3` alias at offsets 0x0C..0x18 (RM0456 §51.6.4) with one load-multiple under
/// `hra-ldm`; four separate HR reads otherwise. Only valid after DCIS.
#[inline(always)]
fn read_hr4() -> [u32; 4] {
    #[cfg(feature = "hra-ldm")]
    {
        let (a, b, c, d): (u32, u32, u32, u32);
        // SAFETY: reads four consecutive HASH registers (HRA0..HRA3) of the secure HASH block;
        // no memory is written and the registers are only read.
        unsafe {
            core::arch::asm!("ldm {p}, {{r0, r1, r2, r3}}", p = in(reg) HASH_BASE + 0x0C,
                out("r0") a, out("r1") b, out("r2") c, out("r3") d, options(nostack, readonly))
        };
        [a.swap_bytes(), b.swap_bytes(), c.swap_bytes(), d.swap_bytes()]
    }
    #[cfg(not(feature = "hra-ldm"))]
    // SAFETY: HR0..HR3, the first four words of the digest bank.
    unsafe {
        [
            REG.hr0.read_at(0).swap_bytes(),
            REG.hr0.read_at(1).swap_bytes(),
            REG.hr0.read_at(2).swap_bytes(),
            REG.hr0.read_at(3).swap_bytes(),
        ]
    }
}

/// Reset the HASH engine: the HASHRST pulse `init_clock` gives it at boot.
/// It clears the core, HR and the context registers (`HASH_CSRx`, which can
/// hold the last block fed — `sk_seed` for the PRFs), which nothing else
/// clears: the per-digest reset only ever ran at the *next* digest's start,
/// and RM0456 does not say INIT clears CSRx. The secure world calls this from
/// `nsc::zeroize_sensitive_state` (lock, idle wipe, FI failure, tamper,
/// faults), so the engine is reset whenever the secrets in SRAM are: on idle
/// that is the same deferral-bounded moment, not the instant the deadline
/// passes while a handler is busy. The clock stays on, and the next digest
/// starts from the reset state, as after boot.
///
/// Any digest in flight is lost, so call it only where no hash resumes. A
/// misplaced call costs a wrong digest or a DCIS timeout, never a stale one:
/// the FI double compute or the H-1 fault posture takes it from there.
pub fn scrub() {
    REG.rcc_ahb2rstr1.set_bits(RCC_HASHRST);
    dsb();
    REG.rcc_ahb2rstr1.clear_bits(RCC_HASHRST);
    dsb();
}

#[inline]
fn write_word(w: u32) {
    // Per Linux stm32-hash.c: push unconditionally. The AHB bus will stall
    // transparently if the internal FIFO is full. Polling DINIS between
    // every word misinterprets "DIN FIFO temporarily saturated" (which is
    // fine — the HASH auto-processes and re-arms) as "don't push".
    REG.din.write(w);
}

/// `dsb`, with cortex-m's fences. The secure image inlines it
/// (`inline-barriers`): without cortex-m's `inline-asm` feature
/// `cortex_m::asm::dsb()` is a call to an out-of-line stub, and turning that
/// workspace feature on would change the FSBL.
#[inline(always)]
fn dsb() {
    #[cfg(not(feature = "inline-barriers"))]
    cortex_m::asm::dsb();
    #[cfg(feature = "inline-barriers")]
    {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: `dsb sy` only waits for earlier memory accesses to complete;
        // it reads or writes no register or memory the compiler tracks, which
        // is what cortex-m's own inline form declares.
        unsafe { core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags)) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
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
    // SAFETY: this symbol's own FFI contract, forwarded unchanged.
    unsafe { init_body() }
}

/// `pqsigner_sha256_init`'s body, inlined there and into the one-shot.
///
/// # Safety
/// As `pqsigner_sha256_init`.
#[inline(always)]
unsafe fn init_body() {
    #[cfg(feature = "hash-probe")]
    probe::init_entered();
    #[cfg(not(feature = "init-restart"))]
    wait_ready();
    // `init-restart`: the same idle wait, and the status word that ended it
    // must not still carry DCIS. The previous digest's `final` clears DCIS
    // after reading HR out, so DCIS set here means that clear was skipped.
    // This catches that one fault and nothing more: a skipped INIT write
    // below leaves DCIS clear and gives a wrong digest. In the signer the FI
    // double compute and verify-before-release catch that; every other
    // consumer fails closed (an image or bundle refused, a wrong address).
    // A skipped CR write after the per-digest reset was the same class.
    #[cfg(feature = "init-restart")]
    if wait_ready_sr() & SR_DCIS != 0 {
        hash_log!("[S] hash: DCIS still set at init — FAULT");
        hash_engine_fault();
    }
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
    // The FSBL pulses HASHRST before every digest (its bytes carry the boot
    // proof). The secure image (`init-restart`) does not: the INIT write
    // below is RM0456's per-message re-initialisation. It resets the hash
    // core, sets NBWE back to 0x11, NBWP and DINNE to 0, clears DCIS and
    // forces HR to its reset value, and it is what the ST HAL and Linux
    // driver do per message. The old claim here, that INIT alone leaves the
    // FIFO unable to take the next block, landed together with the real fix
    // for that stall (pushing DIN without polling DINIS, 4fefc3bc9) and was
    // never tested on its own; the boot self-test now runs 46 back-to-back
    // digests without a reset. The reset moves to `scrub`, which every
    // secret wipe calls.
    #[cfg(not(feature = "init-restart"))]
    {
        REG.rcc_ahb2rstr1.set_bits(RCC_HASHRST);
        dsb();
        REG.rcc_ahb2rstr1.clear_bits(RCC_HASHRST);
        dsb();
    }
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::RESET);
    // INIT leaves NBLW alone, and the reset used to zero it, so the last
    // digest's value (24 after `grind_r`'s 119-byte PRF) would otherwise sit
    // there until this digest's `final` writes its own: a single skipped
    // STR write there would pad with the stale count. RM0456 §51.4.5 has
    // NBLW written before INIT anyway (step 1c, and the caution under it).
    #[cfg(feature = "init-restart")]
    REG.str_.write(0);
    // HASH mode (MODE=0), 8-bit datatype, SHA-256, INIT=1.
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    // The DIN writes that follow go to the same peripheral, so Device-memory
    // ordering already puts them after this one: the secure image drops the
    // barrier (`inline-barriers`). The FSBL keeps it, and its bytes.
    #[cfg(not(feature = "inline-barriers"))]
    cortex_m::asm::dsb();
    #[cfg(feature = "hash-probe")]
    probe::stage(probe::START);
    #[cfg(feature = "hw-sha256-crosscheck")]
    // SAFETY: category 3 — FFI to the binary's software half; no arguments.
    unsafe { pqsigner_xcheck_begin() };
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
    // SAFETY: this symbol's own FFI contract, forwarded unchanged.
    unsafe { update_body(ptr, len) }
}

/// `pqsigner_sha256_update`'s body, inlined there and into the one-shot.
///
/// # Safety
/// As `pqsigner_sha256_update`.
#[inline(always)]
unsafe fn update_body(ptr: *const u8, len: usize) {
    #[cfg(feature = "hash-probe")]
    let t0 = probe::now();
    // SAFETY: category 3 — materialising the FFI `(ptr, len)` pair as
    // a Rust slice. Caller's FFI contract guarantees `ptr..ptr+len`
    // is a valid, live, properly-aligned `[u8]` for the duration of
    // this call.
    let data = unsafe { core::slice::from_raw_parts(ptr, len) };
    #[cfg(feature = "hw-sha256-crosscheck")]
    // SAFETY: category 3 — the same `(ptr, len)` this call's own FFI contract
    // makes a valid, live byte slice for its duration.
    unsafe { pqsigner_xcheck_feed(ptr, len) };
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
    #[cfg(not(feature = "unrolled-io"))]
    while data.len() - i >= 4 {
        let w = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        write_word(w);
        i += 4;
    }
    // The same words in the same order, sixteen bytes a turn. `chunks_exact`
    // fixes every index at compile time, so a turn is four load/store pairs
    // and one branch instead of ~nine instructions a word (bounds and
    // overflow checks included). Lengths are public preimage shapes, so how
    // the bytes split between the loops leaks nothing.
    #[cfg(feature = "unrolled-io")]
    {
        let mut quads = data[i..].chunks_exact(16);
        for q in &mut quads {
            write_word(u32::from_le_bytes([q[0], q[1], q[2], q[3]]));
            write_word(u32::from_le_bytes([q[4], q[5], q[6], q[7]]));
            write_word(u32::from_le_bytes([q[8], q[9], q[10], q[11]]));
            write_word(u32::from_le_bytes([q[12], q[13], q[14], q[15]]));
        }
        let mut words = quads.remainder().chunks_exact(4);
        for w in &mut words {
            write_word(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
        }
        i = data.len() - words.remainder().len();
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
    // SAFETY: this symbol's own FFI contract, forwarded unchanged.
    unsafe { final_body(out) }
}

/// `pqsigner_sha256_final`'s body, inlined there and into the one-shot.
///
/// # Safety
/// As `pqsigner_sha256_final`.
#[inline(always)]
unsafe fn final_body(out: *mut u8) {
    // SAFETY: as `final_body_n`, with all eight words.
    unsafe { final_body_n::<8>(out) }
}

/// `final_body` reading out only the first `W` digest words (`W * 4` bytes to
/// `out`). The signer's tweakable hashes keep 16 bytes (`W = 4`).
///
/// # Safety
/// As `final_body`, with `[out, out + 4 * W)` writable.
#[inline(always)]
unsafe fn final_body_n<const W: usize>(out: *mut u8) {
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
    // `init-restart` (secure image): `init` already wrote STR = 0, so a
    // whole-word message (NBLW = 0) needs only the DCAL write.
    #[cfg(feature = "init-restart")]
    let two_writes = remaining_bits != 0;
    #[cfg(not(feature = "init-restart"))]
    let two_writes = true;
    if two_writes {
        REG.str_.write(remaining_bits);
        // Both writes go to the same register, so they reach it in order without
        // a barrier: the secure image drops it (`inline-barriers`), the FSBL
        // keeps it. Nonzero NBLW without the barrier is exercised by both boot
        // self-tests ("abc" and the 131-byte vector end on NBLW = 24) and, in
        // every sign, by `grind_r`'s 119-byte PRF (NBLW = 24, ~2^11 a pass).
        #[cfg(not(feature = "inline-barriers"))]
        cortex_m::asm::dsb();
    }
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
    #[cfg(not(feature = "unrolled-io"))]
    for i in 0..W {
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
    // The same eight words with constant offsets: no counter or address
    // arithmetic between the peripheral reads. `to_be` stored little-endian
    // is `to_be_bytes` in memory, and an unaligned word store is legal on
    // ARMv8-M Mainline (nothing sets `CCR.UNALIGN_TRP`; `update`'s word
    // loads already rely on it).
    #[cfg(feature = "unrolled-io")]
    {
        macro_rules! hr_out {
            ($($i:literal)*) => {$(
                // SAFETY: as in the rolled loop — HR0..HR7 is the 8-word
                // digest bank at 0x310..0x32C and `$i < 8`; `[out, out + 32)`
                // is valid and writable by this function's FFI contract.
                unsafe { out.add($i * 4).cast::<u32>().write_unaligned(REG.hr0.read_at($i).to_be()) };
            )*};
        }
        hr_out!(0 1 2 3);
        if W == 8 {
            hr_out!(4 5 6 7);
        }
    }
    #[cfg(feature = "hw-sha256-crosscheck")]
    xcheck_digest(out);

    // Clear DCIS (write 0 to bit 1 per STM32U5 RM — SR.DCIS is rc_w0).
    // DCIS and DINIS are rc_w0; writing DINIS's 1 and 0 everywhere else clears
    // DCIS alone and keeps the reserved bits at 0 (`init-restart`, secure image;
    // the FSBL keeps the read-modify-write).
    #[cfg(feature = "init-restart")]
    REG.sr.write(SR_DINIS);
    #[cfg(not(feature = "init-restart"))]
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

/// SHA-256 of one contiguous buffer: `init`, a single `update` and `final`
/// in one call, for `sphincs-c10`'s `sha256_bytes` (`oneshot`, secure image
/// only; the FSBL keeps the three-call API). The three bodies are inlined
/// here, so the engine sequence, the probe stages, the crosscheck and the UI
/// tick are the streamed digest's; only the calls between them go.
///
/// # Safety
/// Category 3 — FFI symbol. `(ptr, len)` names a single valid, live byte
/// slice and `out` 32 bytes of valid, writable memory, as for `update` and
/// `final`; no other SHA-256 stream may be in flight.
#[cfg(feature = "oneshot")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_oneshot(ptr: *const u8, len: usize, out: *mut u8) {
    // SAFETY: this symbol's contract is the three bodies' contracts joined,
    // in their order, with nothing else in flight.
    unsafe {
        init_body();
        update_body(ptr, len);
        final_body(out);
    }
}

/// `pqsigner_sha256_oneshot` that writes only the first 16 digest bytes
/// (HR0..HR3) to `out`: the signer's tweakable hashes truncate to n = 16.
///
/// # Safety
/// As `pqsigner_sha256_oneshot`, with `out` naming 16 writable bytes.
#[cfg(feature = "oneshot")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_oneshot16(ptr: *const u8, len: usize, out: *mut u8) {
    // SAFETY: as `pqsigner_sha256_oneshot`; `final_body_n::<4>` writes 16 bytes.
    unsafe {
        init_body();
        update_body(ptr, len);
        final_body_n::<4>(out);
    }
}

/// C10 WOTS chain in the driver (`chain`, secure image only): over the 96-byte
/// `seed ‖ adrs ‖ pad16(val)` buffer at `buf`, `steps` times set the chain
/// position (bytes [56..60), big-endian) to `start_pos + i` and replace the
/// value (bytes [64..80)) with the first 16 bytes of SHA-256 of the buffer;
/// the final value is written back to [64..80). The same engine sequence and
/// fault checks as `oneshot16` per step, but the 15 fixed preimage words and
/// the running value stay in registers instead of going through SRAM.
///
/// # Safety
/// `buf` names 96 readable and writable bytes; no other SHA-256 stream is in
/// flight; `init_clock` has run.
#[cfg(feature = "chain")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_chain16(buf: *mut u8, start_pos: u32, steps: u32) {
    // SAFETY: `buf..buf + 96` is readable (caller contract); unaligned word reads
    // are legal on ARMv8-M Mainline.
    let w = |i: usize| unsafe { buf.add(4 * i).cast::<u32>().read_unaligned() };
    let c: [u32; 16] = core::array::from_fn(w);
    let v = chain_core(&c, [w(16), w(17), w(18), w(19)], start_pos, steps);
    for (k, x) in v.iter().enumerate() {
        // SAFETY: `buf + 64 + 4k`, k < 4, is inside the caller's 96 bytes.
        unsafe { buf.add(64 + 4 * k).cast::<u32>().write_unaligned(*x) };
    }    #[cfg(feature = "tick-batch")]
    // SAFETY: the engine is idle; the tick does not hash (tick-batch contract).
    unsafe {
        pqsigner_hash_tick_n(steps);
    }
}

/// The chain loop of `chain16`: `c` holds words 0..16 of the preimage (word 14,
/// the chain position, is replaced per step), `v` the value words.
#[cfg(feature = "chain")]
#[inline(always)]
fn chain_core(c: &[u32; 16], v: [u32; 4], start_pos: u32, steps: u32) -> [u32; 4] {
    // WOTS chain preimages have six structurally zero words: the pad half of
    // `pad16(pk_seed)` (4..8), the address type ADRS_WOTS (11) and the hash
    // address (15). Public shape, so the branch leaks nothing; the zero path
    // writes literal zeros and keeps fewer words live.
    if c[4] | c[5] | c[6] | c[7] | c[11] | c[15] == 0 {
        chain_steps::<true>(c, v, start_pos, steps)
    } else {
        chain_steps::<false>(c, v, start_pos, steps)
    }
}

/// `v1-asm-chain` (round 7, secure-only; the FSBL never names it): the WOTS-shaped
/// (`Z`) v1 chain loop, hand-scheduled. Per step it does what the Rust loop does
/// (BUSY spin with a 2^24 guard, stale-DCIS refusal, INIT, the 16 block-1 words
/// with position `pos`, the value and four zero words, DCAL; DCIS poll with a
/// 2^24 guard; HR0..3; SR clear). The 18th store waits for block 1, so loop
/// control sits after it; a timed spin places the first DCIS poll.
#[cfg(feature = "v1-asm-chain")]
const V1_ASM_SPIN: u32 = 14;

#[cfg(all(feature = "v1-asm-chain", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1_chain_asm(blk: &[u32; 10], v: [u32; 4], start_pos: u32) -> [u32; 4] {
    let (o0, o1, o2, o3): (u32, u32, u32, u32);
    // SAFETY: drives only the secure HASH block (r4 = HASH_BASE + 0x0C); reads the
    // 40-byte staging array; on a hang or a stale DCIS it calls `hash_engine_fault`.
    unsafe {
        core::arch::asm!(
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 3f",
            // engine window after DCAL: CR value back in lr, loop control, timed wait
            "1:",
            "movs r8, #{spin}",
            "10:",
            "subs r8, r8, #1",
            "bne 10b",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bpl 11f",
            "4:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "rev r0, r0",                  // r1..r3 are byte-swapped in the block-0 window
            "3:",
            "ldr r8, [r4, #0x18]",
            "tst r8, #10",
            "bne 40f",
            "41:",
            "str lr, [r4, #-12]",          // INIT
            "movs.w lr, #0",               // lr = 0 until the window
            "ldm r12, {{r8, r9, r10, r11}}",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "ldr r8, [r12, #16]",
            "ldr r9, [r12, #20]",
            "ldr r10, [r12, #24]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str lr, [r4, #-8]",
            "ldrd r8, r9, [r12, #28]",
            "rev r10, r5",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str r0, [r4, #-8]",           // word 16: block 1 starts
            // block-0 window (~46 free cycles before the next store completes)
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "add r5, r5, #1",
            "ldr r11, [r12, #36]",
            "mov.w r8, #256",
            "str r1, [r4, #-8]",           // waits for block 0
            "str r2, [r4, #-8]",
            "str r3, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str r8, [r4, #-4]",           // DCAL (NBLW = 0)
            "movw lr, #0x24",
            "movt lr, #0x6",
            "cmp r5, r11",
            "bne 1b",
            // last digest: counted poll, read, clear
            "mov.w r9, #16777216",
            "21:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 22f",
            "subs r9, r9, #1",
            "bne 21b",
            "b 99f",
            "22:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "b 98f",
            // DCIS not yet: seven straight polls, then a counted poll
            "11:",
            ".rept 7",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 4b",
            ".endr",
            "mov.w r9, #16777216",
            "12:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 4b",
            "subs r9, r9, #1",
            "bne 12b",
            "b 99f",
            // BUSY still set, or a stale DCIS
            "40:",
            "mov.w r9, #16777216",
            "42:",
            "tst r8, #8",
            "beq 43f",
            "subs r9, r9, #1",
            "beq 99f",
            "ldr r8, [r4, #0x18]",
            "b 42b",
            "43:",
            "tst r8, #2",
            "beq 41b",
            "99:",
            "bl {fault}",
            "98:",
            spin = const V1_ASM_SPIN,
            fault = sym hash_engine_fault,
            inout("r0") v[0] => o0,
            // r1..r3 enter byte-swapped: the loop swaps them back in the block-0 window.
            inout("r1") v[1].swap_bytes() => o1,
            inout("r2") v[2].swap_bytes() => o2,
            inout("r3") v[3].swap_bytes() => o3,
            in("r4") HASH_BASE + 0x0C,
            inout("r5") start_pos => _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            in("r12") blk.as_ptr(),
            out("lr") _,
        );
    }
    [o0, o1, o2, o3]
}

#[cfg(feature = "chain")]
#[inline(always)]
fn chain_steps<const Z: bool>(c: &[u32; 16], mut v: [u32; 4], start_pos: u32, steps: u32) -> [u32; 4] {
    #[cfg(all(feature = "v1-asm-chain", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    if Z && steps != 0 {
        // The engine is idle (no stale DCIS) before STR, as below.
        if wait_ready_sr() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
        let blk = [c[0], c[1], c[2], c[3], c[8], c[9], c[10], c[12], c[13], start_pos.wrapping_add(steps)];
        return v1_chain_asm(&blk, v, start_pos);
    }
    let k = |i: usize| if Z && matches!(i, 4 | 5 | 6 | 7 | 11 | 15) { 0 } else { c[i] };
    let (c0, c1, c2, c3, c4, c5, c6, c7) = (k(0), k(1), k(2), k(3), k(4), k(5), k(6), k(7));
    let (c8, c9, c10, c11, c12, c13, c15) = (k(8), k(9), k(10), k(11), k(12), k(13), k(15));
    // NBLW = 0 for every step: STR is written once, after the first BUSY wait
    // (and again after a UI tick, which may hash); a step writes STR only with
    // DCAL (NBLW bits 0).
    if steps != 0 {
        // The engine is idle (the loop repeats this check per step) before STR.
        if wait_ready_sr() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
    }
    let mut step = 0u32;
    while step < steps {
        // init_body (init-restart): idle, no stale DCIS, INIT. `no-busy-wait` (measurement only):
        // read SR once for the stale-DCIS check and do not wait for BUSY to clear.
        #[cfg(not(feature = "no-busy-wait"))]
        if wait_ready_sr() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        #[cfg(feature = "no-busy-wait")]
        if REG.sr.read() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
        let pos = start_pos.wrapping_add(step);
        write_word(c0); write_word(c1); write_word(c2); write_word(c3);
        write_word(c4); write_word(c5); write_word(c6); write_word(c7);
        write_word(c8); write_word(c9); write_word(c10); write_word(c11);
        write_word(c12); write_word(c13); write_word(pos.swap_bytes()); write_word(c15);
        write_word(v[0]); write_word(v[1]); write_word(v[2]); write_word(v[3]);
        write_word(0); write_word(0); write_word(0); write_word(0);
        // final_body: NBLW = 0 (init wrote it), DCAL alone.
        REG.str_.write(STR_DCAL);
        let mut t = 0u32;
        while REG.sr.read() & SR_DCIS == 0 {
            t += 1;
            if t > 10_000_000 {
                hash_engine_fault();
            }
        }
        v = read_hr4();
        REG.sr.write(SR_DINIS);
        #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
        {
            // SAFETY: as in `final_body`: this digest is finished.
            unsafe { pqsigner_hash_tick() };
            // The tick may run a digest of its own and leave NBLW nonzero.
            REG.str_.write(0);
        }
        step += 1;
    }
    v
}

/// WOTS secret and its chain in one call (`prfchain`, secure image only):
/// `v = SHA-256(sk_seed ‖ prf_tail)[..16]` (an 80-byte PRF preimage whose
/// first 32 bytes are read from `sk_seed` in place and never copied), then
/// `steps` chain steps from position 0 over `seed_adrs ‖ pad16(v)`; the
/// chain end (or the secret itself, for `steps == 0`) goes to `out`. The
/// secret and the intermediate values stay in registers.
///
/// # Safety
/// `sk_seed` names 32, `prf_tail` 48 and `seed_adrs` 64 readable bytes, `out`
/// 16 writable bytes; no other SHA-256 stream is in flight.
#[cfg(feature = "prfchain")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_wots_prf_chain16(
    sk_seed: *const u8,
    prf_tail: *const u8,
    seed_adrs: *const u8,
    steps: u32,
    out: *mut u8,
) {
    // PRF: init, 8 words of sk_seed, 12 tail words, DCAL, HR0..3.
    if ready_sr_fast() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.str_.write(0);
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    // SAFETY: caller contract (32 and 48 readable bytes).
    unsafe {
        feed_words(sk_seed, 8);
        feed_words(prf_tail, 12);
    }
    REG.str_.write(STR_DCAL);
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            hash_engine_fault();
        }
    }
    let v = read_hr4();
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`.
    unsafe {
        pqsigner_hash_tick();
    }
    // SAFETY: `seed_adrs` names 64 readable bytes (caller contract).
    let c: [u32; 16] = core::array::from_fn(|i| unsafe { seed_adrs.add(4 * i).cast::<u32>().read_unaligned() });
    let v = chain_core(&c, v, 0, steps);
    for (k, x) in v.iter().enumerate() {
        // SAFETY: `out + 4k`, k < 4, inside the caller's 16 bytes.
        unsafe { out.add(4 * k).cast::<u32>().write_unaligned(*x) };
    }
    #[cfg(feature = "tick-batch")]
    // SAFETY: the engine is idle; the tick does not hash.
    unsafe {
        pqsigner_hash_tick_n(1 + steps);
    }
}

/// FORS leaf in one call (`forsleaf`, secure image only):
/// `s = SHA-256(sk_seed ‖ prf_tail)[..16]` (48-byte PRF; `sk_seed` read in
/// place), then `SHA-256(seed_adrs ‖ s ‖ 0^16)[..16]` to `out`. The secret
/// stays in registers.
///
/// # Safety
/// `sk_seed` 32, `prf_tail` 16 and `seed_adrs` 64 readable bytes, `out` 16
/// writable; no other SHA-256 stream in flight.
#[cfg(feature = "forsleaf")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_fors_leaf16(sk_seed: *const u8, prf_tail: *const u8, seed_adrs: *const u8, out: *mut u8) {
    if ready_sr_fast() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.str_.write(0);
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    // SAFETY: caller contract.
    unsafe {
        feed_words(sk_seed, 8);
        feed_words(prf_tail, 4);
    }
    REG.str_.write(STR_DCAL);
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            hash_engine_fault();
        }
    }
    let v = read_hr4();
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`.
    unsafe {
        pqsigner_hash_tick();
    }
    if ready_sr_fast() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.str_.write(0);
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    // SAFETY: caller contract.
    unsafe { feed_words(seed_adrs, 16) };
    write_word(v[0]);
    write_word(v[1]);
    write_word(v[2]);
    write_word(v[3]);
    write_word(0);
    write_word(0);
    write_word(0);
    write_word(0);
    // SAFETY: caller contract (16 writable bytes).
    unsafe { gather_final16(out) };
}

/// Merkle node (`forsleaf`, secure image only): first 16 bytes of
/// SHA-256(seed_adrs ‖ l ‖ 0^16 ‖ r ‖ 0^16), i.e. `th_pair(seed, adrs,
/// pad16(l), pad16(r))` with the two 16-byte children read in place.
///
/// # Safety
/// `seed_adrs` 64, `l` and `r` 16 readable bytes each, `out` 16 writable; no
/// other SHA-256 stream in flight.
#[cfg(feature = "forsleaf")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_node16(seed_adrs: *const u8, l: *const u8, r: *const u8, out: *mut u8) {
    gather_init();
    // SAFETY: caller contract.
    unsafe {
        feed_words(seed_adrs, 16);
        feed_words(l, 4);
        write_word(0);
        write_word(0);
        write_word(0);
        write_word(0);
        feed_words(r, 4);
        write_word(0);
        write_word(0);
        write_word(0);
        write_word(0);
        gather_final16(out);
    }
}

/// `v1-asm-key` (round 8, secure-only; the FSBL never names it): every chain of one
/// WOTS key of the keygen shape (no order, no digits, `fixed_steps` > 0, WOTS-shaped
/// zero words) in one asm loop. Per chain: the 80-byte PRF (`sk_seed` read in place
/// with single loads, never copied; tail words, then `rev(i)`), then `fixed_steps`
/// chain steps exactly as `v1_chain_asm`. The previous chain's output store and the
/// next chain index run in the PRF's block-0 window; every digest has the same checks
/// as the Rust loop (BUSY spin with a 2^24 guard, stale-DCIS refusal, DCIS poll with a
/// 2^24 guard, SR clear). `st`: 0..4 c0..c3, 4 c8, 5 c9, 6 c10, 7 c12, 8 rev(i) (set
/// per chain), 9 steps, 10..21 tail words 0..10, 21 `sk_seed`, 22 out pointer, 23 i
/// (starts at u32::MAX), 24 n.
#[cfg(feature = "v1-asm-key")]
const V1K_SPIN_STEP: u32 = 10;
#[cfg(feature = "v1-asm-key")]
const V1K_SPIN_PRF: u32 = 14;
#[cfg(feature = "v1-asm-key")]
const V1K_SPIN_END: u32 = 12;

#[cfg(all(feature = "v1-asm-key", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1_key_asm(st: *mut u32) {
    // SAFETY: drives only the secure HASH block (r4 = HASH_BASE + 0x0C); reads and
    // updates the 25-word staging array at `st`, reads 32 bytes at st[21] (`sk_seed`)
    // with single loads, writes 16 bytes per chain at st[22] (advanced by 16); on a
    // hang or a stale DCIS it calls `hash_engine_fault`.
    unsafe {
        core::arch::asm!(
            "movw lr, #0x24",
            "movt lr, #0x6",
            "ldr r5, [r12, #84]",          // sk_seed
            "b 60f",
            // ---- chain step loop (as v1_chain_asm) ----
            "1:",
            "movs r8, #{spin}",
            "10:",
            "subs r8, r8, #1",
            "bne 10b",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bpl 11f",
            "4:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "rev r0, r0",
            "3:",
            "ldr r8, [r4, #0x18]",
            "tst r8, #10",
            "bne 40f",
            "41:",
            // block 0: c0..c2 arrive preloaded in r9..r11 (loaded in the previous digest's
            // window); the other words load between the stores.
            "str lr, [r4, #-12]",          // INIT
            "str r9, [r4, #-8]",           // c0
            "str r10, [r4, #-8]",          // c1
            "str r11, [r4, #-8]",          // c2
            "add r8, r12, #12",
            "ldm r8, {{r8, r9, r10, r11}}", // c3, c8, c9, c10
            "movs.w lr, #0",
            "str r8, [r4, #-8]",           // c3
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str r9, [r4, #-8]",           // c8
            "str r10, [r4, #-8]",          // c9
            "str r11, [r4, #-8]",          // c10
            "str lr, [r4, #-8]",
            "ldrd r8, r9, [r12, #28]",     // c12, c13 = rev(i)
            "rev r10, r5",                 // position
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str r0, [r4, #-8]",           // word 16: block 0 starts
            // block-0 window: swaps, position, end test (flags live to the bne), next c0..c2
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "add r5, r5, #1",
            "ldr r11, [r12, #36]",
            "cmp r5, r11",
            "ldm r12, {{r9, r10, r11}}",
            "mov.w r8, #256",
            "str r1, [r4, #-8]",           // waits for block 0
            "str r2, [r4, #-8]",
            "str r3, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str lr, [r4, #-8]",
            "str r8, [r4, #-4]",           // DCAL (NBLW = 0)
            "movw lr, #0x24",
            "movt lr, #0x6",
            "bne 1b",
            // ---- chain done: the next chain's PRF, or the last read-out ----
            "ldr r5, [r12, #84]",          // sk_seed
            "ldr r8, [r12, #92]",
            "ldr r9, [r12, #96]",
            "adds r8, r8, #1",
            "cmp r8, r9",
            "beq 70f",
            "movs r8, #{spin_end}",
            "20:",
            "subs r8, r8, #1",
            "bne 20b",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bpl 21f",
            "5:",
            "ldm r4, {{r0, r1, r2, r3}}",  // chain output, swapped in the PRF's block-0 window
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "60:",
            "ldr r8, [r4, #0x18]",
            "tst r8, #10",
            "bne 50f",
            "51:",
            "str lr, [r4, #-12]",          // INIT (PRF)
            "ldr r8, [r5]",
            "ldr r9, [r5, #4]",
            "ldr r10, [r5, #8]",
            "ldr r11, [r5, #12]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "ldr r8, [r5, #16]",
            "ldr r9, [r5, #20]",
            "ldr r10, [r5, #24]",
            "ldr r11, [r5, #28]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "ldrd r8, r9, [r12, #40]",
            "ldrd r10, r11, [r12, #48]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "ldrd r8, r9, [r12, #56]",
            "ldrd r10, r11, [r12, #64]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "ldr r8, [r12, #72]",
            "str r8, [r4, #-8]",           // word 16 (tail 8): block 0 starts
            // block-0 window: next chain index, the previous chain's output
            "ldr r10, [r12, #92]",
            "adds r10, r10, #1",           // Z: first chain (i was u32::MAX)
            "str r10, [r12, #92]",
            "rev r11, r10",
            "str r11, [r12, #32]",         // c13 = rev(i)
            "beq 52f",
            "ldr r9, [r12, #88]",
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "str r0, [r9]",
            "str r1, [r9, #4]",
            "str r2, [r9, #8]",
            "str r3, [r9, #12]",
            "add r9, r9, #16",
            "str r9, [r12, #88]",
            "52:",
            "ldrd r8, r9, [r12, #76]",     // tail 9, 10
            "movs r5, #0",
            "mov.w r3, #256",
            "str r8, [r4, #-8]",           // waits for block 0
            "str r9, [r4, #-8]",
            "str r11, [r4, #-8]",          // rev(i)
            "str r3, [r4, #-4]",           // DCAL (NBLW = 0)
            "ldm r12, {{r9, r10, r11}}",   // the first step's c0..c2
            "movs r8, #{spin_prf}",
            "30:",
            "subs r8, r8, #1",
            "bne 30b",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bpl 31f",
            "6:",
            "ldm r4, {{r0, r1, r2, r3}}",  // chain secret; r1..r3 swapped in the step's window
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "rev r0, r0",
            "b 3b",
            // ---- last chain: counted poll, read, clear, store ----
            "70:",
            "mov.w r9, #16777216",
            "71:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 72f",
            "subs r9, r9, #1",
            "bne 71b",
            "b 99f",
            "72:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r8, #1",
            "str r8, [r4, #0x18]",
            "ldr r9, [r12, #88]",
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "str r0, [r9]",
            "str r1, [r9, #4]",
            "str r2, [r9, #8]",
            "str r3, [r9, #12]",
            "b 98f",
            // ---- DCIS not yet: seven straight polls, then a counted poll ----
            "11:",
            ".rept 7",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 4b",
            ".endr",
            "mov.w r0, #16777216",         // r0..r3 are dead before the HR read; r9..r11 hold c0..c2
            "12:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 4b",
            "subs r0, r0, #1",
            "bne 12b",
            "b 99f",
            "21:",
            ".rept 7",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 5b",
            ".endr",
            "mov.w r9, #16777216",
            "22:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 5b",
            "subs r9, r9, #1",
            "bne 22b",
            "b 99f",
            "31:",
            ".rept 7",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 6b",
            ".endr",
            "mov.w r0, #16777216",
            "32:",
            "ldr r8, [r4, #0x18]",
            "lsls r8, r8, #30",
            "bmi 6b",
            "subs r0, r0, #1",
            "bne 32b",
            "b 99f",
            // ---- BUSY still set, or a stale DCIS (step INIT / PRF INIT) ----
            "40:",
            "mov.w lr, #16777216",         // r0..r3 hold the digest, r9..r11 c0..c2
            "42:",
            "tst r8, #8",
            "beq 43f",
            "subs lr, lr, #1",
            "beq 99f",
            "ldr r8, [r4, #0x18]",
            "b 42b",
            "43:",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "tst r8, #2",
            "beq 41b",
            "b 99f",
            "50:",
            "mov.w r9, #16777216",
            "53:",
            "tst r8, #8",
            "beq 54f",
            "subs r9, r9, #1",
            "beq 99f",
            "ldr r8, [r4, #0x18]",
            "b 53b",
            "54:",
            "tst r8, #2",
            "beq 51b",
            "99:",
            "bl {fault}",
            "98:",
            spin = const V1K_SPIN_STEP,
            spin_end = const V1K_SPIN_END,
            spin_prf = const V1K_SPIN_PRF,
            fault = sym hash_engine_fault,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            in("r4") HASH_BASE + 0x0C,
            out("r5") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            in("r12") st,
            out("lr") _,
        );
    }
}

/// `v1-asm-key-ga` (round 9, secure-only; the FSBL never names it): `v1_key_asm` as a
/// standalone AAPCS function in `global_asm!`. There r6 and r7 are ordinary callee-saved
/// registers (saved in the prologue with r4..r11 and lr, sp kept 8-byte aligned), so LLVM's
/// frame-pointer (r7) and base-pointer (r6) uses never meet this code: nothing in it runs
/// inside a Rust frame. The two extra registers hold c3 and c8 between steps, so a step's
/// block 0 loads four words (one `ldm`) instead of six. Same digests, same per-digest checks.
/// Called as `pq1_v1_key_loop(st)` with the staging layout of `v1_key_asm`.
#[cfg(all(feature = "v1-asm-key-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
core::arch::global_asm!(
    ".syntax unified",
    ".section .text.pq1_v1_key_loop,\"ax\",%progbits",
    ".p2align 2",
    ".global pq1_v1_key_loop",
    ".type pq1_v1_key_loop,%function",
    ".thumb_func",
    "pq1_v1_key_loop:",
    "push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
    "sub sp, sp, #4",  // sp 8-byte aligned at the bl to the fault hook
    "mov r12, r0",  // st
    "movw r4, #{hb_lo}",
    "movt r4, #{hb_hi}",  // HASH_BASE + 0x0C
    "movw lr, #0x24",
    "movt lr, #0x6",
    "ldr r5, [r12, #84]",  // sk_seed
    "b 60f",
    // ---- chain step loop (as v1_chain_asm) ----
    "1:",
    "movs r8, #{spin}",
    "10:",
    "subs r8, r8, #1",
    "bne 10b",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bpl 11f",
    "4:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r8, #1",
    "str r8, [r4, #0x18]",
    "rev r0, r0",
    "3:",
    "ldr r8, [r4, #0x18]",
    "tst r8, #10",
    "bne 40f",
    "41:",
    // block 0: c0 c1 c2 c3 c8 arrive preloaded in r6 r7 r9 r10 r11 (loaded in the previous
    // digest's window); c9 c10 c12 c13 by one ldm.
    "str lr, [r4, #-12]",  // INIT
    "str r6, [r4, #-8]",  // c0
    "str r7, [r4, #-8]",  // c1
    "str r9, [r4, #-8]",  // c2
    "str r10, [r4, #-8]",  // c3
    "movs.w lr, #0",
    "add r8, r12, #20",
    "ldm r8, {{r6, r8, r9, r10}}",  // c9, c10, c12, c13 (ascending registers <- ascending words)
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r11, [r4, #-8]",  // c8
    "str r6, [r4, #-8]",  // c9
    "str r8, [r4, #-8]",  // c10
    "rev r7, r5",  // position
    "str lr, [r4, #-8]",
    "str r9, [r4, #-8]",  // c12
    "str r10, [r4, #-8]",  // c13 = rev(i)
    "str r7, [r4, #-8]",  // position
    "str lr, [r4, #-8]",
    "str r0, [r4, #-8]",  // word 16: block 0 starts
    // block-0 window: swaps, position, end test (flags live to the bne), next c0 c1 c2 c3 c8
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "add r5, r5, #1",
    "ldr r11, [r12, #36]",
    "cmp r5, r11",
    "ldm r12, {{r6, r7, r9, r10, r11}}",
    "mov.w r8, #256",
    "str r1, [r4, #-8]",  // waits for block 0
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r8, [r4, #-4]",  // DCAL (NBLW = 0)
    "movw lr, #0x24",
    "movt lr, #0x6",
    "bne 1b",
    // ---- chain done: the next chain's PRF, or the last read-out ----
    "ldr r5, [r12, #84]",  // sk_seed
    "ldr r8, [r12, #92]",
    "ldr r9, [r12, #96]",
    "adds r8, r8, #1",
    "cmp r8, r9",
    "beq 70f",
    "movs r8, #{spin_end}",
    "20:",
    "subs r8, r8, #1",
    "bne 20b",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bpl 21f",
    "5:",
    "ldm r4, {{r0, r1, r2, r3}}",  // chain output, swapped in the PRF's block-0 window
    "movs r8, #1",
    "str r8, [r4, #0x18]",
    "60:",
    "ldr r8, [r4, #0x18]",
    "tst r8, #10",
    "bne 50f",
    "51:",
    "str lr, [r4, #-12]",  // INIT (PRF)
    "ldr r8, [r5]",
    "ldr r9, [r5, #4]",
    "ldr r10, [r5, #8]",
    "ldr r11, [r5, #12]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "ldr r8, [r5, #16]",
    "ldr r9, [r5, #20]",
    "ldr r10, [r5, #24]",
    "ldr r11, [r5, #28]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "ldrd r8, r9, [r12, #40]",
    "ldrd r10, r11, [r12, #48]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "ldrd r8, r9, [r12, #56]",
    "ldrd r10, r11, [r12, #64]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "ldr r8, [r12, #72]",
    "str r8, [r4, #-8]",  // word 16 (tail 8): block 0 starts
    // block-0 window: next chain index, the previous chain's output
    "ldr r10, [r12, #92]",
    "adds r10, r10, #1",  // Z: first chain (i was u32::MAX)
    "str r10, [r12, #92]",
    "rev r11, r10",
    "str r11, [r12, #32]",  // c13 = rev(i)
    "beq 52f",
    "ldr r9, [r12, #88]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "str r0, [r9]",
    "str r1, [r9, #4]",
    "str r2, [r9, #8]",
    "str r3, [r9, #12]",
    "add r9, r9, #16",
    "str r9, [r12, #88]",
    "52:",
    "ldrd r8, r9, [r12, #76]",  // tail 9, 10
    "movs r5, #0",
    "mov.w r3, #256",
    "str r8, [r4, #-8]",  // waits for block 0
    "str r9, [r4, #-8]",
    "str r11, [r4, #-8]",  // rev(i)
    "str r3, [r4, #-4]",  // DCAL (NBLW = 0)
    "ldm r12, {{r6, r7, r9, r10, r11}}",  // the first step's c0 c1 c2 c3 c8
    "movs r8, #{spin_prf}",
    "30:",
    "subs r8, r8, #1",
    "bne 30b",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bpl 31f",
    "6:",
    "ldm r4, {{r0, r1, r2, r3}}",  // chain secret; r1..r3 swapped in the step's window
    "movs r8, #1",
    "str r8, [r4, #0x18]",
    "rev r0, r0",
    "b 3b",
    // ---- last chain: counted poll, read, clear, store ----
    "70:",
    "mov.w r9, #16777216",
    "71:",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 72f",
    "subs r9, r9, #1",
    "bne 71b",
    "b 99f",
    "72:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r8, #1",
    "str r8, [r4, #0x18]",
    "ldr r9, [r12, #88]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "str r0, [r9]",
    "str r1, [r9, #4]",
    "str r2, [r9, #8]",
    "str r3, [r9, #12]",
    "b 98f",
    // ---- DCIS not yet: seven straight polls, then a counted poll ----
    "11:",
    ".rept 7",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 4b",
    ".endr",
    "mov.w r0, #16777216",  // r0..r3 are dead before the HR read; r9..r11 hold c0..c2
    "12:",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 4b",
    "subs r0, r0, #1",
    "bne 12b",
    "b 99f",
    "21:",
    ".rept 7",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 5b",
    ".endr",
    "mov.w r9, #16777216",
    "22:",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 5b",
    "subs r9, r9, #1",
    "bne 22b",
    "b 99f",
    "31:",
    ".rept 7",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 6b",
    ".endr",
    "mov.w r0, #16777216",
    "32:",
    "ldr r8, [r4, #0x18]",
    "lsls r8, r8, #30",
    "bmi 6b",
    "subs r0, r0, #1",
    "bne 32b",
    "b 99f",
    // ---- BUSY still set, or a stale DCIS (step INIT / PRF INIT) ----
    "40:",
    "mov.w lr, #16777216",  // r0..r3 hold the digest, r9..r11 c0..c2
    "42:",
    "tst r8, #8",
    "beq 43f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r8, [r4, #0x18]",
    "b 42b",
    "43:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r8, #2",
    "beq 41b",
    "b 99f",
    "50:",
    "mov.w r9, #16777216",
    "53:",
    "tst r8, #8",
    "beq 54f",
    "subs r9, r9, #1",
    "beq 99f",
    "ldr r8, [r4, #0x18]",
    "b 53b",
    "54:",
    "tst r8, #2",
    "beq 51b",
    "99:",
    "bl {fault}",
    "98:",
    "add sp, sp, #4",
    "pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}",
    ".size pq1_v1_key_loop, . - pq1_v1_key_loop",
    spin = const V1K_SPIN_STEP,
    spin_end = const V1K_SPIN_END,
    spin_prf = const V1K_SPIN_PRF,
    hb_lo = const (HASH_BASE + 0x0C) & 0xFFFF,
    hb_hi = const (HASH_BASE + 0x0C) >> 16,
    fault = sym hash_engine_fault,
);

#[cfg(all(feature = "v1-asm-key-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
extern "C" {
    /// The `v1-asm-key-ga` loop above.
    fn pq1_v1_key_loop(st: *mut u32);
}

/// All `n` chains of one WOTS key in one call (`prfchain`, secure image only).
/// For `k` in `0..n`, chain `i = order[k]` (or `k` when `order` is null):
/// `s_i = SHA-256(sk_seed ‖ prf_tail with ci = i)[..16]`, then `steps_i`
/// chain steps from position 0 over `seed_adrs` with the chain index set to
/// `i` (`steps_i = digits[i]`, or `fixed_steps` when `digits` is null); the
/// result goes to `out[16 i..16 i + 16]`. The fixed words are loaded once per
/// key, the secrets and intermediate values stay in registers, and `sk_seed`
/// is read in place.
///
/// # Safety
/// `sk_seed` 32, `prf_tail` 48 and `seed_adrs` 64 readable bytes; `order` and
/// `digits` null or `n` readable bytes, each order entry `< n`; `out` `16 n`
/// writable bytes; no other SHA-256 stream in flight.
#[cfg(feature = "prfchain")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_wots_chains16(
    sk_seed: *const u8,
    prf_tail: *const u8,
    seed_adrs: *const u8,
    order: *const u8,
    digits: *const u8,
    fixed_steps: u32,
    n: u32,
    out: *mut u8,
) {
    // SAFETY: caller contract (64 readable bytes).
    let mut c: [u32; 16] = core::array::from_fn(|i| unsafe { seed_adrs.add(4 * i).cast::<u32>().read_unaligned() });
    // SAFETY: caller contract (48 readable bytes).
    let t: [u32; 12] = core::array::from_fn(|i| unsafe { prf_tail.add(4 * i).cast::<u32>().read_unaligned() });
    let z = c[4] | c[5] | c[6] | c[7] | c[11] | c[15] == 0;
    // The asm stores chain i's output after chain i + 1's PRF has read `sk_seed`; the loop
    // below stores it first. Take the asm path only when `out` cannot overlap `sk_seed`
    // (public pointers), so both paths give the same bytes for every input.
    #[cfg(all(feature = "v1-asm-key", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    if z
        && order.is_null()
        && digits.is_null()
        && fixed_steps != 0
        && n != 0
        && ((out as usize).saturating_add(16 * n as usize) <= sk_seed as usize || sk_seed as usize + 32 <= out as usize)
    {
        // The engine is idle (no stale DCIS) before STR, as in the loop below; every
        // digest of the asm loop writes STR only with DCAL (NBLW 0).
        if wait_ready_sr() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
        let mut st = [
            c[0], c[1], c[2], c[3], c[8], c[9], c[10], c[12], 0, fixed_steps,
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10],
            sk_seed as u32, out as u32, u32::MAX, n,
        ];
        #[cfg(not(feature = "v1-asm-key-ga"))]
        v1_key_asm(st.as_mut_ptr());
        #[cfg(feature = "v1-asm-key-ga")]
        // SAFETY: the `global_asm!` loop's contract is `v1_key_asm`'s (the staging array above).
        unsafe {
            pq1_v1_key_loop(st.as_mut_ptr())
        };
        #[cfg(feature = "tick-batch")]
        // SAFETY: the engine is idle; the tick does not hash. One tick per key.
        unsafe {
            pqsigner_hash_tick_n(n * (1 + fixed_steps));
        }
        return;
    }
    #[cfg(feature = "tick-batch")]
    let mut ticks = 0u32;
    let mut k = 0u32;
    while k < n {
        // SAFETY: caller contract on `order` / `digits`.
        let i = if order.is_null() { k } else { u32::from(unsafe { *order.add(k as usize) }) };
        if i >= n {
            // An out-of-range chain index would write outside `out`.
            hash_engine_fault();
        }
        let steps = if digits.is_null() { fixed_steps } else { u32::from(unsafe { *digits.add(i as usize) }) };
        let ci = i.swap_bytes();
        // PRF: sk_seed ‖ tail[0..11] ‖ ci.
        if ready_sr_fast() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
        REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
        // SAFETY: caller contract (32 readable bytes).
        unsafe { feed_words(sk_seed, 8) };
        write_word(t[0]); write_word(t[1]); write_word(t[2]); write_word(t[3]);
        write_word(t[4]); write_word(t[5]); write_word(t[6]); write_word(t[7]);
        write_word(t[8]); write_word(t[9]); write_word(t[10]); write_word(ci);
        REG.str_.write(STR_DCAL);
        let mut w = 0u32;
        while REG.sr.read() & SR_DCIS == 0 {
            w += 1;
            if w > 10_000_000 {
                hash_engine_fault();
            }
        }
        let v = read_hr4();
        REG.sr.write(SR_DINIS);
        #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
        // SAFETY: as in `final_body`.
        unsafe {
            pqsigner_hash_tick();
        }
        #[cfg(feature = "tick-batch")]
        {
            ticks += 1 + steps;
        }
        c[13] = ci;
        let v = if z { chain_steps::<true>(&c, v, 0, steps) } else { chain_steps::<false>(&c, v, 0, steps) };
        for (j, x) in v.iter().enumerate() {
            // SAFETY: `out + 16 i + 4 j` is inside the caller's `16 n` bytes (i < n).
            unsafe { out.add(16 * i as usize + 4 * j).cast::<u32>().write_unaligned(*x) };
        }
        k += 1;
    }
    #[cfg(feature = "tick-batch")]
    // SAFETY: the engine is idle; the tick does not hash. One tick per key.
    unsafe {
        pqsigner_hash_tick_n(ticks);
    }
}

/// `th_multi` in place (`gather`, secure image only): first 16 bytes of
/// SHA-256(seed ‖ adrs ‖ pad16(v_0) ‖ … ‖ pad16(v_{n-1})), with `seed` and `adrs`
/// (32 bytes each) and the `n` 16-byte values read where they are.
///
/// # Safety
/// `seed`, `adrs` 32 readable bytes each, `vals` `16 n` readable bytes, `out`
/// 16 writable; no other SHA-256 stream in flight.
#[cfg(feature = "gather")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_th_multi16(seed: *const u8, adrs: *const u8, vals: *const u8, n: u32, out: *mut u8) {
    gather_init();
    // SAFETY: caller contract.
    unsafe {
        feed32(seed);
        feed32(adrs);
        let mut i = 0usize;
        while i < n as usize {
            let q = vals.add(16 * i).cast::<u32>();
            let (a, b, c, d) = (q.read_unaligned(), q.add(1).read_unaligned(), q.add(2).read_unaligned(), q.add(3).read_unaligned());
            write_word(a);
            write_word(b);
            write_word(c);
            write_word(d);
            write_word(0);
            write_word(0);
            write_word(0);
            write_word(0);
            i += 1;
        }
        gather_final16(out);
    }
}

/// One DCAL + wait + HR0..HR3 read-out + DCIS clear, value returned in registers.
#[cfg(feature = "forsleaf")]
#[inline(always)]
fn final16_regs() -> [u32; 4] {
    REG.str_.write(STR_DCAL);
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            hash_engine_fault();
        }
    }
    let v = read_hr4();
    REG.sr.write(SR_DINIS);
    v
}

/// `v1-asm-fors` (round 8, secure-only; the FSBL never names it): the digest-to-digest
/// transitions of the v1 FORS subtree, hand-scheduled. Each waits for the digest in
/// flight (straight-line polls, then a 2^24-guarded loop), reads HR0..3, clears DCIS,
/// waits for BUSY to clear (2^24 guard) and refuses a stale DCIS, INIT, feeds the next
/// message with NBLW 0, DCAL. Work that does not feed block 0 sits after the 17th DIN
/// store, where the CPU would otherwise stall on block 0. The Rust caller runs the
/// tree logic while the engine works.
#[cfg(feature = "v1-asm-fors")]
macro_rules! v1x_head {
    () => {
        concat!(
            "movw lr, #0x24\n", "movt lr, #0x6\n",
            ".rept 16\n", "ldr r12, [r4, #0x18]\n", "lsls r12, r12, #30\n", "bmi 4f\n", ".endr\n",
            "mov.w r10, #16777216\n",
            "3:\n", "ldr r12, [r4, #0x18]\n", "lsls r12, r12, #30\n", "bmi 4f\n", "subs r10, r10, #1\n", "bne 3b\n", "b 99f\n",
            "4:\n",
            "ldm r4, {{r0, r1, r2, r3}}\n",
            "movs r12, #1\n", "str r12, [r4, #0x18]\n",
        )
    };
}
#[cfg(feature = "v1-asm-fors")]
macro_rules! v1x_init {
    () => {
        concat!("ldr r12, [r4, #0x18]\n", "tst r12, #10\n", "bne 40f\n", "41:\n", "str lr, [r4, #-12]\n")
    };
}
#[cfg(feature = "v1-asm-fors")]
macro_rules! v1x_tail {
    () => {
        concat!(
            "b 98f\n",
            "40:\n", "mov.w r10, #16777216\n",
            "42:\n", "tst r12, #8\n", "beq 43f\n", "subs r10, r10, #1\n", "beq 99f\n", "ldr r12, [r4, #0x18]\n", "b 42b\n",
            "43:\n", "tst r12, #2\n", "beq 41b\n",
            "99:\n", "bl {fault}\n",
            "98:\n",
        )
    };
}
#[cfg(feature = "v1-asm-fors")]
macro_rules! v1x_st4 {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!("str ", $a, ", [r4, #-8]\n", "str ", $b, ", [r4, #-8]\n", "str ", $c, ", [r4, #-8]\n", "str ", $d, ", [r4, #-8]\n")
    };
}
#[cfg(feature = "v1-asm-fors")]
macro_rules! v1x_blk0 {
    () => {
        concat!(
            "ldm r5!, {{r8, r9, r10, r12}}\n", v1x_st4!("r8", "r9", "r10", "r12"),
            "ldm r5!, {{r8, r9, r10, r12}}\n", v1x_st4!("r8", "r9", "r10", "r12"),
            "ldm r5!, {{r8, r9, r10, r12}}\n", v1x_st4!("r8", "r9", "r10", "r12"),
            "ldm r5!, {{r8, r9, r10, r12}}\n", v1x_st4!("r8", "r9", "r10", "r12"),
        )
    };
}

/// Transition into the PRF of the next leaf: message `sk_seed ‖ tp[0..4]` (12 words, one
/// block), `sk_seed` read in place with single-word loads (no copy). Returns the digest
/// in flight (a finished leaf or node).
#[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1x_prf(sk: *const u8, tp: *const u32) -> [u32; 4] {
    let (v0, v1, v2, v3): (u32, u32, u32, u32);
    // SAFETY: drives only the secure HASH block (r4); reads 32 bytes at `sk` and 16 at
    // `tp`; on a hang or a stale DCIS it calls `hash_engine_fault`, which does not return.
    unsafe {
        core::arch::asm!(
            v1x_head!(),
            v1x_init!(),
            "ldr r8, [r5]\n", "ldr r9, [r5, #4]\n", "ldr r10, [r5, #8]\n", "ldr r12, [r5, #12]\n",
            v1x_st4!("r8", "r9", "r10", "r12"),
            "ldr r8, [r5, #16]\n", "ldr r9, [r5, #20]\n", "ldr r10, [r5, #24]\n", "ldr r12, [r5, #28]\n",
            v1x_st4!("r8", "r9", "r10", "r12"),
            "ldm r11, {{r8, r9, r10, r12}}\n",
            v1x_st4!("r8", "r9", "r10", "r12"),
            "mov.w r8, #256\n", "str r8, [r4, #-4]\n",
            "rev r0, r0\n", "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n",
            v1x_tail!(),
            fault = sym hash_engine_fault,
            out("r0") v0, out("r1") v1, out("r2") v2, out("r3") v3,
            in("r4") HASH_BASE + 0x0C, in("r5") sk, in("r11") tp,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
    [v0, v1, v2, v3]
}

/// Transition into the leaf: message `la[0..16] ‖ x ‖ 0^4` (24 words, two blocks) with
/// `x` the PRF digest in flight, which stays in registers.
#[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1x_leaf(la: *const u32) {
    // SAFETY: as `v1x_prf`; reads 64 bytes at `la` (4-aligned).
    unsafe {
        core::arch::asm!(
            v1x_head!(),
            "rev r0, r0\n",
            v1x_init!(),
            v1x_blk0!(),
            "str r0, [r4, #-8]\n",                 // word 16: block 0 starts
            "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n", "movs.w lr, #0\n", "mov.w r8, #256\n",
            v1x_st4!("r1", "r2", "r3", "lr"),      // the first store waits for block 0
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            "str r8, [r4, #-4]\n",                 // DCAL
            v1x_tail!(),
            fault = sym hash_engine_fault,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            in("r4") HASH_BASE + 0x0C, inout("r5") la => _,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
}

/// Transition into a node: message `na[0..16] ‖ L ‖ 0^4 ‖ R ‖ 0^4` (32 words, three
/// blocks) with `R` the digest in flight and `L` the four words at `l`.
#[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1x_node(na: *const u32, l: *const u32) {
    // SAFETY: as `v1x_prf`; reads 64 bytes at `na` and 16 at `l` (both 4-aligned).
    unsafe {
        core::arch::asm!(
            v1x_head!(),
            v1x_init!(),
            v1x_blk0!(),
            "ldm r11, {{r8, r9, r10, r12}}\n",
            "str r8, [r4, #-8]\n",                 // word 16: block 0 starts
            "rev r0, r0\n", "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n", "movs.w lr, #0\n", "mov.w r8, #256\n",
            v1x_st4!("r9", "r10", "r12", "lr"),    // the first store waits for block 0
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            v1x_st4!("r0", "r1", "r2", "r3"),
            v1x_st4!("lr", "lr", "lr", "lr"),
            "str r8, [r4, #-4]\n",                 // DCAL
            v1x_tail!(),
            fault = sym hash_engine_fault,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            in("r4") HASH_BASE + 0x0C, inout("r5") na => _, in("r11") l,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
}

/// `v1x_leaf` for the FORS shape (round 9): block 0 is `s0..s3 ‖ 0^4 ‖ 0 ‖ 0 ‖ w10 w11 w12 ‖ 0 ‖ 0
/// ‖ be32(j)` (pad16's zero half, layer 0, the tree's high word, ci and height 0; checked in
/// Rust), so only `lz = [s0..s3, w10, w11, w12, be32(j)]` is loaded and the zeros come from a
/// register.
#[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1x_leaf_z(lz: *const u32) {
    // SAFETY: as `v1x_prf`; reads 32 bytes at `lz` (4-aligned).
    unsafe {
        core::arch::asm!(
            v1x_head!(),
            "rev r0, r0\n",
            v1x_init!(),
            "ldm r5, {{r8, r9, r10, r12}}\n",      // s0..s3
            "movs.w lr, #0\n",
            v1x_st4!("r8", "r9", "r10", "r12"),
            v1x_st4!("lr", "lr", "lr", "lr"),
            "add r8, r5, #16\n",
            "ldm r8, {{r8, r9, r10, r12}}\n",      // w10, w11, w12, be32(j)
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            "str r8, [r4, #-8]\n", "str r9, [r4, #-8]\n", "str r10, [r4, #-8]\n",
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            "str r12, [r4, #-8]\n",
            "str r0, [r4, #-8]\n",                 // word 16: block 0 starts
            "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n", "mov.w r8, #256\n",
            v1x_st4!("r1", "r2", "r3", "lr"),      // the first store waits for block 0
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            "str r8, [r4, #-4]\n",                 // DCAL
            v1x_tail!(),
            fault = sym hash_engine_fault,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            in("r4") HASH_BASE + 0x0C, in("r5") lz,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
}

/// `v1x_node` for the FORS shape (round 9): block 0 is `s0..s3 ‖ 0^4 ‖ 0 ‖ 0 ‖ w10 w11 w12 ‖ 0 ‖
/// be32(h) ‖ be32(i)`; `nz = [s0..s3, w10, w11, w12, be32(h), be32(i)]`.
#[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1x_node_z(nz: *const u32, l: *const u32) {
    // SAFETY: as `v1x_prf`; reads 36 bytes at `nz` and 16 at `l` (both 4-aligned).
    unsafe {
        core::arch::asm!(
            v1x_head!(),
            v1x_init!(),
            "ldm r5, {{r8, r9, r10, r12}}\n",      // s0..s3
            "movs.w lr, #0\n",
            v1x_st4!("r8", "r9", "r10", "r12"),
            v1x_st4!("lr", "lr", "lr", "lr"),
            "add r8, r5, #16\n",
            "ldm r8, {{r8, r9, r10, r12}}\n",      // w10, w11, w12, be32(h)
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            "str r8, [r4, #-8]\n", "str r9, [r4, #-8]\n", "str r10, [r4, #-8]\n",
            "ldr r8, [r5, #32]\n",                 // be32(i)
            "str lr, [r4, #-8]\n",
            "str r12, [r4, #-8]\n",
            "str r8, [r4, #-8]\n",
            "ldm r11, {{r8, r9, r10, r12}}\n",
            "str r8, [r4, #-8]\n",                 // word 16: block 0 starts
            "rev r0, r0\n", "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n", "mov.w r8, #256\n",
            v1x_st4!("r9", "r10", "r12", "lr"),    // the first store waits for block 0
            "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n", "str lr, [r4, #-8]\n",
            v1x_st4!("r0", "r1", "r2", "r3"),
            v1x_st4!("lr", "lr", "lr", "lr"),
            "str r8, [r4, #-4]\n",                 // DCAL
            v1x_tail!(),
            fault = sym hash_engine_fault,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _,
            in("r4") HASH_BASE + 0x0C, in("r5") nz, in("r11") l,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
}

/// `v1-asm-fors-ga` (round 10, secure-only; the FSBL never names it): the whole 16-leaf FORS
/// subtree of the FORS shape (see `v1x_leaf_z`) as one standalone AAPCS function in
/// `global_asm!`, tree logic included (the E9 pattern: r6/r7 are ordinary callee-saved registers
/// here). The leaf's seven fixed words stay in r5..r11 across its wait, so a leaf loads only
/// `be32(j)`; a node loads `be32(h)`, `be32(i)` and `L[0]` between stores and `L[1..3]` after the
/// 17th store; a PRF finds `sk_seed[0..7)` preloaded (registers only, read in place with single
/// loads) and loads `sk_seed[7]`, the tail and `be32(j)` after INIT. The finished node's push,
/// the index updates and the constant reloads run in the engine windows. Every digest keeps the
/// checks of the Rust loop (DCIS poll with a 2^24 guard, SR clear, BUSY wait with a 2^24 guard
/// and stale-DCIS refusal before INIT, NBLW 0). It issues leaf `j0`'s PRF itself, so the caller
/// never holds `sk_seed` words its prologue would push (round 10: the residue gate caught that);
/// `ctx`:
/// 0..7 leaf words 0..3, 10..12; 7..14 node words 0..3, 10..12; 14..17 tail; 17 `sk_seed`;
/// 18 `j0`; 19..23 the root (out).
#[cfg(all(feature = "v1-asm-fors-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
core::arch::global_asm!(
    ".syntax unified",
    ".section .text.pq1_v1_fors_sub_z,\"ax\",%progbits",
    ".p2align 2",
    ".global pq1_v1_fors_sub_z",
    ".type pq1_v1_fors_sub_z,%function",
    ".thumb_func",
    "pq1_v1_fors_sub_z:",
    "push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
    "sub sp, sp, #196",
    // frame: 0 L0..L6, 28 N0..N6, 56 t0 t1 t2, 68 rev(j+1), 72 rev(j), 76 rev(h+1), 80 rev(j>>(h+1)),
    // 84 sk_seed, 88 j, 92 k, 96 depth, 100 h, 104 left ptr, 108 ctx, 112 node stack (5 x 16)
    "str r0, [sp, #108]",
    "mov r12, r0",
    "mov lr, sp",
    "ldm r12!, {{r0, r1, r2, r3, r5, r6, r7}}",
    "stm lr!, {{r0, r1, r2, r3, r5, r6, r7}}",
    "ldm r12!, {{r0, r1, r2, r3, r5, r6, r7}}",
    "stm lr!, {{r0, r1, r2, r3, r5, r6, r7}}",
    "ldm r12!, {{r0, r1, r2, r5, r6}}",
    "stm lr!, {{r0, r1, r2}}",
    "str r5, [sp, #84]",
    "str r6, [sp, #88]",
    "movs r0, #0",
    "str r0, [sp, #92]",
    "str r0, [sp, #96]",
    "rev r1, r6",
    "str r1, [sp, #72]",
    "adds r1, r6, #1",
    "rev r1, r1",
    "str r1, [sp, #68]",
    "movw r4, #{hb_lo}",
    "movt r4, #{hb_hi}",
    "movw lr, #0x24",
    "movt lr, #0x6",
    // first PRF (leaf j0), issued here so the caller never holds sk_seed words: idle and no stale
    // DCIS (as gather_init), STR 0, INIT, sk_seed (single loads, registers only), tail, be32(j0), DCAL
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 50f",
    "51:",
    "movs r0, #0",
    "str r0, [r4, #-4]",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #84]",
    "ldr r0, [r12]",
    "ldr r1, [r12, #4]",
    "ldr r2, [r12, #8]",
    "ldr r3, [r12, #12]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldr r0, [r12, #16]",
    "ldr r1, [r12, #20]",
    "ldr r2, [r12, #24]",
    "ldr r3, [r12, #28]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldr r0, [sp, #56]",
    "ldr r1, [sp, #60]",
    "ldr r2, [sp, #64]",
    "ldr r3, [sp, #72]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "mov.w r0, #256",
    "str r0, [r4, #-4]",
    "mov r12, sp",
    "ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}",
    "b 10f",
    // BUSY still set, or a stale DCIS, before the first INIT
    "50:",
    "mov.w r0, #16777216",
    "52:",
    "tst r12, #8",
    "beq 53f",
    "subs r0, r0, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 52b",
    "53:",
    "tst r12, #2",
    "beq 51b",
    "b 99f",
    // ==== LEAF (the PRF digest in flight; leaf constants in r5..r11) ====
    "10:",
    ".rept 16",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 11f",
    ".endr",
    "mov.w r0, #16777216",
    "12:",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 11f",
    "subs r0, r0, #1",
    "bne 12b",
    "b 99f",
    "11:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 13f",
    "14:",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #72]",
    "movs.w lr, #0",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r12, [r4, #-8]",
    "str r0, [r4, #-8]",
    // block-0 window
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "mov.w r12, #256",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r12, [r4, #-4]",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "ldr r0, [sp, #92]",
    "tst r0, #1",
    "bne 20f",
    "b 30f",
    "13:",
    "mov.w lr, #16777216",
    "15:",
    "tst r12, #8",
    "beq 16f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 15b",
    "16:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 14b",
    "b 99f",
    // ==== NODE (the right child in flight) ====
    "20:",
    "movs r0, #0",
    "str r0, [sp, #100]",
    "21:",
    "add r12, sp, #28",
    "ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}",
    "ldr r0, [sp, #100]",
    "adds r1, r0, #1",
    "rev r2, r1",
    "str r2, [sp, #76]",
    "ldr r2, [sp, #88]",
    "lsrs r2, r2, r1",
    "rev r2, r2",
    "str r2, [sp, #80]",
    "ldr r0, [sp, #96]",
    "subs r0, r0, #1",
    "str r0, [sp, #96]",
    "add r1, sp, #112",
    "add r0, r1, r0, lsl #4",
    "str r0, [sp, #104]",
    ".rept 16",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 22f",
    ".endr",
    "mov.w r0, #16777216",
    "25:",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 22f",
    "subs r0, r0, #1",
    "bne 25b",
    "b 99f",
    "22:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 23f",
    "24:",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #104]",
    "movs.w lr, #0",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "ldr r5, [r12]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r9, [r4, #-8]",
    "ldr r9, [sp, #76]",
    "str r10, [r4, #-8]",
    "ldr r10, [sp, #80]",
    "str r11, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r5, [r4, #-8]",
    // block-0 window
    "add r12, r12, #4",
    "ldm r12, {{r6, r7, r8}}",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "mov.w r12, #256",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str lr, [r4, #-8]",
    "str r12, [r4, #-4]",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "ldr r0, [sp, #100]",
    "adds r0, r0, #1",
    "str r0, [sp, #100]",
    "ldr r1, [sp, #92]",
    "lsrs r2, r1, r0",
    "tst r2, #1",
    "bne 21b",
    "cmp r1, #15",
    "beq 40f",
    "b 30f",
    "23:",
    "mov.w lr, #16777216",
    "26:",
    "tst r12, #8",
    "beq 27f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 26b",
    "27:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 24b",
    "b 99f",
    // ==== PRF of leaf j+1 (the finished leaf/node in flight) ====
    "30:",
    "ldr r12, [sp, #84]",
    "ldr r5, [r12]",
    "ldr r6, [r12, #4]",
    "ldr r7, [r12, #8]",
    "ldr r8, [r12, #12]",
    "ldr r9, [r12, #16]",
    "ldr r10, [r12, #20]",
    "ldr r11, [r12, #24]",
    ".rept 16",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 32f",
    ".endr",
    "mov.w r0, #16777216",
    "35:",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 32f",
    "subs r0, r0, #1",
    "bne 35b",
    "b 99f",
    "32:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 33f",
    "34:",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #84]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "ldr r12, [r12, #28]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "add lr, sp, #56",
    "ldm lr, {{r5, r6, r7, r8}}",
    "str r12, [r4, #-8]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "mov.w r12, #256",
    "str r12, [r4, #-4]",
    // PRF window: push the finished node, j += 1, k += 1, leaf constants back
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r5, [sp, #96]",
    "add r6, sp, #112",
    "add r6, r6, r5, lsl #4",
    "stm r6, {{r0, r1, r2, r3}}",
    "adds r5, r5, #1",
    "str r5, [sp, #96]",
    "ldr r0, [sp, #88]",
    "adds r0, r0, #1",
    "str r0, [sp, #88]",
    "rev r1, r0",
    "str r1, [sp, #72]",
    "adds r1, r0, #1",
    "rev r1, r1",
    "str r1, [sp, #68]",
    "ldr r0, [sp, #92]",
    "adds r0, r0, #1",
    "str r0, [sp, #92]",
    "mov r12, sp",
    "ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "b 10b",
    "33:",
    "mov.w lr, #16777216",
    "36:",
    "tst r12, #8",
    "beq 37f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 36b",
    "37:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 34b",
    "b 99f",
    // ==== root ====
    "40:",
    ".rept 16",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 41f",
    ".endr",
    "mov.w r0, #16777216",
    "43:",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 41f",
    "subs r0, r0, #1",
    "bne 43b",
    "b 99f",
    "41:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r12, [sp, #108]",
    "add r12, r12, #76",
    "stm r12, {{r0, r1, r2, r3}}",
    "b 98f",
    "99:",
    "bl {fault}",
    "98:",
    "add sp, sp, #196",
    "pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}",
    ".size pq1_v1_fors_sub_z, . - pq1_v1_fors_sub_z",

    hb_lo = const (HASH_BASE + 0x0C) & 0xFFFF,
    hb_hi = const (HASH_BASE + 0x0C) >> 16,
    fault = sym hash_engine_fault,
);

#[cfg(all(feature = "v1-asm-fors-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
extern "C" {
    /// The `v1-asm-fors-ga` subtree above.
    fn pq1_v1_fors_sub_z(ctx: *mut u32);
}

/// A 16-leaf FORS subtree in one call (`forsleaf`, secure image only): leaves
/// `j0..j0+16` (each `th(leaf_sa with ha = j, pad16(PRF(sk_seed ‖ tail with leaf = j)))`)
/// and the 15 nodes above them (`node_sa` with height and index set), in the
/// treehash order of `fors_tree_fast`; the height-4 root goes to `out`. No
/// auth-path logic: the caller builds the subtree that holds the revealed leaf
/// leaf by leaf.
///
/// # Safety
/// `sk_seed` 32, `tail` 16, `leaf_sa` and `node_sa` 64 readable bytes each, `out`
/// 16 writable; `j0` a multiple of 16; no other SHA-256 stream in flight.
#[cfg(feature = "forsleaf")]
#[no_mangle]
// `v1-asm-fors-ga`: the wrapper runs between every two calls of the asm subtree; one section keeps
// them contiguous, so a direct-mapped ICACHE (the shipped 1-way setting) cannot alias them.
#[cfg_attr(feature = "v1-asm-fors-ga", link_section = ".text.pq1_v1_fors_sub_z")]
pub unsafe extern "C" fn pqsigner_fors_subtree16(
    sk_seed: *const u8,
    tail: *const u8,
    leaf_sa: *const u8,
    node_sa: *const u8,
    j0: u32,
    out: *mut u8,
) {
    // SAFETY: caller contract (16 and 64 readable bytes).
    let t: [u32; 3] = core::array::from_fn(|i| unsafe { tail.add(4 * i).cast::<u32>().read_unaligned() });
    let la: [u32; 15] = core::array::from_fn(|i| unsafe { leaf_sa.add(4 * i).cast::<u32>().read_unaligned() });
    let na: [u32; 14] = core::array::from_fn(|i| unsafe { node_sa.add(4 * i).cast::<u32>().read_unaligned() });
    let mut stack = [[0u32; 4]; 5];
    #[cfg(all(feature = "v1-asm-fors", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    {
        // Block-0 staging for the asm transitions (4-aligned): the leaf's 15 fixed words and
        // its hash address; the node's 14 fixed words, height and index; the PRF tail.
        let mut la16 = [0u32; 16];
        la16[..15].copy_from_slice(&la);
        let mut na16 = [0u32; 16];
        na16[..14].copy_from_slice(&na);
        let mut tp = [t[0], t[1], t[2], j0.swap_bytes()];
        // The FORS shape (round 9): pad16's zero half, layer 0, the tree's high word, ci and
        // (for leaves) the height are zero. Public data; the zero-word transitions need it.
        let zf = la[4] | la[5] | la[6] | la[7] | la[8] | la[9] | la[13] | la[14] == 0
            && na[4] | na[5] | na[6] | na[7] | na[8] | na[9] | na[13] == 0;
        let mut lz = [la[0], la[1], la[2], la[3], la[10], la[11], la[12], 0];
        let mut nz = [na[0], na[1], na[2], na[3], na[10], na[11], na[12], 0, 0];
        let mut sp = 0usize;
        // `j0 + 16` before any digest, as the loop below evaluates it first.
        let end = j0 + 16;
        #[cfg(feature = "v1-asm-fors-ga")]
        if zf {
            let mut ctx = [
                la[0], la[1], la[2], la[3], la[10], la[11], la[12],
                na[0], na[1], na[2], na[3], na[10], na[11], na[12],
                t[0], t[1], t[2], sk_seed as u32, j0, 0, 0, 0, 0, 0,
            ];
            // SAFETY: the subtree's contract (the context above; it issues leaf j0's PRF);
            // `sk_seed` names 32 readable bytes (caller contract).
            unsafe { pq1_v1_fors_sub_z(ctx.as_mut_ptr()) };
            for k in 0..4 {
                // SAFETY: `out + 4k`, k < 4, inside the caller's 16 bytes.
                unsafe { out.add(4 * k).cast::<u32>().write_unaligned(ctx[19 + k]) };
            }
            let _ = (&mut lz, &mut nz, &mut la16, &mut na16, &mut tp, &mut stack, &mut sp, end);
            #[cfg(feature = "tick-batch")]
            // SAFETY: the engine is idle; the tick does not hash.
            unsafe {
                pqsigner_hash_tick_n(16 * 2 + 15);
            }
            return;
        }
        // PRF of leaf j0.
        gather_init();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        write_word(tp[0]);
        write_word(tp[1]);
        write_word(tp[2]);
        write_word(tp[3]);
        REG.str_.write(STR_DCAL);
        let mut j = j0;
        loop {
            if zf {
                lz[7] = j.swap_bytes();
                v1x_leaf_z(lz.as_ptr());
            } else {
                la16[15] = j.swap_bytes();
                v1x_leaf(la16.as_ptr());
            }
            // `j` is a right child at each height whose bit is set (j0 is a multiple of 16).
            let mut h = 0u32;
            while h < 4 && (j >> h) & 1 == 1 {
                sp -= 1;
                if zf {
                    nz[7] = (h + 1).swap_bytes();
                    nz[8] = (j >> (h + 1)).swap_bytes();
                    v1x_node_z(nz.as_ptr(), stack[sp].as_ptr());
                } else {
                    na16[14] = (h + 1).swap_bytes();
                    na16[15] = (j >> (h + 1)).swap_bytes();
                    v1x_node(na16.as_ptr(), stack[sp].as_ptr());
                }
                h += 1;
            }
            j += 1;
            let node = if j < end {
                tp[3] = j.swap_bytes();
                v1x_prf(sk_seed, tp.as_ptr())
            } else {
                let mut w = 0u32;
                while REG.sr.read() & SR_DCIS == 0 {
                    w += 1;
                    if w > 10_000_000 {
                        hash_engine_fault();
                    }
                }
                let v = read_hr4();
                REG.sr.write(SR_DINIS);
                v
            };
            stack[sp] = node;
            sp += 1;
            if j == end {
                break;
            }
        }
        for (k, x) in stack[0].iter().enumerate() {
            // SAFETY: `out + 4k`, k < 4, inside the caller's 16 bytes.
            unsafe { out.add(4 * k).cast::<u32>().write_unaligned(*x) };
        }
        #[cfg(feature = "tick-batch")]
        // SAFETY: the engine is idle; the tick does not hash.
        unsafe {
            pqsigner_hash_tick_n(16 * 2 + 15);
        }
        return;
    }
    #[allow(unreachable_code)]
    let mut heights = [0u32; 5];
    let mut sp = 0usize;
    let mut j = j0;
    while j < j0 + 16 {
        let jb = j.swap_bytes();
        // PRF: sk_seed ‖ "fors" ‖ ht ‖ tree ‖ leaf.
        gather_init();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        write_word(t[0]);
        write_word(t[1]);
        write_word(t[2]);
        write_word(jb);
        let sec = final16_regs();
        // Leaf: seed ‖ adrs(ha = j) ‖ pad16(secret).
        gather_init();
        for w in la {
            write_word(w);
        }
        write_word(jb);
        write_word(sec[0]);
        write_word(sec[1]);
        write_word(sec[2]);
        write_word(sec[3]);
        write_word(0);
        write_word(0);
        write_word(0);
        write_word(0);
        let mut node = final16_regs();
        let mut h = 0u32;
        while sp > 0 && heights[sp - 1] == h {
            sp -= 1;
            let left = stack[sp];
            gather_init();
            for w in na {
                write_word(w);
            }
            write_word((h + 1).swap_bytes());
            write_word((j >> (h + 1)).swap_bytes());
            write_word(left[0]);
            write_word(left[1]);
            write_word(left[2]);
            write_word(left[3]);
            write_word(0);
            write_word(0);
            write_word(0);
            write_word(0);
            write_word(node[0]);
            write_word(node[1]);
            write_word(node[2]);
            write_word(node[3]);
            write_word(0);
            write_word(0);
            write_word(0);
            write_word(0);
            node = final16_regs();
            h += 1;
        }
        stack[sp] = node;
        heights[sp] = h;
        sp += 1;
        j += 1;
    }
    for (k, x) in stack[0].iter().enumerate() {
        // SAFETY: `out + 4k`, k < 4, inside the caller's 16 bytes.
        unsafe { out.add(4 * k).cast::<u32>().write_unaligned(*x) };
    }
    #[cfg(feature = "tick-batch")]
    // SAFETY: the engine is idle; the tick does not hash.
    unsafe {
        pqsigner_hash_tick_n(16 * 2 + 15);
    }
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body` (one call stands for the subtree's 47 digests here).
    unsafe {
        pqsigner_hash_tick();
    }
}

/// Feed `n` words from `p` (unaligned reads).
#[cfg(any(feature = "prfchain", feature = "forsleaf", feature = "search"))]
#[inline(always)]
unsafe fn feed_words(p: *const u8, n: usize) {
    // Fully unrolled for the constant `n` of every caller (4, 8, 12, 16):
    // loads are issued in groups of four ahead of their stores.
    if n % 4 != 0 {
        // Every caller passes 4, 8, 12, 16 or 28; a remainder would be dropped.
        hash_engine_fault();
    }
    let q = p.cast::<u32>();
    let mut i = 0;
    while i + 4 <= n {
        // SAFETY: callers pass `p` naming `4n` readable bytes.
        let (a, b, c, d) = unsafe {
            (q.add(i).read_unaligned(), q.add(i + 1).read_unaligned(), q.add(i + 2).read_unaligned(), q.add(i + 3).read_unaligned())
        };
        write_word(a);
        write_word(b);
        write_word(c);
        write_word(d);
        i += 4;
    }
}

/// Start one digest of the 128-byte message at `buf` with its last word
/// (bytes [124..128)) replaced by `count` big-endian: init (stale-DCIS check,
/// NBLW = 0, INIT), 32 DIN words, DCAL. `search` only.
#[cfg(feature = "search")]
#[inline(always)]
unsafe fn issue128(buf: *const u8, count: u32) {
    if ready_sr_fast() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.str_.write(0);
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
    // SAFETY: `buf..buf + 124` is inside the caller's 128 bytes.
    unsafe { feed_words(buf, 28) };
    // SAFETY: words 28..31 of the same 128 bytes.
    let q = unsafe { buf.add(112).cast::<u32>() };
    let (a, b, c) = unsafe { (q.read_unaligned(), q.add(1).read_unaligned(), q.add(2).read_unaligned()) };
    write_word(a);
    write_word(b);
    write_word(c);
    write_word(count.swap_bytes());
    REG.str_.write(STR_DCAL);
}

/// Wait for the digest in flight and read all eight HR words into `d` as
/// digest bytes; clear DCIS. `search` only.
#[cfg(feature = "search")]
#[inline(always)]
fn collect<const FULL: bool>(d: &mut [u32; 8]) {
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            hash_engine_fault();
        }
    }
    // SAFETY: HR0..HR7 is the digest bank; `swap_bytes` stored little-endian
    // is the big-endian digest word in memory order. Without FULL only HR3..HR7
    // (bytes 12..32, which hold every bit the WOTS+C digit sum reads) are read.
    unsafe {
        if FULL {
            d[0] = REG.hr0.read_at(0).swap_bytes();
            d[1] = REG.hr0.read_at(1).swap_bytes();
            d[2] = REG.hr0.read_at(2).swap_bytes();
        } else {
            d[0] = 0;
            d[1] = 0;
            d[2] = 0;
        }
        d[3] = REG.hr0.read_at(3).swap_bytes();
        d[4] = REG.hr0.read_at(4).swap_bytes();
        d[5] = REG.hr0.read_at(5).swap_bytes();
        d[6] = REG.hr0.read_at(6).swap_bytes();
        d[7] = REG.hr0.read_at(7).swap_bytes();
    }
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`: the digest is out and the engine idle.
    unsafe {
        pqsigner_hash_tick();
    }
}

/// `v1-asm-search` (round 8, secure-only; the FSBL never names it): the `search128` loop
/// for WOTS-shaped messages (words 4..8 and 20..31 zero), hand-scheduled. Per try it does
/// what the Rust loop does: DCIS poll with a 2^24 guard, HR3..HR7 read, SR clear; if a next
/// try exists, BUSY wait (2^24 guard) with stale-DCIS refusal, INIT, the 32 words (count
/// big-endian last), DCAL; then `pred` on the previous try's digest (`d[0..3]` zero,
/// `d[3..8]` HR3..HR7 in memory order), called from the engine window. Returns `(c, flag)`:
/// 0 = no hit (`c = end`); 1 = try `c` hit and `c + 1` is in flight; 2 = try `c` hit, nothing
/// in flight. `st`: words 0..20 the message words 0..19, 33 `pred`, 40..48 `d`. Under
/// `tick-batch` the caller ticks once per call (the signer calls with at most 4,096 tries),
/// not every 32 tries as the Rust loop does.
#[cfg(feature = "v1-asm-search")]
const V1S_SPIN: u32 = 1;

#[cfg(all(feature = "v1-asm-search", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v1_search_asm(st: *mut u32, start: u32, end: u32) -> (u32, u32) {
    let (c, flag): (u32, u32);
    // SAFETY: drives only the secure HASH block (r4 = HASH_BASE); reads the 48-word staging
    // array at `st` and writes its words 43..48; calls `pred` (an `extern "C"` function that
    // reads only its 32-byte argument, caller contract) with an 8-byte-aligned stack; on a
    // hang or a stale DCIS it calls `hash_engine_fault`, which does not return.
    unsafe {
        core::arch::asm!(
            "movw lr, #0x24",
            "movt lr, #0x6",
            "1:",
            "movs r12, #{spin}",
            "10:",
            "subs r12, r12, #1",
            "bne 10b",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bpl 11f",
            "4:",
            "add r12, r4, #0x31C",            // HR3
            "ldm r12, {{r0, r1, r2, r3, r10}}", // HR3..HR7
            "movs r12, #1",
            "str r12, [r4, #0x24]",
            "add r11, r8, #1",
            "cmp r11, r9",
            "beq 50f",
            // issue try r11
            "ldr r12, [r4, #0x24]",
            "tst r12, #10",
            "bne 40f",
            "41:",
            "str lr, [r4]",                   // INIT
            "ldrd r12, lr, [r5]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldrd r12, lr, [r5, #8]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "movs r12, #0",
            "str r12, [r4, #4]",
            "str r12, [r4, #4]",
            "str r12, [r4, #4]",
            "str r12, [r4, #4]",
            "ldrd r12, lr, [r5, #32]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldrd r12, lr, [r5, #40]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldrd r12, lr, [r5, #48]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldrd r12, lr, [r5, #56]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldr r12, [r5, #64]",
            "str r12, [r4, #4]",              // word 16: block 0 starts
            // block-0 window: the previous try's digest words for `pred`, block-1 words
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "rev r10, r10",
            "str r0, [r5, #172]",
            "str r1, [r5, #176]",
            "str r2, [r5, #180]",
            "str r3, [r5, #184]",
            "str r10, [r5, #188]",
            "ldrd r0, r1, [r5, #68]",
            "ldr r2, [r5, #76]",
            "rev r3, r11",
            "movs r12, #0",
            "mov.w r10, #256",
            "str r0, [r4, #4]",               // waits for block 0
            "str r1, [r4, #4]",
            "str r2, [r4, #4]",
            ".rept 11",
            "str r12, [r4, #4]",
            ".endr",
            "str r3, [r4, #4]",               // count
            "str r10, [r4, #8]",              // DCAL (NBLW = 0)
            // engine window: pred(d) for try r8
            "add r0, r5, #160",
            "ldr r12, [r5, #132]",
            "blx r12",
            "tst r0, #0xFF",
            "bne 60f",
            "mov r8, r11",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 1b",
            // last try: nothing to issue
            "50:",
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "rev r10, r10",
            "str r0, [r5, #172]",
            "str r1, [r5, #176]",
            "str r2, [r5, #180]",
            "str r3, [r5, #184]",
            "str r10, [r5, #188]",
            "add r0, r5, #160",
            "ldr r12, [r5, #132]",
            "blx r12",
            "tst r0, #0xFF",
            "bne 61f",
            "mov r8, r9",
            "movs r0, #0",
            "b 97f",
            "60:",
            "movs r0, #1",
            "b 97f",
            "61:",
            "movs r0, #2",
            "b 97f",
            // DCIS not yet: seven straight polls, then a counted poll (2^24)
            "11:",
            ".rept 7",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bmi 4b",
            ".endr",
            "mov.w r0, #16777216",
            "12:",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bmi 4b",
            "subs r0, r0, #1",
            "bne 12b",
            "b 99f",
            // BUSY still set, or a stale DCIS: the HR words are live, so the counter is pushed
            // (two words: the stack stays 8-byte aligned)
            "40:",
            "push {{r0, r1}}",
            "mov.w r0, #16777216",
            "42:",
            "tst r12, #8",
            "beq 43f",
            "subs r0, r0, #1",
            "beq 99f",
            "ldr r12, [r4, #0x24]",
            "b 42b",
            "43:",
            "pop {{r0, r1}}",
            "tst r12, #2",
            "beq 41b",
            "99:",
            "bl {fault}",
            "97:",
            spin = const V1S_SPIN,
            fault = sym hash_engine_fault,
            out("r0") flag,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            in("r4") HASH_BASE,
            in("r5") st,
            inout("r8") start => c,
            in("r9") end,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("lr") _,
            clobber_abi("C"),
        );
    }
    (c, flag)
}

/// `v1-asm-search-ga` (round 10, secure-only; the FSBL never names it): the WOTS+C count search
/// for the WOTS digest shape as one standalone AAPCS function in `global_asm!` (the E9 pattern).
/// Block 0 (`S`'s four words, three address words, zeros elsewhere) is constant across tries and
/// stays in callee-saved r5..r11, which also survive the per-try `pred` call; only word 16 is
/// loaded before the 17th store. The previous try's digest words, the block-1 words and the count
/// go through the block-0 window; the last-try test runs in the engine window (two wait loops).
/// Per try the same checks as the Rust loop (DCIS poll with a 2^24 guard, SR clear; BUSY wait with
/// a 2^24 guard and stale-DCIS refusal before INIT; NBLW 0). Results and `pred` arguments as
/// `v1_search_asm`. In `.text.pq1_c10_search` with `search128` and the signer's predicate, so a
/// direct-mapped ICACHE cannot alias the loop and its per-try callback (round 8).
#[cfg(all(feature = "v1-asm-search-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
core::arch::global_asm!(
    ".syntax unified",
    ".section .text.pq1_c10_search,\"ax\",%progbits",
    ".p2align 2",
    ".global pq1_v1_search_z",
    ".type pq1_v1_search_z,%function",
    ".thumb_func",
    "pq1_v1_search_z:",
    "push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
    "sub sp, sp, #68",
    // frame: 0 d (pred argument, d[0..3] zero), 32 count (try in flight), 36 end, 40 pred, 44 ctx, 48 m0..m3, 64 HR7 temp
    // ctx: 0..7 words 0..3, 8, 10, 12 (in r5..r11 throughout); 7..11 words 16..19; 11 start; 12 end; 13 pred; 14 c, 15 flag (out)
    "str r0, [sp, #44]",
    "mov r12, r0",
    "ldm r12!, {{r5, r6, r7, r8, r9, r10, r11}}",
    "ldm r12!, {{r0, r1, r2, r3}}",
    "add lr, sp, #48",
    "stm lr, {{r0, r1, r2, r3}}",
    "ldm r12, {{r0, r1, r2}}",
    "str r0, [sp, #32]",
    "str r1, [sp, #36]",
    "str r2, [sp, #40]",
    "movs r3, #0",
    "str r3, [sp]",
    "str r3, [sp, #4]",
    "str r3, [sp, #8]",
    "movw r4, #{hb_lo}",
    "movt r4, #{hb_hi}",
    "adds r0, r0, #1",
    "cmp r0, r1",
    "beq 50f",
    // ==== a try in flight, a next try to issue ====
    "10:",
    ".rept 16",
    "ldr r12, [r4, #0x24]",
    "lsls r12, r12, #30",
    "bmi 11f",
    ".endr",
    "mov.w r0, #16777216",
    "12:",
    "ldr r12, [r4, #0x24]",
    "lsls r12, r12, #30",
    "bmi 11f",
    "subs r0, r0, #1",
    "bne 12b",
    "b 99f",
    "11:",
    "addw r12, r4, #796",
    "ldm r12, {{r0, r1, r2, r3, r12}}",
    "mov.w lr, #1",
    "str lr, [r4, #0x24]",
    "ldr lr, [r4, #0x24]",
    "tst lr, #10",
    "bne 13f",
    "14:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "str lr, [r4]",
    "movs.w lr, #0",
    "str r12, [sp, #64]",
    "ldr r12, [sp, #48]",
    "str r5, [r4, #4]",
    "str r6, [r4, #4]",
    "str r7, [r4, #4]",
    "str r8, [r4, #4]",
    "str lr, [r4, #4]",
    "str lr, [r4, #4]",
    "str lr, [r4, #4]",
    "str lr, [r4, #4]",
    "str r9, [r4, #4]",
    "str lr, [r4, #4]",
    "str r10, [r4, #4]",
    "str lr, [r4, #4]",
    "str r11, [r4, #4]",
    "str lr, [r4, #4]",
    "str lr, [r4, #4]",
    "str lr, [r4, #4]",
    "str r12, [r4, #4]",
    // block-0 window: the previous try's digest words for pred, block-1 words, the count
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "str r0, [sp, #12]",
    "str r1, [sp, #16]",
    "str r2, [sp, #20]",
    "str r3, [sp, #24]",
    "ldr r0, [sp, #64]",
    "rev r0, r0",
    "str r0, [sp, #28]",
    "ldr r3, [sp, #32]",
    "adds r3, r3, #1",
    "rev r3, r3",
    "ldr r0, [sp, #52]",
    "ldr r1, [sp, #56]",
    "ldr r2, [sp, #60]",
    "mov.w r12, #256",
    "str r0, [r4, #4]",
    "str r1, [r4, #4]",
    "str r2, [r4, #4]",
    ".rept 11",
    "str lr, [r4, #4]",
    ".endr",
    "str r3, [r4, #4]",
    "str r12, [r4, #8]",
    // engine window: pred on the previous try (callee-saved r4..r11 survive the call)
    "mov r0, sp",
    "ldr r12, [sp, #40]",
    "blx r12",
    "tst r0, #0xFF",
    "bne 60f",
    "ldr r0, [sp, #32]",
    "adds r0, r0, #1",
    "str r0, [sp, #32]",
    "ldr r1, [sp, #36]",
    "adds r0, r0, #1",
    "cmp r0, r1",
    "beq 50f",
    "b 10b",
    // BUSY still set, or a stale DCIS (HR words live: the counter is pushed, two words)
    "13:",
    "push {{r0, r1}}",
    "mov.w r0, #16777216",
    "15:",
    "tst lr, #8",
    "beq 16f",
    "subs r0, r0, #1",
    "beq 99f",
    "ldr lr, [r4, #0x24]",
    "b 15b",
    "16:",
    "pop {{r0, r1}}",
    "tst lr, #2",
    "beq 14b",
    "b 99f",
    // ==== the last try in flight: nothing to issue ====
    "50:",
    ".rept 16",
    "ldr r12, [r4, #0x24]",
    "lsls r12, r12, #30",
    "bmi 51f",
    ".endr",
    "mov.w r0, #16777216",
    "52:",
    "ldr r12, [r4, #0x24]",
    "lsls r12, r12, #30",
    "bmi 51f",
    "subs r0, r0, #1",
    "bne 52b",
    "b 99f",
    "51:",
    "addw r12, r4, #796",
    "ldm r12, {{r0, r1, r2, r3, r12}}",
    "mov.w lr, #1",
    "str lr, [r4, #0x24]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "rev r12, r12",
    "str r0, [sp, #12]",
    "str r1, [sp, #16]",
    "str r2, [sp, #20]",
    "str r3, [sp, #24]",
    "str r12, [sp, #28]",
    "mov r0, sp",
    "ldr r12, [sp, #40]",
    "blx r12",
    "tst r0, #0xFF",
    "bne 61f",
    "ldr r0, [sp, #36]",
    "movs r1, #0",
    "b 70f",
    "60:",
    "ldr r0, [sp, #32]",
    "movs r1, #1",
    "b 70f",
    "61:",
    "ldr r0, [sp, #32]",
    "movs r1, #2",
    "70:",
    "ldr r12, [sp, #44]",
    "str r0, [r12, #56]",
    "str r1, [r12, #60]",
    "b 98f",
    "99:",
    "bl {fault}",
    "98:",
    "add sp, sp, #68",
    "pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}",
    ".size pq1_v1_search_z, . - pq1_v1_search_z",

    hb_lo = const HASH_BASE & 0xFFFF,
    hb_hi = const HASH_BASE >> 16,
    fault = sym hash_engine_fault,
);

#[cfg(all(feature = "v1-asm-search-ga", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
extern "C" {
    /// The `v1-asm-search-ga` loop above.
    fn pq1_v1_search_z(ctx: *mut u32);
}

/// Counter search (`search`, secure image only): for `c` in `start..start+n`,
/// SHA-256 the 128-byte message at `buf` with bytes [124..128) = `c`
/// (big-endian); return the first `c` whose digest satisfies `pred` (the
/// digest is written to `out`), or `start + n` if none does. Try `c + 1` is
/// already in the engine while `pred` checks try `c` (and is discarded if `c`
/// is the answer), so the check costs no engine time. The answer and its
/// digest are exactly the sequential search's.
///
/// # Safety
/// `buf` names 128 readable bytes and `out` 32 writable bytes; `pred` reads
/// only its 32-byte argument; `start + n` does not overflow; no other SHA-256
/// stream is in flight; `init_clock` has run.
#[cfg(feature = "search")]
#[no_mangle]
// `v1-asm-search` calls `pred` once per try: keep the loop and the signer's predicate in one
// section (the signer names the same one), so a direct-mapped ICACHE (the shipped 1-way
// setting) can never map them onto the same lines whatever the link layout.
#[cfg_attr(feature = "v1-asm-search", link_section = ".text.pq1_c10_search")]
pub unsafe extern "C" fn pqsigner_sha256_search128(
    buf: *const u8,
    start: u32,
    n: u32,
    pred: unsafe extern "C" fn(*const u8) -> bool,
    out: *mut u8,
) -> u32 {
    let end = start + n;
    if n == 0 {
        return end;
    }
    let mut d = [0u32; 8];
    #[cfg(all(feature = "v1-asm-search", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    {
        // SAFETY: caller contract (128 readable bytes); unaligned word reads are legal.
        let w = |i: usize| unsafe { buf.add(4 * i).cast::<u32>().read_unaligned() };
        // The WOTS+C preimage shape: pad16(pk_seed)'s zero half (words 4..8) and the zero
        // words after the 16-byte node (20..31). Public data, so the branch leaks nothing.
        if w(4) | w(5) | w(6) | w(7) == 0 && (20..31).all(|i| w(i) == 0) {
            let mut st = [0u32; 48];
            for (i, x) in st.iter_mut().take(20).enumerate() {
                *x = w(i);
            }
            st[33] = pred as usize as u32;
            // SAFETY: caller contract.
            unsafe { issue128(buf, start) };
            // `v1-asm-search-ga`: with the address's zero words too (tree high word, type, ci, cp,
            // ha: the WOTS digest address), block 0 is seven constant words kept in registers.
            #[cfg(feature = "v1-asm-search-ga")]
            let (c, flag) = if w(9) | w(11) | w(13) | w(14) | w(15) == 0 {
                let mut ctx = [
                    w(0), w(1), w(2), w(3), w(8), w(10), w(12), w(16), w(17), w(18), w(19),
                    start, end, pred as usize as u32, 0, 0,
                ];
                // SAFETY: the function's contract (the context above, try `start` in flight;
                // `pred` reads only its 32-byte argument, caller contract).
                unsafe { pq1_v1_search_z(ctx.as_mut_ptr()) };
                (ctx[14], ctx[15])
            } else {
                v1_search_asm(st.as_mut_ptr(), start, end)
            };
            #[cfg(not(feature = "v1-asm-search-ga"))]
            let (c, flag) = v1_search_asm(st.as_mut_ptr(), start, end);
            if flag == 0 {
                #[cfg(feature = "tick-batch")]
                // SAFETY: the engine is idle; the tick does not hash.
                unsafe {
                    pqsigner_hash_tick_n(n)
                };
                return end;
            }
            if flag == 1 {
                let mut discard = [0u32; 8];
                collect::<false>(&mut discard);
            }
            // The hit's first 12 bytes were not read: hash try `c` once more, in full.
            // SAFETY: caller contract.
            unsafe { issue128(buf, c) };
            collect::<true>(&mut d);
            // SAFETY: `out` names 32 writable bytes (caller contract).
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) };
            #[cfg(feature = "tick-batch")]
            // SAFETY: the engine is idle; the tick does not hash. Tries start..=c, the
            // speculative try, and the recompute.
            unsafe {
                pqsigner_hash_tick_n((c - start).saturating_add(2 + u32::from(flag == 1)))
            };
            return c;
        }
    }
    // SAFETY: caller contract.
    unsafe { issue128(buf, start) };
    let mut c = start;
    #[cfg(feature = "tick-batch")]
    let mut since_tick = 0u32;
    loop {
        collect::<false>(&mut d);
        #[cfg(feature = "tick-batch")]
        {
            since_tick += 1;
            if since_tick == 32 {
                // A tick only between digests: wait out the next try first is not
                // needed, the tick runs with that try in the engine and must not hash.
                // SAFETY: the tick does not touch the HASH (tick-batch contract).
                unsafe { pqsigner_hash_tick_n(32) };
                since_tick = 0;
            }
        }
        let next = c + 1;
        let more = next != end;
        if more {
            // SAFETY: caller contract.
            unsafe { issue128(buf, next) };
        }
        // SAFETY: `d` is 32 readable bytes; `pred` reads only those.
        if unsafe { pred(d.as_ptr().cast::<u8>()) } {
            if more {
                let mut discard = [0u32; 8];
                collect::<false>(&mut discard);
            }
            // The hit's first 12 bytes were not read: hash try `c` once more, in full.
            // SAFETY: caller contract.
            unsafe { issue128(buf, c) };
            collect::<true>(&mut d);
            // SAFETY: `out` names 32 writable bytes (caller contract).
            unsafe { core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) };
            #[cfg(feature = "tick-batch")]
            // SAFETY: the engine is idle (the speculative try was collected).
            unsafe { pqsigner_hash_tick_n(since_tick + u32::from(more) + 1) };
            return c;
        }
        if !more {
            #[cfg(feature = "tick-batch")]
            // SAFETY: the engine is idle.
            unsafe { pqsigner_hash_tick_n(since_tick) };
            return end;
        }
        c = next;
    }
}

/// v1 R grind in one call (`v1-grindr`, round 8, secure image only; the FSBL never names
/// it). For `nonce` in `0..max`: `R = SHA-256(sk_seed ‖ "R_grind" ‖ [rand] ‖ message ‖
/// 0^28 ‖ be32(nonce))[..16]` (119 or 103 bytes; `sk_seed` read in place, never copied),
/// then `D = SHA-256(seed ‖ root ‖ R ‖ 0^16 ‖ message ‖ 0xFF^32)`; the first nonce whose `D`
/// has bits 132..143 clear (`read_bits_le(D, 132, 11) == 0`: `HR3 & 0x7FF0 == 0`) writes R
/// to `r_out`, D to `d_out` and is returned; `max` if none. Every digest: idle and no stale
/// DCIS, STR 0, INIT, the words, NBLW then NBLW | DCAL as the one-shot (DCAL alone for whole
/// words), DCIS poll with the 10,000,000 guard, SR clear. Under `tick-batch` the digests
/// are reported once, when the grind returns (about 2^11 nonces, ~1 M cycles, on average).
///
/// # Safety
/// `sk_seed` 32, `rand` 16 (or null), `message`, `seed`, `root` 32 readable bytes; `r_out`
/// 16 and `d_out` 32 writable; no other SHA-256 stream in flight.
#[cfg(feature = "v1-grindr")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v1_grind_r(
    sk_seed: *const u8,
    rand: *const u8,
    message: *const u8,
    seed: *const u8,
    root: *const u8,
    max: u32,
    r_out: *mut u8,
    d_out: *mut u8,
) -> u32 {
    // SAFETY: this function's contract.
    let found = unsafe { v1_grind_r_inner(sk_seed, rand, message, seed, root, max, r_out, d_out) };
    // The inner frame held the PRF tail words (rand, message) in compiler-chosen slots beyond
    // the arrays it wipes (round 8: a dead-stack scan found rand bytes in spill slots). Zero
    // the dead stack below sp that the inner call used (its frame is 376 bytes in the bench
    // build; landing must re-check the size and the stack headroom below this call).
    // SAFETY: the 512 bytes are first allocated (`sub sp`: AAPCS-conformant, 8-byte aligned,
    // and bounded by MSPLIM, so a shortfall faults instead of overwriting), zeroed, then
    // released; no live object lies below the incoming sp.
    unsafe {
        core::arch::asm!(
            "sub sp, sp, #512",
            "mov {p}, sp",
            "movs {z}, #0",
            "mov.w {c}, #128",
            "1:",
            "str {z}, [{p}], #4",
            "subs {c}, {c}, #1",
            "bne 1b",
            "add sp, sp, #512",
            p = out(reg) _,
            z = out(reg) _,
            c = out(reg) _,
        );
    }
    found
}

/// `pqsigner_v1_grind_r`'s body, in its own frame so the caller can zero that frame after it.
///
/// # Safety
/// As `pqsigner_v1_grind_r`.
#[cfg(feature = "v1-grindr")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn v1_grind_r_inner(
    sk_seed: *const u8,
    rand: *const u8,
    message: *const u8,
    seed: *const u8,
    root: *const u8,
    max: u32,
    r_out: *mut u8,
    d_out: *mut u8,
) -> u32 {
    // The PRF bytes after sk_seed, up to the nonce: "R_grind" ‖ [rand] ‖ message ‖ 0^28.
    let mut tb = [0u8; 88];
    tb[..7].copy_from_slice(b"R_grind");
    let mut off = 7;
    // SAFETY: caller contract (16 and 32 readable bytes); `tb` has room (7 + 16 + 32 + 28 < 88).
    unsafe {
        if !rand.is_null() {
            core::ptr::copy_nonoverlapping(rand, tb.as_mut_ptr().add(off), 16);
            off += 16;
        }
        core::ptr::copy_nonoverlapping(message, tb.as_mut_ptr().add(off), 32);
    }
    off += 32;
    let mut tw: [u32; 22] = core::array::from_fn(|i| u32::from_le_bytes([tb[4 * i], tb[4 * i + 1], tb[4 * i + 2], tb[4 * i + 3]]));
    // SAFETY: caller contract (32 readable bytes each; public data).
    let ld8 = |p: *const u8| -> [u32; 8] { core::array::from_fn(|i| unsafe { p.add(4 * i).cast::<u32>().read_unaligned() }) };
    let (sw, rw, mw) = (ld8(seed), ld8(root), ld8(message));
    let mut rr = [0u32; 4];
    let mut dd = [0u32; 8];
    // The nonce's first byte is the top byte of tail word (off + 28) / 4: 20 with rand, 16 without.
    let found = if off == 55 {
        // SAFETY: caller contract.
        unsafe { v1_grind_body::<20>(sk_seed, &tw, &sw, &rw, &mw, max, &mut rr, &mut dd) }
    } else {
        // SAFETY: caller contract.
        unsafe { v1_grind_body::<16>(sk_seed, &tw, &sw, &rw, &mw, max, &mut rr, &mut dd) }
    };
    // `tb`/`tw` hold the caller's rand: wipe them (volatile, so the stores stay).
    for b in tb.iter_mut() {
        // SAFETY: a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    for w in tw.iter_mut() {
        // SAFETY: a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    if found < max {
        // SAFETY: caller contract (16 and 32 writable bytes).
        unsafe {
            for k in 0..4 {
                r_out.add(4 * k).cast::<u32>().write_unaligned(rr[k]);
            }
            for k in 0..8 {
                d_out.add(4 * k).cast::<u32>().write_unaligned(dd[k]);
            }
        }
    }
    #[cfg(feature = "tick-batch")]
    // SAFETY: the engine is idle; the tick does not hash.
    unsafe {
        pqsigner_hash_tick_n((if found < max { found + 1 } else { max }).saturating_mul(2));
    }
    found
}

/// The nonce loop of `pqsigner_v1_grind_r`; `A` is the tail word holding the nonce's
/// first byte (its top byte), the 3-byte final word follows.
#[cfg(feature = "v1-grindr")]
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn v1_grind_body<const A: usize>(
    sk_seed: *const u8,
    tw: &[u32; 22],
    sw: &[u32; 8],
    rw: &[u32; 8],
    mw: &[u32; 8],
    max: u32,
    rr: &mut [u32; 4],
    dd: &mut [u32; 8],
) -> u32 {
    let wait = || {
        let mut t = 0u32;
        while REG.sr.read() & SR_DCIS == 0 {
            t += 1;
            if t > 10_000_000 {
                hash_engine_fault();
            }
        }
    };
    let mut nonce = 0u32;
    while nonce < max {
        // R PRF.
        if ready_sr_fast() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
        REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
        // SAFETY: caller contract (32 readable bytes).
        unsafe { feed_words(sk_seed, 8) };
        for w in tw.iter().take(A) {
            write_word(*w);
        }
        write_word(tw[A] | (nonce >> 24) << 24);
        write_word(nonce.swap_bytes() >> 8);
        REG.str_.write(24);
        REG.str_.write(24 | STR_DCAL);
        wait();
        let r = read_hr4();
        REG.sr.write(SR_DINIS);
        #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
        // SAFETY: as in `final_body`: this digest is finished; the next INIT rewrites STR.
        unsafe {
            pqsigner_hash_tick();
        }
        // h_msg.
        if ready_sr_fast() & SR_DCIS != 0 {
            hash_engine_fault();
        }
        REG.str_.write(0);
        REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
        for w in sw {
            write_word(*w);
        }
        for w in rw {
            write_word(*w);
        }
        write_word(r[0]);
        write_word(r[1]);
        write_word(r[2]);
        write_word(r[3]);
        write_word(0);
        write_word(0);
        write_word(0);
        write_word(0);
        for w in mw {
            write_word(*w);
        }
        for _ in 0..8 {
            write_word(0xFFFF_FFFF);
        }
        REG.str_.write(STR_DCAL);
        wait();
        // SAFETY: HR3, inside the digest bank.
        if unsafe { REG.hr0.read_at(3) } & 0x7FF0 == 0 {
            // SAFETY: HR0..HR7, the digest bank; byte-swapped into memory order.
            unsafe {
                for (i, x) in dd.iter_mut().enumerate() {
                    *x = REG.hr0.read_at(i).swap_bytes();
                }
            }
            REG.sr.write(SR_DINIS);
            #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
            // SAFETY: as in `final_body`.
            unsafe {
                pqsigner_hash_tick();
            }
            *rr = r;
            return nonce;
        }
        REG.sr.write(SR_DINIS);
        #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
        // SAFETY: as in `final_body`.
        unsafe {
            pqsigner_hash_tick();
        }
        nonce += 1;
    }
    max
}

/// Feed the eight words of a 32-byte part straight from its memory.
#[cfg(feature = "gather")]
#[inline(always)]
unsafe fn feed32(p: *const u8) {
    // SAFETY: `p` names 32 readable bytes (callers' contract).
    unsafe {
        let q = p.cast::<u32>();
        write_word(q.read_unaligned());
        write_word(q.add(1).read_unaligned());
        write_word(q.add(2).read_unaligned());
        write_word(q.add(3).read_unaligned());
        write_word(q.add(4).read_unaligned());
        write_word(q.add(5).read_unaligned());
        write_word(q.add(6).read_unaligned());
        write_word(q.add(7).read_unaligned());
    }
}

/// Init (stale-DCIS check, NBLW = 0, INIT) for the gather digests.
#[cfg(feature = "gather")]
#[inline(always)]
fn gather_init() {
    if ready_sr_fast() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.str_.write(0);
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
}

/// DCAL, wait, write HR0..HR3 (16 digest bytes) to `out`, clear DCIS.
#[cfg(feature = "gather")]
#[inline(always)]
unsafe fn gather_final16(out: *mut u8) {
    REG.str_.write(STR_DCAL);
    let mut t = 0u32;
    while REG.sr.read() & SR_DCIS == 0 {
        t += 1;
        if t > 10_000_000 {
            hash_engine_fault();
        }
    }
    // SAFETY: HR0..HR3; `out` names 16 writable bytes (callers' contract).
    unsafe {
        let o = out.cast::<u32>();
        o.write_unaligned(REG.hr0.read_at(0).swap_bytes());
        o.add(1).write_unaligned(REG.hr0.read_at(1).swap_bytes());
        o.add(2).write_unaligned(REG.hr0.read_at(2).swap_bytes());
        o.add(3).write_unaligned(REG.hr0.read_at(3).swap_bytes());
    }
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`.
    unsafe {
        pqsigner_hash_tick();
    }
}

/// First 16 bytes of SHA-256(a ‖ b ‖ c), three 32-byte parts read in place
/// (`gather`, secure image only): `th` without its 96-byte preimage copy.
///
/// # Safety
/// `a`, `b`, `c` name 32 readable bytes each, `out` 16 writable bytes; no
/// other SHA-256 stream is in flight.
#[cfg(feature = "gather")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_3x32_16(a: *const u8, b: *const u8, c: *const u8, out: *mut u8) {
    gather_init();
    // SAFETY: caller contract.
    unsafe {
        feed32(a);
        feed32(b);
        feed32(c);
        gather_final16(out);
    }
}

/// First 16 bytes of SHA-256(a ‖ b ‖ c ‖ d) (`gather`): `th_pair` in place.
///
/// # Safety
/// As `pqsigner_sha256_3x32_16`, with a fourth 32-byte part `d`.
#[cfg(feature = "gather")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_4x32_16(a: *const u8, b: *const u8, c: *const u8, d: *const u8, out: *mut u8) {
    gather_init();
    // SAFETY: caller contract.
    unsafe {
        feed32(a);
        feed32(b);
        feed32(c);
        feed32(d);
        gather_final16(out);
    }
}

#[cfg(feature = "tick-batch")]
extern "C" {
    /// `tick-batch`: `n` digests finished since the last tick; the engine is idle
    /// or (inside `search128`) holds a try the tick must not disturb, so the
    /// callee must not hash. Defined by the secure world (or the bench stub).
    fn pqsigner_hash_tick_n(n: u32);
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

// ---------------------------------------------------------------------------
// RESEARCH (#1155): C10 v2 one-block entries. Every v2 preimage is `… ‖ A7`
// (A7 = 7-byte compact address, last), 39, 43 or 55 bytes: one SHA-256 block,
// ten to fourteen DIN words, the last holding three valid bytes (NBLW = 24).
// NBLW is written before INIT (which leaves it alone) and again with DCAL, so
// the HAL order (NBLW, then DCAL) holds. `a0`/`a1` are A7's two DIN words in
// memory order: bytes 0..4, and bytes 4..7 plus one ignored byte.
// ---------------------------------------------------------------------------

#[cfg(feature = "v2")]
const V2_NBLW: u32 = 24;

/// Start of every v2 entry: wait until idle, then NBLW = 24 in STR. Every
/// digest inside the entry then needs only INIT (`v2_begin`): INIT leaves STR
/// alone, and each `v2_end16`/issue rewrites the same NBLW with DCAL.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_entry() {
    let _ = v2_ready_sr();
    REG.str_.write(V2_NBLW);
}

/// v2 polls give up after 2^24 status reads (a hung engine is a fault, as in
/// `wait_ready_sr`). A down-counter from an encodable immediate keeps no
/// constant live across the hot loops, which frees a register there.
#[cfg(feature = "v2")]
const V2_POLLS: u32 = 1 << 24;

/// `wait_ready_sr` for the v2 loops: the status word once BUSY is clear.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_ready_sr() -> u32 {
    #[cfg(feature = "no-busy-wait")]
    return REG.sr.read();
    #[cfg(not(feature = "no-busy-wait"))]
    {
        let mut t = V2_POLLS;
        loop {
            let sr = REG.sr.read();
            if sr & SR_BUSY == 0 {
                return sr;
            }
            t -= 1;
            if t == 0 {
                hash_engine_fault();
            }
        }
    }
}

/// Wait for DCIS (digest ready) in the v2 loops.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_wait_dcis() {
    let mut t = V2_POLLS;
    while REG.sr.read() & SR_DCIS == 0 {
        t -= 1;
        if t == 0 {
            hash_engine_fault();
        }
    }
}

#[cfg(feature = "v2")]
#[inline(always)]
fn v2_begin() {
    if v2_ready_sr() & SR_DCIS != 0 {
        hash_engine_fault();
    }
    REG.cr.write(CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT);
}

#[cfg(feature = "v2")]
#[inline(always)]
fn v2_end16() -> [u32; 4] {
    REG.str_.write(V2_NBLW | STR_DCAL);
    v2_wait_dcis();
    let v = read_hr4();
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`: the digest is out and the engine idle.
    unsafe {
        pqsigner_hash_tick();
    }
    v
}

/// A7's second DIN word with chain position `pos`: `a1` is that word (memory
/// order `[b4, b5, b6, 0]`) with `cp` clear; `cp` is the top nibble of b5
/// (spec 0.2), i.e. bits 12..15 of the word.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_a1(a1: u32, pos: u32) -> u32 {
    a1 | pos << 12
}

#[cfg(feature = "v2")]
#[inline(always)]
unsafe fn v2_load4(p: *const u8) -> [u32; 4] {
    let q = p.cast::<u32>();
    // SAFETY: callers pass 16 readable bytes.
    unsafe { [q.read_unaligned(), q.add(1).read_unaligned(), q.add(2).read_unaligned(), q.add(3).read_unaligned()] }
}

#[cfg(feature = "v2")]
#[inline(always)]
unsafe fn v2_store4(p: *mut u8, v: [u32; 4]) {
    let q = p.cast::<u32>();
    // SAFETY: callers pass 16 writable bytes.
    unsafe {
        q.write_unaligned(v[0]);
        q.add(1).write_unaligned(v[1]);
        q.add(2).write_unaligned(v[2]);
        q.add(3).write_unaligned(v[3]);
    }
}

/// `ci`'s least significant bit in A7's second DIN word (`[b4, b5, b6, 0]`):
/// draft 0.3 puts `ci` at A7 bits 23..18 (word bits 7..2); the `v2-split810`
/// research variant moves it to bits 22..17 (word bits 6..1) to give `kp` 10 bits.
#[cfg(all(feature = "v2", not(feature = "v2-split810")))]
const V2_CI_LSB: u32 = 2;
#[cfg(all(feature = "v2", feature = "v2-split810"))]
const V2_CI_LSB: u32 = 1;

/// `ha`'s least significant bit in A7's second DIN word (see `v2_ha`).
#[cfg(all(feature = "v2", feature = "v2-prf2"))]
const V2_HA_LSB: u32 = 1 << 17;

/// RESEARCH (`v2-prf2`): close a PRF digest that carries two secrets, keep
/// half `half` (0 = bytes 0..16, 1 = bytes 16..32) and wipe the local copy.
#[cfg(all(feature = "v2", feature = "v2-prf2"))]
#[inline(always)]
fn v2_prf2_half(half: u32) -> [u32; 4] {
    REG.str_.write(V2_NBLW | STR_DCAL);
    let mut d = [0u32; 8];
    v2_collect(&mut d);
    let v = if half == 0 { [d[0], d[1], d[2], d[3]] } else { [d[4], d[5], d[6], d[7]] };
    v2_wipe8(&mut d);
    v
}

/// RESEARCH (`v2-prf2`): close a two-secret PRF digest into `d` (both halves).
#[cfg(all(feature = "v2", feature = "v2-prf2"))]
#[inline(always)]
fn v2_prf2_both(d: &mut [u32; 8]) {
    REG.str_.write(V2_NBLW | STR_DCAL);
    v2_collect(d);
}

#[cfg(all(feature = "v2", feature = "v2-prf2"))]
#[inline(always)]
fn v2_wipe8(d: &mut [u32; 8]) {
    for x in d.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// v2 chain loop: F over `S ‖ v ‖ A7` at positions `start..start + steps`.
/// `v2-asm-chain` (round 7): the same chain loop, hand-scheduled. Every digest
/// is fed, checked and cleared exactly as in the Rust loop below (BUSY spin with
/// a 2^24 hang guard, stale-DCIS tripwire before INIT, DCIS poll with a 2^24
/// guard, SR clear after the read), so the output and the fault checks are the
/// same. What changes is the schedule: `S` stays in r8..r11, the HR read lands
/// in r0..r3, and loop control runs inside the engine window after DCAL instead
/// of between DCIS and the next DCAL.
/// Spin iterations (3 cycles each) after the window's loop control, so the
/// first DCIS poll lands just after the engine finishes. Tuned on the kit.
#[cfg(feature = "v2-asm-chain")]
const V2_ASM_SPIN: u32 = 13;

#[cfg(all(feature = "v2-asm-chain", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v2_chain_core(s: [u32; 4], v: [u32; 4], a0: u32, low24: u32, start: u32, steps: u32) -> [u32; 4] {
    let a1 = v2_a1(low24, start);
    let end = v2_a1(low24, start.wrapping_add(steps));
    if a1 == end {
        return v;
    }
    let (o0, o1, o2, o3): (u32, u32, u32, u32);
    // SAFETY: drives only the secure HASH block (CR, DIN, STR, SR, HRA0..3 at
    // r4 = HASH_BASE + 0x0C); pushes/pops two words of its own; on a hang or a
    // stale DCIS it calls `hash_engine_fault`, which does not return.
    unsafe {
        core::arch::asm!(
            "push {{r12, lr}}",            // [sp] = a0, [sp + 4] = end
            "movw lr, #0x24",              // lr = CR value (8-bit data, SHA-256, INIT), kept live
            "movt lr, #0x6",
            "b 3f",
            // engine window after DCAL: loop control, then a timed wait
            "1:",
            "add.w r5, r5, #4096",
            "ldr r12, [sp, #4]",
            "cmp r5, r12",
            "beq 20f",
            "movs r12, #{spin}",
            "10:",
            "subs r12, r12, #1",
            "bne 10b",
            // first DCIS poll; a hit falls through
            "ldr r12, [r4, #0x18]",
            "lsls r12, r12, #30",
            "bpl 11f",
            "4:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r12, #1",
            "str r12, [r4, #0x18]",        // clear DCIS
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            // issue: BUSY clear and no stale DCIS, INIT, 10 DIN words, DCAL
            "3:",
            "ldr r12, [r4, #0x18]",
            "tst r12, #10",
            "bne 40f",
            "41:",
            "str lr, [r4, #-12]",
            "str r8, [r4, #-8]",
            "str r9, [r4, #-8]",
            "ldr r12, [sp]",
            "str r10, [r4, #-8]",
            "str r11, [r4, #-8]",
            "str r0, [r4, #-8]",
            "str r1, [r4, #-8]",
            "str r2, [r4, #-8]",
            "str r3, [r4, #-8]",
            "str r12, [r4, #-8]",
            "str r5, [r4, #-8]",
            "mov.w r12, #280",
            "str r12, [r4, #-4]",
            "b 1b",
            // DCIS not yet: seven more straight polls, then a counted poll (2^24)
            "11:",
            ".rept 7",
            "ldr r12, [r4, #0x18]",
            "lsls r12, r12, #30",
            "bmi 4b",
            ".endr",
            "mov.w lr, #16777216",
            "12:",
            "ldr r12, [r4, #0x18]",
            "lsls r12, r12, #30",
            "bmi 13f",
            "subs lr, lr, #1",
            "bne 12b",
            "b 99f",
            "13:",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 4b",
            // BUSY still set, or a stale DCIS: spin on BUSY (2^24), then DCIS must be clear
            "40:",
            "mov.w lr, #16777216",
            "42:",
            "tst r12, #8",
            "beq 43f",
            "subs lr, lr, #1",
            "beq 99f",
            "ldr r12, [r4, #0x18]",
            "b 42b",
            "43:",
            "tst r12, #2",
            "bne 99f",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 41b",
            // last digest: counted poll, read, clear, exit
            "20:",
            "mov.w lr, #16777216",
            "21:",
            "ldr r12, [r4, #0x18]",
            "lsls r12, r12, #30",
            "bmi 22f",
            "subs lr, lr, #1",
            "bne 21b",
            "b 99f",
            "22:",
            "ldm r4, {{r0, r1, r2, r3}}",
            "movs r12, #1",
            "str r12, [r4, #0x18]",
            "rev r0, r0",
            "rev r1, r1",
            "rev r2, r2",
            "rev r3, r3",
            "pop {{r12, lr}}",
            "b 98f",
            "99:",
            "bl {fault}",
            "98:",
            spin = const V2_ASM_SPIN,
            fault = sym hash_engine_fault,
            inout("r0") v[0] => o0,
            inout("r1") v[1] => o1,
            inout("r2") v[2] => o2,
            inout("r3") v[3] => o3,
            in("r4") HASH_BASE + 0x0C,
            inout("r5") a1 => _,
            in("r8") s[0],
            in("r9") s[1],
            in("r10") s[2],
            in("r11") s[3],
            inout("r12") a0 => _,
            inout("lr") end => _,
        );
    }
    [o0, o1, o2, o3]
}

#[cfg(all(feature = "v2", not(all(feature = "v2-asm-chain", not(all(feature = "tick-hook", not(feature = "tick-batch")))))))]
#[inline(always)]
fn v2_chain_core(s: [u32; 4], mut v: [u32; 4], a0: u32, low24: u32, start: u32, steps: u32) -> [u32; 4] {
    // The second A7 word is the loop variable (`cp` is its bits 12..15, so a
    // step adds 1 << 12): fewer live values, so `S` stays in registers.
    let mut a1 = v2_a1(low24, start);
    let end = v2_a1(low24, start.wrapping_add(steps));
    while a1 != end {
        v2_begin();
        write_word(s[0]); write_word(s[1]); write_word(s[2]); write_word(s[3]);
        write_word(v[0]); write_word(v[1]); write_word(v[2]); write_word(v[3]);
        write_word(a0); write_word(a1);
        v = v2_end16();
        a1 = a1.wrapping_add(1 << 12);
    }
    v
}

/// Round 7 attribution (a Rust timed poll in the chain loop gave 116-122 for
/// spins 3..11, no gain: the chain needs the asm schedule): a fixed delay (3 cycles per iteration) inside the engine
/// window, so the first DCIS poll lands just after the digest completes.
#[cfg(feature = "v2-fold-sum")]
#[inline(always)]
fn v2_spin(n: u32) {
    // SAFETY: a register-only countdown; n >= 1.
    unsafe { core::arch::asm!("1:", "subs {0}, {0}, #1", "bne 1b", inout(reg) n => _, options(nomem, nostack)) }
}
#[cfg(feature = "v2-fold-sum")]
const V2_RUST_SEARCH_SPIN: u32 = 1;

/// Exact digits 0..31 of the WOTS+C digest (w5, w6, w7; w7 least significant), as
/// `g24` sums them: ten whole digits per word paired under 0o0707070707, folded to
/// 12-bit fields, summed by one multiply (see the round 7 ledger for the check).
#[cfg(feature = "v2-fold-sum")]
#[inline(always)]
fn v2_fold_s4(w5: u32, w6: u32, w7: u32) -> u32 {
    const A: u32 = 0x071C_71C7;
    const B: u32 = 0x3F03_F03F;
    let t = (w7 & A)
        .wrapping_add((w7 >> 3) & A)
        .wrapping_add((w6 >> 1) & A)
        .wrapping_add((w6 >> 4) & A)
        .wrapping_add((w5 >> 2) & A)
        .wrapping_add((w5 >> 5) & A);
    let u = (t & B).wrapping_add((t >> 6) & B);
    (u.wrapping_mul(0x0100_1001) >> 24)
        .wrapping_add(w7 >> 30 | (w6 & 1) << 2)
        .wrapping_add(w6 >> 31 | (w5 & 3) << 1)
}
#[cfg(feature = "v2-fold-sum")]
#[inline(always)]
fn v2_fold_rest(w3: u32, w4: u32) -> u32 {
    const A: u32 = 0x071C_71C7;
    const B: u32 = 0x3F03_F03F;
    let t = (w4 & A).wrapping_add((w4 >> 3) & A);
    let u = (t & B).wrapping_add((t >> 6) & B);
    (u.wrapping_mul(0x0100_1001) >> 24).wrapping_add(w4 >> 30 | (w3 & 1) << 2)
}

/// # Safety
/// `seed` 16 readable bytes, `val` 16 readable and writable; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_chain16(seed: *const u8, val: *mut u8, a0: u32, low24: u32, start: u32, steps: u32) {
    v2_entry();
    // SAFETY: caller contract.
    let (s, v) = unsafe { (v2_load4(seed), v2_load4(val)) };
    let v = v2_chain_core(s, v, a0, low24, start, steps);
    // SAFETY: caller contract.
    unsafe { v2_store4(val, v) };
}

/// WOTS secret (`sk_seed ‖ A7_prf`) then its chain from position 0; the
/// secret stays in registers.
///
/// # Safety
/// `sk_seed` 32 and `seed` 16 readable bytes, `out` 16 writable; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_prf_chain16(
    sk_seed: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8,
) {
    v2_entry();
    v2_begin();
    // SAFETY: caller contract.
    unsafe { feed_words(sk_seed, 8) };
    write_word(p0);
    #[cfg(not(feature = "v2-prf2"))]
    let v = {
        write_word(p1);
        v2_end16()
    };
    // `v2-prf2`: chain `ci`'s secret is half `ci & 1` of the PRF over `ci & !1`.
    #[cfg(feature = "v2-prf2")]
    let v = {
        write_word(p1 & !(1 << V2_CI_LSB));
        v2_prf2_half(p1 >> V2_CI_LSB & 1)
    };
    // SAFETY: caller contract.
    let s = unsafe { v2_load4(seed) };
    let v = v2_chain_core(s, v, a0, low24, 0, steps);
    // SAFETY: caller contract.
    unsafe { v2_store4(out, v) };
}

/// A whole WOTS key's chains in one call: for chain `ci` in `0..43`, the secret
/// `sk_seed ‖ A7_prf(ci)`, then `steps` chain steps from position 0, written to
/// `out + 16 ci`. `p0`/`p1` and `a0`/`low24` are the WOTS_PRF and WOTS_HASH A7
/// words of the key pair with `ci = cp = 0`; `ci` sits at A7 bits 23..18, i.e.
/// bits 2..7 of the second DIN word.
///
/// # Safety
/// `sk_seed` 32 and `seed` 16 readable bytes, `out` 688 writable; `steps <= 15`;
/// no other stream in flight.
/// `v2-asm-key-ga` (round 10, research format, secure-only): every chain of one v2 WOTS key
/// (`steps` 1..=15, one PRF per chain) as one standalone AAPCS function in `global_asm!` (the E9
/// pattern). Each chain's PRF is issued from asm: `sk_seed[0..7)` load (registers only, single
/// loads) during the previous chain's last step, `sk_seed[7]` and `p0`, `p1 | c` after INIT; the
/// previous chain's output store, the next chain's index words and the `S` reload run in the PRF's
/// engine window. The chain steps are the `v2-asm-chain` schedule. Every digest keeps the Rust
/// loop's checks (DCIS poll with a 2^24 guard, SR clear, BUSY wait with a 2^24 guard and stale-DCIS
/// refusal before INIT, NBLW 24 at DCAL). `ctx`: 0 `sk_seed`, 1 `p0`, 2 `p1`, 3..7 `S`, 7 `a0`,
/// 8 `low24`, 9 `steps`, 10 chain count (43), 11 `out`.
#[cfg(all(feature = "v2-asm-key-ga", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
core::arch::global_asm!(
    ".syntax unified",
    ".section .text.pq1_v2_key_loop,\"ax\",%progbits",
    ".p2align 2",
    ".global pq1_v2_key_loop",
    ".type pq1_v2_key_loop,%function",
    ".thumb_func",
    "pq1_v2_key_loop:",
    "push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
    "sub sp, sp, #68",
    // frame: 0 a0, 4 end (a1 after the last step), 8 p0, 12 p1|c, 16 a1 base (low24|c), 20 ci, 24 n, 28 steps,
    // 32 sk_seed, 36 out (this chain), 40 S0..S3, 56 p1, 60 low24
    // ctx: 0 sk_seed, 1 p0, 2 p1, 3..7 S, 7 a0, 8 low24, 9 steps, 10 n, 11 out
    "ldm r0, {{r1, r2, r3, r5, r6, r7, r8, r9, r10, r11, r12, lr}}",
    "str r1, [sp, #32]",
    "str r2, [sp, #8]",
    "str r3, [sp, #56]",
    "str r5, [sp, #40]",
    "str r6, [sp, #44]",
    "str r7, [sp, #48]",
    "str r8, [sp, #52]",
    "str r9, [sp, #0]",
    "str r10, [sp, #60]",
    "str r11, [sp, #28]",
    "str r12, [sp, #24]",
    "str lr, [sp, #36]",
    "movs r0, #0",
    "str r0, [sp, #20]",
    "str r3, [sp, #12]",
    "str r10, [sp, #16]",
    "orr r0, r10, r11, lsl #12",
    "str r0, [sp, #4]",
    "movw r4, #{hb_lo}",
    "movt r4, #{hb_hi}",
    "movw lr, #0x24",
    "movt lr, #0x6",
    // first PRF: idle and no stale DCIS (as v2_begin), INIT, sk_seed (single loads), p0, p1|c, DCAL
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 50f",
    "51:",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #32]",
    "ldr r0, [r12]",
    "ldr r1, [r12, #4]",
    "ldr r2, [r12, #8]",
    "ldr r3, [r12, #12]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldr r0, [r12, #16]",
    "ldr r1, [r12, #20]",
    "ldr r2, [r12, #24]",
    "ldr r3, [r12, #28]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldrd r0, r1, [sp, #8]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    "b 32f",
    // ==== chain step loop (S in r8..r11, a1 in r5): the v2 chain schedule ====
    "1:",
    "add.w r5, r5, #4096",
    "ldr r12, [sp, #4]",
    "cmp r5, r12",
    "beq 20f",
    "movs r12, #{spin}",
    "10:",
    "subs r12, r12, #1",
    "bne 10b",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bpl 11f",
    "4:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "3:",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 40f",
    "41:",
    "str lr, [r4, #-12]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "ldr r12, [sp]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str r12, [r4, #-8]",
    "str r5, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    "b 1b",
    "11:",
    ".rept 7",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 4b",
    ".endr",
    "mov.w r0, #16777216",
    "12:",
    "ldr r12, [r4, #0x18]",
    "lsls r12, r12, #30",
    "bmi 4b",
    "subs r0, r0, #1",
    "bne 12b",
    "b 99f",
    "40:",
    "mov.w lr, #16777216",
    "42:",
    "tst r12, #8",
    "beq 43f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 42b",
    "43:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 41b",
    "b 99f",
    // ==== chain done (its last step in flight): the next chain's PRF, or the last read-out ====
    "20:",
    "ldr r0, [sp, #20]",
    "adds r0, r0, #1",
    "ldr r1, [sp, #24]",
    "cmp r0, r1",
    "beq 70f",
    "str r0, [sp, #20]",
    "lsls r1, r0, #{lsb}",
    "ldr r2, [sp, #56]",
    "orrs r2, r2, r1",
    "str r2, [sp, #12]",
    "ldr r2, [sp, #60]",
    "orrs r2, r2, r1",
    "str r2, [sp, #16]",
    "ldr r3, [sp, #28]",
    "orr r3, r2, r3, lsl #12",
    "str r3, [sp, #4]",
    "ldr r1, [sp, #32]",
    "ldr r8, [r1]",
    "ldr r9, [r1, #4]",
    "ldr r10, [r1, #8]",
    "ldr r11, [r1, #12]",
    "ldr r6, [r1, #16]",
    "ldr r7, [r1, #20]",
    "ldr r5, [r1, #24]",
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 21f",
    ".endr",
    "mov.w r1, #16777216",
    "22:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 21f",
    "subs r1, r1, #1",
    "bne 22b",
    "b 99f",
    "21:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 23f",
    "24:",
    "str lr, [r4, #-12]",
    "ldr lr, [sp, #32]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "ldr r12, [lr, #28]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r5, [r4, #-8]",
    "ldrd r8, r9, [sp, #8]",
    "str r12, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    // PRF window: the finished chain's output to out, out += 16
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r12, [sp, #36]",
    "str r0, [r12]",
    "str r1, [r12, #4]",
    "str r2, [r12, #8]",
    "str r3, [r12, #12]",
    "add r12, r12, #16",
    "str r12, [sp, #36]",
    "movw lr, #0x24",
    "movt lr, #0x6",
    // (the first chain enters here) S back, the chain's a1 base, wait for the PRF
    "32:",
    "add r12, sp, #40",
    "ldm r12, {{r8, r9, r10, r11}}",
    "ldr r5, [sp, #16]",
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 33f",
    ".endr",
    "mov.w r1, #16777216",
    "34:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 33f",
    "subs r1, r1, #1",
    "bne 34b",
    "b 99f",
    "33:",
    "b 4b",
    "23:",
    "mov.w lr, #16777216",
    "25:",
    "tst r12, #8",
    "beq 26f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 25b",
    "26:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 24b",
    "b 99f",
    // ==== the last chain's last step: read, clear, store ====
    "70:",
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 71f",
    ".endr",
    "mov.w r1, #16777216",
    "72:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 71f",
    "subs r1, r1, #1",
    "bne 72b",
    "b 99f",
    "71:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r12, [sp, #36]",
    "str r0, [r12]",
    "str r1, [r12, #4]",
    "str r2, [r12, #8]",
    "str r3, [r12, #12]",
    "b 98f",
    // BUSY still set, or a stale DCIS, before the first INIT
    "50:",
    "mov.w r0, #16777216",
    "52:",
    "tst r12, #8",
    "beq 53f",
    "subs r0, r0, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 52b",
    "53:",
    "tst r12, #2",
    "beq 51b",
    "b 99f",
    "99:",
    "bl {fault}",
    "98:",
    "add sp, sp, #68",
    "pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}",
    ".size pq1_v2_key_loop, . - pq1_v2_key_loop",

    spin = const V2_ASM_SPIN,
    lsb = const V2_CI_LSB,
    hb_lo = const (HASH_BASE + 0x0C) & 0xFFFF,
    hb_hi = const (HASH_BASE + 0x0C) >> 16,
    fault = sym hash_engine_fault,
);

#[cfg(all(feature = "v2-asm-key-ga", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
extern "C" {
    /// The `v2-asm-key-ga` loop above.
    fn pq1_v2_key_loop(ctx: *mut u32);
}

#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_wots_chains16(
    sk_seed: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8,
) {
    v2_entry();
    if steps > 15 {
        hash_engine_fault();
    }
    // SAFETY: caller contract.
    let s = unsafe { v2_load4(seed) };
    // The asm stores chain k after chain k + 1's PRF has read `sk_seed`; the loop below stores it
    // first. Take the asm path only when `out` (688 bytes) cannot overlap `sk_seed` (public
    // pointers), so both paths give the same bytes for every input (Astra, round 11).
    #[cfg(all(feature = "v2-asm-key-ga", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    if steps != 0 && ((out as usize).saturating_add(688) <= sk_seed as usize || (sk_seed as usize).saturating_add(32) <= out as usize) {
        let mut ctx = [sk_seed as u32, p0, p1, s[0], s[1], s[2], s[3], a0, low24, steps, 43, out as u32];
        // SAFETY: the loop's contract (the context above); caller contract for `sk_seed` (32
        // readable bytes) and `out` (688 writable bytes); the engine is idle, STR holds NBLW 24.
        unsafe { pq1_v2_key_loop(ctx.as_mut_ptr()) };
        return;
    }
    let mut ci = 0u32;
    while ci < 43 {
        let c = ci << V2_CI_LSB;
        v2_begin();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        write_word(p0);
        write_word(p1 | c);
        #[cfg(not(feature = "v2-prf2"))]
        {
            let v = v2_end16();
            let v = v2_chain_core(s, v, a0, low24 | c, 0, steps);
            // SAFETY: `out + 16 ci`, ci < 43, inside the caller's 688 bytes.
            unsafe { v2_store4(out.add(16 * ci as usize), v) };
            ci += 1;
        }
        // `v2-prf2`: one PRF (even `ci`) gives chains `ci` and `ci + 1`; chain 42 is unpaired.
        #[cfg(feature = "v2-prf2")]
        {
            let mut d = [0u32; 8];
            v2_prf2_both(&mut d);
            let v = v2_chain_core(s, [d[0], d[1], d[2], d[3]], a0, low24 | c, 0, steps);
            // SAFETY: `out + 16 ci`, ci < 43, inside the caller's 688 bytes.
            unsafe { v2_store4(out.add(16 * ci as usize), v) };
            if ci + 1 < 43 {
                let v = v2_chain_core(s, [d[4], d[5], d[6], d[7]], a0, low24 | (ci + 1) << V2_CI_LSB, 0, steps);
                // SAFETY: `out + 16 (ci + 1)`, ci + 1 < 43.
                unsafe { v2_store4(out.add(16 * (ci + 1) as usize), v) };
            }
            v2_wipe8(&mut d);
            ci += 2;
        }
    }
}

/// A whole WOTS public key in one call: the 43 chains of `pqsigner_v2_wots_chains16`
/// written into the T_43 preimage `S ‖ A7(WOTS_PK) ‖ 0x00 ‖ v_0 ‖ … ‖ v_42`
/// (712 bytes, in a driver-side buffer that is written in full and never
/// zero-filled), then its one-shot compression, first 16 bytes to `out`.
/// `k0`/`k1` are the WOTS_PK A7 words (`k1`'s top byte is the 0x00 pad).
///
/// # Safety
/// `sk_seed` 32 and `seed` 16 readable bytes, `out` 16 writable; `steps <= 15`;
/// no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_wots_pk16(
    sk_seed: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, k0: u32, k1: u32, steps: u32,
    out: *mut u8,
) {
    let mut buf = core::mem::MaybeUninit::<[u32; 178]>::uninit();
    let b = buf.as_mut_ptr().cast::<u32>();
    // SAFETY: `b` names 178 writable words. Words 0..6 are written here and
    // 6..178 by `pqsigner_v2_wots_chains16` (43 x 4), so all 712 bytes are
    // initialized before the one-shot reads them; caller contract for the rest.
    unsafe {
        let s = v2_load4(seed);
        for (i, w) in s.iter().enumerate() {
            b.add(i).write(*w);
        }
        b.add(4).write(k0);
        b.add(5).write(k1);
        pqsigner_v2_wots_chains16(sk_seed, p0, p1, seed, a0, low24, steps, b.add(6).cast::<u8>());
        pqsigner_sha256_oneshot16(b.cast::<u8>(), 712, out);
    }
}

/// H: `S ‖ L ‖ R ‖ A7`, 55 bytes.
///
/// # Safety
/// `seed`, `l`, `r` 16 readable bytes each, `out` 16 writable; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_node16(seed: *const u8, l: *const u8, r: *const u8, a0: u32, a1: u32, out: *mut u8) {
    v2_entry();
    v2_begin();
    // SAFETY: caller contract.
    unsafe {
        feed_words(seed, 4);
        feed_words(l, 4);
        feed_words(r, 4);
    }
    write_word(a0);
    write_word(a1);
    let v = v2_end16();
    // SAFETY: caller contract.
    unsafe { v2_store4(out, v) };
}

/// FORS leaf: secret `sk_seed ‖ A7_prf`, then F `S ‖ secret ‖ A7`; the secret
/// stays in registers.
///
/// # Safety
/// `sk_seed` 32 and `seed` 16 readable bytes, `out` 16 writable; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_fors_leaf16(sk_seed: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, a1: u32, out: *mut u8) {
    v2_entry();
    v2_begin();
    // SAFETY: caller contract.
    unsafe { feed_words(sk_seed, 8) };
    write_word(p0);
    #[cfg(not(feature = "v2-prf2"))]
    let x = {
        write_word(p1);
        v2_end16()
    };
    // `v2-prf2`: leaf `j`'s secret is half `j & 1` of the PRF over `j & !1`.
    #[cfg(feature = "v2-prf2")]
    let x = {
        write_word(p1 & !V2_HA_LSB);
        v2_prf2_half(u32::from(p1 & V2_HA_LSB != 0))
    };
    v2_begin();
    // SAFETY: caller contract.
    unsafe { feed_words(seed, 4) };
    write_word(x[0]); write_word(x[1]); write_word(x[2]); write_word(x[3]);
    write_word(a0);
    write_word(a1);
    let v = v2_end16();
    // SAFETY: caller contract.
    unsafe { v2_store4(out, v) };
}

/// `ha` (node or leaf index, < 2^11) in A7's second DIN word: A7 bits 11..1,
/// i.e. the low nibble of byte 5 (word bits 8..11) and bits 7..1 of byte 6
/// (word bits 17..23).
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_ha(x: u32) -> u32 {
    (x & 0x7F) << 17 | (x >> 7) << 8
}

/// `v2-asm-fors` (round 7): one digest-to-digest transition of the FORS subtree,
/// hand-scheduled. Wait for DCIS (straight-line polls, then a 2^24-guarded loop),
/// read HR0..3 (returned, byte-swapped as `read_hr4`), clear DCIS, wait BUSY clear
/// (2^24 guard) and refuse a stale DCIS, INIT, feed the next message, DCAL. The
/// Rust caller prepares the next message's fixed words while the engine runs.
#[cfg(feature = "v2-asm-fors")]
macro_rules! v2x_head {
    ($cr:literal) => {
        concat!(
            ".rept 16\n", "ldr r12, [{hb}, #0x18]\n", "lsls r12, r12, #30\n", "bmi 4f\n", ".endr\n",
            "mov.w r10, #16777216\n",
            "3:\n", "ldr r12, [{hb}, #0x18]\n", "lsls r12, r12, #30\n", "bmi 4f\n", "subs r10, r10, #1\n", "bne 3b\n", "b 99f\n",
            "4:\n",
            "ldm {hb}, {{r0, r1, r2, r3}}\n",
            "movs r12, #1\n", "str r12, [{hb}, #0x18]\n",
            "rev r0, r0\n", "rev r1, r1\n", "rev r2, r2\n", "rev r3, r3\n",
            "ldr r12, [{hb}, #0x18]\n", "tst r12, #10\n", "bne 40f\n",
            "41:\n",
            "str ", $cr, ", [{hb}, #-12]\n",
        )
    };
}
#[cfg(feature = "v2-asm-fors")]
macro_rules! v2x_tail {
    () => {
        concat!(
            "mov.w r12, #280\n", "str r12, [{hb}, #-4]\n",
            "b 98f\n",
            "40:\n", "mov.w r10, #16777216\n",
            "42:\n", "tst r12, #8\n", "beq 43f\n", "subs r10, r10, #1\n", "beq 99f\n", "ldr r12, [{hb}, #0x18]\n", "b 42b\n",
            "43:\n", "tst r12, #2\n", "beq 41b\n",
            "99:\n", "bl {fault}\n",
            "98:\n",
        )
    };
}
#[cfg(feature = "v2-asm-fors")]
macro_rules! v2x_store4 {
    ($a:literal, $b:literal, $c:literal, $d:literal) => {
        concat!("str ", $a, ", [{hb}, #-8]\n", "str ", $b, ", [{hb}, #-8]\n", "str ", $c, ", [{hb}, #-8]\n", "str ", $d, ", [{hb}, #-8]\n")
    };
}

/// Transition into F: message `S ‖ x ‖ a0 ‖ a1'` with `x` the digest in flight;
/// `ss` = `[S0..S3, a0, a1']`.
#[cfg(feature = "v2-asm-fors")]
#[inline(always)]
fn v2x_f(ss: *const u32) -> [u32; 4] {
    let (v0, v1, v2, v3): (u32, u32, u32, u32);
    // SAFETY: drives only the secure HASH block; reads 24 bytes at `ss`; on a hang or
    // a stale DCIS it calls `hash_engine_fault`, which does not return.
    unsafe {
        core::arch::asm!(
            v2x_head!("{cr}"),
            "ldm {ss}, {{r8, r9, r10, r12}}\n",
            v2x_store4!("r8", "r9", "r10", "r12"),
            v2x_store4!("r0", "r1", "r2", "r3"),
            "ldrd r8, r9, [{ss}, #16]\n", "str r8, [{hb}, #-8]\n", "str r9, [{hb}, #-8]\n",
            v2x_tail!(),
            hb = in(reg) HASH_BASE + 0x0C, cr = in(reg) CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT, ss = in(reg) ss,
            fault = sym hash_engine_fault,
            out("r0") v0, out("r1") v1, out("r2") v2, out("r3") v3,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
    [v0, v1, v2, v3]
}

/// Transition into H: message `S ‖ L ‖ R ‖ a0 ‖ a1'` with `R` the digest in flight,
/// `L` the four words at `l`.
#[cfg(feature = "v2-asm-fors")]
#[inline(always)]
fn v2x_h(ss: *const u32, l: *const u32) -> [u32; 4] {
    let (v0, v1, v2, v3): (u32, u32, u32, u32);
    // SAFETY: as `v2x_f`; also reads 16 bytes at `l`.
    unsafe {
        core::arch::asm!(
            v2x_head!("{cr}"),
            "ldm {ss}, {{r8, r9, r10, r12}}\n",
            v2x_store4!("r8", "r9", "r10", "r12"),
            "ldm {l}, {{r8, r9, r10, r12}}\n",
            v2x_store4!("r8", "r9", "r10", "r12"),
            v2x_store4!("r0", "r1", "r2", "r3"),
            "ldrd r8, r9, [{ss}, #16]\n", "str r8, [{hb}, #-8]\n", "str r9, [{hb}, #-8]\n",
            v2x_tail!(),
            hb = in(reg) HASH_BASE + 0x0C, cr = in(reg) CR_DATATYPE_8B | CR_ALGO_SHA256 | CR_INIT, ss = in(reg) ss, l = in(reg) l,
            fault = sym hash_engine_fault,
            out("r0") v0, out("r1") v1, out("r2") v2, out("r3") v3,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
    [v0, v1, v2, v3]
}

/// Transition into the next leaf's PRF: message `sk_seed ‖ p0 ‖ p1'`, `sk_seed`
/// read in place with single-word loads (no copy; unaligned is fine), `pp` =
/// `[p0, p1']`. The CR value is materialized in `lr` inside the engine window.
#[cfg(feature = "v2-asm-fors")]
#[inline(always)]
fn v2x_prf(sk: *const u8, pp: *const u32) -> [u32; 4] {
    let (v0, v1, v2, v3): (u32, u32, u32, u32);
    // SAFETY: as `v2x_f`; reads 32 bytes at `sk` and 8 at `pp`.
    unsafe {
        core::arch::asm!(
            "movw lr, #0x24\n", "movt lr, #0x6\n",
            v2x_head!("lr"),
            "ldr r8, [{sk}]\n", "ldr r9, [{sk}, #4]\n", "ldr r10, [{sk}, #8]\n", "ldr r12, [{sk}, #12]\n",
            v2x_store4!("r8", "r9", "r10", "r12"),
            "ldr r8, [{sk}, #16]\n", "ldr r9, [{sk}, #20]\n", "ldr r10, [{sk}, #24]\n", "ldr r12, [{sk}, #28]\n",
            v2x_store4!("r8", "r9", "r10", "r12"),
            "ldrd r8, r9, [{pp}]\n", "str r8, [{hb}, #-8]\n", "str r9, [{hb}, #-8]\n",
            "movs r10, #0\n", "movs r12, #0\n",
            v2x_tail!(),
            hb = in(reg) HASH_BASE + 0x0C, sk = in(reg) sk, pp = in(reg) pp,
            fault = sym hash_engine_fault,
            out("r0") v0, out("r1") v1, out("r2") v2, out("r3") v3,
            out("r8") _, out("r9") _, out("r10") _, out("r12") _, out("lr") _,
        );
    }
    [v0, v1, v2, v3]
}

/// Root of the v2 FORS subtree of height `h` over leaves `j0..j0 + 2^h` of one
/// FORS tree: leaf `j` is `F(S ‖ PRF(sk_seed ‖ A7_prf(ha = j)) ‖ A7(ha = j))`
/// and the node at height `k` with index `i` is `H(S ‖ L ‖ R ‖ A7(cp = k, ha = i))`.
/// `p0`/`p1` and `a0`/`a1` are the FORS_PRF and FORS_TREE A7 words of the tree
/// with `cp = ha = 0`. Each auth-path node of a FORS tree is one such subtree,
/// and `h = 11` gives the tree root, so the signer keeps the auth-path logic.
///
/// # Safety
/// `sk_seed` 32 and `seed` 16 readable bytes, `out` 16 writable; no other
/// stream in flight. `h <= 11`, `j0` a multiple of `2^h` and `j0 + 2^h <= 2^11`
/// (checked: a violation halts like an engine fault).
/// `v2-asm-fors-ga` (round 11, research format, secure-only): the v2 FORS subtree (any height
/// 0..=11) as one standalone AAPCS function in `global_asm!` (the E10 pattern). `S` and `a0` stay
/// in r5..r9; a leaf (F) has `a1 | ha(j)` preloaded and loads nothing; a node (H) has `L[0..3)`
/// preloaded and loads `L[3]` and its A7 word after INIT; a PRF has `sk_seed[0..7)` preloaded
/// (registers only, single loads) and loads `sk_seed[7]`, `p0`, `p1 | ha(j)` after INIT. The asm
/// issues leaf `j0`'s PRF itself, so the caller never holds `sk_seed` words (round 10's lesson).
/// The treehash, the A7 words and the node stack run in the engine windows. Every digest keeps
/// the checks of the Rust loop (DCIS poll with a 2^24 guard, SR clear, BUSY wait with a 2^24
/// guard and stale-DCIS refusal before INIT, NBLW 24 at DCAL). `ctx`: 0..4 `S`, 4 `a0`, 5 `a1`,
/// 6 `p0`, 7 `p1`, 8 `sk_seed`, 9 `j0`, 10 `h`, 11..15 the root (out).
#[cfg(all(feature = "v2-asm-fors-ga", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
core::arch::global_asm!(
    ".syntax unified",
    ".section .text.pq1_v2_fors_sub,\"ax\",%progbits",
    ".p2align 2",
    ".global pq1_v2_fors_sub",
    ".type pq1_v2_fors_sub,%function",
    ".thumb_func",
    "pq1_v2_fors_sub:",
    "push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}",
    "sub sp, sp, #276",
    // frame: 0 S0..S3, 16 a0, 20 a1, 24 p0, 28 p1 | ha(j), 32 p1, 36 sk_seed, 40 j, 44 end, 48 h, 52 k, 56 idx,
    // 60 depth, 64 a1 | k << 12 | ha(idx), 68 ctx, 72 L3, 76 stack (12 x 16)
    // ctx: 0..4 S, 4 a0, 5 a1, 6 p0, 7 p1, 8 sk_seed, 9 j0, 10 h, 11..15 the root (out)
    "str r0, [sp, #68]",
    "ldm r0, {{r1, r2, r3, r5, r6, r7, r8, r9, r10, r11, r12}}",
    "str r1, [sp, #0]",
    "str r2, [sp, #4]",
    "str r3, [sp, #8]",
    "str r5, [sp, #12]",
    "str r6, [sp, #16]",
    "str r7, [sp, #20]",
    "str r8, [sp, #24]",
    "str r9, [sp, #32]",
    "str r10, [sp, #36]",
    "str r11, [sp, #40]",
    "str r12, [sp, #48]",
    "movs r0, #1",
    "lsls r0, r0, r12",
    "add r0, r0, r11",
    "str r0, [sp, #44]",
    "movs r0, #0",
    "str r0, [sp, #60]",
    "and r1, r11, #0x7F",
    "lsls r1, r1, #17",
    "lsrs r2, r11, #7",
    "orr r1, r1, r2, lsl #8",
    "orr r1, r1, r9",
    "str r1, [sp, #28]",
    "movw r4, #{hb_lo}",
    "movt r4, #{hb_hi}",
    "movw lr, #0x24",
    "movt lr, #0x6",
    // first PRF (leaf j0), issued here so the caller never holds sk_seed words: idle and no stale DCIS (v2_begin), INIT
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 80f",
    "81:",
    "str lr, [r4, #-12]",
    "ldr r12, [sp, #36]",
    "ldr r0, [r12]",
    "ldr r1, [r12, #4]",
    "ldr r2, [r12, #8]",
    "ldr r3, [r12, #12]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldr r0, [r12, #16]",
    "ldr r1, [r12, #20]",
    "ldr r2, [r12, #24]",
    "ldr r3, [r12, #28]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "ldrd r0, r1, [sp, #24]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    // ==== F (leaf j; its PRF in flight): S, a0 in r5..r9, a1 | ha(j) in r10 ====
    "10:",
    "mov r12, sp",
    "ldm r12, {{r5, r6, r7, r8, r9}}",
    "ldr r0, [sp, #40]",
    "and r10, r0, #0x7F",
    "lsls r10, r10, #17",
    "lsrs r1, r0, #7",
    "orr r10, r10, r1, lsl #8",
    "ldr r1, [sp, #20]",
    "orr r10, r10, r1",
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 11f",
    ".endr",
    "mov.w r1, #16777216",
    "12:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 11f",
    "subs r1, r1, #1",
    "bne 12b",
    "b 99f",
    "11:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 13f",
    "14:",
    "str lr, [r4, #-12]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    "ldr r0, [sp, #40]",
    "str r0, [sp, #56]",
    "movs r1, #0",
    "str r1, [sp, #52]",
    // ==== merges: while k < h and idx is odd ====
    "20:",
    "ldr r0, [sp, #52]",
    "ldr r1, [sp, #48]",
    "cmp r0, r1",
    "bhs 30f",
    "ldr r2, [sp, #56]",
    "tst r2, #1",
    "beq 30f",
    "lsrs r2, r2, #1",
    "str r2, [sp, #56]",
    "adds r0, r0, #1",
    "str r0, [sp, #52]",
    "and r3, r2, #0x7F",
    "lsls r3, r3, #17",
    "lsrs r1, r2, #7",
    "orr r3, r3, r1, lsl #8",
    "orr r3, r3, r0, lsl #12",
    "ldr r1, [sp, #20]",
    "orr r3, r3, r1",
    "str r3, [sp, #64]",
    "ldr r1, [sp, #60]",
    "subs r1, r1, #1",
    "str r1, [sp, #60]",
    "add r3, sp, #76",
    "add r3, r3, r1, lsl #4",
    "ldr r2, [r3, #12]",
    "str r2, [sp, #72]",
    "ldm r3, {{r10, r11, r12}}",
    // H (R in flight): L0..L2 in r10..r12; lr does the status work, so the CR value is re-made
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 21f",
    ".endr",
    "mov.w r1, #16777216",
    "22:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 21f",
    "subs r1, r1, #1",
    "bne 22b",
    "b 99f",
    "21:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "mov.w lr, #1",
    "str lr, [r4, #0x18]",
    "ldr lr, [r4, #0x18]",
    "tst lr, #10",
    "bne 23f",
    "24:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "str lr, [r4, #-12]",
    "ldr lr, [sp, #72]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r10, [r4, #-8]",
    "ldr r10, [sp, #64]",
    "str r11, [r4, #-8]",
    "str r12, [r4, #-8]",
    "str lr, [r4, #-8]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "str r0, [r4, #-8]",
    "str r1, [r4, #-8]",
    "str r2, [r4, #-8]",
    "str r3, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "mov.w r11, #280",
    "str r11, [r4, #-4]",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "b 20b",
    // ==== next leaf: its PRF, or the root ====
    "30:",
    "ldr r0, [sp, #40]",
    "adds r0, r0, #1",
    "str r0, [sp, #40]",
    "ldr r1, [sp, #44]",
    "cmp r0, r1",
    "beq 70f",
    "and r2, r0, #0x7F",
    "lsls r2, r2, #17",
    "lsrs r3, r0, #7",
    "orr r2, r2, r3, lsl #8",
    "ldr r1, [sp, #32]",
    "orr r2, r2, r1",
    "str r2, [sp, #28]",
    "ldr r12, [sp, #36]",
    "ldr r5, [r12]",
    "ldr r6, [r12, #4]",
    "ldr r7, [r12, #8]",
    "ldr r8, [r12, #12]",
    "ldr r9, [r12, #16]",
    "ldr r10, [r12, #20]",
    "ldr r11, [r12, #24]",
    // PRF (the finished node in flight): sk_seed[0..7) in r5..r11
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 31f",
    ".endr",
    "mov.w r1, #16777216",
    "32:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 31f",
    "subs r1, r1, #1",
    "bne 32b",
    "b 99f",
    "31:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "ldr r12, [r4, #0x18]",
    "tst r12, #10",
    "bne 33f",
    "34:",
    "str lr, [r4, #-12]",
    "ldr lr, [sp, #36]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "ldr r12, [lr, #28]",
    "str r7, [r4, #-8]",
    "str r8, [r4, #-8]",
    "str r9, [r4, #-8]",
    "str r10, [r4, #-8]",
    "str r11, [r4, #-8]",
    "ldrd r5, r6, [sp, #24]",
    "str r12, [r4, #-8]",
    "str r5, [r4, #-8]",
    "str r6, [r4, #-8]",
    "mov.w r12, #280",
    "str r12, [r4, #-4]",
    // PRF window: push the finished node
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r5, [sp, #60]",
    "add r6, sp, #76",
    "add r6, r6, r5, lsl #4",
    "stm r6, {{r0, r1, r2, r3}}",
    "adds r5, r5, #1",
    "str r5, [sp, #60]",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "b 10b",
    // ==== the root ====
    "70:",
    ".rept 16",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 71f",
    ".endr",
    "mov.w r1, #16777216",
    "72:",
    "ldr r0, [r4, #0x18]",
    "lsls r0, r0, #30",
    "bmi 71f",
    "subs r1, r1, #1",
    "bne 72b",
    "b 99f",
    "71:",
    "ldm r4, {{r0, r1, r2, r3}}",
    "movs r12, #1",
    "str r12, [r4, #0x18]",
    "rev r0, r0",
    "rev r1, r1",
    "rev r2, r2",
    "rev r3, r3",
    "ldr r12, [sp, #68]",
    "add r12, r12, #44",
    "stm r12, {{r0, r1, r2, r3}}",
    "b 98f",
    // BUSY still set, or a stale DCIS before an INIT (first PRF: r0 counts)
    "80:",
    "mov.w r0, #16777216",
    "82:",
    "tst r12, #8",
    "beq 83f",
    "subs r0, r0, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 82b",
    "83:",
    "tst r12, #2",
    "beq 81b",
    "b 99f",
    // F: r11 is free, it counts
    "13:",
    "mov.w r11, #16777216",
    "15:",
    "tst r12, #8",
    "beq 16f",
    "subs r11, r11, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 15b",
    "16:",
    "tst r12, #2",
    "beq 14b",
    "b 99f",
    // H: everything is live, the counter is pushed (two words)
    "23:",
    "push {{r0, r1}}",
    "mov.w r0, #16777216",
    "25:",
    "tst lr, #8",
    "beq 26f",
    "subs r0, r0, #1",
    "beq 99f",
    "ldr lr, [r4, #0x18]",
    "b 25b",
    "26:",
    "pop {{r0, r1}}",
    "tst lr, #2",
    "beq 24b",
    "b 99f",
    // PRF: lr counts, the CR value is re-made
    "33:",
    "mov.w lr, #16777216",
    "35:",
    "tst r12, #8",
    "beq 36f",
    "subs lr, lr, #1",
    "beq 99f",
    "ldr r12, [r4, #0x18]",
    "b 35b",
    "36:",
    "movw lr, #0x24",
    "movt lr, #0x6",
    "tst r12, #2",
    "beq 34b",
    "b 99f",
    "99:",
    "bl {fault}",
    "98:",
    "add sp, sp, #276",
    "pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}",
    ".size pq1_v2_fors_sub, . - pq1_v2_fors_sub",

    hb_lo = const (HASH_BASE + 0x0C) & 0xFFFF,
    hb_hi = const (HASH_BASE + 0x0C) >> 16,
    fault = sym hash_engine_fault,
);

#[cfg(all(feature = "v2-asm-fors-ga", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
extern "C" {
    /// The `v2-asm-fors-ga` subtree above.
    fn pq1_v2_fors_sub(ctx: *mut u32);
}

#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_fors_subtree16(
    sk_seed: *const u8, seed: *const u8, p0: u32, p1: u32, a0: u32, a1: u32, j0: u32, h: u32, out: *mut u8,
) {
    v2_entry();
    if h > 11 || j0 & ((1 << h) - 1) != 0 || j0 + (1 << h) > 1 << 11 {
        hash_engine_fault();
    }
    // SAFETY: caller contract.
    let s = unsafe { v2_load4(seed) };
    let mut stack = [[0u32; 4]; 12];
    let mut sp = 0usize;
    let end = j0 + (1 << h);
    #[cfg(all(feature = "v2-asm-fors", not(feature = "v2-prf2"), not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    {
        #[cfg(feature = "v2-asm-fors-ga")]
        {
            let mut ctx = [s[0], s[1], s[2], s[3], a0, a1, p0, p1, sk_seed as u32, j0, h, 0, 0, 0, 0];
            // SAFETY: the subtree's contract (the context above; it issues leaf j0's PRF);
            // caller contract for `sk_seed` (32 readable bytes); STR holds NBLW 24 (v2_entry).
            unsafe { pq1_v2_fors_sub(ctx.as_mut_ptr()) };
            let _ = (&mut stack, &mut sp, end);
            // SAFETY: caller contract (16 writable bytes).
            unsafe { v2_store4(out, [ctx[11], ctx[12], ctx[13], ctx[14]]) };
            return;
        }
        // Staging for the asm transitions: `ss` = S, a0, a1'; `pp` = p0, p1'. The
        // PRF transitions read `sk_seed` in place (no copy of the secret).
        #[allow(unreachable_code)]
        let mut ss = [s[0], s[1], s[2], s[3], a0, 0];
        let mut pp = [p0, p1 | v2_ha(j0)];
        v2_begin();
        // SAFETY: caller contract.
        unsafe { feed_words(sk_seed, 8) };
        write_word(pp[0]);
        write_word(pp[1]);
        REG.str_.write(V2_NBLW | STR_DCAL);
        let mut j = j0;
        loop {
            ss[5] = a1 | v2_ha(j);
            let _ = v2x_f(ss.as_ptr());
            let mut k = 0u32;
            let mut idx = j;
            while k < h && idx & 1 == 1 {
                sp -= 1;
                idx >>= 1;
                k += 1;
                ss[5] = a1 | k << 12 | v2_ha(idx);
                let _ = v2x_h(ss.as_ptr(), stack[sp].as_ptr());
            }
            j += 1;
            let node = if j < end {
                pp[1] = p1 | v2_ha(j);
                v2x_prf(sk_seed, pp.as_ptr())
            } else {
                v2_wait_dcis();
                let v = read_hr4();
                REG.sr.write(SR_DINIS);
                v
            };
            stack[sp] = node;
            sp += 1;
            if j == end {
                break;
            }
        }
        // SAFETY: caller contract.
        unsafe { v2_store4(out, stack[0]) };
        return;
    }
    #[allow(unreachable_code)]
    let mut j = j0;
    // `v2-prf2`: the two secrets of the current leaf pair.
    #[cfg(feature = "v2-prf2")]
    let mut pair = [0u32; 8];
    while j < end {
        let ha = v2_ha(j);
        #[cfg(not(feature = "v2-prf2"))]
        let x = {
            v2_begin();
            // SAFETY: caller contract.
            unsafe { feed_words(sk_seed, 8) };
            write_word(p0);
            write_word(p1 | ha);
            v2_end16()
        };
        // One PRF per leaf pair, at the even leaf (or at `j0` when a height-0
        // subtree starts on an odd leaf).
        #[cfg(feature = "v2-prf2")]
        let x = {
            if j & 1 == 0 || j == j0 {
                v2_begin();
                // SAFETY: caller contract.
                unsafe { feed_words(sk_seed, 8) };
                write_word(p0);
                write_word(p1 | v2_ha(j & !1));
                v2_prf2_both(&mut pair);
            }
            if j & 1 == 0 { [pair[0], pair[1], pair[2], pair[3]] } else { [pair[4], pair[5], pair[6], pair[7]] }
        };
        v2_begin();
        write_word(s[0]); write_word(s[1]); write_word(s[2]); write_word(s[3]);
        write_word(x[0]); write_word(x[1]); write_word(x[2]); write_word(x[3]);
        write_word(a0);
        write_word(a1 | ha);
        let mut node = v2_end16();
        // While `node` is a right child below the subtree root, fold in its left
        // sibling (pushed earlier): stack depth stays at most h + 1.
        let mut k = 0u32;
        let mut idx = j;
        while k < h && idx & 1 == 1 {
            sp -= 1;
            idx >>= 1;
            k += 1;
            let l = stack[sp];
            v2_begin();
            write_word(s[0]); write_word(s[1]); write_word(s[2]); write_word(s[3]);
            write_word(l[0]); write_word(l[1]); write_word(l[2]); write_word(l[3]);
            write_word(node[0]); write_word(node[1]); write_word(node[2]); write_word(node[3]);
            write_word(a0);
            write_word(a1 | k << 12 | v2_ha(idx));
            node = v2_end16();
        }
        stack[sp] = node;
        sp += 1;
        j += 1;
    }
    #[cfg(feature = "v2-prf2")]
    v2_wipe8(&mut pair);
    // SAFETY: caller contract.
    unsafe { v2_store4(out, stack[0]) };
}

/// v2 R grind (FORS+C) in the driver: for `nonce` in `start..start + n`,
/// `R = SHA-256(prf[..len] with be32(nonce) as its last 4 bytes)[..16]`, then
/// `D = SHA-256(hm with R at bytes 64..80)` (H_MSG, 87 bytes). The first nonce
/// whose last FORS index `(D >> 132) & 0x7FF` (D big-endian; bits 4..14 of HR3)
/// is 0 is returned, with R to `out_r` and D to `out_d`; else `start + n`.
/// `len` is 103 or 119 (v1's R PRF, spec §6), like 87 ≡ 3 (mod 4), so NBLW = 24
/// throughout. The local copy of the PRF input holds `sk_seed`; it is wiped with
/// volatile writes before returning.
///
/// # Safety
/// `prf` `len` and `hm` 87 readable bytes, `out_r` 16 and `out_d` 32 writable;
/// `start + n` does not overflow; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_grind_r(
    prf: *const u8, len: u32, hm: *const u8, start: u32, n: u32, out_r: *mut u8, out_d: *mut u8,
) -> u32 {
    v2_entry();
    if len != 103 && len != 119 {
        hash_engine_fault();
    }
    let len = len as usize;
    let nw = (len + 3) / 4;
    let mut pb = [0u8; 120];
    let mut hb = [0u8; 88];
    // SAFETY: caller contract (`len` and 87 readable bytes).
    unsafe {
        core::ptr::copy_nonoverlapping(prf, pb.as_mut_ptr(), len);
        core::ptr::copy_nonoverlapping(hm, hb.as_mut_ptr(), 87);
    }
    let mut hw = [0u32; 22];
    for (i, w) in hw.iter_mut().enumerate() {
        *w = u32::from_le_bytes([hb[4 * i], hb[4 * i + 1], hb[4 * i + 2], hb[4 * i + 3]]);
    }
    let end = start.wrapping_add(n);
    let mut c = start;
    let mut found = end;
    while c != end {
        pb[len - 4..len].copy_from_slice(&c.to_be_bytes());
        v2_begin();
        let mut i = 0;
        while i < nw {
            write_word(u32::from_le_bytes([pb[4 * i], pb[4 * i + 1], pb[4 * i + 2], pb[4 * i + 3]]));
            i += 1;
        }
        let r = v2_end16();
        hw[16] = r[0];
        hw[17] = r[1];
        hw[18] = r[2];
        hw[19] = r[3];
        v2_begin();
        for w in hw {
            write_word(w);
        }
        REG.str_.write(V2_NBLW | STR_DCAL);
        let mut d = [0u32; 8];
        v2_collect(&mut d);
        if (d[3].swap_bytes() >> 4) & 0x7FF == 0 {
            // SAFETY: `out_r` 16 and `out_d` 32 writable bytes.
            unsafe {
                v2_store4(out_r, r);
                core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out_d, 32);
            }
            found = c;
            break;
        }
        c = c.wrapping_add(1);
    }
    for b in pb.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    found
}

/// One WOTS_DIGEST try `S ‖ m ‖ be32(count) ‖ A7` (43 bytes), issued.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_issue43(sm: &[u32; 8], count: u32, a0: u32, a1: u32) {
    v2_begin();
    for w in sm {
        write_word(*w);
    }
    write_word(count.swap_bytes());
    write_word(a0);
    write_word(a1);
    REG.str_.write(V2_NBLW | STR_DCAL);
}

#[cfg(feature = "v2")]
#[inline(always)]
fn v2_collect(d: &mut [u32; 8]) {
    v2_wait_dcis();
    // SAFETY: HR0..HR7, the digest bank; byte-swapped into memory order.
    unsafe {
        for (i, x) in d.iter_mut().enumerate() {
            *x = REG.hr0.read_at(i).swap_bytes();
        }
    }
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`.
    unsafe {
        pqsigner_hash_tick();
    }
}

/// WOTS+C digit sum in v1's digit position (spec 0.3): digit i = bits
/// 3i..3i+2 of the digest as a 256-bit big-endian integer, i.e. its LOW 129
/// bits. `w` = big-endian words 3..7 of the digest. Five 24-bit groups of eight
/// digits from the bottom, then digits 40..42 (bits 120..128). Wrapping
/// arithmetic: the release profile keeps overflow checks, and this is the
/// grind's inner loop.
#[cfg(feature = "v2")]
#[inline(always)]
fn v2_digit_sum(w: &[u32; 5]) -> u32 {
    #[inline(always)]
    fn g24(v: u32) -> u32 {
        let s = (v & 0o07070707).wrapping_add((v >> 3) & 0o07070707);
        let s = (s & 0o00770077).wrapping_add((s >> 6) & 0o00770077);
        (s & 0o7777).wrapping_add(s >> 12)
    }
    let (w3, w4, w5, w6, w7) = (w[0], w[1], w[2], w[3], w[4]);
    let t = w4 >> 24 | (w3 & 1) << 8;
    g24(w7 & 0x00FF_FFFF)
        .wrapping_add(g24(w7 >> 24 | (w6 & 0xFFFF) << 8))
        .wrapping_add(g24(w6 >> 16 | (w5 & 0xFF) << 16))
        .wrapping_add(g24(w5 >> 8))
        .wrapping_add(g24(w4 & 0x00FF_FFFF))
        .wrapping_add((t & 7).wrapping_add((t >> 3) & 7).wrapping_add(t >> 6))
}

/// `v2-asm-search` (round 7): the count search loop, hand-scheduled. Returns
/// `(c, flag)`: flag 0 = no hit in `start..end` (`c = end`); 1 = try `c` hit and
/// try `c + 1` is in flight; 2 = try `c` hit, nothing in flight. Per try it does
/// what the Rust loop does (BUSY/stale-DCIS check, INIT, `S‖m`, count, A7, DCAL;
/// DCIS poll with a 2^24 guard; SR clear) and the same exact early reject on
/// digits 0..31. Differences are only in schedule: HR3..HR7 in one `ldm`, `S‖m`
/// via two `ldm`, the digit sum in the next try's engine window, a timed first poll.
#[cfg(feature = "v2-asm-search")]
const V2_ASM_SEARCH_SPIN: u32 = 1;

#[cfg(all(feature = "v2-asm-search", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
macro_rules! v2_search_issue {
    // Issue try r8: BUSY clear and no stale DCIS, INIT, S‖m (8), count, a0, a1, DCAL.
    () => {
        concat!(
            "ldr r5, [sp, #16]\n",
            "ldr r12, [r4, #0x24]\n",
            "tst r12, #10\n",
            "bne 40f\n",
            "41:\n",
            "str lr, [r4]\n",
            "ldm r5!, {{r9, r11, r12, lr}}\n",
            "str r9, [r4, #4]\n",
            "str r11, [r4, #4]\n",
            "str r12, [r4, #4]\n",
            "str lr, [r4, #4]\n",
            "ldm r5, {{r9, r11, r12, lr}}\n",
            "str r9, [r4, #4]\n",
            "str r11, [r4, #4]\n",
            "str r12, [r4, #4]\n",
            "str lr, [r4, #4]\n",
            "rev r9, r8\n",
            "str r9, [r4, #4]\n",
            "ldrd r9, r11, [sp]\n",
            "str r9, [r4, #4]\n",
            "str r11, [r4, #4]\n",
            "mov.w r12, #280\n",
            "str r12, [r4, #8]\n",
        )
    };
}

#[cfg(all(feature = "v2-asm-search", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
#[inline(always)]
fn v2_search_asm(sm: *const u8, a0: u32, a1: u32, start: u32, end: u32, target: u32) -> (u32, u32) {
    let (c, flag): (u32, u32);
    // SAFETY: drives only the secure HASH block (r4 = HASH_BASE); reads 32 bytes at
    // `sm` (caller contract); pushes/pops its own 6-word frame; on a hang or a stale
    // DCIS it calls `hash_engine_fault`, which does not return.
    unsafe {
        core::arch::asm!(
            "push {{r0, r1, r2, r3, r5, r12}}", // [sp] a0, [4] a1, [8] end, [12] target, [16] sm, [20] pad (8-byte sp)
            "movw lr, #0x24",
            "movt lr, #0x6",
            v2_search_issue!(),
            "movw lr, #0x24",                 // the issue's ldm reused lr: CR value back
            "movt lr, #0x6",
            "b 1f",
            // BUSY still set, or a stale DCIS (shared by both issue sites via 40/41 in the
            // first expansion only: the second issue jumps to 42/43 below)
            "40:",
            "mov.w lr, #16777216",
            "44:",
            "tst r12, #8",
            "beq 45f",
            "subs lr, lr, #1",
            "beq 99f",
            "ldr r12, [r4, #0x24]",
            "b 44b",
            "45:",
            "tst r12, #2",
            "bne 99f",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 41b",
            // wait for DCIS of the try in flight: timed spin, then the first poll
            "1:",
            "movs r12, #{spin}",
            "10:",
            "subs r12, r12, #1",
            "bne 10b",
            "2:",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bpl 11f",
            "4:",
            "addw r12, r4, #796",              // HR3
            "ldm r12, {{r0, r1, r2, r3, r10}}",  // w3, w4, w5, w6, w7
            "movs r12, #1",
            "str r12, [r4, #0x24]",
            "add r8, r8, #1",
            "ldr r12, [sp, #8]",
            "cmp r8, r12",
            "beq 5f",
            // issue the next try (second site: its slow path is 42/43)
            "ldr r5, [sp, #16]",
            "ldr r12, [r4, #0x24]",
            "tst r12, #10",
            "bne 42f",
            "43:",
            "str lr, [r4]",
            "ldm r5!, {{r9, r11, r12, lr}}",
            "str r9, [r4, #4]",
            "str r11, [r4, #4]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "ldm r5, {{r9, r11, r12, lr}}",
            "str r9, [r4, #4]",
            "str r11, [r4, #4]",
            "str r12, [r4, #4]",
            "str lr, [r4, #4]",
            "rev r9, r8",
            "str r9, [r4, #4]",
            "ldrd r9, r11, [sp]",
            "str r9, [r4, #4]",
            "str r11, [r4, #4]",
            "mov.w r12, #280",
            "str r12, [r4, #8]",
            // digit sum of try r8 - 1 (r0..r3, r10), in the engine window. Digits 0..31 are
            // w7[29:0], w7[31:30]|w6[0], w6[30:1], w6[31]|w5[1:0], w5[31:2] (w7 least
            // significant, as in `g24`). Ten whole digits per word, paired under
            // A = 0o0707070707 (fields <= 14, three words <= 42 < 64), folded to 12-bit
            // fields under B, then summed by one multiply into bits 24..31 (<= 210; the
            // next partial product starts at bit 36). Checked against the reference
            // digit sum on 300k vectors (round 7 notes) before the kit run.
            "5:",
            "movw lr, #0x71C7",                // A = 0o0707070707
            "movt lr, #0x071C",
            "movw r9, #0xF03F",                // B = 0x3F03F03F (12-bit fold)
            "movt r9, #0x3F03",
            "and r5, r10, lr",
            "and r11, lr, r10, lsr #3",
            "add r5, r5, r11",
            "and r11, lr, r3, lsr #1",
            "add r5, r5, r11",
            "and r11, lr, r3, lsr #4",
            "add r5, r5, r11",
            "and r11, lr, r2, lsr #2",
            "add r5, r5, r11",
            "and r11, lr, r2, lsr #5",
            "add r5, r5, r11",
            "and r11, r5, r9",
            "and r5, r9, r5, lsr #6",
            "add r5, r5, r11",
            "movw r11, #0x1001",               // fields at 0, 12, 24 summed into bits 24..31
            "movt r11, #0x0100",
            "mul r5, r5, r11",
            "lsr r5, r5, #24",
            "lsr r11, r10, #30",
            "bfi r11, r3, #2, #1",
            "add r5, r5, r11",
            "lsr r11, r3, #31",
            "bfi r11, r2, #1, #2",
            "add r5, r5, r11",
            "ldr r12, [sp, #12]",
            "add r11, r5, #77",
            "cmp r11, r12",
            "bhs 6f",
            // early reject (lr back to the CR value before the next issue)
            "movw lr, #0x24",
            "movt lr, #0x6",
            "ldr r12, [sp, #8]",
            "cmp r8, r12",
            "bne 1b",
            "movs r0, #0",
            "b 97f",
            "6:",
            // digits 32..41 = w4[29:0], digit 42 = w4[31:30]|w3[0]
            "and r11, r1, lr",
            "and r12, lr, r1, lsr #3",
            "add r11, r11, r12",
            "and r12, r11, r9",
            "and r11, r9, r11, lsr #6",
            "add r11, r11, r12",
            "movw r12, #0x1001",
            "movt r12, #0x0100",
            "mul r11, r11, r12",
            "add r5, r5, r11, lsr #24",
            "lsr r11, r1, #30",
            "bfi r11, r0, #2, #1",
            "add r5, r5, r11",
            "ldr r12, [sp, #12]",
            "cmp r5, r12",
            "beq 7f",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "ldr r12, [sp, #8]",
            "cmp r8, r12",
            "bne 2b",
            "movs r0, #0",
            "b 97f",
            // hit on try r8 - 1
            "7:",
            "ldr r12, [sp, #8]",
            "cmp r8, r12",
            "ite eq",
            "moveq r0, #2",
            "movne r0, #1",
            "sub r8, r8, #1",
            "b 97f",
            // DCIS not yet: seven straight polls, then a counted poll (2^24)
            "11:",
            ".rept 7",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bmi 4b",
            ".endr",
            "mov.w lr, #16777216",
            "12:",
            "ldr r12, [r4, #0x24]",
            "lsls r12, r12, #30",
            "bmi 13f",
            "subs lr, lr, #1",
            "bne 12b",
            "b 99f",
            "13:",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 4b",
            // second issue site's slow path
            "42:",
            "mov.w lr, #16777216",
            "46:",
            "tst r12, #8",
            "beq 47f",
            "subs lr, lr, #1",
            "beq 99f",
            "ldr r12, [r4, #0x24]",
            "b 46b",
            "47:",
            "tst r12, #2",
            "bne 99f",
            "movw lr, #0x24",
            "movt lr, #0x6",
            "b 43b",
            "99:",
            "bl {fault}",
            "97:",
            "add sp, sp, #24",
            spin = const V2_ASM_SEARCH_SPIN,
            fault = sym hash_engine_fault,
            inout("r0") a0 => flag,
            inout("r1") a1 => _,
            inout("r2") end => _,
            inout("r3") target => _,
            in("r4") HASH_BASE,
            inout("r5") sm => _,
            inout("r8") start => c,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("lr") _,
        );
    }
    (c, flag)
}

/// v2 count search with the WOTS+C target in the driver (no callback): the
/// first `c` in `start..start + n` whose digest's digit sum is `target`
/// (digest to `out`), else `start + n`. Try `c + 1` is in the engine while the
/// sum of try `c` is computed.
///
/// # Safety
/// `sm` 32 readable bytes (`S ‖ m`), `out` 32 writable; `start + n` does not
/// overflow; no other stream in flight.
#[cfg(feature = "v2")]
#[no_mangle]
pub unsafe extern "C" fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32 {
    v2_entry();
    let end = start.wrapping_add(n);
    if n == 0 {
        return end;
    }
    #[inline(always)]
    fn g24(v: u32) -> u32 {
        let s = (v & 0o07070707).wrapping_add((v >> 3) & 0o07070707);
        let s = (s & 0o00770077).wrapping_add((s >> 6) & 0o00770077);
        (s & 0o7777).wrapping_add(s >> 12)
    }
    // SAFETY (issue): caller contract, `sm` names 32 readable bytes.
    let issue = |count: u32| unsafe {
        v2_begin();
        feed_words(sm, 8);
        write_word(count.swap_bytes());
        write_word(a0);
        write_word(a1);
        REG.str_.write(V2_NBLW | STR_DCAL);
    };
    #[cfg(all(feature = "v2-asm-search", not(all(feature = "tick-hook", not(feature = "tick-batch")))))]
    {
        let _ = g24;
        // The asm reads `S ‖ m` with `ldm`, which needs a word-aligned address; the
        // contract promises only 32 readable bytes, so copy it (public data).
        // SAFETY: caller contract, `sm` names 32 readable bytes.
        let smw: [u32; 8] = core::array::from_fn(|i| unsafe { sm.cast::<u32>().add(i).read_unaligned() });
        let (c, flag) = v2_search_asm(smw.as_ptr().cast::<u8>(), a0, a1, start, end, target);
        if flag == 0 {
            return end;
        }
        // A hit: drop the try in flight, then recompute try `c` for all eight words.
        let mut d = [0u32; 8];
        if flag == 1 {
            v2_collect(&mut d);
        }
        issue(c);
        v2_collect(&mut d);
        // SAFETY: `out` names 32 writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) };
        return c;
    }
    #[allow(unreachable_code)]
    issue(start);
    let mut c = start;
    loop {
        // Per try only HR3..HR7, the words the digit sum reads (big-endian).
        #[cfg(feature = "v2-fold-sum")]
        v2_spin(V2_RUST_SEARCH_SPIN);
        v2_wait_dcis();
        // SAFETY: HR3..HR7, inside the digest bank.
        let (w3, w4, w5, w6, w7) =
            unsafe { (REG.hr0.read_at(3), REG.hr0.read_at(4), REG.hr0.read_at(5), REG.hr0.read_at(6), REG.hr0.read_at(7)) };
        REG.sr.write(SR_DINIS);
        // The per-digest UI tick, as in `v2_collect` (product builds only).
        #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
        // SAFETY: as in `final_body`: the digest is out and the engine idle.
        unsafe {
            pqsigner_hash_tick();
        }
        let next = c.wrapping_add(1);
        let more = next != end;
        if more {
            issue(next);
        }
        // Digits 0..31 first (`v2_digit_sum`'s first four groups). Digits
        // 32..42 add at most 11 x 7 = 77, so below `target - 77` there is no
        // hit and the rest is skipped (public grind data: branching is fine).
        #[cfg(not(feature = "v2-fold-sum"))]
        let s4 = g24(w7 & 0x00FF_FFFF)
            .wrapping_add(g24(w7 >> 24 | (w6 & 0xFFFF) << 8))
            .wrapping_add(g24(w6 >> 16 | (w5 & 0xFF) << 16))
            .wrapping_add(g24(w5 >> 8));
        #[cfg(feature = "v2-fold-sum")]
        let s4 = v2_fold_s4(w5, w6, w7);
        if s4.wrapping_add(77) >= target {
            #[cfg(not(feature = "v2-fold-sum"))]
            let sum = {
                let t = w4 >> 24 | (w3 & 1) << 8;
                s4.wrapping_add(g24(w4 & 0x00FF_FFFF))
                    .wrapping_add((t & 7).wrapping_add((t >> 3) & 7).wrapping_add(t >> 6))
            };
            #[cfg(feature = "v2-fold-sum")]
            let sum = s4.wrapping_add(v2_fold_rest(w3, w4));
            debug_assert!(sum == v2_digit_sum(&[w3, w4, w5, w6, w7]));
            if sum == target {
                // A hit (twice per pass): drop the try in flight, then recompute
                // this one to read all eight digest words.
                let mut d = [0u32; 8];
                if more {
                    v2_collect(&mut d);
                }
                issue(c);
                v2_collect(&mut d);
                // SAFETY: `out` names 32 writable bytes.
                unsafe { core::ptr::copy_nonoverlapping(d.as_ptr().cast::<u8>(), out, 32) };
                return c;
            }
        }
        if !more {
            return end;
        }
        c = next;
    }
}

