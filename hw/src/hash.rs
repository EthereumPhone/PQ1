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

#[cfg(feature = "chain")]
#[inline(always)]
fn chain_steps<const Z: bool>(c: &[u32; 16], mut v: [u32; 4], start_pos: u32, steps: u32) -> [u32; 4] {
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
        // init_body (init-restart): idle, no stale DCIS, INIT.
        if wait_ready_sr() & SR_DCIS != 0 {
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
        // SAFETY: HR0..HR3 are the first four words of the digest bank.
        unsafe {
            v = [
                REG.hr0.read_at(0).swap_bytes(),
                REG.hr0.read_at(1).swap_bytes(),
                REG.hr0.read_at(2).swap_bytes(),
                REG.hr0.read_at(3).swap_bytes(),
            ];
        }
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
    if wait_ready_sr() & SR_DCIS != 0 {
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
    // SAFETY: HR0..HR3.
    let v = unsafe {
        [
            REG.hr0.read_at(0).swap_bytes(),
            REG.hr0.read_at(1).swap_bytes(),
            REG.hr0.read_at(2).swap_bytes(),
            REG.hr0.read_at(3).swap_bytes(),
        ]
    };
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
    if wait_ready_sr() & SR_DCIS != 0 {
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
    // SAFETY: HR0..HR3.
    let v = unsafe {
        [
            REG.hr0.read_at(0).swap_bytes(),
            REG.hr0.read_at(1).swap_bytes(),
            REG.hr0.read_at(2).swap_bytes(),
            REG.hr0.read_at(3).swap_bytes(),
        ]
    };
    REG.sr.write(SR_DINIS);
    #[cfg(all(feature = "tick-hook", not(feature = "tick-batch")))]
    // SAFETY: as in `final_body`.
    unsafe {
        pqsigner_hash_tick();
    }
    if wait_ready_sr() & SR_DCIS != 0 {
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
        if wait_ready_sr() & SR_DCIS != 0 {
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
        // SAFETY: HR0..HR3.
        let v = unsafe {
            [
                REG.hr0.read_at(0).swap_bytes(),
                REG.hr0.read_at(1).swap_bytes(),
                REG.hr0.read_at(2).swap_bytes(),
                REG.hr0.read_at(3).swap_bytes(),
            ]
        };
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
    // SAFETY: HR0..HR3.
    let v = unsafe {
        [
            REG.hr0.read_at(0).swap_bytes(),
            REG.hr0.read_at(1).swap_bytes(),
            REG.hr0.read_at(2).swap_bytes(),
            REG.hr0.read_at(3).swap_bytes(),
        ]
    };
    REG.sr.write(SR_DINIS);
    v
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
    if wait_ready_sr() & SR_DCIS != 0 {
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
    if wait_ready_sr() & SR_DCIS != 0 {
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
