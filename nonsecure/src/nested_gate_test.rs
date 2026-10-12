//! #896 nested-gateway test runner (hardware only).
//!
//! # What this exercises
//!
//! Commits `b87eb660` / `763eb7ec` made the non-secure to secure gateway
//! one-at-a-time (#846): a second gateway call made while one is in flight
//! is refused. Every existing test reads that in source or runs the QEMU
//! mailbox, which cannot nest. This runner makes the nested call actually
//! happen on silicon.
//!
//! It installs a *non-secure* SysTick handler and lets it fire while an
//! outer `sign_userop` is parked inside the secure veneer. From the handler
//! it makes a second gateway call (`is_unlocked`, the cheapest entry) and
//! records what came back. With the gate present the nested call is refused
//! (`is_unlocked` returns 0 although the device is unlocked). With the gate
//! compiled out on the secure side (`gateway-gate-off`, the negative
//! control) the nested call is admitted (returns 1). A positive PASS means
//! "refused because of the gate" only when the negative control on the same
//! board PASSes too: the control is what shows the handler really reaches a
//! nested call and that nothing but the gate refuses it.
//!
//! # Proving the call was nested
//!
//! A banked non-secure SysTick preempting secure *thread* mode is the
//! premise behind #846 and is itself unconfirmed on this silicon. The runner
//! does not assume it. It reads the DWT cycle counter when the outer call
//! starts (`t0`) and returns (`t_ret`), and the handler records when its
//! nested call starts and when it FINISHES. The call counts as nested only
//! if it started well after `t0` and finished well before `t_ret`
//! (`NESTED_GUARD_MS` each side). A tick that was held pending and taken
//! after the outer call returned finishes microseconds before `main`
//! resumes, so it fails the second test no matter how long the handler ran.
//! (The handler cannot read its own `EXC_RETURN`: cortex-m-rt calls it from
//! a trampoline, so `LR` inside it is not the exception-return value.)
//!
//! Outcomes:
//!   * nested, and the result is the one this build expects -> PASS
//!   * nested, and the result is the other one              -> FAIL
//!   * no nested call proven                                 -> INCONCLUSIVE
//!   * DWT not counting / possible counter wrap              -> INCONCLUSIVE
//!
//! # Scope (of #896)
//!
//! Covers: a nested gateway call is refused with the gate, admitted without
//! it (negative control), the gate reopens after the outer call (a following
//! ordinary sign is admitted), the premise is proven or reported as
//! INCONCLUSIVE, and the ORIGINAL outer response is printed between
//! `--RESP-BEGIN--`/`--RESP-END--` so `tools/verify-c10-sig` can check that
//! the signature the device returned under the nested call covers the
//! calldata it was given. The outer sign uses exactly that verifier's fixed
//! transaction (chain 84532, slot 0, no initCode, to 0x11..11, 1e15 wei).
//!
//! Does NOT cover: the PendSV idle-reunlock dialog (#152), the secure stack
//! high-water mark with the fix (#854), or the full nested-SIGN swap case
//! under `gateway-gate-off` (left out on purpose: it would run a second sign
//! in handler mode on top of the parked outer call and roughly double secure
//! stack use).
//!
//! Reports over semihosting, so it needs a debug probe: the SWD bench board,
//! not the enclosed DFU unit. Pairs with the secure crate's `e2e-test`
//! (auto-provision, pre-unlock, short-circuited confirm, so no human is
//! needed at the dialogs). Run with `make nested-gate-test-hw` (gate
//! present) and `make nested-gate-test-nctl-hw` (negative control).

#![allow(static_mut_refs)]

use crate::nsc_api;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use cortex_m_semihosting::{debug, hprintln};
use sphincs_tz_shared::{MAX_SIGN_RESPONSE_LEN, SIGN_USEROP_HEADER_LEN, SIG_TYPE2_LEN};

// === Build-time expectation ================================================

/// Positive build: the gate is present, so the nested call must be
/// refused. Negative-control build (`nested-gate-expect-admit`, paired with
/// the secure `gateway-gate-off`): the nested call must be admitted.
#[cfg(not(feature = "nested-gate-expect-admit"))]
const EXPECT_NESTED_ADMITTED: bool = false;
#[cfg(feature = "nested-gate-expect-admit")]
const EXPECT_NESTED_ADMITTED: bool = true;

// === Shared state between `main` and the SysTick handler ===================

/// True only while the outer gateway call is in flight.
static OUTER_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// True only while the handler is allowed to act.
static ARMED: AtomicBool = AtomicBool::new(false);
/// SysTick handler runs since the phase armed.
static TICKS: AtomicU32 = AtomicU32::new(0);
/// Make the nested call only on or after this tick (about 0.5 s into the
/// outer sign), so it lands in the middle of the window, not at its edges.
static FIRE_AFTER: AtomicU32 = AtomicU32::new(u32::MAX);
/// Set once the handler has made its one nested call.
static FIRED: AtomicBool = AtomicBool::new(false);
/// 2 = the handler never made the call; 0 = refused; 1 = admitted.
static NESTED_RESULT: AtomicU32 = AtomicU32::new(2);
/// DWT cycle counts just before and just after the handler's nested call.
static NESTED_CYC_START: AtomicU32 = AtomicU32::new(0);
static NESTED_CYC_END: AtomicU32 = AtomicU32::new(0);

// === Scratch buffers =======================================================

static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN] = [0u8; MAX_SIGN_RESPONSE_LEN];
static mut PAYLOAD_BUF: [u8; SIGN_USEROP_HEADER_LEN] = [0u8; SIGN_USEROP_HEADER_LEN];

// === Timing (DWT, enabled by the secure world before NS boots) =============

const DWT_CYCCNT: *const u32 = 0xE000_1004 as *const u32;
/// Secure world sets SYSCLK to 160 MHz (see `hw::rcc::init`).
const CPU_HZ: u32 = 160_000_000;
const CYC_PER_MS: u32 = CPU_HZ / 1000;
/// Minimum margin between the nested call and either end of the outer call.
const NESTED_GUARD_MS: u32 = 50;
/// The 32-bit counter wraps after ~26.8 s at 160 MHz. A coarse tick-based
/// elapsed time above this means `wrapping_sub` can no longer be trusted.
const WRAP_SAFE_MS: u32 = 25_000;

#[inline(always)]
fn cycles_now() -> u32 {
    // SAFETY: DWT_CYCCNT is a free-running read-only counter the secure
    // world enabled before booting NS.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

// === Non-secure SysTick ====================================================

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;
/// ENABLE | TICKINT | CLKSOURCE(processor clock).
const SYST_CSR_RUN: u32 = 0b111;
const TICK_MS: u32 = 20;
/// 20 ms at 160 MHz = 3_200_000 cycles, under the 24-bit reload maximum.
const SYST_RELOAD: u32 = CYC_PER_MS * TICK_MS;
const _: () = assert!(SYST_RELOAD <= 0x00FF_FFFF);

fn systick_start() {
    // SAFETY: the non-secure SysTick (banked; the secure world owns its own
    // instance) at the standard SCS offsets. Single-threaded setup.
    unsafe {
        core::ptr::write_volatile(SYST_RVR, SYST_RELOAD);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, SYST_CSR_RUN);
    }
}

fn systick_stop() {
    // SAFETY: as above; disable the counter and its interrupt.
    unsafe { core::ptr::write_volatile(SYST_CSR, 0) };
}

/// Non-secure SysTick handler. While armed and the outer call is in flight,
/// make exactly one nested gateway call after `FIRE_AFTER` ticks and record
/// the result and when the call started and finished. The call is
/// `is_unlocked`, the cheapest gateway entry; it never makes a nested sign.
#[cortex_m_rt::exception]
fn SysTick() {
    let t = TICKS.fetch_add(1, Ordering::SeqCst) + 1;
    if !ARMED.load(Ordering::SeqCst) || FIRED.load(Ordering::SeqCst) {
        return;
    }
    if !OUTER_IN_FLIGHT.load(Ordering::SeqCst) || t < FIRE_AFTER.load(Ordering::SeqCst) {
        return;
    }
    NESTED_CYC_START.store(cycles_now(), Ordering::SeqCst);
    // True only if the call ran (the device is unlocked this session). A
    // gate refusal returns 0 -> false. `main` checks the device is unlocked
    // before and after, so false here can only mean the gate refused.
    let admitted = nsc_api::is_unlocked();
    NESTED_CYC_END.store(cycles_now(), Ordering::SeqCst);
    NESTED_RESULT.store(u32::from(admitted), Ordering::SeqCst);
    FIRED.store(true, Ordering::SeqCst);
}

// === Sign payloads =========================================================

const ENTRY_POINT_V06: [u8; 20] = [
    0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57, 0x8a,
    0x02, 0x6d, 0x27, 0x89,
];
const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// The outer transaction. Must stay byte-identical to the constants in
/// `tools/verify-c10-sig/src/main.rs` so the printed response verifies with
/// that tool unchanged: chain 84532, account 0, slot 0, normal mode (no
/// initCode, no slot registration), nonce 0, gas 50k / 800k / 150k, fees
/// 1 gwei / 0.1 gwei, `paymasterAndData` hash = sha256(""), to 0x11 x 20,
/// value 1e15 wei, no inner calldata.
const OUTER_CHAIN_ID: u64 = 84_532;
const OUTER_TO: [u8; 20] = [0x11; 20];
const OUTER_VALUE_WEI: u128 = 1_000_000_000_000_000;
/// The follow-up ordinary sign (phase B) only has to be admitted, so it
/// uses a different destination and amount.
const FOLLOWUP_TO: [u8; 20] = [0xBB; 20];
const FOLLOWUP_VALUE_WEI: u128 = 2_000_000_000_000_000;

/// Build a normal-mode single-UserOp payload (flags = 0: account 0, slot 0,
/// no initCode, no slot registration).
fn build_payload(buf: &mut [u8], sender: &[u8; 20], to: &[u8; 20], value_wei: u128) -> usize {
    fn u128_be_slot(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        out
    }
    let call_gas = u128_be_slot(50_000);
    let ver_gas = u128_be_slot(800_000);
    let pre_gas = u128_be_slot(150_000);
    let max_fee = u128_be_slot(1_000_000_000);
    let max_prio = u128_be_slot(100_000_000);
    let value = u128_be_slot(value_wei);

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&OUTER_CHAIN_ID.to_be_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // flags
    off += 4;
    buf[off..off + 20].copy_from_slice(sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
    off += 20;
    buf[off..off + 32].copy_from_slice(&[0u8; 32]); // nonce 0
    off += 32;
    for field in [&call_gas, &ver_gas, &pre_gas, &max_fee, &max_prio] {
        buf[off..off + 32].copy_from_slice(field);
        off += 32;
    }
    buf[off..off + 32].copy_from_slice(&SHA256_EMPTY);
    off += 32;
    buf[off..off + 20].copy_from_slice(to);
    off += 20;
    buf[off..off + 32].copy_from_slice(&value);
    off += 32;
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes()); // data_len = 0
    off += 2;
    debug_assert_eq!(off, SIGN_USEROP_HEADER_LEN);
    off
}

/// End offset of a unified-sign response and its Type-2 wrapper length:
/// `count(8) | ic_len(4) ic | t1_len(4) t1 | t2_len(4) t2`. Every read and
/// every addition is checked, so a malformed response yields `None`.
fn response_shape(sig: &[u8]) -> Option<(usize, usize)> {
    let be = |o: usize| -> Option<usize> {
        let b = sig.get(o..o.checked_add(4)?)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let ic_len = be(8)?;
    let t1_off = 12usize.checked_add(ic_len)?;
    let t1_len = be(t1_off)?;
    let t2_off = t1_off.checked_add(4)?.checked_add(t1_len)?;
    let t2_len = be(t2_off)?;
    let end = t2_off.checked_add(4)?.checked_add(t2_len)?;
    if end > sig.len() {
        return None;
    }
    Some((end, t2_len))
}

// === Runner ================================================================

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS][ngt] === nested-gateway test (#896) ===");
    hprintln!(
        "[NS][ngt] build expects the nested call to be {}",
        if EXPECT_NESTED_ADMITTED { "ADMITTED (gate off)" } else { "REFUSED (gate on)" }
    );

    if !nsc_api::is_unlocked() {
        verdict_fail("gateway not pre-unlocked (needs e2e-test on the secure side)");
    }
    let mut sender = [0u8; 20];
    if nsc_api::get_wallet_address(&mut sender, 0, 0) != 0 {
        verdict_fail("could not derive the account-0 sender");
    }

    // --- Phase A: nested call while the outer sign is in flight ---------
    let ok_before = nsc_api::is_unlocked();
    FIRED.store(false, Ordering::SeqCst);
    NESTED_RESULT.store(2, Ordering::SeqCst);
    NESTED_CYC_START.store(0, Ordering::SeqCst);
    NESTED_CYC_END.store(0, Ordering::SeqCst);
    TICKS.store(0, Ordering::SeqCst);
    FIRE_AFTER.store(500 / TICK_MS, Ordering::SeqCst); // ~0.5 s in
    ARMED.store(true, Ordering::SeqCst);

    // SAFETY: single-threaded except for the SysTick handler, which never
    // touches these buffers (it only calls `is_unlocked`).
    let payload_len = unsafe { build_payload(&mut PAYLOAD_BUF, &sender, &OUTER_TO, OUTER_VALUE_WEI) };
    systick_start();
    let t0 = cycles_now();
    OUTER_IN_FLIGHT.store(true, Ordering::SeqCst);
    let outer_status = unsafe { nsc_api::sign_userop(&PAYLOAD_BUF[..payload_len], &mut SIG_BUF) };
    let t_ret = cycles_now();
    OUTER_IN_FLIGHT.store(false, Ordering::SeqCst);
    let ticks_at_return = TICKS.load(Ordering::SeqCst);
    ARMED.store(false, Ordering::SeqCst);
    systick_stop();
    let ok_after = nsc_api::is_unlocked();

    let fired = FIRED.load(Ordering::SeqCst);
    let nested = NESTED_RESULT.load(Ordering::SeqCst);
    let th0 = NESTED_CYC_START.load(Ordering::SeqCst);
    let th1 = NESTED_CYC_END.load(Ordering::SeqCst);

    let total = t_ret.wrapping_sub(t0);
    let before = th0.wrapping_sub(t0); // outer start -> nested call start
    let after = t_ret.wrapping_sub(th1); // nested call end -> outer return
    let handler = th1.wrapping_sub(th0);
    let guard = CYC_PER_MS * NESTED_GUARD_MS;

    hprintln!(
        "[NS][ngt] outer: status={} total_ms={} ticks_at_return={}",
        outer_status,
        total / CYC_PER_MS,
        ticks_at_return
    );
    hprintln!(
        "[NS][ngt] handler: fired={} start_after_ms={} end_before_return_ms={} call_us={} nested_result={} (2=not-run,0=refused,1=admitted)",
        fired,
        before / CYC_PER_MS,
        after / CYC_PER_MS,
        handler / (CYC_PER_MS / 1000),
        nested
    );
    hprintln!("[NS][ngt] unlocked before={} after={}", ok_before, ok_after);

    // Print the ORIGINAL outer response before anything else reuses SIG_BUF.
    let shape = unsafe { response_shape(&SIG_BUF) };
    let mut outer_shape_ok = false;
    if outer_status == 0 {
        if let Some((end, t2_len)) = shape {
            outer_shape_ok = t2_len == SIG_TYPE2_LEN;
            let count = unsafe { u64::from_be_bytes(SIG_BUF[0..8].try_into().unwrap_or([0xFF; 8])) };
            hprintln!("[NS][ngt] outer response: {} bytes, offchain_count={}", end, count);
            hprintln!("--RESP-BEGIN--");
            print_hex(unsafe { &SIG_BUF[..end] });
            hprintln!("--RESP-END--");
        }
    }

    // --- Phase B: the gate reopened; an ordinary call is admitted -------
    let followup_len =
        unsafe { build_payload(&mut PAYLOAD_BUF, &sender, &FOLLOWUP_TO, FOLLOWUP_VALUE_WEI) };
    let followup_status =
        unsafe { nsc_api::sign_userop(&PAYLOAD_BUF[..followup_len], &mut SIG_BUF) };
    hprintln!("[NS][ngt] follow-up ordinary sign: status={}", followup_status);

    // --- Verdict --------------------------------------------------------
    if !(outer_status == 0 && outer_shape_ok && ok_before && ok_after && followup_status == 0) {
        verdict_fail("outer sign, response shape, liveness or follow-up sign check failed");
    }
    if total < 1000 * CYC_PER_MS {
        verdict_inconclusive("DWT reports under 1 s for a full sign: cycle counter not counting");
    }
    if ticks_at_return.saturating_mul(TICK_MS) > WRAP_SAFE_MS {
        verdict_inconclusive("outer call near or past the 26.8 s DWT wrap: timing not trustworthy");
    }
    let proven_nested = fired && before > guard && after > guard && handler < total;
    if !proven_nested {
        // Not a pass for either build: the premise (a banked NS SysTick
        // preempting the secure veneer) was not observed.
        verdict_inconclusive("no nested call proven inside the in-flight window (premise not observed)");
    }

    let admitted = nested == 1;
    if admitted == EXPECT_NESTED_ADMITTED {
        hprintln!(
            "[NS][ngt] PASS: nested call was {} as this build expects",
            if admitted { "ADMITTED (gate off)" } else { "REFUSED (gate on)" }
        );
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        hprintln!(
            "[NS][ngt] FAIL: nested call was {} but this build expects {}",
            if admitted { "ADMITTED" } else { "REFUSED" },
            if EXPECT_NESTED_ADMITTED { "ADMITTED" } else { "REFUSED" }
        );
        debug::exit(debug::EXIT_FAILURE);
    }
    loop {}
}

fn verdict_fail(why: &str) -> ! {
    hprintln!("[NS][ngt] FAIL: {}", why);
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}

fn verdict_inconclusive(why: &str) -> ! {
    hprintln!("[NS][ngt] INCONCLUSIVE: {}", why);
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}

/// Print bytes as hex, 64 bytes per line, so a host can scrape the
/// response from between the markers.
fn print_hex(bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut line = [0u8; 128];
    for chunk in bytes.chunks(64) {
        let mut n = 0;
        for &b in chunk {
            line[n] = HEX[(b >> 4) as usize];
            line[n + 1] = HEX[(b & 0x0F) as usize];
            n += 2;
        }
        // ASCII hex by construction, so the checked conversion never fails.
        if let Ok(s) = core::str::from_utf8(&line[..n]) {
            hprintln!("{}", s);
        }
    }
}
