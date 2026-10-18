//! DVT row 13.10: can a hostile non-secure image hold the idle wipe off?
//!
//! # Hypothesis (code read)
//!
//! The secure SysTick skips the 120 s idle wipe while `handler_is_busy()`.
//! A non-secure exception that preempts an in-flight gateway handler and
//! never returns keeps `HANDLER_DEPTH > 0` for as long as it likes. The IWDG
//! watcher caps a busy handler at `MAX_BUSY_TICKS` (~30 s), but any change of
//! the registered NS heartbeat resets that cap. So an NS handler that parks
//! AND bumps the heartbeat may keep both the wipe and the watchdog away.
//!
//! # What this runner does
//!
//! It registers a heartbeat, starts one ordinary `sign_userop`, and lets the
//! non-secure SysTick fire ~0.5 s into it. The handler then parks for
//! [`HOLD_MS`] (longer than the 120 s idle timeout), bumping the heartbeat
//! every [`BUMP_EVERY_MS`] unless built with `idle-hold-nobump` (the control:
//! a parked handler that does not bump must be reset by the IWDG after
//! ~30 s). After the handler returns, `main` records the outer status and the
//! unlock state, then keeps sampling `is_unlocked` while bumping the
//! heartbeat, so the run also shows when the wipe finally fires.
//!
//! # Reading the result
//!
//! No semihosting: the probe is detached for most of the run, and a BKPT
//! with no debugger escalates to a reset. Every result is a word in
//! [`IHT`], read over SWD while the core runs; the secure side is read the
//! same way (`STATE`, `HANDLER_DEPTH`, `TICKS`, `LAST_ACTIVITY`).
//! [`IHT_BOOTS`] lives in `.uninit`, so an IWDG reset shows up as a count
//! above 1 (DVT units run with `SRAM_RST=0`).

use super::{build_payload, cycles_now, systick_start, systick_stop, CYC_PER_MS, OUTER_TO, OUTER_VALUE_WEI};
use super::{PAYLOAD_BUF, SIG_BUF};
use crate::nsc_api;
use core::sync::atomic::{AtomicBool, Ordering};

/// How long the parked handler holds the outer call: past the 120 s idle
/// timeout by a margin the 1 ms secure tick cannot blur.
/// `IHT_HOLD_MS` at build time overrides it (a short hold is the control
/// that tells "parked" apart from "parked past the idle timeout").
const HOLD_MS: u64 = match option_env!("IHT_HOLD_MS") {
    Some(v) => parse_ms(v),
    None => 200_000,
};

const fn parse_ms(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v = 0u64;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "IHT_HOLD_MS must be decimal milliseconds");
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    v
}
/// Heartbeat bump period inside the park (the watcher only checks "changed").
const BUMP_EVERY_MS: u64 = 100;
/// Sampling period of `is_unlocked` after the outer call returns.
const SAMPLE_EVERY_MS: u64 = 1_000;
/// Fire this many 20 ms NS ticks into the outer call (~0.5 s).
const FIRE_AFTER_TICKS: u32 = 25;

#[cfg(not(feature = "idle-hold-nobump"))]
const BUMP: bool = true;
#[cfg(feature = "idle-hold-nobump")]
const BUMP: bool = false;

/// Report block, read over SWD. Word meanings:
/// 0 magic `0x1D1E_0013`; 1 phase (1 started, 2 parked, 3 park done,
/// 4 outer returned, 5 sampling); 2 ms parked so far; 3 heartbeat bumps;
/// 4 outer status; 5 unlocked before; 6 unlocked right after; 7 bump build;
/// 8 heartbeat registration rc; 9 ms since the outer call returned;
/// 10 last `is_unlocked` sample; 11 ms after return of the first locked
/// sample (`u32::MAX` until seen); 12 samples taken; 13 boot count copy.
#[no_mangle]
#[used]
static mut IHT: [u32; 16] = [0; 16];

/// `[magic, boots]`, kept across resets (not zeroed by the runtime).
#[no_mangle]
#[used]
#[link_section = ".uninit.IHT_BOOTS"]
static mut IHT_BOOTS: [u32; 2] = [0; 2];
const BOOTS_MAGIC: u32 = 0xB007_1310;

/// The registered NS heartbeat. Not a secret.
static mut HB: u32 = 0;

static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static DONE: AtomicBool = AtomicBool::new(false);
static mut TICKS: u32 = 0;

fn rep(i: usize, v: u32) {
    // SAFETY: `IHT` is a plain word array written by `main` and the SysTick
    // handler, never concurrently for the same index; volatile so SWD reads
    // see every update.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(IHT[i]), v) };
}

fn bump() {
    // SAFETY: `HB` is only written here and only read by the secure SysTick.
    unsafe {
        let p = core::ptr::addr_of_mut!(HB);
        core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
    }
}

/// Busy-wait `ms`, bumping the heartbeat every `BUMP_EVERY_MS` if `bump_hb`.
/// Elapsed time accumulates short DWT deltas, so the 26.8 s wrap is harmless.
fn spin(ms: u64, bump_hb: bool, mut on_ms: impl FnMut(u64)) {
    let mut prev = cycles_now();
    let mut acc: u64 = 0;
    let mut next_bump = BUMP_EVERY_MS;
    loop {
        let now = cycles_now();
        acc += u64::from(now.wrapping_sub(prev));
        prev = now;
        let el = acc / u64::from(CYC_PER_MS);
        if el >= next_bump {
            next_bump += BUMP_EVERY_MS;
            if bump_hb {
                bump();
            }
            on_ms(el);
        }
        if el >= ms {
            return;
        }
    }
}

#[cortex_m_rt::exception]
fn SysTick() {
    // SAFETY: only this handler touches `TICKS`.
    let t = unsafe {
        TICKS += 1;
        TICKS
    };
    if !IN_FLIGHT.load(Ordering::SeqCst) || DONE.load(Ordering::SeqCst) || t < FIRE_AFTER_TICKS {
        return;
    }
    DONE.store(true, Ordering::SeqCst);
    rep(1, 2);
    let mut bumps = 0u32;
    spin(HOLD_MS, BUMP, |el| {
        if BUMP {
            bumps += 1;
            rep(3, bumps);
        }
        rep(2, el as u32);
    });
    rep(1, 3);
}

#[cortex_m_rt::entry]
fn main() -> ! {
    // SAFETY: single-threaded before SysTick starts.
    let boots = unsafe {
        let b = &mut *core::ptr::addr_of_mut!(IHT_BOOTS);
        if b[0] != BOOTS_MAGIC {
            b[0] = BOOTS_MAGIC;
            b[1] = 0;
        }
        b[1] = b[1].wrapping_add(1);
        b[1]
    };
    rep(0, 0x1D1E_0013);
    rep(7, u32::from(BUMP));
    rep(11, u32::MAX);
    rep(13, boots);
    rep(8, nsc_api::register_heartbeat(core::ptr::addr_of!(HB) as u32));
    rep(5, u32::from(nsc_api::is_unlocked()));

    let mut sender = [0u8; 20];
    if nsc_api::get_wallet_address(&mut sender, 0, 0) != 0 {
        rep(1, 0xE1);
        park_forever();
    }
    // SAFETY: the SysTick handler never touches these buffers.
    let len = unsafe { build_payload(&mut PAYLOAD_BUF, &sender, &OUTER_TO, OUTER_VALUE_WEI) };
    rep(1, 1);
    systick_start();
    IN_FLIGHT.store(true, Ordering::SeqCst);
    let st = unsafe { nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF) };
    IN_FLIGHT.store(false, Ordering::SeqCst);
    systick_stop();
    rep(4, st);
    rep(6, u32::from(nsc_api::is_unlocked()));
    rep(1, 4);

    // Sample the unlock state once a second for ten minutes, bumping the
    // heartbeat so the IWDG never resets an honest idle loop.
    rep(1, 5);
    let mut samples = 0u32;
    let mut seen_locked = false;
    let mut next = SAMPLE_EVERY_MS;
    spin(600_000, true, |el| {
        rep(9, el as u32);
        if el >= next {
            next += SAMPLE_EVERY_MS;
            let u = nsc_api::is_unlocked();
            samples += 1;
            rep(10, u32::from(u));
            rep(12, samples);
            if !u && !seen_locked {
                seen_locked = true;
                rep(11, el as u32);
            }
        }
    });
    park_forever();
}

fn park_forever() -> ! {
    loop {
        spin(1_000, true, |_| {});
    }
}
