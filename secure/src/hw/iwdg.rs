//! Independent watchdog (IWDG) — USB-path hang detection.
//!
//! The USB stack runs in the **non-secure** world as a poll loop
//! (`nonsecure/src/main.rs`). A malicious or buggy host could wedge
//! that loop (e.g. an input that drives the APDU parser into an
//! infinite loop), leaving the device unresponsive with no way to
//! recover short of a power-cycle. The IWDG is the backstop: if the
//! system stops making forward progress, the watchdog resets the chip,
//! and the boot-time `reset_cause` path classifies the IWDG reset as
//! abnormal and zeroizes SRAM before re-running unlock.
//!
//! # Liveness model (why it doesn't false-fire on legit long ops)
//!
//! The IWDG is **owned + kicked by the secure world** — `init` runs in
//! secure boot, and the secure SysTick handler (1 ms cadence) calls
//! [`systick_watch_and_kick`] every tick. It keeps the watchdog fed
//! while any of three progress signals holds:
//!
//!   1. **NS heartbeat advanced, with no gateway handler busy** — NS bumps
//!      a counter (a `static mut` in NS SRAM, registered with us once at
//!      boot via [`register_ns_heartbeat`]) on every poll-loop iteration.
//!      A live NS loop keeps this advancing even when idle-polling. While a
//!      handler is busy the heartbeat is NOT a progress signal (#981): the
//!      NS thread that owns it is blocked in the veneer and cannot loop, so
//!      a change can only come from a non-secure exception that preempted
//!      the secure handler (or from an NS DMA write, or a re-registered
//!      address). On EVT-3D21 (2026-10-18, DVT row 13.10) such an exception
//!      parked inside a sign and bumped the heartbeat every 100 ms; because
//!      this signal used to be checked first and reset `BUSY_TICKS`, the
//!      busy cap below never bound and the session stayed unlocked for as
//!      long as NS liked. The stock NS image installs no exception handlers
//!      and bumps from its poll loop only (`nonsecure/src/main.rs`), so
//!      ignoring the heartbeat while busy costs a legitimate image nothing.
//!   2. **A gateway handler is busy** — `nsc::handler_is_busy()` is
//!      true whenever a CMSE veneer is mid-flight. This covers the
//!      multi-second secure operations (first-sign ~3 s, batch sign,
//!      ~2 s FW-slot erase) during which NS is blocked in the veneer
//!      and therefore NOT bumping its heartbeat. Without this signal
//!      a long legit sign would look like a hang.
//!   3. **Trusted UI is waiting for a physical button** — the narrow
//!      `timeout::TrustedUiWaitGuard` is live and the 120 s inactivity
//!      timer has not expired. This prevents the 30 s compute deadline
//!      from resetting the device in the middle of a legitimate confirm
//!      dialog. The timeout condition is load-bearing: a wedged input
//!      backend stops receiving this exception once idle, then falls back
//!      to the ordinary bounded watchdog path.
//!
//! Only when all progress signals are absent for `NS_STALL_LIMIT_TICKS`
//! consecutive ticks does SysTick stop kicking, after which the IWDG
//! hardware timeout (~2 s) resets the chip. Total NS-loop-hang
//! detection ≈ `NS_STALL_LIMIT_TICKS` (4 s) + IWDG (~2 s) ≈ 6 s.
//!
//! A secure-world deadlock with interrupts disabled stops SysTick
//! entirely → no kicks → IWDG fires directly (~2 s), independent of
//! the heartbeat logic. A secure handler that spins with interrupts enabled
//! is capped by `MAX_BUSY_TICKS`. Trusted UI temporarily suspends that compute
//! deadline only while it is actually waiting for secure physical input and
//! the independent inactivity timer remains live.
//!
//! # Secure-only register ownership
//!
//! IWDG is reached only through its **Secure alias** (`0x5000_3000`).
//! `sau::configure_gtzc` marks `GTZC1_TZSC_SECCFGR1` bit 7 Secure whenever
//! the `iwdg` feature is selected, verifies that register image, and locks
//! TZSC before non-secure boot. This source-level ownership is required by
//! forced-blind architecture, but it is not silicon evidence: issue #79 still
//! owns denial receipts for non-secure CPU and preconfigured non-secure GPDMA
//! reload attempts.
//!
//! # Feature gating
//!
//! Behind `iwdg`. **OFF for `mode-bringup` / `mode-e2e`**: a live IWDG
//! would reset the device during probe-rs breakpoints / semihosting
//! pauses. When the feature is off every entry point compiles to a
//! no-op, so call sites are safe without the flag — and crucially
//! `init` never starts the watchdog, so test builds can't self-reset.

#![allow(dead_code)]

#[cfg(feature = "iwdg")]
use crate::hw::mmio::Reg32;

// IWDG Secure alias — see module doc on the attribution contract.
#[cfg(feature = "iwdg")]
const IWDG_SECURE_ALIAS: u32 = 0x5000_3000;

#[cfg(feature = "iwdg")]
struct IwdgRegs {
    kr: Reg32,  // key register   @ 0x00 (write 0xCCCC start / 0x5555 access / 0xAAAA reload)
    pr: Reg32,  // prescaler       @ 0x04
    rlr: Reg32, // reload          @ 0x08
    sr: Reg32,  // status (PVU/RVU/WVU) @ 0x0C
}

// SAFETY: each address is a real, 4-byte-aligned IWDG MMIO register.
// Two writers exist: `init` (secure boot) and the secure SysTick
// handler (`kick` / `systick_watch_and_kick`), and SysTick is ALREADY
// live when `init` runs — so `init`'s KEY_ACCESS → PR → RLR window is
// protected by a `cortex_m::interrupt::free` critical section (F32/
// RUN-4), and every other access is a single 32-bit volatile write
// (indivisible on its own). SysTick never re-enters itself.
#[cfg(feature = "iwdg")]
const REG: IwdgRegs = unsafe {
    IwdgRegs {
        kr: Reg32::new(IWDG_SECURE_ALIAS + 0x00),
        pr: Reg32::new(IWDG_SECURE_ALIAS + 0x04),
        rlr: Reg32::new(IWDG_SECURE_ALIAS + 0x08),
        sr: Reg32::new(IWDG_SECURE_ALIAS + 0x0C),
    }
};

#[cfg(feature = "iwdg")]
const KEY_RELOAD: u32 = 0xAAAA; // refresh the down-counter ("kick")
#[cfg(feature = "iwdg")]
const KEY_START: u32 = 0xCCCC; // start IWDG (and auto-start LSI)
#[cfg(feature = "iwdg")]
const KEY_ACCESS: u32 = 0x5555; // unlock PR/RLR for writing

// Prescaler /256 (PR=6) + reload 250 → ~2 s at the nominal 32 kHz LSI.
// LSI is ±~50% so the real timeout is ~1–3 s; that imprecision is
// irrelevant because normal operation kicks every 1 ms (SysTick) —
// orders of magnitude under even the 1 s low end. The PRECISE
// false-fire threshold is the SysTick-counted `NS_STALL_LIMIT_TICKS`,
// not this coarse hardware timeout.
#[cfg(feature = "iwdg")]
const PR_DIV_256: u32 = 6;
#[cfg(feature = "iwdg")]
const RLR_2S: u32 = 250;

// 4 s of 1 ms SysTick ticks of *no progress* (neither NS heartbeat
// advancing nor a handler busy) before we stop feeding the watchdog.
// Comfortably above any NS-side loop-body stall — every loop op
// (poll / try_receive / queue_response / poll_tx) is sub-millisecond,
// and the multi-second secure crypto is covered by `handler_is_busy()`
// — so only a genuine hang reaches this.
#[cfg(feature = "iwdg")]
const NS_STALL_LIMIT_TICKS: u32 = 4000;

// rr-2 (Trezor-port): max consecutive ticks a *busy handler* alone may feed
// the watchdog. `handler_busy` legitimately holds across a bounded window —
// the longest after the last button press is one cold first sign (slot
// keygen + Type-1 + Type-2, 12-17 s measured on pq1, DVT row 1.10; a batch
// of up to `MAX_BATCH_TXS` members still produces ONE Type-2, so it is the
// same bound) — but a handler that spins forever with its `HandlerGuard` held
// would otherwise feed the IWDG forever (the hole flagged in the module doc
// above) AND suppress the 120 s idle-wipe (which shares the `handler_busy`
// gate). Set generously (~30 s at 1 kHz SysTick) above the worst legit
// continuous-busy window so a real sign never trips it, but a wedged or
// preempted-and-parked handler does. Since #981 nothing the non-secure world
// does can reset this count while a handler is busy: only the trusted-UI
// exception (secure-only, idle-bounded) and the handler going idle do.
#[cfg(feature = "iwdg")]
const MAX_BUSY_TICKS: u32 = 30_000;

// Heartbeat-watch state. Sole writer is the secure SysTick handler
// (single-threaded, non-reentrant) plus the one-time boot registration.
#[cfg(feature = "iwdg")]
static mut NS_HEARTBEAT_ADDR: u32 = 0; // 0 = NS hasn't registered yet
#[cfg(feature = "iwdg")]
static mut LAST_HEARTBEAT: u32 = 0;
#[cfg(feature = "iwdg")]
static mut STALL_TICKS: u32 = 0;
// rr-2: consecutive ticks fed on `handler_busy` alone. Reset when the
// handler goes idle or a trusted dialog is genuinely waiting — never by the
// NS heartbeat (#981).
#[cfg(feature = "iwdg")]
static mut BUSY_TICKS: u32 = 0;
// #981 diagnostic: busy ticks on which the NS heartbeat differed from the
// last value seen while no handler was busy (LAST_HEARTBEAT is frozen during
// a busy window, so after the first foreign bump every busy tick counts).
// The stock NS image cannot produce one (its only bump is in the thread-mode
// poll loop, which is blocked in the veneer), so a nonzero value means a
// non-secure exception preempted a secure handler and is feeding the
// heartbeat. Read over SWD by `tools/dvt/idle_hold.py`; it gates
// nothing. Saturating.
#[cfg(feature = "iwdg")]
static mut HB_WHILE_BUSY: u32 = 0;

/// Start the IWDG with a ~2 s timeout. Once started it CANNOT be
/// stopped (hardware property) — that's the point. Call from secure
/// boot after `setup_systick()` so SysTick is already feeding it.
#[cfg(feature = "iwdg")]
pub fn init() {
    // Freeze the IWDG counter while a debugger has the core halted
    // (DBGMCU_APB1FZR1.DBG_IWDG_STOP, bit 12). Without this, every
    // probe-rs / OpenOCD halt — breakpoint, semihosting roundtrip,
    // RTT poll, single-step — lets the LSI-clocked IWDG keep counting
    // and bite mid-debug. The bit has NO effect when no debugger is
    // attached (production), so it's safe to always set. Standard
    // practice for any IWDG-enabled firmware that's ever debugged.
    // SAFETY: single 32-bit RMW of a debug-component register
    // (DBGMCU @ 0xE0044000, APB1FZR1 @ +0x08), accessible from secure.
    unsafe {
        const DBGMCU_APB1FZR1: *mut u32 = (0xE004_4000u32 + 0x08) as *mut u32;
        const DBG_IWDG_STOP: u32 = 1 << 12;
        let v = core::ptr::read_volatile(DBGMCU_APB1FZR1);
        core::ptr::write_volatile(DBGMCU_APB1FZR1, v | DBG_IWDG_STOP);
    }

    // Start first (also auto-starts the LSI clock), then unlock +
    // program prescaler/reload, wait for the LSI-domain update to
    // settle, and take the first explicit reload. The default 0.5 s
    // timeout (PR=/4, RLR=0xFFF) gives ample margin to finish this
    // config before the first bite.
    REG.kr.write(KEY_START);
    // F32/RUN-4: the KEY_ACCESS → PR → RLR sequence must be atomic
    // w.r.t. SysTick. `init` runs with SysTick ALREADY live (SysTick
    // starts at boot; `iwdg::init` runs much later), and the SysTick
    // boot-grace path (`NS_HEARTBEAT_ADDR == 0`) writes `KR=0xAAAA`
    // every tick — a kick landing between KEY_ACCESS and the PR/RLR
    // writes revokes PR/RLR write access (a non-0x5555 KR write
    // re-locks the window) and the new prescaler/reload are silently
    // dropped: the watchdog keeps its reset-default ~0.5 s timeout
    // while every liveness budget assumes ~2 s. The critical section
    // makes the sequence indivisible. The SR-settle spin and the final
    // reload stay OUTSIDE it — a stuck LSI-domain update must not wedge
    // the system with interrupts masked, and the reload needs no access
    // unlock. A kick during the settle window is harmless: PR/RLR were
    // already written; only their LSI-domain propagation is in flight.
    cortex_m::interrupt::free(|_| {
        REG.kr.write(KEY_ACCESS);
        REG.pr.write(PR_DIV_256);
        REG.rlr.write(RLR_2S);
    });
    // Wait for PVU | RVU | WVU (SR bits 2:0) to clear — the new
    // prescaler/reload have propagated to the LSI clock domain.
    while REG.sr.read() & 0b111 != 0 {
        core::hint::spin_loop();
    }
    REG.kr.write(KEY_RELOAD);
}

/// Refresh the watchdog counter. This is deliberately private: after the one
/// direct initialization reload, every runtime call site is dominated by the
/// verified tick-health/CFI gate in [`systick_watch_and_kick`].
#[cfg(feature = "iwdg")]
#[inline]
fn kick() {
    REG.kr.write(KEY_RELOAD);
}

/// Register the NS heartbeat counter address (called once, via a CMSE
/// veneer, from NS boot). Returns `true` if the address validated as a
/// 4-byte-aligned location inside NS SRAM and was stored.
#[cfg(feature = "iwdg")]
pub fn register_ns_heartbeat(addr: u32) -> bool {
    use sphincs_tz_shared::{NS_SRAM_BASE, NS_SRAM_END};
    if addr & 0x3 != 0 || addr < NS_SRAM_BASE || addr.saturating_add(4) > NS_SRAM_END {
        return false;
    }
    // SAFETY: single-threaded boot-time registration; SysTick (the only
    // other accessor) reads this with a volatile load.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(NS_HEARTBEAT_ADDR), addr);
    }
    true
}

/// Called from the secure SysTick handler every ~1 ms. Feeds the IWDG
/// while the system is making progress; stops feeding after
/// `NS_STALL_LIMIT_TICKS` ticks of no progress so the watchdog resets a
/// hung device. The secure-state booleans are passed in rather than reaching
/// across modules from inside the ISR. `trusted_ui_waiting` is accepted as
/// progress only while `idle_timed_out == false`; it therefore cannot turn a
/// leaked UI guard into an unbounded watchdog feed.
#[cfg(feature = "iwdg")]
pub fn systick_watch_and_kick(
    tick_health: u32,
    tick_cfi: u32,
    handler_busy: bool,
    trusted_ui_waiting: bool,
    idle_timed_out: bool,
) {
    // This guard dominates every runtime reload, including boot grace. A
    // skipped tick helper, invalid/frozen pair, skipped completion publish, or
    // mismatched CFI word therefore cannot feed the independent watchdog.
    if tick_health != crate::fi::OK_SENTINEL || tick_cfi != crate::timeout::TICK_CFI_COMPLETE {
        return;
    }

    // SAFETY: SysTick is the sole runtime writer of these statics and
    // does not re-enter itself; the boot registration of
    // `NS_HEARTBEAT_ADDR` has completed by the time NS is running.
    unsafe {
        let addr = core::ptr::read_volatile(core::ptr::addr_of!(NS_HEARTBEAT_ADDR));
        if addr == 0 {
            // Boot grace: NS hasn't registered its heartbeat yet. Keep
            // the watchdog fed so the boot window doesn't trip it.
            kick();
            return;
        }
        // Read the NS heartbeat (secure reading an NS SRAM address —
        // permitted; the address was range-validated at registration).
        let hb = core::ptr::read_volatile(addr as *const u32);
        let last = core::ptr::read_volatile(core::ptr::addr_of!(LAST_HEARTBEAT));

        if trusted_ui_waiting && !idle_timed_out {
            // A secure confirmation dialog is making intentional progress by
            // waiting for a human. Reset both machine-stall counters so the
            // 30 s compute deadline cannot false-fire during the documented
            // 120 s UI window. Only real secure UI code can hold the guard,
            // and it does not reset LAST_ACTIVITY; once the inactivity timer
            // expires this branch becomes unreachable and a wedged input
            // backend is reset by the normal handler/NS bound below.
            // (The SysTick idle-wipe deferral cap, `timeout::wipe_defer_step`,
            // bounds the case where the dialog itself was preempted and
            // parked by a non-secure exception — #981.)
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            kick();
        } else if handler_busy {
            // A secure veneer is mid-flight — NS is blocked in the gateway so
            // its heartbeat can't advance. Legitimate for a BOUNDED window,
            // but rr-2: cap it, or a wedged handler holding its `HandlerGuard`
            // feeds the watchdog forever. `handler_busy` is NOT an NS stall,
            // so reset STALL_TICKS; count busy ticks separately.
            //
            // #981: this branch is checked BEFORE the heartbeat. A heartbeat
            // change here is not progress (module doc, signal 1) and must not
            // reset BUSY_TICKS; LAST_HEARTBEAT is deliberately left alone so
            // the first tick after the handler returns sees ordinary NS
            // progress. The change is only counted, as evidence.
            if hb != last {
                let n = core::ptr::read_volatile(core::ptr::addr_of!(HB_WHILE_BUSY)).saturating_add(1);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(HB_WHILE_BUSY), n);
            }
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            let b = core::ptr::read_volatile(core::ptr::addr_of!(BUSY_TICKS)).saturating_add(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), b);
            if b < MAX_BUSY_TICKS {
                kick();
            } else if b == MAX_BUSY_TICKS {
                secure_log!(
                    "[S][iwdg] BUSY LIMIT hit (b={}) — handler wedged busy, stopping kicks, IWDG will fire",
                    b
                );
            }
            // else: busy past the cap → stop feeding → IWDG fires.
        } else if hb != last {
            // Genuine NS forward progress (NS looped, no handler in flight)
            // — reset both timers.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(LAST_HEARTBEAT), hb);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            kick();
        } else {
            // No NS progress and no busy handler → NS-loop stall.
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BUSY_TICKS), 0);
            let s = core::ptr::read_volatile(core::ptr::addr_of!(STALL_TICKS)).saturating_add(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(STALL_TICKS), s);
            if s < NS_STALL_LIMIT_TICKS {
                // Still within the grace window — keep feeding.
                kick();
            } else if s == NS_STALL_LIMIT_TICKS {
                // DIAGNOSTIC: about to stop feeding — IWDG will reset
                // in ~2 s. Logged once at the threshold crossing so we
                // can tell a real stall from flaky USB. hb/last captured
                // for the post-mortem.
                secure_log!(
                    "[S][iwdg] STALL LIMIT hit (s={}) hb=0x{:08x} last=0x{:08x} — stopping kicks, IWDG will fire",
                    s, hb, last
                );
            }
            // else: stalled past the limit → stop feeding → IWDG fires.
        }
    }
}

// ---------------------------------------------------------------------------
// No-op stubs when the feature is off. `init` deliberately does NOT
// start the watchdog, so a non-`iwdg` build (every test build) can
// never self-reset.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "iwdg"))]
pub fn init() {}
#[cfg(not(feature = "iwdg"))]
pub fn register_ns_heartbeat(_addr: u32) -> bool {
    false
}
#[cfg(not(feature = "iwdg"))]
pub fn systick_watch_and_kick(
    tick_health: u32,
    tick_cfi: u32,
    _handler_busy: bool,
    _trusted_ui_waiting: bool,
    _idle_timed_out: bool,
) {
    // Keep the same mandatory API and fail-closed health gate in test/QEMU
    // variants. These builds have no independent watchdog and therefore do
    // not constitute forced-blind production authority.
    if tick_health != crate::fi::OK_SENTINEL || tick_cfi != crate::timeout::TICK_CFI_COMPLETE {
        return;
    }
}
