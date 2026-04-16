//! Secure gateway with trusted-UI sign confirmation.
//!
//! Two transports, selected at compile time by the `stm32u585` feature:
//!
//!   * **QEMU mps2-an505** (`not(feature = "stm32u585")`): SysTick-polled
//!     shared-memory mailbox. This is the workaround for QEMU 8.2.2's
//!     broken SG instruction check — `poll_gateway()` runs from the
//!     SysTick handler, reads `CMD`/`ARG0..2` out of NS SRAM, runs
//!     [`dispatch`], writes `RESULT`, and raises `DONE`.
//!   * **Real STM32U585** (`feature = "stm32u585"`): proper ARMv8-M
//!     CMSE `cmse-nonsecure-entry` veneers. The `--cmse-implib` linker
//!     pass emits SG stubs for every `nsc_*` entry point below into
//!     `veneers.o`; the non-secure crate links against that implib and
//!     calls them as regular `extern "C"` functions. There is no
//!     mailbox and no SysTick poll — NS issues `BLXNS` → SG →
//!     secure-state-handler → `BXNS` synchronously. The `cmd_*`
//!     handlers are shared across both transports; the only thing that
//!     changes is who pulls the trigger.
//!
//! Gateway commands (see `sphincs_tz_shared::CMD_*`):
//!
//! | ID | Name            | NS → S args                              | S behavior |
//! |----|-----------------|------------------------------------------|------------|
//! | 1  | GET_REMAINING   | —                                        | reads chip; returns u32 |
//! | 2  | REQUEST_UNLOCK  | —                                        | secure UI prompts for PIN |
//! | 3  | GET_PUBKEY      | out_ptr, out_len                         | reads slot 2 |
//! | 5  | CLEAR_SIGN      | payload_ptr, sig_out_ptr, total_len      | ZK verify → display → UserOp sign |
//! | 6  | CLEAR_SIGN_MSG  | payload_ptr, sig_out_ptr, total_len      | ZK verify → EIP-712 → sign |
//! | 7  | SIGN_USEROP     | payload_ptr, sig_out_ptr, total_len      | parse AA + inner tx → confirm → UserOp sign |
//!
//! ## Layout
//!
//! This module is split along command boundaries so each `cmd_*` handler
//! lives in its own file and the shared plumbing (state, pointer
//! validation, the decrypt→derive→sign tail) lives in its own. Adding a
//! new gateway command means creating a new `cmd_*.rs` submodule, adding
//! a match arm in [`dispatch`], and wiring up a new `CMD_*` constant in
//! `sphincs_tz_shared`. **No other file in this module needs to change.**
//!
//!   * [`state`]         — single `SecureState` singleton + `with_state`
//!     closure accessors. The one and only place `static mut` lives.
//!   * [`ptr_validate`]  — NS SRAM/flash pointer + length validators.
//!   * [`sign_and_emit`] — shared "decrypt entropy → derive SK → hedged
//!     SLH-DSA sign → write to NS" tail used by every signing command.
//!   * [`userop_tail`]  — shared "reconstruct execute() callData →
//!     compute userOpHash → decrypt_and_sign" tail used by every
//!     UserOp signing command.
//!   * [`cmd_get_remaining`], [`cmd_request_unlock`], [`cmd_get_pubkey`],
//!     [`cmd_clear_sign`], [`cmd_clear_sign_msg`], [`cmd_sign_userop`].

mod cmd_get_jardin_slot_info;
mod cmd_get_remaining;
mod cmd_is_unlocked;
mod cmd_lock;
mod cmd_request_unlock;
mod cmd_sign_userop;
pub(crate) mod jardin_flash;
mod ptr_validate;
mod state;

// HIGH-2 fix: refuse to build hardware images that also enable any of
// the dev-only features. `e2e-test` exposes `set_e2e_unlocked` with no
// PIN check; `debug-log` and `ui-semihosting` leak secure-world state
// via the semihosting channel; `ui-mirror` streams the OLED over RTT;
// `mock-se` substitutes an in-SRAM fake SE. Any of these enabled on a
// `stm32u585` release build is a ship-blocker.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    any(
        feature = "e2e-test",
        feature = "debug-log",
        feature = "ui-semihosting",
        feature = "ui-mirror",
        feature = "mock-se",
    )
))]
compile_error!(
    "Hardware release builds (stm32u585 + !debug_assertions) must not enable \
     e2e-test / debug-log / ui-semihosting / ui-mirror / mock-se. These \
     features either bypass PIN checks or leak secure-world state."
);

#[cfg(not(feature = "stm32u585"))]
use sphincs_tz_shared::{
    NscStatus, CMD_GET_JARDIN_SLOT_INFO, CMD_GET_REMAINING, CMD_IS_UNLOCKED, CMD_LOCK, CMD_NONE,
    CMD_REQUEST_UNLOCK, CMD_SIGN_USEROP, SHARED_MAILBOX_BASE,
};

// ---------------------------------------------------------------------------
// Shared-memory mailbox layout (QEMU NS SRAM, derived from shared crate
// constants). Only used on the QEMU transport; the STM32U585 build uses
// CMSE veneers and never touches the mailbox.
// ---------------------------------------------------------------------------

#[cfg(not(feature = "stm32u585"))]
const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_RESULT: *mut u32 = (SHARED_MAILBOX_BASE + 16) as *mut u32;
#[cfg(not(feature = "stm32u585"))]
const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

/// Arguments handed to a `cmd_*` handler. On the QEMU transport these
/// are read out of the shared mailbox in [`poll_gateway`] before
/// dispatch runs (a TOCTOU snapshot so NS can't race the validator).
/// On the STM32U585 CMSE transport they're just the three `u32`
/// register arguments of the `nsc_*` veneer wrapped into a struct so
/// the shared `cmd_*::run` bodies can stay identical across transports.
pub(super) struct GatewayArgs {
    pub(super) arg0: u32,
    pub(super) arg1: u32,
    pub(super) arg2: u32,
}

// ---------------------------------------------------------------------------
// Public API consumed by `secure/src/main.rs`
// ---------------------------------------------------------------------------

/// Whether the device is currently unlocked (PIN verified this session).
pub fn is_unlocked() -> bool {
    state::peek_state(|s| s.pin_verified)
}

/// HIGH-7 guard: depth counter incremented on handler entry,
/// decremented on exit. SysTick refuses to wipe when depth > 0 so
/// a long-running signing handler that holds stack-local copies of
/// secrets can't have the BSS copy zeroed out from underneath it
/// (which would leave the stack copies disagreeing with the state
/// the user just had wiped — a classic aliasing-under-ISR bug).
///
/// Stored as a plain `static mut u32` with volatile access. We do
/// not need atomicity because Cortex-M33 single-core execution is
/// strictly linear outside ISRs, and SysTick reads the value with a
/// `read_volatile` + comparison that is itself atomic on 32-bit
/// aligned loads.
static mut HANDLER_DEPTH: u32 = 0;

/// Guard type: increment on construction, decrement on drop.
pub(crate) struct HandlerGuard;

impl HandlerGuard {
    /// RAII guard — call at the top of every long-running gateway
    /// handler (sign, request_unlock). Drop at function exit.
    pub(crate) fn enter() -> Self {
        // SAFETY: single-threaded outside ISRs; we only need the
        // write to be visible before SysTick can fire again.
        unsafe {
            let d = core::ptr::read_volatile(core::ptr::addr_of!(HANDLER_DEPTH));
            core::ptr::write_volatile(core::ptr::addr_of_mut!(HANDLER_DEPTH), d + 1);
        }
        HandlerGuard
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        unsafe {
            let d = core::ptr::read_volatile(core::ptr::addr_of!(HANDLER_DEPTH));
            let nd = d.saturating_sub(1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(HANDLER_DEPTH), nd);
        }
    }
}

/// Read the current handler-busy depth from a SysTick handler.
pub fn handler_is_busy() -> bool {
    // SAFETY: 32-bit aligned volatile load is atomic on Cortex-M33.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(HANDLER_DEPTH)) > 0 }
}

/// Test-only helper: stamp the secure-side master secret and mark the
/// device unlocked directly, skipping the interactive PIN dialog. Used
/// by the `e2e-test` boot path; compiled out of every other build.
#[cfg(feature = "e2e-test")]
pub fn set_e2e_unlocked(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Set the gateway to "unlocked" state with the given master secret.
/// Used by the first-boot wizard to auto-unlock after provisioning.
pub fn unlock_with_master(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Zeroize all sensitive global state. Called from the panic handler,
/// the inactivity wipe, and the cancel/idle-wipe branches of every
/// interactive dialog.
pub fn zeroize_sensitive_state() {
    state::with_state(|s| s.zeroize_sensitive());
    unsafe {
        use crate::secure_element::WalletStore;
        (&mut *core::ptr::addr_of_mut!(crate::SE)).zeroize_caches();
    }
}

/// Initialize the shared-memory mailbox by clearing CMD/RESULT/DONE.
/// Must be called once during boot before [`poll_gateway`]. QEMU-only;
/// the STM32U585 CMSE path has no mailbox and no boot-time init.
#[cfg(not(feature = "stm32u585"))]
pub fn init_gateway() {
    unsafe {
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
        core::ptr::write_volatile(SHARED_RESULT, 0);
        core::ptr::write_volatile(SHARED_DONE, 0);
    }
}

/// Poll the mailbox once and, if a command is pending, dispatch it to
/// the right `cmd_*` handler, write the result word, raise DONE, and
/// clear CMD. The dispatch runs to completion without yielding — the
/// single-threaded invariant the whole state/sign machinery relies on.
/// QEMU-only; never called on the STM32U585 CMSE path.
#[cfg(not(feature = "stm32u585"))]
pub fn poll_gateway() {
    unsafe {
        let cmd = core::ptr::read_volatile(SHARED_CMD);
        if cmd == CMD_NONE {
            return;
        }

        let args = GatewayArgs {
            arg0: core::ptr::read_volatile(SHARED_ARG0),
            arg1: core::ptr::read_volatile(SHARED_ARG1),
            arg2: core::ptr::read_volatile(SHARED_ARG2),
        };

        let result = dispatch(cmd, &args);

        core::ptr::write_volatile(SHARED_RESULT, result);
        // Order matters: write RESULT before DONE so NS can't see DONE=1
        // with stale RESULT. Then clear CMD last so NS can issue another.
        core::ptr::write_volatile(SHARED_DONE, 1);
        core::ptr::write_volatile(SHARED_CMD, CMD_NONE);
    }
}

/// Route a single mailbox command to its handler. All commands run with
/// exclusive access to `SecureState` for the duration of dispatch (see
/// the non-reentrant invariant on [`poll_gateway`]).
#[cfg(not(feature = "stm32u585"))]
unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining::run(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock::run(),
        CMD_SIGN_USEROP => cmd_sign_userop::run(args),
        CMD_IS_UNLOCKED => cmd_is_unlocked::run(),
        CMD_LOCK => cmd_lock::run(),
        CMD_GET_JARDIN_SLOT_INFO => cmd_get_jardin_slot_info::run(args),
        _ => NscStatus::InternalError as u32,
    }
}

// ---------------------------------------------------------------------------
// CMSE veneers — STM32U585 hardware transport
// ---------------------------------------------------------------------------
//
// Each function below is an ARMv8-M Security Extension entry point. The
// linker's `--cmse-implib` pass emits an SG stub for every one into
// `veneers.o`; that implib gets linked into the non-secure world, so NS
// resolves a normal `extern "C"` symbol at the stub address and calls it
// with `BLXNS`. The stub issues `SG`, switches to secure state, clears
// caller-saved registers, and transfers control here. On return the
// compiler emits `BXNS` back to NS.
//
// The bodies are intentionally thin: each one constructs a `GatewayArgs`
// snapshot and delegates straight to the same `cmd_*::run` handler the
// QEMU `dispatch()` path uses, so handler semantics stay identical
// across transports.

/// CMD_GET_REMAINING — returns the remaining PIN attempts.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    unsafe { cmd_get_remaining::run() }
}

/// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, never crosses NS.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32 {
    unsafe { cmd_request_unlock::run() }
}

/// CMD_SIGN_USEROP — unified JARDÍN Type 1 / Type 2 sign command.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    unsafe { cmd_sign_userop::run(&args) }
}

/// CMD_IS_UNLOCKED — return 1 if unlocked, 0 if locked.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_is_unlocked() -> u32 {
    unsafe { cmd_is_unlocked::run() }
}

/// CMD_LOCK — zeroize secrets and lock the device.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_lock() -> u32 {
    unsafe { cmd_lock::run() }
}

/// CMD_GET_JARDIN_SLOT_INFO — query JARDIN slot state (from flash).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_jardin_slot_info(
    payload_ptr: u32,
    out_ptr: u32,
    out_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: payload_ptr, arg1: out_ptr, arg2: out_len };
    unsafe { cmd_get_jardin_slot_info::run(&args) }
}
