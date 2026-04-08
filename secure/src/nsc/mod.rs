//! Secure gateway with trusted-UI sign confirmation.
//!
//! Today this runs as a SysTick-polled shared-memory mailbox (a QEMU
//! workaround for the broken SG instruction check on mps2-an505). On real
//! STM32U585 hardware the same dispatch logic will be invoked from CMSE
//! `cmse-nonsecure-entry` veneers — the only difference is who pulls the
//! trigger (poll vs direct call).
//!
//! Gateway commands (see `sphincs_tz_shared::CMD_*`):
//!
//! | ID | Name            | NS → S args                              | S behavior |
//! |----|-----------------|------------------------------------------|------------|
//! | 1  | GET_REMAINING   | —                                        | reads chip; returns u32 |
//! | 2  | REQUEST_UNLOCK  | —                                        | secure UI prompts for PIN |
//! | 3  | GET_PUBKEY      | out_ptr, out_len                         | reads slot 2 |
//! | 4  | SIGN            | unsigned_tx_ptr, sig_out_ptr, total_len  | parse → confirm → sign |
//! | 5  | CLEAR_SIGN      | payload_ptr, sig_out_ptr, total_len      | ZK verify → display → sign |
//! | 6  | CLEAR_SIGN_MSG  | payload_ptr, sig_out_ptr, total_len      | ZK verify → EIP-712 → sign |
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
//!   * [`cmd_get_remaining`], [`cmd_request_unlock`], [`cmd_get_pubkey`],
//!     [`cmd_sign`], [`cmd_clear_sign`], [`cmd_clear_sign_msg`].

mod cmd_clear_sign;
mod cmd_clear_sign_msg;
mod cmd_get_pubkey;
mod cmd_get_remaining;
mod cmd_request_unlock;
mod cmd_sign;
mod ptr_validate;
mod sign_and_emit;
mod state;

use sphincs_tz_shared::{
    NscStatus, CMD_CLEAR_SIGN, CMD_CLEAR_SIGN_MSG, CMD_GET_PUBKEY, CMD_GET_REMAINING, CMD_NONE,
    CMD_REQUEST_UNLOCK, CMD_SIGN, SHARED_MAILBOX_BASE,
};

// ---------------------------------------------------------------------------
// Shared-memory mailbox layout (NS SRAM, derived from shared crate constants)
// ---------------------------------------------------------------------------

const SHARED_CMD: *mut u32 = SHARED_MAILBOX_BASE as *mut u32;
const SHARED_ARG0: *mut u32 = (SHARED_MAILBOX_BASE + 4) as *mut u32;
const SHARED_ARG1: *mut u32 = (SHARED_MAILBOX_BASE + 8) as *mut u32;
const SHARED_ARG2: *mut u32 = (SHARED_MAILBOX_BASE + 12) as *mut u32;
const SHARED_RESULT: *mut u32 = (SHARED_MAILBOX_BASE + 16) as *mut u32;
const SHARED_DONE: *mut u32 = (SHARED_MAILBOX_BASE + 20) as *mut u32;

/// Snapshot of shared memory arguments, read atomically in [`poll_gateway`]
/// before dispatch() runs, to prevent TOCTOU races where NS modifies args
/// between the secure-side validation and use.
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

/// Test-only helper: stamp the secure-side master secret and mark the
/// device unlocked directly, skipping the interactive PIN dialog. Used
/// by the `e2e-test` boot path; compiled out of every other build.
#[cfg(feature = "e2e-test")]
pub fn set_e2e_unlocked(master: [u8; 32]) {
    state::with_state(|s| s.mark_unlocked(master));
}

/// Zeroize all sensitive global state. Called from the panic handler,
/// the inactivity wipe, and the cancel/idle-wipe branches of every
/// interactive dialog.
pub fn zeroize_sensitive_state() {
    state::with_state(|s| s.zeroize_sensitive());
}

/// Initialize the shared-memory mailbox by clearing CMD/RESULT/DONE.
/// Must be called once during boot before [`poll_gateway`].
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

/// Route a single gateway command to its handler. All commands run with
/// exclusive access to `SecureState` for the duration of dispatch (see
/// the non-reentrant invariant on [`poll_gateway`]).
unsafe fn dispatch(cmd: u32, args: &GatewayArgs) -> u32 {
    match cmd {
        CMD_GET_REMAINING => cmd_get_remaining::run(),
        CMD_REQUEST_UNLOCK => cmd_request_unlock::run(),
        CMD_GET_PUBKEY => cmd_get_pubkey::run(args),
        CMD_SIGN => cmd_sign::run(args),
        CMD_CLEAR_SIGN => cmd_clear_sign::run(args),
        CMD_CLEAR_SIGN_MSG => cmd_clear_sign_msg::run(args),
        _ => NscStatus::InternalError as u32,
    }
}

// ---------------------------------------------------------------------------
// CMSE veneer kept for real hardware (bypasses QEMU's broken SG check)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32 {
    state::peek_state(|s| s.remaining_attempts as u32)
}
