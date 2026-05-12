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
//!   * [`cmd_get_remaining`], [`cmd_request_unlock`], [`cmd_sign_userop`].

mod cmd_get_init_code;
mod cmd_get_remaining;
mod cmd_get_wallet_address;
mod cmd_is_unlocked;
mod cmd_lock;
mod cmd_offchain_status;
mod cmd_offchain_sync;
mod cmd_request_unlock;
mod cmd_sign_offchain;
mod cmd_sign_userop;
mod cmd_sign_userop_batch;
#[cfg(feature = "e2e-test")]
mod cmd_test_pin_lockout;

// Firmware-update commands. Only built for the STM32U585 target
// because they depend on the bank-2 flash / OTP primitives that the
// QEMU build doesn't model.
#[cfg(feature = "stm32u585")]
mod cmd_fw_abort;
#[cfg(feature = "stm32u585")]
mod cmd_fw_begin;
#[cfg(feature = "stm32u585")]
mod cmd_fw_chunk;
#[cfg(feature = "stm32u585")]
mod cmd_fw_commit;
#[cfg(feature = "stm32u585")]
mod cmd_fw_status;

mod ns_ptr;
mod ptr_validate;
mod state;
mod trailer;

// HIGH-2 fix: refuse to build hardware images that also enable any of
// the dev-only features. `debug-log` and `ui-semihosting` leak secure-
// world state via the semihosting channel; `ui-mirror` streams the OLED
// over RTT; `ui-capture` emits per-frame SHA-256 fingerprints over the
// secure-log channel; `mock-se` substitutes an in-SRAM fake SE; the rest
// each replace some part of the production trust model with a dev-only
// shortcut. Any of these on a `stm32u585` release build is a ship-blocker.
//
// Hardware test images opt in by also enabling `e2e-test` (which exposes
// `set_e2e_unlocked` so the automated harness never needs to drive the
// PIN UI). `e2e-test` is the unambiguous "not-shippable" marker, so when
// it's on we permit the other dev features needed to drive the tests
// (`make e2e-hw`, `make test-key-speed`). CI must still gate shipped
// firmware on `e2e-test` being OFF.
//
// Reference: `/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`
// Phase 2.
#[cfg(all(
    feature = "stm32u585",
    not(debug_assertions),
    not(feature = "e2e-test"),
    not(feature = "dev-testkey"),
    any(
        feature = "debug-log",
        feature = "ui-semihosting",
        feature = "ui-mirror",
        feature = "ui-capture",
        feature = "mock-se",
        feature = "otp-hardcoded-master-key",
        feature = "saes-self-test",
        feature = "uart-console",
        feature = "boot-pulse",
        feature = "bhk-hardcoded-master-key",
        feature = "se050-rotate-scp03",
    )
))]
compile_error!(
    "Hardware release builds (stm32u585 + !debug_assertions) must not enable \
     debug-log / ui-semihosting / ui-mirror / ui-capture / mock-se / \
     otp-hardcoded-master-key / bhk-hardcoded-master-key / saes-self-test / \
     uart-console / boot-pulse / se050-rotate-scp03. These features leak \
     secure-world state, replace the SE with a mock, replace the per-device \
     OTP master key or BHK with a shared compile-time constant, halt the \
     boot flow after a diagnostic, stream diagnostic bytes on PA9 UART, \
     pulse PE13 with boot-progress markers, or perform a one-shot \
     irreversible SCP03 key-rotation ceremony then halt. Hardware test \
     images may opt in by also enabling `e2e-test` (auto-provisioning, \
     non-interactive) or `dev-testkey` (interactive UI, OTP substituted \
     with a compile-time constant)."
);

// Dedicated guard: `otp-hardcoded-master-key` + `optiga-lock-operational` is
// a specifically catastrophic combination. The lock-operational feature
// commits the E140 LcsO=Operational bump, which is hardware-irreversible;
// the hardcoded-master-key feature makes the PBS derivation a compile-time
// constant shared by every device built with the feature. Combining them
// would lock a chip to a PBS that is identical across every dev board —
// effectively publishing the Shielded Connection key. Refuse to build.
#[cfg(all(
    feature = "otp-hardcoded-master-key",
    feature = "optiga-lock-operational",
))]
compile_error!(
    "otp-hardcoded-master-key and optiga-lock-operational are mutually \
     exclusive. Enabling both would bump E140 LcsO=Operational (irreversible) \
     against a PBS derived from a shared compile-time constant, effectively \
     publishing the Shielded Connection pairing secret."
);

// ---------------------------------------------------------------------------
// UI-axis mutual exclusivity (Phase 2)
//
// `ui-semihosting`, `ui-oled`, and `ui-noop` are mutually exclusive UI
// *backends* — exactly one provides the `Display` and `Input` types that
// `secure/src/ui/mod.rs` re-exports. The `ui-mirror` flag sits on top of
// `ui-oled` (it implies it) and `ui-capture` sits on top of any backend
// (it emits a SHA-256 hash of every flushed frame as a side effect), so
// those two compose with the backend axis rather than competing with it.
//
// Combining two backends compiles today (the first cfg-match wins
// silently), which is footgun-shaped. This fence makes "two backends"
// a build error.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "ui-semihosting", feature = "ui-oled"))]
compile_error!(
    "UI backends `ui-semihosting` and `ui-oled` are mutually exclusive. \
     Pick exactly one. The Makefile recipes set the right combination; \
     a manual `cargo build -p secure --features ...` must also pick one."
);

#[cfg(all(feature = "ui-semihosting", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-semihosting` and `ui-noop` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "ui-oled", feature = "ui-noop"))]
compile_error!(
    "UI backends `ui-oled` and `ui-noop` are mutually exclusive. \
     Pick exactly one."
);

// At least one UI backend must be selected when targeting actual hardware
// or QEMU. (Pure `cargo test -p sphincs-tz-secure --tests` builds run on
// the host with neither stm32u585 nor any UI backend — those are exempt
// because they exercise pure-logic modules only.)
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "ui-semihosting",
        feature = "ui-oled",
        feature = "ui-noop",
    ))
))]
compile_error!(
    "Exactly one UI backend must be selected: `ui-semihosting`, `ui-oled`, \
     or `ui-noop`. (`ui-mirror` implies `ui-oled`; `ui-capture` composes with \
     any backend.)"
);

// ---------------------------------------------------------------------------
// Secure-element-axis mutual exclusivity (Phase 2)
//
// `dual-se` is the explicit "both production SEs simultaneously" build,
// implemented as `dual-se = ["optiga-trust-m", "se050"]`. Outside of
// `dual-se`, exactly one of {mock-se, tropic01-se, se050, optiga-trust-m}
// must be selected.
//
// The selection is done in `secure/src/main.rs` today by a chain of
// `#[cfg(all(feature = "mock-se", not(feature = "se050"), ...))]` blocks
// (negative-condition voting) — i.e., simultaneous selection compiles
// silently with a "first match wins" semantics. Make it loud here.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "mock-se", feature = "tropic01-se"))]
compile_error!(
    "Secure-element backends `mock-se` and `tropic01-se` are mutually \
     exclusive. Pick exactly one."
);

#[cfg(all(feature = "mock-se", feature = "se050"))]
compile_error!(
    "Secure-element backends `mock-se` and `se050` are mutually exclusive. \
     Pick exactly one."
);

#[cfg(all(feature = "mock-se", feature = "optiga-trust-m"))]
compile_error!(
    "Secure-element backends `mock-se` and `optiga-trust-m` are mutually \
     exclusive. Pick exactly one. (Note: `dual-se` implies both `optiga-trust-m` \
     and `se050`, so combining `mock-se` with `dual-se` is also forbidden.)"
);

#[cfg(all(feature = "tropic01-se", feature = "se050"))]
compile_error!(
    "Secure-element backends `tropic01-se` and `se050` are mutually exclusive. \
     `tropic01-se` is a standalone-only backend; for two-SE builds use `dual-se`."
);

#[cfg(all(feature = "tropic01-se", feature = "optiga-trust-m"))]
compile_error!(
    "Secure-element backends `tropic01-se` and `optiga-trust-m` are mutually \
     exclusive. `tropic01-se` is a standalone-only backend; for two-SE builds \
     use `dual-se`."
);

// At least one SE backend must be selected when targeting hardware or QEMU.
#[cfg(all(
    not(test),
    target_arch = "arm",
    not(any(
        feature = "mock-se",
        feature = "tropic01-se",
        feature = "se050",
        feature = "optiga-trust-m",
        feature = "dual-se",
    ))
))]
compile_error!(
    "Exactly one secure-element backend must be selected: `mock-se`, \
     `tropic01-se`, `se050`, `optiga-trust-m`, or `dual-se`."
);

#[cfg(not(feature = "stm32u585"))]
use sphincs_tz_shared::{
    NscStatus, CMD_GET_INIT_CODE, CMD_GET_REMAINING, CMD_GET_WALLET_ADDRESS, CMD_IS_UNLOCKED,
    CMD_LOCK, CMD_NONE, CMD_OFFCHAIN_STATUS, CMD_OFFCHAIN_SYNC, CMD_REQUEST_UNLOCK,
    CMD_SIGN_OFFCHAIN, CMD_SIGN_USEROP, CMD_SIGN_USEROP_BATCH, SHARED_MAILBOX_BASE,
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
/// Stored as `AtomicU32` so the entry-side `fetch_add(1)` is a
/// single LDREX/STREX RMW. An earlier plain-`static mut` version had
/// a tiny but real race window between the read of the old value
/// and the write of `+1` where SysTick could observe `depth == 0`,
/// run idle-wipe, then resume — leaving the handler operating on
/// wiped state. The wipe is fail-safe (the handler bails out at the
/// pin-verified check) but the race violates the docstring promise
/// that "SysTick refuses to wipe when depth > 0".
static HANDLER_DEPTH: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Guard type: increment on construction, decrement on drop.
pub(crate) struct HandlerGuard;

impl HandlerGuard {
    /// RAII guard — call at the top of every long-running gateway
    /// handler (sign, request_unlock). Drop at function exit.
    pub(crate) fn enter() -> Self {
        HANDLER_DEPTH.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        HandlerGuard
    }
}

impl Drop for HandlerGuard {
    fn drop(&mut self) {
        // Saturating decrement via CAS loop. `fetch_sub` would
        // underflow if Drop ever runs more times than `enter`
        // (cannot happen in safe Rust, but stays conservative).
        use core::sync::atomic::Ordering;
        let mut cur = HANDLER_DEPTH.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match HANDLER_DEPTH.compare_exchange_weak(
                cur, next, Ordering::SeqCst, Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

/// Read the current handler-busy depth from a SysTick handler.
pub fn handler_is_busy() -> bool {
    HANDLER_DEPTH.load(core::sync::atomic::Ordering::SeqCst) > 0
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

/// Gated unlock — every PIN verify MUST go through this.
///
/// Wraps the raw `WalletStore::unlock` with the MCU-side attempt
/// counter at secure-flash page 126:
///
///   1. Check the counter. If ≥ MAX_ATTEMPTS, refuse — return
///      `PinLocked`. Caller is responsible for running
///      `trigger_lockout_wipe` on that signal.
///   2. **Pre-commit**: bump the counter BEFORE calling the SE
///      driver. A power loss or glitch between here and the chip
///      verify leaves the attempt charged. Without this, an
///      attacker who reliably cuts power mid-verify could brute-
///      force without burning MCU attempts.
///   3. Call `WalletStore::unlock`. On `Ok`, erase the counter
///      (fresh start); on `Err`, leave the bump committed.
///   4. If the flash bump itself fails (PROGERR or post-write
///      readback mismatch), refuse the attempt with
///      `InternalError`. Prevents the "glitch flash writes to
///      burn SE attempts without MCU attempts" attack.
///
/// QEMU (no `stm32u585`): passthrough — no flash, no counter, just
/// `se.unlock(pin)`. The counter gate is a production hardware
/// hardening; dev QEMU builds don't need it.
///
/// See `trigger_lockout_wipe` in `cmd_request_unlock.rs` for the
/// wipe path that follows from `PinLocked`.
pub unsafe fn gated_unlock(
    se: &mut impl crate::secure_element::WalletStore,
    pin: &[u8; 8],
) -> Result<[u8; 32], crate::secure_element::UnlockError> {
    use crate::secure_element::UnlockError;

    #[cfg(feature = "stm32u585")]
    {
        let pre_count = crate::hw::flash::pin_attempts_read();
        if pre_count >= sphincs_tz_shared::MAX_ATTEMPTS {
            return Err(UnlockError::PinLocked);
        }
        if crate::hw::flash::pin_attempts_bump().is_err() {
            // Flash write fault (PROGERR or readback mismatch).
            // Refuse without ever calling the SE driver.
            return Err(UnlockError::InternalError);
        }
    }

    let result = se.unlock(pin);

    // FI guard: capture the discriminant twice, separated by
    // `wait_random()`, and route the verdict through the
    // hamming-distant sentinel in `fi::check_true`. A single
    // glitch that turns an `Err` into an `Ok` selection would have
    // to also defeat both `is_ok()` re-evaluations and the sentinel
    // compare. This raises the cost of the "wrong PIN unlocks +
    // resets the counter" attack from a single fault to a multi-
    // fault sequence; the SE silicon counter still rate-limits at
    // the cryptographic gate.
    //
    // Note: if `result` is `Ok(_)` with garbage master_secret
    // (because the SE driver itself was glitched at the chip
    // boundary), the downstream AES-GCM entropy_blob decrypt MAC
    // check will reject it. This FI guard is defense in depth, not
    // a primary gate.
    let is_ok_1 = result.is_ok();
    crate::fi::wait_random();
    let is_ok_2 = result.is_ok();
    // Sentinel-encoded verdict (not a bare `bool`) — a glitch on this call or
    // on the `match`'s guard then almost certainly yields a value `!= OK_SENTINEL`
    // and so falls to the `Ok(_) => InternalError` arm rather than `Ok(master)`.
    let verdict = crate::fi::check_true_into_sentinel(|| is_ok_1 && is_ok_2);

    match result {
        Ok(master) if verdict == crate::fi::OK_SENTINEL => {
            #[cfg(feature = "stm32u585")]
            let _ = crate::hw::flash::pin_attempts_reset();
            Ok(master)
        }
        Ok(_) => {
            // FI inconsistency between the two reads of `result.is_ok()` (or a
            // glitched `verdict`) — refuse without resetting the MCU counter.
            // Counter stays bumped from the pre-commit above.
            Err(UnlockError::InternalError)
        }
        Err(e) => Err(e),
    }
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
        CMD_SIGN_USEROP_BATCH => cmd_sign_userop_batch::run(args),
        CMD_GET_WALLET_ADDRESS => cmd_get_wallet_address::run(args),
        CMD_GET_INIT_CODE => cmd_get_init_code::run(args),
        CMD_SIGN_OFFCHAIN => cmd_sign_offchain::run(args),
        CMD_OFFCHAIN_STATUS => cmd_offchain_status::run(args),
        CMD_OFFCHAIN_SYNC => cmd_offchain_sync::run(args),
        CMD_IS_UNLOCKED => cmd_is_unlocked::run(),
        CMD_LOCK => cmd_lock::run(),
        #[cfg(feature = "e2e-test")]
        sphincs_tz_shared::CMD_TEST_PIN_LOCKOUT => cmd_test_pin_lockout::run(),
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
    secure_log!("[NSC] get_remaining_attempts");
    let r = unsafe { cmd_get_remaining::run() };
    secure_log!("[NSC] get_remaining_attempts -> {}", r);
    r
}

/// CMD_REQUEST_UNLOCK — secure UI prompts for PIN, never crosses NS.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32 {
    secure_log!("[NSC] request_unlock");
    let r = unsafe { cmd_request_unlock::run() };
    secure_log!("[NSC] request_unlock -> {}", r);
    r
}

/// CMD_SIGN_USEROP — unified Type 1 / Type 2 sign command.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop::run(&args) };
    secure_log!("[NSC] sign_userop -> {}", r);
    r
}

/// CMD_SIGN_USEROP_BATCH — atomic multi-call sign command. Same
/// Type 1 / Type 2 wire output as `nsc_sign_userop`; payload differs
/// (header + N inner-tx blocks). See `cmd_sign_userop_batch.rs` for
/// the contract.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_userop_batch(
    payload_ptr: u32,
    sig_out_ptr: u32,
    total_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_userop_batch (len={})", total_len);
    let args = GatewayArgs { arg0: payload_ptr, arg1: sig_out_ptr, arg2: total_len };
    let r = unsafe { cmd_sign_userop_batch::run(&args) };
    secure_log!("[NSC] sign_userop_batch -> {}", r);
    r
}

/// CMD_IS_UNLOCKED — return 1 if unlocked, 0 if locked.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_is_unlocked() -> u32 {
    secure_log!("[NSC] is_unlocked");
    let r = unsafe { cmd_is_unlocked::run() };
    secure_log!("[NSC] is_unlocked -> {}", r);
    r
}

/// CMD_LOCK — zeroize secrets and lock the device.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_lock() -> u32 {
    secure_log!("[NSC] lock");
    let r = unsafe { cmd_lock::run() };
    secure_log!("[NSC] lock -> {}", r);
    r
}

/// CMD_TEST_PIN_LOCKOUT — non-interactive brute-force verification.
/// Destructive (locks SE050 silicon + maxes MCU counter); only built
/// under `e2e-test`. See `cmd_test_pin_lockout.rs` for the contract.
#[cfg(all(feature = "stm32u585", feature = "e2e-test"))]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_test_pin_lockout() -> u32 {
    secure_log!("[NSC] test_pin_lockout");
    let r = unsafe { cmd_test_pin_lockout::run() };
    secure_log!("[NSC] test_pin_lockout -> {}", r);
    r
}

// ---------------------------------------------------------------------------
// Firmware-update CMSE veneers
// ---------------------------------------------------------------------------

/// CMD_FW_BEGIN — initiate firmware-update streaming session.
/// arg0 = manifest_ptr, arg2 = MANIFEST_SIZE (8192).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_begin(manifest_ptr: u32, manifest_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: manifest_ptr,
        arg1: 0,
        arg2: manifest_len,
    };
    unsafe { cmd_fw_begin::run(&args) }
}

/// CMD_FW_CHUNK — stream one image chunk. arg0 = chunk_ptr, arg2 = chunk_len.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_chunk(chunk_ptr: u32, chunk_len: u32) -> u32 {
    let args = GatewayArgs {
        arg0: chunk_ptr,
        arg1: 0,
        arg2: chunk_len,
    };
    unsafe { cmd_fw_chunk::run(&args) }
}

/// CMD_FW_COMMIT — finalize staged update. No args.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_commit() -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: 0, arg2: 0 };
    unsafe { cmd_fw_commit::run(&args) }
}

/// CMD_FW_STATUS — read update progress. arg1 = out_ptr.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_status(out_ptr: u32) -> u32 {
    let args = GatewayArgs { arg0: 0, arg1: out_ptr, arg2: 0 };
    unsafe { cmd_fw_status::run(&args) }
}

/// CMD_FW_ABORT — discard partial update.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_fw_abort() -> u32 {
    unsafe { cmd_fw_abort::run() }
}

/// CMD_GET_WALLET_ADDRESS — compute CREATE2-predicted wallet address for
/// `account_index` (0..=255). Account 0 is the legacy single-account
/// derivation; higher indices yield independent on-chain wallets from
/// the same BIP-39 seed.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_wallet_address(
    out_ptr: u32,
    account_index: u32,
) -> u32 {
    secure_log!("[NSC] get_wallet_address (acct={})", account_index);
    let args = GatewayArgs { arg0: out_ptr, arg1: account_index, arg2: 0 };
    let r = unsafe { cmd_get_wallet_address::run(&args) };
    secure_log!("[NSC] get_wallet_address -> {}", r);
    r
}

/// CMD_GET_INIT_CODE — return the 4280-byte ERC-4337 initCode for
/// `(account_index, chain_id)`. Companion uses it to get accurate
/// gas estimates for first-deploy UserOps; the same bytes are
/// emitted by the deploy path of `CMD_SIGN_USEROP`. See the command
/// docs in `shared::CMD_GET_INIT_CODE`.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_init_code(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] get_init_code (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_get_init_code::run(&args) };
    secure_log!("[NSC] get_init_code -> {}", r);
    r
}

/// CMD_SIGN_OFFCHAIN — sign an EIP-1271 hash with the slot key.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign_offchain(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    secure_log!("[NSC] sign_offchain (len={})", in_len);
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    let r = unsafe { cmd_sign_offchain::run(&args) };
    secure_log!("[NSC] sign_offchain -> {}", r);
    r
}

/// CMD_OFFCHAIN_STATUS — read the firmware's per-slot off-chain state.
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_status(
    in_ptr: u32,
    out_ptr: u32,
    in_len: u32,
) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: out_ptr, arg2: in_len };
    unsafe { cmd_offchain_status::run(&args) }
}

/// CMD_OFFCHAIN_SYNC — bump the firmware's per-slot `last_userop_count`
/// to a companion-supplied floor. See `cmd_offchain_sync::run` for the
/// full rationale (firmware-reflash recovery).
#[cfg(feature = "stm32u585")]
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_offchain_sync(in_ptr: u32, in_len: u32) -> u32 {
    let args = GatewayArgs { arg0: in_ptr, arg1: 0, arg2: in_len };
    unsafe { cmd_offchain_sync::run(&args) }
}

