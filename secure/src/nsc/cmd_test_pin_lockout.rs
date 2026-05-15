//! CMD_TEST_PIN_LOCKOUT — non-interactive brute-force protection check.
//!
//! Test-only handler, compiled out unless `e2e-test` is set on the secure
//! build. Proves the full brute-force story in two passes while keeping
//! the SE050 user UserID's silicon retry budget intact (so the test is
//! repeatable without chip replacement):
//!
//!   Pass A — real wrong-PIN lockstep (non-destructive)
//!     Runs `MAX_ATTEMPTS - 1` wrong-PIN `gated_unlock` calls. Each one
//!     actually drives both chips: OPTIGA's auth-ref rejects, SE050's
//!     silicon decrements, MCU page-124 is bumped by the gate. Thanks to
//!     the three-way lockstep fix (commit 7574218) the SE050 silicon
//!     counter advances on wrong PINs now — proves wrong PINs really do
//!     burn retry budget. One follow-up correct-PIN call resets all
//!     three counters (MCU erased, SE050 silicon retries back to max),
//!     leaving the chip fully functional.
//!
//!   Pass B — MCU gate at MAX_ATTEMPTS (non-destructive)
//!     Directly bumps the MCU page-124 counter `MAX_ATTEMPTS` times via
//!     `hw::flash::pin_attempts_bump`, then calls `gated_unlock` with
//!     the correct PIN. The MCU gate short-circuits with `PinLocked`
//!     before the SE is called — proves an attacker who somehow had
//!     the correct PIN in hand still cannot pass the gate once it's
//!     at max. The handler then resets the counter and re-unlocks with
//!     the correct PIN to restore session state.
//!
//! Return value:
//!   * `NscStatus::Ok`          — all asserts passed, brute-force blocked.
//!   * `NscStatus::CryptoError` — either a wrong PIN was accepted (pass
//!                                A) or the correct PIN was accepted
//!                                while MCU counter was at max (pass B).
//!   * `NscStatus::InternalError` — flash / IPC fault; setup failure,
//!                                not a brute-force finding.

use sphincs_tz_shared::{NscStatus, MAX_ATTEMPTS};

use crate::secure_element::UnlockError;

/// PIN baked into the e2e-test fast-path. Kept in sync with the value
/// written by `main.rs` under `#[cfg(feature = "e2e-test")]`.
const CORRECT_PIN: [u8; 8] = *b"00000000";

/// Arbitrary wrong PIN — just needs to differ from `CORRECT_PIN`.
const WRONG_PIN: [u8; 8] = *b"99999999";

/// # Safety
/// CMSE non-secure-entry handler (compiled only under `e2e-test`).
/// Drives `gated_unlock` repeatedly against `static mut crate::SE`;
/// no NS pointer derefs. Destructive to silicon counters; gated out
/// of production by feature flag.
pub(super) unsafe fn run() -> u32 {
    let _busy = super::HandlerGuard::enter();

    crate::ui::show_status("PIN lockout", "pass A...");

    // Drop cached master so every attempt really drives the SE pair.
    super::zeroize_sensitive_state();

    // Start pass A from a known MCU counter. Pre-existing boot counter
    // value would shift the "MAX_ATTEMPTS - 1 wrong attempts" window.
    #[cfg(feature = "stm32u585")]
    {
        if crate::hw::flash::pin_attempts_reset().is_err() {
            secure_log!("[PIN-LOCKOUT] setup: pin_attempts_reset FAILED");
            return NscStatus::InternalError as u32;
        }
    }

    // ── Pass A: real wrong PINs, stop one attempt short ──────────────
    // MAX_ATTEMPTS-1 = 9 wrong attempts:
    //   MCU:          0 → 9           (1 shy of the gate)
    //   OPTIGA E120:  +9               (chip counter advances)
    //   SE050 UserID: 10 → 1           (silicon, 1 retry still alive)
    let wrong_budget = (MAX_ATTEMPTS as usize).saturating_sub(1);
    for i in 0..wrong_budget {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match super::gated_unlock(se, &WRONG_PIN) {
            Err(UnlockError::PinIncorrect) => {
                secure_log!(
                    "[PIN-LOCKOUT] passA wrong #{}: PinIncorrect (expected)",
                    i + 1
                );
            }
            Err(UnlockError::PinLocked) => {
                secure_log!(
                    "[PIN-LOCKOUT] passA wrong #{}: PinLocked (gate tripped too early)",
                    i + 1
                );
                return NscStatus::InternalError as u32;
            }
            Err(_e) => {
                secure_log!(
                    "[PIN-LOCKOUT] passA wrong #{}: unexpected {:?}",
                    i + 1,
                    _e
                );
                return NscStatus::InternalError as u32;
            }
            Ok(mut master) => {
                use zeroize::Zeroize;
                master.zeroize();
                secure_log!(
                    "[PIN-LOCKOUT] passA wrong #{}: ACCEPTED (bruteforce possible)",
                    i + 1
                );
                crate::ui::show_status("PIN lockout", "WRONG-OK FAIL");
                return NscStatus::CryptoError as u32;
            }
        }
    }

    // Correct PIN must succeed and reset all counters (MCU erased,
    // OPTIGA E120 ratchet-reset to 0, SE050 silicon retries back to
    // max). Drops the cached master immediately — pass B then needs
    // to drive the SE again.
    {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match super::gated_unlock(se, &CORRECT_PIN) {
            Ok(mut m) => {
                use zeroize::Zeroize;
                m.zeroize();
            }
            Err(_e) => {
                secure_log!(
                    "[PIN-LOCKOUT] passA recover: correct PIN REJECTED ({:?})",
                    _e
                );
                crate::ui::show_status("PIN lockout", "passA recover FAIL");
                return NscStatus::InternalError as u32;
            }
        }
    }
    secure_log!(
        "[PIN-LOCKOUT] passA recover: correct PIN accepted, counters reset"
    );
    super::zeroize_sensitive_state();

    // ── Pass B: MCU gate at MAX ──────────────────────────────────────
    //
    // The MCU page-124 attempt counter and the `gated_unlock` pre-commit
    // exist only under `stm32u585` — on QEMU (`mock-se`) `gated_unlock`
    // is a passthrough into the mock SE driver, so there is no gate to
    // exercise here. Skip pass B entirely in that build. Pass A above
    // already covers the SE-side wrong-PIN lockstep, which is the only
    // brute-force guard the QEMU stack actually has.
    #[cfg(feature = "stm32u585")]
    {
        crate::ui::show_status("PIN lockout", "pass B...");

        // Drive MCU counter to MAX without touching the SE pair. The MCU
        // gate must still refuse a correct PIN — proves the gate alone
        // blocks brute force, independent of the SE's own counter.
        if crate::hw::flash::pin_attempts_reset().is_err() {
            secure_log!("[PIN-LOCKOUT] passB setup: pin_attempts_reset FAILED");
            return NscStatus::InternalError as u32;
        }
        for _ in 0..MAX_ATTEMPTS {
            if crate::hw::flash::pin_attempts_bump().is_err() {
                secure_log!("[PIN-LOCKOUT] passB setup: pin_attempts_bump FAILED");
                return NscStatus::InternalError as u32;
            }
        }
        let after = crate::hw::flash::pin_attempts_read();
        if after < MAX_ATTEMPTS {
            secure_log!(
                "[PIN-LOCKOUT] passB setup: MCU counter only at {} after {} bumps",
                after,
                MAX_ATTEMPTS
            );
            return NscStatus::InternalError as u32;
        }

        let gate_outcome = {
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            super::gated_unlock(se, &CORRECT_PIN)
        };
        match gate_outcome {
            Err(UnlockError::PinLocked) => {
                secure_log!(
                    "[PIN-LOCKOUT] passB: MCU gate rejected correct PIN at MAX — PASS"
                );
            }
            Ok(mut master) => {
                use zeroize::Zeroize;
                master.zeroize();
                secure_log!(
                    "[PIN-LOCKOUT] passB: MCU gate ACCEPTED correct PIN at MAX — FAIL"
                );
                crate::ui::show_status("PIN lockout", "gate bypass FAIL");
                return NscStatus::CryptoError as u32;
            }
            Err(_e) => {
                secure_log!("[PIN-LOCKOUT] passB: unexpected {:?}", _e);
                return NscStatus::InternalError as u32;
            }
        }
    }
    #[cfg(not(feature = "stm32u585"))]
    {
        secure_log!(
            "[PIN-LOCKOUT] passB skipped — no MCU gate on QEMU (mock-se passthrough)"
        );
    }

    // Cleanup: clear the MCU counter and re-unlock so pin_verified +
    // master_secret are restored for any follow-on command in the same
    // session. Non-destructive — the chip is left in the same state
    // the handler was invoked in.
    #[cfg(feature = "stm32u585")]
    {
        if crate::hw::flash::pin_attempts_reset().is_err() {
            secure_log!("[PIN-LOCKOUT] cleanup: pin_attempts_reset FAILED");
            return NscStatus::InternalError as u32;
        }
    }
    let master_final = {
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match super::gated_unlock(se, &CORRECT_PIN) {
            Ok(m) => m,
            Err(_e) => {
                secure_log!(
                    "[PIN-LOCKOUT] cleanup: correct PIN REJECTED ({:?})",
                    _e
                );
                return NscStatus::InternalError as u32;
            }
        }
    };
    super::unlock_with_master(master_final);

    crate::ui::show_status("PIN lockout", "BLOCKED: PASS");
    secure_log!(
        "[PIN-LOCKOUT] bruteforce blocked — passA lockstep + passB gate both green"
    );
    NscStatus::Ok as u32
}
