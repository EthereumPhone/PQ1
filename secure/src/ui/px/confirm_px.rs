//! The pixel-UI confirmation loop over a proven screen transcript.
//!
//! Mirrors `ui::confirm::confirm_checked_inner` point for point — empty
//! transcript refuses, the `e2e-test` fast path shows every page and
//! auto-confirms, the `TrustedUiWaitGuard` is scoped to the wait, the
//! inactivity timer is reset only by a real button event, the deadline is
//! sampled before and after every wait and immediately before the affirmative
//! return, and the `OK_SENTINEL` is minted at exactly one site — but the
//! navigation is DESIGN.md § Input (`FlowDriver`), not the 16×4 page grammar.
//!
//! # Consent policy (decision 2026-10-13)
//!
//! The sign gesture on the device is the **two-button chord click** (both
//! down together, fires on release; parity with the legacy dialog's
//! two-button confirm, owner decision 2026-09-22); hold-right is a no-op and
//! hold-left declines everywhere. The chord signs ONLY on the auto-inserted
//! `Confirm?`, from the moment it is shown, or on the LAST screen, the
//! returning ask — never on the opening ask, never on a detail
//! ([`FlowDriver::sign_point`]). This replaces the 2026-09-24 scroll-to-end
//! switch `PX_COMMIT_REQUIRES_SEEN_LAST`, under which `Confirm?` was drawn
//! armed but could not sign until the last screen had been painted. Signing
//! from `Confirm?` skips every screen after it. The legacy 16×4 path keeps its
//! 2026-06-26 scroll-to-end gate (`confirm_core::seen_last`). Recorded in
//! `docs/security/HARDENING.md` § 2.4.

use super::text;
use crate::timeout;
use crate::ui::confirm::ConfirmResult;
use crate::ui::input;
use crate::ui::{Button, Press};
use pqsigner_ui_px::driver::{Btn, FlowDriver, Gesture, NavResult};
use pqsigner_ui_px::Screens;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LoopResult {
    Confirmed,
    Cancelled,
    IdleWipe,
    DeadlineExpired,
}

/// Run the confirmation dialog over `screens`. Returns the user's decision
/// and the FI gate: `crate::fi::OK_SENTINEL` only on the accept branch.
pub fn confirm_screens_checked(screens: &Screens, atlas: super::AtlasArg<'_>) -> (ConfirmResult, u32) {
    let mut never = || false;
    let (r, gate) = confirm_inner(screens, atlas, &mut never);
    let cr = match r {
        LoopResult::Confirmed => ConfirmResult::Confirmed,
        LoopResult::Cancelled | LoopResult::DeadlineExpired => ConfirmResult::Cancelled,
        LoopResult::IdleWipe => ConfirmResult::IdleWipe,
    };
    (cr, gate)
}

fn confirm_inner(screens: &Screens, atlas: super::AtlasArg<'_>, deadline_expired: &mut dyn FnMut() -> bool) -> (LoopResult, u32) {
    let _ = &atlas;
    let visible = screens.as_slice();
    let Some(mut driver) = FlowDriver::new(visible) else {
        return (LoopResult::Cancelled, crate::fi::FAIL_SENTINEL);
    };
    if deadline_expired() {
        return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
    }

    // ---- e2e-test fast-path: show every (screen, page), then auto-confirm.
    #[cfg(feature = "e2e-test")]
    {
        for (idx, s) in visible.iter().enumerate() {
            for page in 0..s.npages().max(1) {
                if deadline_expired() {
                    return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
                }
                text::present(s, page, idx, visible.len());
            }
        }
        let _ = &mut driver;
        if deadline_expired() {
            return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
        }
        return (LoopResult::Confirmed, crate::fi::OK_SENTINEL);
    }

    // The NV3007 presenter owns the loop on hardware (same seams, animated).
    #[cfg(all(not(feature = "e2e-test"), feature = "ui-lcd"))]
    {
        let _ = &mut driver;
        let (out, gate) = super::lcd::run_flow(screens, atlas, deadline_expired);
        return match out {
            super::PxOutcome::Signed => (LoopResult::Confirmed, gate),
            super::PxOutcome::Declined | super::PxOutcome::Cancelled => (LoopResult::Cancelled, crate::fi::FAIL_SENTINEL),
            super::PxOutcome::IdleWipe => (LoopResult::IdleWipe, crate::fi::FAIL_SENTINEL),
            super::PxOutcome::DeadlineExpired => (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL),
        };
    }

    #[cfg(all(not(feature = "e2e-test"), not(feature = "ui-lcd")))]
    {
        // F14/SCAFI-2: the arming flag is a `FihBool` (complement pair +
        // double read), never a bare bool — a stuck-at on a plain bool would
        // read `true` in both the gate and the sentinel closure.
        let mut commit_armed = crate::fih::FihBool::new_false();
        loop {
            if deadline_expired() {
                return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }
            let idx = driver.index();
            let page = driver.page();
            text::present(&visible[idx], page, idx, visible.len());
            driver.mark_rendered();

            // Re-derive the arming from the screen just painted: kind ∈
            // {hero, confirm} AND the record's commit byte (double-read) AND
            // the consent policy (`Confirm?` or the last screen only).
            let armed = driver.sign_point(visible);
            if armed {
                commit_armed.set_true();
            } else {
                commit_armed.set_false();
            }

            if deadline_expired() {
                return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }
            let mut wait_abort = || timeout::is_idle() || deadline_expired();
            // Scoped to the wait only (see confirm.rs): the watchdog learns
            // "waiting on a human"; this does NOT reset the inactivity timer.
            let event = match {
                let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();
                input().wait_button(&mut wait_abort)
            } {
                Some(ev) => ev,
                None => {
                    if deadline_expired() {
                        return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
                    }
                    return (LoopResult::IdleWipe, crate::fi::FAIL_SENTINEL);
                }
            };
            if deadline_expired() {
                return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
            }
            // A button event IS real user activity — the only reset site.
            timeout::reset_activity();

            // The legacy input backends encode the two-button confirm chord
            // as `(Right, Long)` (`hw::buttons::wait_event`; semihosting `L`),
            // so on this text path that event IS the chord.
            let gesture = match event {
                (Button::Left, Press::Short) => Gesture::Tap(Btn::Left),
                (Button::Right, Press::Short) => Gesture::Tap(Btn::Right),
                (Button::Left, Press::Long) => Gesture::HoldCommit(Btn::Left),
                (Button::Right, Press::Long) => Gesture::Chord,
            };
            match driver.apply(visible, gesture) {
                NavResult::Decline => return (LoopResult::Cancelled, crate::fi::FAIL_SENTINEL),
                NavResult::Sign => {
                    // The ONE affirmative site: the sentinel is born from the
                    // FI-hardened arming flag, then a final fresh deadline
                    // sample precedes the return.
                    let gate = commit_armed.check_sentinel();
                    if gate != crate::fi::OK_SENTINEL {
                        continue;
                    }
                    if deadline_expired() {
                        return (LoopResult::DeadlineExpired, crate::fi::FAIL_SENTINEL);
                    }
                    return (LoopResult::Confirmed, gate);
                }
                NavResult::Moved | NavResult::PageTurned | NavResult::Ignored => {}
            }
        }
    }
}
