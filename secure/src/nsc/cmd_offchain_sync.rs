//! CMD_OFFCHAIN_SYNC — bump per-slot `last_userop_count` to a
//! companion-supplied target. "Set if greater", idempotent.
//!
//! The repair path in `cmd_sign_userop::run` computes
//! `new_offchain_count = max(local_offchain, last_userop_snapshot)`
//! using firmware-flash state only. After a firmware reflash that
//! wipes the offchain-state flash region, both counters start at
//! zero — but the on-chain `offchainSigCount[ownerIndex]` may still
//! be non-zero (carried over from before the reflash). Without a way
//! to inform the firmware of the on-chain floor, the next userop emits
//! `newOffchainCount = 0` and reverts with
//! `OffchainSigCountNotMonotonic`.
//!
//! Wire layout:
//!   * Input (21 bytes):
//!       [ 0.. 1) account_index (u8)
//!       [ 1.. 9) chain_id      (u64 BE)
//!       [ 9..13) slot_index    (u32 BE)
//!       [13..21) target_count  (u64 BE)
//!   * Output: no body, SW only.
//!
//! Security note: the value set here is part of the firmware's few-time-key
//! budget and is therefore shown exactly on the trusted display whenever it
//! raises the floor. The on-chain combined-cap check remains authoritative for
//! accepted operations, while the firmware cap additionally covers signatures
//! released but never submitted.
//!
//! What the value-only reasoning missed (page-123 exhaustion → permanent-brick;
//! `docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md`): the durable *write*
//! mints a fresh page-123 journal entry for a companion-chosen, seed-independent
//! `slot_key`. With no consent gate a hostile companion can spray distinct
//! `(account,chain,slot)` tuples to fill the page and wedge compaction into a
//! permanent, seed-survivable signing brick. Two defences now apply:
//!   1. **Consent (here):** creating a slot the firmware has NOT seen before,
//!      or raising an existing slot's floor, requires an explicit trusted-
//!      display `confirm()` bound to the current + target counts. A spray would
//!      need one physical confirm per distinct tuple. Idempotent no-op syncs
//!      stay confirm-free.
//!   2. **Structural cap:** `offchain_state::MAX_DISTINCT_SLOTS` (enforced at the
//!      flash `write_entry` chokepoint and the host mock) refuses a new distinct
//!      slot past a budget chosen so compaction can never fail — the page is
//!      provably un-wedgeable by any caller, confirmed or not.

use sphincs_tz_shared::{NscStatus, MAX_ACCOUNT_INDEX, OFFCHAIN_SYNC_INPUT_LEN};

use super::ptr_validate::validate_ns_read_ptr;
use super::GatewayArgs;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// derefs happen only after `validate_ns_read_ptr` has proved the
/// input range is fully NS-classified. No output buffer in this
/// command (status word only).
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    let _busy = super::HandlerGuard::enter();

    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        return NscStatus::NotInitialized as u32;
    }

    let in_ptr = args.arg0 as *const u8;
    let total_len = args.arg2 as usize;

    if total_len != OFFCHAIN_SYNC_INPUT_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS read
    // pointer (bare `if !validate` is single-fault FAIL-OUT). This handler
    // has no output buffer, so only the read pointer is validated.
    let read_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_read_ptr(args.arg0, OFFCHAIN_SYNC_INPUT_LEN)
    });
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        return NscStatus::InvalidPointer as u32;
    }

    let mut buf = [0u8; OFFCHAIN_SYNC_INPUT_LEN];
    for i in 0..OFFCHAIN_SYNC_INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = buf[0] as u32;
    let chain_id = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let slot_index = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    let target_count = u64::from_be_bytes([
        buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20],
    ]);
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    // Value-inflation → consent-free durable slot brick defence (Layer 1;
    // `docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md`). `target_count` is
    // fully companion-controlled and, for an already-registered slot, is written
    // durably WITHOUT a confirm (the gate below only fires for new slots). The
    // sign paths promote it verbatim into the monotonic `offchain` counter, so an
    // un-clamped `>= MAX_SLOT_USES` would permanently trip the combined-cap gate —
    // a seed-survivable, consent-free brick of the slot. Clamp it to
    // `OFFCHAIN_COUNT_CEILING` (`MAX_SLOT_USES - 1`) at the source: a truthful
    // on-chain `offchainSigCount` (the only value a legitimate sync mirrors) is
    // always `< MAX_SLOT_USES`, so this never rejects an honest sync, while a
    // hostile inflation can no longer reach the brick state. Belt-and-braces: the
    // durable flash setters clamp again (see `crate::offchain_state`), so a single
    // skipped site cannot re-open the hole.
    let target_count = crate::offchain_state::clamp_offchain_count(target_count);
    let target_count_for_display = target_count;

    let slot_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // Bind the trusted display to a stable, FI-checked snapshot of the current
    // floor. The flash reader already performs forward/reverse scans; repeat
    // the complete read with jitter and fail closed on disagreement or an
    // impossible above-ceiling value. No writer can race this handler under
    // HandlerGuard, so a mismatch is corruption/fault, not normal concurrency.
    let current_count_a = crate::offchain_state::last_userop_count_read(&slot_key);
    crate::fi::wait_random();
    let current_count_b = crate::offchain_state::last_userop_count_read(&slot_key);
    if current_count_a != current_count_b
        || current_count_a > crate::offchain_state::OFFCHAIN_COUNT_CEILING
    {
        crate::ui::show_status("Counter sync", "state invalid");
        return NscStatus::InternalError as u32;
    }
    let current_count = current_count_a;

    // Consent gate — two brick classes, one confirm.
    //
    // (a) NEW-SLOT (page-123 exhaustion → permanent-brick fix; module Security
    //     note + docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md). A durable
    //     write for a slot the firmware has NOT seen before mints a new page-123
    //     journal entry for a companion-chosen, seed-independent slot_key; an
    //     unbounded spray of distinct tuples would wedge compaction into a
    //     permanent signing brick. One physical confirm per distinct tuple makes
    //     a spray infeasible.
    //
    // (b) VALUE-INFLATION (docs/security/vulns/VULN-offchain-sync-value-inflation-slot-brick.md).
    //     Even on an ALREADY-registered slot, a sync that RAISES `last_userop` is
    //     promoted into the monotonic off-chain counter and burns the slot's
    //     few-time budget toward exhaustion with no user interaction. The clamp
    //     above already blocks the permanent, cap-tripping brick; this confirm
    //     additionally denies the *consent-free near-exhaustion* that would
    //     otherwise let a hostile companion force the slot-rotation treadmill.
    //     A raise only ever occurs on genuine recovery (post-reflash catch-up —
    //     itself a NEW slot, case (a) — or a rare multi-device floor advance),
    //     so gating it costs an honest user at most one confirm while removing
    //     the attacker's silent lever. Fail-safe: if this read glitches the sync
    //     is over-gated (an extra confirm), never under-gated.
    //
    // An idempotent re-sync (`target <= stored`) is a no-op and stays confirm-
    // free. Bare unsafe facade calls match this file's existing convention.
    let is_new_slot = !crate::offchain_state::offchain_count_is_registered(&slot_key);
    let raises_floor = target_count > current_count;
    if is_new_slot || raises_floor {
        use crate::ui::confirm::{confirm_checked, ConfirmResult};
        let pages = crate::tx::display::build_offchain_sync_pages(
            account_index as u8,
            chain_id,
            slot_index,
            current_count,
            target_count_for_display,
        );
        // Port step 4: every fact row of the proven pages as design screens;
        // the page dialog only when the pixel path cannot run.
        #[cfg(feature = "ui-px")]
        let px = super::px_confirm_plain(|t| crate::ui::px::status_map::offchain_sync_screens(pages.as_slice(), t)).ok();
        #[cfg(not(feature = "ui-px"))]
        let px: Option<(ConfirmResult, u32)> = None;
        let (cr, cr_verdict) = match px {
            Some(out) => out,
            None => confirm_checked(pages.as_slice()),
        };
        match cr {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail closed.
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }

        // The exact target rendered above must be the exact target committed
        // below. Evaluate the binding twice through the FI sentinel; black_box
        // prevents the optimiser from folding two immutable locals into a
        // compile-time `true` and deleting the check.
        if crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(target_count) == core::hint::black_box(target_count_for_display)
                && core::hint::black_box(target_count)
                    <= crate::offchain_state::OFFCHAIN_COUNT_CEILING
        }) != crate::fi::OK_SENTINEL
        {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }

    // `last_userop_count_set` is tolerant of `target <= current` (no-op).
    // The repair branch in `cmd_sign_userop::run` will pick up the new
    // floor via `last_userop_count_read` → `max(local, last_userop)`,
    // and `offchain_count_promote_to` will bump `local_offchain` in turn
    // so subsequent off-chain signs see a consistent base.
    if crate::offchain_state::last_userop_count_set(&slot_key, target_count).is_err() {
        return NscStatus::InternalError as u32;
    }

    NscStatus::Ok as u32
}
