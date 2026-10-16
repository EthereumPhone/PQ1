//! Host-side test suite for the `secure-nsc-core` slice.
//!
//! ## What is covered here
//!
//! The slice covers four files under `secure/src/nsc/`:
//!
//!   * `mod.rs`         — gateway dispatcher, `HandlerGuard` busy
//!                        counter, `gated_unlock`, CMSE veneers (real
//!                        hardware), and the compile-time feature-gate
//!                        fences that block dev features from
//!                        shipping in production.
//!   * `state.rs`       — `SecureState` singleton, FI-hardened
//!                        `pin_verified`, bootstrap pubkey LRU cache,
//!                        slot cache, and the `with_state` /
//!                        `peek_state` closure accessors.
//!   * `ns_ptr.rs`      — `NsPtr<T>` typestate + `ReadPtr<T>` /
//!                        `WritePtr<T>` proofs returned by the
//!                        F-8-hardened two-pass validators.
//!   * `ptr_validate.rs` — the raw `validate_ns_read_ptr` /
//!                        `validate_ns_write_ptr` predicates plus
//!                        (on real hardware) the `tt`-driven SAU
//!                        cross-check.
//!
//! The first two are largely reachable on host through the
//! `nsc_core_under_test` scaffold; their inline `#[cfg(test)] mod tests`
//! blocks supply most of the positive + negative coverage.
//!
//! This file adds the cross-file coverage they can't carry alone:
//!
//!   1. **Mirror tests for `HandlerGuard`.** `nsc::mod.rs` itself
//!      can't be re-included (its `cmd_*` siblings drag in OLED, SE,
//!      flash, etc.), so we re-derive the documented semantics here
//!      against a fresh `AtomicU32` so any regression in the docstring
//!      contract surfaces in CI rather than on real hardware.
//!   2. **Wire-frozen constant pins.** Every constant the slice's
//!      validators / dispatcher / state machine consume from
//!      `pqsigner-proto` (NS memory layout, mailbox window, status
//!      codes, command IDs, attempt budget). A silent drift would
//!      mis-route a gateway call or open a memory window the
//!      validators no longer cover.
//!   3. **Source-text invariant pins.** Load-bearing gates whose
//!      presence is the whole point of the slice — the pin-verified
//!      check inside `with_state`, the `pub(super)` visibility of
//!      `STATE`, the `static mut STATE` declaration shape, the
//!      two-pass F-8 hardening inside `validate_*`, the `unsafe fn
//!      gated_unlock` pre-commit, the absence of forbidden code
//!      paths (`rotateMasterKeys`, classical signers, ECDSA, etc.),
//!      and the `compile_error!` fences that block dev features in
//!      production.
//!
//! Negative tests are framed around the assumption each gate enforces
//! (CLAUDE.md invariants #1, #2, #4, #6, #7, #8 + the per-file
//! docstrings). When the assumption holds, the test passes; when a
//! future refactor violates it, the test fails with a panic message
//! naming the assumption attacked.

#![cfg(test)]

use std::sync::atomic::{AtomicU32, Ordering};

use sphincs_tz_shared::{
    MAX_ATTEMPTS, NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, NscStatus,
    SHARED_MAILBOX_BASE, SHARED_MAILBOX_END,
};

use super::ns_ptr::NsPtr;
use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::{peek_state, with_state};
use super::state::tests::state_test_lock;

// ─────────────────────────────────────────────────────────────────────
// 0. Slice source-text fixtures (loaded once, used by §3 below).
// ─────────────────────────────────────────────────────────────────────

const NSC_MOD_SRC: &str = include_str!("../nsc/mod.rs");
const NSC_STATE_SRC: &str = include_str!("../nsc/state.rs");
const NSC_NS_PTR_SRC: &str = include_str!("../nsc/ns_ptr.rs");
const NSC_PTR_VALIDATE_SRC: &str = include_str!("../nsc/ptr_validate.rs");
const REQUEST_UNLOCK_SRC: &str = include_str!("../nsc/cmd_request_unlock.rs");
const TEST_PIN_LOCKOUT_SRC: &str = include_str!("../nsc/cmd_test_pin_lockout.rs");
const MAIN_SRC: &str = include_str!("../main.rs");

const ALL_SLICE_FILES: &[(&str, &str)] = &[
    ("nsc/mod.rs", NSC_MOD_SRC),
    ("nsc/state.rs", NSC_STATE_SRC),
    ("nsc/ns_ptr.rs", NSC_NS_PTR_SRC),
    ("nsc/ptr_validate.rs", NSC_PTR_VALIDATE_SRC),
];

/// Load production-shaped Rust sources for call-graph exclusivity pins.
/// Files whose path contains `test` are excluded so inline host tests can call
/// private state transitions without looking like firmware callers.
fn production_secure_rust_sources() -> Vec<(std::path::PathBuf, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("read secure/src") {
            let entry = entry.expect("read secure/src entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let relative = path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .expect("source below secure manifest");
            if relative.to_string_lossy().contains("test") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read Rust source");
            out.push((relative.to_path_buf(), src));
        }
    }

    let mut out = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut out,
    );
    out
}

// ─────────────────────────────────────────────────────────────────────
// 1. Wire-frozen constants — positive coverage.
//
// These values are part of the firmware-↔-companion ABI; the slice's
// validators / dispatcher read them on every gateway call. A change
// here is a breaking change.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_max_attempts_is_ten() {
    assert_eq!(MAX_ATTEMPTS, 10,
        "MAX_ATTEMPTS feeds nsc::gated_unlock; CLAUDE.md invariant #2 \
         (10-wrong-PIN → factory reset) depends on this value");
}

#[test]
fn positive_nscstatus_invalid_pointer_wire_value_pinned() {
    assert_eq!(NscStatus::InvalidPointer as u32, 4,
        "NscStatus::InvalidPointer wire value MUST stay 4 (companion ABI)");
}

#[test]
fn positive_nscstatus_pin_locked_wire_value_pinned() {
    assert_eq!(NscStatus::PinLocked as u32, 2);
    assert_eq!(NscStatus::PinIncorrect as u32, 1);
    assert_eq!(NscStatus::Ok as u32, 0);
    assert_eq!(NscStatus::InternalError as u32, 0xFFFF_FFFF);
}

#[test]
fn positive_ns_memory_layout_constants_pinned() {
    // QEMU mps2-an505 NS memory layout — see `pqsigner-proto`
    // `mem_layout` (no stm32u585 feature on host build).
    assert_eq!(NS_SRAM_BASE, 0x2802_0000);
    assert_eq!(NS_SRAM_END, 0x2822_0000);
    assert_eq!(NS_FLASH_BASE, 0x0020_0000);
    assert_eq!(NS_FLASH_END, 0x0040_0000);
    assert_eq!(SHARED_MAILBOX_BASE, 0x2802_FF00);
    assert_eq!(SHARED_MAILBOX_END, 0x2802_FF18);
}

#[test]
fn positive_mailbox_inside_ns_sram() {
    // The mailbox must live INSIDE NS SRAM so the overlap check
    // (`ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE`) fires
    // for every accidental request.
    assert!(SHARED_MAILBOX_BASE >= NS_SRAM_BASE);
    assert!(SHARED_MAILBOX_END <= NS_SRAM_END);
    assert!(SHARED_MAILBOX_BASE < SHARED_MAILBOX_END,
        "non-empty mailbox window required for the overlap predicate");
}

// ─────────────────────────────────────────────────────────────────────
// 2. HandlerGuard mirror — exercise the documented depth-counter
// semantics on a fresh `AtomicU32`. Source-text pins in §3 prove the
// real implementation has the same shape.
// ─────────────────────────────────────────────────────────────────────

/// Local mirror of `nsc::HANDLER_DEPTH` so the contract is exercised
/// without dragging the real `nsc` module into the test build.
struct MirrorGuard<'a>(&'a AtomicU32);

impl<'a> MirrorGuard<'a> {
    fn enter(counter: &'a AtomicU32) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        MirrorGuard(counter)
    }
}

impl<'a> Drop for MirrorGuard<'a> {
    fn drop(&mut self) {
        // Saturating decrement via CAS loop (same shape as
        // `nsc::HandlerGuard::drop`).
        let mut cur = self.0.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match self.0.compare_exchange_weak(
                cur, next, Ordering::SeqCst, Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

fn mirror_is_busy(counter: &AtomicU32) -> bool {
    counter.load(Ordering::SeqCst) > 0
}

#[test]
fn positive_handler_guard_enter_marks_busy() {
    let c = AtomicU32::new(0);
    assert!(!mirror_is_busy(&c), "fresh counter must not be busy");
    let _g = MirrorGuard::enter(&c);
    assert!(mirror_is_busy(&c));
}

#[test]
fn positive_handler_guard_drop_clears_busy() {
    let c = AtomicU32::new(0);
    {
        let _g = MirrorGuard::enter(&c);
        assert!(mirror_is_busy(&c));
    }
    assert!(!mirror_is_busy(&c),
        "after the last guard drops, busy MUST be false");
}

#[test]
fn positive_handler_guard_nesting_is_reference_counted() {
    let c = AtomicU32::new(0);
    let outer = MirrorGuard::enter(&c);
    {
        let _inner = MirrorGuard::enter(&c);
        assert_eq!(c.load(Ordering::SeqCst), 2,
            "two live guards must yield depth 2");
    }
    assert_eq!(c.load(Ordering::SeqCst), 1,
        "inner drop must decrement to 1, NOT 0");
    drop(outer);
    assert_eq!(c.load(Ordering::SeqCst), 0);
}

/// Assumption: the SysTick idle-wipe path checks `handler_is_busy()`
/// before zeroing BSS. A guard inside a long-running handler MUST
/// keep `busy == true` for the whole handler body. If `Drop` ran
/// underneath us we'd silently dis-arm the protection.
#[test]
fn negative_handler_guard_busy_stays_true_for_lifetime() {
    let c = AtomicU32::new(0);
    let g = MirrorGuard::enter(&c);
    // Many "loop iterations" of secure-side work — busy must stay
    // true the entire time.
    for _ in 0..1000 {
        assert!(mirror_is_busy(&c),
            "busy must remain true while a guard is alive");
    }
    drop(g);
}

/// Assumption: dropping more times than entering MUST NOT underflow
/// past zero. Cannot be done in safe Rust (Drop can't be called
/// twice), but the `compare_exchange_weak` saturating shape proves it
/// at the algorithm level for future contributors who reach for
/// `fetch_sub`.
#[test]
fn negative_mirror_saturating_decrement_does_not_underflow() {
    let c = AtomicU32::new(0);
    // Manually run the drop logic against a counter already at 0.
    let mut cur = c.load(Ordering::SeqCst);
    loop {
        let next = cur.saturating_sub(1);
        match c.compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
    assert_eq!(c.load(Ordering::SeqCst), 0,
        "saturating decrement on a 0 counter MUST yield 0, not u32::MAX");
}

// ─────────────────────────────────────────────────────────────────────
// 3. Source-text invariant pins.
//
// These are intentionally coarse — they catch a refactor that removes
// or moves a load-bearing gate. They are NOT a substitute for
// behaviour tests but they cover code paths that can't be exercised
// on host (CMSE veneers, flash bumps, etc.).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_pin_verified_is_fih_hardened_storage() {
    // The whole point of F-14 is that `pin_verified` is a `FihBool`,
    // not a bare `bool`. A future refactor that "simplifies" it to a
    // raw bool re-opens the F-14 storage-glitch attack.
    assert!(NSC_STATE_SRC.contains("pub(super) pin_verified: FihBool"),
        "state.rs must store pin_verified as FihBool (F-14)");
    assert!(NSC_STATE_SRC.contains("pin_verified.set_true()"),
        "mark_unlocked must use the FihBool API, not raw assignment");
    assert!(NSC_STATE_SRC.contains("pin_verified.set_false()"),
        "zeroize_sensitive must use the FihBool API, not raw assignment");
}

#[test]
fn positive_forced_attempt_has_one_armed_writer_and_one_production_caller() {
    assert_eq!(
        NSC_STATE_SRC
            .matches("self.write_words(FORCED_ATTEMPT_ARMED_WORDS);")
            .count(),
        1,
        "arm_forced_attempt_after_pin must be the sole Armed codeword writer",
    );
    assert!(
        NSC_STATE_SRC.contains("pub(super) fn arm_forced_attempt_after_pin"),
        "the PIN-only arm transition must remain confined to the nsc module",
    );

    let callers: Vec<_> = production_secure_rust_sources()
        .into_iter()
        .filter(|(path, _)| path != std::path::Path::new("src/nsc/state.rs"))
        .flat_map(|(path, src)| {
            let count = src.matches(".arm_forced_attempt_after_pin()").count();
            std::iter::repeat_n(path, count)
        })
        .collect();
    assert_eq!(
        callers,
        vec![std::path::PathBuf::from("src/nsc/mod.rs")],
        "only nsc::unlock_after_verified_pin may call the Armed writer",
    );

    let charge_callers: Vec<_> = production_secure_rust_sources()
        .into_iter()
        .filter(|(path, _)| path != std::path::Path::new("src/nsc/state.rs"))
        .flat_map(|(path, src)| {
            let count = src
                .matches(".charge_forced_attempt_for_warning()")
                .count();
            std::iter::repeat_n(path, count)
        })
        .collect();
    assert_eq!(
        charge_callers,
        vec![std::path::PathBuf::from(
            "src/nsc/cmd_sign_userop_forced.rs",
        )],
        "only the terminal forced-userop route may consume the PIN-scoped attempt",
    );
}

#[test]
fn positive_forced_attempt_pin_wrapper_has_exact_three_real_pin_call_sites() {
    let callers: Vec<_> = production_secure_rust_sources()
        .into_iter()
        .flat_map(|(path, src)| {
            let count = src.matches("unlock_after_verified_pin(master)").count();
            std::iter::repeat_n(path, count)
        })
        .collect();

    let mut expected = vec![
        std::path::PathBuf::from("src/main.rs"),
        std::path::PathBuf::from("src/main.rs"),
        std::path::PathBuf::from("src/nsc/cmd_request_unlock.rs"),
    ];
    expected.sort();
    let mut callers = callers;
    callers.sort();
    assert_eq!(
        callers, expected,
        "only boot PIN, idle re-PIN, and CMD_REQUEST_UNLOCK may arm",
    );

    assert!(
        REQUEST_UNLOCK_SRC.contains("super::gated_unlock(se, pin)")
            && REQUEST_UNLOCK_SRC.contains("super::unlock_after_verified_pin(master)"),
        "CMD_REQUEST_UNLOCK must arm only inside gated_unlock success",
    );
    assert!(
        MAIN_SRC.matches("nsc::gated_unlock(").count() >= 2,
        "boot and PendSV must retain real gated PIN verification",
    );
}

#[test]
fn positive_forced_attempt_non_pin_unlocks_remain_generic_and_disarmed() {
    assert!(
        NSC_STATE_SRC.contains("self.forced_attempt.disarm();"),
        "generic mark_unlocked and zeroize must explicitly select Disarmed",
    );
    assert_eq!(
        MAIN_SRC.matches("nsc::unlock_with_master(master);").count(),
        1,
        "first-boot auto-unlock must remain the sole main.rs generic unlock",
    );
    assert!(
        NSC_MOD_SRC.contains("pub fn set_e2e_unlocked(master: [u8; 32])")
            && NSC_MOD_SRC.contains("state::with_state(|s| s.mark_unlocked(master));"),
        "e2e helper must use generic mark_unlocked and stay Disarmed",
    );
    assert!(
        TEST_PIN_LOCKOUT_SRC.contains("super::unlock_with_master(master_final);"),
        "the PIN-lockout test helper must remain generic/Disarmed",
    );
    assert!(
        !TEST_PIN_LOCKOUT_SRC.contains("unlock_after_verified_pin")
            && !TEST_PIN_LOCKOUT_SRC.contains("arm_forced_attempt_after_pin"),
        "test helpers must never arm a forced attempt",
    );
}

#[test]
fn positive_forced_attempt_charge_keeps_voted_cfi_readback_shape() {
    let start = NSC_STATE_SRC
        .find("pub(super) fn charge_forced_attempt_for_warning")
        .expect("forced-attempt charge primitive must exist");
    let body = &NSC_STATE_SRC[start..];
    let read_armed = body
        .find("let initial = self.phase();")
        .expect("charge must begin with a voted phase read");
    let write_spent = body
        .find("self.write_words(FORCED_ATTEMPT_SPENT_WORDS);")
        .expect("charge must publish the exact Spent codeword");
    let readback = body
        .find("let readback = self.phase();")
        .expect("charge must independently read back after publication");
    let cfi_check = body
        .find("cfi.check_into_sentinel(FORCED_CHARGE_CFI_EXPECTED)")
        .expect("charge must completion-check all CFI steps");
    assert!(
        read_armed < write_spent && write_spent < readback && readback < cfi_check,
        "charge order must remain voted Armed -> Spent -> voted readback -> CFI check",
    );
    assert!(
        body.contains("cfi.bump(FORCED_CHARGE_CFI_READ_ARMED);")
            && body.contains("cfi.bump(FORCED_CHARGE_CFI_WRITE_SPENT);")
            && body.contains("cfi.bump(FORCED_CHARGE_CFI_READBACK);"),
        "all three transition steps must remain in the CFI transcript",
    );
}

#[test]
fn positive_pre_commit_pattern_in_gated_unlock() {
    // The pin_attempts_bump() pre-commit before SE.unlock() is the
    // defense against the "glitch SE-side without burning MCU
    // attempts" attack. Removing it makes brute-force trivially
    // cheap.
    assert!(NSC_MOD_SRC.contains("pin_attempts_bump()"),
        "gated_unlock must pre-commit the page-124 bump before the SE call");
    assert!(NSC_MOD_SRC.contains("pin_attempts_reset_after_correct_pin()"),
        "gated_unlock must reset the page-124 counter on Ok");
}

#[test]
fn negative_gated_unlock_reset_failure_fails_closed() {
    // F17/SCAFI-5: the success arm must NOT swallow a page-124 reset
    // failure (`let _ = pin_attempts_reset()`). The counter was
    // pre-charged BEFORE the SE verify, so a silently-failed reset
    // leaves it charged after a CORRECT PIN — N good unlocks then
    // accumulate N markers → spurious lockout → lockout wipe. The
    // reset verdict must ride the FAIL-IN sentinel and refuse the
    // unlock (InternalError) on failure. Window is scoped to
    // gated_unlock so the (deliberate) best-effort discard in the
    // reconcile wipe path is not flagged.
    let start = NSC_MOD_SRC
        .find("pub unsafe fn gated_unlock")
        .expect("gated_unlock must exist");
    let end = NSC_MOD_SRC
        .find("/// Boot-time directional rollback check")
        .expect("gated_unlock body window must close before reconcile");
    let body = &NSC_MOD_SRC[start..end];
    assert!(
        body.contains(
            "let reset_result = crate::hw::flash::pin_attempts_reset_after_correct_pin();"
        ),
        "the success arm must bind the reset result, not discard it",
    );
    assert!(
        body.contains("check_true_into_sentinel(|| reset_result.is_ok())"),
        "the reset verdict must ride the FAIL-IN sentinel",
    );
    assert!(
        body.contains("return Err(UnlockError::InternalError);"),
        "a failed reset must refuse the unlock (fail-closed)",
    );
    // Scoped to the CORRECT-PIN reset. The duress-wipe arm's
    // `pin_attempts_reset_after_wipe` (#951) is discarded on purpose, as in
    // `trigger_lockout_wipe`: it refuses unless the salt is gone, and a
    // refusal leaves the counter charged, which is the safe direction.
    assert!(
        !body.contains("let _ = crate::hw::flash::pin_attempts_reset_after_correct_pin"),
        "F17/SCAFI-5: the success arm must not swallow pin_attempts_reset failure",
    );
    assert!(
        !body.contains("let _ = crate::hw::flash::pin_attempts_reset()"),
        "an unguarded reset must not appear in gated_unlock",
    );
}

#[test]
fn positive_gated_unlock_duress_first_dispatch() {
    // §32 P3: gated_unlock must try the DECOY credential first and only
    // fall through to the real unlock on no-match — the ordering that
    // lets the duress path SKIP the real verify (no E120 drift) while the
    // pad keeps timing uniform. Pin the dispatch shape in source.
    assert!(
        NSC_MOD_SRC.contains("se.unlock_duress(pin)"),
        "gated_unlock must attempt the duress credential (unlock_duress)",
    );
    assert!(
        NSC_MOD_SRC.contains("se.duress_pad(pin)"),
        "gated_unlock must run the timing pad on a duress match",
    );
    // The duress branch must be tried BEFORE the real unlock so a duress
    // match can skip the real verify. Verify unlock_duress appears before
    // the fall-through `se.unlock(pin)` in the dispatch.
    let dpos = NSC_MOD_SRC.find("se.unlock_duress(pin)").expect("unlock_duress present");
    let rpos = NSC_MOD_SRC[dpos..].find("Err(_) => se.unlock(pin)")
        .expect("real unlock must be the fall-through arm");
    assert!(rpos > 0, "real unlock must be the Err fall-through of unlock_duress");
}

#[test]
fn positive_gated_unlock_wipe_on_duress_branch() {
    // §32 P5: in wipe-on-duress mode, a duress match must WIPE
    // (factory_reset_admin) and return PinLocked — NOT open the decoy.
    assert!(
        NSC_MOD_SRC.contains("is_duress_wipe_mode()"),
        "gated_unlock must consult the wipe-on-duress flag on a duress match",
    );
    // The wipe branch must `factory_reset_admin()` then return
    // `Err(UnlockError::PinLocked)`. Between them the ONLY counter reset
    // allowed is the wipe-guarded one (#951, 2026-10-16): the same
    // `pin_attempts_reset_after_wipe` `trigger_lockout_wipe` runs, which
    // refuses unless the salt is verifiably gone. This pin used to forbid any
    // reset here ("confused state, leave it bumped"); it predates that guard,
    // and leaving the counter bumped is what made the next wallet start
    // short of attempts after a duress wipe from the boot or PendSV prompt.
    let wipe_pos = NSC_MOD_SRC.find("se.factory_reset_admin()")
        .expect("wipe-mode branch must factory_reset_admin");
    let after = &NSC_MOD_SRC[wipe_pos..];
    let locked_pos = after.find("Err(UnlockError::PinLocked)")
        .expect("wipe must be followed by PinLocked");
    let window = &after[..locked_pos];
    assert_eq!(
        window.matches("pin_attempts_reset").count(),
        1,
        "exactly one counter reset between the wipe and the PinLocked return",
    );
    assert!(
        window.contains("crate::hw::flash::pin_attempts_reset_after_wipe()"),
        "the reset after a duress wipe must be the salt-guarded one (#951)",
    );
}

#[test]
fn negative_gated_unlock_duress_decoy_is_explicit_sentinel_conditional() {
    // F26/LIFE-1 (cut point B): the decoy release (the attacker's
    // bypass target under coercion) must be the EXPLICIT conditional
    // riding the Hamming-distant sentinel; the wipe must be the
    // fall-through. The old `if wipe_mode { wipe } else { decoy }`
    // shape made decoy the fall-through — one glitch on the mode read
    // (or a skipped compare) silently downgraded wipe-on-duress to the
    // decoy wallet, the inverted FAIL-OUT shape the F-15 idiom bans.
    assert!(
        NSC_MOD_SRC.contains("let open_decoy = crate::fi::check_true_into_sentinel(|| {"),
        "the decoy release must ride check_true_into_sentinel",
    );
    assert!(
        NSC_MOD_SRC.contains("!crate::hw::flash::is_duress_wipe_mode()"),
        "the sentinel closure must (double-)read the fail-closed mode byte",
    );
    assert!(
        NSC_MOD_SRC.contains("if open_decoy == crate::fi::OK_SENTINEL {"),
        "decoy must be the explicit OK_SENTINEL conditional (wipe = fall-through)",
    );
    assert!(
        !NSC_MOD_SRC.contains("let wipe_mode = crate::hw::flash::is_duress_wipe_mode();"),
        "F26/LIFE-1: the bare-bool FAIL-OUT mode read must not come back",
    );
}

#[test]
fn positive_gated_unlock_is_unsafe_fn() {
    // Calling gated_unlock requires exclusive access to the static SE
    // driver — encoded as `unsafe fn` so a call site has to spell out
    // the soundness argument.
    assert!(NSC_MOD_SRC.contains("pub unsafe fn gated_unlock"),
        "gated_unlock must remain `unsafe fn` — exclusive SE access \
         is a precondition the caller MUST acknowledge");
}

#[test]
fn positive_gated_unlock_has_entry_jitter_before_the_gate() {
    // §18 P1 — the PIN gate is linear from external trigger to the
    // F-15 sentinel with no internal shuffle, so a profiled
    // single-fault attacker can glitch at a fixed offset. An entry
    // `wait_random()` desyncs that offset. It MUST sit before the
    // first `pin_attempts_read` (the start of the F-15 gate) so the
    // jitter actually covers the gate, not just trail it.
    let fn_start = NSC_MOD_SRC
        .find("pub unsafe fn gated_unlock")
        .expect("gated_unlock must exist");
    let body = &NSC_MOD_SRC[fn_start..];
    let first_wait = body
        .find("crate::fi::wait_random();")
        .expect("gated_unlock must call wait_random() for §18 entry jitter");
    let first_read = body
        .find("pin_attempts_read()")
        .expect("gated_unlock must read the page-124 counter");
    assert!(
        first_wait < first_read,
        "gated_unlock's entry-jitter wait_random() must precede the first \
         pin_attempts_read — otherwise the jitter trails the gate it's \
         meant to desync (§18 P1)"
    );
}

#[test]
fn positive_validate_ns_uses_f8_two_pass_pattern() {
    // F-8: the validator is called TWICE through
    // `check_true_into_sentinel`, with `wait_random()` between, before
    // a ReadPtr<T> / WritePtr<T> proof is constructed.
    let v1 = NSC_NS_PTR_SRC.matches("check_true_into_sentinel").count();
    let v2 = NSC_NS_PTR_SRC.matches("wait_random()").count();
    assert!(v1 >= 4,
        "ns_ptr must do TWO sentinel-encoded validations on EACH of \
         validate_read + validate_write (saw {v1} check_true_into_sentinel calls)");
    assert!(v2 >= 2,
        "ns_ptr must call wait_random() between the two validations \
         on each path (saw {v2})");
}

#[test]
fn positive_ptr_validate_uses_checked_add_for_overflow() {
    assert!(NSC_PTR_VALIDATE_SRC.contains("checked_add"),
        "ptr_validate must use checked_add to refuse u32 overflow");
}

#[test]
fn positive_ptr_validate_rejects_mailbox_overlap_explicitly() {
    // The overlap check is the load-bearing defense against the
    // mailbox-aliasing TOCTOU attack on the dispatcher.
    assert!(NSC_PTR_VALIDATE_SRC.contains("SHARED_MAILBOX_END")
        && NSC_PTR_VALIDATE_SRC.contains("SHARED_MAILBOX_BASE"),
        "ptr_validate must explicitly check the mailbox window");
}

#[test]
fn positive_ptr_validate_double_checks_sau_on_hardware() {
    // HIGH-1: the constant-window check is backed by an actual TT
    // (Test Target) ARMv8-M instruction query on real silicon. Both
    // validators must invoke it after the constant-window check.
    let occurrences = NSC_PTR_VALIDATE_SRC.matches("tt_range_is_ns").count();
    assert!(occurrences >= 3, // 1 cfg-gated impl + 2 callers
        "ptr_validate must invoke tt_range_is_ns from both read and write paths");
}

#[test]
fn positive_state_static_mut_lives_in_state_module_only() {
    // The whole point of `state.rs` is to be the unique
    // address-taking site for STATE — a `static mut` elsewhere in
    // `nsc/` would defeat that invariant. Scan every slice file
    // except state.rs.
    for (name, src) in ALL_SLICE_FILES {
        if *name == "nsc/state.rs" { continue; }
        assert!(!src.contains("static mut STATE"),
            "{name} must not declare `static mut STATE` — state.rs is \
             the unique address-taking site for SecureState");
    }
}

#[test]
fn positive_handler_depth_uses_atomic_u32() {
    // The earlier-version race (plain `static mut` depth, R-M-W
    // window where SysTick observed depth=0 mid-bump) is fixed by
    // using AtomicU32 with SeqCst fetch_add. Pinning the type +
    // ordering catches a refactor that drops back to a plain
    // counter.
    assert!(NSC_MOD_SRC.contains("AtomicU32::new(0)"),
        "HANDLER_DEPTH must remain AtomicU32 — see the race-window \
         postmortem in mod.rs");
    assert!(NSC_MOD_SRC.contains("fetch_add(1"),
        "HandlerGuard::enter must use fetch_add for the entry bump");
    assert!(NSC_MOD_SRC.contains("Ordering::SeqCst"),
        "HandlerGuard memory order must be SeqCst (single-threaded \
         secure world; SeqCst is the conservative choice)");
}

#[test]
fn positive_handler_drop_is_saturating() {
    // A `fetch_sub` would underflow if Drop ever ran more times than
    // enter. Even though that's structurally impossible in safe Rust,
    // the saturating CAS loop documents intent.
    assert!(NSC_MOD_SRC.contains("saturating_sub(1)"),
        "HandlerGuard::drop must use saturating_sub, not fetch_sub");
    assert!(NSC_MOD_SRC.contains("compare_exchange_weak"),
        "HandlerGuard::drop must CAS-loop to apply the saturating \
         decrement atomically");
}

// ─────────────────────────────────────────────────────────────────────
// 4. CLAUDE.md "What NOT to do" — algorithmic-policy negatives.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_slice_does_not_mention_forbidden_signer_algorithms() {
    // Invariant #5: one signature primitive (SPHINCS+C10). No
    // classical fallback anywhere in the firmware. The slice should
    // not even SAY ECDSA / Ed25519 / secp256k1 / FORS+C (other than
    // as a forbidden token in a comment).
    for (name, src) in ALL_SLICE_FILES {
        for forbidden in &["ecdsa", "secp256k1", "ed25519"] {
            // CLAUDE.md mentions some of these in negative-prose form;
            // here we just ensure no code path references them.
            assert!(!src.to_lowercase().contains(&format!("use {}", forbidden)),
                "{name} must not import {forbidden} — CLAUDE.md \"What NOT to do\"");
            assert!(!src.to_lowercase().contains(&format!("{}::", forbidden)),
                "{name} must not invoke {forbidden} — CLAUDE.md \"What NOT to do\"");
        }
    }
}

#[test]
fn negative_slice_does_not_expose_rotate_master_keys_path() {
    // Invariant #6: bootstrap C10 keys are immutable per-wallet.
    // There must be no `rotate_master_keys` / `reset_bootstrap_uses`
    // / `increase_max_*` symbol in the slice.
    for (name, src) in ALL_SLICE_FILES {
        for forbidden in &[
            "rotate_master_keys",
            "rotateMasterKeys",
            "reset_bootstrap_uses",
            "resetBootstrapUses",
            "reset_slot_uses",
            "resetSlotUses",
            "increase_max_",
            "increaseMax",
        ] {
            assert!(!src.contains(forbidden),
                "{name} must not contain `{forbidden}` (CLAUDE.md invariant #6/#7)");
        }
    }
}

#[test]
fn negative_dispatcher_does_not_admit_alloc_or_heap() {
    // Slice must remain stack-only — no Vec/Box/String creeping in
    // via a future refactor.
    for (name, src) in ALL_SLICE_FILES {
        for forbidden in &["Vec::new", "Vec::with_capacity", "Box::new", "String::new", "String::from", "alloc::"] {
            assert!(!src.contains(forbidden),
                "{name} must not use `{forbidden}` — slice is stack-only");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// 5. Cross-file regression: `is_unlocked` reflects state.
//
// Exercises the gateway-side accessor via the scaffold state module.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_is_unlocked_mirror_reflects_mark_unlocked() {
    // The "real" `is_unlocked` is `nsc::is_unlocked` which calls
    // `state::peek_state(|s| s.pin_verified.is_true_fi())`. We
    // exercise the exact predicate against the scaffolded state.
    // Imports brought in at module scope.
    let _g = state_test_lock();
    // Land in a known clean state.
    with_state(|s| s.zeroize_sensitive());
    assert!(!peek_state(|s| s.pin_verified.is_true_fi()),
        "fresh / zeroized state must read as locked");
    with_state(|s| s.mark_unlocked([0u8; 32]));
    assert!(peek_state(|s| s.pin_verified.is_true_fi()),
        "post-mark_unlocked the device must read as unlocked");
    with_state(|s| s.zeroize_sensitive());
    assert!(!peek_state(|s| s.pin_verified.is_true_fi()),
        "post-zeroize the device must read as locked again");
}

// ─────────────────────────────────────────────────────────────────────
// 6. Additional pointer-validation negatives — exercised through the
// raw predicates so future call sites that bypass NsPtr<T> still inherit
// these checks.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_raw_validate_read_rejects_address_past_ns_flash_end() {
    let p = NS_FLASH_END;
    assert!(!validate_ns_read_ptr(p, 1),
        "address at NS_FLASH_END with non-zero len MUST be rejected");
}

#[test]
fn negative_raw_validate_write_rejects_flash_range() {
    assert!(!validate_ns_write_ptr(NS_FLASH_BASE, 1),
        "NS flash MUST never be writable (read-only invariant)");
    assert!(!validate_ns_write_ptr(NS_FLASH_END - 1, 1));
}

#[test]
fn negative_raw_validate_rejects_cross_region_run() {
    // Start inside NS flash but extend past NS_FLASH_END (would cross
    // into the unmapped gap between flash and SRAM).
    let p = NS_FLASH_END - 4;
    assert!(!validate_ns_read_ptr(p, 8),
        "cross-region run from NS flash to gap MUST be refused");
}

#[test]
fn negative_typestate_read_into_slice_length_contract() {
    // ReadPtr::read_into_slice asserts `dst.len() == self.len()` —
    // confirms via NsPtr API that read validation produces a ReadPtr
    // with the exact length the caller asked for (so a downstream
    // length-mismatch is impossible in safe code without violating
    // the assert).
    let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE);
    let rp = p.validate_read(123).unwrap();
    assert_eq!(rp.len(), 123,
        "ReadPtr::len must equal the validated length verbatim");
}

#[test]
fn negative_typestate_write_length_matches_validation() {
    let p: NsPtr<u8> = NsPtr::new(NS_SRAM_BASE);
    let wp = p.validate_write(64).unwrap();
    assert_eq!(wp.len(), 64);
    assert!(!wp.is_empty());
}

// ─────────────────────────────────────────────────────────────────────
// 7. Production-build feature-gate fences (compile_error! blocks).
//
// These are pinned by source-text because cargo can't easily simulate
// the production cfg combination from a host test.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_production_build_blocks_dev_features() {
    // The compile_error! fence in nsc/mod.rs lists exactly which dev
    // features are forbidden on a `stm32u585 + !debug_assertions +
    // !e2e-test + !dev-testkey` build. CI gates on this — a refactor
    // that quietly drops an entry from the fence would let that
    // dev-only feature ship.
    let must_be_listed = &[
        "debug-log",
        "ui-semihosting",
        "ui-capture",
        "mock-se",
        "otp-hardcoded-master-key",
        "bhk-hardcoded-master-key",
        "saes-self-test",
        "uart-console",
        "boot-pulse",
        "se050-rotate-scp03",
        "sca-trigger",
    ];
    for feat in must_be_listed {
        assert!(NSC_MOD_SRC.contains(&format!("feature = \"{}\"", feat)),
            "production-build fence must continue to list `{feat}` (mod.rs compile_error!)");
    }
    // And the fence message itself must remain present.
    assert!(NSC_MOD_SRC.contains("compile_error!"),
        "production-build fence (compile_error!) must remain in nsc/mod.rs");
}

#[test]
fn positive_se_tunnel_ship_blocker_fences_present() {
    // audit se-tunnels 20260611 HIGH-1: a production SE050 build must REQUIRE
    // per-device derived SCP03 keys; without `se050-derived-scp03` the channel
    // authenticates with the published AN12436 factory keyset and a bus sniffer
    // decrypts `half_E`. Pin the fence by source so a refactor can't drop it.
    assert!(
        NSC_MOD_SRC.contains("not(feature = \"se050-derived-scp03\")")
            && NSC_MOD_SRC.contains("HIGH-1"),
        "nsc/mod.rs must keep the HIGH-1 se050-derived-scp03 production fence"
    );
    // audit se-tunnels 20260611 MEDIUM-1: `optiga-no-shield` (plaintext I2C,
    // bus-sniffable `half_O`) must not ship.
    assert!(
        NSC_MOD_SRC.contains("feature = \"optiga-no-shield\"")
            && NSC_MOD_SRC.contains("MEDIUM-1"),
        "nsc/mod.rs must keep the MEDIUM-1 optiga-no-shield production fence"
    );
}

#[test]
fn positive_otp_hardcoded_and_optiga_lock_operational_mutually_exclusive() {
    // The dedicated guard against the catastrophic combination
    // (hardcoded PBS + irreversible operational lock).
    assert!(NSC_MOD_SRC.contains("otp-hardcoded-master-key")
        && NSC_MOD_SRC.contains("optiga-lock-operational"),
        "nsc/mod.rs must keep the otp-hardcoded × optiga-lock fence");
}

#[test]
fn positive_legacy_otp_rollback_backend_blocks_production() {
    // STM32U585 OTP is programmed as complete 128-bit ECC quad-words. The
    // legacy rollback tally attempts to reprogram those QWs one bit at a time,
    // so the interface-freeze phase must remain fail-loud for shipping builds.
    assert!(
        NSC_MOD_SRC.contains("legacy firmware rollback")
            && NSC_MOD_SRC.contains("reprograms ECC-protected OTP quad-words")
            && NSC_MOD_SRC.contains("OPEN-JRN-HW/DUR")
            && NSC_MOD_SRC.contains("OPEN-ECC")
            && NSC_MOD_SRC.contains("OPEN-OTP"),
        "mode-production must stay blocked until an approved rollback backend replaces the invalid bitwise OTP tally"
    );
    assert!(
        NSC_MOD_SRC.contains(
            "#[cfg(all(feature = \"mode-production\", feature = \"stm32u585\"))]"
        ),
        "the rollback ship blocker must cover every STM32U585 production build"
    );
}

#[test]
fn positive_rdp2_self_lock_requires_explicit_production_mode() {
    assert!(
        NSC_MOD_SRC.contains(
            "#[cfg(all(feature = \"rdp2-self-lock\", not(feature = \"mode-production\")))]"
        ) && NSC_MOD_SRC.contains("RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION"),
        "the irreversible self-lock feature must fail compilation outside mode-production"
    );
}

#[test]
fn positive_ui_backend_mutually_exclusive_fences_present() {
    // Three pairwise compile_error! fences (semihosting × oled,
    // semihosting × noop, oled × noop). Count them.
    let pairs = NSC_MOD_SRC.matches("mutually exclusive").count();
    assert!(pairs >= 5,
        "mod.rs must keep ≥5 mutual-exclusion fences (UI + SE axes); saw {pairs}");
}

// ─────────────────────────────────────────────────────────────────────
// 8. Lifecycle: an unlock → zeroize → unlock cycle exposes no stale
// secret, and the closure-based accessor returns &mut SecureState
// (not a leaked pointer).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_zeroize_then_unlock_does_not_leak_prior_secret() {
    // Imports brought in at module scope.
    let _g = state_test_lock();
    with_state(|s| s.mark_unlocked([0x37u8; 32]));
    with_state(|s| s.zeroize_sensitive());
    // Verify intermediate state is zero before the next unlock.
    let interim = peek_state(|s| s.master_secret);
    assert_eq!(interim, [0u8; 32]);
    with_state(|s| s.mark_unlocked([0x99u8; 32]));
    let new_master = peek_state(|s| s.master_secret);
    assert_eq!(new_master, [0x99u8; 32]);
    // No byte of the previous secret should be observable.
    for b in new_master.iter() {
        assert_ne!(*b, 0x37,
            "no byte of the prior 0x37-pattern master may survive in BSS \
             across zeroize → re-unlock");
    }
}

#[test]
fn negative_with_state_closure_bounds_lifetime() {
    // Closure-based accessor: the mutable borrow cannot escape. We
    // demonstrate by extracting an owned snapshot inside the closure.
    let _g = state_test_lock();
    let snapshot: [u8; 32] = with_state(|s| s.master_secret);
    // `snapshot` is now an owned copy; no reference to `s` survives.
    let _ = snapshot;
}
