//! Factory provisioning state machine.
//!
//! **QUARANTINED LEGACY DESIGN.** Entry and completion attempt to program the
//! same one-write STM32U585 OTP QW. Every factory build is compile-blocked, no
//! receipt value grants RDP2 authority, and this module is retained only for
//! review/tests until a replacement ceremony is approved.
//!
//! The factory operator does NOT need to understand the failure —
//! they read the step + error code off the OLED and report it back.
//! The error codes map to known failure classes in
//! `docs/provisioning/factory-provisioning.md`.
//!
//! ## Output state (success path)
//!
//! After a successful run the chip has:
//!
//! - **STM32**: OTP master burned (one-time TRNG draw), BHK
//!   provisioned + flash-page-126 wrapped, page-124 PIN counter
//!   blank, TZ option bytes configured at flash time by the
//!   factory operator (separate STM32_Programmer_CLI step).
//! - **OPTIGA Trust M**: PBS at OID `E140` derived from the device
//!   secret hierarchy + paired via Shielded Connection; user-OID
//!   metadata (`F1D0..F1D9`) configured with `Conf(E140)` AC; LUC
//!   counter at `E120` configured. User OIDs are CLEARED — they
//!   get user-specific entropy/keys from the wizard later.
//! - **SE050**: SCP03 keys rotated from NXP defaults to derived
//!   per-device keys; admin UserID provisioned with the two-entry
//!   `TAG_POLICY` (user auth → full; admin auth → DELETE);
//!   canary object installed for the policy self-test. User
//!   UserID + entropy/VK objects CLEARED — wizard fills them
//!   later.
//!
//! ## End-user flow (after factory)
//!
//! 1. Power-on at home → `is_provisioned()` returns false (no
//!    user objects) → wizard runs.
//! 2. User enters PIN + generates / restores a mnemonic.
//! 3. `provision_from_mnemonic` writes user entropy + VK + PIN
//!    into the pre-configured SE infrastructure.
//! 4. Subsequent boots show the unlock prompt.
//!
//! ## Implementation pattern: provision-then-wipe
//!
//! The current SE drivers don't expose an "infrastructure-only"
//! provisioning path — `provision()` does both admin setup AND user
//! object storage in one call. To get factory-ready state today we
//! provision with deterministic-zero user state and then immediately
//! run `factory_reset_admin` which wipes user objects but preserves
//! admin/SCP03/PBS infrastructure. The dummy user state never leaves
//! the secure world.
//!
//! A future refactor could split the SE drivers' provision into
//! `factory_provision()` (infrastructure only) + `user_provision()`
//! (user state only). Until then, provision-then-wipe is the
//! simplest correct path.

#![cfg(feature = "factory-provisioning")]

// ---------------------------------------------------------------------------
// Compile-time fence — refuse to build a factory image that would
// permanently burn chip state UNLESS the user explicitly opts in via
// `factory-production-irreversible-im-sure`.
//
// What's caught:
//   - `optiga-lock-operational`: bumps OPTIGA OIDs to LcsO=Op
//     (one-way per the OPTIGA SRM).
//   - `bhk` without `bhk-hardcoded-master-key`: TRNG-burns + flash-
//     writes + BHKLOCKs the per-die BHK.
//   - No `dev-testkey` AND no `otp-hardcoded-master-key`: triggers
//     the production OTP master-key burn (one-way per the STM32U5
//     OTP spec).
//
// This is a *foot-gun guard*, not a security gate — anyone who can
// add `factory-production-irreversible-im-sure` to the build can
// also remove it. The point is to make the irreversible build
// profile something the user has to deliberately type, not something
// they can stumble into by forgetting `dev-testkey` in a Makefile
// target.
// ---------------------------------------------------------------------------

#[cfg(all(
    not(feature = "factory-production-irreversible-im-sure"),
    any(
        feature = "optiga-lock-operational",
        feature = "bhk",
        not(any(feature = "dev-testkey", feature = "otp-hardcoded-master-key")),
    )
))]
compile_error!(
    "factory-provisioning would burn IRREVERSIBLE chip state without an explicit \
     `factory-production-irreversible-im-sure` opt-in. \
     One or more of: `optiga-lock-operational`, `bhk`, or a production OTP-master path \
     (neither `dev-testkey` nor `otp-hardcoded-master-key`) is enabled. \
     Add `factory-production-irreversible-im-sure` to acknowledge the chip-state changes \
     are permanent, OR add `dev-testkey` to the build for dev iteration."
);

use crate::secure_element::WalletStore;
use crate::ui::{display, ascii_str};

// ---------------------------------------------------------------------------
// Step + error enumeration
// ---------------------------------------------------------------------------

// Pure surface lives in `crate::factory_ui` so it is host-testable; re-exported
// here so `FactoryStep` / `FactoryErrorCode` keep their published paths.
pub use crate::factory_ui::{FactoryErrorCode, FactoryStep};
use crate::factory_ui::{format_step_err, DISPLAY_COLS};


// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------


/// Show a step-progress panel:
/// ```
///   FACTORY PROVISION
///   [X/N] LABEL
///   running...
///
/// ```
fn show_step_running(step: FactoryStep) {
    let d = display();
    d.clear();
    d.draw_line(0, " FACTORY PROVIS ");

    let mut row1 = [b' '; DISPLAY_COLS];
    row1[0] = b'[';
    row1[1] = b'0' + step.number();
    row1[2] = b'/';
    row1[3] = b'0' + FactoryStep::total();
    row1[4] = b']';
    row1[5] = b' ';
    let label = step.label().as_bytes();
    let max = core::cmp::min(label.len(), DISPLAY_COLS - 6);
    row1[6..6 + max].copy_from_slice(&label[..max]);
    d.draw_line(1, ascii_str(&row1));

    d.draw_line(2, "running...");
    d.draw_line(3, "");
    d.flush();
}

/// Show the failure panel and halt forever in WFI.
fn halt_with_failure(step: FactoryStep, code: FactoryErrorCode) -> ! {
    secure_log!(
        "[FACTORY] FAIL step={:?} code=0x{:04X} hint={}",
        step,
        code.raw(),
        code.hint()
    );

    let d = display();
    d.clear();
    d.draw_line(0, "  FACTORY FAIL  ");

    // Row 1: "STEP X/N ERR XXXX"
    let mut row1 = [b' '; DISPLAY_COLS];
    let s = format_step_err(step, code, &mut row1);
    d.draw_line(1, s);

    // Row 2: short hint
    d.draw_line(2, code.hint());

    // Row 3: instruct operator to report.
    d.draw_line(3, " REPORT VENDOR ");
    d.flush();

    loop {
        cortex_m::asm::wfi();
    }
}

/// Fail closed if this quarantined path is ever reached despite its build
/// fences. No display from this module may grant factory/ship authority.
fn halt_with_success() -> ! {
    secure_log!("[FACTORY] LEGACY PATH BLOCKED");

    let d = display();
    d.clear();
    d.draw_line(0, " LEGACY BLOCKED ");
    d.draw_line(1, "RECEIPT INVALID ");
    d.draw_line(2, " NO AUTHORITY   ");
    d.draw_line(3, " NOT FOR SHIP   ");

    d.flush();

    loop {
        cortex_m::asm::wfi();
    }
}


// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Run the factory ceremony to completion or first failure. Never
/// returns.
///
/// # Safety contract
///
/// Caller must have already done the standard secure-world boot
/// path up to the point where `ui::init()` has completed and the
/// global `SE` (`DualSecureElement`) is initialized. We do NOT do
/// any of the pre-init work here — calling this function before
/// the SEs are alive is undefined.
pub fn run_and_halt(se: &mut dyn WalletStore) -> ! {
    secure_log!("[FACTORY] ===== begin =====");

    // Sentinel: mark "ceremony entered" before step 1. The host
    // fixture's polling loop watches OTP for this bit to distinguish
    // "chip never started ceremony" (sentinel = 0xFFFFFFFF) from
    // "ceremony started, may be in progress or stalled at a failure
    // panel" (sentinel = 0xFFFFFFFE). Failure to write the entry
    // sentinel is silent — the operator still sees the FAIL panel on
    // OLED if the ceremony actually crashes. We don't want a stuck
    // OTP write to brick the ceremony before it's even started.
    //
    // The full ceremony-complete sentinel (bit 1 OR bit 2) is written
    // at step 7 once all checks have passed. The host fixture treats:
    //   0xFFFFFFFF  → didn't start
    //   0xFFFFFFFE  → started, halted at failure panel
    //   0xFFFFFFFC  → started + rehearsal completed
    //   0xFFFFFFFA  → legacy production bits (quarantined; no RDP2 authority)
    //   0xFFFFFFF8  → legacy combined bits (quarantined; no RDP2 authority)
    let _ = unsafe {
        crate::hw::otp::factory_sentinel_record(
            crate::hw::otp::FACTORY_SENTINEL_BIT_RAN,
        )
    };

    // Step 1: hardware self-test.
    // Currently delegates to the existing SAES self-test path under
    // `saes-self-test`. If that feature isn't compiled in, the step
    // passes trivially — the wallet still works without it. A future
    // hardening pass should make Tier-1 + Tier-2 self-tests
    // mandatory in factory builds (require the features in the
    // `factory-provisioning` Cargo deps).
    show_step_running(FactoryStep::HardwareSelfTest);
    if let Err(code) = step_hardware_self_test() {
        halt_with_failure(FactoryStep::HardwareSelfTest, code);
    }

    // Step 2: OTP master key.
    show_step_running(FactoryStep::OtpMasterKey);
    if let Err(code) = step_otp_master_key() {
        halt_with_failure(FactoryStep::OtpMasterKey, code);
    }

    // Step 3: pre-populated state check.
    show_step_running(FactoryStep::PrePopulatedStateCheck);
    if let Err(code) = step_pre_populated_state_check(se) {
        halt_with_failure(FactoryStep::PrePopulatedStateCheck, code);
    }

    // Step 4: dual-SE provisioning with deterministic-zero user state.
    show_step_running(FactoryStep::DualSeProvisionInfrastructure);
    if let Err(code) = step_dual_se_provision_infrastructure(se) {
        halt_with_failure(FactoryStep::DualSeProvisionInfrastructure, code);
    }

    // Step 5: wipe the dummy user state we just wrote.
    show_step_running(FactoryStep::WipeUserState);
    if let Err(code) = step_wipe_user_state(se) {
        halt_with_failure(FactoryStep::WipeUserState, code);
    }

    // Step 6: post-wipe cross-validation.
    show_step_running(FactoryStep::PostWipeValidation);
    if let Err(code) = step_post_wipe_validation(se) {
        halt_with_failure(FactoryStep::PostWipeValidation, code);
    }

    // Step 7: write the OTP sentinel for the host-side factory
    // fixture to read before boxing the unit (per work-todo #36 there
    // is no fixture RDP2 bump; the device self-locks at first field
    // boot).
    show_step_running(FactoryStep::WriteOtpSentinel);
    if let Err(code) = step_write_otp_sentinel() {
        halt_with_failure(FactoryStep::WriteOtpSentinel, code);
    }

    secure_log!("[FACTORY] ===== all steps OK =====");
    halt_with_success();
}

// ---------------------------------------------------------------------------
// Step bodies
// ---------------------------------------------------------------------------

fn step_hardware_self_test() -> Result<(), FactoryErrorCode> {
    // The Tier-1 (SAES-DHUK) + Tier-2 (BHK) self-tests are gated
    // behind their own features (`saes-self-test`, `bhk`). When
    // those features are present the boot path already invokes them
    // and halts on failure before reaching this function. So the
    // factory ceremony's "step 1" is really a sanity guard: if we
    // got here, the prior init blocks already passed.
    //
    // Future hardening: add an explicit re-validation here that
    // SAES KEYVALID is set and that the BHK fingerprint matches a
    // pre-recorded factory-line expectation. Defer to the §22
    // attestation work — the manifest signed by the factory HSM
    // will record the BHK fingerprint as part of the device-binding
    // record.
    Ok(())
}

fn step_otp_master_key() -> Result<(), FactoryErrorCode> {
    // Under `dev-testkey` / `otp-hardcoded-master-key`, the OTP
    // master is a compile-time constant — no burn happens at boot.
    // Under the production path, `hw::otp::ensure_device_master()`
    // burns 32 random bytes to OTP on first boot. Either way, we
    // verify the master is in the expected state for THIS build
    // profile.
    //
    // Today the existing boot path calls `ensure_device_master` as
    // needed and panics on hardware fault. So we treat this step as
    // "got here → previous code already validated". A future
    // hardening would explicitly probe the OTP region and surface
    // a structured error rather than relying on the panic path.
    Ok(())
}

fn step_pre_populated_state_check(se: &mut dyn WalletStore) -> Result<(), FactoryErrorCode> {
    // Refuse to re-provision a chip that already has user data.
    //
    // Two cases this catches:
    //   (a) Customer chip mistakenly flashed with factory firmware
    //       — would wipe their wallet on the dummy-provision step.
    //   (b) Re-running the factory firmware on a chip that's
    //       already been through it — we'd be doing the work twice
    //       and the user state from the prior run would already
    //       have been wiped, but a fresh `provision()` on
    //       already-provisioned chips can fail in subtle ways
    //       (see the wipe-for-wizard predicate comments).
    //
    // Simplest correct gate: `is_provisioned()` MUST be false on a
    // fresh chip. If the customer wants to re-run factory firmware
    // on a chip that's been used, they run `make wipe-for-wizard`
    // first to clear user state explicitly.
    //
    // Additional gate via the OTP sentinel: if the chip's OTP shows
    // `BIT_PRODUCTION` already cleared, we've already completed a
    // production run on this chip. Refuse to re-run. The host
    // fixture should not be replaying production firmware against a
    // shipped-and-returned chip.
    if se.is_provisioned() {
        return Err(FactoryErrorCode::AlreadyUserProvisioned);
    }

    #[cfg(not(feature = "factory-provisioning-rehearsal"))]
    {
        // Production mode: check the OTP sentinel. If
        // BIT_PRODUCTION is already cleared, we've been here
        // before — refuse to re-run. Rehearsal mode is allowed to
        // re-run since it doesn't change SE state.
        let sentinel = crate::hw::otp::factory_sentinel_read();
        if (sentinel & crate::hw::otp::FACTORY_SENTINEL_BIT_PRODUCTION) == 0 {
            return Err(FactoryErrorCode::SentinelAlreadyProduction);
        }
    }

    Ok(())
}

fn step_dual_se_provision_infrastructure(
    se: &mut dyn WalletStore,
) -> Result<(), FactoryErrorCode> {
    // REHEARSAL MODE: skip the actual provision call. The panel
    // sequence still renders so the operator can validate the OLED
    // layout, but no SE-side state is mutated. Useful for dev
    // iteration without burning chip cycles.
    #[cfg(feature = "factory-provisioning-rehearsal")]
    {
        let _ = se;
        secure_log!("[FACTORY] step 4 SKIPPED (rehearsal mode)");
        return Ok(());
    }

    // Provision with deterministic-zero user state.
    //
    // The four secrets we pass through (`entropy`, `master_secret`,
    // `vk`, `bootstrap_vk`, `pin`) are all-zero placeholders. They
    // are stored on the SEs by `provision()` but immediately wiped
    // by step 5's `factory_reset_admin`. The SEs end up with:
    //   - admin UserID installed (SE050) — survives the wipe
    //   - SCP03 keys rotated (SE050) — survives the wipe
    //   - PBS at E140 (OPTIGA) — survives the wipe
    //   - user OIDs F1Dx populated with zero bytes — wiped
    //   - canary object — survives the wipe
    //
    // The zero user state never leaves the secure world during this
    // window (no semihosting output of these values), and is
    // overwritten by `factory_reset_admin` immediately after.
    //
    // We log the OPTIGA error class via `secure_log!` for our own
    // post-mortem, but the operator just sees a single
    // DualSeProvisionFailed code (or a sub-classified code if we
    // identified the failure mode further upstream).
    #[cfg(not(feature = "factory-provisioning-rehearsal"))]
    {
        let entropy = [0u8; 32];
        let master_secret = [0u8; 32];
        let vk = [0u8; 32];
        let bootstrap_vk = [0u8; 32];
        let pin = [0u8; 8];

        match se.provision(&entropy, &master_secret, &vk, &bootstrap_vk, &pin) {
            Ok(()) => Ok(()),
            Err(e) => {
                secure_log!("[FACTORY] provision returned {:?}", e);
                // Future: pattern-match `e` to surface
                // OptigaHandshakeFailed or Se050Scp03RotationFailed
                // when those specific failure modes are detectable.
                // Today DualSecureElement maps every sub-failure to
                // SeError::InternalError, so we collapse here.
                Err(FactoryErrorCode::DualSeProvisionFailed)
            }
        }
    }
}

fn step_wipe_user_state(se: &mut dyn WalletStore) -> Result<(), FactoryErrorCode> {
    // REHEARSAL MODE: skip the wipe (step 4 didn't write anything to
    // wipe).
    #[cfg(feature = "factory-provisioning-rehearsal")]
    {
        let _ = se;
        secure_log!("[FACTORY] step 5 SKIPPED (rehearsal mode)");
        return Ok(());
    }

    // factory_reset_admin wipes user objects on both SEs, preserves
    // admin / SCP03 / PBS / metadata. After this step, the SEs are
    // "factory ready": SE infrastructure in place, no user data.
    #[cfg(not(feature = "factory-provisioning-rehearsal"))]
    {
        match se.factory_reset_admin() {
            Ok(()) => Ok(()),
            Err(e) => {
                secure_log!("[FACTORY] factory_reset_admin returned {:?}", e);
                Err(FactoryErrorCode::WipeFailed)
            }
        }
    }
}

fn step_post_wipe_validation(se: &mut dyn WalletStore) -> Result<(), FactoryErrorCode> {
    // REHEARSAL MODE: nothing was wiped, so nothing to validate.
    // We still call is_provisioned() to exercise the read path on
    // the SEs — that's the kind of basic communication smoke check
    // that benefits from being run on every ceremony, rehearsal or
    // not.
    #[cfg(feature = "factory-provisioning-rehearsal")]
    {
        let _ = se.is_provisioned();
        secure_log!("[FACTORY] step 6 in rehearsal mode (read-only smoke check)");
        return Ok(());
    }

    #[cfg(not(feature = "factory-provisioning-rehearsal"))]
    {
        // After the wipe, `is_provisioned()` must return false (the
        // user objects on both SEs were the only thing keeping it
        // true). If it's still true, the wipe was incomplete.
        if se.is_provisioned() {
            return Err(FactoryErrorCode::UserResidueAfterWipe);
        }

        // Future hardening: verify the admin UserID is still
        // reachable by attempting an `iterative_wipe` no-op against
        // a known stale OID — should return "not found" rather than
        // "access denied", which would prove the admin policy is
        // functional. Today we trust the readback inside
        // factory_reset_admin (`if !self.admin_exists() { erase
        // admin page }`).
        Ok(())
    }
}

fn step_write_otp_sentinel() -> Result<(), FactoryErrorCode> {
    // Compose the bits to clear based on build mode. Rehearsal mode
    // clears BIT_RAN | BIT_REHEARSAL; production mode clears BIT_RAN
    // | BIT_PRODUCTION. Both modes set BIT_RAN so the host fixture
    // can distinguish "ceremony at least attempted" from "fresh
    // chip".
    #[cfg(feature = "factory-provisioning-rehearsal")]
    let bits = crate::hw::otp::FACTORY_SENTINEL_BIT_RAN
        | crate::hw::otp::FACTORY_SENTINEL_BIT_REHEARSAL;
    #[cfg(not(feature = "factory-provisioning-rehearsal"))]
    let bits = crate::hw::otp::FACTORY_SENTINEL_BIT_RAN
        | crate::hw::otp::FACTORY_SENTINEL_BIT_PRODUCTION;

    // SAFETY: factory_sentinel_record commits one OTP quad-word. The
    // irreversibility contract is documented at the call site doc-
    // comment above. We're in the factory ceremony's final step —
    // every prior step has passed, so this is the one-way
    // commitment that says "this chip went through factory".
    match unsafe { crate::hw::otp::factory_sentinel_record(bits) } {
        Ok(()) => Ok(()),
        Err(e) => {
            secure_log!("[FACTORY] factory_sentinel_record returned {:?}", e);
            Err(FactoryErrorCode::SentinelWriteFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// Host tests — pure-logic helpers (format strings, enum invariants)
// ---------------------------------------------------------------------------

// The pure step/error/format surface moved to `secure/src/factory_ui.rs`
// (#723), together with the six tests that used to sit here and could never
// run: this module is `#![cfg(feature = "factory-provisioning")]`, that
// feature pulls in `stm32u585`, and `crate::hw` / `crate::fw_update` /
// `crate::ui` are all `#[cfg(not(test))]` — so the module does not compile
// host-side even with its own feature enabled.
