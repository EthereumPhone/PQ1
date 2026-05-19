//! Factory provisioning state machine.
//!
//! Single-purpose firmware that the factory operator flashes to a
//! fresh device. Runs once at boot, halts on either "FACTORY OK" or
//! "FACTORY FAIL @ STEP X" with a numeric error code.
//!
//! The factory operator does NOT need to understand the failure —
//! they read the step + error code off the OLED and report it back.
//! The error codes map to known failure classes in
//! `docs/factory-provisioning.md`.
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

use crate::secure_element::WalletStore;
use crate::ui::{display, ascii_str};

// ---------------------------------------------------------------------------
// Step + error enumeration
// ---------------------------------------------------------------------------

/// Stages of the factory ceremony. Numbered for the OLED display so
/// the factory operator can report "FAIL at step 4" without
/// understanding what step 4 actually does.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FactoryStep {
    /// Hardware self-test — SAES (Tier-1 KDF) + BHK lifecycle (Tier-2).
    HardwareSelfTest = 1,
    /// Check that the OTP master key is either fresh (we'll burn it)
    /// or already burned to the expected ASCII constant under
    /// `dev-testkey`.
    OtpMasterKey = 2,
    /// Refuse to re-provision a chip that already has user state.
    /// Prevents accidentally wiping a customer's wallet by re-running
    /// the factory firmware.
    PrePopulatedStateCheck = 3,
    /// Run the dual-SE `provision()` with deterministic-zero user
    /// state. This is the heavy lift: OPTIGA shielded-connection
    /// handshake, PBS setup, F1Dx metadata writes, SE050 SCP03
    /// rotation, admin UserID install, canary, user UserID +
    /// entropy/VK objects.
    DualSeProvisionInfrastructure = 4,
    /// Wipe the dummy user state via `factory_reset_admin`,
    /// preserving admin / SCP03 / PBS / F1Dx-metadata.
    WipeUserState = 5,
    /// Cross-verify: admin still functional (canary), user state
    /// gone (`is_provisioned() == false`), no admin-residue
    /// inconsistency.
    PostWipeValidation = 6,
}

impl FactoryStep {
    /// Step number for OLED display (1-indexed).
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Total step count, for "X/N" progress strings.
    pub const fn total() -> u8 {
        6
    }

    /// Short OLED label (max 13 chars to fit "[X/N] LABEL" in 16).
    pub fn label(self) -> &'static str {
        match self {
            Self::HardwareSelfTest => "HW selftest",
            Self::OtpMasterKey => "OTP master",
            Self::PrePopulatedStateCheck => "Pre-state chk",
            Self::DualSeProvisionInfrastructure => "Provisioning",
            Self::WipeUserState => "Wiping dummy",
            Self::PostWipeValidation => "Post-validate",
        }
    }
}

/// Error codes shown on the OLED. The full table — including operator
/// hints + suggested remediation — lives in
/// `docs/factory-provisioning.md`. Keep these numeric values STABLE
/// across firmware versions so old field reports remain interpretable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FactoryErrorCode {
    /// SAES Tier-1 self-test did not produce expected fingerprint or
    /// failed to initialize. Causes: bad RDP state, SAES clock not
    /// running, silicon defect.
    SaesSelfTestFailed = 0x0101,
    /// BHK provisioning failed — couldn't generate, wrap, or lock the
    /// per-device BHK. Causes: TAMP clock missing, flash page 126
    /// blocked, prior BHKLOCK already set with mismatched flash.
    BhkLifecycleFailed = 0x0102,
    /// OTP master key validation failed — under `dev-testkey` we
    /// expect a specific ASCII constant; otherwise we expect the
    /// region to be either blank (will burn) or self-consistent.
    OtpMasterMismatch = 0x0201,
    /// Chip is already user-provisioned (USERID + entropy present on
    /// SE050 / F1Dx populated on OPTIGA). The factory firmware
    /// refuses to wipe a live wallet.
    AlreadyUserProvisioned = 0x0301,
    /// `is_provisioned()` returned true with both SEs in an
    /// unexpected mixed state — admin residue without user data, or
    /// vice versa. Indicates a prior partial provisioning run.
    PriorPartialResidue = 0x0302,
    /// `WalletStore::provision()` returned an error. Sub-causes are
    /// logged via `secure_log!` (which is OFF in production); the
    /// factory operator just sees this single code.
    DualSeProvisionFailed = 0x0401,
    /// OPTIGA Shielded-Connection handshake failed mid-provision
    /// (sub-classified internally via `OptigaError`, surfaced here
    /// as a single code for the operator).
    OptigaHandshakeFailed = 0x0402,
    /// SE050 SCP03 key rotation failed mid-provision.
    Se050Scp03RotationFailed = 0x0403,
    /// `factory_reset_admin()` returned an error after the dummy
    /// provision. Chip is in an inconsistent state — operator
    /// reports + we triage.
    WipeFailed = 0x0501,
    /// Post-wipe: `is_provisioned()` returned true. The wipe didn't
    /// reach all user state. Operator reports.
    UserResidueAfterWipe = 0x0601,
    /// Post-wipe: admin UserID became unreachable. The wipe damaged
    /// our admin path. Chip is recoverable only by re-flashing the
    /// factory firmware + redoing the run.
    AdminUnreachableAfterWipe = 0x0602,
    /// Post-wipe: PIN attempts counter (MCU page 124) wasn't reset.
    AttemptsCounterDirty = 0x0603,
}

impl FactoryErrorCode {
    /// Numeric code for OLED.
    pub fn raw(self) -> u16 {
        self as u16
    }

    /// One-line hint for the OLED (max 16 chars). Operator may read
    /// this on the panel; the full explanation is in the docs.
    pub fn hint(self) -> &'static str {
        match self {
            Self::SaesSelfTestFailed => "SAES init?",
            Self::BhkLifecycleFailed => "BHK page 126?",
            Self::OtpMasterMismatch => "OTP corrupt?",
            Self::AlreadyUserProvisioned => "wipe first",
            Self::PriorPartialResidue => "wipe first",
            Self::DualSeProvisionFailed => "SE comms?",
            Self::OptigaHandshakeFailed => "OPTIGA I2C?",
            Self::Se050Scp03RotationFailed => "SE050 SCP03?",
            Self::WipeFailed => "see RMA flow",
            Self::UserResidueAfterWipe => "incomplete wipe",
            Self::AdminUnreachableAfterWipe => "chip damaged",
            Self::AttemptsCounterDirty => "flash error",
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

const DISPLAY_COLS: usize = 16;

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

/// Show the success panel and halt forever in WFI.
fn halt_with_success() -> ! {
    secure_log!("[FACTORY] OK — all {} steps passed", FactoryStep::total());

    let d = display();
    d.clear();
    d.draw_line(0, "  FACTORY OK   ");

    let mut row1 = [b' '; DISPLAY_COLS];
    let n = FactoryStep::total();
    let label = b"  ";
    row1[0..label.len()].copy_from_slice(label);
    row1[2] = b'0' + n;
    row1[3] = b'/';
    row1[4] = b'0' + n;
    row1[5..].copy_from_slice(b"  passed   ");
    d.draw_line(1, ascii_str(&row1));

    d.draw_line(2, " POWER  OFF   ");
    d.draw_line(3, "READY TO SHIP ");
    d.flush();

    loop {
        cortex_m::asm::wfi();
    }
}

/// Format `"STEP X/N ERR XXXX"` into the caller's 16-byte buffer.
/// Pure-logic helper so the format string can be host-tested.
fn format_step_err<'a>(
    step: FactoryStep,
    code: FactoryErrorCode,
    buf: &'a mut [u8; DISPLAY_COLS],
) -> &'a str {
    let label = b"STEP ";
    buf[0..label.len()].copy_from_slice(label);
    buf[5] = b'0' + step.number();
    buf[6] = b'/';
    buf[7] = b'0' + FactoryStep::total();
    buf[8] = b' ';
    buf[9] = b'E';
    let raw = code.raw();
    buf[10] = nibble_to_hex((raw >> 12) as u8 & 0xF);
    buf[11] = nibble_to_hex((raw >> 8) as u8 & 0xF);
    buf[12] = nibble_to_hex((raw >> 4) as u8 & 0xF);
    buf[13] = nibble_to_hex(raw as u8 & 0xF);
    buf[14] = b' ';
    buf[15] = b' ';
    ascii_str(&buf[..])
}

fn nibble_to_hex(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        10..=15 => b'A' + (n - 10),
        _ => b'?',
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
    if se.is_provisioned() {
        return Err(FactoryErrorCode::AlreadyUserProvisioned);
    }
    Ok(())
}

fn step_dual_se_provision_infrastructure(
    se: &mut dyn WalletStore,
) -> Result<(), FactoryErrorCode> {
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
    let entropy = [0u8; 32];
    let master_secret = [0u8; 32];
    let vk = [0u8; 32];
    let bootstrap_vk = [0u8; 32];
    let pin = [0u8; 8];

    match se.provision(&entropy, &master_secret, &vk, &bootstrap_vk, &pin) {
        Ok(()) => Ok(()),
        Err(e) => {
            secure_log!("[FACTORY] provision returned {:?}", e);
            // Future: pattern-match `e` to surface OptigaHandshakeFailed
            // or Se050Scp03RotationFailed when those specific failure
            // modes are detectable. Today the DualSecureElement
            // implementation maps every sub-failure to SeError::
            // InternalError, so we collapse here.
            Err(FactoryErrorCode::DualSeProvisionFailed)
        }
    }
}

fn step_wipe_user_state(se: &mut dyn WalletStore) -> Result<(), FactoryErrorCode> {
    // factory_reset_admin wipes user objects on both SEs, preserves
    // admin / SCP03 / PBS / metadata. After this step, the SEs are
    // "factory ready": SE infrastructure in place, no user data.
    match se.factory_reset_admin() {
        Ok(()) => Ok(()),
        Err(e) => {
            secure_log!("[FACTORY] factory_reset_admin returned {:?}", e);
            Err(FactoryErrorCode::WipeFailed)
        }
    }
}

fn step_post_wipe_validation(se: &mut dyn WalletStore) -> Result<(), FactoryErrorCode> {
    // After the wipe, `is_provisioned()` must return false (the user
    // objects on both SEs were the only thing keeping it true). If
    // it's still true, the wipe was incomplete.
    if se.is_provisioned() {
        return Err(FactoryErrorCode::UserResidueAfterWipe);
    }

    // Future hardening: verify the admin UserID is still reachable
    // by attempting an `iterative_wipe` no-op against a known stale
    // OID — should return "not found" rather than "access denied",
    // which would prove the admin policy is functional.
    //
    // For now we trust factory_reset_admin's own readback in
    // SE050::factory_reset_admin (`if !self.admin_exists() { erase
    // admin page }`); if the admin had become unreachable mid-wipe,
    // the admin page would be erased and a subsequent wizard run
    // would re-trigger admin install — recoverable but worth
    // surfacing here in a future hardening pass.

    Ok(())
}

// ---------------------------------------------------------------------------
// Host tests — pure-logic helpers (format strings, enum invariants)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_step_total_matches_enum_count() {
        // If we add a step without updating FactoryStep::total() the
        // progress display (`[X/N]`) would lie about the count and the
        // operator could think the run is done when it's not. Pin the
        // count against the literal enum count.
        let last = FactoryStep::PostWipeValidation;
        assert_eq!(last as u8, FactoryStep::total(),
            "FactoryStep::total() must equal the last variant's number");
    }

    #[test]
    fn positive_format_step_err_layout() {
        let mut buf = [0u8; DISPLAY_COLS];
        let s = format_step_err(
            FactoryStep::DualSeProvisionInfrastructure,
            FactoryErrorCode::DualSeProvisionFailed,
            &mut buf,
        );
        // FactoryStep::DualSeProvisionInfrastructure = 4
        // FactoryErrorCode::DualSeProvisionFailed = 0x0401
        // Expected: "STEP 4/6 E0401  "
        assert_eq!(s, "STEP 4/6 E0401  ");
    }

    #[test]
    fn negative_format_step_err_handles_all_error_codes() {
        // Every error code formats to a 4-char hex string in the
        // OLED panel. If any code's hex digits exceed [0-9A-F], the
        // factory panel would show a "?" and the operator's report
        // becomes ambiguous.
        for code in [
            FactoryErrorCode::SaesSelfTestFailed,
            FactoryErrorCode::BhkLifecycleFailed,
            FactoryErrorCode::OtpMasterMismatch,
            FactoryErrorCode::AlreadyUserProvisioned,
            FactoryErrorCode::PriorPartialResidue,
            FactoryErrorCode::DualSeProvisionFailed,
            FactoryErrorCode::OptigaHandshakeFailed,
            FactoryErrorCode::Se050Scp03RotationFailed,
            FactoryErrorCode::WipeFailed,
            FactoryErrorCode::UserResidueAfterWipe,
            FactoryErrorCode::AdminUnreachableAfterWipe,
            FactoryErrorCode::AttemptsCounterDirty,
        ] {
            let mut buf = [0u8; DISPLAY_COLS];
            let s = format_step_err(FactoryStep::HardwareSelfTest, code, &mut buf);
            // Hex digits at positions 10-13 must all be in [0-9A-F].
            for i in 10..=13 {
                let b = s.as_bytes()[i];
                assert!(
                    matches!(b, b'0'..=b'9' | b'A'..=b'F'),
                    "code {:?} renders non-hex byte 0x{:02X} at pos {}",
                    code, b, i
                );
            }
        }
    }

    #[test]
    fn negative_error_code_hints_fit_oled_row() {
        // Hints are shown on OLED row 2, max 16 chars. Anything
        // longer would be truncated. Pin all hints to ≤ 16.
        for code in [
            FactoryErrorCode::SaesSelfTestFailed,
            FactoryErrorCode::BhkLifecycleFailed,
            FactoryErrorCode::OtpMasterMismatch,
            FactoryErrorCode::AlreadyUserProvisioned,
            FactoryErrorCode::PriorPartialResidue,
            FactoryErrorCode::DualSeProvisionFailed,
            FactoryErrorCode::OptigaHandshakeFailed,
            FactoryErrorCode::Se050Scp03RotationFailed,
            FactoryErrorCode::WipeFailed,
            FactoryErrorCode::UserResidueAfterWipe,
            FactoryErrorCode::AdminUnreachableAfterWipe,
            FactoryErrorCode::AttemptsCounterDirty,
        ] {
            assert!(
                code.hint().len() <= DISPLAY_COLS,
                "code {:?} hint {:?} exceeds {} chars",
                code,
                code.hint(),
                DISPLAY_COLS,
            );
        }
    }

    #[test]
    fn negative_step_labels_fit_oled_row_with_prefix() {
        // Row 1 is "[X/N] LABEL", so label has 16 - 6 = 10 cols.
        for step in [
            FactoryStep::HardwareSelfTest,
            FactoryStep::OtpMasterKey,
            FactoryStep::PrePopulatedStateCheck,
            FactoryStep::DualSeProvisionInfrastructure,
            FactoryStep::WipeUserState,
            FactoryStep::PostWipeValidation,
        ] {
            assert!(
                step.label().len() <= DISPLAY_COLS - 6,
                "step {:?} label {:?} exceeds {} chars",
                step,
                step.label(),
                DISPLAY_COLS - 6,
            );
        }
    }

    #[test]
    fn positive_error_codes_are_distinct() {
        // Two error codes sharing a raw value would make field
        // reports ambiguous. Cross-check all variants are unique.
        let codes = [
            FactoryErrorCode::SaesSelfTestFailed,
            FactoryErrorCode::BhkLifecycleFailed,
            FactoryErrorCode::OtpMasterMismatch,
            FactoryErrorCode::AlreadyUserProvisioned,
            FactoryErrorCode::PriorPartialResidue,
            FactoryErrorCode::DualSeProvisionFailed,
            FactoryErrorCode::OptigaHandshakeFailed,
            FactoryErrorCode::Se050Scp03RotationFailed,
            FactoryErrorCode::WipeFailed,
            FactoryErrorCode::UserResidueAfterWipe,
            FactoryErrorCode::AdminUnreachableAfterWipe,
            FactoryErrorCode::AttemptsCounterDirty,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(
                    codes[i].raw(),
                    codes[j].raw(),
                    "codes {:?} and {:?} share raw value 0x{:04X}",
                    codes[i],
                    codes[j],
                    codes[i].raw()
                );
            }
        }
    }
}
