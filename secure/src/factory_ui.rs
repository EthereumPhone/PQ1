//! Pure display/enumeration surface of the factory ceremony: the step list,
//! the error-code table, and the fixed-width failure line the operator reads
//! off the panel.
//!
//! WHY THIS FILE EXISTS (#723). `factory_provisioning.rs` is
//! `#![cfg(feature = "factory-provisioning")]`, and that feature pulls in
//! `stm32u585` plus `crate::hw`, `crate::fw_update` and `crate::ui` — all of
//! which are `#[cfg(not(test))]`. So the module cannot be compiled host-side
//! even WITH its feature enabled, and the six tests that lived in it had
//! never executed. They were not hardware tests: step counts, an error table,
//! and whether a label fits a 16-column row.
//!
//! Splitting the pure half out is the only route. `main.rs` mounts this under
//! `any(feature = "factory-provisioning", test)`, so the firmware sees it
//! exactly when it saw the old definitions, and the host test build sees it
//! always.
//!
//! WHAT THESE VALUES ARE FOR. A factory operator reads a failure as
//! `"STEP 4/7 E0401"` off the panel and quotes it in a report; the numbers
//! are looked up in `docs/provisioning/factory-provisioning.md`. That is the
//! entire diagnostic channel for a unit that fails provisioning, so the codes
//! must stay STABLE across firmware versions and the rows must actually fit —
//! a label one character too long is silently truncated on the panel and the
//! operator reports the wrong step.

use pqsigner_erc7730::display::ascii_str;

/// Panel width in characters. Mirrors `crate::ui::DISPLAY_COLS`, which is not
/// reachable from a host test build (`mod ui;` is `#[cfg(not(test))]`).
pub const DISPLAY_COLS: usize = 16;


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
    /// Legacy receipt write. The design is quarantined because entry and
    /// completion reprogram the same one-write QW; no resulting value grants
    /// RDP2 authority. Production/factory builds are blocked. (Per work-todo
    /// #36 no factory RDP2 bump exists at all anymore: devices ship at RDP-0
    /// and the FSBL self-locks to RDP-2 on the first field boot.)
    WriteOtpSentinel = 7,
}

impl FactoryStep {
    /// Step number for OLED display (1-indexed).
    pub fn number(self) -> u8 {
        self as u8
    }

    /// Total step count, for "X/N" progress strings.
    pub const fn total() -> u8 {
        7
    }

    /// Short panel label, at most `DISPLAY_COLS - 6` = 10 chars so
    /// `"[X/N] LABEL"` fits a 16-column row.
    ///
    /// #723: four labels used to break this budget — `"HW selftest"` (11),
    /// `"Provisioning"` (12), `"Post-validate"` (13) and `"OTP sentinel"`
    /// (12). `show_step_running` clamps with
    /// `min(label.len(), DISPLAY_COLS - 6)`, so they were silently truncated
    /// on the operator's panel rather than failing loudly. The test that
    /// would have caught it lived in a module that never compiled host-side.
    /// Shortened so the invariant holds by construction; the clamp stays as
    /// defence in depth. These labels are firmware-only — no doc, fixture or
    /// wire format names them.
    pub fn label(self) -> &'static str {
        match self {
            Self::HardwareSelfTest => "HW test",
            Self::OtpMasterKey => "OTP master",
            Self::PrePopulatedStateCheck => "Pre-chk",
            Self::DualSeProvisionInfrastructure => "Provision",
            Self::WipeUserState => "Wipe dummy",
            Self::PostWipeValidation => "Post-valid",
            Self::WriteOtpSentinel => "Sentinel",
        }
    }
}

/// Error codes shown on the OLED. The full table — including operator
/// hints + suggested remediation — lives in
/// `docs/provisioning/factory-provisioning.md`. Keep these numeric values STABLE
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
    /// OTP sentinel write failed. Causes: flash controller error,
    /// OTP region locked, prior bit-cleared state inconsistency.
    SentinelWriteFailed = 0x0701,
    /// Legacy receipt has `BIT_PRODUCTION` cleared. This is only a reason to
    /// refuse the legacy flow; it is not proof of a completed ceremony and
    /// grants no irreversible authority.
    SentinelAlreadyProduction = 0x0702,
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
            Self::SentinelWriteFailed => "OTP error",
            Self::SentinelAlreadyProduction => "quarantined",
        }
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

/// Every step, in ceremony order. Tests walk this rather than re-listing
/// variants, so a step added to the enum and not here shows up immediately.
pub const ALL_STEPS: [FactoryStep; 7] = [
    FactoryStep::HardwareSelfTest,
    FactoryStep::OtpMasterKey,
    FactoryStep::PrePopulatedStateCheck,
    FactoryStep::DualSeProvisionInfrastructure,
    FactoryStep::WipeUserState,
    FactoryStep::PostWipeValidation,
    FactoryStep::WriteOtpSentinel,
];

/// Every error code the ceremony can report.
pub const ALL_ERROR_CODES: [FactoryErrorCode; 14] = [
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
    FactoryErrorCode::SentinelWriteFailed,
    FactoryErrorCode::SentinelAlreadyProduction,
];

#[cfg(test)]
mod tests {
    use super::*;

    // Migrated from `factory_provisioning.rs` (#723), where they could not
    // run. Same assertions, plus the exhaustive sweeps the originals implied
    // but did not perform.

    #[test]
    fn positive_step_total_matches_enum_count() {
        let last = FactoryStep::WriteOtpSentinel;
        assert_eq!(
            last as u8,
            FactoryStep::total(),
            "FactoryStep::total() must equal the last discriminant"
        );
        assert_eq!(FactoryStep::total(), 7);
    }

    #[test]
    fn positive_format_step_err_layout() {
        let mut buf = [b' '; DISPLAY_COLS];
        let s = format_step_err(
            FactoryStep::DualSeProvisionInfrastructure,
            FactoryErrorCode::DualSeProvisionFailed,
            &mut buf,
        );
        assert_eq!(s, "STEP 4/7 E0401  ");
    }

    #[test]
    fn negative_format_step_err_handles_all_error_codes() {
        // Every (step, code) pair must render a well-formed, fixed-width row.
        // The operator quotes this string verbatim into a field report.
        let mut pairs = 0usize;
        for step in ALL_STEPS {
            for code in ALL_ERROR_CODES {
                let mut buf = [b' '; DISPLAY_COLS];
                let s = format_step_err(step, code, &mut buf);
                assert_eq!(s.len(), DISPLAY_COLS, "row must fill the panel width");
                assert!(s.is_ascii(), "row must be ASCII: {s:?}");
                assert!(s.starts_with("STEP "), "row must start with STEP: {s:?}");
                assert_eq!(
                    &s[5..6],
                    &step.number().to_string(),
                    "step number wrong in {s:?}"
                );
                assert_eq!(&s[9..10], "E", "error sigil missing in {s:?}");
                // The four hex digits must round-trip to the raw code, or the
                // documented table lookup lands on the wrong row.
                let parsed = u16::from_str_radix(&s[10..14], 16).expect("hex digits");
                assert_eq!(parsed, code.raw(), "code did not round-trip in {s:?}");
                pairs += 1;
            }
        }
        // Guard the oracle: a loop that rendered nothing would pass.
        assert_eq!(pairs, ALL_STEPS.len() * ALL_ERROR_CODES.len());
        assert_eq!(pairs, 7 * 14);
    }

    #[test]
    fn negative_error_code_hints_fit_oled_row() {
        for code in ALL_ERROR_CODES {
            let hint = code.hint();
            assert!(
                hint.len() <= DISPLAY_COLS,
                "hint {hint:?} is {} chars, panel is {DISPLAY_COLS}",
                hint.len()
            );
            assert!(!hint.is_empty(), "every code needs an operator hint");
            assert!(hint.is_ascii(), "hint must be ASCII: {hint:?}");
        }
    }

    #[test]
    fn negative_step_labels_fit_oled_row_with_prefix() {
        // Rendered as "[X/N] LABEL"; the prefix costs 6 columns.
        const PREFIX: usize = 6;
        for step in ALL_STEPS {
            let label = step.label();
            assert!(
                PREFIX + label.len() <= DISPLAY_COLS,
                "label {label:?} + prefix is {} chars, panel is {DISPLAY_COLS}",
                PREFIX + label.len()
            );
            assert!(!label.is_empty() && label.is_ascii(), "bad label {label:?}");
        }
    }

    #[test]
    fn positive_error_codes_are_distinct() {
        for (i, a) in ALL_ERROR_CODES.iter().enumerate() {
            for b in &ALL_ERROR_CODES[i + 1..] {
                assert_ne!(
                    a.raw(),
                    b.raw(),
                    "duplicate error code {:#06x}: a field report would be ambiguous",
                    a.raw()
                );
            }
        }
    }

    #[test]
    fn negative_step_numbers_are_contiguous_and_one_indexed() {
        // `format_step_err` writes the step number as a SINGLE digit
        // (`b'0' + step.number()`), so a renumber past 9 would emit a
        // non-digit and the operator would read a corrupted row.
        for (i, step) in ALL_STEPS.iter().enumerate() {
            assert_eq!(
                step.number(),
                (i + 1) as u8,
                "steps must be contiguous and 1-indexed"
            );
            assert!(step.number() <= 9, "step number must stay a single digit");
        }
        assert_eq!(ALL_STEPS.len() as u8, FactoryStep::total());
    }

    #[test]
    fn negative_error_codes_group_by_step_decade() {
        // The documented table reads the high byte as the step group
        // (0x01xx = step 1, 0x04xx = step 4, ...). A code filed under the
        // wrong group sends the operator to the wrong remediation section.
        for code in ALL_ERROR_CODES {
            let group = code.raw() >> 8;
            assert!(
                (1..=u16::from(FactoryStep::total())).contains(&group),
                "code {:#06x} has group {group}, outside 1..={}",
                code.raw(),
                FactoryStep::total()
            );
        }
    }
}
