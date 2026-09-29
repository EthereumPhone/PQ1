//! First-boot provisioning state machine — pure, resumable (host-testable).
//!
//! Work-todo #36 Phase B: after the RDP-2 self-lock, rotate the SE pairing
//! secrets off the factory transport keysets to final BHK-/salted-DHUK-rooted
//! secrets. Completed quad-word programs are recorded **commit-LAST** so an
//! ordinary power loss can resume. The append-only page has finite capacity;
//! exhaustion or silicon-level partial-program ambiguity fails closed to RMA.
//!
//! This module is the pure control flow only: it drives the hardware through
//! the [`FirstBootHw`] seam and never touches flash / the SEs / the display
//! directly. That keeps the whole resume matrix host-testable with a scripted
//! fake (see the tests), while the real implementation lives in `first_boot::
//! mod` behind the `stm32u585` + `rdp2-self-lock` gates.

#![allow(dead_code)]

use super::journal::{
    DONE_ALL, DONE_BHK, DONE_OPTIGA_PBS, DONE_SE050_ADMIN, DONE_SE050_KEYS, STEP_ALL_DONE,
    STEP_BHK, STEP_OPTIGA_PBS, STEP_SE050_ADMIN, STEP_SE050_KEYS,
};

/// Numbered step of the first-boot ceremony (1-indexed for the fault screen).
/// `Preconditions`/`Finalize` bracket the four rotation steps.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FirstBootStep {
    /// Phase A: pre-lock option-byte verification + the RDP-2 burn.
    Lock = 0,
    Preconditions = 1,
    Bhk = 2,
    Se050Keys = 3,
    Se050Admin = 4,
    OptigaPbs = 5,
    Finalize = 6,
}

impl FirstBootStep {
    #[must_use]
    pub const fn number(self) -> u8 {
        self as u8
    }

    /// Total step count for the "X/N" fault line.
    pub const TOTAL: u8 = 6;
}

/// Numbered first-boot error, kept **disjoint** from `FactoryErrorCode`
/// (0x01xx–0x07xx) by living in 0x08xx–0x0Fxx. Values are STABLE across
/// firmware versions so old field-failure photos stay interpretable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u16)]
pub enum FirstBootError {
    // Phase A (pre-lock) — halt UNLOCKED, unit stays returnable.
    /// Legacy aggregate ship-profile mismatch. Retained (stable value) so old
    /// field-failure photos stay interpretable, but **no longer emitted** — the
    /// granular `Ob*` codes below name the exact failing field instead.
    ObProfileMismatch = 0x0801,
    /// The RDP=0xCC program / OPTSTRT sequence reported an error.
    RdpProgramFailed = 0x0802,
    /// R2.3: the factory OTP master is not burned. Caught PRE-lock so the unit
    /// halts UNLOCKED/returnable (vs the post-lock `OtpMasterNotBurned` RMA).
    OtpMasterMissingPreLock = 0x0803,
    /// Ship-profile: `FLASH_OPTR.TZEN` is not set (`ObField::Tzen`).
    ObTzenMismatch = 0x0804,
    /// Ship-profile: `FLASH_OPTR.RDP` is not the ship byte 0xAA (`ObField::Rdp`).
    ObRdpNotShipLevel = 0x0805,
    /// Ship-profile: `SECWM1R1` is not all-bank-1-secure (`ObField::Secwm1`).
    ObSecwm1Mismatch = 0x0806,
    /// Ship-profile: `SECWM2R1` is not all-bank-2-NS (`ObField::Secwm2`).
    ObSecwm2Mismatch = 0x0807,
    /// Ship-profile: `SECBOOTADD0` does not select the FSBL base
    /// (`ObField::SecBootAdd0`) — a boot redirect.
    ObSecBootAdd0Mismatch = 0x0808,
    /// Ship-profile: `WRP1A` does not write-protect the FSBL pages
    /// (`ObField::Wrp1a`).
    ObWrp1aMismatch = 0x0809,
    /// Ship-profile: an OEM key-lock bit is set, OR the OEM-lock mask is not yet
    /// silicon-pinned so the check fails closed (`ObField::OemLock`; see
    /// `lockdown::OEM_LOCK_MASK_PINNED`).
    ObOemLockPresentOrUnpinned = 0x080A,
    /// A per-device flash page (123..=127) is not blank at ship — a planted
    /// journal/salt, or a used bench part.
    PerDevicePageNotBlank = 0x080B,
    /// Ship-profile: `WRP2A` does not write-protect the BANK-2 FSBL mirror
    /// (`ObField::Wrp2a`). Added 2026-09-24 — the profile previously did not
    /// even receive `WRP2AR`, so the mirror the frozen geometry requires in
    /// both banks was never verified before the RDP-2 burn made it permanent.
    ObWrp2aMismatch = 0x080C,
    /// Ship-profile: `FLASH_OPTR.SWAP_BANK` is set (`ObField::SwapBank`).
    /// Added 2026-09-24. RM0456 §7.6.2 excepts this bit from the RDP-2 freeze,
    /// so it is the one OPTR field that can still move on a locked die.
    ObSwapBankSet = 0x080D,
    /// Ship-profile: `SECBOOTADD0R.BOOT_LOCK` is clear where the profile
    /// requires it (`ObField::BootLock`). Added 2026-09-24.
    ObBootLockClear = 0x080E,

    // Phase B (post-lock) — RMA / retry.
    /// OTP master is blank — the factory must burn it; first boot must not.
    OtpMasterNotBurned = 0x0811,
    /// SAES Tier-1 (DHUK) self-check failed.
    SaesDead = 0x0812,
    /// BHK provision / load-lock / self-test failed.
    BhkProvisionFailed = 0x0821,
    /// Page-126 refused programming (bench program-hostility) — silicon RMA.
    BhkPageHostile = 0x0822,
    /// SE050 SCP03 session could not be established under FINAL or TRANSPORT.
    Se050EstablishFailed = 0x0831,
    /// SE050 GP PUT KEY (transport → final) failed.
    Se050PutKeyFailed = 0x0832,
    /// Re-establish under the FINAL keyset did not confirm.
    Se050KeyConfirmFailed = 0x0833,
    /// SE050 admin credential re-key (delete + recreate) failed.
    Se050AdminRekeyFailed = 0x0841,
    /// The TRNG salt could not be persisted to the journal before use.
    OptigaSaltPersistFailed = 0x0851,
    /// OPTIGA SetData(E140) of the final PBS failed.
    OptigaSetDataFailed = 0x0852,
    /// Re-shield under the FINAL PBS did not confirm.
    OptigaConfirmFailed = 0x0853,
    /// The 3-source TRNG salt draw itself failed (a platform/OPTIGA/SE050 leg
    /// or the all-zero acceptance gate). Distinct from `OptigaSaltPersistFailed`
    /// (which is now journal-persist only). See #443: the OPTIGA leg is
    /// mandatory, so the shield must be up (`optiga_establish_transport_shield`)
    /// before this draw.
    TrngSaltDrawFailed = 0x0854,
    /// The pre-salt OPTIGA TRANSPORT-PBS handshake failed (#443). Doubles as
    /// authenticate-before-rotate: a chip that no longer pairs under the
    /// factory transport PBS is caught here, before any journal write.
    OptigaTransportShieldFailed = 0x0855,
    /// A journal step-marker write failed.
    JournalWriteFailed = 0x0861,
    /// The SEs are not in the expected factory transport state (e.g. a transit
    /// attacker pre-rotated them) — never fall back to vendor defaults.
    UnexpectedState = 0x08F0,
}

impl FirstBootError {
    #[must_use]
    pub const fn raw(self) -> u16 {
        self as u16
    }
}

/// Map a ship-profile [`ObField`](sphincs_tz_shared::lockdown::ObField)
/// mismatch to its distinct Phase-A fault code. **Exhaustive on purpose**: a
/// new `ObField` variant breaks this build instead of silently collapsing into
/// a generic code, so every option-byte discrepancy keeps naming itself on the
/// fault screen (R5.1 stable-code requirement).
#[must_use]
pub const fn ob_field_code(f: sphincs_tz_shared::lockdown::ObField) -> FirstBootError {
    use sphincs_tz_shared::lockdown::ObField as F;
    match f {
        F::Tzen => FirstBootError::ObTzenMismatch,
        F::Rdp => FirstBootError::ObRdpNotShipLevel,
        F::Secwm1 => FirstBootError::ObSecwm1Mismatch,
        F::Secwm2 => FirstBootError::ObSecwm2Mismatch,
        F::SecBootAdd0 => FirstBootError::ObSecBootAdd0Mismatch,
        F::Wrp1a => FirstBootError::ObWrp1aMismatch,
        F::Wrp2a => FirstBootError::ObWrp2aMismatch,
        F::SwapBank => FirstBootError::ObSwapBankSet,
        F::BootLock => FirstBootError::ObBootLockClear,
        F::OemLock => FirstBootError::ObOemLockPresentOrUnpinned,
    }
}

/// Pad an ASCII byte slice into a 16-column display row (space-filled,
/// truncated at 16). Pure helper for [`build_lock_confirm_pages`].
const fn pad16(s: &[u8]) -> [u8; 16] {
    let mut row = [b' '; 16];
    let n = if s.len() < 16 { s.len() } else { 16 };
    let mut i = 0;
    while i < n {
        row[i] = s[i];
        i += 1;
    }
    row
}

/// Build the 2-page "confirm to lock" screen shown before the irreversible
/// RDP-2 burn (R2.4, owner decision 2026-07-17). Structurally identical to
/// `[ui::confirm::Page; 2]` (`[[u8; 16]; 4]` per page), so the hardware caller
/// passes it straight to `confirm_checked`, whose **both-buttons chord**
/// (synthesized to a long-right confirm) and scroll-to-end `FihBool` gate then
/// require the user to page to page 2 and press BOTH buttons before the burn.
/// Footer rows (row 3) are kept ≤ 12 columns so the draw-time ` i/n` page
/// indicator overlays cleanly. Pure + host-testable (byte-exact).
#[must_use]
pub const fn build_lock_confirm_pages() -> [[[u8; 16]; 4]; 2] {
    [
        [
            pad16(b"CONFIRM: LOCK"),
            pad16(b"DEVICE FOREVER."),
            pad16(b"SWD verify OFF"),
            pad16(b"after lock."),
        ],
        [
            pad16(b"Press BOTH keys"),
            pad16(b"to LOCK forever"),
            pad16(b"Hold LEFT to"),
            pad16(b"cancel."),
        ],
    ]
}

/// The single combined authorization for the RDP-2 burn (R2.4). Returns
/// [`crate::fi::OK_SENTINEL`] iff an affirmative confirm carried the accept
/// sentinel. The RESULT is itself a Hamming-distant sentinel — produced by the
/// double-evaluated `check_true_into_sentinel`, NOT a bare bool — so the caller
/// gates on `== OK_SENTINEL`, matching the sibling `confirm_checked` and
/// `TransportAuthProof::authorize_write` gates. A bool return would be one
/// stuck-at-1 fault from burning the single most irreversible option byte.
#[must_use]
pub fn rdp_burn_authorized(confirmed: bool, sentinel: u32) -> u32 {
    crate::fi::check_true_into_sentinel(|| confirmed && sentinel == crate::fi::OK_SENTINEL)
}

/// A terminal first-boot fault: which step failed + the numbered code.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FirstBootFault {
    pub step: FirstBootStep,
    pub code: FirstBootError,
}

impl FirstBootFault {
    #[must_use]
    pub const fn new(step: FirstBootStep, code: FirstBootError) -> Self {
        Self { step, code }
    }
}

/// The hardware seam the Phase-B state machine drives. Every method is a
/// durable, resumable operation; the pure `run` below sequences them and
/// records progress via `commit_step` / `commit_salt`.
///
/// Implementations MUST make the rotation methods idempotent + two-phase
/// (confirm the NEW keyset works before considering the OLD dead; on resume
/// try FINAL first, fall back to TRANSPORT) — see the real impl in
/// `first_boot::mod`.
pub trait FirstBootHw {
    /// Current journal state (re-scanned from page 127).
    fn journal(&self) -> super::journal::JournalState;
    /// Append a step-completion marker (commit-LAST).
    fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError>;
    /// Persist the TRNG salt (commit-LAST, BEFORE it is used to derive the PBS).
    fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError>;

    /// Precondition: the factory-burned OTP master is present.
    fn otp_master_burned(&self) -> bool;
    /// Precondition: SAES Tier-1 (DHUK) is alive.
    fn saes_alive(&self) -> bool;

    /// BHK first-write: erase-and-reprovision UNCONDITIONALLY (anti-pre-plant)
    /// from STM32 + OPTIGA + SE050 entropy, then load-lock + self-test.
    fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError>;
    /// Rotate SE050 SCP03 transport → final (two-phase confirm).
    fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError>;
    /// Re-key the SE050 admin credential transport → final.
    fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError>;
    /// Bring the OPTIGA shielded session up under the factory TRANSPORT PBS
    /// (E140 untouched) so the 3-source BHK and `trng_salt` draws can reach
    /// the OPTIGA TRNG. Fresh-path only — with a committed salt the rotation
    /// self-establishes (FINAL-probe-first) and a transport handshake against
    /// an already-rotated chip would fail spuriously.
    fn optiga_establish_transport_shield(&mut self) -> Result<(), FirstBootError>;
    /// Draw a fresh 32-byte TRNG salt. Requires the OPTIGA shield to be up
    /// (see `optiga_establish_transport_shield`): the strong-RNG's OPTIGA leg
    /// is mandatory and sentinel-gated.
    fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError>;
    /// Rotate the OPTIGA PBS transport → salted-final (two-phase confirm).
    fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError>;

    /// UI hook: entering `step` (`resuming` = we've been here before).
    fn ui_step(&mut self, step: FirstBootStep, resuming: bool);
}

/// Run the Phase-B ceremony to completion (or the first fault). `Ok(())`
/// means the journal now reads `ALL_DONE` and normal boot may proceed to the
/// seed wizard.
///
/// Resumability: each step is guarded on its journal marker, so a boot that
/// re-enters after a power loss skips every already-committed step and
/// resumes at the first incomplete one. The single writer within a run is us,
/// so the completed-set is tracked locally after the initial scan.
pub fn run(hw: &mut dyn FirstBootHw) -> Result<(), FirstBootFault> {
    // Step 1 — preconditions (read-only; run every boot, no marker).
    if !hw.otp_master_burned() {
        return Err(FirstBootFault::new(
            FirstBootStep::Preconditions,
            FirstBootError::OtpMasterNotBurned,
        ));
    }
    if !hw.saes_alive() {
        return Err(FirstBootFault::new(
            FirstBootStep::Preconditions,
            FirstBootError::SaesDead,
        ));
    }

    let js = hw.journal();
    let resuming = !js.is_blank();
    let mut done = js.done;
    let salt = js.salt;
    let mut optiga_transport_ready = false;

    // Step 2 — BHK first-write (anti-pre-plant erase-and-reprovision).
    if done & DONE_BHK == 0 {
        hw.ui_step(FirstBootStep::Bhk, resuming);
        // The BHK is a long-lived key root, so it must use the same mandatory
        // three-source policy as wallet entropy. E140 is still on the factory
        // transport PBS here; establish its shield before asking OPTIGA for
        // entropy. A clean run reuses this session for the later salt draw.
        hw.optiga_establish_transport_shield()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Bhk, e))?;
        optiga_transport_ready = true;
        hw.bhk_provision_and_lock()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Bhk, e))?;
        hw.commit_step(STEP_BHK)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Bhk, e))?;
        done |= DONE_BHK;
    }

    // Step 3 — SE050 SCP03 rotation transport → final.
    if done & DONE_SE050_KEYS == 0 {
        hw.ui_step(FirstBootStep::Se050Keys, resuming);
        hw.se050_rotate_scp03()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Keys, e))?;
        hw.commit_step(STEP_SE050_KEYS)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Keys, e))?;
        done |= DONE_SE050_KEYS;
    }

    // Step 4 — SE050 admin credential re-key transport → final.
    if done & DONE_SE050_ADMIN == 0 {
        hw.ui_step(FirstBootStep::Se050Admin, resuming);
        hw.se050_rekey_admin()
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Admin, e))?;
        hw.commit_step(STEP_SE050_ADMIN)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Se050Admin, e))?;
        done |= DONE_SE050_ADMIN;
    }

    // Step 5 — OPTIGA PBS rotation transport → salted-final. The salt is
    // committed to the journal BEFORE use so a resume derives the SAME final
    // PBS (a fresh salt each attempt would strand the E140 write).
    if done & DONE_OPTIGA_PBS == 0 {
        hw.ui_step(FirstBootStep::OptigaPbs, resuming);
        let s = match salt {
            Some(s) => s,
            None => {
                // #443: the salt has never been drawn ⇒ E140 still carries the
                // transport PBS ⇒ this handshake is safe AND the only way the
                // OPTIGA TRNG leg of the 3-source draw can answer. On a resume
                // with a committed salt this whole arm is skipped, so a
                // transport handshake against an already-rotated chip never runs.
                if !optiga_transport_ready {
                    hw.optiga_establish_transport_shield()
                        .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
                }
                let s = hw
                    .trng_salt()
                    .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
                hw.commit_salt(&s)
                    .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
                s
            }
        };
        hw.optiga_rotate_pbs(&s)
            .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
        hw.commit_step(STEP_OPTIGA_PBS)
            .map_err(|e| FirstBootFault::new(FirstBootStep::OptigaPbs, e))?;
        done |= DONE_OPTIGA_PBS;
    }

    // Step 6 — finalize.
    if done & DONE_ALL == 0 {
        hw.commit_step(STEP_ALL_DONE)
            .map_err(|e| FirstBootFault::new(FirstBootStep::Finalize, e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::journal::{self, PAGE_QWS, QW};
    use super::*;
    use std::panic::{self, AssertUnwindSafe};
    use std::vec::Vec;

    /// Panic payload used to simulate a power loss at a chosen op boundary.
    const POWERCUT: &str = "POWERCUT";

    /// Scripted `FirstBootHw` fake. The `page` (journal) and the SE-state
    /// flags persist across a simulated reset; `cut_at` injects a panic after
    /// the N-th durable op to model a power cut at that boundary.
    struct FakeHw {
        page: Vec<u8>, // 512*16 journal image; survives "reset"
        // Simulated durable SE / BHK state (persists across reset).
        bhk_final: bool,
        se050_keys_final: bool,
        se050_admin_final: bool,
        optiga_pbs_final: bool,
        // Preconditions / injected failures.
        otp_burned: bool,
        saes_ok: bool,
        fail: Option<FirstBootError>,
        fail_on_step: Option<u8>,
        // #443: the OPTIGA shielded session. VOLATILE — cleared on every
        // simulated reset (the test harness sets it false after each cut) so a
        // resume must re-establish it before the salt draw can succeed.
        optiga_shield_up: bool,
        establish_calls: usize,
        fail_establish: bool,
        // Deterministic "TRNG" salt (varies per test, not per call).
        salt_source: [u8; 32],
        // Power-cut injection.
        ops: usize,
        cut_at: Option<usize>,
        // Bookkeeping.
        bhk_calls: usize,
        scp03_calls: usize,
        admin_calls: usize,
        optiga_calls: usize,
        optiga_salt_used: Option<[u8; 32]>,
    }

    impl FakeHw {
        fn new() -> Self {
            FakeHw {
                page: std::vec![0xFFu8; PAGE_QWS * QW],
                bhk_final: false,
                se050_keys_final: false,
                se050_admin_final: false,
                optiga_pbs_final: false,
                otp_burned: true,
                saes_ok: true,
                fail: None,
                fail_on_step: None,
                optiga_shield_up: false,
                establish_calls: 0,
                fail_establish: false,
                salt_source: [0x5Au8; 32],
                ops: 0,
                cut_at: None,
                bhk_calls: 0,
                scp03_calls: 0,
                admin_calls: 0,
                optiga_calls: 0,
                optiga_salt_used: None,
            }
        }

        /// Register a durable op; panic (simulate reset) if this is the cut op.
        fn tick(&mut self) {
            self.ops += 1;
            if Some(self.ops) == self.cut_at {
                panic!("{POWERCUT}");
            }
        }

        fn journal_done(&self) -> u32 {
            journal::scan(&self.page).done
        }

        fn append(&mut self, rec: &[u8; QW]) -> Result<(), FirstBootError> {
            let idx = journal::scan(&self.page).next_free;
            if idx >= PAGE_QWS {
                return Err(FirstBootError::JournalWriteFailed);
            }
            self.page[idx * QW..idx * QW + QW].copy_from_slice(rec);
            Ok(())
        }
    }

    impl FirstBootHw for FakeHw {
        fn journal(&self) -> journal::JournalState {
            journal::scan(&self.page)
        }
        fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError> {
            let rec = journal::encode_step(step_id);
            self.append(&rec)?; // durable first
            self.tick(); // then a cut here loses nothing (marker persisted)
            Ok(())
        }
        fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
            let recs = journal::encode_salt(salt);
            if !self
                .journal()
                .can_append(journal::SALT_COMPLETION_RESERVE_QWS)
            {
                return Err(FirstBootError::OptigaSaltPersistFailed);
            }
            for r in &recs {
                self.append(r)
                    .map_err(|_| FirstBootError::OptigaSaltPersistFailed)?;
                self.tick();
            }
            Ok(())
        }
        fn otp_master_burned(&self) -> bool {
            self.otp_burned
        }
        fn saes_alive(&self) -> bool {
            self.saes_ok
        }
        fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(
                self.journal_done() & DONE_BHK,
                0,
                "BHK step re-run after its marker was committed"
            );
            assert!(
                self.optiga_shield_up,
                "three-source BHK draw requires the OPTIGA transport shield"
            );
            self.bhk_calls += 1;
            self.tick(); // cut before the durable effect
            if self.fail_on_step == Some(2) {
                return Err(self.fail.unwrap());
            }
            self.bhk_final = true; // idempotent durable effect
            self.tick(); // cut after the effect, before commit
            Ok(())
        }
        fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_SE050_KEYS, 0, "SCP03 re-run after commit");
            self.scp03_calls += 1;
            self.tick();
            if self.fail_on_step == Some(3) {
                return Err(self.fail.unwrap());
            }
            self.se050_keys_final = true;
            self.tick();
            Ok(())
        }
        fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_SE050_ADMIN, 0, "admin re-run after commit");
            self.admin_calls += 1;
            self.tick();
            if self.fail_on_step == Some(4) {
                return Err(self.fail.unwrap());
            }
            self.se050_admin_final = true;
            self.tick();
            Ok(())
        }
        fn optiga_establish_transport_shield(&mut self) -> Result<(), FirstBootError> {
            // The real helper only runs on the fresh path; a committed salt
            // means the chip may already be rotated, where a transport
            // handshake would fail. Mirror that invariant here.
            assert_eq!(
                self.journal().salt,
                None,
                "transport establish must not run after a committed salt"
            );
            self.establish_calls += 1;
            self.tick(); // a power cut can land in the transport handshake
            if self.fail_establish {
                return Err(FirstBootError::OptigaTransportShieldFailed);
            }
            self.optiga_shield_up = true;
            Ok(())
        }
        fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError> {
            // #443 regression: the 3-source draw's OPTIGA leg is mandatory, so
            // the shield MUST be up. Without the establish call sequenced first
            // this returns the deterministic-brick error.
            if !self.optiga_shield_up {
                return Err(FirstBootError::TrngSaltDrawFailed);
            }
            self.tick();
            Ok(self.salt_source)
        }
        fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
            assert_eq!(self.journal_done() & DONE_OPTIGA_PBS, 0, "PBS re-run after commit");
            // The salt handed to us MUST be the currently committed journal
            // value, including after a torn earlier attempt regenerated it.
            assert_eq!(Some(*salt), self.journal().salt, "rotation used a non-persisted salt");
            self.optiga_salt_used = Some(*salt);
            self.optiga_calls += 1;
            self.tick();
            if self.fail_on_step == Some(5) {
                return Err(self.fail.unwrap());
            }
            self.optiga_pbs_final = true;
            self.tick();
            Ok(())
        }
        fn ui_step(&mut self, _step: FirstBootStep, _resuming: bool) {}
    }

    fn all_final(hw: &FakeHw) -> bool {
        hw.bhk_final
            && hw.se050_keys_final
            && hw.se050_admin_final
            && hw.optiga_pbs_final
            && hw.journal().all_done()
    }

    fn prime_pre_salt(hw: &mut FakeHw, next_free: usize) {
        assert!(next_free >= 3 && next_free <= PAGE_QWS);
        for step in [STEP_BHK, STEP_SE050_KEYS, STEP_SE050_ADMIN] {
            hw.append(&journal::encode_step(step)).unwrap();
        }
        let junk = [0xA5u8; QW];
        while hw.journal().next_free < next_free {
            hw.append(&junk).unwrap();
        }
        assert_eq!(hw.journal().next_free, next_free);
    }

    fn run_expect_powercut(hw: &mut FakeHw) {
        let prev = panic::take_hook();
        panic::set_hook(std::boxed::Box::new(|_| {}));
        let res = panic::catch_unwind(AssertUnwindSafe(|| run(hw)));
        panic::set_hook(prev);
        assert!(res.is_err(), "configured power cut did not fire");
        // The OPTIGA shielded session is volatile — a power cut drops it.
        hw.optiga_shield_up = false;
    }

    #[test]
    fn clean_run_completes() {
        let mut hw = FakeHw::new();
        assert_eq!(run(&mut hw), Ok(()));
        assert!(all_final(&hw));
        // Each rotation step ran exactly once on a clean run.
        assert_eq!(hw.bhk_calls, 1);
        assert_eq!(hw.scp03_calls, 1);
        assert_eq!(hw.admin_calls, 1);
        assert_eq!(hw.optiga_calls, 1);
        // #443: the transport shield is established exactly once, before the
        // single salt draw.
        assert_eq!(hw.establish_calls, 1);
    }

    #[test]
    fn idempotent_second_run_is_noop() {
        let mut hw = FakeHw::new();
        assert_eq!(run(&mut hw), Ok(()));
        let (b, s, a, o) = (hw.bhk_calls, hw.scp03_calls, hw.admin_calls, hw.optiga_calls);
        // Re-run on a fully-provisioned device: every step guarded off.
        assert_eq!(run(&mut hw), Ok(()));
        assert_eq!((hw.bhk_calls, hw.scp03_calls, hw.admin_calls, hw.optiga_calls), (b, s, a, o));
    }

    #[test]
    fn precondition_faults_are_rma() {
        let mut hw = FakeHw::new();
        hw.otp_burned = false;
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Preconditions, FirstBootError::OtpMasterNotBurned))
        );

        let mut hw = FakeHw::new();
        hw.saes_ok = false;
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Preconditions, FirstBootError::SaesDead))
        );
    }

    #[test]
    fn step_failure_surfaces_step_and_code() {
        let mut hw = FakeHw::new();
        hw.fail_on_step = Some(3);
        hw.fail = Some(FirstBootError::Se050PutKeyFailed);
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(FirstBootStep::Se050Keys, FirstBootError::Se050PutKeyFailed))
        );
        // BHK completed and is durable; the failed step left no marker.
        assert!(hw.journal().has(DONE_BHK));
        assert!(!hw.journal().has(DONE_SE050_KEYS));
    }

    #[test]
    fn transport_shield_failure_halts_with_0x0855() {
        // A chip that no longer answers the transport PBS handshake is caught
        // before the mandatory three-source BHK is drawn or written.
        let mut hw = FakeHw::new();
        hw.fail_establish = true;
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(
                FirstBootStep::Bhk,
                FirstBootError::OptigaTransportShieldFailed,
            ))
        );
        assert!(!hw.journal().has(DONE_BHK));
        assert_eq!(hw.journal().salt, None);
        assert_eq!(hw.optiga_calls, 0);
    }

    #[test]
    fn resume_with_committed_salt_never_establishes() {
        // On a resume where the salt is already committed, the fresh-path
        // establish MUST be skipped — a transport handshake against an
        // already-rotated chip would fail. Prime steps 2-4 + a committed salt,
        // poison the establish, and require a clean completion regardless.
        let mut hw = FakeHw::new();
        prime_pre_salt(&mut hw, 3);
        for r in &journal::encode_salt(&[0x77u8; 32]) {
            hw.append(r).unwrap();
        }
        assert_eq!(hw.journal().salt, Some([0x77u8; 32]));
        hw.fail_establish = true; // must never be reached
        assert_eq!(run(&mut hw), Ok(()));
        assert_eq!(hw.establish_calls, 0, "establish ran despite a committed salt");
        assert_eq!(hw.optiga_salt_used, Some([0x77u8; 32]));
    }

    /// Drive one cut+resume cycle: run with `cut_at`, swallow the powercut
    /// panic, then resume (no cut) to completion. Returns the fake for asserts.
    fn cut_then_resume(cut_at: usize) -> FakeHw {
        let mut hw = FakeHw::new();
        hw.cut_at = Some(cut_at);

        // Suppress the default panic printout for the injected powercut.
        let prev = panic::take_hook();
        panic::set_hook(std::boxed::Box::new(|_| {}));
        let res = panic::catch_unwind(AssertUnwindSafe(|| run(&mut hw)));
        panic::set_hook(prev);

        match res {
            Ok(r) => {
                // No cut fired (cut_at past the op count) — must have completed.
                assert_eq!(r, Ok(()), "uncut run must complete");
            }
            Err(payload) => {
                // The formatted `panic!` yields a `String` payload; accept both.
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<std::string::String>().map(|s| s.as_str()))
                    .unwrap_or("");
                assert_eq!(msg, POWERCUT, "only the injected powercut may unwind");
            }
        }

        // Resume: same device (page + SE flags persisted), no more cuts. The
        // OPTIGA shielded session, being volatile, did NOT persist the reset.
        hw.cut_at = None;
        hw.optiga_shield_up = false;
        assert_eq!(run(&mut hw), Ok(()), "resume after cut@{cut_at} must complete");
        hw
    }

    #[test]
    fn power_cut_at_every_boundary_converges() {
        // A clean run performs this many durable ticks; cut at each one.
        let total_ops = {
            let mut hw = FakeHw::new();
            let _ = run(&mut hw);
            hw.ops
        };
        assert!(total_ops >= 10, "expected a healthy number of op boundaries");

        for cut in 1..=total_ops + 1 {
            let hw = cut_then_resume(cut);
            assert!(all_final(&hw), "cut@{cut} did not converge to ALL_DONE");
            // Anti-pre-plant / idempotence: no step ran more than twice
            // (once pre-cut without a committed marker, once on resume).
            assert!(hw.bhk_calls <= 2, "cut@{cut}: BHK ran {} times", hw.bhk_calls);
            assert!(hw.scp03_calls <= 2, "cut@{cut}: SCP03 ran {} times", hw.scp03_calls);
            assert!(hw.admin_calls <= 2, "cut@{cut}: admin ran {} times", hw.admin_calls);
            assert!(hw.optiga_calls <= 2, "cut@{cut}: OPTIGA ran {} times", hw.optiga_calls);
        }
    }

    #[test]
    fn salt_persisted_before_use_survives_cut() {
        // Find the op index of the salt commit, cut right after it, and assert
        // the resume reuses the SAME salt (does not regenerate).
        let mut hw = FakeHw::new();
        hw.salt_source = [0x9Cu8; 32];
        // Run until the salt lands in the journal, then inspect.
        let _ = run(&mut hw);
        assert_eq!(hw.journal().salt, Some([0x9Cu8; 32]));
        // A fresh device, cut somewhere inside the OPTIGA step, must still end
        // with exactly the persisted salt (optiga_rotate_pbs asserts salt match).
        for cut in 1..=hw.ops + 1 {
            let mut h = FakeHw::new();
            h.salt_source = [0x9Cu8; 32];
            h.cut_at = Some(cut);
            let prev = panic::take_hook();
            panic::set_hook(std::boxed::Box::new(|_| {}));
            let _ = panic::catch_unwind(AssertUnwindSafe(|| run(&mut h)));
            panic::set_hook(prev);
            h.cut_at = None;
            h.optiga_shield_up = false; // volatile session dropped by the reset
            assert_eq!(run(&mut h), Ok(()));
            if let Some(s) = h.journal().salt {
                assert_eq!(s, [0x9Cu8; 32], "cut@{cut}: salt changed across resume");
            }
        }
    }

    #[test]
    fn torn_salt_data_is_orphaned_and_regenerated_before_use() {
        for cut_after_qw in 1..=2 {
            let mut hw = FakeHw::new();
            prime_pre_salt(&mut hw, 3);
            hw.salt_source = [0x11u8; 32];
            // #443: establish is tick 1, TRNG is tick 2; each completed salt QW
            // is one further boundary.
            hw.cut_at = Some(2 + cut_after_qw);
            run_expect_powercut(&mut hw);
            assert_eq!(hw.journal().salt, None);

            hw.cut_at = None;
            hw.salt_source = [0x22u8; 32];
            assert_eq!(run(&mut hw), Ok(()));
            assert_eq!(hw.journal().salt, Some([0x22u8; 32]));
            assert_eq!(hw.optiga_salt_used, Some([0x22u8; 32]));
        }
    }

    #[test]
    fn committed_salt_header_is_reused_after_cut() {
        let mut hw = FakeHw::new();
        prime_pre_salt(&mut hw, 3);
        hw.salt_source = [0x31u8; 32];
        hw.cut_at = Some(5); // establish + TRNG + QW1 + QW2 + committed header.
        run_expect_powercut(&mut hw);
        assert_eq!(hw.journal().salt, Some([0x31u8; 32]));

        hw.cut_at = None;
        hw.salt_source = [0x42u8; 32];
        assert_eq!(run(&mut hw), Ok(()));
        assert_eq!(hw.optiga_salt_used, Some([0x31u8; 32]));
    }

    #[test]
    fn near_full_journal_refuses_salt_without_writing() {
        let mut hw = FakeHw::new();
        prime_pre_salt(&mut hw, PAGE_QWS - 2);
        let before = hw.page.clone();

        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(
                FirstBootStep::OptigaPbs,
                FirstBootError::OptigaSaltPersistFailed,
            ))
        );
        assert_eq!(hw.page, before);
        assert_eq!(hw.journal().salt, None);
        assert_eq!(hw.optiga_calls, 0);
    }

    #[test]
    fn repeated_torn_salt_attempts_exhaust_capacity_fail_closed() {
        let mut hw = FakeHw::new();
        prime_pre_salt(&mut hw, PAGE_QWS - 8);

        // Four resets immediately after QW1 consume four orphan QWs. The
        // five-QW completion reserve then refuses another attempt.
        for attempt in 0..4u8 {
            hw.salt_source = [0x50 + attempt; 32];
            hw.cut_at = Some(hw.ops + 3); // establish, TRNG, then salt QW1.
            run_expect_powercut(&mut hw);
            assert_eq!(hw.journal().salt, None);
        }
        assert_eq!(hw.journal().next_free, PAGE_QWS - 4);

        hw.cut_at = None;
        let before = hw.page.clone();
        assert_eq!(
            run(&mut hw),
            Err(FirstBootFault::new(
                FirstBootStep::OptigaPbs,
                FirstBootError::OptigaSaltPersistFailed,
            ))
        );
        assert_eq!(hw.page, before, "capacity refusal must not consume another QW");
        assert_eq!(hw.optiga_calls, 0);
        assert!(!hw.journal().all_done());
    }

    #[test]
    fn ob_field_code_is_total_and_distinct() {
        use sphincs_tz_shared::lockdown::ObField;
        let all = [
            ObField::Tzen,
            ObField::Rdp,
            ObField::Secwm1,
            ObField::Secwm2,
            ObField::SecBootAdd0,
            ObField::Wrp1a,
            ObField::OemLock,
        ];
        let mut codes = Vec::new();
        for f in all {
            let c = ob_field_code(f).raw();
            // Each maps into the distinct pre-lock 0x0804..=0x080A band.
            assert!((0x0804..=0x080A).contains(&c), "{f:?} -> {c:#06x} out of band");
            assert!(!codes.contains(&c), "{f:?} -> {c:#06x} collides");
            codes.push(c);
        }
        assert_eq!(codes.len(), 7, "all seven fields mapped");
    }

    #[test]
    fn rdp_burn_authorized_requires_both_words_and_returns_sentinel() {
        let ok = crate::fi::OK_SENTINEL;
        // Only confirmed + the accept sentinel authorizes, and the RESULT is
        // itself OK_SENTINEL (not a bare bool) so the caller gates on it.
        assert_eq!(rdp_burn_authorized(true, ok), ok, "confirmed + sentinel authorizes");
        // Missing EITHER word must deny (two-independent-words FI idiom).
        assert_ne!(rdp_burn_authorized(false, ok), ok, "not confirmed");
        assert_ne!(rdp_burn_authorized(true, 0), ok, "zero sentinel");
        assert_ne!(rdp_burn_authorized(true, !ok), ok, "wrong sentinel");
    }

    #[test]
    fn lock_confirm_pages_are_byte_exact_and_overlay_safe() {
        let pages = build_lock_confirm_pages();
        let expect = [
            ["CONFIRM: LOCK", "DEVICE FOREVER.", "SWD verify OFF", "after lock."],
            ["Press BOTH keys", "to LOCK forever", "Hold LEFT to", "cancel."],
        ];
        for (pi, page) in pages.iter().enumerate() {
            for (ri, row) in page.iter().enumerate() {
                assert_eq!(row.len(), 16, "every row is 16 columns");
                let s = core::str::from_utf8(row).expect("ascii row");
                assert!(s.is_ascii(), "non-ascii on the trusted lock screen");
                assert_eq!(s.trim_end(), expect[pi][ri], "page {pi} row {ri}");
            }
            // Footer (row 3) must leave room for the draw-time ` i/n` overlay.
            let footer = &page[3];
            let used = footer.iter().rposition(|&c| c != b' ').map_or(0, |p| p + 1);
            assert!(used + 4 <= 16, "page {pi} footer too long for i/n overlay");
        }
    }
}
