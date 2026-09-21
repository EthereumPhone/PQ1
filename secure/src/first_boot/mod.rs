//! First-boot self-provisioning (work-todo #36) — RDP-2 self-lock + on-device
//! rotation of the SE pairing secrets off the factory transport keysets.
//!
//! **Factory ⇄ first-boot split (authoritative — mirror in the docs):**
//! the factory flashes the batch-uniform image, sets the option-byte profile
//! (everything EXCEPT RDP), burns the per-device OTP master, and provisions
//! the SE-internal structure + irreversible locks onto per-device *transport*
//! keysets (public-by-assumption, rooted in the OTP master). The device ships
//! at RDP-0. On the **first field boot** this module verifies that ship state,
//! self-locks RDP-2, then rotates the transport keysets to final BHK-/salted-
//! DHUK-rooted secrets — before the seed wizard. See
//! `docs/provisioning/first-boot-provisioning.md`.
//!
//! Structure:
//! - [`journal`] — pure page-127 commit-LAST log codec (host-tested).
//! - [`state`] — pure resumable state machine over the [`state::FirstBootHw`]
//!   seam (host-tested with a scripted fake + power-cut matrix).
//! - the hardware glue (real `FirstBootHw` impl + the two boot entry points)
//!   lives below, gated on `stm32u585` + `rdp2-self-lock`, and is the only
//!   part that touches flash / the SEs / the display.

pub mod journal;
pub mod state;

// --- hardware glue (real silicon, feature-gated) ---------------------------
// The `run_pre_lock_and_maybe_lock` / `run_post_lock_provisioning` entry
// points and the real `FirstBootHw` implementation are added below under
// `#[cfg(all(not(test), feature = "rdp2-self-lock"))]` (the feature implies
// `stm32u585` transitively via `bhk` → `saes-dhuk`).

/// What the page-127 journal says about which OPTIGA PBS is installed.
///
/// The three cases must stay distinguishable. An `Option<[u8; 32]>` collapses
/// the last two into `None`, and `secret_keys::current_pbs` then fell back to
/// the UNSALTED secret in both — silently selecting the wrong credential for a
/// device whose E140 already holds the salted-final one.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[derive(Clone, Copy, Debug)]
pub enum FinalPbs {
    /// The first-boot rotation has not completed. The pre-rotation unsalted
    /// secret is the correct credential.
    PreRotation,
    /// Rotation completed and the salt is recoverable: the salted-final PBS is
    /// the only correct credential.
    Rotated([u8; 32]),
    /// Rotation completed but the salt is NOT recoverable, so the installed
    /// credential cannot be reconstructed. There is no safe fallback — the
    /// unsalted value is a different secret, and handing it to the PRL
    /// handshake fails against an E140 that was paired with the salted one.
    RotatedSaltMissing,
}

/// Classify the journal in a single scan.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[must_use]
pub fn final_pbs_state() -> FinalPbs {
    // SAFETY: page 127 (KEY_PAGE) is a fixed 8 KB in-flash region, owned
    // outright by this journal; this is a read-only view.
    let page = unsafe {
        core::slice::from_raw_parts(
            crate::hw::flash::KEY_PAGE_ADDR as *const u8,
            journal::PAGE_QWS * journal::QW,
        )
    };
    let st = journal::scan(page);
    if !st.all_done() {
        return FinalPbs::PreRotation;
    }
    match st.salt {
        Some(salt) => FinalPbs::Rotated(salt),
        None => FinalPbs::RotatedSaltMissing,
    }
}

/// Scan the page-127 journal and return the persisted TRNG salt iff the whole
/// first-boot ceremony has completed (`ALL_DONE`).
///
/// **Prefer [`final_pbs_state`] for credential selection.** This returns `None`
/// both before the rotation and when a completed rotation's salt is missing,
/// and those two cases require opposite behaviour.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[must_use]
pub fn journal_salt_if_all_done() -> Option<[u8; 32]> {
    // SAFETY: page 127 (KEY_PAGE) is a fixed 8 KB in-flash region, owned
    // outright by this journal; this is a read-only view.
    let page = unsafe {
        core::slice::from_raw_parts(
            crate::hw::flash::KEY_PAGE_ADDR as *const u8,
            journal::PAGE_QWS * journal::QW,
        )
    };
    let st = journal::scan(page);
    if st.all_done() {
        st.salt
    } else {
        None
    }
}

/// Has the first-boot ceremony fully completed (journal `ALL_DONE`)? Used by
/// `main` to gate the every-boot BHK provision/load block: pre-`ALL_DONE` the
/// BHK is owned by Phase B (journal-gated, anti-pre-plant), so the every-boot
/// block must stand down to avoid a stale double-lock.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
#[must_use]
pub fn journal_all_done() -> bool {
    // `journal_page()` is defined in the Phase A/B section below (forward
    // reference is fine at module scope).
    journal::scan(journal_page()).all_done()
}

// ===========================================================================
// Phase A (pre-lock) + Phase B (post-lock) entry points + the real
// `FirstBootHw` implementation. Only compiled for the shipping self-lock
// feature. `rdp2-self-lock` implies `stm32u585` (via `bhk` → `saes-dhuk`), so
// these are real-silicon paths.
// ===========================================================================

#[cfg(all(not(test), feature = "rdp2-self-lock"))]
use state::{FirstBootError, FirstBootHw, FirstBootStep};

/// Read the 8 KB page-127 journal as a memory-mapped slice (no stack copy).
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
fn journal_page() -> &'static [u8] {
    // SAFETY: page 127 (KEY_PAGE) is a fixed 8 KB in-flash region owned
    // outright by the first-boot journal; this is a read-only view.
    unsafe {
        core::slice::from_raw_parts(
            crate::hw::flash::KEY_PAGE_ADDR as *const u8,
            journal::PAGE_QWS * journal::QW,
        )
    }
}

/// Render a numbered fault + park. `EXXXX` is the stable [`FirstBootError`]
/// code (0x08xx–0x0Fxx, disjoint from `FactoryErrorCode`); a field owner
/// photographs it for the vendor error-code → diagnosis table.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
fn halt_first_boot(code: FirstBootError) -> ! {
    #[cfg(feature = "debug-log")]
    secure_log!("[first_boot] FAULT code={:#06x} — HALT", code.raw());

    // "EXXXX HALT" — pure ASCII, fits the 16-col row.
    let raw = code.raw();
    let hex = b"0123456789ABCDEF";
    let mut line = [0u8; 16];
    line[0] = b'E';
    line[1] = hex[((raw >> 12) & 0xF) as usize];
    line[2] = hex[((raw >> 8) & 0xF) as usize];
    line[3] = hex[((raw >> 4) & 0xF) as usize];
    line[4] = hex[(raw & 0xF) as usize];
    line[5..10].copy_from_slice(b" HALT");
    let sub = core::str::from_utf8(&line[..10]).unwrap_or("HALT");
    crate::ui::show_status("FIRST BOOT FAIL", sub);

    loop {
        cortex_m::asm::wfi();
    }
}

/// **Phase A** (work-todo #36): runs at earliest boot when RDP != Level 2.
/// Verifies the ship option-byte profile + blank per-device pages, warns the
/// user, then programs RDP=0xCC (which resets the MCU). Returns normally only
/// when the device is ALREADY locked (RDP-2) — i.e. every boot after the
/// first — so the caller continues into Phase B / normal boot. A profile
/// mismatch halts UNLOCKED (the unit stays returnable/reflashable — never turn
/// a bad flash into an RDP-2 brick).
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
pub fn run_pre_lock_and_maybe_lock() {
    use crate::hw::flash;
    use sphincs_tz_shared::lockdown::{self, RdpLevel};

    // Idempotence: already locked → normal boot (this check runs every boot).
    if flash::rdp_level() == RdpLevel::L2 {
        return;
    }

    // R2.1 — verify the published ship option-byte profile (TZEN / RDP / SECWM
    // / SECBOOTADD0 / WRP1A / OEM-locks). A mismatch means this is not a genuine
    // RDP-0 ship unit (or a transit attacker tampered with the option bytes).
    // The granular `ObField` → E08xx map names the exact failing field on the
    // fault screen (R5.1). Phase A only ever WRITES the RDP byte, never WRP or
    // any other option byte — this is R2.1 "verify, don't set".
    if let Err(field) = lockdown::verify_ship_profile(
        flash::optr_raw(),
        flash::secwm1r1_raw(),
        flash::secwm2r1_raw(),
        flash::secboot_add0_reg(),
        flash::wrp1ar_raw(),
        flash::oem_lock_status_raw(),
        &lockdown::SHIP_PROFILE_U585,
    ) {
        halt_first_boot(state::ob_field_code(field));
    }

    // R2.2 — blank-check the per-device pages 123..=127 BEFORE locking: a
    // pre-planted page-127 journal salt would otherwise yield a predictable
    // final PBS (#36 hardening #3), and a planted journal would spoof "already
    // done". Distinct code from the profile mismatch.
    for page in 123..=127u32 {
        if !flash::is_secure_page_blank(page) {
            halt_first_boot(FirstBootError::PerDevicePageNotBlank);
        }
    }

    // R2.3 — the factory OTP master roots every transport keyset Phase B
    // authenticates against. Verify it PRE-lock (fail UNLOCKED / returnable,
    // 0x0803) so a unit the factory left unburned is never welded shut only to
    // discover the post-lock RMA code 0x0811. (Phase B keeps a belt-and-braces
    // re-check for resume boots and FI skips.)
    if !crate::hw::otp::is_device_master_burned() {
        halt_first_boot(FirstBootError::OtpMasterMissingPreLock);
    }

    // R2.4 — CONFIRM GATE (owner decision 2026-07-17). The RDP-2 burn is the
    // single most irreversible action the device ever takes — it permanently
    // forfeits SWD verification — so it MUST NOT run automatically. Show the
    // lock-confirm screen and require a deliberate BOTH-buttons chord (the
    // button driver synthesizes it to a long-right confirm) after the user has
    // scrolled to the last page. Everything above was a pure read, so until
    // this confirm the device has touched no SE / USB / journal state (R2.4).
    //
    // Timing note (do NOT "fix" by moving `setup_systick`/`iwdg::init` earlier):
    // Phase A runs before SysTick and before the IWDG start, on purpose. The
    // button driver polls via a calibrated busy-wait (`buttons::delay_ms`), so
    // presses are detected without SysTick; `is_idle()` reads the never-ticked
    // counter as 0 → never idle → the prompt blocks indefinitely for the
    // deliberate press (exactly R2.4); and with the IWDG not yet started there
    // is no watchdog reset while the user reads and confirms. Starting either
    // timer here would trade this correct behaviour for an idle-wipe/watchdog
    // reset mid-confirm.
    let pages = state::build_lock_confirm_pages();
    let (verdict, sentinel) = crate::ui::confirm::confirm_checked(&pages);
    let confirmed = matches!(verdict, crate::ui::confirm::ConfirmResult::Confirmed);
    // Two independent words, both required (FI idiom), and the gate itself
    // returns a Hamming-distant sentinel — so the burn fires only on an exact
    // `OK_SENTINEL`, never on a stuck-at-1 truthy value. Decline / cancel / idle
    // all mean "not now" → stay unlocked and re-prompt next boot.
    if state::rdp_burn_authorized(confirmed, sentinel) != crate::fi::OK_SENTINEL {
        park_unlocked_reprompt_next_boot();
    }

    // R2.4 passed → R2.5 burn. "DO NOT POWER OFF" during the OPTSTRT window.
    crate::ui::show_status("LOCKING", "DO NOT POWER OFF");
    // (BOR/VBUS power-stability check is a silicon-validation refinement — see
    // the #36 runbook; BOR is configured via the shipped option-byte profile.)

    // Program RDP=0xCC → OBL_LAUNCH. On success this resets the MCU and never
    // returns; it only returns on a pre-launch error.
    // SAFETY: the ship profile + blank per-device pages + OTP master are
    // verified above and the user confirmed the lock.
    if unsafe { flash::program_rdp_level2_and_launch() }.is_err() {
        halt_first_boot(FirstBootError::RdpProgramFailed);
    }
    // Unreachable on success (the device reset). If OBL_LAUNCH somehow failed
    // to reset, park rather than continue below RDP-2.
    loop {
        cortex_m::asm::wfe();
    }
}

/// R2.4 decline / cancel / idle: the owner did not confirm the lock. Stay at
/// RDP-0, touch nothing (no SE, no USB, no journal), and park. The next
/// power-on re-enters Phase A (RDP != L2) and shows the same prompt again. This
/// is deliberately NOT a fault (no `E08xx`) and NOT a wipe — no wallet exists
/// on the device yet.
#[cfg(all(not(test), feature = "rdp2-self-lock"))]
fn park_unlocked_reprompt_next_boot() -> ! {
    crate::ui::show_status("NOT LOCKED", "power to retry");
    loop {
        cortex_m::asm::wfi();
    }
}

/// The real [`FirstBootHw`] over the dual-SE + the platform HW modules.
#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
struct FirstBootHwImpl<'a> {
    se: &'a mut crate::dual_se::DualSecureElement,
}

#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
impl FirstBootHw for FirstBootHwImpl<'_> {
    fn journal(&self) -> journal::JournalState {
        journal::scan(journal_page())
    }

    fn commit_step(&mut self, step_id: u8) -> Result<(), FirstBootError> {
        let idx = self.journal().next_free;
        let rec = journal::encode_step(step_id);
        // SAFETY: append at the scanned `next_free` (currently-erased QW).
        unsafe { crate::hw::flash::write_journal_qw(idx, &rec) }
            .map_err(|_| FirstBootError::JournalWriteFailed)
    }

    fn commit_salt(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
        let recs = journal::encode_salt(salt);
        let st = self.journal();
        // Reserve the complete three-QW salt record plus the two step markers
        // that must follow it. Refuse before the first program command rather
        // than persist a salt that can never reach ALL_DONE.
        if !st.can_append(journal::SALT_COMPLETION_RESERVE_QWS) {
            return Err(FirstBootError::OptigaSaltPersistFailed);
        }
        let mut idx = st.next_free;
        for r in &recs {
            // SAFETY: consecutive erased QWs from `next_free` (data, data, hdr).
            unsafe { crate::hw::flash::write_journal_qw(idx, r) }
                .map_err(|_| FirstBootError::OptigaSaltPersistFailed)?;
            idx += 1;
        }
        Ok(())
    }

    fn otp_master_burned(&self) -> bool {
        crate::hw::otp::is_device_master_burned()
    }

    fn saes_alive(&self) -> bool {
        crate::hw::saes::self_test().is_ok()
    }

    fn bhk_provision_and_lock(&mut self) -> Result<(), FirstBootError> {
        // Anti-pre-plant (#36 hardening #2): erase page 126 UNCONDITIONALLY so
        // a known BHK planted at RDP-0 (which survives RDP 0→2, no mass-erase)
        // is destroyed before we provision a fresh three-source BHK. The
        // state machine established the OPTIGA transport shield immediately
        // before this call. Establish SE050 explicitly under its OTP-rooted
        // transport SCP03 keys too: ordinary `Se050::init` would select the
        // not-yet-existing BHK-derived final keys and is circular here.
        self.se
            .se050
            .establish_transport_for_entropy()
            .map_err(|_| FirstBootError::BhkProvisionFailed)?;
        // Use the explicit handle to avoid aliasing the global SE.
        // SAFETY: single-threaded secure world; page 126 is the BHK store.
        unsafe {
            crate::hw::flash::erase_secure_page(crate::hw::bhk::BHK_PAGE_NUM)
                .map_err(|_| FirstBootError::BhkPageHostile)?;
        }
        let mut bhk = [0u8; 32];
        crate::rng_strong::fill_with_source_draw(&mut bhk, |source, block| match source {
            crate::rng_strong_fold::SeSource::Optiga => self.se.optiga.random(block).is_ok(),
            crate::rng_strong_fold::SeSource::Se050 => self
                .se
                .se050
                .random_from_established_transport(block)
                .is_ok(),
        })
        .map_err(|_| FirstBootError::BhkProvisionFailed)?;
        unsafe {
            crate::hw::bhk::provision_from_entropy(&mut bhk)
                .map_err(|_| FirstBootError::BhkProvisionFailed)?;
            crate::hw::bhk::load_and_lock().map_err(|_| FirstBootError::BhkProvisionFailed)?;
        }
        Ok(())
    }

    fn se050_rotate_scp03(&mut self) -> Result<(), FirstBootError> {
        self.se
            .se050
            .rotate_scp03_transport_to_final()
            .map_err(|_| FirstBootError::Se050EstablishFailed)
    }

    fn se050_rekey_admin(&mut self) -> Result<(), FirstBootError> {
        self.se
            .se050
            .rekey_admin_transport_to_final()
            .map_err(|_| FirstBootError::Se050AdminRekeyFailed)
    }

    fn optiga_establish_transport_shield(&mut self) -> Result<(), FirstBootError> {
        // #443: bring the shield up under the transport PBS (E140 untouched) so
        // the 3-source salt draw's mandatory OPTIGA leg can answer. Both the
        // inconclusive-`Transport` and authoritative-`Shield` verdicts map to
        // the same halt code — the next boot re-enters the fresh path and
        // re-tries the handshake with a fresh link.
        self.se
            .optiga
            .establish_transport_shield()
            .map_err(|_| FirstBootError::OptigaTransportShieldFailed)
    }

    fn trng_salt(&mut self) -> Result<[u8; 32], FirstBootError> {
        // The OPTIGA shield was established just above (fresh path), so the
        // strong-RNG's mandatory OPTIGA leg can answer. A failure here is the
        // draw itself (a TRNG/leg fault or the all-zero gate) — distinct from
        // the journal-persist failure that keeps `OptigaSaltPersistFailed`.
        let mut salt = [0u8; 32];
        crate::rng_strong::fill_with_store(&mut salt, self.se)
            .map_err(|_| FirstBootError::TrngSaltDrawFailed)?;
        Ok(salt)
    }

    fn optiga_rotate_pbs(&mut self, salt: &[u8; 32]) -> Result<(), FirstBootError> {
        self.se
            .optiga
            .rotate_pbs_to_salted(salt)
            .map_err(|_| FirstBootError::OptigaSetDataFailed)
    }

    fn ui_step(&mut self, _step: FirstBootStep, resuming: bool) {
        if resuming {
            crate::ui::show_status("RECOVERING", "DO NOT POWER OFF");
        } else {
            crate::ui::show_status("FIRST BOOT SETUP", "DO NOT POWER OFF");
        }
    }
}

/// **Phase B** (work-todo #36): post-lock, journaled, resumable provisioning.
/// Runs after the RDP-2 self-lock, BEFORE first PIN entry / the seed wizard.
/// A completed ceremony (journal `ALL_DONE`) returns immediately; otherwise it
/// resumes the state machine and either completes or halts on a numbered RMA.
#[cfg(all(not(test), feature = "rdp2-self-lock", feature = "dual-se"))]
pub fn run_post_lock_provisioning(se: &mut crate::dual_se::DualSecureElement) {
    let js = journal::scan(journal_page());
    if js.all_done() {
        return;
    }

    // Resume-load the BHK: if the BHK step already committed on a prior boot
    // but the whole ceremony hasn't (so the every-boot BHK block in `main` is
    // still gated OFF), the BHK is on flash but NOT yet loaded into the TAMP
    // backup registers this boot — and step 3 derives BHK-rooted SE050 keys.
    // Load + lock it now (exactly once per boot; step 2 owns the first-time
    // provision, so these two paths never both run in one boot).
    if js.has(journal::DONE_BHK) {
        // SAFETY: BHK was provisioned on a prior boot; load into TAMP + lock.
        if unsafe { crate::hw::bhk::load_and_lock() }.is_err() {
            halt_first_boot(FirstBootError::BhkProvisionFailed);
        }
    }

    let mut hw = FirstBootHwImpl { se };
    if let Err(fault) = state::run(&mut hw) {
        halt_first_boot(fault.code);
    }
    // Ok → journal ALL_DONE; boot continues to the seed wizard.
}
