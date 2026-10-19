//! NXP SE050 secure element driver.
//!
//! Stores BIP-39 entropy on the SE050, protected by a hardware-enforced
//! UserID PIN (max 10 attempts before permanent lockout).
//!
//! Communication: I2C1 (PB8 SCL, PB9 SDA) -> T1oI2C -> SE05x APDUs,
//! all wrapped in an SCP03 authenticated/encrypted channel.

pub mod i2c;
#[cfg(feature = "se050-probe")]
pub mod probe;
pub mod t1oi2c;
pub mod apdu;
pub mod scp03;

use apdu::Se050Error;
use scp03::Scp03Session;
use t1oi2c::{T1Error, T1State};

// ---------------------------------------------------------------------------
// Object IDs on the SE050
// ---------------------------------------------------------------------------

/// UserID authentication object — hardware-enforced PIN.
/// Range v6 (0x7B10xxxx). Previous ranges retire on bench chips after
/// cross-test contamination leaves their UserIDs / admin-UserIDs stuck
/// with no software recovery path:
///   v1 (0x7B00_0000/2/3/5) — early-firmware sweep, policy gaps
///   v2 (0x7B00_2000)       — same era, ditto
///   v3 (0x7B06_xxxx)       — retired 2026-04-21 after cross-test
///                            admin-PIN-mismatch incident
///   v4 (0x7B0C_xxxx)       — retired 2026-04-21 same day, after a
///                            Transport glitch mid-`admin_factory_reset`
///                            left admin UserID on chip while the
///                            unconditional page-125 erase burned the
///                            matching flash PIN
///   v5 (0x7B0E_xxxx)       — retired 2026-04-22 on bench board after
///                            a pre-`7fa28b0` firmware run had already
///                            unconditionally erased page 125 while
///                            leaving the admin UserID on chip with
///                            a randomly-generated PIN. With page 125
///                            blank the conditional-erase code (added
///                            in `7fa28b0`) can't recover the admin
///                            PIN; no firmware-reachable credential
///                            can delete the stranded admin, so the
///                            range is permanently contaminated on
///                            that chip. v6 ships with the hardware-
///                            root-derived admin PIN (`se050_admin_pin()`,
///                            see below), so this failure class is
///                            structurally eliminated — the admin PIN
///                            is always firmware-reproducible, no flash
///                            pairing to desync.
/// Bumping the range yields a chip as usable as a fresh one — the
/// stuck OIDs occupy <150 bytes of ~130 KB persistent storage.
pub const USERID_OBJ: u32 = 0x7B10_0000;

/// Raw BIP-39 entropy (32 bytes), policy requires UserID auth.
pub const ENTROPY_OBJ: u32 = 0x7B10_0001;

/// Verifying key (32 bytes), policy requires UserID auth.
pub const VK_OBJ: u32 = 0x7B10_0002;

/// Bootstrap verifying key (32 bytes), policy requires UserID auth.
pub const BOOTSTRAP_VK_OBJ: u32 = 0x7B10_0003;

// ---- §32 duress (decoy) wallet objects (`duress-pin` feature) -------------
// A second decoy wallet's SE050 share, gated behind a SECOND UserID with
// `max_attempts=0` (unlimited — a wrong duress PIN must not trip SE050's
// own silicon lockout; the MCU page-124 counter is what gates lockout on a
// wrong duress entry, handled in the P3 unlock path). Lives in the v6
// 0x7B10_xxxx range so the admin-wipe sweep (ADMIN_WIPE_OBJ has delete
// authority over the range) reclaims it on factory reset. Coexistence with
// the real UserID validated on silicon 2026-05-20 (`make duress-probe-hw`).
/// Duress UserID (decoy wallet PIN gate, max_attempts=0 / unlimited).
pub const DURESS_USERID_OBJ: u32 = 0x7B10_0010;
/// Duress half_E (decoy entropy SE050 share), policy requires duress UserID auth.
pub const DURESS_ENTROPY_OBJ: u32 = 0x7B10_0011;
/// Duress verifying key (decoy wallet VK).
pub const DURESS_VK_OBJ: u32 = 0x7B10_0012;
/// Duress bootstrap verifying key (decoy wallet).
pub const DURESS_BOOTSTRAP_VK_OBJ: u32 = 0x7B10_0013;

/// Admin wipe UserID. Second auth object, created at provisioning
/// with a hardware-root-derived PIN (`hw::secret_keys::se050_admin_pin()`
/// → `derive_into_bhk("pqsigner/se050-admin-pin-v1")`): in a `bhk`
/// build (the current candidate hardware shape since the Phase-2C call-site
/// flip, `aa23f05`) that's `SAES-CMAC(silicon-BHK, …)`; with `saes-dhuk`
/// alone it falls through to `SAES-CMAC(DHUK, …)`; on the legacy /
/// `otp-hardcoded-master-key` path it's `HKDF(OTP-master/const, …)`.
/// Every variant is deterministic per device and stable across power
/// cycles, reflashes, and a flash mass-erase (the only exception: the
/// BHK lives in flash page 126, so an RDP regression loses it → the
/// SE050 needs re-pairing afterward — but losing the *admin* PIN that
/// way is non-fatal, you don't need it during recovery, and an RDP2-locked
/// unit can't be regressed). Used by the PIN-lockout
/// factory-reset path: after 10 failed user PIN attempts, firmware
/// authenticates against this object and deletes every user object
/// (which all carry an admin-delete policy entry pointing here).
///
/// **Current-helper invariant (post-v6)**: the admin PIN is reproducible from
/// a silicon hardware root, never persisted, so there is no flash-side
/// pairing to drift out of sync with the on-chip UserID. The #36 candidate
/// rekeys the factory transport UserID to this BHK-rooted final helper; its
/// handoff/recovery contract and silicon authority remain open. Previous
/// ranges (v3–v5) paired admin with a flash page-125 PIN slot and
/// retired whenever the two desynchronised; v6 removes the coupling
/// entirely (`hw::flash::write_admin_pin`/`read_admin_pin` deleted).
///
/// Page 125 still exists — it now holds only the wipe-in-progress
/// flag (`arm_wipe_flag / is_wipe_armed`) and the legacy PIN slot
/// that pre-v6 provisionings wrote to. On fresh v6 provisionings the
/// PIN slot stays blank; `erase_admin_page` is still called
/// conditionally after a successful wipe to clear the flag.
pub const ADMIN_WIPE_OBJ: u32 = 0x7B10_00A0;

/// The admin-delete policy entry of the user and duress UserID objects.
///
/// Shipping images: `None`. That is S-6
/// (`docs/security/security-review-2026-05.md` §C-8): with an admin entry,
/// whoever holds the admin credential could delete the UserID, recreate it
/// with a value of their own, and read the half it gates.
///
/// Bench images (`e2e-test` / `otp-hardcoded-master-key`): the admin wipe
/// object (#912). On those builds the admin credential derives from a
/// public constant, so S-6 protects nothing; and a UserID that only its own
/// value can delete strands the chip, because every wrong value spends one
/// of its ten attempts for good and a locked UserID blocks provisioning at
/// its OID. With the entry, the admin wipe removes it and no clean-up has to
/// guess a PIN.
///
/// The predicate is the bench predicate of `pin_gate::salt_policy` (pinned
/// together in `se050_under_test`). `mode-production` forbids both
/// features; the assertion below fails the build if that ever stops being
/// true.
///
/// Not covered: an image built with `e2e-skip-admin-wipe` provisions no
/// admin object, so `store_objects` has no admin entry to give (`admin_ref`
/// is `None`) and its UserID is again deletable only by its own value. No
/// Makefile target enables that feature any more. A second run of such an
/// image does NOT work: the OPTIGA half is rewritten and the SE050 half is
/// kept, so the unlock check fails.
pub(crate) const USERID_ADMIN_DELETE: Option<u32> =
    if cfg!(any(feature = "e2e-test", feature = "otp-hardcoded-master-key")) {
        Some(ADMIN_WIPE_OBJ)
    } else {
        None
    };

#[cfg(feature = "mode-production")]
const _: () = assert!(
    USERID_ADMIN_DELETE.is_none(),
    "S-6: a production image must not give the admin delete authority over a UserID"
);

/// What to tell a bench operator when the user UserID is still on the chip
/// after an admin wipe. There are two different causes and only one of them
/// is a reason to present a value. They are told apart by whether the admin
/// wipe itself completed (`admin_wipe_ok`), NOT by whether the admin object
/// is still there: after a failed admin VERIFY or a refused delete the
/// session is pending (A3) and an existence check cannot be trusted, and a
/// refused UserID delete also makes the admin object's own delete fail
/// (pre-landing review of #912).
#[must_use]
pub(crate) const fn userid_survivor_help(admin_wipe_ok: bool) -> &'static str {
    if admin_wipe_ok {
        "the admin wipe ran and the SE050 user UserID is still on the chip, so that \
         UserID has no admin-delete entry (written before #912, or by an \
         `e2e-skip-admin-wipe` image). Only its own value deletes it. Nothing is \
         guessed here: a wrong value costs one of its ten attempts for good. Run \
         `make se050-reset SE050_RESET_PIN=<its PIN> SE050_RESET_FORMAT=<raw|derived>` once"
    } else {
        "the admin wipe did NOT complete (its error is in the line above) and the \
         SE050 user UserID is still on the chip. If the admin authentication failed, \
         the admin object on this chip was written under another key root (a `bhk` \
         or `saes-dhuk` image, or another master) and nothing in this image can \
         delete anything: flash the image flavour that provisioned the chip. Do NOT \
         spend a UserID attempt on this"
    }
}

// -- Factory-reset self-test object IDs --
// Distinct from production IDs so the test never collides with a real
// provisioning, and is repeatable on a chip that already has prod
// objects at 0x7B10_xxxx.
#[cfg(feature = "se050-reset-e2e")]
const TEST_USERID_OBJ: u32 = 0x7B07_0000;
#[cfg(feature = "se050-reset-e2e")]
const TEST_DATA_OBJ_A: u32 = 0x7B07_0001;
#[cfg(feature = "se050-reset-e2e")]
const TEST_DATA_OBJ_B: u32 = 0x7B07_0002;

// ---------------------------------------------------------------------------
// Se050
// ---------------------------------------------------------------------------

/// SE050 secure element driver.
///
/// Caches the encrypted entropy blob, VK, and bootstrap VK in struct fields
/// after provisioning or unlock, so signing operations don't require
/// re-authenticating against the SE050 hardware.
pub struct Se050 {
    t1: T1State,
    scp03: Scp03Session,
    ready: bool,
    // Caches populated on provision/unlock, cleared on zeroize.
    entropy_blob_cache: [u8; crate::crypto::ENTROPY_BLOB_LEN],
    blob_cached: crate::fih::FihBool,
    vk_cache: [u8; 32],
    vk_cached: bool,
    bootstrap_vk_cache: [u8; 32],
    bootstrap_vk_cached: bool,
    /// In-RAM mirror of the SE050 UserID remaining-attempts counter.
    /// Display cache only — never a control-flow gate. The chip's own
    /// UserID counter is authoritative and durable across reboots;
    /// this field resets to `MAX_ATTEMPTS` in the driver constructor
    /// and on every successful unlock, so after a power cycle with
    /// prior failures the cache can temporarily report more remaining
    /// than the chip. The next successful unlock re-syncs both to
    /// `MAX_ATTEMPTS` (chip auto-resets on success, cache mirrors).
    /// Do NOT promote this value to a lockout or skip-SE gate.
    remaining: u8,
}

impl Se050 {
    pub const fn new() -> Self {
        Self {
            t1: T1State::new(),
            scp03: Scp03Session::new(),
            ready: false,
            entropy_blob_cache: [0; crate::crypto::ENTROPY_BLOB_LEN],
            blob_cached: crate::fih::FihBool::new_false(),
            vk_cache: [0; 32],
            vk_cached: false,
            bootstrap_vk_cache: [0; 32],
            bootstrap_vk_cached: false,
            remaining: sphincs_tz_shared::MAX_ATTEMPTS,
        }
    }

    /// Re-initialize SE050 state for a fresh handshake.
    ///
    /// Clears `ready`, replaces `scp03` with a zeroed `Scp03Session`,
    /// then runs the normal `init()` sequence (T=1' reset, applet
    /// SELECT, SCP03 establish). Caller is responsible for ensuring no
    /// outstanding session IDs from the prior handshake are reused —
    /// every fresh `init()` yields a new MCV / counter pair.
    ///
    /// **Production use (A3 mitigation, 2026-05-28).** Originally only
    /// the `se050-stress` harness called this. Silicon Finding A3
    /// (`docs/secure-elements/se050-silicon-findings.md` §4) showed B-U585I-IOT02A
    /// leaves the chip in a "session-pending" state after a failed
    /// `verify_session` (and possibly a failed `delete_object_authed`
    /// / `close_session`); subsequent non-session APDUs — and even
    /// fresh `create_session` calls — return SW=0x6982 until the chip
    /// is power-cycled OR `reinit()` is invoked. Production callers
    /// (`authenticate_and_read` failed-verify path, `admin_factory_
    /// reset` post-wipe verification, duress / user-reset failed-
    /// verify paths) now invoke `reinit()` to recover so the next
    /// gateway command sees a clean chip. Cost is ~one SCP03
    /// handshake (~100–300 ms on silicon).
    pub fn reinit(&mut self) -> Result<(), Se050Error> {
        self.ready = false;
        self.scp03 = Scp03Session::new();
        self.init()
    }

    /// Split-borrow accessor exposing the T=1' state and SCP03 session
    /// as two co-living mutable references. Used by the `se050-stress`
    /// harness (`StressCtx`, `oid::admin_sweep_*`) to call the
    /// crate-private `apdu::*` helpers, which take both refs in the
    /// same signature.
    ///
    /// Implemented as a single accessor so the borrow checker sees the
    /// two fields as disjoint (the existing `run_*_roundtrip` impls
    /// use `&mut self.t1` / `&mut self.scp03` directly for the same
    /// reason). Production code MUST go through the typed helpers;
    /// this exists for in-tree testing only.
    #[cfg(any(feature = "se050-stress", feature = "se050-probe"))]
    pub(crate) fn t1_scp03_mut(&mut self) -> (&mut T1State, &mut Scp03Session) {
        (&mut self.t1, &mut self.scp03)
    }

    /// Initialize the SE050: T1oI2C reset, applet SELECT, SCP03 establish.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops only while
    /// the SCP03 session is live: `ready && !scp03.active` — the state the
    /// lock / idle-wipe zeroize leaves behind — re-runs the FULL sequence
    /// (idle-relock fix 2026-07-02). Short-circuiting on the stale `ready`
    /// flag alone is what made every post-relock APDU run session-less:
    /// the chip (whose own SCP03 session was still up) refused them with
    /// 0x6982/0x6985 and a correct PIN surfaced as "Wrong PIN".
    pub fn init(&mut self) -> Result<(), Se050Error> {
        if self.ready {
            if self.scp03.active {
                return Ok(());
            }
            // Same recovery contract as `reinit()`: discard the dead
            // session state, then fall through to the full handshake.
            self.ready = false;
            self.scp03 = Scp03Session::new();
        }

        unsafe {
            // SAFETY: single-threaded secure world; the T=1 link + applet
            // select touch only this driver's `t1` state.
            self.link_bringup()?;

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init: establishing SCP03...");

            scp03::establish(&mut self.scp03, &mut self.t1)?;

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init complete");
        }

        self.ready = true;
        Ok(())
    }

    /// T=1 link bring-up: power-on settle → `interface_reset` (cold-boot
    /// retry loop) → `select_applet`. Shared by `init` (which then does the
    /// SCP03 establish under the build's preferred keys) and the work-todo #36
    /// first-boot rotation methods (which establish under explicit
    /// transport/final keys). Does NOT establish SCP03 or set `ready`.
    ///
    /// # Safety
    /// Drives the SE050 T=1 interface; single-threaded secure world.
    unsafe fn link_bringup(&mut self) -> Result<(), Se050Error> {
        // SAFETY: matches the original `init` body — all T=1 / applet-select
        // operations run in the single-threaded secure world on this driver's
        // own `t1` state.
        unsafe {
            // Initial power-on settle (~3 ms at 160 MHz). Covers the
            // warm-reset case (`probe-rs reset`) where the SE050 was
            // recently powered and only needs the T=1 state to clear.
            // The retry loop below handles the cold-boot case.
            for _ in 0..500_000 {
                cortex_m::asm::nop();
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init: interface reset...");

            // Cold-boot retry loop. On a true cold power-cycle (USB-C
            // unplug → replug, first boot after board power-up) the
            // SE050's internal regulator + secure-channel scheduler can
            // take 20–200 ms to become T=1-responsive — well past the
            // 3 ms single-shot delay above. During that window
            // `interface_reset()` fails fast: I2C NACKs the S(RESET_REQ)
            // write (`T1Error::I2c`) or the SOF poll in `read_frame`
            // exhausts `MAX_READ_RETRIES` without ever seeing 0xA5
            // (`T1Error::Timeout`). Without retrying, we propagate
            // `Se050Error::Transport`, `check_provisioned` returns
            // false, and the first-boot wizard fires on an
            // already-provisioned device. Mirrors the OPTIGA ACK retry
            // pattern in `optiga::mod::OptigaTrustM::init`.
            //
            // 20 attempts × ~50 ms delay = ~1 s total. Empirically, a
            // cold SE050 responds by attempt 3–5; the headroom covers
            // worst-case slow regulators / capacitor pre-charge on the
            // TRUSTMV3SHIELDTOBO1 + SE050 arduino-shield combo.
            const MAX_RESET_ATTEMPTS: u32 = 20;
            const RESET_RETRY_DELAY_CYCLES: u32 = 8_000_000; // ~50 ms @ 160 MHz
            let mut reset_ok = false;
            let mut success_attempt: u32 = 0;
            #[allow(unused_assignments)]
            let mut last_err: Option<T1Error> = None;
            for attempt in 0..MAX_RESET_ATTEMPTS {
                match self.t1.interface_reset() {
                    Ok(()) => {
                        reset_ok = true;
                        success_attempt = attempt;
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        cortex_m::asm::delay(RESET_RETRY_DELAY_CYCLES);
                    }
                }
            }
            if !reset_ok {
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[SE050] interface_reset FAILED after {} attempts: {:?}",
                    MAX_RESET_ATTEMPTS, last_err
                );
                return Err(Se050Error::Transport);
            }
            #[cfg(feature = "debug-log")]
            if success_attempt > 0 {
                secure_log!(
                    "[SE050] interface_reset OK on attempt {} (cold-boot retry)",
                    success_attempt + 1
                );
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init: selecting applet...");

            apdu::select_applet(&mut self.t1)?;

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] link bring-up complete (applet selected)");
        }

        Ok(())
    }

    /// First-boot-only SCP03 establishment under the explicit OTP-rooted
    /// transport keys, before the BHK exists.
    ///
    /// The ordinary [`Self::init`] selects the build's preferred final keys;
    /// in a `bhk` build those are BHK-derived and therefore circular while we
    /// are generating the BHK itself. This method has no fallback and exists
    /// solely to make the SE050 TRNG available to that three-source draw.
    #[cfg(feature = "rdp2-self-lock")]
    pub(crate) fn establish_transport_for_entropy(&mut self) -> Result<(), Se050Error> {
        use crate::hw::secret_keys as sk;
        use zeroize::Zeroize;

        let map = |_| Se050Error::Scp03;
        let mut enc = sk::transport_se050_scp03_enc().map_err(map)?;
        let mut mac = sk::transport_se050_scp03_mac().map_err(map)?;

        self.ready = false;
        self.scp03.zeroize_session();
        self.scp03 = Scp03Session::new();
        let result = (|| unsafe {
            self.link_bringup()?;
            scp03::establish_with(&mut self.scp03, &mut self.t1, &enc, &mac)
                .map_err(|_| Se050Error::Scp03)?;
            self.ready = true;
            Ok(())
        })();

        enc.zeroize();
        mac.zeroize();
        crate::fi::zeroize_barrier();
        if result.is_err() {
            self.ready = false;
            self.scp03.zeroize_session();
        }
        result
    }

    /// Draw from the SE050 TRNG using the already-established explicit
    /// transport session. Never calls lazy [`Self::init`] and therefore can
    /// never switch to the circular BHK-derived key selection.
    #[cfg(feature = "rdp2-self-lock")]
    pub(crate) fn random_from_established_transport(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), Se050Error> {
        if buf.is_empty() {
            return Ok(());
        }
        buf.fill(0);
        crate::fi::zeroize_barrier();
        if !self.ready || !self.scp03.active {
            return Err(Se050Error::Scp03);
        }
        let result = unsafe {
            apdu::get_random(&mut self.t1, &mut self.scp03, buf).map(|_| ())
        };
        if result.is_err() {
            buf.fill(0);
            crate::fi::zeroize_barrier();
        }
        result
    }

    /// work-todo #36 first-boot: rotate the SCP03 keyset from the factory
    /// **transport** keys to the **final** BHK-rooted keys, two-phase.
    ///
    /// Resumable: probes the FINAL keyset first (if it already establishes,
    /// the rotation completed on a prior boot and this is a no-op). Otherwise
    /// establishes under TRANSPORT, sends GP `PUT KEY` (new final keys wrapped
    /// under the current transport DEK), then re-establishes under FINAL to
    /// **confirm** before returning — so a crash mid-rotation re-enters and
    /// converges (the OLD keyset is only "dead" once NEW is proven live).
    ///
    /// Silicon-validation deferred (see the #36 runbook): the transport→final
    /// PUT KEY flow + the re-establish-after-failed-auth link handling must be
    /// proven on a sacrificial part.
    #[cfg(feature = "rdp2-self-lock")]
    pub fn rotate_scp03_transport_to_final(&mut self) -> Result<(), Se050Error> {
        use crate::hw::secret_keys as sk;
        use zeroize::Zeroize;

        let map = |_| Se050Error::Scp03;
        let mut final_enc = sk::se050_scp03_enc_key().map_err(map)?;
        let mut final_mac = sk::se050_scp03_mac_key().map_err(map)?;
        let mut final_dek = sk::se050_scp03_dek_key().map_err(map)?;
        let mut tr_enc = sk::transport_se050_scp03_enc().map_err(map)?;
        let mut tr_mac = sk::transport_se050_scp03_mac().map_err(map)?;
        let mut tr_dek = sk::transport_se050_scp03_dek().map_err(map)?;

        self.ready = false;
        self.scp03.zeroize_session();
        let result = (|| unsafe {
            // Fresh link, then probe FINAL (resume / idempotence).
            //
            // D1: distinguish "the SE rejected these keys" (authoritative — not
            // rotated yet, fall through and rotate) from "the bus faulted"
            // (inconclusive — we learned NOTHING, and must not fall through to
            // a PUT KEY). The old `.is_ok()` collapsed both into "not final",
            // so a T=1' glitch during the probe drove an irreversible key
            // install. Failing closed here IS the retry: the ceremony is
            // journal-resumable and the next boot re-enters with a fresh link.
            self.link_bringup()?;
            self.scp03 = Scp03Session::new();
            match scp03::establish_with(&mut self.scp03, &mut self.t1, &final_enc, &final_mac) {
                Ok(()) => {
                    self.ready = true;
                    return Ok(());
                }
                Err(e) if e.is_inconclusive() => return Err(e),
                // Authoritative reject (cryptogram mismatch / status word):
                // the FINAL keyset is genuinely not installed.
                Err(_) => {}
            }

            // Not final yet: clean link, establish under TRANSPORT. This mutual
            // SCP03 auth (card cryptogram FI-verified inside establish_with_keys)
            // IS the authenticate-before-rotate step — bind it to a proof the
            // PUT KEY must consume, so a glitch that skips the establish leaves
            // the write refused (named production gate).
            let mut proof = scp03::TransportAuthProof::pending(scp03::AUTH_CTX_SCP03_TRANSPORT);
            self.link_bringup()?;
            self.scp03.zeroize_session();
            self.scp03 = Scp03Session::new();
            scp03::establish_with(&mut self.scp03, &mut self.t1, &tr_enc, &tr_mac)
                .map_err(|_| Se050Error::Scp03)?;
            proof.record(scp03::AUTH_CTX_SCP03_TRANSPORT, || self.scp03.active);

            // Install the FINAL keyset in place (KVN 0x0B), key blocks wrapped
            // under the CURRENT (transport) DEK. The buffer holds the wrapped
            // key blocks — wipe it on drop (was previously left in the clear).
            let apdu_buf = zeroize::Zeroizing::new(
                scp03::build_put_key_apdu(&final_enc, &final_mac, &final_dek, &tr_dek).0,
            );
            let mut resp = zeroize::Zeroizing::new([0u8; 32]);

            // CONSUME the authenticate-before-rotate proof immediately before the
            // destructive PUT KEY. A pending proof (skipped/failed transport
            // auth) fails closed here — keys are never installed unauthenticated.
            if proof.authorize_write(scp03::AUTH_CTX_SCP03_TRANSPORT) != crate::fi::OK_SENTINEL {
                return Err(Se050Error::Scp03);
            }

            // `send_apdu` ALREADY strips + verifies SW==0x9000 (the `?`
            // propagates any non-9000 status); its return length is the KCV
            // response BODY, not `body||SW`. The old code re-parsed the body
            // tail as a "SW", which false-failed every real PUT KEY (an empty
            // body → n<2 → Err; a KCV body → a KCV byte read as SW ≠ 0x9000) —
            // i.e. this path never worked on silicon (#398 driver bug). Verify
            // the response KCVs instead, catching a garbled/torn write at write
            // time (HW-ASSUME-PUTKEY-ATOMIC).
            let body_len = apdu::send_apdu(
                &mut self.t1,
                &mut self.scp03,
                &apdu_buf[..scp03::PUT_KEY_APDU_LEN],
                &mut resp[..],
            )?;
            if scp03::verify_put_key_response(&resp[..body_len], &final_enc, &final_mac, &final_dek)
                != crate::fi::OK_SENTINEL
            {
                return Err(Se050Error::Scp03);
            }

            // Confirm: re-establish under FINAL. Only now is rotation "done".
            // (DEK-liveness — proving the FINAL DEK too, not just ENC/MAC — is
            // the bench-gated torn-DEK safety net for the no-KCV-echo case; see
            // the #36 runbook / HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT.)
            self.link_bringup()?;
            self.scp03.zeroize_session();
            self.scp03 = Scp03Session::new();
            scp03::establish_with(&mut self.scp03, &mut self.t1, &final_enc, &final_mac)
                .map_err(|_| Se050Error::Scp03)?;
            self.ready = true;
            Ok(())
        })();

        final_enc.zeroize();
        final_mac.zeroize();
        final_dek.zeroize();
        tr_enc.zeroize();
        tr_mac.zeroize();
        tr_dek.zeroize();
        result
    }

    /// work-todo #36 first-boot: re-key the admin UserID credential
    /// (`ADMIN_WIPE_OBJ`) from the factory **transport** admin PIN to the
    /// **final** BHK-rooted admin PIN. Must run AFTER
    /// `rotate_scp03_transport_to_final` (it uses the final SCP03 channel).
    ///
    /// Resumable: (a) admin absent → recreate with FINAL; (b) already verifies
    /// under FINAL → done; (c) verifies under TRANSPORT → delete + recreate
    /// with FINAL. The admin UserID is created with UNLIMITED attempts, so the
    /// FINAL-then-TRANSPORT verify probes cannot lock it out.
    #[cfg(feature = "rdp2-self-lock")]
    pub fn rekey_admin_transport_to_final(&mut self) -> Result<(), Se050Error> {
        use crate::hw::secret_keys as sk;
        use zeroize::Zeroize;

        self.init()?; // final SCP03 channel (rotation step already completed)

        let map = |_| Se050Error::Scp03;
        let mut final_pin = sk::se050_admin_pin().map_err(map)?;
        let mut tr_pin = sk::transport_se050_admin_pin().map_err(map)?;

        let result = (|| unsafe {
            // (a) Admin object missing (crashed between delete and recreate)?
            //
            // D1: `check_exists` returns `Ok(bool)` when the SE answered and
            // `Err` when we could not ask. The old `.unwrap_or(false)` mapped
            // "I don't know" onto "it's missing" — and "missing" is the branch
            // that WRITES. A single bus glitch on a read-only existence probe
            // therefore drove a credential install. Propagate instead: the
            // ceremony is journal-resumable, so the next boot re-asks.
            match apdu::check_exists(&mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ) {
                Ok(false) => {
                    apdu::write_userid_unlimited(
                        &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ, apdu::UserIdValue::DeviceSecret(&final_pin), None,
                    )?;
                    return Ok(());
                }
                Ok(true) => {}
                Err(e) => return Err(e),
            }

            // (b) Already re-keyed? Verify under FINAL.
            if let Ok(sid) = apdu::create_session(&mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ) {
                let ok = apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&final_pin)).is_ok();
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                if ok {
                    return Ok(());
                }
            }

            // (c) Authenticate under TRANSPORT, delete, recreate with FINAL.
            // The verify_session under the transport admin PIN IS the
            // authenticate-before-rotate step; bind it to a proof the delete
            // must consume, so a skipped/glitched auth (or a wrong transport
            // credential — captured as `auth_ok == false`) fails closed before
            // the destructive delete rather than propagating past it.
            let mut proof = scp03::TransportAuthProof::pending(scp03::AUTH_CTX_ADMIN_TRANSPORT);
            let sid = apdu::create_session(&mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ)?;
            let auth_ok =
                apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&tr_pin)).is_ok();
            proof.record(scp03::AUTH_CTX_ADMIN_TRANSPORT, || auth_ok);
            if proof.authorize_write(scp03::AUTH_CTX_ADMIN_TRANSPORT) != crate::fi::OK_SENTINEL {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                return Err(Se050Error::Scp03);
            }
            apdu::delete_object_authed(&mut self.t1, &mut self.scp03, &sid, ADMIN_WIPE_OBJ)?;
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
            apdu::write_userid_unlimited(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ, apdu::UserIdValue::DeviceSecret(&final_pin), None,
            )?;
            Ok(())
        })();

        final_pin.zeroize();
        tr_pin.zeroize();
        result
    }

    /// **IRREVERSIBLE — sacrificial evidence only.** One-shot GP `PUT KEY`
    /// path: replace the SE050's SCP03 platform keyset `0x0B` in place with
    /// this device's deterministic derived keys
    /// (`secret_keys::se050_scp03_*_key()`, BHK-rooted in a `bhk` build).
    /// This bypasses the journaled `rdp2-self-lock` transport→final path and
    /// must not be used on a unit intended to ship. After this, the published factory
    /// keys are gone and the chip only opens with firmware that re-derives
    /// the matching keys (`establish()`'s probe-on-boot handles that).
    ///
    /// Pre-conditions the sacrificial evidence caller MUST have satisfied
    /// (see `work-todo #20` Stage B + `docs/archive/production-todo-retired-2026-07-19.md`): the unit is at its final
    /// per-die-DHUK RDP level (RDP ≥ 1) so the BHK is stable; the BHK has
    /// been provisioned; this is a factory-fresh chip still holding the
    /// `PLATFORM_*` keys (we `init()` here, which establishes SCP03 —
    /// falling back to the factory keys on a fresh chip — so the running
    /// session is the factory-keyed one, which is what `PUT KEY` needs).
    ///
    /// Refuses (`Se050Error::Scp03`) if the "derived" keys would actually
    /// be the published factory constants — that would mean the derived
    /// path isn't selecting a real root and the ceremony would be a no-op
    /// at best and a desync hazard at worst.
    #[cfg(feature = "se050-rotate-scp03")]
    pub fn rotate_scp03_keys(&mut self) -> Result<(), Se050Error> {
        self.init()?;
        if !self.scp03.active {
            return Err(Se050Error::Scp03);
        }
        let (new_enc, new_mac, new_dek) = scp03::load_platform_keys()?;
        // Guard: never PUT KEY the published constants over themselves.
        if scp03::keys_are_factory_default(&new_enc, &new_mac, &new_dek) {
            #[cfg(feature = "debug-log")]
            secure_log!("[SE050/rotate] REFUSE: derived SCP03 keys == published factory keys — root not selecting?");
            return Err(Se050Error::Scp03);
        }
        // Factory rotation: the chip is still on the published AN12436
        // defaults, so the current DEK that wraps the new key blocks is
        // `PLATFORM_DEK`. (First-boot transport→final rotation passes the
        // per-device transport DEK instead — see work-todo #36.)
        //
        // The PUT KEY APDU carries the new static keys under DEK encryption;
        // wrap it so the buffer auto-wipes on every return path (finding
        // F12/LCR-F4). `new_enc/new_mac/new_dek` are already `Zeroizing`.
        let (apdu, len) =
            scp03::build_put_key_apdu(&new_enc, &new_mac, &new_dek, &crate::scp03_logic::PLATFORM_DEK);
        let apdu = zeroize::Zeroizing::new(apdu);
        let mut resp = zeroize::Zeroizing::new([0u8; 32]);
        // `send_apdu` ALREADY strips + verifies SW==0x9000 (the `?` propagates
        // any non-9000 status); its return length is the KCV response BODY, not
        // `body||SW`. Re-parsing the body tail as a "SW" (the pre-#398 pattern
        // fixed in the first-boot rotation above) false-failed every real
        // PUT KEY — after the chip had already installed the new keys, i.e. the
        // exact desync hazard this function's doc warns about. Verify the
        // echoed KCVs instead (HW-ASSUME-PUTKEY-ATOMIC).
        let body_len =
            unsafe { apdu::send_apdu(&mut self.t1, &mut self.scp03, &apdu[..len], &mut resp[..])? };
        if scp03::verify_put_key_response(&resp[..body_len], &new_enc, &new_mac, &new_dek)
            != crate::fi::OK_SENTINEL
        {
            return Err(Se050Error::Scp03);
        }
        #[cfg(feature = "debug-log")]
        secure_log!("[SE050/rotate] PUT KEY OK — keyset 0x0B replaced with derived keys");
        Ok(())
    }

    /// Iteratively delete every user-created object on the SE050 via
    /// `Se05x_API_DeleteAll_Iterative` semantics.
    ///
    /// Check whether the admin-wipe UserID object exists on the chip.
    /// Used by the dual-SE pre-clean cascade to decide whether it's
    /// safe to erase secure-flash page 125 (don't erase if the admin
    /// UserID is still on the chip — the flash PIN is the only way
    /// to delete it on the next attempt).
    pub fn admin_exists(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        unsafe {
            apdu::check_exists(&mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ)
                .unwrap_or(false)
        }
    }

    /// Draw `buf.len()` bytes from the SE050 hardware TRNG over the
    /// established SCP03 channel. The bytes are NOT intended to be
    /// used in isolation — `hw::rng_strong` XOR-mixes this stream with
    /// the STM32 TRNG (and the OPTIGA TRNG in dual-SE builds) so a
    /// single broken or biased source cannot dictate the output.
    ///
    /// Any `buf.len()` is accepted — `apdu::get_random` chunks requests
    /// larger than the SCP03 per-APDU `GetRandom` ceiling (224 B on this
    /// silicon) across multiple commands.
    pub fn random(&mut self, buf: &mut [u8]) -> Result<(), Se050Error> {
        if buf.is_empty() {
            return Ok(());
        }
        // Self-heal, one bounded retry, as `OptigaTrustM::random` does. Once a
        // bus fault lands mid-APDU the card drops the SCP03 session (the next
        // command answers 0x6982, then 0x6985) while the host still holds
        // `ready && scp03.active`, so `init()` returned early on every later
        // call and every strong-RNG draw failed until reboot (DVT row 4.9,
        // EVT-3D21 2026-10-17). On a failure, discard the session so the
        // retry runs the full SELECT + SCP03 establish. A second failure
        // surfaces as Err; `rng_strong::fill` fails closed.
        let mut last_err = Se050Error::Transport;
        for attempt in 0..2u8 {
            buf.fill(0);
            crate::fi::zeroize_barrier();
            let result = if attempt == 0 { self.init() } else { self.reinit() }.and_then(|()| {
                unsafe { apdu::get_random(&mut self.t1, &mut self.scp03, buf).map(|_| ()) }
            });
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if attempt == 0 {
                        secure_log!(
                            "[SE050] random: {:?} — dropping SCP03 session, re-establish + retry",
                            error
                        );
                    }
                    last_err = error;
                }
            }
        }
        buf.fill(0);
        crate::fi::zeroize_barrier();
        Err(last_err)
    }

    /// PROBE ONLY (`duress-probe-e2e`, §32 duress-PIN feasibility):
    /// create a SECOND UserID at `obj_id` with `max_attempts=0`
    /// (unlimited — like the admin UserID, so it never trips lockout),
    /// then auth against it with `pin`. Returns `Ok(())` iff the
    /// create + verify both succeed — i.e. a duress UserID coexists
    /// with the real one and auths independently. Cleans up any stale
    /// object at `obj_id` first so the probe is re-runnable.
    #[cfg(feature = "duress-probe-e2e")]
    pub fn probe_provision_and_auth_duress_userid(
        &mut self,
        obj_id: u32,
        userid_value: &'static [u8],
    ) -> Result<(), Se050Error> {
        self.init()?;
        unsafe {
            // Re-runnable: if a duress UserID from a prior probe exists,
            // auth with the same pin and self-delete it (best-effort).
            if apdu::check_exists(&mut self.t1, &mut self.scp03, obj_id).unwrap_or(false) {
                if let Ok(sid) = apdu::create_session(&mut self.t1, &mut self.scp03, obj_id) {
                    if apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Fixed(userid_value)).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, obj_id,
                        );
                    }
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                }
            }
            // Unlimited-attempts UserID, no admin binding — the duress
            // credential never locks out at the SE level (the MCU
            // page-124 counter does).  Explicit-unlimited per S-7a.
            apdu::write_userid_unlimited(&mut self.t1, &mut self.scp03, obj_id, apdu::UserIdValue::Fixed(userid_value), None)?;

            // Auth against it.
            let session_id = apdu::create_session(&mut self.t1, &mut self.scp03, obj_id)?;
            let r = apdu::verify_session(&mut self.t1, &mut self.scp03, &session_id, apdu::UserIdValue::Fixed(userid_value));
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
            r?;
        }
        Ok(())
    }

    /// PROBE ONLY (`duress-probe-e2e`, §32 timing measurement): auth
    /// against an EXISTING UserID at `obj_id` — create_session +
    /// verify_session + close, no write/delete. This is the exact shape
    /// of the "extra real verify" a duress entry would run for timing
    /// uniformity, so its latency IS the timing signal we're measuring.
    #[cfg(feature = "duress-probe-e2e")]
    pub fn probe_auth_existing_userid(
        &mut self,
        obj_id: u32,
        userid_value: &'static [u8],
    ) -> Result<(), Se050Error> {
        self.init()?;
        unsafe {
            let sid = apdu::create_session(&mut self.t1, &mut self.scp03, obj_id)?;
            let r = apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Fixed(userid_value));
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
            r
        }
    }

    /// Authenticate the duress UserID with the decoy credential and read back the
    /// decoy SE050 half (`DURESS_ENTROPY_OBJ`). Mirrors
    /// `authenticate_and_read` for the duress credential. Returns `Err`
    /// (before the read, session closed) if the verify fails. Used by
    /// `DualSecureElement::unlock_duress` (P3) + the P2 validation recipe.
    #[cfg(feature = "duress-pin")]
    pub fn duress_read_half(
        &mut self,
        duress_cred: &crate::pin_credential::Se050PinCredential,
    ) -> Result<[u8; 32], Se050Error> {
        self.init()?;
        unsafe {
            let sid = apdu::create_session(&mut self.t1, &mut self.scp03, DURESS_USERID_OBJ)?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Credential(duress_cred),
            ) {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                // A3 recovery — see authenticate_and_read failed-verify
                // path. Critical for the duress-pin chain in
                // `nsc::gated_unlock`: a wrong-PIN-against-duress is
                // expected on every regular unlock, so without this
                // reinit the subsequent `se.unlock(pin)` call's
                // `create_session` would always surface SW=0x6982.
                let _ = self.reinit();
                return Err(e);
            }
            let mut half_e = [0u8; 32];
            let n = apdu::read_authed(
                &mut self.t1, &mut self.scp03, &sid, DURESS_ENTROPY_OBJ, &mut half_e,
            );
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
            match n {
                Ok(32) => Ok(half_e),
                Ok(_) => Err(Se050Error::Transport),
                Err(e) => Err(e),
            }
        }
    }

    /// Verify-ONLY against the duress UserID — no read (session opened,
    /// verified, closed). The SE050 half of the §32 P3 timing PAD: stands
    /// in for the skipped real-UserID verify on a duress-correct unlock so
    /// the total op-count matches a real unlock.
    #[cfg(feature = "duress-pin")]
    pub fn duress_verify(&mut self, duress_cred: &crate::pin_credential::Se050PinCredential) -> Result<(), Se050Error> {
        self.init()?;
        let r = unsafe {
            let sid = apdu::create_session(&mut self.t1, &mut self.scp03, DURESS_USERID_OBJ)?;
            let r = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Credential(duress_cred),
            );
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
            r
        };
        if r.is_err() {
            // A3 recovery — see `authenticate_and_read` doc.
            let _ = self.reinit();
        }
        r
    }

    /// Attempt a non-consuming read of the USERID object's
    /// **failed-attempts USED** attribute. On the production policy this is
    /// expected to return `None`: silicon rejects the attribute read with
    /// SW=0x6986. It therefore supplies no SE050 boot-reconciliation input.
    ///
    /// Mechanism: `ReadObjectAttributes` (CLA=0x80 INS_READ
    /// P2_ATTRIBUTES) reads the object's attribute structure over the
    /// transport SCP03 channel.
    ///
    /// Wire format of the inner TAG_3 value bytes (on a successful read):
    ///
    /// ```text
    ///   off  size  field
    ///    0    4    obj_id (BE)
    ///    4    1    obj_type
    ///    5    1    auth_attr (0x01 = SET for auth objects)
    ///    6    2    auth_attempts (BE)  ← failed-attempt counter
    ///    8    4    auth_obj_id (BE)
    ///   12    2    max_attempts (BE)
    ///   14..       policy bytes
    /// ```
    ///
    /// Returns `Some(used)` (saturating to `u8::MAX`) on success;
    /// `None` if the object doesn't exist, the response is malformed,
    /// the chip rejects the read, or `auth_attr != SET`. The caller —
    /// [`SecureElement::pin_attempt_count`] via the trait impl — uses
    /// `None` as "skip the SE050 leg of the boot-time reconcile."
    ///
    /// **⚠️ Silicon caveat (A1, 2026-05-28).** An earlier draft of this
    /// doc claimed "no user-session authentication is required —
    /// attribute reads describe the object's own policy and state and
    /// are policy-gate-independent in the SE050 design" with a citation
    /// to the NXP SDK `sss_pkcs11_pal_helpers.c:603-613` parser. The
    /// first end-to-end stress run on a real B-U585I-IOT02A
    /// (`docs/secure-elements/se050-silicon-findings.md` §2; raw evidence
    /// `b88gzpjod.output:1503-1504`) showed the chip returns SW=0x6986
    /// (policy denial) on a freshly-created UserID gated by the standard
    /// two-entry policy `(self → ALLOW_WRITE|ALLOW_DELETE|REQUIRE_SM,
    /// admin → ALLOW_DELETE|REQUIRE_SM)`. The SDK parser is reachable
    /// from inside a user session; transport SCP03 alone is not
    /// sufficient. The "policy-gate-independent" claim is therefore
    /// **retracted**.
    ///
    /// **Operational consequence.** On production `USERID_OBJ` (same
    /// policy shape) this method returns `None` at boot, so there is no SE050
    /// boot-counter leg. The directional OPTIGA-E120/page-124 check remains
    /// available (PIN comparison is in
    /// SE silicon, and a desolder-bench attacker who derives
    /// `se050_admin_pin()` still can't read user-gated objects per the
    /// `audit_admin_passive_read_refused` silicon claim). The skipped
    /// SE050 leg is a defense-in-depth loss, not a confidentiality
    /// loss. Callers must log the unavailable leg rather than treating it as
    /// agreement.
    ///
    /// **No workaround using attribute reads.** Recovering the counter
    /// without burning an attempt would require either (1) opening a
    /// session with the correct PIN (which resets the counter to 0 — no
    /// help mid-investigation) or (2) burning a wrong PIN and reading
    /// the SW=0x63Cx counter-remaining nibble (which costs one slot per
    /// readback). Neither path fits the boot-time reconcile.
    pub fn pin_attempt_count_raw(&mut self) -> Option<u8> {
        if self.init().is_err() {
            return None;
        }
        let mut buf = [0u8; 64];
        let n = unsafe {
            match apdu::read_object_attributes(
                &mut self.t1, &mut self.scp03, USERID_OBJ, &mut buf,
            ) {
                Ok(n) => n,
                Err(_) => return None,
            }
        };
        // Need at least bytes 0..14 (obj_id..max_attempts) parsed.
        if n < 14 {
            return None;
        }
        // auth_attr must be SET (0x01) for `auth_attempts` to be meaningful.
        if buf[5] != 0x01 {
            return None;
        }
        let auth_attempts = u16::from_be_bytes([buf[6], buf[7]]);
        let max_attempts = u16::from_be_bytes([buf[12], buf[13]]);
        if max_attempts == 0 {
            // 0 = unlimited (admin UserID); reconcile is meaningless.
            return None;
        }
        Some(u8::try_from(auth_attempts).unwrap_or(u8::MAX))
    }

    /// Two-pass: first unauthenticated SCP03 sweep, then (if `auth_obj_id`
    /// + `pin` provided) an authenticated retry against that UserID. The
    /// UserID itself is self-deleted at the end if it was created with
    /// the self-deletable policy (see `apdu::write_userid`).
    ///
    /// Returns `(deleted, remaining_failed, auth_ok)`. See
    /// `apdu::iterative_delete_all` for the meaning of `auth_ok`.
    pub fn iterative_wipe(
        &mut self,
        auth_obj_id: Option<u32>,
        userid_value: Option<apdu::UserIdValue<'_>>,
    ) -> Result<(u16, u16, bool), Se050Error> {
        self.init()?;
        let result = unsafe {
            apdu::iterative_delete_all(&mut self.t1, &mut self.scp03, auth_obj_id, userid_value)
        };
        // A3 recovery (see `authenticate_and_read`): a failed verify leaves
        // the chip's session-pending state behind, and the next
        // `create_session` would answer 0x6982. Callers try several values
        // in a row, so flush that state whenever an authenticated sweep did
        // not authenticate. The UserID attempt counter is in NVM and is not
        // affected.
        if auth_obj_id.is_some() && !matches!(result, Ok((_, _, true))) {
            let _ = self.reinit();
        }
        result
    }

    /// Bench clean-up: verify against the user UserID, delete every
    /// UserID-gated data object, then self-delete the UserID itself. Leaves
    /// the SE050 side blank and ready for re-provisioning.
    ///
    /// `userid_value` is the value of the UserID object, typed so that it
    /// cannot be a PIN typed in at run time (see `apdu::UserIdValue`). On a
    /// wallet provisioned by this firmware it is a die-bound
    /// `Se050PinCredential` (#855). The e2e pre-clean also tries the known
    /// test PINs as compile-time constants, which only ever match a chip
    /// that was provisioned by pre-#855 firmware. No product path calls
    /// this.
    ///
    /// The UserID deletion only succeeds if it was created with the
    /// self-deletable policy (new UserIDs have it; legacy ones don't).
    /// Zeroizes cached blobs in RAM on success.
    pub fn user_factory_reset(
        &mut self,
        userid_value: apdu::UserIdValue<'_>,
    ) -> Result<(), Se050Error> {
        use zeroize::Zeroize;
        self.init()?;

        unsafe {
            let session_id =
                apdu::create_session(&mut self.t1, &mut self.scp03, USERID_OBJ)?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &session_id, userid_value,
            ) {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
                // A3 recovery — see `authenticate_and_read` doc.
                let _ = self.reinit();
                return Err(e);
            }

            for obj in &[ENTROPY_OBJ, VK_OBJ, BOOTSTRAP_VK_OBJ] {
                let _ = apdu::delete_object_authed(
                    &mut self.t1, &mut self.scp03, &session_id, *obj,
                );
            }

            // Self-delete the UserID (needs self-deletable policy).
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &session_id, USERID_OBJ,
            );

            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
        }

        self.entropy_blob_cache.zeroize();
        self.blob_cached.set_false();
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        #[cfg(feature = "debug-log")]
        secure_log!("[SE050] User factory reset complete");

        Ok(())
    }

    /// Self-contained factory-reset roundtrip test.
    ///
    /// 1. Cleanup: if a previous test left a UserID at `TEST_USERID_OBJ`,
    ///    log in with `pin` and wipe it (best-effort).
    /// 2. Provision: create a fresh UserID with the self-deletable
    ///    policy (via `apdu::write_userid`) at `TEST_USERID_OBJ`, plus
    ///    two gated binary data objects.
    /// 3. Verify-presence: assert all three objects exist on chip.
    /// 4. Reset: open a session against the test UserID, verify `pin`,
    ///    delete both data objects, then self-delete the UserID.
    /// 5. Verify-absence: assert none of the three objects remain.
    ///
    /// Returns `Ok(())` on full success, `Err` describing which step
    /// failed otherwise. Never panics.
    ///
    /// Uses `0x7B07_xxxx` object IDs so it never collides with a real
    /// dual-SE provisioning at `0x7B06_xxxx`. Repeatable on the same
    /// chip — step 1 cleans up after itself.
    #[cfg(feature = "se050-reset-e2e")]
    pub fn run_factory_reset_roundtrip(
        &mut self,
        test_userid_value: &'static [u8],
    ) -> Result<(), Se050Error> {
        self.init()?;

        // ---- 1. Cleanup any prior test residue ----
        unsafe {
            if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_USERID_OBJ)
                .unwrap_or(false)
            {
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[E2E] Prior test UserID present, wiping..."
                );

                if let Ok(sid) = apdu::create_session(
                    &mut self.t1, &mut self.scp03, TEST_USERID_OBJ
                ) {
                    if apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Fixed(test_userid_value)).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_DATA_OBJ_A
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_DATA_OBJ_B
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_USERID_OBJ
                        );
                    }
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                }

                // If still present, the prior policy wasn't self-deletable
                // (was created before the fix). The test cannot proceed.
                if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_USERID_OBJ)
                    .unwrap_or(true)
                {
                    return Err(Se050Error::Status(0x6986));
                }
            }
        }

        #[cfg(feature = "debug-log")]
        secure_log!("[E2E] step 1: cleanup OK");

        // ---- 2. Provision fresh UserID + 2 gated data objects ----
        unsafe {
            apdu::write_userid(
                &mut self.t1, &mut self.scp03, TEST_USERID_OBJ, apdu::UserIdValue::Fixed(test_userid_value), 9, None,
            )?;

            let payload_a = [0xA0u8; 32];
            let payload_b = [0xB1u8; 32];
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA_OBJ_A, &payload_a, TEST_USERID_OBJ, None,
            )?;
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA_OBJ_B, &payload_b, TEST_USERID_OBJ, None,
            )?;
        }

        #[cfg(feature = "debug-log")]
        secure_log!("[E2E] step 2: provision OK");

        // ---- 3. Verify presence ----
        unsafe {
            for obj in &[TEST_USERID_OBJ, TEST_DATA_OBJ_A, TEST_DATA_OBJ_B] {
                if !apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(false)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E] presence check FAILED for 0x{:08x}", obj
                    );
                    return Err(Se050Error::Status(0x6A82));
                }
            }
        }

        #[cfg(feature = "debug-log")]
        secure_log!("[E2E] step 3: presence OK (3/3)");

        // ---- 4. Factory reset using the same PIN ----
        unsafe {
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_USERID_OBJ,
            )?;
            apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Fixed(test_userid_value))
                .map_err(|e| {
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                    e
                })?;

            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_DATA_OBJ_A,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_DATA_OBJ_B,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_USERID_OBJ,
            )?;

            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
        }

        #[cfg(feature = "debug-log")]
        secure_log!("[E2E] step 4: factory reset OK");

        // ---- 5. Verify absence ----
        unsafe {
            for obj in &[TEST_USERID_OBJ, TEST_DATA_OBJ_A, TEST_DATA_OBJ_B] {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E] absence check FAILED for 0x{:08x}", obj
                    );
                    return Err(Se050Error::Status(0x6A83));
                }
            }
        }

        #[cfg(feature = "debug-log")]
        secure_log!("[E2E] step 5: absence OK (3/3)");

        Ok(())
    }

    /// Self-contained admin-auth wipe roundtrip on isolated OID range
    /// `0x7B09_xxxx`.
    ///
    /// Provisions a fake "user UserID", a fake "admin UserID", and a
    /// gated data object using the two-entry TAG_POLICY template (user
    /// → full access; admin → DELETE). Then exercises the admin-auth
    /// delete path — the one real PIN-lockout factory reset uses —
    /// WITHOUT verifying the user PIN, proving that admin can wipe
    /// even when the user's credential is blocked.
    ///
    /// Verifies all three objects are gone at the end.
    ///
    /// Uses OIDs distinct from the production range (`0x7B06_xxxx`) AND
    /// from the user-reset e2e range (`0x7B07_xxxx`) so it runs safely
    /// on a chip that already has real provisioning. Repeatable on the
    /// same chip — step 1 cleans up any prior test residue.
    #[cfg(feature = "se050-admin-wipe-e2e")]
    pub fn run_admin_wipe_roundtrip(&mut self) -> Result<(), Se050Error> {
        self.init()?;

        const TEST_USER: u32 = 0x7B09_0000;
        const TEST_DATA: u32 = 0x7B09_0001;
        const TEST_ADMIN: u32 = 0x7B09_00A0;
        let test_user_value: &'static [u8] = b"testuser";
        let admin_pin: [u8; 16] = *b"testadminpin1234";
        let payload: [u8; 8] = [0xC0, 0xFF, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05];

        unsafe {
            // ---- 1. Cleanup prior residue via admin session ----
            // If admin obj still exists from a prior run, open a session,
            // verify PIN, delete everything. This depends on the test
            // admin PIN matching across runs (fixed constant above).
            if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_ADMIN)
                .unwrap_or(false)
            {
                if let Ok(sid) = apdu::create_session(
                    &mut self.t1, &mut self.scp03, TEST_ADMIN,
                ) {
                    if apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
                    ).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_DATA,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_USER,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_ADMIN,
                        );
                    }
                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &sid,
                    );
                }

                if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_ADMIN)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!("[E2E-ADMIN] cleanup FAILED: test-admin stuck");
                    return Err(Se050Error::Status(0x6986));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-ADMIN] step 1: cleanup OK");

            // ---- 2. Provision admin UserID first (so user objects can ref it) ----
            apdu::write_userid_unlimited(
                &mut self.t1, &mut self.scp03, TEST_ADMIN, apdu::UserIdValue::DeviceSecret(&admin_pin), None,
            )?;

            // User UserID with two-entry policy: self + admin
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                TEST_USER, apdu::UserIdValue::Fixed(test_user_value), 5, Some(TEST_ADMIN),
            )?;

            // Data object with two-entry policy: user + admin
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA, &payload, TEST_USER, Some(TEST_ADMIN),
            )?;

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-ADMIN] step 2: provision OK");

            // ---- 3. Verify all three objects exist on-chip ----
            for obj in &[TEST_USER, TEST_DATA, TEST_ADMIN] {
                if !apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(false)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E-ADMIN] step 3: 0x{:08x} missing after provision", obj
                    );
                    return Err(Se050Error::Status(0x6A82));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-ADMIN] step 3: presence OK (3/3)");

            // ---- 4. Admin-auth wipe — the actual path exercised by PIN lockout ----
            // Note: we do NOT verify the user PIN here. That's the whole point:
            // admin can delete user-gated objects without user auth.
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
            ).map_err(|e| {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                e
            })?;

            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_DATA,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_USER,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_ADMIN,
            )?;

            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-ADMIN] step 4: admin wipe OK");

            // ---- 5. Verify nothing survives ----
            for obj in &[TEST_USER, TEST_DATA, TEST_ADMIN] {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E-ADMIN] step 5: 0x{:08x} survived wipe", obj
                    );
                    return Err(Se050Error::Status(0x6A83));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-ADMIN] step 5: absence OK (3/3)");
        }

        Ok(())
    }

    /// Negative security test: prove the admin PIN **cannot** read user-PIN-
    /// gated secrets, only delete them. Falsifies the load-bearing claim
    /// that the two-entry TAG_POLICY (user → READ|WRITE|DELETE, admin →
    /// DELETE only — see `apdu::build_policy` at `se050/apdu.rs:339-365`)
    /// is silicon-enforced, not driver-enforced.
    ///
    /// The relevant threat model: if `hw::secret_keys::se050_admin_pin()` is
    /// derived from a key that leaks (DHUK today; BHK after Tier-2 phase 2C),
    /// an attacker with physical access can authenticate as admin. This test
    /// asserts that even with a fully authenticated admin session, the chip
    /// refuses to release secret bytes — i.e. user PIN remains the read gate.
    ///
    /// Sequence on isolated OID range `0x7B0B_xxxx`:
    ///   1. Cleanup prior residue.
    ///   2. Provision admin UserID, user UserID, secret data object with
    ///      the two-entry policy. Secret payload is a 32-B sentinel.
    ///   3. Sanity: open user session, verify user PIN, READ secret → must
    ///      return the sentinel byte-for-byte (else test setup is broken).
    ///   4. ATTACK: open admin session, verify admin PIN, READ secret →
    ///      **must** be refused. Success here is a security failure.
    ///   5. Control: same admin session DELETEs all three objects → must
    ///      succeed (proves the admin session is genuinely admin-authed,
    ///      so step 4's refusal wasn't due to bogus auth).
    ///   6. Verify nothing survives.
    ///
    /// PASS iff: step 3 read matches sentinel, step 4 read errors, step 5
    /// deletes succeed, step 6 finds chip empty.
    ///
    /// Uses OIDs distinct from production (`0x7B10_xxxx`) and from the
    /// admin-wipe (`0x7B09`) / crash-safety (`0x7B0A`) test ranges so it
    /// runs safely on a chip with real provisioning. Repeatable.
    #[cfg(feature = "se050-admin-extract-attempt-e2e")]
    pub fn run_admin_extract_attempt(&mut self) -> Result<(), Se050Error> {
        self.init()?;

        const TEST_USER:  u32 = 0x7B0B_0000;
        const TEST_DATA:  u32 = 0x7B0B_0001;
        const TEST_ADMIN: u32 = 0x7B0B_00A0;
        let test_user_value: &'static [u8] = b"testuser";
        let admin_pin: [u8; 16] = *b"testadminpin1234";
        // 32-B sentinel: distinct, non-zero, unmistakable in a hex dump.
        let payload: [u8; 32] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE,
            0xC0, 0xFF, 0xEE, 0x42, 0x13, 0x37, 0xB0, 0x0B,
            0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x21, 0x21,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        unsafe {
            // ---- 1. Cleanup prior residue via admin session ----
            if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_ADMIN)
                .unwrap_or(false)
            {
                if let Ok(sid) = apdu::create_session(
                    &mut self.t1, &mut self.scp03, TEST_ADMIN,
                ) {
                    if apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
                    ).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_DATA,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_USER,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_ADMIN,
                        );
                    }
                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &sid,
                    );
                }

                if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_ADMIN)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!("[E2E-EXTRACT] cleanup FAILED: test-admin stuck");
                    return Err(Se050Error::Status(0x6986));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-EXTRACT] step 1: cleanup OK");

            // ---- 2. Provision admin + user UserIDs + secret data object ----
            apdu::write_userid_unlimited(
                &mut self.t1, &mut self.scp03, TEST_ADMIN, apdu::UserIdValue::DeviceSecret(&admin_pin), None,
            )?;
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                TEST_USER, apdu::UserIdValue::Fixed(test_user_value), 5, Some(TEST_ADMIN),
            )?;
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA, &payload, TEST_USER, Some(TEST_ADMIN),
            )?;

            #[cfg(feature = "debug-log")]
            secure_log!(
                "[E2E-EXTRACT] step 2: provision OK \
                 (policy: user=READ|WRITE|DELETE, admin=DELETE only)"
            );

            // ---- 3. Sanity: USER auth CAN read the sentinel ----
            // If this fails, the test setup is wrong — the secret should
            // be readable by whoever holds the user PIN. A failure here
            // means we cannot draw any conclusion from step 4.
            {
                let sid = apdu::create_session(
                    &mut self.t1, &mut self.scp03, TEST_USER,
                )?;
                if apdu::verify_session(
                    &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::Fixed(test_user_value),
                ).is_err() {
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                    #[cfg(feature = "debug-log")]
                    secure_log!("[E2E-EXTRACT] step 3: user PIN verify FAILED — test setup broken");
                    return Err(Se050Error::Status(0xDEAD));
                }

                let mut buf = [0u8; 64];
                let read_result = apdu::read_authed(
                    &mut self.t1, &mut self.scp03, &sid, TEST_DATA, &mut buf,
                );
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

                match read_result {
                    Ok(n) => {
                        if n != payload.len() || buf[..n] != payload {
                            #[cfg(feature = "debug-log")]
                            secure_log!(
                                "[E2E-EXTRACT] step 3: user read returned {} bytes, sentinel mismatch — test broken",
                                n
                            );
                            return Err(Se050Error::Status(0xDEAE));
                        }
                        #[cfg(feature = "debug-log")]
                        secure_log!(
                            "[E2E-EXTRACT] step 3: user-auth read OK ({} B match sentinel)",
                            n
                        );
                    }
                    Err(_e) => {
                        #[cfg(feature = "debug-log")]
                        secure_log!(
                            "[E2E-EXTRACT] step 3: user-auth read FAILED ({:?}) — test broken",
                            _e
                        );
                        return Err(Se050Error::Status(0xDEAF));
                    }
                }
            }

            // ---- 4. ATTACK: admin auth attempts to extract the secret ----
            // The security claim under test. Per `apdu::build_policy` admin
            // has ALLOW_DELETE only, no ALLOW_READ. The chip must refuse.
            let admin_sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &admin_sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
            ).map_err(|e| {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &admin_sid);
                e
            })?;

            let mut attack_buf = [0u8; 64];
            let attack_result = apdu::read_authed(
                &mut self.t1, &mut self.scp03, &admin_sid, TEST_DATA, &mut attack_buf,
            );

            if let Ok(n) = attack_result {
                let leaked_sentinel = n >= payload.len() && attack_buf[..payload.len()] == payload;
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[E2E-EXTRACT] step 4: SECURITY FAILURE — admin-auth read returned {} bytes (sentinel leaked: {})",
                    n,
                    leaked_sentinel
                );
                // Don't even try to clean up; we want this case loud.
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &admin_sid);
                // 0xBAD0 = "admin extracted user-gated secret"
                return Err(Se050Error::Status(0xBAD0));
            }

            #[cfg(feature = "debug-log")]
            secure_log!(
                "[E2E-EXTRACT] step 4: admin-auth read REFUSED ({:?}) — security property holds",
                attack_result.err().unwrap()
            );

            // ---- 5. Control: admin CAN delete (proves admin session is real) ----
            // If admin's auth were bogus, step 4's refusal could be a false
            // positive. A successful delete here closes that loophole: the
            // chip accepted the admin credentials for the DELETE operation
            // but specifically denied them for READ.
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &admin_sid, TEST_DATA,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &admin_sid, TEST_USER,
            )?;
            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &admin_sid, TEST_ADMIN,
            )?;
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &admin_sid);

            #[cfg(feature = "debug-log")]
            secure_log!(
                "[E2E-EXTRACT] step 5: admin-auth delete OK \
                 (admin session was genuinely admin → step 4 refusal was a real READ deny, \
                 not bogus-auth)"
            );

            // ---- 6. Verify nothing survives ----
            for obj in &[TEST_USER, TEST_DATA, TEST_ADMIN] {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E-EXTRACT] step 6: 0x{:08x} survived wipe", obj
                    );
                    return Err(Se050Error::Status(0x6A83));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!(
                "[E2E-EXTRACT] PASS: admin can DELETE but NOT READ user-PIN-gated secrets"
            );
        }

        Ok(())
    }

    /// Two-phase crash-safety test: simulates power loss mid-wipe on test
    /// OID range `0x7B0A_xxxx`, then verifies the boot-time resume mechanism
    /// correctly finishes the wipe after reset.
    ///
    /// Single firmware, phase is auto-detected via the wipe-in-progress
    /// flag at flash page 125 QW1:
    ///
    /// PHASE 1 (flag blank on boot):
    ///   a. Clean up any prior test residue.
    ///   b. Provision admin UserID at `0x7B0A_00A0`, user UserID at
    ///      `0x7B0A_0000`, data object at `0x7B0A_0001`. All with the
    ///      real two-entry TAG_POLICY template.
    ///   c. Erase page 125's legacy area and arm its wipe flag. The test
    ///      admin PIN is a compile-time test literal; production re-derives
    ///      its admin PIN from the BHK/DHUK root and never stores it here.
    ///   e. Partial wipe: open admin session, delete ONLY the data
    ///      object, leaving user + admin UserIDs intact. This models
    ///      power being cut halfway through the wipe sequence.
    ///   f. Halt. Reports "PHASE 1 — RESET BOARD NOW".
    ///
    /// PHASE 2 (flag armed on boot):
    ///   a. Verify pre-resume state: data gone, user present, admin
    ///      present, flag armed. Any deviation = FAIL.
    ///   b. Reuse the compile-time test PIN (production would re-derive
    ///      `secret_keys::se050_admin_pin()`).
    ///   c. Open admin session, delete remaining user + admin UserIDs.
    ///   d. Verify all three test objects are gone.
    ///   e. Erase flash page 125 — clears the flag and legacy area,
    ///      proving the normal wipe-completion path works.
    ///   f. Reports "PHASE 2 — CRASH-SAFETY RESUME: PASS".
    ///
    /// Returns a status tag the caller can print. Destructive to page 125's
    /// wipe/legacy state — use only on an authorized throwaway test device.
    #[cfg(feature = "se050-crash-safety-e2e")]
    pub fn run_crash_safety_roundtrip(&mut self) -> Result<&'static str, Se050Error> {
        self.init()?;

        #[cfg(feature = "stm32u585")]
        let flag_armed = unsafe { crate::hw::flash::is_wipe_armed() };
        #[cfg(not(feature = "stm32u585"))]
        let flag_armed = false;

        if flag_armed {
            self.crash_safety_phase2()
                .map(|()| "PHASE 2 — CRASH-SAFETY RESUME: PASS")
        } else {
            self.crash_safety_phase1()
                .map(|()| "PHASE 1 COMPLETE — RESET THE BOARD TO TRIGGER RESUME")
        }
    }

    #[cfg(feature = "se050-crash-safety-e2e")]
    fn crash_safety_phase1(&mut self) -> Result<(), Se050Error> {
        const TEST_USER: u32 = 0x7B0A_0000;
        const TEST_DATA: u32 = 0x7B0A_0001;
        const TEST_ADMIN: u32 = 0x7B0A_00A0;
        let admin_pin: [u8; 16] = *b"crashsafetypin00";
        let test_user_value: &'static [u8] = b"crashsim";
        let payload: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

        unsafe {
            // ---- a. Cleanup prior residue via admin session ----
            if apdu::check_exists(&mut self.t1, &mut self.scp03, TEST_ADMIN)
                .unwrap_or(false)
            {
                if let Ok(sid) = apdu::create_session(
                    &mut self.t1, &mut self.scp03, TEST_ADMIN,
                ) {
                    if apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
                    ).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_DATA,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_USER,
                        );
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, TEST_ADMIN,
                        );
                    }
                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &sid,
                    );
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 1a cleanup OK");

            // ---- b. Provision admin + user + data with 2-entry policy ----
            apdu::write_userid_unlimited(
                &mut self.t1, &mut self.scp03, TEST_ADMIN, apdu::UserIdValue::DeviceSecret(&admin_pin), None,
            )?;
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                TEST_USER, apdu::UserIdValue::Fixed(test_user_value), 5, Some(TEST_ADMIN),
            )?;
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA, &payload, TEST_USER, Some(TEST_ADMIN),
            )?;

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 1b provision OK");

            // ---- c. Arm the wipe-in-progress flag (page 125) ----
            // Phase 2 uses the same compile-time `*b"crashsafetypin00"`
            // admin PIN literal, so there's nothing to persist across
            // the simulated crash — we just erase page 125 (clean flag
            // state) then arm the flag at WIPE_FLAG_OFFSET. (Production
            // resume re-derives its admin PIN from a silicon hardware
            // root via `secret_keys::se050_admin_pin()` (BHK in a `bhk`
            // build), not from flash — the page-125 PIN slot is dead
            // storage on v6 chips.)
            #[cfg(feature = "stm32u585")]
            {
                crate::hw::flash::erase_admin_page()
                    .map_err(|_| Se050Error::Transport)?;
                crate::hw::flash::arm_wipe_flag()
                    .map_err(|_| Se050Error::Transport)?;

                #[cfg(feature = "debug-log")]
                secure_log!("[E2E-CRASH] 1c page 125 erased + wipe flag armed");
            }

            // ---- e. Partial wipe: delete only the data object ----
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
            ).map_err(|e| {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                e
            })?;

            apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_DATA,
            )?;

            // Intentionally DO NOT delete TEST_USER or TEST_ADMIN — models
            // power cut mid-wipe after step (e) but before step (f).
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 1e partial wipe done (data deleted, user+admin remain)");
        }

        Ok(())
    }

    #[cfg(feature = "se050-crash-safety-e2e")]
    fn crash_safety_phase2(&mut self) -> Result<(), Se050Error> {
        const TEST_USER: u32 = 0x7B0A_0000;
        const TEST_DATA: u32 = 0x7B0A_0001;
        const TEST_ADMIN: u32 = 0x7B0A_00A0;

        unsafe {
            // ---- a. Verify expected pre-resume state ----
            let data_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, TEST_DATA,
            ).unwrap_or(true);
            let user_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, TEST_USER,
            ).unwrap_or(false);
            let admin_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            ).unwrap_or(false);

            #[cfg(feature = "debug-log")]
            secure_log!(
                "[E2E-CRASH] 2a state: data={} user={} admin={}",
                data_exists, user_exists, admin_exists
            );

            if data_exists || !user_exists || !admin_exists {
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[E2E-CRASH] 2a FAIL: expected data=false user=true admin=true"
                );
                return Err(Se050Error::Status(0x6A90));
            }

            // ---- b. Admin PIN — the same compile-time literal phase 1
            // provisioned the admin UserID with. Nothing to read back
            // from flash: this is a self-contained test, the PIN never
            // varies. (The real crash-resume path re-derives via
            // `secret_keys::se050_admin_pin()` — that's exercised by
            // `dual-se-admin-wipe-e2e`, not here.)
            let mut admin_pin: [u8; 16] = *b"crashsafetypin00";

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 2b admin PIN ready (compile-time literal)");

            // ---- c. Finish the wipe ----
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(&admin_pin),
            ).map_err(|e| {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                e
            })?;

            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_USER,
            );
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, TEST_ADMIN,
            );
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            use zeroize::Zeroize;
            admin_pin.zeroize();

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 2c resume wipe done");

            // ---- d. Verify all three test objects gone ----
            for obj in &[TEST_USER, TEST_DATA, TEST_ADMIN] {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                    .unwrap_or(true)
                {
                    #[cfg(feature = "debug-log")]
                    secure_log!(
                        "[E2E-CRASH] 2d FAIL: 0x{:08x} survived resume", obj
                    );
                    return Err(Se050Error::Status(0x6A91));
                }
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 2d absence OK (3/3)");

            // ---- e. Erase page 125 — clears admin PIN + wipe flag atomically ----
            #[cfg(feature = "stm32u585")]
            {
                crate::hw::flash::erase_admin_page()
                    .map_err(|_| Se050Error::Transport)?;

                if crate::hw::flash::is_wipe_armed() {
                    #[cfg(feature = "debug-log")]
                    secure_log!("[E2E-CRASH] 2e FAIL: flag still armed after erase");
                    return Err(Se050Error::Status(0x6A92));
                }

                #[cfg(feature = "debug-log")]
                secure_log!("[E2E-CRASH] 2e page 125 erased, flag cleared");
            }
        }

        Ok(())
    }

    /// Check if the device has been provisioned (UserID object exists).
    fn check_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        unsafe {
            apdu::check_exists(&mut self.t1, &mut self.scp03, USERID_OBJ)
                .unwrap_or(false)
        }
    }

    /// Store objects on the SE050 behind a UserID PIN gate, plus provision
    /// the admin-wipe UserID that protects the PIN-lockout factory-reset
    /// path.
    ///
    /// The three data blobs get a two-entry TAG_POLICY: (user auth → full
    /// access) + (admin auth → DELETE only). The user UserID gets the admin
    /// DELETE entry only on bench images (`USERID_ADMIN_DELETE`, #912); on
    /// shipping builds it has none (S-6), so the admin wipe cannot remove
    /// it. The admin UserID has unlimited attempts (max_attempts=0) — its PIN
    /// is a 16-byte value derived from the device root axis
    /// (`secret_keys::se050_admin_pin` → `derive_into_bhk`; BHK/DHUK/OTP,
    /// never the OPTIGA PBS), so brute force is infeasible and the wipe
    /// path must not lock itself out.
    ///
    /// Re-provisioning semantics: on the `admin_pin = Some(..)` path (real
    /// hardware), any stale user objects (USERID + 3 data blobs) from a
    /// prior session are deleted via admin auth before the fresh writes,
    /// so this function produces the committed `(entropy, vk,
    /// bootstrap_vk, pin)` regardless of prior chip state. On the
    /// `admin_pin = None` path (QEMU / `e2e-skip-admin-wipe`), existing
    /// user objects are preserved (there is no admin auth to delete them
    /// with, and those paths don't carry persistent chip state in
    /// practice).
    fn store_objects(
        &mut self,
        user_cred: &crate::pin_credential::Se050PinCredential,
        max_attempts: u16,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        admin_pin: Option<&[u8; 16]>,
    ) -> Result<(), Se050Error> {
        self.init().map_err(|e| {
            secure_log!("[SE050/store] init() FAILED: {:?}", e);
            e
        })?;

        unsafe {
            // Admin UserID first: must exist before user objects reference it
            // in their admin-delete policy entries.
            if let Some(admin) = admin_pin {
                let admin_exists = match apdu::check_exists(
                    &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        secure_log!(
                            "[SE050/store] check_exists(ADMIN_WIPE_OBJ) ERR: {:?} — treating as not-exists",
                            e
                        );
                        false
                    }
                };
                secure_log!("[SE050/store] admin_exists={}", admin_exists);

                if !admin_exists {
                    secure_log!("[SE050/store] writing admin UserID (unlimited attempts, no admin_ref)");
                    // Unlimited per S-7a — admin PIN is 16 bytes of
                    // HW-root-derived entropy; SE-side lockout would
                    // only fire on a hardware glitch, not actual
                    // brute force.
                    apdu::write_userid_unlimited(
                        &mut self.t1, &mut self.scp03,
                        ADMIN_WIPE_OBJ, apdu::UserIdValue::DeviceSecret(admin), None,
                    ).map_err(|e| {
                        secure_log!("[SE050/store] write admin UserID FAILED: {:?}", e);
                        e
                    })?;
                }
            }

            let admin_ref = admin_pin.map(|_| ADMIN_WIPE_OBJ);
            secure_log!(
                "[SE050/store] admin_ref={}",
                if admin_ref.is_some() { "ADMIN_WIPE_OBJ" } else { "None" }
            );

            // Stale-user-object sweep. `DualSecureElement::is_provisioned`
            // is the AND of both SEs, so the wizard runs whenever OPTIGA
            // reports unprovisioned — even if SE050 still holds the user
            // objects from a prior session. Without this sweep, the
            // `!exists` skip branches below would retain the stale
            // USERID_OBJ (wrong PIN if the user picked a different one)
            // and stale ENTROPY_OBJ (old half_E), desyncing the XOR split
            // against the fresh half_O written to OPTIGA. On unlock, the
            // dual-SE consistency check fails with `CRITICAL: reconstructed
            // entropy doesn't match master!`.
            //
            // Gated on `admin_pin.is_some()` — the only code path that
            // can reach a persistent chip with stale user objects, and
            // the only one that has admin auth to delete them. QEMU and
            // `e2e-skip-admin-wipe` keep the existing skip-if-exists
            // semantics (no persistent state / fixed test fixtures).
            if let Some(admin) = admin_pin {
                const STALE_OBJS: [u32; 4] = [
                    USERID_OBJ, ENTROPY_OBJ, VK_OBJ, BOOTSTRAP_VK_OBJ,
                ];
                let mut present = [false; 4];
                let mut any_stale = false;
                for (i, obj) in STALE_OBJS.iter().enumerate() {
                    if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj)
                        .unwrap_or(false)
                    {
                        present[i] = true;
                        any_stale = true;
                    }
                }

                if any_stale {
                    secure_log!(
                        "[SE050/store] stale user objects — userid={} entropy={} vk={} bvk={}",
                        present[0], present[1], present[2], present[3]
                    );
                    let session_id = apdu::create_session(
                        &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
                    ).map_err(|e| {
                        secure_log!(
                            "[SE050/store] stale sweep: create_session FAILED: {:?}", e
                        );
                        e
                    })?;

                    if let Err(e) = apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &session_id, apdu::UserIdValue::DeviceSecret(admin),
                    ) {
                        secure_log!(
                            "[SE050/store] stale sweep: verify_session FAILED: {:?}", e
                        );
                        let _ = apdu::close_session(
                            &mut self.t1, &mut self.scp03, &session_id,
                        );
                        return Err(e);
                    }

                    // Data objects only — S-6 dropped admin-delete from
                    // USERID_OBJ's policy, so the admin session cannot
                    // delete idx=0 (USERID_OBJ). If a stale USERID_OBJ
                    // is present here, the `userid_exists && admin_pin.
                    // is_some()` check below fails provisioning loud —
                    // the chip is in a stuck state (USERID locked from
                    // a prior session, no recovery path that doesn't
                    // wipe via NXP-only factory reset) and the OID
                    // range must be bumped.
                    for idx in [1usize, 2, 3] {
                        if present[idx] {
                            if let Err(e) = apdu::delete_object_authed(
                                &mut self.t1, &mut self.scp03,
                                &session_id, STALE_OBJS[idx],
                            ) {
                                secure_log!(
                                    "[SE050/store] stale sweep: delete(0x{:08x}) FAILED: {:?}",
                                    STALE_OBJS[idx], e
                                );
                                let _ = apdu::close_session(
                                    &mut self.t1, &mut self.scp03, &session_id,
                                );
                                return Err(e);
                            }
                        }
                    }

                    // #912: a UserID written by a bench image carries an
                    // admin-delete entry, so it goes here too. One written
                    // before #912, or by a shipping image, refuses
                    // (SW=0x6986); the `userid_exists` check below then
                    // fails loudly. Last in the session and best-effort: a
                    // refused delete leaves the session pending (A3), which
                    // the reinit clears.
                    let mut userid_delete_refused = false;
                    if USERID_ADMIN_DELETE.is_some() && present[0] {
                        if let Err(_e) = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &session_id, STALE_OBJS[0],
                        ) {
                            secure_log!(
                                "[SE050/store] stale sweep: admin delete of USERID_OBJ refused: {:?}",
                                _e
                            );
                            userid_delete_refused = true;
                        }
                    }

                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &session_id,
                    );
                    if userid_delete_refused {
                        self.reinit()?;
                    }
                    secure_log!("[SE050/store] stale sweep complete");
                }
            }

            // User UserID: skip if already exists.
            //
            // Bug 2 (work-todo #28) hardening: if `admin_pin` is provided
            // the stale sweep above should have admin-auth-deleted any
            // prior USERID_OBJ, so `exists` should be false here. If it
            // IS still true we're in one of two states, both worth
            // surfacing loudly:
            //   1. The sweep's admin_factory_reset silently failed
            //      (Bug 1 would have masked this; now fixed).
            //   2. The on-chip object pre-dates v6 and its admin-delete
            //      policy entry doesn't match our current ADMIN_WIPE_OBJ,
            //      so the sweep couldn't touch it.
            // Either way, skipping would inherit a stale policy shape
            // permanently. Fail loud.
            let userid_exists = match apdu::check_exists(
                &mut self.t1, &mut self.scp03, USERID_OBJ
            ) {
                Ok(v) => v,
                Err(e) => {
                    secure_log!(
                        "[SE050/store] check_exists(USERID_OBJ=0x{:08x}) ERR: {:?} — treating as not-exists",
                        USERID_OBJ, e
                    );
                    false
                }
            };
            secure_log!(
                "[SE050/store] USERID_OBJ=0x{:08x} exists={}",
                USERID_OBJ, userid_exists
            );

            if userid_exists && admin_pin.is_some() {
                secure_log!(
                    "[SE050/store] FAILED: USERID_OBJ exists after stale sweep \
                     (Bug #28 — prior firmware's admin-delete policy doesn't \
                     match current ADMIN_WIPE_OBJ; re-provisioning would \
                     inherit the stale policy). On a bench board: {}",
                    userid_survivor_help(true)
                );
                return Err(Se050Error::Status(0x6986));
            }

            if !userid_exists {
                secure_log!(
                    "[SE050/store] writing USERID_OBJ (value_len={} max_attempts={}, admin-delete={})",
                    crate::pin_credential::SE050_CRED_LEN, max_attempts,
                    admin_ref.and(USERID_ADMIN_DELETE).is_some()
                );
                // S-6 fix (docs/security/security-review-2026-05.md §C-8): the
                // user UserID's policy is created WITHOUT an admin
                // delete-entry, so an admin-credential compromise can
                // no longer delete USERID_OBJ → recreate it at the
                // same OID with attacker-chosen PIN → satisfy the
                // data objects' `[USERID_OBJ → ALLOW_READ]` policy →
                // read `half_E`. Data objects KEEP their admin
                // delete-entry (DoS-wipe is acceptable; the safety
                // contract is "seed destroyed", not "chip stays
                // re-provisionable"). Trade-off: after lockout +
                // admin_factory_reset, USERID_OBJ is orphaned on
                // chip; the OID range must be bumped to reuse the
                // chip — see the v6 → vN comment at the top of this
                // module. Bench images are the exception (#912): there
                // `USERID_ADMIN_DELETE` names the admin object.
                // #855: the object value is the die-bound credential, never
                // the PIN.
                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    USERID_OBJ, apdu::UserIdValue::Credential(user_cred), max_attempts,
                    admin_ref.and(USERID_ADMIN_DELETE),
                ).map_err(|e| {
                    secure_log!("[SE050/store] write USERID_OBJ FAILED: {:?}", e);
                    e
                })?;
            }

            // Binary data objects: skip if already exist. Same Bug 2
            // hardening as USERID_OBJ — if an object survives the
            // stale sweep under admin mode, fail loud.
            let objs: [(u32, &[u8]); 3] = [
                (ENTROPY_OBJ, entropy),
                (VK_OBJ, vk),
                (BOOTSTRAP_VK_OBJ, bootstrap_vk),
            ];

            for (obj_id, data) in &objs {
                let exists = match apdu::check_exists(
                    &mut self.t1, &mut self.scp03, *obj_id
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        secure_log!(
                            "[SE050/store] check_exists(0x{:08x}) ERR: {:?} — treating as not-exists",
                            obj_id, e
                        );
                        false
                    }
                };
                secure_log!("[SE050/store] 0x{:08x} exists={}", obj_id, exists);

                if exists && admin_pin.is_some() {
                    secure_log!(
                        "[SE050/store] FAILED: 0x{:08x} exists after stale sweep \
                         (Bug #28 — stale policy shape on chip)",
                        obj_id,
                    );
                    return Err(Se050Error::Status(0x6986));
                }

                if !exists {
                    secure_log!(
                        "[SE050/store] writing 0x{:08x} (len={})",
                        obj_id, data.len()
                    );
                    // WRITE-ONCE: ENTROPY_OBJ (half_E) / VK / bootstrap_vk
                    // must not be re-seedable by a live PIN session (would
                    // desync the dual-SE XOR split). Admin-delete preserved
                    // for the factory-reset/re-provision path.
                    apdu::write_binary_write_once(
                        &mut self.t1, &mut self.scp03,
                        *obj_id, data, USERID_OBJ, admin_ref,
                    ).map_err(|e| {
                        secure_log!(
                            "[SE050/store] write_binary_write_once(0x{:08x}) FAILED: {:?}",
                            obj_id, e
                        );
                        e
                    })?;
                }
            }
        }

        Ok(())
    }

    /// §32 duress (decoy) provisioning on SE050. Mirrors [`store_objects`]
    /// for the SECOND credential set:
    ///   - `DURESS_USERID_OBJ` UserID with `max_attempts=0` (UNLIMITED —
    ///     a wrong duress PIN must NOT trip SE050's own silicon lockout;
    ///     the MCU page-124 counter gates lockout on a wrong duress entry,
    ///     handled in the P3 unlock path)
    ///   - `DURESS_ENTROPY_OBJ` (decoy half_E), `DURESS_VK_OBJ`,
    ///     `DURESS_BOOTSTRAP_VK_OBJ`, each gated on the duress UserID
    ///
    /// All objects carry the admin-delete policy entry (`admin_pin` →
    /// `ADMIN_WIPE_OBJ`) so the existing factory-reset-admin sweep
    /// reclaims them. Assumes the admin UserID already exists (the real
    /// `store_objects` ran first in the same wizard step). Includes an
    /// admin-auth stale sweep so re-provisioning is idempotent.
    #[cfg(feature = "duress-pin")]
    fn store_duress_objects(
        &mut self,
        half_e: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_cred: &crate::pin_credential::Se050PinCredential,
        admin_pin: Option<&[u8; 16]>,
    ) -> Result<(), Se050Error> {
        self.init()?;
        let admin_ref = admin_pin.map(|_| ADMIN_WIPE_OBJ);

        unsafe {
            // Stale-duress-object sweep (admin-auth), idempotent re-provision.
            if let Some(admin) = admin_pin {
                const STALE: [u32; 4] = [
                    DURESS_USERID_OBJ, DURESS_ENTROPY_OBJ, DURESS_VK_OBJ, DURESS_BOOTSTRAP_VK_OBJ,
                ];
                let mut present = [false; 4];
                let mut any = false;
                for (i, obj) in STALE.iter().enumerate() {
                    if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj).unwrap_or(false) {
                        present[i] = true;
                        any = true;
                    }
                }
                if any {
                    secure_log!("[SE050/duress] stale duress objects — sweeping via admin");
                    let sid = apdu::create_session(&mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ)?;
                    if let Err(e) = apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(admin)) {
                        let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                        return Err(e);
                    }
                    // S-6: skip idx=0 (DURESS_USERID_OBJ) — admin can no
                    // longer delete it.  Survival is acceptable here; on
                    // a stuck duress UserID, the `check_exists(DURESS_
                    // USERID_OBJ)` below will skip the write and leave
                    // any old duress state in place (matches the
                    // `store_objects` stuck-USERID semantics).
                    for idx in [1usize, 2, 3] {
                        if present[idx] {
                            if let Err(e) = apdu::delete_object_authed(
                                &mut self.t1, &mut self.scp03, &sid, STALE[idx],
                            ) {
                                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                                return Err(e);
                            }
                        }
                    }
                    // #912: on a bench build the duress UserID carries an
                    // admin-delete entry; remove it as well (last, and
                    // best-effort, as in `store_objects`).
                    let mut userid_delete_refused = false;
                    if USERID_ADMIN_DELETE.is_some() && present[0] {
                        if apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &sid, STALE[0],
                        ).is_err() {
                            userid_delete_refused = true;
                        }
                    }
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                    if userid_delete_refused {
                        self.reinit()?;
                    }
                }
            }

            // Duress UserID — unlimited attempts (MCU page-124 counter
            // gates lockout, not the SE).  S-6 fix — pass `None` for
            // the admin policy entry (same rationale as USERID_OBJ in
            // `store_objects`); admin-delete on data objects below
            // remains.  Explicit-unlimited per S-7a.
            let duress_userid_exists =
                apdu::check_exists(&mut self.t1, &mut self.scp03, DURESS_USERID_OBJ).unwrap_or(false);
            // #912: on a bench build the sweep above removes a duress
            // UserID that has the admin-delete entry. One that is still
            // here was written before #912. Writing fresh decoy data under
            // it would report success and leave a decoy the new duress PIN
            // cannot open, so refuse instead. (It has unlimited attempts, so
            // removing it with its own value is safe; no tool does it yet.)
            if USERID_ADMIN_DELETE.is_some() && admin_pin.is_some() && duress_userid_exists {
                secure_log!(
                    "[SE050/duress] FAILED: DURESS_USERID_OBJ survives the admin sweep (written \
                     before #912, no admin-delete entry); refusing to provision a decoy under it"
                );
                return Err(Se050Error::Status(0x6986));
            }
            if !duress_userid_exists {
                secure_log!(
                    "[SE050/duress] writing DURESS_USERID_OBJ (unlimited, admin-delete={})",
                    admin_ref.and(USERID_ADMIN_DELETE).is_some()
                );
                apdu::write_userid_unlimited(
                    &mut self.t1, &mut self.scp03,
                    DURESS_USERID_OBJ, apdu::UserIdValue::Credential(duress_cred),
                    admin_ref.and(USERID_ADMIN_DELETE),
                )?;
            }

            // Duress data objects, gated on the duress UserID.
            let objs: [(u32, &[u8]); 3] = [
                (DURESS_ENTROPY_OBJ, half_e),
                (DURESS_VK_OBJ, vk),
                (DURESS_BOOTSTRAP_VK_OBJ, bootstrap_vk),
            ];
            for (obj_id, data) in &objs {
                if !apdu::check_exists(&mut self.t1, &mut self.scp03, *obj_id).unwrap_or(false) {
                    secure_log!("[SE050/duress] writing 0x{:08x}", obj_id);
                    // WRITE-ONCE: decoy half_E / VK / bootstrap_vk, same
                    // re-seed-desync rationale as the real store_objects.
                    apdu::write_binary_write_once(
                        &mut self.t1, &mut self.scp03,
                        *obj_id, data, DURESS_USERID_OBJ, admin_ref,
                    )?;
                }
            }
        }
        secure_log!("[SE050/duress] store_duress_objects complete");
        Ok(())
    }

    /// Provision admin wipe credential on an already-initialized chip.
    ///
    /// Used by the dual-SE glue during first-boot to install the admin
    /// UserID before the user UserID is written (so user-object admin-delete
    /// policies resolve). Idempotent — safe to call on a chip that already
    /// has the admin object.
    pub fn provision_admin(&mut self, admin_pin: &[u8; 16]) -> Result<(), Se050Error> {
        self.init().map_err(|e| {
            secure_log!("[SE050/admin] init() FAILED: {:?}", e);
            e
        })?;
        unsafe {
            let exists_res = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            );
            let exists = match &exists_res {
                Ok(v) => *v,
                Err(e) => {
                    secure_log!(
                        "[SE050/admin] check_exists(ADMIN_WIPE_OBJ=0x{:08x}) ERR: {:?} — treating as not-exists",
                        ADMIN_WIPE_OBJ, e
                    );
                    false
                }
            };
            secure_log!(
                "[SE050/admin] ADMIN_WIPE_OBJ=0x{:08x} exists={}",
                ADMIN_WIPE_OBJ, exists
            );
            if !exists {
                secure_log!("[SE050/admin] writing admin UserID (16-byte PIN, unlimited attempts, no admin_ref)");
                // Explicit-unlimited per S-7a — admin PIN is 16-byte
                // HW-root-derived; SE-side lockout is unnecessary.
                apdu::write_userid_unlimited(
                    &mut self.t1, &mut self.scp03,
                    ADMIN_WIPE_OBJ, apdu::UserIdValue::DeviceSecret(admin_pin), None,
                ).map_err(|e| {
                    secure_log!("[SE050/admin] write_userid FAILED: {:?}", e);
                    e
                })?;
                secure_log!("[SE050/admin] admin UserID written OK");
            } else {
                secure_log!("[SE050/admin] admin already present — skipping create");
            }
        }
        Ok(())
    }

    /// PIN-lockout factory reset: authenticate as the admin UserID and
    /// wipe every gated user object, then self-delete the admin UserID
    /// itself. Does not touch PBS or any other chip state.
    ///
    /// Call this from the dual-SE coordinator after (a) the user UserID
    /// has been blocked by SE050 silicon (10 wrong PIN attempts) or (b)
    /// a persisted wipe-in-progress flag indicates a prior wipe was
    /// interrupted. The admin PIN is derived on the STM32 side from the
    /// OPTIGA PBS — caller supplies it here.
    ///
    /// Zeroizes all cached blobs on success and clears the ready flag so
    /// the SE050 is re-initialised cleanly on next use.
    pub fn admin_factory_reset(&mut self, admin_pin: &[u8; 16]) -> Result<(), Se050Error> {
        use zeroize::Zeroize;
        self.init()?;

        // Data + canary objects — these MUST be gone after a successful
        // admin wipe for the "wallet data is erased" contract to hold.
        // Each carries the admin-delete policy entry (`build_policy`
        // with `admin_auth_obj_id = Some(ADMIN_WIPE_OBJ)`), so an admin
        // session is authorised to delete them.
        //
        // Includes the full v6 canary range (0x7B10_00B0..B5) — matches
        // what `policy_roundtrip_selftest` writes (Bug 3 / work-todo
        // #29). If the selftest crashed between write and its own
        // cleanup, admin_factory_reset sweeps the stragglers.
        //
        // The decoy wallet's three data objects are on this list in EVERY
        // build (#948): they carry the admin-delete entry everywhere, and
        // they have to go while the admin session still exists, or they
        // stay on the chip with nothing able to delete them. Until
        // 2026-10-16 only bench builds listed them, so a shipping-shaped
        // wipe left the decoy's half and keys behind and still reported
        // success (the post-check below walks this same list). Deleting an
        // object that was never created is tolerated, which is how
        // non-duress builds already ran the bench list.
        const DATA_AND_CANARY_OBJS: &[(u32, &str)] = &[
            (ENTROPY_OBJ, "ENTROPY_OBJ"),
            (VK_OBJ, "VK_OBJ"),
            (BOOTSTRAP_VK_OBJ, "BOOTSTRAP_VK_OBJ"),
            (DURESS_ENTROPY_OBJ, "DURESS_ENTROPY_OBJ"),
            (DURESS_VK_OBJ, "DURESS_VK_OBJ"),
            (DURESS_BOOTSTRAP_VK_OBJ, "DURESS_BOOTSTRAP_VK_OBJ"),
            (0x7B10_00B0, "CANARY_USERID"),
            (0x7B10_00B1, "CANARY_DATA_1"),
            (0x7B10_00B2, "CANARY_DATA_2"),
            (0x7B10_00B3, "CANARY_DATA_3"),
            (0x7B10_00B4, "CANARY_DATA_4"),
            (0x7B10_00B5, "CANARY_DATA_5"),
        ];

        // Auth objects — post-S-6 the UserID's policy has NO admin-
        // delete entry (closes the substitution attack described in
        // docs/security/security-review-2026-05.md §C-8). So admin-auth deletes
        // on these will fail with SW=0x6986; that's expected, not an
        // error. They are still attempted (best-effort) and logged, but
        // survival is acceptable and does NOT fail the wipe. The user
        // data wipe — what the safety contract guarantees — is gated on
        // `DATA_AND_CANARY_OBJS` alone.
        #[cfg(not(any(feature = "e2e-test", feature = "otp-hardcoded-master-key")))]
        const AUTH_OBJS_BEST_EFFORT: &[(u32, &str)] = &[
            (USERID_OBJ, "USERID_OBJ"),
        ];
        // #912: a bench image creates both UserIDs with an admin-delete
        // entry (`USERID_ADMIN_DELETE`), so on a bench build this loop is
        // what removes them and leaves the chip re-provisionable.
        #[cfg(any(feature = "e2e-test", feature = "otp-hardcoded-master-key"))]
        const AUTH_OBJS_BEST_EFFORT: &[(u32, &str)] = &[
            (USERID_OBJ, "USERID_OBJ"),
            (DURESS_USERID_OBJ, "DURESS_USERID_OBJ"),
        ];

        unsafe {
            // If the admin UserID doesn't exist, there's nothing structured
            // to wipe via this path — fall back to plain iterative delete.
            let admin_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            ).unwrap_or(false);

            if !admin_exists {
                secure_log!(
                    "[SE050/admin-wipe] no admin UserID on chip, falling back to iterative_delete_all"
                );
                let _ = apdu::iterative_delete_all(
                    &mut self.t1, &mut self.scp03, None, None,
                );
            } else {
                let session_id = apdu::create_session(
                    &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
                )?;

                if let Err(e) = apdu::verify_session(
                    &mut self.t1, &mut self.scp03, &session_id, apdu::UserIdValue::DeviceSecret(admin_pin),
                ) {
                    secure_log!("[SE050/admin-wipe] verify_session FAILED: {:?}", e);
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
                    return Err(e);
                }

                // Delete every gated user object under admin auth,
                // including the policy_roundtrip_selftest canaries —
                // otherwise a selftest that crashed between write and
                // admin-delete leaves them stranded with an admin-
                // delete policy that unauth delete can't clear.
                //
                // Log the delete-APDU status per object so downstream
                // diagnosis can tell policy-rejection (chip-side
                // `0x6982`/`0x6986`) apart from session-invalidation
                // after Nth delete. Silent `let _ = ...` was masking
                // both patterns indistinguishably — see work-todo Bug 1.
                for (obj_id, name) in DATA_AND_CANARY_OBJS {
                    match apdu::delete_object_authed(
                        &mut self.t1, &mut self.scp03, &session_id, *obj_id,
                    ) {
                        Ok(()) => {
                            secure_log!("[SE050/admin-wipe] delete {} (0x{:08x}): Ok", name, obj_id);
                        }
                        Err(e) => {
                            secure_log!(
                                "[SE050/admin-wipe] delete {} (0x{:08x}): Err({:?})",
                                name, obj_id, e
                            );
                        }
                    }
                }
                // Best-effort UserID delete — expected to fail with
                // SW=0x6986 post-S-6 (no admin-delete in policy).  We
                // still try, in case the chip was provisioned with a
                // pre-S-6 policy that DID include admin-delete (which
                // would mean we're a fresh build sweeping legacy
                // state); a successful delete here just cleans up the
                // stale shape.
                for (obj_id, name) in AUTH_OBJS_BEST_EFFORT {
                    match apdu::delete_object_authed(
                        &mut self.t1, &mut self.scp03, &session_id, *obj_id,
                    ) {
                        Ok(()) => {
                            secure_log!(
                                "[SE050/admin-wipe] delete {} (0x{:08x}): Ok (legacy admin-delete policy)",
                                name, obj_id
                            );
                        }
                        Err(e) => {
                            secure_log!(
                                "[SE050/admin-wipe] delete {} (0x{:08x}): Err({:?}) — expected post-S-6 (UserID orphan)",
                                name, obj_id, e
                            );
                        }
                    }
                }

                // Self-delete the admin UserID inside its own session.
                match apdu::delete_object_authed(
                    &mut self.t1, &mut self.scp03, &session_id, ADMIN_WIPE_OBJ,
                ) {
                    Ok(()) => {
                        secure_log!("[SE050/admin-wipe] delete ADMIN_WIPE_OBJ (self): Ok");
                    }
                    Err(e) => {
                        secure_log!("[SE050/admin-wipe] delete ADMIN_WIPE_OBJ (self): Err({:?})", e);
                    }
                }

                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
            }
        }

        // A3 mitigation (2026-05-28): the AUTH_OBJS_BEST_EFFORT loop
        // above legitimately fails with SW=0x6986 post-S-6
        // (UserID has no admin-delete policy entry), leaving the chip
        // in a "session-pending" state per
        // `docs/secure-elements/se050-silicon-findings.md` §4. Without recovery, every
        // subsequent non-session APDU — both the `iterative_delete_all`
        // sweep below AND the post-wipe `check_exists` verification —
        // returns SW=0x6982, which the `unwrap_or(false)` callers
        // silently coerce to "object is gone". That would be a
        // false-negative on survivor detection: a real surviving user
        // object would be reported as wiped, and the safety contract's
        // post-condition check would pass on an unwiped chip. Flush
        // the session-pending state before the verification block.
        let _ = self.reinit();

        unsafe {
            // Follow up with an unauthenticated sweep to catch any stragglers
            // (e.g. legacy objects from prior firmware versions that don't
            // have the admin-delete policy entry).
            let _ = apdu::iterative_delete_all(
                &mut self.t1, &mut self.scp03, None, None,
            );

            // Post-wipe verification.  Each data / canary object MUST
            // be gone — that's the safety guarantee.  Auth objects
            // (USERID_OBJ) may survive (S-6); we log but don't fail on
            // their survival.  Admin UserID survival is tracked
            // separately below and also informational only.
            let mut first_survivor: Option<(u32, &str)> = None;
            let mut surviving_count: u32 = 0;
            for (obj_id, name) in DATA_AND_CANARY_OBJS {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj_id).unwrap_or(false) {
                    surviving_count += 1;
                    secure_log!(
                        "[SE050/admin-wipe] post-check {} (0x{:08x}): SURVIVED",
                        name, obj_id
                    );
                    if first_survivor.is_none() {
                        first_survivor = Some((*obj_id, name));
                    }
                }
            }
            // Auth-object survival is informational only (chip is
            // single-use post-lockout — the OID range must be bumped
            // to reuse the chip; the security contract is data
            // destruction, which is checked above).
            for (obj_id, name) in AUTH_OBJS_BEST_EFFORT {
                let surv = apdu::check_exists(
                    &mut self.t1, &mut self.scp03, *obj_id,
                ).unwrap_or(false);
                secure_log!(
                    "[SE050/admin-wipe] post-check {} (0x{:08x}): {} (S-6: survival acceptable)",
                    name, obj_id,
                    if surv { "SURVIVED" } else { "gone" }
                );
            }

            let admin_post = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
            ).unwrap_or(false);
            secure_log!(
                "[SE050/admin-wipe] post-check ADMIN_WIPE_OBJ: {}",
                if admin_post { "SURVIVED (page-125 erase will be skipped)" } else { "gone" },
            );

            if surviving_count > 0 {
                secure_log!(
                    "[SE050/admin-wipe] FAILED: {} user object(s) survived (first: {})",
                    surviving_count,
                    first_survivor.map(|(_, n)| n).unwrap_or("?"),
                );
                // Don't clear caches — the wipe was incomplete, the
                // caller needs to retry or escalate. Zeroizing caches
                // now would leave the driver in a "ready for fresh
                // provision" state that doesn't match the chip.
                return Err(Se050Error::Status(0x6986));
            }
        }

        self.entropy_blob_cache.zeroize();
        self.blob_cached.set_false();
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        secure_log!("[SE050/admin-wipe] Admin factory reset complete (all user objects gone)");

        Ok(())
    }

    /// Round-trip self-test: write a canary UserID + 5 gated data objects
    /// with the same TAG_POLICY template used by real provisioning, then
    /// admin-auth-delete all 6 in a single session — the exact shape
    /// the real `admin_factory_reset` uses (6 user objects under one
    /// ADMIN_WIPE_OBJ session). Aborts provisioning if any canary
    /// survives.
    ///
    /// Bug 3 (work-todo #29) hardening: the pre-refactor version only
    /// wrote + deleted 2 canaries, so a session-invalidation quirk
    /// that bites on the Nth (for N > 2) delete would pass selftest
    /// while breaking production. The 6-canary shape catches that.
    ///
    /// Uses object IDs 0x7B10_00B0..0x7B10_00B5 (inside the v6 block
    /// but distinct from the production UserID/data range).
    pub fn policy_roundtrip_selftest(&mut self, admin_pin: &[u8; 16]) -> Result<(), Se050Error> {
        self.init().map_err(|e| {
            secure_log!("[SE050/selftest] init() FAILED: {:?}", e);
            e
        })?;

        // 6 canary objects = 1 UserID (for its own delete) + 5 data
        // objects. Matches production's USER_OBJS count
        // (ENTROPY + VK + BOOTSTRAP_VK + USERID + 2 cleanup canaries = 6).
        const CANARY_USERID: u32 = 0x7B10_00B0;
        const CANARY_DATA_OBJS: &[(u32, &str)] = &[
            (0x7B10_00B1, "CANARY_DATA_1"),
            (0x7B10_00B2, "CANARY_DATA_2"),
            (0x7B10_00B3, "CANARY_DATA_3"),
            (0x7B10_00B4, "CANARY_DATA_4"),
            (0x7B10_00B5, "CANARY_DATA_5"),
        ];
        let canary_value: &'static [u8] = b"00000000";

        unsafe {
            let admin_exists = match apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            ) {
                Ok(v) => v,
                Err(e) => {
                    secure_log!(
                        "[SE050/selftest] check_exists(ADMIN_WIPE_OBJ) ERR: {:?}",
                        e
                    );
                    false
                }
            };
            secure_log!("[SE050/selftest] admin_exists={}", admin_exists);
            if !admin_exists {
                secure_log!("[SE050/selftest] returning NotProvisioned");
                return Err(Se050Error::NotProvisioned);
            }

            // Admin-authenticated cleanup of any stranded canary residue
            // from a prior interrupted selftest run. Unauthenticated
            // delete can't touch them (they carry an admin-delete policy).
            secure_log!("[SE050/selftest] admin-auth cleanup of canary residue");
            let cleanup_sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
            ).map_err(|e| {
                secure_log!("[SE050/selftest] cleanup create_session FAILED: {:?}", e);
                e
            })?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &cleanup_sid, apdu::UserIdValue::DeviceSecret(admin_pin),
            ) {
                secure_log!("[SE050/selftest] cleanup verify_session FAILED: {:?}", e);
                let _ = apdu::close_session(
                    &mut self.t1, &mut self.scp03, &cleanup_sid,
                );
                return Err(e);
            }
            for (obj_id, _name) in CANARY_DATA_OBJS {
                let _ = apdu::delete_object_authed(
                    &mut self.t1, &mut self.scp03, &cleanup_sid, *obj_id,
                );
            }
            // CANARY_USERID may carry the legacy (pre-S-6) admin-delete
            // policy on chips provisioned by older firmware; if so this
            // succeeds.  On chips with the new shape (no admin-delete)
            // this returns SW=0x6986 and we fall through to the
            // self-delete path below.
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &cleanup_sid, CANARY_USERID,
            );
            let _ = apdu::close_session(
                &mut self.t1, &mut self.scp03, &cleanup_sid,
            );

            // Self-delete path — CANARY_USERID with the new shape can
            // only be deleted by a session authenticated against itself
            // (i.e. PIN-verified).  The canary PIN is the fixed value
            // `00000000` so a prior orphaned UserID is always
            // reclaimable.  Skip if the object is gone (cleaned up
            // above) or if it never existed.
            if apdu::check_exists(
                &mut self.t1, &mut self.scp03, CANARY_USERID,
            ).unwrap_or(false) {
                if let Ok(self_sid) = apdu::create_session(
                    &mut self.t1, &mut self.scp03, CANARY_USERID,
                ) {
                    if apdu::verify_session(
                        &mut self.t1, &mut self.scp03, &self_sid, apdu::UserIdValue::Fixed(canary_value),
                    ).is_ok() {
                        let _ = apdu::delete_object_authed(
                            &mut self.t1, &mut self.scp03, &self_sid, CANARY_USERID,
                        );
                    }
                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &self_sid,
                    );
                }
            }

            // Write the canary UserID first — data objects reference it
            // as their primary auth.  Mirrors production shape: NO
            // admin-delete entry on the UserID (S-6), admin-delete is
            // ONLY on the data objects.
            secure_log!("[SE050/selftest] write CANARY_USERID (no admin_ref — S-6 production shape)");
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                CANARY_USERID, apdu::UserIdValue::Fixed(canary_value), 5, None,
            ).map_err(|e| {
                secure_log!("[SE050/selftest] write CANARY_USERID FAILED: {:?}", e);
                e
            })?;

            for (obj_id, name) in CANARY_DATA_OBJS {
                let payload: [u8; 4] = [
                    0xDE, 0xAD, (*obj_id & 0xFF) as u8, 0xEF,
                ];
                secure_log!("[SE050/selftest] write {} (0x{:08x})", name, obj_id);
                apdu::write_binary_gated(
                    &mut self.t1, &mut self.scp03,
                    *obj_id, &payload, CANARY_USERID, Some(ADMIN_WIPE_OBJ),
                ).map_err(|e| {
                    secure_log!(
                        "[SE050/selftest] write {} (0x{:08x}) FAILED: {:?}",
                        name, obj_id, e,
                    );
                    e
                })?;
            }

            // ONE admin session → 6 deletes (5 data + 1 UserID),
            // matching production's admin_factory_reset shape. Per-delete
            // logging mirrors the production path, so a session-
            // invalidation pattern shows up identically in both.
            secure_log!("[SE050/selftest] create_session against ADMIN_WIPE_OBJ (6-delete path)");
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
            ).map_err(|e| {
                secure_log!("[SE050/selftest] create_session FAILED: {:?}", e);
                e
            })?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, apdu::UserIdValue::DeviceSecret(admin_pin),
            ) {
                secure_log!("[SE050/selftest] verify_session FAILED: {:?}", e);
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                return Err(e);
            }

            for (obj_id, name) in CANARY_DATA_OBJS {
                match apdu::delete_object_authed(
                    &mut self.t1, &mut self.scp03, &sid, *obj_id,
                ) {
                    Ok(()) => {
                        secure_log!(
                            "[SE050/selftest] delete {} (0x{:08x}): Ok",
                            name, obj_id,
                        );
                    }
                    Err(e) => {
                        secure_log!(
                            "[SE050/selftest] delete {} (0x{:08x}): Err({:?})",
                            name, obj_id, e,
                        );
                    }
                }
            }
            // CANARY_USERID delete — expected to FAIL post-S-6 (admin
            // no longer has DELETE on UserID auth objects).  Try
            // anyway: a successful delete here means the chip received
            // a pre-S-6 canary policy from an earlier firmware build
            // and is being swept clean.  Treat both outcomes as
            // non-fatal; the survivor handling below allows it.
            match apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, CANARY_USERID,
            ) {
                Ok(()) => {
                    secure_log!(
                        "[SE050/selftest] delete CANARY_USERID (0x{:08x}): Ok (legacy admin-delete policy on chip)",
                        CANARY_USERID,
                    );
                }
                Err(e) => {
                    secure_log!(
                        "[SE050/selftest] delete CANARY_USERID (0x{:08x}): Err({:?}) — expected post-S-6",
                        CANARY_USERID, e,
                    );
                }
            }
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            // Self-delete the canary UserID via its own PIN-verified
            // session (the production "graceful user delete" path —
            // not used in `admin_factory_reset`, but it IS the only
            // legitimate path that can delete a UserID post-S-6, and
            // the selftest needs to leave the chip clean for re-runs).
            secure_log!("[SE050/selftest] self-delete CANARY_USERID via PIN verify");
            if let Ok(self_sid) = apdu::create_session(
                &mut self.t1, &mut self.scp03, CANARY_USERID,
            ) {
                if apdu::verify_session(
                    &mut self.t1, &mut self.scp03, &self_sid, apdu::UserIdValue::Fixed(canary_value),
                ).is_ok() {
                    let _ = apdu::delete_object_authed(
                        &mut self.t1, &mut self.scp03, &self_sid, CANARY_USERID,
                    );
                }
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &self_sid);
            }

            // Post-check: data objects MUST be gone (admin had delete).
            // CANARY_USERID survival is acceptable here even after the
            // self-delete attempt above (e.g. the canary already
            // self-deleted via the admin session above on a legacy
            // chip, leaving create_session→Err here).
            let mut data_survivors: u32 = 0;
            for (obj_id, name) in CANARY_DATA_OBJS {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj_id)
                    .unwrap_or(false)
                {
                    data_survivors += 1;
                    secure_log!(
                        "[SE050/selftest] post-delete SURVIVOR: {} (0x{:08x})",
                        name, obj_id,
                    );
                }
            }
            let canary_userid_surv = apdu::check_exists(
                &mut self.t1, &mut self.scp03, CANARY_USERID,
            ).unwrap_or(false);
            if canary_userid_surv {
                secure_log!(
                    "[SE050/selftest] post-delete CANARY_USERID (0x{:08x}): survived (orphan, acceptable post-S-6)",
                    CANARY_USERID,
                );
            }

            if data_survivors > 0 {
                secure_log!(
                    "[SE050/selftest] FAILED: {} data canaries survived the 5-delete admin session \
                     (policy TLV byte-order regression OR session-invalidation quirk)",
                    data_survivors,
                );
                return Err(Se050Error::Status(0x6986));
            }
        }

        secure_log!("[SE050/selftest] PASS (5 data canaries admin-deleted, UserID handled via self-delete)");
        Ok(())
    }

    /// Authenticate with PIN and read entropy + cached VKs from hardware.
    ///
    /// Reads all three PIN-gated objects (entropy, VK, bootstrap VK) in a
    /// single authenticated session so the unlock path never needs to run
    /// the SPHINCS+C10 hypertree keygen (<1 s per key on Cortex-M33 with
    /// `hw-sha256`, but still the dominant unlock-path cost).
    ///
    /// On success returns `(entropy, vk, bootstrap_vk)`. On PIN failure the
    /// SE050 hardware decrements its attempt counter internally.
    ///
    /// **A3 mitigation (2026-05-28).** On the failed-verify path the
    /// chip's session-pending state would surface SW=0x6982 from the
    /// NEXT `create_session` call (per
    /// `docs/secure-elements/se050-silicon-findings.md` §4 + the stress run's tests
    /// 013/014/015 evidence). Without recovery, a user's 2nd-and-later
    /// wrong PIN would propagate as `UnlockError::InternalError`
    /// (via `Status(0x6982)` → `classify_se050_unlock_error`'s `_`
    /// arm) instead of `PinIncorrect`. We `reinit()` after the failed
    /// verify so the next unlock attempt sees a fresh SCP03 state.
    /// The SE050's NVM `auth_attempts` counter persists across the
    /// reinit (`pin_counter_persists_across_reinit` stress test, P2),
    /// so the security gate is unaffected.
    fn authenticate_and_read(
        &mut self,
        user_cred: &crate::pin_credential::Se050PinCredential,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), Se050Error> {
        self.init()?;

        unsafe {
            // Create session against UserID
            let session_id = apdu::create_session(
                &mut self.t1, &mut self.scp03, USERID_OBJ,
            )?;

            // Verify the credential (SE050 hardware does the comparison).
            // #855: what is presented is the die-bound credential, never
            // the PIN.
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &session_id, apdu::UserIdValue::Credential(user_cred),
            ) {
                let _ = apdu::close_session(
                    &mut self.t1, &mut self.scp03, &session_id,
                );
                // A3 recovery before propagating the verify failure:
                // flush the chip's session-pending state so the next
                // unlock attempt's `create_session` doesn't surface
                // SW=0x6982 (which would otherwise classify as
                // `UnlockError::InternalError` and confuse the user UX
                // / the desync of the SE050 counter from the user's
                // mental model). The SE050's NVM `auth_attempts`
                // counter persists across reinit, so the security gate
                // is unaffected.
                let _ = self.reinit();
                return Err(e);
            }

            // Read all three objects through the authenticated session.
            // All share the same UserID auth policy.
            let mut entropy = [0u8; 32];
            let mut vk = [0u8; 32];
            let mut bootstrap_vk = [0u8; 32];

            let n_entropy = apdu::read_authed(
                &mut self.t1, &mut self.scp03,
                &session_id, ENTROPY_OBJ, &mut entropy,
            );

            let n_vk = apdu::read_authed(
                &mut self.t1, &mut self.scp03,
                &session_id, VK_OBJ, &mut vk,
            );

            let n_bvk = apdu::read_authed(
                &mut self.t1, &mut self.scp03,
                &session_id, BOOTSTRAP_VK_OBJ, &mut bootstrap_vk,
            );

            // Always close the session
            let _ = apdu::close_session(
                &mut self.t1, &mut self.scp03, &session_id,
            );

            // Entropy is mandatory; VK reads are best-effort (fall back
            // to full keygen in unlock if they fail).
            match n_entropy {
                Ok(32) => {}
                Ok(_) => return Err(Se050Error::Transport),
                Err(e) => return Err(e),
            }

            // Zero out VK buffers on read failure so unlock can detect
            // the miss and fall back to keygen.
            if !matches!(n_vk, Ok(32)) {
                vk = [0u8; 32];
            }
            if !matches!(n_bvk, Ok(32)) {
                bootstrap_vk = [0u8; 32];
            }

            Ok((entropy, vk, bootstrap_vk))
        }
    }
}

// ---------------------------------------------------------------------------
// WalletStore implementation
// ---------------------------------------------------------------------------

use crate::secure_element::{SeError, UnlockError, WalletStore};

/// Translate an `Se050Error` from `authenticate_and_read` into the
/// gateway-visible `UnlockError`.
///
/// Pure function so a host test can pin the §25 Gap 4 contract
/// (`AuthMethodBlocked → PinLocked`) without needing an I2C transport.
/// Attempt-counter bookkeeping (`self.remaining`) stays in the caller
/// because it needs `&mut self`.
///
/// **Dispatch contract** (mirrored in `cmd_request_unlock.rs:117-122`):
/// - `PinIncorrect` → `PinIncorrect` (gateway bumps MCU counter, wipes
///   if MAX reached).
/// - `AuthMethodBlocked` → `PinLocked` (gateway fires
///   `trigger_lockout_wipe` directly; covers the desync case where
///   SE050 is silicon-locked but MCU page-124 has been reset).
/// - All other errors → `InternalError` (transport glitch, SCP03
///   error, etc. — gateway treats as transient, no wipe).
fn classify_se050_unlock_error(e: &Se050Error) -> UnlockError {
    match e {
        Se050Error::PinIncorrect => UnlockError::PinIncorrect,
        Se050Error::AuthMethodBlocked => UnlockError::PinLocked,
        _ => UnlockError::InternalError,
    }
}

// ---------------------------------------------------------------------------
// Credential-typed entry points (#855)
// ---------------------------------------------------------------------------
//
// These are what `DualSecureElement` calls. They take an
// `Se050PinCredential` — a PRF output under the device hardware key — and
// never a PIN. The `WalletStore` methods further down that still take a PIN
// are thin single-chip shims: they turn the PIN into a credential through
// `crate::pin_gate` on their first line and then call these.

impl Se050 {
    /// Dual-SE entry point: store the wallet objects from a
    /// [`Se050Image`](crate::pin_credential::Se050Image), which can only be
    /// built by `pin_credential::chip_images` and therefore always pairs
    /// this chip's own credential with its own masked half.
    pub(crate) fn provision_image(
        &mut self,
        image: &crate::pin_credential::Se050Image,
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
    ) -> Result<(), SeError> {
        self.provision_with_credential(image.stored_half(), vk, bootstrap_vk, image.credential())
    }

    /// Dual-SE entry point for the decoy wallet; see [`provision_image`](Self::provision_image).
    #[cfg(feature = "duress-pin")]
    pub(crate) fn provision_duress_image(
        &mut self,
        image: &crate::pin_credential::Se050Image,
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
    ) -> Result<(), SeError> {
        self.provision_duress_with_credential(
            image.stored_half(),
            vk,
            bootstrap_vk,
            image.credential(),
        )
    }

    /// Store the wallet objects, with the user UserID holding `user_cred`.
    /// Called by [`provision_image`](Self::provision_image) and by the
    /// single-chip shim, which on a bench single-SE050 build stores an
    /// unmasked value.
    pub(crate) fn provision_with_credential(
        &mut self,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        user_cred: &crate::pin_credential::Se050PinCredential,
    ) -> Result<(), SeError> {
        // Admin-wipe flow (STM32 target only — QEMU has no flash):
        //   1. Derive the per-device admin PIN via
        //      `secret_keys::se050_admin_pin()` → `derive_into_bhk(...)`:
        //      `SAES-CMAC(BHK, ...)` in a `bhk` build (the current candidate
        //      hardware shape), `SAES-CMAC(DHUK, ...)` with `saes-dhuk` alone,
        //      `HKDF(OTP-master/const, ...)` on the legacy / dev path.
        //      Nothing is persisted to flash; the PIN is re-derivable on every
        //      boot from silicon HUK state. The #36 candidate uses this as the
        //      final BHK-rooted credential, but that candidate is not
        //      production-approved until handoff/recovery/silicon closure.
        //   2. Provision ADMIN_WIPE_OBJ UserID with that PIN.
        //   3. Run a canary round-trip selftest proving the admin-delete
        //      policy actually works (guardrail against TLV byte-order
        //      regressions).
        //   4. Provision data objects with two-entry TAG_POLICY (user
        //      auth → full; admin auth → DELETE) and the user UserID
        //      with the admin DELETE entry only on bench images (S-6,
        //      `USERID_ADMIN_DELETE`).
        //
        // On QEMU: step 1-3 are skipped; objects get single-entry
        // policies. PIN-lockout recovery is N/A on QEMU since there's
        // no persistent chip state to wipe anyway.
        #[cfg(all(feature = "stm32u585", not(feature = "e2e-skip-admin-wipe")))]
        {
            secure_log!("[SE050/prov] start (HUK-derived admin PIN)");

            // Derive the admin PIN from a silicon hardware root via
            // `se050_admin_pin()` → `derive_into_bhk(...)`: BHK in a `bhk`
            // build, DHUK with `saes-dhuk`, OTP-master/const on the legacy
            // / dev path. Deterministic per device, stable across power
            // cycles and reflashes; under `dev-testkey` / `otp-hardcoded-
            // master-key` / `bhk-hardcoded-master-key` it's deterministic
            // across chip swaps too.
            let mut admin_pin = crate::hw::secret_keys::se050_admin_pin()
                .map_err(|e| {
                    secure_log!("[SE050/prov] se050_admin_pin() FAILED: {:?}", e);
                    SeError::InternalError
                })?;
            secure_log!("[SE050/prov] derived admin PIN from HUK");

            secure_log!("[SE050/prov] -> provision_admin");
            self.provision_admin(&admin_pin).map_err(|e| {
                secure_log!("[SE050/prov] provision_admin FAILED: {:?}", e);
                SeError::InternalError
            })?;
            secure_log!("[SE050/prov] provision_admin OK");

            secure_log!("[SE050/prov] -> policy_roundtrip_selftest");
            self.policy_roundtrip_selftest(&admin_pin).map_err(|e| {
                secure_log!("[SE050/prov] policy_roundtrip_selftest FAILED: {:?}", e);
                SeError::InternalError
            })?;
            secure_log!("[SE050/prov] policy_roundtrip_selftest OK");

            secure_log!("[SE050/prov] -> store_objects");
            self.store_objects(
                user_cred,
                sphincs_tz_shared::MAX_ATTEMPTS as u16,
                entropy, vk, bootstrap_vk,
                Some(&admin_pin),
            ).map_err(|e| {
                secure_log!("[SE050/prov] store_objects FAILED: {:?}", e);
                SeError::InternalError
            })?;
            secure_log!("[SE050/prov] store_objects OK");

            use zeroize::Zeroize;
            admin_pin.zeroize();
            secure_log!("[SE050/prov] done (admin-wipe path)");
        }

        // Non-stm32u585 targets and `e2e-skip-admin-wipe` builds take
        // the simpler single-policy path: no admin UserID, no canary
        // selftest, no two-entry TAG_POLICY. PIN-lockout recovery is
        // N/A under `e2e-skip-admin-wipe` because the test's PIN is
        // fixed and never exhausts attempts. See the feature docs in
        // `secure/Cargo.toml` for when to (not) set this.
        #[cfg(any(not(feature = "stm32u585"), feature = "e2e-skip-admin-wipe"))]
        {
            self.store_objects(
                user_cred,
                sphincs_tz_shared::MAX_ATTEMPTS as u16,
                entropy, vk, bootstrap_vk,
                None,
            ).map_err(|_| SeError::InternalError)?;
        }


        // Cache VK + bootstrap VK so cmd_get_pubkey works before first unlock.
        self.vk_cache.copy_from_slice(vk);
        self.vk_cached = true;
        self.bootstrap_vk_cache.copy_from_slice(bootstrap_vk);
        self.bootstrap_vk_cached = true;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        Ok(())
    }

    /// Store the decoy wallet objects, with the duress UserID holding
    /// `duress_cred`. `entropy` is the SE050's decoy half.
    #[cfg(feature = "duress-pin")]
    pub(crate) fn provision_duress_with_credential(
        &mut self,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_cred: &crate::pin_credential::Se050PinCredential,
    ) -> Result<(), SeError> {
        // `entropy` here is SE050's decoy half_E (DualSE pre-split it).
        // Derive the admin PIN exactly as `provision` does so the duress
        // objects carry the same admin-delete policy → factory_reset_admin
        // sweeps them. QEMU / e2e-skip-admin-wipe use no admin (None).
        #[cfg(all(feature = "stm32u585", not(feature = "e2e-skip-admin-wipe")))]
        {
            use zeroize::Zeroize;
            let mut admin_pin = crate::hw::secret_keys::se050_admin_pin()
                .map_err(|_| SeError::InternalError)?;
            let r = self.store_duress_objects(
                entropy, vk, bootstrap_vk, duress_cred, Some(&admin_pin),
            );
            admin_pin.zeroize();
            r.map_err(|_| SeError::InternalError)?;
        }
        #[cfg(any(not(feature = "stm32u585"), feature = "e2e-skip-admin-wipe"))]
        {
            self.store_duress_objects(entropy, vk, bootstrap_vk, duress_cred, None)
                .map_err(|_| SeError::InternalError)?;
        }
        Ok(())
    }
}

impl Se050 {
    /// Present `user_cred` to the user UserID and read the wallet objects.
    pub(crate) fn unlock_with_credential(
        &mut self,
        user_cred: &crate::pin_credential::Se050PinCredential,
    ) -> Result<[u8; 32], UnlockError> {
        use zeroize::Zeroize;

        let (mut entropy, vk_from_se, bvk_from_se) =
            self.authenticate_and_read(user_cred).map_err(|e| {
                // Side-effects (attempt-counter bookkeeping) live
                // here because they need `&mut self`; the pure
                // variant translation is in
                // [`classify_se050_unlock_error`] so a host test
                // can pin the §25 Gap 4 mapping
                // (`AuthMethodBlocked → PinLocked`) without
                // standing up a fake I2C transport.
                match &e {
                    Se050Error::PinIncorrect => {
                        if self.remaining > 0 {
                            self.remaining -= 1;
                        }
                    }
                    Se050Error::AuthMethodBlocked => {
                        self.remaining = 0;
                    }
                    _ => {}
                }
                classify_se050_unlock_error(&e)
            })?;

        // Successful unlock — reset attempt counter.
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        let master_secret = crate::crypto::kdf(b"sphincs-master", &entropy, 0);

        // Cache encrypted entropy blob for the signing code.
        let blob = crate::crypto::encrypt_entropy_blob(&entropy, &master_secret);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached.set_true();

        // Cache VK + bootstrap VK directly from SE050 — no hypertree
        // keygen needed. These were written at provisioning time and are
        // read in the same authenticated session as the entropy.
        //
        // A zero VK means the SE050 read failed (legacy provisioning or
        // transport glitch). This used to re-derive the legacy C7 key from
        // `entropy` (under dual-SE, from `half_E` alone, so the result was
        // meaningless) and left its secret seed on the stack on every such
        // unlock (DVT1 row 5.5). The slot carries no authority: cache the
        // public placeholder instead.
        if vk_from_se != [0u8; 32] {
            self.vk_cache.copy_from_slice(&vk_from_se);
        } else {
            self.vk_cache.copy_from_slice(&crate::crypto::RETIRED_LEGACY_VK);
        }
        self.vk_cached = true;

        if bvk_from_se != [0u8; 32] {
            self.bootstrap_vk_cache.copy_from_slice(&bvk_from_se);
        } else {
            self.bootstrap_vk_cache
                .copy_from_slice(&crate::crypto::RETIRED_LEGACY_BOOTSTRAP_VK);
        }
        self.bootstrap_vk_cached = true;

        entropy.zeroize();
        crate::fi::zeroize_barrier();

        Ok(master_secret)
    }
}

impl WalletStore for Se050 {
    fn is_provisioned(&mut self) -> bool {
        self.check_provisioned()
    }

    /// Single-chip shim (the bench `se050` backend, and e2e flows that drive
    /// this chip on its own). Derives the die-bound credential first; the
    /// PIN goes no further than this function.
    fn provision(
        &mut self,
        entropy: &[u8; 32],
        _master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // SAFETY: `&mut self` on the SE driver implies the single-threaded
        // secure-world context the page-125 salt write requires.
        let set = unsafe {
            crate::pin_gate::provisioning_credentials(
                crate::pin_credential::WalletRole::Real,
                pin,
            )
        }
        .map_err(|_| SeError::InternalError)?;
        self.provision_with_credential(entropy, vk, bootstrap_vk, &set.se050)
    }

    /// Single-chip shim; see [`provision`](Self::provision).
    #[cfg(feature = "duress-pin")]
    fn provision_duress(
        &mut self,
        entropy: &[u8; 32],
        _master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // The decoy is provisioned right after the real wallet, under the
        // salt that provisioning has just minted; refused otherwise.
        let set = crate::pin_gate::decoy_provisioning_credentials(duress_pin)
            .map_err(|_| SeError::InternalError)?;
        self.provision_duress_with_credential(entropy, vk, bootstrap_vk, &set.se050)
    }

    #[cfg(feature = "duress-pin")]
    fn duress_is_provisioned(&mut self) -> bool {
        if self.init().is_err() {
            return false;
        }
        unsafe {
            apdu::check_exists(&mut self.t1, &mut self.scp03, DURESS_USERID_OBJ)
                .unwrap_or(false)
        }
    }

    fn pin_credentials_recomputable(&mut self) -> bool {
        crate::pin_gate::credentials_recomputable()
    }

    /// Single-chip shim; see [`provision`](Self::provision). With no usable
    /// salt on page 125 the credential cannot be recomputed, so this fails
    /// with `InternalError` before any APDU is sent.
    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        let set = crate::pin_gate::unlock_credentials(
            crate::pin_credential::WalletRole::Real,
            pin,
        )
        .map_err(|_| UnlockError::InternalError)?;
        self.unlock_with_credential(&set.se050)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached.is_true_fi() || buf.len() < crate::crypto::ENTROPY_BLOB_LEN {
            return Err(SeError::SlotNotFound);
        }
        buf[..crate::crypto::ENTROPY_BLOB_LEN]
            .copy_from_slice(&self.entropy_blob_cache);
        Ok(crate::crypto::ENTROPY_BLOB_LEN)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.vk_cache);
        Ok(32)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.bootstrap_vk_cached || buf.len() < 32 {
            return Err(SeError::SlotNotFound);
        }
        buf[..32].copy_from_slice(&self.bootstrap_vk_cache);
        Ok(32)
    }

    fn remaining_attempts(&mut self) -> u8 {
        self.remaining
    }

    fn sync_remaining_with_mcu(&mut self, mcu_used: u8) {
        let mcu_remaining = sphincs_tz_shared::MAX_ATTEMPTS.saturating_sub(mcu_used);
        if mcu_remaining < self.remaining {
            self.remaining = mcu_remaining;
        }
    }

    fn zeroize_caches(&mut self) {
        use zeroize::Zeroize;
        self.entropy_blob_cache.zeroize();
        self.blob_cached.set_false();
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        // MEDIUM-1 (audit secret-lifecycle 20260611): also tear down the
        // live SCP03 session keys so they don't outlive the unlock session
        // in SRAM. Lock / idle-wipe / panic reach here via
        // `nsc::zeroize_sensitive_state`.
        self.scp03.zeroize_session();
        // Idle-relock fix (2026-07-02): drop `ready` WITH the session.
        // Leaving it set made the next `init()` a no-op, so the post-lock
        // re-unlock ran session-less — `send_apdu` (then) downgraded to
        // cleartext CLA=0x80, the chip refused with 0x6982/0x6985, and a
        // correct PIN rendered as "Wrong PIN" while burning a page-124
        // attempt per retry. Cleared, the next SE access re-runs the full
        // T=1' reset + SELECT + SCP03 establish — the same re-handshake-
        // on-next-access contract as OPTIGA's `ensure_shield`.
        self.ready = false;
    }

    fn random(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        Se050::random(self, buf).map_err(|_| SeError::InternalError)
    }

    fn random_se050(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        Se050::random(self, buf).map_err(|_| SeError::InternalError)
    }

    fn pin_attempt_count(&mut self) -> Option<u8> {
        // Saturate at MAX_ATTEMPTS — a chip-side `auth_attempts` ≥ MAX
        // means "locked out, treat as fully consumed" for reconcile.
        let cap = sphincs_tz_shared::MAX_ATTEMPTS;
        self.pin_attempt_count_raw().map(|n| n.min(cap))
    }

    #[cfg(feature = "stm32u585")]
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        // Re-derive the admin PIN via `secret_keys::se050_admin_pin()`
        // → `derive_into_bhk("pqsigner/se050-admin-pin-v1")` — the same
        // derivation `store_objects` uses to write the admin UserID. In a
        // `bhk` build (the current candidate hardware shape) that's
        // `SAES-CMAC(BHK, ...)`;
        // with `saes-dhuk` alone it falls through to `SAES-CMAC(DHUK, ...)`;
        // the legacy / `otp-hardcoded-master-key` path is `HKDF(OTP-master/
        // const, ...)`. Every variant is deterministic per device across
        // ordinary reflashes. The BHK-rooted variant depends on the wrapped
        // BHK in page 126: a flash mass erase destroys that root, so a newly
        // generated BHK cannot authenticate the existing SE050 admin object
        // without an authorized re-pair/reprovision ceremony. The former
        // page-125 PIN slot is gone entirely (no `write_admin_pin` /
        // `read_admin_pin` anymore); deriving on demand removes page-125 PIN
        // desynchronization, but it does not make BHK loss recoverable or by
        // itself approve the journaled first-boot credential protocol.
        //
        // Page 125 still holds the wipe-in-progress flag (for crash-safe
        // resume) at `WIPE_FLAG_OFFSET`, which we arm below — a separate
        // slot from the dead QW0, so flag operations don't touch it.
        use zeroize::Zeroize;

        // #855: arm the wipe flag and destroy the PIN-credential salt before
        // the first APDU. From here on the value in the user UserID can
        // never be recomputed by this device, whatever happens to the
        // chip-side wipe below — including the early return just after
        // this, which used to report success having wiped nothing.
        //
        // SAFETY: `&mut self` on the SE driver implies the single-threaded
        // secure-world context the page-125 writes require.
        let salt_gone = unsafe { crate::pin_gate::begin_wipe() };

        let mut admin_pin = match crate::hw::secret_keys::se050_admin_pin() {
            Ok(p) => p,
            Err(e) => {
                secure_log!(
                    "[SE050/factory_reset_admin] se050_admin_pin() FAILED: {:?} — \
                     falling back to unauth sweep (user objects will survive)",
                    e
                );
                unsafe {
                    let _ = self.iterative_wipe(None, None);
                }
                self.zeroize_caches();
                return salt_gone.map_err(|_| SeError::InternalError);
            }
        };

        unsafe {
            // Already armed by `begin_wipe` above in the normal case; kept
            // as a second attempt if that program failed.
            if !crate::hw::flash::is_wipe_armed() {
                let _ = crate::hw::flash::arm_wipe_flag();
            }

            // Propagate any error from admin_factory_reset — now that
            // it returns Err when user objects survive, the trait-
            // level dispatch can tell whether the wipe actually
            // completed and let the page-125 erase gate on real
            // chip state rather than a silent swallow.
            let wipe_result = self.admin_factory_reset(&admin_pin);
            admin_pin.zeroize();

            // Conditional erase: only burn the flash state if the chip
            // confirms the admin UserID is actually gone AND the salt was
            // destroyed. Otherwise leave page 125 intact so the next resume
            // retries. (The erase also returns the salt log to blank.)
            if salt_gone.is_ok() && !self.admin_exists() {
                let _ = crate::hw::flash::erase_admin_page();
            }

            if let Err(e) = wipe_result {
                secure_log!(
                    "[SE050/factory_reset_admin] admin_factory_reset returned Err({:?}) — \
                     wipe incomplete; flash state preserved for resume",
                    e
                );
                return Err(SeError::InternalError);
            }
        }

        self.zeroize_caches();
        salt_gone.map_err(|_| SeError::InternalError)
    }
}

#[cfg(feature = "e2e-test")]
impl Se050 {
    /// e2e-only: reset the in-RAM `remaining` cache to `MAX_ATTEMPTS`
    /// without touching any durable state. Simulates the post-reboot
    /// condition where `const fn new()` yields MAX but the chip's own
    /// UserID counter retains its actual value. Used by
    /// `pin-gate-hw-counter-e2e` phase-5 to exercise the boot-time
    /// `sync_remaining_with_mcu` path without power-cycling the board.
    pub fn _e2e_force_remaining_to_max(&mut self) {
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;
    }
}

// Host tests for §25 Gap 4 live in
// `secure/src/se050_under_test/pure_tests.rs` as source-text pins
// (the established pattern in this crate, because the production
// module is `#[cfg(not(test))]` gated and inline `#[cfg(test)]`
// blocks never run). Real-silicon validation is the deferred step:
// run `iterative_wipe` on a throwaway UserID to drive it to
// attempts=0, then VERIFY, capture the SW — if it's not 0x6986
// update both the `apdu::verify_session` arm and the
// `AuthMethodBlocked` doc.
