//! NXP SE050 secure element driver.
//!
//! Stores BIP-39 entropy on the SE050, protected by a hardware-enforced
//! UserID PIN (max 10 attempts before permanent lockout).
//!
//! Communication: I2C1 (PB8 SCL, PB9 SDA) -> T1oI2C -> SE05x APDUs,
//! all wrapped in an SCP03 authenticated/encrypted channel.

pub mod i2c;
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
///                            that chip. v6 ships with the OTP-
///                            derived admin PIN (`se050_admin_pin()`),
///                            so this failure class is structurally
///                            eliminated — the admin PIN is always
///                            firmware-reproducible, no flash pairing
///                            to desync.
/// Bumping the range yields a chip as usable as a fresh one — the
/// stuck OIDs occupy <150 bytes of ~130 KB persistent storage.
pub const USERID_OBJ: u32 = 0x7B10_0000;

/// Raw BIP-39 entropy (32 bytes), policy requires UserID auth.
pub const ENTROPY_OBJ: u32 = 0x7B10_0001;

/// Verifying key (32 bytes), policy requires UserID auth.
pub const VK_OBJ: u32 = 0x7B10_0002;

/// Bootstrap verifying key (32 bytes), policy requires UserID auth.
pub const BOOTSTRAP_VK_OBJ: u32 = 0x7B10_0003;

/// Admin wipe UserID. Second auth object, created at provisioning
/// with an OTP-derived PIN (`hw::secret_keys::se050_admin_pin()` —
/// HKDF over OTP master, deterministic per device, stable across
/// power cycles and flash mass-erase). Used by the PIN-lockout
/// factory-reset path: after 10 failed user PIN attempts, firmware
/// authenticates against this object and deletes every user object
/// (which all carry an admin-delete policy entry pointing here).
///
/// **Invariant (post-v6)**: the admin PIN is reproducible from OTP,
/// so there is no flash-side pairing to drift out of sync with the
/// on-chip UserID. Previous ranges (v3–v5) paired admin with flash
/// page 125 and retired whenever the two desynchronised; v6 removes
/// the coupling entirely.
///
/// Page 125 still exists — it now holds only the wipe-in-progress
/// flag (`arm_wipe_flag / is_wipe_armed`) and the legacy PIN slot
/// that pre-v6 provisionings wrote to. On fresh v6 provisionings the
/// PIN slot stays blank; `erase_admin_page` is still called
/// conditionally after a successful wipe to clear the flag.
pub const ADMIN_WIPE_OBJ: u32 = 0x7B10_00A0;

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
    blob_cached: bool,
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
            blob_cached: false,
            vk_cache: [0; 32],
            vk_cached: false,
            bootstrap_vk_cache: [0; 32],
            bootstrap_vk_cached: false,
            remaining: sphincs_tz_shared::MAX_ATTEMPTS,
        }
    }

    /// Initialize the SE050: T1oI2C reset, applet SELECT, SCP03 establish.
    ///
    /// Called lazily on first use. Subsequent calls are no-ops.
    pub fn init(&mut self) -> Result<(), Se050Error> {
        if self.ready {
            return Ok(());
        }

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
            secure_log!("[SE050] Init: establishing SCP03...");

            scp03::establish(&mut self.scp03, &mut self.t1)?;

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init complete");
        }

        self.ready = true;
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
        pin: Option<&[u8]>,
    ) -> Result<(u16, u16, bool), Se050Error> {
        self.init()?;
        unsafe {
            apdu::iterative_delete_all(&mut self.t1, &mut self.scp03, auth_obj_id, pin)
        }
    }

    /// User-initiated factory reset: verify PIN, delete every UserID-gated
    /// data object, then self-delete the UserID itself. Leaves the SE050
    /// side blank and ready for re-provisioning.
    ///
    /// The UserID deletion only succeeds if it was created with the
    /// self-deletable policy (new UserIDs have it; legacy ones don't).
    /// Zeroizes cached blobs in RAM on success.
    pub fn user_factory_reset(&mut self, pin: &[u8]) -> Result<(), Se050Error> {
        use zeroize::Zeroize;
        self.init()?;

        unsafe {
            let session_id =
                apdu::create_session(&mut self.t1, &mut self.scp03, USERID_OBJ)?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &session_id, pin,
            ) {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
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
        self.blob_cached = false;
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        #[cfg(feature = "debug-log")]
        secure_log!("[SE050] User factory reset complete");

        Ok(())
    }

    /// Legacy platform factory reset — kept for completeness but does
    /// NOT actually wipe objects. `SetPlatformSCPRequest` only toggles
    /// SCP03-mandatory. Use `iterative_wipe` or `user_factory_reset`
    /// for real cleanup.
    pub fn factory_reset(&mut self) -> Result<(), Se050Error> {
        self.init()?;
        unsafe {
            apdu::platform_factory_reset(&mut self.t1, &mut self.scp03)?;
        }
        self.ready = false;
        self.scp03 = scp03::Scp03Session::new();
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
    pub fn run_factory_reset_roundtrip(&mut self, pin: &[u8]) -> Result<(), Se050Error> {
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
                        &mut self.t1, &mut self.scp03, &sid, pin
                    ).is_ok() {
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
                &mut self.t1, &mut self.scp03, TEST_USERID_OBJ, pin, 9, None,
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
            apdu::verify_session(&mut self.t1, &mut self.scp03, &sid, pin)
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
        let user_pin: [u8; 8] = *b"testuser";
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
                        &mut self.t1, &mut self.scp03, &sid, &admin_pin,
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
            apdu::write_userid(
                &mut self.t1, &mut self.scp03, TEST_ADMIN, &admin_pin, 0, None,
            )?;

            // User UserID with two-entry policy: self + admin
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                TEST_USER, &user_pin, 5, Some(TEST_ADMIN),
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
                &mut self.t1, &mut self.scp03, &sid, &admin_pin,
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
    ///   c. Persist the test admin PIN to flash page 125 QW0 so the
    ///      resume phase can read it back (same mechanism the real
    ///      wipe path uses).
    ///   d. Arm the wipe flag at page 125 QW1.
    ///   e. Partial wipe: open admin session, delete ONLY the data
    ///      object, leaving user + admin UserIDs intact. This models
    ///      power being cut halfway through the wipe sequence.
    ///   f. Halt. Reports "PHASE 1 — RESET BOARD NOW".
    ///
    /// PHASE 2 (flag armed on boot):
    ///   a. Verify pre-resume state: data gone, user present, admin
    ///      present, flag armed. Any deviation = FAIL.
    ///   b. Read test admin PIN from flash page 125 QW0 (same read
    ///      path the real `factory_reset_admin` uses).
    ///   c. Open admin session, delete remaining user + admin UserIDs.
    ///   d. Verify all three test objects are gone.
    ///   e. Erase flash page 125 — clears admin PIN and flag atomically,
    ///      proving the normal wipe-completion path works.
    ///   f. Reports "PHASE 2 — CRASH-SAFETY RESUME: PASS".
    ///
    /// Returns a status tag the caller can print. Destructive to any
    /// real admin PIN on page 125 — only run on a chip that hasn't yet
    /// been through first-boot wizard with production firmware.
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
        let user_pin: [u8; 8] = *b"crashsim";
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
                        &mut self.t1, &mut self.scp03, &sid, &admin_pin,
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
            apdu::write_userid(
                &mut self.t1, &mut self.scp03, TEST_ADMIN, &admin_pin, 0, None,
            )?;
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                TEST_USER, &user_pin, 5, Some(TEST_ADMIN),
            )?;
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA, &payload, TEST_USER, Some(TEST_ADMIN),
            )?;

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 1b provision OK");

            // ---- c. Persist admin PIN to flash (so phase 2 can read it) ----
            #[cfg(feature = "stm32u585")]
            {
                crate::hw::flash::write_admin_pin(&admin_pin)
                    .map_err(|_| Se050Error::Transport)?;

                #[cfg(feature = "debug-log")]
                secure_log!("[E2E-CRASH] 1c admin PIN persisted to flash page 125");

                // ---- d. Arm the wipe flag ----
                crate::hw::flash::arm_wipe_flag()
                    .map_err(|_| Se050Error::Transport)?;

                #[cfg(feature = "debug-log")]
                secure_log!("[E2E-CRASH] 1d wipe flag armed");
            }

            // ---- e. Partial wipe: delete only the data object ----
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, &admin_pin,
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

            // ---- b. Read admin PIN from flash (same path real resume uses) ----
            #[cfg(feature = "stm32u585")]
            let mut admin_pin = {
                let mut buf = [0u8; 16];
                crate::hw::flash::read_admin_pin(&mut buf);
                buf
            };
            #[cfg(not(feature = "stm32u585"))]
            let mut admin_pin = [0u8; 16];

            #[cfg(feature = "debug-log")]
            secure_log!("[E2E-CRASH] 2b admin PIN read from flash");

            // ---- c. Finish the wipe ----
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, TEST_ADMIN,
            )?;
            apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, &admin_pin,
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
    /// Every user object (UserID + three data blobs) gets a two-entry
    /// TAG_POLICY: (user auth → full access) + (admin auth → DELETE only).
    /// The admin UserID has unlimited attempts (max_attempts=0) — its PIN
    /// is a 16-byte random derived from the OPTIGA PBS, so brute force is
    /// infeasible and the wipe path must not lock itself out.
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
        pin: &[u8],
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
                    secure_log!("[SE050/store] writing admin UserID (max_attempts=0, no admin_ref)");
                    apdu::write_userid(
                        &mut self.t1, &mut self.scp03,
                        ADMIN_WIPE_OBJ, admin, 0, None,
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
                        &mut self.t1, &mut self.scp03, &session_id, admin,
                    ) {
                        secure_log!(
                            "[SE050/store] stale sweep: verify_session FAILED: {:?}", e
                        );
                        let _ = apdu::close_session(
                            &mut self.t1, &mut self.scp03, &session_id,
                        );
                        return Err(e);
                    }

                    // Data objects first, USERID_OBJ last. Only delete
                    // confirmed-present objects so any error propagated
                    // below is a real failure, not delete-on-absent. Order
                    // within {data objects} is cosmetic — admin-auth
                    // delete doesn't chain through USERID_OBJ.
                    for idx in [1usize, 2, 3, 0] {
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

                    let _ = apdu::close_session(
                        &mut self.t1, &mut self.scp03, &session_id,
                    );
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
                     inherit the stale policy)"
                );
                return Err(Se050Error::Status(0x6986));
            }

            if !userid_exists {
                secure_log!(
                    "[SE050/store] writing USERID_OBJ (pin_len={} max_attempts={})",
                    pin.len(), max_attempts
                );
                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    USERID_OBJ, pin, max_attempts, admin_ref,
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
                    apdu::write_binary_gated(
                        &mut self.t1, &mut self.scp03,
                        *obj_id, data, USERID_OBJ, admin_ref,
                    ).map_err(|e| {
                        secure_log!(
                            "[SE050/store] write_binary_gated(0x{:08x}) FAILED: {:?}",
                            obj_id, e
                        );
                        e
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Provision the SE050 with admin-wipe support.
    ///
    /// Same as the WalletStore::provision path except every user object
    /// gets a two-entry TAG_POLICY whose second entry authorises ADMIN_WIPE_OBJ
    /// to delete. Caller (dual_se.rs) supplies the per-device admin PIN
    /// derived from the OPTIGA PBS.
    pub fn provision_with_admin(
        &mut self,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
        admin_pin: &[u8; 16],
    ) -> Result<(), Se050Error> {
        self.store_objects(
            pin,
            sphincs_tz_shared::MAX_ATTEMPTS as u16,
            entropy, vk, bootstrap_vk,
            Some(admin_pin),
        )?;

        self.vk_cache.copy_from_slice(vk);
        self.vk_cached = true;
        self.bootstrap_vk_cache.copy_from_slice(bootstrap_vk);
        self.bootstrap_vk_cached = true;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

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
                secure_log!("[SE050/admin] writing admin UserID (16-byte PIN, max_attempts=0, no admin_ref)");
                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    ADMIN_WIPE_OBJ, admin_pin, 0, None,
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

        // Objects that MUST be gone after a successful admin wipe for
        // the "wallet data is erased" contract to hold. Admin UserID
        // survival is tracked separately below — the caller's
        // `admin_exists()` check drives flash-page-125 erase decisions.
        //
        // Cleanup list covers the full v6 canary range (0x7B10_00B0..B5)
        // — matches what `policy_roundtrip_selftest` writes (Bug 3 /
        // work-todo #29). If the selftest crashed between write and
        // its own cleanup, admin_factory_reset sweeps the stragglers.
        const USER_OBJS: &[(u32, &str)] = &[
            (ENTROPY_OBJ, "ENTROPY_OBJ"),
            (VK_OBJ, "VK_OBJ"),
            (BOOTSTRAP_VK_OBJ, "BOOTSTRAP_VK_OBJ"),
            (USERID_OBJ, "USERID_OBJ"),
            (0x7B10_00B0, "CANARY_USERID"),
            (0x7B10_00B1, "CANARY_DATA_1"),
            (0x7B10_00B2, "CANARY_DATA_2"),
            (0x7B10_00B3, "CANARY_DATA_3"),
            (0x7B10_00B4, "CANARY_DATA_4"),
            (0x7B10_00B5, "CANARY_DATA_5"),
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
                    &mut self.t1, &mut self.scp03, &session_id, admin_pin,
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
                for (obj_id, name) in USER_OBJS {
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

            // Follow up with an unauthenticated sweep to catch any stragglers
            // (e.g. legacy objects from prior firmware versions that don't
            // have the admin-delete policy entry).
            let _ = apdu::iterative_delete_all(
                &mut self.t1, &mut self.scp03, None, None,
            );

            // Post-wipe verification. Each user object MUST be gone; if
            // any survived the admin-auth delete the wipe is incomplete
            // and the caller (flash-page-125 erase, multi-chip wipe
            // coordinator) needs to know so it doesn't falsely advance
            // state. Admin UserID survival is NOT a hard failure here:
            // it matters for page-125 lifecycle but user-data wipe
            // (the security guarantee) is orthogonal.
            let mut first_survivor: Option<(u32, &str)> = None;
            let mut surviving_count: u32 = 0;
            for (obj_id, name) in USER_OBJS {
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
        self.blob_cached = false;
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
        let canary_pin: [u8; 8] = *b"00000000";

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
                &mut self.t1, &mut self.scp03, &cleanup_sid, admin_pin,
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
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &cleanup_sid, CANARY_USERID,
            );
            let _ = apdu::close_session(
                &mut self.t1, &mut self.scp03, &cleanup_sid,
            );

            // Write the canary UserID first — data objects reference it
            // as their primary auth.
            secure_log!("[SE050/selftest] write CANARY_USERID");
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                CANARY_USERID, &canary_pin, 5, Some(ADMIN_WIPE_OBJ),
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
                &mut self.t1, &mut self.scp03, &sid, admin_pin,
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
            match apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, CANARY_USERID,
            ) {
                Ok(()) => {
                    secure_log!("[SE050/selftest] delete CANARY_USERID (0x{:08x}): Ok", CANARY_USERID);
                }
                Err(e) => {
                    secure_log!(
                        "[SE050/selftest] delete CANARY_USERID (0x{:08x}): Err({:?})",
                        CANARY_USERID, e,
                    );
                }
            }
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            // Post-check every canary — any survivor means the
            // production 6-delete shape is broken.
            let mut survivors: u32 = 0;
            for (obj_id, name) in CANARY_DATA_OBJS {
                if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj_id)
                    .unwrap_or(false)
                {
                    survivors += 1;
                    secure_log!(
                        "[SE050/selftest] post-delete SURVIVOR: {} (0x{:08x})",
                        name, obj_id,
                    );
                }
            }
            if apdu::check_exists(&mut self.t1, &mut self.scp03, CANARY_USERID)
                .unwrap_or(false)
            {
                survivors += 1;
                secure_log!(
                    "[SE050/selftest] post-delete SURVIVOR: CANARY_USERID (0x{:08x})",
                    CANARY_USERID,
                );
            }

            if survivors > 0 {
                secure_log!(
                    "[SE050/selftest] FAILED: {} canary/canaries survived the 6-delete admin session \
                     (policy TLV byte-order regression OR session-invalidation quirk)",
                    survivors,
                );
                return Err(Se050Error::Status(0x6986));
            }
        }

        secure_log!("[SE050/selftest] PASS (6 canaries admin-deleted in one session)");
        Ok(())
    }

    /// Authenticate with PIN and read entropy + cached VKs from hardware.
    ///
    /// Reads all three PIN-gated objects (entropy, VK, bootstrap VK) in a
    /// single authenticated session so the unlock path never needs to run
    /// the expensive SPHINCS+C7 hypertree keygen (~25s per key on Cortex-M33).
    ///
    /// On success returns `(entropy, vk, bootstrap_vk)`. On PIN failure the
    /// SE050 hardware decrements its attempt counter internally.
    fn authenticate_and_read(
        &mut self,
        pin: &[u8],
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), Se050Error> {
        self.init()?;

        unsafe {
            // Create session against UserID
            let session_id = apdu::create_session(
                &mut self.t1, &mut self.scp03, USERID_OBJ,
            )?;

            // Verify PIN (SE050 hardware does the comparison)
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &session_id, pin,
            ) {
                let _ = apdu::close_session(
                    &mut self.t1, &mut self.scp03, &session_id,
                );
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

impl WalletStore for Se050 {
    fn is_provisioned(&mut self) -> bool {
        self.check_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        _master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // Admin-wipe flow (STM32 target only — QEMU has no flash):
        //   1. Load or generate the per-device admin PIN via STM32 TRNG,
        //      persist to secure flash page 125.
        //   2. Provision ADMIN_WIPE_OBJ UserID with that PIN.
        //   3. Run a canary round-trip selftest proving the admin-delete
        //      policy actually works (guardrail against TLV byte-order
        //      regressions).
        //   4. Provision user UserID + data objects with two-entry
        //      TAG_POLICY (user auth → full; admin auth → DELETE).
        //
        // On QEMU: step 1-3 are skipped; objects get single-entry
        // policies. PIN-lockout recovery is N/A on QEMU since there's
        // no persistent chip state to wipe anyway.
        #[cfg(all(feature = "stm32u585", not(feature = "e2e-skip-admin-wipe")))]
        {
            secure_log!("[SE050/prov] start (OTP-derived admin PIN)");

            // Derive the admin PIN from OTP master (via HKDF-Expand).
            // Deterministic per device, stable across power cycles and
            // flash mass-erase. Under `dev-testkey` / `otp-hardcoded-
            // master-key` it's deterministic across chip swaps too.
            let mut admin_pin = crate::hw::secret_keys::se050_admin_pin()
                .map_err(|e| {
                    secure_log!("[SE050/prov] se050_admin_pin() FAILED: {:?}", e);
                    SeError::InternalError
                })?;
            secure_log!("[SE050/prov] derived admin PIN from OTP master");

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
                pin,
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
                pin,
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

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        use zeroize::Zeroize;

        let (mut entropy, vk_from_se, bvk_from_se) =
            self.authenticate_and_read(pin).map_err(|e| match e {
                Se050Error::PinIncorrect => {
                    if self.remaining > 0 {
                        self.remaining -= 1;
                    }
                    UnlockError::PinIncorrect
                }
                _ => UnlockError::InternalError,
            })?;

        // Successful unlock — reset attempt counter.
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        let master_secret = crate::crypto::kdf(b"sphincs-master", &entropy, 0);

        // Cache encrypted entropy blob for the signing code.
        let blob = crate::crypto::encrypt_entropy_blob(&entropy, &master_secret);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached = true;

        // Cache VK + bootstrap VK directly from SE050 — no hypertree
        // keygen needed. These were written at provisioning time and are
        // read in the same authenticated session as the entropy.
        //
        // A zero VK means the SE050 read failed (legacy provisioning or
        // transport glitch). Fall back to the expensive full keygen only
        // in that case.
        if vk_from_se != [0u8; 32] {
            self.vk_cache.copy_from_slice(&vk_from_se);
            self.vk_cached = true;
        } else {
            let (sk, vk_bytes) = crate::crypto::derive_keypair_from_entropy(&entropy);
            drop(sk);
            self.vk_cache.copy_from_slice(&vk_bytes);
            self.vk_cached = true;
        }

        if bvk_from_se != [0u8; 32] {
            self.bootstrap_vk_cache.copy_from_slice(&bvk_from_se);
            self.bootstrap_vk_cached = true;
        } else {
            let bvk = crate::crypto::derive_bootstrap_vk_from_entropy(&entropy);
            self.bootstrap_vk_cache.copy_from_slice(&bvk);
            self.bootstrap_vk_cached = true;
        }

        entropy.zeroize();

        Ok(master_secret)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached || buf.len() < crate::crypto::ENTROPY_BLOB_LEN {
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
        self.blob_cached = false;
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
    }

    #[cfg(feature = "stm32u585")]
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        // Re-derive the admin PIN from OTP master — the same derivation
        // the provisioning path uses (`store_objects` calls
        // `crate::hw::secret_keys::se050_admin_pin()` to write the
        // admin UserID). The flash-page-125 PIN slot is a legacy of
        // pre-v6 provisionings and is deliberately blank on chips
        // provisioned under the v6 OTP-derived admin scheme — reading
        // it and branching on `is_admin_pin_blank()` would route
        // every v6 wipe into `iterative_wipe(None, None)`, which
        // can't touch admin-gated user objects and leaves the wallet
        // seed on-chip.
        //
        // Page 125 still holds the wipe-in-progress flag (for crash-
        // safe resume) which we arm below; the flag offset is
        // separate from the legacy PIN slot so flag operations
        // don't touch the PIN.
        use zeroize::Zeroize;

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
                return Ok(());
            }
        };

        unsafe {
            let _ = crate::hw::flash::arm_wipe_flag();

            // Propagate any error from admin_factory_reset — now that
            // it returns Err when user objects survive, the trait-
            // level dispatch can tell whether the wipe actually
            // completed and let the page-125 erase gate on real
            // chip state rather than a silent swallow.
            let wipe_result = self.admin_factory_reset(&admin_pin);
            admin_pin.zeroize();

            // Conditional erase: only burn the flash state if the chip
            // confirms the admin UserID is actually gone. Otherwise
            // leave page 125 intact so the next resume retries.
            if !self.admin_exists() {
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
        Ok(())
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
