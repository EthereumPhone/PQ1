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
use t1oi2c::T1State;

// ---------------------------------------------------------------------------
// Object IDs on the SE050
// ---------------------------------------------------------------------------

/// UserID authentication object — hardware-enforced PIN.
/// Range v3 (0x7B06xxxx) to avoid stale objects from old firmware.
pub const USERID_OBJ: u32 = 0x7B06_0000;

/// Raw BIP-39 entropy (32 bytes), policy requires UserID auth.
pub const ENTROPY_OBJ: u32 = 0x7B06_0001;

/// Verifying key (32 bytes), policy requires UserID auth.
pub const VK_OBJ: u32 = 0x7B06_0002;

/// Bootstrap verifying key (32 bytes), policy requires UserID auth.
pub const BOOTSTRAP_VK_OBJ: u32 = 0x7B06_0003;

/// Admin wipe UserID. Second auth object, created at provisioning with a
/// per-device random PIN derived from the OPTIGA PBS. Used only by the
/// PIN-lockout factory-reset path: after 10 failed user PIN attempts,
/// firmware authenticates against this object and deletes every user
/// object (which all carry an admin-delete policy entry pointing here).
///
/// The admin PIN itself is never persisted in plaintext anywhere —
/// derived on demand via `crypto::derive_se050_admin_pin(&pbs)`.
pub const ADMIN_WIPE_OBJ: u32 = 0x7B06_00A0;

// -- Factory-reset self-test object IDs --
// Distinct from production IDs so the test never collides with a real
// provisioning, and is repeatable on a chip that already has prod
// objects at 0x7B06_xxxx.
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
            // Power-on delay (~3 ms for SE050 VCC stabilization)
            for _ in 0..500_000 {
                cortex_m::asm::nop();
            }

            #[cfg(feature = "debug-log")]
            secure_log!("[SE050] Init: interface reset...");

            self.t1.interface_reset().map_err(|_| Se050Error::Transport)?;

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
    /// Skips objects that already exist (re-provisioning without wipe is
    /// rejected at the SE050 level by the existing policies).
    fn store_objects(
        &mut self,
        pin: &[u8],
        max_attempts: u16,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        admin_pin: Option<&[u8; 16]>,
    ) -> Result<(), Se050Error> {
        self.init()?;

        unsafe {
            // Admin UserID first: must exist before user objects reference it
            // in their admin-delete policy entries.
            if let Some(admin) = admin_pin {
                let admin_exists = apdu::check_exists(
                    &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
                ).unwrap_or(false);

                if !admin_exists {
                    #[cfg(feature = "debug-log")]
                    secure_log!("[SE050] Creating admin UserID...");

                    // Admin UserID policy: self-delete under admin auth.
                    // max_attempts=0 = unlimited (PIN is per-device random).
                    apdu::write_userid(
                        &mut self.t1, &mut self.scp03,
                        ADMIN_WIPE_OBJ, admin, 0, None,
                    )?;
                }
            }

            let admin_ref = admin_pin.map(|_| ADMIN_WIPE_OBJ);

            // User UserID: skip if already exists.
            let userid_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, USERID_OBJ
            ).unwrap_or(false);

            if !userid_exists {
                #[cfg(feature = "debug-log")]
                secure_log!("[SE050] Creating UserID...");

                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    USERID_OBJ, pin, max_attempts, admin_ref,
                )?;
            }

            // Binary data objects: skip if already exist.
            let objs: [(u32, &[u8]); 3] = [
                (ENTROPY_OBJ, entropy),
                (VK_OBJ, vk),
                (BOOTSTRAP_VK_OBJ, bootstrap_vk),
            ];

            for (obj_id, data) in &objs {
                let exists = apdu::check_exists(
                    &mut self.t1, &mut self.scp03, *obj_id
                ).unwrap_or(false);

                if !exists {
                    #[cfg(feature = "debug-log")]
                    secure_log!("[SE050] Writing obj 0x{:08x}...", obj_id);

                    apdu::write_binary_gated(
                        &mut self.t1, &mut self.scp03,
                        *obj_id, data, USERID_OBJ, admin_ref,
                    )?;
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
        self.init()?;
        unsafe {
            let exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            ).unwrap_or(false);
            if !exists {
                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    ADMIN_WIPE_OBJ, admin_pin, 0, None,
                )?;
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

        unsafe {
            // If the admin UserID doesn't exist, there's nothing structured
            // to wipe via this path — fall back to plain iterative delete.
            let admin_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            ).unwrap_or(false);

            if !admin_exists {
                #[cfg(feature = "debug-log")]
                secure_log!("[SE050] admin_factory_reset: no admin obj, falling back to iterative_delete_all");
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
                    let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
                    return Err(e);
                }

                // Delete every gated user object under admin auth.
                for obj in &[ENTROPY_OBJ, VK_OBJ, BOOTSTRAP_VK_OBJ, USERID_OBJ] {
                    let _ = apdu::delete_object_authed(
                        &mut self.t1, &mut self.scp03, &session_id, *obj,
                    );
                }

                // Self-delete the admin UserID inside its own session.
                let _ = apdu::delete_object_authed(
                    &mut self.t1, &mut self.scp03, &session_id, ADMIN_WIPE_OBJ,
                );

                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &session_id);
            }

            // Follow up with an unauthenticated sweep to catch any stragglers
            // (e.g. legacy objects from prior firmware versions that don't
            // have the admin-delete policy entry).
            let _ = apdu::iterative_delete_all(
                &mut self.t1, &mut self.scp03, None, None,
            );
        }

        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.vk_cache.zeroize();
        self.vk_cached = false;
        self.bootstrap_vk_cache.zeroize();
        self.bootstrap_vk_cached = false;
        self.remaining = sphincs_tz_shared::MAX_ATTEMPTS;

        #[cfg(feature = "debug-log")]
        secure_log!("[SE050] Admin factory reset complete");

        Ok(())
    }

    /// Round-trip self-test: write a canary UserID + gated data object with
    /// the same TAG_POLICY template used by real provisioning, then verify
    /// the admin-delete path actually clears them. Aborts provisioning if
    /// the canary survives — guardrail against future byte-order bugs in
    /// the policy TLV construction.
    ///
    /// Uses object IDs 0x7B06_00B0 / 0x7B06_00B1 (distinct from production
    /// range). Caller provides the admin PIN so the test exercises the
    /// SAME auth path the real wipe will use.
    pub fn policy_roundtrip_selftest(&mut self, admin_pin: &[u8; 16]) -> Result<(), Se050Error> {
        self.init()?;

        const CANARY_USERID: u32 = 0x7B06_00B0;
        const CANARY_DATA: u32 = 0x7B06_00B1;
        let canary_pin: [u8; 8] = *b"00000000";

        unsafe {
            // Cleanup any prior canary residue before testing.
            let _ = apdu::delete_object(&mut self.t1, &mut self.scp03, CANARY_DATA);
            let _ = apdu::delete_object(&mut self.t1, &mut self.scp03, CANARY_USERID);

            // Ensure admin UserID exists for the test (it should at this point).
            let admin_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ
            ).unwrap_or(false);
            if !admin_exists {
                return Err(Se050Error::NotProvisioned);
            }

            // Write canary UserID with admin-delete policy entry.
            apdu::write_userid(
                &mut self.t1, &mut self.scp03,
                CANARY_USERID, &canary_pin, 5, Some(ADMIN_WIPE_OBJ),
            )?;

            let canary_data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                CANARY_DATA, &canary_data, CANARY_USERID, Some(ADMIN_WIPE_OBJ),
            )?;

            // Exercise admin-delete path.
            let sid = apdu::create_session(
                &mut self.t1, &mut self.scp03, ADMIN_WIPE_OBJ,
            )?;
            if let Err(e) = apdu::verify_session(
                &mut self.t1, &mut self.scp03, &sid, admin_pin,
            ) {
                let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);
                return Err(e);
            }
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, CANARY_DATA,
            );
            let _ = apdu::delete_object_authed(
                &mut self.t1, &mut self.scp03, &sid, CANARY_USERID,
            );
            let _ = apdu::close_session(&mut self.t1, &mut self.scp03, &sid);

            // Verify both canary objects are gone.
            let data_gone = !apdu::check_exists(
                &mut self.t1, &mut self.scp03, CANARY_DATA,
            ).unwrap_or(true);
            let user_gone = !apdu::check_exists(
                &mut self.t1, &mut self.scp03, CANARY_USERID,
            ).unwrap_or(true);

            if !(data_gone && user_gone) {
                // Admin-delete failed — policy byte layout is wrong.
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[SE050] policy_roundtrip_selftest FAILED: data_gone={} user_gone={}",
                    data_gone, user_gone
                );
                return Err(Se050Error::Status(0x6986));
            }
        }

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
        #[cfg(feature = "stm32u585")]
        {
            let mut admin_pin = [0u8; 16];
            unsafe {
                if crate::hw::flash::is_admin_pin_blank() {
                    crate::rng::fill(&mut admin_pin)
                        .map_err(|_| SeError::InternalError)?;
                    crate::hw::flash::write_admin_pin(&admin_pin)
                        .map_err(|_| SeError::InternalError)?;
                } else {
                    crate::hw::flash::read_admin_pin(&mut admin_pin);
                }
            }

            self.provision_admin(&admin_pin)
                .map_err(|_| SeError::InternalError)?;
            self.policy_roundtrip_selftest(&admin_pin)
                .map_err(|_| SeError::InternalError)?;

            self.store_objects(
                pin,
                sphincs_tz_shared::MAX_ATTEMPTS as u16,
                entropy, vk, bootstrap_vk,
                Some(&admin_pin),
            ).map_err(|_| SeError::InternalError)?;

            use zeroize::Zeroize;
            admin_pin.zeroize();
        }

        #[cfg(not(feature = "stm32u585"))]
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
        // Load admin PIN from flash (populated at first-boot provision),
        // arm the wipe flag for crash-safety, wipe SE050 under admin auth,
        // then erase page 125 to clear both the PIN and the flag.
        unsafe {
            if crate::hw::flash::is_admin_pin_blank() {
                // Nothing provisioned via the admin flow — best-effort
                // unauthenticated sweep in case the chip still has legacy
                // objects around.
                let _ = self.iterative_wipe(None, None);
            } else {
                let mut admin_pin = [0u8; 16];
                crate::hw::flash::read_admin_pin(&mut admin_pin);

                let _ = crate::hw::flash::arm_wipe_flag();

                if self.admin_factory_reset(&admin_pin).is_err() {
                    // Admin session failed (rare — chip glitch, corrupted
                    // SCP03). Fall back to iterative delete so we still
                    // clear everything we can.
                    let _ = self.iterative_wipe(None, None);
                }

                use zeroize::Zeroize;
                admin_pin.zeroize();
            }

            let _ = crate::hw::flash::erase_admin_page();
        }

        self.zeroize_caches();
        Ok(())
    }
}
