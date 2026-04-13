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
const USERID_OBJ: u32 = 0x7B06_0000;

/// Raw BIP-39 entropy (32 bytes), policy requires UserID auth.
const ENTROPY_OBJ: u32 = 0x7B06_0001;

/// Verifying key (32 bytes), policy requires UserID auth.
const VK_OBJ: u32 = 0x7B06_0002;

/// Bootstrap verifying key (32 bytes), policy requires UserID auth.
const BOOTSTRAP_VK_OBJ: u32 = 0x7B06_0003;

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
                &mut self.t1, &mut self.scp03, TEST_USERID_OBJ, pin, 9,
            )?;

            let payload_a = [0xA0u8; 32];
            let payload_b = [0xB1u8; 32];
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA_OBJ_A, &payload_a, TEST_USERID_OBJ,
            )?;
            apdu::write_binary_gated(
                &mut self.t1, &mut self.scp03,
                TEST_DATA_OBJ_B, &payload_b, TEST_USERID_OBJ,
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

    /// Store objects on the SE050 behind a UserID PIN gate.
    ///
    /// Creates a UserID object with the PIN (can't be deleted after creation),
    /// then stores three binary objects behind a policy that requires UserID
    /// authentication to read. Skips creation of any existing object.
    fn store_objects(
        &mut self,
        pin: &[u8],
        max_attempts: u16,
        entropy: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
    ) -> Result<(), Se050Error> {
        self.init()?;

        unsafe {
            // UserID: skip if already exists (can't be deleted)
            let userid_exists = apdu::check_exists(
                &mut self.t1, &mut self.scp03, USERID_OBJ
            ).unwrap_or(false);

            if !userid_exists {
                #[cfg(feature = "debug-log")]
                secure_log!("[SE050] Creating UserID...");

                apdu::write_userid(
                    &mut self.t1, &mut self.scp03,
                    USERID_OBJ, pin, max_attempts,
                )?;
            }

            // Binary objects: skip if already exist (reprovisioning requires
            // factory reset due to UserID policy)
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
                        *obj_id, data, USERID_OBJ,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Authenticate with PIN and read the stored entropy from hardware.
    ///
    /// On success returns the 32-byte entropy. On PIN failure the SE050
    /// hardware decrements its attempt counter internally.
    fn authenticate_and_read(&mut self, pin: &[u8]) -> Result<[u8; 32], Se050Error> {
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

            // Read entropy through the authenticated session
            let mut entropy = [0u8; 32];
            let n = apdu::read_authed(
                &mut self.t1, &mut self.scp03,
                &session_id, ENTROPY_OBJ, &mut entropy,
            );

            // Always close the session
            let _ = apdu::close_session(
                &mut self.t1, &mut self.scp03, &session_id,
            );

            match n {
                Ok(32) => Ok(entropy),
                Ok(_) => Err(Se050Error::Transport), // unexpected length
                Err(e) => Err(e),
            }
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
        self.store_objects(pin, sphincs_tz_shared::MAX_ATTEMPTS as u16, entropy, vk, bootstrap_vk)
            .map_err(|_| SeError::InternalError)?;

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

        let mut entropy = self.authenticate_and_read(pin).map_err(|e| match e {
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

        // Cache VK + bootstrap VK.
        let (sk, vk_bytes) = crate::crypto::derive_keypair_from_entropy(&entropy);
        drop(sk);
        self.vk_cache.copy_from_slice(&vk_bytes);
        self.vk_cached = true;

        let bvk = crate::crypto::derive_bootstrap_vk_from_entropy(&entropy);
        self.bootstrap_vk_cache.copy_from_slice(&bvk);
        self.bootstrap_vk_cached = true;

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
}
