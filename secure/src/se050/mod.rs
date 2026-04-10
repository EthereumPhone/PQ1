//! NXP SE050 secure element driver for PQSigner.
//!
//! Implements the `SecureElement` trait using the SE050's binary file
//! objects for retentive memory (r_mem) and HMAC key objects for the
//! MAC-and-Destroy (MACD) protocol used by PIN verification.
//!
//! Communication: I2C1 (PB8 SCL, PB9 SDA) → T1oI2C → SE05x APDUs.
//! Runs entirely in the secure TrustZone world.

pub mod i2c;
pub mod t1oi2c;
pub mod apdu;
pub mod scp03;

use crate::secure_element::{SeError, SecureElement};
use t1oi2c::T1State;

// ---------------------------------------------------------------------------
// Object ID allocation on the SE050
// ---------------------------------------------------------------------------

/// Base object ID for r_mem binary file slots.
/// Slot N → object ID 0x7B000000 + N.
const RMEM_OBJ_BASE: u32 = 0x7B00_0000;

/// Base object ID for MACD HMAC key slots (legacy, kept for compatibility).
/// Slot N → object ID 0x7B001000 + N.
const MACD_OBJ_BASE: u32 = 0x7B00_1000;

/// UserID authentication object — hardware-enforced PIN.
/// The SE050 verifies the PIN internally; max 9 attempts before lockout.
const USERID_OBJ_ID: u32 = 0x7B00_2000;

/// SE050 Platform SCP03 applet resource ID (0x7FFF0207).
/// Used for mandate_scp03 operations if needed.
#[allow(dead_code)]
const PLATFORM_SCP_OBJ_ID: u32 = 0x7FFF_0207;

/// Maximum r_mem slots (matches MockSecureElement).
const NUM_RMEM_SLOTS: u16 = 8;

/// Maximum MACD slots (legacy, kept for trait compatibility).
const NUM_MACD_SLOTS: u16 = 16;

// ---------------------------------------------------------------------------
// Se050SecureElement
// ---------------------------------------------------------------------------

/// SE050 secure element implementation.
///
/// Communicates with the NXP SE050 over I2C1 using T1oI2C framing.
/// The applet is selected on the first operation (lazy init).
pub struct Se050SecureElement {
    t1: T1State,
    scp03: scp03::Scp03Session,
    initialized: bool,
}

impl Se050SecureElement {
    pub const fn new() -> Self {
        Self {
            t1: T1State::new(),
            scp03: scp03::Scp03Session::new(),
            initialized: false,
        }
    }

    /// Public wrapper for `ensure_init` — used by `is_provisioned` to
    /// establish the SCP03 session before checking object existence.
    pub unsafe fn ensure_init_pub(&mut self) -> Result<(), SeError> {
        self.ensure_init()
    }

    /// Borrow the T1 state for direct APDU calls from outside this module.
    pub unsafe fn t1_mut(&mut self) -> &mut T1State {
        &mut self.t1
    }

    /// Ensure the SE050 applet is selected. Called lazily on first use.
    ///
    /// Performs the full startup sequence:
    /// 1. T1oI2C interface reset (S-frame) — required after power-on
    /// 2. GP SELECT to activate the SE050 applet
    unsafe fn ensure_init(&mut self) -> Result<(), SeError> {
        if !self.initialized {
            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[S][SE050] Starting init...");

            // Delay for SE050 power-on (needs ~3 ms after VCC stable)
            for _ in 0..500_000 {
                cortex_m::asm::nop();
            }

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[S][SE050] Sending interface reset...");

            match self.t1.interface_reset() {
                Ok(()) => {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] Interface reset OK");
                }
                Err(ref e) => {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] Interface reset FAILED: {:?}", e);
                    return Err(SeError::InternalError);
                }
            }

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[S][SE050] Selecting applet...");

            match apdu::select_applet(&mut self.t1) {
                Ok(()) => {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] Applet selected OK");
                }
                Err(ref e) => {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] Applet select FAILED: {:?}", e);
                    return Err(SeError::InternalError);
                }
            }

            // Establish SCP03 authenticated session
            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[S][SE050] Establishing SCP03 session...");

            match scp03::establish(&mut self.scp03, &mut self.t1) {
                Ok(()) => {
                    // Set the global SCP03 session pointer so send_apdu wraps APDUs
                    apdu::SCP03_SESSION = Some(&mut self.scp03 as *mut _);
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] SCP03 session established");
                }
                Err(ref e) => {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!("[S][SE050] SCP03 FAILED: {:?}", e);
                    return Err(SeError::InternalError);
                }
            }

            self.initialized = true;
        }
        Ok(())
    }
}

impl SecureElement for Se050SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError> {
        if slot >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        if data.len() > 512 {
            return Err(SeError::InvalidParameter);
        }

        unsafe {
            self.ensure_init()?;
            let obj_id = RMEM_OBJ_BASE + slot as u32;

            // Delete existing object first (can't resize binary files).
            let exists = apdu::check_object_exists(&mut self.t1, obj_id)
                .unwrap_or(false);
            if exists {
                let _ = apdu::delete_object(&mut self.t1, obj_id);
            }

            apdu::write_binary(&mut self.t1, obj_id, data)
                .map_err(|_| SeError::InternalError)
        }
    }

    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError> {
        if slot >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }

        unsafe {
            self.ensure_init()?;
            let obj_id = RMEM_OBJ_BASE + slot as u32;

            // Check existence first
            let exists = apdu::check_object_exists(&mut self.t1, obj_id)
                .map_err(|_| SeError::InternalError)?;
            if !exists {
                return Err(SeError::SlotNotFound);
            }

            apdu::read_object(&mut self.t1, obj_id, buf)
                .map_err(|_| SeError::InternalError)
        }
    }

    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError> {
        if slot >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }

        unsafe {
            self.ensure_init()?;
            let obj_id = RMEM_OBJ_BASE + slot as u32;

            apdu::delete_object(&mut self.t1, obj_id)
                .map_err(|_| SeError::InternalError)
        }
    }

    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError> {
        if slot >= NUM_MACD_SLOTS {
            return Err(SeError::SlotNotFound);
        }

        // MACD uses the SE050's HMAC-SHA256 engine. The 32-byte slot
        // state is stored as an HMAC key object — the key material
        // NEVER leaves the SE050.
        //
        // Flow:
        // 1. If HMAC key exists → MACGenerate(key, data_in) → output
        //    If not exists → create key with data_in, MAC(key, data_in)
        // 2. "Destroy": delete key, re-create with data_in as new key
        unsafe {
            self.ensure_init()?;
            let obj_id = MACD_OBJ_BASE + slot as u32;

            let exists = apdu::check_object_exists(&mut self.t1, obj_id)
                .map_err(|_| SeError::InternalError)?;

            if !exists {
                // First call: create HMAC key with data_in
                apdu::write_hmac_key(&mut self.t1, obj_id, data_in)
                    .map_err(|_| SeError::InternalError)?;
            } else {
                // Stale object from previous firmware may not be an HMAC key.
                // Try MAC — if it fails, delete and recreate.
                let mut probe = [0u8; 32];
                if apdu::mac_oneshot(&mut self.t1, obj_id, data_in, &mut probe).is_err() {
                    let _ = apdu::delete_object(&mut self.t1, obj_id);
                    apdu::write_hmac_key(&mut self.t1, obj_id, data_in)
                        .map_err(|_| SeError::InternalError)?;
                }
            }

            // Compute HMAC(key, data_in) on the SE050
            let mut output = [0u8; 32];
            apdu::mac_oneshot(&mut self.t1, obj_id, data_in, &mut output)
                .map_err(|_| SeError::InternalError)?;

            // "Destroy": replace key with data_in
            let _ = apdu::delete_object(&mut self.t1, obj_id);
            apdu::write_hmac_key(&mut self.t1, obj_id, data_in)
                .map_err(|_| SeError::InternalError)?;

            Ok(output)
        }
    }
}

// ---------------------------------------------------------------------------
// SE050-native UserID PIN authentication
// ---------------------------------------------------------------------------
//
// These methods bypass the MACD chain entirely. The SE050 hardware
// enforces PIN verification internally via a UserID object with a
// configurable max-attempts counter. Binary objects (entropy, VKs) are
// stored with a policy that requires an authenticated session against
// the UserID object before they can be read.
//
// Provisioning:
//   1. SCP03 session (already established in ensure_init)
//   2. Delete stale UserID + binary objects (idempotent)
//   3. WriteUserID(PIN, max_attempts=9)
//   4. WriteBinaryWithPolicy(entropy_blob, auth=UserID)
//   5. WriteBinaryWithPolicy(VK, auth=UserID)
//   6. WriteBinaryWithPolicy(bootstrap_VK, auth=UserID)
//
// Unlock:
//   1. SCP03 session
//   2. CreateSession(UserID) → session_id
//   3. VerifySessionUserID(session_id, PIN)
//   4. ReadObjectAuthed(session_id, entropy_blob_obj) → encrypted entropy
//   5. Decrypt entropy on MCU, derive signing key
//   6. CloseSession(session_id)

impl Se050SecureElement {
    /// Provision the UserID authentication object with the user's PIN.
    ///
    /// Only creates the UserID if it doesn't already exist. On SE050E,
    /// auth objects cannot be trivially deleted — once created, the UserID
    /// persists until a factory reset. For reprovisioning with a different
    /// PIN, a factory reset is required.
    pub fn provision_userid(&mut self, pin: &[u8], max_attempts: u16) -> Result<(), SeError> {
        unsafe {
            self.ensure_init()?;

            let exists = apdu::check_object_exists(&mut self.t1, USERID_OBJ_ID)
                .unwrap_or(false);

            if exists {
                #[cfg(feature = "debug-log")]
                cortex_m_semihosting::hprintln!(
                    "[SE050] UserID 0x{:08x} already exists, skipping creation",
                    USERID_OBJ_ID
                );
                return Ok(());
            }

            apdu::write_user_id(&mut self.t1, USERID_OBJ_ID, pin, max_attempts)
                .map_err(|_e| {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!(
                        "[SE050] WriteUserID failed: {:?}", _e
                    );
                    SeError::InternalError
                })
        }
    }

    /// Write a binary object gated by the UserID PIN policy.
    ///
    /// The object can only be read after authenticating via
    /// `authenticate_userid`. Deletes any existing object first.
    pub fn write_binary_userid_gated(
        &mut self,
        object_id: u32,
        data: &[u8],
    ) -> Result<(), SeError> {
        unsafe {
            self.ensure_init()?;

            let exists = apdu::check_object_exists(&mut self.t1, object_id)
                .unwrap_or(false);

            if exists {
                // Object already exists with UserID policy. Updating requires
                // a UserID-authenticated session, and deleting auth-gated objects
                // also requires auth. For initial provisioning this is fine — the
                // objects are created once and persist. For reprovisioning (PIN
                // change), a factory reset would be needed.
                #[cfg(feature = "debug-log")]
                cortex_m_semihosting::hprintln!(
                    "[SE050] obj 0x{:08x} already exists, skipping",
                    object_id
                );
            } else {
                // New object: create with UserID policy
                apdu::write_binary_with_policy(
                    &mut self.t1, object_id, data, USERID_OBJ_ID
                ).map_err(|_e| {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!(
                        "[SE050] WriteBinary(policy) obj=0x{:08x} failed: {:?}",
                        object_id, _e
                    );
                    SeError::InternalError
                })?;
            }

            Ok(())
        }
    }

    /// Authenticate against the UserID by verifying the PIN.
    ///
    /// Returns an 8-byte session ID that must be passed to `read_authed`
    /// to read UserID-gated objects. The SE050 hardware enforces the
    /// attempt counter — after `max_attempts` failures the UserID locks.
    pub fn authenticate_userid(&mut self, pin: &[u8]) -> Result<[u8; 8], SeError> {
        unsafe {
            self.ensure_init()?;

            // Step 1: Create a session against the UserID object
            let session_id = apdu::create_session(&mut self.t1, USERID_OBJ_ID)
                .map_err(|_e| {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!(
                        "[SE050] CreateSession failed: {:?}", _e
                    );
                    SeError::InternalError
                })?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!(
                "[SE050] Session: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                session_id[0], session_id[1], session_id[2], session_id[3],
                session_id[4], session_id[5], session_id[6], session_id[7]
            );

            // Step 2: Verify the PIN against the UserID
            apdu::verify_session_user_id(&mut self.t1, &session_id, pin)
                .map_err(|_e| {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!(
                        "[SE050] VerifySessionUserID failed: {:?}", _e
                    );
                    let _ = apdu::close_session(&mut self.t1, &session_id);
                    SeError::InternalError
                })?;

            #[cfg(feature = "debug-log")]
            cortex_m_semihosting::hprintln!("[SE050] UserID PIN verified OK");

            Ok(session_id)
        }
    }

    /// Read a UserID-gated binary object using an authenticated session.
    pub fn read_authed(
        &mut self,
        session_id: &[u8; 8],
        object_id: u32,
        buf: &mut [u8],
    ) -> Result<usize, SeError> {
        unsafe {
            self.ensure_init()?;
            apdu::read_object_authed(&mut self.t1, session_id, object_id, buf)
                .map_err(|_e| {
                    #[cfg(feature = "debug-log")]
                    cortex_m_semihosting::hprintln!(
                        "[SE050] ReadObject(authed) obj=0x{:08x} failed: {:?}",
                        object_id, _e
                    );
                    SeError::InternalError
                })
        }
    }

    /// Close a UserID session.
    pub fn close_userid_session(&mut self, session_id: &[u8; 8]) {
        unsafe {
            let _ = apdu::close_session(&mut self.t1, session_id);
        }
    }
}
