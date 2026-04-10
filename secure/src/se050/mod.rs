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

/// Base object ID for MACD HMAC key slots.
/// Slot N → object ID 0x7B001000 + N.
const MACD_OBJ_BASE: u32 = 0x7B00_1000;

/// Maximum r_mem slots (matches MockSecureElement).
const NUM_RMEM_SLOTS: u16 = 8;

/// Maximum MACD slots (matches MockSecureElement).
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

            // Check if object exists — if so, delete first (can't resize).
            // If it doesn't exist, WriteBinary will create it with TAG_3.
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
