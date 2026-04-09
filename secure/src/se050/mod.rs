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

use crate::secure_element::{SeError, SecureElement};
use t1oi2c::T1State;

/// HMAC-SHA256 computed in software (same as MockSecureElement).
/// The SE050 provides tamper-resistant storage for the state; the
/// HMAC computation itself runs on the MCU.
fn hmac_sha256(key: &[u8; 32], data: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

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
    initialized: bool,
}

impl Se050SecureElement {
    pub const fn new() -> Self {
        Self {
            t1: T1State::new(),
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

            // Delete existing object if present (overwrite semantics)
            let _ = apdu::delete_object(&mut self.t1, obj_id);

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

        // MACD state is stored as a Binary object on the SE050 (tamper-
        // resistant). HMAC-SHA256 is computed in software — identical to
        // MockSecureElement, but with hardware-protected state storage.
        unsafe {
            self.ensure_init()?;
            let obj_id = MACD_OBJ_BASE + slot as u32;

            let exists = apdu::check_object_exists(&mut self.t1, obj_id)
                .map_err(|_| SeError::InternalError)?;

            let output = if exists {
                // Read current 32-byte state. If the object is a stale
                // HMAC key from a previous firmware version, ReadObject
                // will fail — delete it and treat as fresh.
                let mut state = [0u8; 32];
                match apdu::read_object(&mut self.t1, obj_id, &mut state) {
                    Ok(n) if n >= 32 => hmac_sha256(data_in, &state),
                    _ => {
                        let _ = apdu::delete_object(&mut self.t1, obj_id);
                        hmac_sha256(data_in, data_in)
                    }
                }
            } else {
                hmac_sha256(data_in, data_in)
            };

            // "Destroy": overwrite state with data_in
            let _ = apdu::delete_object(&mut self.t1, obj_id);
            apdu::write_binary(&mut self.t1, obj_id, data_in)
                .map_err(|_| SeError::InternalError)?;

            Ok(output)
        }
    }
}
