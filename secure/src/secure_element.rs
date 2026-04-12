/// Secure Element abstraction — low-level trait + high-level WalletStore.
///
/// `SecureElement` is the low-level r-mem/MACD abstraction implemented by
/// backends with MAC-and-Destroy slot storage (Mock, Tropic01).
///
/// `WalletStore` is the high-level wallet-operations trait implemented by
/// ALL backends (Mock, SE050, Tropic01). Call sites use only `WalletStore`.

#[derive(Debug)]
pub enum SeError {
    SlotNotFound,
    SlotExpired,
    InvalidParameter,
    InternalError,
}

/// PIN-verification error returned by [`WalletStore::unlock`].
#[derive(Debug)]
pub enum UnlockError {
    PinIncorrect,
    PinLocked,
    InternalError,
}

/// Low-level secure element operations: r-mem slots and MAC-and-Destroy.
///
/// Implemented by backends with MACD-capable storage (Mock, Tropic01).
/// SE050 does NOT implement this — it uses hardware UserID PIN gating.
pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}

/// High-level wallet operations: provisioning, PIN unlock, entropy access.
///
/// Every SE backend implements this trait. Call sites use only `WalletStore`
/// methods — no `#[cfg]` feature gates needed.
pub trait WalletStore {
    /// Returns `true` if the SE has been provisioned with entropy.
    fn is_provisioned(&mut self) -> bool;

    /// Store pre-derived entropy, VK, and set up PIN protection.
    ///
    /// The caller handles key derivation (the "recovery contract") via
    /// [`crypto::provision_from_mnemonic`] and passes pre-derived data here.
    /// Each backend stores it according to its own security model:
    /// - Mock/Tropic01: encrypts entropy, sets up MACD PIN chain
    /// - SE050: stores raw entropy behind hardware UserID PIN gate
    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError>;

    /// Verify PIN and return the 32-byte master secret on success.
    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError>;

    /// Read the encrypted entropy blob (for signing / key derivation).
    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError>;

    /// Read the cached default verifying key (32 bytes).
    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError>;

    /// Read the bootstrap verifying key (32 bytes).
    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError>;

    /// Return the number of remaining PIN attempts.
    fn remaining_attempts(&mut self) -> u8;

    /// Zeroize any cached secrets (called on idle wipe / lock / panic).
    fn zeroize_caches(&mut self);
}

// ---------------------------------------------------------------------------
// Mock Secure Element for QEMU
// ---------------------------------------------------------------------------

const NUM_RMEM_SLOTS: usize = 8;
const MAX_RMEM_DATA: usize = 512;
const NUM_MACD_SLOTS: usize = 16;

pub struct MockSecureElement {
    rmem_occupied: [bool; NUM_RMEM_SLOTS],
    rmem_len: [usize; NUM_RMEM_SLOTS],
    rmem_data: [[u8; MAX_RMEM_DATA]; NUM_RMEM_SLOTS],
    macd_initialized: [bool; NUM_MACD_SLOTS],
    macd_state: [[u8; 32]; NUM_MACD_SLOTS],
}

impl MockSecureElement {
    pub const fn new() -> Self {
        Self {
            rmem_occupied: [false; NUM_RMEM_SLOTS],
            rmem_len: [0; NUM_RMEM_SLOTS],
            rmem_data: [[0u8; MAX_RMEM_DATA]; NUM_RMEM_SLOTS],
            macd_initialized: [false; NUM_MACD_SLOTS],
            macd_state: [[0u8; 32]; NUM_MACD_SLOTS],
        }
    }
}

/// Simple HMAC-SHA256 for MACD simulation.
/// Uses the hmac crate (no_std compatible).
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

impl SecureElement for MockSecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        if data.len() > MAX_RMEM_DATA {
            return Err(SeError::InvalidParameter);
        }
        self.rmem_data[s][..data.len()].copy_from_slice(data);
        self.rmem_len[s] = data.len();
        self.rmem_occupied[s] = true;
        Ok(())
    }

    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS || !self.rmem_occupied[s] {
            return Err(SeError::SlotNotFound);
        }
        let len = self.rmem_len[s];
        if buf.len() < len {
            return Err(SeError::InvalidParameter);
        }
        buf[..len].copy_from_slice(&self.rmem_data[s][..len]);
        Ok(len)
    }

    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError> {
        let s = slot as usize;
        if s >= NUM_RMEM_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        self.rmem_data[s] = [0u8; MAX_RMEM_DATA];
        self.rmem_len[s] = 0;
        self.rmem_occupied[s] = false;
        Ok(())
    }

    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError> {
        let s = slot as usize;
        if s >= NUM_MACD_SLOTS {
            return Err(SeError::SlotNotFound);
        }
        // Simplified mock: HMAC(data_in, slot_state_or_zeros).
        // Each call replaces slot_state with data_in (like TROPIC01's
        // "overwrite slot with input" behavior for re-init).
        // Output = HMAC(data_in, previous_state) — deterministic per (input, state) pair.
        let output = if self.macd_initialized[s] {
            hmac_sha256(data_in, &self.macd_state[s])
        } else {
            self.macd_initialized[s] = true;
            hmac_sha256(data_in, data_in)
        };
        // Store data_in as new state (not output) — this ensures that
        // calling with the same init_in restores the slot to a known state,
        // matching TROPIC01's re-initialization behavior.
        self.macd_state[s] = *data_in;
        Ok(output)
    }
}

impl WalletStore for MockSecureElement {
    fn is_provisioned(&mut self) -> bool {
        use crate::crypto::{RMEM_ENCRYPTED_ENTROPY, RMEM_PIN_STATE, RMEM_VERIFYING_KEY};
        let mut buf = [0u8; 128];
        self.r_mem_read(RMEM_ENCRYPTED_ENTROPY, &mut buf).is_ok()
            && self.r_mem_read(RMEM_PIN_STATE, &mut buf).is_ok()
            && self.r_mem_read(RMEM_VERIFYING_KEY, &mut buf).is_ok()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        crate::crypto::store_macd_encrypted(self, entropy, master_secret, vk, bootstrap_vk, pin);
        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        use sphincs_tz_shared::NscStatus;
        crate::pin::verify_pin(self, pin).map_err(|e| match e {
            NscStatus::PinIncorrect => UnlockError::PinIncorrect,
            NscStatus::PinLocked => UnlockError::PinLocked,
            _ => UnlockError::InternalError,
        })
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.r_mem_read(crate::crypto::RMEM_ENCRYPTED_ENTROPY, buf)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.r_mem_read(crate::crypto::RMEM_VERIFYING_KEY, buf)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.r_mem_read(crate::crypto::RMEM_BOOTSTRAP_VK, buf)
    }

    fn remaining_attempts(&mut self) -> u8 {
        use crate::crypto::{deserialize_pin_state, PIN_STATE_MAX_LEN, RMEM_PIN_STATE};
        use sphincs_tz_shared::MAX_ATTEMPTS;

        let mut buf = [0u8; PIN_STATE_MAX_LEN];
        match self.r_mem_read(RMEM_PIN_STATE, &mut buf) {
            Ok(len) => match deserialize_pin_state(&buf, len) {
                Ok(ps) => {
                    if ps.next_index >= MAX_ATTEMPTS {
                        0
                    } else {
                        MAX_ATTEMPTS - ps.next_index
                    }
                }
                Err(_) => MAX_ATTEMPTS,
            },
            Err(_) => MAX_ATTEMPTS,
        }
    }

    fn zeroize_caches(&mut self) {
        // Mock stores everything in r-mem, no caching layer.
    }
}
