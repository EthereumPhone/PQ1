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

    /// Re-sync the in-RAM remaining-attempts cache against the MCU
    /// page-124 counter. Called once at boot to correct for the
    /// software mirror resetting to `MAX_ATTEMPTS` on every power-on
    /// while the chips themselves keep durable state.
    ///
    /// `mcu_used` is the count read from flash; the impl must keep
    /// the cache at `min(self.remaining, MAX_ATTEMPTS - mcu_used)`
    /// — a stale-high cache can only be ratcheted DOWN, never up,
    /// so this is safe to call even when the cache is already
    /// authoritative (fresh provision, mid-session state).
    ///
    /// Default no-op: correct for Mock (reads r-mem directly) and
    /// Tropic01 (queries the chip on every `remaining_attempts`).
    fn sync_remaining_with_mcu(&mut self, _mcu_used: u8) {}

    /// Zeroize any cached secrets (called on idle wipe / lock / panic).
    fn zeroize_caches(&mut self);

    /// PIN-lockout factory reset: wipe every persistent secret so the
    /// device returns to a fresh unprovisioned state. Default no-op for
    /// backends that don't persist anything (the mock); real backends
    /// override. See `DualSecureElement::factory_reset_admin` for the
    /// STM32 + dual-SE implementation.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        self.zeroize_caches();
        Ok(())
    }
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
    /// Phase 10 PR D realism knob — when set, the next
    /// `mac_and_destroy` call returns `SeError::InternalError` to
    /// simulate a clock/voltage glitch mid-MACD. The flag clears
    /// itself after one shot so a single `simulate_glitch(true)`
    /// affects exactly one operation.
    glitch_armed: bool,
}

impl MockSecureElement {
    pub const fn new() -> Self {
        Self {
            rmem_occupied: [false; NUM_RMEM_SLOTS],
            rmem_len: [0; NUM_RMEM_SLOTS],
            rmem_data: [[0u8; MAX_RMEM_DATA]; NUM_RMEM_SLOTS],
            macd_initialized: [false; NUM_MACD_SLOTS],
            macd_state: [[0u8; 32]; NUM_MACD_SLOTS],
            glitch_armed: false,
        }
    }

    /// Arm a one-shot glitch — the next `mac_and_destroy` call returns
    /// `SeError::InternalError`. Used by host tests of the
    /// `nsc::gated_unlock` FI-hardening path: the MCU's page-124
    /// pre-commit bumps the attempt counter BEFORE the SE round-trip,
    /// so a glitch that drops the SE call still charges the attempt.
    /// Verifying that contract on host requires deterministic glitch
    /// injection, which is what this knob provides.
    pub fn simulate_glitch(&mut self) {
        self.glitch_armed = true;
    }

    /// Returns `true` iff every MACD slot has been programmed at least
    /// once. The existing PIN-verify path resets all slots on a
    /// successful unlock, so this is `true` after any `unlock()` in
    /// the post-provision lifecycle.
    pub fn macd_all_initialized(&self) -> bool {
        self.macd_initialized.iter().all(|&b| b)
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
        // Phase 10 PR D — one-shot glitch injection for FI tests.
        if self.glitch_armed {
            self.glitch_armed = false;
            return Err(SeError::InternalError);
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

// ---------------------------------------------------------------------------
// Host tests — exercise the 10-wrong-PIN brick path on the mock SE so
// the production-only behaviour previously covered solely by
// `make pin-gate-wipe-e2e` (real hardware) gets a host regression
// guard. Phase 10 PR D of the modularity refactor.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::provision_from_mnemonic;
    use sphincs_tz_bip39::Mnemonic;
    use sphincs_tz_shared::{MAX_ATTEMPTS, NscStatus};

    fn make_provisioned() -> MockSecureElement {
        let mut se = MockSecureElement::new();
        let mnemonic = Mnemonic::from_entropy(&[0u8; 32]);
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        provision_from_mnemonic(&mut se, &mnemonic, &pin);
        se
    }

    /// Provisioning leaves the mock in a usable state — the entropy
    /// blob and VK slots are populated.
    ///
    /// We probe slots directly instead of going through
    /// `is_provisioned()` because that helper uses a 128-byte buffer
    /// that can't fit the 481-byte PIN_STATE blob — a pre-existing
    /// quirk on the mock-SE path. The PIN-correct unlock test below
    /// is the real end-to-end check that provisioning landed
    /// everywhere it was supposed to.
    #[test]
    fn provision_populates_slots() {
        let mut se = make_provisioned();
        let mut entropy_buf = [0u8; 64];
        let mut vk_buf = [0u8; 32];
        let mut bvk_buf = [0u8; 32];
        assert!(
            se.r_mem_read(0, &mut entropy_buf).is_ok(),
            "encrypted-entropy slot must be populated"
        );
        assert!(
            se.r_mem_read(2, &mut vk_buf).is_ok(),
            "VK slot must be populated"
        );
        assert!(
            se.r_mem_read(3, &mut bvk_buf).is_ok(),
            "bootstrap-VK slot must be populated"
        );
    }

    /// The correct PIN unlocks and the attempt counter resets to
    /// `MAX_ATTEMPTS` afterwards.
    #[test]
    fn correct_pin_unlocks_and_resets_counter() {
        let mut se = make_provisioned();
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        let secret = se.unlock(&pin).expect("correct PIN should unlock");
        assert_ne!(secret, [0u8; 32], "master_secret must be non-zero");
        assert_eq!(
            se.remaining_attempts(),
            MAX_ATTEMPTS,
            "successful unlock must reset attempt counter"
        );
    }

    /// Wrong PINs decrement the remaining-attempts counter monotonically.
    #[test]
    fn wrong_pin_decrements_remaining_attempts() {
        let mut se = make_provisioned();
        assert_eq!(se.remaining_attempts(), MAX_ATTEMPTS);

        let bad_pin = [0u8, 0, 0, 0, 0, 0, 0, 0];
        for tried in 0..3 {
            assert!(
                matches!(se.unlock(&bad_pin), Err(UnlockError::PinIncorrect)),
                "iteration {} should report PinIncorrect",
                tried,
            );
            let remaining = se.remaining_attempts();
            assert_eq!(
                remaining,
                MAX_ATTEMPTS - (tried + 1),
                "remaining must drop by 1 per wrong attempt",
            );
        }
    }

    /// 10 wrong PINs in a row must brick the entropy blob and surface
    /// `PinLocked` on subsequent attempts. This is the post-mortem
    /// guarantee of `make pin-gate-wipe-e2e` on real hardware; mocking
    /// it on host means the regression catches drift earlier.
    #[test]
    fn ten_wrong_pins_brick_the_mock() {
        let mut se = make_provisioned();
        let bad_pin = [0u8, 0, 0, 0, 0, 0, 0, 0];

        // First 9 attempts must report PinIncorrect (still some
        // budget left).
        for i in 0..9 {
            let r = se.unlock(&bad_pin);
            assert!(
                matches!(r, Err(UnlockError::PinIncorrect)),
                "attempt {} should report PinIncorrect, got {:?}",
                i + 1,
                r
            );
        }
        assert_eq!(se.remaining_attempts(), 1, "1 attempt must remain");

        // Attempt 10 trips the brick path inside `verify_pin` which
        // erases the encrypted entropy and PIN state. The PIN is still
        // wrong, so `unlock` reports PinLocked (the brick was issued
        // *because* the attempt failed and the counter rolled).
        let r10 = se.unlock(&bad_pin);
        assert!(
            matches!(r10, Err(UnlockError::PinLocked)),
            "10th wrong attempt should report PinLocked, got {:?}",
            r10
        );
        // After bricking, the encrypted-entropy slot has been erased.
        // (We don't check `is_provisioned()` here because of the
        // 128-byte-buffer quirk noted on `provision_populates_slots`
        // above — instead probe the slot directly.)
        let mut entropy_buf = [0u8; 64];
        assert!(
            matches!(se.r_mem_read(0, &mut entropy_buf), Err(SeError::SlotNotFound)),
            "bricked mock must have its entropy slot erased"
        );

        // And subsequent unlocks (with even the correct PIN!) fail
        // because the encrypted entropy blob is gone.
        let correct_pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        let r11 = se.unlock(&correct_pin);
        assert!(
            matches!(r11, Err(UnlockError::InternalError | UnlockError::PinLocked)),
            "post-brick unlock with correct PIN must still fail, got {:?}",
            r11
        );
    }

    /// `simulate_glitch` arms a one-shot fault on the next
    /// `mac_and_destroy` call. The pin-verify path catches the
    /// `SeError::InternalError` and surfaces `NscStatus::InternalError`.
    /// The MCU page-124 pre-commit pattern in `nsc::gated_unlock`
    /// uses this to charge the attempt regardless.
    #[test]
    fn simulate_glitch_one_shot_fires_then_clears() {
        let mut se = make_provisioned();

        // First call: glitched.
        se.simulate_glitch();
        let dummy = [0u8; 32];
        let glitch_result = se.mac_and_destroy(0, &dummy);
        assert!(
            matches!(glitch_result, Err(SeError::InternalError)),
            "armed glitch should error on first call"
        );

        // Second call: clean (the glitch is one-shot).
        let clean_result = se.mac_and_destroy(0, &dummy);
        assert!(
            clean_result.is_ok(),
            "second call must succeed — glitch flag must auto-clear"
        );
    }

    /// `pin::verify_pin` propagates a glitch as `NscStatus::InternalError`.
    #[test]
    fn glitched_unlock_returns_internal_error() {
        let mut se = make_provisioned();
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];

        se.simulate_glitch();
        let r = crate::pin::verify_pin(&mut se, &pin);
        assert_eq!(
            r,
            Err(NscStatus::InternalError),
            "glitched MACD must surface as InternalError"
        );
    }
}
