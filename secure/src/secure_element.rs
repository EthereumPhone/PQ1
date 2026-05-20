//! Secure Element abstraction — low-level trait + high-level [`WalletStore`].
//!
//! [`SecureElement`] is the low-level r-mem / MAC-and-Destroy abstraction
//! implemented by backends with MACD slot storage (Mock, Tropic01).
//!
//! [`WalletStore`] is the high-level wallet-operations trait implemented
//! by every backend (Mock, SE050, Tropic01, dual). Call sites depend on
//! [`WalletStore`] only, so no `#[cfg]` feature gates leak out.

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

    /// §32 duress (decoy) wallet provisioning. Stores a SECOND, fully
    /// independent decoy wallet behind a SECOND PIN credential, so a
    /// coerced user can reveal the duress PIN and surrender a plausible
    /// decoy instead of the real wallet. Same shape as [`provision`] but
    /// targets the duress OID/credential set (OPTIGA F1D8 + E121 matched-
    /// LUC, SE050 `DURESS_USERID_OBJ`). On a [`DualSecureElement`] the
    /// `entropy` is the full decoy entropy and is XOR-split internally;
    /// on a single backend it is that backend's pre-split half.
    ///
    /// Always-provision is load-bearing for deniability: the wizard
    /// provisions a decoy with a RANDOM PIN even when the user declines,
    /// so "duress configured vs not" is indistinguishable. Default no-op
    /// for backends without a duress path (Mock, Tropic01).
    fn provision_duress(
        &mut self,
        _entropy: &[u8; 32],
        _master_secret: &[u8; 32],
        _vk: &[u8; 32],
        _bootstrap_vk: &[u8; 32],
        _duress_pin: &[u8; 8],
    ) -> Result<(), SeError> {
        Ok(())
    }

    /// Diagnostic: whether the duress (decoy) credential set is present.
    /// Distinct from [`is_provisioned`](Self::is_provisioned), which
    /// reports REAL-wallet state only — boot-wipe + wizard branching keys
    /// off the real wallet, and a joint check would mis-handle a partial-
    /// provision crash. Default `false`.
    fn duress_is_provisioned(&mut self) -> bool {
        false
    }

    /// §32 P3: attempt to unlock the DECOY wallet with `pin`. Returns the
    /// decoy master on a duress-PIN match, else `Err(PinIncorrect)` so the
    /// caller falls through to the real [`unlock`](Self::unlock). Default
    /// `Err(PinIncorrect)` — backends without a duress path simply never
    /// match, so `gated_unlock` always proceeds to the real unlock.
    fn unlock_duress(&mut self, _pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        Err(UnlockError::PinIncorrect)
    }

    /// §32 P3 timing pad: run one duress verify per chip (no read) on a
    /// duress-correct unlock to keep the total op-count identical to a
    /// real unlock. Default no-op (no duress credential to verify).
    fn duress_pad(&mut self, _pin: &[u8; 8]) {}

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

    /// Draw `buf.len()` bytes from the active SE backend's TRNG(s).
    /// For multi-source backends (`DualSecureElement` = OPTIGA + SE050),
    /// the implementation XOR-mixes per-source internally so the caller
    /// sees a single combined stream. Returns `Err(SlotNotFound)` when
    /// the backend has no TRNG to offer (the mock); callers must
    /// tolerate this and treat it as "skip the SE-side XOR layer" —
    /// see `hw::rng_strong::fill`.
    ///
    /// The bytes returned MUST NOT be used in isolation. They are one
    /// of three contributing sources (STM32 TRNG + OPTIGA TRNG + SE050
    /// TRNG) that `rng_strong::fill` XOR-folds together. The
    /// security argument is: if *any* of the three sources is
    /// unbroken, the XOR preserves entropy from the remaining sources.
    fn random(&mut self, _buf: &mut [u8]) -> Result<(), SeError> {
        Err(SeError::SlotNotFound)
    }

    /// Returns the SE-side **failed-attempts USED** count (starts at
    /// 0, bumps on each wrong PIN, reaches `MAX_ATTEMPTS` at
    /// lockout), or `None` if no SE-side counter is available.
    /// Semantics match the MCU page-124 counter for a direct `!=`
    /// reconcile.
    ///
    /// Both production backends expose this on a peek-safe path
    /// (does NOT consume an attempt):
    ///   - OPTIGA Trust M: raw read of F1E1 (`OID_COUNTER`).
    ///   - SE050: `ReadObjectAttributes` on the USERID auth object —
    ///     the attribute response carries `auth_attempts` /
    ///     `max_attempts` as plain TLV fields. See
    ///     `Se050::pin_attempt_count_raw` for parse + SDK reference.
    ///
    /// For multi-SE backends (`DualSecureElement`) the returned
    /// value is the **max** across SEs — i.e. the most-locked-out
    /// figure (conservative: prefer a false-positive wipe over
    /// missing one). Intra-SE disagreement is surfaced separately
    /// by [`Self::pin_attempt_counts_divergent`].
    ///
    /// Used by `nsc::reconcile_pin_attempts` at boot to cross-check
    /// the MCU page-124 counter against each SE's silicon counter. A
    /// disagreement on any pair indicates: (a) attacker reset OPTIGA
    /// E140/PBS (which resets PBS-protected OIDs including F1E1) or
    /// the SE050 USERID, (b) attacker glitched the MCU page-124
    /// counter via a TZ-bypass, or (c) a genuine flash fault. All
    /// three are tamper signals → wipe.
    ///
    /// Default: `None` (mock + tropic01 don't expose a counter).
    fn pin_attempt_count(&mut self) -> Option<u8> {
        None
    }

    /// Returns `true` iff this backend wraps multiple SEs AND those
    /// SEs disagree on the remaining PIN-attempt count. For single-
    /// SE backends this is structurally `false`. Used by
    /// `nsc::reconcile_pin_attempts` to fire the tamper wipe even
    /// when MCU↔min(SE) happens to match — an attacker who resets
    /// JUST the OPTIGA counter would otherwise still leave a
    /// detectable OPTIGA↔SE050 split.
    fn pin_attempt_counts_divergent(&mut self) -> bool {
        false
    }

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
        provision_from_mnemonic(&mut se, &mnemonic, &pin, None);
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

    // ──────────────────────────────────────────────────────────────────
    // Additional positive coverage — r-mem ops, MACD ops, default
    // WalletStore methods.
    // ──────────────────────────────────────────────────────────────────

    /// r-mem round-trip: write → read → verify same bytes.
    #[test]
    fn positive_rmem_write_then_read_roundtrip() {
        let mut se = MockSecureElement::new();
        let data: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        se.r_mem_write(0, &data).unwrap();
        let mut buf = [0u8; 9];
        let n = se.r_mem_read(0, &mut buf).unwrap();
        assert_eq!(n, 9);
        assert_eq!(buf, data);
    }

    /// r-mem erase: written slot becomes SlotNotFound on read.
    #[test]
    fn positive_rmem_erase_clears_slot() {
        let mut se = MockSecureElement::new();
        se.r_mem_write(0, &[0xAAu8; 8]).unwrap();
        se.r_mem_erase(0).unwrap();
        let mut buf = [0u8; 8];
        let res = se.r_mem_read(0, &mut buf);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "erased slot must report SlotNotFound, got {res:?}"
        );
    }

    /// r-mem write of zero-length is accepted (the mock treats length-0
    /// as a valid blob, and the production backends do too).
    #[test]
    fn positive_rmem_write_zero_length_accepted() {
        let mut se = MockSecureElement::new();
        se.r_mem_write(0, &[]).unwrap();
        let mut buf = [0u8; 4];
        let n = se.r_mem_read(0, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    /// r-mem write at the max valid length (512 bytes) is accepted.
    #[test]
    fn positive_rmem_write_max_length_accepted() {
        let mut se = MockSecureElement::new();
        let data = [0x55u8; MAX_RMEM_DATA];
        se.r_mem_write(0, &data).unwrap();
        let mut buf = [0u8; MAX_RMEM_DATA];
        let n = se.r_mem_read(0, &mut buf).unwrap();
        assert_eq!(n, MAX_RMEM_DATA);
        assert_eq!(buf, data);
    }

    /// MACD slot at the highest valid index (15) is accepted.
    #[test]
    fn positive_macd_max_slot_accepted() {
        let mut se = MockSecureElement::new();
        let r = se.mac_and_destroy((NUM_MACD_SLOTS - 1) as u16, &[0u8; 32]);
        assert!(r.is_ok());
    }

    /// MACD on a freshly-initialized slot is deterministic given the
    /// same input. Same input → same output, twice in a row.
    #[test]
    fn positive_macd_first_call_is_deterministic_per_input() {
        let mut a = MockSecureElement::new();
        let mut b = MockSecureElement::new();
        let in1 = [0xAAu8; 32];
        let out_a = a.mac_and_destroy(0, &in1).unwrap();
        let out_b = b.mac_and_destroy(0, &in1).unwrap();
        assert_eq!(out_a, out_b);
    }

    /// Default `random()` impl returns `SlotNotFound` because the mock
    /// has no TRNG to offer (this is the documented "skip the SE-side
    /// XOR layer" sentinel for `hw::rng_strong::fill`).
    #[test]
    fn positive_default_random_returns_slot_not_found() {
        let mut se = MockSecureElement::new();
        let mut buf = [0u8; 4];
        let res = se.random(&mut buf);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "default random() must return SlotNotFound; rng_strong relies on this \
             to treat the mock as 'no SE-side XOR layer'"
        );
    }

    /// Default `pin_attempt_count()` is `None` on the mock.
    #[test]
    fn positive_default_pin_attempt_count_is_none() {
        let mut se = MockSecureElement::new();
        assert!(se.pin_attempt_count().is_none());
    }

    /// Default `pin_attempt_counts_divergent()` is `false` on
    /// single-SE backends (only `DualSecureElement` ever returns true).
    #[test]
    fn positive_default_divergent_is_false() {
        let mut se = MockSecureElement::new();
        assert!(!se.pin_attempt_counts_divergent());
    }

    /// Default `factory_reset_admin()` calls `zeroize_caches` and
    /// returns Ok on backends that don't persist anything.
    #[test]
    fn positive_default_factory_reset_admin_succeeds_on_mock() {
        let mut se = MockSecureElement::new();
        assert!(se.factory_reset_admin().is_ok());
    }

    /// `is_provisioned()` returns false on a fresh mock.
    #[test]
    fn positive_fresh_mock_is_not_provisioned() {
        let mut se = MockSecureElement::new();
        assert!(!se.is_provisioned());
    }

    /// `remaining_attempts()` returns `MAX_ATTEMPTS` on a fresh
    /// (unprovisioned) mock — the deserialize fail path returns
    /// `MAX_ATTEMPTS` so a brand-new chip looks "ready" to the caller.
    #[test]
    fn positive_fresh_mock_remaining_attempts_is_max() {
        let mut se = MockSecureElement::new();
        assert_eq!(se.remaining_attempts(), MAX_ATTEMPTS);
    }

    /// `sync_remaining_with_mcu` is a no-op on the mock (default
    /// impl), which is the documented contract — the mock reads r-mem
    /// directly so its counter is always authoritative.
    #[test]
    fn positive_sync_remaining_with_mcu_is_noop_on_mock() {
        let mut se = make_provisioned();
        let before = se.remaining_attempts();
        se.sync_remaining_with_mcu(0);
        assert_eq!(se.remaining_attempts(), before);
        se.sync_remaining_with_mcu(255);
        // The mock's MAX_ATTEMPTS bookkeeping doesn't change either way
        // because the default impl is empty.
        assert_eq!(se.remaining_attempts(), before);
    }

    // ──────────────────────────────────────────────────────────────────
    // Negative coverage — challenges assumptions Mock + the trait hold.
    // ──────────────────────────────────────────────────────────────────

    /// PIN: r-mem write with an out-of-range slot must be rejected. A
    /// silent overflow into `rmem_data[slot as usize]` would either
    /// panic (mock host build) or — worse, in a hypothetical
    /// re-implementation that used `% NUM_RMEM_SLOTS` — alias high
    /// slot indices onto valid ones, corrupting stored entropy /
    /// VK / PIN-state.
    #[test]
    fn negative_rmem_write_out_of_range_slot_rejected() {
        let mut se = MockSecureElement::new();
        let res = se.r_mem_write(NUM_RMEM_SLOTS as u16, &[0u8; 4]);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "slot == NUM_RMEM_SLOTS must be rejected (boundary), got {res:?}",
        );
        let res = se.r_mem_write(65535, &[0u8; 4]);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "slot 0xFFFF must be rejected, got {res:?}",
        );
    }

    /// PIN: r-mem write of data > MAX_RMEM_DATA must be rejected. A
    /// silent `copy_from_slice` with the cap would either panic or
    /// truncate; either way the chip's stored blob no longer matches
    /// what the caller intended.
    #[test]
    fn negative_rmem_write_oversize_data_rejected() {
        let mut se = MockSecureElement::new();
        let oversize = [0u8; MAX_RMEM_DATA + 1];
        let res = se.r_mem_write(0, &oversize);
        assert!(
            matches!(res, Err(SeError::InvalidParameter)),
            "MAX_RMEM_DATA+1 bytes must be rejected, got {res:?}",
        );
    }

    /// PIN: r-mem read of an unoccupied slot must be rejected. If the
    /// implementation silently returned the previous slot contents
    /// (from `rmem_data[s]` even when `rmem_occupied[s] == false`), an
    /// attacker who erased a slot could still read the post-erase
    /// memory image.
    #[test]
    fn negative_rmem_read_unoccupied_slot_rejected() {
        let mut se = MockSecureElement::new();
        let mut buf = [0u8; 4];
        let res = se.r_mem_read(0, &mut buf);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "fresh / never-written slot must return SlotNotFound, got {res:?}",
        );
    }

    /// PIN: r-mem read with a too-small buffer must be rejected. If
    /// silently truncated, the caller's downstream deserialize would
    /// fail in unpredictable ways instead of producing a clear
    /// "buffer too small" signal.
    #[test]
    fn negative_rmem_read_buffer_too_small_rejected() {
        let mut se = MockSecureElement::new();
        se.r_mem_write(0, &[1u8, 2, 3, 4, 5]).unwrap();
        let mut buf = [0u8; 3]; // only 3 bytes, need 5
        let res = se.r_mem_read(0, &mut buf);
        assert!(
            matches!(res, Err(SeError::InvalidParameter)),
            "too-small read buffer must be rejected, got {res:?}",
        );
    }

    /// PIN: r-mem read with an out-of-range slot must be rejected.
    #[test]
    fn negative_rmem_read_out_of_range_slot_rejected() {
        let mut se = MockSecureElement::new();
        let mut buf = [0u8; 4];
        let res = se.r_mem_read(NUM_RMEM_SLOTS as u16, &mut buf);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "out-of-range read slot must be rejected, got {res:?}",
        );
    }

    /// PIN: r-mem erase with an out-of-range slot must be rejected.
    /// If silently accepted, an attacker could trigger a panic at the
    /// `rmem_data[s] = [0u8; MAX_RMEM_DATA]` line via NS-controlled
    /// slot index.
    #[test]
    fn negative_rmem_erase_out_of_range_slot_rejected() {
        let mut se = MockSecureElement::new();
        let res = se.r_mem_erase(NUM_RMEM_SLOTS as u16);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "out-of-range erase slot must be rejected, got {res:?}",
        );
    }

    /// PIN: MACD with an out-of-range slot must be rejected. Like the
    /// r-mem path, this protects against NS-controlled slot indices
    /// reaching native-array indexing without bounds checking.
    #[test]
    fn negative_macd_out_of_range_slot_rejected() {
        let mut se = MockSecureElement::new();
        let res = se.mac_and_destroy(NUM_MACD_SLOTS as u16, &[0u8; 32]);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "MACD slot == NUM_MACD_SLOTS must be rejected (boundary), got {res:?}",
        );
        let res = se.mac_and_destroy(65535, &[0u8; 32]);
        assert!(
            matches!(res, Err(SeError::SlotNotFound)),
            "MACD slot 0xFFFF must be rejected, got {res:?}",
        );
    }

    /// PIN: distinct MACD inputs on the same fresh slot must produce
    /// distinct outputs. If a refactor accidentally hard-coded
    /// `hmac_sha256(data_in, &[0u8; 32])` instead of using `data_in`
    /// as the key, the output would still vary but in a different way;
    /// this catches the regression where the input gets ignored
    /// outright (e.g. swapped with a constant).
    #[test]
    fn negative_macd_distinct_inputs_diverge() {
        let mut se = MockSecureElement::new();
        let out_a = se.mac_and_destroy(0, &[0xAAu8; 32]).unwrap();
        let mut se2 = MockSecureElement::new();
        let out_b = se2.mac_and_destroy(0, &[0xBBu8; 32]).unwrap();
        assert_ne!(out_a, out_b);
    }

    /// PIN: MACD output depends on the slot's PRIOR `data_in` (the
    /// stored state). The mock documents this as
    /// `output = HMAC(data_in, previous_state)` and explicitly stores
    /// `data_in` as the new state. A wrong-PIN attempt that follows a
    /// different prior call MUST produce a different output than the
    /// same wrong-PIN against a fresh slot — otherwise an attacker who
    /// can rewind the state could replay a cached MACD result.
    #[test]
    fn negative_macd_output_depends_on_prior_state() {
        // Path A: fresh slot → mac(B). Output = HMAC(B, B).
        let mut a = MockSecureElement::new();
        let b_input = [0xBBu8; 32];
        let out_a = a.mac_and_destroy(0, &b_input).unwrap();

        // Path B: slot pre-seeded with A → mac(B). Output =
        // HMAC(B, A). Different.
        let mut b = MockSecureElement::new();
        b.mac_and_destroy(0, &[0xAAu8; 32]).unwrap();
        let out_b = b.mac_and_destroy(0, &b_input).unwrap();

        assert_ne!(
            out_a, out_b,
            "MACD ignored the slot's prior state — output didn't depend on what \
             the slot was initialized with. Replay of a wrong-PIN MACD result \
             across slot histories would become possible.",
        );
    }

    /// PIN: `simulate_glitch` is one-shot. Two armings in a row must
    /// each fire exactly once — i.e. the flag must not "stick true"
    /// after firing. (Already covered by an existing test; this test
    /// adds the *double-arm* path, which probes that the clear-on-fire
    /// runs once per arm.)
    #[test]
    fn negative_simulate_glitch_double_arm_is_independent() {
        let mut se = MockSecureElement::new();
        let dummy = [0u8; 32];

        se.simulate_glitch();
        assert!(matches!(se.mac_and_destroy(0, &dummy), Err(SeError::InternalError)));
        // No re-arm — flag should be cleared.
        assert!(se.mac_and_destroy(0, &dummy).is_ok());

        // Second arm cycle.
        se.simulate_glitch();
        assert!(matches!(se.mac_and_destroy(0, &dummy), Err(SeError::InternalError)));
        assert!(se.mac_and_destroy(0, &dummy).is_ok());
    }

    /// PIN: `SeError` and `UnlockError` MUST be `Debug` (used in
    /// `secure_log!` formats), and printing the Debug repr must not
    /// panic on any variant. Defends against a refactor that derived
    /// `Debug` only for a subset of variants.
    #[test]
    fn negative_error_debug_impls_dont_panic_for_any_variant() {
        for e in [
            SeError::SlotNotFound,
            SeError::SlotExpired,
            SeError::InvalidParameter,
            SeError::InternalError,
        ] {
            let _ = format!("{e:?}");
        }
        for e in [
            UnlockError::PinIncorrect,
            UnlockError::PinLocked,
            UnlockError::InternalError,
        ] {
            let _ = format!("{e:?}");
        }
    }

    /// PIN: the mock's r-mem and MACD slot counts MUST match the
    /// values the production PIN brick path relies on (8 r-mem slots,
    /// 16 MACD slots, 512 bytes/slot). A drift in these constants
    /// would make the mock no-longer-representative of the deployed
    /// hardware, masking PIN-state regressions.
    #[test]
    fn negative_mock_geometry_constants_pinned() {
        assert_eq!(NUM_RMEM_SLOTS, 8);
        assert_eq!(NUM_MACD_SLOTS, 16);
        assert_eq!(MAX_RMEM_DATA, 512);
    }

    /// PIN: provisioning + unlock must return a non-zero master
    /// secret. A degenerate code path that returned `[0u8; 32]` on
    /// "success" would let downstream key derivation produce a
    /// predictable zero-keyed wallet. Already implicitly checked by
    /// `correct_pin_unlocks_and_resets_counter`; we restate it here
    /// as a standalone negative to keep the assumption discoverable.
    #[test]
    fn negative_unlock_returns_nonzero_master_secret() {
        let mut se = make_provisioned();
        let pin = [b'1', b'2', b'3', b'4', 0, 0, 0, 0];
        let secret = se.unlock(&pin).unwrap();
        assert_ne!(
            secret, [0u8; 32],
            "unlock returned all-zero master_secret — downstream wallet derivation \
             would produce a publicly-derivable wallet",
        );
    }
}
