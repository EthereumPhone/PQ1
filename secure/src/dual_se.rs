//! Dual-SE XOR entropy split: Tropic01 + SE050.
//!
//! The 32-byte BIP-39 entropy is XOR-split into two halves:
//!   `half_T` (stored on Tropic01) and `half_E` (stored on SE050).
//! Neither chip alone reveals any bit of the seed.
//!
//! On unlock, both SEs are PIN-verified independently (hardware-gated),
//! the halves are fetched, and the full entropy is reconstructed:
//!   `entropy = half_T XOR half_E`
//!
//! The master_secret is derived from the full entropy:
//!   `master_secret = KDF("sphincs-master", entropy, 0)`
//!
//! Both SEs store the same master_secret (encrypted under their own
//! per-SE PIN scheme) so we can cross-verify: if the two don't match,
//! one chip has been tampered with.

use crate::crypto;
use crate::se050::Se050;
use crate::secure_element::{SeError, UnlockError, WalletStore};
use crate::tropic01_se::Tropic01SecureElement;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// XOR two 32-byte arrays. Inherently constant-time.
fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Dual secure element wrapper.
///
/// Manages XOR-split entropy across Tropic01 (half_T) and SE050 (half_E).
/// Both SEs run their own PIN verification (hardware-gated); the master
/// secret returned by each must match (derived from the same full entropy).
pub struct DualSecureElement {
    pub tropic01: Tropic01SecureElement,
    pub se050: Se050,
    /// Cached encrypted entropy blob (half_T encrypted under master_secret).
    /// Used by the signing flow to avoid re-authenticating Tropic01 per sign.
    entropy_blob_cache: [u8; crypto::ENTROPY_BLOB_LEN],
    blob_cached: bool,
}

impl DualSecureElement {
    pub const fn new() -> Self {
        Self {
            tropic01: Tropic01SecureElement::new(),
            se050: Se050::new(),
            entropy_blob_cache: [0; crypto::ENTROPY_BLOB_LEN],
            blob_cached: false,
        }
    }

    /// Load pairing key for Tropic01 (delegates to inner driver).
    pub fn load_pairing_key(&mut self) {
        self.tropic01.load_pairing_key();
    }
}

impl WalletStore for DualSecureElement {
    fn is_provisioned(&mut self) -> bool {
        self.tropic01.is_provisioned() && self.se050.is_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // Generate a random mask for the XOR split.
        // half_T = random 32 bytes (stored on Tropic01)
        // half_E = entropy XOR half_T (stored on SE050)
        // Reconstruction: half_T XOR half_E = entropy
        let mut half_t = [0u8; 32];
        crate::rng::fill(&mut half_t).map_err(|_| SeError::InternalError)?;
        let half_e = xor_32(entropy, &half_t);

        // Both SEs get the same master_secret (derived from full entropy).
        // This lets us cross-verify on unlock.
        //
        // Tropic01 stores half_T as its "entropy" and master_secret in
        // the MACD PIN chain. SE050 stores half_E as its "entropy" behind
        // hardware UserID PIN gating.
        //
        // The VK and bootstrap VK are identical on both chips.
        self.tropic01.provision(&half_t, master_secret, vk, bootstrap_vk, pin)?;
        self.se050.provision(&half_e, master_secret, vk, bootstrap_vk, pin)?;

        half_t.zeroize();

        secure_log!("[DUAL] Provisioned: entropy XOR-split across Tropic01 + SE050");
        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // Unlock Tropic01 first (MACD PIN chain → master_secret).
        let master_t = self.tropic01.unlock(pin)?;

        // Unlock SE050 (UserID PIN → master_secret).
        // If this fails, the Tropic01 has already consumed an attempt.
        // The dual-chip PIN lockout sync (intent log) is a separate
        // hardening item — for now, best-effort.
        let master_e = self.se050.unlock(pin).map_err(|e| {
            // Zeroize the Tropic01 master_secret on SE050 failure
            let mut m = master_t;
            m.zeroize();
            e
        })?;

        // Cross-verify: both SEs must return the same master_secret
        // (derived from the same full entropy at provisioning time).
        // If they disagree, one chip has been tampered with or replaced.
        let match_ok: bool = master_t.ct_eq(&master_e).into();

        let mut me = master_e;
        me.zeroize();

        if !match_ok {
            let mut mt = master_t;
            mt.zeroize();
            secure_log!("[DUAL] CRITICAL: master secret mismatch between SEs!");
            return Err(UnlockError::InternalError);
        }

        // Now reconstruct the full entropy from both halves, encrypt it
        // under master_secret, and cache the blob for the signing flow.
        //
        // Read half_T from Tropic01 (encrypted entropy blob → decrypt)
        // Read half_E from SE050 (encrypted entropy blob → decrypt)
        let mut blob_t = [0u8; 64];
        let blob_t_len = self.tropic01.read_entropy_blob(&mut blob_t)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_t = crypto::decrypt_entropy_blob(
            &blob_t[..blob_t_len], &master_t
        ).map_err(|_| UnlockError::InternalError)?;
        blob_t.zeroize();

        let mut blob_e = [0u8; 64];
        let blob_e_len = self.se050.read_entropy_blob(&mut blob_e)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_t
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_t, &half_e);
        half_t.zeroize();
        half_e.zeroize();

        // Verify consistency: kdf("sphincs-master", full_entropy, 0) must
        // equal the master_secret we already got from both SEs.
        let derived_master = crypto::kdf(b"sphincs-master", &full_entropy, 0);
        let consistent: bool = derived_master.ct_eq(&master_t).into();
        if !consistent {
            full_entropy.zeroize();
            let mut mt = master_t;
            mt.zeroize();
            secure_log!("[DUAL] CRITICAL: reconstructed entropy doesn't match master!");
            return Err(UnlockError::InternalError);
        }

        // Cache the encrypted full-entropy blob for the signing flow.
        let blob = crypto::encrypt_entropy_blob(&full_entropy, &master_t);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached = true;

        full_entropy.zeroize();

        secure_log!("[DUAL] Unlocked: entropy reconstructed from XOR split");
        Ok(master_t)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached || buf.len() < crypto::ENTROPY_BLOB_LEN {
            return Err(SeError::SlotNotFound);
        }
        buf[..crypto::ENTROPY_BLOB_LEN].copy_from_slice(&self.entropy_blob_cache);
        Ok(crypto::ENTROPY_BLOB_LEN)
    }

    fn read_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        // Both SEs store the same VK; read from SE050 (cached, no session overhead)
        self.se050.read_vk(buf)
    }

    fn read_bootstrap_vk(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        self.se050.read_bootstrap_vk(buf)
    }

    fn remaining_attempts(&mut self) -> u8 {
        // Return the minimum of both SEs (more restrictive)
        let t = self.tropic01.remaining_attempts();
        let e = self.se050.remaining_attempts();
        t.min(e)
    }

    fn zeroize_caches(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.tropic01.zeroize_caches();
        self.se050.zeroize_caches();
    }
}
