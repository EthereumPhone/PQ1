//! Dual-SE XOR entropy split: OPTIGA Trust M + SE050.
//!
//! The 32-byte BIP-39 entropy is XOR-split into two halves:
//!   `half_O` (stored on OPTIGA Trust M) and `half_E` (stored on SE050).
//! Neither chip alone reveals any bit of the seed.
//!
//! On unlock, both SEs are PIN-verified independently (hardware-gated),
//! the halves are fetched, and the full entropy is reconstructed:
//!   `entropy = half_O XOR half_E`
//!
//! The master_secret is derived from the full entropy:
//!   `master_secret = KDF("sphincs-master", entropy, 0)`
//!
//! Both SEs store the same master_secret (encrypted under their own
//! per-SE PIN scheme) so we can cross-verify: if the two don't match,
//! one chip has been tampered with.

use crate::crypto;
use crate::optiga::OptigaTrustM;
use crate::se050::Se050;
use crate::secure_element::{SeError, UnlockError, WalletStore};
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
/// Manages XOR-split entropy across OPTIGA Trust M (half_O) and SE050 (half_E).
/// Both SEs run their own PIN verification (hardware-gated); the master
/// secret returned by each must match (derived from the same full entropy).
pub struct DualSecureElement {
    pub optiga: OptigaTrustM,
    pub se050: Se050,
    /// Cached encrypted entropy blob (full entropy encrypted under master_secret).
    /// Used by the signing flow to avoid re-authenticating per sign.
    entropy_blob_cache: [u8; crypto::ENTROPY_BLOB_LEN],
    blob_cached: bool,
}

impl DualSecureElement {
    pub const fn new() -> Self {
        Self {
            optiga: OptigaTrustM::new(),
            se050: Se050::new(),
            entropy_blob_cache: [0; crypto::ENTROPY_BLOB_LEN],
            blob_cached: false,
        }
    }

    /// Load Platform Binding Secret for OPTIGA Trust M (delegates to inner driver).
    pub fn load_pbs(&mut self) {
        self.optiga.load_pbs();
    }
}

impl WalletStore for DualSecureElement {
    fn is_provisioned(&mut self) -> bool {
        self.optiga.is_provisioned() && self.se050.is_provisioned()
    }

    fn provision(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        pin: &[u8; 8],
    ) -> Result<(), SeError> {
        secure_log!("[DUAL/prov] start");

        let mut half_o = [0u8; 32];
        if crate::rng::fill(&mut half_o).is_err() {
            secure_log!("[DUAL/prov] rng::fill FAILED");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL/prov] rng OK, calling optiga.provision");
        let half_e = xor_32(entropy, &half_o);

        // Both SEs get the same master_secret (derived from full entropy).
        // This lets us cross-verify on unlock.
        //
        // OPTIGA Trust M stores half_O as its "entropy" and master_secret
        // behind the HMAC auth reference PIN gate.
        // SE050 stores half_E as its "entropy" behind hardware UserID PIN gating.
        //
        // The VK and bootstrap VK are identical on both chips.
        if let Err(e) = self.optiga.provision(&half_o, master_secret, vk, bootstrap_vk, pin) {
            secure_log!("[DUAL/prov] optiga.provision FAILED: {:?}", e);
            return Err(e);
        }
        secure_log!("[DUAL/prov] optiga OK, calling se050.provision");
        if let Err(e) = self.se050.provision(&half_e, master_secret, vk, bootstrap_vk, pin) {
            secure_log!("[DUAL/prov] se050.provision FAILED: {:?}", e);
            return Err(e);
        }

        half_o.zeroize();

        secure_log!("[DUAL] Provisioned: entropy XOR-split across OPTIGA Trust M + SE050");
        Ok(())
    }

    fn unlock(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // Unlock OPTIGA Trust M first (HMAC auth reference → master_secret).
        let master_o = self.optiga.unlock(pin)?;

        // Unlock SE050 (UserID PIN → master_secret).
        // If this fails, the OPTIGA has already consumed an attempt.
        // The dual-chip PIN lockout sync (intent log) is a separate
        // hardening item — for now, best-effort.
        let master_e = self.se050.unlock(pin).map_err(|e| {
            // Zeroize the OPTIGA master_secret on SE050 failure
            let mut m = master_o;
            m.zeroize();
            e
        })?;

        // Cross-verify: both SEs must return the same master_secret
        // (derived from the same full entropy at provisioning time).
        // If they disagree, one chip has been tampered with or replaced.
        let match_ok: bool = master_o.ct_eq(&master_e).into();

        let mut me = master_e;
        me.zeroize();

        if !match_ok {
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: master secret mismatch between SEs!");
            return Err(UnlockError::InternalError);
        }

        // Now reconstruct the full entropy from both halves, encrypt it
        // under master_secret, and cache the blob for the signing flow.
        //
        // Read half_O from OPTIGA (encrypted entropy blob → decrypt)
        // Read half_E from SE050 (encrypted entropy blob → decrypt)
        let mut blob_o = [0u8; 64];
        let blob_o_len = self.optiga.read_entropy_blob(&mut blob_o)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_o = crypto::decrypt_entropy_blob(
            &blob_o[..blob_o_len], &master_o
        ).map_err(|_| UnlockError::InternalError)?;
        blob_o.zeroize();

        let mut blob_e = [0u8; 64];
        let blob_e_len = self.se050.read_entropy_blob(&mut blob_e)
            .map_err(|_| UnlockError::InternalError)?;
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_o
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_o, &half_e);
        half_o.zeroize();
        half_e.zeroize();

        // Verify consistency: kdf("sphincs-master", full_entropy, 0) must
        // equal the master_secret we already got from both SEs.
        let derived_master = crypto::kdf(b"sphincs-master", &full_entropy, 0);
        let consistent: bool = derived_master.ct_eq(&master_o).into();
        if !consistent {
            full_entropy.zeroize();
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: reconstructed entropy doesn't match master!");
            return Err(UnlockError::InternalError);
        }

        // Cache the encrypted full-entropy blob for the signing flow.
        let blob = crypto::encrypt_entropy_blob(&full_entropy, &master_o);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached = true;

        full_entropy.zeroize();

        secure_log!("[DUAL] Unlocked: entropy reconstructed from XOR split");
        Ok(master_o)
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
        let o = self.optiga.remaining_attempts();
        let e = self.se050.remaining_attempts();
        o.min(e)
    }

    fn zeroize_caches(&mut self) {
        self.entropy_blob_cache.zeroize();
        self.blob_cached = false;
        self.optiga.zeroize_caches();
        self.se050.zeroize_caches();
    }

    /// Wipe both SEs via their admin recovery paths and clear SRAM caches.
    ///
    /// OPTIGA: `optiga.factory_reset()` overwrites every user OID through
    /// the shielded-connection path (`Change = Auto(F1D0) OR Conf(0xE140)`).
    /// Works even if the user PIN is forgotten. The PBS in flash is
    /// preserved so the chip remains usable for re-provisioning; the user
    /// OIDs are now blank.
    ///
    /// SE050: delegates to its own `factory_reset_admin` which uses the
    /// admin UserID at 0x7B06_00A0 to delete user objects.
    ///
    /// A best-effort attempt is made on each backend — if one fails we
    /// still try the other and wipe SRAM state.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        let optiga_result = self.optiga.factory_reset_admin();
        let se050_result = self.se050.factory_reset_admin();

        self.zeroize_caches();

        // Surface the first error we saw, but SRAM is zeroized regardless.
        optiga_result.and(se050_result)?;

        secure_log!("[DUAL] Factory reset complete — OPTIGA user data wiped, SE050 wiped");
        Ok(())
    }
}

impl DualSecureElement {
    /// End-to-end roundtrip test of the dual-SE admin-wipe integration.
    /// Exercises the production `factory_reset_admin` dispatch across
    /// both chips (OPTIGA Conf(E140) path + SE050 admin-UserID DELETE
    /// path) plus the cross-chip unlock that reconstructs the XOR split.
    ///
    /// Scope: the `WalletStore::factory_reset_admin` integration on
    /// DualSecureElement — NOT the PIN-lockout-triggers-wipe flow that
    /// calls it. That integration is deferred (separate test).
    ///
    /// Flow:
    /// 1. Pre-clean. Call `factory_reset_admin` to normalise both
    ///    chips to an unprovisioned state regardless of prior contents.
    ///    Idempotent by design on both sides.
    /// 2. Verify both chips report `!is_provisioned()` after step 1.
    /// 3. Provision fresh test data: entropy=0x55 pattern, master_secret
    ///    derived via the same KDF the DualSE unlock path uses (so the
    ///    cross-check at line ~170 of this file passes), vk=0xAA,
    ///    bootstrap_vk=0xBB, pin=`b"dualwipe"`.
    /// 4. Verify both chips now report `is_provisioned()`.
    /// 5. Call `unlock(test_pin)` and verify the returned master_secret
    ///    byte-exactly matches what we provisioned. Proves both chips
    ///    authenticated + the XOR reconstruction matches.
    /// 6. Call `factory_reset_admin` — the test proper.
    /// 7. Verify both chips report `!is_provisioned()`.
    /// 8. Call `unlock(test_pin)` and verify it now fails.
    ///
    /// Uses the REAL production object ranges: OPTIGA F1D0..F1D4 + F1E1,
    /// SE050 0x7B06_xxxx. This test DESTROYS any wallet state on both
    /// chips. Re-run the normal first-boot wizard afterwards to restore.
    ///
    /// LcsO-safety: the `dual-se-admin-wipe-e2e` feature MUST NOT imply
    /// `optiga-lock-operational`. All OPTIGA operations on the
    /// exercised paths stay at LcsO=Creation — `lock_oid` is a no-op
    /// under the default feature set.
    #[cfg(feature = "dual-se-admin-wipe-e2e")]
    pub fn run_admin_wipe_roundtrip(&mut self) -> Result<(), SeError> {
        let test_entropy: [u8; 32] = [0x55; 32];
        let test_master = crate::crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xAA; 32];
        let test_bvk: [u8; 32] = [0xBB; 32];
        let test_pin: [u8; 8] = *b"dualwipe";

        // ---- 1. Pre-clean ----
        //    Goal: normalise both chips to unprovisioned regardless of
        //    what the prior state is. Three cases we have to cover:
        //
        //    (a) Both chips already unprovisioned. No-op.
        //    (b) Both provisioned with matching admin PIN in flash. The
        //        normal production wipe path works. Just call
        //        `factory_reset_admin`.
        //    (c) SE050 provisioned but flash page 125 is erased (e.g.
        //        the prior `optiga-admin-wipe-e2e` run cleared it as
        //        post-test hygiene). `factory_reset_admin` falls
        //        through to `iterative_wipe(None, None)` which is
        //        unauthenticated — user objects with the two-entry
        //        TAG_POLICY cannot be deleted that way. We have to
        //        try user-PIN candidates to wipe SE050 `0x7B06_xxxx`.
        //
        //    Strategy: OPTIGA unconditional (Conf(E140) always works),
        //    SE050 admin-first then user-PIN-fallback cascade. Erase
        //    page 125 at the end so `provision()` below generates a
        //    fresh admin PIN.
        secure_log!("[DUAL-E2E-ADMIN] step 1: pre-clean");

        // OPTIGA: Conf(E140) wipe. Idempotent on blank chips.
        if let Err(e) = self.optiga.factory_reset() {
            secure_log!("[DUAL-E2E-ADMIN] step 1: OPTIGA factory_reset error {:?} (continuing)", e);
        }

        // SE050: try admin auth first if page 125 has a PIN.
        #[cfg(feature = "stm32u585")]
        unsafe {
            if !crate::hw::flash::is_admin_pin_blank() {
                let mut admin_pin = [0u8; 16];
                crate::hw::flash::read_admin_pin(&mut admin_pin);
                let _ = self.se050.admin_factory_reset(&admin_pin);
                admin_pin.zeroize();
            }

            // User-PIN fallback if objects survived admin attempt
            // (e.g. page-125 PIN didn't match prior provisioning).
            // Mirrors `make se050-reset` candidate list.
            if self.se050.is_provisioned() {
                const PIN_CANDIDATES: &[&[u8]] = &[
                    b"00000000", // e2e-test fast-path default
                    b"dualwipe", // our own test PIN (prior run of this test)
                    b"12345678",
                    b"11111111",
                ];
                for &pin in PIN_CANDIDATES {
                    let _ = self.se050.iterative_wipe(
                        Some(crate::se050::USERID_OBJ),
                        Some(pin),
                    );
                    if !self.se050.is_provisioned() {
                        break;
                    }
                }
            }

            // Erase page 125 so provision() generates a fresh admin
            // PIN + clears any stale wipe flag.
            let _ = crate::hw::flash::erase_admin_page();
        }

        // ---- 2. Verify both chips unprovisioned after pre-clean ----
        if self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 2 FAILED: OPTIGA still provisioned after pre-clean");
            return Err(SeError::InternalError);
        }
        if self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 2 FAILED: SE050 still provisioned after pre-clean");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 2: both chips unprovisioned after pre-clean OK");

        // ---- 3. Provision fresh test data ----
        secure_log!("[DUAL-E2E-ADMIN] step 3: provision");
        self.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &test_pin)?;
        secure_log!("[DUAL-E2E-ADMIN] step 3: provision OK");

        // ---- 4. Verify both chips provisioned ----
        if !self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 4 FAILED: OPTIGA not provisioned after provision");
            return Err(SeError::InternalError);
        }
        if !self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 4 FAILED: SE050 not provisioned after provision");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 4: both chips provisioned OK");

        // ---- 5. Pre-wipe unlock: master_secret roundtrip ----
        //    Authenticates both chips, reads both entropy halves, XORs
        //    them back, derives master_secret from full entropy, and
        //    cross-checks against what each chip returned. All three
        //    branches have to agree for unlock to return Ok.
        secure_log!("[DUAL-E2E-ADMIN] step 5: pre-wipe unlock");
        let recovered = match self.unlock(&test_pin) {
            Ok(m) => m,
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: unlock pre-wipe returned {:?}", e);
                return Err(SeError::InternalError);
            }
        };
        if recovered != test_master {
            secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: master_secret mismatch post-unlock");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 5: pre-wipe unlock OK (master_secret matches)");

        // ---- 6. The wipe proper ----
        secure_log!("[DUAL-E2E-ADMIN] step 6: factory_reset_admin");
        self.factory_reset_admin()?;
        secure_log!("[DUAL-E2E-ADMIN] step 6: factory_reset_admin OK");

        // ---- 7. Verify both chips unprovisioned ----
        if self.optiga.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 7 FAILED: OPTIGA still provisioned after wipe");
            return Err(SeError::InternalError);
        }
        if self.se050.is_provisioned() {
            secure_log!("[DUAL-E2E-ADMIN] step 7 FAILED: SE050 still provisioned after wipe");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 7: both chips unprovisioned post-wipe OK");

        // ---- 8. Post-wipe unlock must fail ----
        //    Don't care which specific error variant — the contract is
        //    "no seed derivable from a wiped pair." OPTIGA will hit the
        //    sentinel path and return NotProvisioned; SE050 objects are
        //    deleted so auth would fail at PIN verify. Whichever trips
        //    first, we just need NOT Ok.
        match self.unlock(&test_pin) {
            Ok(_) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8 FAILED: unlock SUCCEEDED after wipe");
                return Err(SeError::InternalError);
            }
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8: post-wipe unlock correctly failed ({:?})", e);
            }
        }

        Ok(())
    }
}
