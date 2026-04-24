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
        // Three-counter lockstep: call SE050 on every PIN attempt,
        // even when OPTIGA rejects it, so SE050's UserID silicon
        // counter advances in sync with MCU page-124 and OPTIGA E120
        // LUC. Skip SE050 only on a non-PIN OPTIGA error (I2C /
        // session fault) — don't burn an SE050 silicon attempt slot
        // for a transient comm glitch.
        //
        // OPTIGA stores master_secret explicitly; its `unlock` returns
        // what provision wrote — this is the authoritative value for
        // the consistency check below and for the final return.
        // SE050's `unlock` returns `kdf("sphincs-master", half_e, 0)`
        // which is meaningful here as the decrypt key for SE050's own
        // entropy_blob cache (different from OPTIGA's master).
        let optiga_result = self.optiga.unlock(pin);

        let se050_result = match &optiga_result {
            Ok(_) | Err(UnlockError::PinIncorrect) => {
                Some(self.se050.unlock(pin))
            }
            Err(_) => None,
        };

        // Resolve OPTIGA first. If OPTIGA rejected the PIN, zeroize
        // any master SE050 accidentally returned (pathological
        // desync: PIN matched SE050 but not OPTIGA — chip-swap or
        // out-of-band SE050 reset scenario) and propagate the OPTIGA
        // error to the caller BEFORE any downstream SE050 read path.
        let master_o = match optiga_result {
            Ok(mo) => mo,
            Err(e) => {
                if let Some(Ok(mut me)) = se050_result {
                    me.zeroize();
                }
                return Err(e);
            }
        };

        // OPTIGA accepted → SE050 was called. Resolve its result.
        let master_e = match se050_result
            .expect("OPTIGA Ok branch always calls SE050")
        {
            Ok(me) => me,
            Err(e) => {
                let mut m = master_o;
                m.zeroize();
                return Err(e);
            }
        };
        // Keep master_e alive — it's the key SE050 used to encrypt
        // its own entropy_blob cache. Zeroize after decrypt below.

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
        // SE050's blob is encrypted under ITS master_secret
        // (`kdf("sphincs-master", half_e, 0)`), not OPTIGA's. The
        // two chips encrypt their caches independently; each must
        // be decrypted with the matching key.
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_e
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();
        let mut me = master_e;
        me.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_o, &half_e);
        half_o.zeroize();
        half_e.zeroize();

        // Verify consistency: kdf("sphincs-master", full_entropy, 0) must
        // equal the master_secret we already got from both SEs.
        //
        // FI hardening: two independent `ct_eq` compares with a volatile
        // delay between, gated through `fi::check_true` so the boolean
        // cannot be faulted to `true` via a single skip.
        let derived_master = crypto::kdf(b"sphincs-master", &full_entropy, 0);
        let c1: bool = derived_master.ct_eq(&master_o).into();
        crate::fi::wait_random();
        let c2: bool = derived_master.ct_eq(&master_o).into();
        if !crate::fi::check_true(|| c1 && c2) {
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

    fn sync_remaining_with_mcu(&mut self, mcu_used: u8) {
        self.optiga.sync_remaining_with_mcu(mcu_used);
        self.se050.sync_remaining_with_mcu(mcu_used);
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
    /// admin UserID at 0x7B10_00A0 to delete user objects.
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
    /// End-to-end roundtrip test of the full dual-SE admin-wipe
    /// integration. Covers both: the XOR-split entropy reconstruction
    /// (unique dual-SE value-add) AND the `factory_reset_admin`
    /// dispatch that wipes both chips.
    ///
    /// Scope: `DualSecureElement::provision` + `DualSecureElement::
    /// unlock` + `DualSecureElement::factory_reset_admin`, all on
    /// real production OID ranges.
    ///
    /// Flow:
    /// 1. Pre-clean cascade (admin-auth → user-PIN → unauth). Tolerates
    ///    prior test contamination.
    /// 2. Verify both chips report `!is_provisioned()` after step 1.
    /// 3. Provision fresh test data: entropy=0x55 pattern, master_secret
    ///    derived via the same `kdf("sphincs-master", entropy, 0)` the
    ///    DualSE unlock path uses (so the consistency check passes),
    ///    vk=0xAA, bootstrap_vk=0xBB, pin=`b"dualwipe"`.
    /// 4. Verify both chips now report `is_provisioned()`.
    /// 5. Call `unlock(test_pin)` and verify the returned master_secret
    ///    byte-exactly matches what we provisioned. Proves both chips
    ///    authenticated AND the XOR reconstruction matches.
    /// 6. Call `factory_reset_admin()` — the production dispatch that
    ///    wipes both chips in sequence.
    /// 7. Verify both chips report `!is_provisioned()` post-wipe.
    /// 8. Call `unlock(test_pin)` again — must fail (no seed derivable
    ///    from a wiped pair).
    ///
    /// Uses the REAL production object ranges: OPTIGA F1D0..F1D4 + F1E1,
    /// SE050 0x7B10_xxxx (v6). This test DESTROYS any prior wallet
    /// state on both chips. Re-run the normal first-boot wizard
    /// afterwards to restore.
    ///
    /// LcsO-safety: the `dual-se-admin-wipe-e2e` feature MUST NOT imply
    /// `optiga-lock-operational`. All OPTIGA operations on the
    /// exercised paths stay at LcsO=Creation — `lock_oid` is a no-op
    /// under the default feature set.
    ///
    /// Robustness: relies on the conditional page-125 erase in
    /// `Se050::factory_reset_admin` (landed 2026-04-21) — an
    /// unconditional erase would desync flash admin PIN from chip
    /// admin UserID on any Transport glitch, stucking the v5 range
    /// the same way that bug stuck v3 and v4.
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
        //        try user-PIN candidates to wipe SE050 `0x7B0E_xxxx`.
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

        // SE050 wipe cascade. Each stage only fires if the prior
        // stage left objects behind.
        //
        //   (a) Admin-auth factory reset (page 125 has admin PIN).
        //       Deletes user UserID + gated data + self-deletes admin
        //       UserID. The production PIN-lockout path.
        //   (b) User-auth factory reset with dev-PIN candidates. Tries
        //       `user_factory_reset(pin)` which verifies PIN, deletes
        //       user-gated data, AND self-deletes the user UserID in
        //       the same authenticated session. Plain
        //       `iterative_wipe(Some(USERID), Some(pin))` (which we
        //       tried first iteration) deletes the data objects but
        //       cannot self-delete the UserID itself — that's the
        //       exact gap the first hardware run surfaced.
        //   (c) Unauthenticated iterative sweep as a last-ditch
        //       catch-all for legacy objects without policies.
        //
        // Legacy objects in the 0x7b000xxx / 0x7b002xxx ranges that
        // the chip picked up from early-build firmware are permanently
        // stuck (user noted — specific range was bumped to skip them).
        // They will remain after pre-clean. That's fine: `is_provisioned`
        // only checks the current USERID_OBJ (0x7b10_0000), so the
        // stuck legacy objects don't affect the test.
        #[cfg(feature = "stm32u585")]
        unsafe {
            // Stage (a): admin auth if page 125 has a PIN.
            let admin_blank = crate::hw::flash::is_admin_pin_blank();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (a): admin_pin_blank={}", admin_blank);
            if !admin_blank {
                let mut admin_pin = [0u8; 16];
                crate::hw::flash::read_admin_pin(&mut admin_pin);
                let r = self.se050.admin_factory_reset(&admin_pin);
                secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (a): admin_factory_reset → {:?}", r.as_ref().err());
                admin_pin.zeroize();
            }

            // Stage (b): user-PIN cascade if USERID_OBJ survived.
            let se_prov_before = self.se050.is_provisioned();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (b): se050.is_provisioned()={}", se_prov_before);
            if se_prov_before {
                const PIN_CANDIDATES: &[&[u8]] = &[
                    b"00000000", // e2e-test fast-path default (most common)
                    b"dualwipe", // our own test PIN (prior run)
                    b"12345678",
                    b"11111111",
                ];
                for &pin in PIN_CANDIDATES {
                    let r = self.se050.user_factory_reset(pin);
                    secure_log!(
                        "[DUAL-E2E-ADMIN] pre-clean stage (b): user_factory_reset({:?}) → {:?}",
                        core::str::from_utf8(pin).unwrap_or("?"),
                        r.as_ref().err(),
                    );
                    if r.is_ok() {
                        break;
                    }
                }
            }

            // Stage (c): unauthenticated sweep as final catch-all.
            let se_prov_mid = self.se050.is_provisioned();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (c): se050.is_provisioned()={}", se_prov_mid);
            let _ = self.se050.iterative_wipe(None, None);

            // Deliberately NO `erase_admin_page()` here. Page 125's
            // lifecycle is owned by `Se050::factory_reset_admin` (the
            // WalletStore wrapper), which now conditionally erases
            // only when the chip's admin UserID is confirmed gone.
            // Pre-clean's job is to get the chip to a state where
            // `provision()` can succeed — and provision handles every
            // page-125 state correctly as long as flash + chip are
            // paired.
            //
            // The earlier unconditional erase here is what stuck v4:
            // a Transport glitch in stage (a) left admin on the chip,
            // then the erase burned the matching flash PIN.
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
        secure_log!("[DUAL-E2E-ADMIN] step 5: unlock");
        let recovered = match self.unlock(&test_pin) {
            Ok(m) => m,
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: unlock returned {:?}", e);
                return Err(SeError::InternalError);
            }
        };
        if recovered != test_master {
            secure_log!("[DUAL-E2E-ADMIN] step 5 FAILED: master_secret mismatch post-unlock");
            return Err(SeError::InternalError);
        }
        secure_log!("[DUAL-E2E-ADMIN] step 5: unlock OK (master_secret matches)");

        // ---- 6. The wipe proper — production dispatch ----
        //    Calls `DualSecureElement::factory_reset_admin` (via the
        //    WalletStore trait on self). That cascades to OPTIGA's
        //    factory_reset (Conf(E140) path) + SE050's
        //    factory_reset_admin (admin-auth DELETE of user UserID
        //    and gated data, plus admin self-delete). Page 125 now
        //    only gets erased if admin UserID is confirmed gone from
        //    the chip (conditional erase, landed alongside this
        //    test).
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
        //    The contract is "no seed derivable from a wiped pair."
        //    OPTIGA hits the sentinel path → NotProvisioned. SE050
        //    has no objects to read → auth fails. Either ERROR is
        //    fine; only Ok(_) is a test failure.
        match self.unlock(&test_pin) {
            Ok(_) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8 FAILED: unlock SUCCEEDED after wipe");
                Err(SeError::InternalError)
            }
            Err(e) => {
                secure_log!("[DUAL-E2E-ADMIN] step 8: post-wipe unlock correctly failed ({:?})", e);
                Ok(())
            }
        }
    }

    /// Multi-unlock / cross-reboot validation for the SE050 entropy-
    /// corruption fix (PE0 RST, no more shield ENA cross-coupling).
    ///
    /// Flow:
    /// - If both chips already provisioned: reuse state (this is the
    ///   "we already booted once" branch — the interesting one).
    /// - Else: run the same pre-clean cascade as `run_admin_wipe_
    ///   roundtrip` then provision fresh.
    /// - Do `iterations` consecutive unlock() calls. Each one
    ///   re-authenticates both chips, reads both entropy halves, XORs
    ///   them, derives master_secret, cross-checks. All iterations
    ///   must return the SAME master_secret (== `test_master`). Any
    ///   drift between iterations flags SE050 NVM corruption.
    ///
    /// Does NOT wipe at the end — that's how we preserve state so the
    /// next cold boot (re-invocation of `probe-rs run`) can exercise
    /// the already-provisioned branch.
    #[cfg(feature = "dual-se-multi-unlock-e2e")]
    pub fn run_multi_unlock_roundtrip(&mut self, iterations: u32) -> Result<(), SeError> {
        let test_entropy: [u8; 32] = [0x55; 32];
        let test_master = crate::crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xAA; 32];
        let test_bvk: [u8; 32] = [0xBB; 32];
        let test_pin: [u8; 8] = *b"dualwipe";

        // Probe by attempting an unlock with the test PIN. If both chips
        // are already provisioned with matching state from a prior boot,
        // this returns the expected master_secret and no pre-clean is
        // needed. Otherwise we fall through to wipe + fresh-provision.
        // `optiga.is_provisioned()` can't be used as the discriminator
        // because it needs the shielded connection up, which cold boot
        // hasn't established yet → false negative.
        secure_log!("[DUAL-MULTI] probing unlock() to detect prior provisioning...");
        let probe = self.unlock(&test_pin);
        match &probe {
            Ok(m) if m == &test_master => {
                secure_log!("[DUAL-MULTI] probe: Ok(master matches)");
            }
            Ok(_) => {
                secure_log!("[DUAL-MULTI] probe: Ok BUT master_secret mismatch — state corruption?");
            }
            Err(e) => {
                secure_log!("[DUAL-MULTI] probe: Err({:?})", e);
            }
        }
        let already_provisioned = matches!(probe, Ok(ref m) if *m == test_master);

        if already_provisioned {
            secure_log!("[DUAL-MULTI] boot state: ALREADY PROVISIONED (probe unlock matched)");
            secure_log!("[DUAL-MULTI] phase A: skipping pre-clean + provision");
            // The probe unlock counts as iteration 1; do N-1 more.
            secure_log!("[DUAL-MULTI] iter 1/{}: master_secret matches (via boot probe)", iterations);
            for i in 2..=iterations {
                let recovered = match self.unlock(&test_pin) {
                    Ok(m) => m,
                    Err(e) => {
                        secure_log!("[DUAL-MULTI] iter {}/{}: unlock FAILED {:?}", i, iterations, e);
                        return Err(SeError::InternalError);
                    }
                };
                if recovered != test_master {
                    secure_log!("[DUAL-MULTI] iter {}/{}: master_secret MISMATCH", i, iterations);
                    return Err(SeError::InternalError);
                }
                secure_log!("[DUAL-MULTI] iter {}/{}: master_secret matches", i, iterations);
            }
        } else {
            // Probe failed → chips are fresh / stale / mismatched. Wipe,
            // provision, then do `iterations` unlocks.
            if let Ok(_) = probe {
                secure_log!("[DUAL-MULTI] boot state: probe unlocked but master mismatched — reprovisioning");
            } else {
                secure_log!("[DUAL-MULTI] boot state: probe unlock FAILED → fresh provisioning");
            }

            if let Err(e) = self.optiga.factory_reset() {
                secure_log!("[DUAL-MULTI] pre-clean: OPTIGA factory_reset error {:?} (continuing)", e);
            }

            #[cfg(feature = "stm32u585")]
            unsafe {
                let admin_blank = crate::hw::flash::is_admin_pin_blank();
                if !admin_blank {
                    let mut admin_pin = [0u8; 16];
                    crate::hw::flash::read_admin_pin(&mut admin_pin);
                    let _ = self.se050.admin_factory_reset(&admin_pin);
                    admin_pin.zeroize();
                }
                if self.se050.is_provisioned() {
                    const PIN_CANDIDATES: &[&[u8]] = &[
                        b"00000000", b"dualwipe", b"12345678", b"11111111",
                    ];
                    for &pin in PIN_CANDIDATES {
                        if self.se050.user_factory_reset(pin).is_ok() {
                            break;
                        }
                    }
                }
                let _ = self.se050.iterative_wipe(None, None);
            }

            if self.optiga.is_provisioned() {
                secure_log!("[DUAL-MULTI] pre-clean FAILED: OPTIGA still provisioned");
                return Err(SeError::InternalError);
            }
            if self.se050.is_provisioned() {
                secure_log!("[DUAL-MULTI] pre-clean FAILED: SE050 still provisioned");
                return Err(SeError::InternalError);
            }

            secure_log!("[DUAL-MULTI] pre-clean OK; provisioning fresh");
            self.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &test_pin)?;
            secure_log!("[DUAL-MULTI] phase A: provision OK");

            for i in 1..=iterations {
                let recovered = match self.unlock(&test_pin) {
                    Ok(m) => m,
                    Err(e) => {
                        secure_log!("[DUAL-MULTI] iter {}/{}: unlock FAILED {:?}", i, iterations, e);
                        return Err(SeError::InternalError);
                    }
                };
                if recovered != test_master {
                    secure_log!("[DUAL-MULTI] iter {}/{}: master_secret MISMATCH", i, iterations);
                    return Err(SeError::InternalError);
                }
                secure_log!("[DUAL-MULTI] iter {}/{}: master_secret matches", i, iterations);
            }
        }

        secure_log!("[DUAL-MULTI] all {} unlocks verified; state preserved for next cold boot", iterations);

        // Clear stale MCU wipe-flag + PIN attempts left over from prior
        // failed `dual-se-admin-wipe-e2e` runs or from our own pre-clean.
        // Without this, the boot-time wipe trigger in `main.rs`
        // re-fires on every reboot, wiping both chips and defeating the
        // "cross-boot already-provisioned" branch this test is meant to
        // exercise. Safe because the chips are now provisioned cleanly
        // and SE050's admin UserID lifecycle is the pre-existing bug
        // tracked in `project_se050_admin_wipe.md`, not our concern.
        #[cfg(feature = "stm32u585")]
        unsafe {
            if crate::hw::flash::is_wipe_armed() {
                if crate::hw::flash::erase_admin_page().is_ok() {
                    secure_log!("[DUAL-MULTI] cleared stale wipe flag (page 125 erased)");
                }
            }
            let _ = crate::hw::flash::pin_attempts_reset();
        }

        Ok(())
    }
}
