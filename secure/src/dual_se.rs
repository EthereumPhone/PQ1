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
//! ## What the chips are shown (#855)
//!
//! Neither chip ever receives the PIN, nor anything computable from the PIN
//! without this microcontroller. For each wallet this module derives, from
//! `PRF(device_key, label || salt || PIN)`:
//!
//!   - a credential for the OPTIGA and a *different* one for the SE050, so
//!     what one chip stores does not open the other;
//!   - a mask for each half, so each chip stores `half XOR mask` and the two
//!     stored values do not XOR to the entropy.
//!
//! A new salt is minted before the first SE write of every provisioning
//! (any older one is retired first), and every wipe destroys the salt
//! before it sends anything to a chip. The backends are called through
//! `provision_image` / `unlock_with_credential`, never with a PIN. (The one
//! exception is the e2e-only clean-up helper below, which presents known
//! test PINs as compile-time constants to delete UserID objects written by
//! pre-#855 firmware.)
//!
//! The master_secret is derived from the full entropy:
//!   `master_secret = KDF("sphincs-master", entropy, 0)`
//!
//! Both SEs store the same master_secret (encrypted under their own
//! per-SE PIN scheme) so we can cross-verify: if the two don't match,
//! one chip has been tampered with.

use crate::crypto;
use crate::optiga::OptigaTrustM;
use crate::pin_credential::WalletRole;
use crate::se050::Se050;
use crate::secure_element::{SeError, UnlockError, WalletStore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

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
    blob_cached: crate::fih::FihBool,
}

impl DualSecureElement {
    pub const fn new() -> Self {
        Self {
            optiga: OptigaTrustM::new(),
            se050: Se050::new(),
            entropy_blob_cache: [0; crypto::ENTROPY_BLOB_LEN],
            blob_cached: crate::fih::FihBool::new_false(),
        }
    }

    /// Load Platform Binding Secret for OPTIGA Trust M (delegates to inner driver).
    pub fn load_pbs(&mut self) {
        self.optiga.load_pbs();
    }

    /// Bring-up transport OPTIGA E140 pairing, run before the legacy seed
    /// wizard draws entropy — see `OptigaTrustM::pair_for_first_boot` for why
    /// (mandatory `ensure_shield` in `random()` needs a paired chip). This is
    /// not the production-final fresh-TRNG rotation or E140 lock ceremony.
    /// The OPTIGA-level error detail is logged by the inner driver;
    /// callers only branch on success.
    pub fn pair_optiga_for_first_boot(&mut self) -> Result<(), SeError> {
        self.optiga
            .pair_for_first_boot()
            .map_err(|_| SeError::InternalError)
    }

    /// Generate a fresh OPTIGA-side XOR half via a 3-source TRNG mix
    /// (STM32 ⊕ OPTIGA ⊕ SE050). The security of the dual-SE split
    /// depends critically on this half being unpredictable: if an
    /// attacker recovers the SE050 half (or guesses this one), they
    /// reconstruct the seed by XOR. Mixing three sources means any single
    /// unbroken source preserves entropy.
    ///
    /// Uses the explicit-handle `rng_strong::fill_with_store` path so holding
    /// `&mut self` never re-enters the global SE singleton. That path obtains
    /// and validates the two chip streams separately before folding either.
    ///
    /// Both-or-fail (finding F1): each SE's `random()` contribution is
    /// mandatory — a failed read aborts provisioning rather than being
    /// silently dropped. The previous `if …is_ok()` mixing let `half_o`
    /// degrade to the platform TRNG alone when both SE reads failed or were
    /// glitched: an attacker who influenced the STM32 TRNG and later extracted
    /// the SE050 half could then recover the full seed (`half_E XOR half_O`),
    /// defeating invariant #1. This matches the strict semantics of
    /// `DualSecureElement::random`. Also fail-closed on an all-zero result
    /// (stuck-at-0 fault surviving all three sources).
    fn generate_split_half(&mut self) -> Result<[u8; 32], SeError> {
        // `half_o` = the OPTIGA-side half in both the real and decoy
        // splits (the SE050 half is `entropy XOR half_o`).
        let mut half_o = [0u8; 32];
        if crate::rng_strong::fill_with_store(&mut half_o, self).is_err() {
            secure_log!(
                "[DUAL/prov] strict STM32+OPTIGA+SE050 draw FAILED — refusing degraded split"
            );
            half_o.zeroize();
            return Err(SeError::InternalError);
        }
        Ok(half_o)
    }

    /// Draw the bytes of a new PIN-credential salt from the same strict
    /// three-source generator as the split half.
    fn draw_pin_salt(&mut self, out: &mut [u8; crate::pin_credential::SALT_LEN]) -> Result<(), ()> {
        crate::rng_strong::fill_with_store(&mut out[..], self)
    }

    /// Wipe the OPTIGA side of a dual-SE store, supplying the legacy E120
    /// reset path with a strict three-source transient authorization value.
    /// A failed source skips only that optional counter reset; the underlying
    /// OPTIGA wipe still runs without a weaker replacement secret.
    pub(crate) fn reset_optiga_for_admin(&mut self) -> Result<(), SeError> {
        #[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]
        let result = {
            let mut transient_secret = Zeroizing::new([0u8; 32]);
            let result = if crate::rng_strong::fill_with_store(&mut *transient_secret, self)
                .is_ok()
            {
                self.optiga
                    .factory_reset_with_transient_secret(&mut *transient_secret)
                    .map_err(|_| SeError::InternalError)
            } else {
                secure_log!(
                    "[DUAL] strict transient-auth RNG failed — skipping optional \
                     OPTIGA E120 reset; continuing best-effort wipe"
                );
                self.optiga.factory_reset_admin()
            };
            transient_secret.zeroize();
            crate::fi::zeroize_barrier();
            result
        };
        #[cfg(not(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational"))))]
        let result = self.optiga.factory_reset_admin();
        result
    }
}

/// Dev diagnostic (`unlock-diag`): the step at which the last
/// [`DualSecureElement::unlock`] failed, 0 while none has. 1 = no usable salt
/// (credentials), 2/3 = OPTIGA rejected the PIN / other OPTIGA error, 4/5 =
/// the same for the SE050, 6/7 = OPTIGA blob read / decrypt, 8/9 = SE050
/// blob read / decrypt, 10 = the reconstructed entropy disagrees with the
/// stored master. A step number only, never a secret; added 2026-10-16 to
/// find why the auto-unlock after setup failed on the EVT.
#[cfg(feature = "unlock-diag")]
static LAST_UNLOCK_FAIL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[inline(always)]
fn unlock_failed_at(_step: u8) {
    #[cfg(feature = "unlock-diag")]
    LAST_UNLOCK_FAIL.store(_step, core::sync::atomic::Ordering::Relaxed);
}

/// See [`LAST_UNLOCK_FAIL`].
#[cfg(feature = "unlock-diag")]
pub fn last_unlock_failure() -> u8 {
    LAST_UNLOCK_FAIL.load(core::sync::atomic::Ordering::Relaxed)
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

        // Keep every reconstructing split-half copy in an auto-wiping wrapper.
        // This closure is intentional: all four wrappers drop before the
        // barrier below on success, either SE provisioning error, or either
        // optional ML-KEM sealing error. Returning directly from one of those
        // branches must never leave a raw half live on the stack.
        let provision_result = (|| -> Result<(), SeError> {
            // #855: the salt is persisted before anything is written to
            // either chip, then the credentials and half masks are derived
            // from it. A failure here leaves both chips untouched.
            //
            // SAFETY: `&mut self` on the SE store implies the single-threaded
            // secure-world context the page-125 salt write requires.
            let salt = unsafe {
                crate::pin_gate::load_or_create_salt(|bytes| self.draw_pin_salt(bytes))
            }
            .map_err(|_e| {
                secure_log!("[DUAL/prov] PIN-credential salt unavailable: {:?}", _e);
                SeError::InternalError
            })?;
            let creds = crate::pin_gate::credentials(WalletRole::Real, &salt, pin).map_err(|_e| {
                secure_log!("[DUAL/prov] PIN-credential derivation FAILED: {:?}", _e);
                SeError::InternalError
            })?;

            let half_o = Zeroizing::new(self.generate_split_half()?);
            secure_log!("[DUAL/prov] rng OK (3-source XOR mix), calling optiga.provision");
            let half_e = Zeroizing::new(xor_32(entropy, &half_o));

            // Under the ML-KEM hybrid inner wrap (#28), seal each half BEFORE it
            // crosses I²C: the SE stores the 32-byte AES-GCM ciphertext (object
            // size unchanged), and the 1568-byte ML-KEM ct + 16-byte tag go to
            // the ct-store. Without the feature the direct-half flow remains
            // byte-for-byte identical; the two Copy aliases are also Zeroizing.
            #[cfg(feature = "mlkem-inner-wrap")]
            let (se_half_o, se_half_e) = (
                Zeroizing::new(
                    crate::pq_wrap::seal_half_for_se(
                        crate::pq_wrap::HalfId::OptigaHalfO,
                        0,
                        &half_o,
                    )
                    .map_err(|_| SeError::InternalError)?,
                ),
                Zeroizing::new(
                    crate::pq_wrap::seal_half_for_se(
                        crate::pq_wrap::HalfId::Se050HalfE,
                        0,
                        &half_e,
                    )
                    .map_err(|_| SeError::InternalError)?,
                ),
            );
            #[cfg(not(feature = "mlkem-inner-wrap"))]
            let (se_half_o, se_half_e) =
                (Zeroizing::new(*half_o), Zeroizing::new(*half_e));

            // #855: what each chip is given is decided in one host-tested
            // place, `pin_credential::chip_images`: each chip's own
            // credential, and its half XOR its own PIN-keyed mask, so the
            // values read out of both chips do not XOR to the entropy
            // without the device key and the PIN. The mask is the outermost
            // layer: applied last here, removed first in `unlock`.
            let (optiga_image, se050_image) =
                crate::pin_credential::chip_images(creds, &se_half_o, &se_half_e);

            // OPTIGA Trust M stores its half-object + master_secret behind the
            // HMAC auth reference gate; SE050 stores its half-object behind
            // hardware UserID gating. Each gate holds a different die-bound
            // credential. The VK and bootstrap VK are identical on both chips.
            if let Err(e) =
                self.optiga
                    .provision_image(&optiga_image, master_secret, vk, bootstrap_vk)
            {
                secure_log!("[DUAL/prov] optiga.provision FAILED: {:?}", e);
                return Err(e);
            }
            secure_log!("[DUAL/prov] optiga OK, calling se050.provision");
            if let Err(e) = self.se050.provision_image(&se050_image, vk, bootstrap_vk) {
                secure_log!("[DUAL/prov] se050.provision FAILED: {:?}", e);
                return Err(e);
            }
            Ok(())
        })();

        // The closure's Zeroizing locals have dropped on every exit. Keep an
        // explicit compiler barrier at the security boundary before exposing
        // its Result to the caller.
        crate::fi::zeroize_barrier();
        provision_result?;

        secure_log!("[DUAL] Provisioned: entropy XOR-split across OPTIGA Trust M + SE050");
        Ok(())
    }

    #[cfg(feature = "duress-pin")]
    fn provision_duress(
        &mut self,
        entropy: &[u8; 32],
        master_secret: &[u8; 32],
        vk: &[u8; 32],
        bootstrap_vk: &[u8; 32],
        duress_pin: &[u8; 8],
    ) -> Result<(), SeError> {
        // `entropy` is the FULL decoy entropy; XOR-split it across the two
        // chips exactly like the real wallet — invariant #1 (no full
        // entropy on a single chip) applies to the decoy too. A fresh
        // 3-source half is drawn so the decoy split is independent of the
        // real one.
        secure_log!("[DUAL/duress] start");

        // #855: the decoy uses the salt of the real wallet provisioned just
        // before it (one salt per provisioning; a wipe kills both wallets),
        // with its own labels, so its credentials and masks are unrelated to
        // the real ones even for the same PIN.
        let creds = crate::pin_gate::decoy_provisioning_credentials(duress_pin)
            .map_err(|_e| {
                secure_log!("[DUAL/duress] PIN-credential derivation FAILED: {:?}", _e);
                SeError::InternalError
            })?;

        let mut half_o = self.generate_split_half()?;
        let mut half_e = xor_32(entropy, &half_o);
        let (optiga_image, se050_image) =
            crate::pin_credential::chip_images(creds, &half_o, &half_e);

        if let Err(e) =
            self.optiga
                .provision_duress_image(&optiga_image, master_secret, vk, bootstrap_vk)
        {
            secure_log!("[DUAL/duress] optiga.provision_duress FAILED: {:?}", e);
            half_o.zeroize();
            crate::fi::zeroize_barrier();
            half_e.zeroize();
            return Err(e);
        }
        if let Err(e) = self.se050.provision_duress_image(&se050_image, vk, bootstrap_vk) {
            secure_log!("[DUAL/duress] se050.provision_duress FAILED: {:?}", e);
            half_o.zeroize();
            crate::fi::zeroize_barrier();
            half_e.zeroize();
            return Err(e);
        }

        half_o.zeroize();
        crate::fi::zeroize_barrier();
        half_e.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!("[DUAL/duress] Provisioned decoy: entropy XOR-split across OPTIGA + SE050");
        Ok(())
    }

    #[cfg(feature = "duress-pin")]
    fn duress_is_provisioned(&mut self) -> bool {
        self.optiga.duress_is_provisioned() && self.se050.duress_is_provisioned()
    }

    /// §32 P3: attempt to unlock the DECOY wallet with `pin`. Reads both
    /// decoy halves (OPTIGA F1D9 via F1D8 auto-state auth; SE050
    /// `DURESS_ENTROPY_OBJ` via the duress UserID), reconstructs the decoy
    /// entropy, and returns the decoy master. Returns `Err(PinIncorrect)`
    /// if `pin` is not the duress PIN — the caller (`gated_unlock`) then
    /// falls through to the real `unlock`.
    ///
    /// Timing: BOTH chips' duress verifies run even when the first fails
    /// (no short-circuit), mirroring the three-counter-lockstep of the
    /// real `unlock` and keeping the op-count uniform across real/duress
    /// entries. The OPTIGA verify fires only LUC(E121) — the real E120 is
    /// never touched on a duress entry, so no lockout drift.
    #[cfg(feature = "duress-pin")]
    fn unlock_duress(&mut self, pin: &[u8; 8]) -> Result<[u8; 32], UnlockError> {
        // #855: derive the decoy credentials for this PIN. With no usable
        // salt nothing can match, so report "not the duress PIN" and let the
        // caller fall through to the real unlock (which then refuses).
        let creds = match crate::pin_gate::unlock_credentials(WalletRole::Duress, pin) {
            Ok(c) => c,
            Err(_) => return Err(UnlockError::PinIncorrect),
        };

        // OPTIGA returns (half_o, stored_decoy_master_from_F1DA); SE050
        // returns half_e. Both chips are ALWAYS verified (no `?` short-
        // circuit) so the op-count is uniform across real/duress entries.
        let ro = unsafe { self.optiga.duress_read_half(&creds.optiga) };
        let re = self.se050.duress_read_half(&creds.se050);
        match (ro, re) {
            (Ok((mut half_o, mut stored_master)), Ok(mut half_e)) => {
                // Each chip returned `half XOR mask`; remove the masks.
                let mut full = xor_32(
                    &creds.mask_optiga.apply(&half_o),
                    &creds.mask_se050.apply(&half_e),
                );
                half_o.zeroize();
                crate::fi::zeroize_barrier();
                half_e.zeroize();
                crate::fi::zeroize_barrier();

                // FI cross-check (parity with the real `unlock`): the
                // master derived from the reconstructed decoy entropy MUST
                // equal the decoy master stored on-chip (F1DA). Defends a
                // glitch on the halve reads that yields wrong entropy.
                // Two `ct_eq` compares separated by `wait_random`, gated
                // through the hamming-distant sentinel.
                let derived_master = crypto::kdf(b"sphincs-master", &full, 0);
                let c1: bool = derived_master.ct_eq(&stored_master).into();
                crate::fi::wait_random();
                let c2: bool = derived_master.ct_eq(&stored_master).into();
                stored_master.zeroize();
                crate::fi::zeroize_barrier();
                if crate::fi::check_true_into_sentinel(|| c1 && c2) != crate::fi::OK_SENTINEL {
                    full.zeroize();
                    crate::fi::zeroize_barrier();
                    secure_log!("[DUAL/duress] CRITICAL: decoy entropy doesn't match stored master");
                    return Err(UnlockError::InternalError);
                }

                let blob = crypto::encrypt_entropy_blob(&full, &derived_master);
                self.entropy_blob_cache.copy_from_slice(&blob);
                self.blob_cached.set_true();
                full.zeroize();
                crate::fi::zeroize_barrier();
                secure_log!("[DUAL/duress] decoy wallet unlocked");
                Ok(derived_master)
            }
            (other_o, other_e) => {
                if let Ok((mut h, mut m)) = other_o {
                    h.zeroize();
                    m.zeroize();
                    crate::fi::zeroize_barrier();
                }
                if let Ok(mut h) = other_e {
                    h.zeroize();
                    crate::fi::zeroize_barrier();
                }
                Err(UnlockError::PinIncorrect)
            }
        }
    }

    /// §32 P3 timing PAD: run one duress verify on each chip (no read).
    /// Called on a duress-correct unlock to replace the SKIPPED real
    /// verify so the total op-count matches a real unlock (4 verifies +
    /// 2 reads either way). The OPTIGA verify is the matched-LUC twin of
    /// the real F1D0 verify; the SE050 verify twins the real UserID
    /// verify. Best-effort — a transient failure here doesn't fail the
    /// already-successful unlock; it only perturbs the timing pad.
    #[cfg(feature = "duress-pin")]
    fn duress_pad(&mut self, pin: &[u8; 8]) {
        // #855: same derivation as `unlock_duress`, so a duress-correct
        // unlock still runs two derivations and four verifies — the same
        // count as a real one.
        let Ok(creds) = crate::pin_gate::unlock_credentials(WalletRole::Duress, pin) else {
            return;
        };
        let _ = unsafe { self.optiga.duress_verify(&creds.optiga) };
        let _ = self.se050.duress_verify(&creds.se050);
    }

    fn pin_credentials_recomputable(&mut self) -> bool {
        crate::pin_gate::credentials_recomputable()
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
        //
        // #855: neither chip is shown the PIN. Derive this PIN's die-bound
        // credentials and half masks first. With no usable salt on page 125
        // (wiped, never provisioned, or provisioned by pre-#855 firmware)
        // they cannot be recomputed: refuse before any SE traffic.
        // `gated_unlock` already refuses such a wallet before it charges an
        // attempt; this is the backstop for a caller that reaches `unlock`
        // directly or a fault that skipped that check.
        let creds = crate::pin_gate::unlock_credentials(WalletRole::Real, pin).map_err(|_e| {
            secure_log!("[DUAL] PIN credentials unavailable: {:?}", _e);
            unlock_failed_at(1);
            UnlockError::InternalError
        })?;

        let optiga_result = self.optiga.unlock_with_credential(&creds.optiga);

        let se050_result = match &optiga_result {
            Ok(_) | Err(UnlockError::PinIncorrect) => {
                Some(self.se050.unlock_with_credential(&creds.se050))
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
                unlock_failed_at(if matches!(e, UnlockError::PinIncorrect) { 2 } else { 3 });
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
                unlock_failed_at(if matches!(e, UnlockError::PinIncorrect) { 4 } else { 5 });
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
            .map_err(|_| { unlock_failed_at(6); UnlockError::InternalError })?;
        let mut stored_o = crypto::decrypt_entropy_blob(
            &blob_o[..blob_o_len], &master_o
        ).map_err(|_| { unlock_failed_at(7); UnlockError::InternalError })?;
        blob_o.zeroize();
        // #855: the chip stored `half XOR mask`; remove the PIN-keyed mask
        // (outermost layer, so before the optional ML-KEM open below).
        let mut half_o = *creds.mask_optiga.apply(&stored_o);
        stored_o.zeroize();
        // Under the inner wrap, what the SE stored (and we just decrypted) is
        // the 32-byte AES-GCM ciphertext; open it (ct + tag from the ct-store)
        // to recover the real half_O. The borrow in `&half_o` ends before the
        // re-assignment.
        #[cfg(feature = "mlkem-inner-wrap")]
        {
            half_o = crate::pq_wrap::open_half_from_se(
                crate::pq_wrap::HalfId::OptigaHalfO, 0, &half_o,
            )
            .map_err(|_| UnlockError::InternalError)?;
        }

        let mut blob_e = [0u8; 64];
        let blob_e_len = self.se050.read_entropy_blob(&mut blob_e)
            .map_err(|_| { unlock_failed_at(8); UnlockError::InternalError })?;
        // SE050's blob is encrypted under ITS master_secret
        // (`kdf("sphincs-master", half_e, 0)`), not OPTIGA's. The
        // two chips encrypt their caches independently; each must
        // be decrypted with the matching key.
        let mut stored_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_e
        ).map_err(|_| { unlock_failed_at(9); UnlockError::InternalError })?;
        blob_e.zeroize();
        // #855: same for the SE050 half.
        let mut half_e = *creds.mask_se050.apply(&stored_e);
        stored_e.zeroize();
        // Same for half_E on the SE050.
        #[cfg(feature = "mlkem-inner-wrap")]
        {
            half_e = crate::pq_wrap::open_half_from_se(
                crate::pq_wrap::HalfId::Se050HalfE, 0, &half_e,
            )
            .map_err(|_| UnlockError::InternalError)?;
        }
        let mut me = master_e;
        me.zeroize();

        // Reconstruct the full entropy
        let mut full_entropy = xor_32(&half_o, &half_e);
        half_o.zeroize();
        crate::fi::zeroize_barrier();
        half_e.zeroize();
        crate::fi::zeroize_barrier();

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
        if crate::fi::check_true_into_sentinel(|| c1 && c2) != crate::fi::OK_SENTINEL {
            full_entropy.zeroize();
            crate::fi::zeroize_barrier();
            let mut mo = master_o;
            mo.zeroize();
            secure_log!("[DUAL] CRITICAL: reconstructed entropy doesn't match master!");
            unlock_failed_at(10);
            return Err(UnlockError::InternalError);
        }

        // Cache the encrypted full-entropy blob for the signing flow.
        let blob = crypto::encrypt_entropy_blob(&full_entropy, &master_o);
        self.entropy_blob_cache.copy_from_slice(&blob);
        self.blob_cached.set_true();

        full_entropy.zeroize();
        crate::fi::zeroize_barrier();

        secure_log!("[DUAL] Unlocked: entropy reconstructed from XOR split");
        Ok(master_o)
    }

    fn read_entropy_blob(&mut self, buf: &mut [u8]) -> Result<usize, SeError> {
        if !self.blob_cached.is_true_fi() || buf.len() < crypto::ENTROPY_BLOB_LEN {
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
        self.blob_cached.set_false();
        self.optiga.zeroize_caches();
        self.se050.zeroize_caches();
    }

    fn pin_attempt_count(&mut self) -> Option<u8> {
        // OPTIGA exposes a peek-safe counter (E120 in the production
        // `optiga-hw-counter` configuration). The production SE050 UserID
        // policy denies `ReadObjectAttributes` with SW=0x6986, so its leg is
        // `None`; see `Se050::pin_attempt_count_raw`.
        //
        // Combined value: MAX of whatever's available — counters
        // are "attempts USED" (higher = closer to lockout), so the
        // strict aggregate is `max`, not `min`. Reconciliation uses the
        // available count directionally (`se_used > mcu_used`), because the
        // MCU is precharged and may benignly lead. Intra-SE divergence is
        // meaningful only when both legs are actually readable.
        let o = self.optiga.pin_attempt_count();
        let s = self.se050.pin_attempt_count();
        match (o, s) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    fn pin_attempt_counts_divergent(&mut self) -> bool {
        // Tamper signal: OPTIGA and SE050 disagree on remaining attempts
        // even though both reported a value. Only flagged when both
        // Some — None on either side means "no readable counter, no
        // comparison possible," not divergence.
        match (
            self.optiga.pin_attempt_count(),
            self.se050.pin_attempt_count(),
        ) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }

    /// Legacy combined-SE helper for non-key protocol callers. Pull random
    /// bytes from both SEs and XOR-mix them in-place; per-source bytes never
    /// leave this function. Security-critical entropy does not use this
    /// already-combined result: `rng_strong` calls `random_optiga` and
    /// `random_se050` separately and verifies each contribution.
    ///
    /// **Strict (both-or-fail).** Both OPTIGA and SE050 MUST contribute.
    /// If either chip fails to provide entropy we return `Err` — the
    /// caller propagates that. Degrading to a single SE under EMFI / I2C
    /// glitching on one of the two buses would let an attacker reduce entropy to
    /// effectively two sources (STM32 + one SE) without anything
    /// noticing; refusing the call is the loud failure mode.
    fn random(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        let mut tmp = [0u8; 32];
        let mut off = 0;
        while off < buf.len() {
            let len = (buf.len() - off).min(tmp.len());

            // OPTIGA contribution — mandatory.
            self.optiga.random(&mut tmp[..len]).map_err(|_| {
                tmp.zeroize();
                SeError::InternalError
            })?;
            for i in 0..len {
                buf[off + i] ^= tmp[i];
            }
            // SE050 contribution — mandatory.
            tmp.zeroize();
            self.se050.random(&mut tmp[..len]).map_err(|_| {
                tmp.zeroize();
                SeError::InternalError
            })?;
            for i in 0..len {
                buf[off + i] ^= tmp[i];
            }
            tmp.zeroize();

            off += len;
        }
        Ok(())
    }

    fn random_optiga(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.optiga
            .random(buf)
            .map_err(|_| SeError::InternalError)
    }

    fn random_se050(&mut self, buf: &mut [u8]) -> Result<(), SeError> {
        self.se050
            .random(buf)
            .map_err(|_| SeError::InternalError)
    }

    /// Wipe both SEs via their admin recovery paths and clear SRAM caches.
    ///
    /// OPTIGA: `optiga.factory_reset()` overwrites every user OID through
    /// the shielded-connection path (`Change = Auto(F1D0) OR Conf(0xE140)`).
    /// Works even if the user PIN is forgotten. The DHUK-derived PBS remains
    /// reproducible and the shield stays available for re-provisioning; the
    /// user OIDs are now blank. No PBS is stored on flash page 126.
    ///
    /// SE050: delegates to its own `factory_reset_admin` which uses the
    /// admin UserID at 0x7B10_00A0 to delete user objects.
    ///
    /// A best-effort attempt is made on each backend — if one fails we
    /// still try the other and wipe SRAM state.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        // #855: before the first command to either chip, arm the
        // wipe-in-progress flag and destroy the PIN-credential salt. From
        // this point the credentials and masks of this wallet can never be
        // recomputed by this device: a value read out of a chip beforehand
        // cannot be tested against it again, and the halves left on the
        // chips are undecryptable even if a chip-side wipe below fails or is
        // blocked. Callers reset the page-124 counter only through
        // `pin_attempts_reset_after_wipe`, which re-checks that the salt is
        // gone.
        //
        // If the salt could NOT be destroyed (a flash fault), the chip wipes
        // below still run: destroying the halves is the point of a wipe and
        // costs the attacker more, not less. The failure is returned after
        // them, and the counter reset is refused, so the device stays locked
        // out and the next boot wipes again.
        //
        // SAFETY: `&mut self` on the SE store implies the single-threaded
        // secure-world context the page-125 writes require.
        let salt_gone = unsafe { crate::pin_gate::begin_wipe() };

        // #952: the PIN-attempt log is this wallet's history; forget it.
        crate::pin_attempt_log::clear();

        // #949: the off-chain counters and registration flags on page 123
        // belong to this wallet. Erased while the wipe flag is armed and
        // before the SE050 leg erases page 125 (which marks the wipe
        // complete), so a power cut here is resumed by the next boot.
        //
        // SAFETY: same single-threaded secure-world context as above.
        let offchain_result = unsafe { crate::hw::flash::erase_offchain_page_for_wipe() };

        let optiga_result = self.reset_optiga_for_admin();
        let se050_result = self.se050.factory_reset_admin();

        self.zeroize_caches();

        // The SE050 leg erases page 125 (and with it the wipe-in-progress
        // flag) once *its* wipe is confirmed, whatever happened to the
        // OPTIGA leg. If any part of this wipe failed, put the flag back so
        // the next boot resumes it; otherwise a chip could be left holding
        // a wallet that nothing will ever wipe or open. (Found in review.)
        if salt_gone.is_err()
            || offchain_result.is_err()
            || optiga_result.is_err()
            || se050_result.is_err()
        {
            // SAFETY: same single-threaded secure-world context as above;
            // one quad-word program in page 125.
            unsafe {
                if !crate::hw::flash::is_wipe_armed() {
                    let _ = crate::hw::flash::arm_wipe_flag();
                }
            }
        }

        // Surface the first error we saw, but SRAM is zeroized regardless.
        salt_gone.map_err(|()| SeError::InternalError)?;
        offchain_result.map_err(|()| SeError::InternalError)?;
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
    ///    derived the way the DualSE unlock path derives it, the unkeyed
    ///    SHA-256 "sphincs-master" hash of the entropy (so the consistency
    ///    check passes); vk=0xAA, bootstrap_vk=0xBB; test PIN `b"dualwipe"`.
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
        if let Err(e) = self.reset_optiga_for_admin() {
            secure_log!("[DUAL-E2E-ADMIN] step 1: OPTIGA factory_reset error {:?} (continuing)", e);
        }

        // SE050 wipe cascade. Each stage only fires if the prior
        // stage left objects behind.
        //
        //   (a) Admin-auth factory reset (page 125 has admin PIN).
        //       Deletes user UserID + gated data + self-deletes admin
        //       UserID. The production PIN-lockout path.
        //   (b) User-auth factory reset with dev-PIN candidates. Runs
        //       the SE050 user-auth reset, which verifies the UserID
        //       value, deletes user-gated data, AND self-deletes the
        //       user UserID in the same authenticated session. The plain
        //       authenticated iterative sweep (which we tried first
        //       iteration) deletes the data objects but
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
            // Stage (a): admin-auth wipe via the v6 HUK-derived admin
            // PIN (`factory_reset_admin` → `secret_keys::se050_admin_pin`
            // → `derive_into_bhk(...)` — `SAES-CMAC(BHK, …)` in a `bhk`
            // build, `SAES-CMAC(DHUK, …)` with `saes-dhuk`, `HKDF(OTP-
            // master/const, …)` legacy — → `admin_factory_reset` →
            // conditional page-125 erase). This is the only admin-PIN
            // source on v6 chips; the pre-v6 page-125 PIN slot is gone
            // (no `write_admin_pin`).
            let r = self.se050.factory_reset_admin();
            secure_log!("[DUAL-E2E-ADMIN] pre-clean stage (a): factory_reset_admin → {:?}", r.as_ref().err());
            // A failed admin VERIFY leaves the session pending (A3) and
            // every existence check after it would read "absent".
            let _ = self.se050.reinit();

            // Stage (b): nothing to guess (#912). A UserID written by a
            // bench image from #912 on has an admin-delete entry and stage
            // (a) removed it. One that is still here was written earlier.
            if self.se050.is_provisioned() {
                secure_log!(
                    "[DUAL-E2E-ADMIN] pre-clean stage (b): {}",
                    crate::se050::userid_survivor_help(r.is_ok())
                );
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
        //
        // #912: the probe presents this test's credential to whatever
        // wallet is on the chips. If that wallet is not ours it is a wrong
        // value, and a wrong value costs one of the SE050 UserID's ten
        // attempts for good. So probe only when this test's own mark is on
        // page 125 (`hw::flash::mark_multi_unlock_fixture`, left below after
        // a successful provisioning; a reboot keeps it, every completed wipe
        // erases it). A salt record would not do: every flow that provisions
        // writes one. Without the mark, skip straight to the pre-clean,
        // which presents nothing.
        #[cfg(feature = "stm32u585")]
        let wallet_is_ours = crate::hw::flash::multi_unlock_fixture_present();
        #[cfg(not(feature = "stm32u585"))]
        let wallet_is_ours = true;
        let probe = if wallet_is_ours {
            secure_log!("[DUAL-MULTI] probing unlock() to detect prior provisioning...");
            self.unlock(&test_pin)
        } else {
            secure_log!(
                "[DUAL-MULTI] no fixture mark on page 125: not probing (the wallet on the chips, \
                 if any, is not this test's); going to pre-clean"
            );
            Err(UnlockError::InternalError)
        };
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

            if let Err(e) = self.reset_optiga_for_admin() {
                secure_log!("[DUAL-MULTI] pre-clean: OPTIGA factory_reset error {:?} (continuing)", e);
            }

            #[cfg(feature = "stm32u585")]
            unsafe {
                // Admin-auth wipe via the v6 HUK-derived admin PIN
                // (`secret_keys::se050_admin_pin` → `derive_into_bhk`,
                // i.e. BHK in a `bhk` build / DHUK / OTP-legacy).
                let admin_wipe = self.se050.factory_reset_admin();
                secure_log!("[DUAL-MULTI] pre-clean: factory_reset_admin → {:?}", admin_wipe.as_ref().err());
                // A failed admin VERIFY leaves the session pending (A3).
                let _ = self.se050.reinit();
                // #912: nothing is guessed. See the admin-wipe cascade.
                if self.se050.is_provisioned() {
                    secure_log!(
                        "[DUAL-MULTI] pre-clean: {}",
                        crate::se050::userid_survivor_help(admin_wipe.is_ok())
                    );
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

            // Clear a stale wipe flag left by the pre-clean (or by an
            // earlier failed run) BEFORE provisioning. `provision` writes
            // the PIN-credential salt into page 125 (#855); erasing that
            // page afterwards, as this test used to, would destroy the salt
            // of the wallet it just created.
            #[cfg(feature = "stm32u585")]
            unsafe {
                if crate::hw::flash::is_wipe_armed()
                    && crate::hw::flash::erase_admin_page().is_ok()
                {
                    secure_log!("[DUAL-MULTI] cleared stale wipe flag (page 125 erased)");
                }
            }

            secure_log!("[DUAL-MULTI] pre-clean OK; provisioning fresh");
            self.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &test_pin)?;
            secure_log!("[DUAL-MULTI] phase A: provision OK");
            // #912: from here on the wallet on the chips is this test's.
            // Leave the mark the next boot's probe is gated on.
            #[cfg(feature = "stm32u585")]
            // SAFETY: single-threaded secure world; programs one quad-word
            // of page 125.
            if unsafe { crate::hw::flash::mark_multi_unlock_fixture() }.is_err() {
                secure_log!("[DUAL-MULTI] could not leave the fixture mark; the next boot will re-provision");
            }

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

        // Clear stale MCU PIN attempts left over from prior failed
        // `dual-se-admin-wipe-e2e` runs or from our own pre-clean. Without
        // this, the boot-time wipe trigger in `main.rs` re-fires on every
        // reboot, wiping both chips and defeating the "cross-boot
        // already-provisioned" branch this test is meant to exercise.
        //
        // The stale wipe FLAG is cleared before provisioning (above), never
        // here: page 125 now also holds the PIN-credential salt of the
        // wallet this test leaves provisioned (#855).
        #[cfg(feature = "stm32u585")]
        unsafe {
            let _ = crate::hw::flash::pin_attempts_reset_bench();
        }

        Ok(())
    }
}
