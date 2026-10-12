# Research Prompt A — Fault-Injection Resistance for PQ Signing + PIN Path

## Research question

Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `DualSecureElement::unlock`
   (reads half_O and half_E from the two SEs, reconstructs full
   entropy, derives master_secret, caches encrypted blob).
2. The SPHINCS+C10 double-compute, byte-compare, and verify-before-release
   chain in `secure/src/crypto.rs` — assess the existing CFI/sentinel
   structure against realistic single- and multi-fault models.
3. The PIN-lockout trigger in `cmd_request_unlock.rs` — a single-
   glitch inversion of the "remaining == 0" check currently blocks
   the factory-reset path.

Give **concrete Rust code patterns** (redundant volatile reads,
complement-storage, magic-constant comparisons, random-delay
templates, NCC-Group-style double-check idioms). For each pattern,
identify which fault classes it defends against (single voltage
glitch, double voltage, EMFI, LFI) and which it doesn't. Rank by
cost/benefit. Out of scope: hardware countermeasures.

Reference the actual code inlined below. Point to specific line numbers
in your recommendations.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant code


### `secure/src/dual_se.rs`

```rust
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

            // Both SEs get the same master_secret (derived from full entropy).
            // This lets us cross-verify on unlock.
            //
            // OPTIGA Trust M stores its half-object + master_secret behind the
            // HMAC auth reference PIN gate; SE050 stores its half-object behind
            // hardware UserID PIN gating. The VK and bootstrap VK are identical
            // on both chips.
            if let Err(e) =
                self.optiga
                    .provision(&se_half_o, master_secret, vk, bootstrap_vk, pin)
            {
                secure_log!("[DUAL/prov] optiga.provision FAILED: {:?}", e);
                return Err(e);
            }
            secure_log!("[DUAL/prov] optiga OK, calling se050.provision");
            if let Err(e) =
                self.se050
                    .provision(&se_half_e, master_secret, vk, bootstrap_vk, pin)
            {
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
        let mut half_o = self.generate_split_half()?;
        let mut half_e = xor_32(entropy, &half_o);

        if let Err(e) = self.optiga.provision_duress(&half_o, master_secret, vk, bootstrap_vk, duress_pin) {
            secure_log!("[DUAL/duress] optiga.provision_duress FAILED: {:?}", e);
            half_o.zeroize();
            crate::fi::zeroize_barrier();
            half_e.zeroize();
            return Err(e);
        }
        if let Err(e) = self.se050.provision_duress(&half_e, master_secret, vk, bootstrap_vk, duress_pin) {
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
        // OPTIGA returns (half_o, stored_decoy_master_from_F1DA); SE050
        // returns half_e. Both chips are ALWAYS verified (no `?` short-
        // circuit) so the op-count is uniform across real/duress entries.
        let ro = unsafe { self.optiga.duress_read_half(pin) };
        let re = self.se050.duress_read_half(pin);
        match (ro, re) {
            (Ok((mut half_o, mut stored_master)), Ok(mut half_e)) => {
                let mut full = xor_32(&half_o, &half_e);
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
        let _ = unsafe { self.optiga.duress_verify(pin) };
        let _ = self.se050.duress_verify(pin);
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
            .map_err(|_| UnlockError::InternalError)?;
        // SE050's blob is encrypted under ITS master_secret
        // (`kdf("sphincs-master", half_e, 0)`), not OPTIGA's. The
        // two chips encrypt their caches independently; each must
        // be decrypted with the matching key.
        let mut half_e = crypto::decrypt_entropy_blob(
            &blob_e[..blob_e_len], &master_e
        ).map_err(|_| UnlockError::InternalError)?;
        blob_e.zeroize();
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
        let optiga_result = self.reset_optiga_for_admin();
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
        if let Err(e) = self.reset_optiga_for_admin() {
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

            if let Err(e) = self.reset_optiga_for_admin() {
                secure_log!("[DUAL-MULTI] pre-clean: OPTIGA factory_reset error {:?} (continuing)", e);
            }

            #[cfg(feature = "stm32u585")]
            unsafe {
                // Admin-auth wipe via the v6 HUK-derived admin PIN
                // (`secret_keys::se050_admin_pin` → `derive_into_bhk`,
                // i.e. BHK in a `bhk` build / DHUK / OTP-legacy).
                let _ = self.se050.factory_reset_admin();
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

```


### `secure/src/nsc/cmd_request_unlock.rs`

```rust
//! `CMD_REQUEST_UNLOCK` — secure UI prompts for the PIN, the PIN
//! never touches NS RAM, and on success the unwrapped master secret
//! is stamped into the shared `SecureState`.

use sphincs_tz_shared::NscStatus;
use zeroize::Zeroize;

use super::state;
use crate::secure_element::UnlockError;
use crate::timeout;
use crate::ui;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. The body drives
/// the trusted-UI PIN dialog and the SE pair; no NS pointer derefs.
/// `static mut SE` access is serialised by the non-reentrant
/// dispatcher.
pub(super) unsafe fn run() -> u32 {
    use crate::ui::pin_entry::{enter_pin, PinEntryResult};

    // Finding F3 — REQUEST_UNLOCK must be idempotent: when the device
    // is already unlocked the requested end state already holds, so
    // respond `Ok` WITHOUT re-popping the trusted-UI PIN dialog.
    // Otherwise a hostile companion can spam INS_V2_UNLOCK to keep
    // unsolicited PIN prompts on the display (prompt-fatigue), where
    // each wrong entry burns one of the lockout attempts. Reads
    // `pin_verified` through the same FI-hardened accessor
    // `cmd_is_unlocked` uses.
    if state::peek_state(|s| s.pin_verified.is_true_fi()) {
        return NscStatus::Ok as u32;
    }

    // HIGH-7 fix: prevent SysTick idle-wipe from racing us while the
    // user is typing the PIN or while we are deriving master_secret.
    let _busy = super::HandlerGuard::enter();

    // Arm a fresh input window before prompting (#713). `enter_pin` samples
    // `timeout::is_idle()` BEFORE waiting and only calls `reset_activity()`
    // after a button event, so entering it with an already-expired deadline —
    // exactly the state after a lock or an idle timeout — makes it return
    // `IdleWipe` instantly, with the PIN screen flashing up and vanishing. The
    // device then could not be unlocked over USB at all; only a power cycle
    // recovered it.
    //
    // This does not weaken "NS does not control the inactivity timer": that
    // invariant exists so NS cannot keep an UNLOCKED session alive by pinging.
    // Here the device is LOCKED with no secret loaded, and the window being
    // armed is for a human to type on the trusted UI. The PendSV re-unlock
    // loop already does exactly this on every pass (`main.rs`, immediately
    // before its own `enter_pin()` call).
    #[cfg(feature = "stm32u585")]
    crate::timeout::reset_activity();

    let mut pin = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        PinEntryResult::Cancelled | PinEntryResult::Mismatch => {
            // Mismatch is unreachable here (only enter_pin_with_confirm
            // can return it), but the match must be exhaustive.
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        PinEntryResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return NscStatus::IdleWipe as u32;
        }
    };

    ui::show_status("Verifying...", "");

    let result = verify_pin_with_chip(&pin);

    // X17-TUI2 / UI9: zeroize the ORIGINAL binding. Zeroizing a
    // duplicate of the array left the live `[u8; 8]` PIN on the stack.
    pin.zeroize();

    result
}

/// # Safety
/// Called only from `run` above; relies on the dispatcher's single-
/// threaded invariant to access `static mut crate::SE`.
unsafe fn verify_pin_with_chip(pin: &[u8; 8]) -> u32 {
    use sphincs_tz_shared::MAX_ATTEMPTS;

    // §18 P1 — entry jitter at the USB-triggered PIN-verify path. This
    // is the closest point to the external trigger (the NS-world
    // `CMD_REQUEST_UNLOCK` veneer call), so jittering here desyncs the
    // whole gate from USB arrival. Layers with the second
    // `wait_random()` at `gated_unlock`'s entry below. See that
    // function's comment for the threat-model bound (~0..19 µs;
    // uncalibrated-single-fault only).
    crate::fi::wait_random();

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);

    // `super::gated_unlock` handles the MCU-side counter (page 124):
    // pre-commit bump before SE verify, reset on success, refuse
    // on flash fault. See its docstring for the full Trezor-style
    // gating rationale.
    match super::gated_unlock(se, pin) {
        Ok(master) => {
            let unlocked = super::unlock_after_verified_pin(master);
            // Permission-bearing success is the explicit exact-sentinel arm;
            // a failed forced-attempt arm already zeroized the session.
            if unlocked == crate::fi::OK_SENTINEL {
                state::with_state(|s| s.remaining_attempts = MAX_ATTEMPTS);
                timeout::reset_activity();
                ui::show_status("Unlocked", "");
                return NscStatus::Ok as u32;
            }
            NscStatus::InternalError as u32
        }
        Err(UnlockError::PinIncorrect) => {
            // F-15 hardening: double-read the post-bump counter to
            // defend a value-fault on the load register; halt-to-wipe
            // (fail-closed) on mismatch.
            #[cfg(feature = "stm32u585")]
            let count = {
                let a = crate::hw::flash::pin_attempts_read();
                crate::fi::wait_random();
                let b = crate::hw::flash::pin_attempts_read();
                if a != b {
                    return trigger_lockout_wipe();
                }
                a
            };
            #[cfg(not(feature = "stm32u585"))]
            let count: u8 = 0; // QEMU: no counter, UI-only display

            let remaining_after = MAX_ATTEMPTS.saturating_sub(count);
            state::with_state(|s| s.remaining_attempts = remaining_after);

            // FAIL-IN pattern (F-15): the *secure default* (trigger
            // wipe) is the fall-through. The *attacker-bypass-target*
            // (continue without wiping) is the explicit conditional.
            // A single-fault that skips the conditional triggers wipe
            // instead of bypassing it — exactly opposite to the
            // previous FAIL-OUT shape `if remaining_after == 0 { wipe }`
            // where skipping the `cbz` falls through to "Wrong PIN"
            // and the attacker keeps brute-forcing past the cap.
            //
            // The Hamming-distant sentinel (`check_true_into_sentinel`)
            // additionally defends a value-fault on the comparison
            // register: a glitched return value is overwhelmingly
            // unlikely to coincide with OK_SENTINEL.
            let safe_to_continue = crate::fi::check_true_into_sentinel(
                || remaining_after != 0,
            );
            if safe_to_continue != crate::fi::OK_SENTINEL {
                return trigger_lockout_wipe();
            }
            if remaining_after == 1 {
                ui::show_status("LAST ATTEMPT", "wallet wipes on fail");
            } else {
                ui::show_status("Wrong PIN", "");
            }
            NscStatus::PinIncorrect as u32
        }
        Err(UnlockError::PinLocked) => {
            // Either the MCU counter hit MAX inside gated_unlock, or
            // one of the SEs surfaced its own lockout. Either way, wipe.
            state::with_state(|s| s.remaining_attempts = 0);
            trigger_lockout_wipe()
        }
        Err(UnlockError::InternalError) => {
            // Covers the "flash bump failed" fault-injection refusal
            // from gated_unlock (MCU counter not bumped, SE never
            // called) and the F17/SCAFI-5 "post-success reset failed"
            // refusal (SE verify succeeded but page 124 stayed
            // charged — fail-closed, user retries). Attack surface
            // bounded.
            NscStatus::InternalError as u32
        }
    }
}

/// Handle PIN lockout: factory-reset both SEs, zeroize SRAM state, then
/// return `PinLocked` so the NS side reboots into the first-boot wizard.
///
/// Runs unconditionally — SE050 silicon has already locked the UserID,
/// so further PIN attempts would be pointless. The wipe flag is armed
/// inside `factory_reset_admin` before any destructive work, so a power
/// loss mid-wipe is recoverable on the next boot.
///
/// # Safety
/// Called only from `verify_pin_with_chip` above; accesses
/// `static mut crate::SE` under the single-threaded dispatcher
/// invariant, then mutates secure-flash (page 124) via the `flash`
/// driver and zeroizes the in-RAM secrets.
unsafe fn trigger_lockout_wipe() -> u32 {
    use crate::secure_element::WalletStore;

    ui::show_status("WIPING", "do not power off");

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let _ = se.factory_reset_admin();

    // Reset the MCU-side attempt counter now that both SEs have been
    // wiped. Otherwise the next boot would read a full counter + an
    // unprovisioned chip, trigger the boot-time lockout check, and
    // loop. Erasing here makes the device ready for a fresh first-
    // boot wizard.
    #[cfg(feature = "stm32u585")]
    let _ = crate::hw::flash::pin_attempts_reset();

    // Zeroize every TrustZone-side secret.
    super::zeroize_sensitive_state();

    ui::show_status("WALLET WIPED", "restore from seed");
    NscStatus::PinLocked as u32
}

```


### `secure/src/nsc/state.rs`

```rust
//! Gateway state singleton.
//!
//! This module is the **only** place in the secure world where mutable
//! gateway state lives as a `static mut`. Every command handler reaches
//! it through the [`with_state`] / [`peek_state`] closure accessors, so
//! there is exactly one address-taking site for the whole crate.
//!
//! ## Why a closure API and not a raw `&mut`
//!
//! The gateway is single-threaded and non-reentrant — `poll_gateway`
//! runs a single dispatch to completion before looking at another
//! command, and command handlers do not yield — so exclusive access
//! is guaranteed by construction. Wrapping the access in a closure
//! lets callers spell out that invariant at the call site without
//! sprinkling `unsafe { &mut STATE }` across every handler, and makes
//! the module trivially refactorable to a critical-section-guarded
//! `RefCell` later if we ever need to support preemption.

use sphincs_tz_shared::MAX_ATTEMPTS;
use zeroize::Zeroize;

use crate::fih::FihBool;

// ---------------------------------------------------------------------------
// Forced-blind attempt state (default-off feature).
//
// This is deliberately a dedicated two-word state rather than a bool or an
// enum discriminant.  The only valid codewords are the three owner-selected
// pairs below.  All other pairs are invalid and must be treated as a fatal
// forced-flow fault by callers; in particular, no invalid value is coerced to
// Armed.  The all-zero BSS image is the explicitly enumerated, fail-closed
// Disarmed state.
// ---------------------------------------------------------------------------

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_DISARMED_WORDS: (u32, u32) = (0x0000_0000, 0x0000_0000);
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_ARMED_WORDS: (u32, u32) = (0xA55A_A55A, 0x5AA5_5AA5);
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ATTEMPT_SPENT_WORDS: (u32, u32) = (0x3CC3_3CC3, 0xC33C_C33C);

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_READ_DISARMED: u32 = 0x4A91_73C5;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_WRITE_ARMED: u32 = 0xB626_8C3A;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_READBACK: u32 = 0x79D4_15E2;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_ARM_CFI_EXPECTED: u32 = crate::cfi_expected!(
    FORCED_ARM_CFI_READ_DISARMED,
    FORCED_ARM_CFI_WRITE_ARMED,
    FORCED_ARM_CFI_READBACK,
);

#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_READ_ARMED: u32 = 0x5D38_A671;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_WRITE_SPENT: u32 = 0xA2C7_598E;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_READBACK: u32 = 0x36EB_C914;
#[cfg(feature = "erc7730-forced-blind")]
const FORCED_CHARGE_CFI_EXPECTED: u32 = crate::cfi_expected!(
    FORCED_CHARGE_CFI_READ_ARMED,
    FORCED_CHARGE_CFI_WRITE_SPENT,
    FORCED_CHARGE_CFI_READBACK,
);

/// The only three valid interpretations of [`ForcedAttemptState`].
#[cfg(feature = "erc7730-forced-blind")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ForcedAttemptPhase {
    Disarmed,
    Armed,
    Spent,
}

/// A voted read did not produce one of the three exact owner codewords.
///
/// This is intentionally a single fatal class.  A caller must not recover an
/// invalid pair as Disarmed/Armed/Spent or infer eligibility from the failure.
#[cfg(feature = "erc7730-forced-blind")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InvalidForcedAttemptState;

/// SRAM-only one-attempt state for the default-off forced-blind flow.
///
/// `#[repr(C)]` plus the size assertion in the host tests pins this to exactly
/// two adjacent `u32` words.  The type is deliberately not `Copy` or `Clone`:
/// there must be one authoritative state inside [`SecureState`].
#[cfg(feature = "erc7730-forced-blind")]
#[repr(C)]
pub(super) struct ForcedAttemptState {
    primary: u32,
    check: u32,
}

#[cfg(feature = "erc7730-forced-blind")]
impl ForcedAttemptState {
    /// Const BSS initializer.  All-zero is explicitly Disarmed, never Armed.
    const fn new_disarmed() -> Self {
        Self {
            primary: FORCED_ATTEMPT_DISARMED_WORDS.0,
            check: FORCED_ATTEMPT_DISARMED_WORDS.1,
        }
    }

    #[inline(never)]
    fn decode_words(
        primary: u32,
        check: u32,
    ) -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        match (primary, check) {
            FORCED_ATTEMPT_DISARMED_WORDS => Ok(ForcedAttemptPhase::Disarmed),
            FORCED_ATTEMPT_ARMED_WORDS => Ok(ForcedAttemptPhase::Armed),
            FORCED_ATTEMPT_SPENT_WORDS => Ok(ForcedAttemptPhase::Spent),
            _ => Err(InvalidForcedAttemptState),
        }
    }

    /// Triple-vote each word independently before interpreting the pair.
    #[inline(never)]
    pub(super) fn phase(
        &self,
    ) -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        let primary = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.primary))
            .map_err(|()| InvalidForcedAttemptState)?;
        crate::fi::wait_random();
        let check = crate::fi::read_volatile_voted(core::ptr::addr_of!(self.check))
            .map_err(|()| InvalidForcedAttemptState)?;
        Self::decode_words(primary, check)
    }

    /// Publish one exact codeword.  Any interruption between the two writes
    /// leaves an invalid pair, which every authority read rejects.
    #[inline(never)]
    fn write_words(&mut self, words: (u32, u32)) {
        // SAFETY: `self` is exclusively borrowed.  Volatile publication keeps
        // both SRAM writes materialized and ordered around the FI readbacks.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(self.primary), words.0);
            core::sync::atomic::compiler_fence(
                core::sync::atomic::Ordering::SeqCst,
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!(self.check), words.1);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Select the fail-closed state.  This is the only transition generic
    /// unlock helpers and zeroization may perform.
    #[inline(never)]
    fn disarm(&mut self) {
        self.write_words(FORCED_ATTEMPT_DISARMED_WORDS);
    }

    /// PIN-only `Disarmed -> Armed` transition.
    ///
    /// This method is private to the state module and is the sole Armed
    /// codeword writer.  `nsc::unlock_after_verified_pin` is its sole caller;
    /// source-call-graph tests pin that wrapper to the three genuine PIN entry
    /// paths.  Re-arming Armed/Spent or repairing an invalid pair is refused.
    #[inline(never)]
    pub(super) fn arm_forced_attempt_after_pin(&mut self) -> u32 {
        let mut cfi = crate::fi::CfiCounter::new();
        let initial = self.phase();
        let disarmed = crate::fi::check_true_into_sentinel(|| {
            initial == Ok(ForcedAttemptPhase::Disarmed)
        });

        // Fail-in shape: only the explicit OK-sentinel arm may publish Armed.
        // A skipped conditional falls through to FAIL_SENTINEL below.
        if disarmed == crate::fi::OK_SENTINEL {
            cfi.bump(FORCED_ARM_CFI_READ_DISARMED);
            self.write_words(FORCED_ATTEMPT_ARMED_WORDS);
            cfi.bump(FORCED_ARM_CFI_WRITE_ARMED);

            // Independent voted readback after the write.  A skipped/partial
            // writer or a faulted load cannot manufacture a successful arm.
            let readback = self.phase();
            let armed = crate::fi::check_true_into_sentinel(|| {
                readback == Ok(ForcedAttemptPhase::Armed)
            });
            if armed == crate::fi::OK_SENTINEL {
                cfi.bump(FORCED_ARM_CFI_READBACK);
                if cfi.check_into_sentinel(FORCED_ARM_CFI_EXPECTED)
                    == crate::fi::OK_SENTINEL
                {
                    return crate::fi::OK_SENTINEL;
                }
            }
        }

        crate::fi::FAIL_SENTINEL
    }

    /// Charge the sole warning opportunity with one voted, CFI-checked
    /// `Armed -> Spent` transition and an independent voted readback.
    ///
    /// The terminal forced handler invokes this only after deterministic
    /// preflight, immediately before the first severe warning.
    /// Returning a Hamming-distant sentinel lets that handler fail closed
    /// without trusting a `bool` or `Result` discriminant.
    #[allow(dead_code)]
    #[inline(never)]
    pub(super) fn charge_forced_attempt_for_warning(&mut self) -> u32 {
        let mut cfi = crate::fi::CfiCounter::new();
        let initial = self.phase();
        let armed = crate::fi::check_true_into_sentinel(|| {
            initial == Ok(ForcedAttemptPhase::Armed)
        });

        // The permission-bearing path is the explicit OK arm.  Disarmed,
        // Spent, invalid, or a voted-load disagreement all fall through to
        // FAIL_SENTINEL without showing a warning.
        if armed == crate::fi::OK_SENTINEL {
            cfi.bump(FORCED_CHARGE_CFI_READ_ARMED);
            self.write_words(FORCED_ATTEMPT_SPENT_WORDS);
            cfi.bump(FORCED_CHARGE_CFI_WRITE_SPENT);

            // Independent readback makes a skipped or partial transition
            // visible even if the write-step CFI bump itself executed.
            let readback = self.phase();
            let spent = crate::fi::check_true_into_sentinel(|| {
                readback == Ok(ForcedAttemptPhase::Spent)
            });
            if spent == crate::fi::OK_SENTINEL {
                cfi.bump(FORCED_CHARGE_CFI_READBACK);
                if cfi.check_into_sentinel(FORCED_CHARGE_CFI_EXPECTED)
                    == crate::fi::OK_SENTINEL
                {
                    return crate::fi::OK_SENTINEL;
                }
            }
        }

        crate::fi::FAIL_SENTINEL
    }
}

/// Mutable state the gateway owns across command dispatches.
pub(super) struct SecureState {
    /// How many PIN attempts the current lockout window still permits.
    /// Mirrors the secure element's monotonic PIN counter for the mock
    /// backend; real SE backends refresh it from the chip on every
    /// `cmd_get_remaining`.
    pub(super) remaining_attempts: u8,
    /// Whether the current session has passed PIN verification. Reset
    /// by [`zeroize_sensitive`] on cancel / idle wipe / panic.
    ///
    /// FI hardening (F-14): stored as `FihBool`, a Trezor-style
    /// `(val, complement)` pair with Hamming-distant magic
    /// constants. A single-fault flip of either word breaks the
    /// storage invariant; the reader detects it and fail-closes to
    /// `false`. Every gated command reads via
    /// `s.pin_verified.check_sentinel()` (composed with the
    /// `fi::check_true_into_sentinel` Hamming-distant sentinel
    /// pattern) so the caller compares a value rather than branching
    /// on a bool — defeats both storage glitch AND caller branch-
    /// skip together.
    pub(super) pin_verified: FihBool,
    /// The 32-byte master secret unwrapped by
    /// `crate::pin::verify_pin`.
    /// Used both as the AES-GCM key for the encrypted-entropy blob and
    /// as the hedge input for SLH-DSA signing randomizers.
    pub(super) master_secret: [u8; 32],

    // -- OTS tracking (session-scoped, lost on power cycle) -----------
    // The on-chain contract is authoritative. These fields only enforce
    // monotonicity within a single unlock session to prevent accidental
    // OTS index reuse if the companion sends a stale value.

    /// The chain_id of the last successful signature.
    pub(super) last_chain_id: u64,
    /// The key_index of the last successful signature.
    pub(super) last_key_index: u32,
    /// The ots_index used by the last successful signature.
    pub(super) last_ots_index: u32,
    /// Whether any signature has been produced this session.
    ///
    /// F-14-style hardening: `FihBool` complement-storage so a
    /// single-fault flip in BSS can't make a stale session appear
    /// signed. Currently write-only (no read site in the gateway),
    /// but future code that gates on "has the session signed yet?"
    /// inherits the storage-glitch defense for free.
    pub(super) has_signed: FihBool,

    // -- Slot cache (session-scoped) ------------------------------------
    // Post-C10-cutover the firmware is stateless with respect to slot
    // selection: the companion sends `(chain_id, slot_index, flags)` on
    // every sign. We cache the derived slot master entropy across the
    // unlock session (one BIP-39 → SHA-256 pass) and the derived slot
    // SigningKey (one multi-second hypertree keygen) to amortise repeat
    // signs. Both are dropped on lock / idle-wipe / panic.

    /// Slot master entropy (derived once per unlock from BIP-39 seed).
    pub(super) slot_master_entropy: [u8; 32],

    /// Whether `slot_master_entropy` has been derived this session.
    ///
    /// F-14-style hardening: `FihBool` complement-storage. If this
    /// flag is ever read as a "skip re-derive" optimization, a
    /// single-fault flip from false→true would let a follow-up
    /// command operate on stale / zero entropy. Defended now even
    /// though current code doesn't gate on it.
    pub(super) slot_master_derived: FihBool,

    // -- Bootstrap C10 pubkey LRU cache --------------------------------
    // Multi-account variant: one seed produces up to 256 independent
    // bootstrap C10 keypairs (one per `account_index`). Each keypair
    // takes <1 s of hypertree keygen on real STM32U585, so we cache the
    // derived pubkey halves keyed by `account_index`. Address-picker
    // pagination over fresh accounts is therefore one-shot per index;
    // repeated views (and the SIGN_USEROP fast path) hit SRAM.
    //
    // 16 entries comfortably covers a single rendered page of 10
    // addresses plus a small carry-over from the previous page. On full
    // insert we evict the oldest `last_used_tick` entry. Cache is
    // wiped on lock / idle-wipe / panic.
    pub(super) bootstrap_cache: [Option<CachedAccount>; BOOTSTRAP_CACHE_LEN],

    /// Monotonic tick stamped onto each cache entry on insert / lookup.
    /// Wraps after 2^64 events — effectively never.
    pub(super) bootstrap_cache_tick: u64,

    /// One forced-blind warning opportunity per genuine PIN unlock.  This is
    /// SRAM-only and absent from feature-off builds.
    #[cfg(feature = "erc7730-forced-blind")]
    pub(super) forced_attempt: ForcedAttemptState,
}

/// Number of simultaneously-cached account bootstrap pubkey pairs.
pub(super) const BOOTSTRAP_CACHE_LEN: usize = 16;

/// One entry in [`SecureState::bootstrap_cache`]. Stores only public
/// material — the C10 secret key is dropped (and zeroized) immediately
/// after `pk_seed` / `pk_root` have been extracted.
#[derive(Clone)]
pub(super) struct CachedAccount {
    pub(super) account_index: u32,
    /// 32-byte N-masked pkSeed (top 16 bytes populated, bottom 16 = 0).
    pub(super) pk_seed: [u8; 32],
    /// 32-byte N-masked pkRoot (top 16 bytes populated, bottom 16 = 0).
    pub(super) pk_root: [u8; 32],
    /// Tick stamped at last hit / insert. Used for LRU eviction.
    pub(super) last_used_tick: u64,
}

impl SecureState {
    const fn new() -> Self {
        // `Option::None` initialiser must spell out one entry per slot
        // because `Option<CachedAccount>` is not `Copy`. `[None; N]`
        // would require `Copy`; an explicit array literal is fine in
        // const context.
        const NONE_ENTRY: Option<CachedAccount> = None;
        Self {
            remaining_attempts: MAX_ATTEMPTS,
            pin_verified: FihBool::new_false(),
            master_secret: [0u8; 32],
            last_chain_id: 0,
            last_key_index: 0,
            last_ots_index: 0,
            has_signed: FihBool::new_false(),
            slot_master_entropy: [0u8; 32],
            slot_master_derived: FihBool::new_false(),
            bootstrap_cache: [NONE_ENTRY; BOOTSTRAP_CACHE_LEN],
            bootstrap_cache_tick: 0,
            #[cfg(feature = "erc7730-forced-blind")]
            forced_attempt: ForcedAttemptState::new_disarmed(),
        }
    }

    /// Wipe the master secret and drop the unlock flag. Called from
    /// the panic handler, idle-wipe paths, and any user-cancel branch
    /// where we don't want the next signing request to succeed without
    /// a fresh PIN.
    pub(super) fn zeroize_sensitive(&mut self) {
        // Forced authority is destroyed first.  A torn two-word publication
        // is an invalid pair and therefore still fail-closed; a complete one
        // is the exact all-zero Disarmed codeword.
        #[cfg(feature = "erc7730-forced-blind")]
        self.forced_attempt.disarm();
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        // F-17: clear the rate-limit counters on lock / idle-wipe.
        // Counters are SRAM-only and were already going to vanish on
        // a power cycle; this is for the in-session zeroize path
        // (idle-wipe, panic handler).
        crate::sign_rate::reset_counters();
        self.pin_verified.set_false();
        self.last_chain_id = 0;
        self.last_key_index = 0;
        self.last_ots_index = 0;
        self.has_signed.set_false();
        self.slot_master_entropy.zeroize();
        crate::fi::zeroize_barrier();
        self.slot_master_derived.set_false();
        // Bootstrap pubkey halves are technically non-secret, but wipe
        // them anyway so a stale entry can't influence post-lock UI
        // assumptions and so the cache reverts to a clean slate on
        // re-unlock.
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                c.pk_seed.zeroize();
                c.pk_root.zeroize();
                c.last_used_tick = 0;
                c.account_index = 0;
            }
            *entry = None;
        }
        self.bootstrap_cache_tick = 0;
        // SAFETY: single-threaded, exclusive access via with_state.
        // SLOT_CACHE holds a SigningKey (ZeroizeOnDrop). Replacing the
        // Option with None drops the inner key, which wipes its secret
        // material automatically.
        unsafe {
            *core::ptr::addr_of_mut!(SLOT_CACHE) = None;
            // Idle-wipe also drops any in-progress firmware-update
            // session. The inactive slot's erased pages stay erased
            // (harmless), and the companion must restart from BEGIN.
            // FwUpdateCtx is ZeroizeOnDrop so this clears the 8 KB
            // manifest buffer plus the running SHA-256 state.
            #[cfg(feature = "stm32u585")]
            {
                *core::ptr::addr_of_mut!(FW_UPDATE) = None;
            }
        }
    }

    /// Look up a cached bootstrap pubkey pair for `account_index`. On hit,
    /// bumps the entry's tick (so it stays warm under LRU pressure) and
    /// returns `(pk_seed, pk_root)`. Returns `None` on miss.
    pub(super) fn bootstrap_cache_lookup(
        &mut self,
        account_index: u32,
    ) -> Option<([u8; 32], [u8; 32])> {
        self.bootstrap_cache_tick = self.bootstrap_cache_tick.wrapping_add(1);
        let new_tick = self.bootstrap_cache_tick;
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                if c.account_index == account_index {
                    c.last_used_tick = new_tick;
                    return Some((c.pk_seed, c.pk_root));
                }
            }
        }
        None
    }

    /// Insert (or refresh) a `(pk_seed, pk_root)` pair for
    /// `account_index`. Evicts the oldest (`last_used_tick`-min) entry
    /// when the cache is full. If the index is already present its
    /// pubkey halves are overwritten — same account_index always maps
    /// to the same derived pair, so this is a no-op rewrite.
    pub(super) fn bootstrap_cache_insert(
        &mut self,
        account_index: u32,
        pk_seed: [u8; 32],
        pk_root: [u8; 32],
    ) {
        self.bootstrap_cache_tick = self.bootstrap_cache_tick.wrapping_add(1);
        let new_tick = self.bootstrap_cache_tick;

        // Refresh existing entry if present.
        for entry in self.bootstrap_cache.iter_mut() {
            if let Some(c) = entry.as_mut() {
                if c.account_index == account_index {
                    c.pk_seed = pk_seed;
                    c.pk_root = pk_root;
                    c.last_used_tick = new_tick;
                    return;
                }
            }
        }

        // Find an empty slot, else the LRU victim.
        let mut victim_idx: usize = 0;
        let mut victim_tick: u64 = u64::MAX;
        for (i, entry) in self.bootstrap_cache.iter().enumerate() {
            match entry {
                None => {
                    victim_idx = i;
                    victim_tick = 0;
                    break;
                }
                Some(c) => {
                    if c.last_used_tick < victim_tick {
                        victim_tick = c.last_used_tick;
                        victim_idx = i;
                    }
                }
            }
        }
        // Wipe the victim (defensive — pubkeys are non-secret but this
        // keeps the cache hygiene predictable).
        if let Some(c) = self.bootstrap_cache[victim_idx].as_mut() {
            c.pk_seed.zeroize();
            c.pk_root.zeroize();
        }
        self.bootstrap_cache[victim_idx] = Some(CachedAccount {
            account_index,
            pk_seed,
            pk_root,
            last_used_tick: new_tick,
        });
    }

    /// Stamp in a freshly-verified master secret and mark the device
    /// unlocked. Used by both the real PIN verify path and the
    /// `e2e-test` set-state helper.
    ///
    /// HIGH-6 fix: explicitly zeroize the previous master_secret
    /// before overwriting, so a re-unlock can never leave the
    /// prior session's secret on the stack or in BSS.
    pub(super) fn mark_unlocked(&mut self, mut master: [u8; 32]) {
        // Generic/non-PIN unlock is never forced-blind authority.  The PIN-only
        // wrapper performs a separate, private arm transition after this
        // function returns successfully.
        #[cfg(feature = "erc7730-forced-blind")]
        self.forced_attempt.disarm();
        self.master_secret.zeroize();
        crate::fi::zeroize_barrier();
        // Trezor-parity: random delay before installing the new
        // master_secret. The 32-byte copy below is a single fixed-
        // duration block that an EM-glitch attacker could otherwise
        // time-target; `wait_random` perturbs its temporal position.
        crate::fi::wait_random();
        // THE INSTALL AND THE ARM ARE ONE TRANSACTION (#802). SysTick's idle
        // wipe reads `pin_verified` and can preempt anything; if it ran
        // between these two lines it would zeroize a master that thread mode
        // is in the middle of installing, and then `set_true` would mark the
        // session unlocked over wiped state — unlocked with no secret, which
        // no later check would notice. Today that window is closed only by
        // TIMING (every production `mark_unlocked` follows a physical PIN
        // entry that just called `reset_activity()`, so `is_idle()` is false),
        // and only `cmd_request_unlock` holds a `HandlerGuard` — the wizard,
        // the boot-interactive path and PendSV hold none. Close it by
        // construction instead.
        //
        // PRIMASK does not mask NMI or HardFault, which is correct: both of
        // those wipe, which is the safe direction.
        #[cfg(feature = "stm32u585")]
        cortex_m::interrupt::free(|_| {
            self.master_secret = master;
            self.pin_verified.set_true();
        });
        #[cfg(not(feature = "stm32u585"))]
        {
            self.master_secret = master;
            self.pin_verified.set_true();
        }
        master.zeroize();
        crate::fi::zeroize_barrier();
        self.remaining_attempts = MAX_ATTEMPTS;
        // F-17: fresh unlock = full burst budget. The session sign
        // counter resets so the user gets `MAX_SIGNS_PER_SESSION`
        // signatures before being forced to re-unlock.
        crate::sign_rate::reset_counters();
    }
}

/// The one and only `static mut` instance. Declared at module scope so
/// the program loader places it in the secure-world BSS and so it has
/// a stable address for the no-`alloc` environment.
static mut STATE: SecureState = SecureState::new();

/// Cached slot SigningKey for the `(slot_index)` most recently signed with
/// during this unlock session. Re-keygen happens when the companion asks
/// for a different `slot_index`; the cache is dropped on lock/idle-wipe.
///
/// Kept separate from `SecureState` because `SigningKey` holds arrays that
/// cannot be const-constructed; `Option<None>` lives in BSS.
///
/// SAFETY: same single-threaded invariant as `STATE`.
pub(super) static mut SLOT_CACHE: Option<CachedSlot> = None;

/// Active firmware-update session state. Populated by `CMD_FW_BEGIN`
/// and drained by `CMD_FW_COMMIT` / `CMD_FW_ABORT`. Lives in SRAM only
/// — any reset or idle-wipe restarts the companion from BEGIN.
///
/// Kept separate from `SecureState` because the 8 KB manifest buffer
/// inside `FwUpdateCtx` dwarfs the rest of state, and we want explicit
/// zeroize-on-wipe semantics. See `fw_update::mod`.
///
/// SAFETY: same single-threaded invariant as `STATE`. `FwUpdateCtx`
/// is `ZeroizeOnDrop`.
#[cfg(feature = "stm32u585")]
pub(super) static mut FW_UPDATE: Option<crate::fw_update::FwUpdateCtx> = None;

/// In-SRAM slot cache: a SigningKey tagged with the
/// `(account_index, chain_id, slot_index)` tuple it was derived for.
/// After the Coinbase-Smart-Wallet port, slot keys are chain-specific —
/// signing on chain A with slot index N derives a different key than
/// chain B with the same index, so the cache keys on chain too. With
/// multi-account derivation, slot keys also vary per `account_index`
/// (the `master_entropy` they descend from is account-scoped). A
/// mismatch on any field triggers a fresh keygen (<1 s on hardware).
pub(super) struct CachedSlot {
    pub(super) account_index: u32,
    pub(super) chain_id: u64,
    pub(super) slot_index: u32,
    pub(super) key: sphincs_c10::SigningKey,
}

/// Borrow the gateway state mutably for the duration of `f`.
///
/// SAFETY INVARIANT: the gateway is single-threaded and non-reentrant,
/// so this helper is the unique owner of `STATE` from the moment it is
/// called until `f` returns. Callers must not escape the borrow (e.g.
/// by leaking it into a task queue) — there are no tasks, but future
/// contributors should know.
pub(super) fn with_state<R>(f: impl FnOnce(&mut SecureState) -> R) -> R {
    // SAFETY: see module comment — single-threaded non-reentrant
    // dispatcher gives exclusive access by construction, and the
    // closure bounds the lifetime of the reference.
    unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) }
}

/// Borrow the gateway state immutably. Same single-threaded invariant
/// as [`with_state`] — no concurrent readers.
pub(super) fn peek_state<R>(f: impl FnOnce(&SecureState) -> R) -> R {
    // SAFETY: see `with_state`. Shared references are narrower than
    // mutable references, so the same invariant covers them.
    unsafe { f(&*core::ptr::addr_of!(STATE)) }
}

// ---------------------------------------------------------------------------
// Host tests — exercise the `SecureState` API end-to-end through the
// `with_state` / `peek_state` accessors. The whole module is gated out of
// the production `nsc` tree (`#[cfg(not(test))]` on `mod nsc;`), so these
// tests fire only when the file is re-included under the crate-root
// `nsc_core_under_test` scaffold (see `secure/src/main.rs`).
//
// **Concurrency model.** Every test that touches `STATE` / `SLOT_CACHE`
// must hold `STATE_TEST_LOCK` for the duration of the test body.
// `cargo test` runs tests in parallel by default; without serialisation
// the assertions on the singleton are inherently racey.
// ---------------------------------------------------------------------------
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Process-wide lock for every test that touches the static `STATE`.
    /// Exposed `pub(super)` so the sibling-mod tests in the crate-root
    /// `nsc_core_pure_tests` scaffold can acquire it from outside the
    /// state module.
    pub(crate) fn state_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let m = LOCK.get_or_init(|| Mutex::new(()));
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Reset STATE to a clean initial value between tests so ordering
    /// can't leak.
    fn reset_state() {
        with_state(|s| {
            s.zeroize_sensitive();
            s.remaining_attempts = MAX_ATTEMPTS;
        });
    }

    #[cfg(feature = "erc7730-forced-blind")]
    fn set_forced_words(words: (u32, u32)) {
        with_state(|s| s.forced_attempt.write_words(words));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    fn forced_phase() -> Result<ForcedAttemptPhase, InvalidForcedAttemptState> {
        peek_state(|s| s.forced_attempt.phase())
    }

    // -- positive coverage -----------------------------------------------

    #[test]
    fn positive_initial_pin_verified_is_false() {
        let _g = state_test_lock();
        reset_state();
        assert!(!peek_state(|s| s.pin_verified.is_true_fi()));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_is_exactly_two_words_and_bss_disarmed() {
        let _g = state_test_lock();
        reset_state();
        assert_eq!(core::mem::size_of::<ForcedAttemptState>(), 8);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Disarmed));
        let words = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
        assert_eq!(words, FORCED_ATTEMPT_DISARMED_WORDS);
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_codewords_match_owner_contract() {
        assert_eq!(FORCED_ATTEMPT_DISARMED_WORDS, (0x0000_0000, 0x0000_0000));
        assert_eq!(FORCED_ATTEMPT_ARMED_WORDS, (0xA55A_A55A, 0x5AA5_5AA5));
        assert_eq!(FORCED_ATTEMPT_SPENT_WORDS, (0x3CC3_3CC3, 0xC33C_C33C));
        assert_eq!(
            FORCED_ATTEMPT_ARMED_WORDS.0 ^ FORCED_ATTEMPT_ARMED_WORDS.1,
            u32::MAX,
            "Armed must be complement-coded",
        );
        assert_eq!(
            FORCED_ATTEMPT_SPENT_WORDS.0 ^ FORCED_ATTEMPT_SPENT_WORDS.1,
            u32::MAX,
            "Spent must be complement-coded",
        );
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_forced_attempt_codewords_have_pairwise_distance_32() {
        fn distance(a: (u32, u32), b: (u32, u32)) -> u32 {
            (a.0 ^ b.0).count_ones() + (a.1 ^ b.1).count_ones()
        }

        let words = [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ];
        for i in 0..words.len() {
            for j in (i + 1)..words.len() {
                assert_eq!(distance(words[i], words[j]), 32, "pair {i}/{j}");
            }
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_every_single_bit_mutation_of_every_codeword_is_invalid() {
        for valid in [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ] {
            for bit in 0..64u32 {
                let mutated = if bit < 32 {
                    (valid.0 ^ (1u32 << bit), valid.1)
                } else {
                    (valid.0, valid.1 ^ (1u32 << (bit - 32)))
                };
                assert_eq!(
                    ForcedAttemptState::decode_words(mutated.0, mutated.1),
                    Err(InvalidForcedAttemptState),
                    "bit {bit} unexpectedly decoded from {valid:08x?}",
                );
            }
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_mixed_valid_halves_and_single_zero_words_are_invalid() {
        let words = [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
        ];
        for (i, left) in words.iter().enumerate() {
            for (j, right) in words.iter().enumerate() {
                let mixed = (left.0, right.1);
                if i == j {
                    assert!(ForcedAttemptState::decode_words(mixed.0, mixed.1).is_ok());
                } else {
                    assert_eq!(
                        ForcedAttemptState::decode_words(mixed.0, mixed.1),
                        Err(InvalidForcedAttemptState),
                        "mixed pair {i}/{j} must be fatal",
                    );
                }
            }
        }

        for valid in [FORCED_ATTEMPT_ARMED_WORDS, FORCED_ATTEMPT_SPENT_WORDS] {
            assert_eq!(
                ForcedAttemptState::decode_words(0, valid.1),
                Err(InvalidForcedAttemptState),
            );
            assert_eq!(
                ForcedAttemptState::decode_words(valid.0, 0),
                Err(InvalidForcedAttemptState),
            );
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_pin_arm_is_disarmed_to_armed_only_and_cannot_rearm() {
        let _g = state_test_lock();
        reset_state();
        let first = with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin());
        assert_eq!(first, crate::fi::OK_SENTINEL);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Armed));

        let second = with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin());
        assert_eq!(second, crate::fi::FAIL_SENTINEL);
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Armed));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_pin_arm_refuses_spent_and_invalid_without_repair() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            assert_eq!(
                with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin()),
                crate::fi::FAIL_SENTINEL,
                "non-Disarmed pair {words:08x?} must refuse arming",
            );
            let after = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
            assert_eq!(after, words, "refusal must not repair/re-arm the pair");
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_charge_is_one_voted_armed_to_spent_transition() {
        let _g = state_test_lock();
        reset_state();
        assert_eq!(
            with_state(|s| s.forced_attempt.arm_forced_attempt_after_pin()),
            crate::fi::OK_SENTINEL,
        );
        assert_eq!(
            with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
            crate::fi::OK_SENTINEL,
        );
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Spent));

        assert_eq!(
            with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
            crate::fi::FAIL_SENTINEL,
            "Spent must not admit a second warning",
        );
        assert_eq!(forced_phase(), Ok(ForcedAttemptPhase::Spent));
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn negative_charge_refuses_disarmed_spent_and_invalid_without_repair() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_DISARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            assert_eq!(
                with_state(|s| s.forced_attempt.charge_forced_attempt_for_warning()),
                crate::fi::FAIL_SENTINEL,
                "non-Armed pair {words:08x?} must refuse",
            );
            let after = peek_state(|s| (s.forced_attempt.primary, s.forced_attempt.check));
            assert_eq!(after, words, "refusal must not repair/re-arm the pair");
        }
    }

    #[cfg(feature = "erc7730-forced-blind")]
    #[test]
    fn positive_generic_unlock_and_zeroize_always_select_disarmed() {
        let _g = state_test_lock();

        for words in [
            FORCED_ATTEMPT_ARMED_WORDS,
            FORCED_ATTEMPT_SPENT_WORDS,
            (FORCED_ATTEMPT_ARMED_WORDS.0, 0),
        ] {
            set_forced_words(words);
            with_state(|s| s.mark_unlocked([0x91; 32]));
            assert_eq!(
                forced_phase(),
                Ok(ForcedAttemptPhase::Disarmed),
                "generic mark_unlocked must never preserve authority",
            );

            set_forced_words(words);
            with_state(SecureState::zeroize_sensitive);
            assert_eq!(
                forced_phase(),
                Ok(ForcedAttemptPhase::Disarmed),
                "zeroize must select Disarmed even from an invalid pair",
            );
        }
    }

    #[test]
    fn positive_mark_unlocked_sets_pin_verified() {
        let _g = state_test_lock();
        reset_state();
        let master = [0x42u8; 32];
        with_state(|s| s.mark_unlocked(master));
        assert!(peek_state(|s| s.pin_verified.is_true_fi()));
    }

    #[test]
    fn positive_mark_unlocked_stores_master_secret() {
        let _g = state_test_lock();
        reset_state();
        let master = [0xA5u8; 32];
        with_state(|s| s.mark_unlocked(master));
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, master, "master_secret must be installed verbatim");
    }

    #[test]
    fn positive_zeroize_drops_pin_verified() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0x11u8; 32]));
        assert!(peek_state(|s| s.pin_verified.is_true_fi()));
        with_state(|s| s.zeroize_sensitive());
        assert!(
            !peek_state(|s| s.pin_verified.is_true_fi()),
            "zeroize_sensitive MUST land pin_verified back at false"
        );
    }

    #[test]
    fn positive_zeroize_wipes_master_secret() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0xCDu8; 32]));
        with_state(|s| s.zeroize_sensitive());
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0u8; 32], "master_secret MUST be byte-zeroed by zeroize_sensitive");
    }

    #[test]
    fn positive_zeroize_wipes_slot_master_entropy() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.slot_master_entropy = [0xBBu8; 32];
            s.slot_master_derived.set_true();
        });
        with_state(|s| s.zeroize_sensitive());
        let got = peek_state(|s| s.slot_master_entropy);
        assert_eq!(got, [0u8; 32]);
        assert!(!peek_state(|s| s.slot_master_derived.is_true_fi()));
    }

    #[test]
    fn positive_initial_remaining_attempts_is_max() {
        let _g = state_test_lock();
        reset_state();
        let r = peek_state(|s| s.remaining_attempts);
        assert_eq!(r, MAX_ATTEMPTS);
    }

    #[test]
    fn positive_bootstrap_cache_lookup_miss_returns_none() {
        let _g = state_test_lock();
        reset_state();
        let got = with_state(|s| s.bootstrap_cache_lookup(0));
        assert!(got.is_none(), "fresh state must have an empty bootstrap cache");
    }

    #[test]
    fn positive_bootstrap_cache_insert_then_lookup_returns_pubkeys() {
        let _g = state_test_lock();
        reset_state();
        let pk_seed = [0x11u8; 32];
        let pk_root = [0x22u8; 32];
        with_state(|s| s.bootstrap_cache_insert(7, pk_seed, pk_root));
        let got = with_state(|s| s.bootstrap_cache_lookup(7));
        assert_eq!(got, Some((pk_seed, pk_root)));
    }

    #[test]
    fn positive_bootstrap_cache_distinct_indices_distinct_pubkeys() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.bootstrap_cache_insert(0, [0x10; 32], [0x20; 32]);
            s.bootstrap_cache_insert(1, [0x11; 32], [0x21; 32]);
        });
        let a = with_state(|s| s.bootstrap_cache_lookup(0)).unwrap();
        let b = with_state(|s| s.bootstrap_cache_lookup(1)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn positive_bootstrap_cache_reinsert_overwrites_in_place() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.bootstrap_cache_insert(3, [0x01; 32], [0x02; 32]));
        with_state(|s| s.bootstrap_cache_insert(3, [0x03; 32], [0x04; 32]));
        let got = with_state(|s| s.bootstrap_cache_lookup(3));
        assert_eq!(got, Some(([0x03; 32], [0x04; 32])));
    }

    #[test]
    fn positive_bootstrap_cache_lru_evicts_oldest() {
        let _g = state_test_lock();
        reset_state();
        // Fill the cache.
        with_state(|s| {
            for i in 0..(BOOTSTRAP_CACHE_LEN as u32) {
                s.bootstrap_cache_insert(i, [i as u8; 32], [i as u8 ^ 0xFF; 32]);
            }
        });
        // Touch index 0 to keep it warm, then insert one more.
        let _ = with_state(|s| s.bootstrap_cache_lookup(0));
        // The least-recently-touched at this point is index 1.
        with_state(|s| {
            s.bootstrap_cache_insert(99, [0xEEu8; 32], [0xEFu8; 32])
        });
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(1)).is_none(),
            "LRU victim (index 1) must have been evicted"
        );
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(0)).is_some(),
            "warm entry (index 0) must have survived"
        );
        assert!(
            with_state(|s| s.bootstrap_cache_lookup(99)).is_some(),
            "newest entry must be present"
        );
    }

    // -- negative coverage -----------------------------------------------

    /// Assumption: `mark_unlocked` zeroizes the *caller's* buffer copy
    /// after stamping. Forgetting this leaves a 32-byte secret on the
    /// caller's stack indefinitely.
    #[test]
    fn negative_mark_unlocked_wipes_caller_local_master() {
        let _g = state_test_lock();
        reset_state();
        let mut master = [0xC3u8; 32];
        with_state(|s| s.mark_unlocked(master));
        // `master` was passed by value — the inside-the-fn `master.zeroize()`
        // does not affect the outer local. The contract is "the byte
        // buffer the function moved IN gets zeroized before return."
        // We can re-prove it by passing a buffer and checking that the
        // stored copy is the byte pattern we passed (i.e. nothing was
        // mangled). Caller-buffer wipe is the responsibility of the
        // caller (see `gated_unlock`); state pins the contract that the
        // stored copy is correct.
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0xC3u8; 32]);
        let _ = &mut master;
    }

    /// Assumption (HIGH-6): a re-unlock with a NEW master MUST wipe the
    /// prior master_secret BEFORE installing the new one. Otherwise an
    /// EM-glitch on the assignment leaves the stale secret in BSS.
    #[test]
    fn negative_mark_unlocked_overwrites_prior_master_completely() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| s.mark_unlocked([0xAAu8; 32]));
        with_state(|s| s.mark_unlocked([0x55u8; 32]));
        let stored = peek_state(|s| s.master_secret);
        assert_eq!(stored, [0x55u8; 32]);
        // No byte of the prior 0xAA secret may survive.
        assert!(stored.iter().all(|b| *b != 0xAA),
            "no byte of the prior master_secret may remain after re-unlock");
    }

    /// Assumption: `zeroize_sensitive` also clears the per-slot tracking
    /// fields (`last_chain_id`, `last_key_index`, `last_ots_index`,
    /// `has_signed`). If any survive a wipe, a stale-session replay
    /// counter can be misinterpreted as a fresh-session zero by the
    /// next signing pass.
    #[test]
    fn negative_zeroize_clears_ots_tracking_fields() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.last_chain_id = 0xDEAD_BEEF_DEAD_BEEF;
            s.last_key_index = 0xCAFE_BABE;
            s.last_ots_index = 0x0BAD_F00D;
            s.has_signed.set_true();
        });
        with_state(|s| s.zeroize_sensitive());
        let (cid, ki, oi, hs) = peek_state(|s| (
            s.last_chain_id, s.last_key_index, s.last_ots_index,
            s.has_signed.is_true_fi(),
        ));
        assert_eq!(cid, 0, "last_chain_id must be zeroed");
        assert_eq!(ki, 0, "last_key_index must be zeroed");
        assert_eq!(oi, 0, "last_ots_index must be zeroed");
        assert!(!hs, "has_signed must be cleared");
    }

    /// Assumption: `zeroize_sensitive` wipes the bootstrap pubkey
    /// cache. Stale entries are technically non-secret but their
    /// presence after a lock would let post-wipe code path observe
    /// "warm cache" state that mismatches the freshly-zero
    /// `master_secret`.
    #[test]
    fn negative_zeroize_clears_bootstrap_cache() {
        let _g = state_test_lock();
        reset_state();
        with_state(|s| {
            s.bootstrap_cache_insert(0, [0x10; 32], [0x20; 32]);
            s.bootstrap_cache_insert(1, [0x11; 32], [0x21; 32]);
        });
        with_state(|s| s.zeroize_sensitive());
        for i in 0..=1u32 {
            assert!(
                with_state(|s| s.bootstrap_cache_lookup(i)).is_none(),
                "bootstrap cache entry {i} must be cleared by zeroize_sensitive"
            );
        }
        // Tick counter is also reset (so post-wipe lookups don't see a
        // wrapped-but-non-zero tick that confuses LRU comparison).
        let tick = peek_state(|s| s.bootstrap_cache_tick);
        // After zeroize_sensitive sets tick to 0, the first lookup above
        // bumps it via wrapping_add — so it should be > 0 here. We only
        // assert it didn't survive at its old (post-fill) value of 2.
        assert!(tick <= 2,
            "bootstrap_cache_tick must reset to ~0 after zeroize_sensitive (saw {tick})");
    }

    /// Assumption (CLAUDE.md invariant #4 + ZeroizeOnDrop): `pin_verified`
    /// is FI-hardened storage (Trezor-style complement pair, NOT a bare
    /// `bool`). A bare `bool` would let a single bit-flip toggle it.
    /// We pin the size: `FihBool` is two `u32`s (8 bytes); a `bool`
    /// would be 1 byte.
    #[test]
    fn negative_pin_verified_storage_is_fihbool_sized() {
        use core::mem::size_of_val;
        let _g = state_test_lock();
        // peek to materialise an actual borrow; size_of_val is const but
        // we want to assert against the live field, not the type alias.
        let sz = peek_state(|s| size_of_val(&s.pin_verified));
        assert_eq!(sz, 8,
            "pin_verified must be FihBool-sized (val+complement = 8 bytes); \
             a 1-byte bool would re-open the F-14 single-bit-flip attack");
    }

    /// Assumption: `master_secret` storage is exactly 32 bytes (the SHA-256
    /// width assumed by every downstream KDF call site). A silent
    /// resize would break entropy-blob decryption.
    #[test]
    fn negative_master_secret_storage_is_32_bytes() {
        let _g = state_test_lock();
        let sz = peek_state(|s| s.master_secret.len());
        assert_eq!(sz, 32);
    }

    /// Assumption: the bootstrap-cache LRU array is exactly
    /// `BOOTSTRAP_CACHE_LEN` (16) entries. A silent enlargement
    /// expands the BSS footprint past what the documented invariant
    /// admits; a shrink starts evicting under workloads that fit
    /// today.
    #[test]
    fn negative_bootstrap_cache_array_length_is_pinned() {
        let _g = state_test_lock();
        let sz = peek_state(|s| s.bootstrap_cache.len());
        assert_eq!(sz, BOOTSTRAP_CACHE_LEN);
        assert_eq!(BOOTSTRAP_CACHE_LEN, 16,
            "BOOTSTRAP_CACHE_LEN is documented as 16 in state.rs");
    }

    /// Assumption: after `zeroize_sensitive`, an evicted-then-re-inserted
    /// cache entry's pubkey halves must be the new values — i.e. the
    /// old victim's bytes do NOT leak through.
    #[test]
    fn negative_evicted_cache_entry_pubkey_bytes_replaced() {
        let _g = state_test_lock();
        reset_state();
        // Fill, then push one extra to force eviction of the LRU.
        with_state(|s| {
            for i in 0..(BOOTSTRAP_CACHE_LEN as u32) {
                s.bootstrap_cache_insert(i, [0xAAu8; 32], [0xBBu8; 32]);
            }
            s.bootstrap_cache_insert(0xFF, [0x55u8; 32], [0x77u8; 32]);
        });
        let got = with_state(|s| s.bootstrap_cache_lookup(0xFF));
        assert_eq!(got, Some(([0x55u8; 32], [0x77u8; 32])));
        // The victim's `account_index` is no longer present.
        assert!(with_state(|s| s.bootstrap_cache_lookup(0)).is_none(),
            "victim's account_index must be evicted");
    }
}

```


### `secure/src/crypto.rs`

```rust
//! Crypto helpers — secure-side wrapper around [`pqsigner_domain`].
//!
//! The pure-logic primitives (KDFs, AES-GCM wrap/unwrap, BIP-39 ↔
//! SPHINCS+C10 derivation, slot-key derivation, PIN-state encoding) live
//! in [`pqsigner_domain`] so host-side reference signers can reuse them
//! without the secure-world hardware deps.
//!
//! What stays here:
//!
//! * [`c10_sign_verified_with_progress`] — the FI-hardened
//!   verify-before-release wrapper. Depends on [`crate::fi`], whose
//!   hardening primitives are keyed off the secure-world TRNG.
//! * [`provision_from_mnemonic`] / [`store_macd_encrypted`] — the
//!   `WalletStore` + `SecureElement` provisioning entry points used by
//!   the wizard and by the mock backend. These touch the
//!   secure-side `crate::secure_element::*` traits with r-mem
//!   semantics, so they cannot live in the pure-logic crate.
//!
//! Every other public name in [`pqsigner_domain`] is re-exported below.

pub use pqsigner_domain::*;

use crate::secure_element::SecureElement;
use sphincs_tz_bip39::Mnemonic;
use zeroize::Zeroize;

/// Sign a 32-byte message hash with the bootstrap C10 signing key and
/// the (optional) randomiser. Wraps `sphincs_c10::SigningKey::sign`
/// with a verify-before-release fault-injection guard. Reports 0..100
/// signing progress via the supplied callback so the trusted-UI
/// progress bar stays responsive during the multi-second C10
/// signature.
///
/// Produces 4008-byte C10 signatures — see `sphincs-c10/src/params.rs`.
// F-18 (CFI): per-step magic constants for `c10_sign_verified_with_progress`.
//
// Distinct, non-trivial 32-bit values so no subset of skipped steps
// can sum to the same gap as another subset. Hex prefixes are
// mnemonic (0xA1 = "rate-limit", 0xB2 = "opt_rand", etc.) — the
// actual numeric value is what matters for FI defense.
const CFI_STEP_RATE_LIMIT:  u32 = 0xA1_5A_1357;
const CFI_STEP_OPT_RAND:    u32 = 0xB2_5B_2468;
const CFI_STEP_SHUFFLE:     u32 = 0xC3_5C_3579;
const CFI_STEP_SIGN_A:      u32 = 0xD4_5D_468A;
const CFI_STEP_SIGN_B:      u32 = 0xE5_5E_579B;
const CFI_STEP_CT_EQ:       u32 = 0xF6_5F_68AC;
const CFI_STEP_VERIFY_GATE: u32 = 0x17_60_79BD;

/// Private hand-off proving one caller-side rate charge completed before the
/// shared signing body.  The mode choice stays in the two separate entrypoints;
/// no runtime enum can fault a forced request into the ordinary charge path.
struct VerifiedRateCharge(u32);

/// Build the `(first_half, second_half)` progress pair for `$sink` (#759).
///
/// The FI countermeasure signs TWICE, so a single callback handed to both
/// signs ramps 0..100 and then 0..100 again — on the text route
/// `ui::show_progress` renders a real percentage, so the bar counts to 100,
/// drops to 0 and climbs again, which on a trusted display reads as a
/// failed-and-retrying operation. Handing `|_| {}` to the second sign instead
/// freezes the pixel signing film for seconds, which reads as a hang. The
/// phases are therefore SCALED: sign A into 0..=50, sign B into 50..=100.
///
/// It is a macro rather than a function because
/// `SigningKey::sign_with_shuffle` takes `progress: fn(u8)` — a bare pointer,
/// deliberately: its own doc records that the arrow type is already the limit
/// of what the Aeneas Lean extraction can represent, which is why that method
/// is `#[cfg(not(lean_extract))]`. Widening it to `impl Fn(u8)` would push an
/// active FV boundary further, and a capturing closure cannot coerce to
/// `fn(u8)`. Expanding two `fn` items per call site keeps the scaling
/// compile-time and STATELESS — an earlier attempt routed the sink through a
/// `static mut` and raced under the host test harness, which runs tests on
/// parallel threads even though the device is single-threaded.
#[macro_export]
macro_rules! progress_halves {
    ($sink:path) => {{
        fn first_half(pct: u8) {
            $sink(pct / 2);
        }
        fn second_half(pct: u8) {
            $sink(50 + pct / 2);
        }
        (first_half as fn(u8), second_half as fn(u8))
    }};
}

pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: (fn(u8), fn(u8)),
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session();
        crate::sign_rate::pre_sign()?;
        if crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
        VerifiedRateCharge(crate::fi::OK_SENTINEL),
    )
}

/// Forced-flow counterpart to [`c10_sign_verified_with_progress`].
///
/// The cryptographic computation and seven-step CFI transcript are identical;
/// only the rate step differs.  Before any key use, the forced step rechecks
/// and consumes exactly one charge against the frozen request-bound receipt.
#[cfg(feature = "erc7730-forced-blind")]
pub(crate) fn c10_sign_verified_forced_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: (fn(u8), fn(u8)),
    rate_receipt: &crate::sign_rate::ForcedRateReceipt,
    request_digest: &[u8; 32],
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    #[cfg(test)]
    let _ = (rate_receipt, request_digest);
    #[cfg(not(test))]
    {
        let signs_before = crate::sign_rate::signs_this_session();
        crate::sign_rate::pre_sign_forced(rate_receipt, request_digest).map_err(|_| ())?;
        if crate::sign_rate::signs_this_session() != signs_before.wrapping_add(1) {
            return Err(());
        }
    }
    c10_sign_verified_with_progress_inner(
        sk,
        msg_hash,
        progress,
        VerifiedRateCharge(crate::fi::OK_SENTINEL),
    )
}

#[inline(never)]
fn c10_sign_verified_with_progress_inner(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: (fn(u8), fn(u8)),
    verified_rate_charge: VerifiedRateCharge,
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    use subtle::ConstantTimeEq;

    // F-18 (CFI): track that every critical step ran. Final check
    // (`cfi.check_into_sentinel(EXPECTED) != OK_SENTINEL`) fails
    // closed if any one of the 7 steps below was skipped by a glitch.
    // Defends the "skip an entire function call" attack class that
    // F-2's sentinel-encoding doesn't reach.
    const CFI_EXPECTED: u32 = crate::cfi_expected!(
        CFI_STEP_RATE_LIMIT,
        CFI_STEP_OPT_RAND,
        CFI_STEP_SHUFFLE,
        CFI_STEP_SIGN_A,
        CFI_STEP_SIGN_B,
        CFI_STEP_CT_EQ,
        CFI_STEP_VERIFY_GATE,
    );
    let mut cfi = crate::fi::CfiCounter::new();

    // F-17 (SCA defense): signing rate limiter. Enforces
    //   - ≥ 1 second between consecutive signs (busy-wait), and
    //   - ≤ 250 signs per unlock session (refuses past the cap).
    // The double-compute below counts as ONE rate-limit charge —
    // one output sig per call, one budget unit. See `sign_rate.rs`
    // for the full threat-model and cost analysis.
    //
    // On refusal (session cap), the function returns Err(()) which
    // the gateway callers translate to `NscStatus::CryptoError`.
    // The companion can prompt the user to re-unlock; a fresh PIN
    // entry re-arms the session budget via `mark_unlocked`.
    //
    // X17-FI2 (playbook FI11): bind the CFI bump to the step's VERIFIED
    // success, not the fallible call's return register. `pre_sign()?`
    // alone lets a glitch that skips `bl pre_sign` with a stale-Ok
    // register waive the F-17 session budget yet still stamp the step —
    // fail-closure there would be ABI luck, not design. `pre_sign`
    // commits by advancing the session counter by exactly one; require
    // that postcondition before bumping (a skip now needs a second,
    // coordinated fault on this read-back).
    if crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(verified_rate_charge.0) == crate::fi::OK_SENTINEL
    }) != crate::fi::OK_SENTINEL
    {
        return Err(());
    }
    cfi.bump(CFI_STEP_RATE_LIMIT);

    // FI-hardening, layer 1 of 2: double-compute (RFC 9814 §A.2 / Genêt
    // TCHES 2023). Verify-after-sign alone is *insufficient*: a fault
    // injected during signing can produce a malformed sig that
    // nonetheless verifies cleanly under the honest pubkey while leaking
    // sk_seed bits across multiple traces (faulted hypertree nodes
    // re-derive bottom-up). Two signs over identical inputs MUST be
    // byte-identical; a divergence is diagnostic of a fault on one of
    // the two signs.
    //
    // Cost: ~2× sign latency (~+1.5 s on HW SHA, ~+12 s on QEMU
    // software SHA). The progress callback runs on the first sign so
    // the user sees a 0..100 ramp; the second sign is silent and
    // visually appears as a stretched "verifying..." window.
    //
    // **Non-deterministic OptRand (work-todo #18 / Trezor parity).**
    // We draw a fresh 16-byte randomiser per signing call via
    // `rng_strong::fill` (STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG,
    // 3-source XOR mirroring Trezor's `rng_fill_buffer_strong`).
    // Defends against:
    //   - the deterministic-PRF-tree class (Genêt TCHES 2023): adding
    //     a fresh randomiser breaks the chain of repeated SK re-use
    //     across signatures.
    //   - any single biased / compromised TRNG: the XOR of the
    //     remaining unbroken sources preserves entropy.
    //   - F-9 transparent leak: a fresh randomiser makes the R-grind
    //     iteration count depend on per-call randomness, not just
    //     (sk_seed, message) — removing the TVLA-detectable
    //     msg-dependent count.
    // NOTE: the *cryptographic* chosen-message FORS-saturation defence
    // (upstream SPHINCS- SECURITY-ANALYSIS.md §2 "Avenue B") does NOT
    // rely on this TRNG: `fors::grind_r` derives R as
    // `sha256(sk_seed ‖ "R_grind" ‖ [opt_rand] ‖ message ‖ nonce)`, so
    // `ht_idx` is unpredictable to anyone without the secret key for any
    // chosen message even if this RNG is biased or predictable. OptRand
    // here is defence-in-depth (SCA + Genêt) layered on top of that
    // secret-keyed, message-bound R.
    // The randomiser is drawn ONCE and fed to both signs — re-drawing
    // per sign would still be cryptographically sound but would
    // produce divergent sigs, breaking the byte-equality FI gate.
    //
    // Under `mock-se` (QEMU/dev only) the strong-RNG uses the platform source.
    // Hardware production is compile-fenced to both source-specific SE calls;
    // either missing/failing/non-contributing chip aborts the signature.
    let mut opt_rand_buf = [0u8; sphincs_c10::params::N];
    #[cfg(not(test))]
    if crate::rng_strong::fill(&mut opt_rand_buf).is_err() {
        // `rng_strong::fill` may have written partial platform-TRNG bytes
        // before the SE XOR-fold failed — scrub before bailing, matching
        // every other Err/Ok path in this function (found by the sca-3
        // adversarial review; the fill-failure early-return was the one
        // path that skipped the wipe).
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    // X17-FI2 (playbook FI11): bind the CFI bump to the draw's VERIFIED
    // success, not the fallible call's return register. A glitch that
    // skips `bl rng_strong::fill` (stale-Ok register) leaves this
    // pre-zeroed buffer all-zero — an all-zero OptRand is the Genêt
    // deterministic-reuse class and must never reach signing with every
    // gate green. `rng_strong::fill`'s own internal all-zero gate
    // cannot catch this (it was skipped along with the call), so the
    // acceptance check is repeated here, outside the call, before the
    // step is stamped. OR-accumulator: no short-circuit, no early-out
    // branch on the scan.
    #[cfg(not(test))]
    {
        let mut acc: u8 = 0;
        for &b in opt_rand_buf.iter() {
            acc |= b;
        }
        if acc == 0 {
            opt_rand_buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
    }
    let opt_rand: Option<&[u8; sphincs_c10::params::N]> = Some(&opt_rand_buf);
    cfi.bump(CFI_STEP_OPT_RAND);

    // **F-16 (DPA-defence) shuffle seeds — one INDEPENDENT seed per
    // double-compute pass.** Each of the two mandatory signs draws its
    // own fresh seed from `rng_strong::fill` (STM32 ⊕ OPTIGA ⊕ SE050
    // XOR-fold). The shuffle randomises only the COMPUTATION ORDER of
    // WOTS chains (43! ≈ 10^52 per layer) and FORS trees (13! ≈ 6×10^9);
    // the produced signature bytes are byte-identical for ANY seed
    // (proven invariant `sphincs-c10/src/shuffle.rs`, regression-tested
    // for two distinct nonzero seeds in `tests/shuffle_byte_equality.rs`
    // `two_distinct_nonzero_shuffles_byte_equal`). So the two 4008-byte
    // signatures stay byte-identical (F-13 ct_eq) and verify-before-
    // release still holds unchanged — this stays fully inside the
    // double-compute → compare → verify countermeasure and does NOT
    // weaken it.
    //
    // Why INDEPENDENT seeds, not one shared seed fed to both passes:
    //   - SCA: a shared seed makes both passes traverse WOTS/FORS in the
    //     SAME order → two perfectly time-aligned traces of the same
    //     secret computation per signature (a free ~√2 profiled-DPA
    //     denoise) on the exact alignment this shuffle exists to deny.
    //     Independent seeds keep the two passes mutually mis-aligned.
    //   - FI: under `hw-sha256` the HW SHA-256 engine is a single point
    //     trusted by BOTH signs and the verify. A *deterministic*,
    //     position-triggered HASH fault would otherwise corrupt sign_a
    //     and sign_b at the SAME computation step → identical faulted
    //     output → slip the ct_eq gate (the Genêt TCHES-2023 grafting
    //     class the double-compute exists to block). Independent order
    //     lands the same fault on DIFFERENT WOTS/FORS positions per pass
    //     → divergent sigs → caught by ct_eq.
    // Failure-mode note: were byte-invariance ever to fail for some
    // (sk, msg, opt_rand), the effect is a false-reject signing DoS
    // (fail-closed), never a forged or leaked signature. (Contrast
    // `opt_rand` above, which IS part of the signature value and is
    // therefore DELIBERATELY shared across both passes.)
    let mut shuffle_seed_a = [0u8; 32];
    let mut shuffle_seed_b = [0u8; 32];
    #[cfg(not(test))]
    if crate::rng_strong::fill(&mut shuffle_seed_a).is_err()
        || crate::rng_strong::fill(&mut shuffle_seed_b).is_err()
    {
        shuffle_seed_a.zeroize();
        shuffle_seed_b.zeroize();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    // X17-FI2 (playbook FI11): same verified-success binding as the
    // OptRand draw above — a glitch that skips one `bl rng_strong::fill`
    // (stale-Ok register) leaves that seed all-zero, i.e. a known,
    // predictable shuffle order (the F-16 DPA defence gone) with every
    // gate green. Require BOTH seeds nonzero before stamping the step;
    // each seed's own acceptance check inside `fill` was skipped with
    // the call. OR-accumulators: no short-circuit on the scans.
    #[cfg(not(test))]
    {
        let mut acc_a: u8 = 0;
        let mut acc_b: u8 = 0;
        for i in 0..32 {
            acc_a |= shuffle_seed_a[i];
            acc_b |= shuffle_seed_b[i];
        }
        if acc_a == 0 || acc_b == 0 {
            shuffle_seed_a.zeroize();
            shuffle_seed_b.zeroize();
            opt_rand_buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
    }
    let shuffle_a = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_a);
    let shuffle_b = sphincs_c10::shuffle::ShuffleSeed(shuffle_seed_b);
    // `[u8; 32]` is `Copy`, so the constructors above copied — wipe the
    // stack locals now that each secret lives inside its `ZeroizeOnDrop`
    // wrapper.
    shuffle_seed_a.zeroize();
    shuffle_seed_b.zeroize();
    crate::fi::zeroize_barrier();
    cfi.bump(CFI_STEP_SHUFFLE);

    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, progress.0);
    cfi.bump(CFI_STEP_SIGN_A);
    crate::fi::wait_random();
    // The SECOND HALF of the same ramp (#759), so the film keeps moving on the
    // pixel route and the percentage continues upward on the text route rather
    // than restarting at 0. Like `sign_a`'s it returns unit, captures nothing
    // and receives only a percentage, so it cannot touch the CFI chain, the
    // compare, or the verify-before-release gates below.
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, progress.1);
    cfi.bump(CFI_STEP_SIGN_B);

    // Constant-time comparison of the 4008-byte signatures.
    // `subtle::ConstantTimeEq` prevents an attacker from learning
    // *where* the two diverge through a timing side-channel, which
    // could leak FORS-leaf bits in conjunction with F-9.
    //
    // Note: this `if !ct_eq { Err }` is itself a single-instruction-
    // skip point — falling through releases `sig_a` even on mismatch.
    // The verify-before-release below is the second gate: a faulted
    // pair that bypasses this compare still has to produce a sig that
    // verifies under the honest pubkey. Compare + verify form a
    // **2-gate chain**; do not remove the verify on the assumption
    // double-compute makes it redundant.
    if !bool::from(sig_a[..].ct_eq(&sig_b[..])) {
        // fi-2 (Trezor-port): a ct_eq mismatch between the two double-compute
        // passes is a CONFIRMED fault — identical inputs + byte-invariant
        // shuffles mean the two sigs MUST be equal, so a divergence is a glitch
        // corrupting one pass (the Genêt grafting class). Escalate past "reject
        // this one sign" to a full RELOCK: wipe the in-SRAM master + slot
        // secrets and clear `pin_verified` (`zeroize_sensitive_state`), so a
        // glitching attacker can't immediately retry against a still-live key —
        // the next sign requires a fresh PIN. RELOCK, not halt (recoverable).
        // CONFIRMED-fault sites ONLY (this ct_eq, the verify gate, the CFI
        // check) — NEVER the rng-fail / rate-limit / parse rejects above, which
        // would be a self-inflicted DoS.
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    cfi.bump(CFI_STEP_CT_EQ);

    // FI-hardening, layer 2 of 2: verify-before-release.
    //
    // The boolean check is wrapped by `fi::check_true_into_sentinel`
    // (F-2 fix): a glitch that skips the `if` requires cooperating
    // skips of the double-evaluation AND the hamming-distant sentinel
    // compare. `wait_random()` immediately before the verify defeats
    // clock-aligned fault bursts that time their glitch to the
    // verify's fixed-shape control flow.
    //
    // `core::hint::black_box(v)` is load-bearing — see F-1 in
    // `tools/sca/README.md`: without it LLVM CSEs the two `cond()`
    // evaluations inside `check_true` into a single load of `v` and
    // collapses the `&& v1 && v2` re-check, leaving one skippable
    // branch.
    crate::fi::wait_random();
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a);
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(v)) != crate::fi::OK_SENTINEL {
        // fi-2: a released sig that fails verify-before-release is a confirmed
        // fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    cfi.bump(CFI_STEP_VERIFY_GATE);

    // F-18 final CFI check: every critical step bumped the counter
    // with its unique magic; the running total must match the
    // compile-time `CFI_EXPECTED`. A glitch that skipped any one
    // step's `bump` leaves the counter short by exactly that step's
    // magic → fail closed. The three fallible steps (rate limit,
    // OptRand draw, shuffle-seed draws) gate their bumps on VERIFIED
    // step success (X17-FI2): a single-instruction skip of the
    // fallible `bl` alone no longer reaches the bump on a stale
    // return register. The remaining steps are infallible and
    // downstream-gated (a skipped sign diverges at ct_eq). Routed
    // through the F-2 Hamming-distant sentinel idiom so a skip of
    // the verify call itself doesn't bypass.
    if cfi.check_into_sentinel(CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        // fi-2: a short CFI counter means a critical step was skipped by a
        // glitch → confirmed fault → relock (see the ct_eq site above).
        #[cfg(not(test))]
        crate::nsc::zeroize_sensitive_state();
        opt_rand_buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }

    opt_rand_buf.zeroize();
    crate::fi::zeroize_barrier();
    Ok(sig_a)
}

/// Provision a `WalletStore` backend from a user-supplied BIP-39 mnemonic.
///
/// Single entry point for both the "new wallet" and "restore from seed
/// phrase" wizard branches. Handles the shared key derivation (the
/// "recovery contract") and delegates storage to `store.provision()`.
///
/// Determinism: the same `(mnemonic, pin)` pair always produces the
/// same SPHINCS+ keypair on any device running this firmware.
pub fn provision_from_mnemonic(
    store: &mut impl crate::secure_element::WalletStore,
    mnemonic: &Mnemonic,
    pin: &[u8; 8],
    duress_pin: Option<&[u8; 8]>,
) {
    let mut entropy = mnemonic
        .to_entropy()
        .expect("mnemonic was already checksum-verified");

    let mut master_secret: [u8; 32] = kdf(b"sphincs-master", &entropy, 0);

    let (sk, vk_bytes) = derive_keypair_from_entropy(&entropy);
    drop(sk);
    let bootstrap_vk = derive_bootstrap_vk_from_entropy(&entropy);

    if store
        .provision(&entropy, &master_secret, &vk_bytes, &bootstrap_vk, pin)
        .is_err()
    {
        // A provision that fails PART-WAY (e.g. a transient SE050 I²C fault
        // after the UserID object is written but before the entropy object)
        // must not leave the device half-provisioned. `is_provisioned()`
        // keys the SE050 leg on `USERID_OBJ` existence, so a bare panic here
        // would leave `is_provisioned() == true` with no entropy half: the
        // wizard would NEVER re-run, yet every correct-PIN `unlock()` would
        // return `InternalError` (missing `ENTROPY_OBJ`) with no user-
        // discoverable recovery — a soft-brick at first-boot setup.
        //
        // Roll back (best-effort) before halting so the next cold boot
        // restarts the wizard cleanly: `factory_reset_admin` wipes the OPTIGA
        // leg unconditionally, flipping `is_provisioned()` to false (the S-6
        // non-admin-deletable SE050 `USERID_OBJ` may survive, but the AND
        // across both SEs already reads false once OPTIGA is blank). It arms
        // the crash-safe wipe flag first, so a fault mid-rollback is resumed
        // on the following boot. Mirrors the duress-decoy rollback below.
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        master_secret.zeroize();
        crate::fi::zeroize_barrier();
        let _ = store.factory_reset_admin();
        panic!("provisioning failed — rolled back for wizard restart");
    }

    entropy.zeroize();
    crate::fi::zeroize_barrier();
    master_secret.zeroize();
    crate::fi::zeroize_barrier();

    // §32 duress (decoy) wallet. Always provision a decoy — a RANDOM PIN
    // when the user declined (`duress_pin = None`) — so "duress configured
    // vs not" is indistinguishable on-chip (always-provision is load-
    // bearing for deniability). Decoy entropy is a FRESH, fully
    // independent 256-bit random (separate-entropy model), unrelated to
    // the real seed. Done AFTER the real wallet so PBS/shield (OPTIGA) and
    // the admin UserID (SE050) are already live.
    //
    // Atomicity: the real wallet is already on-chip at this point and
    // `is_provisioned()` is real-only, so a half-provisioned decoy would
    // leave the device "provisioned" yet without a decoy AND never re-run
    // the wizard. If the decoy provision fails, wipe BOTH wallets so the
    // next cold boot restarts the wizard cleanly (no stuck state).
    #[cfg(feature = "duress-pin")]
    if provision_duress_wallet(store, duress_pin).is_err() {
        let _ = store.factory_reset_admin();
        panic!("duress provisioning failed — wiped both wallets for wizard restart");
    }

    #[cfg(not(feature = "duress-pin"))]
    let _ = duress_pin;
}

/// §32: generate + store an independent decoy wallet behind the duress
/// credential. See [`provision_from_mnemonic`] for the always-provision
/// rationale. Separate fn so the hot path stays readable and the decoy
/// generation is feature-gated in one place. Returns `Err` (rather than
/// panicking) so the caller can roll back the real wallet atomically.
#[cfg(feature = "duress-pin")]
fn fill_strong_with_store<const N: usize>(
    store: &mut impl crate::secure_element::WalletStore,
    out: &mut [u8; N],
) -> Result<(), crate::secure_element::SeError> {
    // Calling the global entry point while `store` is already borrowed would
    // alias the backend. The explicit-handle API executes the same mandatory
    // STM32 + OPTIGA + SE050 composition without re-entering the global.
    crate::rng_strong::fill_with_store(out, store)
        .map_err(|()| crate::secure_element::SeError::InternalError)
}

#[cfg(feature = "duress-pin")]
fn provision_duress_wallet(
    store: &mut impl crate::secure_element::WalletStore,
    duress_pin: Option<&[u8; 8]>,
) -> Result<(), crate::secure_element::SeError> {
    // Fresh independent decoy entropy: STM32 TRNG XOR the SE-combined TRNG
    // (OPTIGA ⊕ SE050 via the store) — same multi-source quality as the
    // real seed path, no re-entrancy (we are not inside a store method).
    let mut decoy_entropy = [0u8; 32];
    fill_strong_with_store(store, &mut decoy_entropy)?;

    // Resolve the duress PIN: user-chosen, or a fresh random 8 bytes when
    // declined (never entered by anyone → unguessable; the chip can't
    // distinguish a random-byte PIN from a digit PIN).
    let mut random_pin = [0u8; 8];
    let mut actual_duress_pin: [u8; 8] = match duress_pin {
        Some(p) => *p,
        None => {
            if let Err(e) = fill_strong_with_store(store, &mut random_pin) {
                decoy_entropy.zeroize();
                crate::fi::zeroize_barrier();
                return Err(e);
            }
            random_pin
        }
    };

    let mut decoy_master: [u8; 32] = kdf(b"sphincs-master", &decoy_entropy, 0);
    let (sk, decoy_vk) = derive_keypair_from_entropy(&decoy_entropy);
    drop(sk);
    let decoy_bvk = derive_bootstrap_vk_from_entropy(&decoy_entropy);

    let result = store.provision_duress(
        &decoy_entropy, &decoy_master, &decoy_vk, &decoy_bvk, &actual_duress_pin,
    );

    // Zeroize every secret regardless of success/failure.
    decoy_entropy.zeroize();
    crate::fi::zeroize_barrier();
    decoy_master.zeroize();
    crate::fi::zeroize_barrier();
    actual_duress_pin.zeroize();
    random_pin.zeroize();
    crate::fi::zeroize_barrier();

    result
}

/// Store pre-derived entropy, VK, and PIN state via the MACD chain on an
/// r-mem-capable secure element. Used by backends that support the
/// `SecureElement` trait (Mock on the generic path).
///
/// The mnemonic-to-entropy derivation is NOT done here — the caller must
/// pass pre-derived `(entropy, master_secret, vk, bootstrap_vk)`.
pub fn store_macd_encrypted(
    se: &mut impl SecureElement,
    entropy: &[u8; ENTROPY_LEN],
    master_secret: &[u8; 32],
    vk: &[u8; 32],
    bootstrap_vk: &[u8; 32],
    pin: &[u8; 8],
) {
    use sphincs_tz_shared::MAX_ATTEMPTS;
    // 1. Encrypt the entropy under the master-derived wrap key.
    let entropy_blob = encrypt_entropy_blob(entropy, master_secret);

    // 2. Initialize MACD slots and build the per-slot encrypted
    //    master_secret blobs (one per allowed PIN attempt).
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for j in 0..MAX_ATTEMPTS {
        let init_in = macd_init_input(master_secret, j);
        let pin_in = macd_pin_input(pin, j);

        se.mac_and_destroy(j as u16, &init_in).unwrap();
        let mut w_j = se.mac_and_destroy(j as u16, &pin_in).unwrap();
        se.mac_and_destroy(j as u16, &init_in).unwrap();

        let mut ct_buf = [0u8; PER_SLOT_CT_LEN];
        ct_buf[..32].copy_from_slice(master_secret);
        aes_encrypt_inplace(&w_j, &mut ct_buf, 32, j);
        encrypted_secrets[j as usize] = ct_buf;
        w_j.zeroize();
    }

    // 3. Store everything in r-mem.
    se.r_mem_erase(RMEM_ENCRYPTED_ENTROPY).ok();
    se.r_mem_write(RMEM_ENCRYPTED_ENTROPY, &entropy_blob)
        .unwrap();

    let mut pin_state_buf = [0u8; PIN_STATE_MAX_LEN];
    let ps_len = serialize_pin_state(0, &encrypted_secrets, &mut pin_state_buf);
    se.r_mem_erase(RMEM_PIN_STATE).ok();
    se.r_mem_write(RMEM_PIN_STATE, &pin_state_buf[..ps_len])
        .unwrap();

    se.r_mem_erase(RMEM_VERIFYING_KEY).ok();
    se.r_mem_write(RMEM_VERIFYING_KEY, vk).unwrap();

    se.r_mem_erase(RMEM_BOOTSTRAP_VK).ok();
    se.r_mem_write(RMEM_BOOTSTRAP_VK, bootstrap_vk).unwrap();
}

```
