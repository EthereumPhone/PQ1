# Research Prompt A — Fault-Injection Resistance for PQ Signing + PIN Path

## Research question

Given the 2024-2025 state of voltage / EMFI / laser fault injection
against STM32 Cortex-M33 designs, what is the minimum set of
**software** glitch countermeasures we should add to these three flows:

1. The seed XOR-reconstruction code path in `DualSecureElement::unlock`
   (reads half_O and half_E from the two SEs, reconstructs full
   entropy, derives master_secret, caches encrypted blob).
2. The SLH-DSA signature verify-before-release guard in
   `sign_and_emit.rs` — currently a single compare that should be
   double-glitch-resistant.
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

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

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

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

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

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

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
        // Generate a random mask for the XOR split.
        // half_O = random 32 bytes (stored on OPTIGA Trust M)
        // half_E = entropy XOR half_O (stored on SE050)
        // Reconstruction: half_O XOR half_E = entropy
        let mut half_o = [0u8; 32];
        crate::rng::fill(&mut half_o).map_err(|_| SeError::InternalError)?;
        let half_e = xor_32(entropy, &half_o);

        // Both SEs get the same master_secret (derived from full entropy).
        // This lets us cross-verify on unlock.
        //
        // OPTIGA Trust M stores half_O as its "entropy" and master_secret
        // behind the HMAC auth reference PIN gate.
        // SE050 stores half_E as its "entropy" behind hardware UserID PIN gating.
        //
        // The VK and bootstrap VK are identical on both chips.
        self.optiga.provision(&half_o, master_secret, vk, bootstrap_vk, pin)?;
        self.se050.provision(&half_e, master_secret, vk, bootstrap_vk, pin)?;

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

    /// Delegate SE050 wipe to its WalletStore impl (handles admin PIN,
    /// wipe flag, admin-auth delete, flash erase). Then erase PBS to
    /// orphan OPTIGA from this STM32 (no shielded channel without PBS
    /// means no reads of half_O), and zeroize all SRAM state.
    fn factory_reset_admin(&mut self) -> Result<(), SeError> {
        let _ = self.se050.factory_reset_admin();

        #[cfg(feature = "stm32u585")]
        unsafe {
            let _ = crate::hw::flash::erase_pbs_page();
        }

        self.zeroize_caches();
        secure_log!("[DUAL] Factory reset complete — SE050 wiped, PBS erased");
        Ok(())
    }
}

```


### `secure/src/nsc/sign_and_emit.rs`

```rust
//! Shared "decrypt entropy → derive signing key → hedged SPHINCS+C7 sign
//! → write signature to NS" tail used by every signing command.
//!
//! Before this module existed every `cmd_*` signing path had its own
//! near-duplicate copy of the tail, and every new gateway command
//! meant pasting another one. Hoisting it into a single helper means:
//!
//!   * Adding a new signing flavour (new EIP-712 protocol, new
//!     clear-sign variant, …) is a five-line change in the new
//!     `cmd_*.rs`: compute a 32-byte message hash, validate the out
//!     pointer, hand both to [`decrypt_and_sign`], done.
//!   * Security-critical changes to the hedge / randomizer / zeroize
//!     pattern happen in one place, not three.
//!
//! The helper is only called once per command dispatch, so it owns
//! the SigningKey for the smallest possible window — the stack slot
//! is wiped by sphincs_c7's `ZeroizeOnDrop` when the function returns.

use sphincs_tz_shared::{NscStatus, SIGNATURE_LEN, WRAPPER_HEADER_LEN};
use zeroize::Zeroize;

use super::state::SecureState;

/// End-to-end "produce a signature over `msg_hash` and drop it on
/// `sig_ptr`" helper.
///
/// The caller must have:
///
///   * verified that the device is unlocked (`state.pin_verified`);
///   * validated `sig_ptr` via
///     [`super::ptr_validate::validate_ns_write_ptr`] with a length of
///     [`SIGNATURE_LEN`];
///   * gotten through trusted-UI confirmation.
///
/// On success the secure-to-NS signature copy is complete and the
/// trusted UI shows `success_banner`.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `SIGNATURE_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn decrypt_and_sign(
    state: &SecureState,
    msg_hash: &[u8; 32],
    sig_ptr: *mut u8,
    success_banner: &str,
) -> u32 {
    // 1. Read the encrypted entropy blob from the SE.
    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut entropy_blob) {
            Ok(len) => len,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };

    // 2. Decrypt the entropy using the master secret unwrapped from
    //    PIN entry.
    let mut entropy = match crate::crypto::decrypt_entropy_blob(
        &entropy_blob[..entropy_blob_len],
        &state.master_secret,
    ) {
        Ok(e) => e,
        Err(_) => {
            entropy_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    entropy_blob.zeroize();

    // 3. Read the cached default VK from r-mem to extract pk_root.
    //    This avoids the expensive hypertree rebuild (~10-15s) by
    //    using SigningKey::from_parts with the cached pk_root.
    let mut vk_buf = [0u8; 32];
    {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        if se.read_vk(&mut vk_buf).is_err() {
            entropy.zeroize();
            return NscStatus::InternalError as u32;
        }
    }
    let mut cached_pk_root = [0u8; 16];
    cached_pk_root.copy_from_slice(&vk_buf[16..32]);

    // 4. Re-derive the SPHINCS+C7 signing key from the entropy +
    //    cached pk_root. BIP-39 chain (PBKDF2 + 2x Keccak) is fast;
    //    from_parts skips the hypertree rebuild.
    let signing_key = crate::crypto::derive_signing_key_from_entropy_fast(
        &entropy,
        &cached_pk_root,
    );
    entropy.zeroize();

    // 5. Hedged sign: mix the chip-bound master secret into the per-sig
    //    randomizer so the same message produces different signatures
    //    across different unlocks.
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&state.master_secret, msg_hash, &mut rand_buf);

    let sig = signing_key.sign(msg_hash, Some(&rand_buf));

    // 6. Write the 3,704-byte signature to NS memory, byte-at-a-time
    //    via volatile writes (so the compiler can't fold the copy into
    //    a memcpy that skips unmapped pages or similar shenanigans).
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(i), sig[i]);
    }

    // 7. Wipe the per-sig randomizer. The SigningKey goes out of scope
    //    at the end of this function and sphincs_c7 zeroizes on drop.
    rand_buf.zeroize();

    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    // Brief pause so the user sees "Signed", then restore idle screen.
    for _ in 0..3_000_000u32 { cortex_m::asm::nop(); }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// v2 wrapper variant: writes a 73-byte PQSignatureWrapper header
/// (signer_type + key_index + ots_index + pk_seed_padded + pk_root_padded)
/// followed by the 3,704-byte raw SPHINCS+C7 signature. Total output:
/// `WRAPPER_TOTAL_LEN` (3,777) bytes.
///
/// The caller must have validated `sig_ptr` for `WRAPPER_TOTAL_LEN` bytes.
///
/// SAFETY: `sig_ptr` must point at a pre-validated `WRAPPER_TOTAL_LEN`-byte
/// NS-writable region.
pub(super) unsafe fn decrypt_and_sign_wrapped(
    state: &SecureState,
    msg_hash: &[u8; 32],
    sig_ptr: *mut u8,
    signer_type: u8,
    chain_id: u64,
    key_index: u32,
    ots_index: u32,
    success_banner: &str,
) -> u32 {
    // 1. Read the encrypted entropy blob from the SE.
    let mut entropy_blob = [0u8; 64];
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut entropy_blob) {
            Ok(len) => len,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };

    // 2. Decrypt the entropy.
    let mut entropy = match crate::crypto::decrypt_entropy_blob(
        &entropy_blob[..entropy_blob_len],
        &state.master_secret,
    ) {
        Ok(e) => e,
        Err(_) => {
            entropy_blob.zeroize();
            return NscStatus::CryptoError as u32;
        }
    };
    entropy_blob.zeroize();

    // 3. Derive the correct signing key based on signer_type.
    //    BOOTSTRAP: use cached VK from r-mem for fast path (from_parts).
    //    MAIN: per-chain, per-epoch key — no cached VK, full keygen required.
    let signing_key = if signer_type == sphincs_tz_shared::SIGNER_BOOTSTRAP {
        // Bootstrap VK is cached in r-mem — use fast path.
        let mut bvk_buf = [0u8; 32];
        {
            use crate::secure_element::WalletStore;
            let se = &mut *core::ptr::addr_of_mut!(crate::SE);
            if se.read_bootstrap_vk(&mut bvk_buf).is_err() {
                entropy.zeroize();
                return NscStatus::InternalError as u32;
            }
        }
        let mut cached_pk_root = [0u8; 16];
        cached_pk_root.copy_from_slice(&bvk_buf[16..32]);
        crate::crypto::derive_bootstrap_key_from_entropy_fast(&entropy, &cached_pk_root)
    } else {
        crate::crypto::derive_main_key_from_entropy(&entropy, chain_id, key_index)
    };
    entropy.zeroize();

    // 4. Write the 73-byte wrapper header via volatile writes.
    let mut hdr_pos: usize = 0;

    // signer_type (1 byte)
    core::ptr::write_volatile(sig_ptr.add(hdr_pos), signer_type);
    hdr_pos += 1;

    // key_index (4 bytes BE)
    let ki = key_index.to_be_bytes();
    for b in &ki {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos), *b);
        hdr_pos += 1;
    }

    // ots_index (4 bytes BE)
    let oi = ots_index.to_be_bytes();
    for b in &oi {
        core::ptr::write_volatile(sig_ptr.add(hdr_pos), *b);
        hdr_pos += 1;
    }

    // pk_seed (32 bytes: raw 16 bytes right-padded to bytes32)
    {
        let vk_bytes = signing_key.verifying_key().to_bytes();
        // VK = pk_seed[16] || pk_root[16]
        // Pad pk_seed to 32 bytes
        for i in 0..16 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), vk_bytes[i]);
        }
        for i in 16..32 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), 0u8);
        }
        hdr_pos += 32;

        // pk_root (32 bytes: raw 16 bytes right-padded to bytes32)
        for i in 0..16 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), vk_bytes[16 + i]);
        }
        for i in 16..32 {
            core::ptr::write_volatile(sig_ptr.add(hdr_pos + i), 0u8);
        }
        hdr_pos += 32;
    }

    debug_assert_eq!(hdr_pos, WRAPPER_HEADER_LEN);

    // 5. Hedged sign
    let mut rand_buf = [0u8; 16];
    derive_sign_randomizer(&state.master_secret, msg_hash, &mut rand_buf);

    let sig = signing_key.sign(msg_hash, Some(&rand_buf));

    // 6. Write the raw 3,704-byte signature after the header.
    let sig_offset = WRAPPER_HEADER_LEN;
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(sig_ptr.add(sig_offset + i), sig[i]);
    }

    // 7. Cleanup
    rand_buf.zeroize();

    crate::timeout::reset_activity();
    crate::ui::show_status(success_banner, "");

    for _ in 0..3_000_000u32 { cortex_m::asm::nop(); }
    crate::ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Derive a 16-byte randomizer for hedged SPHINCS+C7 signing from the
/// master secret and the message hash. Keeping this private to the
/// `sign_and_emit` module means callers can't accidentally use it
/// with an unbounded pre-image.
fn derive_sign_randomizer(master: &[u8; 32], msg_hash: &[u8; 32], out: &mut [u8; 16]) {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(b"sphincsc7-sign-rand");
    h.update(master);
    h.update(msg_hash);
    let r = h.finalize();
    out.copy_from_slice(&r[..16]);
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

pub(super) unsafe fn run() -> u32 {
    use crate::ui::pin_entry::{enter_pin, PinEntryResult};

    let pin = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        PinEntryResult::Cancelled | PinEntryResult::Mismatch => {
            // Mismatch is unreachable here (only enter_pin_with_confirm
            // can return it), but the match must be exhaustive.
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        PinEntryResult::IdleWipe => {
            super::zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    };

    ui::show_status("Verifying...", "");

    let result = verify_pin_with_chip(&pin);

    let mut pin_copy = pin;
    pin_copy.zeroize();

    result
}

unsafe fn verify_pin_with_chip(pin: &[u8; 8]) -> u32 {
    use crate::secure_element::WalletStore;

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    match se.unlock(pin) {
        Ok(master) => {
            state::with_state(|s| s.mark_unlocked(master));
            timeout::reset_activity();
            ui::show_status("Unlocked", "");
            NscStatus::Ok as u32
        }
        Err(UnlockError::PinIncorrect) => {
            let new_remaining = state::with_state(|s| {
                if s.remaining_attempts > 0 {
                    s.remaining_attempts -= 1;
                }
                s.remaining_attempts
            });
            if new_remaining == 0 {
                // Last attempt just failed — the SE has blocked itself.
                // Fall through to the lockout handler below.
                return trigger_lockout_wipe();
            }
            if new_remaining == 1 {
                ui::show_status("LAST ATTEMPT", "wallet wipes on fail");
            } else {
                ui::show_status("Wrong PIN", "");
            }
            NscStatus::PinIncorrect as u32
        }
        Err(UnlockError::PinLocked) => {
            state::with_state(|s| s.remaining_attempts = 0);
            trigger_lockout_wipe()
        }
        Err(UnlockError::InternalError) => {
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
unsafe fn trigger_lockout_wipe() -> u32 {
    use crate::secure_element::WalletStore;

    ui::show_status("WIPING", "do not power off");

    let se = &mut *core::ptr::addr_of_mut!(crate::SE);
    let _ = se.factory_reset_admin();

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

/// Mutable state the gateway owns across command dispatches.
pub(super) struct SecureState {
    /// How many PIN attempts the current lockout window still permits.
    /// Mirrors the secure element's monotonic PIN counter for the mock
    /// backend; for the real TROPIC01 backend the value is refreshed
    /// from the chip on every `cmd_get_remaining`.
    pub(super) remaining_attempts: u8,
    /// Whether the current session has passed PIN verification. Reset
    /// by [`zeroize_sensitive`] on cancel / idle wipe / panic.
    pub(super) pin_verified: bool,
    /// The 32-byte master secret unwrapped by
    /// `crate::pin::verify_pin` (or the TROPIC01 MAC-and-Destroy flow).
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
    pub(super) has_signed: bool,
}

impl SecureState {
    const fn new() -> Self {
        Self {
            remaining_attempts: MAX_ATTEMPTS,
            pin_verified: false,
            master_secret: [0u8; 32],
            last_chain_id: 0,
            last_key_index: 0,
            last_ots_index: 0,
            has_signed: false,
        }
    }

    /// Wipe the master secret and drop the unlock flag. Called from
    /// the panic handler, idle-wipe paths, and any user-cancel branch
    /// where we don't want the next signing request to succeed without
    /// a fresh PIN.
    pub(super) fn zeroize_sensitive(&mut self) {
        self.master_secret.zeroize();
        self.pin_verified = false;
        self.last_chain_id = 0;
        self.last_key_index = 0;
        self.last_ots_index = 0;
        self.has_signed = false;
    }

    /// Stamp in a freshly-verified master secret and mark the device
    /// unlocked. Used by both the real PIN verify path and the
    /// `e2e-test` set-state helper.
    pub(super) fn mark_unlocked(&mut self, master: [u8; 32]) {
        self.master_secret = master;
        self.pin_verified = true;
        self.remaining_attempts = MAX_ATTEMPTS;
    }
}

/// The one and only `static mut` instance. Declared at module scope so
/// the program loader places it in the secure-world BSS and so it has
/// a stable address for the no-`alloc` environment.
static mut STATE: SecureState = SecureState::new();

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

```


### `secure/src/crypto.rs`

```rust
//! Crypto helpers: KDF, AES-GCM wrap/unwrap, PIN state ser/de, and on-unlock
//! SPHINCS+C7 key derivation from the stored BIP-39 entropy.
//!
//! ## Why entropy and not the SPHINCS+C7 seed?
//!
//! The on-device secret blob is the **32-byte BIP-39 entropy** — the raw
//! 256 bits the user's 24-word phrase encodes. On every unlock the secure
//! world re-runs the full BIP-39 derivation:
//!
//! ```text
//!     entropy (32 B)
//!         │
//!         ▼ Mnemonic::from_entropy()
//!     mnemonic
//!         │
//!         ▼ PBKDF2-HMAC-SHA512, 2048 iters
//!     bip39_seed (64 B)
//!         │
//!         ▼ slhdsa_seed_from_bip39  (2 × Keccak-256 KDF)
//!     SPHINCS+C7 seed (48 B)
//!         │
//!         ▼ SigningKey::keygen
//!     sphincs_c7::SigningKey
//! ```
//!
//! Storing entropy rather than the post-PBKDF2 seed has two benefits:
//! 1. Smaller secure-element footprint (32 B vs 48 B plaintext, 60 B vs 76 B
//!    AES-GCM blob).
//! 2. The on-device secret is bit-for-bit identical to the user's recovery
//!    paper backup — there is no derived intermediate that could go stale
//!    if anything in the BIP-39 chain ever changes.
//!
//! The cost is one PBKDF2-HMAC-SHA512 (2048 iters) per unlock, dwarfed by
//! the SPHINCS+ signing time itself.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::secure_element::SecureElement;
use sphincs_c7::SigningKey;
use sphincs_tz_bip39::{Mnemonic, ENTROPY_BYTES};
use sphincs_tz_shared::MAX_ATTEMPTS;
use zeroize::Zeroize;

// r-mem slot assignments
pub const RMEM_ENCRYPTED_ENTROPY: u16 = 0;
pub const RMEM_PIN_STATE: u16 = 1;
/// Legacy slot: stores the "default" verifying key (the old single-signer VK).
/// Kept for backward compatibility; new code should use RMEM_BOOTSTRAP_VK.
pub const RMEM_VERIFYING_KEY: u16 = 2;
/// Bootstrap signer verifying key (32 bytes). Set at provisioning, never
/// changes. Used by CMD_GET_BOOTSTRAP_PUBKEY.
pub const RMEM_BOOTSTRAP_VK: u16 = 3;

/// Length of the SPHINCS+C7 seed material:
/// `sk_seed (32) ‖ pk_seed (16)`. Computed from the BIP-39
/// entropy on every unlock; never persisted.
pub const SEED_LEN: usize = 48;

/// On-device entropy length: 256 bits = the BIP-39 entropy that the user's
/// 24-word phrase encodes.
pub const ENTROPY_LEN: usize = ENTROPY_BYTES;

/// Total stored blob: 12-byte nonce ‖ encrypted_entropy (32) ‖ AES-GCM tag (16).
pub const ENTROPY_BLOB_LEN: usize = 12 + ENTROPY_LEN + 16;

// ---------------------------------------------------------------------------
// KDF helpers
// ---------------------------------------------------------------------------

pub fn kdf(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

/// Keccak-256 based KDF for SPHINCS+C7 seed derivation.
/// Used by the signing key derivation paths; the SHA-256 `kdf()` above
/// is kept for non-signing helpers (wrap-key, entropy-nonce, MACD).
pub fn kdf_keccak(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

pub fn macd_init_input(master_secret: &[u8; 32], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-init", master_secret, j)
}

pub fn macd_pin_input(pin: &[u8; 8], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-pin", pin, j)
}

pub fn derive_wrap_key(master_secret: &[u8; 32]) -> [u8; 32] {
    kdf(b"sphincs-wrap-key", master_secret, 0)
}

pub fn derive_entropy_nonce(master_secret: &[u8; 32]) -> [u8; 12] {
    let h = kdf(b"sphincs-entropy-nonce", master_secret, 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

fn nonce_for(index: u8) -> [u8; 12] {
    let h: [u8; 32] = kdf(b"sphincs-nonce", &[index], 0);
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

// ---------------------------------------------------------------------------
// AES-GCM helpers (in-place, no_std)
// ---------------------------------------------------------------------------

pub fn aes_encrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    plaintext_len: usize,
    nonce_idx: u8,
) -> usize {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = nonce_for(nonce_idx);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut buf[..plaintext_len])
        .expect("AES-GCM encrypt failed");
    buf[plaintext_len..plaintext_len + 16].copy_from_slice(&tag);
    plaintext_len + 16
}

pub fn aes_decrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    ct_len: usize,
    nonce_idx: u8,
) -> Result<usize, ()> {
    if ct_len < 16 {
        return Err(());
    }
    let plaintext_len = ct_len - 16;
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = nonce_for(nonce_idx);
    let (ct, tag_bytes) = buf[..ct_len].split_at_mut(plaintext_len);
    let tag = aes_gcm::Tag::from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], ct, tag)
        .map_err(|_| ())?;
    Ok(plaintext_len)
}

// ---------------------------------------------------------------------------
// Entropy encryption/decryption with the master secret
// ---------------------------------------------------------------------------

/// Encrypt the 32-byte BIP-39 entropy under the wrap key derived from
/// `master_secret`. Output layout: `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
pub fn encrypt_entropy_blob(
    entropy: &[u8; ENTROPY_LEN],
    master_secret: &[u8; 32],
) -> [u8; ENTROPY_BLOB_LEN] {
    let mut wrap = derive_wrap_key(master_secret);
    let nonce = derive_entropy_nonce(master_secret);

    let mut blob = [0u8; ENTROPY_BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..12 + ENTROPY_LEN].copy_from_slice(entropy);

    let cipher = Aes256Gcm::new_from_slice(&wrap).unwrap();
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            &[],
            &mut blob[12..12 + ENTROPY_LEN],
        )
        .expect("entropy encryption");
    blob[12 + ENTROPY_LEN..].copy_from_slice(&tag);

    wrap.zeroize();
    blob
}

/// Decrypt a stored entropy blob with the master secret. Returns the
/// 32-byte BIP-39 entropy on success.
pub fn decrypt_entropy_blob(
    blob: &[u8],
    master_secret: &[u8; 32],
) -> Result<[u8; ENTROPY_LEN], ()> {
    if blob.len() != ENTROPY_BLOB_LEN {
        return Err(());
    }
    let mut wrap = derive_wrap_key(master_secret);
    // The nonce stored at the head of the blob; we trust it because the
    // wrap_key is master-bound.
    let nonce: [u8; 12] = blob[..12].try_into().unwrap();
    let mut entropy_buf = [0u8; ENTROPY_LEN];
    entropy_buf.copy_from_slice(&blob[12..12 + ENTROPY_LEN]);
    let tag = aes_gcm::Tag::from_slice(&blob[12 + ENTROPY_LEN..]);

    let cipher = Aes256Gcm::new_from_slice(&wrap).unwrap();
    let r = cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut entropy_buf, tag)
        .map_err(|_| ());

    wrap.zeroize();
    r?;
    Ok(entropy_buf)
}

/// Derive a fully-formed SPHINCS+C7 signing key from a 48-byte seed.
/// Calls `SigningKey::keygen` which builds the full hypertree — the
/// `pk_root` Merkle root is *computed* from `(sk_seed, pk_seed)`.
///
/// **Expensive** (~10s on Cortex-M33). At provisioning time, compute once
/// and cache the VK. At signing time, use `SigningKey::from_parts` with
/// the cached `pk_root` to skip the hypertree rebuild.
pub fn derive_signing_key(seed: &[u8; SEED_LEN]) -> SigningKey {
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[0..32]);
    pk_seed.copy_from_slice(&seed[32..48]);
    SigningKey::keygen(sk_seed, pk_seed)
}

/// Derive the 48-byte SPHINCS+C7 seed material deterministically from the
/// 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512 output of the user's mnemonic).
///
/// Domain-separated with `"sphincsc7-sk-seed"` / `"sphincsc7-pk-seed"` so
/// the same mnemonic, used in a completely different wallet (e.g. BIP-44
/// Bitcoin), produces independent key material.
///
/// Two Keccak-256 chunks: one full 32-byte `sk_seed` and the first 16 bytes
/// of a second hash for `pk_seed`. The index byte is 0 for both (domain
/// tag provides separation).
///
/// This function is the **recovery contract**: as long as it remains stable,
/// the same 24-word phrase always produces the same SPHINCS+C7 keypair, so a
/// user who loses or bricks their device can restore from their written-down
/// phrase on any device that runs this firmware.
pub fn slhdsa_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_keccak(b"sphincsc7-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_keccak(b"sphincsc7-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);       // sk_seed: full 32 bytes
    out[32..48].copy_from_slice(&chunk1[..16]); // pk_seed: first 16 bytes
    out
}

/// Run the full BIP-39 → SPHINCS+C7 derivation chain on a 32-byte entropy
/// and return the signing key. Called on every unlock so the `SigningKey`
/// only exists in secure SRAM for the duration of the actual signing
/// operation, never persisted in any form.
///
/// PBKDF2-HMAC-SHA512 (2048 iters) is the dominant cost (~tens of ms on a
/// Cortex-M33; dwarfed by SPHINCS+ signing's seconds).
pub fn derive_signing_key_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> SigningKey {
    // 1. Reconstruct the mnemonic from the stored entropy (recomputes
    //    checksum; never produces words out loud).
    let mnemonic = Mnemonic::from_entropy(entropy);

    // 2. PBKDF2-HMAC-SHA512 with the empty passphrase.
    let mut bip39_seed = mnemonic.to_seed("");

    // 3. Domain-separate to the 48-byte SPHINCS+C7 seed.
    let mut slh_seed = slhdsa_seed_from_bip39(&bip39_seed);
    bip39_seed.zeroize();

    // 4. SPHINCS+C7 KeyGen (builds hypertree).
    let sk = derive_signing_key(&slh_seed);
    slh_seed.zeroize();

    // mnemonic Drop zeros its 24 word indices.
    sk
}

/// Fast-path signing key derivation: re-derive `(sk_seed, pk_seed)` from
/// entropy via the BIP-39 chain, then reconstruct the `SigningKey` using
/// `from_parts` with a pre-computed `pk_root` (read from r-mem at call
/// site). Skips the expensive hypertree rebuild (~10-15s on Cortex-M33).
///
/// The caller MUST supply a `pk_root` that was computed by the same
/// `(sk_seed, pk_seed)` -- i.e., the VK cached at provisioning time.
pub fn derive_signing_key_from_entropy_fast(
    entropy: &[u8; ENTROPY_LEN],
    cached_pk_root: &[u8; 16],
) -> SigningKey {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let mut slh_seed = slhdsa_seed_from_bip39(&bip39_seed);
    bip39_seed.zeroize();

    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&slh_seed[0..32]);
    pk_seed.copy_from_slice(&slh_seed[32..48]);
    slh_seed.zeroize();

    let mut pk_root = [0u8; 16];
    pk_root.copy_from_slice(cached_pk_root);

    SigningKey::from_parts(sk_seed, pk_seed, pk_root)
}

/// Fast-path bootstrap signing key derivation: same as
/// `derive_bootstrap_key_from_entropy` but uses a cached `pk_root`
/// instead of rebuilding the hypertree.
pub fn derive_bootstrap_key_from_entropy_fast(
    entropy: &[u8; ENTROPY_LEN],
    cached_pk_root: &[u8; 16],
) -> SigningKey {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let mut seed = bootstrap_seed_from_bip39(&bip39_seed);
    bip39_seed.zeroize();

    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[0..32]);
    pk_seed.copy_from_slice(&seed[32..48]);
    seed.zeroize();

    let mut pk_root = [0u8; 16];
    pk_root.copy_from_slice(cached_pk_root);

    SigningKey::from_parts(sk_seed, pk_seed, pk_root)
}

/// Same as `derive_signing_key_from_entropy` but also returns the 32-byte
/// verifying key bytes. Used by provisioning to cache the VK in r-mem
/// slot 2 without keeping the full SigningKey alive longer than necessary.
pub fn derive_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> (SigningKey, [u8; 32]) {
    let sk = derive_signing_key_from_entropy(entropy);
    let vk_bytes = sk.verifying_key().to_bytes();
    (sk, vk_bytes)
}

// ---------------------------------------------------------------------------
// Two-tier key derivation: bootstrap + per-chain main signers
// ---------------------------------------------------------------------------
//
// Both key classes derive from the same BIP-39 entropy via domain-separated
// KDFs that mirror the BIP-85 path structure:
//
//   bootstrap         = derive(seed, "pqwallet-c7-bootstrap", 0)
//   chain-main-key_i  = derive(seed, "pqwallet-c7-main", chainId, keyIndex)
//
// Using SPHINCS+C7 for both. The domain separation ensures the bootstrap
// key and all per-chain main keys are cryptographically independent.

/// Derive the bootstrap signer's SPHINCS+C7 seed (48 bytes) from the
/// BIP-39 seed. The bootstrap signer is global (not per-chain), stateless,
/// and never rotates.
pub fn bootstrap_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_keccak(b"pqwallet-c7-bootstrap-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_keccak(b"pqwallet-c7-bootstrap-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

/// Derive a per-chain main signer's SPHINCS+C7 seed (48 bytes) from the
/// BIP-39 seed, chain ID, and key epoch index.
///
/// Each (chain_id, key_index) pair produces a cryptographically
/// independent keypair. Keys on different chains cannot collide even if
/// the key indices match, because the chain ID is part of the KDF input.
pub fn main_signer_seed_from_bip39(
    bip39_seed: &[u8; 64],
    chain_id: u64,
    key_index: u32,
) -> [u8; SEED_LEN] {
    // Build a domain-specific input: bip39_seed ‖ chain_id BE ‖ key_index BE
    let mut input = [0u8; 64 + 8 + 4];
    input[..64].copy_from_slice(bip39_seed);
    input[64..72].copy_from_slice(&chain_id.to_be_bytes());
    input[72..76].copy_from_slice(&key_index.to_be_bytes());

    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_keccak(b"pqwallet-c7-main-sk-seed", &input, 0);
    let chunk1 = kdf_keccak(b"pqwallet-c7-main-pk-seed", &input, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

/// Derive the bootstrap signing key from BIP-39 entropy.
pub fn derive_bootstrap_key_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> SigningKey {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let mut seed = bootstrap_seed_from_bip39(&bip39_seed);
    bip39_seed.zeroize();
    let sk = derive_signing_key(&seed);
    seed.zeroize();
    sk
}

/// Derive the bootstrap keypair (signing key + 32-byte verifying key).
pub fn derive_bootstrap_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> (SigningKey, [u8; 32]) {
    let sk = derive_bootstrap_key_from_entropy(entropy);
    let vk_bytes = sk.verifying_key().to_bytes();
    (sk, vk_bytes)
}

/// Derive a per-chain main signing key from BIP-39 entropy.
pub fn derive_main_key_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    chain_id: u64,
    key_index: u32,
) -> SigningKey {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let mut seed = main_signer_seed_from_bip39(&bip39_seed, chain_id, key_index);
    bip39_seed.zeroize();
    let sk = derive_signing_key(&seed);
    seed.zeroize();
    sk
}

/// Derive a per-chain main keypair (signing key + 32-byte verifying key).
pub fn derive_main_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    chain_id: u64,
    key_index: u32,
) -> (SigningKey, [u8; 32]) {
    let sk = derive_main_key_from_entropy(entropy, chain_id, key_index);
    let vk_bytes = sk.verifying_key().to_bytes();
    (sk, vk_bytes)
}

/// Derive the bootstrap verifying key bytes only (no signing key retained).
pub fn derive_bootstrap_vk_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> [u8; 32] {
    let (sk, vk) = derive_bootstrap_keypair_from_entropy(entropy);
    drop(sk);
    vk
}

/// Derive a per-chain main verifying key bytes only.
pub fn derive_main_vk_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    chain_id: u64,
    key_index: u32,
) -> [u8; 32] {
    let (sk, vk) = derive_main_keypair_from_entropy(entropy, chain_id, key_index);
    drop(sk);
    vk
}

// ---------------------------------------------------------------------------
// PIN state serialization (unchanged — used by mock-SE MACD path)
// ---------------------------------------------------------------------------

pub const PER_SLOT_CT_LEN: usize = 32 + 16; // master_secret (32) + AES-GCM tag (16)
pub const PIN_STATE_MAX_LEN: usize = 1 + MAX_ATTEMPTS as usize * PER_SLOT_CT_LEN; // 481

pub fn serialize_pin_state(
    next_index: u8,
    encrypted_secrets: &[[u8; PER_SLOT_CT_LEN]],
    buf: &mut [u8],
) -> usize {
    buf[0] = next_index;
    let mut offset = 1;
    for c in encrypted_secrets {
        buf[offset..offset + PER_SLOT_CT_LEN].copy_from_slice(c);
        offset += PER_SLOT_CT_LEN;
    }
    offset
}

pub struct PinState {
    pub next_index: u8,
    pub num_slots: usize,
    pub encrypted_secrets: [[u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize],
}

pub fn deserialize_pin_state(blob: &[u8], blob_len: usize) -> Result<PinState, ()> {
    if blob_len == 0 {
        return Err(());
    }
    let next_index = blob[0];
    let rest = &blob[1..blob_len];
    if rest.len() % PER_SLOT_CT_LEN != 0 {
        return Err(());
    }
    let num_slots = rest.len() / PER_SLOT_CT_LEN;
    let mut encrypted_secrets = [[0u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize];
    for (i, chunk) in rest.chunks(PER_SLOT_CT_LEN).enumerate() {
        encrypted_secrets[i].copy_from_slice(chunk);
    }
    Ok(PinState {
        next_index,
        num_slots,
        encrypted_secrets,
    })
}

// ---------------------------------------------------------------------------
// WalletStore provisioning helpers
// ---------------------------------------------------------------------------

/// Provision a `WalletStore` backend from a user-supplied BIP-39 mnemonic.
///
/// This is the single entry point for both the "new wallet" and "restore
/// from seed phrase" wizard branches. Handles the shared key derivation
/// (the "recovery contract") and delegates storage to `store.provision()`.
///
/// Determinism: the same `(mnemonic, pin)` pair always produces the same
/// SPHINCS+ keypair on any device running this firmware.
pub fn provision_from_mnemonic(
    store: &mut impl crate::secure_element::WalletStore,
    mnemonic: &sphincs_tz_bip39::Mnemonic,
    pin: &[u8; 8],
) {
    let mut entropy = mnemonic
        .to_entropy()
        .expect("mnemonic was already checksum-verified");

    let mut master_secret: [u8; 32] = kdf(b"sphincs-master", &entropy, 0);

    let (sk, vk_bytes) = derive_keypair_from_entropy(&entropy);
    drop(sk);
    let bootstrap_vk = derive_bootstrap_vk_from_entropy(&entropy);

    store
        .provision(&entropy, &master_secret, &vk_bytes, &bootstrap_vk, pin)
        .expect("provisioning failed");

    entropy.zeroize();
    master_secret.zeroize();
}

/// Store pre-derived entropy, VK, and PIN state via the MACD chain on an
/// r-mem-capable secure element. Used by backends that support the
/// `SecureElement` trait (Mock, Tropic01 on the generic path).
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
