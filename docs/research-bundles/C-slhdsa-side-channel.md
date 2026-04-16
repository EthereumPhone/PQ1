# Research Prompt C — SLH-DSA Side-Channel Landscape on Cortex-M33

## Research question

What side-channel attacks (power, EM, cache, timing, μarch) have been
demonstrated or are theoretically plausible against hash-based
signature schemes (SPHINCS+ / SLH-DSA) on ARM Cortex-M33-class chips?

Specifically:

1. Does the published academic literature include practical SLH-DSA
   SCA key-recovery attacks? If so, what are the noise thresholds
   (number of traces, signal-to-noise ratios, distance constraints)?
   If not, what's the closest analogue (SPHINCS-variant attacks,
   generic hash-based-sig attacks, WOTS chain extraction)?
2. Which specific operations within an SLH-DSA signature are the
   most leak-prone? (Candidates: FORS leaf computation exposing SK
   bits; WOTS chain walks exposing step counts; HT layer transitions;
   PRF evaluations consuming the master seed.)
3. Is the SHA-256 hardware accelerator on STM32U585 (HASH peripheral)
   SCA-hardened? If we route SLH-DSA's hashing through it instead of
   software SHA-256, does that eliminate the main leak surface or
   just move it?
4. Our design rotates the main signer every ~2^20 signatures. Is
   that already beyond the SCA trace-count threshold for practical
   recovery, or do we need tighter rotation?
5. Does migration from SHA2-128f to SHA2-192f meaningfully improve
   the SCA posture, or is it orthogonal?

Deliverables: catalogued threat list with severity + mitigation per
item, plus specific recommendations on per-signer rotation cadence
and whether to route hashing through the HASH peripheral.


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


### `secure/src/nsc/cmd_sign_userop.rs`

```rust
//! `CMD_SIGN_USEROP` — wrap a user-authorised inner EIP-1559
//! transaction as an ERC-4337 v0.6 `UserOperation`, display the inner
//! tx on the trusted UI, recompute the canonical `userOpHash` natively,
//! and sign that hash with SLH-DSA-SHA2-128f.
//!
//! ## Deployment modes
//!
//! The first byte of the payload is the **mode byte**:
//!
//!   * `0` — deployed, no ERC-20 bundle (legacy default)
//!   * `1` — deployed, with ERC-20 bundle (legacy default)
//!   * `2` — **not deployed**: firmware generates initCode automatically
//!   * `3` — not deployed + with ERC-20 bundle
//!
//! When mode ≥ 2, the firmware derives the bootstrap keypair internally,
//! produces the factory authorization signature, builds and hashes the
//! initCode, and includes it in the structured UserOp response alongside
//! the reconstructed callData and the main-signer PQSignatureWrapper.
//!
//! ## Why the secure world (and not NS) computes the userOpHash
//!
//! The single point of authorisation in this device is the trusted UI:
//! whatever bytes the user confirms are exactly the bytes that get
//! authorised on chain. For a normal EIP-1559 sign that's the keccak256
//! of the displayed envelope. For an ERC-4337 UserOp the EntryPoint
//! actually executes `userOp.callData`, which the user never sees as
//! such — they see "send 1 ETH to 0xabc". So the secure world has to
//! reconstruct the callData byte-for-byte from the displayed inner tx
//! and feed only that reconstruction into the userOpHash. A hostile
//! NS that swapped the AA wrapper would have the secure world produce a
//! signature over a hash that doesn't match what NS gave the bundler,
//! so verification on chain would fail loud — never silent fund theft.
//!
//! ## Wire format
//!
//! See `sphincs_tz_shared::CMD_SIGN_USEROP` for the canonical layout.

use sphincs_tz_shared::{
    NscStatus, MAX_TX_LEN, MAX_USEROP_RESPONSE_LEN, USEROP_HEADER_LEN, USEROP_PREFIX_LEN,
};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::GatewayArgs;
use crate::ui;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::aa::userop::parse_header;
    use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
    use crate::erc20::{dispatch_tx, TxKind};
    use crate::tx::{
        display::{
            render_blind_sign_pages, render_contract_creation_pages, render_erc20_known_pages,
            render_erc20_unknown_pages, render_pages,
        },
        eip1559,
    };
    use crate::ui::confirm::{confirm, ConfirmResult};

    ui::show_status("Sign", "validating...");

    if !super::state::peek_state(|s| s.pin_verified) {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let has_ots_trailer = args.arg2 & 0x8000_0000 != 0;
    let total_len = (args.arg2 & 0x7FFF_FFFF) as usize;
    //
    // NOTE: These are used only for the PQSignatureWrapper header and
    // the initCode path. The v1 legacy path ignores them.

    // 1. Pointer + size validation.
    // The v2 USB handler may append an 8-byte OTS trailer (key_index + ots_index).
    const OTS_TRAILER_LEN: usize = 8;
    if total_len < USEROP_PREFIX_LEN + 1
        || total_len > USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN + OTS_TRAILER_LEN
    {
        ui::show_status("Sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }

    // 2. TOCTOU snapshot
    const SNAP_LEN: usize = USEROP_PREFIX_LEN + MAX_TX_LEN + 4 + MAX_ERC20_BUNDLE_LEN + OTS_TRAILER_LEN;
    static mut SNAP_BUF: [u8; SNAP_LEN] = [0u8; SNAP_LEN];
    let buf = &mut SNAP_BUF[..];
    if total_len > buf.len() {
        return NscStatus::InvalidPointer as u32;
    }
    for i in 0..total_len {
        buf[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    ui::show_status("Sign", "parsing...");

    // 3. Parse mode byte.
    let mode = buf[0];
    let has_bundle = mode == 1 || mode == 3;
    let needs_init_code = mode >= 2;

    // Validate output buffer size based on mode.
    let required_out = if needs_init_code {
        MAX_USEROP_RESPONSE_LEN
    } else {
        MAX_USEROP_RESPONSE_LEN // same max — actual write is smaller
    };
    if !validate_ns_write_ptr(args.arg1, required_out) {
        return NscStatus::InvalidPointer as u32;
    }

    // 4. Parse the fixed AA header.
    let mut aa = match parse_header(&buf[..USEROP_HEADER_LEN]) {
        Ok(a) => a,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };

    // 5. Parse the inner-tx length and locate the envelope.
    let tx_len_off = USEROP_HEADER_LEN;
    let tx_len_bytes: [u8; 4] = match buf[tx_len_off..tx_len_off + 4].try_into() {
        Ok(v) => v,
        Err(_) => return NscStatus::InvalidPointer as u32,
    };
    let tx_len = u32::from_le_bytes(tx_len_bytes) as usize;
    if tx_len == 0 || tx_len > MAX_TX_LEN {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_start = USEROP_PREFIX_LEN;
    let tx_end = tx_start + tx_len;
    if tx_end > total_len {
        return NscStatus::InvalidPointer as u32;
    }
    let tx_bytes = &buf[tx_start..tx_end];

    // 6. Parse the inner EIP-1559 envelope.
    let parsed = match eip1559::parse(tx_bytes) {
        Ok(t) => t,
        Err(_) => {
            ui::show_status("Bad tx", "(parse fail)");
            return NscStatus::CryptoError as u32;
        }
    };

    if aa.chain_id != parsed.tx.chain_id {
        ui::show_status("Bad tx", "(chain mismatch)");
        return NscStatus::CryptoError as u32;
    }

    // 7. Optional ERC-20 metadata bundle.
    let verified_meta: Option<Erc20Metadata<'_>> = if has_bundle {
        if tx_end + 4 > total_len {
            None
        } else {
            let blen_bytes: [u8; 4] = match buf[tx_end..tx_end + 4].try_into() {
                Ok(v) => v,
                Err(_) => return NscStatus::InvalidPointer as u32,
            };
            let bundle_len = u32::from_le_bytes(blen_bytes) as usize;
            let bundle_start = tx_end + 4;
            let bundle_end = bundle_start + bundle_len;
            if bundle_len == 0 || bundle_len > MAX_ERC20_BUNDLE_LEN || bundle_end > total_len {
                None
            } else {
                match verify_erc20_bundle(&buf[bundle_start..bundle_end]) {
                    Some(meta) => {
                        let to_match = match parsed.tx.to {
                            Some(addr) => addr == meta.contract,
                            None => false,
                        };
                        if meta.chain_id == parsed.tx.chain_id && to_match {
                            Some(meta)
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            }
        }
    } else {
        None
    };

    // 8. Trust-ladder dispatch + trusted UI confirmation.
    let kind = dispatch_tx(&parsed, verified_meta);

    #[cfg(all(feature = "e2e-test", feature = "debug-log"))]
    {
        let kind_name: &str = match &kind {
            TxKind::ValueTransfer => "ValueTransfer",
            TxKind::Erc20Known(_, _) => "Erc20Known",
            TxKind::Erc20Unknown(_) => "Erc20Unknown",
            TxKind::ContractCall => "ContractCall",
            TxKind::ContractCreation => "ContractCreation",
        };
        secure_log!("[S][e2e] cmd_sign_userop dispatch = {}", kind_name);
    }

    if matches!(kind, TxKind::ContractCreation) {
        ui::show_status("UserOp", "no CREATE");
        return NscStatus::CryptoError as u32;
    }

    let pages = match kind {
        TxKind::ValueTransfer => render_pages(&parsed.tx),
        TxKind::Erc20Known(call, meta) => render_erc20_known_pages(&parsed.tx, &call, &meta),
        TxKind::Erc20Unknown(call) => render_erc20_unknown_pages(&parsed.tx, &call),
        TxKind::ContractCall => render_blind_sign_pages(&parsed.tx, parsed.data),
        TxKind::ContractCreation => render_contract_creation_pages(&parsed.tx, parsed.data),
    };

    // For undeployed accounts, add a visual hint on the confirmation screen.
    #[cfg(not(feature = "e2e-test"))]
    if needs_init_code {
        ui::show_status("DEPLOY+Sign", "confirm...");
    }

    let confirm_result = confirm(pages.as_slice());
    match confirm_result {
        ConfirmResult::Confirmed => {}
        ConfirmResult::Cancelled => {
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            ui::show_status("Locked", "(idle wipe)");
            return NscStatus::IdleWipe as u32;
        }
    }

    // 9. Extract key_index and ots_index from the TOCTOU-snapped buffer.
    // The v2 USB handler appends key_index(4 BE) + ots_index(4 BE) after
    // the wire payload and sets bit 31 of total_len to signal presence.
    // Legacy v1 callers (QEMU mailbox) don't set the flag → default to 0.
    let (key_index, ots_index, payload_len) = if has_ots_trailer && total_len >= 8 {
        let pl = total_len - 8;
        let ki = u32::from_be_bytes([buf[pl], buf[pl + 1], buf[pl + 2], buf[pl + 3]]);
        let oi = u32::from_be_bytes([buf[pl + 4], buf[pl + 5], buf[pl + 6], buf[pl + 7]]);
        (ki, oi, pl)
    } else {
        (0u32, 0u32, total_len)
    };
    let _ = payload_len; // payload parsing above used total_len before the trailer was stripped

    // 10. OTS monotonicity: only enforced for v2 callers that supply
    //     explicit key_index/ots_index via the trailer. Legacy v1 callers
    //     default to (0, 0) and don't support OTS tracking.
    if has_ots_trailer {
        let ots_ok = super::state::peek_state(|s| {
            if !s.has_signed {
                return true;
            }
            if s.last_chain_id == aa.chain_id && s.last_key_index == key_index {
                ots_index > s.last_ots_index
            } else {
                true // different chain or key epoch: companion is authoritative
            }
        });
        if !ots_ok {
            ui::show_status("OTS reuse", "rejected");
            return NscStatus::CryptoError as u32;
        }
    }

    // 11. Hand off to the signing tail.
    let mut result_len: usize = 0;
    let status = super::userop_tail::sign_userop_full(
        &mut aa,
        &parsed.tx,
        parsed.data,
        out_ptr,
        &mut result_len as *mut usize,
        needs_init_code,
        key_index,
        ots_index,
        "Signed",
    );

    // Record OTS state on success so the next signing request for the
    // same (chain_id, key_index) must present a strictly greater index.
    // Only tracked for v2 callers with explicit OTS indices.
    if status == NscStatus::Ok as u32 && has_ots_trailer {
        super::state::with_state(|s| {
            s.last_chain_id = aa.chain_id;
            s.last_key_index = key_index;
            s.last_ots_index = ots_index;
            s.has_signed = true;
        });
    }

    status
}

```


### `secure/Cargo.toml`

```toml
[package]
name = "sphincs-tz-secure"
version = "0.1.0"
edition.workspace = true

[dependencies]
sphincs-tz-shared = { workspace = true }
sphincs-tz-bip39  = { workspace = true }

# Crypto (all no_std, no alloc)
sphincs-c7 = { workspace = true }
aes-gcm = { version = "0.10", default-features = false, features = ["aes"] }
aes = { version = "0.8", default-features = false }
cmac = { version = "0.7", default-features = false }
sha2 = { version = "0.10", default-features = false }
sha3 = { version = "0.10", default-features = false }
subtle = { version = "2.6", default-features = false }
hmac    = { workspace = true }
zerocopy = { version = "0.8", default-features = false }
zeroize = { workspace = true }

# BLS12-381 pairing for Groth16 ZK proof verification (no_std, no alloc).
# Uses our fork which adds a `pka` feature for STM32U585 hardware acceleration.
# Base features `groups` + `pairings` come from the workspace dep; the `pka`
# feature is layered in by the `pka-accel` Cargo feature below.
bls12_381 = { workspace = true }

# TROPIC01 secure element (for real chip mode)
tropic01 = { git = "https://github.com/tropicsquare/libtropic-rs", rev = "0cacb5ed94e5df491bfbb39e8702cc47598f7d63", features = ["keys"], optional = true }
x25519-dalek = { version = "2.0.1", default-features = false, features = ["static_secrets"], optional = true }
embedded-hal = { version = "1", optional = true }

# OLED display + graphics (for real hardware UI)
ssd1306 = { version = "0.10", default-features = false, optional = true }
embedded-graphics = { version = "0.8", default-features = false, optional = true }

# RTT (Real-Time Transfer) for the `ui-mirror` debug feature only.
# Streams the SSD1306 framebuffer to the host via the ST-LINK probe so the
# OLED contents can be viewed in a terminal. Debug-only — gated out of
# production builds by `make prod-check`.
rtt-target = { version = "0.5", optional = true }

# ARM-only: these crates don't compile on x86_64, so they're gated to the
# ARM target. This lets `cargo test -p sphincs-tz-secure` run the
# pure-logic unit tests (aa, tx) on the host without pulling in hardware deps.
[target.'cfg(target_arch = "arm")'.dependencies]
cortex-m = { workspace = true, features = ["critical-section-single-core"] }
cortex-m-rt          = { workspace = true }
cortex-m-semihosting = { workspace = true }

[features]
default = ["mock-se", "debug-log", "ui-semihosting"]
debug-log = []
mock-se = []
tropic01-se = ["dep:tropic01", "dep:x25519-dalek", "dep:embedded-hal"]
ui-semihosting = []
ui-oled = ["dep:ssd1306", "dep:embedded-graphics", "dep:embedded-hal"]
ui-noop = []  # Silent no-op UI for standalone USB operation (no debugger/OLED)
pka-accel = ["bls12_381/pka"]  # STM32U585 PKA hardware acceleration for BLS12-381 Fp arithmetic
stm32u585 = ["sphincs-tz-shared/stm32u585"]  # Real STM32U585 hardware target (vs QEMU mps2-an505)
# Non-interactive automated end-to-end test mode. Provisions a fixed
# test mnemonic + PIN at boot, marks PIN as verified, and short-circuits
# every confirm() / enter_pin() dialog so no stdin input is needed.
# Logs the chosen TxKind variant on every cmd_sign for assertions.
# NEVER ship in production: it disables every meaningful trust gate.
e2e-test = []
usb = []  # Enable USB OTG hardware init (clock, GPIO, GTZC) for host communication
se050 = []  # NXP SE050 secure element via I2C1 (OM-SE050ARD on Arduino R3 headers)
optiga-trust-m = []  # Infineon OPTIGA Trust M V3 via I2C1 (TRUSTMV3SHIELDTOBO1 on Arduino R3 headers)
dual-se = ["optiga-trust-m", "se050"]  # Both SEs active: XOR-split entropy across OPTIGA Trust M + SE050
se050-factory-reset = ["se050"]  # Wipe all SE050 objects on boot, then halt. Use `make se050-reset`.
se050-reset-e2e = ["se050"]  # Self-contained factory-reset roundtrip test. Use `make se050-reset-e2e`.
se050-admin-wipe-e2e = ["se050"]  # Admin-auth wipe roundtrip test on isolated OID range. Use `make se050-admin-wipe-e2e`.
se050-crash-safety-e2e = ["se050"]  # 2-phase test: partial wipe + reset + resume. Use `make se050-crash-safety-e2e`.
spi1-arduino = []  # Use SPI1/PE12-PE15 (Arduino R3 headers) instead of SPI2/PB12-PB15 for TROPIC01
stsafe-probe = ["stm32u585", "mock-se"]  # I2C2 bus scan to detect on-board STSAFE-A110
gpio-buttons = ["stm32u585"]  # GPIO button driver: PI2 (LEFT) + PA15 (RIGHT) on CN14
button-test = ["stm32u585", "mock-se", "gpio-buttons"]  # Flash + run GPIO button test
qr-screen-test = ["ui-oled", "stm32u585", "mock-se"]  # Render QR + companion-app URL at boot, then halt. Use `make qr-screen`.
# Stream the SSD1306 framebuffer to the host over RTT so the OLED can be
# viewed in a terminal during development. Implies `ui-oled` (nothing to
# mirror without it). NEVER ship in production: `make prod-check` rejects
# any build that has this feature enabled. See `tools/oled-mirror`.
ui-mirror = ["dep:rtt-target", "ui-oled"]

[build-dependencies]
qrcodegen = "1.8"

[dev-dependencies]
hex = { workspace = true }

```
