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

    // e2e-test: skip SPHINCS+C7 keygen (minutes on QEMU/Pi per key).
    // Write deterministic mock VK bytes — e2e tests never verify them.
    #[cfg(feature = "e2e-test")]
    let (vk_bytes, bootstrap_vk) = {
        use sha3::{Digest, Keccak256};
        let mut h = Keccak256::new();
        h.update(b"e2e-mock-vk");
        h.update(&entropy);
        let hash = h.finalize();
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&hash);
        let mut h2 = Keccak256::new();
        h2.update(b"e2e-mock-bootstrap-vk");
        h2.update(&entropy);
        let hash2 = h2.finalize();
        let mut bvk = [0u8; 32];
        bvk.copy_from_slice(&hash2);
        (vk, bvk)
    };
    #[cfg(not(feature = "e2e-test"))]
    let (vk_bytes, bootstrap_vk) = {
        let (sk, vk_bytes) = derive_keypair_from_entropy(&entropy);
        drop(sk);
        let bootstrap_vk = derive_bootstrap_vk_from_entropy(&entropy);
        (vk_bytes, bootstrap_vk)
    };

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
