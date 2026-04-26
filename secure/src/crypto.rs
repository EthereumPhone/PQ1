//! Crypto helpers: KDF, AES-GCM wrap/unwrap, PIN state ser/de, and on-unlock
//! SPHINCS+C10 key derivation from the stored BIP-39 entropy.
//!
//! ## Why entropy and not the SPHINCS+C10 seed?
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
//!         ▼ slhdsa_seed_from_bip39  (2 × SHA-256 KDF)
//!     SPHINCS+C10 seed (48 B)
//!         │
//!         ▼ SigningKey::keygen
//!     sphincs_c10::SigningKey
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
use sphincs_c10::SigningKey;
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

/// Length of the SPHINCS+C10 seed material:
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

/// SHA-256 based KDF for SPHINCS+C10 / slot seed derivation.
///
/// Historically this was Keccak-256 but we switched to SHA-256 across the
/// entire signing stack so the firmware can call the STM32U585 HASH
/// peripheral (1 cycle/byte single-block, vs ~12 cycles/byte for software
/// Keccak). Domain tags stay the same; only the hash primitive changed.
pub fn kdf_sha256(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
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

/// Derive a fully-formed SPHINCS+C10 signing key from a 48-byte seed.
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

/// Derive the 48-byte SPHINCS+C10 seed material deterministically from the
/// 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512 output of the user's mnemonic).
///
/// Domain-separated with `"sphincsc7-sk-seed"` / `"sphincsc7-pk-seed"` so
/// the same mnemonic, used in a completely different wallet (e.g. BIP-44
/// Bitcoin), produces independent key material.
///
/// Two SHA-256 chunks: one full 32-byte `sk_seed` and the first 16 bytes
/// of a second hash for `pk_seed`. The index byte is 0 for both (domain
/// tag provides separation).
///
/// This function is the **recovery contract**: as long as it remains stable,
/// the same 24-word phrase always produces the same SPHINCS+C10 keypair, so a
/// user who loses or bricks their device can restore from their written-down
/// phrase on any device that runs this firmware.
pub fn slhdsa_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_sha256(b"sphincsc7-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_sha256(b"sphincsc7-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);       // sk_seed: full 32 bytes
    out[32..48].copy_from_slice(&chunk1[..16]); // pk_seed: first 16 bytes
    out
}

/// Run the full BIP-39 → SPHINCS+C10 derivation chain on a 32-byte entropy
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

    // 3. Domain-separate to the 48-byte SPHINCS+C10 seed.
    let mut slh_seed = slhdsa_seed_from_bip39(&bip39_seed);
    bip39_seed.zeroize();

    // 4. SPHINCS+C10 KeyGen (builds hypertree).
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
// Using SPHINCS+C10 for both. The domain separation ensures the bootstrap
// key and all per-chain main keys are cryptographically independent.

/// Derive the bootstrap signer's SPHINCS+C10 seed (48 bytes) from the
/// BIP-39 seed. The bootstrap signer is global (not per-chain), stateless,
/// and never rotates.
pub fn bootstrap_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_sha256(b"pqwallet-c7-bootstrap-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_sha256(b"pqwallet-c7-bootstrap-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0);
    out[32..48].copy_from_slice(&chunk1[..16]);
    out
}

/// Derive a per-chain main signer's SPHINCS+C10 seed (48 bytes) from the
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
    let chunk0 = kdf_sha256(b"pqwallet-c7-main-sk-seed", &input, 0);
    let chunk1 = kdf_sha256(b"pqwallet-c7-main-pk-seed", &input, 0);
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
// Slot-key master-entropy derivation
// ---------------------------------------------------------------------------
//
// Slot keys are derived deterministically from the BIP-39 seed via
// domain-separated SHA-256: same 24 words + slot_index → same slot keypair.

/// Derive the master entropy for slot keys from the BIP-39 seed.
/// Domain-separated so it is independent from C10 bootstrap keys.
///
/// `account_index == 0` uses the single-account formula
/// (`kdf_sha256("pqwallet-slot-master", bip39_seed, 0)`).
/// Indices 1..=255 fold the index into a separate domain tag —
/// different account, different slot identity.
pub fn slot_master_entropy_from_bip39(
    bip39_seed: &[u8; 64],
    account_index: u32,
) -> [u8; 32] {
    if account_index == 0 {
        kdf_sha256(b"pqwallet-slot-master", bip39_seed, 0)
    } else {
        let mut h = Sha256::new();
        h.update(b"pqwallet-slot-master-acct");
        h.update(bip39_seed);
        h.update(account_index.to_be_bytes());
        h.finalize().into()
    }
}

/// Derive slot master entropy from raw BIP-39 entropy (runs the full
/// BIP-39 chain: mnemonic → PBKDF2 → domain KDF). See
/// [`slot_master_entropy_from_bip39`] for the `account_index` contract.
pub fn slot_master_entropy_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> [u8; 32] {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let master = slot_master_entropy_from_bip39(&bip39_seed, account_index);
    bip39_seed.zeroize();
    master
}

// ---------------------------------------------------------------------------
// SPHINCS+C10 bootstrap keypair derivation (SPHINCs--compatible)
// ---------------------------------------------------------------------------
//
// The bootstrap C10 keypair is the long-term identity of a wallet:
// the CREATE2 salt is `sha256(masterPkSeed || masterPkRoot)`, so the
// same 24 words produce the same on-chain wallet address across every
// chain forever — given the same hash primitive and the same `h` tree
// shape. Switching from C11 (h=16) to C10 (h=18) changes `masterPkRoot`
// and therefore the per-seed wallet address.
//
// The "sphincs-c6-v1" domain tag for the HMAC-SHA512 step is a historical
// quirk inherited from when the reference repo used SPHINCS+C6; we keep
// it verbatim to avoid an unnecessary second drift in the recovery
// contract. The underlying hash primitive is SHA-256; the master identity
// SPHINCS+ parameter set is C10.
//
// This derivation is separate from the slot master entropy above: the
// C10 bootstrap keys sign only Type 1 slot-registration payloads (max
// 65,536 per chain, enforced on-chain by `PQSmartWallet.bootstrapUses`),
// never user txs. Per-tx signing uses the per-slot C10 keypairs.

/// SPHINCS+C10 bootstrap-key derivation from the 64-byte BIP-39 seed.
///
/// Returns `(pk_seed_32, sk_seed_32)`.
///
/// - `pk_seed_32`: the top 16 bytes are `sha256("pk_seed" || master[0..32])[0..16]`
///   and the bottom 16 bytes are zero. This is the N-mask layout used by
///   every SPHINCS+C10 internal hash and the on-chain `masterPkSeed`
///   immutable.
/// - `sk_seed_32`: the full 32 bytes of `sha256("sk_seed" || master[0..32])`.
///
/// `master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)` (only the first 32
/// bytes are consumed; the remainder is discarded and wiped).
///
/// `account_index == 0` reproduces the legacy single-account derivation
/// byte-for-byte (recovery contract). For accounts 1..=255 the master is
/// `HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed || account_index_be4)`,
/// then the same `pk_seed`/`sk_seed` SHA-256 splits run on top — a fresh
/// SPHINCS+ identity per account, but reusing the same downstream layout.
pub fn derive_c10_master_from_bip39_seed(
    bip39_seed: &[u8; 64],
    account_index: u32,
) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    // Step 1: HMAC-SHA512(domain, key-material) → 64-byte master.
    //
    // Account 0: domain = b"sphincs-c6-v1" (13 ASCII bytes; NO length-
    // prefix, NO NUL terminator — matches `keygen.rs:38` in the reference).
    // The HMAC input is the BIP-39 seed only.
    //
    // Accounts 1..=255: domain = b"sphincs-c6-v1-acct"; HMAC input is
    // bip39_seed || account_index_be4. Folds the index into the master
    // entropy so each account has an independent C10 hypertree.
    //
    // Use the `Mac::new_from_slice` path explicitly because both `Mac`
    // and `KeyInit` traits define an identically-named constructor.
    let domain: &[u8] = if account_index == 0 {
        b"sphincs-c6-v1"
    } else {
        b"sphincs-c6-v1-acct"
    };
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(domain)
        .expect("HMAC-SHA512 accepts any key length");
    mac.update(bip39_seed);
    if account_index != 0 {
        mac.update(&account_index.to_be_bytes());
    }
    let master_ga = mac.finalize().into_bytes();
    let mut master = [0u8; 64];
    master.copy_from_slice(&master_ga);

    // Step 2: pk_seed = mask_n(sha256("pk_seed" || master[0..32]))
    //   mask_n keeps bytes [0..16] and zeros bytes [16..32].
    let mut pk_hasher = Sha256::new();
    pk_hasher.update(b"pk_seed");
    pk_hasher.update(&master[..32]);
    let pk_digest: [u8; 32] = pk_hasher.finalize().into();
    let mut pk_seed = [0u8; 32];
    pk_seed[..16].copy_from_slice(&pk_digest[..16]);

    // Step 3: sk_seed = sha256("sk_seed" || master[0..32])  (full 32 bytes, no mask).
    let mut sk_hasher = Sha256::new();
    sk_hasher.update(b"sk_seed");
    sk_hasher.update(&master[..32]);
    let sk_digest: [u8; 32] = sk_hasher.finalize().into();
    let mut sk_seed = [0u8; 32];
    sk_seed.copy_from_slice(&sk_digest);

    master.zeroize();

    (pk_seed, sk_seed)
}

/// Convenience wrapper: run the BIP-39 chain from 32-byte entropy, then
/// derive the C10 bootstrap keys for `account_index`. Wipes the
/// intermediate `bip39_seed`.
pub fn derive_c10_master_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> ([u8; 32], [u8; 32]) {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let result = derive_c10_master_from_bip39_seed(&bip39_seed, account_index);
    bip39_seed.zeroize();
    result
}

/// Full C10 bootstrap-keypair derivation including hypertree-root keygen.
///
/// Returns `(signing_key, master_pk_seed_32, master_pk_root_32)`.
///
/// - `signing_key` is a ready-to-use `sphincs_c10::SigningKey`.
/// - `master_pk_seed_32` is the N-masked public seed suitable for storing
///   as an on-chain `bytes32` (top 16 bytes populated, bottom 16 zero).
/// - `master_pk_root_32` is the N-masked hypertree root in the same layout.
///
/// **Expensive**: runs the full C10 hypertree keygen (512 WOTS keys at
/// the top layer + Merkle root). Only call when actually producing a
/// Type 1 signature. On Cortex-M33 this takes ~5-6 s with the HASH
/// peripheral; on QEMU it takes much less.
pub fn derive_c10_master_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> (sphincs_c10::SigningKey, [u8; 32], [u8; 32]) {
    derive_c10_master_keypair_from_entropy_with_progress(entropy, account_index, |_| {})
}

/// Like [`derive_c10_master_keypair_from_entropy`] but reports 0..100 keygen
/// progress via the supplied callback so a trusted-UI progress bar can be
/// kept responsive during the multi-second operation.
pub fn derive_c10_master_keypair_from_entropy_with_progress(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
    progress: impl Fn(u8),
) -> (sphincs_c10::SigningKey, [u8; 32], [u8; 32]) {
    progress(0);
    let (pk_seed_32, sk_seed_32) = derive_c10_master_from_entropy(entropy, account_index);

    // Pack pk_seed into the 16-byte N-slot shape the sphincs-c10 crate expects.
    let mut pk_seed_16 = [0u8; 16];
    pk_seed_16.copy_from_slice(&pk_seed_32[..16]);
    let mut sk_seed_arr = [0u8; 32];
    sk_seed_arr.copy_from_slice(&sk_seed_32);

    // SigningKey::keygen builds the full hypertree. The report() closure
    // inside progress() remains the caller's responsibility — the keygen
    // itself is a single expensive call with no sub-progress hook.
    progress(10);
    let sk = sphincs_c10::SigningKey::keygen(sk_seed_arr, pk_seed_16);
    progress(100);

    // Build the N-masked 32-byte pk_root for on-chain storage.
    let mut pk_root_32 = [0u8; 32];
    pk_root_32[..16].copy_from_slice(sk.pk_root());

    (sk, pk_seed_32, pk_root_32)
}

/// Sign a 32-byte message hash with the bootstrap C10 signing key and the
/// (optional) randomiser. Wraps `sphincs_c10::SigningKey::sign` with a
/// verify-before-release fault-injection guard.
///
/// Produces 4008-byte C10 signatures — see `sphincs-c10/src/params.rs`.
pub fn c10_sign_verified(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    c10_sign_verified_with_progress(sk, msg_hash, |_| {})
}

/// Like [`c10_sign_verified`] but reports 0..100 signing progress via the
/// supplied callback so the trusted-UI progress bar stays responsive
/// during the multi-second C10 signature.
pub fn c10_sign_verified_with_progress(
    sk: &sphincs_c10::SigningKey,
    msg_hash: &[u8; 32],
    progress: fn(u8),
) -> Result<[u8; sphincs_c10::params::SIGNATURE_LEN], ()> {
    let sig = sk.sign_with_progress(msg_hash, None, progress);
    // Verify before release (fault-injection guard).
    //
    // The boolean check is wrapped by `fi::check_true` so a glitch that
    // skips the `if` requires cooperating skips of the double-evaluation
    // AND the hamming-distant sentinel compare. `wait_random()` immediately
    // before the verify defeats clock-aligned fault bursts that time their
    // glitch to the verify's fixed-shape control flow.
    crate::fi::wait_random();
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig);
    if !crate::fi::check_true(|| v) {
        return Err(());
    }
    Ok(sig)
}

// ---------------------------------------------------------------------------
// Per-slot C10 keypair derivation
// ---------------------------------------------------------------------------
//
// Post-cutover the per-slot signing key is itself a SPHINCS+C10 keypair. The
// firmware is stateless with respect to slot selection — it re-derives the
// keypair deterministically from `(slot_master_entropy, slot_index)` on
// every sign (and caches the result in SRAM for the remainder of the unlock
// session).
//
// Derivation chain:
//
//   slot_master_entropy = sha256("pqwallet-slot-master" || bip39_seed)
//   slot_entropy        = sha256(master || "slot_entropy" || slot_index_be)
//   r                   = sha256(master || "slot_r"        || slot_index_be)
//   slot_sk_seed        = sha256("slot_c10_sk_seed" || slot_entropy)
//   slot_pk_seed_16     = sha256("slot_c10_pk_seed" || slot_entropy)[0..16]

/// Compute the deterministic slot entropy for a given `(chain_id, slot_index)`.
///
/// Post-Coinbase-port, slot keys are chain-specific so the same seed
/// produces different slot identities on different chains. This is the
/// cryptographic underpinning of the role-split design: an attacker
/// who learned a slot key on chain A still cannot impersonate the user
/// on chain B.
pub fn slot_entropy(
    master_entropy: &[u8; 32],
    chain_id: u64,
    slot_index: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(master_entropy);
    h.update(b"slot_entropy");
    h.update(chain_id.to_be_bytes());
    h.update(slot_index.to_be_bytes());
    h.finalize().into()
}

/// Compute the per-slot randomiser `r`. Same chain-binding rule as
/// [`slot_entropy`].
pub fn slot_r(master_entropy: &[u8; 32], chain_id: u64, slot_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(master_entropy);
    h.update(b"slot_r");
    h.update(chain_id.to_be_bytes());
    h.update(slot_index.to_be_bytes());
    h.finalize().into()
}

/// Derive the slot C10 `(sk_seed_32, pk_seed_32)` pair from slot entropy.
/// `pk_seed_32` uses the N-mask layout (top 16 bytes populated, bottom 16
/// zero) to match the on-chain `bytes32` shape expected by the C10 verifier.
fn derive_c10_slot_seeds(slot_entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut sk_h = Sha256::new();
    sk_h.update(b"slot_c10_sk_seed");
    sk_h.update(slot_entropy);
    let sk_seed: [u8; 32] = sk_h.finalize().into();

    let mut pk_h = Sha256::new();
    pk_h.update(b"slot_c10_pk_seed");
    pk_h.update(slot_entropy);
    let pk_digest: [u8; 32] = pk_h.finalize().into();
    let mut pk_seed = [0u8; 32];
    pk_seed[..16].copy_from_slice(&pk_digest[..16]);

    (sk_seed, pk_seed)
}

/// Full slot-C10-keypair derivation including hypertree keygen.
///
/// Returns `(signing_key, pk_seed_32, pk_root_32)`, both pubkey halves in
/// the N-masked 32-byte layout the on-chain `slots[slotKey]` commitment
/// hashes over (`sha256(pk_seed[..16] || pk_root[..16])`).
///
/// **Expensive**: ~5-6 s on Cortex-M33 with the HASH peripheral. Callers
/// should cache the resulting `SigningKey` across signs of the same slot.
pub fn derive_c10_slot_keypair(
    master_entropy: &[u8; 32],
    chain_id: u64,
    slot_index: u32,
) -> (SigningKey, [u8; 32], [u8; 32]) {
    derive_c10_slot_keypair_with_progress(master_entropy, chain_id, slot_index, |_| {})
}

/// Progress-reporting variant of [`derive_c10_slot_keypair`].
pub fn derive_c10_slot_keypair_with_progress(
    master_entropy: &[u8; 32],
    chain_id: u64,
    slot_index: u32,
    progress: impl Fn(u8),
) -> (SigningKey, [u8; 32], [u8; 32]) {
    progress(0);
    let mut entropy = slot_entropy(master_entropy, chain_id, slot_index);
    let (sk_seed_32, pk_seed_32) = derive_c10_slot_seeds(&entropy);
    entropy.zeroize();

    let mut pk_seed_16 = [0u8; 16];
    pk_seed_16.copy_from_slice(&pk_seed_32[..16]);
    let mut sk_seed_arr = [0u8; 32];
    sk_seed_arr.copy_from_slice(&sk_seed_32);

    progress(10);
    let sk = SigningKey::keygen(sk_seed_arr, pk_seed_16);
    progress(100);

    let mut pk_root_32 = [0u8; 32];
    pk_root_32[..16].copy_from_slice(sk.pk_root());

    (sk, pk_seed_32, pk_root_32)
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

// ---------------------------------------------------------------------------
// Host-only tests for the SPHINCS+C10 derivation recovery contract.
// ---------------------------------------------------------------------------
//
// These assert byte-for-byte equality against values computed independently
// by a host Python script using hashlib + pycryptodome. The fixed mnemonic
// is BIP-39 24-word test vector 1 (entropy = 32 zero bytes, checksum 0x66,
// last word derived at index 102 → "art").
//
// If this test ever fails, someone has silently changed the recovery
// contract — the same 24 words will now produce a different on-chain wallet
// address. Treat this as a breaking-change red flag and revert the change.

#[cfg(test)]
mod c10_derivation_tests {
    use super::*;
    use sphincs_tz_bip39::Mnemonic;
    use std::string::String;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&std::format!("{:02x}", b));
        }
        out
    }

    /// Reference values for the SHA-256-based C10 bootstrap derivation.
    /// Mnemonic: `abandon abandon ... abandon art` (entropy = 32 zero bytes),
    /// empty passphrase.
    ///
    /// - `REF_BIP39_SEED` and `REF_MASTER` are unchanged (BIP-39 uses
    ///   PBKDF2-HMAC-SHA512; the bootstrap master's HMAC-SHA512 is also
    ///   unchanged — the HMAC tag `"sphincs-c6-v1"` is frozen by the
    ///   recovery contract).
    /// - `REF_PK_SEED` / `REF_SK_SEED` are the SHA-256 reductions over
    ///   `"pk_seed" || master[..32]` and `"sk_seed" || master[..32]`
    ///   — they are independent of the C10/C11 hypertree shape, so the
    ///   same values stayed valid across the C11 → C10 cutover. Only
    ///   `masterPkRoot` (built by hypertree keygen) changes, and that
    ///   lives in the `c10_master_keypair_produces_valid_signature` test
    ///   rather than a fixed hex constant.
    const REF_BIP39_SEED: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";
    const REF_MASTER: &str = "667261ca90c0989a022a50e6df59ae712c335076a19c252dfb81f81b06537a9a5c0dd6a84a695fdcf15c5e7279abcf9895be2905cde3fc93de929394f8feed38";
    const REF_PK_SEED: &str = "af6bc9b41afd361f3e8858a3d16826ff00000000000000000000000000000000";
    const REF_SK_SEED: &str = "383ae7407208edc6eb7f6718a60455bdee48f6b6601dc06f6dcfebebba0a100c";

    #[test]
    fn bip39_seed_matches_reference() {
        // Verify our BIP-39 impl produces the same PBKDF2 seed for the
        // fixed test mnemonic that Python's hashlib.pbkdf2_hmac produces.
        let mnemonic = Mnemonic::from_entropy(&[0u8; 32]);
        let seed = mnemonic.to_seed("");
        assert_eq!(hex(&seed), REF_BIP39_SEED, "BIP-39 seed drifted");
    }

    #[test]
    fn derive_c10_master_from_bip39_seed_matches_reference() {
        // Decode the reference bip39_seed from hex directly so this test
        // isolates the derive_c10_master_from_bip39_seed function from
        // our BIP-39 implementation.
        let mut seed = [0u8; 64];
        decode_hex_into(REF_BIP39_SEED, &mut seed);

        let (pk_seed, sk_seed) = derive_c10_master_from_bip39_seed(&seed, 0);
        assert_eq!(hex(&pk_seed), REF_PK_SEED, "pk_seed drifted");
        assert_eq!(hex(&sk_seed), REF_SK_SEED, "sk_seed drifted");
    }

    #[test]
    fn derive_c10_master_from_entropy_matches_reference() {
        // End-to-end from raw 32-byte entropy (which is what we actually
        // have on-device) through mnemonic → PBKDF2 → HMAC-SHA512 → SHA-256.
        let (pk_seed, sk_seed) = derive_c10_master_from_entropy(&[0u8; 32], 0);
        assert_eq!(hex(&pk_seed), REF_PK_SEED, "end-to-end pk_seed drifted");
        assert_eq!(hex(&sk_seed), REF_SK_SEED, "end-to-end sk_seed drifted");
    }

    #[test]
    fn c10_master_top_16_bytes_kept_bottom_zeroed() {
        // pk_seed must have its bottom 16 bytes zero (the N-mask).
        let (pk_seed, _) = derive_c10_master_from_bip39_seed(&[0u8; 64], 0);
        assert!(pk_seed[16..].iter().all(|&b| b == 0), "pk_seed bottom 16 must be zero");
    }

    #[test]
    fn c10_master_account_indices_yield_distinct_keys() {
        // Recovery contract: account 0 stays byte-identical to the legacy
        // single-account derivation; accounts 1+ MUST diverge so a single
        // seed yields independent on-chain wallet addresses per account.
        let seed = [0xAAu8; 32];
        let (pk0, sk0) = derive_c10_master_from_entropy(&seed, 0);
        let (pk1, sk1) = derive_c10_master_from_entropy(&seed, 1);
        let (pk2, sk2) = derive_c10_master_from_entropy(&seed, 2);
        let (pk255, sk255) = derive_c10_master_from_entropy(&seed, 255);
        assert_ne!(pk0, pk1, "account 1 must produce a distinct pk_seed");
        assert_ne!(sk0, sk1, "account 1 must produce a distinct sk_seed");
        assert_ne!(pk1, pk2, "account 2 must differ from account 1");
        assert_ne!(sk1, sk2, "account 2 must differ from account 1");
        assert_ne!(pk2, pk255, "account 255 must differ from account 2");
        assert_ne!(sk2, sk255, "account 255 must differ from account 2");
        // Determinism per account.
        let (pk1b, sk1b) = derive_c10_master_from_entropy(&seed, 1);
        assert_eq!((pk1, sk1), (pk1b, sk1b), "account 1 must be deterministic");
    }

    #[test]
    fn slot_master_entropy_account_indices_diverge() {
        let seed = [0xCDu8; 32];
        let m0 = slot_master_entropy_from_entropy(&seed, 0);
        let m1 = slot_master_entropy_from_entropy(&seed, 1);
        let m255 = slot_master_entropy_from_entropy(&seed, 255);
        assert_ne!(m0, m1, "slot master entropy must vary per account");
        assert_ne!(m1, m255, "slot master entropy must vary per account");
    }

    #[test]
    fn c10_master_is_deterministic() {
        let (pk1, sk1) = derive_c10_master_from_entropy(&[0xAAu8; 32], 0);
        let (pk2, sk2) = derive_c10_master_from_entropy(&[0xAAu8; 32], 0);
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn c10_master_distinct_entropy_distinct_keys() {
        let (pk_a, sk_a) = derive_c10_master_from_entropy(&[0u8; 32], 0);
        let (pk_b, sk_b) = derive_c10_master_from_entropy(&[1u8; 32], 0);
        assert_ne!(pk_a, pk_b);
        assert_ne!(sk_a, sk_b);
    }

    #[test]
    fn c10_master_keypair_produces_valid_signature() {
        // Full Type 1 flow: derive master → sign a 32-byte hash → verify.
        let (sk, master_pk_seed_32, master_pk_root_32) =
            derive_c10_master_keypair_from_entropy(&[0x17u8; 32], 0);

        // master_pk_seed_32 and master_pk_root_32 must be N-masked.
        assert!(master_pk_seed_32[16..].iter().all(|&b| b == 0));
        assert!(master_pk_root_32[16..].iter().all(|&b| b == 0));

        let msg = [0xBDu8; 32];
        let sig = c10_sign_verified(&sk, &msg).expect("c10 sign must succeed");
        assert_eq!(sig.len(), sphincs_c10::params::SIGNATURE_LEN);

        // Independent verify against the 16-byte pk_seed / pk_root.
        let mut pk_seed_16 = [0u8; 16];
        pk_seed_16.copy_from_slice(&master_pk_seed_32[..16]);
        let mut pk_root_16 = [0u8; 16];
        pk_root_16.copy_from_slice(&master_pk_root_32[..16]);
        assert!(sphincs_c10::verify(&pk_seed_16, &pk_root_16, &msg, &sig));

        // A different message must fail verification.
        let other_msg = [0xBEu8; 32];
        assert!(!sphincs_c10::verify(&pk_seed_16, &pk_root_16, &other_msg, &sig));
    }

    /// Decode an even-length lowercase hex string into a byte slice.
    fn decode_hex_into(hex_str: &str, out: &mut [u8]) {
        assert_eq!(hex_str.len(), out.len() * 2);
        let b = hex_str.as_bytes();
        for i in 0..out.len() {
            let hi = decode_nibble(b[2 * i]);
            let lo = decode_nibble(b[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
    }

    fn decode_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex nibble"),
        }
    }

}
