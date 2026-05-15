//! `pqsigner-domain` — pure-logic key derivation + AES-GCM wrap/unwrap
//! + BIP-39 → SPHINCS+C10 bridge.
//!
//! Phase 5 PR 5.3 of the modularity refactor extracted these helpers
//! out of `secure/src/crypto.rs`. `secure/src/crypto.rs` now re-exports
//! every item below via `pub use pqsigner_domain::*;` and keeps only
//! the helpers that need `crate::fi` (`c10_sign_verified*`) or the
//! `crate::secure_element::*` traits (`provision_from_mnemonic`,
//! `store_macd_encrypted`).
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
//! 1. Smaller secure-element footprint (32 B vs 48 B plaintext, 60 B vs
//!    76 B AES-GCM blob).
//! 2. The on-device secret is bit-for-bit identical to the user's
//!    recovery paper backup — there is no derived intermediate that
//!    could go stale if anything in the BIP-39 chain ever changes.
//!
//! The cost is one PBKDF2-HMAC-SHA512 (2048 iters) per unlock, dwarfed
//! by the SPHINCS+C10 signing time itself.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

use pqsigner_proto::MAX_ATTEMPTS;
use sphincs_c10::SigningKey;
use sphincs_tz_bip39::{Mnemonic, ENTROPY_BYTES};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// r-mem slot assignments (consumed by `secure_element` impls + provisioning)
// ---------------------------------------------------------------------------

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

const _: () = assert!(ENTROPY_BLOB_LEN == 60, "entropy blob layout must stay 60 B");

// ---------------------------------------------------------------------------
// KDF helpers
// ---------------------------------------------------------------------------

/// Three-input SHA-256 KDF: `SHA-256(domain ‖ input ‖ index)`.
///
/// The hash primitive is fixed to SHA-256 so the firmware can route the
/// inner block through the STM32U585 HASH peripheral (~1 cycle/byte
/// single-block, vs ~12 cycles/byte for software Keccak). The `kdf_sha256`
/// alias predates the cutover from Keccak-256 and is retained so callers
/// that want to be explicit about the primitive can keep doing so.
#[must_use]
pub fn kdf(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(input);
    h.update([index]);
    h.finalize().into()
}

/// Explicit alias for [`kdf`]; see that function for the contract.
#[inline]
#[must_use]
pub fn kdf_sha256(domain: &[u8], input: &[u8], index: u8) -> [u8; 32] {
    kdf(domain, input, index)
}

#[must_use]
pub fn macd_init_input(master_secret: &[u8; 32], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-init", master_secret, j)
}

#[must_use]
pub fn macd_pin_input(pin: &[u8; 8], j: u8) -> [u8; 32] {
    kdf(b"sphincs-macd-pin", pin, j)
}

#[must_use]
pub fn derive_wrap_key(master_secret: &[u8; 32]) -> [u8; 32] {
    kdf(b"sphincs-wrap-key", master_secret, 0)
}

#[must_use]
pub fn derive_entropy_nonce(master_secret: &[u8; 32]) -> [u8; 12] {
    truncate_to_nonce(&kdf(b"sphincs-entropy-nonce", master_secret, 0))
}

fn nonce_for(index: u8) -> [u8; 12] {
    truncate_to_nonce(&kdf(b"sphincs-nonce", &[index], 0))
}

/// First 12 bytes of a 32-byte digest, formatted as a 96-bit AES-GCM nonce.
fn truncate_to_nonce(digest: &[u8; 32]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n.copy_from_slice(&digest[..12]);
    n
}

// ---------------------------------------------------------------------------
// AES-GCM helpers (in-place, no_std)
// ---------------------------------------------------------------------------

/// AES-256-GCM tag length in bytes (RFC 5116 §3.2 "AES_256_GCM").
pub const AES_GCM_TAG_LEN: usize = 16;

/// Construct the AES-256-GCM cipher. Infallible: `AES-256` accepts any
/// 32-byte key, and that is the only key length we expose.
fn aes256_gcm(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("AES-256-GCM accepts a 32-byte key")
}

pub fn aes_encrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    plaintext_len: usize,
    nonce_idx: u8,
) -> usize {
    let nonce = nonce_for(nonce_idx);
    let tag = aes256_gcm(key)
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut buf[..plaintext_len])
        // AEAD encryption is infallible for short inputs (well under the
        // 2^39-bit GCM limit); the only documented failure is exceeding
        // that length, which the secure world's stack-only buffers cannot.
        .expect("AES-GCM encrypt cannot fail for these input lengths");
    buf[plaintext_len..plaintext_len + AES_GCM_TAG_LEN].copy_from_slice(&tag);
    plaintext_len + AES_GCM_TAG_LEN
}

pub fn aes_decrypt_inplace(
    key: &[u8; 32],
    buf: &mut [u8],
    ct_len: usize,
    nonce_idx: u8,
) -> Result<usize, ()> {
    if ct_len < AES_GCM_TAG_LEN {
        return Err(());
    }
    let plaintext_len = ct_len - AES_GCM_TAG_LEN;
    let nonce = nonce_for(nonce_idx);
    let (ct, tag_bytes) = buf[..ct_len].split_at_mut(plaintext_len);
    let tag = aes_gcm::Tag::from_slice(tag_bytes);
    aes256_gcm(key)
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], ct, tag)
        .map_err(|_| ())?;
    Ok(plaintext_len)
}

// ---------------------------------------------------------------------------
// Entropy encryption/decryption with the master secret
// ---------------------------------------------------------------------------

/// Encrypt the 32-byte BIP-39 entropy under the wrap key derived from
/// `master_secret`. Output layout: `nonce(12) ‖ ciphertext(32) ‖ tag(16)`.
#[must_use]
pub fn encrypt_entropy_blob(
    entropy: &[u8; ENTROPY_LEN],
    master_secret: &[u8; 32],
) -> [u8; ENTROPY_BLOB_LEN] {
    const CT_END: usize = 12 + ENTROPY_LEN;

    let mut wrap = derive_wrap_key(master_secret);
    let nonce = derive_entropy_nonce(master_secret);

    let mut blob = [0u8; ENTROPY_BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..CT_END].copy_from_slice(entropy);

    let tag = aes256_gcm(&wrap)
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut blob[12..CT_END])
        .expect("AES-GCM encrypt cannot fail for a 32-byte plaintext");
    blob[CT_END..].copy_from_slice(&tag);

    wrap.zeroize();
    blob
}

/// Decrypt a stored entropy blob with the master secret. Returns the
/// 32-byte BIP-39 entropy on success.
pub fn decrypt_entropy_blob(
    blob: &[u8],
    master_secret: &[u8; 32],
) -> Result<[u8; ENTROPY_LEN], ()> {
    const CT_END: usize = 12 + ENTROPY_LEN;

    if blob.len() != ENTROPY_BLOB_LEN {
        return Err(());
    }
    let mut wrap = derive_wrap_key(master_secret);
    // The blob's leading 12 bytes are the nonce. We trust it because the
    // wrap key is master-bound — an attacker who mutates the nonce only
    // affects this wallet's own decryption.
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut entropy_buf = [0u8; ENTROPY_LEN];
    entropy_buf.copy_from_slice(&blob[12..CT_END]);
    let tag = aes_gcm::Tag::from_slice(&blob[CT_END..]);

    let r = aes256_gcm(&wrap)
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &[], &mut entropy_buf, tag)
        .map_err(|_| ());

    wrap.zeroize();
    r?;
    Ok(entropy_buf)
}

/// Split a 48-byte SPHINCS+C10 seed into its `(sk_seed_32, pk_seed_16)`
/// halves. The bytes are copied, so the caller is free to zeroize the
/// source buffer immediately after.
fn split_seed_48(seed: &[u8; SEED_LEN]) -> ([u8; 32], [u8; 16]) {
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 16];
    sk_seed.copy_from_slice(&seed[0..32]);
    pk_seed.copy_from_slice(&seed[32..48]);
    (sk_seed, pk_seed)
}

/// Run PBKDF2-HMAC-SHA512 on the BIP-39 mnemonic for `entropy`, hand the
/// resulting 64-byte seed to `f`, then zeroize the seed.
///
/// Centralises the "mnemonic → bip39_seed → use → wipe" pattern so every
/// derivation that consumes raw entropy has the same wipe discipline.
fn with_bip39_seed<T>(entropy: &[u8; ENTROPY_LEN], f: impl FnOnce(&[u8; 64]) -> T) -> T {
    let mnemonic = Mnemonic::from_entropy(entropy);
    let mut bip39_seed = mnemonic.to_seed("");
    let result = f(&bip39_seed);
    bip39_seed.zeroize();
    // mnemonic Drop zeros its 24 word indices.
    result
}

/// Derive a fully-formed SPHINCS+C10 signing key from a 48-byte seed.
/// Calls `SigningKey::keygen` which builds the full hypertree — the
/// `pk_root` Merkle root is *computed* from `(sk_seed, pk_seed)`.
///
/// **Expensive** (~10s on Cortex-M33). At provisioning time, compute once
/// and cache the VK. At signing time, use `SigningKey::from_parts` with
/// the cached `pk_root` to skip the hypertree rebuild.
#[must_use]
pub fn derive_signing_key(seed: &[u8; SEED_LEN]) -> SigningKey {
    let (sk_seed, pk_seed) = split_seed_48(seed);
    SigningKey::keygen(sk_seed, pk_seed)
}

/// Build a `SigningKey` from a 48-byte seed + cached pk_root, skipping the
/// hypertree rebuild. Used by every `_fast` derivation path.
fn signing_key_from_parts_with_seed(
    seed: &[u8; SEED_LEN],
    cached_pk_root: &[u8; 16],
) -> SigningKey {
    let (sk_seed, pk_seed) = split_seed_48(seed);
    SigningKey::from_parts(sk_seed, pk_seed, *cached_pk_root)
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
#[must_use]
pub fn slhdsa_seed_from_bip39(bip39_seed: &[u8; 64]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    let chunk0 = kdf_sha256(b"sphincsc7-sk-seed", bip39_seed, 0);
    let chunk1 = kdf_sha256(b"sphincsc7-pk-seed", bip39_seed, 0);
    out[0..32].copy_from_slice(&chunk0); // sk_seed: full 32 bytes
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
#[must_use]
pub fn derive_signing_key_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> SigningKey {
    with_bip39_seed(entropy, |bip39_seed| {
        let mut slh_seed = slhdsa_seed_from_bip39(bip39_seed);
        let sk = derive_signing_key(&slh_seed);
        slh_seed.zeroize();
        sk
    })
}

/// Fast-path signing key derivation: re-derive `(sk_seed, pk_seed)` from
/// entropy via the BIP-39 chain, then reconstruct the `SigningKey` using
/// `from_parts` with a pre-computed `pk_root` (read from r-mem at call
/// site). Skips the expensive hypertree rebuild (~10-15s on Cortex-M33).
///
/// The caller MUST supply a `pk_root` that was computed by the same
/// `(sk_seed, pk_seed)` -- i.e., the VK cached at provisioning time.
#[must_use]
pub fn derive_signing_key_from_entropy_fast(
    entropy: &[u8; ENTROPY_LEN],
    cached_pk_root: &[u8; 16],
) -> SigningKey {
    with_bip39_seed(entropy, |bip39_seed| {
        let mut slh_seed = slhdsa_seed_from_bip39(bip39_seed);
        let sk = signing_key_from_parts_with_seed(&slh_seed, cached_pk_root);
        slh_seed.zeroize();
        sk
    })
}

/// Fast-path bootstrap signing key derivation: same as
/// `derive_bootstrap_key_from_entropy` but uses a cached `pk_root`
/// instead of rebuilding the hypertree.
#[must_use]
pub fn derive_bootstrap_key_from_entropy_fast(
    entropy: &[u8; ENTROPY_LEN],
    cached_pk_root: &[u8; 16],
) -> SigningKey {
    with_bip39_seed(entropy, |bip39_seed| {
        let mut seed = bootstrap_seed_from_bip39(bip39_seed);
        let sk = signing_key_from_parts_with_seed(&seed, cached_pk_root);
        seed.zeroize();
        sk
    })
}

/// Same as `derive_signing_key_from_entropy` but also returns the 32-byte
/// verifying key bytes. Used by provisioning to cache the VK in r-mem
/// slot 2 without keeping the full SigningKey alive longer than necessary.
#[must_use]
pub fn derive_keypair_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> (SigningKey, [u8; 32]) {
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
#[must_use]
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
#[must_use]
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
#[must_use]
pub fn derive_bootstrap_key_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> SigningKey {
    with_bip39_seed(entropy, |bip39_seed| {
        let mut seed = bootstrap_seed_from_bip39(bip39_seed);
        let sk = derive_signing_key(&seed);
        seed.zeroize();
        sk
    })
}

/// Derive the bootstrap keypair (signing key + 32-byte verifying key).
#[must_use]
pub fn derive_bootstrap_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
) -> (SigningKey, [u8; 32]) {
    let sk = derive_bootstrap_key_from_entropy(entropy);
    let vk_bytes = sk.verifying_key().to_bytes();
    (sk, vk_bytes)
}

/// Derive a per-chain main signing key from BIP-39 entropy.
#[must_use]
pub fn derive_main_key_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    chain_id: u64,
    key_index: u32,
) -> SigningKey {
    with_bip39_seed(entropy, |bip39_seed| {
        let mut seed = main_signer_seed_from_bip39(bip39_seed, chain_id, key_index);
        let sk = derive_signing_key(&seed);
        seed.zeroize();
        sk
    })
}

/// Derive a per-chain main keypair (signing key + 32-byte verifying key).
#[must_use]
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
#[must_use]
pub fn derive_bootstrap_vk_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> [u8; 32] {
    derive_bootstrap_keypair_from_entropy(entropy).1
}

/// Derive a per-chain main verifying key bytes only.
#[must_use]
pub fn derive_main_vk_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    chain_id: u64,
    key_index: u32,
) -> [u8; 32] {
    derive_main_keypair_from_entropy(entropy, chain_id, key_index).1
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
#[must_use]
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
#[must_use]
pub fn slot_master_entropy_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> [u8; 32] {
    with_bip39_seed(entropy, |bip39_seed| {
        slot_master_entropy_from_bip39(bip39_seed, account_index)
    })
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
#[must_use]
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
    let mut master = [0u8; 64];
    master.copy_from_slice(&mac.finalize().into_bytes());
    let master_lo = &master[..32];

    // Step 2: pk_seed = mask_n(sha256("pk_seed" || master[0..32]))
    //   mask_n keeps bytes [0..16] and zeros bytes [16..32].
    let pk_digest: [u8; 32] = Sha256::new()
        .chain_update(b"pk_seed")
        .chain_update(master_lo)
        .finalize()
        .into();
    let mut pk_seed = [0u8; 32];
    pk_seed[..16].copy_from_slice(&pk_digest[..16]);

    // Step 3: sk_seed = sha256("sk_seed" || master[0..32])  (full 32 bytes, no mask).
    let sk_seed: [u8; 32] = Sha256::new()
        .chain_update(b"sk_seed")
        .chain_update(master_lo)
        .finalize()
        .into();

    master.zeroize();

    (pk_seed, sk_seed)
}

/// Convenience wrapper: run the BIP-39 chain from 32-byte entropy, then
/// derive the C10 bootstrap keys for `account_index`. Wipes the
/// intermediate `bip39_seed`.
#[must_use]
pub fn derive_c10_master_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> ([u8; 32], [u8; 32]) {
    with_bip39_seed(entropy, |bip39_seed| {
        derive_c10_master_from_bip39_seed(bip39_seed, account_index)
    })
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
/// Type 1 signature. On Cortex-M33 this takes <1 s with the HASH
/// peripheral; on QEMU it takes much less.
#[must_use]
pub fn derive_c10_master_keypair_from_entropy(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
) -> (SigningKey, [u8; 32], [u8; 32]) {
    derive_c10_master_keypair_from_entropy_with_progress(entropy, account_index, |_| {})
}

/// Like [`derive_c10_master_keypair_from_entropy`] but reports 0..100 keygen
/// progress via the supplied callback so a trusted-UI progress bar can be
/// kept responsive during the multi-second operation.
pub fn derive_c10_master_keypair_from_entropy_with_progress(
    entropy: &[u8; ENTROPY_LEN],
    account_index: u32,
    progress: impl Fn(u8),
) -> (SigningKey, [u8; 32], [u8; 32]) {
    progress(0);
    let (pk_seed_32, sk_seed_32) = derive_c10_master_from_entropy(entropy, account_index);
    progress(10);
    let (sk, pk_root_32) = c10_keygen_from_n_masked_seeds(&sk_seed_32, &pk_seed_32);
    progress(100);
    (sk, pk_seed_32, pk_root_32)
}

/// Run `SigningKey::keygen` over the N-masked 32-byte seed layout used
/// across this crate, returning the signing key alongside the N-masked
/// 32-byte `pk_root` suitable for on-chain storage.
///
/// `sphincs-c10` itself takes a 16-byte `pk_seed`; we accept the 32-byte
/// layout (top 16 populated, bottom 16 zero) here to keep callers honest
/// about the on-chain `bytes32` shape.
fn c10_keygen_from_n_masked_seeds(
    sk_seed_32: &[u8; 32],
    pk_seed_32: &[u8; 32],
) -> (SigningKey, [u8; 32]) {
    let mut pk_seed_16 = [0u8; 16];
    pk_seed_16.copy_from_slice(&pk_seed_32[..16]);
    let sk = SigningKey::keygen(*sk_seed_32, pk_seed_16);

    let mut pk_root_32 = [0u8; 32];
    pk_root_32[..16].copy_from_slice(sk.pk_root());
    (sk, pk_root_32)
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
#[must_use]
pub fn slot_entropy(master_entropy: &[u8; 32], chain_id: u64, slot_index: u32) -> [u8; 32] {
    slot_field(master_entropy, b"slot_entropy", chain_id, slot_index)
}

/// Compute the per-slot randomiser `r`. Same chain-binding rule as
/// [`slot_entropy`].
#[must_use]
pub fn slot_r(master_entropy: &[u8; 32], chain_id: u64, slot_index: u32) -> [u8; 32] {
    slot_field(master_entropy, b"slot_r", chain_id, slot_index)
}

/// `sha256(master_entropy ‖ tag ‖ chain_id_be8 ‖ slot_index_be4)` —
/// shared shape between [`slot_entropy`] and [`slot_r`].
fn slot_field(
    master_entropy: &[u8; 32],
    tag: &[u8],
    chain_id: u64,
    slot_index: u32,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(master_entropy)
        .chain_update(tag)
        .chain_update(chain_id.to_be_bytes())
        .chain_update(slot_index.to_be_bytes())
        .finalize()
        .into()
}

/// Derive the slot C10 `(sk_seed_32, pk_seed_32)` pair from slot entropy.
/// `pk_seed_32` uses the N-mask layout (top 16 bytes populated, bottom 16
/// zero) to match the on-chain `bytes32` shape expected by the C10 verifier.
fn derive_c10_slot_seeds(slot_entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sk_seed: [u8; 32] = Sha256::new()
        .chain_update(b"slot_c10_sk_seed")
        .chain_update(slot_entropy)
        .finalize()
        .into();

    let pk_digest: [u8; 32] = Sha256::new()
        .chain_update(b"slot_c10_pk_seed")
        .chain_update(slot_entropy)
        .finalize()
        .into();
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
/// **Expensive**: <1 s on Cortex-M33 with the HASH peripheral. Callers
/// should cache the resulting `SigningKey` across signs of the same slot.
#[must_use]
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

    progress(10);
    let (sk, pk_root_32) = c10_keygen_from_n_masked_seeds(&sk_seed_32, &pk_seed_32);
    progress(100);

    (sk, pk_seed_32, pk_root_32)
}

// ---------------------------------------------------------------------------
// PIN state serialization (used by the mock-SE MACD path)
// ---------------------------------------------------------------------------

/// Encrypted master-secret slot: AES-GCM ciphertext (32 B) ‖ tag (16 B).
pub const PER_SLOT_CT_LEN: usize = 32 + AES_GCM_TAG_LEN;

/// Max serialised PIN-state blob: 1-byte `next_index` + one slot per
/// attempt. 481 B at `MAX_ATTEMPTS = 10`.
pub const PIN_STATE_MAX_LEN: usize = 1 + MAX_ATTEMPTS as usize * PER_SLOT_CT_LEN;

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
    /// Number of populated entries in `encrypted_secrets`
    /// (entries `num_slots..MAX_ATTEMPTS` are zeroed).
    pub num_slots: usize,
    pub encrypted_secrets: [[u8; PER_SLOT_CT_LEN]; MAX_ATTEMPTS as usize],
}

pub fn deserialize_pin_state(blob: &[u8], blob_len: usize) -> Result<PinState, ()> {
    if blob_len == 0 || blob_len > PIN_STATE_MAX_LEN {
        return Err(());
    }
    let next_index = blob[0];
    let rest = &blob[1..blob_len];
    if !rest.len().is_multiple_of(PER_SLOT_CT_LEN) {
        return Err(());
    }
    let num_slots = rest.len() / PER_SLOT_CT_LEN;
    // `blob_len <= PIN_STATE_MAX_LEN` already bounds `num_slots <= MAX_ATTEMPTS`,
    // but we check explicitly so a future MAX_ATTEMPTS bump cannot silently
    // panic.
    if num_slots > MAX_ATTEMPTS as usize {
        return Err(());
    }
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
    const REF_BIP39_SEED: &str = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";
    const REF_PK_SEED: &str = "af6bc9b41afd361f3e8858a3d16826ff00000000000000000000000000000000";
    const REF_SK_SEED: &str = "383ae7407208edc6eb7f6718a60455bdee48f6b6601dc06f6dcfebebba0a100c";

    #[test]
    fn bip39_seed_matches_reference() {
        let mnemonic = Mnemonic::from_entropy(&[0u8; 32]);
        let seed = mnemonic.to_seed("");
        assert_eq!(hex(&seed), REF_BIP39_SEED, "BIP-39 seed drifted");
    }

    #[test]
    fn derive_c10_master_from_bip39_seed_matches_reference() {
        let mut seed = [0u8; 64];
        decode_hex_into(REF_BIP39_SEED, &mut seed);

        let (pk_seed, sk_seed) = derive_c10_master_from_bip39_seed(&seed, 0);
        assert_eq!(hex(&pk_seed), REF_PK_SEED, "pk_seed drifted");
        assert_eq!(hex(&sk_seed), REF_SK_SEED, "sk_seed drifted");
    }

    #[test]
    fn derive_c10_master_from_entropy_matches_reference() {
        let (pk_seed, sk_seed) = derive_c10_master_from_entropy(&[0u8; 32], 0);
        assert_eq!(hex(&pk_seed), REF_PK_SEED, "end-to-end pk_seed drifted");
        assert_eq!(hex(&sk_seed), REF_SK_SEED, "end-to-end sk_seed drifted");
    }

    #[test]
    fn c10_master_top_16_bytes_kept_bottom_zeroed() {
        let (pk_seed, _) = derive_c10_master_from_bip39_seed(&[0u8; 64], 0);
        assert!(pk_seed[16..].iter().all(|&b| b == 0), "pk_seed bottom 16 must be zero");
    }

    #[test]
    fn c10_master_account_indices_yield_distinct_keys() {
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
        let sig = sk.sign(&msg, None);
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

#[cfg(test)]
mod aes_gcm_tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x55u8; 32];
        let plaintext = [0xA5u8; 64];
        let mut buf = [0u8; 64 + AES_GCM_TAG_LEN];
        buf[..64].copy_from_slice(&plaintext);

        let ct_len = aes_encrypt_inplace(&key, &mut buf, 64, 7);
        assert_eq!(ct_len, 64 + AES_GCM_TAG_LEN);
        assert_ne!(&buf[..64], &plaintext, "ciphertext must differ from plaintext");

        let pt_len = aes_decrypt_inplace(&key, &mut buf, ct_len, 7).expect("decrypt");
        assert_eq!(pt_len, 64);
        assert_eq!(&buf[..64], &plaintext, "decrypted plaintext mismatch");
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let key = [0u8; 32];
        let mut buf = [0u8; AES_GCM_TAG_LEN - 1];
        let n = buf.len();
        assert!(aes_decrypt_inplace(&key, &mut buf, n, 0).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let mut buf = [0u8; 32 + AES_GCM_TAG_LEN];
        let ct_len = aes_encrypt_inplace(&[0x11u8; 32], &mut buf, 32, 3);
        assert!(aes_decrypt_inplace(&[0x22u8; 32], &mut buf, ct_len, 3).is_err());
    }

    #[test]
    fn decrypt_rejects_wrong_nonce_index() {
        let mut buf = [0u8; 32 + AES_GCM_TAG_LEN];
        let ct_len = aes_encrypt_inplace(&[0x33u8; 32], &mut buf, 32, 5);
        assert!(aes_decrypt_inplace(&[0x33u8; 32], &mut buf, ct_len, 6).is_err());
    }

    #[test]
    fn entropy_blob_roundtrip() {
        let entropy = [0x7Du8; ENTROPY_LEN];
        let master = [0xC3u8; 32];
        let blob = encrypt_entropy_blob(&entropy, &master);
        assert_eq!(blob.len(), ENTROPY_BLOB_LEN);
        let out = decrypt_entropy_blob(&blob, &master).expect("decrypt");
        assert_eq!(out, entropy);
    }

    #[test]
    fn entropy_blob_rejects_wrong_master() {
        let entropy = [0u8; ENTROPY_LEN];
        let blob = encrypt_entropy_blob(&entropy, &[0xAAu8; 32]);
        assert!(decrypt_entropy_blob(&blob, &[0xBBu8; 32]).is_err());
    }

    #[test]
    fn entropy_blob_rejects_wrong_length() {
        let mut blob = [0u8; ENTROPY_BLOB_LEN - 1];
        assert!(decrypt_entropy_blob(&blob, &[0u8; 32]).is_err());
        let _ = &mut blob; // silence "unused mut"
    }
}

#[cfg(test)]
mod pin_state_tests {
    use super::*;

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut slots = [[0u8; PER_SLOT_CT_LEN]; 3];
        for (i, s) in slots.iter_mut().enumerate() {
            s.fill(0x10 + i as u8);
        }
        let mut buf = [0u8; PIN_STATE_MAX_LEN];
        let len = serialize_pin_state(2, &slots, &mut buf);
        assert_eq!(len, 1 + 3 * PER_SLOT_CT_LEN);

        let ps = deserialize_pin_state(&buf, len).expect("deserialize");
        assert_eq!(ps.next_index, 2);
        assert_eq!(ps.num_slots, 3);
        for (i, expected) in slots.iter().enumerate() {
            assert_eq!(&ps.encrypted_secrets[i], expected);
        }
    }

    #[test]
    fn deserialize_rejects_empty_blob() {
        assert!(deserialize_pin_state(&[], 0).is_err());
    }

    #[test]
    fn deserialize_rejects_misaligned_blob() {
        let buf = [0u8; 1 + PER_SLOT_CT_LEN + 1];
        assert!(deserialize_pin_state(&buf, buf.len()).is_err());
    }

    #[test]
    fn deserialize_rejects_overlong_blob() {
        let buf = [0u8; PIN_STATE_MAX_LEN + PER_SLOT_CT_LEN];
        assert!(deserialize_pin_state(&buf, buf.len()).is_err());
    }
}

#[cfg(test)]
mod kdf_tests {
    use super::*;

    #[test]
    fn kdf_alias_matches_kdf() {
        let a = kdf(b"dom", b"input", 3);
        let b = kdf_sha256(b"dom", b"input", 3);
        assert_eq!(a, b);
    }

    #[test]
    fn kdf_distinguishes_index() {
        assert_ne!(kdf(b"d", b"i", 0), kdf(b"d", b"i", 1));
    }

    #[test]
    fn kdf_distinguishes_domain() {
        assert_ne!(kdf(b"d1", b"i", 0), kdf(b"d2", b"i", 0));
    }

    #[test]
    fn derive_entropy_nonce_is_master_bound() {
        let n1 = derive_entropy_nonce(&[0u8; 32]);
        let n2 = derive_entropy_nonce(&[1u8; 32]);
        assert_ne!(n1, n2);
    }
}
