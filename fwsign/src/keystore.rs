//! Encrypted-at-rest vendor signing key.
//!
//! The vendor signing key is a SPHINCS+C10 keypair: 32 bytes of sk_seed
//! plus the derived 16-byte pk_seed and 16-byte pk_root. Losing it bricks
//! the ability to sign new releases (every device's FSBL holds the
//! matching pubkey and RDP-2 makes FSBL immutable), so the at-rest
//! encryption has to be serious — but also usable by humans, so it's
//! passphrase-based via Argon2id + XChaCha20-Poly1305 AEAD.
//!
//! ## Threat model
//!
//! * **Laptop seized**: without the passphrase, the key is useless.
//!   Argon2id with 64 MiB memory + 3 iterations makes offline brute-force
//!   ~1 s per guess on commodity hardware — enough to make any passphrase
//!   above ~8 words of entropy impractical to crack.
//! * **Malware on the signing machine during signing**: out of scope;
//!   the design assumes the signing machine is air-gapped. If it isn't,
//!   everything is lost the moment the key is decrypted.
//! * **Quantum adversary against the KDF/AEAD**: Argon2id and
//!   XChaCha20-Poly1305 are not PQ-secure themselves, but a CRQC that
//!   breaks them also breaks every pre-PQ crypto primitive on the
//!   planet — in that world the threat model is different. The
//!   *signature primitive* (SPHINCS+C10) is PQ-secure, which is what
//!   matters for firmware authenticity.
//!
//! ## Blob format
//!
//! ```text
//! offset  size  field
//!   0      4   magic "PQSK"  (PQSigner Key)
//!   4      2   version 0x0001 BE
//!   6     16   argon2id salt
//!  22     24   XChaCha20-Poly1305 nonce
//!  46     16   Poly1305 tag
//!  62     64   ciphertext: sk_seed(32) || pk_seed(16) || pk_root(16)
//! ```
//!
//! Total: 126 bytes, fits in a single FIDO2 writable file or a QR code.

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use sphincs_c10::{params::N, SigningKey};
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"PQSK";
const VERSION: u16 = 0x0001;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const PLAIN_LEN: usize = 32 + N + N; // 64
const CIPHER_LEN: usize = PLAIN_LEN; // XChaCha20 keeps ciphertext len == plaintext len
const HEADER_LEN: usize = 4 + 2 + SALT_LEN + NONCE_LEN + TAG_LEN; // 62
pub const BLOB_LEN: usize = HEADER_LEN + CIPHER_LEN; // 126

// Named offsets into the 126-byte blob. Keeping these as constants — rather
// than repeating `6 + SALT_LEN + NONCE_LEN + ...` arithmetic at every use —
// makes the seal/open layout match the format-table in the module docs at a
// glance and prevents an off-by-one if the header layout ever shifts.
const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = MAGIC_OFFSET + 4;
const SALT_OFFSET: usize = VERSION_OFFSET + 2;
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LEN;
const TAG_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;
const CIPHER_OFFSET: usize = HEADER_LEN;

// Argon2id parameters. OWASP 2024 recommendation for disk-encryption use
// cases — 64 MiB memory, 3 iterations, parallelism 4. Strikes a balance
// between signing-machine tolerability (~1 s to unlock) and attacker
// brute-force cost.
const ARGON_MEM_KIB: u32 = 64 * 1024;
const ARGON_ITERS: u32 = 3;
const ARGON_PARALLELISM: u32 = 4;

/// In-memory vendor signing key. Zeroised on drop.
pub struct VendorKey {
    sk_seed: Zeroizing<[u8; 32]>,
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

impl VendorKey {
    /// Assemble from raw components. Test-only — production paths always
    /// go through `generate` or `open` so the `sk_seed`/`pk_seed` invariants
    /// (`pk_seed` masked, `pk_root` derived from a real keygen) hold.
    #[cfg(test)]
    pub fn from_parts(sk_seed: [u8; 32], pk_seed: [u8; N], pk_root: [u8; N]) -> Self {
        Self {
            sk_seed: Zeroizing::new(sk_seed),
            pk_seed,
            pk_root,
        }
    }

    /// Generate a fresh key from the OS RNG and run full keygen. The
    /// 2-3 s hypertree build runs once per vendor-key lifetime, not
    /// per signing operation.
    pub fn generate() -> Result<Self> {
        let mut sk_seed = Zeroizing::new([0u8; 32]);
        let mut pk_seed = [0u8; N];
        OsRng.fill_bytes(&mut sk_seed[..]);
        OsRng.fill_bytes(&mut pk_seed[..]);

        let signing_key = SigningKey::keygen(*sk_seed, pk_seed);
        let pk_root = *signing_key.pk_root();

        Ok(Self {
            sk_seed,
            pk_seed,
            pk_root,
        })
    }

    pub fn pk_seed(&self) -> &[u8; N] {
        &self.pk_seed
    }

    pub fn pk_root(&self) -> &[u8; N] {
        &self.pk_root
    }

    /// Sign a 32-byte message hash. The signing key is reconstructed
    /// from the stored seeds on every call — SPHINCS+C10 doesn't have
    /// mutable secret state beyond the seed, so this is free.
    pub fn sign(&self, msg_hash: &[u8; 32]) -> [u8; sphincs_c10::params::SIGNATURE_LEN] {
        let sk = SigningKey::from_parts(*self.sk_seed, self.pk_seed, self.pk_root);
        sk.sign(msg_hash, None)
    }

    /// Encrypt under a passphrase and return the serialized blob.
    pub fn seal(&self, passphrase: &str) -> Result<[u8; BLOB_LEN]> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        derive_key(passphrase, &salt, &mut key_bytes)?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

        // Build plaintext: sk_seed || pk_seed || pk_root.
        let mut plain = Zeroizing::new([0u8; PLAIN_LEN]);
        plain[..32].copy_from_slice(&self.sk_seed[..]);
        plain[32..32 + N].copy_from_slice(&self.pk_seed);
        plain[32 + N..].copy_from_slice(&self.pk_root);

        // AAD binds the magic + version + salt + nonce to the
        // ciphertext so any tampering of the header is detected on
        // decrypt.
        let aad = aad_bytes(&salt, &nonce);

        let sealed = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain[..],
                    aad: &aad,
                },
            )
            .map_err(|e| anyhow!("AEAD encryption failed: {e}"))?;

        if sealed.len() != CIPHER_LEN + TAG_LEN {
            bail!(
                "unexpected ciphertext length: got {}, want {}",
                sealed.len(),
                CIPHER_LEN + TAG_LEN
            );
        }

        // chacha20poly1305's `encrypt` returns ciphertext || tag. We split
        // them back out so the on-disk layout is header || tag || ciphertext
        // — keeping the tag adjacent to its metadata makes the blob easier
        // to hand-parse and matches the format-table in the module docs.
        let (ct, tag) = sealed.split_at(CIPHER_LEN);

        let mut blob = [0u8; BLOB_LEN];
        blob[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&MAGIC);
        blob[VERSION_OFFSET..VERSION_OFFSET + 2].copy_from_slice(&VERSION.to_be_bytes());
        blob[SALT_OFFSET..SALT_OFFSET + SALT_LEN].copy_from_slice(&salt);
        blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce);
        blob[TAG_OFFSET..TAG_OFFSET + TAG_LEN].copy_from_slice(tag);
        blob[CIPHER_OFFSET..CIPHER_OFFSET + CIPHER_LEN].copy_from_slice(ct);

        Ok(blob)
    }

    /// Decrypt + deserialize a blob produced by `seal`.
    pub fn open(blob: &[u8], passphrase: &str) -> Result<Self> {
        if blob.len() != BLOB_LEN {
            bail!(
                "vendor-key blob wrong size: got {} bytes, want {BLOB_LEN}",
                blob.len(),
            );
        }
        if blob[MAGIC_OFFSET..MAGIC_OFFSET + 4] != MAGIC {
            bail!("vendor-key blob bad magic: not a PQSK blob");
        }
        let version = u16::from_be_bytes([blob[VERSION_OFFSET], blob[VERSION_OFFSET + 1]]);
        if version != VERSION {
            bail!("vendor-key blob unsupported version: {version:#06x} (want {VERSION:#06x})");
        }

        let salt = &blob[SALT_OFFSET..SALT_OFFSET + SALT_LEN];
        let nonce = &blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN];
        let tag = &blob[TAG_OFFSET..TAG_OFFSET + TAG_LEN];
        let ct = &blob[CIPHER_OFFSET..CIPHER_OFFSET + CIPHER_LEN];

        let mut key_bytes = Zeroizing::new([0u8; 32]);
        derive_key(passphrase, salt, &mut key_bytes)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes[..]));

        // Reassemble ciphertext || tag in the layout chacha20poly1305 expects.
        let mut sealed = Vec::with_capacity(CIPHER_LEN + TAG_LEN);
        sealed.extend_from_slice(ct);
        sealed.extend_from_slice(tag);

        // Wrapping the plaintext in `Zeroizing` ensures it is wiped on
        // every exit path (success, length mismatch, or panic unwind) —
        // zeroize's `alloc` feature implements `Zeroize for Vec<u8>` which
        // `Zeroizing`'s Drop calls.
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: &sealed,
                        aad: &aad_bytes(salt, nonce),
                    },
                )
                .map_err(|_| {
                    anyhow!("AEAD decryption failed (wrong passphrase or tampered blob)")
                })?,
        );

        if plain.len() != PLAIN_LEN {
            bail!("decrypted payload wrong length");
        }

        let mut sk_seed = Zeroizing::new([0u8; 32]);
        sk_seed.copy_from_slice(&plain[..32]);
        let mut pk_seed = [0u8; N];
        pk_seed.copy_from_slice(&plain[32..32 + N]);
        let mut pk_root = [0u8; N];
        pk_root.copy_from_slice(&plain[32 + N..]);

        Ok(Self {
            sk_seed,
            pk_seed,
            pk_root,
        })
    }
}

fn aad_bytes(salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    // "PQSK" || version || salt || nonce — every byte the decryptor
    // sees before the ciphertext, so any header tamper is detected.
    let mut aad = Vec::with_capacity(HEADER_LEN - TAG_LEN);
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&VERSION.to_be_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

fn derive_key(passphrase: &str, salt: &[u8], out: &mut [u8; 32]) -> Result<()> {
    let params = argon2::Params::new(ARGON_MEM_KIB, ARGON_ITERS, ARGON_PARALLELISM, None)
        .map_err(|e| anyhow!("bad argon2 params: {e}"))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out[..])
        .map_err(|e| anyhow!("argon2 KDF failed: {e}"))?;
    Ok(())
}

/// Prompt the user for a passphrase on stdin with echo suppressed.
pub fn prompt_passphrase(label: &str) -> Result<String> {
    rpassword::prompt_password(format!("{label}: "))
        .with_context(|| "failed to read passphrase")
}

/// Prompt twice and only accept if both entries match. Used during
/// `keygen` so a typo doesn't permanently lock the key.
pub fn prompt_passphrase_twice() -> Result<String> {
    let first = prompt_passphrase("Enter new passphrase")?;
    let again = prompt_passphrase("Repeat passphrase")?;
    if first != again {
        bail!("passphrases did not match");
    }
    if first.is_empty() {
        bail!("empty passphrase is not allowed");
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        // Skip full keygen (takes 2-3s) — use from_parts with fixed values.
        let key = VendorKey::from_parts([0x42; 32], [0x43; N], [0x44; N]);
        let pk_seed = *key.pk_seed();
        let pk_root = *key.pk_root();

        let blob = key.seal("correct horse battery staple").unwrap();
        assert_eq!(blob.len(), BLOB_LEN);

        let opened = VendorKey::open(&blob, "correct horse battery staple").unwrap();
        assert_eq!(opened.pk_seed(), &pk_seed);
        assert_eq!(opened.pk_root(), &pk_root);

        // Wrong passphrase must fail.
        assert!(VendorKey::open(&blob, "wrong passphrase").is_err());
    }

    #[test]
    fn tampered_blob_rejected() {
        let key = VendorKey::from_parts([0x42; 32], [0x43; N], [0x44; N]);
        let mut blob = key.seal("pw").unwrap();

        // Flip a byte in the ciphertext.
        blob[HEADER_LEN] ^= 0x01;
        assert!(VendorKey::open(&blob, "pw").is_err());
    }

    #[test]
    fn tampered_header_rejected() {
        let key = VendorKey::from_parts([0x42; 32], [0x43; N], [0x44; N]);
        let mut blob = key.seal("pw").unwrap();

        // Flip a byte in the salt (part of AAD).
        blob[6] ^= 0x01;
        assert!(VendorKey::open(&blob, "pw").is_err());
    }
}
