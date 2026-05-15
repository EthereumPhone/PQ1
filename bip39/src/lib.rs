//! Minimal `no_std` BIP-39 implementation tailored to a hardware wallet.
//!
//! Supports 24-word English mnemonics only — that is the entire surface the
//! SPHINCS+ wallet needs. The wordlist is statically compiled into flash, no
//! heap allocation is used anywhere on the encode/decode/seed paths, and the
//! [`Mnemonic`] type wipes its word indices on drop. The type is deliberately
//! `!Copy + !Clone`, so a `mem::forget` is the only way to leak the phrase.
//!
//! This crate intentionally does **not** depend on the upstream `bip39` crate.
//! Avoiding `bitcoin_hashes` and the surrounding dependency tree keeps the
//! secure-world TCB tiny and lets us audit every line.
//!
//! ## Examples
//!
//! ```
//! use sphincs_tz_bip39::Mnemonic;
//!
//! let entropy = [0u8; 32];
//! let m = Mnemonic::from_entropy(&entropy);
//! assert_eq!(m.word(0), "abandon");
//! assert_eq!(m.word(23), "art");
//! let recovered = m.to_entropy().unwrap();
//! assert_eq!(recovered, entropy);
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod wordlist;
pub use wordlist::WORDLIST;

use core::fmt;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// Number of words in the mnemonic (this crate is 24-words only).
pub const WORD_COUNT: usize = 24;

/// Raw entropy length: 256 bits.
pub const ENTROPY_BYTES: usize = 32;

/// Length of the BIP-39 seed produced by [`Mnemonic::to_seed`].
pub const SEED_BYTES: usize = 64;

/// Number of bits per BIP-39 word index.
const BITS_PER_WORD: usize = 11;

/// PBKDF2 iteration count required by BIP-39.
const PBKDF2_ITERS: u32 = 2048;

/// 24 BIP-39 word indices into the English wordlist.
///
/// Wrapped so the only way to construct one is via [`Mnemonic::from_entropy`],
/// [`Mnemonic::from_words`], or [`Mnemonic::from_indices`] — all of which
/// validate the BIP-39 checksum.
pub struct Mnemonic {
    indices: [u16; WORD_COUNT],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BipError {
    /// Word not found in the English wordlist.
    UnknownWord,
    /// BIP-39 checksum byte did not verify (one or more wrong words).
    BadChecksum,
    /// Wrong number of words supplied to [`Mnemonic::from_words`].
    WrongLength,
}

impl fmt::Display for BipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownWord => f.write_str("word not in BIP-39 English wordlist"),
            Self::BadChecksum => f.write_str("BIP-39 checksum mismatch"),
            Self::WrongLength => f.write_str("expected 24 BIP-39 words"),
        }
    }
}

impl Mnemonic {
    /// Build a mnemonic from 32 bytes of entropy. Computes the SHA-256
    /// checksum and bit-packs entropy ‖ checksum into 24 × 11-bit indices.
    #[must_use]
    pub fn from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Self {
        // 24 words × 11 bits = 264 bits = 256 entropy + 8 checksum bits.
        let cs = Sha256::digest(entropy)[0];

        let mut packed = [0u8; ENTROPY_BYTES + 1];
        packed[..ENTROPY_BYTES].copy_from_slice(entropy);
        packed[ENTROPY_BYTES] = cs;

        let mut indices = [0u16; WORD_COUNT];
        for (w, slot) in indices.iter_mut().enumerate() {
            *slot = read_11_bits(&packed, w * BITS_PER_WORD);
        }
        Self { indices }
    }

    /// Parse a mnemonic from a slice of words. Each word is looked up in the
    /// English wordlist and the BIP-39 checksum is verified.
    ///
    /// Accepts case-insensitive input by lowercasing on the fly.
    pub fn from_words<S: AsRef<str>>(words: &[S]) -> Result<Self, BipError> {
        if words.len() != WORD_COUNT {
            return Err(BipError::WrongLength);
        }
        let mut indices = [0u16; WORD_COUNT];
        for (i, w) in words.iter().enumerate() {
            indices[i] = lookup_word_exact(w.as_ref()).ok_or(BipError::UnknownWord)?;
        }
        let m = Self { indices };
        m.to_entropy()?;
        Ok(m)
    }

    /// Build a mnemonic from already-validated wordlist indices. Verifies the
    /// BIP-39 checksum so a recovery wizard cannot accidentally accept a
    /// phrase whose last word's checksum bits are wrong.
    pub fn from_indices(indices: [u16; WORD_COUNT]) -> Result<Self, BipError> {
        if indices.iter().any(|&i| (i as usize) >= WORDLIST.len()) {
            return Err(BipError::UnknownWord);
        }
        let m = Self { indices };
        m.to_entropy()?;
        Ok(m)
    }

    /// Recover the original 32-byte entropy. Returns [`BipError::BadChecksum`]
    /// if the 8-bit BIP-39 checksum does not match.
    pub fn to_entropy(&self) -> Result<[u8; ENTROPY_BYTES], BipError> {
        // Reverse the bit-packing: 24 × 11 bits → 33 bytes (entropy ‖ cs).
        let mut packed = [0u8; ENTROPY_BYTES + 1];
        for (w, &idx) in self.indices.iter().enumerate() {
            write_11_bits(&mut packed, w * BITS_PER_WORD, idx);
        }
        let mut entropy = [0u8; ENTROPY_BYTES];
        entropy.copy_from_slice(&packed[..ENTROPY_BYTES]);
        let stored_cs = packed[ENTROPY_BYTES];
        let computed_cs = Sha256::digest(&entropy)[0];
        if stored_cs != computed_cs {
            entropy.zeroize();
            return Err(BipError::BadChecksum);
        }
        Ok(entropy)
    }

    /// Look up the i-th word as a `&'static str` from the wordlist.
    #[must_use]
    pub fn word(&self, i: usize) -> &'static str {
        WORDLIST[self.indices[i] as usize]
    }

    /// Iterate the 24 words as static strings.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices.iter().map(|&i| WORDLIST[i as usize])
    }

    /// Wordlist index of the i-th word. Useful for verify-backup spot checks
    /// (compare indices rather than `&str` to keep callers branchless).
    #[must_use]
    pub fn word_index(&self, i: usize) -> u16 {
        self.indices[i]
    }

    /// Derive the 64-byte BIP-39 seed via PBKDF2-HMAC-SHA512.
    ///
    /// - `password = "<word1> <word2> ... <word24>"` (NFKD, ASCII for English)
    /// - `salt     = "mnemonic" || passphrase`
    /// - `iters    = 2048`
    /// - `dk_len   = 64`
    ///
    /// We pass an empty passphrase from the wallet today; the parameter exists
    /// so a future "25th word" feature is non-breaking.
    ///
    /// # Panics
    ///
    /// Panics if `passphrase` is longer than 248 bytes (the salt buffer is
    /// 256 bytes and the `"mnemonic"` prefix takes 8). Refusing to silently
    /// truncate is intentional: a silently shortened salt would produce a
    /// different seed and brick recovery.
    #[must_use]
    pub fn to_seed(&self, passphrase: &str) -> [u8; SEED_BYTES] {
        // Worst case password is 24 × 8 (longest BIP-39 word) + 23 spaces
        // = 215 bytes, well under 256.
        let mut password = [0u8; 256];
        let mut password_len = 0usize;
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                password[password_len] = b' ';
                password_len += 1;
            }
            let wb = w.as_bytes();
            password[password_len..password_len + wb.len()].copy_from_slice(wb);
            password_len += wb.len();
        }

        // salt = "mnemonic" || passphrase
        const SALT_PREFIX: &[u8] = b"mnemonic";
        let mut salt = [0u8; 256];
        salt[..SALT_PREFIX.len()].copy_from_slice(SALT_PREFIX);
        let pp = passphrase.as_bytes();
        assert!(
            SALT_PREFIX.len() + pp.len() <= salt.len(),
            "passphrase too long",
        );
        salt[SALT_PREFIX.len()..SALT_PREFIX.len() + pp.len()].copy_from_slice(pp);
        let salt_len = SALT_PREFIX.len() + pp.len();

        let mut out = [0u8; SEED_BYTES];
        pbkdf2_hmac_sha512(&password[..password_len], &salt[..salt_len], PBKDF2_ITERS, &mut out);

        // password reveals the mnemonic; salt may carry a user passphrase.
        password.zeroize();
        salt.zeroize();
        out
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // `Zeroize` adds a compiler fence so the wipe cannot be optimised away.
        self.indices.zeroize();
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the actual words: this struct holds a wallet recovery
        // secret. Use `mnemonic.words()` explicitly when you really need them.
        f.write_str("Mnemonic(<24 words redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Bit packing helpers
// ---------------------------------------------------------------------------

/// Read 11 bits MSB-first from `buf` starting at bit offset `bit`.
#[inline]
fn read_11_bits(buf: &[u8], bit: usize) -> u16 {
    let byte = bit / 8;
    let shift = bit % 8;
    // Load up to three bytes big-endian; the desired 11-bit window lives
    // `shift` bits down from the top of the resulting 24-bit value.
    let b0 = u32::from(buf[byte]);
    let b1 = u32::from(buf[byte + 1]);
    let b2 = if byte + 2 < buf.len() { u32::from(buf[byte + 2]) } else { 0 };
    let combined = (b0 << 16) | (b1 << 8) | b2;
    let top = 24 - shift - BITS_PER_WORD;
    ((combined >> top) & 0x7FF) as u16
}

/// Write 11 bits MSB-first into `buf` starting at bit offset `bit`.
#[inline]
fn write_11_bits(buf: &mut [u8], bit: usize, value: u16) {
    debug_assert!(value < 0x800);
    let byte = bit / 8;
    let shift = bit % 8;
    let top = 24 - shift - BITS_PER_WORD;
    let v = u32::from(value) << top;
    buf[byte] |= ((v >> 16) & 0xFF) as u8;
    buf[byte + 1] |= ((v >> 8) & 0xFF) as u8;
    if byte + 2 < buf.len() {
        buf[byte + 2] |= (v & 0xFF) as u8;
    }
}

// ---------------------------------------------------------------------------
// Firmware measurement helpers
// ---------------------------------------------------------------------------

/// Extract 8 × 11-bit BIP-39 word indices from the first 88 bits of a
/// SHA-256 hash. Used for firmware measurement display — **not** for
/// mnemonic generation.
#[must_use]
pub fn hash_to_word_indices(hash: &[u8; 32]) -> [u16; 8] {
    let mut indices = [0u16; 8];
    for (i, slot) in indices.iter_mut().enumerate() {
        *slot = read_11_bits(hash, i * BITS_PER_WORD);
    }
    indices
}

// ---------------------------------------------------------------------------
// Wordlist lookup helpers
// ---------------------------------------------------------------------------

/// Maximum length of any BIP-39 English word ("mountain" / "mushroom" /
/// "mystery" / ... — all ≤ 8 chars). The recovery UX never has to deal with
/// a longer input.
const MAX_WORD_LEN: usize = 16;

/// Lowercase `input` into a fixed buffer, returning the populated prefix or
/// `None` if it exceeds [`MAX_WORD_LEN`].
fn lowercase_ascii(input: &str, buf: &mut [u8; MAX_WORD_LEN]) -> Option<usize> {
    let bytes = input.as_bytes();
    if bytes.len() > buf.len() {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    Some(bytes.len())
}

/// Exact-match lookup. Case-insensitive in the ASCII range.
#[must_use]
pub fn lookup_word_exact(input: &str) -> Option<u16> {
    let mut buf = [0u8; MAX_WORD_LEN];
    let len = lowercase_ascii(input, &mut buf)?;
    let needle = &buf[..len];
    WORDLIST
        .binary_search_by(|w| w.as_bytes().cmp(needle))
        .ok()
        .map(|i| i as u16)
}

/// Result of a prefix-narrowing lookup, used by the recovery UX.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefixLookup {
    /// Exactly one word matches the prefix; recovery UX can auto-select.
    Unique(u16),
    /// Multiple words match. `start..end` is the half-open range of indices
    /// into [`WORDLIST`] so the caller can iterate without allocation.
    Multiple { start: usize, end: usize },
    /// No matches. The UX should reject the input.
    None,
}

/// Find all wordlist entries with the given (case-insensitive) prefix.
/// Because BIP-39 English words have a unique 4-letter prefix, the user
/// usually only needs to type 3 or 4 letters before the result becomes
/// [`PrefixLookup::Unique`].
#[must_use]
pub fn lookup_prefix(prefix: &str) -> PrefixLookup {
    if prefix.is_empty() {
        return PrefixLookup::Multiple { start: 0, end: WORDLIST.len() };
    }
    let mut buf = [0u8; MAX_WORD_LEN];
    let Some(len) = lowercase_ascii(prefix, &mut buf) else {
        return PrefixLookup::None;
    };
    let needle = &buf[..len];

    // First index whose word is >= needle (lexicographic lower bound).
    let start = WORDLIST.partition_point(|w| w.as_bytes() < needle);

    // Walk forward while words still start with needle.
    let mut end = start;
    while end < WORDLIST.len() && WORDLIST[end].as_bytes().starts_with(needle) {
        end += 1;
    }

    match end - start {
        0 => PrefixLookup::None,
        1 => PrefixLookup::Unique(start as u16),
        _ => PrefixLookup::Multiple { start, end },
    }
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA512 (no_alloc)
// ---------------------------------------------------------------------------

type HmacSha512 = Hmac<Sha512>;

/// PBKDF2 with HMAC-SHA512 PRF, RFC 2898. `out` is exactly one HMAC-SHA512
/// output block, so a single iteration of the outer block loop suffices.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8; SEED_BYTES]) {
    // HMAC accepts any key length, so new_from_slice never returns Err here;
    // it is the only path to a typed Hmac instance.
    let new_mac = || HmacSha512::new_from_slice(password).expect("HMAC accepts any key length");

    // U_1 = HMAC(password, salt || INT(1))
    let mut mac = new_mac();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u_prev = mac.finalize().into_bytes();
    out.copy_from_slice(&u_prev);

    // T = U_1 ^ U_2 ^ ... ^ U_iters, where U_n = HMAC(password, U_{n-1}).
    for _ in 1..iters {
        let mut mac = new_mac();
        mac.update(&u_prev);
        u_prev = mac.finalize().into_bytes();
        for (b, x) in out.iter_mut().zip(u_prev.iter()) {
            *b ^= *x;
        }
    }
}
