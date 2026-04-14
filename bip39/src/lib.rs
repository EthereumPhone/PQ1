//! Minimal `no_std` BIP-39 implementation tailored to a hardware wallet.
//!
//! Supports 24-word English mnemonics only — that is the entire surface the
//! SPHINCS+ wallet needs. The wordlist is statically compiled into flash, no
//! heap allocation is used anywhere on the encode/decode/seed paths, and the
//! `Mnemonic` type zeroes its word indices on drop so an accidental `mem::forget`
//! is the only way to leak the phrase.
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

/// Length of the BIP-39 seed produced by `to_seed`.
pub const SEED_BYTES: usize = 64;

/// Number of bits per BIP-39 word index.
const BITS_PER_WORD: usize = 11;

/// PBKDF2 iteration count required by BIP-39.
const PBKDF2_ITERS: u32 = 2048;

/// 24 BIP-39 word indices into the English wordlist.
///
/// Wrapper rather than a public field so the only way to construct one is via
/// `from_entropy` or `from_words`, both of which validate.
#[derive(Clone)]
pub struct Mnemonic {
    indices: [u16; WORD_COUNT],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BipError {
    /// Word not found in the English wordlist.
    UnknownWord,
    /// BIP-39 checksum byte did not verify (one or more wrong words).
    BadChecksum,
    /// Wrong number of words supplied to `from_words`.
    WrongLength,
}

impl Mnemonic {
    /// Build a mnemonic from 32 bytes of entropy. Computes the SHA-256
    /// checksum and bit-packs entropy ‖ checksum into 24 × 11-bit indices.
    pub fn from_entropy(entropy: &[u8; ENTROPY_BYTES]) -> Self {
        // 24 words × 11 bits = 264 bits = 256 entropy + 8 checksum bits.
        let cs = Sha256::digest(entropy)[0];

        // Pack entropy ‖ checksum into a 33-byte buffer, then chunk into
        // 11-bit indices, MSB first.
        let mut packed = [0u8; ENTROPY_BYTES + 1];
        packed[..ENTROPY_BYTES].copy_from_slice(entropy);
        packed[ENTROPY_BYTES] = cs;

        let mut indices = [0u16; WORD_COUNT];
        for (w, slot) in indices.iter_mut().enumerate() {
            let bit = w * BITS_PER_WORD;
            *slot = read_11_bits(&packed, bit);
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
        // Round-trip through to_entropy to verify checksum.
        m.to_entropy()?;
        Ok(m)
    }

    /// Build a mnemonic from already-validated wordlist indices. Verifies
    /// the BIP-39 checksum so a recovery wizard cannot accidentally accept
    /// a phrase whose last word's checksum bits are wrong.
    pub fn from_indices(indices: [u16; WORD_COUNT]) -> Result<Self, BipError> {
        for &i in &indices {
            if (i as usize) >= WORDLIST.len() {
                return Err(BipError::UnknownWord);
            }
        }
        let m = Self { indices };
        m.to_entropy()?;
        Ok(m)
    }

    /// Recover the original 32-byte entropy. Returns `BadChecksum` if the
    /// 8-bit BIP-39 checksum does not match.
    pub fn to_entropy(&self) -> Result<[u8; ENTROPY_BYTES], BipError> {
        // Reverse the bit-packing: 24 × 11 bits → 33 bytes (entropy ‖ cs).
        let mut packed = [0u8; ENTROPY_BYTES + 1];
        for (w, &idx) in self.indices.iter().enumerate() {
            let bit = w * BITS_PER_WORD;
            write_11_bits(&mut packed, bit, idx);
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
    pub fn word(&self, i: usize) -> &'static str {
        WORDLIST[self.indices[i] as usize]
    }

    /// Iterate the 24 words as static strings.
    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices.iter().map(|&i| WORDLIST[i as usize])
    }

    /// Equality on word indices, useful for verify-backup spot checks.
    pub fn word_index(&self, i: usize) -> u16 {
        self.indices[i]
    }

    /// Derive the 64-byte BIP-39 seed via PBKDF2-HMAC-SHA512.
    ///
    /// `password = "<word1> <word2> ... <word24>"` (NFKD, ASCII for English)
    /// `salt     = "mnemonic" || passphrase`
    /// `iters    = 2048`
    /// `dk_len   = 64`
    ///
    /// We pass an empty passphrase from the wallet today; the parameter exists
    /// so a future "25th word" feature is non-breaking.
    pub fn to_seed(&self, passphrase: &str) -> [u8; SEED_BYTES] {
        // Build "<word> <word> ..." into a stack buffer. Worst case is
        // 24 * 8 (longest BIP-39 word) + 23 spaces = 215 bytes, well under
        // a fixed 256-byte budget.
        let mut password = [0u8; 256];
        let mut len = 0usize;
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                password[len] = b' ';
                len += 1;
            }
            let wb = w.as_bytes();
            password[len..len + wb.len()].copy_from_slice(wb);
            len += wb.len();
        }

        // Build salt = "mnemonic" || passphrase into a stack buffer.
        let mut salt = [0u8; 256];
        let prefix = b"mnemonic";
        salt[..prefix.len()].copy_from_slice(prefix);
        let pp = passphrase.as_bytes();
        // Refuse to silently truncate exotic passphrases.
        assert!(pp.len() + prefix.len() <= salt.len(), "passphrase too long");
        salt[prefix.len()..prefix.len() + pp.len()].copy_from_slice(pp);
        let salt_len = prefix.len() + pp.len();

        let mut out = [0u8; SEED_BYTES];
        pbkdf2_hmac_sha512(&password[..len], &salt[..salt_len], PBKDF2_ITERS, &mut out);

        // Wipe transient buffers (password contains the mnemonic).
        password.zeroize();
        salt.zeroize();
        out
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        for w in self.indices.iter_mut() {
            *w = 0;
        }
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the actual words: this struct holds a wallet recovery
        // secret. Use `mnemonic.words()` explicitly when you really need them.
        write!(f, "Mnemonic(<24 words redacted>)")
    }
}

// ---------------------------------------------------------------------------
// Bit packing helpers
// ---------------------------------------------------------------------------

/// Read 11 bits MSB-first from `buf` starting at bit offset `bit`.
fn read_11_bits(buf: &[u8], bit: usize) -> u16 {
    let byte = bit / 8;
    let shift = bit % 8;
    // Read up to three bytes, big-endian, then shift the desired window down.
    let b0 = buf[byte] as u32;
    let b1 = buf[byte + 1] as u32;
    let b2 = if byte + 2 < buf.len() { buf[byte + 2] as u32 } else { 0 };
    let combined = (b0 << 16) | (b1 << 8) | b2;
    // We want bits [shift .. shift+11] of combined, where bit 0 is the
    // most-significant bit of byte `byte`. combined is 24 bits wide, so the
    // top is bit 0; the desired window starts shift bits from the top.
    let top = 24 - shift - BITS_PER_WORD;
    ((combined >> top) & 0x7FF) as u16
}

/// Write 11 bits MSB-first into `buf` starting at bit offset `bit`.
fn write_11_bits(buf: &mut [u8], bit: usize, value: u16) {
    debug_assert!(value < 0x800);
    let byte = bit / 8;
    let shift = bit % 8;
    let top = 24 - shift - BITS_PER_WORD;
    let v = (value as u32) << top;
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
/// SHA-256 hash. Used for firmware measurement display — NOT for mnemonic
/// generation.
pub fn hash_to_word_indices(hash: &[u8; 32]) -> [u16; 8] {
    let mut indices = [0u16; 8];
    for i in 0..8 {
        indices[i] = read_11_bits(hash, i * BITS_PER_WORD);
    }
    indices
}

// ---------------------------------------------------------------------------
// Wordlist lookup helpers
// ---------------------------------------------------------------------------

/// Exact-match lookup. Case-insensitive in the ASCII range.
pub fn lookup_word_exact(input: &str) -> Option<u16> {
    // Compare bytewise after lowercasing both sides. The wordlist is already
    // all lowercase, so we just lowercase the input.
    let mut buf = [0u8; 16];
    let bytes = input.as_bytes();
    if bytes.len() > buf.len() {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b.to_ascii_lowercase();
    }
    let lower = &buf[..bytes.len()];

    // Wordlist is sorted, so use binary search.
    let mut lo = 0usize;
    let mut hi = WORDLIST.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        match WORDLIST[mid].as_bytes().cmp(lower) {
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
            core::cmp::Ordering::Equal => return Some(mid as u16),
        }
    }
    None
}

/// Result of a prefix-narrowing lookup, used by the recovery UX.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefixLookup {
    /// Exactly one word matches the prefix; recovery UX can auto-select.
    Unique(u16),
    /// Multiple words match; the UX should let the user disambiguate.
    /// Returns the (start, end) range of indices into WORDLIST so the caller
    /// can iterate without allocation.
    Multiple { start: usize, end: usize },
    /// No matches. The UX should reject the input.
    None,
}

/// Find all wordlist entries with the given (case-insensitive) prefix.
/// Because BIP-39 English words have a unique 4-letter prefix, the user
/// usually only needs to type 3 or 4 letters before the result becomes
/// `Unique`.
pub fn lookup_prefix(prefix: &str) -> PrefixLookup {
    if prefix.is_empty() {
        return PrefixLookup::Multiple { start: 0, end: WORDLIST.len() };
    }
    let mut lower = [0u8; 16];
    let bytes = prefix.as_bytes();
    if bytes.len() > lower.len() {
        return PrefixLookup::None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        lower[i] = b.to_ascii_lowercase();
    }
    let needle = &lower[..bytes.len()];

    // Find first index whose word starts with needle (lower bound).
    let mut lo = 0usize;
    let mut hi = WORDLIST.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if WORDLIST[mid].as_bytes() < needle {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let start = lo;

    // Walk forward while words still start with needle.
    let mut end = start;
    while end < WORDLIST.len() && starts_with(WORDLIST[end].as_bytes(), needle) {
        end += 1;
    }

    match end - start {
        0 => PrefixLookup::None,
        1 => PrefixLookup::Unique(start as u16),
        _ => PrefixLookup::Multiple { start, end },
    }
}

fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && &haystack[..needle.len()] == needle
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA512 (no_alloc)
// ---------------------------------------------------------------------------

type HmacSha512 = Hmac<Sha512>;

/// PBKDF2 with HMAC-SHA512 PRF, RFC 2898. `out` may be any length up to
/// 64 bytes (one block) — that covers our 64-byte BIP-39 seed.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iters: u32, out: &mut [u8; SEED_BYTES]) {
    // dk_len == 64 == one HMAC-SHA512 output block, so a single iteration
    // of the outer "block" loop is sufficient.
    let mut block = [0u8; 64];

    // U_1 = HMAC(password, salt || INT(1))
    let mut mac = HmacSha512::new_from_slice(password).expect("hmac key");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let u1 = mac.finalize().into_bytes();
    block.copy_from_slice(&u1);

    // U_n = HMAC(password, U_{n-1}); T = U_1 ^ U_2 ^ ... ^ U_iters
    let mut u_prev = u1;
    for _ in 1..iters {
        let mut mac = HmacSha512::new_from_slice(password).expect("hmac key");
        mac.update(&u_prev);
        let u_n = mac.finalize().into_bytes();
        for (b, x) in block.iter_mut().zip(u_n.iter()) {
            *b ^= *x;
        }
        u_prev = u_n;
    }

    out.copy_from_slice(&block);
}
