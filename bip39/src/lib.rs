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

/// Maximum byte length of any English BIP-39 word.
///
/// The longest words ("abandon", "absurd", "ability", ..., "wrestle") max
/// out at 8 bytes; this is used as the fixed stride for the constant-time
/// flat wordlist (`WORDLIST_FLAT` / `WORDLIST_LENS`). Per-word lengths are
/// in [3, 8].
pub const MAX_WORD_BYTES: usize = 8;

/// Constant-time flat representation of the BIP-39 wordlist.
///
/// `WORDLIST` is `&[&str; 2048]` — each entry is a fat pointer to a string
/// elsewhere in `.rodata`. Reading `WORDLIST[idx].as_bytes()` therefore
/// performs TWO address-keyed loads:
///   1. `WORDLIST + idx * sizeof(&str)` — sequential if you iterate
///      sequentially over `idx`, but **index-keyed** if you fetch a
///      single entry whose index is a secret.
///   2. The (ptr, len) fat-pointer dereferences a flash region whose
///      address ALSO depends on `idx` (each word is at a different
///      `.rodata` offset).
///
/// `WORDLIST_FLAT[idx]` is a fixed-stride 8-byte slot (zero-padded to 8
/// bytes) and `WORDLIST_LENS[idx]` is a u8. Both arrays have predictable
/// `&table + idx * stride` addresses — when you iterate sequentially
/// over `idx` to perform a constant-time scan, the access pattern is
/// fully deterministic regardless of which entry matches the secret
/// `target_idx`. See [`Mnemonic::to_seed`] for the consumer + the
/// `tools/sca/leakage_bip39.py` F-22 regression harness for the
/// rationale.
const fn flatten_wordlist() -> ([[u8; MAX_WORD_BYTES]; 2048], [u8; 2048]) {
    let mut flat = [[0u8; MAX_WORD_BYTES]; 2048];
    let mut lens = [0u8; 2048];
    let mut i = 0;
    while i < 2048 {
        let w = WORDLIST[i].as_bytes();
        let mut j = 0;
        while j < w.len() {
            flat[i][j] = w[j];
            j += 1;
        }
        lens[i] = w.len() as u8;
        i += 1;
    }
    (flat, lens)
}

const FLATTENED: ([[u8; MAX_WORD_BYTES]; 2048], [u8; 2048]) = flatten_wordlist();
/// Fixed-stride 8-byte representation of each wordlist entry, zero-padded.
/// See [`flatten_wordlist`] for the rationale (F-22 fix).
pub static WORDLIST_FLAT: [[u8; MAX_WORD_BYTES]; 2048] = FLATTENED.0;
/// Per-entry byte length corresponding to [`WORDLIST_FLAT`].
pub static WORDLIST_LENS: [u8; 2048] = FLATTENED.1;

/// Constant-time `target == entry` comparison for u16 — returns `0xFF`
/// iff equal, `0x00` otherwise, with no secret-dependent branches.
#[inline(always)]
fn ct_eq_u16(a: u16, b: u16) -> u8 {
    // x = 0 iff a == b. (x | -x) >> 31 = 0 iff x == 0, else 1.
    let x: u32 = a as u32 ^ b as u32;
    let nz: u32 = (x | x.wrapping_neg()) >> 31; // 0 iff eq, 1 iff diff
    (nz as u8).wrapping_sub(1) // 0xFF iff eq, 0x00 iff diff
}

/// Constant-time `a < b` for u8 — returns `0xFF` iff `a < b`, `0x00` else.
#[inline(always)]
fn ct_lt_u8(a: u8, b: u8) -> u8 {
    // (a - b) >> 7 in two's-complement = 1 iff a < b (sign bit set).
    let r: i16 = (a as i16) - (b as i16);
    let bit = ((r >> 15) & 1) as u8; // 1 iff a < b
    bit.wrapping_neg() // 0xFF iff a < b, 0x00 else
}

/// Constant-time wordlist lookup: scan all 2048 entries, mask-and-OR the
/// one matching `target_idx`. Writes the (zero-padded) 8-byte word + its
/// length. Closes the F-22 leak (see [`flatten_wordlist`]).
///
/// `target_idx` is assumed in `[0, 2048)`. Caller guarantees that via
/// the `Mnemonic::indices` invariant.
///
/// **`core::hint::black_box` barriers** are critical: without them LLVM
/// notices `entry[b] & mask` is non-zero only at the matching index and
/// "optimises" the 2048-entry scan into a direct `WORDLIST_FLAT[target_idx]`
/// lookup — defeating the entire constant-time property. The barriers
/// force the compiler to treat the mask, the entry pointer, and the
/// accumulator as opaque values that must flow through every iteration.
/// Verified by re-running `make -C tools/sca bip39-leak` and confirming
/// `max|t| ≤ 4.5` on the post-fix `sca_bip39_wordlist_lookup_ct` probe.
#[inline(never)]
fn ct_load_word(target_idx: u16) -> ([u8; MAX_WORD_BYTES], u8) {
    use core::hint::black_box;
    let mut bytes = [0u8; MAX_WORD_BYTES];
    let mut len: u8 = 0;
    let mut entry_idx: u16 = 0;
    while entry_idx < 2048 {
        // Force LLVM to materialise each iteration's mask / loads / OR
        // separately — without these barriers it folds the scan into a
        // direct index-keyed lookup.
        let entry_idx_obf = black_box(entry_idx);
        let entry = &WORDLIST_FLAT[entry_idx_obf as usize];
        let entry_len = WORDLIST_LENS[entry_idx_obf as usize];
        let mask = black_box(ct_eq_u16(entry_idx_obf, target_idx));
        let mut b = 0;
        while b < MAX_WORD_BYTES {
            bytes[b] = black_box(bytes[b] | (entry[b] & mask));
            b += 1;
        }
        len = black_box(len | (entry_len & mask));
        entry_idx += 1;
    }
    (bytes, len)
}

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
    ///
    /// **Address-leaks the index** (`WORDLIST[i].as_bytes()` loads from
    /// flash at an address that encodes `i`). Safe for callers where `i`
    /// is public (e.g. [`measured_boot`]'s firmware-hash word display
    /// where the hash is signed and visible by design). For SECRET
    /// indices — the master mnemonic in the provisioning wizard —
    /// prefer [`Self::word_bytes`] which uses the F-22 constant-time
    /// scan.
    #[must_use]
    pub fn word(&self, i: usize) -> &'static str {
        WORDLIST[self.indices[i] as usize]
    }

    /// Constant-time word lookup: copy the i-th word's bytes into the
    /// caller's `out` buffer (zero-padded to 8 bytes) and return the
    /// actual length (3-8). No load or store address depends on the
    /// secret index — uses the same [`ct_load_word`] scan that closes
    /// F-22 in [`Self::to_seed`].
    ///
    /// `out` is 8 bytes (the max BIP-39 English word length); the
    /// fixed-stride layout is what makes the scan address-deterministic.
    /// Callers that want a `&str` view can do
    /// `core::str::from_utf8(&out[..len as usize])` after — the SCAN
    /// itself is constant-time, the post-scan handling depends on the
    /// caller's secrecy stance.
    pub fn word_bytes(&self, i: usize, out: &mut [u8; MAX_WORD_BYTES]) -> u8 {
        let (bytes, len) = ct_load_word(self.indices[i]);
        *out = bytes;
        len
    }

    /// Iterate the 24 words as static strings.
    ///
    /// **Same address-leak caveat as [`Self::word`].** For secret
    /// indices, iterate `0..WORD_COUNT` and call [`Self::word_bytes`]
    /// per index.
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
        // F-22 constant-time password assembly. Three phases, all
        // value-only — no address-keyed loads or stores depend on the
        // secret indices.
        //
        // Phase 1: constant-time wordlist resolution.
        //   For each of the 24 indices, scan all 2048 entries of
        //   WORDLIST_FLAT, mask-and-OR the matching one. After this
        //   loop, words[i] holds the i-th word's bytes (zero-padded
        //   to 8) and lens[i] holds its length, with NO load-address
        //   dependence on the secret indices.
        let mut words = [[0u8; MAX_WORD_BYTES]; WORD_COUNT];
        let mut lens = [0u8; WORD_COUNT];
        for i in 0..WORD_COUNT {
            let (w, l) = ct_load_word(self.indices[i]);
            words[i] = w;
            lens[i] = l;
        }

        // Phase 2: cumulative offsets in the password buffer.
        //   offsets[i] = sum(lens[0..i]) + i (one space per prior word).
        //   Pure arithmetic on lens — VALUES leak (length sum is observable
        //   via PBKDF2's bit-length-of-password padding byte; ~7 bits worst
        //   case, vastly smaller than the 264-bit F-22 leak this fix
        //   closes; tracked as a separate follow-up).
        let mut offsets = [0u16; WORD_COUNT];
        let mut i = 1;
        while i < WORD_COUNT {
            offsets[i] = offsets[i - 1] + lens[i - 1] as u16 + 1;
            i += 1;
        }
        let mut password_len: u16 = WORD_COUNT as u16 - 1; // 23 spaces
        let mut j = 0;
        while j < WORD_COUNT {
            password_len += lens[j] as u16;
            j += 1;
        }

        // Phase 3: constant-time password write.
        //   For each output byte position p in 0..MAX_PASSWORD_LEN, scan
        //   all (word, byte_in_word) candidates and mask-OR the right
        //   byte. Every write is to `password[p]` at a fixed loop-counter-
        //   derived offset — no secret-keyed store addresses. Word and
        //   offset arrays are stack-resident at fixed addresses.
        //
        //   Cost: 24 words × 8 max-bytes × 215 max-positions ≈ 41 K
        //   inner iterations; each is ~10 instructions; total ~0.4 M
        //   cycles, < 5 ms on Cortex-M33 — acceptable for a once-per-
        //   unlock op.
        const MAX_PASSWORD_LEN: usize =
            WORD_COUNT * MAX_WORD_BYTES + (WORD_COUNT - 1); // 24*8 + 23 = 215
        let mut password = [0u8; 256];
        let mut p = 0;
        while p < MAX_PASSWORD_LEN {
            let mut acc: u8 = 0;
            let mut w = 0;
            while w < WORD_COUNT {
                let off = offsets[w];
                // Word body bytes: position p == off + b, for b in [0, lens[w]).
                let mut b = 0;
                while b < MAX_WORD_BYTES {
                    let in_range = ct_lt_u8(b as u8, lens[w]);
                    let pos_match = ct_eq_u16(p as u16, off + b as u16);
                    acc |= words[w][b] & in_range & pos_match;
                    b += 1;
                }
                // Inter-word space: position p == off + lens[w] iff w is
                // not the last word. ct_lt(w, WORD_COUNT-1) ensures the
                // final word has no trailing space.
                let is_not_last = ct_lt_u8(w as u8, (WORD_COUNT - 1) as u8);
                let space_pos = ct_eq_u16(p as u16, off + lens[w] as u16);
                acc |= b' ' & is_not_last & space_pos;
                w += 1;
            }
            password[p] = acc;
            p += 1;
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
        pbkdf2_hmac_sha512(
            &password[..password_len as usize],
            &salt[..salt_len],
            PBKDF2_ITERS,
            &mut out,
        );

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

/// Constant-time wordlist-by-index lookup.
///
/// Same scan + `black_box` barrier pattern as the private
/// [`ct_load_word`] (which [`Mnemonic::word_bytes`] uses internally).
/// Public so secret-bearing UI paths outside this crate
/// (e.g. `seed_wizard::render_candidate_screen`) can resolve a wordlist
/// entry by index without the address-keyed `WORDLIST[idx]` load.
///
/// Returns the 8-byte zero-padded word bytes and the actual length (3-8).
#[must_use]
pub fn word_bytes_at(idx: u16) -> ([u8; MAX_WORD_BYTES], u8) {
    ct_load_word(idx)
}

/// Constant-time check: is `needle` exactly one of the 2048 BIP-39
/// English wordlist entries?
///
/// Closes F-27: the previous in-`seed_wizard.rs` helper used
/// `WORDLIST.binary_search_by(...)` whose visited midpoint addresses
/// leaked the typed prefix in the recovery candidate-pick gate. This
/// scans all 2048 entries unconditionally; mask-OR accumulates the
/// per-entry verdict.
///
/// The verdict per entry is `(entry_bytes == needle_padded) AND
/// (entry_len == needle.len())`. The length check is critical:
/// `WORDLIST_FLAT` entries are zero-padded to [`MAX_WORD_BYTES`], so a
/// bytewise-only compare would accept a needle like `"act\0\0\0\0\0"`
/// (length 8) against the entry `"act"` (length 3 with 5 zero bytes
/// of storage padding). Real callers slice their needle to its actual
/// length, but the public API must be robust to oddly-shaped inputs.
///
/// `needle.len()` must be `<= MAX_WORD_BYTES`. Empty needle returns
/// `false` (no wordlist entry has length 0). `core::hint::black_box`
/// barriers per F-22's load-bearing pattern.
#[must_use]
pub fn is_exact_wordlist_entry(needle: &[u8]) -> bool {
    use core::hint::black_box;
    if needle.is_empty() || needle.len() > MAX_WORD_BYTES {
        return false;
    }
    let nlen = needle.len() as u8;
    let mut padded = [0u8; MAX_WORD_BYTES];
    padded[..needle.len()].copy_from_slice(needle);

    let mut any_match: u8 = 0;
    let mut entry_idx: u16 = 0;
    while entry_idx < 2048 {
        let idx_obf = black_box(entry_idx);
        let entry = &WORDLIST_FLAT[idx_obf as usize];
        let entry_len = WORDLIST_LENS[idx_obf as usize];
        let mut all_eq: u8 = 0xFF;
        let mut i = 0;
        while i < MAX_WORD_BYTES {
            let byte_eq = ct_eq_u8(entry[i], padded[i]);
            all_eq = black_box(all_eq & byte_eq);
            i += 1;
        }
        let len_eq = ct_eq_u8(entry_len, nlen);
        let is_match: u8 = black_box(all_eq & len_eq);
        any_match = black_box(any_match | (is_match & 1));
        entry_idx += 1;
    }
    any_match != 0
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
///
/// **F-25 fix (constant-time scan).** The previous implementation used
/// `WORDLIST.partition_point` (binary search) + a forward `starts_with`
/// walk, both of which visited `WORDLIST[idx]` at indices that depended
/// on the typed prefix. During recovery (user typing 24 words back
/// from a paper backup), an EM-scoping attacker could reconstruct each
/// typed prefix from the per-keystroke address pattern (~45σ leak per
/// call). Now scans all 2048 entries unconditionally and accumulates
/// the matching range via constant-time mask-OR over the flat
/// `WORDLIST_FLAT` + `WORDLIST_LENS` tables (same tables F-22 added
/// for the `to_seed` fix). Cost: ~2048 × 8 = 16 KB of stack reads per
/// keystroke; ~1 ms wall on Cortex-M33 (acceptable since keystroke
/// rate ≤ 5/s).
///
/// `core::hint::black_box` barriers per iteration prevent LLVM from
/// folding the scan into a binary search — same load-bearing pattern
/// as F-22's `ct_load_word`.
#[must_use]
pub fn lookup_prefix(prefix: &str) -> PrefixLookup {
    use core::hint::black_box;

    if prefix.is_empty() {
        return PrefixLookup::Multiple { start: 0, end: WORDLIST.len() };
    }
    let mut buf = [0u8; MAX_WORD_LEN];
    let Some(plen_raw) = lowercase_ascii(prefix, &mut buf) else {
        return PrefixLookup::None;
    };
    // Lookups longer than MAX_WORD_BYTES (the longest BIP-39 word) can
    // never match. Cap to MAX_WORD_BYTES for the scan; if the typed
    // prefix is longer, none of the 2048 entries match.
    if plen_raw > MAX_WORD_BYTES {
        return PrefixLookup::None;
    }
    let plen: u8 = plen_raw as u8;
    let mut needle = [0u8; MAX_WORD_BYTES];
    needle[..plen_raw].copy_from_slice(&buf[..plen_raw]);

    // Sentinel for "no match seen yet" — must be outside [0, 2048).
    const NO_MATCH: u16 = 0xFFFF;
    let mut first: u16 = NO_MATCH;
    let mut count: u16 = 0;

    let mut entry_idx: u16 = 0;
    while entry_idx < 2048 {
        let idx_obf = black_box(entry_idx);
        let entry = &WORDLIST_FLAT[idx_obf as usize];
        let entry_len = WORDLIST_LENS[idx_obf as usize];

        // is_match: does entry start with needle?
        //   For each byte position 0..MAX_WORD_BYTES, check
        //   (i >= plen) OR (entry[i] == needle[i]).
        //   Then require entry_len >= plen.
        let mut all_bytes_match: u8 = 0xFF;
        let mut i = 0u8;
        while (i as usize) < MAX_WORD_BYTES {
            // 0xFF if i < plen (position is within the needle), else 0
            let in_needle = ct_lt_u8(i, plen);
            // out_of_needle = 0xFF if i >= plen
            let out_of_needle = !in_needle;
            // byte_eq = 0xFF iff entry[i] == needle[i]
            let byte_eq = ct_eq_u8(entry[i as usize], needle[i as usize]);
            // matches at this position if it's out-of-needle OR bytes are equal.
            let pos_ok = out_of_needle | byte_eq;
            all_bytes_match = black_box(all_bytes_match & pos_ok);
            i += 1;
        }
        // entry_len >= plen ↔ NOT (entry_len < plen)
        let len_ok = !ct_lt_u8(entry_len, plen);
        let is_match: u8 = black_box(all_bytes_match & len_ok); // 0xFF if match

        // first ← min(first, idx_obf if match else NO_MATCH).
        // Since WORDLIST is sorted and matches are contiguous, the first
        // match is the lowest matching index. We update first only the
        // FIRST time is_match fires; afterwards first != NO_MATCH so the
        // update predicate is false. All arithmetic is constant-time.
        let mask16: u16 = is_match as u16 | ((is_match as u16) << 8);
        let is_first_match: u16 = ct_eq_u16(first, NO_MATCH) as u16
            | ((ct_eq_u16(first, NO_MATCH) as u16) << 8);
        let update: u16 = mask16 & is_first_match;
        first = black_box((first & !update) | (idx_obf & update));

        // count++ on match. is_match >> 7 = 0 or 1.
        count = black_box(count + ((is_match >> 7) as u16));

        entry_idx += 1;
    }

    match count {
        0 => PrefixLookup::None,
        1 => PrefixLookup::Unique(first),
        n => PrefixLookup::Multiple {
            start: first as usize,
            end: (first as usize) + (n as usize),
        },
    }
}

/// Constant-time `a == b` for u8 — returns 0xFF iff equal, 0x00 else.
#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    let nz: u8 = ((x | x.wrapping_neg()) >> 7) & 1;
    nz.wrapping_sub(1)
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
