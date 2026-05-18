//! Wordlist stability / integrity invariants.
//!
//! Renaming, re-ordering, or replacing a wordlist entry would change every
//! mnemonic the wallet has ever produced and could brick recovery for already-
//! provisioned hardware. These tests fail loudly if the wordlist mutates.

use sha2::{Digest, Sha256};
use sphincs_tz_bip39::WORDLIST;

/// SHA-256 of the canonical `english.txt` (each word followed by `'\n'`).
/// Documented in `src/wordlist.rs`.
const EXPECTED_WORDLIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

#[test]
fn wordlist_has_exactly_2048_entries() {
    assert_eq!(
        WORDLIST.len(),
        2048,
        "BIP-39 English wordlist must contain exactly 2048 entries — \
         a different size would change every mnemonic produced"
    );
}

#[test]
fn wordlist_first_and_last_entries_are_canonical() {
    assert_eq!(WORDLIST[0], "abandon");
    assert_eq!(WORDLIST[2047], "zoo");
}

#[test]
fn negative_wordlist_is_strictly_sorted_ascending() {
    // `lookup_word_exact` relies on `WORDLIST.binary_search_by`; if the slice
    // is ever reordered the lookup silently misses words. This catches that
    // refactor.
    for pair in WORDLIST.windows(2) {
        assert!(
            pair[0] < pair[1],
            "wordlist not strictly sorted: {:?} >= {:?}",
            pair[0],
            pair[1],
        );
    }
}

#[test]
fn negative_wordlist_contains_only_lowercase_ascii_letters() {
    // The lowercase helper only `.to_ascii_lowercase()` bytes; any non-ASCII
    // letter or punctuation would make `lookup_word_exact` non-canonical.
    for w in WORDLIST.iter() {
        for &b in w.as_bytes() {
            assert!(
                b.is_ascii_lowercase(),
                "wordlist entry {:?} contains non-lowercase-ASCII byte 0x{:02x}",
                w,
                b,
            );
        }
    }
}

#[test]
fn negative_wordlist_lengths_fit_max_word_len_buffer() {
    // `lowercase_ascii` allocates a 16-byte stack buffer (MAX_WORD_LEN). Any
    // word longer than that could not be looked up even if a user typed it
    // perfectly.
    for w in WORDLIST.iter() {
        assert!(
            w.as_bytes().len() <= 16,
            "wordlist entry {:?} exceeds MAX_WORD_LEN (16)",
            w,
        );
        // BIP-39 spec also guarantees a minimum length of 3.
        assert!(
            w.as_bytes().len() >= 3,
            "wordlist entry {:?} below BIP-39 minimum length 3",
            w,
        );
    }
}

#[test]
fn negative_wordlist_sha256_matches_official_english_txt() {
    // The wallet's mnemonics are domain-bound to this exact wordlist. Any
    // silent edit (a typo fix, a letter case change) would re-key every user.
    let mut h = Sha256::new();
    for w in WORDLIST.iter() {
        h.update(w.as_bytes());
        h.update(b"\n");
    }
    let got_hex = hex::encode(h.finalize());
    assert_eq!(
        got_hex, EXPECTED_WORDLIST_SHA256,
        "wordlist SHA-256 mismatch — the BIP-39 English wordlist has been \
         modified! This breaks recovery for every device ever provisioned."
    );
}

#[test]
fn negative_wordlist_has_unique_4_letter_prefix() {
    // BIP-39 design property used by `lookup_prefix` — every word is uniquely
    // identified by its first 4 letters (or by the whole word if shorter).
    // Any duplicate key here would mean the prefix-recovery UX could not
    // disambiguate a user's input.
    fn key(w: &str) -> [u8; 4] {
        let mut k = [0u8; 4];
        let b = w.as_bytes();
        let n = b.len().min(4);
        k[..n].copy_from_slice(&b[..n]);
        k
    }
    for pair in WORDLIST.windows(2) {
        let a = key(pair[0]);
        let b = key(pair[1]);
        assert_ne!(
            a, b,
            "BIP-39 4-letter prefix property violated: {:?} vs {:?}",
            pair[0], pair[1]
        );
    }
}
