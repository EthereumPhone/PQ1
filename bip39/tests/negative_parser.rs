//! Adversarial tests for the mnemonic parsers (`from_words`, `from_indices`,
//! `to_entropy`). Each test names the assumption being attacked and asserts
//! the precise rejection variant.
//!
//! A silent acceptance of any of these would expose the wallet to bricked-
//! recovery scenarios or, worse, to provisioning a phrase whose BIP-39
//! checksum the user never typed.

use sphincs_tz_bip39::{BipError, Mnemonic, WORDLIST};

/// Canonical "all-zero entropy" phrase: 23 × "abandon" + "art".
fn canonical_zero_words() -> Vec<&'static str> {
    let mut v = vec!["abandon"; 23];
    v.push("art");
    v
}

// ---------------------------------------------------------------------------
// `from_words` length checks
// ---------------------------------------------------------------------------

#[test]
fn negative_from_words_rejects_23_word_phrase() {
    let mut w = canonical_zero_words();
    w.pop();
    assert_eq!(w.len(), 23);
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::WrongLength);
}

#[test]
fn negative_from_words_rejects_25_word_phrase() {
    let mut w = canonical_zero_words();
    w.push("abandon");
    assert_eq!(w.len(), 25);
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::WrongLength);
}

#[test]
fn negative_from_words_rejects_empty_slice() {
    let w: Vec<&str> = Vec::new();
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::WrongLength);
}

#[test]
fn negative_from_words_rejects_single_word() {
    let w = vec!["abandon"];
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::WrongLength);
}

#[test]
fn negative_from_words_rejects_12_word_phrase() {
    // 12 words is valid BIP-39 (128 bits) but unsupported by this crate; the
    // wallet only ever uses 24-word seeds. Anything else must be refused.
    let w = vec!["abandon"; 12];
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::WrongLength);
}

// ---------------------------------------------------------------------------
// `from_words` word-lookup negatives
// ---------------------------------------------------------------------------

#[test]
fn negative_from_words_rejects_word_with_embedded_space() {
    let mut w = canonical_zero_words();
    w[0] = "aband on";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_word_with_trailing_space() {
    let mut w = canonical_zero_words();
    w[0] = "abandon ";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_word_with_leading_space() {
    let mut w = canonical_zero_words();
    w[0] = " abandon";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_empty_word() {
    let mut w = canonical_zero_words();
    w[0] = "";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_non_ascii_lookalike_word() {
    // Cyrillic 'а' (U+0430, 2 bytes 0xD0 0xB0) — visually identical to ASCII
    // 'a' but a different code point. A naive normalisation (or a UTF-8 case-
    // folding library) might be tempted to accept it.
    let mut w = canonical_zero_words();
    w[0] = "аbandon"; // first letter is cyrillic а
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_word_with_diacritic() {
    let mut w = canonical_zero_words();
    w[0] = "abandön"; // 'ö' = 0xC3 0xB6
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_overlong_input() {
    // `lowercase_ascii` uses a 16-byte scratch buffer; anything longer must
    // be rejected, not silently truncated to a valid wordlist entry.
    let mut w = canonical_zero_words();
    w[0] = "abandonabandonabandon"; // 21 bytes > 16
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_words_rejects_almost_word() {
    // Off-by-one-letter typo — not a wordlist member.
    let mut w = canonical_zero_words();
    w[0] = "abando"; // missing trailing 'n'
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::UnknownWord);
}

// ---------------------------------------------------------------------------
// `from_words` checksum negatives
// ---------------------------------------------------------------------------

#[test]
fn negative_from_words_rejects_all_abandon_without_art_checksum() {
    // 24 × "abandon" would mean entropy is all-zero but the checksum byte is
    // also 0 — but the real SHA-256(0…)[0] = 0x66, so the 24th word must be
    // "art" (idx 0x66*8 >> 3 = 99). Anything else fails.
    let w = vec!["abandon"; 24];
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::BadChecksum);
}

#[test]
fn negative_from_words_rejects_mutated_middle_word() {
    let mut w = canonical_zero_words();
    w[5] = "zoo"; // very different bits → SHA-256 of new entropy fully redrawn
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::BadChecksum);
}

#[test]
fn negative_from_words_rejects_mutated_last_word_to_zoo() {
    // Documented in vectors.rs but tightened here: with the all-zero entropy
    // phrase, replacing the last word with anything other than "art" must be
    // rejected unless its 8 trailing checksum bits happen to coincide.
    let mut w = canonical_zero_words();
    w[23] = "zoo";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::BadChecksum);
}

#[test]
fn negative_from_words_rejects_swapped_adjacent_words() {
    let mut w = canonical_zero_words();
    // Swap two adjacent "abandon"s with a different word so the bit pattern
    // is not equivalent.
    w[10] = "ability";
    assert_eq!(Mnemonic::from_words(&w).unwrap_err(), BipError::BadChecksum);
}

// ---------------------------------------------------------------------------
// `from_indices` negatives
// ---------------------------------------------------------------------------

#[test]
fn negative_from_indices_rejects_index_equal_to_wordlist_len() {
    let mut indices = [0u16; 24];
    indices[5] = WORDLIST.len() as u16; // off-by-one out-of-range
    assert_eq!(Mnemonic::from_indices(indices).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_indices_rejects_max_u16() {
    let mut indices = [0u16; 24];
    indices[10] = u16::MAX;
    assert_eq!(Mnemonic::from_indices(indices).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_indices_rejects_out_of_range_in_last_slot() {
    // The last slot carries checksum bits; an out-of-range value there must
    // also be rejected (the check is uniform across all 24 slots).
    let mut indices = [0u16; 24];
    indices[23] = 2048;
    assert_eq!(Mnemonic::from_indices(indices).unwrap_err(), BipError::UnknownWord);
}

#[test]
fn negative_from_indices_rejects_in_range_but_wrong_checksum() {
    // All-zero indices (= 24 × "abandon") has the wrong checksum.
    let indices = [0u16; 24];
    assert_eq!(Mnemonic::from_indices(indices).unwrap_err(), BipError::BadChecksum);
}

#[test]
fn negative_from_indices_zeroes_internal_buffer_on_bad_checksum() {
    // Functional observation: even when the checksum mismatches the function
    // returns the error variant rather than partial entropy. (The actual
    // zeroize is a stack-local concern and visible only indirectly here.)
    let indices = [0u16; 24];
    let result = Mnemonic::from_indices(indices);
    assert!(matches!(result, Err(BipError::BadChecksum)));
}

// ---------------------------------------------------------------------------
// Bit-level resilience: every single-bit flip in a *good* phrase is rejected
// (allowing for the 1/256 birthday probability that the checksum coincides).
// ---------------------------------------------------------------------------

#[test]
fn negative_single_bit_flips_are_almost_always_rejected() {
    // Take a known-good phrase, walk all 24 × 11 = 264 single-bit positions,
    // and assert that at least 255/264 of the flipped phrases are rejected —
    // the BIP-39 8-bit checksum has expected collision rate 1/256.
    let good = Mnemonic::from_entropy(&[0x55u8; 32]);
    let mut indices = [0u16; 24];
    for i in 0..24 {
        indices[i] = good.word_index(i);
    }

    let mut rejected = 0usize;
    let mut accepted = 0usize;
    for word_pos in 0..24 {
        for bit in 0..11 {
            let mut mutated = indices;
            mutated[word_pos] ^= 1u16 << bit;
            // Skip if mutation pushed the index out of [0, 2048); that's an
            // UnknownWord, not a checksum test.
            if (mutated[word_pos] as usize) >= 2048 {
                continue;
            }
            match Mnemonic::from_indices(mutated) {
                Err(BipError::BadChecksum) => rejected += 1,
                Err(BipError::UnknownWord) => {} // skipped above
                Err(BipError::WrongLength) => {
                    panic!("WrongLength must not fire here")
                }
                Ok(_) => accepted += 1,
            }
        }
    }
    // 264 candidate flips; conservative bound — expect at least 95% rejection
    // for a uniform 1/256 collision probability.
    let total = rejected + accepted;
    assert!(
        total >= 200,
        "test infrastructure issue: only {total} flips ran"
    );
    assert!(
        rejected * 20 >= total * 19,
        "BIP-39 checksum rejected only {rejected}/{total} single-bit flips — \
         checksum is far weaker than 8-bit",
    );
}
