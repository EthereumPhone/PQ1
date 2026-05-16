//! Positive functional coverage of the `Mnemonic` surface and the
//! `hash_to_word_indices` helper. Existing `tests/vectors.rs` covers the
//! Trezor reference vectors; this file fills in golden-path coverage of every
//! remaining public function.

use sphincs_tz_bip39::{
    hash_to_word_indices, BipError, Mnemonic, ENTROPY_BYTES, SEED_BYTES, WORDLIST, WORD_COUNT,
};

#[test]
fn positive_constants_have_documented_values() {
    assert_eq!(WORD_COUNT, 24);
    assert_eq!(ENTROPY_BYTES, 32);
    assert_eq!(SEED_BYTES, 64);
}

#[test]
fn positive_from_entropy_all_zeros_produces_canonical_phrase() {
    let m = Mnemonic::from_entropy(&[0u8; 32]);
    for i in 0..23 {
        assert_eq!(m.word(i), "abandon", "word {i} of all-zero entropy");
    }
    assert_eq!(m.word(23), "art");
}

#[test]
fn positive_from_entropy_all_ones_produces_zoo_vote_phrase() {
    let m = Mnemonic::from_entropy(&[0xFFu8; 32]);
    for i in 0..23 {
        assert_eq!(m.word(i), "zoo", "word {i} of all-0xFF entropy");
    }
    assert_eq!(m.word(23), "vote");
}

#[test]
fn positive_words_iterator_yields_exactly_24() {
    let m = Mnemonic::from_entropy(&[0u8; 32]);
    let collected: Vec<&'static str> = m.words().collect();
    assert_eq!(collected.len(), WORD_COUNT);
}

#[test]
fn positive_word_index_matches_wordlist_lookup() {
    let m = Mnemonic::from_entropy(&[0xABu8; 32]);
    for i in 0..WORD_COUNT {
        let idx = m.word_index(i);
        assert!(
            (idx as usize) < WORDLIST.len(),
            "word_index({i}) = {idx} out of wordlist range"
        );
        assert_eq!(WORDLIST[idx as usize], m.word(i));
    }
}

#[test]
fn positive_from_indices_round_trips_through_to_entropy() {
    let entropy = [0xABu8; 32];
    let m = Mnemonic::from_entropy(&entropy);
    let mut indices = [0u16; WORD_COUNT];
    for i in 0..WORD_COUNT {
        indices[i] = m.word_index(i);
    }
    let m2 = Mnemonic::from_indices(indices).expect("checksum should verify");
    assert_eq!(m2.to_entropy().unwrap(), entropy);
    // And the words round-trip identically too.
    for i in 0..WORD_COUNT {
        assert_eq!(m.word(i), m2.word(i));
    }
}

#[test]
fn positive_from_words_accepts_owned_string_slice() {
    // The signature is `&[S] where S: AsRef<str>`; check it works for owned
    // `String`s, not just `&str`.
    let mut owned: Vec<String> = (0..23).map(|_| "abandon".to_string()).collect();
    owned.push("art".to_string());
    let m = Mnemonic::from_words(&owned).expect("parse owned strings");
    assert_eq!(m.to_entropy().unwrap(), [0u8; 32]);
}

#[test]
fn positive_to_seed_is_deterministic() {
    let m = Mnemonic::from_entropy(&[0u8; 32]);
    let s1 = m.to_seed("");
    let s2 = m.to_seed("");
    assert_eq!(s1, s2, "BIP-39 seed derivation must be deterministic");
    assert_eq!(s1.len(), SEED_BYTES);
}

#[test]
fn positive_different_passphrases_produce_different_seeds() {
    let m = Mnemonic::from_entropy(&[0u8; 32]);
    let a = m.to_seed("");
    let b = m.to_seed("TREZOR");
    let c = m.to_seed("password");
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn positive_different_mnemonics_produce_different_seeds() {
    // Hard-but-not-impossible second-preimage check on PBKDF2-HMAC-SHA512:
    // two distinct mnemonics with the same passphrase must derive different
    // seeds.
    let m1 = Mnemonic::from_entropy(&[0u8; 32]);
    let m2 = Mnemonic::from_entropy(&[0xFFu8; 32]);
    assert_ne!(m1.to_seed(""), m2.to_seed(""));
}

#[test]
fn positive_biperror_display_strings_are_stable() {
    // External code (recovery wizard UX) renders these strings to the user.
    // Stability here keeps trusted-UI text byte-stable across refactors.
    assert_eq!(
        format!("{}", BipError::UnknownWord),
        "word not in BIP-39 English wordlist",
    );
    assert_eq!(
        format!("{}", BipError::BadChecksum),
        "BIP-39 checksum mismatch",
    );
    assert_eq!(
        format!("{}", BipError::WrongLength),
        "expected 24 BIP-39 words",
    );
}

#[test]
fn positive_biperror_is_copy_clone_eq() {
    // Trivial-value error type — copying it must not move secret bytes.
    let e: BipError = BipError::BadChecksum;
    let f = e; // Copy
    assert_eq!(e, f);
    #[allow(clippy::clone_on_copy)]
    let g = e.clone();
    assert_eq!(e, g);
}

#[test]
fn positive_hash_to_word_indices_returns_8_in_range_indices() {
    // Used by the firmware-measurement display, not for key material.
    let h = [0xA5u8; 32];
    let idxs = hash_to_word_indices(&h);
    assert_eq!(idxs.len(), 8);
    for (i, idx) in idxs.iter().enumerate() {
        assert!(
            (*idx as usize) < WORDLIST.len(),
            "index {i} out of wordlist range: {}",
            idx
        );
    }
}

#[test]
fn positive_hash_to_word_indices_zero_hash_is_all_zero() {
    let idxs = hash_to_word_indices(&[0u8; 32]);
    assert_eq!(idxs, [0u16; 8]);
}

#[test]
fn positive_hash_to_word_indices_top_11_bits_are_first_word() {
    // 0xFF 0xE0 ... -> top 11 bits = 0x7FF.
    let mut h = [0u8; 32];
    h[0] = 0xFF;
    h[1] = 0xE0;
    let idxs = hash_to_word_indices(&h);
    assert_eq!(idxs[0], 0x7FF);
    // The next 11 bits start mid-byte 1 — that bit window is all zeros.
    assert_eq!(idxs[1], 0);
}

#[test]
fn positive_hash_to_word_indices_matches_mnemonic_packing_for_first_8_words() {
    // The bit-packing used by `hash_to_word_indices` must agree with the
    // one used by `Mnemonic::from_entropy` (they share the underlying
    // `read_11_bits` helper). Verify on a value with no checksum overlap.
    let entropy = [0xAAu8; 32];
    let m = Mnemonic::from_entropy(&entropy);
    let idxs = hash_to_word_indices(&entropy);
    for i in 0..8 {
        assert_eq!(
            idxs[i],
            m.word_index(i),
            "word {i} disagrees between hash_to_word_indices and Mnemonic"
        );
    }
}
