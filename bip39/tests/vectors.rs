//! Official BIP-39 24-word test vectors from
//! <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>.
//!
//! Each tuple is (entropy_hex, mnemonic, seed_hex_TREZOR_passphrase).
//! All vectors use the passphrase "TREZOR".

use sphincs_tz_bip39::{BipError, Mnemonic};

const VECTORS: &[(&str, &str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
    (
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    ),
    (
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    ),
];

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn from_entropy_matches_vectors() {
    for (entropy_hex, expected_mnemonic, _seed) in VECTORS {
        let entropy_bytes = unhex(entropy_hex);
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&entropy_bytes);
        let m = Mnemonic::from_entropy(&entropy);
        let actual: Vec<&'static str> = m.words().collect();
        let expected: Vec<&str> = expected_mnemonic.split_whitespace().collect();
        assert_eq!(actual.len(), 24);
        assert_eq!(actual, expected, "entropy={}", entropy_hex);
    }
}

#[test]
fn to_entropy_round_trips() {
    for (entropy_hex, _mnemonic, _seed) in VECTORS {
        let entropy_bytes = unhex(entropy_hex);
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&entropy_bytes);
        let m = Mnemonic::from_entropy(&entropy);
        let recovered = m.to_entropy().expect("checksum should verify");
        assert_eq!(recovered, entropy);
    }
}

#[test]
fn from_words_round_trips() {
    for (entropy_hex, mnemonic, _seed) in VECTORS {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        let m = Mnemonic::from_words(&words).expect("parse");
        let entropy_bytes = unhex(entropy_hex);
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&entropy_bytes);
        let recovered = m.to_entropy().expect("checksum");
        assert_eq!(recovered, entropy);
    }
}

#[test]
fn checksum_mutation_is_detected() {
    // Take a known good mnemonic and swap the last word for any other valid
    // word. The 8-bit checksum should reject ~255/256 of those swaps.
    let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let mut v: Vec<&str> = words.split_whitespace().collect();
    // Replace the last word with "zoo" — different word with different bits.
    v[23] = "zoo";
    let err = Mnemonic::from_words(&v).unwrap_err();
    assert_eq!(err, BipError::BadChecksum);
}

#[test]
fn unknown_word_is_rejected() {
    let words = "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let v: Vec<&str> = words.split_whitespace().collect();
    let err = Mnemonic::from_words(&v).unwrap_err();
    assert_eq!(err, BipError::UnknownWord);
}

#[test]
fn wrong_length_is_rejected() {
    let words = vec!["abandon"; 12];
    let err = Mnemonic::from_words(&words).unwrap_err();
    assert_eq!(err, BipError::WrongLength);
}

#[test]
fn to_seed_matches_trezor_vectors() {
    for (_entropy, mnemonic, expected_seed_hex) in VECTORS {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        let m = Mnemonic::from_words(&words).expect("parse");
        let seed = m.to_seed("TREZOR");
        let expected = unhex(expected_seed_hex);
        assert_eq!(
            &seed[..],
            &expected[..],
            "seed mismatch for mnemonic starting with {}",
            words[0]
        );
    }
}

#[test]
fn case_insensitive_lookup() {
    let words = "ABANDON Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ART";
    let v: Vec<&str> = words.split_whitespace().collect();
    let m = Mnemonic::from_words(&v).expect("parse");
    assert_eq!(m.word(0), "abandon");
    assert_eq!(m.word(23), "art");
}

#[test]
fn debug_does_not_leak_words() {
    let m = Mnemonic::from_entropy(&[0u8; 32]);
    let s = format!("{:?}", m);
    assert!(s.contains("redacted"), "Debug must not print word contents");
    assert!(!s.contains("abandon"), "Debug must not print word contents");
}

// The progress variant (the pixel busy film ticks through the PBKDF2
// stretch) derives the same seed and reports densely inside its band.
#[test]
fn to_seed_with_progress_matches_vectors_and_reports_in_band() {
    use std::cell::RefCell;
    thread_local!(static PROG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) });
    fn cb(pct: u8) {
        PROG.with(|v| v.borrow_mut().push(pct));
    }
    for (entropy_hex, _, seed_hex) in VECTORS {
        let entropy: [u8; 32] = hex::decode(entropy_hex).unwrap().try_into().unwrap();
        let m = Mnemonic::from_entropy(&entropy);
        PROG.with(|v| v.borrow_mut().clear());
        let seed = m.to_seed_with_progress("TREZOR", cb, 10, 40);
        assert_eq!(hex::encode(seed), *seed_hex);
        assert_eq!(seed, m.to_seed("TREZOR"));
        let prog: Vec<u8> = PROG.with(|v| v.borrow().clone());
        assert_eq!(prog.len(), 32, "one report per 64 of the 2048 iterations: {prog:?}");
        assert_eq!(prog.last().copied(), Some(40));
        assert!(prog.iter().all(|p| (10..=40).contains(p)), "{prog:?}");
        assert!(prog.windows(2).all(|w| w[0] <= w[1]), "{prog:?}");
    }
}
