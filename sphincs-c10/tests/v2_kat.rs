//! RESEARCH (#1155): the Rust v2 hash layer against the Python reference
//! (`research/c10-autoresearch/c10v2/c10v2_ref.py`, written from the spec).
//! The Python side forks the clean-room v1 signer; the Rust side keeps the
//! production `wots`/`fors`/`hypertree` and swaps only `hash.rs`. Agreement is
//! evidence about the spec AND the scheme structure, from two code bases.
#![cfg(feature = "v2")]

use sphincs_c10::params::{N, SIGNATURE_LEN, VERIFYING_KEY_LEN};
use sphincs_c10::{SigningKey, VerifyingKey};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn v2_matches_python_reference_kats() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../research/c10-autoresearch/c10v2/kat-v2-draft02.txt");
    let text = std::fs::read_to_string(path).expect("KAT file");
    let mut n = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let sk: [u8; 32] = hex(f[0]).try_into().unwrap();
        let ps: [u8; N] = hex(f[1]).try_into().unwrap();
        let root: [u8; N] = hex(f[2]).try_into().unwrap();
        let msg: [u8; 32] = hex(f[3]).try_into().unwrap();
        let sig: [u8; SIGNATURE_LEN] = hex(f[4]).try_into().unwrap();
        let key = SigningKey::keygen(sk, ps);
        assert_eq!(key.pk_root(), &root, "pk_root, vector {n}");
        let got = key.sign(&msg, None);
        assert!(got[..] == sig[..], "signature bytes, vector {n}");
        let mut vk = [0u8; VERIFYING_KEY_LEN];
        vk[..N].copy_from_slice(&ps);
        vk[N..].copy_from_slice(&root);
        let vk = VerifyingKey::from_bytes(&vk);
        assert!(vk.verify(&msg, &sig), "Rust verifies the Python signature, vector {n}");
        let mut bad = sig;
        bad[2336 + 5] ^= 1;
        assert!(!vk.verify(&msg, &bad), "near-miss rejected, vector {n}");
        n += 1;
    }
    assert_eq!(n, 6, "all KAT vectors ran");
}

/// Spec 0.2 §7.3: signatures that rebuild the CORRECT root (checked on the
/// Python side with the +C checks off) and break exactly one +C rule — the
/// FORS last index, the WOTS digit sum at layer 0, at layer 1. Rust must
/// reject every one.
#[test]
fn v2_rejects_plus_c_only_near_misses() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../research/c10-autoresearch/c10v2/nearmiss-v2-draft02.txt");
    let text = std::fs::read_to_string(path).expect("near-miss file");
    let mut n = 0;
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let mut vk = [0u8; VERIFYING_KEY_LEN];
        vk[..N].copy_from_slice(&hex(f[1]));
        vk[N..].copy_from_slice(&hex(f[2]));
        let msg: [u8; 32] = hex(f[3]).try_into().unwrap();
        let sig: [u8; SIGNATURE_LEN] = hex(f[4]).try_into().unwrap();
        assert!(!VerifyingKey::from_bytes(&vk).verify(&msg, &sig), "+C-only near-miss {} ACCEPTED", f[0]);
        n += 1;
    }
    assert_eq!(n, 3);
}
