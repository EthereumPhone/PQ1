//! Reference side of the differential: pristine master sphincs-c10 (software SHA-256).
//! Prints one line per case: index, pk_root hex, SHA-256 of the signature.
use sha2::{Digest, Sha256};
use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};
include!("../../diff_cases.rs");
fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(40);
    let every: u32 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(4);
    let mut key: Option<(u32, SigningKey)> = None;
    for i in 0..n {
        let c = case(i, every);
        if key.as_ref().map(|k| k.0) != Some(i / every) { key = Some((i / every, SigningKey::keygen(c.sk_seed, c.pk_seed))); }
        let sk = &key.as_ref().unwrap().1;
        let sig = sk.sign_with_shuffle_silent(&c.msg, c.opt_rand.as_ref(), &ShuffleSeed(c.shuffle));
        assert!(sk.verifying_key().verify(&c.msg, &sig));
        println!("{i} {} {}", hex::encode(sk.pk_root()), hex::encode(Sha256::digest(sig)));
    }
}
