use pqsigner_domain as d;
use sha2::Digest;
fn p(n: &str, b: &[u8]) { println!("{} {}", n, hex::encode(b)); }
fn main() {
    let ent = [0u8; 32];
    let seed = sphincs_tz_bip39::Mnemonic::from_entropy(&ent).to_seed("");
    p("bip39_seed", &seed);
    let (pk, sk) = d::derive_c10_master_from_bip39_seed(&seed, 0);
    p("master_pk_seed", &pk); p("master_sk_seed", &sk);
    let m = d::hmac_sha512_bytes(b"sphincs-c6-v1", &seed); p("master_hmac", &m);
    let sm = d::slot_master_entropy_from_bip39(&seed, 0); p("slot_master", &sm);
    p("slhdsa_seed", &d::slhdsa_seed_from_bip39(&seed));
    p("bootstrap_seed", &d::bootstrap_seed_from_bip39(&seed));
    for (c, s) in [(1u64, 0u32), (1, 1), (2, 1)] {
        let se = d::slot_entropy(&sm, c, s);
        p(&format!("slot_entropy_c{}s{}", c, s), &se);
        let mut b = Vec::new(); b.extend_from_slice(b"slot_c10_sk_seed"); b.extend_from_slice(&se);
        p(&format!("slot_sk_seed_c{}s{}", c, s), &sha2::Sha256::digest(&b));
    }
}
