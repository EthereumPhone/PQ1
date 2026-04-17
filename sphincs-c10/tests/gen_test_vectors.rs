//! Generate Rust-side C10 test vectors for the Solidity `SPHINCsC10Asm`
//! verifier. Produces a signature from a deterministic keypair + message,
//! runs the Rust verifier locally as a sanity check, and writes the
//! result to `../contracts/smart-wallet/test/c10_test_vectors.json` so
//! the forge test harness can load it with `vm.readFile`.
//!
//! Run with:
//!   cargo test -p sphincs-c10 --test gen_test_vectors --release -- --nocapture
//!
//! Release mode is strongly recommended — the hypertree keygen runs in
//! software sha2 and takes O(seconds) on a laptop, O(30+ s) in debug.

use sphincs_c10::params::{N, SIGNATURE_LEN};
use sphincs_c10::{verify, SigningKey};
use std::fs;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn pad_to_b32_hex(val: &[u8; N]) -> String {
    // Bytes32-shaped hex: top N bytes populated, bottom 32-N bytes zero.
    let mut out = [0u8; 32];
    out[..N].copy_from_slice(val);
    to_hex(&out)
}

#[test]
fn generate_c10_test_vectors() {
    // Deterministic keypair so re-runs are bit-identical.
    let sk_seed: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
    ];
    let pk_seed: [u8; N] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];

    println!("Running C10 hypertree keygen (this takes a few seconds)…");
    let sk = SigningKey::keygen(sk_seed, pk_seed);

    let msg: [u8; 32] = *b"PQSigner OS C10 Foundry test vec";
    assert_eq!(msg.len(), 32);

    println!("Signing…");
    let sig = sk.sign(&msg, None);
    assert_eq!(sig.len(), SIGNATURE_LEN, "sig must be 4008 bytes");

    // Self-verify sanity check.
    assert!(
        verify(sk.pk_seed(), sk.pk_root(), &msg, &sig),
        "Rust verify must accept freshly-generated sig"
    );

    let json = format!(
        r#"{{
  "pkSeed": "{}",
  "pkRoot": "{}",
  "message": "{}",
  "signature": "{}",
  "sigLen": {}
}}"#,
        pad_to_b32_hex(sk.pk_seed()),
        pad_to_b32_hex(sk.pk_root()),
        to_hex(&msg),
        to_hex(&sig),
        sig.len()
    );

    let out_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/smart-wallet/test/c10_test_vectors.json"
    );
    fs::write(out_path, &json).expect("write c10 test vectors");
    println!("Wrote C10 vectors to {}", out_path);
}
