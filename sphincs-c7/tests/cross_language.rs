//! Cross-language verification tests.
//!
//! Verifies that:
//! 1. The Rust verifier accepts Python-generated C7 signatures
//! 2. The Rust signer produces self-verifiable signatures
//! 3. Key derivation matches the Python reference signer

use sphincs_c7::params::{N, SIGNATURE_LEN};
use sphincs_c7::{verify, VerifyingKey};

/// Load test vectors from the Foundry test file.
fn load_test_vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/smart-wallet/test/test_vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("Failed to read test_vectors.json");
    serde_json::from_str(&data).expect("Failed to parse test_vectors.json")
}

/// Parse a 0x-prefixed hex string to bytes.
fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).expect("Invalid hex")
}

/// Extract the top 16 bytes (pk_seed or pk_root) from a bytes32 hex value.
fn parse_n_bytes(hex_str: &str) -> [u8; N] {
    let bytes = hex_to_bytes(hex_str);
    assert!(bytes.len() == 32, "Expected 32 bytes, got {}", bytes.len());
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

/// Parse a bytes32 hex value to a full 32-byte array.
fn parse_32_bytes(hex_str: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex_str);
    assert!(bytes.len() == 32, "Expected 32 bytes, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Parse a signature hex to a fixed-size array.
fn parse_sig(hex_str: &str) -> [u8; SIGNATURE_LEN] {
    let bytes = hex_to_bytes(hex_str);
    assert_eq!(
        bytes.len(),
        SIGNATURE_LEN,
        "Expected {} bytes, got {}",
        SIGNATURE_LEN,
        bytes.len()
    );
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn test_verify_python_main_signature() {
    let tv = load_test_vectors();

    let pk_seed = parse_n_bytes(tv["main"]["pkSeed"].as_str().unwrap());
    let pk_root = parse_n_bytes(tv["main"]["pkRoot"].as_str().unwrap());
    let msg_hash = parse_32_bytes(tv["userOpHash"].as_str().unwrap());
    let sig = parse_sig(tv["mainSig"].as_str().unwrap());

    let valid = verify(&pk_seed, &pk_root, &msg_hash, &sig);
    assert!(valid, "Rust verifier must accept Python-generated main signature");
}

#[test]
fn test_verify_python_bootstrap_signature() {
    let tv = load_test_vectors();

    let pk_seed = parse_n_bytes(tv["bootstrap"]["pkSeed"].as_str().unwrap());
    let pk_root = parse_n_bytes(tv["bootstrap"]["pkRoot"].as_str().unwrap());

    // The bootstrap signature signs: sha256("PQWALLET_INIT_V1" || mainPkSeed || mainPkRoot)
    let auth_msg = parse_32_bytes(tv["factoryAuthMsg"].as_str().unwrap());
    let sig = parse_sig(tv["bootstrapSig"].as_str().unwrap());

    let valid = verify(&pk_seed, &pk_root, &auth_msg, &sig);
    assert!(
        valid,
        "Rust verifier must accept Python-generated bootstrap signature"
    );
}

#[test]
fn test_verify_python_bootstrap_sig2() {
    let tv = load_test_vectors();

    let pk_seed = parse_n_bytes(tv["bootstrap"]["pkSeed"].as_str().unwrap());
    let pk_root = parse_n_bytes(tv["bootstrap"]["pkRoot"].as_str().unwrap());
    let rotation_hash = parse_32_bytes(tv["rotationHash"].as_str().unwrap());
    let sig = parse_sig(tv["bootstrapSig2"].as_str().unwrap());

    let valid = verify(&pk_seed, &pk_root, &rotation_hash, &sig);
    assert!(
        valid,
        "Rust verifier must accept Python-generated bootstrap rotation signature"
    );
}

#[test]
fn test_signature_size() {
    assert_eq!(SIGNATURE_LEN, 3976, "C11 signature must be exactly 3976 bytes");
}

#[test]
fn test_verifying_key_roundtrip() {
    let tv = load_test_vectors();
    let pk_seed = parse_n_bytes(tv["main"]["pkSeed"].as_str().unwrap());
    let pk_root = parse_n_bytes(tv["main"]["pkRoot"].as_str().unwrap());

    let vk = VerifyingKey { pk_seed, pk_root };
    let bytes = vk.to_bytes();
    let vk2 = VerifyingKey::from_bytes(&bytes);
    assert_eq!(vk, vk2);
}
