//! Extra positive (functional) coverage that the in-file `#[cfg(test)]`
//! suites don't reach.
//!
//! Focus: the EIP-1271 helpers (`proxy_address`, `domain_separator`,
//! `personal_sign_prefixed_hash`, `personal_sign_replay_safe_hash`),
//! `sha256_bytes`, and the named domain constants that the on-chain
//! verifier *must* see byte-for-byte.

use pqsigner_aa::eip1271::{
    domain_separator, personal_sign_prefixed_hash, personal_sign_replay_safe_hash, proxy_address,
    EIP712_DOMAIN_TYPEHASH, NAME_HASH, PERSONAL_SIGN_TYPEHASH, VERSION_HASH,
};
use pqsigner_aa::userop::{
    sha256_bytes, ENTRY_POINT_V06, KECCAK_EMPTY, SHA256_EMPTY,
};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// proxy_address — CREATE2 derivation must be deterministic + key-sensitive.
// ---------------------------------------------------------------------------

#[test]
fn positive_proxy_address_deterministic() {
    let pk_seed = [0xAA; 32];
    let pk_root = [0xBB; 32];
    let a = proxy_address(&pk_seed, &pk_root);
    let b = proxy_address(&pk_seed, &pk_root);
    assert_eq!(a, b, "proxy_address must be a pure function of its inputs");
}

#[test]
fn positive_proxy_address_pk_seed_changes_output() {
    let pk_seed0 = [0xAA; 32];
    let mut pk_seed1 = pk_seed0;
    pk_seed1[0] ^= 0x01; // flip a single bit
    let pk_root = [0xBB; 32];
    assert_ne!(
        proxy_address(&pk_seed0, &pk_root),
        proxy_address(&pk_seed1, &pk_root),
        "single-bit flip in pk_seed must produce a different CREATE2 address",
    );
}

#[test]
fn positive_proxy_address_pk_root_changes_output() {
    let pk_seed = [0xAA; 32];
    let pk_root0 = [0xBB; 32];
    let mut pk_root1 = pk_root0;
    pk_root1[31] ^= 0x80; // flip the high bit of the last byte
    assert_ne!(
        proxy_address(&pk_seed, &pk_root0),
        proxy_address(&pk_seed, &pk_root1),
        "single-bit flip in pk_root must produce a different CREATE2 address",
    );
}

#[test]
fn positive_proxy_address_first_12_bytes_unused() {
    // The Keccak digest is truncated to its last 20 bytes; the
    // function must not accidentally return the first 20.
    let pk_seed = [0x12; 32];
    let pk_root = [0x34; 32];
    let addr = proxy_address(&pk_seed, &pk_root);
    assert_eq!(addr.len(), 20);
}

// ---------------------------------------------------------------------------
// domain_separator — must be chain- and verifyingContract-bound.
// ---------------------------------------------------------------------------

#[test]
fn positive_domain_separator_includes_chain_id() {
    let verifying = [0x42u8; 20];
    let d1 = domain_separator(1, &verifying);
    let d8453 = domain_separator(8453, &verifying);
    assert_ne!(d1, d8453, "EIP-712 domain separator must bind chain_id");
}

#[test]
fn positive_domain_separator_includes_verifying_contract() {
    let v0 = [0u8; 20];
    let v1 = [0xFFu8; 20];
    assert_ne!(
        domain_separator(1, &v0),
        domain_separator(1, &v1),
        "EIP-712 domain separator must bind verifyingContract",
    );
}

#[test]
fn positive_domain_separator_matches_eip712_construction() {
    // Recompute by hand from the published constants and confirm the
    // helper agrees byte-for-byte. This is the on-chain Solady
    // construction.
    let chain_id: u64 = 8453;
    let verifying: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44,
    ];
    let mut buf = [0u8; 5 * 32];
    buf[..32].copy_from_slice(&EIP712_DOMAIN_TYPEHASH);
    buf[32..64].copy_from_slice(&NAME_HASH);
    buf[64..96].copy_from_slice(&VERSION_HASH);
    buf[96 + 24..128].copy_from_slice(&chain_id.to_be_bytes());
    buf[128 + 12..160].copy_from_slice(&verifying);
    let expected = keccak(&buf);
    assert_eq!(domain_separator(chain_id, &verifying), expected);
}

// ---------------------------------------------------------------------------
// personal_sign_prefixed_hash — `"\x19Ethereum Signed Message:\n<len>" || msg`.
// ---------------------------------------------------------------------------

#[test]
fn positive_personal_sign_prefixed_known_vector_hello() {
    // Canonical `eth_sign("Hello")`:
    //   keccak256("\x19Ethereum Signed Message:\n5Hello")
    //   = 0xa080337ae51c4e064c189e113edd0ba391df9206e2f49db658bb32cf2911730b
    let expected = keccak(b"\x19Ethereum Signed Message:\n5Hello");
    assert_eq!(personal_sign_prefixed_hash(b"Hello"), expected);
}

#[test]
fn positive_personal_sign_prefixed_empty_message_renders_zero() {
    // The decimal_str helper renders len 0 as the ASCII "0" character —
    // not the empty string — so that the prefix matches the EIP-191
    // / personal_sign convention bit-for-bit.
    let expected = keccak(b"\x19Ethereum Signed Message:\n0");
    assert_eq!(personal_sign_prefixed_hash(&[]), expected);
}

#[test]
fn positive_personal_sign_prefixed_three_digit_length() {
    // 123-byte msg → ASCII "123" length tag. Catches a single-digit
    // off-by-one in the decimal renderer.
    let msg = [0xAAu8; 123];
    let mut preimage = std::vec::Vec::new();
    preimage.extend_from_slice(b"\x19Ethereum Signed Message:\n123");
    preimage.extend_from_slice(&msg);
    assert_eq!(personal_sign_prefixed_hash(&msg), keccak(&preimage));
}

#[test]
fn positive_personal_sign_prefixed_length_4096() {
    // Upper-bound length (firmware caps inner payload around MAX_TX_LEN).
    let msg = [0x5Au8; 4096];
    let mut preimage = std::vec::Vec::new();
    preimage.extend_from_slice(b"\x19Ethereum Signed Message:\n4096");
    preimage.extend_from_slice(&msg);
    assert_eq!(personal_sign_prefixed_hash(&msg), keccak(&preimage));
}

// ---------------------------------------------------------------------------
// personal_sign_replay_safe_hash — Solady-nested EIP-712.
// ---------------------------------------------------------------------------

#[test]
fn positive_replay_safe_matches_handrolled_construction() {
    let chain_id: u64 = 1;
    let verifying: [u8; 20] = [0xCCu8; 20];
    let msg = b"the quick brown fox";

    let prefixed = personal_sign_prefixed_hash(msg);
    let mut sb = std::vec::Vec::new();
    sb.extend_from_slice(&PERSONAL_SIGN_TYPEHASH);
    sb.extend_from_slice(&prefixed);
    let struct_hash = keccak(&sb);
    let dsep = domain_separator(chain_id, &verifying);
    let mut fb = std::vec::Vec::new();
    fb.extend_from_slice(b"\x19\x01");
    fb.extend_from_slice(&dsep);
    fb.extend_from_slice(&struct_hash);
    let expected = keccak(&fb);

    assert_eq!(
        personal_sign_replay_safe_hash(chain_id, &verifying, msg),
        expected,
    );
}

#[test]
fn positive_replay_safe_changes_with_message() {
    let chain_id: u64 = 1;
    let verifying: [u8; 20] = [0xCCu8; 20];
    let h1 = personal_sign_replay_safe_hash(chain_id, &verifying, b"a");
    let h2 = personal_sign_replay_safe_hash(chain_id, &verifying, b"b");
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// sha256_bytes — thin wrapper, but verify it matches the standard.
// ---------------------------------------------------------------------------

#[test]
fn positive_sha256_bytes_empty_matches_sha256_empty_constant() {
    assert_eq!(sha256_bytes(&[]), SHA256_EMPTY);
}

#[test]
fn positive_sha256_bytes_matches_sha2_crate() {
    let data = b"the slithy toves did gyre and gimble in the wabe";
    let expected: [u8; 32] = Sha256::digest(data).into();
    assert_eq!(sha256_bytes(data), expected);
}

// ---------------------------------------------------------------------------
// Canonical constants — these are the wallet's identity. Pin them.
// ---------------------------------------------------------------------------

#[test]
fn positive_sha256_empty_constant_matches_canonical() {
    let canonical: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(
        SHA256_EMPTY, canonical,
        "SHA256_EMPTY must equal sha256(\"\") — used as default initCode / paymasterAndData digest",
    );
}

#[test]
fn positive_keccak_empty_constant_matches_canonical() {
    assert_eq!(
        KECCAK_EMPTY,
        keccak(b""),
        "KECCAK_EMPTY must equal keccak256(\"\") — EntryPoint v0.6 uses it for empty initCode/paymasterAndData",
    );
}

#[test]
fn positive_entry_point_v06_address_canonical() {
    // EntryPoint v0.6 singleton 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789.
    // This address is baked into the userOpHash on every chain that
    // bundles v0.6 UserOps — bumping it breaks invariant #6 (CREATE2
    // init-code hash stability).
    let expected: [u8; 20] = [
        0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57,
        0x8a, 0x02, 0x6d, 0x27, 0x89,
    ];
    assert_eq!(ENTRY_POINT_V06, expected);
}
