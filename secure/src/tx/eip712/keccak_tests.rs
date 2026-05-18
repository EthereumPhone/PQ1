//! Tests for the protocol-agnostic EIP-712 primitives in
//! [`super`] — `keccak`, `eip712_domain_separator`, `final_digest`, and
//! the private `DOMAIN_TYPEHASH_PREIMAGE`.
//!
//! Split into a positive suite (known-answer vectors + structural
//! determinism) and a negative suite that attacks every documented
//! assumption the primitives carry:
//!
//!   1. **Frozen domain typehash preimage.** The exact ASCII string the
//!      EIP-712 v0 standard requires. Any rename / reordering /
//!      whitespace change would silently relocate every digest the
//!      wallet ever signs.
//!   2. **Frozen-framing on `final_digest`.** Must prepend `0x19 0x01`
//!      then the DS then the struct_hash — exactly. Off-by-one or
//!      byte-swap inside the buffer would yield digests that diverge
//!      from anything Solidity / verifiers / orderbooks compute.
//!   3. **Field-flip sensitivity.** Each of the four `eip712_domain_separator`
//!      inputs MUST affect the output (otherwise CowSwap can be replayed
//!      across chains, or a different name/version can collide).
//!   4. **EnumOutOfRange exhaustiveness.** All `Eip712Error` variants
//!      have stable `Debug` formatting so production telemetry stays
//!      parseable.

use super::{eip712_domain_separator, final_digest, keccak, Eip712Error, DOMAIN_TYPEHASH_PREIMAGE};

// ---------------------------------------------------------------------------
// Known-answer vectors. These are stable cross-implementation values
// computed via Python `eth_utils.keccak` / on-chain `keccak256` /
// `solady.EIP712`. Any future "performance optimisation" to the keccak
// primitive that breaks them silently moves every digest off-chain code
// computes.
// ---------------------------------------------------------------------------

const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

const KECCAK_ABC: [u8; 32] = [
    0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
    0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45,
];

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,
///  address verifyingContract)")` — the canonical v0 EIP-712 domain
/// typehash that every Solidity verifier on the planet expects. Anchored
/// here so a rename in the production code breaks this test before it
/// breaks a real signing flow.
const DOMAIN_TYPEHASH_KNOWN: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d, 0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca, 0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

// ---------------------------------------------------------------------------
// Positive coverage
// ---------------------------------------------------------------------------

#[test]
fn positive_keccak_empty_known_vector() {
    assert_eq!(keccak(b""), KECCAK_EMPTY);
}

#[test]
fn positive_keccak_abc_known_vector() {
    assert_eq!(keccak(b"abc"), KECCAK_ABC);
}

#[test]
fn positive_keccak_output_length_is_32() {
    let h = keccak(b"any input at all");
    assert_eq!(h.len(), 32);
}

#[test]
fn positive_domain_separator_is_deterministic() {
    let name = keccak(b"PQTest");
    let version = keccak(b"1");
    let contract = [0x42u8; 20];
    let a = eip712_domain_separator(&name, &version, 1, &contract);
    let b = eip712_domain_separator(&name, &version, 1, &contract);
    assert_eq!(a, b);
}

#[test]
fn positive_final_digest_is_deterministic_and_framed() {
    // `final_digest` must hash exactly `0x19 0x01 || DS || struct_hash`.
    // Reconstruct that preimage byte-for-byte and confirm the helper
    // produces the same keccak.
    let ds = [0xaa; 32];
    let sh = [0xbb; 32];
    let want = {
        let mut buf = [0u8; 2 + 32 + 32];
        buf[0] = 0x19;
        buf[1] = 0x01;
        buf[2..34].copy_from_slice(&ds);
        buf[34..66].copy_from_slice(&sh);
        keccak(&buf)
    };
    assert_eq!(final_digest(&ds, &sh), want);
}

// ---------------------------------------------------------------------------
// Negative coverage — assumptions held by `super`
// ---------------------------------------------------------------------------

#[test]
fn negative_domain_typehash_preimage_is_byte_stable() {
    // ASSUMPTION: `DOMAIN_TYPEHASH_PREIMAGE` is the canonical EIP-712 v0
    // string. ATTACK: a refactor renames a field or adds whitespace,
    // shifting every signed digest into an unverifiable address space.
    assert_eq!(
        DOMAIN_TYPEHASH_PREIMAGE,
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "DOMAIN_TYPEHASH_PREIMAGE must be the canonical EIP-712 v0 string \
         — any rename invalidates every wallet signature"
    );
    assert_eq!(keccak(DOMAIN_TYPEHASH_PREIMAGE), DOMAIN_TYPEHASH_KNOWN);
}

#[test]
fn negative_domain_separator_binds_chain_id() {
    // ASSUMPTION: chain_id is mixed into the DS (replay-across-chains
    // protection). ATTACK: flip the chain_id and assert the DS shifts.
    let name = keccak(b"PQTest");
    let version = keccak(b"1");
    let contract = [0x42u8; 20];
    let a = eip712_domain_separator(&name, &version, 1, &contract);
    let b = eip712_domain_separator(&name, &version, 137, &contract);
    assert_ne!(
        a, b,
        "chain_id MUST be bound into the domain separator (cross-chain replay)"
    );
}

#[test]
fn negative_domain_separator_binds_verifying_contract() {
    // ASSUMPTION: verifyingContract is bound into the DS (cross-protocol
    // replay protection). ATTACK: swap the address.
    let name = keccak(b"PQTest");
    let version = keccak(b"1");
    let a = eip712_domain_separator(&name, &version, 1, &[0x42; 20]);
    let b = eip712_domain_separator(&name, &version, 1, &[0x43; 20]);
    assert_ne!(a, b, "verifyingContract MUST be bound into the domain separator");
}

#[test]
fn negative_domain_separator_binds_name_hash() {
    let na = keccak(b"PQTest");
    let nb = keccak(b"PQTest2");
    let version = keccak(b"1");
    let contract = [0x42u8; 20];
    let a = eip712_domain_separator(&na, &version, 1, &contract);
    let b = eip712_domain_separator(&nb, &version, 1, &contract);
    assert_ne!(a, b, "name_hash MUST affect the domain separator");
}

#[test]
fn negative_domain_separator_binds_version_hash() {
    let name = keccak(b"PQTest");
    let va = keccak(b"1");
    let vb = keccak(b"2");
    let contract = [0x42u8; 20];
    let a = eip712_domain_separator(&name, &va, 1, &contract);
    let b = eip712_domain_separator(&name, &vb, 1, &contract);
    assert_ne!(a, b, "version_hash MUST affect the domain separator");
}

#[test]
fn negative_domain_separator_chain_id_is_left_padded_uint256_be() {
    // ASSUMPTION: chain_id is encoded as 24 zero bytes + 8 BE bytes in
    // the DS preimage (per EIP-712 / Solidity ABI). ATTACK: a refactor
    // that emits chain_id as LE or as 8 trailing bytes in a 32-byte slot
    // packed to the *left* would yield different separators for the same
    // chain. We pin the expected encoding by reconstructing it.
    let name = keccak(b"PQTest");
    let version = keccak(b"1");
    let contract = [0x42u8; 20];

    let chain_id: u64 = 0x0123_4567_89ab_cdef;
    let got = eip712_domain_separator(&name, &version, chain_id, &contract);

    let domain_typehash = keccak(DOMAIN_TYPEHASH_PREIMAGE);
    let mut buf = [0u8; 32 * 5];
    buf[0..32].copy_from_slice(&domain_typehash);
    buf[32..64].copy_from_slice(&name);
    buf[64..96].copy_from_slice(&version);
    buf[96 + 24..96 + 32].copy_from_slice(&chain_id.to_be_bytes());
    buf[128 + 12..128 + 32].copy_from_slice(&contract);
    let want = keccak(&buf);
    assert_eq!(got, want, "chain_id must be uint256 BE in slot[96..128]");
}

#[test]
fn negative_final_digest_binds_domain_separator() {
    // ASSUMPTION: changing DS changes the final digest. ATTACK: a
    // refactor that accidentally hashed only the struct_hash would yield
    // an EIP-712-incompatible signature.
    let ds1 = [0x11; 32];
    let ds2 = [0x22; 32];
    let sh = [0xbb; 32];
    assert_ne!(
        final_digest(&ds1, &sh),
        final_digest(&ds2, &sh),
        "domain_separator must affect final_digest"
    );
}

#[test]
fn negative_final_digest_binds_struct_hash() {
    let ds = [0xaa; 32];
    let sh1 = [0x11; 32];
    let sh2 = [0x22; 32];
    assert_ne!(
        final_digest(&ds, &sh1),
        final_digest(&ds, &sh2),
        "struct_hash must affect final_digest"
    );
}

#[test]
fn negative_final_digest_byte_swap_changes_output() {
    // ASSUMPTION: byte order inside the 0x19||0x01||DS||SH preimage is
    // fixed. ATTACK: swap DS and SH at the call site and the digest must
    // differ — proves the helper isn't symmetric.
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert_ne!(
        final_digest(&a, &b),
        final_digest(&b, &a),
        "argument order to final_digest must be DS, struct_hash — not commutative"
    );
}

#[test]
fn negative_eip712_error_variants_have_distinct_debug() {
    // Telemetry parses on Debug output; assert the two variants don't
    // accidentally collapse to the same string after a refactor.
    let a = std::format!("{:?}", Eip712Error::EnumOutOfRange);
    let b = std::format!("{:?}", Eip712Error::ChainIdMismatch);
    assert_ne!(a, b);
    assert!(a.contains("EnumOutOfRange"));
    assert!(b.contains("ChainIdMismatch"));
}
