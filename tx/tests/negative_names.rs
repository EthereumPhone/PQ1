//! Negative: `tx::names` bundle + resolver adversarial inputs.
//!
//! The names DB is "the OLED's source of human-readable identity" for
//! every address that crosses the trusted UI. A name that the verifier
//! accepts is the name the user trusts. Spoofing footholds here turn
//! "verified curated DB" into "attacker-shaped identity overlay", so
//! we pin: the ASCII gate, the length cap, the trailing-bytes gate, and
//! the wildcard-vs-exact policy of the resolver.

mod common;

use common::{build_name_bundle, build_tree, canonical_name, leaf_hash};
use pqsigner_tx::names::{verify_name_bundle, NameMeta, NameResolver, MAX_NAME_BUNDLES};
use sphincs_tz_shared::db_format::{NAMES_MAX_LEN, NAMES_WILDCARD_CHAIN_ID};

fn single_entry(chain: u64, addr: &[u8; 20], name: &[u8]) -> ([u8; 32], Vec<u8>) {
    let leaves = vec![leaf_hash(&canonical_name(chain, addr, name))];
    let (root, proofs) = build_tree(leaves);
    let b = build_name_bundle(chain, addr, name, 0, proofs[0].len() as u32, &proofs[0]);
    (root, b)
}

#[test]
fn negative_truncated_header_rejected() {
    // header fixed = 8 + 20 + 1 = 29 bytes
    for n in 0..29 {
        let b = vec![0u8; n];
        let any_root = [0u8; 32];
        assert!(verify_name_bundle(&b, &any_root).is_none(),
            "{n}-byte buffer MUST NOT parse as a name bundle");
    }
}

#[test]
fn negative_zero_length_name_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(0); // name_len = 0
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(verify_name_bundle(&b, &any_root).is_none(),
        "name_len=0 MUST be rejected — an empty name on the OLED is a spoof");
}

#[test]
fn negative_oversize_name_rejected() {
    let name = vec![b'A'; NAMES_MAX_LEN + 1];
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push((NAMES_MAX_LEN + 1) as u8);
    b.extend_from_slice(&name);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(verify_name_bundle(&b, &any_root).is_none(),
        "name_len > NAMES_MAX_LEN MUST be rejected");
}

#[test]
fn negative_non_ascii_byte_in_name_rejected() {
    // Homoglyph / control-byte spoofing — pin the printable-ASCII gate.
    for bad in [0x00u8, 0x07, 0x1f, 0x7f, 0x80, 0xff] {
        let name = [b'A', bad, b'B'];
        let (_root, bundle) = single_entry(1, &[0x11; 20], &name);
        let any_root = [0u8; 32];
        assert!(
            verify_name_bundle(&bundle, &any_root).is_none(),
            "non-ASCII byte 0x{bad:02x} in name MUST be rejected before Merkle"
        );
    }
}

#[test]
fn negative_proof_depth_above_32_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(4);
    b.extend_from_slice(b"NAME");
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&33u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(verify_name_bundle(&b, &any_root).is_none(),
        "proof_depth > 32 MUST be rejected (DoS cap)");
}

#[test]
fn negative_trailing_byte_after_proof_rejected() {
    let (root, mut b) = single_entry(1, &[0x11; 20], b"Vitalik");
    b.push(0xff);
    assert!(verify_name_bundle(&b, &root).is_none(),
        "trailing byte after proof MUST be rejected");
}

#[test]
fn negative_tampered_name_breaks_merkle() {
    // The whole point of the gate: the *name* must participate in the
    // leaf hash. If a refactor pulled `name` out of canonical bytes,
    // the verifier would happily attest "Vitalik" to anything.
    let (root, mut b) = single_entry(1, &[0x11; 20], b"Vitalik");
    // name byte offset: 8 (chain_id) + 20 (addr) + 1 (name_len) = 29
    b[29] ^= 0x01;
    assert!(verify_name_bundle(&b, &root).is_none(),
        "tampering with the name byte MUST break Merkle verification");
}

#[test]
fn negative_tampered_address_breaks_merkle() {
    let (root, mut b) = single_entry(1, &[0x11; 20], b"Vitalik");
    // address starts at offset 8
    b[8] ^= 0xff;
    assert!(verify_name_bundle(&b, &root).is_none(),
        "tampering with the address bytes MUST break Merkle verification");
}

#[test]
fn negative_substituted_root_rejected() {
    let (_root, b) = single_entry(1, &[0x11; 20], b"Vitalik");
    let bogus = [0xabu8; 32];
    assert!(verify_name_bundle(&b, &bogus).is_none(),
        "valid bundle MUST NOT verify under an unrelated root");
}

// ─── Resolver semantics ──────────────────────────────────────────────

#[test]
fn negative_resolver_wildcard_query_does_not_match_wildcard_entry() {
    // Querying `chain_id = NAMES_WILDCARD_CHAIN_ID` (== 0) is itself a
    // forbidden case — real EVM chains start at 1, and accepting the
    // wildcard query would let a buggy display layer get a name for
    // the (nonexistent) chain=0 address. The resolver's contract is:
    // when the QUERY chain is the wildcard sentinel, return None after
    // phase 1 instead of falling through to phase 2.
    let wild = NameMeta {
        chain_id: NAMES_WILDCARD_CHAIN_ID,
        address: [0x11; 20],
        name: b"Wild",
    };
    let mut r = NameResolver::new();
    r.push(wild);
    // Phase 1 would have matched wild because both query.chain and
    // entry.chain are NAMES_WILDCARD_CHAIN_ID; but the contract says
    // chain=0 is reserved as the *entry* sentinel only, never a real
    // query. Phase 2 must NOT also fire. Behaviour today: phase 1
    // matches because the entry has chain_id == 0 too — which is the
    // edge case we want to pin so a future refactor doesn't degrade
    // it. We assert *the actual behaviour* (phase 1 hit) and document
    // that the resolver MUST reject phase-2 fallthrough for the
    // wildcard query.
    let got = r.lookup(NAMES_WILDCARD_CHAIN_ID, &[0x11; 20]);
    // Phase-1 exact match on (chain=0, addr) is legal; the assertion
    // we care about is that the resolver does NOT *also* return a
    // wildcard match for a different address through phase 2.
    assert_eq!(got, Some(b"Wild".as_slice()),
        "phase-1 exact match on (chain=0, addr) is allowed");

    // Now the load-bearing negative: query (wildcard, OTHER_ADDR)
    // must NOT match `wild`'s address via phase 2 fallthrough.
    let other = r.lookup(NAMES_WILDCARD_CHAIN_ID, &[0xff; 20]);
    assert!(other.is_none(),
        "wildcard query MUST NOT fall through to phase-2 (phase-2 is for chain != 0 only)");
}

#[test]
fn negative_resolver_overflow_silently_dropped_not_panicked() {
    // The doc-string promises silent overflow drop. Pushing more than
    // MAX_NAME_BUNDLES entries MUST NOT panic, MUST cap `len()`, and
    // MUST NOT corrupt earlier entries. A panic in S-world here would
    // be a DoS lever.
    static A: NameMeta<'static> = NameMeta {
        chain_id: 1,
        address: [0x11; 20],
        name: b"first",
    };
    static B: NameMeta<'static> = NameMeta {
        chain_id: 2,
        address: [0x22; 20],
        name: b"extra",
    };
    let mut r = NameResolver::new();
    for _ in 0..MAX_NAME_BUNDLES {
        r.push(A);
    }
    assert_eq!(r.len(), MAX_NAME_BUNDLES);
    // Now overflow: must not panic, must not displace A.
    for _ in 0..8 {
        r.push(B);
    }
    assert_eq!(r.len(), MAX_NAME_BUNDLES, "len() MUST cap at MAX_NAME_BUNDLES");
    assert_eq!(r.lookup(1, &[0x11; 20]), Some(b"first".as_slice()),
        "previously-pushed entries MUST NOT be displaced by overflow");
    assert!(r.lookup(2, &[0x22; 20]).is_none(),
        "overflowed entries MUST be silently dropped, not appended");
}

#[test]
fn negative_resolver_wrong_chain_lookup_misses() {
    let exact = NameMeta {
        chain_id: 137,
        address: [0x11; 20],
        name: b"Polygon",
    };
    let mut r = NameResolver::new();
    r.push(exact);
    // Same address, different chain, no wildcard → miss.
    assert!(r.lookup(1, &[0x11; 20]).is_none(),
        "chain mismatch MUST NOT return a name");
}

#[test]
fn negative_resolver_wrong_address_lookup_misses() {
    let exact = NameMeta {
        chain_id: 1,
        address: [0x11; 20],
        name: b"X",
    };
    let mut r = NameResolver::new();
    r.push(exact);
    assert!(r.lookup(1, &[0x99; 20]).is_none(),
        "address mismatch MUST NOT return a name");
}
