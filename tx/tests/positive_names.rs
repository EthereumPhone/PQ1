//! Positive: `tx::names` bundle verifier + resolver happy paths.

mod common;

use common::{build_name_bundle, build_tree, canonical_name, leaf_hash};
use pqsigner_tx::names::{verify_name_bundle, NameMeta, NameResolver, MAX_NAME_BUNDLES};
use sphincs_tz_shared::db_format::{NAMES_MAX_LEN, NAMES_WILDCARD_CHAIN_ID};

fn fixture() -> (
    [u8; 32],
    Vec<(u64, [u8; 20], &'static [u8])>,
    Vec<Vec<[u8; 32]>>,
) {
    let entries: Vec<(u64, [u8; 20], &[u8])> = vec![
        (1, [0x11; 20], b"Vitalik"),
        (1, [0x22; 20], b"Uniswap V3 Router"),
        (NAMES_WILDCARD_CHAIN_ID, [0x33; 20], b"Curated Wildcard"),
    ];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, a, n)| leaf_hash(&canonical_name(*c, a, n)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    (root, entries, proofs)
}

#[test]
fn positive_bundle_round_trip_all_entries() {
    let (root, entries, proofs) = fixture();
    for (i, (chain, addr, name)) in entries.iter().enumerate() {
        let b = build_name_bundle(
            *chain,
            addr,
            name,
            i as u32,
            proofs[i].len() as u32,
            &proofs[i],
        );
        let meta = verify_name_bundle(&b, &root).expect("must verify");
        assert_eq!(meta.chain_id, *chain);
        assert_eq!(&meta.address, addr);
        assert_eq!(meta.name, *name);
    }
}

#[test]
fn positive_name_at_max_len_accepted() {
    let max_name = vec![b'A'; NAMES_MAX_LEN];
    let entries = vec![(1u64, [0xaa; 20], max_name.as_slice())];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, a, n)| leaf_hash(&canonical_name(*c, a, n)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    let b = build_name_bundle(
        entries[0].0,
        &entries[0].1,
        entries[0].2,
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    let m = verify_name_bundle(&b, &root).expect("max-length name accepted");
    assert_eq!(m.name.len(), NAMES_MAX_LEN);
}

#[test]
fn positive_resolver_default_is_empty() {
    let r: NameResolver<'static> = NameResolver::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    assert!(r.lookup(1, &[0x11; 20]).is_none());
}

#[test]
fn positive_resolver_exact_match_wins_over_wildcard() {
    // Two entries — chain-specific must win over the chain=0 wildcard
    // even if the wildcard is added first.
    let wild = NameMeta {
        chain_id: NAMES_WILDCARD_CHAIN_ID,
        address: [0x11; 20],
        name: b"WildcardName",
    };
    let exact = NameMeta {
        chain_id: 137,
        address: [0x11; 20],
        name: b"PolygonName",
    };
    let mut r = NameResolver::new();
    r.push(wild);
    r.push(exact);

    assert_eq!(r.lookup(137, &[0x11; 20]), Some(b"PolygonName".as_slice()),
        "exact (chain, addr) match MUST be returned even when a wildcard exists");
}

#[test]
fn positive_resolver_wildcard_falls_through_for_chain_specific_miss() {
    let wild = NameMeta {
        chain_id: NAMES_WILDCARD_CHAIN_ID,
        address: [0x11; 20],
        name: b"WildcardName",
    };
    let mut r = NameResolver::new();
    r.push(wild);

    // Query for chain=137; no exact entry, falls through to wildcard.
    assert_eq!(
        r.lookup(137, &[0x11; 20]),
        Some(b"WildcardName".as_slice()),
        "chain=0 wildcard MUST be matched when no exact entry exists"
    );
}

#[test]
fn positive_resolver_len_tracks_pushes() {
    let mut r: NameResolver<'static> = NameResolver::new();
    static A: NameMeta<'static> = NameMeta {
        chain_id: 1,
        address: [0u8; 20],
        name: b"a",
    };
    for n in 0..MAX_NAME_BUNDLES {
        assert_eq!(r.len(), n);
        r.push(A);
    }
    assert_eq!(r.len(), MAX_NAME_BUNDLES);
    assert!(!r.is_empty());
}
