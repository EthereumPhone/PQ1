//! Positive: `tx::erc20::bundle::verify_erc20_bundle` happy paths.

mod common;

use common::{build_erc20_bundle, build_tree, canonical_erc20, leaf_hash};
use pqsigner_tx::erc20::bundle::{verify_erc20_bundle, MAX_ERC20_BUNDLE_LEN};

fn three_real_entries() -> (
    [u8; 32],
    Vec<(u64, [u8; 20], u8, &'static [u8], &'static [u8])>,
    Vec<Vec<[u8; 32]>>,
) {
    let entries: Vec<(u64, [u8; 20], u8, &[u8], &[u8])> = vec![
        (1, [0x11u8; 20], 6, b"USD Coin", b"USDC"),
        (1, [0x22u8; 20], 18, b"Wrapped Ether", b"WETH"),
        (137, [0x33u8; 20], 6, b"Polygon USDC", b"USDC.e"),
    ];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, k, d, n, s)| leaf_hash(&canonical_erc20(*c, k, *d, n, s)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    (root, entries, proofs)
}

#[test]
fn positive_curated_bundle_round_trip() {
    let (root, entries, proofs) = three_real_entries();
    for (i, (chain, contract, decimals, name, sym)) in entries.iter().enumerate() {
        let bundle = build_erc20_bundle(
            *chain,
            contract,
            *decimals,
            name,
            sym,
            i as u32,
            proofs[i].len() as u32,
            &proofs[i],
        );
        assert!(
            bundle.len() <= MAX_ERC20_BUNDLE_LEN,
            "test fixture bundle must fit MAX_ERC20_BUNDLE_LEN"
        );
        let meta = verify_erc20_bundle(&bundle, &root).expect("bundle must verify");
        assert_eq!(meta.chain_id, *chain);
        assert_eq!(&meta.contract, contract);
        assert_eq!(meta.decimals, *decimals);
        assert_eq!(meta.name, *name);
        assert_eq!(meta.symbol, *sym);
    }
}

#[test]
fn positive_name_len_at_64_byte_cap_accepted() {
    let name = [b'A'; 64];
    let entries = vec![(1u64, [0xaau8; 20], 6u8, &name[..], &b"X"[..])];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, k, d, n, s)| leaf_hash(&canonical_erc20(*c, k, *d, n, s)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    let bundle = build_erc20_bundle(
        entries[0].0,
        &entries[0].1,
        entries[0].2,
        &name,
        b"X",
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    let meta = verify_erc20_bundle(&bundle, &root).expect("64-byte name accepted");
    assert_eq!(meta.name.len(), 64);
}

#[test]
fn positive_symbol_len_at_64_byte_cap_accepted() {
    let symbol = [b'X'; 64];
    let entries = vec![(1u64, [0xaau8; 20], 6u8, &b"name"[..], &symbol[..])];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, k, d, n, s)| leaf_hash(&canonical_erc20(*c, k, *d, n, s)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    let bundle = build_erc20_bundle(
        entries[0].0,
        &entries[0].1,
        entries[0].2,
        b"name",
        &symbol,
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    let meta = verify_erc20_bundle(&bundle, &root).expect("64-byte symbol accepted");
    assert_eq!(meta.symbol.len(), 64);
}

#[test]
fn positive_max_bundle_len_constant_is_above_realistic_size() {
    // Sanity-pin the constant — every shipped firmware sizes the
    // gateway copy buffer off of this. 1.1 KB upper bound was the
    // documented intent.
    assert!(MAX_ERC20_BUNDLE_LEN >= 1024);
    assert!(MAX_ERC20_BUNDLE_LEN <= 8 * 1024,
        "if this balloons past 8 KB the secure-side stack budget needs an audit");
}

#[test]
fn positive_special_printable_ascii_accepted() {
    // OLED renders 0x20..=0x7e — accepting symbol="USDC.e" (with a dot)
    // is what makes Polygon-shaped curation possible.
    let entries = vec![(1u64, [0xaau8; 20], 6u8, &b"NAME"[..], &b"USDC.e"[..])];
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|(c, k, d, n, s)| leaf_hash(&canonical_erc20(*c, k, *d, n, s)))
        .collect();
    let (root, proofs) = build_tree(leaves);
    let bundle = build_erc20_bundle(
        entries[0].0,
        &entries[0].1,
        entries[0].2,
        b"NAME",
        b"USDC.e",
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    assert!(verify_erc20_bundle(&bundle, &root).is_some());
}
