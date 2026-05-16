//! Negative: `tx::erc20::bundle::verify_erc20_bundle` adversarial inputs.
//!
//! The bundle is the funnel through which **all** ERC-20 trusted-display
//! bytes pass. Each field — `name_len`, `symbol_len`, `proof_depth`,
//! the printable-ASCII gate, the trailing-byte rejection — is a barrier
//! against a different attacker capability. We pin each.

mod common;

use common::{build_erc20_bundle, build_tree, canonical_erc20, leaf_hash};
use pqsigner_tx::erc20::bundle::verify_erc20_bundle;

fn single_entry_fixture(
    chain: u64,
    contract: &[u8; 20],
    decimals: u8,
    name: &[u8],
    sym: &[u8],
) -> ([u8; 32], Vec<u8>) {
    let leaves = vec![leaf_hash(&canonical_erc20(chain, contract, decimals, name, sym))];
    let (root, proofs) = build_tree(leaves);
    let bundle = build_erc20_bundle(
        chain,
        contract,
        decimals,
        name,
        sym,
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    (root, bundle)
}

#[test]
fn negative_truncated_header_rejected() {
    // Any length below header-fixed (8+20+1+1 = 30) must reject without
    // panicking — pins index-safe slicing.
    for n in 0..30 {
        let b = vec![0u8; n];
        let any_root = [0u8; 32];
        assert!(
            verify_erc20_bundle(&b, &any_root).is_none(),
            "{n}-byte buffer MUST NOT parse as an ERC20 bundle"
        );
    }
}

#[test]
fn negative_zero_length_name_rejected() {
    // name_len=0 is a spoofing foothold: a row with an empty name would
    // render as a single-line "(empty) — USDC" on the OLED. Forbidden.
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(6); // decimals
    b.push(0); // name_len = 0  ← attack
    b.push(4); // symbol_len
    b.extend_from_slice(b"USDC");
    b.extend_from_slice(&0u32.to_le_bytes()); // leaf_index
    b.extend_from_slice(&0u32.to_le_bytes()); // proof_depth
    let any_root = [0u8; 32];
    assert!(
        verify_erc20_bundle(&b, &any_root).is_none(),
        "name_len=0 MUST be rejected — see MAX_DISPLAY_FIELD guard"
    );
}

#[test]
fn negative_oversize_name_rejected() {
    // name_len = 65 violates the 64-byte OLED cap.
    let name = vec![b'A'; 65];
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(6);
    b.push(65u8);
    b.extend_from_slice(&name);
    b.push(4);
    b.extend_from_slice(b"USDC");
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(verify_erc20_bundle(&b, &any_root).is_none(),
        "name_len>64 (OLED display cap) MUST be rejected");
}

#[test]
fn negative_zero_length_symbol_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(6);
    b.push(3);
    b.extend_from_slice(b"USD");
    b.push(0); // symbol_len = 0
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(
        verify_erc20_bundle(&b, &any_root).is_none(),
        "symbol_len=0 MUST be rejected"
    );
}

#[test]
fn negative_oversize_symbol_rejected() {
    let sym = vec![b'X'; 65];
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(6);
    b.push(3);
    b.extend_from_slice(b"USD");
    b.push(65u8);
    b.extend_from_slice(&sym);
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let any_root = [0u8; 32];
    assert!(verify_erc20_bundle(&b, &any_root).is_none(),
        "symbol_len>64 MUST be rejected");
}

#[test]
fn negative_non_ascii_byte_in_name_rejected() {
    // Spoofing foothold: a "USDC" entry with a homoglyph or zero-width
    // joiner would let an attacker make their custom token look like
    // the curated USDC. The OLED can't render it anyway.
    for bad_byte in [0x00u8, 0x07, 0x1f, 0x7f, 0x80, 0xff] {
        let name = [b'U', b'S', bad_byte, b'C'];
        let (_root, mut bundle) = single_entry_fixture(1, &[0x11; 20], 6, &name, b"USDC");
        // Even with a valid proof, the ASCII gate must fail first.
        let any_root = [0u8; 32];
        assert!(
            verify_erc20_bundle(&bundle, &any_root).is_none(),
            "non-ASCII byte 0x{bad_byte:02x} in name MUST be rejected"
        );
        // Use the bundle to silence unused warnings even if early-exit.
        bundle.clear();
    }
}

#[test]
fn negative_non_ascii_byte_in_symbol_rejected() {
    let sym = [b'U', 0x07, b'D', b'C'];
    let (_root, bundle) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", &sym);
    let any_root = [0u8; 32];
    assert!(
        verify_erc20_bundle(&bundle, &any_root).is_none(),
        "non-ASCII byte in symbol MUST be rejected before Merkle check"
    );
}

#[test]
fn negative_proof_depth_above_32_rejected() {
    // depth > 32 means a hostile NS forces the verifier through an
    // unbounded SHA-256 chain. The 32-cap is the DoS guard.
    let mut b = Vec::new();
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&[0x11u8; 20]);
    b.push(6);
    b.push(4);
    b.extend_from_slice(b"NAME");
    b.push(3);
    b.extend_from_slice(b"SYM");
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&33u32.to_le_bytes()); // ← attack
    let any_root = [0u8; 32];
    assert!(verify_erc20_bundle(&b, &any_root).is_none(),
        "proof_depth > 32 MUST be rejected (DoS cap)");
}

#[test]
fn negative_trailing_byte_after_proof_rejected() {
    let (root, mut b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    b.push(0xff);
    assert!(
        verify_erc20_bundle(&b, &root).is_none(),
        "any trailing byte after the proof MUST be rejected"
    );
}

#[test]
fn negative_truncated_proof_rejected() {
    let (root, mut b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    // Singleton tree → depth=0 → no proof, so chop the last "proof byte"
    // = the proof_depth itself. Test multi-entry trees too:
    let leaves = vec![
        leaf_hash(&canonical_erc20(1, &[0x11; 20], 6, b"USDC", b"USD")),
        leaf_hash(&canonical_erc20(1, &[0x22; 20], 6, b"WETH", b"WETH")),
    ];
    let (root2, proofs) = build_tree(leaves);
    let _ = root;
    let mut b2 = build_erc20_bundle(
        1,
        &[0x11; 20],
        6,
        b"USDC",
        b"USD",
        0,
        proofs[0].len() as u32,
        &proofs[0],
    );
    b2.pop();
    assert!(
        verify_erc20_bundle(&b2, &root2).is_none(),
        "truncated proof MUST be rejected"
    );
    // Also drop the trailing byte from `b` (the singleton case).
    b.pop();
    let any_root = [0u8; 32];
    assert!(verify_erc20_bundle(&b, &any_root).is_none());
}

#[test]
fn negative_tampered_chain_id_breaks_merkle() {
    // Build a real bundle, then flip a chain_id byte. The leaf hash
    // changes, so the Merkle walk lands on a different root.
    let (root, mut b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    b[0] ^= 0x01;
    assert!(verify_erc20_bundle(&b, &root).is_none(),
        "tampered chain_id MUST break Merkle verification");
}

#[test]
fn negative_tampered_contract_breaks_merkle() {
    let (root, mut b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    // contract starts at offset 8
    b[8] ^= 0xff;
    assert!(verify_erc20_bundle(&b, &root).is_none(),
        "tampered contract address MUST break Merkle verification");
}

#[test]
fn negative_tampered_decimals_breaks_merkle() {
    let (root, mut b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    // decimals at offset 28
    b[28] ^= 0xff;
    assert!(verify_erc20_bundle(&b, &root).is_none(),
        "tampered decimals MUST break Merkle verification — \
         silent off-by-N renders the wrong amount on the OLED");
}

#[test]
fn negative_substituted_root_rejected() {
    let (_root, b) = single_entry_fixture(1, &[0x11; 20], 6, b"USDC", b"USD");
    let bogus = [0xabu8; 32];
    assert!(verify_erc20_bundle(&b, &bogus).is_none(),
        "a valid bundle must NOT verify under an unrelated root");
}
