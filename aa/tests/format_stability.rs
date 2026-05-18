//! Frozen wire-format & KDF-tag stability tests.
//!
//! Everything in this file pins a value that the on-chain verifier or
//! a deployed bundler will look at byte-for-byte. A test failing here
//! means a refactor changed something that is *intentionally not
//! changeable* — see CLAUDE.md "Wire formats (frozen — on-chain
//! verifier depends on them)" and "No casual KDF tag changes".

use pqsigner_aa::eip1271::{
    EIP712_DOMAIN_TYPEHASH, NAME_HASH, PERSONAL_SIGN_TYPEHASH, VERSION_HASH,
};
use pqsigner_aa::userop::{
    ENTRY_POINT_V06, EXECUTE_BATCH_SELECTOR, EXECUTE_SELECTOR, KECCAK_EMPTY, SHA256_EMPTY,
};
use pqsigner_proto::{
    EIP6492_BLOB_LEN, EIP6492_FACTORY_CALLDATA_LEN, EIP6492_FACTORY_CALLDATA_PADDED,
    EIP6492_INNER_WRAPPER_LEN, EIP6492_MAGIC, MAX_BATCH_TXS, MAX_TX_LEN, USEROP_HEADER_LEN,
};
use sha3::{Digest, Keccak256};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// EIP-712 typehashes — derived from a fixed canonical Solidity string.
// Anyone who renames "PQSmartWallet" → e.g. "PQ Smart Wallet" silently
// breaks every off-chain signature.
// ---------------------------------------------------------------------------

#[test]
fn stability_name_hash_is_keccak_of_pqsmartwallet() {
    // *NEVER* change the literal "PQSmartWallet" — the wallet's
    // EIP-712 domain `name` field is baked into the on-chain
    // `_domainNameAndVersion()`.
    assert_eq!(NAME_HASH, keccak(b"PQSmartWallet"));
}

#[test]
fn stability_version_hash_is_keccak_of_1() {
    assert_eq!(VERSION_HASH, keccak(b"1"));
}

#[test]
fn stability_personal_sign_typehash_matches_solady() {
    // Solady's `_PERSONAL_SIGN_TYPEHASH` is locked at
    // `keccak256("PersonalSign(bytes prefixed)")`.
    assert_eq!(PERSONAL_SIGN_TYPEHASH, keccak(b"PersonalSign(bytes prefixed)"));
}

#[test]
fn stability_eip712_domain_typehash_matches_standard() {
    assert_eq!(
        EIP712_DOMAIN_TYPEHASH,
        keccak(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ),
    );
}

// ---------------------------------------------------------------------------
// Hash constants (used as defaults inside the on-chain verifier path).
// ---------------------------------------------------------------------------

#[test]
fn stability_sha256_empty_constant() {
    // Used inline by the on-chain `sphincsDigest` when initCode /
    // paymasterAndData are absent.
    use sha2::{Digest as _, Sha256};
    let canonical: [u8; 32] = Sha256::digest(b"").into();
    assert_eq!(SHA256_EMPTY, canonical);
}

#[test]
fn stability_keccak_empty_constant() {
    assert_eq!(KECCAK_EMPTY, keccak(b""));
}

// ---------------------------------------------------------------------------
// EntryPoint v0.6 address & selectors. Invariant #6: bumping the
// EntryPoint would shift the CREATE2 init-code hash and break
// cross-chain wallet-address stability.
// ---------------------------------------------------------------------------

#[test]
fn stability_entry_point_v06_address() {
    // 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 — the canonical
    // v0.6 singleton.
    assert_eq!(
        ENTRY_POINT_V06,
        [
            0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E,
            0x57, 0x8a, 0x02, 0x6d, 0x27, 0x89,
        ],
    );
}

#[test]
fn stability_execute_selector_matches_signature() {
    // bytes4(keccak256(
    //   "executeWithOffchainCount(uint256,uint256,address,uint256,bytes)"
    // )) = 0x14443c57.
    let sig = b"executeWithOffchainCount(uint256,uint256,address,uint256,bytes)";
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&keccak(sig)[..4]);
    assert_eq!(EXECUTE_SELECTOR, sel);
    assert_eq!(EXECUTE_SELECTOR, [0x14, 0x44, 0x3c, 0x57]);
}

#[test]
fn stability_execute_batch_selector_matches_signature() {
    let sig = b"executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])";
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&keccak(sig)[..4]);
    assert_eq!(EXECUTE_BATCH_SELECTOR, sel);
    assert_eq!(EXECUTE_BATCH_SELECTOR, [0x7a, 0x38, 0x99, 0x33]);
}

// ---------------------------------------------------------------------------
// ERC-6492 — magic suffix + blob layout. Universal verifiers compare
// against these byte ranges.
// ---------------------------------------------------------------------------

#[test]
fn stability_eip6492_magic_is_repeating_6492() {
    assert_eq!(EIP6492_MAGIC.len(), 32);
    for chunk in EIP6492_MAGIC.chunks(2) {
        assert_eq!(chunk, [0x64, 0x92]);
    }
}

#[test]
fn stability_eip6492_blob_is_8608_bytes() {
    // Bumping this is an on-chain breaking change. Pin it.
    assert_eq!(EIP6492_BLOB_LEN, 8608);
    assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4260);
    assert_eq!(EIP6492_FACTORY_CALLDATA_PADDED, 4288);
    assert_eq!(EIP6492_INNER_WRAPPER_LEN, 4128);
    // Internal layout consistency: head(96) + fc-len(32) + fc(padded) +
    // inner-len(32) + inner + magic(32) = total.
    assert_eq!(
        EIP6492_BLOB_LEN,
        96 + 32 + EIP6492_FACTORY_CALLDATA_PADDED + 32 + EIP6492_INNER_WRAPPER_LEN + 32,
    );
}

// ---------------------------------------------------------------------------
// Wire-format frozen sizes.
// ---------------------------------------------------------------------------

#[test]
fn stability_userop_header_is_305_bytes() {
    // From CLAUDE.md "Unified sign input":
    //   1 has_bundle + 20 sender + 20 entry_point + 8 chain_id +
    //   6*32 gas + 2*32 hashes = 305.
    assert_eq!(USEROP_HEADER_LEN, 305);
    assert_eq!(
        USEROP_HEADER_LEN,
        1 + 20 + 20 + 8 + 6 * 32 + 2 * 32,
        "USEROP_HEADER_LEN must equal the on-wire field sum",
    );
}

#[test]
fn stability_max_tx_len_and_batch_caps() {
    assert_eq!(MAX_TX_LEN, 4096);
    assert_eq!(MAX_BATCH_TXS, 4);
}
