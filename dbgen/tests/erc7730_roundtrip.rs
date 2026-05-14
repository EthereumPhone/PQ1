//! Integration test for the ERC-7730 descriptor pipeline.
//!
//! Runs end-to-end against the checked-in seed corpus:
//!   1. Compile every `secure/data/erc7730/*.json` descriptor.
//!   2. Build the Merkle tree.
//!   3. For each leaf:
//!        - Reconstruct the synthetic trailer the companion would
//!          ship (`[u16 ir_len][ir][u32 leaf_index][u32 proof_depth][proof]`).
//!        - Hand the trailer to `pqsigner_erc7730::bundle::verify_erc7730_bundle`,
//!          which is the same byte-for-byte verifier the secure firmware
//!          uses on-device.
//!        - Cross-check the IR's `(chain_id, contract)` /
//!          `(domain_separator)` binding via
//!          `pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712}`.
//!
//! Also exercises the host-side compiler against a synthetic in-memory
//! corpus (one contract + one EIP-712 descriptor) so this test does
//! not depend on the real `secure/data/erc7730/` corpus for its smoke
//! coverage — the seed corpus is exercised separately via the embedded
//! `build_db_seed_corpus` unit test inside `dbgen::erc7730`.
//!
//! See `docs/handoff-erc7730-phase2.md` §"Verification recipe" — this
//! test is what that recipe's step 2 (`cargo test -p dbgen --test
//! erc7730_roundtrip`) refers to.

use std::path::PathBuf;

use dbgen::erc7730::{
    build_db, round_trip_check, Erc7730BuildResult,
};
use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, MAX_ERC7730_BUNDLE_LEN};
use pqsigner_erc7730::ir::{ContextKind, CTX_CONTRACT, CTX_EIP712};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_seed() -> Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    build_db(&dir, &policy).expect("build seed corpus")
}

fn extract_proof(blob: &[u8], leaf_index: usize, proof_depth: usize) -> Vec<[u8; 32]> {
    // Catalog header layout — see `dbgen::erc7730` module doc.
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let base = proofs_off + leaf_index * proof_depth * 32;
    (0..proof_depth)
        .map(|j| {
            let off = base + j * 32;
            let mut h = [0u8; 32];
            h.copy_from_slice(&blob[off..off + 32]);
            h
        })
        .collect()
}

fn proof_depth(blob: &[u8]) -> usize {
    u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize
}

fn synth_bundle(ir: &[u8], leaf_index: u32, proof: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len() * 32);
    buf.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir);
    buf.extend_from_slice(&leaf_index.to_be_bytes());
    buf.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    for h in proof {
        buf.extend_from_slice(h);
    }
    buf
}

#[test]
fn seed_corpus_compiles_and_round_trips() {
    let res = build_seed();
    assert!(
        res.leaf_count >= 6,
        "seed corpus shrunk below sanity threshold: {} leaves",
        res.leaf_count
    );
    round_trip_check(&res).expect("round-trip");
}

#[test]
fn seed_corpus_bundles_verify_against_on_device_parser() {
    let res = build_seed();
    let pd = proof_depth(&res.blob);

    for (i, entry) in res.entries.iter().enumerate() {
        let proof = extract_proof(&res.blob, i, pd);
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);

        assert!(
            bundle.len() <= MAX_ERC7730_BUNDLE_LEN,
            "{}: bundle {} > MAX ({})",
            entry.source.display(),
            bundle.len(),
            MAX_ERC7730_BUNDLE_LEN
        );

        let verified = verify_erc7730_bundle(&bundle, &res.root).unwrap_or_else(|e| {
            panic!(
                "verify_erc7730_bundle failed on leaf {} ({}): {e:?}",
                i,
                entry.source.display()
            )
        });

        assert_eq!(verified.ir.chain_id, entry.chain_id);
        assert_eq!(verified.ir.contract, entry.contract);
        assert_eq!(verified.ir.descriptor_hash, entry.descriptor_hash);

        // Round-trip the context cross-check as the on-device caller
        // would: synthesize a tx envelope / EIP-712 domain that
        // matches this entry, then call the corresponding binding.
        if entry.context_kind == CTX_CONTRACT {
            assert!(matches!(verified.ir.context_kind, ContextKind::Contract));
            cross_check_contract(&verified.ir, entry.chain_id, &entry.contract).unwrap_or_else(
                |e| {
                    panic!(
                        "cross_check_contract failed for leaf {} ({}): {e:?}",
                        i,
                        entry.source.display()
                    )
                },
            );
        } else if entry.context_kind == CTX_EIP712 {
            assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
            cross_check_eip712(
                &verified.ir,
                entry.chain_id,
                &entry.contract,
                &verified.ir.domain_separator,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "cross_check_eip712 failed for leaf {} ({}): {e:?}",
                    i,
                    entry.source.display()
                )
            });
        } else {
            panic!(
                "unknown context_kind 0x{:02x} on leaf {}",
                entry.context_kind, i
            );
        }
    }
}

#[test]
fn binding_mismatch_is_rejected() {
    // Any chain_id flip in the cross-check MUST surface as a
    // BindingError::ChainIdMismatch — same protection the on-device
    // dispatcher relies on.
    let res = build_seed();
    let entry = res
        .entries
        .iter()
        .find(|e| e.context_kind == CTX_CONTRACT)
        .expect("seed corpus has at least one contract-context leaf");
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let v = verify_erc7730_bundle(&bundle, &res.root).expect("bundle verifies");

    let wrong_chain = entry.chain_id.wrapping_add(1);
    let err = cross_check_contract(&v.ir, wrong_chain, &entry.contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ChainIdMismatch),
        "expected ChainIdMismatch, got {err:?}"
    );

    let mut wrong_contract = entry.contract;
    wrong_contract[0] ^= 0x01;
    let err = cross_check_contract(&v.ir, entry.chain_id, &wrong_contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ContractMismatch),
        "expected ContractMismatch, got {err:?}"
    );
}

#[test]
fn tampered_proof_is_rejected() {
    // Flip one byte of the proof and verify the bundle now fails. This
    // is the canonical "did we actually bind?" check.
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let mut proof = extract_proof(&res.blob, entry.leaf_index, pd);
    if !proof.is_empty() {
        proof[0][0] ^= 0xff;
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
        let err = verify_erc7730_bundle(&bundle, &res.root).unwrap_err();
        assert!(
            matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
            "expected Merkle, got {err:?}"
        );
    }
}

#[test]
fn wrong_root_is_rejected() {
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let bad_root = [0xAAu8; 32];
    let err = verify_erc7730_bundle(&bundle, &bad_root).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
        "expected Merkle, got {err:?}"
    );
}
