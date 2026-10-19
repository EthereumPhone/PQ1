//! Generation boundary for the synthetic nested-calldata parent/child pair.
//!
//! The feature controls only the explicit E2E catalogue route. The same test
//! binary is run with the feature off and on so production output is pinned
//! byte-for-byte across both configurations.

use std::path::PathBuf;

use dbgen::erc7730::{
    build_db_tolerant_with_erc20_capabilities, resolved_descriptor_sha256, Erc7730BuildResult,
};
#[cfg(feature = "nested-calldata-test-fixture")]
use pqsigner_erc7730::render::{
    calldata_policy::{
        TEST_NESTED_CALLDATA_CALLEE_PATH, TEST_NESTED_CALLDATA_FIELD_PATH,
        TEST_NESTED_CALLDATA_PARENT_CONTRACT, TEST_NESTED_CALLDATA_PARENT_SELECTOR,
    },
    params::{parse as parse_params, DYNAMIC_KIND_BYTES},
    policy::TerminalKind,
};
use pqsigner_erc7730::{
    ir::{Erc7730Ir, FormatOp},
    render::calldata_policy::{
        PRODUCTION_NESTED_CALLDATA_ENROLLMENTS, TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
    },
};
use sha2::{Digest, Sha256};

const PRODUCTION_ROOT_HEX: &str =
    "8c3dc4b2b1789106a1043aed08114b7827d56052dd920eb0dd6671a84db643e6";
const PRODUCTION_BLOB_SHA256_HEX: &str =
    "551d620f6a2cda7c2963070119ee221c2bc0f4196d4c2e85e0bb7c6cd57e17bf";
const PRODUCTION_BLOOM_SHA256_HEX: &str =
    "9269d7224a81364644f38cad7ad0be541597f253522921557a6c96a384ee904d";
const PRODUCTION_LEAF_COUNT: usize = 365;
#[cfg(feature = "nested-calldata-test-fixture")]
const CHILD_CONTRACT: [u8; 20] = [0x56; 20];
#[cfg(feature = "nested-calldata-test-fixture")]
const CHILD_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen sits below the workspace root")
        .to_path_buf()
}

fn build_production() -> Erc7730BuildResult {
    let root = workspace_root();
    let registry = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build exact production ERC20 capability corpus");
    build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &policy,
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production catalogue")
    .0
}

fn assert_no_calldata(result: &Erc7730BuildResult) {
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated production IR parses");
        for format in ir.format_iter() {
            for field in format.expect("production format parses").fields() {
                assert_ne!(
                    FormatOp::try_from(field.expect("production field parses").format_op),
                    Ok(FormatOp::Calldata),
                    "production catalogue admitted nested calldata from {}",
                    entry.source.display(),
                );
            }
        }
    }
}

#[test]
fn production_catalogue_is_byte_identical_with_fixture_feature_off_or_on() {
    assert!(PRODUCTION_NESTED_CALLDATA_ENROLLMENTS.is_empty());
    let result = build_production();
    assert_no_calldata(&result);
    assert_eq!(result.leaf_count, PRODUCTION_LEAF_COUNT);
    assert_eq!(hex::encode(result.root), PRODUCTION_ROOT_HEX);
    assert_eq!(
        hex::encode(Sha256::digest(&result.blob)),
        PRODUCTION_BLOB_SHA256_HEX
    );
    assert_eq!(
        hex::encode(Sha256::digest(result.known_calls_bloom)),
        PRODUCTION_BLOOM_SHA256_HEX
    );

    let root = workspace_root();
    assert_eq!(
        result.blob,
        std::fs::read(root.join("tools/companion-stub/erc7730_db.bin"))
            .expect("read checked-in production descriptor blob")
    );
    assert_eq!(
        result.known_calls_bloom.as_slice(),
        std::fs::read(root.join("secure/data/erc7730-known-calls.bloom"))
            .expect("read checked-in production known-call Bloom")
    );
}

#[test]
fn parent_policy_hash_matches_dbgen_resolved_jcs_authority() {
    let source = workspace_root().join("secure/data/erc7730-e2e/nested-calldata-parent.json");
    let recomputed = resolved_descriptor_sha256(&source, None)
        .expect("compute parent hash through dbgen resolved-JCS authority");
    assert_eq!(
        recomputed, TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
        "update only the exact test enrollment when the parent source intentionally changes"
    );
}

#[cfg(feature = "nested-calldata-test-fixture")]
fn build_e2e() -> Erc7730BuildResult {
    let root = workspace_root();
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20-e2e.json"))
        .expect("build exact E2E ERC20 capability corpus");
    dbgen::erc7730::build_e2e_db_with_policy_override_and_erc20_capabilities(
        &root.join("secure/data/erc7730-e2e"),
        &policy,
        false,
        None,
        &erc20.capabilities,
    )
    .expect("build explicitly authorized E2E catalogue")
}

#[cfg(feature = "nested-calldata-test-fixture")]
fn extract_proof(blob: &[u8], leaf_index: usize, proof_depth: usize) -> Vec<[u8; 32]> {
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let base = proofs_off + leaf_index * proof_depth * 32;
    (0..proof_depth)
        .map(|index| {
            let offset = base + index * 32;
            blob[offset..offset + 32].try_into().unwrap()
        })
        .collect()
}

#[cfg(feature = "nested-calldata-test-fixture")]
fn legacy_bundle(ir: &[u8], leaf_index: u32, proof: &[[u8; 32]]) -> Vec<u8> {
    let mut bundle = Vec::with_capacity(2 + ir.len() + 8 + proof.len() * 32);
    bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    bundle.extend_from_slice(ir);
    bundle.extend_from_slice(&leaf_index.to_be_bytes());
    bundle.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    for sibling in proof {
        bundle.extend_from_slice(sibling);
    }
    bundle
}

#[cfg(feature = "nested-calldata-test-fixture")]
fn proof_set(outer: &[u8], child: &[u8]) -> Vec<u8> {
    use pqsigner_erc7730::proof_set::{
        ERC7730_PROOF_SET_COUNT, ERC7730_PROOF_SET_MAGIC, ERC7730_PROOF_SET_VERSION,
    };

    let mut payload = Vec::with_capacity(8 + outer.len() + child.len());
    payload.extend_from_slice(&ERC7730_PROOF_SET_MAGIC.to_be_bytes());
    payload.push(ERC7730_PROOF_SET_VERSION);
    payload.push(ERC7730_PROOF_SET_COUNT as u8);
    for bundle in [outer, child] {
        payload.extend_from_slice(&(bundle.len() as u16).to_be_bytes());
        payload.extend_from_slice(bundle);
    }
    payload
}

#[cfg(feature = "nested-calldata-test-fixture")]
fn entry_for<'a>(
    result: &'a Erc7730BuildResult,
    contract: &[u8; 20],
) -> &'a dbgen::erc7730::Emitted {
    result
        .entries
        .iter()
        .find(|entry| entry.chain_id == 31_337 && entry.contract == *contract)
        .expect("exact synthetic deployment is present")
}

#[cfg(feature = "nested-calldata-test-fixture")]
#[test]
fn e2e_pair_has_one_exact_parent_calldata_and_verifies_as_a_proof_set() {
    use pqsigner_erc7730::{
        binding::cross_check_contract, proof_set::verify_erc7730_proof_set_with_leaf_count,
    };

    let result = build_e2e();
    let parent = entry_for(&result, &TEST_NESTED_CALLDATA_PARENT_CONTRACT);
    let child = entry_for(&result, &CHILD_CONTRACT);
    assert_eq!(parent.descriptor_hash, TEST_NESTED_CALLDATA_DESCRIPTOR_HASH);

    let mut calldata_fields = 0usize;
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated E2E IR parses");
        for format in ir.format_iter() {
            let format = format.expect("E2E format parses");
            for (ordinal, field) in format.fields().enumerate() {
                let field = field.expect("E2E field parses");
                if FormatOp::try_from(field.format_op) == Ok(FormatOp::Calldata) {
                    calldata_fields += 1;
                    assert_eq!(entry.contract, TEST_NESTED_CALLDATA_PARENT_CONTRACT);
                    assert_eq!(format.selector, TEST_NESTED_CALLDATA_PARENT_SELECTOR);
                    assert_eq!(ordinal, 1);
                    assert_eq!(
                        ir.path_bytes(field.path_off).expect("parent field path"),
                        TEST_NESTED_CALLDATA_FIELD_PATH
                    );
                    let params = parse_params(&ir, field.param_off).expect("parent field params");
                    assert_eq!(
                        params.nested_callee,
                        Some(&TEST_NESTED_CALLDATA_CALLEE_PATH)
                    );
                    assert_eq!(params.dynamic_kind, Some(DYNAMIC_KIND_BYTES));
                    assert_eq!(params.terminal_kind, Some(TerminalKind::DynamicBytes));
                }
            }
        }
    }
    assert_eq!(
        calldata_fields, 1,
        "E2E catalogue must have one parent calldata field"
    );

    let child_ir = Erc7730Ir::parse(&child.ir_bytes).expect("child IR parses");
    let child_format = child_ir
        .find_format_by_selector(&CHILD_SELECTOR)
        .expect("child format table parses")
        .expect("child transfer selector is present");
    assert!(child_format.fields().all(|field| {
        FormatOp::try_from(field.expect("child field parses").format_op) != Ok(FormatOp::Calldata)
    }));

    let depth = u32::from_le_bytes(result.blob[24..28].try_into().unwrap()) as usize;
    let parent_proof = extract_proof(&result.blob, parent.leaf_index, depth);
    let child_proof = extract_proof(&result.blob, child.leaf_index, depth);
    let parent_bundle = legacy_bundle(&parent.ir_bytes, parent.leaf_index as u32, &parent_proof);
    let child_bundle = legacy_bundle(&child.ir_bytes, child.leaf_index as u32, &child_proof);
    let payload = proof_set(&parent_bundle, &child_bundle);
    let verified =
        verify_erc7730_proof_set_with_leaf_count(&payload, &result.root, result.leaf_count)
            .expect("actual generated parent/child pair verifies as one proof set");
    assert_eq!(verified.outer.leaf_index as usize, parent.leaf_index);
    let verified_child = verified.child.expect("distinct child proof is retained");
    assert_eq!(verified_child.leaf_index as usize, child.leaf_index);
    cross_check_contract(
        &verified.outer.descriptor.ir,
        31_337,
        &TEST_NESTED_CALLDATA_PARENT_CONTRACT,
    )
    .expect("parent deployment binding");
    cross_check_contract(&verified_child.descriptor.ir, 31_337, &CHILD_CONTRACT)
        .expect("child deployment binding");
}
