use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use dbgen::erc7730::{build_db_tolerant, load_policy, try_compile_one, Emitted, SkipReport};
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const POLICY_DEV: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

const APPROVE_TYPE: &str = "approve(address spender,uint256 amount)";
const WATCH_TYPE: &str = "watch_tg_invmru_2f69f1b(address first,address second)";

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let ordinal = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dbgen_eip712_curation_{name}_{}_{ordinal}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temporary test directory");
        fs::write(path.join("policy.toml"), POLICY_DEV).expect("write test policy");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write_json(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).expect("write test descriptor");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn address(tail: u8) -> String {
    format!("0x{:040x}", tail)
}

fn eip712_descriptor(deployments: &[(u64, u8)], pqsigner: Option<Value>) -> Value {
    let deployments = deployments
        .iter()
        .map(|(chain_id, tail)| {
            json!({
                "chainId": chain_id,
                "address": address(*tail),
            })
        })
        .collect::<Vec<_>>();
    let mut descriptor = json!({
        "context": {
            "eip712": {
                "domain": {
                    "name": "EIP712 curation test",
                    "version": "1"
                },
                "deployments": deployments
            }
        },
        "metadata": {
            "owner": "PQSigner",
            "contractName": "EIP712 curation test"
        },
        "display": {
            "formats": {
                APPROVE_TYPE: {
                    "intent": "Approve",
                    "fields": [
                        {
                            "path": "spender",
                            "format": "addressName",
                            "label": "Spender",
                            "visible": "always"
                        },
                        {
                            "path": "amount",
                            "format": "raw",
                            "label": "Amount",
                            "visible": "always"
                        }
                    ]
                },
                WATCH_TYPE: {
                    "intent": "Watch",
                    "fields": [
                        {
                            "path": "first",
                            "format": "addressName",
                            "label": "First",
                            "visible": "always"
                        },
                        {
                            "path": "second",
                            "format": "addressName",
                            "label": "Second",
                            "visible": "always"
                        }
                    ]
                }
            }
        }
    });
    if let Some(pqsigner) = pqsigner {
        descriptor["_pqsigner"] = pqsigner;
    }
    descriptor
}

fn compile_one(name: &str, descriptor: &Value) -> Result<Vec<Emitted>, String> {
    let dir = TempDir::new(name);
    let path = dir.write_json("eip712-test.json", descriptor);
    let policy = load_policy(&dir.path().join("policy.toml")).unwrap();
    try_compile_one(&path, &policy, Some(dir.path()))
}

fn only_format_hash(entry: &Emitted) -> [u8; 32] {
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("emitted IR parses");
    let formats = ir
        .format_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("emitted formats parse");
    assert_eq!(formats.len(), 1, "curated deployment has one format");
    formats[0].type_hash
}

fn find_skip<'a>(skips: &'a [SkipReport], file_name: &str, fragment: &str) -> &'a SkipReport {
    skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str()) == Some(file_name)
                && skip.reason.contains(fragment)
        })
        .unwrap_or_else(|| {
            panic!(
                "missing `{fragment}` receipt for {file_name}: {:?}",
                skips.iter().map(|skip| &skip.reason).collect::<Vec<_>>()
            )
        })
}

#[test]
fn eip712_deployment_formats_admit_exact_types_and_skip_omitted_deployments() {
    // These source signatures collide after calldata canonicalization. EIP-712
    // dispatch authenticates the full 32-byte type hash, so selector collision
    // logic must not constrain this exact typed-data admission.
    let approve_selector = keccak256(b"approve(address,uint256)");
    let watch_selector = keccak256(b"watch_tg_invmru_2f69f1b(address,address)");
    assert_eq!(&approve_selector[..4], &watch_selector[..4]);

    let descriptor = eip712_descriptor(
        &[(1, 1), (10, 2), (137, 3)],
        Some(json!({
            "deploymentFormats": [
                {
                    "chainId": 1,
                    "address": address(1),
                    "formats": [APPROVE_TYPE]
                },
                {
                    "chainId": 10,
                    "address": address(2),
                    "formats": [WATCH_TYPE]
                }
            ]
        })),
    );
    let dir = TempDir::new("exact_admission");
    dir.write_json("eip712-scoped.json", &descriptor);
    let (result, skips) = build_db_tolerant(
        dir.path(),
        &dir.path().join("policy.toml"),
        Some(dir.path()),
    )
    .expect("exact EIP-712 deployment/type curation builds");

    assert_eq!(result.leaf_count, 2);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.known_call_count, 0);
    let expected = [
        (1, 1, keccak256(APPROVE_TYPE.as_bytes())),
        (10, 2, keccak256(WATCH_TYPE.as_bytes())),
    ];
    for (entry, (chain_id, address_tail, type_hash)) in result.entries.iter().zip(expected) {
        assert_eq!(entry.chain_id, chain_id);
        assert_eq!(entry.contract[..19], [0; 19]);
        assert_eq!(entry.contract[19], address_tail);
        assert_eq!(entry.primary_type_hash, type_hash);
        assert_eq!(only_format_hash(entry), type_hash);
    }
    assert_ne!(
        result.entries[0].primary_type_hash, result.entries[1].primary_type_hash,
        "full EIP-712 hashes, not four-byte selectors, distinguish formats"
    );
    find_skip(&skips, "eip712-scoped.json", "chain_id=137");
}

#[test]
fn eip712_refusal_only_complete_quarantine_emits_zero_leaves() {
    let quarantined = eip712_descriptor(
        &[(1, 1), (10, 2)],
        Some(json!({
            "deploymentFormats": [],
            "refusalOnlyFormats": [APPROVE_TYPE, WATCH_TYPE]
        })),
    );
    let entries =
        compile_one("complete_quarantine_one", &quarantined).expect("quarantine is valid");
    assert!(
        entries.is_empty(),
        "a complete EIP-712 quarantine must emit no empty IR leaves"
    );

    let dir = TempDir::new("complete_quarantine_catalogue");
    dir.write_json("eip712-quarantined.json", &quarantined);
    let safe = eip712_descriptor(&[(42161, 4)], None);
    dir.write_json("eip712-safe.json", &safe);
    let (result, skips) = build_db_tolerant(
        dir.path(),
        &dir.path().join("policy.toml"),
        Some(dir.path()),
    )
    .expect("zero-leaf quarantine coexists with a safe descriptor");
    assert_eq!(result.leaf_count, 1);
    assert_eq!(result.entries[0].chain_id, 42161);
    find_skip(&skips, "eip712-quarantined.json", "zero EIP-712 formats");
}

#[test]
fn eip712_curation_rejects_unknown_duplicate_overlap_and_malformed_shapes() {
    let base = eip712_descriptor(
        &[(1, 1)],
        Some(json!({
            "deploymentFormats": [{
                "chainId": 1,
                "address": address(1),
                "formats": [APPROVE_TYPE]
            }]
        })),
    );
    let mut cases: Vec<(&str, Value, &str)> = Vec::new();

    let mut empty = base.clone();
    empty["_pqsigner"] = json!({ "deploymentFormats": [] });
    cases.push((
        "empty",
        empty,
        "must not be empty unless refusalOnlyFormats or thresholdOmissions is non-empty",
    ));

    let mut outside = base.clone();
    outside["_pqsigner"]["deploymentFormats"][0]["chainId"] = json!(10);
    cases.push(("outside", outside, "is not a declared EIP-712 deployment"));

    let mut malformed_address = base.clone();
    malformed_address["_pqsigner"]["deploymentFormats"][0]["address"] = json!("0x1234");
    cases.push(("malformed_address", malformed_address, "address is invalid"));

    let mut empty_formats = base.clone();
    empty_formats["_pqsigner"]["deploymentFormats"][0]["formats"] = json!([]);
    cases.push(("empty_formats", empty_formats, "formats must not be empty"));

    let mut unknown_format = base.clone();
    unknown_format["_pqsigner"]["deploymentFormats"][0]["formats"] =
        json!(["Unknown(uint256 value)"]);
    cases.push(("unknown_format", unknown_format, "names unknown format"));

    let mut normalized_format = base.clone();
    normalized_format["_pqsigner"]["deploymentFormats"][0]["formats"] =
        json!(["approve(address spender, uint256 amount)"]);
    cases.push((
        "normalized_format",
        normalized_format,
        "names unknown format",
    ));

    let mut duplicate_format = base.clone();
    duplicate_format["_pqsigner"]["deploymentFormats"][0]["formats"] =
        json!([APPROVE_TYPE, APPROVE_TYPE]);
    cases.push(("duplicate_format", duplicate_format, "formats duplicates"));

    let mut duplicate_deployment = base.clone();
    let duplicate = duplicate_deployment["_pqsigner"]["deploymentFormats"][0].clone();
    duplicate_deployment["_pqsigner"]["deploymentFormats"] = json!([duplicate.clone(), duplicate]);
    cases.push((
        "duplicate_deployment",
        duplicate_deployment,
        "deploymentFormats duplicates",
    ));

    let mut normalized_duplicate = base.clone();
    normalized_duplicate["context"]["eip712"]["deployments"][0]["address"] =
        json!("0x00000000000000000000000000000000000000aB");
    normalized_duplicate["_pqsigner"]["deploymentFormats"][0]["address"] =
        json!("0x00000000000000000000000000000000000000AB");
    let mut duplicate = normalized_duplicate["_pqsigner"]["deploymentFormats"][0].clone();
    duplicate["address"] = json!("0x00000000000000000000000000000000000000ab");
    normalized_duplicate["_pqsigner"]["deploymentFormats"] = json!([
        normalized_duplicate["_pqsigner"]["deploymentFormats"][0].clone(),
        duplicate
    ]);
    cases.push((
        "normalized_duplicate",
        normalized_duplicate,
        "deploymentFormats duplicates",
    ));

    let mut unknown_refusal = base.clone();
    unknown_refusal["_pqsigner"]["refusalOnlyFormats"] = json!(["Unknown(uint256 value)"]);
    cases.push(("unknown_refusal", unknown_refusal, "names unknown format"));

    let mut duplicate_refusal = base.clone();
    duplicate_refusal["_pqsigner"]["refusalOnlyFormats"] = json!([WATCH_TYPE, WATCH_TYPE]);
    cases.push((
        "duplicate_refusal",
        duplicate_refusal,
        "refusalOnlyFormats duplicates",
    ));

    let mut overlap = base.clone();
    overlap["_pqsigner"]["refusalOnlyFormats"] = json!([APPROVE_TYPE]);
    cases.push(("overlap", overlap, "overlaps deploymentFormats"));

    let mut malformed_formats = base.clone();
    malformed_formats["_pqsigner"]["deploymentFormats"][0]["formats"] = json!("not-an-array");
    cases.push(("malformed_formats", malformed_formats, "invalid type"));

    for (name, descriptor, expected) in cases {
        let error =
            compile_one(name, &descriptor).expect_err("invalid EIP-712 curation must fail closed");
        assert!(
            error.contains(expected),
            "{name}: expected `{expected}` in `{error}`"
        );
    }
}

#[test]
fn contract_context_curation_output_remains_byte_stable() {
    let descriptor = json!({
        "_pqsigner": {
            "deploymentFormats": [
                {
                    "chainId": 1,
                    "address": address(1),
                    "formats": ["transfer(address to,uint256 amount)"]
                },
                {
                    "chainId": 10,
                    "address": address(2),
                    "formats": ["approve(address spender,uint256 amount)"]
                }
            ],
            "refusalOnlyFormats": ["burn(uint256 amount)"]
        },
        "context": {
            "contract": {
                "deployments": [
                    { "chainId": 1, "address": address(1) },
                    { "chainId": 10, "address": address(2) },
                    { "chainId": 137, "address": address(3) }
                ]
            }
        },
        "metadata": {
            "owner": "Contract stability",
            "contractName": "Contract stability"
        },
        "display": {
            "formats": {
                "transfer(address to,uint256 amount)": {
                    "intent": "Transfer",
                    "fields": [
                        {
                            "path": "to",
                            "format": "addressName",
                            "label": "To",
                            "visible": "always"
                        },
                        {
                            "path": "amount",
                            "format": "raw",
                            "label": "Amount",
                            "visible": "always"
                        }
                    ]
                },
                "approve(address spender,uint256 amount)": {
                    "intent": "Approve",
                    "fields": [
                        {
                            "path": "spender",
                            "format": "addressName",
                            "label": "Spender",
                            "visible": "always"
                        },
                        {
                            "path": "amount",
                            "format": "raw",
                            "label": "Amount",
                            "visible": "always"
                        }
                    ]
                },
                "burn(uint256 amount)": {
                    "intent": "Burn",
                    "fields": [{
                        "path": "amount",
                        "format": "raw",
                        "label": "Amount",
                        "visible": "always"
                    }]
                }
            }
        }
    });
    let entries =
        compile_one("contract_stability", &descriptor).expect("contract curation compiles");
    assert_eq!(entries.len(), 2);

    let mut exact_output = Vec::new();
    for entry in entries {
        exact_output.extend_from_slice(&entry.descriptor_hash);
        exact_output.extend_from_slice(&entry.erc8176_hash);
        exact_output.extend_from_slice(&entry.chain_id.to_be_bytes());
        exact_output.extend_from_slice(&entry.contract);
        exact_output.push(entry.context_kind);
        exact_output.extend_from_slice(&entry.primary_type_hash);
        exact_output.extend_from_slice(&(entry.ir_bytes.len() as u32).to_be_bytes());
        exact_output.extend_from_slice(&entry.ir_bytes);
    }
    assert_eq!(
        hex::encode(Sha256::digest(&exact_output)),
        "5f00b5c18aaf513d8d69c6f7e50aaab375f3855de4afd1583db145284c60234b",
        "contract-context curation output changed byte-for-byte"
    );
}
