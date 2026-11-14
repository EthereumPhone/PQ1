//! The ERC-7730 constant-token gate (`check_token_amount_constants`) and the
//! compile-time collection that feeds it (`Emitted::token_amount_constants`).
//!
//! Every effective `tokenAmount` literal `(chain, token)` in an emitted leaf
//! must be an ERC-20 DB row, a native sentinel, or a reviewed exception.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use dbgen::erc20::build_db as build_erc20_db;
use dbgen::erc7730::{
    build_db_tolerant_with_erc20_capabilities, check_token_amount_constants, load_policy,
    try_compile_one, Emitted, TokenConstantException,
};
use serde_json::{json, Value};

const POLICY_DEV: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

const TOKEN: &str = "0x00000000000000000000000000000000000000a1";
const OTHER: &str = "0x00000000000000000000000000000000000000b2";
const NATIVE_EEEE: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let ordinal = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dbgen_token_constant_gate_{name}_{}_{ordinal}",
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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn addr(s: &str) -> [u8; 20] {
    hex::decode(s.trim_start_matches("0x"))
        .expect("hex")
        .try_into()
        .expect("20 bytes")
}

/// One contract descriptor, chain 1, with a single `tokenAmount` field whose
/// `params` are `params`.
fn compile_token_amount(name: &str, params: Value) -> Vec<Emitted> {
    let descriptor = json!({
        "context": {
            "$id": "TokenConstantGate",
            "contract": {
                "deployments": [
                    { "chainId": 1, "address": "0x0000000000000000000000000000000000000c01" }
                ]
            }
        },
        "metadata": {
            "owner": "Synthetic Test Fixture",
            "info": { "url": "https://example.invalid" },
            "contractName": "TokenConstantGate"
        },
        "display": {
            "formats": {
                "deposit(address to,uint256 amount)": {
                    "intent": "Deposit",
                    "fields": [
                        { "path": "to", "format": "raw", "label": "To", "visible": "always" },
                        {
                            "path": "amount",
                            "format": "tokenAmount",
                            "label": "Amount",
                            "visible": "always",
                            "params": params
                        }
                    ]
                }
            }
        }
    });
    let dir = TempDir::new(name);
    let path = dir.path().join("calldata-token-constant.json");
    fs::write(&path, serde_json::to_vec_pretty(&descriptor).unwrap()).unwrap();
    let policy = load_policy(&dir.path().join("policy.toml")).unwrap();
    try_compile_one(&path, &policy, Some(dir.path())).expect("synthetic descriptor compiles")
}

fn only_constants(entries: &[Emitted]) -> Vec<[u8; 20]> {
    assert_eq!(entries.len(), 1, "one deployment, one leaf");
    entries[0].token_amount_constants.clone()
}

#[test]
fn effective_literal_token_is_recorded() {
    let entries = compile_token_amount("literal", json!({ "token": TOKEN }));
    assert_eq!(only_constants(&entries), vec![addr(TOKEN)]);
}

#[test]
fn token_path_is_not_a_constant() {
    let entries = compile_token_amount("path", json!({ "tokenPath": "to" }));
    assert!(only_constants(&entries).is_empty());
}

#[test]
fn native_sentinels_are_not_recorded() {
    let entries = compile_token_amount("eeee", json!({ "token": NATIVE_EEEE }));
    assert!(only_constants(&entries).is_empty());
    let entries = compile_token_amount(
        "declared_native",
        json!({ "token": OTHER, "nativeCurrencyAddress": [OTHER] }),
    );
    assert!(only_constants(&entries).is_empty());
}

fn emitted(chain_id: u64, tokens: &[&str]) -> Emitted {
    Emitted {
        source: PathBuf::from(
            "/abs/checkout/secure/data/erc7730-registry/registry/x/calldata-x.json",
        ),
        descriptor_id: "x".into(),
        descriptor_hash: [0; 32],
        erc8176_hash: [0; 32],
        chain_id,
        contract: [0x0c; 20],
        context_kind: 1,
        primary_type_hash: [0; 32],
        ir_bytes: Vec::new(),
        leaf_index: 0,
        token_amount_constants: tokens.iter().map(|t| addr(t)).collect(),
    }
}

fn erc20_capabilities(rows: &[(u64, &str)]) -> dbgen::erc20::Erc20Capabilities {
    let json = serde_json::to_string(
        &rows
            .iter()
            .map(|(chain_id, address)| {
                json!({
                    "chain_id": chain_id, "address": address,
                    "name": "Token", "symbol": "TKN", "decimals": 18
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let dir = TempDir::new("erc20");
    let path = dir.path().join("erc20.json");
    fs::write(&path, json).unwrap();
    build_erc20_db(&path).expect("build ERC-20 DB").capabilities
}

#[test]
fn gate_accepts_db_tokens_and_used_exceptions() {
    let erc20 = erc20_capabilities(&[(1, TOKEN)]);
    let entries = [emitted(1, &[TOKEN]), emitted(10, &[OTHER])];
    let exceptions = [TokenConstantException {
        chain_id: 10,
        token: OTHER,
        reason: "reviewed",
    }];
    check_token_amount_constants(&entries, &erc20, &exceptions).expect("gate passes");
}

#[test]
fn gate_rejects_unknown_token_naming_chain_token_and_relative_source() {
    // TOKEN is in the DB on chain 1 only: the same address on chain 10 is a
    // different (chain, token) and must be rejected.
    let erc20 = erc20_capabilities(&[(1, TOKEN)]);
    let err = check_token_amount_constants(&[emitted(10, &[TOKEN])], &erc20, &[])
        .expect_err("chain-bound membership");
    assert!(err.contains(&format!("chain_id=10 token={TOKEN}")), "{err}");
    assert!(
        err.contains("in secure/data/erc7730-registry/registry/x/calldata-x.json"),
        "{err}"
    );
    assert!(!err.contains("/abs/checkout"), "no absolute paths: {err}");
}

#[test]
fn gate_rejects_stale_and_malformed_exceptions() {
    let erc20 = erc20_capabilities(&[(1, TOKEN)]);
    let entries = [emitted(1, &[TOKEN])];

    let unused = [TokenConstantException {
        chain_id: 10,
        token: OTHER,
        reason: "r",
    }];
    let err = check_token_amount_constants(&entries, &erc20, &unused).expect_err("unused");
    assert!(err.contains("stale token-constant exception"), "{err}");

    let covered = [TokenConstantException {
        chain_id: 1,
        token: TOKEN,
        reason: "r",
    }];
    let err = check_token_amount_constants(&entries, &erc20, &covered).expect_err("covered");
    assert!(err.contains("now has this token"), "{err}");

    let no_reason = [TokenConstantException {
        chain_id: 10,
        token: OTHER,
        reason: " ",
    }];
    let err = check_token_amount_constants(&[emitted(10, &[OTHER])], &erc20, &no_reason)
        .expect_err("no reason");
    assert!(err.contains("has no reason"), "{err}");

    let dup = [
        TokenConstantException {
            chain_id: 10,
            token: OTHER,
            reason: "r",
        },
        TokenConstantException {
            chain_id: 10,
            token: OTHER,
            reason: "r",
        },
    ];
    let err = check_token_amount_constants(&[emitted(10, &[OTHER])], &erc20, &dup)
        .expect_err("duplicate");
    assert!(err.contains("duplicate"), "{err}");
}

/// The checked-in production catalogue passes the gate with exactly the
/// reviewed exception list, and the list is load-bearing.
#[test]
fn production_catalogue_passes_with_exactly_the_reviewed_exceptions() {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = build_erc20_db(&root.join("secure/data/erc20.json"))
        .expect("production ERC-20 DB satisfies the device rule");
    let (catalogue, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build curated registry");

    check_token_amount_constants(
        &catalogue.entries,
        &erc20.capabilities,
        dbgen::token_constant_exceptions::PRODUCTION,
    )
    .expect("production gate");

    // Non-vacuous: the gate sees the descriptor literals the DB rows were
    // added for (stCORE on Core, rUSDY on Ethereum)...
    let pinned = |chain_id: u64, token: &str| {
        catalogue
            .entries
            .iter()
            .any(|e| e.chain_id == chain_id && e.token_amount_constants.contains(&addr(token)))
    };
    assert!(pinned(1116, "0xb3a8f0f0da9ffc65318aa39e55079796093029ad"));
    assert!(pinned(1, "0xaf37c1167910ebc994e266949387d2c7c326b879"));
    // ...and without the exception list it fails on the excepted token.
    let err = check_token_amount_constants(&catalogue.entries, &erc20.capabilities, &[])
        .expect_err("exceptions are load-bearing");
    assert!(
        err.contains("chain_id=1 token=0x0000206329b97db379d5e1bf586bbdb969c63274"),
        "{err}"
    );
}
