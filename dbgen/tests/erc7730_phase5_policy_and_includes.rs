//! Phase 5 items 1 + 2 — production policy gate + `includes` resolution.
//!
//! Item 1 (production policy gate): exercises `build_db_with_policy_override`.
//!   - Default (force_production = false): existing seed corpus builds clean.
//!   - Override (force_production = true): fails closed without an independently
//!     pinned authenticated ERC-8176 snapshot; embedded attester names never count.
//!
//! Item 2 (`includes` resolution): exercises the local-filesystem resolver
//! `dbgen::erc7730::compile_descriptor`'s new `registry_root` parameter.
//!   - Positive: relative include, registry-relative include, deep-merge.
//!   - Negative: include without `--registry-root`, escape attempt
//!     (`../../etc/passwd`), recursion depth cap.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use dbgen::erc7730::{
    build_db, build_db_tolerant, build_db_with_policy_override, load_policy, round_trip_check,
    try_compile_one, CatalogueProvenance,
};
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;

fn expect_err<T>(res: Result<T, String>, msg: &str) -> String {
    match res {
        Ok(_) => panic!("{msg}"),
        Err(e) => e,
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// ─────────────────────────────────────────────────────────────────────
// Item 1: production policy gate
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dev_policy_accepts_unattested_seed_corpus() {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let result = build_db_with_policy_override(&dir, &policy, false, None)
        .expect("dev policy must accept the seed corpus");
    assert_eq!(result.provenance, CatalogueProvenance::DevUnattested);
    assert!(
        result
            .review_text
            .contains("# Provenance: dev-unattested\n"),
        "review artifact must carry machine-readable dev provenance"
    );
}

#[test]
fn production_policy_rejects_unattested_seed_corpus() {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let err = expect_err(
        build_db_with_policy_override(&dir, &policy, true, None),
        "production policy MUST reject without pinned ERC-8176 evidence",
    );
    assert!(
        err.contains("missing an independently pinned [erc8176_snapshot]")
            && err.contains("obsolete descriptor-embedded `attestations`"),
        "unexpected production-rejection message: {err}"
    );
}

#[test]
fn dbgen_cli_rejects_production_before_generation_starts() {
    let output = Command::new(env!("CARGO_BIN_EXE_dbgen"))
        .args(["--policy", "production"])
        .output()
        .expect("run dbgen production-policy refusal");
    assert!(!output.status.success(), "production request must fail");
    assert!(
        output.stdout.is_empty(),
        "refusal must occur before dbgen starts or writes other catalogue artifacts: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("canonical ERC-7730 policy has no independently pinned ERC-8176 snapshot")
            && stderr.contains("Refusing before writing any generated artifact"),
        "unexpected production refusal: {stderr}"
    );
}

#[test]
fn build_db_default_matches_dev_override() {
    // Sanity: `build_db` (no override) and `build_db_with_policy_override(..,
    // false)` produce byte-identical output. Guards against accidental
    // semantic drift between the two entry points.
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let a = build_db(&dir, &policy).expect("default build");
    let b =
        build_db_with_policy_override(&dir, &policy, false, None).expect("override(false) build");
    assert_eq!(a.blob, b.blob, "blob diverged");
    assert_eq!(a.root, b.root, "root diverged");
    assert_eq!(a.review_text, b.review_text, "review receipt diverged");
    assert_eq!(a.known_calls_bloom, b.known_calls_bloom, "Bloom diverged");
    assert_eq!(a.known_calls, b.known_calls, "known-call set diverged");
    assert_eq!(
        a.known_call_set_hash, b.known_call_set_hash,
        "known-call set digest diverged"
    );
    assert_eq!(a.provenance, b.provenance, "provenance diverged");
}

#[test]
fn production_policy_never_accepts_legacy_embedded_attesters() {
    let dir = make_tempdir("legacy_attesters_not_production");
    fs::write(
        dir.join("policy.toml"),
        concat!(
            "allow_unattested_dev_descriptors = true\n",
            "min_attesters = 2\n",
            "trusted_attesters = [\n",
            "  \"eip155:1:0x0000000000000000000000000000000000000001\",\n",
            "  \"eip155:1:0x0000000000000000000000000000000000000002\",\n",
            "]\n",
        ),
    )
    .unwrap();
    let mut descriptor: serde_json::Value =
        serde_json::from_str(&transfer_descriptor("To", "Amount")).unwrap();
    descriptor["attestations"] = serde_json::json!([
        { "attester": "eip155:1:0x0000000000000000000000000000000000000001" },
        { "attester": "eip155:1:0x0000000000000000000000000000000000000002" }
    ]);
    fs::write(
        dir.join("descriptor.json"),
        serde_json::to_vec_pretty(&descriptor).unwrap(),
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(&dir, &dir.join("policy.toml"), true, None),
        "legacy embedded attesters must never manufacture production provenance",
    );
    assert!(
        err.contains("missing an independently pinned [erc8176_snapshot]")
            && err.contains("obsolete descriptor-embedded `attestations`"),
        "rejection must name the obsolete evidence model: {err}"
    );
}

fn assert_descriptor_key_rejected(name: &str, key_path: &[&str]) {
    let dir = make_tempdir(name);
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let mut descriptor: serde_json::Value =
        serde_json::from_str(&transfer_descriptor("To", "Amount")).unwrap();
    let mut cursor = &mut descriptor;
    for key in &key_path[..key_path.len() - 1] {
        cursor = cursor
            .get_mut(*key)
            .unwrap_or_else(|| panic!("missing fixture object at `{key}`"));
    }
    let rejected_key = key_path[key_path.len() - 1];
    cursor
        .as_object_mut()
        .expect("fixture key parent must be an object")
        .insert(
            rejected_key.to_string(),
            serde_json::json!({ "enabled": true }),
        );
    fs::write(
        dir.join("descriptor.json"),
        serde_json::to_vec_pretty(&descriptor).unwrap(),
    )
    .unwrap();

    let err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "unmodelled descriptor/context key must fail closed",
    );
    assert!(
        (err.contains("unknown field") || err.contains("unsupported"))
            && err.contains(rejected_key),
        "unexpected fail-closed error for `{rejected_key}`: {err}"
    );
}

#[test]
fn unknown_top_level_descriptor_key_is_rejected() {
    assert_descriptor_key_rejected("unknown_descriptor_key", &["futureTrustSemantics"]);
}

#[test]
fn unsupported_contract_proxy_context_is_rejected() {
    assert_descriptor_key_rejected(
        "unsupported_proxy_context",
        &["context", "contract", "proxy"],
    );
}

#[test]
fn unsupported_contract_state_refs_context_is_rejected() {
    assert_descriptor_key_rejected(
        "unsupported_state_refs_context",
        &["context", "contract", "stateRefs"],
    );
}

#[test]
fn unsupported_eip712_schemas_context_is_rejected() {
    let dir = make_tempdir("unsupported_eip712_schemas");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("descriptor.json"),
        r#"{
  "context": {
    "eip712": {
      "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }],
      "domain": { "name": "Schema Test", "version": "1" },
      "schemas": [{ "primaryType": "Order", "types": {} }]
    }
  },
  "metadata": { "owner": "Schema Test", "contractName": "SchemaTest" },
  "display": {
    "formats": {
      "Order(uint256 amount)": {
        "intent": "Order",
        "fields": [{ "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }]
      }
    }
  }
}"#,
    )
    .unwrap();

    let err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "unsupported EIP-712 schemas must fail closed",
    );
    assert!(
        err.contains("context.eip712.schemas") && err.contains("unsupported"),
        "unexpected schemas rejection: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// review 2.2: duplicate-leaf precedence (byte-identical dedup vs conflict)
// ─────────────────────────────────────────────────────────────────────

const POLICY_DEV_2: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

/// A minimal compilable calldata descriptor for `transfer(address,uint256)` at
/// chain 1 / contract 0x…01, parameterised by the two field labels (so two
/// instances with different labels compile to DIFFERENT IR for the SAME leaf
/// key).
fn transfer_descriptor(to_label: &str, amt_label: &str) -> String {
    format!(
        r#"{{
  "context": {{ "contract": {{ "deployments": [{{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }}] }} }},
  "metadata": {{ "owner": "Dup Test", "contractName": "DupTest" }},
  "display": {{ "formats": {{ "transfer(address to, uint256 amount)": {{
      "intent": "Send",
      "fields": [
        {{ "path": "to", "format": "addressName", "label": "{to_label}", "visible": "always" }},
        {{ "path": "amount", "format": "raw", "label": "{amt_label}", "visible": "always" }}
      ] }} }} }}
}}"#
    )
}

#[test]
fn dup_leaf_byte_identical_is_deduped_not_error() {
    // Same (chain, contract) in two differently-named files with IDENTICAL
    // content → identical IR → benign dedup: build succeeds, one leaf, and the
    // drop is recorded as a byte-identical skip (review 2.2).
    let dir = make_tempdir("dup_identical");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let d = transfer_descriptor("To", "Amount");
    fs::write(dir.join("calldata-a.json"), &d).unwrap();
    fs::write(dir.join("calldata-b.json"), &d).unwrap();

    let (res, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("byte-identical dup must dedupe cleanly, not error");
    assert_eq!(res.leaf_count, 1, "identical dup must collapse to one leaf");
    assert!(
        skips.iter().any(|s| s.reason.contains("byte-identical")),
        "the dropped identical dup must be recorded as byte-identical: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn per_deployment_partial_format_drop_is_reported_once() {
    let dir = make_tempdir("deployment_drop_dedup");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-two-deployments.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" },
    { "chainId": 10, "address": "0x0000000000000000000000000000000000000002" }
  ] } },
  "metadata": { "owner": "Drop Test", "contractName": "DropTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "swap(uint256[] amounts)": {
      "intent": "Swap",
      "fields": [
        { "path": "amounts[0]", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("one safe format must survive on both deployments");
    assert_eq!(result.leaf_count, 2);
    let duplicate_drop_count = skips
        .iter()
        .filter(|skip| {
            skip.reason.contains("PARTIAL FORMAT DROP")
                && skip.reason.contains("swap(uint256[] amounts)")
        })
        .count();
    assert_eq!(
        duplicate_drop_count, 1,
        "per-deployment compilation must not duplicate one source-format receipt"
    );
}

#[test]
fn pqsigner_deployment_formats_only_narrows_leaves_not_known_calls() {
    let dir = make_tempdir("deployment_format_allowlist");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-scoped.json"),
        r#"{
  "_pqsigner": { "deploymentFormats": [
    {
      "chainId": 1,
      "address": "0x0000000000000000000000000000000000000001",
      "formats": ["transfer(address to,uint256 amount)"]
    },
    {
      "chainId": 56,
      "address": "0x0000000000000000000000000000000000000002",
      "formats": ["approve(address spender,uint256 amount)"]
    }
  ] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" },
    { "chainId": 56, "address": "0x0000000000000000000000000000000000000002" },
    { "chainId": 137, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Scope Test", "contractName": "ScopeTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("a restrictive deployment/format admission must build");
    assert_eq!(
        result.leaf_count, 2,
        "only the two admitted deployments emit"
    );
    round_trip_check(&result).expect("narrowed catalogue round-trips");

    let expected_leaves = [
        (1, 1, [0xa9, 0x05, 0x9c, 0xbb]),
        (56, 2, [0x09, 0x5e, 0xa7, 0xb3]),
    ];
    for (entry, (chain_id, address_tail, selector)) in result.entries.iter().zip(expected_leaves) {
        assert_eq!(entry.chain_id, chain_id);
        assert_eq!(entry.contract[..19], [0; 19]);
        assert_eq!(entry.contract[19], address_tail);
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("admitted IR parses");
        let formats = ir
            .format_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("admitted formats parse");
        assert_eq!(formats.len(), 1);
        assert_eq!(formats[0].selector, selector);
    }

    assert_eq!(
        result.known_call_count, 6,
        "both declared selectors on all three source deployments remain known"
    );
    for (chain_id, address_tail) in [(1, 1), (56, 2), (137, 3)] {
        let mut contract = [0u8; 20];
        contract[19] = address_tail;
        for selector in [[0xa9, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3]] {
            assert!(
                result.known_calls.contains(&(chain_id, contract, selector)),
                "missing exact known-call tuple chain={chain_id} selector=0x{}",
                hex::encode(selector)
            );
            assert!(known_call_may_contain(
                &result.known_calls_bloom,
                chain_id,
                &contract,
                &selector
            ));
        }
    }
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("PARTIAL FORMAT DROP")
            && skip
                .reason
                .contains("approve(address spender,uint256 amount)")
            && skip.reason.contains("chain_id=1")
            && skip.reason.contains("deploymentFormats allowlist")
            && !skip.reason.contains("underlying compiler rejection")
    }));
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("PARTIAL FORMAT DROP")
            && skip.reason.contains("transfer(address to,uint256 amount)")
            && skip.reason.contains("chain_id=56")
            && skip.reason.contains("deploymentFormats allowlist")
            && !skip.reason.contains("underlying compiler rejection")
    }));
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("chain_id=137") && skip.reason.contains("deploymentFormats allowlist")
    }));

    let mut unscoped: serde_json::Value = serde_json::from_slice(
        &fs::read(dir.join("calldata-scoped.json")).expect("read scoped descriptor"),
    )
    .expect("parse scoped descriptor");
    unscoped
        .as_object_mut()
        .expect("descriptor object")
        .remove("_pqsigner");
    let unscoped_dir = make_tempdir("deployment_format_hash_binding");
    fs::write(unscoped_dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let unscoped_path = unscoped_dir.join("calldata-unscoped.json");
    fs::write(
        &unscoped_path,
        serde_json::to_vec_pretty(&unscoped).unwrap(),
    )
    .unwrap();
    let policy = load_policy(&unscoped_dir.join("policy.toml")).unwrap();
    let unscoped_entries = try_compile_one(&unscoped_path, &policy, Some(&unscoped_dir))
        .expect("ordinary descriptor compiles");
    assert_eq!(unscoped_entries.len(), 3);
    for entry in &unscoped_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("ordinary IR parses");
        assert_eq!(ir.format_iter().count(), 2);
    }
    assert!(unscoped_entries
        .iter()
        .all(|entry| entry.descriptor_hash != result.entries[0].descriptor_hash));
    assert!(unscoped_entries
        .iter()
        .all(|entry| entry.erc8176_hash != result.entries[0].erc8176_hash));
}

#[test]
fn pqsigner_deployment_formats_preserves_isolated_underlying_rejection_diagnostic() {
    let dir = make_tempdir("deployment_format_underlying_rejection");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-scoped.json"),
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000001",
    "formats": ["transfer(address to,uint256 amount)"]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Diagnostic Test", "contractName": "DiagnosticTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "withdraw(address pool,uint256 amount)": {
      "intent": "Withdraw",
      "fields": [
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("the admitted safe sibling must compile");
    assert_eq!(result.leaf_count, 1);
    assert_eq!(
        result.known_call_count, 2,
        "the excluded selector remains exact-known"
    );
    let mut contract = [0u8; 20];
    contract[19] = 1;
    let withdraw_selector = {
        let hash = pqsigner_tx_core::hash::keccak256(b"withdraw(address,uint256)");
        [hash[0], hash[1], hash[2], hash[3]]
    };
    assert!(result
        .known_calls
        .contains(&(1, contract, withdraw_selector)));
    assert!(known_call_may_contain(
        &result.known_calls_bloom,
        1,
        &contract,
        &withdraw_selector
    ));
    assert!(skips.iter().any(|skip| {
        skip.reason
            .contains("withdraw(address pool,uint256 amount)")
            && skip.reason.contains("deploymentFormats allowlist")
            && skip.reason.contains("underlying compiler rejection")
            && skip.reason.contains("parameter #0 (`pool`)")
            && skip.reason.contains("audit H-3")
    }));

    let ir = Erc7730Ir::parse(&result.entries[0].ir_bytes).expect("admitted IR parses");
    let formats = ir
        .format_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("admitted formats parse");
    assert_eq!(formats.len(), 1);
    assert_eq!(
        formats[0].selector,
        [0xa9, 0x05, 0x9c, 0xbb],
        "diagnostic compilation must never add a survivor"
    );
}

#[test]
fn pqsigner_refusal_only_formats_are_hash_bound_and_stay_exact_known() {
    let dir = make_tempdir("refusal_only_formats");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-refusal-only.json"),
        r#"{
  "_pqsigner": {
    "refusalOnlyFormats": ["approve(address spender,uint256 amount)"]
  },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Refusal Test", "contractName": "RefusalTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    },
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("refusal-only marker must narrow the descriptor");
    assert_eq!(result.leaf_count, 1);
    let ir = Erc7730Ir::parse(&result.entries[0].ir_bytes).expect("narrowed IR parses");
    let formats = ir
        .format_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("narrowed formats parse");
    assert_eq!(formats.len(), 1);
    assert_eq!(formats[0].selector, [0xa9, 0x05, 0x9c, 0xbb]);

    let mut contract = [0u8; 20];
    contract[19] = 1;
    assert_eq!(result.known_call_count, 2);
    for selector in [[0xa9, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3]] {
        assert!(result.known_calls.contains(&(1, contract, selector)));
        assert!(known_call_may_contain(
            &result.known_calls_bloom,
            1,
            &contract,
            &selector
        ));
    }
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("PARTIAL FORMAT DROP")
            && skip
                .reason
                .contains("approve(address spender,uint256 amount)")
            && skip.reason.contains("refusalOnlyFormats marker")
    }));

    let mut unmarked: serde_json::Value = serde_json::from_slice(
        &fs::read(dir.join("calldata-refusal-only.json")).expect("read marked descriptor"),
    )
    .expect("parse marked descriptor");
    unmarked
        .as_object_mut()
        .expect("descriptor object")
        .remove("_pqsigner");
    let unmarked_dir = make_tempdir("refusal_only_hash_binding");
    fs::write(unmarked_dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let unmarked_path = unmarked_dir.join("calldata-unmarked.json");
    fs::write(
        &unmarked_path,
        serde_json::to_vec_pretty(&unmarked).unwrap(),
    )
    .unwrap();
    let policy = load_policy(&unmarked_dir.join("policy.toml")).unwrap();
    let unmarked_entries = try_compile_one(&unmarked_path, &policy, Some(&unmarked_dir))
        .expect("ordinary descriptor compiles");
    assert_eq!(unmarked_entries.len(), 1);
    assert_ne!(
        result.entries[0].descriptor_hash,
        unmarked_entries[0].descriptor_hash
    );
    assert_ne!(
        result.entries[0].erc8176_hash,
        unmarked_entries[0].erc8176_hash
    );
}

#[test]
fn pqsigner_refusal_only_format_cannot_hide_selector_collision() {
    let dir = make_tempdir("refusal_only_selector_collision");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-selector-collision.json"),
        r#"{
  "_pqsigner": {
    "refusalOnlyFormats": ["approve(address spender,uint256 amount)"]
  },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Collision", "contractName": "Collision" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "watch_tg_invmru_2f69f1b(address first,address second)": {
      "intent": "Collision",
      "fields": [
        { "path": "first", "format": "addressName", "label": "First" },
        { "path": "second", "format": "addressName", "label": "Second" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("selector-colliding refusal marker must remain a known hard refusal");
    assert_eq!(result.leaf_count, 1, "only the independent safe descriptor");
    let collision_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-selector-collision.json")
        })
        .expect("colliding refusal marker must carry a skip receipt");
    assert!(
        collision_skip.reason.contains("selector 0x095ea7b3")
            && collision_skip
                .reason
                .contains("collides with source formats")
            && collision_skip
                .reason
                .contains("selector-only runtime dispatch cannot authenticate"),
        "unexpected collision refusal: {}",
        collision_skip.reason
    );

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let selector = [0x09, 0x5e, 0xa7, 0xb3];
    assert!(result.known_calls.contains(&(1, contract, selector)));
    assert!(known_call_may_contain(
        &result.known_calls_bloom,
        1,
        &contract,
        &selector
    ));
}

#[test]
fn pqsigner_refusal_only_format_cannot_collide_across_descriptors() {
    let dir = make_tempdir("refusal_only_cross_descriptor_collision");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-refusal.json"),
        r#"{
  "_pqsigner": {
    "refusalOnlyFormats": ["approve(address spender,uint256 amount)"]
  },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Refusal", "contractName": "Refusal" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("calldata-collision.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Collision", "contractName": "Collision" },
  "display": { "formats": {
    "watch_tg_invmru_2f69f1b(address first,address second)": {
      "intent": "Collision",
      "fields": [
        { "path": "first", "format": "addressName", "label": "First" },
        { "path": "second", "format": "addressName", "label": "Second" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("catalogue-wide collision with a refusal marker must fail closed");
    assert_eq!(result.leaf_count, 1, "only the independent safe descriptor");
    let collision_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-collision.json")
                && skip
                    .reason
                    .contains("authenticated refusalOnlyFormats boundary")
        })
        .expect("clear-capable side of the collision must be skipped");
    assert!(
        collision_skip.reason.contains("collides catalogue-wide")
            && collision_skip.reason.contains("approve(address,uint256)")
            && collision_skip
                .reason
                .contains("selector-only runtime dispatch cannot authenticate"),
        "unexpected catalogue-wide collision refusal: {}",
        collision_skip.reason
    );
    assert!(skips.iter().any(|skip| {
        skip.source.file_name().and_then(|name| name.to_str()) == Some("calldata-refusal.json")
    }));

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let selector = [0x09, 0x5e, 0xa7, 0xb3];
    assert!(result.known_calls.contains(&(1, contract, selector)));
    assert!(known_call_may_contain(
        &result.known_calls_bloom,
        1,
        &contract,
        &selector
    ));
}

#[test]
fn pqsigner_refusal_only_formats_reject_unknown_duplicate_and_overlap() {
    let base: serde_json::Value = serde_json::from_str(
        r#"{
  "_pqsigner": {
    "refusalOnlyFormats": ["approve(address spender,uint256 amount)"]
  },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Refusal Test", "contractName": "RefusalTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let mut cases = Vec::new();
    let mut unknown = base.clone();
    unknown["_pqsigner"]["refusalOnlyFormats"] = serde_json::json!(["burn(uint256 amount)"]);
    cases.push(("unknown", unknown, "names unknown format"));

    let mut duplicate = base.clone();
    duplicate["_pqsigner"]["refusalOnlyFormats"] = serde_json::json!([
        "approve(address spender,uint256 amount)",
        "approve(address spender,uint256 amount)"
    ]);
    cases.push(("duplicate", duplicate, "refusalOnlyFormats duplicates"));

    let mut overlap = base.clone();
    overlap["_pqsigner"]["deploymentFormats"] = serde_json::json!([{
        "chainId": 1,
        "address": "0x0000000000000000000000000000000000000001",
        "formats": ["approve(address spender,uint256 amount)"]
    }]);
    cases.push(("overlap", overlap, "overlaps deploymentFormats"));

    for (name, descriptor, expected) in cases {
        let dir = make_tempdir(name);
        fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
        let path = dir.join("calldata-refusal.json");
        fs::write(&path, serde_json::to_vec_pretty(&descriptor).unwrap()).unwrap();
        let policy = load_policy(&dir.join("policy.toml")).unwrap();
        let error = expect_err(
            try_compile_one(&path, &policy, Some(&dir)),
            "invalid refusalOnlyFormats shape must fail closed",
        );
        assert!(
            error.contains(expected),
            "{name}: expected `{expected}` in `{error}`"
        );
    }
}

#[test]
fn pqsigner_threshold_omissions_narrow_one_deployment_and_reject_bad_shapes() {
    // A shared descriptor whose exact-max allowance claim holds on chain 1 but
    // not chain 137 (the Ethereum/Polygon USDT shape): the omission strips the
    // threshold from the chain-137 IR only and changes nothing else.
    let base: serde_json::Value = serde_json::from_str(
        r#"{
  "_pqsigner": { "thresholdOmissions": [{
    "chainId": 137,
    "address": "0x0000000000000000000000000000000000000002",
    "format": "approve(address spender,uint256 amount)",
    "path": "amount"
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" },
    { "chainId": 137, "address": "0x0000000000000000000000000000000000000002" }
  ] } },
  "metadata": { "owner": "Omission Test", "contractName": "OmissionTest" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "tokenAmount", "label": "Amount",
          "params": { "tokenPath": "@.to",
                      "threshold": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" } }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let dir = make_tempdir("threshold_omissions_ok");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let path = dir.join("calldata-omission.json");
    fs::write(&path, serde_json::to_vec_pretty(&base).unwrap()).unwrap();
    let policy = load_policy(&dir.join("policy.toml")).unwrap();
    let emitted = try_compile_one(&path, &policy, Some(&dir)).expect("omission compiles");
    assert_eq!(emitted.len(), 2, "both deployments still emit a leaf");
    for entry in &emitted {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("IR parses");
        let format = ir
            .format_iter()
            .next()
            .expect("one format")
            .expect("format parses");
        let amount = format
            .fields()
            .map(|field| field.expect("field parses"))
            .find(|field| field.label == b"Amount")
            .expect("amount field");
        let params = pqsigner_erc7730::render::params::parse(&ir, amount.param_off)
            .expect("amount params parse");
        match entry.chain_id {
            1 => assert_eq!(params.threshold.copied(), Some([0xff; 32])),
            137 => assert!(
                params.threshold.is_none(),
                "omitted deployment kept its threshold"
            ),
            other => panic!("unexpected chain {other}"),
        }
        assert!(params.message.is_none());
    }

    let mut cases = Vec::new();
    let mut undeclared = base.clone();
    undeclared["_pqsigner"]["thresholdOmissions"][0]["chainId"] = serde_json::json!(56);
    cases.push((
        "undeclared",
        undeclared,
        "is not a declared contract deployment",
    ));

    let mut unknown_format = base.clone();
    unknown_format["_pqsigner"]["thresholdOmissions"][0]["format"] =
        serde_json::json!("burn(uint256 amount)");
    cases.push(("unknown_format", unknown_format, "names unknown format"));

    let mut no_threshold = base.clone();
    no_threshold["_pqsigner"]["thresholdOmissions"][0]["path"] = serde_json::json!("spender");
    cases.push((
        "no_threshold",
        no_threshold,
        "is not a direct tokenAmount field carrying a threshold",
    ));

    let mut missing_path = base.clone();
    missing_path["_pqsigner"]["thresholdOmissions"][0]["path"] = serde_json::json!("value");
    cases.push((
        "missing_path",
        missing_path,
        "must name exactly one direct field",
    ));

    let mut duplicate = base.clone();
    let entry = duplicate["_pqsigner"]["thresholdOmissions"][0].clone();
    duplicate["_pqsigner"]["thresholdOmissions"] = serde_json::json!([entry.clone(), entry]);
    cases.push(("duplicate", duplicate, "thresholdOmissions duplicates"));

    for (name, descriptor, expected) in cases {
        let dir = make_tempdir(&format!("threshold_omissions_{name}"));
        fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
        let path = dir.join("calldata-omission.json");
        fs::write(&path, serde_json::to_vec_pretty(&descriptor).unwrap()).unwrap();
        let policy = load_policy(&dir.join("policy.toml")).unwrap();
        let error = expect_err(
            try_compile_one(&path, &policy, Some(&dir)),
            "invalid thresholdOmissions shape must fail closed",
        );
        assert!(
            error.contains(expected),
            "{name}: expected `{expected}` in `{error}`"
        );
    }
}

#[test]
fn pqsigner_deployment_formats_rejects_every_nonrestrictive_or_ambiguous_shape() {
    let base: serde_json::Value = serde_json::from_str(
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000001",
    "formats": ["transfer(address to,uint256 amount)"]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Scope Test", "contractName": "ScopeTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let mut cases = Vec::new();

    let mut empty_admissions = base.clone();
    empty_admissions["_pqsigner"]["deploymentFormats"] = serde_json::json!([]);
    cases.push(("empty_admissions", empty_admissions, "must not be empty"));

    let mut missing_admissions = base.clone();
    missing_admissions["_pqsigner"] = serde_json::json!({});
    cases.push((
        "missing_admissions",
        missing_admissions,
        "deploymentFormats must not be empty unless refusalOnlyFormats or thresholdOmissions is non-empty",
    ));

    let mut null_extension = base.clone();
    null_extension["_pqsigner"] = serde_json::Value::Null;
    cases.push((
        "null_extension",
        null_extension,
        "must be an object, not null",
    ));

    let mut malformed_address = base.clone();
    malformed_address["_pqsigner"]["deploymentFormats"][0]["address"] = serde_json::json!("0x1234");
    cases.push(("malformed_address", malformed_address, "address is invalid"));

    let mut outside_deployment = base.clone();
    outside_deployment["_pqsigner"]["deploymentFormats"][0]["chainId"] = serde_json::json!(10);
    cases.push((
        "outside_deployment",
        outside_deployment,
        "is not a declared contract deployment",
    ));

    let mut empty_formats = base.clone();
    empty_formats["_pqsigner"]["deploymentFormats"][0]["formats"] = serde_json::json!([]);
    cases.push(("empty_formats", empty_formats, "formats must not be empty"));

    let mut unknown_format = base.clone();
    unknown_format["_pqsigner"]["deploymentFormats"][0]["formats"] =
        serde_json::json!(["burn(uint256 amount)"]);
    cases.push(("unknown_format", unknown_format, "names unknown format"));

    let mut duplicate_format = base.clone();
    duplicate_format["_pqsigner"]["deploymentFormats"][0]["formats"] = serde_json::json!([
        "transfer(address to,uint256 amount)",
        "transfer(address to,uint256 amount)"
    ]);
    cases.push(("duplicate_format", duplicate_format, "formats duplicates"));

    let mut duplicate_deployment = base.clone();
    let duplicate = duplicate_deployment["_pqsigner"]["deploymentFormats"][0].clone();
    duplicate_deployment["_pqsigner"]["deploymentFormats"] =
        serde_json::json!([duplicate.clone(), duplicate]);
    cases.push((
        "duplicate_deployment",
        duplicate_deployment,
        "deploymentFormats duplicates",
    ));

    let mut normalized_duplicate = base.clone();
    normalized_duplicate["context"]["contract"]["deployments"][0]["address"] =
        serde_json::json!("0x00000000000000000000000000000000000000aB");
    normalized_duplicate["_pqsigner"]["deploymentFormats"][0]["address"] =
        serde_json::json!("0x00000000000000000000000000000000000000AB");
    let mut differently_cased = normalized_duplicate["_pqsigner"]["deploymentFormats"][0].clone();
    differently_cased["address"] = serde_json::json!("0x00000000000000000000000000000000000000ab");
    normalized_duplicate["_pqsigner"]["deploymentFormats"] = serde_json::json!([
        normalized_duplicate["_pqsigner"]["deploymentFormats"][0].clone(),
        differently_cased
    ]);
    cases.push((
        "normalized_duplicate",
        normalized_duplicate,
        "deploymentFormats duplicates",
    ));

    let mut unknown_nested_key = base.clone();
    unknown_nested_key["_pqsigner"]["widensAuthority"] = serde_json::json!(true);
    cases.push((
        "unknown_nested_key",
        unknown_nested_key,
        "unknown field `widensAuthority`",
    ));

    let mut unknown_admission_key = base.clone();
    unknown_admission_key["_pqsigner"]["deploymentFormats"][0]["note"] =
        serde_json::json!("not authenticated semantics");
    cases.push((
        "unknown_admission_key",
        unknown_admission_key,
        "unknown field `note`",
    ));

    for (name, descriptor, expected) in cases {
        let dir = make_tempdir(name);
        fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
        let path = dir.join("calldata-scoped.json");
        fs::write(&path, serde_json::to_vec_pretty(&descriptor).unwrap()).unwrap();
        let policy = load_policy(&dir.join("policy.toml")).unwrap();
        let error = expect_err(
            try_compile_one(&path, &policy, Some(&dir)),
            "invalid deploymentFormats shape must fail closed",
        );
        assert!(
            error.contains(expected),
            "{name}: expected `{expected}` in `{error}`"
        );
    }
}

#[test]
fn duplicate_root_pqsigner_keys_are_rejected_before_authority_is_selected() {
    let dir = make_tempdir("duplicate_root_pqsigner_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let path = dir.join("calldata-duplicate-root.json");
    fs::write(
        &path,
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000001",
    "formats": ["transfer(address to,uint256 amount)"]
  }] },
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000001",
    "formats": [
      "transfer(address to,uint256 amount)",
      "approve(address spender,uint256 amount)"
    ]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Duplicate Test", "contractName": "DuplicateTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let policy = load_policy(&dir.join("policy.toml")).unwrap();
    let error = expect_err(
        try_compile_one(&path, &policy, Some(&dir)),
        "duplicate root authority keys must fail closed",
    );
    assert!(
        error.contains("duplicate JSON object key `_pqsigner`"),
        "unexpected duplicate-key rejection: {error}"
    );

    let catalogue_error = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "the tolerant catalogue must not turn duplicate authority keys into a skip",
    );
    assert!(
        catalogue_error.contains("calldata-duplicate-root.json")
            && catalogue_error.contains("known-call omission scan failed closed")
            && catalogue_error.contains("duplicate JSON object key `_pqsigner`"),
        "unexpected tolerant-catalogue rejection: {catalogue_error}"
    );
}

#[test]
fn duplicate_nested_admission_keys_are_rejected_after_json_unescaping() {
    let dir = make_tempdir("duplicate_nested_admission_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let path = dir.join("calldata-duplicate-admission.json");
    fs::write(
        &path,
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "chain\u0049d": 56,
    "address": "0x0000000000000000000000000000000000000002",
    "formats": ["transfer(address to,uint256 amount)"]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 56, "address": "0x0000000000000000000000000000000000000002" }
  ] } },
  "metadata": { "owner": "Duplicate Test", "contractName": "DuplicateTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let policy = load_policy(&dir.join("policy.toml")).unwrap();
    let error = expect_err(
        try_compile_one(&path, &policy, Some(&dir)),
        "duplicate nested admission keys must fail closed",
    );
    assert!(
        error.contains("duplicate JSON object key `chainId`"),
        "unexpected duplicate-key rejection: {error}"
    );
}

#[test]
fn duplicate_include_keys_are_rejected_before_merge() {
    let root = make_tempdir("duplicate_include_key");
    let registry = root.join("registry");
    fs::create_dir(&registry).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        registry.join("common-duplicate.json"),
        r#"{
  "metadata": {
    "owner": "First Owner",
    "owner": "Second Owner",
    "contractName": "DuplicateInclude"
  }
}"#,
    )
    .unwrap();
    let path = registry.join("calldata-leaf.json");
    fs::write(
        &path,
        r#"{
  "includes": "./common-duplicate.json",
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let policy = load_policy(&root.join("policy.toml")).unwrap();
    let error = expect_err(
        try_compile_one(&path, &policy, Some(&root)),
        "duplicate include keys must fail closed",
    );
    assert!(
        error.contains("load include")
            && error.contains("parse descriptor source")
            && error.contains("common-duplicate.json")
            && error.contains("duplicate JSON object key `owner`"),
        "unexpected duplicate-key rejection: {error}"
    );
}

#[test]
fn pqsigner_key_is_reserved_to_each_json_document_root() {
    let base = serde_json::json!({
      "_pqsigner": { "deploymentFormats": [{
        "chainId": 1,
        "address": "0x0000000000000000000000000000000000000001",
        "formats": ["transfer(address to,uint256 amount)"]
      }] },
      "context": { "contract": { "deployments": [
        { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" },
        { "chainId": 56, "address": "0x0000000000000000000000000000000000000002" }
      ] } },
      "metadata": { "owner": "Placement Test", "contractName": "PlacementTest" },
      "display": { "formats": {
        "transfer(address to,uint256 amount)": {
          "intent": "Send",
          "fields": [
            { "path": "to", "format": "addressName", "label": "To" },
            { "path": "amount", "format": "raw", "label": "Amount" }
          ]
        },
        "approve(address spender,uint256 amount)": {
          "intent": "Approve",
          "fields": [
            { "path": "spender", "format": "addressName", "label": "Spender" },
            { "path": "amount", "format": "raw", "label": "Amount" }
          ]
        }
      } }
    });

    for location in ["metadata", "display"] {
        let dir = make_tempdir(&format!("misplaced_pqsigner_{location}"));
        fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
        let mut descriptor = base.clone();
        let extension = descriptor
            .as_object_mut()
            .unwrap()
            .remove("_pqsigner")
            .unwrap();
        descriptor[location]
            .as_object_mut()
            .unwrap()
            .insert("_pqsigner".to_string(), extension);
        let path = dir.join("calldata-misplaced.json");
        fs::write(&path, serde_json::to_vec_pretty(&descriptor).unwrap()).unwrap();

        let policy = load_policy(&dir.join("policy.toml")).unwrap();
        let error = expect_err(
            try_compile_one(&path, &policy, Some(&dir)),
            "a misplaced narrowing block must not restore the full cross-product",
        );
        assert!(
            error.contains("reserved key `_pqsigner` may appear only at a JSON document root"),
            "{location}: unexpected misplaced-key rejection: {error}"
        );
    }

    let root = make_tempdir("misplaced_pqsigner_include");
    let registry = root.join("registry");
    fs::create_dir(&registry).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    let mut descriptor = base;
    let extension = descriptor
        .as_object_mut()
        .unwrap()
        .remove("_pqsigner")
        .unwrap();
    descriptor["includes"] = serde_json::json!("./common-misplaced.json");
    fs::write(
        registry.join("calldata-leaf.json"),
        serde_json::to_vec_pretty(&descriptor).unwrap(),
    )
    .unwrap();
    fs::write(
        registry.join("common-misplaced.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "metadata": { "_pqsigner": extension }
        }))
        .unwrap(),
    )
    .unwrap();

    let policy = load_policy(&root.join("policy.toml")).unwrap();
    let error = expect_err(
        try_compile_one(&registry.join("calldata-leaf.json"), &policy, Some(&root)),
        "a misplaced include narrowing block must fail before merge",
    );
    assert!(
        error.contains("load include")
            && error.contains("parse descriptor source")
            && error.contains("common-misplaced.json")
            && error.contains("reserved key `_pqsigner` may appear only at a JSON document root"),
        "unexpected include misplaced-key rejection: {error}"
    );
}

#[test]
fn pqsigner_selected_format_cannot_hide_omitted_selector_collision() {
    let dir = make_tempdir("deployment_format_selector_collision");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-selector-collision.json"),
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000003",
    "formats": ["approve(address spender,uint256 amount)"]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Collision", "contractName": "Collision" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "watch_tg_invmru_2f69f1b(address first,address second)": {
      "intent": "Collision",
      "fields": [
        { "path": "first", "format": "addressName", "label": "First" },
        { "path": "second", "format": "addressName", "label": "Second" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("selector-colliding admission must remain a known hard refusal");
    assert_eq!(result.leaf_count, 1, "only the independent safe descriptor");
    let collision_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-selector-collision.json")
        })
        .expect("colliding admission must carry a skip receipt");
    assert!(
        collision_skip.reason.contains("selector 0x095ea7b3")
            && collision_skip
                .reason
                .contains("collides with source formats")
            && collision_skip
                .reason
                .contains("selector-only runtime dispatch cannot authenticate"),
        "unexpected collision refusal: {}",
        collision_skip.reason
    );

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let selector = [0x09, 0x5e, 0xa7, 0xb3];
    assert!(result.known_calls.contains(&(1, contract, selector)));
    assert!(known_call_may_contain(
        &result.known_calls_bloom,
        1,
        &contract,
        &selector
    ));
}

#[test]
fn pqsigner_selected_format_cannot_collide_with_dropped_other_descriptor() {
    let dir = make_tempdir("deployment_format_cross_descriptor_collision");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-admitted.json"),
        r#"{
  "_pqsigner": { "deploymentFormats": [{
    "chainId": 1,
    "address": "0x0000000000000000000000000000000000000003",
    "formats": ["approve(address spender,uint256 amount)"]
  }] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Admitted", "contractName": "Admitted" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    }
  } }
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("calldata-dropped-collision.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Dropped", "contractName": "Dropped" },
  "display": { "formats": {
    "watch_tg_invmru_2f69f1b(address first,address second)": {
      "intent": "Collision",
      "fields": [
        { "path": "first", "format": "addressName", "label": "First" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("cross-descriptor collision must remain a known hard refusal");
    assert_eq!(result.leaf_count, 1, "only the independent safe descriptor");
    let admitted_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str()) == Some("calldata-admitted.json")
        })
        .expect("admitted side of the collision must be refused");
    assert!(
        admitted_skip.reason.contains("collides catalogue-wide")
            && admitted_skip.reason.contains("approve(address,uint256)")
            && admitted_skip
                .reason
                .contains("watch_tg_invmru_2f69f1b(address,address)"),
        "unexpected catalogue-wide collision refusal: {}",
        admitted_skip.reason
    );
    assert!(skips.iter().any(|skip| {
        skip.source.file_name().and_then(|name| name.to_str())
            == Some("calldata-dropped-collision.json")
    }));

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let selector = [0x09, 0x5e, 0xa7, 0xb3];
    assert!(result.known_calls.contains(&(1, contract, selector)));
    assert!(known_call_may_contain(
        &result.known_calls_bloom,
        1,
        &contract,
        &selector
    ));
}

#[test]
fn pqsigner_selected_uncompilable_format_drops_the_whole_descriptor_but_stays_known() {
    let dir = make_tempdir("deployment_format_selected_failure");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-mixed.json"),
        r#"{
  "_pqsigner": { "deploymentFormats": [
    {
      "chainId": 1,
      "address": "0x0000000000000000000000000000000000000001",
      "formats": [
        "transfer(address to,uint256 amount)",
        "approve(address spender,uint256 amount)"
      ]
    }
  ] },
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
  ] } },
  "metadata": { "owner": "Scope Test", "contractName": "ScopeTest" },
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    },
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender", "visible": "never" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 137, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Safe Test", "contractName": "SafeTest" },
  "display": { "formats": {
    "ping(uint256 value)": {
      "intent": "Ping",
      "fields": [
        { "path": "value", "format": "raw", "label": "Value", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("tolerant catalogue keeps the independent safe descriptor");
    assert_eq!(result.leaf_count, 1);
    assert_eq!(
        result.entries[0]
            .source
            .file_name()
            .and_then(|name| name.to_str()),
        Some("calldata-safe.json")
    );
    round_trip_check(&result).expect("surviving descriptor round-trips");
    assert!(skips.iter().any(|skip| {
        skip.source.file_name().and_then(|name| name.to_str()) == Some("calldata-mixed.json")
    }));

    let mut contract = [0u8; 20];
    contract[19] = 1;
    for selector in [[0xa9, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3]] {
        assert!(result.known_calls.contains(&(1, contract, selector)));
        assert!(known_call_may_contain(
            &result.known_calls_bloom,
            1,
            &contract,
            &selector
        ));
    }
}

#[test]
fn tolerant_boundary_skips_contract_ir_rejected_by_canonical_device_parser() {
    let dir = make_tempdir("device_parser_boundary");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-safe.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-selector-collision.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }
  ] } },
  "metadata": { "owner": "Collision", "contractName": "Collision" },
  "display": { "formats": {
    "approve(address spender,uint256 amount)": {
      "intent": "Approve",
      "fields": [
        { "path": "spender", "format": "addressName", "label": "Spender" },
        { "path": "amount", "format": "raw", "label": "Amount" }
      ]
    },
    "watch_tg_invmru_2f69f1b(address first,address second)": {
      "intent": "Collision",
      "fields": [
        { "path": "first", "format": "addressName", "label": "First" },
        { "path": "second", "format": "addressName", "label": "Second" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let (result, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("the malformed descriptor must stay inside its tolerant boundary");
    assert_eq!(result.leaf_count, 1, "only the safe descriptor may survive");
    let collision_skip = skips
        .iter()
        .find(|skip| {
            skip.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-selector-collision.json")
        })
        .expect("device-parser rejection must produce a descriptor skip receipt");
    assert!(
        collision_skip
            .reason
            .contains("failed canonical device parsing")
            && collision_skip.reason.contains("BadFormat"),
        "unexpected collision skip: {}",
        collision_skip.reason
    );
}

#[test]
fn dup_leaf_non_identical_is_conflict_error() {
    // Same (chain, contract) but DIFFERENT IR (different field labels) → the
    // device would trust whichever sorts first by filename (a silent trust-swap
    // on re-vendor). Must hard-error, not pick a filename-order winner.
    let dir = make_tempdir("dup_conflict");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-a.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-b.json"),
        transfer_descriptor("Recipient", "Value"),
    )
    .unwrap();

    let err = match build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)) {
        Ok(_) => panic!("non-identical dup MUST hard-error (review 2.2)"),
        Err(e) => e,
    };
    assert!(
        err.contains("CONFLICT") && err.contains("non-identical duplicate"),
        "unexpected error for non-identical dup: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// review 1.3: unmodeled top-level field/format keys gate the format
// ─────────────────────────────────────────────────────────────────────

/// A clean, always-compilable transfer descriptor at contract 0x…02 (distinct
/// from the 0x…01 fixtures) so the tolerant build has ≥1 leaf — otherwise
/// build_db_tolerant errors with "no IR entries emitted" and drops `skips`.
const VALID_SIBLING_02: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }] } },
  "metadata": { "owner": "Sib", "contractName": "Sib" },
  "display": { "formats": { "transfer(address to, uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ] } } }
}"#;

fn transfer_with_extra_field_key(extra_key: &str, extra_val: &str) -> String {
    format!(
        r#"{{
  "context": {{ "contract": {{ "deployments": [{{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }}] }} }},
  "metadata": {{ "owner": "T", "contractName": "T" }},
  "display": {{ "formats": {{ "transfer(address to, uint256 amount)": {{
      "intent": "Send",
      "fields": [
        {{ "path": "to", "format": "addressName", "label": "To", "visible": "always" }},
        {{ "path": "amount", "format": "raw", "label": "Amt", "visible": "always", "{extra_key}": {extra_val} }}
      ] }} }} }}
}}"#
    )
}

#[test]
fn unmodeled_field_key_is_skipped_with_reason() {
    // A field carrying a key dbgen doesn't model (a typo or foreign key) must
    // NOT silently compile — the format skips-loud, naming the offending key
    // (finding 1.3; the $ref-silent-drop failure class).
    let dir = make_tempdir("unmodeled_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-gated.json"),
        transfer_with_extra_field_key("bogusKey", "1"),
    )
    .unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(res.leaf_count, 1, "only the clean sibling leaf survives");
    assert!(
        skips.iter().any(|s| s.reason.contains("unmodeled descriptor key")
            && s.reason.contains("bogusKey")),
        "skip must name the unmodeled key: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn semantic_key_encryption_is_gated_not_ignored() {
    // `encryption` is a VALID v2 key, but dbgen doesn't implement it; rendering
    // as if absent would mis-represent the field, so it must gate (skip-loud),
    // not silently ignore (finding 1.3).
    let dir = make_tempdir("encryption_gated");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-gated.json"),
        transfer_with_extra_field_key("encryption", r#"{"a":1}"#),
    )
    .unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(res.leaf_count, 1, "only the clean sibling leaf survives");
    assert!(
        skips
            .iter()
            .any(|s| s.reason.contains("unmodeled descriptor key")
                && s.reason.contains("encryption")),
        "encryption must gate the format: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn unmodeled_key_in_definition_body_is_gated() {
    // finding 1.3 (definitions-body bypass, verify pass 2026-07-02): an
    // unmodeled key on a $.display.definitions BODY must gate through the $ref
    // channel, exactly like one on the reference object or an inline field —
    // otherwise resolve_display_refs silently discards it on merge (the 1.1
    // silent-drop class, through the very mechanism 1.1 introduced).
    let dir = make_tempdir("def_body_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let d = r#"{
      "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }] } },
      "metadata": { "owner": "T", "contractName": "T" },
      "display": {
        "definitions": { "amt": { "format": "raw", "label": "Amt", "bogusDefKey": 1 } },
        "formats": { "transfer(address to, uint256 amount)": {
          "intent": "Send",
          "fields": [
            { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
            { "path": "amount", "$ref": "$.display.definitions.amt", "visible": "always" }
          ] } } }
    }"#;
    fs::write(dir.join("calldata-gated.json"), d).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(
        res.leaf_count, 1,
        "only the clean sibling survives; the def-body key must gate"
    );
    assert!(
        skips
            .iter()
            .any(|s| s.reason.contains("unmodeled key") && s.reason.contains("bogusDefKey")),
        "skip must name the definition-body key: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn misnamed_descriptor_is_flagged_unscanned() {
    // review 2.3 (filename-convention tripwire): a *.json that carries a
    // descriptor shape (context+display) but doesn't match calldata-*/eip712-*
    // would be SILENTLY dropped by the scanner on an upstream rename. It must
    // instead be flagged UNSCANNED in the (drift-gated) skip report.
    let dir = make_tempdir("misnamed");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    // Mis-named (wrong prefix) — looks like a descriptor, must be flagged.
    fs::write(
        dir.join("swapRouter.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert_eq!(
        res.leaf_count, 1,
        "only the correctly-named descriptor is scanned"
    );
    assert!(
        skips.iter().any(|s| s.reason.contains("UNSCANNED")
            && s.source.file_name().and_then(|n| n.to_str()) == Some("swapRouter.json")),
        "mis-named descriptor must be flagged UNSCANNED: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );

    // Coverage may follow the filename convention, but omission protection
    // must not. The misnamed file still declares mainnet contract 0x...01 and
    // transfer(address,uint256), so stripping its clear-sign proof must refuse
    // instead of restoring the blind-sign rung.
    let mut contract = [0u8; 20];
    contract[19] = 1;
    let digest = pqsigner_tx_core::hash::keccak256(b"transfer(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn deployed_common_descriptor_is_flagged_and_covered_by_omission_filter() {
    // `common-*` is only a naming convention for include templates. It cannot
    // exempt a file that independently carries context+display: upstream may
    // add deployments to a former template, and silently skipping that file
    // would otherwise restore blind-signing for its declared calls.
    let dir = make_tempdir("deployed_common");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("common-deployed.json"),
        transfer_descriptor("To", "Amount").replace(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000003",
        ),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert_eq!(
        res.leaf_count, 1,
        "the common-* descriptor is tripwired, not renderer-compiled"
    );
    assert!(
        skips.iter().any(|skip| {
            skip.reason.contains("UNSCANNED")
                && skip.source.file_name().and_then(|name| name.to_str())
                    == Some("common-deployed.json")
        }),
        "deployed common-* descriptor must be visible in the skip receipt: {:?}",
        skips.iter().map(|skip| &skip.reason).collect::<Vec<_>>()
    );

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let digest = pqsigner_tx_core::hash::keccak256(b"transfer(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn unscanned_child_with_deployments_and_included_formats_is_known() {
    let root = make_tempdir("unscanned_child_include");
    let registry = root.join("registry");
    fs::create_dir(&registry).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(registry.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        registry.join("common-format.json"),
        r#"{
  "metadata": { "owner": "Template", "contractName": "Template" },
  "display": { "formats": {
    "splitCall(address to,uint256 amount)": {
      "intent": "Split",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();
    fs::write(
        registry.join("common-child.json"),
        r#"{
  "\u0063ontext": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000004" }
  ] } },
  "includes": "common-format.json"
}"#,
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&registry, &root.join("policy.toml"), Some(&root)).expect("build");
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("UNSCANNED")
            && skip.source.file_name().and_then(|name| name.to_str()) == Some("common-child.json")
    }));
    let mut contract = [0u8; 20];
    contract[19] = 4;
    let digest = pqsigner_tx_core::hash::keccak256(b"splitCall(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn duplicate_parameter_names_are_unrenderable_but_selector_remains_known() {
    let dir = make_tempdir("duplicate_names_known");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-duplicate.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000005" }
  ] } },
  "metadata": { "owner": "Rejected", "contractName": "Rejected" },
  "display": { "formats": {
    "f(address to,uint256 to)": { "intent": "Rejected", "fields": [] }
  } }
}"#,
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert!(skips
        .iter()
        .any(|skip| skip.reason.contains("duplicate top-level argument name")));
    let mut contract = [0u8; 20];
    contract[19] = 5;
    let digest = pqsigner_tx_core::hash::keccak256(b"f(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn test_fixture_paths_are_not_omission_filter_escape_hatches() {
    let dir = make_tempdir("test_fixture_paths_known");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    let descriptor = |last_byte: u8, signature: &str| {
        format!(
            r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x00000000000000000000000000000000000000{last_byte:02x}" }}
  ] }} }},
  "metadata": {{ "owner": "Fixture", "contractName": "Fixture" }},
  "display": {{ "formats": {{
    "{signature}": {{ "intent": "Fixture", "fields": [] }}
  }} }}
}}"#
        )
    };
    fs::write(
        dir.join("calldata-hidden.tests.backdoor.json"),
        descriptor(0x61, "suffixFixture(uint256 value)"),
    )
    .unwrap();
    fs::write(
        dir.join("tests/calldata-hidden.json"),
        descriptor(0x62, "directoryFixture(address target)"),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert!(
        skips
            .iter()
            .filter(|skip| skip.reason.contains("UNSCANNED"))
            .count()
            >= 2,
        "both fixture-named descriptors need visible omission-scan receipts"
    );

    for (last_byte, signature) in [
        (0x61, "suffixFixture(uint256)"),
        (0x62, "directoryFixture(address)"),
    ] {
        let mut contract = [0u8; 20];
        contract[19] = last_byte;
        let digest = pqsigner_tx_core::hash::keccak256(signature.as_bytes());
        let selector = [digest[0], digest[1], digest[2], digest[3]];
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &res.known_calls_bloom,
            1,
            &contract,
            &selector,
        ));
    }
}

#[test]
fn malformed_contract_selector_grammar_fails_the_catalogue_closed() {
    for (case, signature, expected) in [
        (
            "invalid_function_name",
            "transfer.foo(address to,uint256 amount)",
            "expected `(`",
        ),
        (
            "digit_function_name",
            "1transfer(uint256 amount)",
            "invalid function name",
        ),
        (
            "invalid_uint_width",
            "badWidth(uint7 value)",
            "unsupported ABI type `uint7`",
        ),
        (
            "invalid_bytes_width",
            "badBytes(bytes33 value)",
            "unsupported ABI type `bytes33`",
        ),
        (
            "custom_type",
            "custom(Foo value)",
            "unsupported ABI type `Foo`",
        ),
    ] {
        let dir = make_tempdir(case);
        fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
        fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
        fs::write(
            dir.join("calldata-hostile.json"),
            format!(
                r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x0000000000000000000000000000000000000063" }}
  ] }} }},
  "metadata": {{ "owner": "Hostile", "contractName": "Hostile" }},
  "display": {{ "formats": {{
    "{signature}": {{ "intent": "Hostile", "fields": [] }}
  }} }}
}}"#
            ),
        )
        .unwrap();
        let error = expect_err(
            build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
            "noncanonical selector grammar must abort omission preflight",
        );
        assert!(error.contains(expected), "{case}: {error}");
    }
}

#[test]
fn sibling_ercs_json_is_always_omission_scanned() {
    let root = make_tempdir("sibling_ercs_known");
    let registry = root.join("registry");
    let ercs = root.join("ercs");
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(&ercs).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(registry.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        ercs.join("common-live-binding.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000064" }
  ] } },
  "display": { "formats": {
    "ercsOnly(bytes32 value)": { "intent": "Support template", "fields": [] }
  } }
}"#,
    )
    .unwrap();

    let (res, _) = build_db_tolerant(&registry, &root.join("policy.toml"), Some(&root))
        .expect("sibling ercs scan");
    let mut contract = [0u8; 20];
    contract[19] = 0x64;
    let digest = pqsigner_tx_core::hash::keccak256(b"ercsOnly(bytes32)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn uppercase_json_extension_is_rejected_not_silently_omitted() {
    let dir = make_tempdir("uppercase_json");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-hidden.JSON"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "uppercase JSON extension must fail closed",
    );
    assert!(err.contains("non-canonical JSON filename"), "{err}");
}

// ─────────────────────────────────────────────────────────────────────
// Item 2: `includes` resolution
// ─────────────────────────────────────────────────────────────────────
//
// Strategy: create a per-test tempdir with (a) a tiny "registry" mirror
// holding template fragments, (b) a descriptor that references the
// template via `"includes"`, (c) a policy.toml. Run the compiler and
// assert the merge happened (or was correctly refused).
//
// We use std::env::temp_dir() + a per-test subdir; no extra crate dep.

fn make_tempdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dbgen_phase5_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create tempdir");
    p
}

const POLICY_DEV: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

const TEMPLATE_PERMIT: &str = r#"{
  "metadata": { "owner": "Permit Template", "contractName": "Permit Template" },
  "display": { "formats": {
    "templated()": { "intent": "Templated intent from include", "fields": [] }
  } }
}"#;

const DESCRIPTOR_WITH_RELATIVE_INCLUDE: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }] } },
  "includes": "./common-permit.json",
  "display": { "formats": {
    "transfer(address to,uint256 amount)": {
      "intent": "Local override wins",
      "fields": [
        { "path": "to", "label": "To", "format": "addressName" },
        { "path": "amount", "label": "Amount", "format": "raw" }
      ]
    }
  } }
}"#;

const DESCRIPTOR_WITH_REGISTRY_INCLUDE: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }] } },
  "includes": "templates/permit.json"
}"#;

#[test]
fn include_relative_path_resolves_against_descriptor_dir() {
    let root = make_tempdir("rel_include");
    let registry = root.join("registry");
    fs::create_dir(&registry).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(registry.join("common-permit.json"), TEMPLATE_PERMIT).unwrap();
    fs::write(
        registry.join("descriptor.json"),
        DESCRIPTOR_WITH_RELATIVE_INCLUDE,
    )
    .unwrap();

    // Compile the concrete child directly: include-only common templates are
    // inputs, not standalone catalogue descriptors. Parsing its emitted IR
    // proves both the included and locally declared formats survived merging.
    let policy = load_policy(&root.join("policy.toml")).unwrap();
    let entries = try_compile_one(&registry.join("descriptor.json"), &policy, Some(&root))
        .expect("relative include should resolve and compile");
    assert_eq!(entries.len(), 1);
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&entries[0].ir_bytes).unwrap();
    let selectors = ir
        .format_iter()
        .map(|format| format.unwrap().selector)
        .collect::<Vec<_>>();
    let templated = pqsigner_tx_core::hash::keccak256(b"templated()");
    let transfer = pqsigner_tx_core::hash::keccak256(b"transfer(address,uint256)");
    assert_eq!(
        selectors,
        vec![
            [templated[0], templated[1], templated[2], templated[3]],
            [transfer[0], transfer[1], transfer[2], transfer[3]],
        ]
    );
}

#[test]
fn nested_include_is_relative_to_the_immediate_including_file() {
    let root = make_tempdir("nested_include_relative_base");
    let registry = root.join("registry");
    let project = registry.join("project");
    let sub = project.join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(registry.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        project.join("calldata-leaf.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000071" }
  ] } },
  "metadata": { "owner": "Nested", "contractName": "Nested" },
  "includes": "sub/base.json"
}"#,
    )
    .unwrap();
    fs::write(sub.join("base.json"), r#"{ "includes": "common.json" }"#).unwrap();
    fs::write(
        sub.join("common.json"),
        r#"{ "display": { "formats": {
  "correctNested()": { "intent": "Correct nested include", "fields": [] }
} } }"#,
    )
    .unwrap();
    fs::write(
        project.join("common.json"),
        r#"{ "display": { "formats": {
  "wrongParent()": { "intent": "Wrong parent include", "fields": [] }
} } }"#,
    )
    .unwrap();

    let (res, _) = build_db_tolerant(&registry, &root.join("policy.toml"), Some(&root))
        .expect("nested include build");
    let entry = res
        .entries
        .iter()
        .find(|entry| entry.contract[19] == 0x71)
        .expect("nested include deployment emitted");
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&entry.ir_bytes).expect("parse emitted IR");
    let selectors: Vec<[u8; 4]> = ir
        .format_iter()
        .map(|format| format.expect("format").selector)
        .collect();
    let correct = pqsigner_tx_core::hash::keccak256(b"correctNested()");
    assert_eq!(
        selectors,
        vec![[correct[0], correct[1], correct[2], correct[3]]]
    );
}

#[test]
fn include_without_registry_root_is_rejected() {
    let dir = make_tempdir("no_root");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("descriptor.json"),
        DESCRIPTOR_WITH_REGISTRY_INCLUDE,
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(
            &dir,
            &dir.join("policy.toml"),
            false,
            None, // no registry root → must fail
        ),
        "includes without registry_root MUST fail",
    );
    assert!(
        err.contains("`--registry-root`") || err.contains("registry-root"),
        "unexpected error: {err}"
    );
}

#[test]
fn broken_include_fails_the_catalogue_closed() {
    // Even when the child has enough raw information to recover this one call,
    // a broken include may contain additional deployments or formats. Tolerant
    // renderer compilation is not permission to publish a possibly incomplete
    // known-call filter, so the whole catalogue must fail closed.
    let dir = make_tempdir("broken_include_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();

    let broken = r#"{
      "context": { "contract": { "deployments": [
        { "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }
      ] } },
      "includes": "missing-template.json",
      "metadata": { "owner": "Broken Include", "contractName": "Broken" },
      "display": { "formats": {
        "swap(address target,uint256 amount)": {
          "intent": "Swap",
          "fields": [
            { "path": "target", "label": "Target", "format": "addressName" },
            { "path": "amount", "label": "Amount", "format": "raw" }
          ]
        }
      } }
    }"#;
    fs::write(dir.join("calldata-broken.json"), broken).unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "a broken include must fail the entire catalogue closed",
    );
    assert!(
        err.contains("calldata-broken.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("missing-template.json"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[test]
fn non_string_include_fails_split_declaration_closed() {
    let dir = make_tempdir("non_string_include_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-non-string-include.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000065" }
  ] } },
  "includes": ["common-format.json"]
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("common-format.json"),
        r#"{
  "display": { "formats": {
    "splitCall(address target,uint256 amount)": {
      "intent": "Split",
      "fields": [
        { "path": "target", "format": "addressName", "label": "Target", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let error = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "a present non-string include must fail the catalogue closed",
    );
    assert!(
        error.contains("calldata-non-string-include.json")
            && error.contains("known-call omission scan failed closed")
            && error.contains("`includes` must be a string"),
        "unexpected fail-closed diagnostic: {error}"
    );
}

#[test]
fn selector_parser_differentials_are_not_emitted_but_remain_known() {
    for (case, signature, canonical, last_byte) in [
        (
            "alias_selector_disagreement",
            "aliasCall(uint value)",
            "aliasCall(uint256)",
            0x66,
        ),
        (
            "array_selector_disagreement",
            "arrayCall(uint256 [2] value)",
            "arrayCall(uint256[2])",
            0x67,
        ),
    ] {
        let dir = make_tempdir(case);
        fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
        fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
        fs::write(
            dir.join("calldata-differential.json"),
            format!(
                r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x00000000000000000000000000000000000000{last_byte:02x}" }}
  ] }} }},
  "metadata": {{ "owner": "Differential", "contractName": "Differential" }},
  "display": {{ "formats": {{
    "{signature}": {{
      "intent": "Differential",
      "fields": [
        {{ "path": "value", "format": "raw", "label": "Value", "visible": "always" }}
      ]
    }}
  }} }}
}}"#
            ),
        )
        .unwrap();

        let (result, skips) =
            build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
        assert!(
            skips
                .iter()
                .any(|skip| skip.reason.contains("selector parser disagreement")),
            "the parser disagreement must be visible in the review receipt"
        );
        let mut contract = [0u8; 20];
        contract[19] = last_byte;
        assert!(
            !result
                .entries
                .iter()
                .any(|entry| entry.chain_id == 1 && entry.contract == contract),
            "a parser disagreement must not emit an authenticated leaf"
        );
        let digest = pqsigner_tx_core::hash::keccak256(canonical.as_bytes());
        let selector = [digest[0], digest[1], digest[2], digest[3]];
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &result.known_calls_bloom,
            1,
            &contract,
            &selector,
        ));
    }
}

#[test]
fn malformed_raw_descriptor_fails_tolerant_catalogue_closed() {
    // The renderer build is tolerant only after the independent known-call
    // scan succeeds. A malformed selected descriptor may still have intended
    // deployments/formats that cannot be recovered, so it cannot become a
    // renderer skip while silently disappearing from the Bloom filter.
    let dir = make_tempdir("malformed_raw_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-malformed.json"),
        r#"{ "context": { "contract": { "deployments": [] } }, "display": "#,
    )
    .unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "malformed raw descriptor must fail the entire catalogue closed",
    );
    assert!(
        err.contains("calldata-malformed.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("parse descriptor source"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[test]
fn child_deployments_with_all_formats_in_broken_include_fail_closed() {
    // This is the false-negative shape a selected-file-only scan cannot recover: the
    // child declares deployments, while every callable format is supplied by
    // an include. If that include is malformed, the child contributes zero raw
    // tuples. Silently tolerating resolution failure would publish a Bloom
    // filter that forgets the known call entirely. Every unselected JSON is
    // now parsed independently, so the malformed template itself is the first
    // deterministic fail-closed source in sorted order.
    let dir = make_tempdir("child_deployments_include_formats");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("common-all-formats.json"),
        r#"{
          "display": { "formats": {
            "swap(address target,uint256 amount)": { "intent": "Swap" }
          } }
        } trailing-invalid-json"#,
    )
    .unwrap();
    fs::write(
        dir.join("calldata-child.json"),
        r#"{
          "context": { "contract": { "deployments": [
            { "chainId": 1, "address": "0x0000000000000000000000000000000000000004" }
          ] } },
          "includes": "common-all-formats.json",
          "metadata": { "owner": "Child", "contractName": "Child" }
        }"#,
    )
    .unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "unrecoverable include declarations must fail closed",
    );
    assert!(
        err.contains("common-all-formats.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("parse descriptor source"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_regular_file_name_fails_collectors_closed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = make_tempdir("non_utf8_name");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let bad_name = OsString::from_vec(b"calldata-\xff.json".to_vec());
    fs::write(dir.join(bad_name), transfer_descriptor("To", "Amount")).unwrap();

    let tolerant_err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "tolerant collector must reject a non-UTF-8 regular-file name",
    );
    assert!(
        tolerant_err.contains("non-UTF-8 regular-file name"),
        "unexpected tolerant diagnostic: {tolerant_err}"
    );
    assert!(
        !tolerant_err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must be checkout-path-independent: {tolerant_err}"
    );

    let strict_err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "strict collector must reject a non-UTF-8 regular-file name",
    );
    assert!(
        strict_err.contains("non-UTF-8 regular-file name"),
        "unexpected strict diagnostic: {strict_err}"
    );
    assert!(
        !strict_err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must be checkout-path-independent: {strict_err}"
    );
}

#[test]
fn include_escape_outside_registry_root_is_rejected() {
    // Build the descriptor in a tempdir, point registry_root at a
    // *sibling* directory, and have the include attempt to escape via
    // `../`. The canonicalisation-then-prefix check must refuse.
    let parent = make_tempdir("escape");
    let registry = parent.join("registry");
    let descriptors = parent.join("descriptors");
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(&descriptors).unwrap();
    fs::write(parent.join("OUTSIDE.json"), TEMPLATE_PERMIT).unwrap();
    fs::write(descriptors.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        descriptors.join("descriptor.json"),
        r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }] } },
  "includes": "../OUTSIDE.json"
}"#,
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(
            &descriptors,
            &descriptors.join("policy.toml"),
            false,
            Some(&registry),
        ),
        "../-escape MUST be refused",
    );
    assert!(
        err.contains("outside registry-root") || err.contains("canonicalize"),
        "expected sandbox rejection, got: {err}"
    );
    assert!(
        !err.contains(parent.to_string_lossy().as_ref()),
        "sandbox rejection must not leak the host checkout/temp path: {err}"
    );
}
