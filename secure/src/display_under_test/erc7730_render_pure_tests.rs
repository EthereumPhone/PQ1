//! End-to-end render tests for the ERC-7730 / ERC-8213 display renderers.
//!
//! Each test builds a realistic transaction (chain + to + calldata),
//! verifies the firmware-pinned bundle via `verify_erc7730_bundle`, then
//! runs the on-device renderer at `super::erc7730::render_erc7730_pages`
//! and asserts the resulting 4-row × 16-col display pages line-by-line
//! against the strings a user would actually see on the device.
//!
//! Why this exists: existing tests cover the host pipeline (`dbgen`),
//! the bundle verifier, the path walker, the parameter parser, and the
//! per-formatter row primitives. Until now there was no test that
//! plumbed a full `(tx, calldata, descriptor) -> Pages -> rendered
//! strings` round-trip end-to-end. A regression that breaks the user-
//! visible row text (truncation, intent label, decimal alignment, ticker
//! lookup) would not have been caught by any unit test.
//!
//! Inputs are NOT hand-rolled IR fixtures. Shipping cases come from the real
//! registry through `dbgen`; the remaining unsafe nested renderer-only cases
//! use process-private copies compiled by the same dbgen after changing every
//! explicit `visible:"never"` to `visible:"always"`. Real unsafe sources or
//! individual formats in a partially admitted source are separately asserted
//! absent.
//! UniswapX cannot be made into an equivalent safe positive fixture (dynamic
//! bytes expose only a hash, and showing all fields exceeds the page budget),
//! so those historical vectors are exclusion tests.

use std::path::PathBuf;

use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712, BindingError};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, VerifiedDescriptor};
use pqsigner_erc7730::display::primitives::{
    legacy_fee_rows_are_exactly_renderable, write_addr_full,
};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_tx_core::hash::keccak256;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::{NameMeta, NameResolver};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use super::dispatch::{pick_sign_pages, DispatchPageProofs};
use super::erc7730::{
    render_erc7730_pages, render_erc7730_pages_with_signer,
    render_erc7730_pages_with_signer_checked, INTENT_PUBLICATION_INTERPOLATED,
    INTENT_PUBLICATION_STATIC,
};
use super::erc8213::{
    append_fingerprint_page, fingerprint_final_set_proof, fingerprint_page_proof,
    Kind as Erc8213Kind, FINGERPRINT_CFI_EXPECTED,
};
use super::Pages;

// ───────────────────────────────────────────────────────────────────────
// One-shot seed-corpus build, cached across every test in this module.
// ───────────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Compile the checked-in seed corpus into a Merkle catalog. Doing this
/// per-test is cheap (the seed dir is now a tiny synthetic-only render-test
/// corpus) and keeps each test self-contained — no `static` / `OnceLock`
/// plumbing required.
fn build_seed() -> dbgen::erc7730::Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    dbgen::erc7730::build_db(&dir, &policy).expect("compile seed corpus")
}

/// The PROD catalog — the vendored upstream registry, built tolerantly
/// (the corpus switch). This is what `tools/companion-stub/erc7730_db.bin`
/// and the firmware-pinned `ERC7730_DESCRIPTORS_ROOT` are built from, so a
/// render test that exercises a REAL protocol descriptor (Aave/Tether/WETH/
/// wstETH/…) must drive it from THIS root, not a hand-authored duplicate.
///
/// The registry build is several hundred ms and many tests use it, so memoize
/// it in a `OnceLock` — built once per test binary, not per test.
/// Returns a `&'static`, so callers pass it straight to `find_leaf(res, …)`
/// (NOT `&res`) and read `res.blob` / `res.root` directly.
pub(super) fn build_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static REGISTRY: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let root = workspace_root();
        let reg = root.join("secure/data/erc7730-registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
            .expect("build ERC-20 capability set");
        let (res, _skips) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &reg.join("registry"),
            &policy,
            Some(&reg),
            &erc20.capabilities,
        )
        .expect("build registry corpus");
        res
    })
}

/// Build a registry from the CHECKED-IN synthetic renderer fixtures in
/// `tests/erc7730-renderer-fixtures/`.
///
/// WHY THIS EXISTS. Renderer tests must not be hosted on the production
/// catalogue. They were, and it cost 84 commits of red CI: the #498 EIP-712
/// reconciliation quarantined 24 descriptor sources (`reason_code`s recorded in
/// `tests/erc7730-semantic-evidence/eip712-reconciliation/manifest.json`), five
/// of which happened to be the fixtures these tests used. The renderer did not
/// change; its test data was withdrawn from the catalogue by an unrelated and
/// entirely correct policy decision.
///
/// Coupling renderer coverage to catalogue membership is the wrong dependency.
/// These fixtures are ours, they are not shipped, they sit at addresses no
/// deployment uses, and curation policy cannot take them away.
///
/// They are compiled by the SAME `dbgen` path as production descriptors, so
/// they exercise real compiled IR rather than hand-assembled bytes.
pub(super) fn build_fixture_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static FIXTURES: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    FIXTURES.get_or_init(|| {
        let root = workspace_root();
        let dir = root.join("tests/erc7730-renderer-fixtures/registry");
        let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
            .expect("build ERC-20 capability set");
        let (res, _skips) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &dir,
            &root.join("secure/data/erc7730/policy.toml"),
            None,
            &erc20.capabilities,
        )
        .expect("build synthetic renderer-fixture corpus");
        assert!(
            !res.entries.is_empty(),
            "fixture corpus compiled to nothing - the fixtures or the compiler moved"
        );
        res
    })
}

/// Build a compiler-authenticated C1 `string` descriptor, then coherently
/// change both its authenticated dynamic-kind and terminal-kind TLVs
/// to `bytes`. Production dbgen refuses to emit arbitrary dynamic `bytes`; this
/// process-private fixture proves the device parser independently refuses the
/// now-forbidden `raw` + `DynamicBytes` pair.
fn opaque_bytes_runtime_fixture() -> &'static Vec<u8> {
    static FIXTURE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let temp_root = std::env::temp_dir().join(format!(
            "pqsigner-erc7730-opaque-bytes-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).expect("create opaque-bytes fixture dir");
        let source = temp_root.join("opaque-bytes-runtime.json");
        std::fs::write(
            &source,
            r#"{
              "context": { "contract": { "deployments": [
                { "chainId": 1, "address": "0xbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc" }
              ] } },
              "metadata": { "owner": "Test", "contractName": "Runtime Belt" },
              "display": { "formats": {
                "probe(string data)": {
                  "intent": "Probe",
                  "fields": [
                    { "path": "data", "label": "Data", "format": "raw", "visible": "always" }
                  ]
                }
              } }
            }"#,
        )
        .expect("write opaque-bytes fixture");
        let mut emitted = dbgen::erc7730::try_compile_one(
            &source,
            &dbgen::erc7730::Policy::default(),
            Some(&temp_root),
        )
        .expect("safe string source compiles");
        let mut ir_bytes = emitted
            .pop()
            .expect("one deployment emits one leaf")
            .ir_bytes;
        let tag = pqsigner_erc7730::render::params::PARAM_DYNAMIC_KIND;
        let string_kind = pqsigner_erc7730::render::params::DYNAMIC_KIND_STRING;
        let bytes_kind = pqsigner_erc7730::render::params::DYNAMIC_KIND_BYTES;
        let pattern = [tag, 1, string_kind];
        let hits: Vec<usize> = (pqsigner_erc7730::ir::HEADER_LEN..ir_bytes.len().saturating_sub(2))
            .filter(|&i| ir_bytes[i..i + 3] == pattern)
            .collect();
        assert_eq!(hits.len(), 1, "fixture must have one dynamic-kind TLV");
        ir_bytes[hits[0] + 2] = bytes_kind;
        let terminal_tag = pqsigner_erc7730::render::params::PARAM_TERMINAL_KIND;
        let string_terminal = pqsigner_erc7730::render::policy::TerminalKind::DynamicString as u8;
        let bytes_terminal = pqsigner_erc7730::render::policy::TerminalKind::DynamicBytes as u8;
        let terminal_pattern = [terminal_tag, 1, string_terminal];
        let terminal_hits: Vec<usize> = (pqsigner_erc7730::ir::HEADER_LEN
            ..ir_bytes.len().saturating_sub(2))
            .filter(|&i| ir_bytes[i..i + 3] == terminal_pattern)
            .collect();
        assert_eq!(
            terminal_hits.len(),
            1,
            "fixture must have one terminal-kind TLV"
        );
        ir_bytes[terminal_hits[0] + 2] = bytes_terminal;
        let _ = std::fs::remove_dir_all(&temp_root);
        ir_bytes
    })
}

fn assert_opaque_bytes_runtime_rejected(data: &[u8]) {
    // Keep a realistically framed payload so these tests still cover both
    // printable and binary attacker inputs. Schema v4 refuses the descriptor
    // before payload-dependent rendering, which is stronger than the former
    // formatter-only belt and cannot create a lossy preview.
    let _calldata = calldata_sole_bytes(b"probe(string)", data);
    assert!(
        matches!(
            Erc7730Ir::parse(opaque_bytes_runtime_fixture()),
            Err(pqsigner_erc7730::ir::IrError::BadField)
        ),
        "raw DynamicBytes must fail authenticated-IR admission"
    );
}

fn assert_registry_source_excluded(source_name: &str) {
    assert!(
        !build_registry().entries.iter().any(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        }),
        "unsafe or incomplete descriptor {source_name} must remain absent from the catalogue"
    );
}

#[test]
fn unenrolled_eip712_hash_only_values_have_no_verified_runtime_leaf() {
    let registry = build_registry();
    for source_name in ["eip712-withdraw.json"] {
        assert!(
            !registry.entries.iter().any(|entry| {
                entry.source.file_name().and_then(|n| n.to_str()) == Some(source_name)
            }),
            "{source_name} contains visible EIP-712 dynamic strings whose encodeData words are \
             hashes, not values, and has no exact schema-v6 enrollment; catalogue absence is \
             required so no verified descriptor can reach the secure renderer"
        );
    }
}

#[test]
fn explicit_hidden_material_descriptors_have_no_verified_runtime_leaf() {
    for source_name in [
        "eip712-permit-ethereum-link.json",
        "eip712-UniswapX-ExclusiveDutchOrder.json",
        "eip712-UniswapX-DutchOrder.json",
        "eip712-UniswapX-LimitOrder.json",
        "eip712-uniswap-V2DutchOrder.json",
    ] {
        assert_registry_source_excluded(source_name);
    }
}

/// Locate a leaf by `(source filename, chain_id)` so a multi-chain
/// descriptor (USDT on mainnet vs Polygon) is unambiguous.
pub(super) fn find_leaf<'a>(
    res: &'a dbgen::erc7730::Erc7730BuildResult,
    source_name: &str,
    chain_id: u64,
) -> &'a dbgen::erc7730::Emitted {
    res.entries
        .iter()
        .find(|e| {
            e.chain_id == chain_id
                && e.source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n == source_name)
        })
        .unwrap_or_else(|| {
            panic!(
                "no leaf for {source_name} on chain {chain_id}; entries: {:?}",
                res.entries
                    .iter()
                    .map(|e| (e.source.display().to_string(), e.chain_id))
                    .collect::<Vec<_>>()
            )
        })
}

/// Permit2's three fully visible formats are production catalogue entries.
/// Renderer conformance must therefore use the exact Merkle-root-bound leaf,
/// never a process-private descriptor rewrite that can drift from shipping.
fn production_permit2_leaf(chain_id: u64) -> &'static dbgen::erc7730::Emitted {
    find_leaf(build_registry(), "eip712-uniswap-permit2.json", chain_id)
}

/// Reconstruct the bundle the companion would ship for the on-wire
/// verifier. Mirrors `dbgen/tests/erc7730_roundtrip.rs::synth_bundle`
/// (kept inline here so this module doesn't depend on the dbgen test
/// helpers).
pub(super) fn synth_bundle(blob: &[u8], ir_bytes: &[u8], leaf_index: usize) -> Vec<u8> {
    let proof_depth = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_base = proofs_off + leaf_index * proof_depth * 32;

    let mut buf = Vec::with_capacity(2 + ir_bytes.len() + 4 + 4 + proof_depth * 32);
    buf.extend_from_slice(&(ir_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir_bytes);
    buf.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    buf.extend_from_slice(&(proof_depth as u32).to_be_bytes());
    for j in 0..proof_depth {
        let off = proof_base + j * 32;
        buf.extend_from_slice(&blob[off..off + 32]);
    }
    buf
}

// ───────────────────────────────────────────────────────────────────────
// Tx + calldata builders.
// ───────────────────────────────────────────────────────────────────────

fn u256_from_u64(n: u64) -> U256 {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

fn u256_from_u128(n: u128) -> U256 {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

/// "Approve max" — the value that triggers the unlimited-amount branch
/// in tokenAmount rendering against the descriptor's threshold param.
fn u256_max() -> U256 {
    U256([0xFFu8; 32])
}

/// Plain receiver-tx envelope. ERC-7730 path expects `tx.to ==
/// descriptor.contract`; the caller fills `to` with the real contract
/// address per-test.
pub(super) fn envelope(chain_id: u64, contract: [u8; 20]) -> Eip1559Tx {
    let mut tx = Eip1559Tx::default();
    tx.chain_id = chain_id;
    tx.nonce = 7;
    tx.to = Some(contract);
    tx.value = U256::default();
    tx.gas_limit = 100_000;
    tx.max_fee_per_gas = u256_from_u64(30_000_000_000);
    tx.max_priority_fee_per_gas = u256_from_u64(1_500_000_000);
    tx
}

/// ERC-20 `transfer(address,uint256)` calldata.
fn calldata_transfer(to: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    let mut to_padded = [0u8; 32];
    to_padded[12..].copy_from_slice(&to);
    data.extend_from_slice(&to_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// ERC-20 `approve(address,uint256)` calldata.
fn calldata_approve(spender: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    let mut sp_padded = [0u8; 32];
    sp_padded[12..].copy_from_slice(&spender);
    data.extend_from_slice(&sp_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// `WETH9.deposit()` — zero-argument call. The amount the user is
/// wrapping is `@.value` (envelope's `value`), which the descriptor
/// pulls from the container path.
fn calldata_deposit() -> Vec<u8> {
    vec![0xd0, 0xe3, 0x0d, 0xb0]
}

/// Canonical WETH9 `withdraw(uint256)` calldata. The amount is a full-width
/// unsigned word, so every one of its 32 bytes is effect-bearing.
fn calldata_weth_withdraw(amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&[0x2e, 0x1a, 0x7d, 0x4d]);
    data.extend_from_slice(&amount.0);
    data
}

/// Aave V3 `borrow(address asset, uint256 amount, uint256 interestRateMode,
/// uint16 referralCode, address onBehalfOf)` — all-static 5-word head.
/// Used to exercise the `enum` formatter on `interestRateMode`.
fn calldata_borrow(
    asset: [u8; 20],
    amount: U256,
    interest_rate_mode: U256,
    referral_code: u16,
    on_behalf_of: [u8; 20],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 5 * 32);
    let sel = keccak256(b"borrow(address,uint256,uint256,uint16,address)");
    data.extend_from_slice(&sel[..4]);
    let mut asset_w = [0u8; 32];
    asset_w[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_w);
    data.extend_from_slice(&amount.0);
    data.extend_from_slice(&interest_rate_mode.0);
    let mut ref_w = [0u8; 32];
    ref_w[30..].copy_from_slice(&referral_code.to_be_bytes());
    data.extend_from_slice(&ref_w);
    let mut obo_w = [0u8; 32];
    obo_w[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&obo_w);
    data
}

/// Aave V3 `deposit` / `supply` share the same static argument layout and
/// differ only by selector.
fn calldata_aave_supply_like(
    text_signature: &[u8],
    asset: [u8; 20],
    amount: U256,
    on_behalf_of: [u8; 20],
    referral_code: u16,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 4 * 32);
    let selector = keccak256(text_signature);
    data.extend_from_slice(&selector[..4]);
    let mut asset_word = [0u8; 32];
    asset_word[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_word);
    data.extend_from_slice(&amount.0);
    let mut recipient_word = [0u8; 32];
    recipient_word[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&recipient_word);
    let mut referral_word = [0u8; 32];
    referral_word[30..].copy_from_slice(&referral_code.to_be_bytes());
    data.extend_from_slice(&referral_word);
    data
}

/// Aave V3 `repay(address asset,uint256 amount,uint256 interestRateMode,
/// address onBehalfOf)` — an all-visible format that retains an independent
/// enum-table control alongside the curated `borrow` format.
fn calldata_repay(
    asset: [u8; 20],
    amount: U256,
    interest_rate_mode: U256,
    on_behalf_of: [u8; 20],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 4 * 32);
    let sel = keccak256(b"repay(address,uint256,uint256,address)");
    data.extend_from_slice(&sel[..4]);
    let mut asset_w = [0u8; 32];
    asset_w[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_w);
    data.extend_from_slice(&amount.0);
    data.extend_from_slice(&interest_rate_mode.0);
    let mut obo_w = [0u8; 32];
    obo_w[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&obo_w);
    data
}

fn abi_address_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address);
    word
}

fn abi_u16_word(value: u16) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[30..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Canonical all-static ABI call used by the production-catalogue semantic
/// tests below. Tuple components are supplied already flattened into their
/// 32-byte ABI words, matching Solidity's encoding for an all-static tuple.
fn calldata_static(text_signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let selector = keccak256(text_signature.as_bytes());
    let mut calldata = Vec::with_capacity(4 + words.len() * 32);
    calldata.extend_from_slice(&selector[..4]);
    for word in words {
        calldata.extend_from_slice(word);
    }
    calldata
}

/// Re-confirm the function selector we synthesised actually keccaks to
/// what the descriptor expects. Catches a "we mis-built the calldata"
/// bug before the renderer ever sees it. Mirrors the firmware's own
/// selector dispatch.
fn assert_selector_matches(ir: &Erc7730Ir<'_>, calldata: &[u8], text_sig: &str) {
    let sel = keccak256(text_sig.as_bytes());
    assert_eq!(
        &sel[..4],
        &calldata[..4],
        "test bug: calldata selector != keccak256({text_sig:?})[..4]"
    );
    let key: [u8; 4] = calldata[..4].try_into().unwrap();
    ir.find_format_by_selector(&key)
        .expect("ir format table well-formed")
        .unwrap_or_else(|| panic!("no format for {text_sig:?} in descriptor"));
}

/// Assert that a source admitted for other safe formats still omits this exact
/// selector. The production known-call gate then turns the omitted format into
/// a hard refusal rather than falling through to a generic semantic render.
fn assert_selector_excluded(ir: &Erc7730Ir<'_>, text_sig: &str) {
    let selector = keccak256(text_sig.as_bytes());
    let key: [u8; 4] = selector[..4].try_into().unwrap();
    assert!(
        ir.find_format_by_selector(&key)
            .expect("IR format table well-formed")
            .is_none(),
        "unsafe or incomplete format {text_sig:?} must remain absent from the admitted descriptor"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Row assertion helpers — string-trim then compare.
// ───────────────────────────────────────────────────────────────────────

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    String::from_utf8(row[..end].to_vec()).expect("rendered rows must be printable ASCII")
}

fn page_strs(pages: &Pages, page: usize) -> [String; 4] {
    let p = &pages.buf[page];
    [
        row_str(&p[0]),
        row_str(&p[1]),
        row_str(&p[2]),
        row_str(&p[3]),
    ]
}

/// Index of the semantic intent page in either catalogue-provenance mode.
///
/// Dev-unattested firmware prepends a mandatory warning page. Keep the same
/// semantic assertions useful in both builds, while also proving that the
/// warning has the exact trusted-display text whenever the feature is active.
fn intent_page_index(pages: &Pages) -> usize {
    let index = pqsigner_erc7730::display::render::intent::INTENT_BANNER_PAGES - 1;
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        assert_eq!(
            page_strs(pages, 0),
            [
                "** DEV BUILD **".to_string(),
                "Unattested".to_string(),
                "descriptor".to_string(),
                "> next".to_string(),
            ]
        );
    }
    index
}

fn dump_pages(pages: &Pages) -> String {
    let mut out = String::new();
    for (i, page) in pages.as_slice().iter().enumerate() {
        out.push_str(&format!("--- page {i} ---\n"));
        for row in page.iter() {
            out.push_str(&format!("| {} |\n", row_str(row)));
        }
    }
    out
}

fn assert_all_pages_printable(pages: &Pages) {
    for (p, page) in pages.as_slice().iter().enumerate() {
        for (r, row) in page.iter().enumerate() {
            for (c, &b) in row.iter().enumerate() {
                assert!(
                    (0x20..=0x7E).contains(&b),
                    "page {p} row {r} col {c} byte {:#x} not printable\n{}",
                    b,
                    dump_pages(pages),
                );
            }
        }
    }
}

/// Find the first page whose row 0 trims to exactly `label`. Used to
/// locate a field page when the field-order is descriptor-driven and a
/// test doesn't want to over-pin on page indices.
fn find_page_by_label(pages: &Pages, label: &str) -> usize {
    for (i, page) in pages.as_slice().iter().enumerate() {
        if row_str(&page[0]) == label {
            return i;
        }
    }
    panic!(
        "no page with row 0 == {label:?}; full dump:\n{}",
        dump_pages(pages)
    );
}

fn assert_raw_word_pages(pages: &Pages, label: &str, word: &[u8; 32]) {
    assert_nth_raw_word_pages(pages, label, 0, word);
}

/// Assert a descriptor-authenticated constant annotation without relying on a
/// substring search. Long constants occupy complete three-row chunks; this
/// reconstructs every byte and also catches a missing or duplicated page.
fn assert_constant_text_field_pages(pages: &Pages, label: &str, value: &str) {
    let actual: Vec<usize> = pages
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, page)| (row_str(&page[0]) == label).then_some(index))
        .collect();
    let expected_chunks: Vec<&[u8]> = value.as_bytes().chunks(3 * DISPLAY_COLS).collect();
    assert_eq!(
        actual.len(),
        expected_chunks.len(),
        "constant field {label:?} page count; full dump:\n{}",
        dump_pages(pages)
    );
    for (index, chunk) in actual.into_iter().zip(expected_chunks) {
        let mut expected = [[b' '; DISPLAY_COLS]; 4];
        expected[0][..label.len()].copy_from_slice(label.as_bytes());
        for (row, bytes) in chunk.chunks(DISPLAY_COLS).enumerate() {
            expected[row + 1][..bytes.len()].copy_from_slice(bytes);
        }
        assert_eq!(pages.buf[index], expected);
    }
}

/// Long intents are split over the first two rows. Reassemble them so tests
/// pin the complete semantic title instead of accepting a reassuring prefix.
fn assert_complete_intent(pages: &Pages, expected: &str) {
    let rows = page_strs(pages, intent_page_index(pages));
    assert_eq!(format!("{}{}", rows[0], rows[1]), expected);
}

fn assert_nth_raw_word_pages(pages: &Pages, label: &str, occurrence: usize, word: &[u8; 32]) {
    let first = pages
        .as_slice()
        .iter()
        .enumerate()
        .filter(|(_, page)| row_str(&page[0]) == label && row_str(&page[3]) == "1/2 > next")
        .nth(occurrence)
        .map(|(index, _)| index)
        .unwrap_or_else(|| {
            panic!(
                "no raw-word occurrence {occurrence} for {label:?}; full dump:\n{}",
                dump_pages(pages)
            )
        });
    assert!(first + 1 < pages.len, "raw word lacks its second page");
    let encoded = hex::encode(word);
    assert_eq!(
        page_strs(pages, first),
        [
            label.to_string(),
            encoded[0..16].to_string(),
            encoded[16..32].to_string(),
            "1/2 > next".to_string(),
        ]
    );
    assert_eq!(
        page_strs(pages, first + 1),
        [
            label.to_string(),
            encoded[32..48].to_string(),
            encoded[48..64].to_string(),
            "2/2 > next".to_string(),
        ]
    );
}

fn assert_full_address_field_page(pages: &Pages, label: &str, address: &[u8; 20]) {
    let page = find_page_by_label(pages, label);
    let mut expected = [[b' '; DISPLAY_COLS]; 4];
    expected[0][..label.len()].copy_from_slice(label.as_bytes());
    let [_, r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, address);
    assert_eq!(
        pages.buf[page], expected,
        "address field must show every signed address byte"
    );
}

fn assert_full_contract_identity_page(pages: &Pages, contract: &[u8; 20]) {
    let page = find_page_by_label(pages, "Token contract");
    let mut expected = [[b' '; DISPLAY_COLS]; 4];
    expected[0][..14].copy_from_slice(b"Token contract");
    let [_, r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, contract);
    assert_eq!(
        pages.buf[page], expected,
        "trusted pages must carry the exact bound token contract"
    );
}

fn assert_full_unverified_token_identity_page(pages: &Pages, contract: &[u8; 20]) {
    let page = find_page_by_label(pages, "Token (UNVERIFI~");
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, contract);
    assert_eq!(
        pages.buf[page][1..4],
        expected,
        "unbound token pages must carry the exact signed token contract"
    );
}

fn assert_some_full_unverified_token_identity_page(pages: &Pages, contract: &[u8; 20]) {
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, contract);
    assert!(
        pages
            .as_slice()
            .iter()
            .any(|page| { row_str(&page[0]) == "Token (UNVERIFI~" && page[1..4] == expected }),
        "unbound token pages must carry exact signed token contract 0x{}\n{}",
        hex::encode(contract),
        dump_pages(pages)
    );
}

fn find_full_nft_collection_page(pages: &Pages, collection: &[u8; 20]) -> usize {
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, collection);
    pages
        .as_slice()
        .iter()
        .position(|page| page[1..4] == expected)
        .unwrap_or_else(|| {
            panic!(
                "no page carries full NFT collection {}; dump:\n{}",
                hex::encode(collection),
                dump_pages(pages)
            )
        })
}

// ───────────────────────────────────────────────────────────────────────
// Per-corpus tests. One per representative descriptor + format.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_seed_corpus_compiles() {
    // `secure/data/erc7730/` is now a synthetic-only render-test corpus: the
    // protocol fixtures that used to live here were duplicates of the vendored
    // registry (the PROD corpus, exercised via `build_registry()` in the
    // repointed render tests). Only the synthetic non-registry fixtures remain,
    // so the floor is ≥1.
    let res = build_seed();
    assert!(
        res.leaf_count >= 1,
        "seed corpus has shrunk below the sanity floor ({} leaves)",
        res.leaf_count
    );
}

#[test]
#[ignore = "diagnostic — run with `--ignored` to dump the seed-corpus IR layout"]
fn diagnostic_dump_seed_corpus_path_offsets() {
    let res = build_seed();
    for entry in &res.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("seed IR parses");
        eprintln!(
            "== {} chain={} ctx={:?}",
            entry.source.display(),
            entry.chain_id,
            ir.context_kind
        );
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header");
            let sel = fmt.selector;
            eprintln!(
                "  fmt sel=0x{:02x}{:02x}{:02x}{:02x} intent={:?}",
                sel[0],
                sel[1],
                sel[2],
                sel[3],
                core::str::from_utf8(fmt.intent).unwrap_or("?")
            );
            for field in fmt.fields() {
                let field = field.expect("field");
                eprintln!(
                    "    field op={:#04x} label={:?} path_off={} param_off={}",
                    field.format_op,
                    core::str::from_utf8(field.label).unwrap_or("?"),
                    field.path_off,
                    field.param_off
                );
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// `path_off == 0` collision fix landed in `dbgen::erc7730::Pool::new`:
// the pool now reserves byte 0 with a 1-byte filler so the first
// interned path program lands at offset 1. The on-device walker and
// renderer's `path_off == 0` / `param_off == 0` "no path" sentinels
// stay intact, and the descriptors that previously fell through to
// blind-sign (weth.deposit, tether-usdt.transfer/approve, and the
// accepted Aave/Circle formats) now render their full clear-sign page
// sequence. Incomplete Aave formats remain known-call refusals.
//
// The three tests below assert the user-visible display text end-to-end.

#[test]
fn positive_registry_celo_from_uses_explicit_device_signer() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let calldata = keccak256(b"createAccount()")[..4].to_vec();
    assert_selector_matches(&verified.ir, &calldata, "createAccount()");
    let tx = envelope(42220, entry.contract);
    let resolver = NameResolver::new();

    assert!(matches!(
        render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 from unbound"
        ))
    ));

    let sender = [0x12u8; 20];
    let pages =
        render_erc7730_pages_with_signer(&tx, &calldata, &verified, None, &resolver, &sender)
            .expect("Celo @.from renders from the device signer");
    let field_page = intent_page_index(&pages) + 1;
    assert_eq!(page_strs(&pages, field_page)[0], "Account Owner");
    assert_eq!(&pages.buf[field_page][1], b"0x12121212121212");
    assert_eq!(&pages.buf[field_page][2], b"1212121212121212");
    assert_eq!(&pages.buf[field_page][3][..10], b"1212121212");
}

#[test]
fn production_celo_lockedgold_proxy_renders_and_binds_all_six_routes() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-locked_celo.json", 42_220);
    let proxy: [u8; 20] = hex::decode("6cc083aed9e3ebe302a6336dbc7c921c9f03349e")
        .expect("canonical Celo proxy")
        .try_into()
        .expect("address width");
    assert_eq!(entry.contract, proxy);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Celo leaf");
    assert_eq!(verified.ir.format_count(), Ok(6));

    let resolver = NameResolver::new();
    let signer = [0x42u8; 20];
    let render = |signature: &str, words: &[[u8; 32]], value: U256, from: &[u8; 20]| {
        let calldata = calldata_static(signature, words);
        assert_selector_matches(&verified.ir, &calldata, signature);
        let mut tx = envelope(42_220, entry.contract);
        tx.value = value;
        render_erc7730_pages_with_signer(&tx, &calldata, &verified, None, &resolver, from)
    };

    let lock_value = u256_from_u128(2_500_000_000_000_000_000);
    let lock = render("lock()", &[], lock_value, &signer).expect("lock renders");
    let lock_text = dump_pages(&lock);
    assert!(lock_text.contains("Lock CELO"), "{lock_text}");
    assert!(lock_text.contains("Amount to Lock"), "{lock_text}");
    assert!(lock_text.contains("2.5 CELO"), "{lock_text}");
    assert!(lock_text.contains("Acting Account"), "{lock_text}");
    let changed_lock = render(
        "lock()",
        &[],
        u256_from_u128(2_600_000_000_000_000_000),
        &signer,
    )
    .expect("changed lock renders");
    assert_ne!(lock.as_slice(), changed_lock.as_slice());
    let changed_signer =
        render("lock()", &[], lock_value, &[0x43u8; 20]).expect("changed acting account renders");
    assert_ne!(lock.as_slice(), changed_signer.as_slice());

    let unlock_amount = u256_from_u128(3_000_000_000_000_000_000);
    let unlock = render(
        "unlock(uint256)",
        &[unlock_amount.0],
        U256::default(),
        &signer,
    )
    .expect("unlock renders");
    let unlock_text = dump_pages(&unlock);
    assert!(unlock_text.contains("Amount to Unlock"), "{unlock_text}");
    assert!(unlock_text.contains("3 CELO"), "{unlock_text}");
    let changed_unlock = render(
        "unlock(uint256)",
        &[u256_from_u128(4_000_000_000_000_000_000).0],
        U256::default(),
        &signer,
    )
    .expect("changed unlock renders");
    assert_ne!(unlock.as_slice(), changed_unlock.as_slice());

    let relock_index = u256_from_u64(7);
    let relock_amount = u256_from_u128(1_500_000_000_000_000_000);
    let relock = render(
        "relock(uint256,uint256)",
        &[relock_index.0, relock_amount.0],
        U256::default(),
        &signer,
    )
    .expect("relock renders");
    let relock_text = dump_pages(&relock);
    assert!(relock_text.contains("Amount to Relock"), "{relock_text}");
    assert!(relock_text.contains("1.5 CELO"), "{relock_text}");
    assert!(relock_text.contains("Withdrawal Index"), "{relock_text}");
    let changed_relock_index = render(
        "relock(uint256,uint256)",
        &[u256_from_u64(8).0, relock_amount.0],
        U256::default(),
        &signer,
    )
    .expect("changed relock index renders");
    let changed_relock_amount = render(
        "relock(uint256,uint256)",
        &[relock_index.0, u256_from_u128(1_600_000_000_000_000_000).0],
        U256::default(),
        &signer,
    )
    .expect("changed relock amount renders");
    assert_ne!(relock.as_slice(), changed_relock_index.as_slice());
    assert_ne!(relock.as_slice(), changed_relock_amount.as_slice());

    let withdraw = render(
        "withdraw(uint256)",
        &[relock_index.0],
        U256::default(),
        &signer,
    )
    .expect("withdraw renders");
    let withdraw_text = dump_pages(&withdraw);
    assert!(
        withdraw_text.contains("Claim Withdrawal"),
        "{withdraw_text}"
    );
    assert!(
        withdraw_text.contains("Withdrawal Index"),
        "{withdraw_text}"
    );
    assert!(
        !withdraw_text.contains("Amount to"),
        "live storage amount must not masquerade as signed calldata: {withdraw_text}"
    );
    let changed_withdraw = render(
        "withdraw(uint256)",
        &[u256_from_u64(8).0],
        U256::default(),
        &signer,
    )
    .expect("changed withdrawal index renders");
    assert_ne!(withdraw.as_slice(), changed_withdraw.as_slice());

    let delegatee = [0x11u8; 20];
    let target_share = u256_from_u128(250_000_000_000_000_000_000_000);
    let delegate = render(
        "delegateGovernanceVotes(address,uint256)",
        &[abi_address_word(delegatee), target_share.0],
        U256::default(),
        &signer,
    )
    .expect("delegation renders");
    let delegate_text = dump_pages(&delegate);
    assert!(delegate_text.contains("Target Share %"), "{delegate_text}");
    assert!(delegate_text.contains("25 %"), "{delegate_text}");
    assert!(delegate_text.contains("Delegatee"), "{delegate_text}");
    let changed_delegatee = render(
        "delegateGovernanceVotes(address,uint256)",
        &[abi_address_word([0x12u8; 20]), target_share.0],
        U256::default(),
        &signer,
    )
    .expect("changed delegatee renders");
    let changed_target = render(
        "delegateGovernanceVotes(address,uint256)",
        &[
            abi_address_word(delegatee),
            u256_from_u128(260_000_000_000_000_000_000_000).0,
        ],
        U256::default(),
        &signer,
    )
    .expect("changed target share renders");
    assert_ne!(delegate.as_slice(), changed_delegatee.as_slice());
    assert_ne!(delegate.as_slice(), changed_target.as_slice());

    let revoke_share = u256_from_u128(100_000_000_000_000_000_000_000);
    let revoke = render(
        "revokeDelegatedGovernanceVotes(address,uint256)",
        &[abi_address_word(delegatee), revoke_share.0],
        U256::default(),
        &signer,
    )
    .expect("revoke renders");
    let revoke_text = dump_pages(&revoke);
    assert!(revoke_text.contains("Revoke Share %"), "{revoke_text}");
    assert!(revoke_text.contains("10 %"), "{revoke_text}");
    let changed_revoke = render(
        "revokeDelegatedGovernanceVotes(address,uint256)",
        &[
            abi_address_word(delegatee),
            u256_from_u128(110_000_000_000_000_000_000_000).0,
        ],
        U256::default(),
        &signer,
    )
    .expect("changed revoke share renders");
    assert_ne!(revoke.as_slice(), changed_revoke.as_slice());

    let adjacent_share = u256_from_u128(250_000_000_000_000_000_000_001);
    let adjacent = render(
        "delegateGovernanceVotes(address,uint256)",
        &[abi_address_word(delegatee), adjacent_share.0],
        U256::default(),
        &signer,
    )
    .expect("the adjacent target-share base unit renders exactly");
    let adjacent_rows = page_strs(&adjacent, find_page_by_label(&adjacent, "Target Share %"));
    assert_eq!(adjacent_rows[1], "25.0000000000000");
    assert_eq!(adjacent_rows[2], "000000001 %");
    assert_ne!(delegate.as_slice(), adjacent.as_slice());

    let mut dirty_delegatee = abi_address_word(delegatee);
    dirty_delegatee[0] = 1;
    assert!(render(
        "delegateGovernanceVotes(address,uint256)",
        &[dirty_delegatee, target_share.0],
        U256::default(),
        &signer,
    )
    .is_err());
}

#[test]
fn production_celo_election_vote_renders_all_signed_operands_mainnet_only() {
    const SIGNATURE: &str = "vote(address,uint256,address,address)";
    const MAINNET_CHAIN: u64 = 42_220;
    const ALFAJORES_CHAIN: u64 = 44_787;
    const VOTE_SELECTOR: [u8; 4] = [0x58, 0x0d, 0x74, 0x7a];

    let registry = build_registry();
    let mainnet = find_leaf(registry, "calldata-celo_election.json", MAINNET_CHAIN);
    let mainnet_proxy: [u8; 20] = hex::decode("8d6677192144292870907e3fa8a5527fe55a7ff6")
        .expect("canonical Election proxy")
        .try_into()
        .expect("address width");
    assert_eq!(mainnet.contract, mainnet_proxy);
    let mainnet_bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let mainnet_verified = verify_erc7730_bundle(&mainnet_bundle, &registry.root)
        .expect("verify mainnet Election leaf");
    cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &mainnet.contract)
        .expect("bind mainnet Election leaf");
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, ALFAJORES_CHAIN, &mainnet.contract),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));

    let admitted: std::collections::BTreeSet<[u8; 4]> = mainnet_verified
        .ir
        .format_iter()
        .map(|format| format.expect("Election format parses").selector)
        .collect();
    let expected: std::collections::BTreeSet<[u8; 4]> = [
        "activate(address)",
        "activateForAccount(address,address)",
        "revokeActive(address,uint256,address,address,uint256)",
        "revokeAllActive(address,address,address,uint256)",
        "revokePending(address,uint256,address,address,uint256)",
        SIGNATURE,
    ]
    .iter()
    .map(|signature| keccak256(signature.as_bytes())[..4].try_into().unwrap())
    .collect();
    assert_eq!(mainnet_verified.ir.format_count(), Ok(6));
    assert_eq!(admitted, expected);
    assert_eq!(&keccak256(SIGNATURE.as_bytes())[..4], &VOTE_SELECTOR);

    let group = [0x11; 20];
    let lesser = [0x22; 20];
    let greater = [0x33; 20];
    let vote_value = u256_from_u128(2_500_000_000_000_000_000);
    let words = [
        abi_address_word(group),
        vote_value.0,
        abi_address_word(lesser),
        abi_address_word(greater),
    ];
    let calldata = calldata_static(SIGNATURE, &words);
    assert_eq!(&calldata[..4], &VOTE_SELECTOR);
    assert_selector_matches(&mainnet_verified.ir, &calldata, SIGNATURE);

    let tx = envelope(MAINNET_CHAIN, mainnet.contract);
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let render = |candidate_words: &[[u8; 32]; 4]| {
        let candidate = calldata_static(SIGNATURE, candidate_words);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &candidate,
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        )
    };

    let baseline = render(&words).expect("mainnet Election vote renders");
    assert_eq!(
        baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(
        baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0),
        "the receipt must bind every trusted Election page"
    );
    assert_all_pages_printable(&baseline.pages);
    assert_eq!(
        page_strs(&baseline.pages, intent_page_index(&baseline.pages))[0],
        "Vote"
    );
    assert_full_address_field_page(&baseline.pages, "Validator Group", &group);
    assert_eq!(
        page_strs(
            &baseline.pages,
            find_page_by_label(&baseline.pages, "CELO to Vote")
        ),
        [
            "CELO to Vote".to_string(),
            "2.5 CELO".to_string(),
            String::new(),
            "> next".to_string(),
        ]
    );
    assert_full_address_field_page(&baseline.pages, "Fewer-Vote Hint", &lesser);
    assert_full_address_field_page(&baseline.pages, "More-Vote Hint", &greater);

    let mut changed_group = group;
    changed_group[19] ^= 1;
    let changed_amount = u256_from_u128(3_000_000_000_000_000_000);
    let mut changed_lesser = lesser;
    changed_lesser[19] ^= 1;
    let mut changed_greater = greater;
    changed_greater[19] ^= 1;
    for (word_index, changed_word, operand) in [
        (0usize, abi_address_word(changed_group), "group"),
        (1usize, changed_amount.0, "value"),
        (2usize, abi_address_word(changed_lesser), "lesser"),
        (3usize, abi_address_word(changed_greater), "greater"),
    ] {
        let mut mutated_words = words;
        mutated_words[word_index] = changed_word;
        let mutated = render(&mutated_words)
            .unwrap_or_else(|error| panic!("render independently mutated {operand}: {error:?}"));
        assert_ne!(
            baseline.pages.as_slice(),
            mutated.pages.as_slice(),
            "changing only {operand} must change trusted pages"
        );
        assert!(
            !baseline
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "changing only {operand} must change the transcript receipt"
        );
    }

    let zero_hint_words = [
        abi_address_word(group),
        vote_value.0,
        abi_address_word([0u8; 20]),
        abi_address_word([0u8; 20]),
    ];
    let zero_hints = render(&zero_hint_words).expect("zero list-end hints render literally");
    assert_full_address_field_page(&zero_hints.pages, "Fewer-Vote Hint", &[0u8; 20]);
    assert_full_address_field_page(&zero_hints.pages, "More-Vote Hint", &[0u8; 20]);

    for word_index in [0usize, 2, 3] {
        let mut dirty_words = words;
        dirty_words[word_index][0] = 1;
        assert!(
            render(&dirty_words).is_err(),
            "dirty high address padding in word {word_index} must refuse"
        );
    }
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata[..calldata.len() - 1],
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 short head"
        ))
    ));
    let mut trailing = calldata.clone();
    trailing.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &trailing,
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));

    let mut mainnet_proofs = DispatchPageProofs::new();
    mainnet_proofs.fail_initialize();
    let mut dispatched = pick_sign_pages(
        &tx,
        &calldata,
        &signer,
        None,
        None,
        None,
        Some(&mainnet_verified),
        None,
        None,
        &resolver,
        &mut mainnet_proofs,
    )
    .expect("dispatcher selects the mainnet Election vote descriptor");
    assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());
    let mut verdict = crate::fi::FAIL_SENTINEL;
    mainnet_proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_eq!(verdict, crate::fi::OK_SENTINEL);
    dispatched.buf[find_page_by_label(&dispatched, "Validator Group")][1][0] ^= 1;
    verdict = crate::fi::FAIL_SENTINEL;
    mainnet_proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_ne!(
        verdict,
        crate::fi::OK_SENTINEL,
        "corrupting one visible vote byte must invalidate the dispatcher proof"
    );

    let alfajores = find_leaf(registry, "calldata-celo_election.json", ALFAJORES_CHAIN);
    let alfajores_proxy: [u8; 20] = hex::decode("1c3edf937cfc2f6f51784d20deb1af1f9a8655fa")
        .expect("Alfajores Election proxy")
        .try_into()
        .expect("address width");
    assert_eq!(alfajores.contract, alfajores_proxy);
    let alfajores_bundle = synth_bundle(&registry.blob, &alfajores.ir_bytes, alfajores.leaf_index);
    let alfajores_verified = verify_erc7730_bundle(&alfajores_bundle, &registry.root)
        .expect("verify Alfajores Election leaf");
    cross_check_contract(&alfajores_verified.ir, ALFAJORES_CHAIN, &alfajores.contract)
        .expect("bind Alfajores Election leaf");
    assert_eq!(alfajores_verified.ir.format_count(), Ok(2));
    assert_selector_excluded(&alfajores_verified.ir, SIGNATURE);
    assert!(
        registry
            .known_calls
            .contains(&(ALFAJORES_CHAIN, alfajores.contract, VOTE_SELECTOR)),
        "Alfajores vote stays exact-known even though its format is refused"
    );
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &registry.known_calls_bloom,
        ALFAJORES_CHAIN,
        &alfajores.contract,
        &VOTE_SELECTOR,
    ));
    let alfajores_tx = envelope(ALFAJORES_CHAIN, alfajores.contract);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &alfajores_tx,
            &calldata,
            &alfajores_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::NoFormat)
    ));
    let mut alfajores_proofs = DispatchPageProofs::new();
    alfajores_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &alfajores_tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&alfajores_verified),
            None,
            None,
            &resolver,
            &mut alfajores_proofs,
        )
        .is_err(),
        "a bound Alfajores descriptor must refuse vote without fallback"
    );
}

#[test]
fn production_celo_validators_add_first_member_renders_all_signed_operands_mainnet_only() {
    const SIGNATURE: &str = "addFirstMember(address,address,address)";
    const MAINNET_CHAIN: u64 = 42_220;
    const ALFAJORES_CHAIN: u64 = 44_787;
    const SELECTOR: [u8; 4] = [0x31, 0x73, 0xb8, 0xdb];

    let registry = build_registry();
    let mainnet = find_leaf(registry, "calldata-celo_validators.json", MAINNET_CHAIN);
    let mainnet_proxy: [u8; 20] = hex::decode("aeb865bca93ddc8f47b8e29f40c5399ce34d0c58")
        .expect("canonical Validators proxy")
        .try_into()
        .expect("address width");
    assert_eq!(mainnet.contract, mainnet_proxy);
    let mainnet_bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let mainnet_verified = verify_erc7730_bundle(&mainnet_bundle, &registry.root)
        .expect("verify mainnet Validators leaf");
    cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &mainnet.contract)
        .expect("bind mainnet Validators leaf");
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, ALFAJORES_CHAIN, &mainnet.contract),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));
    assert_eq!(mainnet_verified.ir.format_count(), Ok(10));
    assert_eq!(&keccak256(SIGNATURE.as_bytes())[..4], &SELECTOR);

    let validator = [0x11; 20];
    let lesser = [0x22; 20];
    let greater = [0x33; 20];
    let words = [
        abi_address_word(validator),
        abi_address_word(lesser),
        abi_address_word(greater),
    ];
    let calldata = calldata_static(SIGNATURE, &words);
    assert_eq!(&calldata[..4], &SELECTOR);
    assert_selector_matches(&mainnet_verified.ir, &calldata, SIGNATURE);

    let tx = envelope(MAINNET_CHAIN, mainnet.contract);
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let render = |candidate_words: &[[u8; 32]; 3]| {
        let candidate = calldata_static(SIGNATURE, candidate_words);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &candidate,
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        )
    };

    let baseline = render(&words).expect("mainnet Validators addFirstMember renders");
    assert_eq!(
        baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(
        baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0),
        "the receipt must bind every trusted Validators page"
    );
    assert_all_pages_printable(&baseline.pages);
    assert_eq!(
        find_page_by_label(&baseline.pages, "Network:")
            - pqsigner_erc7730::display::render::intent::INTENT_BANNER_PAGES,
        5,
        "three signed addresses and two authenticated constants must each get a format-owned page"
    );
    assert_eq!(
        page_strs(&baseline.pages, intent_page_index(&baseline.pages)),
        [
            "Add First Member".to_string(),
            "Celo".to_string(),
            "Celo Validators".to_string(),
            "> next".to_string(),
        ]
    );
    assert_full_address_field_page(&baseline.pages, "First Validator", &validator);
    assert_full_address_field_page(&baseline.pages, "Fewer-Vote Hint", &lesser);
    assert_full_address_field_page(&baseline.pages, "More-Vote Hint", &greater);
    assert_eq!(
        page_strs(
            &baseline.pages,
            find_page_by_label(&baseline.pages, "Effective Group")
        ),
        [
            "Effective Group".to_string(),
            "Signer-Mapped".to_string(),
            String::new(),
            String::new(),
        ]
    );
    assert_eq!(
        page_strs(
            &baseline.pages,
            find_page_by_label(&baseline.pages, "Effect")
        ),
        [
            "Effect".to_string(),
            "Marks Eligible".to_string(),
            String::new(),
            String::new(),
        ]
    );

    for (word_index, operand) in [(0usize, "validator"), (1, "lesser"), (2, "greater")] {
        let mut mutated_words = words;
        mutated_words[word_index][31] ^= 1;
        let mutated = render(&mutated_words)
            .unwrap_or_else(|error| panic!("render independently mutated {operand}: {error:?}"));
        assert_ne!(
            baseline.pages.as_slice(),
            mutated.pages.as_slice(),
            "changing only {operand} must change trusted pages"
        );
        assert!(
            !baseline
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "changing only {operand} must change the transcript receipt"
        );
    }

    let zero_hint_words = [
        abi_address_word(validator),
        abi_address_word([0u8; 20]),
        abi_address_word([0u8; 20]),
    ];
    let zero_hints = render(&zero_hint_words).expect("zero list-end hints render literally");
    assert_full_address_field_page(&zero_hints.pages, "Fewer-Vote Hint", &[0u8; 20]);
    assert_full_address_field_page(&zero_hints.pages, "More-Vote Hint", &[0u8; 20]);

    for (word_index, operand) in [(0usize, "validator"), (1, "lesser"), (2, "greater")] {
        let mut dirty_words = words;
        dirty_words[word_index][0] = 1;
        assert!(
            render(&dirty_words).is_err(),
            "dirty high address padding for {operand} must refuse"
        );
    }
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata[..calldata.len() - 1],
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 short head"
        ))
    ));
    let mut trailing = calldata.clone();
    trailing.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &trailing,
            &mainnet_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));

    let mut mainnet_proofs = DispatchPageProofs::new();
    mainnet_proofs.fail_initialize();
    let mut dispatched = pick_sign_pages(
        &tx,
        &calldata,
        &signer,
        None,
        None,
        None,
        Some(&mainnet_verified),
        None,
        None,
        &resolver,
        &mut mainnet_proofs,
    )
    .expect("dispatcher selects mainnet Validators addFirstMember");
    assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());
    let mut verdict = crate::fi::FAIL_SENTINEL;
    mainnet_proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_eq!(verdict, crate::fi::OK_SENTINEL);
    dispatched.buf[find_page_by_label(&dispatched, "First Validator")][1][0] ^= 1;
    verdict = crate::fi::FAIL_SENTINEL;
    mainnet_proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_ne!(
        verdict,
        crate::fi::OK_SENTINEL,
        "corrupting one visible validator byte must invalidate the dispatcher proof"
    );

    let alfajores = find_leaf(registry, "calldata-celo_validators.json", ALFAJORES_CHAIN);
    let alfajores_proxy: [u8; 20] = hex::decode("9acf2a99914e083ad0d610672e93d14b0736bbcc")
        .expect("Alfajores Validators proxy")
        .try_into()
        .expect("address width");
    assert_eq!(alfajores.contract, alfajores_proxy);
    let alfajores_bundle = synth_bundle(&registry.blob, &alfajores.ir_bytes, alfajores.leaf_index);
    let alfajores_verified = verify_erc7730_bundle(&alfajores_bundle, &registry.root)
        .expect("verify Alfajores Validators leaf");
    cross_check_contract(&alfajores_verified.ir, ALFAJORES_CHAIN, &alfajores.contract)
        .expect("bind Alfajores Validators leaf");
    assert_eq!(alfajores_verified.ir.format_count(), Ok(9));
    assert_selector_excluded(&alfajores_verified.ir, SIGNATURE);
    assert!(
        registry
            .known_calls
            .contains(&(ALFAJORES_CHAIN, alfajores.contract, SELECTOR)),
        "Alfajores addFirstMember stays exact-known even though its format is refused"
    );
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &registry.known_calls_bloom,
        ALFAJORES_CHAIN,
        &alfajores.contract,
        &SELECTOR,
    ));
    let alfajores_tx = envelope(ALFAJORES_CHAIN, alfajores.contract);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &alfajores_tx,
            &calldata,
            &alfajores_verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::NoFormat)
    ));
    for descriptor in [Some(&alfajores_verified), None] {
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &alfajores_tx,
                &calldata,
                &signer,
                None,
                None,
                None,
                descriptor,
                None,
                None,
                &resolver,
                &mut proofs,
            )
            .is_err(),
            "Alfajores addFirstMember must not fall back with or without its descriptor"
        );
    }
}

#[test]
fn production_midas_mtbill_deposit_routes_are_operand_complete_and_exactly_scoped() {
    use pqsigner_erc7730::display::MAX_PAGES;

    const CHAIN_ID: u64 = 1;
    const SIGNATURE: &str = "depositInstant(address,uint256,uint256,bytes32)";
    const SELECTOR: [u8; 4] = [0xc0, 0x2d, 0xd2, 0x7a];
    const CUSTOM_RECIPIENT: &str = "depositInstant(address,uint256,uint256,bytes32,address)";
    const CUSTOM_RECIPIENT_SELECTOR: [u8; 4] = [0x42, 0xe8, 0x86, 0x6b];
    const REQUEST: &str = "depositRequest(address,uint256,bytes32)";
    const REQUEST_SELECTOR: [u8; 4] = [0x6e, 0x26, 0xb9, 0xf8];
    const REQUEST_RECIPIENT: &str = "depositRequest(address,uint256,bytes32,address)";
    const REQUEST_RECIPIENT_SELECTOR: [u8; 4] = [0xe5, 0x0e, 0x3d, 0xbb];

    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-MinterVault.json", CHAIN_ID);
    let vault: [u8; 20] = hex::decode("99361435420711723af805f08187c9e6bf796683")
        .expect("canonical mTBILL DepositVault")
        .try_into()
        .expect("address width");
    assert_eq!(entry.contract, vault);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("verify production mTBILL DepositVault leaf");
    cross_check_contract(&verified.ir, CHAIN_ID, &vault)
        .expect("bind production mTBILL DepositVault leaf");
    assert!(matches!(
        cross_check_contract(&verified.ir, 10, &vault),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&verified.ir, CHAIN_ID, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));
    assert_eq!(verified.ir.format_count(), Ok(4));
    assert_eq!(&keccak256(SIGNATURE.as_bytes())[..4], &SELECTOR);
    for (signature, selector) in [
        (CUSTOM_RECIPIENT, CUSTOM_RECIPIENT_SELECTOR),
        (REQUEST, REQUEST_SELECTOR),
        (REQUEST_RECIPIENT, REQUEST_RECIPIENT_SELECTOR),
    ] {
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
    }

    let usdc: [u8; 20] = hex::decode("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        .expect("USDC address")
        .try_into()
        .expect("address width");
    let mtbill: [u8; 20] = hex::decode("dd629e5241cbc5919847783e6c96b2de4754e438")
        .expect("mTBILL address")
        .try_into()
        .expect("address width");
    let metadata = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: mtbill,
        decimals: 18,
        name: b"Midas US Treasury Bill Token",
        symbol: b"mTBILL",
    };
    let signer = [0x42; 20];
    let mut changed_signer = signer;
    changed_signer[19] ^= 1;
    let resolver = NameResolver::new();
    let referral = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];
    let words = [
        abi_address_word(usdc),
        u256_from_u128(2_000_000_000_000_000_000).0,
        u256_from_u128(1_900_000_000_000_000_000).0,
        referral,
    ];
    let calldata = calldata_static(SIGNATURE, &words);
    assert_eq!(calldata.len(), 4 + 4 * 32);
    assert_eq!(&calldata[..4], &SELECTOR);
    assert_selector_matches(&verified.ir, &calldata, SIGNATURE);
    let tx = envelope(CHAIN_ID, vault);

    let render_with = |candidate_words: &[[u8; 32]; 4], candidate_signer: &[u8; 20]| {
        let candidate = calldata_static(SIGNATURE, candidate_words);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &candidate,
            &verified,
            Some(&metadata),
            &resolver,
            candidate_signer,
        )
    };
    let baseline = render_with(&words, &signer).expect("mTBILL instant deposit renders");
    assert_eq!(
        baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(
        baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0),
        "the transcript receipt must bind every trusted Midas page"
    );
    assert_all_pages_printable(&baseline.pages);
    assert!(
        baseline.pages.len <= MAX_PAGES,
        "complete referral and beneficiary display must fit the fixed page budget"
    );
    assert_eq!(
        page_strs(&baseline.pages, intent_page_index(&baseline.pages))[0],
        "Issue mTBILL now"
    );
    assert_full_address_field_page(&baseline.pages, "Payment Token", &usdc);
    let payment_rows = page_strs(
        &baseline.pages,
        find_page_by_label(&baseline.pages, "Payment Amount"),
    );
    assert!(
        payment_rows.iter().any(|row| row.contains("2 token")),
        "normalized 18-decimal input must render as 2 token: {payment_rows:?}"
    );
    let minimum_rows = page_strs(
        &baseline.pages,
        find_page_by_label(&baseline.pages, "Minimum mTBILL"),
    );
    assert!(
        minimum_rows.iter().any(|row| row.contains("1.9 mTBILL")),
        "minimum must use static 18-decimal mTBILL metadata: {minimum_rows:?}"
    );
    assert_raw_word_pages(&baseline.pages, "Referral ID", &referral);
    assert_full_address_field_page(&baseline.pages, "Beneficiary", &signer);

    let payment_token_metadata = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: usdc,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    for candidate_metadata in [None, Some(&payment_token_metadata)] {
        let degraded = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            candidate_metadata,
            &resolver,
            &signer,
        )
        .expect("missing or payment-token metadata degrades without inventing mTBILL scale");
        assert!(
            dump_pages(&degraded.pages).contains("! raw, dec=?"),
            "unbound metadata must keep the static mTBILL minimum exact and unscaled"
        );
        assert_full_unverified_token_identity_page(&degraded.pages, &mtbill);
    }

    for (word_index, operand) in [
        (0usize, "payment token"),
        (1, "payment amount"),
        (2, "minimum mTBILL"),
        (3, "referral ID"),
    ] {
        let mut mutated_words = words;
        mutated_words[word_index] = match word_index {
            1 => u256_from_u128(3_000_000_000_000_000_000).0,
            2 => u256_from_u128(1_800_000_000_000_000_000).0,
            _ => {
                let mut word = mutated_words[word_index];
                word[31] ^= 1;
                word
            }
        };
        let mutated = render_with(&mutated_words, &signer)
            .unwrap_or_else(|error| panic!("render independently mutated {operand}: {error:?}"));
        assert_ne!(
            baseline.pages.as_slice(),
            mutated.pages.as_slice(),
            "changing only {operand} must change trusted pages"
        );
        assert!(
            !baseline
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "changing only {operand} must change the transcript receipt"
        );
    }
    for word_index in [1usize, 2] {
        let mut adjacent_words = words;
        adjacent_words[word_index][31] ^= 1;
        let adjacent = render_with(&adjacent_words, &signer)
            .expect("the adjacent signed base unit renders exactly");
        let (label, expected_row1, expected_row2) = if word_index == 1 {
            ("Payment Amount", "2.00000000000000", "0001 token")
        } else {
            ("Minimum mTBILL", "1.90000000000000", "0001 mTBILL")
        };
        let adjacent_rows = page_strs(&adjacent.pages, find_page_by_label(&adjacent.pages, label));
        assert_eq!(adjacent_rows[1], expected_row1);
        assert_eq!(adjacent_rows[2], expected_row2);
        assert_ne!(baseline.pages.as_slice(), adjacent.pages.as_slice());
        assert!(!baseline
            .transcript_receipt
            .exact_match(&adjacent.transcript_receipt));
    }
    let changed_beneficiary =
        render_with(&words, &changed_signer).expect("changed authenticated signer renders");
    assert_full_address_field_page(&changed_beneficiary.pages, "Beneficiary", &changed_signer);
    assert_ne!(
        baseline.pages.as_slice(),
        changed_beneficiary.pages.as_slice(),
        "authenticated beneficiary changes must be visible"
    );
    assert!(!baseline
        .transcript_receipt
        .exact_match(&changed_beneficiary.transcript_receipt));

    let recipient = [0x77; 20];
    let custom_words = [
        abi_address_word(usdc),
        words[1],
        words[2],
        referral,
        abi_address_word(recipient),
    ];
    let custom_calldata = calldata_static(CUSTOM_RECIPIENT, &custom_words);
    assert_eq!(&custom_calldata[..4], &CUSTOM_RECIPIENT_SELECTOR);
    assert_selector_matches(&verified.ir, &custom_calldata, CUSTOM_RECIPIENT);
    let render_custom = |candidate_words: &[[u8; 32]; 5], candidate_signer: &[u8; 20]| {
        let candidate = calldata_static(CUSTOM_RECIPIENT, candidate_words);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &candidate,
            &verified,
            Some(&metadata),
            &resolver,
            candidate_signer,
        )
    };
    let custom_baseline =
        render_custom(&custom_words, &signer).expect("custom-recipient instant deposit renders");
    assert_eq!(
        custom_baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(custom_baseline
        .transcript_receipt
        .range_matches(&custom_baseline.pages, 0));
    assert_all_pages_printable(&custom_baseline.pages);
    assert!(custom_baseline.pages.len <= MAX_PAGES);
    assert_eq!(
        page_strs(
            &custom_baseline.pages,
            intent_page_index(&custom_baseline.pages)
        )[0],
        "Issue mTBILL now"
    );
    assert_full_address_field_page(&custom_baseline.pages, "Payment Token", &usdc);
    assert_raw_word_pages(&custom_baseline.pages, "Referral ID", &referral);
    assert_full_address_field_page(&custom_baseline.pages, "Beneficiary", &recipient);
    assert_full_address_field_page(&custom_baseline.pages, "Payer", &signer);
    let custom_minimum_rows = page_strs(
        &custom_baseline.pages,
        find_page_by_label(&custom_baseline.pages, "Minimum mTBILL"),
    );
    assert!(
        custom_minimum_rows
            .iter()
            .any(|row| row.contains("1.9 mTBILL")),
        "custom-recipient minimum must use static mTBILL metadata: {custom_minimum_rows:?}"
    );
    for (word_index, operand) in [
        (0usize, "payment token"),
        (1, "payment amount"),
        (2, "minimum mTBILL"),
        (3, "referral ID"),
        (4, "beneficiary"),
    ] {
        let mut mutated_words = custom_words;
        mutated_words[word_index] = match word_index {
            1 => u256_from_u128(3_000_000_000_000_000_000).0,
            2 => u256_from_u128(1_800_000_000_000_000_000).0,
            _ => {
                let mut word = mutated_words[word_index];
                word[31] ^= 1;
                word
            }
        };
        let mutated = render_custom(&mutated_words, &signer).unwrap_or_else(|error| {
            panic!("render independently mutated custom {operand}: {error:?}")
        });
        assert_ne!(
            custom_baseline.pages.as_slice(),
            mutated.pages.as_slice(),
            "changing only custom {operand} must change trusted pages"
        );
        assert!(!custom_baseline
            .transcript_receipt
            .exact_match(&mutated.transcript_receipt));
    }
    let changed_custom_payer = render_custom(&custom_words, &changed_signer)
        .expect("changed authenticated custom payer renders");
    assert_full_address_field_page(&changed_custom_payer.pages, "Payer", &changed_signer);
    assert_ne!(
        custom_baseline.pages.as_slice(),
        changed_custom_payer.pages.as_slice(),
        "authenticated payer changes must be visible on the custom route"
    );

    let request_words = [abi_address_word(usdc), words[1], referral];
    let request_calldata = calldata_static(REQUEST, &request_words);
    assert_eq!(&request_calldata[..4], &REQUEST_SELECTOR);
    assert_selector_matches(&verified.ir, &request_calldata, REQUEST);
    let render_request = |candidate_words: &[[u8; 32]; 3], candidate_signer: &[u8; 20]| {
        let candidate = calldata_static(REQUEST, candidate_words);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &candidate,
            &verified,
            Some(&metadata),
            &resolver,
            candidate_signer,
        )
    };
    let request_baseline =
        render_request(&request_words, &signer).expect("implicit-recipient request renders");
    assert_eq!(
        request_baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(request_baseline
        .transcript_receipt
        .range_matches(&request_baseline.pages, 0));
    assert_all_pages_printable(&request_baseline.pages);
    assert!(request_baseline.pages.len <= MAX_PAGES);
    let request_intent = page_strs(
        &request_baseline.pages,
        intent_page_index(&request_baseline.pages),
    );
    assert_eq!(request_intent[0], "Pay now; request");
    assert_eq!(request_intent[1], " mTBILL");
    assert_full_address_field_page(&request_baseline.pages, "Payment Token", &usdc);
    assert_raw_word_pages(&request_baseline.pages, "Referral ID", &referral);
    assert_full_address_field_page(&request_baseline.pages, "Beneficiary", &signer);
    for page in 0..request_baseline.pages.len {
        assert!(
            !page_strs(&request_baseline.pages, page)
                .iter()
                .any(|row| row == "Minimum mTBILL"),
            "an asynchronous request must not promise a minimum output"
        );
    }
    for (word_index, operand) in [
        (0usize, "payment token"),
        (1, "payment amount"),
        (2, "referral ID"),
    ] {
        let mut mutated_words = request_words;
        mutated_words[word_index] = if word_index == 1 {
            u256_from_u128(3_000_000_000_000_000_000).0
        } else {
            let mut word = mutated_words[word_index];
            word[31] ^= 1;
            word
        };
        let mutated = render_request(&mutated_words, &signer).unwrap_or_else(|error| {
            panic!("render independently mutated request {operand}: {error:?}")
        });
        assert_ne!(request_baseline.pages.as_slice(), mutated.pages.as_slice());
        assert!(!request_baseline
            .transcript_receipt
            .exact_match(&mutated.transcript_receipt));
    }
    let changed_request_beneficiary = render_request(&request_words, &changed_signer)
        .expect("changed implicit request beneficiary renders");
    assert_full_address_field_page(
        &changed_request_beneficiary.pages,
        "Beneficiary",
        &changed_signer,
    );
    assert_ne!(
        request_baseline.pages.as_slice(),
        changed_request_beneficiary.pages.as_slice()
    );

    let request_recipient_words = [
        abi_address_word(usdc),
        words[1],
        referral,
        abi_address_word(recipient),
    ];
    let request_recipient_calldata = calldata_static(REQUEST_RECIPIENT, &request_recipient_words);
    assert_eq!(
        &request_recipient_calldata[..4],
        &REQUEST_RECIPIENT_SELECTOR
    );
    assert_selector_matches(&verified.ir, &request_recipient_calldata, REQUEST_RECIPIENT);
    let render_request_recipient =
        |candidate_words: &[[u8; 32]; 4], candidate_signer: &[u8; 20]| {
            let candidate = calldata_static(REQUEST_RECIPIENT, candidate_words);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &candidate,
                &verified,
                Some(&metadata),
                &resolver,
                candidate_signer,
            )
        };
    let request_recipient_baseline = render_request_recipient(&request_recipient_words, &signer)
        .expect("custom-recipient request renders");
    assert_eq!(
        request_recipient_baseline.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(request_recipient_baseline
        .transcript_receipt
        .range_matches(&request_recipient_baseline.pages, 0));
    assert_all_pages_printable(&request_recipient_baseline.pages);
    assert!(request_recipient_baseline.pages.len <= MAX_PAGES);
    assert_full_address_field_page(&request_recipient_baseline.pages, "Beneficiary", &recipient);
    assert_full_address_field_page(&request_recipient_baseline.pages, "Payer", &signer);
    for page in 0..request_recipient_baseline.pages.len {
        assert!(
            !page_strs(&request_recipient_baseline.pages, page)
                .iter()
                .any(|row| row == "Minimum mTBILL"),
            "a custom asynchronous request must not promise a minimum output"
        );
    }
    for (word_index, operand) in [
        (0usize, "payment token"),
        (1, "payment amount"),
        (2, "referral ID"),
        (3, "beneficiary"),
    ] {
        let mut mutated_words = request_recipient_words;
        mutated_words[word_index] = if word_index == 1 {
            u256_from_u128(3_000_000_000_000_000_000).0
        } else {
            let mut word = mutated_words[word_index];
            word[31] ^= 1;
            word
        };
        let mutated = render_request_recipient(&mutated_words, &signer).unwrap_or_else(|error| {
            panic!("render independently mutated custom request {operand}: {error:?}")
        });
        assert_ne!(
            request_recipient_baseline.pages.as_slice(),
            mutated.pages.as_slice()
        );
        assert!(!request_recipient_baseline
            .transcript_receipt
            .exact_match(&mutated.transcript_receipt));
    }
    let changed_request_payer = render_request_recipient(&request_recipient_words, &changed_signer)
        .expect("changed custom request payer renders");
    assert_full_address_field_page(&changed_request_payer.pages, "Payer", &changed_signer);
    assert_ne!(
        request_recipient_baseline.pages.as_slice(),
        changed_request_payer.pages.as_slice()
    );

    let mut dirty_token = words;
    dirty_token[0][0] = 1;
    assert!(
        render_with(&dirty_token, &signer).is_err(),
        "dirty address padding must refuse"
    );
    let mut dirty_custom_recipient = custom_words;
    dirty_custom_recipient[4][0] = 1;
    assert!(
        render_custom(&dirty_custom_recipient, &signer).is_err(),
        "dirty custom-recipient padding must refuse"
    );
    let mut dirty_request_recipient = request_recipient_words;
    dirty_request_recipient[3][0] = 1;
    assert!(
        render_request_recipient(&dirty_request_recipient, &signer).is_err(),
        "dirty request-recipient padding must refuse"
    );
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata[..calldata.len() - 1],
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 short head"
        ))
    ));
    let mut trailing = calldata.clone();
    trailing.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &trailing,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));

    let mut tampered_bundle = bundle.clone();
    *tampered_bundle
        .last_mut()
        .expect("Midas bundle has proof bytes") ^= 1;
    assert!(
        verify_erc7730_bundle(&tampered_bundle, &registry.root).is_err(),
        "a tampered Midas Merkle proof must fail closed"
    );

    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut dispatched = pick_sign_pages(
        &tx,
        &calldata,
        &signer,
        None,
        None,
        None,
        Some(&verified),
        Some(&metadata),
        None,
        &resolver,
        &mut proofs,
    )
    .expect("dispatcher selects the exact mTBILL instant-deposit route");
    assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());
    let mut verdict = crate::fi::FAIL_SENTINEL;
    proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_eq!(verdict, crate::fi::OK_SENTINEL);
    dispatched.buf[find_page_by_label(&dispatched, "Referral ID")][1][0] ^= 1;
    verdict = crate::fi::FAIL_SENTINEL;
    proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
    assert_ne!(
        verdict,
        crate::fi::OK_SENTINEL,
        "corrupting visible referral bytes must invalidate the dispatcher proof"
    );

    for (signature, admitted_calldata) in [
        (SIGNATURE, &calldata),
        (CUSTOM_RECIPIENT, &custom_calldata),
        (REQUEST, &request_calldata),
        (REQUEST_RECIPIENT, &request_recipient_calldata),
    ] {
        let selector: [u8; 4] = admitted_calldata[..4]
            .try_into()
            .expect("Midas selector width");
        assert!(
            registry.known_calls.contains(&(CHAIN_ID, vault, selector)),
            "admitted Midas route must stay exact-known"
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            CHAIN_ID,
            &vault,
            &selector,
        ));
        let direct = render_erc7730_pages_with_signer_checked(
            &tx,
            admitted_calldata,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("admitted route {signature} renders: {error:?}"));
        let mut admitted_proofs = DispatchPageProofs::new();
        admitted_proofs.fail_initialize();
        let dispatched = pick_sign_pages(
            &tx,
            admitted_calldata,
            &signer,
            None,
            None,
            None,
            Some(&verified),
            Some(&metadata),
            None,
            &resolver,
            &mut admitted_proofs,
        )
        .unwrap_or_else(|error| panic!("dispatcher selects {signature}: {error:?}"));
        assert_eq!(dispatched.as_slice(), direct.pages.as_slice());

        let mut missing_proofs = DispatchPageProofs::new();
        missing_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                admitted_calldata,
                &signer,
                None,
                None,
                None,
                None,
                Some(&metadata),
                None,
                &resolver,
                &mut missing_proofs,
            )
            .is_err(),
            "{signature} must not fall back without its descriptor"
        );
    }

    let excluded_contract: [u8; 20] = hex::decode("a8a5c4ff4c86a459ebbdc39c5be77833b3a15d88")
        .expect("excluded Midas deployment")
        .try_into()
        .expect("address width");
    for selector in [
        SELECTOR,
        CUSTOM_RECIPIENT_SELECTOR,
        REQUEST_SELECTOR,
        REQUEST_RECIPIENT_SELECTOR,
    ] {
        assert!(
            registry
                .known_calls
                .contains(&(CHAIN_ID, excluded_contract, selector)),
            "every route at other Midas deployments remains exact-known"
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            CHAIN_ID,
            &excluded_contract,
            &selector,
        ));
    }
    assert!(matches!(
        cross_check_contract(&verified.ir, CHAIN_ID, &excluded_contract),
        Err(BindingError::ContractMismatch)
    ));

    // Exercise the production boundary directly: the complete proof-set FI
    // proof must reject a rooted descriptor against the wrong target before
    // the dispatcher can gain any fallback authority.
    let excluded_tx = envelope(CHAIN_ID, excluded_contract);
    let proof_set = crate::tx::erc7730::verify_erc7730_proof_set(&bundle, &registry.root)
        .expect("legacy bundle verifies as a one-element proof set");
    let mut bind_verdict = crate::fi::FAIL_SENTINEL;
    let mut bind_cfi = crate::fi::CfiCounter::new();
    crate::tx::erc7730::prove_contract_proof_set_binding(
        &proof_set,
        &registry.root,
        &excluded_tx,
        &calldata,
        &signer,
        None,
        &mut bind_verdict,
        &mut bind_cfi,
    );
    assert_ne!(bind_verdict, crate::fi::OK_SENTINEL);
    assert_eq!(
        bind_cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED),
        crate::fi::OK_SENTINEL,
        "the rejecting binding proof must still complete its CFI transcript"
    );
    let mut excluded_proofs = DispatchPageProofs::new();
    excluded_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &excluded_tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            None,
            Some(&metadata),
            None,
            &resolver,
            &mut excluded_proofs,
        )
        .is_err(),
        "a rejected Midas binding must never acquire fallback authority"
    );

    let mut missing_descriptor_proofs = DispatchPageProofs::new();
    missing_descriptor_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            None,
            Some(&metadata),
            None,
            &resolver,
            &mut missing_descriptor_proofs,
        )
        .is_err(),
        "an exact known call without its descriptor must hard-refuse"
    );
}

#[test]
fn production_midas_mtbill_redemption_routes_are_operand_complete_and_exactly_scoped() {
    use pqsigner_erc7730::display::MAX_PAGES;

    const CHAIN_ID: u64 = 1;
    const INSTANT: &str = "redeemInstant(address,uint256,uint256)";
    const INSTANT_SELECTOR: [u8; 4] = [0x8b, 0x53, 0xf7, 0x5e];
    const INSTANT_RECIPIENT: &str = "redeemInstant(address,uint256,uint256,address)";
    const INSTANT_RECIPIENT_SELECTOR: [u8; 4] = [0x85, 0xab, 0x2c, 0x13];
    const REQUEST: &str = "redeemRequest(address,uint256)";
    const REQUEST_SELECTOR: [u8; 4] = [0xbf, 0xc2, 0xd4, 0x6a];
    const REQUEST_RECIPIENT: &str = "redeemRequest(address,uint256,address)";
    const REQUEST_RECIPIENT_SELECTOR: [u8; 4] = [0x15, 0x57, 0x1a, 0x04];
    const FIAT: &str = "redeemFiatRequest(uint256)";
    const FIAT_SELECTOR: [u8; 4] = [0xd5, 0xf7, 0x3f, 0x5c];

    struct RouteCase {
        signature: &'static str,
        selector: [u8; 4],
        words: Vec<[u8; 32]>,
        instant: bool,
        explicit_recipient: bool,
    }

    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-RedemptionVault.json", CHAIN_ID);
    let vault: [u8; 20] = hex::decode("f6e51d24f4793ac5e71e0502213a9bbe3a6d4517")
        .expect("canonical mTBILL RedemptionVault")
        .try_into()
        .expect("address width");
    assert_eq!(entry.contract, vault);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("verify production mTBILL RedemptionVault leaf");
    cross_check_contract(&verified.ir, CHAIN_ID, &vault)
        .expect("bind production mTBILL RedemptionVault leaf");
    assert!(matches!(
        cross_check_contract(&verified.ir, 10, &vault),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&verified.ir, CHAIN_ID, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));
    assert_eq!(verified.ir.format_count(), Ok(4));
    for (signature, selector) in [
        (INSTANT, INSTANT_SELECTOR),
        (INSTANT_RECIPIENT, INSTANT_RECIPIENT_SELECTOR),
        (REQUEST, REQUEST_SELECTOR),
        (REQUEST_RECIPIENT, REQUEST_RECIPIENT_SELECTOR),
        (FIAT, FIAT_SELECTOR),
    ] {
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
    }
    assert_selector_excluded(&verified.ir, FIAT);

    let usdc: [u8; 20] = hex::decode("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        .expect("USDC address")
        .try_into()
        .expect("address width");
    let mtbill: [u8; 20] = hex::decode("dd629e5241cbc5919847783e6c96b2de4754e438")
        .expect("mTBILL address")
        .try_into()
        .expect("address width");
    let metadata = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: mtbill,
        decimals: 18,
        name: b"Midas US Treasury Bill Token",
        symbol: b"mTBILL",
    };
    let signer = [0x42; 20];
    let mut changed_signer = signer;
    changed_signer[19] ^= 1;
    let recipient = [0x77; 20];
    let resolver = NameResolver::new();
    let tx = envelope(CHAIN_ID, vault);
    let amount = u256_from_u128(2_000_000_000_000_000_000).0;
    let minimum = u256_from_u128(1_900_000_000_000_000_000).0;
    let cases = [
        RouteCase {
            signature: INSTANT,
            selector: INSTANT_SELECTOR,
            words: vec![abi_address_word(usdc), amount, minimum],
            instant: true,
            explicit_recipient: false,
        },
        RouteCase {
            signature: INSTANT_RECIPIENT,
            selector: INSTANT_RECIPIENT_SELECTOR,
            words: vec![
                abi_address_word(usdc),
                amount,
                minimum,
                abi_address_word(recipient),
            ],
            instant: true,
            explicit_recipient: true,
        },
        RouteCase {
            signature: REQUEST,
            selector: REQUEST_SELECTOR,
            words: vec![abi_address_word(usdc), amount],
            instant: false,
            explicit_recipient: false,
        },
        RouteCase {
            signature: REQUEST_RECIPIENT,
            selector: REQUEST_RECIPIENT_SELECTOR,
            words: vec![abi_address_word(usdc), amount, abi_address_word(recipient)],
            instant: false,
            explicit_recipient: true,
        },
    ];

    let output_token_metadata = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: usdc,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let standard_calldata = calldata_static(INSTANT, &cases[0].words);
    for candidate_metadata in [None, Some(&output_token_metadata)] {
        let degraded = render_erc7730_pages_with_signer_checked(
            &tx,
            &standard_calldata,
            &verified,
            candidate_metadata,
            &resolver,
            &signer,
        )
        .expect("missing or output-token metadata degrades without inventing mTBILL scale");
        assert!(
            dump_pages(&degraded.pages).contains("! raw, dec=?"),
            "unbound metadata must keep the static mTBILL input exact and unscaled"
        );
        assert_full_unverified_token_identity_page(&degraded.pages, &mtbill);
    }

    for case in &cases {
        let calldata = calldata_static(case.signature, &case.words);
        assert_eq!(&calldata[..4], &case.selector);
        assert_selector_matches(&verified.ir, &calldata, case.signature);
        assert!(registry
            .known_calls
            .contains(&(CHAIN_ID, vault, case.selector)));
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            CHAIN_ID,
            &vault,
            &case.selector,
        ));
        let render = |candidate_words: &[[u8; 32]], candidate_signer: &[u8; 20]| {
            let candidate = calldata_static(case.signature, candidate_words);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &candidate,
                &verified,
                Some(&metadata),
                &resolver,
                candidate_signer,
            )
        };
        let baseline = render(&case.words, &signer)
            .unwrap_or_else(|error| panic!("render {}: {error:?}", case.signature));
        assert_eq!(
            baseline.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0));
        assert_all_pages_printable(&baseline.pages);
        assert!(
            baseline.pages.len <= MAX_PAGES,
            "{} exceeds the fixed page budget",
            case.signature
        );
        let intent_rows = page_strs(&baseline.pages, intent_page_index(&baseline.pages));
        let visible_intent = format!("{}{}", intent_rows[0], intent_rows[1]);
        assert_eq!(
            visible_intent,
            if case.instant {
                "Redeem mTBILL now"
            } else {
                "Pay mTBILL now;request"
            }
        );
        let amount_rows = page_strs(
            &baseline.pages,
            find_page_by_label(&baseline.pages, "mTBILL Amount"),
        );
        assert!(
            amount_rows.iter().any(|row| row.contains("2 mTBILL")),
            "mTBILL input must use static 18-decimal metadata: {amount_rows:?}"
        );
        assert_full_address_field_page(&baseline.pages, "Output Token", &usdc);
        assert_full_address_field_page(
            &baseline.pages,
            "Beneficiary",
            if case.explicit_recipient {
                &recipient
            } else {
                &signer
            },
        );
        if case.explicit_recipient {
            assert_full_address_field_page(&baseline.pages, "Payer", &signer);
        }
        if case.instant {
            let minimum_rows = page_strs(
                &baseline.pages,
                find_page_by_label(&baseline.pages, "Minimum Output"),
            );
            assert!(
                minimum_rows.iter().any(|row| row.contains("1.9 token")),
                "minimum must show contract-normalized base-18 output units: {minimum_rows:?}"
            );
        } else {
            for page in 0..baseline.pages.len {
                assert!(
                    !page_strs(&baseline.pages, page)
                        .iter()
                        .any(|row| row == "Minimum Output"),
                    "a redemption request must not invent a signed minimum"
                );
            }
        }

        for word_index in 0..case.words.len() {
            let mut mutated_words = case.words.clone();
            mutated_words[word_index] = if word_index == 1 {
                u256_from_u128(3_000_000_000_000_000_000).0
            } else if case.instant && word_index == 2 {
                u256_from_u128(1_800_000_000_000_000_000).0
            } else {
                let mut word = mutated_words[word_index];
                word[31] ^= 1;
                word
            };
            let mutated = render(&mutated_words, &signer).unwrap_or_else(|error| {
                panic!(
                    "render independently mutated word {word_index} for {}: {error:?}",
                    case.signature
                )
            });
            assert_ne!(
                baseline.pages.as_slice(),
                mutated.pages.as_slice(),
                "word {word_index} is not visible for {}",
                case.signature
            );
            assert!(
                !baseline
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "word {word_index} is not receipt-bound for {}",
                case.signature
            );
        }
        let changed_identity = render(&case.words, &changed_signer)
            .unwrap_or_else(|error| panic!("render changed signer {}: {error:?}", case.signature));
        let identity_label = if case.explicit_recipient {
            "Payer"
        } else {
            "Beneficiary"
        };
        assert_full_address_field_page(&changed_identity.pages, identity_label, &changed_signer);
        assert_ne!(baseline.pages.as_slice(), changed_identity.pages.as_slice());
        assert!(!baseline
            .transcript_receipt
            .exact_match(&changed_identity.transcript_receipt));

        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let dispatched = pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&verified),
            Some(&metadata),
            None,
            &resolver,
            &mut proofs,
        )
        .unwrap_or_else(|error| panic!("dispatcher selects {}: {error:?}", case.signature));
        assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());

        let mut missing_proofs = DispatchPageProofs::new();
        missing_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &calldata,
                &signer,
                None,
                None,
                None,
                None,
                Some(&metadata),
                None,
                &resolver,
                &mut missing_proofs,
            )
            .is_err(),
            "{} must not fall back without its descriptor",
            case.signature
        );
    }

    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &standard_calldata[..standard_calldata.len() - 1],
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 short head"
        ))
    ));
    let mut trailing = standard_calldata.clone();
    trailing.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &trailing,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));
    let mut dirty_token = cases[0].words.clone();
    dirty_token[0][0] = 1;
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata_static(INSTANT, &dirty_token),
        &verified,
        Some(&metadata),
        &resolver,
        &signer,
    )
    .is_err());
    let mut dirty_recipient = cases[1].words.clone();
    dirty_recipient[3][0] = 1;
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata_static(INSTANT_RECIPIENT, &dirty_recipient),
        &verified,
        Some(&metadata),
        &resolver,
        &signer,
    )
    .is_err());

    let fiat_calldata = calldata_static(FIAT, &[amount]);
    assert_eq!(&fiat_calldata[..4], &FIAT_SELECTOR);
    assert!(registry
        .known_calls
        .contains(&(CHAIN_ID, vault, FIAT_SELECTOR)));
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &registry.known_calls_bloom,
        CHAIN_ID,
        &vault,
        &FIAT_SELECTOR,
    ));
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &fiat_calldata,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::NoFormat)
    ));
    for descriptor in [Some(&verified), None] {
        let mut fiat_proofs = DispatchPageProofs::new();
        fiat_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &fiat_calldata,
                &signer,
                None,
                None,
                None,
                descriptor,
                Some(&metadata),
                None,
                &resolver,
                &mut fiat_proofs,
            )
            .is_err(),
            "fiat redemption must refuse with or without the token-route descriptor"
        );
    }

    let mut tampered_bundle = bundle.clone();
    *tampered_bundle
        .last_mut()
        .expect("RedemptionVault bundle has proof bytes") ^= 1;
    assert!(verify_erc7730_bundle(&tampered_bundle, &registry.root).is_err());

    let excluded_contract: [u8; 20] = hex::decode("569d7dccbf6923350521ecbc28a555a500c4f0ec")
        .expect("excluded Midas RedemptionVault")
        .try_into()
        .expect("address width");
    for selector in [
        INSTANT_SELECTOR,
        INSTANT_RECIPIENT_SELECTOR,
        REQUEST_SELECTOR,
        REQUEST_RECIPIENT_SELECTOR,
        FIAT_SELECTOR,
    ] {
        assert!(registry
            .known_calls
            .contains(&(CHAIN_ID, excluded_contract, selector)));
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            CHAIN_ID,
            &excluded_contract,
            &selector,
        ));
    }
    assert!(matches!(
        cross_check_contract(&verified.ir, CHAIN_ID, &excluded_contract),
        Err(BindingError::ContractMismatch)
    ));
    let excluded_tx = envelope(CHAIN_ID, excluded_contract);
    let mut excluded_proofs = DispatchPageProofs::new();
    excluded_proofs.fail_initialize();
    assert!(pick_sign_pages(
        &excluded_tx,
        &standard_calldata,
        &signer,
        None,
        None,
        None,
        None,
        Some(&metadata),
        None,
        &resolver,
        &mut excluded_proofs,
    )
    .is_err());
}

#[test]
fn production_celo_election_revokes_render_every_signed_operand_mainnet_only() {
    use pqsigner_erc7730::ir::FormatOp;

    const MAINNET_CHAIN: u64 = 42_220;
    const ALFAJORES_CHAIN: u64 = 44_787;
    const REVOKE_ACTIVE: &str = "revokeActive(address,uint256,address,address,uint256)";
    const REVOKE_ALL_ACTIVE: &str = "revokeAllActive(address,address,address,uint256)";
    const REVOKE_PENDING: &str = "revokePending(address,uint256,address,address,uint256)";

    struct RevokeCase {
        signature: &'static str,
        selector: [u8; 4],
        intent: &'static str,
        words: Vec<[u8; 32]>,
        expected_fields: Vec<(&'static str, u8)>,
        amount: Option<(usize, &'static str, &'static str)>,
        lesser_index: usize,
        greater_index: usize,
        voting_list_index: usize,
    }

    let group = [0x11; 20];
    let lesser = [0x22; 20];
    let greater = [0x33; 20];
    let active_value = u256_from_u128(1_500_000_000_000_000_000);
    let pending_value = u256_from_u128(2_500_000_000_000_000_000);
    let cases = vec![
        RevokeCase {
            signature: REVOKE_ACTIVE,
            selector: [0x6e, 0x19, 0x84, 0x75],
            intent: "Revoke Active Votes",
            words: vec![
                abi_address_word(group),
                active_value.0,
                abi_address_word(lesser),
                abi_address_word(greater),
                u256_from_u64(7).0,
            ],
            expected_fields: vec![
                ("Validator Group", FormatOp::AddressName as u8),
                ("Active CELO to Revoke", FormatOp::Amount as u8),
                ("Fewer-Vote Hint", FormatOp::AddressName as u8),
                ("More-Vote Hint", FormatOp::AddressName as u8),
                ("Voting List Index", FormatOp::Raw as u8),
            ],
            amount: Some((1, "Active CELO to Revoke", "1.5 CELO")),
            lesser_index: 2,
            greater_index: 3,
            voting_list_index: 4,
        },
        RevokeCase {
            signature: REVOKE_ALL_ACTIVE,
            selector: [0xe0, 0xa2, 0xab, 0x52],
            intent: "Revoke All Active Votes",
            words: vec![
                abi_address_word(group),
                abi_address_word(lesser),
                abi_address_word(greater),
                u256_from_u64(9).0,
            ],
            expected_fields: vec![
                ("Validator Group", FormatOp::AddressName as u8),
                ("Fewer-Vote Hint", FormatOp::AddressName as u8),
                ("More-Vote Hint", FormatOp::AddressName as u8),
                ("Voting List Index", FormatOp::Raw as u8),
            ],
            amount: None,
            lesser_index: 1,
            greater_index: 2,
            voting_list_index: 3,
        },
        RevokeCase {
            signature: REVOKE_PENDING,
            selector: [0x9d, 0xfb, 0x60, 0x81],
            intent: "Revoke Pending Votes",
            words: vec![
                abi_address_word(group),
                pending_value.0,
                abi_address_word(lesser),
                abi_address_word(greater),
                u256_from_u64(11).0,
            ],
            expected_fields: vec![
                ("Validator Group", FormatOp::AddressName as u8),
                ("Pending CELO to Revoke", FormatOp::Amount as u8),
                ("Fewer-Vote Hint", FormatOp::AddressName as u8),
                ("More-Vote Hint", FormatOp::AddressName as u8),
                ("Voting List Index", FormatOp::Raw as u8),
            ],
            amount: Some((1, "Pending CELO to Revoke", "2.5 CELO")),
            lesser_index: 2,
            greater_index: 3,
            voting_list_index: 4,
        },
    ];

    let registry = build_registry();
    let mainnet = find_leaf(registry, "calldata-celo_election.json", MAINNET_CHAIN);
    let mainnet_proxy: [u8; 20] = hex::decode("8d6677192144292870907e3fa8a5527fe55a7ff6")
        .expect("canonical Election proxy")
        .try_into()
        .expect("address width");
    assert_eq!(mainnet.contract, mainnet_proxy);
    let mainnet_bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let mainnet_verified = verify_erc7730_bundle(&mainnet_bundle, &registry.root)
        .expect("verify mainnet Election leaf");
    cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &mainnet.contract)
        .expect("bind mainnet Election leaf");
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, ALFAJORES_CHAIN, &mainnet.contract),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));
    assert_eq!(mainnet_verified.ir.format_count(), Ok(6));

    let tx = envelope(MAINNET_CHAIN, mainnet.contract);
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let visible_label = |label: &str| {
        if label.len() <= DISPLAY_COLS {
            label.to_string()
        } else {
            let mut rendered = label[..DISPLAY_COLS - 1].to_string();
            rendered.push('~');
            rendered
        }
    };
    for case in &cases {
        assert_eq!(
            &keccak256(case.signature.as_bytes())[..4],
            &case.selector,
            "selector pin for {}",
            case.signature
        );
        let format = mainnet_verified
            .ir
            .find_format_by_selector(&case.selector)
            .expect("Election format table parses")
            .unwrap_or_else(|| panic!("missing mainnet format {}", case.signature));
        assert_eq!(format.intent, case.intent.as_bytes());
        assert_eq!(usize::from(format.static_head_words), case.words.len());
        assert_eq!(usize::from(format.field_count), case.words.len());
        let actual_fields: Vec<(&str, u8)> = format
            .fields()
            .map(|field| {
                let field = field.expect("revoke field parses");
                (
                    core::str::from_utf8(field.label).expect("ASCII field label"),
                    field.format_op,
                )
            })
            .collect();
        assert_eq!(
            actual_fields.as_slice(),
            case.expected_fields.as_slice(),
            "exact authenticated field order for {}",
            case.signature
        );

        let calldata = calldata_static(case.signature, &case.words);
        assert_eq!(&calldata[..4], &case.selector);
        assert_selector_matches(&mainnet_verified.ir, &calldata, case.signature);
        let render = |candidate_words: &[[u8; 32]]| {
            let candidate = calldata_static(case.signature, candidate_words);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &candidate,
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            )
        };

        let baseline = render(&case.words)
            .unwrap_or_else(|error| panic!("render {}: {error:?}", case.signature));
        assert_eq!(
            baseline.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0));
        assert_all_pages_printable(&baseline.pages);
        let intent_rows = page_strs(&baseline.pages, intent_page_index(&baseline.pages));
        assert_eq!(intent_rows[0], case.intent[..DISPLAY_COLS]);
        assert_eq!(intent_rows[1], case.intent[DISPLAY_COLS..]);
        assert_eq!(intent_rows[2], "Celo Election");
        assert_eq!(intent_rows[3], "> next");
        assert_full_address_field_page(&baseline.pages, "Validator Group", &group);
        assert_full_address_field_page(&baseline.pages, "Fewer-Vote Hint", &lesser);
        assert_full_address_field_page(&baseline.pages, "More-Vote Hint", &greater);
        let voting_list_label = visible_label("Voting List Index");
        assert_raw_word_pages(
            &baseline.pages,
            &voting_list_label,
            &case.words[case.voting_list_index],
        );
        match case.amount {
            Some((_, label, expected)) => {
                let rendered_label = visible_label(label);
                assert_eq!(
                    page_strs(
                        &baseline.pages,
                        find_page_by_label(&baseline.pages, &rendered_label)
                    ),
                    [
                        rendered_label,
                        expected.to_string(),
                        String::new(),
                        "> next".to_string(),
                    ],
                    "exact signed CELO amount for {}",
                    case.signature
                );
            }
            None => {
                for forbidden in ["Active CELO to Revoke", "Pending CELO to Revoke"] {
                    let forbidden = visible_label(forbidden);
                    assert!(
                        baseline
                            .pages
                            .as_slice()
                            .iter()
                            .all(|page| row_str(&page[0]) != forbidden),
                        "{} must not fabricate a live-storage amount page",
                        case.signature
                    );
                }
            }
        }

        let address_indices = [0usize, case.lesser_index, case.greater_index];
        for word_index in 0..case.words.len() {
            let mut mutated_words = case.words.clone();
            if address_indices.contains(&word_index) {
                mutated_words[word_index][31] ^= 1;
            } else if case
                .amount
                .is_some_and(|(amount_index, _, _)| amount_index == word_index)
            {
                mutated_words[word_index] = u256_from_u128(3_000_000_000_000_000_000).0;
            } else {
                mutated_words[word_index][31] ^= 1;
            }
            let mutated = render(&mutated_words).unwrap_or_else(|error| {
                panic!(
                    "render {} with independently mutated word {word_index}: {error:?}",
                    case.signature
                )
            });
            assert_ne!(
                baseline.pages.as_slice(),
                mutated.pages.as_slice(),
                "word {word_index} must change trusted pages for {}",
                case.signature
            );
            assert!(
                !baseline
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "word {word_index} must change the transcript for {}",
                case.signature
            );
        }

        let mut zero_hint_words = case.words.clone();
        zero_hint_words[case.lesser_index] = abi_address_word([0u8; 20]);
        zero_hint_words[case.greater_index] = abi_address_word([0u8; 20]);
        let zero_hints = render(&zero_hint_words)
            .unwrap_or_else(|error| panic!("render zero hints for {}: {error:?}", case.signature));
        assert_full_address_field_page(&zero_hints.pages, "Fewer-Vote Hint", &[0u8; 20]);
        assert_full_address_field_page(&zero_hints.pages, "More-Vote Hint", &[0u8; 20]);

        for word_index in address_indices {
            let mut dirty_words = case.words.clone();
            dirty_words[word_index][0] = 1;
            assert!(
                render(&dirty_words).is_err(),
                "dirty address padding in word {word_index} must refuse {}",
                case.signature
            );
        }
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata[..calldata.len() - 1],
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 short head"
            ))
        ));
        let mut trailing = calldata.clone();
        trailing.push(0);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx,
                &trailing,
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));

        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let mut dispatched = pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&mainnet_verified),
            None,
            None,
            &resolver,
            &mut proofs,
        )
        .unwrap_or_else(|_| panic!("dispatcher selects {}", case.signature));
        assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
        assert_eq!(verdict, crate::fi::OK_SENTINEL);
        dispatched.buf[find_page_by_label(&dispatched, "Validator Group")][1][0] ^= 1;
        verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
        assert_ne!(
            verdict,
            crate::fi::OK_SENTINEL,
            "visible corruption must invalidate the dispatcher proof for {}",
            case.signature
        );
    }

    let alfajores = find_leaf(registry, "calldata-celo_election.json", ALFAJORES_CHAIN);
    let alfajores_proxy: [u8; 20] = hex::decode("1c3edf937cfc2f6f51784d20deb1af1f9a8655fa")
        .expect("Alfajores Election proxy")
        .try_into()
        .expect("address width");
    assert_eq!(alfajores.contract, alfajores_proxy);
    let alfajores_bundle = synth_bundle(&registry.blob, &alfajores.ir_bytes, alfajores.leaf_index);
    let alfajores_verified = verify_erc7730_bundle(&alfajores_bundle, &registry.root)
        .expect("verify Alfajores Election leaf");
    cross_check_contract(&alfajores_verified.ir, ALFAJORES_CHAIN, &alfajores.contract)
        .expect("bind Alfajores Election leaf");
    assert_eq!(alfajores_verified.ir.format_count(), Ok(2));
    let alfajores_tx = envelope(ALFAJORES_CHAIN, alfajores.contract);
    for case in &cases {
        assert_selector_excluded(&alfajores_verified.ir, case.signature);
        assert!(
            registry
                .known_calls
                .contains(&(ALFAJORES_CHAIN, alfajores.contract, case.selector)),
            "Alfajores {} remains exact-known",
            case.signature
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            ALFAJORES_CHAIN,
            &alfajores.contract,
            &case.selector,
        ));
        let calldata = calldata_static(case.signature, &case.words);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &alfajores_tx,
                &calldata,
                &alfajores_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::NoFormat)
        ));

        for descriptor in [Some(&alfajores_verified), None] {
            let mut proofs = DispatchPageProofs::new();
            proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &alfajores_tx,
                    &calldata,
                    &signer,
                    None,
                    None,
                    None,
                    descriptor,
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .is_err(),
                "Alfajores {} must not fall back with or without its descriptor",
                case.signature
            );
        }
    }
}

#[test]
fn production_celo_governance_voting_routes_render_every_signed_operand_mainnet_only() {
    use pqsigner_erc7730::ir::FormatOp;
    use pqsigner_erc7730::render::policy::TerminalKind;

    const MAINNET_CHAIN: u64 = 42_220;
    const ALFAJORES_CHAIN: u64 = 44_787;
    const UPVOTE: &str = "upvote(uint256,uint256,uint256)";
    const REVOKE_UPVOTE: &str = "revokeUpvote(uint256,uint256)";
    const VOTE: &str = "vote(uint256,uint256,uint8)";
    const VOTE_PARTIALLY: &str = "votePartially(uint256,uint256,uint256,uint256,uint256)";

    struct GovernanceCase {
        signature: &'static str,
        selector: [u8; 4],
        intent: &'static str,
        intent_rows: [&'static str; 4],
        words: Vec<[u8; 32]>,
        expected_fields: Vec<(&'static str, u8)>,
        hint_indices: Option<(usize, usize)>,
        enum_index: Option<usize>,
    }

    let cases = vec![
        GovernanceCase {
            signature: UPVOTE,
            selector: [0x57, 0x33, 0x39, 0x78],
            intent: "Upvote",
            intent_rows: ["Upvote", "Celo", "Celo Governance", "> next"],
            words: vec![
                u256_from_u64(42).0,
                u256_from_u64(41).0,
                u256_from_u64(43).0,
            ],
            expected_fields: vec![
                ("Proposal ID", FormatOp::Raw as u8),
                ("Proposal Behind Hint", FormatOp::Raw as u8),
                ("Proposal Ahead Hint", FormatOp::Raw as u8),
            ],
            hint_indices: Some((1, 2)),
            enum_index: None,
        },
        GovernanceCase {
            signature: REVOKE_UPVOTE,
            selector: [0xaf, 0x10, 0x8a, 0x0e],
            intent: "Revoke Current Upvote (No ID)",
            intent_rows: [
                "Revoke Current U",
                "pvote (No ID)",
                "Celo Governance",
                "> next",
            ],
            words: vec![u256_from_u64(41).0, u256_from_u64(43).0],
            expected_fields: vec![
                ("Proposal Behind Hint", FormatOp::Raw as u8),
                ("Proposal Ahead Hint", FormatOp::Raw as u8),
            ],
            hint_indices: Some((0, 1)),
            enum_index: None,
        },
        GovernanceCase {
            signature: VOTE,
            selector: [0xbb, 0xb2, 0xea, 0xb9],
            intent: "Vote",
            intent_rows: ["Vote", "Celo", "Celo Governance", "> next"],
            words: vec![u256_from_u64(42).0, u256_from_u64(7).0, u256_from_u64(3).0],
            expected_fields: vec![
                ("Proposal ID", FormatOp::Raw as u8),
                ("Dequeued Index", FormatOp::Raw as u8),
                ("Vote", FormatOp::Enum as u8),
            ],
            hint_indices: None,
            enum_index: Some(2),
        },
        GovernanceCase {
            signature: VOTE_PARTIALLY,
            selector: [0x2e, 0xdf, 0xd1, 0x2e],
            intent: "Partial Vote",
            intent_rows: ["Partial Vote", "Celo", "Celo Governance", "> next"],
            words: vec![
                u256_from_u64(42).0,
                u256_from_u64(7).0,
                u256_from_u64(100).0,
                u256_from_u64(20).0,
                u256_from_u64(3).0,
            ],
            expected_fields: vec![
                ("Proposal ID", FormatOp::Raw as u8),
                ("Dequeued Index", FormatOp::Raw as u8),
                ("Yes Vote Weight", FormatOp::Raw as u8),
                ("No Vote Weight", FormatOp::Raw as u8),
                ("Abstain Vote Weight", FormatOp::Raw as u8),
            ],
            hint_indices: None,
            enum_index: None,
        },
    ];

    let registry = build_registry();
    let mainnet = find_leaf(registry, "calldata-celo_governance.json", MAINNET_CHAIN);
    let mainnet_proxy: [u8; 20] = hex::decode("d533ca259b330c7a88f74e000a3faea2d63b7972")
        .expect("canonical Governance proxy")
        .try_into()
        .expect("address width");
    assert_eq!(mainnet.contract, mainnet_proxy);
    let mainnet_bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let mainnet_verified = verify_erc7730_bundle(&mainnet_bundle, &registry.root)
        .expect("verify mainnet Governance leaf");
    cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &mainnet.contract)
        .expect("bind mainnet Governance leaf");
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, ALFAJORES_CHAIN, &mainnet.contract),
        Err(BindingError::ChainIdMismatch)
    ));
    assert!(matches!(
        cross_check_contract(&mainnet_verified.ir, MAINNET_CHAIN, &[0x55; 20]),
        Err(BindingError::ContractMismatch)
    ));

    let existing_signatures = [
        "approve(uint256,uint256)",
        "dequeueProposalsIfReady()",
        "prepareHotfix(bytes32)",
        "revokeVotes()",
        "withdraw()",
    ];
    let admitted: std::collections::BTreeSet<[u8; 4]> = mainnet_verified
        .ir
        .format_iter()
        .map(|format| format.expect("Governance format parses").selector)
        .collect();
    let expected: std::collections::BTreeSet<[u8; 4]> = existing_signatures
        .iter()
        .copied()
        .chain([UPVOTE, REVOKE_UPVOTE, VOTE, VOTE_PARTIALLY])
        .map(|signature| keccak256(signature.as_bytes())[..4].try_into().unwrap())
        .collect();
    assert_eq!(mainnet_verified.ir.format_count(), Ok(9));
    assert_eq!(admitted, expected);

    let proof_start = 2 + mainnet.ir_bytes.len() + 8;
    assert!(mainnet_bundle.len() > proof_start);
    let mut corrupted_descriptor = mainnet_bundle.clone();
    corrupted_descriptor[2 + mainnet.ir_bytes.len() / 2] ^= 1;
    assert!(
        verify_erc7730_bundle(&corrupted_descriptor, &registry.root).is_err(),
        "a modified Governance descriptor must not verify"
    );
    let mut corrupted_merkle_proof = mainnet_bundle.clone();
    *corrupted_merkle_proof
        .last_mut()
        .expect("Governance bundle carries a proof") ^= 1;
    assert!(
        verify_erc7730_bundle(&corrupted_merkle_proof, &registry.root).is_err(),
        "a modified Governance Merkle proof must not verify"
    );

    let tx = envelope(MAINNET_CHAIN, mainnet.contract);
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let visible_label = |label: &str| {
        if label.len() <= DISPLAY_COLS {
            label.to_string()
        } else {
            let mut rendered = label[..DISPLAY_COLS - 1].to_string();
            rendered.push('~');
            rendered
        }
    };

    for case in &cases {
        assert_eq!(
            &keccak256(case.signature.as_bytes())[..4],
            &case.selector,
            "selector pin for {}",
            case.signature
        );
        let format = mainnet_verified
            .ir
            .find_format_by_selector(&case.selector)
            .expect("Governance format table parses")
            .unwrap_or_else(|| panic!("missing mainnet format {}", case.signature));
        assert_eq!(format.intent, case.intent.as_bytes());
        assert_eq!(usize::from(format.static_head_words), case.words.len());
        assert_eq!(usize::from(format.field_count), case.words.len());
        let actual_fields: Vec<(&str, u8)> = format
            .fields()
            .map(|field| {
                let field = field.expect("Governance field parses");
                (
                    core::str::from_utf8(field.label).expect("ASCII field label"),
                    field.format_op,
                )
            })
            .collect();
        assert_eq!(actual_fields.as_slice(), case.expected_fields.as_slice());

        let calldata = calldata_static(case.signature, &case.words);
        assert_eq!(&calldata[..4], &case.selector);
        assert_selector_matches(&mainnet_verified.ir, &calldata, case.signature);
        let render = |candidate_words: &[[u8; 32]]| {
            let candidate = calldata_static(case.signature, candidate_words);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &candidate,
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            )
        };

        let baseline = render(&case.words)
            .unwrap_or_else(|error| panic!("render {}: {error:?}", case.signature));
        assert_eq!(
            baseline.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0));
        assert_all_pages_printable(&baseline.pages);
        assert_eq!(
            page_strs(&baseline.pages, intent_page_index(&baseline.pages)),
            case.intent_rows.map(str::to_string)
        );
        for (word_index, (label, format_op)) in case.expected_fields.iter().enumerate() {
            if *format_op == FormatOp::Raw as u8 {
                assert_raw_word_pages(
                    &baseline.pages,
                    &visible_label(label),
                    &case.words[word_index],
                );
            }
        }
        if case.signature == REVOKE_UPVOTE {
            assert!(
                baseline
                    .pages
                    .as_slice()
                    .iter()
                    .all(|page| row_str(&page[0]) != "Proposal ID"),
                "revokeUpvote calldata has no proposal ID; live state must not be fabricated"
            );
        }

        for word_index in 0..case.words.len() {
            let mut mutated_words = case.words.clone();
            if case.enum_index == Some(word_index) {
                mutated_words[word_index] = u256_from_u64(2).0;
            } else {
                mutated_words[word_index][31] ^= 1;
            }
            let mutated = render(&mutated_words).unwrap_or_else(|error| {
                panic!(
                    "render {} with independently mutated word {word_index}: {error:?}",
                    case.signature
                )
            });
            assert_ne!(
                baseline.pages.as_slice(),
                mutated.pages.as_slice(),
                "word {word_index} must change trusted pages for {}",
                case.signature
            );
            assert!(
                !baseline
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "word {word_index} must change the transcript for {}",
                case.signature
            );
        }

        if let Some((behind, ahead)) = case.hint_indices {
            let mut zero_hint_words = case.words.clone();
            zero_hint_words[behind] = [0u8; 32];
            zero_hint_words[ahead] = [0u8; 32];
            let zero_hints = render(&zero_hint_words).unwrap_or_else(|error| {
                panic!("render zero hints for {}: {error:?}", case.signature)
            });
            assert_raw_word_pages(
                &zero_hints.pages,
                &visible_label("Proposal Behind Hint"),
                &[0u8; 32],
            );
            assert_raw_word_pages(
                &zero_hints.pages,
                &visible_label("Proposal Ahead Hint"),
                &[0u8; 32],
            );
        }

        if let Some(enum_index) = case.enum_index {
            let vote_field_page = |pages: &Pages| {
                pages
                    .as_slice()
                    .iter()
                    .enumerate()
                    .skip(intent_page_index(pages) + 1)
                    .find(|(_, page)| row_str(&page[0]) == "Vote")
                    .map(|(index, _)| index)
                    .unwrap_or_else(|| {
                        panic!("missing vote enum field page:\n{}", dump_pages(pages))
                    })
            };
            let enum_field = format
                .fields()
                .nth(enum_index)
                .expect("vote enum field exists")
                .expect("vote enum field parses");
            let params =
                pqsigner_erc7730::render::params::parse(&mainnet_verified.ir, enum_field.param_off)
                    .expect("vote enum params parse");
            assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
            assert_eq!(params.integer_width_bytes, Some(1));
            let enum_off = params.enum_ref.expect("vote enum table is authenticated");
            assert_eq!(mainnet_verified.ir.pool[usize::from(enum_off)], 4);

            for (value, label) in [(0, "None"), (1, "Abstain"), (2, "No"), (3, "Yes")] {
                let word = u256_from_u64(value).0;
                assert_eq!(
                    pqsigner_erc7730::render::enums::lookup_enum_label(
                        mainnet_verified.ir.pool,
                        enum_off,
                        &word,
                    )
                    .expect("canonical vote enum table"),
                    Some(label.as_bytes())
                );
                let mut enum_words = case.words.clone();
                enum_words[enum_index] = word;
                let rendered = render(&enum_words)
                    .unwrap_or_else(|error| panic!("render canonical vote {value}: {error:?}"));
                assert_eq!(
                    page_strs(&rendered.pages, vote_field_page(&rendered.pages)),
                    [
                        "Vote".to_string(),
                        label.to_string(),
                        String::new(),
                        String::new(),
                    ]
                );
            }

            let unknown_word = u256_from_u64(4).0;
            assert_eq!(
                pqsigner_erc7730::render::enums::lookup_enum_label(
                    mainnet_verified.ir.pool,
                    enum_off,
                    &unknown_word,
                )
                .expect("canonical vote enum table"),
                None
            );
            let mut unknown_words = case.words.clone();
            unknown_words[enum_index] = unknown_word;
            let unknown = render(&unknown_words).expect("in-width unknown enum renders loudly");
            assert_eq!(
                page_strs(&unknown.pages, vote_field_page(&unknown.pages)),
                [
                    "Vote".to_string(),
                    "4".to_string(),
                    String::new(),
                    "! enum: unknown".to_string(),
                ]
            );

            let mut dirty_uint8 = case.words.clone();
            dirty_uint8[enum_index][0] = 1;
            assert!(matches!(
                render(&dirty_uint8),
                Err(crate::tx::erc7730_render::RenderErr::Reject(
                    "7730 noncanonical integer"
                ))
            ));
        }

        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata[..calldata.len() - 1],
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 short head"
            ))
        ));
        let mut trailing = calldata.clone();
        trailing.push(0);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx,
                &trailing,
                &mainnet_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));

        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let mut dispatched = pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&mainnet_verified),
            None,
            None,
            &resolver,
            &mut proofs,
        )
        .unwrap_or_else(|_| panic!("dispatcher selects {}", case.signature));
        assert_eq!(dispatched.as_slice(), baseline.pages.as_slice());
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
        assert_eq!(verdict, crate::fi::OK_SENTINEL);
        let first_field_label = visible_label(case.expected_fields[0].0);
        dispatched.buf[find_page_by_label(&dispatched, &first_field_label)][1][0] ^= 1;
        verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
        assert_ne!(
            verdict,
            crate::fi::OK_SENTINEL,
            "visible corruption must invalidate the dispatcher proof for {}",
            case.signature
        );
    }

    let alfajores = find_leaf(registry, "calldata-celo_governance.json", ALFAJORES_CHAIN);
    let alfajores_proxy: [u8; 20] = hex::decode("aa963fc97281d9632d96700ab62a4d1340f9a28a")
        .expect("Alfajores Governance proxy")
        .try_into()
        .expect("address width");
    assert_eq!(alfajores.contract, alfajores_proxy);
    let alfajores_bundle = synth_bundle(&registry.blob, &alfajores.ir_bytes, alfajores.leaf_index);
    let alfajores_verified = verify_erc7730_bundle(&alfajores_bundle, &registry.root)
        .expect("verify Alfajores Governance leaf");
    cross_check_contract(&alfajores_verified.ir, ALFAJORES_CHAIN, &alfajores.contract)
        .expect("bind Alfajores Governance leaf");
    assert_eq!(alfajores_verified.ir.format_count(), Ok(5));
    let alfajores_tx = envelope(ALFAJORES_CHAIN, alfajores.contract);
    for case in &cases {
        assert_selector_excluded(&alfajores_verified.ir, case.signature);
        assert!(
            registry
                .known_calls
                .contains(&(ALFAJORES_CHAIN, alfajores.contract, case.selector)),
            "Alfajores {} remains exact-known",
            case.signature
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            ALFAJORES_CHAIN,
            &alfajores.contract,
            &case.selector,
        ));
        let calldata = calldata_static(case.signature, &case.words);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &alfajores_tx,
                &calldata,
                &alfajores_verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::NoFormat)
        ));

        for descriptor in [Some(&alfajores_verified), None] {
            let mut proofs = DispatchPageProofs::new();
            proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &alfajores_tx,
                    &calldata,
                    &signer,
                    None,
                    None,
                    None,
                    descriptor,
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .is_err(),
                "Alfajores {} must not fall back with or without its descriptor",
                case.signature
            );
        }
    }
}

#[test]
fn positive_usdt_transfer_mainnet_renders_send_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert!(matches!(verified.ir.context_kind, ContextKind::Contract));

    let amount = u256_from_u64(100_000_000); // 100.00 USDT (6 decimals)
    let recipient = [0x33u8; 20];
    let calldata = calldata_transfer(recipient, amount);
    assert_selector_matches(&verified.ir, &calldata, "transfer(address,uint256)");

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let checked = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
        &[0u8; 20],
    )
    .expect("checked static render");
    let pages = checked.pages;
    assert_eq!(
        checked.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert_eq!(checked.transcript_receipt.page_count() as usize, pages.len);
    assert!(checked.transcript_receipt.range_matches(&pages, 0));

    assert_all_pages_printable(&pages);

    // Page 0: intent banner.
    let [r0, r1, r2, r3] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Send");
    assert_eq!(r1, "Tether Limited");
    assert_eq!(r2, "Tether USD");
    assert_eq!(r3, "> next");

    // Amount page — labelled "Amount", value should render as
    // "100" / "USDT" across two rows.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    assert!(
        amount_rows[1].contains("100"),
        "amount row 1 should carry the integer part: rows={amount_rows:?}",
    );
    assert!(
        amount_rows[1].contains("USDT") || amount_rows[2].contains("USDT"),
        "USDT ticker missing from amount: rows={amount_rows:?}",
    );

    // To page — labelled "To".
    let to_page = find_page_by_label(&pages, "To");
    let to_rows = page_strs(&pages, to_page);
    let recipient_hex_head = "3333";
    assert!(
        to_rows.iter().any(|r| r.contains(recipient_hex_head)),
        "recipient hex prefix missing: rows={to_rows:?}",
    );
}

#[test]
fn direct_erc7730_dispatch_uses_its_exact_fee_renderer() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify USDT leaf");
    let amount = u256_from_u64(100_000_000);
    let calldata = calldata_transfer([0x33u8; 20], amount);
    let mut tx = envelope(1, entry.contract);
    tx.max_fee_per_gas = u256_from_u128(123_456_789_012u128 * 1_000_000_000);
    tx.max_priority_fee_per_gas = U256::default();
    tx.gas_limit = 21_000;
    assert!(
        !legacy_fee_rows_are_exactly_renderable(
            &tx.max_fee_per_gas,
            &tx.max_priority_fee_per_gas,
            tx.gas_limit,
            tx.chain_id,
        ),
        "fixture must remain wider than the compact legacy fee painter"
    );

    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let pages = pick_sign_pages(
        &tx,
        &calldata,
        &[0u8; 20],
        None,
        None,
        None,
        Some(&verified),
        Some(&usdt_meta),
        None,
        &resolver,
        &mut proofs,
    )
    .expect("direct ERC-7730 dispatch must use its selected exact fee renderer");

    let mut verdict = crate::fi::FAIL_SENTINEL;
    proofs.final_set_proof(&pages, &tx, false, &mut verdict);
    assert_eq!(verdict, crate::fi::OK_SENTINEL);
    assert!(
        pages
            .buf
            .iter()
            .take(pages.len)
            .flatten()
            .map(|row| String::from_utf8_lossy(row).trim().to_owned())
            .any(|row| row == "123456789012"),
        "the selected ERC-7730 painter must publish the exact max-fee value"
    );
}

#[test]
fn flyingtulip_dynamic_token_path_keeps_static_intent_and_exact_token_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PositionsManager.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify FlyingTulip leaf");
    let resolver = NameResolver::new();
    let tx = envelope(1, entry.contract);
    let amount = u256_from_u64(1_000_000); // 1 USDT at six decimals.
    let assets = [
        [
            0x1c, 0xdd, 0x2e, 0xab, 0x61, 0x11, 0x26, 0x97, 0x62, 0x6f, 0x7b, 0x4b, 0xb0, 0xe2,
            0x3d, 0xa4, 0xfe, 0xbf, 0x7b, 0x7c,
        ],
        [
            0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45,
            0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7,
        ],
    ];

    let calldata_for = |asset: [u8; 20], amount: U256| {
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&keccak256(b"deposit(address,uint256)")[..4]);
        let mut asset_word = [0u8; 32];
        asset_word[12..].copy_from_slice(&asset);
        calldata.extend_from_slice(&asset_word);
        calldata.extend_from_slice(&amount.0);
        calldata
    };
    let render = |asset: [u8; 20], amount: U256| {
        let calldata = calldata_for(asset, amount);
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: asset,
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        };
        render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver)
            .expect("FlyingTulip deposit renders")
    };

    let pages_a = render(assets[0], amount);
    let pages_b = render(assets[1], amount);
    assert_eq!(
        page_strs(&pages_a, intent_page_index(&pages_a))[0],
        "Deposit collater",
        "a calldata-derived tokenPath must not authorize value-bearing intent interpolation"
    );
    assert_eq!(
        page_strs(&pages_b, intent_page_index(&pages_b))[0],
        "Deposit collater"
    );
    let amount_page = find_page_by_label(&pages_a, "Amount");
    let amount_rows = page_strs(&pages_a, amount_page);
    assert!(
        amount_rows[1].contains("1")
            && (amount_rows[1].contains("USDT") || amount_rows[2].contains("USDT")),
        "interpolation must not replace the ordinary amount page: {amount_rows:?}"
    );
    assert_ne!(
        pages_a.as_slice(),
        pages_b.as_slice(),
        "same ticker/decimals must not collapse distinct signed assets"
    );
    assert_full_contract_identity_page(&pages_a, &assets[0]);
    assert_full_contract_identity_page(&pages_b, &assets[1]);

    let two_pages = render(assets[0], u256_from_u64(2_000_000));
    assert_eq!(
        page_strs(&two_pages, intent_page_index(&two_pages))[0],
        "Deposit collater",
        "changing the signed amount must not turn a static intent into interpolation"
    );
    assert_ne!(
        page_strs(&pages_a, find_page_by_label(&pages_a, "Amount")),
        page_strs(&two_pages, find_page_by_label(&two_pages, "Amount")),
        "the retained amount page must change with the same signed word"
    );

    let calldata = calldata_for(assets[0], amount);
    let no_meta = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("static intent remains safe with an exact unverified raw amount");
    assert_eq!(
        page_strs(&no_meta, intent_page_index(&no_meta))[0],
        "Deposit collater"
    );
    assert!(
        dump_pages(&no_meta).contains("! raw, dec=?"),
        "missing token metadata must not imply a decimal scale"
    );
    assert_full_unverified_token_identity_page(&no_meta, &assets[0]);
    for meta in [
        Erc20Metadata {
            chain_id: 2,
            contract: assets[0],
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        },
        Erc20Metadata {
            chain_id: 1,
            contract: [0x55; 20],
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        },
    ] {
        let mismatched = render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver)
            .expect("mismatched metadata remains safely unbound");
        assert_eq!(
            page_strs(&mismatched, intent_page_index(&mismatched))[0],
            "Deposit collater",
            "wrong-chain or wrong-contract metadata must not mint a title witness"
        );
        assert!(dump_pages(&mismatched).contains("! raw, dec=?"));
        assert_full_unverified_token_identity_page(&mismatched, &assets[0]);
    }
}

#[test]
fn usdt_shared_descriptor_never_claims_unlimited_on_either_deployment() {
    let res = build_registry();
    let resolver = NameResolver::new();
    let spender = [0x44u8; 20];
    let mut old_threshold_minus_one = [0xff; 32];
    old_threshold_minus_one[0] = 0x7f;
    let mut old_threshold = [0u8; 32];
    old_threshold[0] = 0x80;
    let mut max_minus_one = [0xff; 32];
    max_minus_one[31] = 0xfe;

    for chain_id in [1, 137] {
        let entry = find_leaf(res, "calldata-usdt.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify USDT leaf");
        let tx = envelope(chain_id, entry.contract);
        let metadata = Erc20Metadata {
            chain_id,
            contract: entry.contract,
            decimals: 6,
            name: b"Tether USD",
            symbol: b"USDT",
        };
        let render = |amount: [u8; 32]| {
            let calldata = calldata_approve(spender, U256(amount));
            assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
            render_erc7730_pages(&tx, &calldata, &verified, Some(&metadata), &resolver)
        };

        let ordinary = render(u256_from_u64(1_000_000).0)
            .expect("ordinary exact USDT approval renders");
        assert_eq!(
            page_strs(&ordinary, intent_page_index(&ordinary))[0],
            "Approve"
        );
        assert_full_address_field_page(&ordinary, "Spender", &spender);
        assert!(
            page_strs(&ordinary, find_page_by_label(&ordinary, "Amount"))[1..3]
                .iter()
                .any(|row| row.contains("1 USDT"))
        );
        assert_full_contract_identity_page(&ordinary, &entry.contract);

        for (name, value) in [
            ("old threshold minus one", old_threshold_minus_one),
            ("old threshold", old_threshold),
            ("max minus one", max_minus_one),
            ("max", [0xff; 32]),
        ] {
            assert!(
                matches!(
                    render(value),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(
                        "7730 inexact scaled value"
                    ))
                ),
                "overwide {name} must refuse rather than inherit a shared infinity claim on chain {chain_id}"
            );
        }
    }
}

#[test]
fn walletconnect_wct_allowance_threshold_is_max_only_on_all_deployments() {
    let res = build_registry();
    let resolver = NameResolver::new();
    let spender = [0x51u8; 20];
    let mut old_threshold_minus_one = [0xff; 32];
    old_threshold_minus_one[0] = 0x7f;
    let mut old_threshold = [0u8; 32];
    old_threshold[0] = 0x80;
    let mut max_minus_one = [0xff; 32];
    max_minus_one[31] = 0xfe;

    for chain_id in [1, 10, 8453] {
        let entry = find_leaf(res, "calldata-wct.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify WCT leaf");
        let tx = envelope(chain_id, entry.contract);
        let metadata = Erc20Metadata {
            chain_id,
            contract: entry.contract,
            decimals: 18,
            name: b"WalletConnect Token",
            symbol: b"WCT",
        };
        let render = |amount: [u8; 32]| {
            let calldata = calldata_approve(spender, U256(amount));
            render_erc7730_pages(&tx, &calldata, &verified, Some(&metadata), &resolver)
        };

        let ordinary = render(u256_from_u64(1_000_000_000_000_000_000).0)
            .expect("render exact one-WCT approval");
        assert_full_address_field_page(&ordinary, "Spender", &spender);
        assert!(
            page_strs(&ordinary, find_page_by_label(&ordinary, "Amount"))[1..3]
                .iter()
                .any(|row| row.contains("1 WCT"))
        );
        assert_full_contract_identity_page(&ordinary, &entry.contract);

        let max = render([0xff; 32]).expect("render exact WCT infinity sentinel");
        assert_eq!(
            page_strs(&max, find_page_by_label(&max, "Amount")),
            [
                "Amount".to_string(),
                "unlimited WCT".to_string(),
                "".to_string(),
                "> next".to_string(),
            ]
        );
        assert_full_address_field_page(&max, "Spender", &spender);
        assert_full_contract_identity_page(&max, &entry.contract);

        for (name, finite) in [
            ("old threshold minus one", old_threshold_minus_one),
            ("old threshold", old_threshold),
            ("max minus one", max_minus_one),
        ] {
            assert!(
                matches!(
                    render(finite),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(
                        "7730 inexact scaled value"
                    ))
                ),
                "finite WCT approval at {name} must not inherit the max-only label on chain {chain_id}"
            );
        }
    }
}

#[test]
fn flyingtulip_borrow_is_finite_while_engine_max_is_unlimited() {
    let res = build_registry();
    let resolver = NameResolver::new();
    let delegate = [0x61u8; 20];
    let engine = [0x62u8; 20];
    let asset = [0x63u8; 20];
    let entries: Vec<_> = res
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-PositionsManager.json")
        })
        .collect();
    assert_eq!(
        entries.len(),
        3,
        "all admitted PositionsManager deployments"
    );

    let mut old_threshold_minus_one = [0xff; 32];
    old_threshold_minus_one[0] = 0x7f;
    let mut old_threshold = [0u8; 32];
    old_threshold[0] = 0x80;
    let mut max_minus_one = [0xff; 32];
    max_minus_one[31] = 0xfe;

    for entry in entries {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified =
            verify_erc7730_bundle(&bundle, &res.root).expect("verify PositionsManager leaf");
        let tx = envelope(entry.chain_id, entry.contract);
        let metadata = Erc20Metadata {
            chain_id: entry.chain_id,
            contract: asset,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let render = |signature: &str, actor: [u8; 20], amount: [u8; 32]| {
            let calldata = calldata_static(
                signature,
                &[abi_address_word(actor), abi_address_word(asset), amount],
            );
            render_erc7730_pages(&tx, &calldata, &verified, Some(&metadata), &resolver)
        };

        let ordinary_borrow = render(
            "approveBorrow(address,address,uint256)",
            delegate,
            u256_from_u64(1_000_000).0,
        )
        .expect("ordinary exact borrow allowance renders");
        assert_full_address_field_page(&ordinary_borrow, "Delegate", &delegate);
        assert!(page_strs(
            &ordinary_borrow,
            find_page_by_label(&ordinary_borrow, "Allowance")
        )[1..3]
            .iter()
            .any(|row| row.contains("1 USDC")));
        assert_full_contract_identity_page(&ordinary_borrow, &asset);

        for (name, value) in [
            ("old threshold minus one", old_threshold_minus_one),
            ("old threshold", old_threshold),
            ("max minus one", max_minus_one),
            ("max", [0xff; 32]),
        ] {
            assert!(
                matches!(
                    render("approveBorrow(address,address,uint256)", delegate, value),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(
                        "7730 inexact scaled value"
                    ))
                ),
                "overwide borrow-delegation storage at {name} must refuse rather than be called unlimited"
            );
        }

        let max_engine = render("approveEngine(address,address,uint256)", engine, [0xff; 32])
            .expect("authenticated engine max renders as unlimited");
        assert_eq!(
            page_strs(&max_engine, find_page_by_label(&max_engine, "Allowance")),
            [
                "Allowance".to_string(),
                "Unlimited USDC".to_string(),
                "".to_string(),
                "> next".to_string(),
            ]
        );
        assert_full_address_field_page(&max_engine, "Engine", &engine);
        assert_full_contract_identity_page(&max_engine, &asset);

        for (name, finite) in [
            ("old threshold minus one", old_threshold_minus_one),
            ("old threshold", old_threshold),
            ("max minus one", max_minus_one),
        ] {
            assert!(
                matches!(
                    render("approveEngine(address,address,uint256)", engine, finite),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(
                        "7730 inexact scaled value"
                    ))
                ),
                "overwide finite engine allowance at {name} must refuse rather than inherit the max-only label"
            );
        }
    }
}

#[test]
fn allowance_threshold_curations_keep_static_operands_and_framing_exact() {
    let registry = build_registry();
    let resolver = NameResolver::new();

    for (source, chain_id, signature, words) in [
        (
            "calldata-usdt.json",
            1,
            "approve(address,uint256)",
            vec![abi_address_word([0x41; 20]), [0xff; 32]],
        ),
        (
            "calldata-wct.json",
            1,
            "approve(address,uint256)",
            vec![abi_address_word([0x42; 20]), [0xff; 32]],
        ),
        (
            "calldata-PositionsManager.json",
            1,
            "approveBorrow(address,address,uint256)",
            vec![
                abi_address_word([0x43; 20]),
                abi_address_word([0x44; 20]),
                [0xff; 32],
            ],
        ),
        (
            "calldata-PositionsManager.json",
            1,
            "approveEngine(address,address,uint256)",
            vec![
                abi_address_word([0x45; 20]),
                abi_address_word([0x46; 20]),
                [0xff; 32],
            ],
        ),
    ] {
        let entry = find_leaf(registry, source, chain_id);
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified =
            verify_erc7730_bundle(&bundle, &registry.root).expect("verify allowance leaf");
        let tx = envelope(chain_id, entry.contract);
        let calldata = calldata_static(signature, &words);

        let mut dirty_address = calldata.clone();
        dirty_address[4] = 1;
        assert!(matches!(
            render_erc7730_pages(&tx, &dirty_address, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 noncanonical address"
            ))
        ));
        assert!(matches!(
            render_erc7730_pages(
                &tx,
                &calldata[..calldata.len() - 1],
                &verified,
                None,
                &resolver,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 short head"
            ))
        ));
        let mut trailing = calldata;
        trailing.push(0);
        assert!(matches!(
            render_erc7730_pages(&tx, &trailing, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));
    }
}

#[test]
fn usdt_exact_zero_approve_derives_revoke_from_authenticated_signed_facts() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let spender = [0x44u8; 20];
    let resolver = NameResolver::new();
    let zero_calldata = calldata_approve(spender, U256::zero());
    let pages = render_erc7730_pages(&tx, &zero_calldata, &verified, Some(&meta), &resolver)
        .expect("render zero approval");

    assert_eq!(
        page_strs(&pages, intent_page_index(&pages))[0],
        "Revoke approval"
    );
    let spender_page = find_page_by_label(&pages, "Spender");
    let spender_blob = page_strs(&pages, spender_page).join("");
    assert!(spender_blob.to_ascii_lowercase().contains("44444444"));
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_blob = page_strs(&pages, amount_page).join(" ");
    assert!(
        amount_blob.contains("0 USDT"),
        "zero amount and authenticated ticker must remain visible: {amount_blob:?}"
    );
    assert_full_contract_identity_page(&pages, &entry.contract);
    assert!(pages
        .as_slice()
        .iter()
        .any(|page| row_str(&page[0]) == "Network:" && row_str(&page[1]) == "Chain: 1"));

    // Exact means all 32 signed amount bytes must be zero. Flipping any one
    // byte leaves every other authenticated fact unchanged: displayable values
    // restore the ordinary approval intent, while overwide values refuse.
    let mut rendered_nonzero = 0usize;
    let mut refused_overwide = 0usize;
    for byte in 0..32 {
        let mut nonzero = [0u8; 32];
        nonzero[byte] = 1;
        let calldata = calldata_approve(spender, U256(nonzero));
        match render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver) {
            Ok(changed) => {
                rendered_nonzero += 1;
                assert_eq!(
                    page_strs(&changed, intent_page_index(&changed))[0],
                    "Approve",
                    "nonzero amount byte {byte} must not be called a revocation"
                );
            }
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 inexact scaled value",
            )) => refused_overwide += 1,
            Err(error) => panic!("unexpected nonzero approval refusal at byte {byte}: {error:?}"),
        }
    }
    assert!(rendered_nonzero > 0, "low nonzero words must render");
    assert!(refused_overwide > 0, "overwide nonzero words must refuse");
}

#[test]
fn usdt_zero_approve_without_matching_erc20_capability_keeps_approve_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let calldata = calldata_approve([0x44; 20], U256::zero());

    let no_meta = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("descriptor-only zero approval renders");
    assert_eq!(
        page_strs(&no_meta, intent_page_index(&no_meta))[0],
        "Approve"
    );

    let wrong_contract = Erc20Metadata {
        chain_id: 1,
        contract: [0x55; 20],
        decimals: 6,
        name: b"Not USDT",
        symbol: b"NOPE",
    };
    let mismatched =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&wrong_contract), &resolver)
            .expect("mismatched metadata remains unbound");
    assert_eq!(
        page_strs(&mismatched, intent_page_index(&mismatched))[0],
        "Approve"
    );

    let wrong_chain = Erc20Metadata {
        chain_id: 10,
        contract: entry.contract,
        decimals: 6,
        name: b"Wrong-chain USDT",
        symbol: b"USDT",
    };
    let chain_mismatched =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&wrong_chain), &resolver)
            .expect("wrong-chain metadata remains unbound");
    assert_eq!(
        page_strs(&chain_mismatched, intent_page_index(&chain_mismatched))[0],
        "Approve"
    );
}

#[test]
fn lido_withdrawal_queue_admitted_routes_bind_every_displayed_operand() {
    #[derive(Clone, Copy)]
    enum ExpectedField {
        Address(&'static str),
        Raw(&'static str),
        Approval,
    }

    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido NFT leaf");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let signer = [0x91; 20];
    let render = |call: &[u8]| {
        render_erc7730_pages_with_signer_checked(&tx, call, &verified, None, &resolver, &signer)
    };
    let assert_field = |pages: &Pages, field: ExpectedField, word: &[u8; 32]| match field {
        ExpectedField::Address(label) => {
            let address: [u8; 20] = word[12..].try_into().expect("address word");
            assert_full_address_field_page(pages, label, &address);
        }
        ExpectedField::Raw(label) => assert_raw_word_pages(pages, label, word),
        ExpectedField::Approval => {
            let label = match word[31] {
                0 if word[..31].iter().all(|byte| *byte == 0) => "Revoke all",
                1 if word[..31].iter().all(|byte| *byte == 0) => "Grant all",
                _ => panic!("test supplied a noncanonical bool"),
            };
            assert_eq!(
                page_strs(pages, find_page_by_label(pages, "Access rights")),
                [
                    "Access rights".to_string(),
                    label.to_string(),
                    "".to_string(),
                    "".to_string(),
                ]
            );
        }
    };

    let cases = [
        (
            "approve(address,uint256)",
            vec![abi_address_word([0x11; 20]), u256_from_u64(117_001).0],
            vec![
                ExpectedField::Address("Approval target"),
                ExpectedField::Raw("Request ID"),
            ],
        ),
        (
            "claimWithdrawal(uint256)",
            vec![u256_from_u64(117_002).0],
            vec![ExpectedField::Raw("Request ID")],
        ),
        (
            "safeTransferFrom(address,address,uint256)",
            vec![
                abi_address_word([0x21; 20]),
                abi_address_word([0x22; 20]),
                u256_from_u64(117_003).0,
            ],
            vec![
                ExpectedField::Address("From"),
                ExpectedField::Address("To"),
                ExpectedField::Raw("Request ID"),
            ],
        ),
        (
            "transferFrom(address,address,uint256)",
            vec![
                abi_address_word([0x31; 20]),
                abi_address_word([0x32; 20]),
                u256_from_u64(117_004).0,
            ],
            vec![
                ExpectedField::Address("From"),
                ExpectedField::Address("To"),
                ExpectedField::Raw("Request ID"),
            ],
        ),
        (
            "setApprovalForAll(address,bool)",
            vec![abi_address_word([0x41; 20]), u256_from_u64(1).0],
            vec![ExpectedField::Address("Operator"), ExpectedField::Approval],
        ),
    ];

    for (signature, words, fields) in cases {
        assert_eq!(words.len(), fields.len());
        let calldata = calldata_static(signature, &words);
        assert_selector_matches(&verified.ir, &calldata, signature);
        let rendered =
            render(&calldata).unwrap_or_else(|err| panic!("render {signature}: {err:?}"));
        assert_all_pages_printable(&rendered.pages);
        assert_eq!(
            rendered.transcript_receipt.page_count() as usize,
            rendered.pages.len
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "receipt must bind every {signature} page"
        );
        for (field, word) in fields.iter().copied().zip(words.iter()) {
            assert_field(&rendered.pages, field, word);
        }

        for (word_index, field) in fields.iter().copied().enumerate() {
            let mut mutated_words = words.clone();
            match field {
                ExpectedField::Approval => mutated_words[word_index] = [0u8; 32],
                ExpectedField::Address(_) | ExpectedField::Raw(_) => {
                    mutated_words[word_index][31] ^= 1;
                }
            }
            let mutated_calldata = calldata_static(signature, &mutated_words);
            let mutated = render(&mutated_calldata).unwrap_or_else(|err| {
                panic!("render mutated {signature} word {word_index}: {err:?}")
            });
            assert_field(&mutated.pages, field, &mutated_words[word_index]);
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "mutating {signature} word {word_index} must change trusted pages"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "mutating {signature} word {word_index} must change the transcript receipt"
            );
        }
    }

    // `_to == address(0)` can clear an ERC-721 token approval. The device must
    // show the exact zero target without guessing approve-vs-revoke semantics.
    let zero_target = calldata_static(
        "approve(address,uint256)",
        &[abi_address_word([0u8; 20]), u256_from_u64(117_005).0],
    );
    let zero_render = render(&zero_target).expect("render branch-neutral zero approval target");
    assert_full_address_field_page(&zero_render.pages, "Approval target", &[0u8; 20]);
    let zero_intent = page_strs(&zero_render.pages, intent_page_index(&zero_render.pages));
    assert_eq!(zero_intent[0], "Set unstETH NFT");
    assert_eq!(zero_intent[1], "approval");
    assert!(!dump_pages(&zero_render.pages).contains("Revoke approval"));

    let noncanonical_bool = calldata_static(
        "setApprovalForAll(address,bool)",
        &[abi_address_word([0x41; 20]), u256_from_u64(2).0],
    );
    assert!(
        matches!(
            render(&noncanonical_bool),
            Err(crate::tx::erc7730_render::RenderErr::Reject(_))
        ),
        "ABI bool word 2 must hard-refuse rather than render an unknown choice"
    );
}

#[test]
fn positive_unlimited_uses_descriptor_message_param() {
    // review 3.6: the descriptor's `message` param overrides the default
    // "unlimited" wording (spec: "message above threshold, defaults to
    // Unlimited"). Synthetic approve with message="Max"; rendered unbound so
    // the amount page reads "Max" / "(unverified)".
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-approve-message.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let amount_page = find_page_by_label(&pages, "Amount");
    let blob = page_strs(&pages, amount_page).join("\n");
    assert!(
        blob.contains("Max"),
        "descriptor message 'Max' must render:\n{blob}"
    );
    assert!(
        !blob.to_lowercase().contains("unlimited"),
        "the message param must OVERRIDE the default 'unlimited':\n{blob}"
    );
}

#[test]
fn usdt_approve_max_unbound_renders_the_exact_raw_word() {
    // The shared Ethereum/Polygon descriptor has no implementation-wide
    // infinity sentinel. Without a matching metadata proof, max therefore
    // remains an exact raw integer rather than acquiring semantic wording.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);
    assert!(
        !dump.to_ascii_lowercase().contains("unlimited"),
        "unbound approve(MAX) must not invent an infinity claim:\n{dump}"
    );
    assert_raw_word_pages(&pages, "Amount", &[0xff; 32]);
    assert_full_unverified_token_identity_page(&pages, &entry.contract);
}

#[test]
fn positive_erc7730_golden_grid_hash() {
    // te-2: full-grid golden over a canonical ERC-7730 render (the REAL USDT
    // approve descriptor). ERC-7730 is the highest-churn WYSIWYS surface (it
    // now also carries Aave clear-signing) and the per-field asserts elsewhere
    // check only the amount/label cells; this binds the WHOLE rendered grid so
    // an intent-banner / divider / row-shift regression trips even if the
    // checked substrings survive. Re-bless GOLDEN only for an INTENTIONAL
    // layout change. (Firmware `ui/golden.rs` cannot cover this screen — its
    // input needs the host-only dbgen registry, built here.)
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    let h = super::golden_grid_hash(&pages);

    // Non-vacuity: a different spender address MUST move the digest (the
    // spender renders on-page), proving the hash binds rendered content.
    let calldata2 = calldata_approve([0x77u8; 20], u256_max());
    let h2 = super::golden_grid_hash(
        &render_erc7730_pages(&tx, &calldata2, &verified, None, &resolver).expect("render"),
    );
    assert_ne!(
        h, h2,
        "golden hash must bind rendered content (spender change did not move it)"
    );

    // Re-blessed after inspecting the full grid: the shared Ethereum/Polygon
    // USDT descriptor can no longer claim one implementation-wide infinity
    // sentinel, so MAX is shown as the exact raw 256-bit word instead of the
    // semantic `unlimited` shorthand. The signed spender and every envelope
    // page remain bound by this digest.
    #[cfg(not(feature = "erc7730-dev-unattested"))]
    const GOLDEN: [u8; 32] = [
        0xba, 0x87, 0x66, 0xce, 0x54, 0xb3, 0x40, 0x79, 0x33, 0x2c, 0x3b, 0x95, 0xaf, 0x30, 0x4d,
        0xc3, 0x08, 0x36, 0x68, 0xb1, 0x6c, 0x18, 0x39, 0xbd, 0x39, 0x14, 0x1b, 0x07, 0x2b, 0x31,
        0x71, 0xef,
    ];
    // Same reviewed grid with the mandatory dev-unattested warning prepended.
    #[cfg(feature = "erc7730-dev-unattested")]
    const GOLDEN: [u8; 32] = [
        0xae, 0xfe, 0xc8, 0x69, 0x32, 0xba, 0xae, 0x83, 0xb4, 0x6d, 0xfd, 0x7d, 0xae, 0x7f, 0x9e,
        0x05, 0x90, 0xba, 0x85, 0x7d, 0x18, 0x96, 0x45, 0x3f, 0x93, 0x17, 0xa1, 0xd6, 0xa8, 0x0f,
        0x25, 0x61,
    ];
    assert_eq!(
        h, GOLDEN,
        "ERC-7730 render golden changed — re-bless if intentional. got={h:?}"
    );
}

#[test]
fn positive_aave_withdraw_eth_renders_native_currency() {
    // Item-1 `nativeCurrencyAddress`: Aave `WrappedTokenGatewayV3.withdrawETH`'s
    // `amount` is a `tokenAmount` whose `token` AND `nativeCurrencyAddress` are
    // both the native-ETH sentinel `0x0`. The renderer must resolve it to chain
    // NATIVE currency — 18 decimals + `native_ticker` ("ETH" on mainnet) —
    // WITHOUT an ERC-20 lookup (we pass `erc20 = None`) and WITHOUT emitting the
    // "Token (UNVERIFIED)" identity page for the sentinel address.
    //
    // Non-vacuity: if `is_native` silently flipped false the amount would fall
    // through to the unbound branch — raw integer "1500000000000000000",
    // footer "! raw, dec=?", plus a "Token (UNVERIFIED)" page for `0x0`. Every
    // assertion below (positive "1.5"/"ETH", negative UNVERIFIED/"! raw, dec=?")
    // therefore discriminates the feature working from not.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WrappedTokenGatewayV3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // withdrawETH(address pool, uint256 amount, address to) — 1.5 ETH, chosen
    // to exercise 18-decimal FRACTIONAL formatting (not a round integer).
    let pool = [0x55u8; 20];
    let to = [0x33u8; 20];
    let amount = u256_from_u64(1_500_000_000_000_000_000); // 1.5e18 wei
    let mut calldata = Vec::with_capacity(4 + 3 * 32);
    let sel = keccak256(b"withdrawETH(address,uint256,address)");
    calldata.extend_from_slice(&sel[..4]);
    let mut pool_w = [0u8; 32];
    pool_w[12..].copy_from_slice(&pool);
    calldata.extend_from_slice(&pool_w);
    calldata.extend_from_slice(&amount.0);
    let mut to_w = [0u8; 32];
    to_w[12..].copy_from_slice(&to);
    calldata.extend_from_slice(&to_w);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "withdrawETH(address,uint256,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    // erc20 = None: native rendering must NOT depend on any companion metadata.
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Intent banner.
    assert_eq!(
        page_strs(&pages, intent_page_index(&pages))[0],
        "Withdraw",
        "intent banner:\n{dump}"
    );

    // (a) Native amount: 18-dec fractional "1.5" + chain native ticker "ETH".
    assert!(
        dump.contains("1.5"),
        "native amount should render 1.5:\n{dump}"
    );
    assert!(
        dump.contains("ETH"),
        "native amount must carry ticker ETH:\n{dump}"
    );

    // (b) NO unbound-token artefacts — the sentinel is native, not an unverified
    // ERC-20. These strings appear ONLY when `is_native` is false.
    assert!(
        !dump.contains("Token (UNVERIFI~"),
        "native render must NOT emit a token-identity page for the 0x0 sentinel:\n{dump}",
    );
    assert!(
        !dump.contains("! raw, dec=?"),
        "native render must NOT fall through to the raw-integer unbound path:\n{dump}",
    );

    // The source ignores ABI word zero. Preserve operand completeness without
    // claiming it selects the immutable Pool that receives the withdrawal.
    assert_raw_word_pages(&pages, "Ignored address", &pool_w);
    assert!(
        dump.to_lowercase().contains("5555"),
        "ignored address must render as raw hex:\n{dump}",
    );
}

#[test]
fn positive_defi_catalogue_aave_gateway_non_permit_routes_bind_ignored_operand() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WrappedTokenGatewayV3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Aave gateway leaf");
    // The deployed mainnet source ignores ABI word zero and forwards through
    // its immutable POOL. Keep the signed word visible and transcript-bound,
    // but never describe it as the pool that receives the operation.
    let ignored_address = [0x55u8; 20];
    let changed_ignored_address = [0x54u8; 20];
    let signer = [0x66u8; 20];
    let recipient = [0x77u8; 20];
    let referral_code = 0x1234u16;
    let resolver = NameResolver::new();

    let cases = [
        (
            "depositETH(address,address,uint16)",
            calldata_static(
                "depositETH(address,address,uint16)",
                &[
                    abi_address_word(ignored_address),
                    abi_address_word(recipient),
                    abi_u16_word(referral_code),
                ],
            ),
            u256_from_u64(1_500_000_000_000_000_000),
            "Supply",
            "Amount to supply",
            "Collateral reci~",
            recipient,
            Some(2usize),
        ),
        (
            "repayETH(address,uint256,address)",
            calldata_static(
                "repayETH(address,uint256,address)",
                &[
                    abi_address_word(ignored_address),
                    u256_from_u64(1_000_000_000_000_000_000).0,
                    abi_address_word(recipient),
                ],
            ),
            u256_from_u64(2_000_000_000_000_000_000),
            "Repay loan",
            "Amount to repay",
            "For debt holder",
            recipient,
            None,
        ),
        (
            "borrowETH(address,uint256,uint16)",
            calldata_static(
                "borrowETH(address,uint256,uint16)",
                &[
                    abi_address_word(ignored_address),
                    u256_from_u64(2_000_000_000_000_000_000).0,
                    abi_u16_word(referral_code),
                ],
            ),
            U256::zero(),
            "Borrow",
            "Amount to borrow",
            "Debtor",
            signer,
            Some(2usize),
        ),
        (
            "withdrawETH(address,uint256,address)",
            calldata_static(
                "withdrawETH(address,uint256,address)",
                &[
                    abi_address_word(ignored_address),
                    u256_from_u64(1_500_000_000_000_000_000).0,
                    abi_address_word(recipient),
                ],
            ),
            U256::zero(),
            "Withdraw",
            "Amount to withd~",
            "To recipient",
            recipient,
            None,
        ),
    ];

    for (
        signature,
        calldata,
        tx_value,
        intent,
        amount_label,
        recipient_label,
        recipient,
        referral_word_index,
    ) in cases
    {
        assert_selector_matches(&verified.ir, &calldata, signature);
        let mut tx = envelope(1, entry.contract);
        tx.value = tx_value;
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render Aave {signature}: {error:?}"));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "Aave {signature} receipt must bind its complete rendered page range"
        );
        assert_all_pages_printable(&rendered.pages);
        assert_eq!(
            page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
            intent
        );
        let _ = find_page_by_label(&rendered.pages, amount_label);
        assert_full_address_field_page(&rendered.pages, recipient_label, &recipient);
        assert_raw_word_pages(
            &rendered.pages,
            "Ignored address",
            &abi_address_word(ignored_address),
        );

        let mut ignored_mutation = calldata.clone();
        ignored_mutation[4..36].copy_from_slice(&abi_address_word(changed_ignored_address));
        let ignored_changed = render_erc7730_pages_with_signer_checked(
            &tx,
            &ignored_mutation,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render ignored-address-mutated Aave {signature}: {error:?}"));
        assert_raw_word_pages(
            &ignored_changed.pages,
            "Ignored address",
            &abi_address_word(changed_ignored_address),
        );
        assert_ne!(
            rendered.pages.as_slice(),
            ignored_changed.pages.as_slice(),
            "the independently changed ignored operand must change Aave pages for {signature}"
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&ignored_changed.transcript_receipt),
            "the independently changed ignored operand must change the Aave transcript for {signature}"
        );

        if let Some(word_index) = referral_word_index {
            let referral_word: [u8; 32] = calldata
                [4 + word_index * 32..4 + (word_index + 1) * 32]
                .try_into()
                .expect("Aave referralCode ABI word");
            assert_eq!(referral_word, abi_u16_word(referral_code));
            assert_raw_word_pages(&rendered.pages, "Referral Code", &referral_word);
            let mut referral_mutation = calldata.clone();
            referral_mutation[4 + word_index * 32..4 + (word_index + 1) * 32]
                .copy_from_slice(&abi_u16_word(referral_code ^ 1));
            let referral_changed = render_erc7730_pages_with_signer_checked(
                &tx,
                &referral_mutation,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| panic!("render referral-mutated Aave {signature}: {error:?}"));
            assert_ne!(rendered.pages.as_slice(), referral_changed.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&referral_changed.transcript_receipt));
        }
    }
}

#[test]
fn aave_pqsmartwallet_incompatible_permit_calls_remain_known_but_refused() {
    let registry = build_registry();
    let resolver = NameResolver::new();

    for (source_name, signature, word_count) in [
        (
            "calldata-WrappedTokenGatewayV3.json",
            "withdrawETHWithPermit(address,uint256,address,uint256,uint8,bytes32,bytes32)",
            7,
        ),
        (
            "calldata-lpv3.json",
            "repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)",
            8,
        ),
        (
            "calldata-lpv3.json",
            "supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)",
            8,
        ),
    ] {
        let entry = find_leaf(registry, source_name, 1);
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root)
            .unwrap_or_else(|error| panic!("verify Aave leaf for {signature}: {error:?}"));
        cross_check_contract(&verified.ir, 1, &entry.contract)
            .unwrap_or_else(|error| panic!("bind Aave leaf for {signature}: {error:?}"));
        assert_selector_excluded(&verified.ir, signature);

        let digest = keccak256(signature.as_bytes());
        let selector: [u8; 4] = digest[..4].try_into().expect("selector width");
        assert!(
            registry
                .known_calls
                .contains(&(1, entry.contract, selector)),
            "excluded Aave permit call must remain exactly known: {signature}"
        );
        assert!(
            pqsigner_erc7730::known_calls::may_contain(
                &registry.known_calls_bloom,
                1,
                &entry.contract,
                &selector,
            ),
            "excluded Aave permit call must remain in the fail-closed Bloom: {signature}"
        );

        let calldata = calldata_static(signature, &vec![[0u8; 32]; word_count]);
        let tx = envelope(1, entry.contract);
        assert!(
            matches!(
                render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
                Err(crate::tx::erc7730_render::RenderErr::NoFormat)
            ),
            "excluded Aave permit call must not render directly: {signature}"
        );

        let mut dispatch_proofs = DispatchPageProofs::new();
        dispatch_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &calldata,
                &[0u8; 20],
                None,
                None,
                None,
                Some(&verified),
                None,
                None,
                &resolver,
                &mut dispatch_proofs,
            )
            .is_err(),
            "bound descriptor must refuse without fallback for excluded Aave permit call: {signature}"
        );
    }
}

#[test]
fn defi_catalogue_aave_multicall_remains_excluded() {
    let res = build_registry();

    let pool = find_leaf(res, "calldata-lpv3.json", 1);
    let pool_bundle = synth_bundle(&res.blob, &pool.ir_bytes, pool.leaf_index);
    let pool_verified =
        verify_erc7730_bundle(&pool_bundle, &res.root).expect("verify Aave Pool leaf");
    assert_selector_excluded(&pool_verified.ir, "multicall(bytes[])");
}

#[test]
fn positive_1inch_clipper_renders_zero_as_native_and_eeee_as_unverified_token() {
    // The deployed V4 ClipperRouter treats only address zero as native. The
    // shared 0xEeee sentinel is valid for other router paths but must not be
    // inherited by these Clipper amounts. `clipperSwap` is all-static,
    // complete, and binds its beneficiary to the device-derived signer.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-AggregationRouterV4-eth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify 1inch leaf");
    let signer = [0x12u8; 20];
    let resolver = NameResolver::new();
    let tx = envelope(1, entry.contract);

    let calldata = |src_token: [u8; 20]| {
        let mut out = Vec::with_capacity(4 + 4 * 32);
        let selector = keccak256(b"clipperSwap(address,address,uint256,uint256)");
        out.extend_from_slice(&selector[..4]);
        for address in [src_token, [0u8; 20]] {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&address);
            out.extend_from_slice(&word);
        }
        out.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_000).0);
        out.extend_from_slice(&u256_from_u64(2_250_000_000_000_000_000).0);
        out
    };

    let native_calldata = calldata([0u8; 20]);
    assert_selector_matches(
        &verified.ir,
        &native_calldata,
        "clipperSwap(address,address,uint256,uint256)",
    );
    let pages = render_erc7730_pages_with_signer(
        &tx,
        &native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("the deployed Clipper native sentinel renders as ETH");
    let dump = dump_pages(&pages);
    assert_eq!(page_strs(&pages, intent_page_index(&pages))[0], "Swap");
    let send = page_strs(&pages, find_page_by_label(&pages, "Amount to Send")).join("\n");
    let receive = page_strs(&pages, find_page_by_label(&pages, "Minimum to Rece~")).join("\n");
    assert!(send.contains("1.5") && send.contains("ETH"), "{dump}");
    assert!(
        receive.contains("2.25") && receive.contains("ETH"),
        "{dump}"
    );
    assert!(
        !dump.contains("Token (UNVERIFI~") && !dump.contains("! raw, dec=?"),
        "address zero must stay on the native path for both amounts:\n{dump}"
    );
    let beneficiary = page_strs(&pages, find_page_by_label(&pages, "Beneficiary"));
    assert_eq!(beneficiary[1], "0x12121212121212");

    // The shared 0xEeee sentinel is deliberately not a Clipper native member,
    // while the zero-address receive token still is. With no ERC-20 metadata,
    // the send amount must become raw and expose the unverified token identity.
    let miss = [0xEEu8; 20];
    let miss_pages =
        render_erc7730_pages_with_signer(&tx, &calldata(miss), &verified, None, &resolver, &signer)
            .expect("one-byte list miss remains safely renderable as unverified raw");
    let miss_dump = dump_pages(&miss_pages);
    assert!(miss_dump.contains("! raw, dec=?"), "{miss_dump}");
    assert!(miss_dump.contains("Token (UNVERIFI~"), "{miss_dump}");
    let miss_receive = page_strs(
        &miss_pages,
        find_page_by_label(&miss_pages, "Minimum to Rece~"),
    )
    .join("\n");
    assert!(
        miss_receive.contains("2.25") && miss_receive.contains("ETH"),
        "the zero destination sentinel must remain native when 0xEeee is rejected:\n{miss_dump}"
    );
}

/// Multi-chain chain-pinning: USDT's registry descriptor carries Mainnet (1)
/// AND Polygon (137) deployments under the SAME JSON. Picking the chain-137
/// leaf (contract 0xc2132D…8e8F, the bridged Polygon USDT) proves the
/// renderer + bundle verifier bind to the right `(chain_id, contract)` leaf —
/// a Mainnet tx must never render against the Polygon leaf and vice-versa.
/// Replaces the deleted vacuous `circle-usdc` chain-pinning test, which fed
/// an EIP-712 descriptor calldata it could never render (its
/// `find_format_by_selector` guard early-returned, asserting nothing).
#[test]
fn positive_usdt_transfer_polygon_chain_pinning() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 137);
    // The chain-137 leaf is the bridged Polygon USDT, a different address
    // from Mainnet's 0xdAC17… — proves we picked the right deployment.
    let polygon_usdt = hex::decode("c2132D05D31c914a87C6611C10748AEb04B58e8F").unwrap();
    assert_eq!(
        &entry.contract[..],
        &polygon_usdt[..],
        "chain-137 leaf must bind the Polygon USDT contract"
    );

    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert_eq!(verified.ir.chain_id, 137, "verified leaf is chain 137");
    assert_eq!(
        &verified.ir.contract,
        &polygon_usdt[..],
        "verified leaf contract"
    );

    let calldata = calldata_transfer([0x33u8; 20], u256_from_u64(100_000_000));
    assert_selector_matches(&verified.ir, &calldata, "transfer(address,uint256)");

    let tx = envelope(137, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 137,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdt_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);

    // The Polygon leaf renders the same "Send" intent as Mainnet.
    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Send");
}

#[test]
fn positive_weth_deposit_and_withdraw_bind_exact_amounts() {
    let res = build_registry();
    let calldata = calldata_deposit();
    assert_eq!(calldata, [0xd0, 0xe3, 0x0d, 0xb0]);

    for (chain_id, expected_contract) in [
        (1, "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        (11_155_111, "fff9976782d46cc05630d1f6ebab18b2324d6b14"),
    ] {
        let entry = find_leaf(res, "calldata-weth.json", chain_id);
        assert_eq!(hex::encode(entry.contract), expected_contract);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify WETH9 leaf");
        cross_check_contract(&verified.ir, chain_id, &entry.contract)
            .expect("bind exact WETH9 deployment");
        assert_selector_matches(&verified.ir, &calldata, "deposit()");

        let render_value = |value| {
            let mut tx = envelope(chain_id, entry.contract);
            tx.value = u256_from_u64(value);
            render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
                .expect("render exact WETH9 deposit")
        };
        let half_pages = render_value(500_000_000_000_000_000);
        assert_all_pages_printable(&half_pages);
        let [intent_r0, owner_r, contract_r, _] =
            page_strs(&half_pages, intent_page_index(&half_pages));
        assert_eq!(intent_r0, "Wrap");
        assert_eq!(owner_r, "WETH");
        assert_eq!(contract_r, "WETH");
        let half_rows = page_strs(&half_pages, find_page_by_label(&half_pages, "Amount"));
        assert_eq!(half_rows[1], "0.5 ETH");

        let one_pages = render_value(1_000_000_000_000_000_000);
        let one_rows = page_strs(&one_pages, find_page_by_label(&one_pages, "Amount"));
        assert_eq!(one_rows[1], "1 ETH");
        assert_ne!(
            half_rows, one_rows,
            "transaction value must alter the transcript"
        );

        let mut trailing = calldata.clone();
        trailing.push(0);
        let mut tx = envelope(chain_id, entry.contract);
        tx.value = u256_from_u64(500_000_000_000_000_000);
        assert!(matches!(
            render_erc7730_pages(&tx, &trailing, &verified, None, &NameResolver::new()),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));

        let metadata = (chain_id == 1).then_some(Erc20Metadata {
            chain_id,
            contract: entry.contract,
            decimals: 18,
            name: b"Wrapped Ether",
            symbol: b"WETH",
        });
        let render_withdraw = |amount| {
            let withdraw = calldata_weth_withdraw(u256_from_u64(amount));
            let tx = envelope(chain_id, entry.contract);
            let pages = render_erc7730_pages(
                &tx,
                &withdraw,
                &verified,
                metadata.as_ref(),
                &NameResolver::new(),
            )
            .expect("render exact WETH9 withdraw");
            (pages, withdraw)
        };

        let half_amount = 500_000_000_000_000_000;
        let (half_withdraw_pages, half_withdraw) = render_withdraw(half_amount);
        assert_eq!(half_withdraw.len(), 36);
        assert_eq!(
            &half_withdraw[4..],
            &u256_from_u64(half_amount).0,
            "the transcript input must carry the exact withdrawal word"
        );
        assert_all_pages_printable(&half_withdraw_pages);
        let [intent_r0, owner_r, contract_r, _] = page_strs(
            &half_withdraw_pages,
            intent_page_index(&half_withdraw_pages),
        );
        assert_eq!(intent_r0, "Unwrap");
        assert_eq!(owner_r, "WETH");
        assert_eq!(contract_r, "WETH");
        let amount_rows = page_strs(
            &half_withdraw_pages,
            find_page_by_label(&half_withdraw_pages, "Amount"),
        )
        .join(" ");
        let amount_compact: String = amount_rows
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        if chain_id == 1 {
            assert!(
                amount_rows.contains("0.5 WETH"),
                "mainnet metadata must scale the exact word: {amount_rows:?}"
            );
            assert_full_contract_identity_page(&half_withdraw_pages, &entry.contract);
        } else {
            assert!(
                amount_compact.contains("500000000000000000")
                    && amount_rows.contains("! raw, dec=?"),
                "Sepolia without metadata must show the exact raw word: {amount_rows:?}"
            );
            assert_full_unverified_token_identity_page(&half_withdraw_pages, &entry.contract);
        }

        let (one_withdraw_pages, _) = render_withdraw(1_000_000_000_000_000_000);
        assert_ne!(
            dump_pages(&half_withdraw_pages),
            dump_pages(&one_withdraw_pages),
            "changing the signed withdrawal word must change the transcript"
        );

        let short = &half_withdraw[..half_withdraw.len() - 1];
        let tx = envelope(chain_id, entry.contract);
        assert!(matches!(
            render_erc7730_pages(
                &tx,
                short,
                &verified,
                metadata.as_ref(),
                &NameResolver::new(),
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 short head"
            ))
        ));
        let mut trailing_withdraw = half_withdraw.clone();
        trailing_withdraw.push(0);
        assert!(matches!(
            render_erc7730_pages(
                &tx,
                &trailing_withdraw,
                &verified,
                metadata.as_ref(),
                &NameResolver::new(),
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));
    }
}

#[test]
fn positive_native_amount_uses_chain_ticker_not_eth_on_polygon() {
    // review 3.5: the `amount` format defaults to the chain's NATIVE ticker,
    // not always "ETH". A Polygon (137) descriptor must render "POL". (The WETH
    // deposit test above covers the chain-1 → ETH case by render.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-native-amount.json", 137);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"pay(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(500_000_000_000_000_000).0); // 0.5
    assert_selector_matches(&verified.ir, &calldata, "pay(uint256)");
    let tx = envelope(137, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let amount_page = find_page_by_label(&pages, "Amount");
    let rows = page_strs(&pages, amount_page).join(" ");
    assert!(
        rows.contains("POL"),
        "Polygon native amount must render POL:\n{rows}"
    );
    assert!(
        !rows.contains("ETH"),
        "must NOT render ETH on Polygon:\n{rows}"
    );
}

// NOTE: The corresponding EIP-712 path (`render_erc7730_eip712_pages`)
// would be the right way to exercise USDC's TransferWithAuthorization
// descriptor — but the firmware-side EIP-712 entry point requires the
// 32-byte primaryTypeHash + ABI-encoded data buffer that the
// `cmd_sign_offchain` handler computes from the dapp's typed payload,
// and that scaffolding is wired through the on-device sign command
// rather than the renderer's public API. A future test pass that
// reaches into `cmd_sign_offchain` would close that gap; for now we
// limit coverage to the contract-context path above.
//
// (Multi-chain chain-pinning is now exercised by
// `positive_usdt_transfer_polygon_chain_pinning` above, against the real
// registry USDT descriptor's chain-137 leaf. The former
// `positive_usdc_transfer_polygon_uses_correct_chain_pinning` was vacuous:
// it fed `transfer` calldata to an EIP-712 `circle-usdc` descriptor whose
// `find_format_by_selector` guard always early-returned, asserting nothing.)

#[test]
fn negative_unknown_selector_returns_no_format() {
    // The renderer must NOT try to fall through to a "best-guess"
    // format. The raw renderer reports `NoFormat`; because this descriptor
    // has already verified and bound, the dispatcher must refuse rather than
    // downgrade the same request to a weaker blind-sign interpretation.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 0xdeadbeef — selector not in the bounded registry WETH descriptor.
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!("expected RenderErr::NoFormat for unknown selector, got {other:?}"),
        Ok(_) => panic!("unknown selector must not render"),
    }
}

#[test]
fn negative_verified_descriptor_no_format_refuses_dispatch() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let mut dispatch_proofs = super::dispatch::DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();

    let outcome = pick_sign_pages(
        &tx,
        &calldata,
        &[0u8; 20],
        None,
        None,
        None,
        Some(&verified),
        None,
        None,
        &resolver,
        &mut dispatch_proofs,
    );
    assert!(
        outcome.is_err(),
        "a bound verified descriptor that cannot render must not fall through"
    );
}

#[test]
fn negative_short_calldata_rejects() {
    // Less than 4 bytes — can't even extract a selector. The renderer
    // must reject cleanly so a verified-descriptor caller can fail closed.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata: Vec<u8> = vec![0xab, 0xcd]; // 2 bytes
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!("expected NoFormat, got {other:?}"),
        Ok(_) => panic!("short calldata must not render"),
    }
}

#[test]
fn positive_intent_truncation_is_safe() {
    // The intent banner now wraps the intent across two rows (up to 32 chars,
    // a visible `~` marker beyond that) instead of the old 10-char "Sign: "
    // prefix form, so an intent of ANY length renders safely (no silent clip).
    // Verify the seed corpus' intents stay within the host-pipeline ASCII cap
    // (≤ 254 B) and that every rendered row stays within DISPLAY_COLS = 16.
    let res = build_seed();
    for entry in &res.entries {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified =
            verify_erc7730_bundle(&bundle, &res.root).expect("seed corpus entries verify");
        if !matches!(verified.ir.context_kind, ContextKind::Contract) {
            continue;
        }
        for fmt in verified.ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            assert!(
                fmt.intent.len() <= 254,
                "intent exceeds the host-pipeline ASCII cap: {:?}",
                core::str::from_utf8(fmt.intent).unwrap_or("<bin>")
            );
            // The banner caps every row at DISPLAY_COLS and marks truncation
            // with `~`; the row-length invariant is asserted at the page level
            // via `assert_all_pages_printable` (and the wrap/marker behaviour by
            // `positive_long_intent_wraps_and_marks_truncation`).
        }
    }
}

#[test]
fn positive_long_intent_wraps_and_marks_truncation() {
    // review 4.1: the intent banner drops the old "Sign: " prefix and wraps the
    // intent across rows 0-1 (32 chars). A >32-char intent gets a visible `~`
    // marker in the last cell — never a silent clip.
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-long-intent.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"f(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1).0);
    assert_selector_matches(&verified.ir, &calldata, "f(uint256)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    // "Withdraw Collateral from the Morpho Market" (42 chars) → rows 0-1.
    let [r0, r1, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(
        r0, "Withdraw Collate",
        "row 0 = first 16 chars, no `Sign:` prefix"
    );
    assert!(
        r1.starts_with("ral from the"),
        "row 1 = intent continuation, got {r1:?}"
    );
    assert!(
        r1.ends_with('~'),
        "row 1 must mark truncation with `~`, got {r1:?}"
    );
}

#[test]
fn positive_medium_intent_wraps_two_rows_no_marker() {
    // review 4.1: a 17..32-char intent uses both rows with NO marker.
    // "Request stETH withdrawal" (24 chars) → "Request stETH wi" / "thdrawal".
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = rw_calldata(&[u256_from_u64(1_000_000_000_000_000_000)], [0x55u8; 20]);
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let [r0, r1, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Request stETH wi");
    assert_eq!(r1, "thdrawal");
    assert!(!r1.contains('~'), "24 chars fits two rows → no marker");
}

#[test]
fn positive_erc8213_fingerprint_renders_full_hash() {
    // The ERC-8213 fingerprint page is independent of the descriptor —
    // it just renders the 32-byte hash. Smoke-test it produces exactly
    // 2 pages and the rendered hex matches the input bytewise.
    let mut pages = Pages::empty_with_len(0);

    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    append_fingerprint_for_test(&mut pages, Erc8213Kind::CalldataDigest(hash))
        .expect("fingerprint fits");

    assert_eq!(pages.len, 2, "fingerprint renders exactly 2 pages");
    assert_all_pages_printable(&pages);

    // Banner: row 0 "8213 Fingerprint", row 1 "CalldataDigest".
    assert_eq!(row_str(&pages.buf[0][0]), "8213 Fingerprint");
    assert_eq!(row_str(&pages.buf[0][1]), "CalldataDigest");
    assert_eq!(row_str(&pages.buf[0][3]), "> verify off-dev");

    // Hash page: 8 bytes per row × 4 rows = full 32 B.
    let hash_page = &pages.buf[1];
    let rendered: String = hash_page
        .iter()
        .map(|r| row_str(r))
        .collect::<Vec<_>>()
        .join("");
    let expected_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rendered, expected_hex,
        "fingerprint rows must spell out the full 32-byte hash bytewise"
    );
}

fn append_fingerprint_for_test(pages: &mut Pages, kind: Erc8213Kind) -> Result<(), ()> {
    let mut cfi = crate::fi::CfiCounter::new();
    append_fingerprint_page(pages, kind, &mut cfi)?;
    if cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(())
}

fn eip712_transcript_verdict(
    proof: &super::erc7730_secure_shim::Eip712TranscriptProof,
    pages: &Pages,
) -> u32 {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    proof.final_set_proof(pages, &mut verdict);
    verdict
}

#[test]
fn positive_erc8213_labels_cover_every_kind() {
    // Pin the label text on every Kind variant. Surfaces a regression
    // where someone renames the label in `erc8213.rs::Kind::label`
    // without updating the doc + tests in lockstep.
    for (kind, expected_label) in [
        (Erc8213Kind::CalldataDigest([0u8; 32]), "CalldataDigest"),
        (Erc8213Kind::Eip712Final([0u8; 32]), "EIP-712 Final"),
        (Erc8213Kind::Raw32([0u8; 32]), "Raw32 Hash"),
        (Erc8213Kind::ReplaySafeHash([0u8; 32]), "ReplaySafe Hash"),
        (Erc8213Kind::SafeTxHash([0u8; 32]), "SafeTxHash"),
    ] {
        let mut pages = Pages::empty_with_len(0);
        append_fingerprint_for_test(&mut pages, kind).expect("fits");
        assert_eq!(
            row_str(&pages.buf[0][1]),
            expected_label,
            "label row for {:?}",
            std::any::type_name_of_val(&kind)
        );
    }
}

#[test]
fn raw32_input_and_replay_safe_signed_hash_render_as_distinct_complete_pairs() {
    let raw_h = [0x11u8; 32];
    let signed_h = [0xA7u8; 32];
    let raw_kind = Erc8213Kind::Raw32(raw_h);
    let signed_kind = Erc8213Kind::ReplaySafeHash(signed_h);
    let mut pages = Pages::empty_with_len(0);

    let raw_index = pages.len;
    append_fingerprint_for_test(&mut pages, raw_kind).unwrap();
    let signed_index = pages.len;
    append_fingerprint_for_test(&mut pages, signed_kind).unwrap();

    assert_eq!(pages.len, 4);
    assert_eq!(row_str(&pages.buf[raw_index][1]), "Raw32 Hash");
    assert_eq!(row_str(&pages.buf[signed_index][1]), "ReplaySafe Hash");
    for row in &pages.buf[raw_index + 1] {
        assert_eq!(row_str(row), "1111111111111111");
    }
    for row in &pages.buf[signed_index + 1] {
        assert_eq!(row_str(row), "a7a7a7a7a7a7a7a7");
    }
    assert_eq!(
        fingerprint_final_set_proof(&pages, raw_index, raw_kind),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        fingerprint_final_set_proof(&pages, signed_index, signed_kind),
        crate::fi::OK_SENTINEL
    );
    assert_ne!(
        fingerprint_final_set_proof(
            &pages,
            signed_index,
            Erc8213Kind::ReplaySafeHash([0xA6; 32]),
        ),
        crate::fi::OK_SENTINEL,
        "the signed-hash proof must bind every nested-hash byte"
    );
}

#[test]
fn erc8213_append_is_atomic_and_requires_both_complete_pages() {
    use pqsigner_erc7730::display::erc8213_contract::FINGERPRINT_PAGES;
    use pqsigner_erc7730::display::MAX_PAGES;

    let mut one_page_short = Pages::empty_with_len(MAX_PAGES - 1);
    one_page_short.buf[MAX_PAGES - 2][0] = *b"existing page   ";
    let before_len = one_page_short.len;
    let before_page = one_page_short.buf[MAX_PAGES - 2];
    assert!(
        append_fingerprint_for_test(&mut one_page_short, Erc8213Kind::CalldataDigest([0xA5; 32]),)
            .is_err(),
        "one free page must not permit a banner without the complete hash"
    );
    assert_eq!(one_page_short.len, before_len);
    assert_eq!(one_page_short.buf[MAX_PAGES - 2], before_page);

    let mut exact_fit = Pages::empty_with_len(MAX_PAGES - FINGERPRINT_PAGES);
    append_fingerprint_for_test(&mut exact_fit, Erc8213Kind::CalldataDigest([0x5A; 32]))
        .expect("exact two-page capacity must fit");
    assert_eq!(exact_fit.len, MAX_PAGES);
    assert_eq!(
        row_str(&exact_fit.buf[MAX_PAGES - 2][0]),
        "8213 Fingerprint"
    );
    assert_eq!(
        row_str(&exact_fit.buf[MAX_PAGES - 1][0]),
        "5a5a5a5a5a5a5a5a"
    );
}

#[test]
fn erc8213_authoritative_append_mints_cfi_and_binds_exact_pair() {
    let kind = Erc8213Kind::Eip712Final([0xa5; 32]);
    let mut pages = Pages::empty_with_len(3);
    for (index, page) in pages.buf[..pages.len].iter_mut().enumerate() {
        *page = [[b'A' + index as u8; DISPLAY_COLS]; 4];
    }
    let prefix = pages.buf;
    let prior_len = pages.len;
    let mut cfi = crate::fi::CfiCounter::new();

    append_fingerprint_page(&mut pages, kind, &mut cfi).expect("pair fits");
    assert_eq!(&pages.buf[..prior_len], &prefix[..prior_len]);
    assert_eq!(
        cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );

    let skipped = crate::fi::CfiCounter::new();
    assert_ne!(
        skipped.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "skipping the whole append must leave caller-owned CFI short"
    );

    pages.buf[prior_len + 1][3][15] ^= 1;
    assert_ne!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
    assert_ne!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
}

#[test]
fn erc8213_proofs_reject_wrong_index_kind_hash_and_short_capacity() {
    use pqsigner_erc7730::display::MAX_PAGES;

    let kind = Erc8213Kind::Raw32([0x3c; 32]);
    let mut pages = Pages::empty_with_len(2);
    let prior_len = pages.len;
    let mut cfi = crate::fi::CfiCounter::new();
    append_fingerprint_page(&mut pages, kind, &mut cfi).unwrap();

    for wrong in [
        Erc8213Kind::Raw32([0x3d; 32]),
        Erc8213Kind::CalldataDigest([0x3c; 32]),
        Erc8213Kind::Eip712Final([0x3c; 32]),
        Erc8213Kind::SafeTxHash([0x3c; 32]),
    ] {
        assert_ne!(
            fingerprint_page_proof(&pages, prior_len, wrong),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            fingerprint_final_set_proof(&pages, prior_len, wrong),
            crate::fi::OK_SENTINEL
        );
    }
    assert_ne!(
        fingerprint_final_set_proof(&pages, prior_len - 1, kind),
        crate::fi::OK_SENTINEL
    );

    pages.push_blank().unwrap();
    assert_ne!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL,
        "the transition proof must reject later growth"
    );
    assert_eq!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL,
        "the final-set proof must tolerate later append-only pages"
    );

    let mut short = Pages::empty_with_len(MAX_PAGES - 1);
    let before = short.buf;
    let mut short_cfi = crate::fi::CfiCounter::new();
    assert!(append_fingerprint_page(&mut short, kind, &mut short_cfi).is_err());
    assert_eq!(short.len, MAX_PAGES - 1);
    assert_eq!(
        short.buf, before,
        "failed atomic append must preserve all pages"
    );
    assert_ne!(
        short_cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
}

// ───────────────────────────────────────────────────────────────────────
// Aave V3 basic lending. `borrow`, `deposit`, and `supply` now expose the
// complete referralCode word instead of hiding signed material. `repay`
// remains an independent enum-table control.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_aave_basic_lending_renders_complete_referral_and_signed_fields() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let asset = [
        0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45, 0x97,
        0xc1, 0x3d, 0x83, 0x1e, 0xc7,
    ];
    let debtor = [0x44u8; 20];
    let collateral_recipient = [0x55u8; 20];
    let amount = u256_from_u64(500_000_000); // 500 USDT at six decimals.
    let referral_code = 0x1234u16;
    let token = Erc20Metadata {
        chain_id: 1,
        contract: asset,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();

    let cases = [
        (
            "borrow(address,uint256,uint256,uint16,address)",
            calldata_borrow(asset, amount, u256_from_u64(2), referral_code, debtor),
            "Borrow",
            "Amount to borrow",
            "Debtor",
            debtor,
        ),
        (
            "deposit(address,uint256,address,uint16)",
            calldata_aave_supply_like(
                b"deposit(address,uint256,address,uint16)",
                asset,
                amount,
                collateral_recipient,
                referral_code,
            ),
            "Supply",
            "Amount to supply",
            "Collateral reci~",
            collateral_recipient,
        ),
        (
            "supply(address,uint256,address,uint16)",
            calldata_aave_supply_like(
                b"supply(address,uint256,address,uint16)",
                asset,
                amount,
                collateral_recipient,
                referral_code,
            ),
            "Supply",
            "Amount to supply",
            "Collateral reci~",
            collateral_recipient,
        ),
    ];

    for (signature, calldata, intent, amount_label, recipient_label, recipient) in cases {
        assert_selector_matches(&verified.ir, &calldata, signature);
        let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&token), &resolver)
            .unwrap_or_else(|error| panic!("render {signature}: {error:?}"));
        assert_all_pages_printable(&pages);
        assert_eq!(page_strs(&pages, intent_page_index(&pages))[0], intent);

        let amount_rows = page_strs(&pages, find_page_by_label(&pages, amount_label));
        assert!(
            amount_rows.iter().any(|row| row.contains("500"))
                && amount_rows.iter().any(|row| row.contains("USDT")),
            "bound amount missing for {signature}: {amount_rows:?}"
        );
        assert_full_contract_identity_page(&pages, &asset);
        assert_full_address_field_page(&pages, recipient_label, &recipient);

        let referral_word: [u8; 32] = calldata[4 + 3 * 32..4 + 4 * 32]
            .try_into()
            .expect("referralCode ABI word");
        assert!(referral_word[..30].iter().all(|byte| *byte == 0));
        assert_eq!(&referral_word[30..], &referral_code.to_be_bytes());
        assert_raw_word_pages(&pages, "Referral Code", &referral_word);

        if signature.starts_with("borrow(") {
            let rows = page_strs(&pages, find_page_by_label(&pages, "Interest Rate m~"));
            assert!(
                rows[1].contains("variable"),
                "borrow enum missing: {rows:?}"
            );
            assert!(!rows.iter().any(|row| row.trim() == "2"));
        }
    }

    let original = calldata_borrow(asset, amount, u256_from_u64(2), 0x1234, debtor);
    let mutated = calldata_borrow(asset, amount, u256_from_u64(2), 0x1235, debtor);
    assert_eq!(original[..4 + 3 * 32], mutated[..4 + 3 * 32]);
    assert_ne!(original[4 + 3 * 32..], mutated[4 + 3 * 32..]);
    let original_pages =
        render_erc7730_pages(&tx, &original, &verified, Some(&token), &resolver).expect("render");
    let mutated_pages =
        render_erc7730_pages(&tx, &mutated, &verified, Some(&token), &resolver).expect("render");
    assert_ne!(
        original_pages.as_slice(),
        mutated_pages.as_slice(),
        "one signed referralCode bit must change the trusted transcript"
    );
    let mutated_word: [u8; 32] = mutated[4 + 3 * 32..4 + 4 * 32]
        .try_into()
        .expect("mutated referralCode word");
    assert_raw_word_pages(&mutated_pages, "Referral Code", &mutated_word);
}

#[test]
fn positive_aave_v2_borrow_and_deposit_bind_complete_referral_words() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv2.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Aave V2 leaf");

    let asset = [
        0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45, 0x97,
        0xc1, 0x3d, 0x83, 0x1e, 0xc7,
    ];
    let debtor = [0x44u8; 20];
    let collateral_recipient = [0x55u8; 20];
    let signer = [0x66u8; 20];
    let amount = u256_from_u64(500_000_000); // 500 USDT at six decimals.
    let referral_code = 0x1234u16;
    let token = Erc20Metadata {
        chain_id: 1,
        contract: asset,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();

    let cases = [
        (
            "borrow(address,uint256,uint256,uint16,address)",
            calldata_borrow(asset, amount, u256_from_u64(2), referral_code, debtor),
            calldata_borrow(asset, amount, u256_from_u64(2), referral_code ^ 1, debtor),
            "Borrow",
            "Amount to borrow",
            "Debtor",
            debtor,
        ),
        (
            "deposit(address,uint256,address,uint16)",
            calldata_aave_supply_like(
                b"deposit(address,uint256,address,uint16)",
                asset,
                amount,
                collateral_recipient,
                referral_code,
            ),
            calldata_aave_supply_like(
                b"deposit(address,uint256,address,uint16)",
                asset,
                amount,
                collateral_recipient,
                referral_code ^ 1,
            ),
            "Supply",
            "Amount to supply",
            "Collateral reci~",
            collateral_recipient,
        ),
    ];

    for (signature, calldata, mutated_calldata, intent, amount_label, recipient_label, recipient) in
        cases
    {
        assert_selector_matches(&verified.ir, &calldata, signature);
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            Some(&token),
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render Aave V2 {signature}: {error:?}"));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "Aave V2 {signature} receipt must bind its complete rendered page range"
        );
        assert_all_pages_printable(&rendered.pages);
        assert_eq!(
            page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
            intent
        );

        let amount_rows = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, amount_label),
        );
        assert!(
            amount_rows.iter().any(|row| row.contains("500"))
                && amount_rows.iter().any(|row| row.contains("USDT")),
            "bound amount missing for {signature}: {amount_rows:?}"
        );
        assert_full_contract_identity_page(&rendered.pages, &asset);
        assert_full_address_field_page(&rendered.pages, recipient_label, &recipient);

        let referral_word: [u8; 32] = calldata[4 + 3 * 32..4 + 4 * 32]
            .try_into()
            .expect("Aave V2 referralCode ABI word");
        assert_eq!(referral_word, abi_u16_word(referral_code));
        assert_raw_word_pages(&rendered.pages, "Referral Code", &referral_word);

        let mutated = render_erc7730_pages_with_signer_checked(
            &tx,
            &mutated_calldata,
            &verified,
            Some(&token),
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render mutated Aave V2 {signature}: {error:?}"));
        let mutated_word: [u8; 32] = mutated_calldata[4 + 3 * 32..4 + 4 * 32]
            .try_into()
            .expect("mutated Aave V2 referralCode ABI word");
        assert_eq!(mutated_word, abi_u16_word(referral_code ^ 1));
        assert_raw_word_pages(&mutated.pages, "Referral Code", &mutated_word);
        assert_ne!(
            rendered.pages.as_slice(),
            mutated.pages.as_slice(),
            "one referralCode bit must change the Aave V2 trusted pages for {signature}"
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "one referralCode bit must change the Aave V2 transcript for {signature}"
        );
    }
}

#[test]
fn positive_serenita_deposit_binds_native_value_receiver_and_complete_referrer() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-EthVault.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Serenita leaf");

    let receiver = [0x44u8; 20];
    let referrer = [0x55u8; 20];
    let signer = [0x66u8; 20];
    let calldata = calldata_static(
        "deposit(address,address)",
        &[abi_address_word(receiver), abi_address_word(referrer)],
    );
    assert_selector_matches(&verified.ir, &calldata, "deposit(address,address)");

    let resolver = NameResolver::new();
    let mut tx = envelope(1, entry.contract);
    tx.value = u256_from_u64(1_500_000_000_000_000_000);
    let rendered = render_erc7730_pages_with_signer_checked(
        &tx, &calldata, &verified, None, &resolver, &signer,
    )
    .expect("render Serenita deposit");
    assert_eq!(
        rendered.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(
        rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0),
        "Serenita receipt must bind its complete rendered page range"
    );
    assert_all_pages_printable(&rendered.pages);
    assert_eq!(
        page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
        "Stake ETH"
    );

    let amount_rows = page_strs(
        &rendered.pages,
        find_page_by_label(&rendered.pages, "Amount to stake"),
    );
    assert!(
        amount_rows.iter().any(|row| row.contains("1.5"))
            && amount_rows.iter().any(|row| row.contains("ETH")),
        "bound native amount missing: {amount_rows:?}"
    );
    assert_full_address_field_page(&rendered.pages, "Shares receiver", &receiver);
    let referrer_word = abi_address_word(referrer);
    assert_raw_word_pages(&rendered.pages, "Referrer", &referrer_word);

    let mut mutated_referrer = referrer;
    mutated_referrer[19] ^= 1;
    let mutated_referrer_calldata = calldata_static(
        "deposit(address,address)",
        &[
            abi_address_word(receiver),
            abi_address_word(mutated_referrer),
        ],
    );
    let mutated_referrer_render = render_erc7730_pages_with_signer_checked(
        &tx,
        &mutated_referrer_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render mutated Serenita referrer");
    assert_raw_word_pages(
        &mutated_referrer_render.pages,
        "Referrer",
        &abi_address_word(mutated_referrer),
    );
    assert_ne!(
        rendered.pages.as_slice(),
        mutated_referrer_render.pages.as_slice(),
        "one signed referrer bit must change trusted pages"
    );
    assert!(
        !rendered
            .transcript_receipt
            .exact_match(&mutated_referrer_render.transcript_receipt),
        "one signed referrer bit must change the transcript receipt"
    );

    let mut mutated_receiver = receiver;
    mutated_receiver[19] ^= 1;
    let mutated_receiver_calldata = calldata_static(
        "deposit(address,address)",
        &[
            abi_address_word(mutated_receiver),
            abi_address_word(referrer),
        ],
    );
    let mutated_receiver_render = render_erc7730_pages_with_signer_checked(
        &tx,
        &mutated_receiver_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render mutated Serenita receiver");
    assert_ne!(
        rendered.pages.as_slice(),
        mutated_receiver_render.pages.as_slice(),
        "one signed receiver bit must change trusted pages"
    );
    assert!(
        !rendered
            .transcript_receipt
            .exact_match(&mutated_receiver_render.transcript_receipt),
        "one signed receiver bit must change the transcript receipt"
    );

    let mut mutated_value_tx = tx;
    mutated_value_tx.value = u256_from_u64(2_000_000_000_000_000_000);
    let mutated_value_render = render_erc7730_pages_with_signer_checked(
        &mutated_value_tx,
        &calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render mutated Serenita native value");
    assert_ne!(
        rendered.pages.as_slice(),
        mutated_value_render.pages.as_slice(),
        "a changed signed native value must change trusted pages"
    );
    assert!(
        !rendered
            .transcript_receipt
            .exact_match(&mutated_value_render.transcript_receipt),
        "a changed signed native value must change the transcript receipt"
    );
}

#[test]
fn positive_p2p_stakewise_deposits_bind_receiver_referrer_and_native_value() {
    let receiver = [0x44u8; 20];
    let referrer = [0x55u8; 20];
    let signer = [0x66u8; 20];
    let value = u256_from_u64(1_500_000_000_000_000_000);
    let expected_deployments = [
        (1u64, "b72668d6ff7a0e318f83097a754c6aed0f8af034"),
        (560_048u64, "8f73c1ce7fe0e17f45b317b33620924a94256fbb"),
    ];

    for (chain_id, expected_contract) in expected_deployments {
        let res = build_registry();
        let entry = find_leaf(res, "calldata-NativeTokenVault.json", chain_id);
        assert_eq!(
            hex::encode(entry.contract),
            expected_contract,
            "P2P deposit selected the wrong deployment"
        );
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify P2P vault leaf");
        assert_eq!(
            cross_check_contract(&verified.ir, chain_id, &entry.contract),
            Ok(())
        );
        let mut wrong_contract = entry.contract;
        wrong_contract[19] ^= 1;
        assert_eq!(
            cross_check_contract(&verified.ir, chain_id, &wrong_contract),
            Err(BindingError::ContractMismatch)
        );

        let calldata = calldata_static(
            "deposit(address,address)",
            &[abi_address_word(receiver), abi_address_word(referrer)],
        );
        assert_selector_matches(&verified.ir, &calldata, "deposit(address,address)");
        let resolver = NameResolver::new();
        let mut tx = envelope(chain_id, entry.contract);
        tx.value = value;
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render P2P deposit on {chain_id}: {error:?}"));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "P2P deposit receipt must bind every page on chain {chain_id}"
        );
        assert_all_pages_printable(&rendered.pages);
        assert_eq!(
            page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
            "Stake ETH with p"
        );
        assert_full_address_field_page(&rendered.pages, "Shares receiver", &receiver);
        assert_full_address_field_page(&rendered.pages, "Referrer address", &referrer);
        let amount_rows = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Amount to depos~"),
        );
        let amount_text = amount_rows.concat();
        if chain_id == 1 {
            assert!(
                amount_text.contains("1.5") && amount_text.contains("ETH"),
                "mainnet P2P deposit lost its authenticated native scale: {amount_rows:?}"
            );
        } else {
            assert!(
                amount_text.contains("1500000000000000000")
                    && amount_text.contains("! raw, dec=?")
                    && !amount_text.contains("ETH"),
                "Hoodi P2P deposit must remain an exact unknown-scale integer: {amount_rows:?}"
            );
        }

        let assert_mutation_changes =
            |mutated_tx: &Eip1559Tx, mutated_calldata: &[u8], operand: &str| {
                let mutated = render_erc7730_pages_with_signer_checked(
                    mutated_tx,
                    mutated_calldata,
                    &verified,
                    None,
                    &resolver,
                    &signer,
                )
                .unwrap_or_else(|error| {
                    panic!("render mutated P2P {operand} on {chain_id}: {error:?}")
                });
                assert_ne!(
                    rendered.pages.as_slice(),
                    mutated.pages.as_slice(),
                    "one signed {operand} bit must change P2P deposit pages on {chain_id}"
                );
                assert!(
                    !rendered
                        .transcript_receipt
                        .exact_match(&mutated.transcript_receipt),
                    "one signed {operand} bit must change the P2P deposit receipt on {chain_id}"
                );
            };

        let mut mutated_receiver = receiver;
        mutated_receiver[19] ^= 1;
        let mutated_receiver_calldata = calldata_static(
            "deposit(address,address)",
            &[
                abi_address_word(mutated_receiver),
                abi_address_word(referrer),
            ],
        );
        assert_mutation_changes(&tx, &mutated_receiver_calldata, "receiver");

        let mut mutated_referrer = referrer;
        mutated_referrer[19] ^= 1;
        let mutated_referrer_calldata = calldata_static(
            "deposit(address,address)",
            &[
                abi_address_word(receiver),
                abi_address_word(mutated_referrer),
            ],
        );
        assert_mutation_changes(&tx, &mutated_referrer_calldata, "referrer");

        let mut mutated_value_tx = tx;
        mutated_value_tx.value = u256_from_u64(2_000_000_000_000_000_000);
        assert_mutation_changes(&mutated_value_tx, &calldata, "native value");
    }
}

#[test]
fn positive_stakewise_exit_queue_routes_bind_raw_shares_and_receiver() {
    let shares = u256_from_u64(1_234_567).0;
    let receiver = [0x77u8; 20];
    let signer = [0x88u8; 20];
    let deployments = [
        (
            "calldata-NativeTokenVault.json",
            1u64,
            "b72668d6ff7a0e318f83097a754c6aed0f8af034",
        ),
        (
            "calldata-NativeTokenVault.json",
            560_048u64,
            "8f73c1ce7fe0e17f45b317b33620924a94256fbb",
        ),
        (
            "calldata-EthVault.json",
            1u64,
            "b36fc5e542cb4fc562a624912f55da2758998113",
        ),
    ];

    for (source_name, chain_id, expected_contract) in deployments {
        let res = build_registry();
        let entry = find_leaf(res, source_name, chain_id);
        assert_eq!(
            hex::encode(entry.contract),
            expected_contract,
            "StakeWise exit selected the wrong deployment"
        );
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified =
            verify_erc7730_bundle(&bundle, &res.root).expect("verify StakeWise vault leaf");
        assert_eq!(
            cross_check_contract(&verified.ir, chain_id, &entry.contract),
            Ok(())
        );
        let mut wrong_contract = entry.contract;
        wrong_contract[19] ^= 1;
        assert_eq!(
            cross_check_contract(&verified.ir, chain_id, &wrong_contract),
            Err(BindingError::ContractMismatch)
        );

        let calldata = calldata_static(
            "enterExitQueue(uint256,address)",
            &[shares, abi_address_word(receiver)],
        );
        assert_selector_matches(&verified.ir, &calldata, "enterExitQueue(uint256,address)");
        let tx = envelope(chain_id, entry.contract);
        let resolver = NameResolver::new();
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| {
            panic!("render StakeWise exit for {source_name} on {chain_id}: {error:?}")
        });
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "StakeWise exit receipt must bind every page for {source_name} on {chain_id}"
        );
        assert_all_pages_printable(&rendered.pages);
        assert_eq!(
            page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
            "Exit vault"
        );
        assert_raw_word_pages(&rendered.pages, "Shares to exit", &shares);
        assert_full_address_field_page(&rendered.pages, "Exit receiver", &receiver);
        assert!(
            rendered.pages.as_slice().iter().all(|page| {
                let label = row_str(&page[0]);
                label != "Token (UNVERIFI~" && label != "Token contract"
            }),
            "corrected raw-share display must not invent token metadata: {}",
            dump_pages(&rendered.pages)
        );

        let assert_mutation_changes = |mutated_calldata: &[u8], operand: &str| {
            let mutated = render_erc7730_pages_with_signer_checked(
                &tx,
                mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "render mutated StakeWise {operand} for {source_name} on {chain_id}: {error:?}"
                )
            });
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "one signed {operand} bit must change StakeWise exit pages for {source_name} on {chain_id}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "one signed {operand} bit must change the StakeWise exit receipt for {source_name} on {chain_id}"
            );
        };

        let mut mutated_shares = shares;
        mutated_shares[31] ^= 1;
        let mutated_shares_calldata = calldata_static(
            "enterExitQueue(uint256,address)",
            &[mutated_shares, abi_address_word(receiver)],
        );
        assert_mutation_changes(&mutated_shares_calldata, "shares");

        let mut mutated_receiver = receiver;
        mutated_receiver[19] ^= 1;
        let mutated_receiver_calldata = calldata_static(
            "enterExitQueue(uint256,address)",
            &[shares, abi_address_word(mutated_receiver)],
        );
        assert_mutation_changes(&mutated_receiver_calldata, "receiver");
    }
}

fn assert_stakewise_claim_rendering(
    source_name: &str,
    chain_id: u64,
    calldata: &[u8],
    signer: [u8; 20],
    expected_date: &str,
    expected_time: &str,
) {
    let res = build_registry();
    let entry = find_leaf(res, source_name, chain_id);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify StakeWise leaf");
    assert_eq!(
        cross_check_contract(&verified.ir, chain_id, &entry.contract),
        Ok(())
    );
    let wrong_chain = if chain_id == 1 { 560_048 } else { 1 };
    assert_eq!(
        cross_check_contract(&verified.ir, wrong_chain, &entry.contract),
        Err(BindingError::ChainIdMismatch),
        "{source_name} evidence must not authorize the same proxy on another chain"
    );
    let mut wrong_contract = entry.contract;
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_contract(&verified.ir, chain_id, &wrong_contract),
        Err(BindingError::ContractMismatch),
        "{source_name} evidence must not authorize another proxy"
    );
    assert_selector_matches(
        &verified.ir,
        calldata,
        "claimExitedAssets(uint256,uint256,uint256)",
    );
    let words: [[u8; 32]; 3] = [
        calldata[4..36].try_into().expect("position ticket word"),
        calldata[36..68].try_into().expect("timestamp word"),
        calldata[68..100].try_into().expect("exit queue index word"),
    ];

    let tx = envelope(chain_id, entry.contract);
    let resolver = NameResolver::new();
    assert!(matches!(
        render_erc7730_pages(&tx, calldata, &verified, None, &resolver),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 from unbound"
        ))
    ));

    let rendered = render_erc7730_pages_with_signer_checked(
        &tx, calldata, &verified, None, &resolver, &signer,
    )
    .unwrap_or_else(|error| panic!("render {source_name} StakeWise claim: {error:?}"));
    assert_eq!(
        rendered.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert_eq!(
        rendered.transcript_receipt.page_count() as usize,
        rendered.pages.len
    );
    assert!(
        rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0),
        "{source_name} receipt must bind its complete rendered page range"
    );
    assert_all_pages_printable(&rendered.pages);
    assert_full_address_field_page(&rendered.pages, "Claim receiver", &signer);
    assert_raw_word_pages(&rendered.pages, "Position Ticket", &words[0]);
    assert_eq!(
        page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Exit initiated ~"),
        ),
        [
            "Exit initiated ~".to_string(),
            expected_date.to_string(),
            expected_time.to_string(),
            "> next".to_string(),
        ]
    );
    assert_raw_word_pages(&rendered.pages, "Exit Queue Index", &words[2]);

    let assert_mutation_changes_transcript =
        |mutated_signer: [u8; 20], mutated_words: [[u8; 32]; 3], field: &str| {
            let mutated_calldata =
                calldata_static("claimExitedAssets(uint256,uint256,uint256)", &mutated_words);
            let mutated = render_erc7730_pages_with_signer_checked(
                &tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &mutated_signer,
            )
            .unwrap_or_else(|error| panic!("render mutated {source_name} {field}: {error:?}"));
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "one bound {field} bit must change the trusted pages for {source_name}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "one bound {field} bit must change the transcript receipt for {source_name}"
            );
        };

    let mut mutated_signer = signer;
    mutated_signer[19] ^= 1;
    assert_mutation_changes_transcript(mutated_signer, words, "sender");

    let mut mutated_ticket = words;
    mutated_ticket[0][31] ^= 1;
    assert_mutation_changes_transcript(signer, mutated_ticket, "position ticket");

    let mut mutated_timestamp = words;
    mutated_timestamp[1][31] ^= 1;
    assert_mutation_changes_transcript(signer, mutated_timestamp, "timestamp");

    let mut mutated_index = words;
    mutated_index[2][31] ^= 1;
    assert_mutation_changes_transcript(signer, mutated_index, "exit queue index");
}

#[test]
fn positive_stakewise_claims_bind_sender_ticket_timestamp_and_queue_index() {
    // Exact calldata from the mainnet Serenita registry fixture
    // `tests/calldata-EthVault.tests.json` (typed-transaction envelope removed).
    let serenita_calldata = hex::decode(concat!(
        "8697d2c2",
        "00000000000000000000000000000000000000000000012438bbbd73dccbbe02",
        "0000000000000000000000000000000000000000000000000000000069a21277",
        "000000000000000000000000000000000000000000000000000000000000007b",
    ))
    .expect("valid Serenita fixture calldata");
    assert_stakewise_claim_rendering(
        "calldata-EthVault.json",
        1,
        &serenita_calldata,
        [0x66; 20],
        "2026-02-27",
        "21:53:59 UTC",
    );

    let p2p_words = [
        u256_from_u64(0x0102_0304_0506_0708).0,
        u256_from_u64(1_735_689_600).0,
        u256_from_u64(42).0,
    ];
    let p2p_calldata = calldata_static("claimExitedAssets(uint256,uint256,uint256)", &p2p_words);
    assert_stakewise_claim_rendering(
        "calldata-NativeTokenVault.json",
        1,
        &p2p_calldata,
        [0x77; 20],
        "2025-01-01",
        "00:00:00 UTC",
    );
    assert_stakewise_claim_rendering(
        "calldata-NativeTokenVault.json",
        560_048,
        &p2p_calldata,
        [0x77; 20],
        "2025-01-01",
        "00:00:00 UTC",
    );
}

#[test]
fn positive_aave_repay_renders_enum_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    // interestRateMode = 2 → "variable" in the descriptor's enum.
    let calldata = calldata_repay(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(2),
        [0x44u8; 20],
    );
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "repay(address,uint256,uint256,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Repay loan");

    // The enum page must show the RESOLVED label "variable", not the bare
    // index "2" (audit M-7). The registry's field label is "Interest Rate
    // mode" (18 chars); row 0 is truncated to DISPLAY_COLS (16), so the page
    // header reads "Interest rate m~".
    let enum_page = find_page_by_label(&pages, "Interest rate m~");
    let rows = page_strs(&pages, enum_page);
    assert!(
        rows[1].contains("variable"),
        "enum index 2 must resolve to label 'variable': rows={rows:?}",
    );
    assert!(
        !rows.iter().any(|r| r.trim() == "2"),
        "must not render the bare enum index: rows={rows:?}",
    );
}

#[test]
fn positive_aave_repay_unknown_enum_value_renders_raw_index_loudly() {
    // review 3.3: interestRateMode = 7 is outside the declared set {0,1,2}. The
    // OLD behaviour declined the WHOLE tx to blind-sign; the spec says render
    // the raw value. Now the enum field renders the exact index (7) with a loud
    // `! enum: unknown` marker — WYSIWYS-honest (the real signed value is shown,
    // not a substituted gloss) and strictly better than blind-signing.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_repay(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(7),
        [0x44u8; 20],
    );
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("unknown enum value must now RENDER (loud raw index), not decline");
    assert_all_pages_printable(&pages);

    // Locate the enum field page by its (truncated) label and assert BOTH the
    // raw index and the loud unknown marker appear ON THAT PAGE (not elsewhere
    // — the envelope nonce is also 7).
    let enum_page = find_page_by_label(&pages, "Interest rate m~");
    let rows = page_strs(&pages, enum_page).join(" ");
    assert!(rows.contains('7'), "raw enum index 7 must render:\n{rows}");
    assert!(
        rows.contains("enum: unknown"),
        "loud unknown-enum marker must render:\n{rows}"
    );
}

#[test]
fn positive_flyingtulip_operator_approval_fixture_binds_operator_and_bool_enum() {
    // Exact mainnet EIP-1559 rawTx from upstream Flying Tulip fixture case 1.
    // The calldata is the canonical 68-byte `setApprovalForAll(address,bool)`
    // payload carried by the RLP `b8 44` item.
    let raw_tx = hex::decode(concat!(
        "02f8ac010901843b9aca008307a12094a4215daaf3745e14e96e169e0e7706c479ce04f280b844",
        "a22cb465000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "c001a06aee32a58edaba9f35e7b16a46ba69e230d3fbb0f8c0d6b1f51c941773a1789a",
        "a0615220ea757712d0e86b4ce78e62647555384cee3b9fb7036649f2aed629255d",
    ))
    .expect("valid upstream Flying Tulip rawTx");
    assert_eq!(
        hex::encode(keccak256(&raw_tx)),
        "128b3c5323857a18254a326f1974c4817a0a8f9214128a25b3e2def1e64b71ab"
    );
    const CALLDATA_START: usize = 39;
    const CALLDATA_LEN: usize = 4 + 2 * 32;
    assert_eq!(&raw_tx[CALLDATA_START - 2..CALLDATA_START], &[0xb8, 0x44]);
    assert_eq!(raw_tx[CALLDATA_START + CALLDATA_LEN], 0xc0);
    let calldata = &raw_tx[CALLDATA_START..CALLDATA_START + CALLDATA_LEN];
    assert_eq!(&calldata[..4], &[0xa2, 0x2c, 0xb4, 0x65]);

    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    assert_eq!(
        hex::encode(entry.contract),
        "a4215daaf3745e14e96e169e0e7706c479ce04f2"
    );
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify pFT NFT leaf");
    let signature = "setApprovalForAll(address,bool)";
    assert_selector_matches(&verified.ir, calldata, signature);

    let operator_word: [u8; 32] = calldata[4..36].try_into().expect("operator ABI word");
    let approved_word: [u8; 32] = calldata[36..68].try_into().expect("approved ABI word");
    let operator: [u8; 20] = operator_word[12..].try_into().expect("operator address");
    assert_eq!(
        hex::encode(operator),
        "d8da6bf26964af9d7eed9e03e53415d37aa96045"
    );
    assert_eq!(approved_word, u256_from_u64(1).0);

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let render = |call: &[u8]| {
        render_erc7730_pages_with_signer_checked(&tx, call, &verified, None, &resolver, &signer)
    };
    let rendered = render(calldata).expect("render Flying Tulip operator approval");
    assert_eq!(
        rendered.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert_eq!(
        rendered.transcript_receipt.page_count() as usize,
        rendered.pages.len
    );
    assert!(
        rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0),
        "receipt must bind the complete trusted-display transcript"
    );
    assert_all_pages_printable(&rendered.pages);
    assert_full_address_field_page(&rendered.pages, "Operator", &operator);
    assert_eq!(
        page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Access rights")
        ),
        [
            "Access rights".to_string(),
            "Grant all".to_string(),
            "".to_string(),
            "".to_string(),
        ]
    );

    let mut mutated_operator = operator;
    mutated_operator[19] ^= 1;
    let mutated_operator_calldata = calldata_static(
        signature,
        &[abi_address_word(mutated_operator), approved_word],
    );
    let mutated_operator_render = render(&mutated_operator_calldata)
        .expect("render independently mutated Flying Tulip operator");
    assert_full_address_field_page(
        &mutated_operator_render.pages,
        "Operator",
        &mutated_operator,
    );
    assert_ne!(
        rendered.pages.as_slice(),
        mutated_operator_render.pages.as_slice(),
        "one operator bit must change trusted pages"
    );
    assert!(
        !rendered
            .transcript_receipt
            .exact_match(&mutated_operator_render.transcript_receipt),
        "one operator bit must change the transcript receipt"
    );

    let denied_calldata = calldata_static(signature, &[operator_word, [0u8; 32]]);
    let denied = render(&denied_calldata).expect("render canonical false approval");
    assert_eq!(
        page_strs(
            &denied.pages,
            find_page_by_label(&denied.pages, "Access rights")
        ),
        [
            "Access rights".to_string(),
            "Deny all".to_string(),
            "".to_string(),
            "".to_string(),
        ]
    );
    assert_ne!(
        rendered.pages.as_slice(),
        denied.pages.as_slice(),
        "the independently changed approved word must change trusted pages"
    );
    assert!(
        !rendered
            .transcript_receipt
            .exact_match(&denied.transcript_receipt),
        "the independently changed approved word must change the transcript receipt"
    );

    let noncanonical_bool = calldata_static(signature, &[operator_word, u256_from_u64(2).0]);
    assert!(
        matches!(
            render(&noncanonical_bool),
            Err(crate::tx::erc7730_render::RenderErr::Reject(_))
        ),
        "ABI bool word 2 must hard-refuse instead of rendering an unknown enum"
    );
}

const FLYINGTULIP_SET_ALLOWED_TARGETS: &str = "setAllowedTargets(address[],bool)";

fn flyingtulip_set_allowed_targets_calldata(targets: &[[u8; 20]], allowed: u64) -> Vec<u8> {
    let mut calldata = keccak256(FLYINGTULIP_SET_ALLOWED_TARGETS.as_bytes())[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(64).0); // two-word head ends here
    calldata.extend_from_slice(&u256_from_u64(allowed).0);
    calldata.extend_from_slice(&u256_from_u64(targets.len() as u64).0);
    for target in targets {
        calldata.extend_from_slice(&abi_address_word(*target));
    }
    calldata
}

fn assert_complete_flyingtulip_target_pages(pages: &Pages, targets: &[[u8; 20]]) {
    let target_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Targets")
        .collect::<Vec<_>>();
    assert_eq!(
        target_pages.len(),
        targets.len() + 1,
        "target array must show one count page and every signed address:\n{}",
        dump_pages(pages)
    );
    assert!(
        page_strs(pages, find_page_by_label(pages, "Targets"))
            .iter()
            .any(|row| row.contains(&format!("{} items", targets.len()))),
        "target count must be explicit:\n{}",
        dump_pages(pages)
    );

    for (index, target) in targets.iter().enumerate() {
        let mut expected = [[b' '; DISPLAY_COLS]; 4];
        expected[0][..7].copy_from_slice(b"Targets");
        let [_, r1, r2, r3] = &mut expected;
        write_addr_full(r1, r2, r3, target);
        assert_eq!(
            *target_pages[index + 1],
            expected,
            "target element {index} must show all 20 signed address bytes"
        );
    }
}

#[test]
fn positive_flyingtulip_session_manager_static_authority_routes_bind_every_operand() {
    const REFUSED: [&str; 5] = [
        "createSession(address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32)",
        "createSessionBySig(address,address,uint48,uint48,uint32,uint16,(address,uint256)[],bytes32,bytes)",
        "invalidateNonceBySig(bytes32,uint256,uint256,address,bytes)",
        "revokeSessionBySig(bytes32,uint256,bytes)",
        "validateAndConsume(address,uint256,(bytes32,bytes32,uint256,uint256,address,uint256),bytes,address)",
    ];

    let registry = build_registry();
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-SessionManager.json")
        })
        .collect();
    assert_eq!(
        entries.len(),
        7,
        "SessionManager render coverage must span all seven deployments"
    );

    for entry in entries {
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root)
            .expect("verify Flying Tulip SessionManager leaf");
        cross_check_contract(&verified.ir, entry.chain_id, &entry.contract)
            .expect("bind Flying Tulip SessionManager leaf");
        for signature in REFUSED {
            assert_selector_excluded(&verified.ir, signature);
        }

        let tx = envelope(entry.chain_id, entry.contract);
        let resolver = NameResolver::new();
        let signer = [0x42; 20];
        let render = |signature: &str, words: &[[u8; 32]]| {
            let calldata = calldata_static(signature, words);
            assert_selector_matches(&verified.ir, &calldata, signature);
            render_erc7730_pages_with_signer_checked(
                &tx, &calldata, &verified, None, &resolver, &signer,
            )
        };

        let session_id = [0x11; 32];
        let revoked = render("revokeSession(bytes32)", &[session_id])
            .expect("render Flying Tulip session revocation");
        assert_eq!(
            revoked.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert_eq!(
            page_strs(&revoked.pages, intent_page_index(&revoked.pages))[0],
            "Revoke session"
        );
        assert_all_pages_printable(&revoked.pages);
        assert_raw_word_pages(&revoked.pages, "Session ID", &session_id);
        let mut mutated_session_id = session_id;
        mutated_session_id[31] ^= 1;
        let mutated_revoke = render("revokeSession(bytes32)", &[mutated_session_id])
            .expect("render independently mutated session ID");
        assert_raw_word_pages(&mutated_revoke.pages, "Session ID", &mutated_session_id);
        assert_ne!(
            revoked.pages.as_slice(),
            mutated_revoke.pages.as_slice(),
            "one session-ID bit must change trusted pages"
        );
        assert!(
            !revoked
                .transcript_receipt
                .exact_match(&mutated_revoke.transcript_receipt),
            "one session-ID bit must change the transcript receipt"
        );

        let target = [0x22; 20];
        let allowed_word = u256_from_u64(1).0;
        let allowed = render(
            "setAllowedTarget(address,bool)",
            &[abi_address_word(target), allowed_word],
        )
        .expect("render allowed Flying Tulip session target");
        assert_eq!(
            allowed.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        let allowed_intent = page_strs(&allowed.pages, intent_page_index(&allowed.pages));
        assert_eq!(
            format!("{}{}", allowed_intent[0], allowed_intent[1]),
            "Update allowed target"
        );
        assert_all_pages_printable(&allowed.pages);
        assert_full_address_field_page(&allowed.pages, "Target", &target);
        assert_eq!(
            page_strs(&allowed.pages, find_page_by_label(&allowed.pages, "Access")),
            [
                "Access".to_string(),
                "Allow".to_string(),
                "".to_string(),
                "".to_string(),
            ]
        );

        let mut mutated_target = target;
        mutated_target[19] ^= 1;
        let mutated_target_render = render(
            "setAllowedTarget(address,bool)",
            &[abi_address_word(mutated_target), allowed_word],
        )
        .expect("render independently mutated session target");
        assert_full_address_field_page(&mutated_target_render.pages, "Target", &mutated_target);
        assert_ne!(
            allowed.pages.as_slice(),
            mutated_target_render.pages.as_slice(),
            "one target bit must change trusted pages"
        );
        assert!(
            !allowed
                .transcript_receipt
                .exact_match(&mutated_target_render.transcript_receipt),
            "one target bit must change the transcript receipt"
        );

        let disallowed = render(
            "setAllowedTarget(address,bool)",
            &[abi_address_word(target), [0u8; 32]],
        )
        .expect("render canonical false session target access");
        assert_eq!(
            page_strs(
                &disallowed.pages,
                find_page_by_label(&disallowed.pages, "Access")
            ),
            [
                "Access".to_string(),
                "Disallow".to_string(),
                "".to_string(),
                "".to_string(),
            ]
        );
        assert_ne!(
            allowed.pages.as_slice(),
            disallowed.pages.as_slice(),
            "the signed access bool must change trusted pages"
        );
        assert!(
            !allowed
                .transcript_receipt
                .exact_match(&disallowed.transcript_receipt),
            "the signed access bool must change the transcript receipt"
        );
        assert!(
            matches!(
                render(
                    "setAllowedTarget(address,bool)",
                    &[abi_address_word(target), u256_from_u64(2).0],
                ),
                Err(crate::tx::erc7730_render::RenderErr::Reject(_))
            ),
            "ABI bool word 2 must hard-refuse instead of rendering an unknown enum"
        );

        let pending_owner = [0x33; 20];
        let ownership = render(
            "transferOwnership(address)",
            &[abi_address_word(pending_owner)],
        )
        .expect("render Flying Tulip pending-owner update");
        assert_eq!(
            ownership.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        let ownership_intent = page_strs(&ownership.pages, intent_page_index(&ownership.pages));
        assert_eq!(
            format!("{}{}", ownership_intent[0], ownership_intent[1]),
            "Update pending owner"
        );
        assert_all_pages_printable(&ownership.pages);
        assert_full_address_field_page(&ownership.pages, "Pending owner", &pending_owner);
        let mut mutated_owner = pending_owner;
        mutated_owner[19] ^= 1;
        let mutated_ownership = render(
            "transferOwnership(address)",
            &[abi_address_word(mutated_owner)],
        )
        .expect("render independently mutated pending owner");
        assert_full_address_field_page(&mutated_ownership.pages, "Pending owner", &mutated_owner);
        assert_ne!(
            ownership.pages.as_slice(),
            mutated_ownership.pages.as_slice(),
            "one pending-owner bit must change trusted pages"
        );
        assert!(
            !ownership
                .transcript_receipt
                .exact_match(&mutated_ownership.transcript_receipt),
            "one pending-owner bit must change the transcript receipt"
        );

        for signature in REFUSED {
            let calldata = calldata_static(signature, &[]);
            assert!(
                matches!(
                    render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
                    Err(crate::tx::erc7730_render::RenderErr::NoFormat)
                ),
                "refused SessionManager route must not render directly: {signature}"
            );
        }
        let refused_calldata = calldata_static(REFUSED[0], &[]);
        let mut dispatch_proofs = DispatchPageProofs::new();
        dispatch_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &refused_calldata,
                &signer,
                None,
                None,
                None,
                Some(&verified),
                None,
                None,
                &resolver,
                &mut dispatch_proofs,
            )
            .is_err(),
            "a bound descriptor must not fall back for a refused SessionManager route"
        );
    }
}

#[test]
fn production_flyingtulip_set_allowed_targets_binds_order_and_refuses_bad_framing() {
    let registry = build_registry();
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-SessionManager.json")
        })
        .collect();
    assert_eq!(
        entries.len(),
        7,
        "target-array render coverage must span all seven SessionManager deployments"
    );

    let zero: [[u8; 20]; 0] = [];
    let one = [[0u8; 20]];
    let two = [[0x11; 20], [0x22; 20]];
    let eight = [
        [0x31; 20], [0x32; 20], [0x33; 20], [0x34; 20], [0x35; 20], [0x36; 20], [0x37; 20],
        [0x38; 20],
    ];

    for entry in entries {
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root)
            .expect("verify Flying Tulip SessionManager leaf");
        cross_check_contract(&verified.ir, entry.chain_id, &entry.contract)
            .expect("bind Flying Tulip SessionManager leaf");
        let tx = envelope(entry.chain_id, entry.contract);
        let resolver = NameResolver::new();
        let signer = [0x42; 20];
        let render = |calldata: &[u8]| {
            render_erc7730_pages_with_signer_checked(
                &tx, calldata, &verified, None, &resolver, &signer,
            )
        };

        for targets in [&zero[..], &one[..], &two[..], &eight[..]] {
            for (allowed, expected_access) in [(0u64, "Disallow"), (1u64, "Allow")] {
                let calldata = flyingtulip_set_allowed_targets_calldata(targets, allowed);
                assert_selector_matches(&verified.ir, &calldata, FLYINGTULIP_SET_ALLOWED_TARGETS);
                let rendered = render(&calldata).unwrap_or_else(|error| {
                    panic!(
                        "render {} targets with access {allowed}: {error:?}",
                        targets.len()
                    )
                });
                assert_eq!(
                    rendered.transcript_receipt.state_code(),
                    INTENT_PUBLICATION_STATIC
                );
                assert!(
                    rendered
                        .transcript_receipt
                        .range_matches(&rendered.pages, 0),
                    "the complete target-array transcript must be bound"
                );
                assert_all_pages_printable(&rendered.pages);
                let intent = page_strs(&rendered.pages, intent_page_index(&rendered.pages));
                assert_eq!(
                    format!("{}{}", intent[0], intent[1]),
                    "Update allowed targets"
                );
                assert_complete_flyingtulip_target_pages(&rendered.pages, targets);
                assert_eq!(
                    page_strs(
                        &rendered.pages,
                        find_page_by_label(&rendered.pages, "Access")
                    ),
                    [
                        "Access".to_string(),
                        expected_access.to_string(),
                        String::new(),
                        String::new(),
                    ]
                );

                let mut proofs = DispatchPageProofs::new();
                proofs.fail_initialize();
                let dispatched = pick_sign_pages(
                    &tx,
                    &calldata,
                    &signer,
                    None,
                    None,
                    None,
                    Some(&verified),
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .expect("production dispatcher must select the authenticated target-array leaf");
                assert_eq!(
                    dispatched.as_slice(),
                    rendered.pages.as_slice(),
                    "dispatcher and direct renderer must publish identical trusted pages"
                );
                let mut verdict = crate::fi::FAIL_SENTINEL;
                proofs.final_set_proof(&dispatched, &tx, false, &mut verdict);
                assert_eq!(
                    verdict,
                    crate::fi::OK_SENTINEL,
                    "dispatcher proof must bind the complete target-array transcript"
                );
            }
        }

        let baseline_calldata = flyingtulip_set_allowed_targets_calldata(&two, 1);
        let baseline = render(&baseline_calldata).expect("render two-target baseline");
        for index in 0..two.len() {
            let mut mutated_targets = two;
            mutated_targets[index][19] ^= 1;
            let mutated_calldata = flyingtulip_set_allowed_targets_calldata(&mutated_targets, 1);
            let mutated = render(&mutated_calldata)
                .unwrap_or_else(|error| panic!("render mutated target {index}: {error:?}"));
            assert_complete_flyingtulip_target_pages(&mutated.pages, &mutated_targets);
            assert_ne!(
                baseline.pages.as_slice(),
                mutated.pages.as_slice(),
                "target element {index} mutation must change trusted pages"
            );
            assert!(
                !baseline
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "target element {index} mutation must change the transcript receipt"
            );
        }

        let reordered_targets = [two[1], two[0]];
        let reordered_calldata = flyingtulip_set_allowed_targets_calldata(&reordered_targets, 1);
        let reordered = render(&reordered_calldata).expect("render reordered target array");
        assert_complete_flyingtulip_target_pages(&reordered.pages, &reordered_targets);
        assert_ne!(
            baseline.pages.as_slice(),
            reordered.pages.as_slice(),
            "target reordering must change trusted pages"
        );
        assert!(
            !baseline
                .transcript_receipt
                .exact_match(&reordered.transcript_receipt),
            "target reordering must change the transcript receipt"
        );

        let disallowed_calldata = flyingtulip_set_allowed_targets_calldata(&two, 0);
        let disallowed = render(&disallowed_calldata).expect("render disallowed target array");
        assert_ne!(
            baseline.pages.as_slice(),
            disallowed.pages.as_slice(),
            "access-bool mutation must change trusted pages"
        );
        assert!(
            !baseline
                .transcript_receipt
                .exact_match(&disallowed.transcript_receipt),
            "access-bool mutation must change the transcript receipt"
        );

        let mut malformed = Vec::new();
        for offset in [32u64, 65, 96] {
            let mut calldata = baseline_calldata.clone();
            calldata[4..36].copy_from_slice(&u256_from_u64(offset).0);
            malformed.push((calldata, "noncanonical array offset"));
        }
        let mut huge_offset = baseline_calldata.clone();
        huge_offset[4] = 1;
        malformed.push((huge_offset, "oversized array offset"));

        let count_offset = 4 + 2 * 32;
        for count in [1u64, 3] {
            let mut calldata = baseline_calldata.clone();
            calldata[count_offset..count_offset + 32].copy_from_slice(&u256_from_u64(count).0);
            malformed.push((calldata, "array length inconsistent with calldata"));
        }
        let mut huge_count = baseline_calldata.clone();
        huge_count[count_offset] = 1;
        malformed.push((huge_count, "oversized array length"));

        let mut trailing = baseline_calldata.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        malformed.push((trailing, "trailing calldata word"));
        let mut truncated = baseline_calldata.clone();
        truncated.pop();
        malformed.push((truncated, "truncated array element"));

        let mut dirty_address = baseline_calldata.clone();
        dirty_address[4 + 3 * 32] = 1;
        malformed.push((dirty_address, "dirty address padding"));

        let noncanonical_bool = flyingtulip_set_allowed_targets_calldata(&two, 2);
        malformed.push((noncanonical_bool, "noncanonical bool 2"));

        let nine = [[0x77; 20]; 9];
        let over_cap = flyingtulip_set_allowed_targets_calldata(&nine, 1);
        malformed.push((over_cap, "nine target elements"));

        for (calldata, case) in malformed {
            assert!(
                matches!(
                    render(&calldata),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(_))
                ),
                "{case} must hard-refuse"
            );
            let mut proofs = DispatchPageProofs::new();
            proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &tx,
                    &calldata,
                    &signer,
                    None,
                    None,
                    None,
                    Some(&verified),
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .is_err(),
                "{case} must refuse through dispatch without a blind fallback"
            );
        }
    }
}

#[test]
fn nftname_small_id_keeps_raw_id_and_full_target_collection_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify pFT NFT leaf");
    let tx = envelope(1, entry.contract);
    let calldata = calldata_approve([0x44; 20], u256_from_u64(7));
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
        .expect("render pFT NFT approve");

    let id = page_strs(&pages, find_page_by_label(&pages, "Position"));
    assert_eq!(id[1], "7");
    assert_eq!(id[3], "! raw nft id");
    let collection_page = find_full_nft_collection_page(&pages, &entry.contract);
    assert_eq!(
        page_strs(&pages, collection_page)[0],
        "+ pFT NFT",
        "descriptor contractName is eligible only because @.to equals the bound collection"
    );
}

#[test]
fn nftname_full_width_id_shows_every_byte_plus_full_collection_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify pFT NFT leaf");
    let tx = envelope(1, entry.contract);
    let token_id = U256([0xAB; 32]);
    let calldata = calldata_approve([0x44; 20], token_id);
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
        .expect("render full-width pFT token id");

    let id_pages: Vec<_> = pages
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, page)| (row_str(&page[0]) == "Position").then_some(index))
        .collect();
    assert_eq!(id_pages.len(), 2, "full uint256 id requires two pages");
    let first = page_strs(&pages, id_pages[0]);
    let second = page_strs(&pages, id_pages[1]);
    for row in [&first[1], &first[2], &second[1], &second[2]] {
        assert_eq!(row, "abababababababab");
    }
    assert_eq!(first[3], "1/2 > next");
    assert_eq!(second[3], "2/2 > next");
    let _ = find_full_nft_collection_page(&pages, &entry.contract);
}

#[test]
fn nftname_external_collection_name_requires_exact_chain_metadata() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftMarketplace.json", 146);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify marketplace leaf");
    let tx = envelope(146, entry.contract);
    let mut calldata = keccak256(b"removeListing(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(9).0);
    assert_selector_matches(&verified.ir, &calldata, "removeListing(uint256)");
    let collection: [u8; 20] = hex::decode("1d8051c90076FaA5b683A3551Ee4369d00f99D67")
        .unwrap()
        .try_into()
        .unwrap();

    let mut exact = NameResolver::new();
    exact.push(NameMeta {
        chain_id: 146,
        address: collection,
        name: b"pFT Positions",
    });
    let exact_pages = render_erc7730_pages(&tx, &calldata, &verified, None, &exact)
        .expect("exact collection name renders");
    let exact_page = find_full_nft_collection_page(&exact_pages, &collection);
    assert_eq!(page_strs(&exact_pages, exact_page)[0], "+ pFT Positions");

    let mut wildcard = NameResolver::new();
    wildcard.push(NameMeta {
        chain_id: 0,
        address: collection,
        name: b"Wildcard Name",
    });
    let wildcard_pages = render_erc7730_pages(&tx, &calldata, &verified, None, &wildcard)
        .expect("wildcard metadata cannot change collection label");
    let wildcard_page = find_full_nft_collection_page(&wildcard_pages, &collection);
    assert_eq!(
        page_strs(&wildcard_pages, wildcard_page)[0],
        "NFT collection"
    );
}

#[test]
fn positive_defi_catalogue_lido_referral_addresses_are_complete_and_bound() {
    let res = build_registry();
    let referral = [0x67u8; 20];
    let mut mutated_referral = referral;
    mutated_referral[19] ^= 1;
    let signer = [0x68u8; 20];
    let resolver = NameResolver::new();

    for (source, signature, amount_label) in [
        ("calldata-stETH.json", "submit(address)", "Amount"),
        (
            "calldata-wstETH-referral-staker.json",
            "stakeETH(address)",
            "Amount to stake",
        ),
    ] {
        let entry = find_leaf(res, source, 1);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root)
            .unwrap_or_else(|error| panic!("verify Lido {source}: {error:?}"));
        let calldata = calldata_static(signature, &[abi_address_word(referral)]);
        let mutated_calldata = calldata_static(signature, &[abi_address_word(mutated_referral)]);
        assert_eq!(
            calldata.len(),
            36,
            "Lido staking calldata is one exact static word"
        );
        assert_selector_matches(&verified.ir, &calldata, signature);

        let mut tx = envelope(1, entry.contract);
        tx.value = u256_from_u64(1_500_000_000_000_000_000);
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render Lido {signature}: {error:?}"));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC,
            "the current catalogue retains Lido's authenticated static intent"
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "Lido {signature} receipt must bind its complete rendered page range"
        );
        assert_all_pages_printable(&rendered.pages);
        let amount_rows = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, amount_label),
        );
        assert_eq!(amount_rows[1], "1.5 ETH");
        let referral_word: [u8; 32] = calldata[4..36].try_into().expect("Lido referral ABI word");
        assert_eq!(referral_word, abi_address_word(referral));
        assert_raw_word_pages(&rendered.pages, "Referral", &referral_word);

        let mut mutated_value_tx = envelope(1, entry.contract);
        mutated_value_tx.value = u256_from_u64(2_000_000_000_000_000_000);
        let mutated_value = render_erc7730_pages_with_signer_checked(
            &mutated_value_tx,
            &calldata,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render value-mutated Lido {signature}: {error:?}"));
        let mutated_amount_rows = page_strs(
            &mutated_value.pages,
            find_page_by_label(&mutated_value.pages, amount_label),
        );
        assert_eq!(mutated_amount_rows[1], "2 ETH");
        assert_ne!(
            rendered.pages.as_slice(),
            mutated_value.pages.as_slice(),
            "a changed signed native value must change Lido trusted pages for {signature}"
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated_value.transcript_receipt),
            "a changed signed native value must change the Lido transcript for {signature}"
        );

        let mutated = render_erc7730_pages_with_signer_checked(
            &tx,
            &mutated_calldata,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render mutated Lido {signature}: {error:?}"));
        let mutated_word: [u8; 32] = mutated_calldata[4..36]
            .try_into()
            .expect("mutated Lido referral ABI word");
        assert_eq!(mutated_word, abi_address_word(mutated_referral));
        assert_raw_word_pages(&mutated.pages, "Referral", &mutated_word);
        assert_ne!(
            rendered.pages.as_slice(),
            mutated.pages.as_slice(),
            "one referral-address bit must change the Lido trusted pages for {signature}"
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "one referral-address bit must change the Lido transcript for {signature}"
        );

        let zero_referral_calldata = calldata_static(signature, &[abi_address_word([0u8; 20])]);
        let zero_referral = render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_referral_calldata,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render zero-referral Lido {signature}: {error:?}"));
        assert_raw_word_pages(&zero_referral.pages, "Referral", &[0u8; 32]);

        let short = &calldata[..35];
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx, short, &verified, None, &resolver, &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 short head"
            ))
        ));

        let mut trailing = calldata.clone();
        trailing.push(0);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx, &trailing, &verified, None, &resolver, &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 static calldata trailing"
            ))
        ));

        let wrong_selector = calldata_static("unknownLido(address)", &[abi_address_word(referral)]);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx,
                &wrong_selector,
                &verified,
                None,
                &resolver,
                &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::NoFormat)
        ));
    }
}

#[test]
fn lido_steth_approve_transfer_and_max_threshold_are_exact() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-stETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido stETH leaf");
    let tx = envelope(1, entry.contract);
    let metadata = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let resolver = NameResolver::new();
    let signer = [0x61; 20];
    let spender = [0x62; 20];
    let recipient = [0x63; 20];

    let render = |calldata: &[u8]| {
        render_erc7730_pages_with_signer_checked(
            &tx,
            calldata,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
    };

    let one_steth = u256_from_u64(1_000_000_000_000_000_000);
    let approve = calldata_approve(spender, one_steth);
    assert_eq!(approve.len(), 68);
    let approved = render(&approve).expect("render exact stETH approval");
    assert_full_address_field_page(&approved.pages, "Spender", &spender);
    assert!(page_strs(
        &approved.pages,
        find_page_by_label(&approved.pages, "Amount")
    )[1..3]
        .iter()
        .any(|row| row.contains("1 stETH")));
    assert_full_contract_identity_page(&approved.pages, &entry.contract);

    let transfer = calldata_transfer(recipient, one_steth);
    assert_eq!(transfer.len(), 68);
    let transferred = render(&transfer).expect("render exact stETH transfer request");
    assert_full_address_field_page(&transferred.pages, "Recipient", &recipient);
    assert!(page_strs(
        &transferred.pages,
        find_page_by_label(&transferred.pages, "Amount")
    )[1..3]
        .iter()
        .any(|row| row.contains("1 stETH")));
    assert_full_contract_identity_page(&transferred.pages, &entry.contract);

    let mutated_transfer = calldata_transfer(recipient, u256_from_u64(2_000_000_000_000_000_000));
    let mutated = render(&mutated_transfer).expect("render changed stETH transfer request");
    assert_ne!(transferred.pages.as_slice(), mutated.pages.as_slice());
    assert!(!transferred
        .transcript_receipt
        .exact_match(&mutated.transcript_receipt));

    let approved_max = render(&calldata_approve(spender, u256_max()))
        .expect("exact uint256 max remains the stETH infinite-allowance sentinel");
    assert_eq!(
        page_strs(
            &approved_max.pages,
            find_page_by_label(&approved_max.pages, "Amount")
        ),
        [
            "Amount".to_string(),
            "Unlimited stETH".to_string(),
            "".to_string(),
            "> next".to_string(),
        ]
    );

    let mut old_threshold_minus_one = [0xff; 32];
    old_threshold_minus_one[0] = 0x7f;
    let mut old_threshold = [0u8; 32];
    old_threshold[0] = 0x80;
    let mut max_minus_one = [0xff; 32];
    max_minus_one[31] = 0xfe;
    for (name, finite) in [
        ("old threshold minus one", old_threshold_minus_one),
        ("old threshold", old_threshold),
        ("max minus one", max_minus_one),
    ] {
        assert!(
            matches!(
                render(&calldata_approve(spender, U256(finite))),
                Err(crate::tx::erc7730_render::RenderErr::Reject(
                    "7730 inexact scaled value"
                ))
            ),
            "finite stETH approval at {name} must not inherit the max-only shorthand"
        );
    }

    let mut dirty_spender = approve.clone();
    dirty_spender[4] = 1;
    assert!(matches!(
        render(&dirty_spender),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 noncanonical address"
        ))
    ));
    assert!(matches!(
        render(&approve[..approve.len() - 1]),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 short head"
        ))
    ));
    let mut trailing = approve.clone();
    trailing.push(0);
    assert!(matches!(
        render(&trailing),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));
}

#[test]
fn lido_wsteth_allowance_threshold_is_max_only_for_all_three_routes() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido wstETH leaf");
    let tx = envelope(1, entry.contract);
    let metadata = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 18,
        name: b"Wrapped liquid staked Ether 2.0",
        symbol: b"wstETH",
    };
    let resolver = NameResolver::new();
    let signer = [0x71; 20];
    let owner = [0x72; 20];
    let spender = [0x73; 20];

    let mut old_threshold_minus_one = [0xff; 32];
    old_threshold_minus_one[0] = 0x7f;
    let mut old_threshold = [0u8; 32];
    old_threshold[0] = 0x80;
    let mut max_minus_one = [0xff; 32];
    max_minus_one[31] = 0xfe;

    for (signature, amount_index, base_words) in [
        (
            "approve(address,uint256)",
            1usize,
            vec![abi_address_word(spender), [0xff; 32]],
        ),
        (
            "increaseAllowance(address,uint256)",
            1usize,
            vec![abi_address_word(spender), [0xff; 32]],
        ),
        (
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            2usize,
            vec![
                abi_address_word(owner),
                abi_address_word(spender),
                [0xff; 32],
                u256_from_u64(2_000_000_000).0,
                u256_from_u64(27).0,
                [0x55; 32],
                [0xaa; 32],
            ],
        ),
    ] {
        let render_words = |words: &[[u8; 32]]| {
            let calldata = calldata_static(signature, words);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata,
                &verified,
                Some(&metadata),
                &resolver,
                &signer,
            )
        };

        let rendered_max = render_words(&base_words)
            .unwrap_or_else(|error| panic!("render max-only {signature}: {error:?}"));
        assert_eq!(
            page_strs(
                &rendered_max.pages,
                find_page_by_label(&rendered_max.pages, "Amount")
            )[1..3],
            ["Max uint256".to_string(), "wstETH".to_string()]
        );

        for (name, finite) in [
            ("old threshold minus one", old_threshold_minus_one),
            ("old threshold", old_threshold),
            ("max minus one", max_minus_one),
        ] {
            let mut words = base_words.clone();
            words[amount_index] = finite;
            assert!(
                matches!(
                    render_words(&words),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(
                        "7730 inexact scaled value"
                    ))
                ),
                "finite wstETH value at {name} must not inherit the max-only label for {signature}"
            );
        }
    }
}

#[test]
fn positive_lido_wsteth_permit_fixture_binds_every_signed_word() {
    // Exact mainnet EIP-1559 rawTx from the upstream Lido wstETH fixture. The
    // RLP item immediately before calldata is `b8 e4`: a 228-byte byte string.
    let raw_tx = hex::decode(concat!(
        "02f901520182932a831d5918850176be191b83037cc2947f39c581f595b53c5cb19bd0b3f8da6c935e2ca080b8e4",
        "d505accf00000000000000000000000008b00ceee2fb66029b53d76110b19eeaabfd1e65",
        "000000000000000000000000e66aa98b55c5a55c9af9da12fe39b8868af9a346",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "000000000000000000000000000000000000000000000000000000000000001b",
        "d925c9dc4daf2b97326adca692aba99dd40a1394c841772f5a724c2dc35953867",
        "e99359d1f68b310a5c7f88d01abaf6956d58334b3ec60f8b70f32380d9474fc",
        "c080a086dc5258e055940460390ded6e39e780df41d52370b43ef0a43caa37cfd4b0e7",
        "a05f786412335c0e17ba3fa0ea7dd8158025feafa6a8a7e5c478abecc0978d960b",
    ))
    .expect("valid upstream permit rawTx");
    assert_eq!(
        hex::encode(keccak256(&raw_tx)),
        "921cbe8ffe2ae92351a33e194d6d170420d94903f636adeb04108565ca6bed86"
    );
    const CALLDATA_START: usize = 46;
    const CALLDATA_LEN: usize = 4 + 7 * 32;
    assert_eq!(&raw_tx[CALLDATA_START - 2..CALLDATA_START], &[0xb8, 0xe4]);
    assert_eq!(raw_tx[CALLDATA_START + CALLDATA_LEN], 0xc0);
    let calldata = &raw_tx[CALLDATA_START..CALLDATA_START + CALLDATA_LEN];
    assert_eq!(
        calldata.len(),
        228,
        "only the RLP calldata item is rendered"
    );

    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido wstETH leaf");
    let signature = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)";
    assert_selector_matches(&verified.ir, calldata, signature);

    let words: [[u8; 32]; 7] = core::array::from_fn(|index| {
        calldata[4 + index * 32..4 + (index + 1) * 32]
            .try_into()
            .expect("static permit ABI word")
    });
    let owner: [u8; 20] = words[0][12..].try_into().expect("owner address");
    let spender: [u8; 20] = words[1][12..].try_into().expect("spender address");
    assert_eq!(
        hex::encode(owner),
        "08b00ceee2fb66029b53d76110b19eeaabfd1e65"
    );
    assert_eq!(
        hex::encode(spender),
        "e66aa98b55c5a55c9af9da12fe39b8868af9a346"
    );
    assert_eq!(words[2], [0xff; 32]);
    assert_eq!(words[3], [0xff; 32]);

    let tx = envelope(1, entry.contract);
    let wsteth_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 18,
        name: b"Wrapped liquid staked Ether 2.0",
        symbol: b"wstETH",
    };
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let render = |call: &[u8]| {
        render_erc7730_pages_with_signer_checked(
            &tx,
            call,
            &verified,
            Some(&wsteth_meta),
            &resolver,
            &signer,
        )
        .expect("render complete Lido wstETH permit")
    };
    let rendered = render(calldata);
    // Besides the intent banner: owner + spender (2), amount + bound-token
    // identity (2), four complete raw words (8), and the checked transaction's
    // network/fees/nonce/confirmation suffix (5).
    let expected_page_count = pqsigner_erc7730::display::render::intent::INTENT_BANNER_PAGES + 17;
    assert_eq!(
        rendered.pages.len,
        expected_page_count,
        "unexpected permit page count:\n{}",
        dump_pages(&rendered.pages)
    );
    assert_eq!(
        rendered.transcript_receipt.page_count() as usize,
        expected_page_count
    );
    assert_eq!(
        rendered.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(rendered
        .transcript_receipt
        .range_matches(&rendered.pages, 0));
    assert_all_pages_printable(&rendered.pages);
    assert_full_address_field_page(&rendered.pages, "Owner", &owner);
    assert_full_address_field_page(&rendered.pages, "Spender", &spender);
    assert_eq!(
        page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Amount")
        ),
        [
            "Amount".to_string(),
            "Max uint256".to_string(),
            "wstETH".to_string(),
            "> next".to_string(),
        ]
    );
    assert_raw_word_pages(&rendered.pages, "Deadline", &words[3]);
    assert_raw_word_pages(&rendered.pages, "V", &words[4]);
    assert_raw_word_pages(&rendered.pages, "R", &words[5]);
    assert_raw_word_pages(&rendered.pages, "S", &words[6]);

    for (word_index, field) in [
        (0, "owner"),
        (1, "spender"),
        (2, "value"),
        (3, "deadline"),
        (4, "v"),
        (5, "r"),
        (6, "s"),
    ] {
        let mut mutated_words = words;
        if word_index == 2 {
            mutated_words[word_index] = u256_from_u64(1_000_000_000_000_000_000).0;
        } else {
            mutated_words[word_index][31] ^= 1;
        }
        let mutated_calldata = calldata_static(signature, &mutated_words);
        let mutated = render(&mutated_calldata);
        assert_ne!(
            rendered.pages.as_slice(),
            mutated.pages.as_slice(),
            "an independent {field} mutation must change trusted pages"
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "an independent {field} mutation must change the transcript receipt"
        );
    }
}

#[test]
fn positive_lido_wsteth_remaining_routes_bind_every_signed_operand() {
    struct Case {
        signature: &'static str,
        words: Vec<[u8; 32]>,
        address_fields: Vec<(usize, &'static str)>,
        amount_index: usize,
        intent: &'static str,
        amount_label: &'static str,
        interpolated: bool,
    }

    let recipient = [0x22; 20];
    let sender = [0x33; 20];
    let spender = [0x44; 20];
    let amount = u256_from_u64(1_000_000_000_000_000_000).0;
    let cases = vec![
        Case {
            signature: "unwrap(uint256)",
            words: vec![amount],
            address_fields: vec![],
            amount_index: 0,
            intent: "Unwrap 1 wstETH",
            amount_label: "wstETH amount",
            interpolated: true,
        },
        Case {
            signature: "transfer(address,uint256)",
            words: vec![abi_address_word(recipient), amount],
            address_fields: vec![(0, "Recipient")],
            amount_index: 1,
            intent: "Transfer wstETH",
            amount_label: "Amount",
            interpolated: false,
        },
        Case {
            signature: "transferFrom(address,address,uint256)",
            words: vec![
                abi_address_word(sender),
                abi_address_word(recipient),
                amount,
            ],
            address_fields: vec![(0, "Sender"), (1, "Recipient")],
            amount_index: 2,
            intent: "Transfer wstETH",
            amount_label: "Amount",
            interpolated: false,
        },
        Case {
            signature: "approve(address,uint256)",
            words: vec![abi_address_word(spender), amount],
            address_fields: vec![(0, "Spender")],
            amount_index: 1,
            intent: "Authorize spending",
            amount_label: "Amount",
            interpolated: false,
        },
        Case {
            signature: "increaseAllowance(address,uint256)",
            words: vec![abi_address_word(spender), amount],
            address_fields: vec![(0, "Spender")],
            amount_index: 1,
            intent: "Increase allowance",
            amount_label: "Amount",
            interpolated: false,
        },
        Case {
            signature: "decreaseAllowance(address,uint256)",
            words: vec![abi_address_word(spender), amount],
            address_fields: vec![(0, "Spender")],
            amount_index: 1,
            intent: "Decrease allowance",
            amount_label: "Amount",
            interpolated: false,
        },
    ];

    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido wstETH leaf");
    let tx = envelope(1, entry.contract);
    let metadata = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 18,
        name: b"Wrapped liquid staked Ether 2.0",
        symbol: b"wstETH",
    };
    let resolver = NameResolver::new();
    let signer = [0x55; 20];

    for case in cases {
        let render = |words: &[[u8; 32]]| {
            let calldata = calldata_static(case.signature, words);
            assert_selector_matches(&verified.ir, &calldata, case.signature);
            render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata,
                &verified,
                Some(&metadata),
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| panic!("render {}: {error:?}", case.signature))
        };

        let rendered = render(&case.words);
        assert_all_pages_printable(&rendered.pages);
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            if case.interpolated {
                INTENT_PUBLICATION_INTERPOLATED
            } else {
                INTENT_PUBLICATION_STATIC
            },
            "unexpected intent-publication mode for {}",
            case.signature
        );

        let intent_rows = page_strs(&rendered.pages, intent_page_index(&rendered.pages));
        let painted_intent = if case.intent.len() <= DISPLAY_COLS {
            intent_rows[0].clone()
        } else {
            format!("{}{}", intent_rows[0], intent_rows[1])
        };
        assert_eq!(
            painted_intent,
            case.intent,
            "unexpected trusted intent for {}:\n{}",
            case.signature,
            dump_pages(&rendered.pages)
        );

        for (word_index, label) in &case.address_fields {
            let address: [u8; 20] = case.words[*word_index][12..]
                .try_into()
                .expect("canonical address word");
            assert_full_address_field_page(&rendered.pages, label, &address);
        }
        let amount_rows = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, case.amount_label),
        );
        assert!(
            amount_rows[1..3].iter().any(|row| row.contains("1")),
            "missing exact wstETH amount for {}: {amount_rows:?}",
            case.signature
        );
        assert!(
            amount_rows[1..3].iter().any(|row| row.contains("wstETH")),
            "amount ticker is not bound for {}: {amount_rows:?}",
            case.signature
        );
        assert_full_contract_identity_page(&rendered.pages, &entry.contract);

        for (word_index, label) in &case.address_fields {
            let mut mutated_words = case.words.clone();
            mutated_words[*word_index][31] ^= 1;
            let mutated = render(&mutated_words);
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "mutating {label} must change trusted pages for {}",
                case.signature
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "mutating {label} must change the transcript for {}",
                case.signature
            );
        }

        let mut mutated_words = case.words.clone();
        mutated_words[case.amount_index] = u256_from_u64(2_000_000_000_000_000_000).0;
        let mutated = render(&mutated_words);
        assert_ne!(
            rendered.pages.as_slice(),
            mutated.pages.as_slice(),
            "mutating the exact amount must change trusted pages for {}",
            case.signature
        );
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "mutating the exact amount must change the transcript for {}",
            case.signature
        );
    }
}

#[test]
fn positive_lombard_lbtc_permit_binds_every_static_word_on_both_deployments() {
    const SIGNATURE: &str = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)";
    let owner = [0x11u8; 20];
    let spender = [0x22u8; 20];
    let words = [
        abi_address_word(owner),
        abi_address_word(spender),
        u256_from_u64(123_456_700).0,
        [0xff; 32],
        u256_from_u64(27).0,
        [0x55; 32],
        [0xaa; 32],
    ];
    let calldata = calldata_static(SIGNATURE, &words);
    assert_eq!(calldata.len(), 4 + 7 * 32);

    let res = build_registry();
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let deployments = [
        (
            "calldata-lbtc-mainnet.json",
            1,
            [
                0x82, 0x36, 0xa8, 0x70, 0x84, 0xf8, 0xb8, 0x43, 0x06, 0xf7, 0x20, 0x07, 0xf3, 0x6f,
                0x26, 0x18, 0xa5, 0x63, 0x44, 0x94,
            ],
        ),
        (
            "calldata-lbtc-sepolia.json",
            11_155_111,
            [
                0x73, 0x1e, 0xfa, 0x68, 0x8f, 0x36, 0x79, 0x68, 0x8c, 0xf6, 0x0a, 0x39, 0x93, 0xb8,
                0x65, 0x81, 0x38, 0x95, 0x3e, 0xd6,
            ],
        ),
    ];

    for (source_name, chain_id, contract) in deployments {
        let entry = find_leaf(res, source_name, chain_id);
        assert_eq!(entry.contract, contract);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root)
            .unwrap_or_else(|error| panic!("verify production LBTC leaf {source_name}: {error:?}"));
        assert!(matches!(verified.ir.context_kind, ContextKind::Contract));
        assert_eq!(verified.ir.chain_id, chain_id);
        assert_eq!(verified.ir.contract, contract);
        assert_selector_matches(&verified.ir, &calldata, SIGNATURE);

        // Mainnet has a Merkle-bound 8-decimal LBTC record. Deliberately pass
        // no metadata on Sepolia: the secure renderer must stay honest by
        // showing the exact raw integer and full unverified token address.
        let metadata = (chain_id == 1).then_some(Erc20Metadata {
            chain_id,
            contract,
            decimals: 8,
            name: b"Lombard Staked Bitcoin",
            symbol: b"LBTC",
        });
        let tx = envelope(chain_id, contract);
        let render = |call: &[u8]| {
            render_erc7730_pages_with_signer_checked(
                &tx,
                call,
                &verified,
                metadata.as_ref(),
                &resolver,
                &signer,
            )
        };

        let rendered = render(&calldata)
            .unwrap_or_else(|error| panic!("render production LBTC leaf {source_name}: {error:?}"));
        assert_eq!(
            rendered.transcript_receipt.state_code(),
            INTENT_PUBLICATION_STATIC
        );
        assert_eq!(
            rendered.transcript_receipt.page_count() as usize,
            rendered.pages.len
        );
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "LBTC receipt must bind the complete trusted-display range for {source_name}"
        );
        assert_all_pages_printable(&rendered.pages);
        // Both deployments now declare "Submit permit"; the mainnet/sepolia
        // split this used to assert disappeared when the Lombard descriptors
        // were refreshed (6d4fa6bb). The renderer renders what the
        // authenticated descriptor says, so this assertion tracks
        // `calldata-lbtc-{mainnet,sepolia}.json` and does not get to disagree
        // with them.
        assert_eq!(
            page_strs(&rendered.pages, intent_page_index(&rendered.pages))[0],
            "Submit permit",
            "intent must match the authenticated descriptor for chain {chain_id}"
        );
        assert_full_address_field_page(&rendered.pages, "Owner", &owner);
        assert_full_address_field_page(&rendered.pages, "Spender", &spender);
        assert_raw_word_pages(&rendered.pages, "Valid Until", &words[3]);
        assert_raw_word_pages(&rendered.pages, "V", &words[4]);
        assert_raw_word_pages(&rendered.pages, "R", &words[5]);
        assert_raw_word_pages(&rendered.pages, "S", &words[6]);

        let allowance = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Allowance"),
        )
        .join(" ");
        if chain_id == 1 {
            assert!(
                allowance.contains("1.234567") && allowance.contains("LBTC"),
                "mainnet LBTC metadata must bind the exact 8-decimal amount: {allowance:?}"
            );
            assert_full_contract_identity_page(&rendered.pages, &contract);
        } else {
            assert!(
                allowance.contains("123456700") && allowance.contains("! raw, dec=?"),
                "Sepolia without metadata must show an exact raw amount: {allowance:?}"
            );
            assert_full_unverified_token_identity_page(&rendered.pages, &contract);
        }

        for (word_index, field) in [
            (0, "owner"),
            (1, "spender"),
            (2, "value"),
            (3, "deadline"),
            (4, "v"),
            (5, "r"),
            (6, "s"),
        ] {
            let mut mutated_words = words;
            if word_index == 2 {
                // Preserve the renderer's exact six-fraction-digit display
                // envelope while independently changing the 8-decimal value.
                mutated_words[word_index] = u256_from_u64(123_456_800).0;
            } else {
                mutated_words[word_index][31] ^= 1;
            }
            let mutated_calldata = calldata_static(SIGNATURE, &mutated_words);
            let mutated = render(&mutated_calldata).unwrap_or_else(|error| {
                panic!("render independently mutated LBTC {field} on {source_name}: {error:?}")
            });
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "one {field} bit must change LBTC trusted pages on {source_name}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "one {field} bit must change the LBTC transcript on {source_name}"
            );
        }

        for (word_index, field) in [(0, "owner"), (1, "spender")] {
            let mut dirty_address_words = words;
            dirty_address_words[word_index][0] = 1;
            let dirty_address = calldata_static(SIGNATURE, &dirty_address_words);
            assert!(
                matches!(
                    render(&dirty_address),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(_))
                ),
                "a {field} address with dirty ABI padding must hard-refuse on {source_name}"
            );
        }

        // Solidity decodes `v` as uint8. A non-zero byte outside the retained
        // low byte is therefore a non-canonical ABI spelling and must refuse,
        // even though the raw formatter could display all 32 supplied bytes.
        let mut dirty_v_words = words;
        dirty_v_words[4][0] = 1;
        let dirty_v = calldata_static(SIGNATURE, &dirty_v_words);
        assert!(
            matches!(
                render(&dirty_v),
                Err(crate::tx::erc7730_render::RenderErr::Reject(_))
            ),
            "uint8 v with dirty high-byte padding must hard-refuse on {source_name}"
        );
    }
}

#[test]
fn positive_lombard_lbtc_mainnet_redeem_is_rendered_as_a_burn_request() {
    const SIGNATURE: &str = "redeem(uint256)";
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-lbtc-mainnet.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("verify production mainnet LBTC leaf");
    let tx = envelope(1, entry.contract);
    let metadata = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 8,
        name: b"Lombard Staked Bitcoin",
        symbol: b"LBTC",
    };
    let resolver = NameResolver::new();
    let signer = [0x42; 20];
    let render = |amount: u64| {
        let calldata = calldata_static(SIGNATURE, &[u256_from_u64(amount).0]);
        assert_selector_matches(&verified.ir, &calldata, SIGNATURE);
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .expect("render mainnet LBTC redemption request")
    };

    let rendered = render(123_456_700);
    assert_all_pages_printable(&rendered.pages);
    assert!(rendered
        .transcript_receipt
        .range_matches(&rendered.pages, 0));
    let intent_rows = page_strs(&rendered.pages, intent_page_index(&rendered.pages));
    assert_eq!(
        format!("{}{}", intent_rows[0], intent_rows[1]),
        "Request redemption"
    );
    let amount_rows = page_strs(
        &rendered.pages,
        find_page_by_label(&rendered.pages, "LBTC to Burn"),
    )
    .join(" ");
    assert!(amount_rows.contains("1.234567") && amount_rows.contains("LBTC"));
    assert_full_contract_identity_page(&rendered.pages, &entry.contract);

    let mutated = render(123_456_800);
    assert_ne!(rendered.pages.as_slice(), mutated.pages.as_slice());
    assert!(!rendered
        .transcript_receipt
        .exact_match(&mutated.transcript_receipt));
}

/// A narrow `uintN` EIP-712 word must reject dirty high-order padding.
///
/// REHOSTED 2026-07-31 from `eip712-tally-ethereum-bravo-governor.json`, which
/// the #498 reconciliation quarantined (`missing-fixed-block-authority`) so it
/// emits no leaf. The property is about the RENDERER's word decoding, not about
/// Tally, so it now runs on a synthetic fixture that curation cannot withdraw.
/// No production EIP-712 survivor declares a `uint8` — Permit2 covers dirty
/// `uint160` only — so without the fixture this coverage would simply be gone.
#[test]
fn eip712_uint8_word_rejects_dirty_high_order_padding() {
    let res = build_fixture_registry();
    let entry = find_leaf(res, "eip712-static-scalars.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify fixture Ballot leaf");
    let primary_type_hash = keccak256(b"Ballot(uint256 proposalId,uint8 support)");

    let mut encoded_data = std::vec![0u8; 64];
    encoded_data[31] = 7; // proposalId
    encoded_data[63] = 1; // support:uint8
    let render = |body: &[u8]| {
        super::erc7730::render_erc7730_eip712_pages(
            1,
            &entry.contract,
            &primary_type_hash,
            body,
            &verified,
            None,
            &NameResolver::new(),
        )
    };
    render(&encoded_data).expect("canonical uint8 Ballot support renders");

    let mut dirty = encoded_data;
    dirty[32] = 1;
    assert!(matches!(
        render(&dirty),
        Err(crate::tx::erc7730_render::RenderErr::Reject(_))
    ));
}

/// Pack-expansion sanity: the registry Lido `wstETH.wrap(uint256)`
/// descriptor renders the exact derived intent + retained field label. A render test
/// (not just round-trip) catches descriptor-authoring slips — wrong
/// path, selector, or label — that re-parse + Merkle-verify can't.
#[test]
fn positive_wsteth_wrap_renders_intent_and_amount_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"wrap(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_000).0); // 1.5e18
    assert_selector_matches(&verified.ir, &calldata, "wrap(uint256)");

    let tx = envelope(1, entry.contract);
    // The registry wrap field is `tokenAmount` with `token` = stETH
    // (0xae7ab9…), so supply stETH ERC-20 metadata (18 decimals) for the
    // amount to render — mirrors how the USDT tests pass `Some(erc20)`.
    let steth: [u8; 20] = hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
        .unwrap()
        .try_into()
        .unwrap();
    let steth_meta = Erc20Metadata {
        chain_id: 1,
        contract: steth,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let resolver = NameResolver::new();
    let checked = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&steth_meta),
        &resolver,
        &[0u8; 20],
    )
    .expect("checked render");
    let pages = checked.pages;
    let transcript = checked.transcript_receipt;
    assert_all_pages_printable(&pages);

    let mut adjacent_calldata = keccak256(b"wrap(uint256)")[..4].to_vec();
    adjacent_calldata.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_001).0);
    let adjacent = render_erc7730_pages_with_signer_checked(
        &tx,
        &adjacent_calldata,
        &verified,
        Some(&steth_meta),
        &resolver,
        &[0u8; 20],
    )
    .expect("the adjacent base unit has an exact trusted display");
    assert_ne!(
        pages.as_slice(),
        adjacent.pages.as_slice(),
        "adjacent signed values must never share the same trusted pages"
    );
    assert!(
        adjacent
            .transcript_receipt
            .range_matches(&adjacent.pages, 0)
    );
    assert!(!transcript.exact_match(&adjacent.transcript_receipt));
    assert_eq!(
        page_strs(&adjacent.pages, intent_page_index(&adjacent.pages))[..2],
        ["Wrap 1.500000000", "000000001 stETH"]
    );

    assert_eq!(transcript.state_code(), INTENT_PUBLICATION_INTERPOLATED);
    assert_eq!(transcript.page_count() as usize, pages.len);
    assert!(transcript.range_matches(&pages, 0));
    let intent_index = intent_page_index(&pages);
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let mut warning_corruption = Pages::with_len(pages.len);
        warning_corruption.buf = pages.buf;
        warning_corruption.buf[0][0][0] ^= 1;
        assert!(
            !transcript.range_matches(&warning_corruption, 0),
            "the dev-unattested warning page is part of the transcript"
        );
    }

    let mut skipped_repaint = Pages::with_len(pages.len);
    skipped_repaint.buf = pages.buf;
    skipped_repaint.buf[intent_index] = [[b' '; DISPLAY_COLS]; 4];
    skipped_repaint.buf[intent_index][0].copy_from_slice(b"! INTENT INVALID");
    assert!(
        !transcript.range_matches(&skipped_repaint, 0),
        "the invalid initial paint must never satisfy the transcript receipt"
    );

    let mut static_substitution = Pages::with_len(pages.len);
    static_substitution.buf = pages.buf;
    static_substitution.buf[intent_index][0] = [b' '; DISPLAY_COLS];
    static_substitution.buf[intent_index][0][..10].copy_from_slice(b"Wrap stETH");
    assert!(
        !transcript.range_matches(&static_substitution, 0),
        "restoring the authenticated static title is not transcript authority"
    );

    for row in 0..4 {
        for col in 0..DISPLAY_COLS {
            let mut corrupted = Pages::with_len(pages.len);
            corrupted.buf = pages.buf;
            corrupted.buf[intent_index][row][col] ^= 1;
            assert!(
                !transcript.range_matches(&corrupted, 0),
                "every one of the 64 visible title bytes must be exact ({row},{col})"
            );
        }
    }

    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Wrap 1.5 stETH");
    // The amount field must render under its authored label (proves
    // `#._stETHAmount` resolved to the right static-head slot).
    let amt_page = find_page_by_label(&pages, "stETH amount");
    let amount_rows = page_strs(&pages, amt_page);
    assert!(
        amount_rows[1].contains("1.5")
            && (amount_rows[1].contains("stETH") || amount_rows[2].contains("stETH")),
        "derived intent must not replace the ordinary amount page: {amount_rows:?}"
    );

    // Mount the same fixture through the production dispatcher seam. This
    // keeps the independently classified requirement and the renderer-issued
    // publication receipt alive through later handler-owned suffixes and the
    // final confirmation-boundary proof.
    let dispatch_once = |dispatch_tx: &Eip1559Tx| {
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let pages = pick_sign_pages(
            dispatch_tx,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut proofs,
        )
        .expect("real wstETH fixture dispatches with its publication receipt");
        (pages, proofs)
    };
    let fingerprint_kind =
        Erc8213Kind::CalldataDigest(pqsigner_tx_core::erc8213::calldata_digest(&calldata));
    let append_later_suffixes = |pages: &mut Pages| {
        let prior_len = pages.len;
        append_fingerprint_for_test(pages, fingerprint_kind)
            .expect("later handler fingerprint suffix fits");
        assert_eq!(pages.len, prior_len + 2);
        assert_eq!(
            fingerprint_final_set_proof(pages, prior_len, fingerprint_kind),
            crate::fi::OK_SENTINEL,
            "the later suffix remains independently bound at final confirmation"
        );
    };
    let final_verdict = |proofs: &DispatchPageProofs, pages: &Pages| {
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(pages, &tx, false, &mut verdict);
        verdict
    };

    let (mut dispatched_pages, dispatch_proofs) = dispatch_once(&tx);
    assert_eq!(
        page_strs(&dispatched_pages, intent_page_index(&dispatched_pages))[0],
        "Wrap 1.5 stETH"
    );
    append_later_suffixes(&mut dispatched_pages);
    assert_eq!(
        final_verdict(&dispatch_proofs, &dispatched_pages),
        crate::fi::OK_SENTINEL,
        "the real receipt must survive later append-only pages"
    );

    let mut omitted_init = DispatchPageProofs::new();
    assert!(
        pick_sign_pages(
            &tx,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut omitted_init,
        )
        .is_err(),
        "omitting fail_initialize must refuse even when classification, render, and receipt otherwise agree"
    );

    let (mut corrupted_pages, corrupted_proofs) = dispatch_once(&tx);
    let corrupted_intent_index = intent_page_index(&corrupted_pages);
    append_later_suffixes(&mut corrupted_pages);
    corrupted_pages.buf[corrupted_intent_index][3][15] ^= 1;
    assert_eq!(
        final_verdict(&corrupted_proofs, &corrupted_pages),
        crate::fi::FAIL_SENTINEL,
        "one changed visible byte must invalidate the real receipt at the final boundary"
    );

    let (mut ordinary_corruption, ordinary_proofs) = dispatch_once(&tx);
    let amount_index = find_page_by_label(&ordinary_corruption, "stETH amount");
    append_later_suffixes(&mut ordinary_corruption);
    ordinary_corruption.buf[amount_index][1][0] ^= 1;
    assert_eq!(
        final_verdict(&ordinary_proofs, &ordinary_corruption),
        crate::fi::FAIL_SENTINEL,
        "an ordinary signed-field page is part of the full transcript"
    );

    let (inner_pages, mut batch_proofs) = dispatch_once(&tx);
    let mut batch_pages = Pages::with_len(inner_pages.len + 1);
    batch_pages.buf[0][0][..12].copy_from_slice(b"Batch member");
    for index in 0..inner_pages.len {
        batch_pages.buf[index + 1] = inner_pages.buf[index];
    }
    append_later_suffixes(&mut batch_pages);
    assert_eq!(
        final_verdict(&batch_proofs, &batch_pages),
        crate::fi::FAIL_SENTINEL,
        "adding a batch prefix without shifting the real receipt index must refuse"
    );
    batch_proofs
        .shift_indices(1)
        .expect("one-page batch prefix index shift");
    assert_eq!(
        final_verdict(&batch_proofs, &batch_pages),
        crate::fi::OK_SENTINEL,
        "the exact one-page batch-prefix shift must preserve the real receipt"
    );

    // Exact outer native value: the dispatcher-owned page is additive to the
    // ERC-7730 transcript, and both proofs must survive the one-page batch
    // prefix shift. The friendly six-decimal form remains unchanged where it
    // is exact; adjacent dust values use an explicit exact-wei fallback.
    let mut exact_outer = envelope(1, entry.contract);
    exact_outer.value = u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let (exact_inner, mut exact_outer_proofs) = dispatch_once(&exact_outer);
    let mut exact_batch = Pages::with_len(exact_inner.len + 1);
    exact_batch.buf[0][0][..12].copy_from_slice(b"Batch member");
    for index in 0..exact_inner.len {
        exact_batch.buf[index + 1] = exact_inner.buf[index];
    }
    exact_outer_proofs.shift_indices(1).unwrap();
    let mut exact_verdict = crate::fi::FAIL_SENTINEL;
    exact_outer_proofs.final_set_proof(&exact_batch, &exact_outer, false, &mut exact_verdict);
    assert_eq!(exact_verdict, crate::fi::OK_SENTINEL);

    let mut one_wei_outer = envelope(1, entry.contract);
    one_wei_outer.value = u256_from_u64(1);
    let (one_wei_pages, one_wei_proofs) = dispatch_once(&one_wei_outer);
    let one_wei_value = page_strs(
        &one_wei_pages,
        find_page_by_label(&one_wei_pages, "! NATIVE ETH"),
    );
    assert_eq!(one_wei_value[1], "1");
    assert_eq!(one_wei_value[2], "wei");
    let mut one_wei_verdict = crate::fi::FAIL_SENTINEL;
    one_wei_proofs.final_set_proof(
        &one_wei_pages,
        &one_wei_outer,
        false,
        &mut one_wei_verdict,
    );
    assert_eq!(one_wei_verdict, crate::fi::OK_SENTINEL);

    let mut one_eth_plus_one_wei_outer = envelope(1, entry.contract);
    one_eth_plus_one_wei_outer.value = u256_from_u64(1_000_000_000_000_000_001);
    let (adjacent_outer_pages, adjacent_outer_proofs) = dispatch_once(&one_eth_plus_one_wei_outer);
    let adjacent_value = page_strs(
        &adjacent_outer_pages,
        find_page_by_label(&adjacent_outer_pages, "! NATIVE ETH"),
    );
    assert_eq!(adjacent_value[1], "1000000000000000");
    assert_eq!(adjacent_value[2], "001 wei");
    assert_ne!(exact_inner.as_slice(), adjacent_outer_pages.as_slice());
    assert_ne!(one_wei_pages.as_slice(), adjacent_outer_pages.as_slice());
    let mut adjacent_outer_verdict = crate::fi::FAIL_SENTINEL;
    adjacent_outer_proofs.final_set_proof(
        &adjacent_outer_pages,
        &one_eth_plus_one_wei_outer,
        false,
        &mut adjacent_outer_verdict,
    );
    assert_eq!(adjacent_outer_verdict, crate::fi::OK_SENTINEL);
}

/// Constant-annotation field (path-less `{value, label}`): the registry
/// yield.xyz USDe-vault `deposit(uint256,address)` descriptor carries
/// `{ "label": "Shares received", "format": "raw", "value":
/// "$.metadata.constants.vaultTicker" }`, which the host resolves to the
/// literal "stk-USDe" and the device renders verbatim under its label — no
/// calldata binding. This is the construct the ERC-4626/7540 vault templates
/// use (the registry coverage lever that took render-coverage 40% -> 76%).
#[test]
fn positive_wsteth_wrap_renders_constant_annotation_field() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-yieldxyz-usde-vault.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit(uint256 _underlying, address receiver).
    let mut calldata = keccak256(b"deposit(uint256,address)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_000_000).0); // _underlying
    let mut recv = [0u8; 32];
    recv[12..].copy_from_slice(&[0x55u8; 20]); // receiver
    calldata.extend_from_slice(&recv);
    assert_selector_matches(&verified.ir, &calldata, "deposit(uint256,address)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let page = find_page_by_label(&pages, "Shares received");
    let rows = page_strs(&pages, page);
    assert!(
        rows.iter().any(|r| r.contains("stk-USDe")),
        "constant-annotation field must render the resolved string: rows={rows:?}",
    );
}

// ───────────────────────────────────────────────────────────────────────
// Dynamic-array walker (sole-dynamic-array `<arg>.[]` render-all).
// Security-critical: it follows the dynamic calldata tail, the slot-
// confusion attack surface. All of the resolution safety lives in
// `formatters::resolve_array`; these tests drive it directly with crafted
// HOSTILE bodies (the descriptor is the trusted/pinned input, the calldata
// body is attacker-controlled) and diff it against the Kani-proven `walk`.
// ───────────────────────────────────────────────────────────────────────

/// Canonical `requestWithdrawals(uint256[],address)` calldata BODY (no
/// selector): `offset(0x40) | owner | length | amounts…`.
fn rw_body(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&u256_from_u64(64).0); // offset to _amounts
    let mut ow = [0u8; 32];
    ow[12..].copy_from_slice(&owner);
    b.extend_from_slice(&ow); // _owner
    b.extend_from_slice(&u256_from_u64(amounts.len() as u64).0); // length
    for a in amounts {
        b.extend_from_slice(&a.0);
    }
    b
}

fn rw_calldata_for(signature: &str, amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut d = keccak256(signature.as_bytes())[..4].to_vec();
    d.extend_from_slice(&rw_body(amounts, owner));
    d
}

fn rw_calldata(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    rw_calldata_for("requestWithdrawals(uint256[],address)", amounts, owner)
}

/// The Lido `_amounts.[]` array field + the format's `static_head_words`,
/// from the trusted/pinned descriptor.
fn lido_array_field<'a>(ir: &'a Erc7730Ir<'a>) -> (crate::tx::erc7730::FieldEntry<'a>, u16) {
    let sel = keccak256(b"requestWithdrawals(uint256[],address)");
    let s4: [u8; 4] = sel[..4].try_into().unwrap();
    let format = ir.find_format_by_selector(&s4).unwrap().unwrap();
    let field = format
        .fields()
        .filter_map(Result::ok)
        .find(|f| f.label == b"Amount")
        .expect("the `_amounts.[]` array field");
    (field, format.static_head_words)
}

#[test]
fn positive_lido_request_withdrawals_renders_every_element() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 1.0 / 2.5 / 0.3 stETH (18 decimals).
    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
        u256_from_u64(300_000_000_000_000_000),
    ];
    let owner = [0x55u8; 20];
    let calldata = rw_calldata(&amounts, owner);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "requestWithdrawals(uint256[],address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // Header makes the count explicit. `write_amount_two_rows` splits an
    // amount across an integer row + a fraction row, so 2.5 → "2" / ".5".
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(
        dump.contains(".5"),
        "amount 2.5 (fraction) missing:\n{dump}"
    );
    assert!(
        dump.contains(".3"),
        "amount 0.3 (fraction) missing:\n{dump}"
    );
    // ARRAY-TAIL-HIDING CLOSED, asserted concretely: one header page + EXACTLY
    // one page per element (3) all labelled "Amount" — never fewer.
    let amount_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]) == "Amount")
        .count();
    assert_eq!(
        amount_pages, 4,
        "expected 1 header + 3 element pages (every element shown):\n{dump}"
    );
    // owner page present.
    let _ = find_page_by_label(&pages, "Owner");
}

/// review finding 1.2 — a `raw`-formatted ARRAY ELEMENT must show EVERY signed
/// byte. The old array Raw arm passed two 16-byte slices to `write_hex_word`
/// (caps at 8 bytes/row), silently dropping bytes 8..16 and 24..32 — so a value
/// living there rendered as all-zeros (WYSIWYS magnitude-hiding, the array
/// sibling of the fixed scalar `render_raw` bug). This feeds an element word
/// with a nonzero byte in BOTH dropped ranges (byte 8 = 0xAA, byte 31 = 0x7B)
/// and asserts both appear on the rendered pages — they would BOTH be invisible
/// under the old form.
#[test]
fn positive_raw_array_element_shows_all_bytes_not_zeros() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-raw-array.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // One bytes32 element: byte[8]=0xAA (in the dropped 8..16 range) and
    // byte[31]=0x7B (in the dropped 24..32 range); everything else zero.
    let mut elem = [0u8; 32];
    elem[8] = 0xAA;
    elem[31] = 0x7B;
    let calldata = {
        let mut d = Vec::with_capacity(4 + 3 * 32);
        d.extend_from_slice(&keccak256(b"record(bytes32[])")[..4]);
        d.extend_from_slice(&u256_from_u64(0x20).0); // offset to the array
        d.extend_from_slice(&u256_from_u64(1).0); // length = 1
        d.extend_from_slice(&elem); // element 0
        d
    };
    assert_selector_matches(&verified.ir, &calldata, "record(bytes32[])");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Both previously-dropped bytes must now render.
    assert!(
        dump.contains("aa"),
        "byte 8 (0xAA, range 8..16) must render — the old form dropped it:\n{dump}"
    );
    assert!(
        dump.contains("7b"),
        "byte 31 (0x7B, low word, range 24..32) must render — the old form \
         dropped it, hiding any BE value < 2^64 as all-zeros:\n{dump}"
    );
}

/// review finding 1.1 — field-level `$ref` into `$.display.definitions` must
/// resolve, verified BY RENDER (not just "it compiled to a leaf", the exact
/// failure mode that shipped the degraded 1inch/paraswap routers). The
/// referenced `tokenAmount` FORMAT (from the definition) and the field-local
/// `tokenPath` param (the reference's own params) must BOTH reach the IR, so
/// the field renders a bound token amount rather than the blank-label 64-hex
/// raw dump the pre-fix silent `$ref`-drop produced. Also pins the `label`
/// merge in both directions: field 1 inherits the definition's "Amount to
/// Send" (it carries no label); field 2 overrides it with "Min Received".
#[test]
fn positive_synthetic_ref_field_renders_bound_token_amount() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-ref-token-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // srcToken == the bound USDC metadata below; the send field's
    // `tokenPath:"srcToken"` must resolve to it so "Amount to Send" binds.
    let usdc: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        .unwrap()
        .try_into()
        .unwrap();
    let dst = [0x77u8; 20];
    let calldata = {
        let mut d = Vec::with_capacity(4 + 4 * 32);
        d.extend_from_slice(&keccak256(b"swap(address,address,uint256,uint256)")[..4]);
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&usdc);
        d.extend_from_slice(&w); // srcToken
        let mut w2 = [0u8; 32];
        w2[12..].copy_from_slice(&dst);
        d.extend_from_slice(&w2); // dstToken
        d.extend_from_slice(&u256_from_u64(1_500_000).0); // sendAmount = 1.5 USDC (6 dp)
        d.extend_from_slice(&u256_from_u64(900_000).0); // minReceive
        d
    };
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "swap(address,address,uint256,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdc_meta = Erc20Metadata {
        chain_id: 1,
        contract: usdc,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdc_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Field 1: definition's label inherited (the field carries none).
    let send_page = find_page_by_label(&pages, "Amount to Send");
    // `$ref` resolved to `tokenAmount` (format from def) AND kept the field's
    // `tokenPath:"srcToken"` (params merge) → a bound USDC amount, not a raw
    // 64-hex dump. Both survivals are proven by the ticker + scaled value.
    let send_rows = page_strs(&pages, send_page).join(" ");
    assert!(
        send_rows.contains("USDC"),
        "send amount must bind the USDC ticker (proves format-from-def + tokenPath-from-field both survived $ref):\n{dump}"
    );
    assert!(
        send_rows.contains(".5"),
        "send amount 1.5 (fraction row) missing — field degraded to raw?:\n{dump}"
    );

    // Field 2: field-local label OVERRIDES the definition's "Amount to Receive".
    let _ = find_page_by_label(&pages, "Min Received");
    assert!(
        !dump.contains("Amount to Receive"),
        "field-local `label` must override the definition's label:\n{dump}"
    );
}

/// The production Lido queue leaf clear-signs both non-permit request routes.
/// Every amount is displayed, a zero owner is replaced only by the independently
/// bound signer, and a literal nonzero owner remains literal. The real catalogue
/// must retain the sole-array framing and eight-element human-review cap.
#[test]
fn production_lido_requests_bind_amounts_and_effective_owner() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido NFT leaf");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let signer = [0x92; 20];
    let mut mutated_signer = signer;
    mutated_signer[19] ^= 1;
    let literal_owner = [0x55; 20];
    let steth: [u8; 20] = hex::decode("ae7ab96520de3a18e5e111b5eaab095312d7fe84")
        .unwrap()
        .try_into()
        .unwrap();
    let wsteth: [u8; 20] = hex::decode("7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0")
        .unwrap()
        .try_into()
        .unwrap();

    for (signature, amount_label, owner_label, token, symbol) in [
        (
            "requestWithdrawals(uint256[],address)",
            "Amount",
            "Initial NFT own~",
            steth,
            &b"stETH"[..],
        ),
        (
            "requestWithdrawalsWstETH(uint256[],address)",
            "Amount to withd~",
            "Beneficiary",
            wsteth,
            &b"wstETH"[..],
        ),
    ] {
        let metadata = Erc20Metadata {
            chain_id: 1,
            contract: token,
            decimals: 18,
            name: symbol,
            symbol,
        };
        let amounts = [
            u256_from_u64(1_000_000_000_000_000_000),
            u256_from_u64(2_500_000_000_000_000_000),
            u256_from_u64(300_000_000_000_000_000),
        ];
        let zero_owner = rw_calldata_for(signature, &amounts, [0u8; 20]);
        assert_selector_matches(&verified.ir, &zero_owner, signature);

        assert!(matches!(
            render_erc7730_pages(&tx, &zero_owner, &verified, Some(&metadata), &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 sender unbound"
            ))
        ));
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_owner,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render zero-owner {signature}: {error:?}"));
        assert_all_pages_printable(&rendered.pages);
        assert_full_address_field_page(&rendered.pages, owner_label, &signer);
        assert_full_contract_identity_page(&rendered.pages, &token);
        let dump = dump_pages(&rendered.pages);
        assert!(
            dump.contains("3 items"),
            "array count missing for {signature}:\n{dump}"
        );
        assert_eq!(
            rendered
                .pages
                .as_slice()
                .iter()
                .filter(|page| row_str(&page[0]) == amount_label)
                .count(),
            4,
            "header plus every amount must render for {signature}:\n{dump}"
        );
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));

        let mutated = render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_owner,
            &verified,
            Some(&metadata),
            &resolver,
            &mutated_signer,
        )
        .unwrap_or_else(|error| panic!("render mutated signer {signature}: {error:?}"));
        assert_full_address_field_page(&mutated.pages, owner_label, &mutated_signer);
        assert_ne!(rendered.pages.as_slice(), mutated.pages.as_slice());
        assert!(!rendered
            .transcript_receipt
            .exact_match(&mutated.transcript_receipt));

        let literal = rw_calldata_for(signature, &amounts, literal_owner);
        let literal_pages =
            render_erc7730_pages(&tx, &literal, &verified, Some(&metadata), &resolver)
                .unwrap_or_else(|error| panic!("render literal owner {signature}: {error:?}"));
        assert_full_address_field_page(&literal_pages, owner_label, &literal_owner);

        for count in [0usize, 1, 8] {
            let values = vec![u256_from_u64(1_000_000_000_000_000_000); count];
            let calldata = rw_calldata_for(signature, &values, [0u8; 20]);
            let pages = render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata,
                &verified,
                Some(&metadata),
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| panic!("render {count}-element {signature}: {error:?}"));
            assert!(
                dump_pages(&pages.pages).contains(&format!("{count} items")),
                "array count must be explicit for {signature}"
            );
            assert_eq!(
                pages
                    .pages
                    .as_slice()
                    .iter()
                    .filter(|page| row_str(&page[0]) == amount_label)
                    .count(),
                count + 1,
                "header plus all {count} elements must render for {signature}"
            );
        }

        let nine = vec![u256_from_u64(1_000_000_000_000_000_000); 9];
        assert!(render_erc7730_pages_with_signer_checked(
            &tx,
            &rw_calldata_for(signature, &nine, [0u8; 20]),
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .is_err());

        let mut wrong_offset = zero_owner.clone();
        wrong_offset[4 + 31] = 96;
        assert!(render_erc7730_pages_with_signer_checked(
            &tx,
            &wrong_offset,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .is_err());

        let mut trailing = zero_owner.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert!(render_erc7730_pages_with_signer_checked(
            &tx,
            &trailing,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .is_err());
    }
}

/// COMPLETENESS + FAITHFULNESS over the WHOLE prod registry: enumerates every
/// compiled sole-dynamic-array (`<arg>.[]`) field across all 776 leaves and
/// checks two things the roundtrip/Kani tests can't (they never render):
///
/// 1. **Coverage guard** — every compiled array's element `format_op` has a
///    `render_array_element` arm (`Raw`/`Amount`/`TokenAmount`/`AddressName`).
///    If a `unit`/`calldata`/nested array ever slips the dbgen gate into the
///    corpus, a verified known call would hard-refuse on a real user tx; this
///    fails loudly during generation/testing instead. (This is the durable
///    regression guard.)
/// 2. **End-to-end render** — the sole-dynamic arrays whose siblings my generic
///    calldata satisfies actually RENDER every element (array-tail-hiding
///    closed). `visible:never` arrays (for example Raw+hidden fields)
///    and multi-field functions my stub calldata can't fully satisfy simply
///    don't reach the ≥4-page bar — that's fine, they're covered by (1) and
///    must not crash.
#[test]
fn all_compiled_registry_array_leaves_render() {
    // render_array_element arms: Raw=0x01, Amount=0x02, TokenAmount=0x03,
    // AddressName=0x07, Unit=0x09 (see pqsigner_erc7730::ir::FormatOp).
    const HANDLED: &[u8] = &[0x01, 0x02, 0x03, 0x07, 0x09];
    let res = build_registry();
    let mut all_arrays: Vec<(String, u8)> = Vec::new();
    let mut rendered: Vec<(String, u8)> = Vec::new();

    for entry in res.entries.iter() {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let Ok(verified) = verify_erc7730_bundle(&bundle, &res.root) else {
            continue;
        };
        let mut arrays: Vec<([u8; 4], usize, Vec<u8>, u8)> = Vec::new();
        for format in verified.ir.format_iter() {
            let Ok(format) = format else { continue };
            for field in format.fields() {
                let Ok(field) = field else { continue };
                let is_arr = super::erc7730::formatters::path_ends_with_array_all(
                    &verified.ir,
                    field.path_off,
                )
                .unwrap_or(false);
                if is_arr {
                    arrays.push((
                        format.selector,
                        format.static_head_words as usize,
                        field.label.to_vec(),
                        field.format_op,
                    ));
                }
            }
        }

        for (selector, shw, label, fmt_op) in arrays {
            let key = format!(
                "{}  sel={}  elem_fmt={}",
                entry
                    .source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?"),
                hex::encode(selector),
                fmt_op,
            );
            all_arrays.push((key.clone(), fmt_op));

            // Canonical SOLE-dynamic-array calldata: selector + head (all words
            // = head_end, so the array's offset slot reads `offset == head_end`
            // whichever slot it is, and every other head field renders that
            // value as a scalar) + tail `[count=3][1][2][3]`.
            let head_end = shw * 32;
            let mut cd = selector.to_vec();
            for _ in 0..shw {
                cd.extend_from_slice(&u256_from_u64(head_end as u64).0);
            }
            cd.extend_from_slice(&u256_from_u64(3).0); // count
            for i in 1..=3u64 {
                cd.extend_from_slice(&u256_from_u64(i).0);
            }

            let tx = envelope(entry.chain_id, entry.contract);
            let resolver = NameResolver::new();
            let want_bytes = &label[..label.len().min(DISPLAY_COLS)];
            let want = String::from_utf8_lossy(want_bytes);
            let want = want.trim_end();
            // A render must never CRASH on a corpus leaf; a decline (Err) or a
            // hidden/unsatisfied field (0 label pages) is acceptable here.
            if let Ok(pages) = render_erc7730_pages(&tx, &cd, &verified, None, &resolver) {
                let label_pages = pages
                    .as_slice()
                    .iter()
                    .filter(|p| row_str(&p[0]) == want)
                    .count();
                if label_pages >= 4 {
                    // header + 3 element pages: every element shown.
                    rendered.push((key, fmt_op));
                }
            }
        }
    }

    // (1) Coverage guard — the durable regression check.
    let unhandled: Vec<&(String, u8)> = all_arrays
        .iter()
        .filter(|(_, f)| !HANDLED.contains(f))
        .collect();
    assert!(
        unhandled.is_empty(),
        "compiled ArrayAll field(s) whose element format has NO render_array_element arm \
         (would hard-refuse if visible — add the arm or tighten the dbgen \
         gate):\n{unhandled:#?}",
    );

    // (2) End-to-end non-vacuity — real sole-dynamic arrays render every element.
    eprintln!(
        "compiled registry array fields: {} total, {} rendered end-to-end",
        all_arrays.len(),
        rendered.len()
    );
    for (k, _f) in &rendered {
        eprintln!("  RENDER  {k}");
    }
    assert!(
        rendered.len() >= 6,
        "expected several sole-dynamic array leaves to render every element, found {}",
        rendered.len()
    );
}

// ───────────────────────────────────────────────────────────────────────
// C1 — dynamic `bytes`/`string` leaf (FollowOffset). The value lives in the
// calldata tail; the device follows the ABI offset at the arg's head slot and
// reads the length-prefixed blob — the SAME position the contract decodes.
// ───────────────────────────────────────────────────────────────────────

/// `f(bytes arg)` calldata: selector + `[offset=32][len][data padded to 32]`.
fn calldata_sole_bytes(sig: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cd = keccak256(sig)[..4].to_vec();
    cd.extend_from_slice(&u256_from_u64(32).0); // offset to the bytes arg
    cd.extend_from_slice(&u256_from_u64(data.len() as u64).0); // length
    if !data.is_empty() {
        let mut padded = data.to_vec();
        while padded.len() % 32 != 0 {
            padded.push(0);
        }
        cd.extend_from_slice(&padded);
    }
    cd
}

/// Production does not advertise `addStorageRoot(bytes)`, and the independent
/// runtime belt rejects the same opaque type even when its attacker-controlled
/// bytes happen to be printable. Payload printability is not authenticated type
/// information and must never turn arbitrary bytes into a trusted string.
#[test]
fn c1_dynamic_bytes_declines_even_when_printable() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Celo Accounts IR parses");
    let selector: [u8; 4] = keccak256(b"addStorageRoot(bytes)")[..4].try_into().unwrap();
    assert!(
        ir.find_format_by_selector(&selector)
            .expect("format table is well formed")
            .is_none(),
        "opaque dynamic bytes format must not be advertised in production"
    );

    for url in [&b"a"[..], b"https://ex.io/s", b"ipfs://Qm12345"] {
        assert_opaque_bytes_runtime_rejected(url);
    }
}

/// Non-printable/oversized bytes also decline. A length and short preview are
/// not injective: equal-length blobs sharing the prefix would show identical
/// clear-sign pages while signing different calldata.
#[test]
fn c1_opaque_bytes_decline_without_lossy_preview() {
    let payload = [0xFFu8; 40]; // binary, 40 bytes → opaque
    assert_opaque_bytes_runtime_rejected(&payload);
}

/// Morpho Blue `borrow` — the nested static-tuple GROUP (`marketParams`)
/// unlocked by field-group flattening. Drives the REAL shipping registry leaf
/// (`calldata-MorphoBlue.json`, mainnet). WYSIWYS differential value-equality:
/// every member of the 5-word `marketParams` tuple AND every post-tuple
/// argument renders from its EXACT ABI head-word slot — `assets` at head word
/// 5, `receiver` at head word 8 (the non-leading-static-tuple slots the
/// slot-confusion fix guards). If the flatten mis-computed any member's slot,
/// the rendered value would differ from the encoded word and this fails.
fn morpho_call(
    signature: &str,
    loan: [u8; 20],
    collateral: [u8; 20],
    oracle: [u8; 20],
    irm: [u8; 20],
    lltv: [u8; 32],
    trailing_words: &[[u8; 32]],
) -> Vec<u8> {
    let mut words = vec![
        abi_address_word(loan),
        abi_address_word(collateral),
        abi_address_word(oracle),
        abi_address_word(irm),
        lltv,
    ];
    words.extend_from_slice(trailing_words);
    calldata_static(signature, &words)
}

/// Canonical ABI calldata for a Morpho route whose sole dynamic argument is
/// the final `bytes data` callback. The callback offset points exactly to the
/// end of the static head and its complete tail is the single zero length
/// word: there is no gap, payload, or trailing byte for the contract to decode.
fn morpho_empty_callback_call(
    signature: &str,
    loan: [u8; 20],
    collateral: [u8; 20],
    oracle: [u8; 20],
    irm: [u8; 20],
    lltv: [u8; 32],
    trailing_static_words: &[[u8; 32]],
) -> Vec<u8> {
    let head_words = 5 + trailing_static_words.len() + 1;
    let mut calldata = keccak256(signature.as_bytes())[..4].to_vec();
    for word in [
        abi_address_word(loan),
        abi_address_word(collateral),
        abi_address_word(oracle),
        abi_address_word(irm),
        lltv,
    ] {
        calldata.extend_from_slice(&word);
    }
    for word in trailing_static_words {
        calldata.extend_from_slice(word);
    }
    calldata.extend_from_slice(&u256_from_u64((head_words * 32) as u64).0);
    calldata.extend_from_slice(&[0u8; 32]);
    calldata
}

fn overwrite_calldata_word(calldata: &mut [u8], word_index: usize, word: [u8; 32]) {
    let start = 4 + word_index * 32;
    calldata[start..start + 32].copy_from_slice(&word);
}

#[test]
fn morpho_borrow_nested_tuple_group_renders_exact_values() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-MorphoBlue.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // Distinct, recognizable words at each of the 9 head slots.
    let addr_word = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let loan: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        .unwrap()
        .try_into()
        .unwrap();
    let collat = [0x22u8; 20];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let receiver = [0x77u8; 20];

    let types_sig =
        "borrow((address,address,address,address,uint256),uint256,uint256,address,address)";
    let mut cd = keccak256(types_sig.as_bytes())[..4].to_vec();
    cd.extend_from_slice(&addr_word(loan)); // slot 0: loanToken
    cd.extend_from_slice(&addr_word(collat)); // slot 1: collateralToken
    cd.extend_from_slice(&addr_word(oracle)); // slot 2: oracle
    cd.extend_from_slice(&addr_word(irm)); // slot 3: irm
    cd.extend_from_slice(&u256_from_u64(0xBEEF).0); // slot 4: lltv
    cd.extend_from_slice(&u256_from_u64(1_500_000).0); // slot 5: assets = 1.5 USDC
    cd.extend_from_slice(&u256_from_u64(0).0); // slot 6: shares
    cd.extend_from_slice(&addr_word(on_behalf)); // slot 7: onBehalf
    cd.extend_from_slice(&addr_word(receiver)); // slot 8: receiver
                                                // Confirms the selector matches AND `borrow` actually compiled into the IR.
    assert_selector_matches(&verified.ir, &cd, types_sig);

    let tx = envelope(1, entry.contract);
    let usdc = Erc20Metadata {
        chain_id: 1,
        contract: loan,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &cd, &verified, Some(&usdc), &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();

    // Tuple members read from their exact slots (addresses not in ERC20_DB/ENS
    // render as the raw calldata address — still faithful to the signed word).
    assert_full_address_field_page(&pages, "Loan Token", &loan);
    assert!(
        dump.contains("2222"),
        "collateralToken (tuple slot 1) not read:\n{dump}"
    );
    assert!(
        dump.contains("3333"),
        "oracle (tuple slot 2) not read:\n{dump}"
    );
    assert!(
        dump.contains("4444"),
        "irm (tuple slot 3) not read:\n{dump}"
    );
    assert!(
        dump.contains("beef"),
        "lltv (tuple slot 4) not read:\n{dump}"
    );
    // Post-tuple args at their WIDTH-AWARE head slots (not logical ordinals).
    assert!(
        page_strs(&pages, find_page_by_label(&pages, "Assets"))[1..3]
            .iter()
            .any(|row| row.contains("1.5 USDC")),
        "assets must resolve from head slot 5 and bind loanToken from tuple slot 0:\n{dump}"
    );
    assert!(
        dump.contains("6666"),
        "onBehalf (head slot 7) not read:\n{dump}"
    );
    assert!(
        dump.contains("7777"),
        "receiver (head slot 8) not read:\n{dump}"
    );
    // Labels the descriptor declares are present.
    let _ = find_page_by_label(&pages, "Loan Token");
    let _ = find_page_by_label(&pages, "Assets");
    let _ = find_page_by_label(&pages, "Receiver");
}

#[test]
fn morpho_withdraw_assets_and_shares_keep_the_exact_input_mode_on_both_chains() {
    let res = build_registry();
    let deployments = [
        (
            1u64,
            hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        (
            8453u64,
            hex::decode("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    ];
    let collateral = [0x22u8; 20];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let receiver = [0x77u8; 20];
    let signature =
        "withdraw((address,address,address,address,uint256),uint256,uint256,address,address)";

    for (chain_id, loan) in deployments {
        let entry = find_leaf(res, "calldata-MorphoBlue.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Morpho leaf");
        let tx = envelope(chain_id, entry.contract);
        let usdc = Erc20Metadata {
            chain_id,
            contract: loan,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let resolver = NameResolver::new();

        let assets_call = morpho_call(
            signature,
            loan,
            collateral,
            oracle,
            irm,
            u256_from_u64(860_000_000_000_000_000).0,
            &[
                u256_from_u64(2_500_000).0,
                [0u8; 32],
                abi_address_word(on_behalf),
                abi_address_word(receiver),
            ],
        );
        assert_selector_matches(&verified.ir, &assets_call, signature);
        let asset_pages =
            render_erc7730_pages(&tx, &assets_call, &verified, Some(&usdc), &resolver)
                .expect("render Morpho asset withdrawal");
        let asset_dump = dump_pages(&asset_pages);
        assert!(
            page_strs(&asset_pages, find_page_by_label(&asset_pages, "Assets"))[1..3]
                .iter()
                .any(|row| row.contains("2.5 USDC")),
            "asset-mode input must render the exact signed loan-token amount:\n{asset_dump}"
        );
        assert_raw_word_pages(&asset_pages, "Shares", &[0u8; 32]);
        assert_full_address_field_page(&asset_pages, "On Behalf", &on_behalf);
        assert_full_address_field_page(&asset_pages, "Receiver", &receiver);

        let share_word = u256_from_u64(0x12_3456).0;
        let shares_call = morpho_call(
            signature,
            loan,
            collateral,
            oracle,
            irm,
            u256_from_u64(860_000_000_000_000_000).0,
            &[
                [0u8; 32],
                share_word,
                abi_address_word(on_behalf),
                abi_address_word(receiver),
            ],
        );
        let share_pages =
            render_erc7730_pages(&tx, &shares_call, &verified, Some(&usdc), &resolver)
                .expect("render Morpho share withdrawal");
        let share_dump = dump_pages(&share_pages);
        assert!(
            page_strs(
                &share_pages,
                find_page_by_label(&share_pages, "Assets")
            )[1..3]
                .iter()
                .any(|row| row.contains("0 USDC")),
            "share-mode input must preserve the signed zero assets instead of inventing a live-state conversion:\n{share_dump}"
        );
        assert_raw_word_pages(&share_pages, "Shares", &share_word);
    }
}

#[test]
fn morpho_withdraw_collateral_amount_binds_collateral_token_not_loan_token() {
    let res = build_registry();
    let deployments = [
        (
            1u64,
            hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        (
            8453u64,
            hex::decode("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("4200000000000000000000000000000000000006")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    ];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let receiver = [0x77u8; 20];
    let signature =
        "withdrawCollateral((address,address,address,address,uint256),uint256,address,address)";

    for (chain_id, loan, collateral) in deployments {
        let entry = find_leaf(res, "calldata-MorphoBlue.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Morpho leaf");
        let calldata = morpho_call(
            signature,
            loan,
            collateral,
            oracle,
            irm,
            u256_from_u64(860_000_000_000_000_000).0,
            &[
                u256_from_u64(40_000_000_000_000_000).0,
                abi_address_word(on_behalf),
                abi_address_word(receiver),
            ],
        );
        assert_selector_matches(&verified.ir, &calldata, signature);
        let weth = Erc20Metadata {
            chain_id,
            contract: collateral,
            decimals: 18,
            name: b"Wrapped Ether",
            symbol: b"WETH",
        };
        let resolver = NameResolver::new();
        let tx = envelope(chain_id, entry.contract);
        let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&weth), &resolver)
            .expect("render Morpho collateral withdrawal");
        let dump = dump_pages(&pages);
        assert!(
            page_strs(&pages, find_page_by_label(&pages, "Assets"))[1..3]
                .iter()
                .any(|row| row.contains("0.04 WETH")),
            "collateral withdrawal must bind assets to marketParams.collateralToken, never loanToken:\n{dump}"
        );
        assert_full_address_field_page(&pages, "Loan Token", &loan);
        assert_full_address_field_page(&pages, "Collateral Token", &collateral);
        assert_full_address_field_page(&pages, "On Behalf", &on_behalf);
        assert_full_address_field_page(&pages, "Receiver", &receiver);
    }
}

#[test]
fn morpho_exact_empty_callback_routes_render_every_operand_on_both_deployments() {
    let res = build_registry();
    let deployments = [
        (
            1u64,
            hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
        (
            8453u64,
            hex::decode("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("4200000000000000000000000000000000000006")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    ];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let lltv = u256_from_u64(860_000_000_000_000_000).0;
    let shares = [0u8; 32];
    let resolver = NameResolver::new();

    for (chain_id, loan, collateral) in deployments {
        let entry = find_leaf(res, "calldata-MorphoBlue.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Morpho leaf");
        let tx = envelope(chain_id, entry.contract);
        let usdc = Erc20Metadata {
            chain_id,
            contract: loan,
            decimals: 6,
            name: b"USD Coin",
            symbol: b"USDC",
        };
        let weth = Erc20Metadata {
            chain_id,
            contract: collateral,
            decimals: 18,
            name: b"Wrapped Ether",
            symbol: b"WETH",
        };

        for signature in [
            "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
            "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
        ] {
            let calldata = morpho_empty_callback_call(
                signature,
                loan,
                collateral,
                oracle,
                irm,
                lltv,
                &[
                    u256_from_u64(2_500_000).0,
                    shares,
                    abi_address_word(on_behalf),
                ],
            );
            let selector: [u8; 4] = calldata[..4].try_into().unwrap();
            assert!(
                verified
                    .ir
                    .find_format_by_selector(&selector)
                    .expect("valid Morpho format table")
                    .is_some(),
                "canonical empty-callback route must be admitted on chain {chain_id}: {signature}"
            );
            assert_selector_matches(&verified.ir, &calldata, signature);
            let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdc), &resolver)
                .expect("render exact-empty Morpho loan-token route");
            assert_all_pages_printable(&pages);
            let dump = dump_pages(&pages);
            assert_full_address_field_page(&pages, "Loan Token", &loan);
            assert_full_address_field_page(&pages, "Collateral Token", &collateral);
            assert_full_address_field_page(&pages, "Oracle", &oracle);
            assert_full_address_field_page(&pages, "Irm", &irm);
            assert_raw_word_pages(&pages, "Lltv", &lltv);
            assert!(
                page_strs(&pages, find_page_by_label(&pages, "Assets"))[1..3]
                    .iter()
                    .any(|row| row.contains("2.5 USDC")),
                "assets must bind marketParams.loanToken on chain {chain_id}:\n{dump}"
            );
            assert_raw_word_pages(&pages, "Shares", &shares);
            assert_full_address_field_page(&pages, "On Behalf", &on_behalf);
            assert_constant_text_field_pages(&pages, "Callback", "none");
        }

        let signature =
            "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)";
        let calldata = morpho_empty_callback_call(
            signature,
            loan,
            collateral,
            oracle,
            irm,
            lltv,
            &[
                u256_from_u64(40_000_000_000_000_000).0,
                abi_address_word(on_behalf),
            ],
        );
        let selector: [u8; 4] = calldata[..4].try_into().unwrap();
        assert!(
            verified
                .ir
                .find_format_by_selector(&selector)
                .expect("valid Morpho format table")
                .is_some(),
            "canonical empty-callback collateral route must be admitted on chain {chain_id}"
        );
        assert_selector_matches(&verified.ir, &calldata, signature);
        let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&weth), &resolver)
            .expect("render exact-empty Morpho collateral-token route");
        assert_all_pages_printable(&pages);
        let dump = dump_pages(&pages);
        assert_full_address_field_page(&pages, "Loan Token", &loan);
        assert_full_address_field_page(&pages, "Collateral Token", &collateral);
        assert_full_address_field_page(&pages, "Oracle", &oracle);
        assert_full_address_field_page(&pages, "Irm", &irm);
        assert_raw_word_pages(&pages, "Lltv", &lltv);
        assert!(
            page_strs(&pages, find_page_by_label(&pages, "Assets"))[1..3]
                .iter()
                .any(|row| row.contains("0.04 WETH")),
            "collateral assets must bind marketParams.collateralToken on chain {chain_id}:\n{dump}"
        );
        assert_full_address_field_page(&pages, "On Behalf", &on_behalf);
        assert_constant_text_field_pages(&pages, "Callback", "none");
    }
}

#[test]
fn morpho_exact_empty_callback_guard_refuses_malformed_or_nonempty_before_publication() {
    let res = build_registry();
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let signer = [0x42u8; 20];
    let lltv = u256_from_u64(860_000_000_000_000_000).0;
    let resolver = NameResolver::new();

    for chain_id in [1u64, 8453] {
        let entry = find_leaf(res, "calldata-MorphoBlue.json", chain_id);
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Morpho leaf");
        let tx = envelope(chain_id, entry.contract);

        for (signature, trailing_static_words) in [
            (
                "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                vec![
                    u256_from_u64(2_500_000).0,
                    [0u8; 32],
                    abi_address_word(on_behalf),
                ],
            ),
            (
                "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                vec![
                    u256_from_u64(2_500_000).0,
                    [0u8; 32],
                    abi_address_word(on_behalf),
                ],
            ),
            (
                "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
                vec![
                    u256_from_u64(40_000_000_000_000_000).0,
                    abi_address_word(on_behalf),
                ],
            ),
        ] {
            let head_words = 5 + trailing_static_words.len() + 1;
            let canonical = morpho_empty_callback_call(
                signature,
                [0x11u8; 20],
                [0x22u8; 20],
                oracle,
                irm,
                lltv,
                &trailing_static_words,
            );
            let render =
                |calldata: &[u8]| render_erc7730_pages(&tx, calldata, &verified, None, &resolver);
            let empty_accepted = render(&canonical).is_ok();
            assert!(
                empty_accepted,
                "canonical empty callback must render on chain {chain_id}: {signature}"
            );

            let offset_word = head_words - 1;
            let length_word = head_words;

            let mut nonempty = canonical.clone();
            overwrite_calldata_word(&mut nonempty, length_word, u256_from_u64(1).0);
            let mut payload = [0u8; 32];
            payload[0] = 0xA5;
            nonempty.extend_from_slice(&payload);
            let nonempty_accepted = render(&nonempty).is_ok();
            assert!(
                !(empty_accepted && nonempty_accepted),
                "empty and effect-bearing callbacks must never both be admitted on chain {chain_id}: {signature}"
            );
            assert!(
                !nonempty_accepted,
                "non-empty callback must refuse before publishing pages on chain {chain_id}: {signature}"
            );

            let mut nonempty_proofs = DispatchPageProofs::new();
            nonempty_proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &tx,
                    &nonempty,
                    &signer,
                    None,
                    None,
                    None,
                    Some(&verified),
                    None,
                    None,
                    &resolver,
                    &mut nonempty_proofs,
                )
                .is_err(),
                "bound non-empty Morpho callback must hard-refuse without fallback on chain {chain_id}: {signature}"
            );

            let selector: [u8; 4] = canonical[..4].try_into().unwrap();
            assert!(
                res.known_calls
                    .contains(&(chain_id, entry.contract, selector)),
                "admitted Morpho call must remain in the exact known-call inventory on chain {chain_id}: {signature}"
            );
            assert!(pqsigner_erc7730::known_calls::may_contain(
                &res.known_calls_bloom,
                chain_id,
                &entry.contract,
                &selector,
            ));
            let mut absent_proofs = DispatchPageProofs::new();
            absent_proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &tx,
                    &canonical,
                    &signer,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    &resolver,
                    &mut absent_proofs,
                )
                .is_err(),
                "known Morpho call must hard-refuse without its bound descriptor on chain {chain_id}: {signature}"
            );

            let mut wrong_offset_into_head = canonical.clone();
            overwrite_calldata_word(
                &mut wrong_offset_into_head,
                offset_word,
                u256_from_u64(((head_words - 1) * 32) as u64).0,
            );

            let mut gapped_tail = canonical.clone();
            overwrite_calldata_word(
                &mut gapped_tail,
                offset_word,
                u256_from_u64(((head_words + 1) * 32) as u64).0,
            );
            gapped_tail.splice(4 + head_words * 32..4 + head_words * 32, [0u8; 32]);

            let mut truncated = canonical.clone();
            truncated.pop();

            let mut dirty_length = canonical.clone();
            let mut dirty_word = [0u8; 32];
            dirty_word[0] = 1;
            overwrite_calldata_word(&mut dirty_length, length_word, dirty_word);

            let mut oversized_length = canonical.clone();
            overwrite_calldata_word(
                &mut oversized_length,
                length_word,
                u256_from_u64((1u64 << 20) + 1).0,
            );

            let mut trailing_bytes = canonical.clone();
            trailing_bytes.extend_from_slice(&[0u8; 32]);

            for (mutation, reason) in [
                (wrong_offset_into_head, "offset into the static head"),
                (gapped_tail, "gap before the dynamic tail"),
                (truncated, "truncated empty length word"),
                (dirty_length, "dirty high length bytes"),
                (oversized_length, "oversized length"),
                (trailing_bytes, "trailing bytes after the empty tail"),
            ] {
                assert!(
                    render(&mutation).is_err(),
                    "{reason} must refuse before publishing pages on chain {chain_id}: {signature}"
                );
            }
        }
    }
}

#[test]
fn array_resolve_matches_walk_differential() {
    // When the Kani-proven `walk` accepts the body, our resolver must agree
    // EXACTLY on (element-start, count). (Not the converse — we are stricter.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);

    let parsed =
        pqsigner_tx::typed_call::parser::parse_text_sig(b"requestWithdrawals(uint256[],address)")
            .unwrap();

    for amounts in [
        vec![],
        vec![u256_from_u64(7)],
        vec![u256_from_u64(7), u256_from_u64(8), u256_from_u64(9)],
    ] {
        let body = rw_body(&amounts, [0x11u8; 20]);
        let walked = pqsigner_tx::typed_call::abi::walk(&parsed, &body).expect("walk accepts");
        let amounts_arg = walked.args[0]; // body_off = the length word
        let (elems_start, count) =
            super::erc7730::formatters::resolve_array(&field, &verified.ir, &body, shw)
                .expect("resolver accepts the same canonical body");
        assert_eq!(
            count, amounts_arg.count as usize,
            "count disagrees with walk"
        );
        assert_eq!(
            elems_start,
            amounts_arg.body_off + 32,
            "element-start disagrees with walk (walk body_off is the length word)"
        );
        // element words must be byte-identical to what walk points at.
        for i in 0..count {
            let mine = &body[elems_start + i * 32..elems_start + i * 32 + 32];
            assert_eq!(mine, &amounts[i].0, "element {i} word mismatch");
        }
    }
}

/// Minimal IR blob carrying just `pool` (CTX_CONTRACT, empty formats) so a
/// test can drive `path_ends_with_array_all` over hand-built path programs.
fn ir_bytes_with_pool(pool: &[u8]) -> Vec<u8> {
    let hl = pqsigner_erc7730::ir::HEADER_LEN;
    let pool_len = pool.len() as u16;
    let mut buf = vec![0u8; hl];
    buf[0] = pqsigner_erc7730::ir::SCHEMA_VER;
    buf[1] = 0x01; // CTX_CONTRACT
    buf[2..10].copy_from_slice(&1u64.to_be_bytes());
    buf[126..128].copy_from_slice(&(hl as u16).to_be_bytes()); // metadata_off
    buf[128..130].copy_from_slice(&((hl as u16) + pool_len).to_be_bytes()); // formats_off
    buf[130..132].copy_from_slice(&pool_len.to_be_bytes()); // pool_len
    buf[132..134].copy_from_slice(&1u16.to_be_bytes()); // formats_len (count byte)
    buf.extend_from_slice(pool);
    buf.push(0u8); // format count = 0
    buf
}

#[test]
fn array_routing_is_structural_not_last_byte() {
    // A SCALAR path [Root][FieldIdx(arg=0x0024)] ends in the byte 0x24, which
    // == PathOp::ArrayAll — but it is NOT an array path. The structural router
    // must return false (→ scalar dispatch / clear-sign), NOT misroute it to
    // render_array (which would needlessly blind-sign a clear-signable field).
    let mut pool = vec![0xFFu8]; // offset-0 filler
    let scalar_off = pool.len() as u16;
    pool.push(4);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x24]); // Root, FieldIdx(0x0024)
    let array_off = pool.len() as u16;
    pool.push(5);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00, 0x24]); // Root, FieldIdx(0), ArrayAll
    let bytes = ir_bytes_with_pool(&pool);
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&bytes).unwrap();

    assert!(
        !super::erc7730::formatters::path_ends_with_array_all(&ir, scalar_off).unwrap(),
        "scalar FieldIdx whose arg low byte is 0x24 must NOT route to render_array"
    );
    assert!(
        super::erc7730::formatters::path_ends_with_array_all(&ir, array_off).unwrap(),
        "a real Root+FieldIdx+ArrayAll path routes to render_array"
    );
    // PathOp::ArrayAll is the wire constant the router + dbgen agree on.
    assert_eq!(pqsigner_erc7730::ir::PathOp::ArrayAll as u8, 0x24);
}

#[test]
fn adversarial_array_resolve_declines_hostile_bodies() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);
    let ir = &verified.ir;
    let resolve = |body: &[u8]| super::erc7730::formatters::resolve_array(&field, ir, body, shw);

    // Baseline: a canonical 2-element body resolves to (elems_start=96, count=2).
    let canon = rw_body(&[u256_from_u64(1), u256_from_u64(2)], [0x11u8; 20]);
    assert_eq!(resolve(&canon).unwrap(), (96, 2));

    // (1) offset word top-28-bytes nonzero (huge offset) → decline.
    let mut b = canon.clone();
    b[0] = 0x01;
    assert!(resolve(&b).is_err(), "huge offset must decline");

    // (2) offset != head-end (gap after the head) → decline.
    let mut b = canon.clone();
    b[31] = 96; // offset 0x60 instead of 0x40
    assert!(resolve(&b).is_err(), "non-head-end offset must decline");

    // (3) offset points INTO the head (alias the owner word) → decline.
    let mut b = canon.clone();
    b[31] = 32;
    assert!(resolve(&b).is_err(), "offset-into-head must decline");

    // (4a) length word top-28-bytes nonzero → decline.
    let mut b = canon.clone();
    b[64] = 0x01; // first byte of the length word (at offset 64)
    assert!(resolve(&b).is_err(), "huge length (top bytes) must decline");

    // (4b) length > MAX_DYNAMIC_LEN → decline.
    let mut b = rw_body(&[u256_from_u64(1)], [0x11u8; 20]);
    // overwrite the length word (offset 64) with MAX_DYNAMIC_LEN + 1.
    let big = (1u32 << 20) + 1;
    b[64 + 28..64 + 32].copy_from_slice(&big.to_be_bytes());
    assert!(resolve(&b).is_err(), "length over the cap must decline");

    // (5a) length OVER-claims (says 3, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 3;
    assert!(resolve(&b).is_err(), "length over-claim must decline");

    // (5b) length UNDER-claims (says 1, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 1;
    assert!(resolve(&b).is_err(), "length under-claim must decline");

    // (6) body truncated mid-element (drop the last 16 bytes of a 2-elem body).
    let b = &canon[..canon.len() - 16];
    assert!(resolve(b).is_err(), "truncated-mid-element must decline");

    // (7) body length not a multiple of 32 (drop 1 byte) → decline.
    let b = &canon[..canon.len() - 1];
    assert!(resolve(b).is_err(), "non-32-aligned body must decline");

    // (8) count == 0 → VALID (renders an empty page, no panic); resolver Ok(_, 0).
    let empty = rw_body(&[], [0x11u8; 20]);
    assert_eq!(
        resolve(&empty).unwrap().1,
        0,
        "empty array is valid, count 0"
    );

    // (9) count large-but-in-bounds (9 > MAX_ARRAY_RENDER=8) → decline, not 9 pages.
    let nine: Vec<U256> = (0..9).map(|i| u256_from_u64(i)).collect();
    let b = rw_body(&nine, [0x11u8; 20]);
    assert!(resolve(&b).is_err(), "over-cap element count must decline");

    // (10) head absent entirely (body shorter than the static head) → decline.
    let b = &canon[..16];
    assert!(resolve(b).is_err(), "short-head must decline");

    // none of the above panicked — the decline-or-safe property holds over all
    // crafted bodies (no UB, no slice-OOB), the core adversarial guarantee.
}

// ───────────────────────────────────────────────────────────────────────
// WYSIWYS belt — VULN-erc7730-visible-never-noparam-clearsign.
//
// A contract-context format that DECLARES a field but renders NONE (the
// field is `visible:"never"`) must be refused on-device so the dispatcher
// falls through to the honest blind-sign ladder instead of a parameter-less
// clear-sign. The build-time visibility gate refuses to COMPILE an
// all-`never` format, so this drives the belt directly: compile a valid
// one-field format with the field `visible:"optional"` (passes the gate and
// emits a visibility TLV), flip that TLV to `never` in the IR bytes, and
// render the patched descriptor — the exact bad-DB shape the belt exists to
// catch even though the gate makes it unshippable.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn belt_rejects_all_hidden_contract_format() {
    use pqsigner_erc7730::ir::HEADER_LEN;

    // 1. Compile a valid one-field descriptor (field visible → passes gate).
    let dir = std::env::temp_dir().join(format!("pq_erc7730_belt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let contract = [0xABu8; 20];
    let addr_hex: String = contract.iter().map(|b| format!("{b:02x}")).collect();
    let desc = format!(
        r#"{{
          "context": {{ "contract": {{ "deployments": [
            {{ "chainId": 1, "address": "0x{addr_hex}" }}
          ] }} }},
          "metadata": {{ "owner": "Belt", "contractName": "Belt" }},
          "display": {{ "formats": {{
            "poke(uint256 amount)": {{
              "intent": "Poke",
              "fields": [
                {{ "path": "amount", "label": "Amount", "format": "raw", "visible": "optional" }}
              ]
            }}
          }} }}
        }}"#
    );
    std::fs::write(dir.join("belt.json"), desc).expect("write desc");
    let policy = workspace_root().join("secure/data/erc7730/policy.toml");
    let res = dbgen::erc7730::build_db(&dir, &policy).expect("compile one-field descriptor");
    let _ = std::fs::remove_dir_all(&dir);
    let mut ir_bytes = res.entries[0].ir_bytes.clone();

    // 2. Flip the field's visibility TLV `optional (0x02)` → `never (0x01)`.
    //    Search past the fixed header only (its sha256 descriptor_hash could
    //    coincidentally hold the 3-byte pattern). push_tlv layout is
    //    `[kind=0x3F][len=0x01][value]`.
    let pat = [0x3Fu8, 0x01, 0x02];
    let hits: Vec<usize> = (HEADER_LEN..ir_bytes.len().saturating_sub(2))
        .filter(|&i| ir_bytes[i..i + 3] == pat)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "exactly one visibility TLV to flip, found {hits:?}"
    );
    ir_bytes[hits[0] + 2] = 0x01; // VIS_NEVER

    // 3. Render the patched IR directly (bypass Merkle verify — we test only
    //    the belt, and VerifiedDescriptor.ir is a public field).
    let ir = Erc7730Ir::parse(&ir_bytes).expect("patched IR still parses");
    assert!(matches!(ir.context_kind, ContextKind::Contract));
    let verified = VerifiedDescriptor { ir };

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&keccak256(b"poke(uint256)")[..4]);
    calldata.extend_from_slice(&u256_from_u64(42).0);
    let tx = envelope(1, contract);
    let resolver = NameResolver::new();

    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(msg)) => {
            assert!(
                msg.contains("no visible fields"),
                "belt reject message: {msg}"
            );
        }
        Err(other) => panic!("expected belt Reject, got a different RenderErr: {other:?}"),
        Ok(_) => panic!(
            "all-hidden contract format must be belt-rejected, but it rendered clear-sign pages"
        ),
    }
}

/// The V2 two-pass EIP-712 transcript binds BOTH the authenticated static text
/// (intent, and the dev-unattested warning) and every displayed field value.
///
/// REHOSTED 2026-07-31 from `eip712-tally-ethereum-pool-token.json`, quarantined
/// by #498 (`missing-fixed-block-authority`). The property under test is the
/// transcript mechanism, not PoolTogether, so it now runs on a synthetic
/// flat-static EIP-712 fixture. That is strictly better than picking another
/// production descriptor: the next curation pass cannot take this one away.
#[test]
fn eip712_v2_two_pass_transcript_binds_static_warning_and_fields() {
    let res = build_fixture_registry();
    let entry = find_leaf(res, "eip712-static-scalars.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify EIP-712 leaf");
    assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
    let format = verified
        .ir
        .format_iter()
        .next()
        .expect("one format")
        .expect("valid format");

    // Ballot(uint256 proposalId, uint8 support) - two static head words.
    assert_eq!(format.static_head_words, 2, "fixture shape changed");
    let mut encoded_data = vec![0u8; format.static_head_words as usize * 32];
    encoded_data[..32].copy_from_slice(&u256_from_u64(7).0); // proposalId
    encoded_data[63] = 1; // support: uint8

    let resolver = NameResolver::new();
    let (mut pages, proof) = super::erc7730_secure_shim::render_erc7730_eip712_pages_checked(
        1,
        &entry.contract,
        &format.type_hash,
        &encoded_data,
        &verified,
        None,
        &resolver,
    )
    .expect("checked V2 EIP-712 render");
    assert_all_pages_printable(&pages);
    assert!(dump_pages(&pages).contains("Fixture ballot"));
    let field_page = find_page_by_label(&pages, "Proposal");

    append_fingerprint_for_test(&mut pages, Erc8213Kind::Eip712Final([0x77; 32]))
        .expect("handler fingerprint suffix fits");
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::OK_SENTINEL,
        "handler-owned fingerprint suffix must preserve the renderer range"
    );

    let mut static_corruption = Pages::with_len(pages.len);
    static_corruption.buf = pages.buf;
    let intent_index = intent_page_index(&static_corruption);
    static_corruption.buf[intent_index][0][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &static_corruption),
        crate::fi::FAIL_SENTINEL,
        "authenticated static intent bytes are transcript-bound"
    );

    let mut field_corruption = Pages::with_len(pages.len);
    field_corruption.buf = pages.buf;
    field_corruption.buf[field_page][1][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &field_corruption),
        crate::fi::FAIL_SENTINEL,
        "every displayed EIP-712 field is transcript-bound"
    );

    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let mut warning_corruption = Pages::with_len(pages.len);
        warning_corruption.buf = pages.buf;
        warning_corruption.buf[0][0][0] ^= 1;
        assert_eq!(
            eip712_transcript_verdict(&proof, &warning_corruption),
            crate::fi::FAIL_SENTINEL,
            "the dev-unattested warning is part of the EIP-712 transcript"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// EIP-712 string-preimage authority: DORMANT, and pinned that way.
//
// This section used to be headed "production catalogue evidence" and asserted
// an exact positive inventory of production EIP-712 string-preimage leaves. It
// asserted the opposite of what this repo ships, and had done since the #498
// reconciliation, 84 commits before anyone noticed:
//
//   * `dbgen/src/erc7730.rs`:
//         const EIP712_STRING_PREIMAGE_ENROLLMENTS: [..; 0] = [];
//         "Production string-preimage authority is intentionally empty."
//     String-preimage authority is compiled-in and per-(descriptor, deployment,
//     type, source). It is not descriptor-driven, so no catalogue edit can
//     grant it — and today it grants nothing.
//   * `dbgen/tests/erc7730_roundtrip.rs`
//     `production_catalogue_has_no_eip712_string_preimage_authority()` asserts
//     exactly that, and passes.
//   * The five descriptors this section rendered (FlyingTulip SpotOrderCancel,
//     Lens LensHub, Rarible 721/1155, Tally pool-token/bravo-governor) are
//     quarantined with recorded `reason_code`s in
//     `tests/erc7730-semantic-evidence/eip712-reconciliation/manifest.json`.
//
// So the V3 multi-page string-preimage renderer is real, compiled, and
// UNREACHABLE from any shipped descriptor. What follows keeps that honest in
// both directions: it pins the dormancy, and it fails loudly the moment the
// dormancy ends without the render coverage coming back with it.
//
// WHY THE V3 COVERAGE IS NOT RE-HOSTED ON A SYNTHETIC FIXTURE. It cannot be,
// without weakening the boundary that makes the dormancy true. Reaching
// `render_erc7730_eip712_pages_v3`'s string path requires an entry in
// `EIP712_STRING_PREIMAGE_ENROLLMENTS`, which is compiled into dbgen and
// asserted empty. Serving these tests would mean either adding a fake
// production enrollment, or threading a table override through the production
// compile path — i.e. building a mechanism whose only purpose is to grant
// string-preimage authority that production is designed never to grant. The
// coverage is not worth the mechanism. dbgen keeps unit-level coverage of the
// enrollment logic via its own `synthetic_eip712_string_enrollment()` and the
// `..._for_in()` seam, which needs no such hole.
//
// Everything that CAN live on a synthetic fixture now does — see
// `build_fixture_registry()` and `tests/erc7730-renderer-fixtures/`.
// ───────────────────────────────────────────────────────────────────────

/// The shipped catalogue must contain NO EIP-712 leaf carrying string
/// preimages. Secure-side mirror of dbgen's
/// `production_catalogue_has_no_eip712_string_preimage_authority`, checked here
/// at the layer that would actually paint them.
///
/// Two gates fail differently, which is the point: dbgen's checks the
/// enrollment table, this checks the compiled IR that reaches the device.
#[test]
fn production_eip712_string_preimage_authority_is_empty() {
    let registry = build_registry();
    let mut offenders = std::vec::Vec::new();
    let mut eip712_leaves = 0usize;
    for entry in &registry.entries {
        let parsed = Erc7730Ir::parse(&entry.ir_bytes).expect("production IR parses");
        if !matches!(parsed.context_kind, ContextKind::Eip712) {
            continue;
        }
        eip712_leaves += 1;
        for format in parsed.format_iter() {
            let format = format.expect("format parses");
            if format.string_preimage_count != 0 {
                offenders.push(std::format!(
                    "{} chain={} count={}",
                    entry.source.display(),
                    entry.chain_id,
                    format.string_preimage_count
                ));
            }
        }
    }
    // NON-VACUITY. "No leaf carries preimages" is trivially true of an empty
    // set. If the catalogue ever stops emitting EIP-712 leaves entirely, this
    // test must fail rather than pass by looking at nothing.
    assert!(
        eip712_leaves > 0,
        "no EIP-712 leaves were examined - this assertion would pass vacuously"
    );
    assert!(
        offenders.is_empty(),
        "EIP-712 string-preimage authority is supposed to be dormant, but these \
         leaves carry preimages: {offenders:?}.\n\
         If this is a deliberate re-enrollment, it is ALSO the moment to restore \
         the V3 render coverage this file dropped on 2026-07-31: exact empty and \
         trailing-space preimages, two-string stream ordering/omission/extra-byte/\
         mutation refusal, multi-page content URIs, and the mixed \
         string-plus-nested-array page-budget boundary. Re-enrolling without them \
         ships an unexercised painter."
    );
}

/// Every source the #498 reconciliation quarantined must emit no leaf.
///
/// This is the property the deleted tests were accidentally testing in reverse.
/// It is cheap, it is the actual shipped contract, and it means a curation
/// regression that silently re-admits one of these is caught here rather than
/// by a renderer test failing for an unrelated-looking reason.
#[test]
fn quarantined_eip712_sources_emit_no_leaf() {
    for source in [
        "eip712-SpotOrderCancel.json",
        "eip712-lens-lenshub.json",
        "eip712-rarible-erc-721.json",
        "eip712-rarible-erc-1155.json",
        "eip712-tally-ethereum-pool-token.json",
        "eip712-tally-ethereum-bravo-governor.json",
    ] {
        assert_registry_source_excluded(source);
    }
}

/// DRIFT GUARD. Every production source these tests pin must still be in the
/// compiled catalogue.
///
/// Without this, a curation change that withdraws a descriptor shows up as a
/// panic inside whichever renderer test happened to use it — which reads as a
/// renderer bug and is what let the previous breakage sit red for 84 commits.
/// Here it reads as what it is: the catalogue moved, go look at the manifest.
#[test]
fn production_sources_used_by_renderer_tests_are_still_in_the_catalogue() {
    const PINNED: [(&str, u64); 6] = [
        ("calldata-lbtc-mainnet.json", 1),
        ("calldata-wstETH.json", 1),
        ("calldata-yieldxyz-usde-vault.json", 1),
        ("eip712-uniswap-permit2.json", 1),
        ("eip712-network-fee-authorization-mainnet.json", 1),
        ("calldata-Safe-1.5.0.json", 1),
    ];
    let registry = build_registry();
    let mut missing = std::vec::Vec::new();
    for (source, chain) in PINNED {
        let present = registry.entries.iter().any(|entry| {
            entry.chain_id == chain
                && entry.source.file_name().and_then(|n| n.to_str()) == Some(source)
        });
        if !present {
            missing.push(std::format!("{source} on chain {chain}"));
        }
    }
    assert!(
        missing.is_empty(),
        "renderer tests pin production sources that are no longer compiled: {missing:?}.\n\
         Check tests/erc7730-semantic-evidence/eip712-reconciliation/manifest.json for a \
         quarantine `reason_code` before touching any renderer test — the catalogue \
         moving is not a renderer defect."
    );
}

/// Synthetic-fixture coverage of the CALLDATA dynamic-string painter.
///
/// This path is live in production (unlike the EIP-712 preimage path above), is
/// capped at `DYN_TEXT_MAX` = 2 x DISPLAY_COLS on a single page, and refuses
/// anything longer or non-printable rather than truncating. Hosted on
/// `tests/erc7730-renderer-fixtures/registry/calldata-string-streams.json` so
/// catalogue curation cannot withdraw it.
#[test]
fn fixture_calldata_string_renders_exactly_and_refuses_overlong_or_nonprintable() {
    let res = build_fixture_registry();
    let entry = find_leaf(res, "calldata-string-streams.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("fixture leaf verifies");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();

    // Exactly at the limit: every byte occupies its own cell, including the
    // trailing space, which must not collapse into display padding.
    let exact = b"abcdefghijklmno pqrstuvwxyz0123 ";
    assert_eq!(exact.len(), 2 * DISPLAY_COLS);
    let calldata = calldata_sole_bytes(b"oneString(string)", exact);
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("exact-length printable string renders");
    let page = find_page_by_label(&pages, "Note");
    assert_eq!(&pages.buf[page][1][..], &exact[..DISPLAY_COLS]);
    assert_eq!(&pages.buf[page][2][..], &exact[DISPLAY_COLS..]);
    assert_all_pages_printable(&pages);

    // One byte over the budget must REFUSE, never truncate: a silently
    // shortened string is a different string on the confirm screen.
    let overlong = b"abcdefghijklmno pqrstuvwxyz0123 X";
    assert!(matches!(
        render_erc7730_pages(
            &tx,
            &calldata_sole_bytes(b"oneString(string)", overlong),
            &verified,
            None,
            &resolver
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(_))
    ));

    // Non-printable bytes must refuse rather than reach the display.
    for bad in [&b"line\nbreak"[..], &b"tab\there"[..], &[0x80u8, b'x'][..]] {
        assert!(
            matches!(
                render_erc7730_pages(
                    &tx,
                    &calldata_sole_bytes(b"oneString(string)", bad),
                    &verified,
                    None,
                    &resolver
                ),
                Err(crate::tx::erc7730_render::RenderErr::Reject(_))
            ),
            "non-printable payload must not render: {bad:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// VULN-erc7730-eip712-nested-struct-address-hide — on-device belt.
//
// A pinned EIP-712 descriptor whose primary type has a nested struct member
// (a single opaque `hashStruct` word this renderer cannot expand) MUST be
// declined to blind-sign, not partially clear-signed or mis-resolved. The
// supported single-rank Permit2 shapes below are driven directly by their
// shipping catalogue leaf; an unsupported multidimensional shape remains a
// process-private authenticated-refusal fixture.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn multidimensional_struct_array_bare_marker_declines_on_device() {
    const SIG: &str = "Batch(Item[][] items,address spender)Item(address token,uint256 amount)";
    let temp_root =
        std::env::temp_dir().join(format!("pqsigner-erc7730-rank-belt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_root);
    std::fs::create_dir_all(&temp_root).expect("create rank-belt fixture dir");
    let source = temp_root.join("rank-belt.json");
    let contract = [0x5Au8; 20];
    let contract_hex: String = contract.iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::write(
        &source,
        format!(
            r#"{{
              "context": {{ "eip712": {{
                "deployments": [{{ "chainId": 1, "address": "0x{contract_hex}" }}],
                "domain": {{ "name": "Rank Belt" }}
              }} }},
              "metadata": {{ "owner": "Test" }},
              "display": {{ "formats": {{
                "{SIG}": {{
                  "intent": "Batch",
                  "fields": [
                    {{ "path": "items.[].amount", "label": "Amount", "format": "tokenAmount",
                       "params": {{ "tokenPath": "items.[].token" }}, "visible": "always" }},
                    {{ "path": "spender", "label": "Spender", "format": "addressName",
                       "visible": "always" }}
                  ]
                }}
              }} }}
            }}"#
        ),
    )
    .expect("write rank-belt fixture");
    let mut emitted = dbgen::erc7730::try_compile_one(
        &source,
        &dbgen::erc7730::Policy::default(),
        Some(&temp_root),
    )
    .expect("unsupported rank emits authenticated refusal IR");
    let _ = std::fs::remove_dir_all(&temp_root);
    let leaf = emitted
        .pop()
        .expect("one deployment emits one refusal leaf");
    assert!(emitted.is_empty());

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("bare-refusal IR is schema-valid");
    let format = ir
        .format_iter()
        .next()
        .expect("one format")
        .expect("valid refusal format");
    assert_eq!(format.field_count, 1);
    assert_eq!(format.nested_descent_count, 0);
    let field = format
        .fields()
        .next()
        .expect("one field")
        .expect("valid field");
    let params = pqsigner_erc7730::render::params::parse(&ir, field.param_off)
        .expect("valid refusal params");
    assert_eq!(params.nested_struct, Some(&[0x01][..]));

    let verified = VerifiedDescriptor { ir };
    let primary_type_hash = keccak256(SIG.as_bytes());
    let encoded_data = [0u8; 64];
    let result = super::erc7730::render_erc7730_eip712_pages_v3(
        1,
        &contract,
        &primary_type_hash,
        &encoded_data,
        &[],
        &verified,
        None,
        &NameResolver::new(),
    );
    match result {
        Err(crate::tx::erc7730_render::RenderErr::Reject(message)) => assert!(
            message.contains("nested unsupported"),
            "device must reject specifically on the bare nested marker: {message}"
        ),
        Err(other) => panic!("expected bare-marker Reject, got {other:?}"),
        Ok(_) => panic!("multidimensional struct-array refusal IR must never clear-sign"),
    }
}

#[test]
fn v2_kind_declines_nested_permit2() {
    // Post-Phase-5: a nested-struct format signed via the OLD kind
    // (`render_erc7730_eip712_pages`, no `nested_blob`) MUST still decline — the
    // descent finds no DFS record to bind the `PermitDetails` hashStruct word,
    // so the whole render Rejects. A companion must use the V3 entry. This keeps
    // the "old kind never clear-signs a nested format" guarantee.
    let leaf = production_permit2_leaf(1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    assert!(matches!(ir.context_kind, ContextKind::Eip712));

    let fmt = ir
        .format_iter()
        .next()
        .expect("≥1 Permit2 format")
        .expect("valid format header");
    let pth = fmt.type_hash;
    let encoded_data = std::vec![0u8; fmt.static_head_words as usize * 32];

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    match super::erc7730::render_erc7730_eip712_pages(
        1,
        &[0u8; 20],
        &pth,
        &encoded_data,
        &verified,
        None,
        &resolver,
    ) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(_)) => {}
        Err(other) => panic!("expected a nested Reject, got {other:?}"),
        Ok(_) => {
            panic!("nested Permit2 format must NOT clear-sign via the V2 (no-nested-blob) path")
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// THE DECISIVE nested-EIP-712 test (design §3 rule 6): the production Permit2
// PermitSingle leaf drives the V3 render path. Every signed terminal field is
// visible in the shipping descriptor. The binding test proves that
// flipping ANY nested word or the committed top-level `details` word declines.
// (a) alone would pass even if the keccak binding were never checked; (b) is
// what proves shown ⟺ signed.
// ───────────────────────────────────────────────────────────────────────

// typeHash(PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)) — foundry.
const PERMIT_DETAILS_TYPEHASH: [u8; 32] = [
    0x65, 0x62, 0x6c, 0xad, 0x6c, 0xb9, 0x64, 0x93, 0xbf, 0x6f, 0x5e, 0xbe, 0xa2, 0x87, 0x56, 0xc9,
    0x66, 0xf0, 0x23, 0xab, 0x9e, 0x8a, 0x83, 0xa7, 0x10, 0x18, 0x49, 0xd5, 0x57, 0x3b, 0x36, 0x78,
];

/// Build a valid PermitSingle (top `encoded_data`, `nested_blob`) for a concrete
/// order. `nested_ed` = token | amount | expiration | nonce (4 words); the top
/// `details` word is the REAL `hashStruct(PermitDetails)` = the device's binding
/// target. Returns `(top_ed[96], nested_blob[2+128])`.
fn permit_single_vectors(
    token: [u8; 20],
    amount: u64,
    expiration: u64,
    nonce: u64,
    spender: [u8; 20],
    sig_deadline: u64,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut nested_ed = std::vec![0u8; 128];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&amount.to_be_bytes());
    nested_ed[64 + 24..96].copy_from_slice(&expiration.to_be_bytes());
    nested_ed[96 + 24..128].copy_from_slice(&nonce.to_be_bytes());

    // The committed word IS the real hashStruct — the same primitive the device
    // recomputes and binds against (not circular: the device uses the IR-pinned
    // type_hash + the blob's nested_ed; a flip in either breaks the equality).
    let details_hs = super::erc7730::nested::hash_struct(&PERMIT_DETAILS_TYPEHASH, &nested_ed);

    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&sig_deadline.to_be_bytes());

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    (top_ed, nested_blob)
}

#[test]
fn v3_permit_single_renders_nested_members() {
    let leaf = production_permit2_leaf(1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let pth = PERMIT_SINGLE_TYPEHASH;
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ]; // USDC
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ]; // Universal Router
    let (top_ed, nested_blob) = permit_single_vectors(
        token,
        1_000_000_000,
        1_704_067_200,
        7,
        spender,
        1_735_689_600,
    );

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let (mut pages, proof) = super::erc7730_secure_shim::render_erc7730_eip712_pages_v3_checked(
        1,
        &[0u8; 20],
        &pth,
        &top_ed,
        &nested_blob,
        &verified,
        None,
        &resolver,
    )
    .expect("valid PermitSingle clear-signs via checked V3");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // spender (top-level, shown).
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    // nested amount = 1_000_000_000 → without token metadata it renders raw
    // (`! raw, dec=?`); the digits must appear.
    assert!(
        dump.contains("1000000000"),
        "nested amount must render:\n{dump}"
    );
    let expiration: [u8; 32] = nested_blob[2 + 64..2 + 96]
        .try_into()
        .expect("PermitSingle expiration word");
    let nonce: [u8; 32] = nested_blob[2 + 96..2 + 128]
        .try_into()
        .expect("PermitSingle nonce word");
    assert_raw_word_pages(&pages, "Expiry (0=now)", &expiration);
    assert_raw_word_pages(&pages, "Allowance nonce", &nonce);
    let _ = find_page_by_label(&pages, "Allowance");
    let _ = find_page_by_label(&pages, "Sig deadline");
    assert!(
        dump.contains("2025"),
        "signature deadline must render:\n{dump}"
    );

    let spender_page = find_page_by_label(&pages, "Spender");
    append_fingerprint_for_test(&mut pages, Erc8213Kind::Eip712Final([0x88; 32]))
        .expect("V3 handler fingerprint suffix fits");
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::OK_SENTINEL,
        "checked V3 transcript survives only the handler suffix"
    );
    pages.buf[spender_page][1][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::FAIL_SENTINEL,
        "nested V3 field corruption must fail the final transcript proof"
    );
}

#[test]
fn v3_permit_single_expiry_zero_and_uint160_unlimited_are_semantically_exact() {
    let leaf = production_permit2_leaf(1);
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    let (base_top, base_blob) = permit_single_vectors(token, 1, 0, 9, spender, 1_735_689_600);
    let render = |top: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("Permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_SINGLE_TYPEHASH,
            top,
            blob,
            &verified,
            None,
            &NameResolver::new(),
        )
    };

    let zero_expiry = render(&base_top, &base_blob).expect("zero-expiry PermitSingle renders");
    let expiration: [u8; 32] = base_blob[2 + 64..2 + 96]
        .try_into()
        .expect("zero expiration word");
    assert_raw_word_pages(&zero_expiry, "Expiry (0=now)", &expiration);
    assert!(
        !dump_pages(&zero_expiry).contains("1970"),
        "Permit2 expiration zero must not be presented as Unix epoch"
    );

    let render_amount = |last_byte: u8| {
        let mut top = base_top.clone();
        let mut blob = base_blob.clone();
        let amount = &mut blob[2 + 32..2 + 64];
        amount.fill(0);
        amount[12..].fill(0xff);
        amount[31] = last_byte;
        let rebound = super::erc7730::nested::hash_struct(&PERMIT_DETAILS_TYPEHASH, &blob[2..]);
        top[..32].copy_from_slice(&rebound);
        render(&top, &blob).expect("canonical uint160 allowance renders")
    };

    let unlimited = render_amount(0xff);
    assert!(
        dump_pages(&unlimited)
            .to_ascii_lowercase()
            .contains("unlimited"),
        "exact uint160::MAX must carry the reusable unlimited-allowance warning"
    );
    let finite = render_amount(0xfe);
    assert!(
        !dump_pages(&finite)
            .to_ascii_lowercase()
            .contains("unlimited"),
        "uint160::MAX - 1 must remain a finite numeric allowance"
    );
}

#[test]
fn v3_permit_single_rejects_hash_bound_dirty_uint160_padding() {
    let leaf = production_permit2_leaf(1);
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let (mut top_ed, mut nested_blob) = permit_single_valid_vectors();

    // PermitDetails.amount is uint160. Keep the companion-supplied body fully
    // hash-bound by recomputing the committed hashStruct after dirtying one of
    // the twelve forbidden high bytes; rejection must therefore come from the
    // width belt, not from a vacuous hash mismatch.
    nested_blob[2 + 32] = 1;
    let rebound = super::erc7730::nested::hash_struct(&PERMIT_DETAILS_TYPEHASH, &nested_blob[2..]);
    top_ed[..32].copy_from_slice(&rebound);

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let result = super::erc7730::render_erc7730_eip712_pages_v3(
        1,
        &[0u8; 20],
        &pth,
        &top_ed,
        &nested_blob,
        &verified,
        None,
        &NameResolver::new(),
    );
    assert!(matches!(
        result,
        Err(crate::tx::erc7730_render::RenderErr::Reject(_))
    ));
}

#[test]
fn v3_permit_single_binding_is_non_vacuous() {
    let leaf = production_permit2_leaf(1);
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    let (top_ed, nested_blob) = permit_single_vectors(
        token,
        1_000_000_000,
        1_735_689_600,
        0,
        spender,
        1_735_689_600,
    );

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, blob, &verified, None, &resolver,
        )
    };

    // Baseline: renders.
    assert!(
        render(&top_ed, &nested_blob).is_ok(),
        "baseline must render"
    );

    // (b1) Flip EVERY byte of EVERY nested word. Each flip breaks
    // keccak(type_hash‖nested_ed) == committed → DECLINE.
    for word in 0..4usize {
        for byte in 0..32usize {
            let mut blob = nested_blob.clone();
            blob[2 + word * 32 + byte] ^= 0x01; // flip one bit inside nested_ed
            assert!(
                render(&top_ed, &blob).is_err(),
                "flipping nested word {word} byte {byte} must decline (binding is live)"
            );
        }
    }

    // (b2) Flip the committed top-level `details` hashStruct word → the device's
    // recomputed hashStruct no longer matches → DECLINE.
    for byte in 0..32usize {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed details word byte {byte} must decline"
        );
    }
}

// PermitSingle primary-type hash (foundry) — shared by the reconciliation tests.
const PERMIT_SINGLE_TYPEHASH: [u8; 32] = [
    0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79, 0x97,
    0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10, 0xf3, 0xd0,
];

fn permit_single_valid_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    permit_single_vectors(
        token,
        1_000_000_000,
        1_735_689_600,
        0,
        spender,
        1_735_689_600,
    )
}

/// Walk an EIP-712 IR's formats section and return the byte offset of the
/// `nested_descent_count` byte of the format whose `type_hash == target`.
/// Mirrors `ir::FormatIter` (fixed prefix 10 B: selector(4) field_count(1)
/// intent_len(1) static_head_words(2) nested_descent_count(1)
/// string_preimage_count(1); then intent; then type_hash(32) for EIP-712;
/// then `field_count` FieldEntry records).
fn eip712_format_ndc_offset(ir_bytes: &[u8], target: &[u8; 32]) -> Option<usize> {
    let formats_off = u16::from_be_bytes([ir_bytes[128], ir_bytes[129]]) as usize;
    let count = *ir_bytes.get(formats_off)? as usize;
    let mut p = formats_off + 1;
    for _ in 0..count {
        let entry_start = p;
        let field_count = *ir_bytes.get(p + 4)? as usize;
        let intent_len = *ir_bytes.get(p + 5)? as usize;
        p += 10 + intent_len; // fixed prefix + intent
        let th = ir_bytes.get(p..p + 32)?;
        let matched = th == target;
        p += 32; // EIP-712 type_hash
        for _ in 0..field_count {
            let label_len = *ir_bytes.get(p + 1)? as usize;
            p += 2 + label_len + 4; // format_op + label_len + label + path_off + param_off
        }
        if matched {
            return Some(entry_start + 8);
        }
    }
    None
}

/// THE reconciliation tripwire test (advisor blocker #1 — the E1 pinned-count
/// control). Schema v4 deep-validates the nested program before rendering, so a
/// format header whose authenticated `nested_descent_count` disagrees with the
/// recursively parsed anchors is rejected at IR admission. This is earlier and
/// stronger than the retained after-render consumption belt: malformed pinned
/// IR cannot become a `VerifiedDescriptor` at all.
#[test]
fn v3_reconciliation_rejects_wrong_pinned_descent_count() {
    let leaf = production_permit2_leaf(1);

    // Locate PermitSingle's format header nested_descent_count byte. The permit2
    // leaf now carries three formats (PermitSingle, PermitTransferFrom,
    // PermitBatch), so we WALK the formats section to find PermitSingle's entry
    // (by its type_hash) rather than assuming it is first. Within a format entry
    // the fixed prefix is selector(4)+field_count(1)+intent_len(1)+
    // static_head_words(2) = 8, so nested_descent_count sits at entry_start + 8.
    let ndc_off = eip712_format_ndc_offset(&leaf.ir_bytes, &PERMIT_SINGLE_TYPEHASH)
        .expect("PermitSingle format present in the permit2 leaf");

    let parse_patched = |ndc: u8| {
        let mut ir_bytes = leaf.ir_bytes.clone();
        assert_eq!(
            ir_bytes[ndc_off], 1,
            "PermitSingle pins exactly one descent point"
        );
        ir_bytes[ndc_off] = ndc;
        Erc7730Ir::parse(&ir_bytes).err()
    };

    // Claim TWO descent points but encode one anchor → reject at admission.
    assert!(
        matches!(
            parse_patched(2),
            Some(pqsigner_erc7730::ir::IrError::BadFormat)
        ),
        "one encoded anchor != pinned nested_descent_count(2) must decline"
    );
    // Claim ZERO while retaining one anchor → reject at admission.
    assert!(
        matches!(
            parse_patched(0),
            Some(pqsigner_erc7730::ir::IrError::BadFormat)
        ),
        "one encoded anchor != pinned nested_descent_count(0) must decline"
    );
}

/// The other half of E4-3 (total consumption): a valid nested_blob plus one
/// trailing byte → after the DFS binds the single record, cursor != blob.len()
/// → decline. (nested_blob is display-only/unsigned, so padding is hygiene not a
/// live exploit — but the cursor check must fire.)
#[test]
fn v3_reconciliation_rejects_trailing_nested_blob() {
    let leaf = production_permit2_leaf(1);
    let (top_ed, mut nested_blob) = permit_single_valid_vectors();
    nested_blob.push(0xEE); // one unconsumed trailing byte

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    assert!(
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_SINGLE_TYPEHASH,
            &top_ed,
            &nested_blob,
            &verified,
            None,
            &resolver,
        )
        .is_err(),
        "cursor != nested_blob.len() (trailing byte) must decline"
    );
}

// typeHash(TokenPermissions(address token,uint256 amount)) — foundry.
const TOKEN_PERMISSIONS_TYPEHASH: [u8; 32] = [
    0x61, 0x83, 0x58, 0xac, 0x3d, 0xb8, 0xdc, 0x27, 0x4f, 0x0c, 0xd8, 0x82, 0x9d, 0xa7, 0xe2, 0x34,
    0xbd, 0x48, 0xcd, 0x73, 0xc4, 0xa7, 0x40, 0xae, 0xde, 0x1a, 0xde, 0xc9, 0x84, 0x6d, 0x06, 0xa1,
];
// typeHash(PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)...) — foundry.
const PERMIT_TRANSFER_FROM_TYPEHASH: [u8; 32] = [
    0x93, 0x9c, 0x21, 0xa4, 0x8a, 0x8d, 0xbe, 0x3a, 0x9a, 0x24, 0x04, 0xa1, 0xd4, 0x66, 0x91, 0xe4,
    0xd3, 0x9f, 0x65, 0x83, 0xd6, 0xec, 0x6b, 0x35, 0x71, 0x46, 0x04, 0xc9, 0x86, 0xd8, 0x01, 0x06,
];

/// The MINIMAL nested binding: Permit2 `PermitTransferFrom` (`TokenPermissions`,
/// 2 members) — unlocked by the `nonce` curation. Proves the v0x03 machinery
/// handles a smaller struct than PermitSingle end-to-end: the nested amount +
/// token render, top-level spender + deadline + nonce show, AND flipping the
/// committed `permitted` word declines (binding is live for the 2-member shape).
#[test]
fn v3_permit_transfer_from_renders_and_flip_declines() {
    let leaf = production_permit2_leaf(1);
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ]; // USDC
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];

    // nested_ed (TokenPermissions) = token | amount (2 words).
    let mut nested_ed = std::vec![0u8; 64];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&500_000_000u64.to_be_bytes()); // 500 USDC
    let permitted_hs = super::erc7730::nested::hash_struct(&TOKEN_PERMISSIONS_TYPEHASH, &nested_ed);

    // top_ed (PermitTransferFrom) = permitted | spender | nonce | deadline (4 words).
    let mut top_ed = std::vec![0u8; 128];
    top_ed[0..32].copy_from_slice(&permitted_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&42u64.to_be_bytes()); // one-time nonce
    top_ed[96 + 24..128].copy_from_slice(&1_735_689_600u64.to_be_bytes()); // deadline (SHOWN)

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_TRANSFER_FROM_TYPEHASH,
            ed,
            blob,
            &verified,
            None,
            &resolver,
        )
    };

    let pages = render(&top_ed, &nested_blob).expect("valid PermitTransferFrom clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    assert!(
        dump.contains("500000000"),
        "nested amount must render:\n{dump}"
    );
    assert!(dump.contains("2025"), "deadline date must render:\n{dump}");
    assert!(!dump.contains("hidden"), "sanity");
    let _ = find_page_by_label(&pages, "Maximum transfer");
    let _ = find_page_by_label(&pages, "Deadline");
    let nonce: [u8; 32] = top_ed[64..96].try_into().expect("PermitTransferFrom nonce");
    assert_raw_word_pages(&pages, "Nonce", &nonce);
    assert!(
        !dump.contains("transfer 500000000"),
        "the signed cap must not be presented as an exact transfer"
    );

    let render_maximum = |last_byte: u8| {
        let mut ed = top_ed.clone();
        let mut blob = nested_blob.clone();
        blob[2 + 32..2 + 64].fill(0xff);
        blob[2 + 63] = last_byte;
        let rebound = super::erc7730::nested::hash_struct(&TOKEN_PERMISSIONS_TYPEHASH, &blob[2..]);
        ed[..32].copy_from_slice(&rebound);
        render(&ed, &blob).expect("canonical uint256 transfer cap renders")
    };
    let any_amount = render_maximum(0xff);
    assert!(
        dump_pages(&any_amount)
            .to_ascii_lowercase()
            .contains("any amount"),
        "exact uint256::MAX must state that the spender may choose any amount"
    );
    let finite = render_maximum(0xfe);
    assert!(
        !dump_pages(&finite)
            .to_ascii_lowercase()
            .contains("any amount"),
        "uint256::MAX - 1 must remain a finite one-time cap"
    );

    // Flip the committed `permitted` hashStruct word → decline (binding live).
    for byte in [0usize, 15, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed permitted word byte {byte} must decline"
        );
    }
    // Flip a nested word → decline.
    let mut blob = nested_blob.clone();
    blob[2 + 40] ^= 0x01; // inside the amount word
    assert!(
        render(&top_ed, &blob).is_err(),
        "flipping nested amount must decline"
    );
}

// PermitBatch primary-type hash (foundry).
const PERMIT_BATCH_TYPEHASH: [u8; 32] = [
    0xaf, 0x1b, 0x0d, 0x30, 0xd2, 0xca, 0xb0, 0x38, 0x0e, 0x68, 0xf0, 0x68, 0x90, 0x07, 0xe3, 0x25,
    0x49, 0x93, 0xc5, 0x96, 0xf2, 0xfd, 0xd0, 0xaa, 0xa7, 0xf4, 0xd0, 0x4f, 0x79, 0x44, 0x08, 0x63,
];

/// A REAL 2-element Permit2 `PermitBatch` (v2 array-of-struct). el0 = USDC/1e9/
/// expiry 1735689600/nonce7, el1 = WETH/5e18/expiry 1767225600/nonce11. The committed `details`
/// word is the foundry-pinned array binding `keccak(hashStruct(el0)‖hashStruct(el1))
/// = 0x57b01054…` (recomputed here via the SAME device primitive — not circular:
/// the device recomputes from the IR-pinned type_hash + the blob; a flip in
/// either breaks the equality). Returns `(top_ed[96], nested_blob)`.
fn permit_batch_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let usdc = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let weth = [
        0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27, 0xeA, 0xD9,
        0x08, 0x3C, 0x75, 0x6C, 0xc2,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];

    let mut el0 = std::vec![0u8; 128];
    el0[12..32].copy_from_slice(&usdc);
    el0[32 + 24..64].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    el0[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());
    el0[96 + 24..128].copy_from_slice(&7u64.to_be_bytes());
    let mut el1 = std::vec![0u8; 128];
    el1[12..32].copy_from_slice(&weth);
    el1[32 + 24..64].copy_from_slice(&5_000_000_000_000_000_000u64.to_be_bytes());
    el1[64 + 24..96].copy_from_slice(&1_767_225_600u64.to_be_bytes());
    el1[96 + 24..128].copy_from_slice(&11u64.to_be_bytes());

    let details_word =
        super::erc7730::nested::hash_struct_array(&PERMIT_DETAILS_TYPEHASH, &[&el0[..], &el1[..]]);
    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_word);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());

    // nested_blob = [u16 elem_count=2] [u16 128][el0] [u16 128][el1].
    let mut blob = std::vec![0u8, 2]; // elem_count = 2
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el1);
    (top_ed, blob)
}

fn permit_batch_repeated_vectors(count: u16) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    assert!((1..=6).contains(&count));
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    let mut elements = std::vec::Vec::new();
    for index in 0..count {
        let mut element = std::vec![0u8; 128];
        element[12..32].copy_from_slice(&token);
        element[32 + 24..64].copy_from_slice(&(1_000_000u64 + index as u64).to_be_bytes());
        element[64 + 24..96].copy_from_slice(&(1_735_689_600u64 + index as u64).to_be_bytes());
        element[96 + 24..128].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        elements.push(element);
    }
    let refs: std::vec::Vec<&[u8]> = elements.iter().map(|element| element.as_slice()).collect();
    let details_word = super::erc7730::nested::hash_struct_array(&PERMIT_DETAILS_TYPEHASH, &refs);
    let mut top_ed = std::vec![0u8; 96];
    top_ed[..32].copy_from_slice(&details_word);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&1_767_225_600u64.to_be_bytes());

    let mut blob = count.to_be_bytes().to_vec();
    for element in elements {
        blob.extend_from_slice(&128u16.to_be_bytes());
        blob.extend_from_slice(&element);
    }
    (top_ed, blob)
}

#[test]
fn v3_permit_batch_page_budget_is_atomic_at_the_verified_boundary() {
    let leaf = production_permit2_leaf(1);
    for count in 1..=6u16 {
        let (top_ed, blob) = permit_batch_repeated_vectors(count);
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("Permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let result = super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_BATCH_TYPEHASH,
            &top_ed,
            &blob,
            &verified,
            None,
            &NameResolver::new(),
        );
        if count <= 3 {
            let pages = result.unwrap_or_else(|error| {
                panic!("{count}-element PermitBatch must fit completely: {error:?}")
            });
            let dump = dump_pages(&pages).to_ascii_lowercase();
            assert!(
                dump.contains(&format!("item {count} of {count}")),
                "accepted batch must include its final complete element:\n{dump}"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(crate::tx::erc7730_render::RenderErr::PageBudget)
                ),
                "{count}-element PermitBatch must fail atomically at the page boundary"
            );
        }
    }
}

#[test]
fn v3_permit_batch_array_renders_both_elements() {
    let leaf = production_permit2_leaf(1);
    let (top_ed, blob) = permit_batch_vectors();
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages_v3(
        1,
        &[0u8; 20],
        &PERMIT_BATCH_TYPEHASH,
        &top_ed,
        &blob,
        &verified,
        None,
        &resolver,
    )
    .expect("valid 2-element PermitBatch clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // Both element amounts render (raw, no token metadata → `! raw, dec=?`; a
    // 19-digit value splits across two display rows, so match the leading run).
    assert!(
        dump.contains("1000000000"),
        "element 0 (USDC 1e9) amount:\n{dump}"
    );
    assert!(
        dump.contains("5000000000000000"),
        "element 1 (WETH 5e18) amount:\n{dump}"
    );
    // Distinct token addresses (unverified pages) prove per-element resolution.
    assert!(
        dump.contains("a0b86991c6218b"),
        "element 0 token (USDC):\n{dump}"
    );
    assert!(dump.contains("c02aaa39"), "element 1 token (WETH):\n{dump}");
    // The "Item 1 of 2" / "Item 2 of 2" dividers.
    assert!(dump.contains("item 1 of 2"), "element 0 divider:\n{dump}");
    assert!(dump.contains("item 2 of 2"), "element 1 divider:\n{dump}");
    let expiry0: [u8; 32] = blob[4 + 64..4 + 96].try_into().expect("element 0 expiry");
    let nonce0: [u8; 32] = blob[4 + 96..4 + 128].try_into().expect("element 0 nonce");
    let expiry1: [u8; 32] = blob[134 + 64..134 + 96]
        .try_into()
        .expect("element 1 expiry");
    let nonce1: [u8; 32] = blob[134 + 96..134 + 128]
        .try_into()
        .expect("element 1 nonce");
    assert_nth_raw_word_pages(&pages, "Expiry (0=now)", 0, &expiry0);
    assert_nth_raw_word_pages(&pages, "Expiry (0=now)", 1, &expiry1);
    assert_nth_raw_word_pages(&pages, "Allowance nonce", 0, &nonce0);
    assert_nth_raw_word_pages(&pages, "Allowance nonce", 1, &nonce1);
    let _ = find_page_by_label(&pages, "Spender");
    let _ = find_page_by_label(&pages, "Sig deadline");
}

#[test]
fn v3_permit_batch_array_binding_is_non_vacuous() {
    let leaf = production_permit2_leaf(1);
    let (top_ed, blob) = permit_batch_vectors();

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_BATCH_TYPEHASH,
            ed,
            b,
            &verified,
            None,
            &resolver,
        )
    };
    assert!(render(&top_ed, &blob).is_ok(), "baseline renders");

    // (a) Flip ONE bit inside EACH element word (both elements, every word) →
    // the concat hashStruct no longer matches `committed` → DECLINE.
    // `blob` layout: elem_count(2) then [len(2) el0(128)] [len(2) el1(128)];
    // element bytes start at offset 4 (el0) and 4+128+2=134 (el1).
    for (base, label) in [(4usize, "el0"), (134usize, "el1")] {
        for word in 0..4usize {
            let mut b = blob.clone();
            b[base + word * 32] ^= 0x01;
            assert!(
                render(&top_ed, &b).is_err(),
                "flipping {label} word {word} must decline (array binding is live)"
            );
        }
    }
    // (b) Flip the committed `details` array word → DECLINE.
    for byte in [0usize, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &blob).is_err(),
            "flipping committed array word byte {byte} declines"
        );
    }
    // (c) Lie about elem_count (claim 1) — the concat over 1 element != committed
    // (which bound 2) → DECLINE (element-count is implicitly bound by the hash).
    let mut b = blob.clone();
    b[0] = 0;
    b[1] = 1;
    assert!(
        render(&top_ed, &b).is_err(),
        "lying elem_count=1 must decline"
    );
    // (d) elem_count = 0 → explicit decline (the empty-batch attack).
    let mut b0 = blob.clone();
    b0[0] = 0;
    b0[1] = 0;
    assert!(
        render(&top_ed, &b0).is_err(),
        "elem_count=0 must decline (empty batch)"
    );
}

/// The canonical EIP-2612 template hides `owner` and `nonce`. The strict
/// compiler no longer carries global semantic allowlists: a hidden signed
/// scalar cannot enter the authenticated catalogue, even when a convention
/// suggests it will equal the signer. Assert exclusion instead of exercising
/// an unreachable trusted-render path.
#[test]
fn erc2612_permit_with_hidden_owner_is_excluded() {
    assert_registry_source_excluded("eip712-permit-ethereum-link.json");
}

// ───────────────────────────────────────────────────────────────────────
// Tier B: canonical dynamic tokenPath framing — Uniswap swaps.
//
// Endpoint tokenPaths identify amount metadata; they do not by themselves
// display a complete signed packed route or address array. Production admits
// the two all-static Router02 single-hop calls, the two V2 `address[]` routes,
// and the two exactly enrolled packed-V3 tuple routes only with authenticated
// recipient/amount/value semantics. Packed V3 paths use a selector-derived
// direction, show every token and fee without a lossy summary, and reject any
// noncanonical tuple/tail framing. A process-private fixture is retained as a
// compiler-level collection-path backstop; the production tests below exercise
// the real Merkle-bound Router02 leaf.
// ───────────────────────────────────────────────────────────────────────
pub(super) const UNI_V3: [u8; 20] = [
    0x68, 0xb3, 0x46, 0x58, 0x33, 0xfb, 0x72, 0xa7, 0x0e, 0xcd, 0xf4, 0x85, 0xe0, 0xe4, 0xc7, 0xbd,
    0x86, 0x65, 0xfc, 0x45,
];
const TOKEN_IN: [u8; 20] = [0x11; 20];
const TOKEN_MID: [u8; 20] = [0xAB; 20];
const TOKEN_OUT: [u8; 20] = [0x22; 20];
const UNI_EXACT_INPUT_SINGLE: &str =
    "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))";
const UNI_EXACT_OUTPUT_SINGLE: &str =
    "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))";
const UNI_EXACT_INPUT_PACKED: &str = "exactInput((bytes,address,uint256,uint256))";
const UNI_EXACT_OUTPUT_PACKED: &str = "exactOutput((bytes,address,uint256,uint256))";
const UNI_SWAP_EXACT_TOKENS: &str = "swapExactTokensForTokens(uint256,uint256,address[],address)";
const UNI_SWAP_TOKENS_FOR_EXACT: &str =
    "swapTokensForExactTokens(uint256,uint256,address[],address)";

const UNI_PACKED_OUTER_OFFSET_WORD: usize = 4;
const UNI_PACKED_PATH_OFFSET_WORD: usize = UNI_PACKED_OUTER_OFFSET_WORD + 32;
const UNI_PACKED_RECIPIENT_WORD: usize = UNI_PACKED_PATH_OFFSET_WORD + 32;
const UNI_PACKED_FIRST_AMOUNT_WORD: usize = UNI_PACKED_RECIPIENT_WORD + 32;
const UNI_PACKED_SECOND_AMOUNT_WORD: usize = UNI_PACKED_FIRST_AMOUNT_WORD + 32;
const UNI_PACKED_PATH_LENGTH_WORD: usize = UNI_PACKED_SECOND_AMOUNT_WORD + 32;
const UNI_PACKED_PATH_DATA: usize = UNI_PACKED_PATH_LENGTH_WORD + 32;

fn calldata_uniswap_single(
    signature: &str,
    recipient: [u8; 20],
    first_amount: u64,
    second_amount: u64,
    sqrt_price_limit_x96: u64,
) -> Vec<u8> {
    calldata_static(
        signature,
        &[
            abi_address_word(TOKEN_IN),
            abi_address_word(TOKEN_OUT),
            u256_from_u64(3_000).0,
            abi_address_word(recipient),
            u256_from_u64(first_amount).0,
            u256_from_u64(second_amount).0,
            u256_from_u64(sqrt_price_limit_x96).0,
        ],
    )
}

pub(super) fn calldata_uniswap_exact_input(recipient: [u8; 20]) -> Vec<u8> {
    calldata_uniswap_single(UNI_EXACT_INPUT_SINGLE, recipient, 1_500_000, 1_000_000, 0)
}

fn calldata_uniswap_exact_output(recipient: [u8; 20]) -> Vec<u8> {
    calldata_uniswap_single(UNI_EXACT_OUTPUT_SINGLE, recipient, 1_000_000, 1_500_000, 0)
}

/// Pack a route in its literal calldata order: `token (uint24 fee token)+`.
fn uniswap_v3_packed_path(tokens: &[[u8; 20]], fees: &[u32]) -> Vec<u8> {
    assert_eq!(tokens.len(), fees.len() + 1, "one more token than fee");
    let mut path = Vec::with_capacity(20 + fees.len() * 23);
    path.extend_from_slice(&tokens[0]);
    for (index, fee) in fees.iter().copied().enumerate() {
        assert!(fee <= 0x00ff_ffff, "fee must fit uint24");
        path.extend_from_slice(&fee.to_be_bytes()[1..]);
        path.extend_from_slice(&tokens[index + 1]);
    }
    path
}

/// Encode the route from the user's execution order. Router02 exact-output
/// calldata stores its path backwards, while exact-input stores it forwards.
/// The trusted renderer must derive that distinction from the signed selector.
fn uniswap_v3_execution_path(signature: &str, tokens: &[[u8; 20]], fees: &[u32]) -> Vec<u8> {
    assert_eq!(tokens.len(), fees.len() + 1, "one more token than fee");
    match signature {
        UNI_EXACT_INPUT_PACKED => uniswap_v3_packed_path(tokens, fees),
        UNI_EXACT_OUTPUT_PACKED => {
            let reverse_tokens = tokens.iter().rev().copied().collect::<Vec<_>>();
            let reverse_fees = fees.iter().rev().copied().collect::<Vec<_>>();
            uniswap_v3_packed_path(&reverse_tokens, &reverse_fees)
        }
        _ => panic!("unsupported packed Router02 signature: {signature}"),
    }
}

/// Canonical ABI encoding of Router02's sole dynamic
/// `(bytes,address,uint256,uint256)` tuple. `path` is already in the literal
/// calldata order so malformed-path tests can bypass the execution-order
/// helper without bypassing ABI framing.
fn calldata_uniswap_packed_raw(
    signature: &str,
    path: &[u8],
    recipient: [u8; 20],
    first_amount: U256,
    second_amount: U256,
) -> Vec<u8> {
    let selector = keccak256(signature.as_bytes());
    let padded_path_len = (path.len() + 31) / 32 * 32;
    let mut calldata = Vec::with_capacity(UNI_PACKED_PATH_DATA + padded_path_len);
    calldata.extend_from_slice(&selector[..4]);
    calldata.extend_from_slice(&u256_from_u64(32).0); // sole outer tuple offset
    calldata.extend_from_slice(&u256_from_u64(128).0); // bytes tail after four-word tuple head
    calldata.extend_from_slice(&abi_address_word(recipient));
    calldata.extend_from_slice(&first_amount.0);
    calldata.extend_from_slice(&second_amount.0);
    calldata.extend_from_slice(&u256_from_u64(path.len() as u64).0);
    calldata.extend_from_slice(path);
    calldata.resize(UNI_PACKED_PATH_DATA + padded_path_len, 0);
    calldata
}

fn calldata_uniswap_packed(
    signature: &str,
    tokens: &[[u8; 20]],
    fees: &[u32],
    recipient: [u8; 20],
    first_amount: U256,
    second_amount: U256,
) -> Vec<u8> {
    let path = uniswap_v3_execution_path(signature, tokens, fees);
    calldata_uniswap_packed_raw(signature, &path, recipient, first_amount, second_amount)
}

#[test]
fn production_uniswap_router02_admits_all_six_guarded_routes_and_keeps_them_known() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Router02 IR parses");
    assert_eq!(ir.format_count(), Ok(6));

    for signature in [
        UNI_EXACT_INPUT_SINGLE,
        UNI_EXACT_OUTPUT_SINGLE,
        UNI_EXACT_INPUT_PACKED,
        UNI_EXACT_OUTPUT_PACKED,
        UNI_SWAP_EXACT_TOKENS,
        UNI_SWAP_TOKENS_FOR_EXACT,
    ] {
        let selector = keccak256(signature.as_bytes());
        let key: [u8; 4] = selector[..4].try_into().expect("selector width");
        assert!(
            ir.find_format_by_selector(&key)
                .expect("Router02 format table parses")
                .is_some(),
            "guarded Router02 call must be admitted: {signature}"
        );
    }

    for signature in [
        UNI_EXACT_INPUT_SINGLE,
        UNI_EXACT_OUTPUT_SINGLE,
        UNI_EXACT_INPUT_PACKED,
        UNI_EXACT_OUTPUT_PACKED,
        UNI_SWAP_EXACT_TOKENS,
        UNI_SWAP_TOKENS_FOR_EXACT,
    ] {
        let digest = keccak256(signature.as_bytes());
        let selector: [u8; 4] = digest[..4].try_into().expect("selector width");
        assert!(
            registry.known_calls.contains(&(1, UNI_V3, selector)),
            "every Router02 call must remain exactly known: {signature}"
        );
        assert!(
            pqsigner_erc7730::known_calls::may_contain(
                &registry.known_calls_bloom,
                1,
                &UNI_V3,
                &selector,
            ),
            "every Router02 call must remain in the fail-closed Bloom: {signature}"
        );
    }
}

fn assert_complete_packed_v3_route_pages(
    pages: &Pages,
    execution_tokens: &[[u8; 20]],
    execution_fees: &[u32],
) {
    let route_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Route")
        .collect::<Vec<_>>();
    assert_eq!(
        route_pages.len(),
        execution_tokens.len(),
        "packed route must have exactly one full-address page per token and no summary page:\n{}",
        dump_pages(pages)
    );
    for (index, token) in execution_tokens.iter().enumerate() {
        let mut expected = [[b' '; DISPLAY_COLS]; 4];
        expected[0][..5].copy_from_slice(b"Route");
        let [_, r1, r2, r3] = &mut expected;
        write_addr_full(r1, r2, r3, token);
        assert_eq!(
            *route_pages[index], expected,
            "packed route token {index} must show all 20 signed bytes in execution order"
        );
    }

    let fee_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Pool fee (ppm)")
        .collect::<Vec<_>>();
    assert_eq!(
        fee_pages.len(),
        execution_fees.len(),
        "packed route must have exactly one raw uint24 page per fee:\n{}",
        dump_pages(pages)
    );
    for (index, fee) in execution_fees.iter().copied().enumerate() {
        assert_eq!(
            [
                row_str(&fee_pages[index][0]),
                row_str(&fee_pages[index][1]),
                row_str(&fee_pages[index][2]),
                row_str(&fee_pages[index][3]),
            ],
            [
                "Pool fee (ppm)".to_string(),
                format!("{fee} ppm"),
                String::new(),
                String::new(),
            ],
            "packed route fee {index} must show the exact unsigned uint24 in execution order"
        );
    }
}

#[test]
fn production_uniswap_router02_packed_routes_render_one_and_five_hops_in_execution_order() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let routes = [
        (vec![TOKEN_IN, TOKEN_OUT], vec![500u32]),
        (
            vec![
                [0x10; 20], [0x20; 20], [0x30; 20], [0x40; 20], [0x50; 20], [0x60; 20],
            ],
            vec![1u32, 500, 3_000, 10_000, 0x00ab_cdef],
        ),
    ];

    for signature in [UNI_EXACT_INPUT_PACKED, UNI_EXACT_OUTPUT_PACKED] {
        for (tokens, fees) in &routes {
            let packed = uniswap_v3_execution_path(signature, tokens, fees);
            if signature == UNI_EXACT_INPUT_PACKED {
                assert_eq!(&packed[..20], &tokens[0]);
            } else {
                assert_eq!(
                    &packed[..20],
                    tokens.last().expect("route has output token"),
                    "exact-output calldata must carry the reverse path"
                );
            }
            let calldata = calldata_uniswap_packed(
                signature,
                tokens,
                fees,
                recipient,
                u256_from_u64(1_500_000),
                u256_from_u64(1_000_000),
            );
            assert_selector_matches(&verified.ir, &calldata, signature);
            let rendered = render_erc7730_pages_with_signer_checked(
                &tx, &calldata, &verified, None, &resolver, &signer,
            )
            .unwrap_or_else(|error| {
                panic!("render {signature} with {} hops: {error:?}", fees.len())
            });
            assert_all_pages_printable(&rendered.pages);
            assert_complete_packed_v3_route_pages(&rendered.pages, tokens, fees);
            assert_full_address_field_page(&rendered.pages, "Beneficiary", &recipient);
            assert!(
                rendered
                    .transcript_receipt
                    .range_matches(&rendered.pages, 0),
                "the complete packed-route transcript must be receipt-bound"
            );
        }
    }
}

#[test]
fn production_uniswap_router02_packed_sender_amount_and_value_guards_are_exact() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let mut changed_signer = signer;
    changed_signer[19] ^= 1;
    let tokens = [TOKEN_IN, TOKEN_OUT];
    let fees = [500u32];
    let mut address_one = [0u8; 20];
    address_one[19] = 1;
    let mut address_two = [0u8; 20];
    address_two[19] = 2;

    for signature in [UNI_EXACT_INPUT_PACKED, UNI_EXACT_OUTPUT_PACKED] {
        let sentinel = calldata_uniswap_packed(
            signature,
            &tokens,
            &fees,
            address_one,
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
        );
        assert!(matches!(
            render_erc7730_pages(&tx, &sentinel, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 sender unbound"
            ))
        ));
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &sentinel, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render packed sentinel {signature}: {error:?}"));
        assert_full_address_field_page(&rendered.pages, "Beneficiary", &signer);
        let changed = render_erc7730_pages_with_signer_checked(
            &tx,
            &sentinel,
            &verified,
            None,
            &resolver,
            &changed_signer,
        )
        .unwrap_or_else(|error| panic!("render changed packed signer {signature}: {error:?}"));
        assert_full_address_field_page(&changed.pages, "Beneficiary", &changed_signer);
        assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
        assert!(!rendered
            .transcript_receipt
            .exact_match(&changed.transcript_receipt));

        let forbidden = calldata_uniswap_packed(
            signature,
            &tokens,
            &fees,
            address_two,
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
        );
        assert!(
            render_erc7730_pages_with_signer_checked(
                &tx, &forbidden, &verified, None, &resolver, &signer,
            )
            .is_err(),
            "address(2) must refuse {signature}"
        );

        let canonical = calldata_uniswap_packed(
            signature,
            &tokens,
            &fees,
            [0x33; 20],
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
        );
        let mut funded = envelope(1, UNI_V3);
        funded.value = u256_from_u64(1);
        assert!(
            render_erc7730_pages_with_signer_checked(
                &funded, &canonical, &verified, None, &resolver, &signer,
            )
            .is_err(),
            "nonzero outer value must refuse {signature}"
        );
    }

    let zero_input = calldata_uniswap_packed(
        UNI_EXACT_INPUT_PACKED,
        &tokens,
        &fees,
        [0x33; 20],
        U256::default(),
        u256_from_u64(1_000_000),
    );
    assert!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_input,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .is_err(),
        "packed exactInput amountIn=0 must refuse"
    );
    let zero_minimum = calldata_uniswap_packed(
        UNI_EXACT_INPUT_PACKED,
        &tokens,
        &fees,
        [0x33; 20],
        u256_from_u64(1_500_000),
        U256::default(),
    );
    render_erc7730_pages_with_signer_checked(
        &tx,
        &zero_minimum,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("exactInput amountOutMinimum=0 is shown, not silently given an unrelated guard");

    for (amount_out, input_cap) in [
        (U256::default(), u256_from_u64(1_500_000)),
        (u256_from_u64(1_000_000), U256::default()),
        (U256::default(), U256::default()),
    ] {
        let zero_semantic = calldata_uniswap_packed(
            UNI_EXACT_OUTPUT_PACKED,
            &tokens,
            &fees,
            [0x33; 20],
            amount_out,
            input_cap,
        );
        render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_semantic,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .expect("exactOutput zero amount/cap must not inherit exactInput's nonzero guard");
    }
}

#[test]
fn production_uniswap_router02_packed_framing_and_hop_bounds_never_fall_back() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let tokens = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let fees = [500u32, 3_000];
    let six_hop_tokens = [
        [0x10; 20], [0x20; 20], [0x30; 20], [0x40; 20], [0x50; 20], [0x60; 20], [0x70; 20],
    ];
    let six_hop_fees = [1u32, 2, 3, 4, 5, 6];

    for signature in [UNI_EXACT_INPUT_PACKED, UNI_EXACT_OUTPUT_PACKED] {
        let packed = uniswap_v3_execution_path(signature, &tokens, &fees);
        let baseline = calldata_uniswap_packed_raw(
            signature,
            &packed,
            [0x33; 20],
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
        );
        render_erc7730_pages_with_signer_checked(
            &tx, &baseline, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("canonical packed tuple must render: {error:?}"));

        let mut malformed: Vec<(Vec<u8>, &'static str)> = Vec::new();

        for (outer_offset, case) in [
            (0u64, "outer tuple head alias"),
            (33, "misaligned outer tuple offset"),
            (64, "gapped outer tuple offset"),
        ] {
            let mut calldata = baseline.clone();
            calldata[UNI_PACKED_OUTER_OFFSET_WORD..UNI_PACKED_OUTER_OFFSET_WORD + 32]
                .copy_from_slice(&u256_from_u64(outer_offset).0);
            malformed.push((calldata, case));
        }
        let mut huge_outer = baseline.clone();
        huge_outer[UNI_PACKED_OUTER_OFFSET_WORD] = 1;
        malformed.push((huge_outer, "oversized outer tuple offset"));

        for (path_offset, case) in [
            (96u64, "path tail aliases tuple head"),
            (129, "misaligned path offset"),
            (160, "gapped path offset"),
        ] {
            let mut calldata = baseline.clone();
            calldata[UNI_PACKED_PATH_OFFSET_WORD..UNI_PACKED_PATH_OFFSET_WORD + 32]
                .copy_from_slice(&u256_from_u64(path_offset).0);
            malformed.push((calldata, case));
        }
        let mut huge_path_offset = baseline.clone();
        huge_path_offset[UNI_PACKED_PATH_OFFSET_WORD] = 1;
        malformed.push((huge_path_offset, "oversized path offset"));

        for (claimed_len, case) in [
            (
                packed.len() as u64 - 1,
                "short nonintegral claimed path length",
            ),
            (
                packed.len() as u64 + 1,
                "long nonintegral claimed path length",
            ),
        ] {
            let mut calldata = baseline.clone();
            calldata[UNI_PACKED_PATH_LENGTH_WORD..UNI_PACKED_PATH_LENGTH_WORD + 32]
                .copy_from_slice(&u256_from_u64(claimed_len).0);
            malformed.push((calldata, case));
        }
        let mut huge_length = baseline.clone();
        huge_length[UNI_PACKED_PATH_LENGTH_WORD] = 1;
        malformed.push((huge_length, "oversized path length"));

        let padding_start = UNI_PACKED_PATH_DATA + packed.len();
        assert!(
            padding_start < baseline.len(),
            "two-hop fixture has padding"
        );
        let mut dirty_padding = baseline.clone();
        dirty_padding[padding_start] = 1;
        malformed.push((dirty_padding, "nonzero bytes padding"));

        let mut trailing_byte = baseline.clone();
        trailing_byte.push(0);
        malformed.push((trailing_byte, "trailing byte after exact tail"));
        let mut trailing_word = baseline.clone();
        trailing_word.extend_from_slice(&[0u8; 32]);
        malformed.push((trailing_word, "trailing word after exact tail"));
        let mut truncated_tail = baseline.clone();
        truncated_tail.pop();
        malformed.push((truncated_tail, "truncated zero padding"));
        malformed.push((
            baseline[..UNI_PACKED_PATH_LENGTH_WORD].to_vec(),
            "truncated tuple before path length",
        ));

        let mut dirty_recipient = baseline.clone();
        dirty_recipient[UNI_PACKED_RECIPIENT_WORD] = 1;
        malformed.push((dirty_recipient, "noncanonical recipient high padding"));

        let zero_hop = uniswap_v3_packed_path(&[[0x10; 20]], &[]);
        malformed.push((
            calldata_uniswap_packed_raw(
                signature,
                &zero_hop,
                [0x33; 20],
                u256_from_u64(1_500_000),
                u256_from_u64(1_000_000),
            ),
            "zero-hop path",
        ));
        let mut nonintegral = packed.clone();
        nonintegral.push(0);
        malformed.push((
            calldata_uniswap_packed_raw(
                signature,
                &nonintegral,
                [0x33; 20],
                u256_from_u64(1_500_000),
                u256_from_u64(1_000_000),
            ),
            "nonintegral hop stride",
        ));
        malformed.push((
            calldata_uniswap_packed(
                signature,
                &six_hop_tokens,
                &six_hop_fees,
                [0x33; 20],
                u256_from_u64(1_500_000),
                u256_from_u64(1_000_000),
            ),
            "six-hop path exceeds review cap",
        ));

        for (calldata, case) in malformed {
            assert!(
                matches!(
                    render_erc7730_pages_with_signer_checked(
                        &tx, &calldata, &verified, None, &resolver, &signer,
                    ),
                    Err(crate::tx::erc7730_render::RenderErr::Reject(_))
                ),
                "{case} must hard-refuse for {signature}"
            );
            let mut proofs = DispatchPageProofs::new();
            proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &tx,
                    &calldata,
                    &signer,
                    None,
                    None,
                    None,
                    Some(&verified),
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .is_err(),
                "{case} must refuse through dispatch without a blind fallback for {signature}"
            );
        }
    }
}

#[test]
fn production_uniswap_router02_packed_every_operand_byte_changes_transcript_or_refuses() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let tokens = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let fees = [500u32, 3_000];

    for signature in [UNI_EXACT_INPUT_PACKED, UNI_EXACT_OUTPUT_PACKED] {
        let packed = uniswap_v3_execution_path(signature, &tokens, &fees);
        let baseline_calldata = calldata_uniswap_packed_raw(
            signature,
            &packed,
            [0x33; 20],
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
        );
        let baseline = render_erc7730_pages_with_signer_checked(
            &tx,
            &baseline_calldata,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render mutation baseline {signature}: {error:?}"));

        let assert_changed_or_refused = |mutated: &[u8], case: &str| {
            if let Ok(changed) = render_erc7730_pages_with_signer_checked(
                &tx, mutated, &verified, None, &resolver, &signer,
            ) {
                assert_ne!(
                    baseline.pages.as_slice(),
                    changed.pages.as_slice(),
                    "{case} changed silently for {signature}"
                );
                assert!(
                    !baseline
                        .transcript_receipt
                        .exact_match(&changed.transcript_receipt),
                    "{case} preserved the transcript receipt for {signature}"
                );
            }
        };

        for packed_token_index in 0..tokens.len() {
            let token_start = UNI_PACKED_PATH_DATA + packed_token_index * 23;
            for byte_index in 0..20usize {
                let mut mutated = baseline_calldata.clone();
                mutated[token_start + byte_index] ^= 1;
                assert_changed_or_refused(
                    &mutated,
                    &format!("packed token {packed_token_index} byte {byte_index}"),
                );
            }
        }
        for packed_fee_index in 0..fees.len() {
            let fee_start = UNI_PACKED_PATH_DATA + packed_fee_index * 23 + 20;
            for byte_index in 0..3usize {
                let mut mutated = baseline_calldata.clone();
                mutated[fee_start + byte_index] ^= 1;
                assert_changed_or_refused(
                    &mutated,
                    &format!("packed fee {packed_fee_index} byte {byte_index}"),
                );
            }
        }
        for byte_index in 0..20usize {
            let mut mutated = baseline_calldata.clone();
            mutated[UNI_PACKED_RECIPIENT_WORD + 12 + byte_index] ^= 1;
            assert_changed_or_refused(&mutated, &format!("recipient byte {byte_index}"));
        }
        for (word_start, label) in [
            (UNI_PACKED_FIRST_AMOUNT_WORD, "first amount"),
            (UNI_PACKED_SECOND_AMOUNT_WORD, "second amount"),
        ] {
            for byte_index in 0..32usize {
                let mut mutated = baseline_calldata.clone();
                mutated[word_start + byte_index] ^= 1;
                assert_changed_or_refused(&mutated, &format!("{label} byte {byte_index}"));
            }
        }
    }
}

#[test]
fn production_uniswap_router02_single_hop_zero_price_and_value_render_literal_recipient() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let recipient = [0x33; 20];

    for (signature, calldata) in [
        (
            UNI_EXACT_INPUT_SINGLE,
            calldata_uniswap_exact_input(recipient),
        ),
        (
            UNI_EXACT_OUTPUT_SINGLE,
            calldata_uniswap_exact_output(recipient),
        ),
    ] {
        assert_selector_matches(&verified.ir, &calldata, signature);
        let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
            .unwrap_or_else(|error| panic!("render {signature}: {error:?}"));
        assert_all_pages_printable(&pages);
        assert_full_address_field_page(&pages, "Beneficiary", &recipient);
        assert_raw_word_pages(&pages, "Price limit", &[0u8; 32]);
        let native_value = page_strs(&pages, find_page_by_label(&pages, "Native value"));
        assert!(
            native_value.iter().any(|row| row.contains('0')),
            "zero outer value must be visible for {signature}: {native_value:?}"
        );
    }
}

#[test]
fn production_uniswap_router02_sender_sentinel_binds_only_the_authenticated_signer() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let mut sender_sentinel = [0u8; 20];
    sender_sentinel[19] = 1;
    let signer = [0x44; 20];
    let mut mutated_signer = signer;
    mutated_signer[19] ^= 1;

    for (signature, calldata) in [
        (
            UNI_EXACT_INPUT_SINGLE,
            calldata_uniswap_exact_input(sender_sentinel),
        ),
        (
            UNI_EXACT_OUTPUT_SINGLE,
            calldata_uniswap_exact_output(sender_sentinel),
        ),
    ] {
        assert!(matches!(
            render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 sender unbound"
            ))
        ));

        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render sentinel {signature}: {error:?}"));
        assert_full_address_field_page(&rendered.pages, "Beneficiary", &signer);
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "sentinel render receipt must bind every page for {signature}"
        );

        let mutated = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            None,
            &resolver,
            &mutated_signer,
        )
        .unwrap_or_else(|error| panic!("render mutated signer {signature}: {error:?}"));
        assert_full_address_field_page(&mutated.pages, "Beneficiary", &mutated_signer);
        assert_ne!(rendered.pages.as_slice(), mutated.pages.as_slice());
        assert!(
            !rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "signer mutation must change the trusted transcript for {signature}"
        );
    }
}

#[test]
fn production_uniswap_router02_semantic_guards_and_static_framing_fail_closed() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let render = |envelope: &Eip1559Tx, calldata: &[u8]| {
        render_erc7730_pages_with_signer_checked(
            envelope, calldata, &verified, None, &resolver, &signer,
        )
    };

    let mut sender_two = [0u8; 20];
    sender_two[19] = 2;
    for calldata in [
        calldata_uniswap_exact_input(sender_two),
        calldata_uniswap_exact_output(sender_two),
    ] {
        assert!(render(&tx, &calldata).is_err(), "address(2) must refuse");
    }

    let zero_exact_input =
        calldata_uniswap_single(UNI_EXACT_INPUT_SINGLE, recipient, 0, 1_000_000, 0);
    assert!(
        render(&tx, &zero_exact_input).is_err(),
        "zero exactInput amount must refuse"
    );

    for (signature, baseline) in [
        (
            UNI_EXACT_INPUT_SINGLE,
            calldata_uniswap_exact_input(recipient),
        ),
        (
            UNI_EXACT_OUTPUT_SINGLE,
            calldata_uniswap_exact_output(recipient),
        ),
    ] {
        let mut nonzero_price = baseline.clone();
        nonzero_price[4 + 6 * 32 + 31] = 1;
        assert!(
            render(&tx, &nonzero_price).is_err(),
            "nonzero price limit must refuse {signature}"
        );

        let mut funded = envelope(1, UNI_V3);
        funded.value = u256_from_u64(1);
        assert!(
            render(&funded, &baseline).is_err(),
            "nonzero outer value must refuse {signature}"
        );

        let mut short = baseline.clone();
        short.pop();
        assert!(
            render(&tx, &short).is_err(),
            "short static tuple must refuse {signature}"
        );
        let mut trailing = baseline.clone();
        trailing.push(0);
        assert!(
            render(&tx, &trailing).is_err(),
            "trailing static data must refuse {signature}"
        );

        for (word, label) in [
            (0usize, "dirty tokenIn address"),
            (2usize, "dirty uint24 fee"),
            (3usize, "dirty recipient address"),
            (6usize, "dirty uint160 price"),
        ] {
            let mut dirty = baseline.clone();
            dirty[4 + word * 32] = 1;
            assert!(
                render(&tx, &dirty).is_err(),
                "{label} must refuse {signature}"
            );
        }
    }
}

#[test]
fn production_uniswap_router02_tuple_and_value_mutations_change_transcript_or_refuse() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];

    for (signature, baseline) in [
        (
            UNI_EXACT_INPUT_SINGLE,
            calldata_uniswap_exact_input(recipient),
        ),
        (
            UNI_EXACT_OUTPUT_SINGLE,
            calldata_uniswap_exact_output(recipient),
        ),
    ] {
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &baseline, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render baseline {signature}: {error:?}"));

        for word in 0..7usize {
            let mut mutated_calldata = baseline.clone();
            mutated_calldata[4 + word * 32 + 31] ^= 1;
            match render_erc7730_pages_with_signer_checked(
                &tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            ) {
                Ok(mutated) => {
                    assert_ne!(
                        rendered.pages.as_slice(),
                        mutated.pages.as_slice(),
                        "tuple word {word} mutation must change pages for {signature}"
                    );
                    assert!(
                        !rendered
                            .transcript_receipt
                            .exact_match(&mutated.transcript_receipt),
                        "tuple word {word} mutation must change receipt for {signature}"
                    );
                }
                Err(_) => assert_eq!(
                    word, 6,
                    "only the guarded price word should reject a canonical low-byte mutation for {signature}"
                ),
            }
        }

        let mut funded = envelope(1, UNI_V3);
        funded.value = u256_from_u64(1);
        assert!(
            render_erc7730_pages_with_signer_checked(
                &funded, &baseline, &verified, None, &resolver, &signer,
            )
            .is_err(),
            "outer value mutation must refuse {signature}"
        );
    }
}

fn safe_uniswap_route_fixture() -> &'static dbgen::erc7730::Emitted {
    static FIXTURE: std::sync::OnceLock<dbgen::erc7730::Emitted> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let temp_root = std::env::temp_dir().join(format!(
            "pqsigner-erc7730-safe-uniswap-route-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).expect("create safe route fixture dir");
        let source = temp_root.join("safe-uniswap-route.json");
        std::fs::write(
            &source,
            r#"{
              "context": { "contract": { "deployments": [
                { "chainId": 1, "address": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45" }
              ] } },
              "metadata": { "owner": "Test", "contractName": "Safe Route" },
              "display": { "formats": {
                "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to)": {
                  "intent": "Swap",
                  "fields": [
                    { "path": "amountIn", "label": "Amount to Send", "format": "tokenAmount",
                      "params": { "tokenPath": "path.[0]" }, "visible": "always" },
                    { "path": "amountOutMin", "label": "Minimum Receive", "format": "tokenAmount",
                      "params": { "tokenPath": "path.[-1]" }, "visible": "always" },
                    { "path": "path.[]", "label": "Route", "format": "addressName", "visible": "always" },
                    { "path": "to", "label": "Beneficiary", "format": "addressName", "visible": "always" }
                  ]
                }
              } }
            }"#,
        )
        .expect("write safe route fixture");
        let emitted = dbgen::erc7730::try_compile_one(
            &source,
            &dbgen::erc7730::Policy::default(),
            Some(&temp_root),
        )
        .expect("whole-route fixture must compile")
        .into_iter()
        .find(|entry| entry.chain_id == 1)
        .expect("safe route fixture emits mainnet leaf");
        let _ = std::fs::remove_dir_all(&temp_root);
        emitted
    })
}

fn meta(contract: [u8; 20], decimals: u8, symbol: &'static [u8]) -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: 1,
        contract,
        decimals,
        name: symbol,
        symbol,
    }
}

/// `swap*ForTokens(uint256 a0, uint256 a1, address[] path, address to)`
/// (same layout for `swapExactTokensForTokens` / `swapTokensForExactTokens`).
fn calldata_v2_swap(
    selector: [u8; 4],
    a0: U256,
    a1: U256,
    path: &[[u8; 20]],
    to: [u8; 20],
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&selector);
    d.extend_from_slice(&a0.0);
    d.extend_from_slice(&a1.0);
    d.extend_from_slice(&u256_from_u64(128).0); // offset to path array (4-word head)
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(&to);
    d.extend_from_slice(&t);
    d.extend_from_slice(&u256_from_u64(path.len() as u64).0); // element count
    for a in path {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        d.extend_from_slice(&w);
    }
    d
}

fn uniswap_v2_swap_calldata(
    signature: &str,
    first_amount: u64,
    second_amount: u64,
    path: &[[u8; 20]],
    recipient: [u8; 20],
) -> Vec<u8> {
    let digest = keccak256(signature.as_bytes());
    let selector: [u8; 4] = digest[..4].try_into().expect("selector width");
    calldata_v2_swap(
        selector,
        u256_from_u64(first_amount),
        u256_from_u64(second_amount),
        path,
        recipient,
    )
}

fn assert_complete_route_pages(pages: &Pages, path: &[[u8; 20]]) {
    let route_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Route")
        .collect::<Vec<_>>();
    assert_eq!(
        route_pages.len(),
        path.len() + 1,
        "route must show one count page and every signed address:\n{}",
        dump_pages(pages)
    );
    assert!(
        page_strs(pages, find_page_by_label(pages, "Route"))
            .iter()
            .any(|row| row.contains(&format!("{} items", path.len()))),
        "route count must be explicit:\n{}",
        dump_pages(pages)
    );

    for (index, address) in path.iter().enumerate() {
        let mut expected = [[b' '; DISPLAY_COLS]; 4];
        expected[0][..5].copy_from_slice(b"Route");
        let [_, r1, r2, r3] = &mut expected;
        write_addr_full(r1, r2, r3, address);
        assert_eq!(
            *route_pages[index + 1],
            expected,
            "route element {index} must show all 20 signed address bytes"
        );
    }
}

#[test]
fn production_uniswap_router02_multihop_renders_every_operand_and_binds_transcript() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];

    for (signature, first_label, second_label) in [
        (UNI_SWAP_EXACT_TOKENS, "Swap input", "Minimum receive"),
        (
            UNI_SWAP_TOKENS_FOR_EXACT,
            "Amount to recei~",
            "Max swap input",
        ),
    ] {
        let calldata = uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &path, recipient);
        assert_selector_matches(&verified.ir, &calldata, signature);
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render production {signature}: {error:?}"));
        assert_all_pages_printable(&rendered.pages);
        assert!(
            rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0),
            "receipt must bind the complete production transcript for {signature}"
        );
        let _ = find_page_by_label(&rendered.pages, first_label);
        let _ = find_page_by_label(&rendered.pages, second_label);
        assert_complete_route_pages(&rendered.pages, &path);
        assert_full_address_field_page(&rendered.pages, "Beneficiary", &recipient);
        let native_value = page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Native value"),
        );
        assert!(
            native_value.iter().any(|row| row.contains('0')),
            "the exact guarded zero outer value must be visible: {native_value:?}"
        );

        let mut scalar_offsets = vec![
            (4 + 31, "first amount"),
            (4 + 32 + 31, "second amount"),
            (4 + 3 * 32 + 31, "beneficiary"),
        ];
        let route_start = 4 + 4 * 32 + 32;
        for index in 0..path.len() {
            scalar_offsets.push((route_start + index * 32 + 31, "route element"));
        }
        for (offset, label) in scalar_offsets {
            let mut mutated_calldata = calldata.clone();
            mutated_calldata[offset] ^= 1;
            let mutated = render_erc7730_pages_with_signer_checked(
                &tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| {
                panic!("canonical {label} mutation must render for {signature}: {error:?}")
            });
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "{label} mutation must change trusted pages for {signature}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "{label} mutation must change the receipt for {signature}"
            );
        }

        let mut funded = envelope(1, UNI_V3);
        funded.value = u256_from_u64(1);
        assert!(
            render_erc7730_pages_with_signer_checked(
                &funded, &calldata, &verified, None, &resolver, &signer,
            )
            .is_err(),
            "nonzero outer value must refuse {signature}"
        );
    }
}

#[test]
fn production_uniswap_router02_multihop_sender_and_amount_guards_fail_closed() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let signer = [0x44; 20];
    let mut mutated_signer = signer;
    mutated_signer[19] ^= 1;
    let mut address_one = [0u8; 20];
    address_one[19] = 1;
    let mut address_two = [0u8; 20];
    address_two[19] = 2;

    for signature in [UNI_SWAP_EXACT_TOKENS, UNI_SWAP_TOKENS_FOR_EXACT] {
        let sentinel =
            uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &path, address_one);
        assert!(matches!(
            render_erc7730_pages(&tx, &sentinel, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::Reject(
                "7730 sender unbound"
            ))
        ));
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &sentinel, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render sender sentinel {signature}: {error:?}"));
        assert_full_address_field_page(&rendered.pages, "Beneficiary", &signer);
        let mutated = render_erc7730_pages_with_signer_checked(
            &tx,
            &sentinel,
            &verified,
            None,
            &resolver,
            &mutated_signer,
        )
        .unwrap_or_else(|error| panic!("render mutated signer {signature}: {error:?}"));
        assert_full_address_field_page(&mutated.pages, "Beneficiary", &mutated_signer);
        assert_ne!(rendered.pages.as_slice(), mutated.pages.as_slice());
        assert!(!rendered
            .transcript_receipt
            .exact_match(&mutated.transcript_receipt));

        let forbidden =
            uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &path, address_two);
        assert!(
            render_erc7730_pages_with_signer_checked(
                &tx, &forbidden, &verified, None, &resolver, &signer,
            )
            .is_err(),
            "address(2) must refuse {signature}"
        );
    }

    let zero_input =
        uniswap_v2_swap_calldata(UNI_SWAP_EXACT_TOKENS, 0, 1_000_000, &path, [0x33; 20]);
    assert!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &zero_input,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .is_err(),
        "exact-input amountIn=0 must refuse"
    );
}

#[test]
fn production_uniswap_router02_multihop_rejects_noncanonical_array_framing() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let render = |calldata: &[u8]| {
        render_erc7730_pages_with_signer_checked(&tx, calldata, &verified, None, &resolver, &signer)
    };

    for signature in [UNI_SWAP_EXACT_TOKENS, UNI_SWAP_TOKENS_FOR_EXACT] {
        let baseline = uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &path, [0x33; 20]);
        assert!(
            render(&baseline).is_ok(),
            "canonical {signature} must render"
        );

        let mut dirty_recipient = baseline.clone();
        dirty_recipient[4 + 3 * 32] = 1;
        assert!(
            render(&dirty_recipient).is_err(),
            "dirty recipient must refuse"
        );
        for index in 0..path.len() {
            let mut dirty_path = baseline.clone();
            dirty_path[4 + 4 * 32 + 32 + index * 32] = 1;
            assert!(
                render(&dirty_path).is_err(),
                "dirty route address {index} must refuse {signature}"
            );
        }

        let mut high_offset = baseline.clone();
        high_offset[4 + 2 * 32] = 1;
        assert!(render(&high_offset).is_err(), "huge offset must refuse");
        let mut gapped_offset = baseline.clone();
        gapped_offset[4 + 2 * 32 + 31] = 160;
        assert!(
            render(&gapped_offset).is_err(),
            "non-head-end offset must refuse"
        );

        let count_offset = 4 + 4 * 32;
        let mut high_count = baseline.clone();
        high_count[count_offset] = 1;
        assert!(render(&high_count).is_err(), "huge count must refuse");
        for bad_count in [0u8, 2, 4] {
            let mut malformed = baseline.clone();
            malformed[count_offset + 31] = bad_count;
            assert!(
                render(&malformed).is_err(),
                "noncanonical count {bad_count} must refuse {signature}"
            );
        }

        let mut trailing = baseline.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert!(render(&trailing).is_err(), "trailing word must refuse");
        let mut short = baseline.clone();
        short.pop();
        assert!(render(&short).is_err(), "short tail must refuse");
        assert!(
            render(&baseline[..4 + 4 * 32 - 1]).is_err(),
            "short head must refuse"
        );

        let eight = [[0x77; 20]; 8];
        let at_cap = uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &eight, [0x33; 20]);
        let at_cap_rendered = render(&at_cap)
            .unwrap_or_else(|error| panic!("eight route elements must render: {error:?}"));
        assert_complete_route_pages(&at_cap_rendered.pages, &eight);

        let nine = [[0x77; 20]; 9];
        let over_budget =
            uniswap_v2_swap_calldata(signature, 1_500_000, 1_000_000, &nine, [0x33; 20]);
        assert!(
            render(&over_budget).is_err(),
            "nine route elements exceed the human-review budget"
        );
    }
}

fn render_safe_uni_result(
    calldata: &[u8],
    token: Option<&Erc20Metadata<'_>>,
) -> Result<Pages, crate::tx::erc7730_render::RenderErr> {
    let entry = safe_uniswap_route_fixture();
    let verified = VerifiedDescriptor {
        ir: Erc7730Ir::parse(&entry.ir_bytes).expect("safe route IR parses"),
    };
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    render_erc7730_pages(&tx, calldata, &verified, token, &resolver)
}

fn render_safe_uni(calldata: &[u8], token: Option<&Erc20Metadata<'_>>) -> Pages {
    render_safe_uni_result(calldata, token).expect("render safe route")
}

#[test]
fn synthetic_uniswap_v2_swap_binds_first_and_last_array_element() {
    // 3-hop path so `[-1]` genuinely selects the LAST element, not index 1.
    // Unlike upstream, the synthetic descriptor also renders `path.[]`.
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let cd_in = calldata_v2_swap(
        [0x47, 0x2b, 0x43, 0xf3],
        u256_from_u64(1_500_000),
        u256_from_u64(1),
        &path,
        [0x33; 20],
    );
    let fixture_ir = Erc7730Ir::parse(&safe_uniswap_route_fixture().ir_bytes).unwrap();
    let selector: [u8; 4] = cd_in[..4].try_into().unwrap();
    let fmt = fixture_ir
        .find_format_by_selector(&selector)
        .unwrap()
        .unwrap();
    for field in fmt.fields() {
        let field = field.unwrap();
        let params = pqsigner_erc7730::render::params::parse(&fixture_ir, field.param_off).unwrap();
        let Some(token_path) = params.token_path else {
            continue;
        };
        let resolved =
            pqsigner_erc7730::render::resolve::resolve_token_address(&token_path[1..], &cd_in[4..])
                .unwrap();
        if field.label == b"Amount to Send" {
            assert_eq!(resolved, TOKEN_IN);
        } else if field.label == b"Minimum Receive" {
            assert_eq!(resolved, TOKEN_OUT);
        }
    }
    let ma = meta(TOKEN_IN, 6, b"TKA");
    let pages = render_safe_uni(&cd_in, Some(&ma));
    let p = find_page_by_label(&pages, "Amount to Send");
    let rows = page_strs(&pages, p);
    assert!(
        rows.iter().any(|r| r.contains("TKA")),
        "path.[0] must bind the first element → TKA: {rows:?}"
    );

    let route_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Route")
        .count();
    assert_eq!(
        route_pages, 4,
        "whole-route display must include one count page plus all three elements"
    );
}

// ───────────────────────────────────────────────────────────────────────
// QuickSwap V2 Router02 — six complete standard swaps, all three
// fee-on-transfer swaps, and the five previously admitted static liquidity
// routes. LP-token metadata is derived rather than signed, so the exact
// liquidity word is deliberately rendered raw. Permit routes and every other
// omitted route remain known hard refusals.
// ───────────────────────────────────────────────────────────────────────
const QUICKSWAP_ROUTER: [u8; 20] = [
    0xa5, 0xe0, 0x82, 0x9c, 0xac, 0xed, 0x8f, 0xfd, 0xd4, 0xde, 0x3c, 0x43, 0x69, 0x6c, 0x57, 0xf7,
    0xd7, 0xa6, 0x78, 0xff,
];
const QUICKSWAP_ADD: &str =
    "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)";
const QUICKSWAP_ADD_NATIVE: &str =
    "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)";
const QUICKSWAP_REMOVE: &str =
    "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)";
const QUICKSWAP_REMOVE_NATIVE: &str =
    "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)";
const QUICKSWAP_REMOVE_NATIVE_FOT: &str =
    "removeLiquidityETHSupportingFeeOnTransferTokens(address,uint256,uint256,uint256,address,uint256)";
const QUICKSWAP_SWAP_EXACT_TOKENS: &str =
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_TOKENS_FOR_EXACT: &str =
    "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE: &str =
    "swapExactTokensForETH(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS: &str =
    "swapExactETHForTokens(uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE: &str =
    "swapTokensForExactETH(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_EXACT_TOKENS_FOT: &str =
    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_EXACT_NATIVE_FOT: &str =
    "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT: &str =
    "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)";
const QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS: &str =
    "swapETHForExactTokens(uint256,address[],address,uint256)";
const QUICKSWAP_WMATIC: [u8; 20] = [
    0x0d, 0x50, 0x0b, 0x1d, 0x8e, 0x8e, 0xf3, 0x1e, 0x21, 0xc9, 0x9d, 0x1d, 0xb9, 0xa6, 0x44, 0x4d,
    0x3a, 0xdf, 0x12, 0x70,
];

fn quickswap_liquidity_word() -> [u8; 32] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]
}

fn quickswap_add_calldata(
    token_a: [u8; 20],
    token_b: [u8; 20],
    amount_a_desired: U256,
    amount_b_desired: U256,
    amount_a_min: U256,
    amount_b_min: U256,
    recipient: [u8; 20],
    deadline: U256,
) -> Vec<u8> {
    calldata_static(
        QUICKSWAP_ADD,
        &[
            abi_address_word(token_a),
            abi_address_word(token_b),
            amount_a_desired.0,
            amount_b_desired.0,
            amount_a_min.0,
            amount_b_min.0,
            abi_address_word(recipient),
            deadline.0,
        ],
    )
}

fn quickswap_add_native_calldata(
    token: [u8; 20],
    amount_token_desired: U256,
    amount_token_min: U256,
    amount_native_min: U256,
    recipient: [u8; 20],
    deadline: U256,
) -> Vec<u8> {
    calldata_static(
        QUICKSWAP_ADD_NATIVE,
        &[
            abi_address_word(token),
            amount_token_desired.0,
            amount_token_min.0,
            amount_native_min.0,
            abi_address_word(recipient),
            deadline.0,
        ],
    )
}

fn quickswap_remove_calldata(signature: &str) -> Vec<u8> {
    let token_a = [0x11; 20];
    let token_b = [0x22; 20];
    let beneficiary = [0x33; 20];
    let liquidity = quickswap_liquidity_word();
    match signature {
        QUICKSWAP_REMOVE => calldata_static(
            signature,
            &[
                abi_address_word(token_a),
                abi_address_word(token_b),
                liquidity,
                u256_from_u64(1_234_567).0,
                u256_from_u64(7_654_321).0,
                abi_address_word(beneficiary),
                u256_from_u64(2_000_000_000).0,
            ],
        ),
        QUICKSWAP_REMOVE_NATIVE | QUICKSWAP_REMOVE_NATIVE_FOT => calldata_static(
            signature,
            &[
                abi_address_word(token_a),
                liquidity,
                u256_from_u64(1_234_567).0,
                u256_from_u64(1_000_000_000_000_000_000).0,
                abi_address_word(beneficiary),
                u256_from_u64(2_000_000_000).0,
            ],
        ),
        _ => panic!("unsupported QuickSwap test route: {signature}"),
    }
}

fn quickswap_swap_calldata(
    signature: &str,
    first_amount: U256,
    second_amount: U256,
    path: &[[u8; 20]],
    beneficiary: [u8; 20],
    deadline: U256,
) -> Vec<u8> {
    let selector = keccak256(signature.as_bytes());
    let native_input = matches!(
        signature,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
    );
    assert!(
        native_input
            || matches!(
                signature,
                QUICKSWAP_SWAP_EXACT_TOKENS
                    | QUICKSWAP_SWAP_TOKENS_FOR_EXACT
                    | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE
                    | QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE
                    | QUICKSWAP_SWAP_EXACT_TOKENS_FOT
                    | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT
            ),
        "unsupported QuickSwap swap route: {signature}"
    );
    let head_words = if native_input { 4 } else { 5 };
    let mut calldata = Vec::with_capacity(4 + (head_words + 1 + path.len()) * 32);
    calldata.extend_from_slice(&selector[..4]);
    calldata.extend_from_slice(&first_amount.0);
    if !native_input {
        calldata.extend_from_slice(&second_amount.0);
    }
    calldata.extend_from_slice(&u256_from_u64((head_words * 32) as u64).0);
    calldata.extend_from_slice(&abi_address_word(beneficiary));
    calldata.extend_from_slice(&deadline.0);
    calldata.extend_from_slice(&u256_from_u64(path.len() as u64).0);
    for token in path {
        calldata.extend_from_slice(&abi_address_word(*token));
    }
    calldata
}

fn quickswap_meta(contract: [u8; 20], symbol: &'static [u8]) -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: 137,
        contract,
        decimals: 6,
        name: symbol,
        symbol,
    }
}

fn assert_some_page_shows_full_address(pages: &Pages, address: &[u8; 20]) {
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, address);
    assert!(
        pages.as_slice().iter().any(|page| page[1..4] == expected),
        "no page shows full address 0x{}\n{}",
        hex::encode(address),
        dump_pages(pages)
    );
}

fn quickswap_rows_with_label(pages: &Pages, label: &str) -> Vec<[String; 4]> {
    pages
        .as_slice()
        .iter()
        .enumerate()
        .filter(|(_, page)| row_str(&page[0]) == label)
        .map(|(index, _)| page_strs(pages, index))
        .collect()
}

#[test]
fn production_quickswap_admits_exactly_fourteen_bounded_routes_and_refuses_permits() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    assert_eq!(entry.contract, QUICKSWAP_ROUTER);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let ir = &verified.ir;

    let admitted_signatures = [
        QUICKSWAP_SWAP_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
        "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
        "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
        QUICKSWAP_REMOVE,
        QUICKSWAP_REMOVE_NATIVE,
        QUICKSWAP_REMOVE_NATIVE_FOT,
    ];
    let admitted: std::collections::BTreeSet<_> = ir
        .format_iter()
        .map(|format| format.expect("QuickSwap format parses").selector)
        .collect();
    let expected: std::collections::BTreeSet<[u8; 4]> = admitted_signatures
        .iter()
        .map(|signature| keccak256(signature.as_bytes())[..4].try_into().unwrap())
        .collect();
    assert_eq!(expected.len(), 14, "all admitted selectors must be unique");
    assert_eq!(admitted, expected);
    assert_eq!(
        &keccak256(QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS.as_bytes())[..4],
        &[0xfb, 0x3b, 0xdb, 0x41],
        "swapETHForExactTokens selector must stay pinned"
    );
    for (signature, selector) in [
        (QUICKSWAP_SWAP_EXACT_TOKENS_FOT, [0x5c, 0x11, 0xd7, 0x95]),
        (QUICKSWAP_SWAP_EXACT_NATIVE_FOT, [0xb6, 0xf9, 0xde, 0x95]),
        (
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
            [0x79, 0x1a, 0xc9, 0x47],
        ),
    ] {
        assert_eq!(
            &keccak256(signature.as_bytes())[..4],
            &selector,
            "fee-on-transfer selector must stay pinned for {signature}"
        );
        assert!(
            admitted.contains(&selector),
            "fee-on-transfer selector must be present in trusted IR: {signature}"
        );
    }

    for signature in [
        QUICKSWAP_REMOVE,
        QUICKSWAP_REMOVE_NATIVE,
        QUICKSWAP_REMOVE_NATIVE_FOT,
    ] {
        let calldata = quickswap_remove_calldata(signature);
        assert_selector_matches(ir, &calldata, signature);
    }

    let excluded = [
        "removeLiquidityWithPermit(address,address,uint256,uint256,uint256,address,uint256,bool,uint8,bytes32,bytes32)",
        "removeLiquidityETHWithPermit(address,uint256,uint256,uint256,address,uint256,bool,uint8,bytes32,bytes32)",
        "removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(address,uint256,uint256,uint256,address,uint256,bool,uint8,bytes32,bytes32)",
    ];
    let tx = envelope(137, QUICKSWAP_ROUTER);
    let resolver = NameResolver::new();
    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let digest = keccak256(signature.as_bytes());
        let selector: [u8; 4] = digest[..4].try_into().expect("selector width");
        assert!(
            registry
                .known_calls
                .contains(&(137, QUICKSWAP_ROUTER, selector)),
            "admitted FOT call must remain exactly known: {signature}"
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            137,
            &QUICKSWAP_ROUTER,
            &selector,
        ));
        let mut missing_descriptor_proofs = DispatchPageProofs::new();
        missing_descriptor_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &selector,
                &[0u8; 20],
                None,
                None,
                None,
                None,
                None,
                None,
                &resolver,
                &mut missing_descriptor_proofs,
            )
            .is_err(),
            "admitted FOT call must hard-refuse when its descriptor trailer is omitted: {signature}"
        );
    }
    for signature in excluded {
        assert_selector_excluded(ir, signature);
        let digest = keccak256(signature.as_bytes());
        let selector: [u8; 4] = digest[..4].try_into().expect("selector width");
        assert!(
            registry
                .known_calls
                .contains(&(137, QUICKSWAP_ROUTER, selector)),
            "excluded QuickSwap call must remain exactly known: {signature}"
        );
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &registry.known_calls_bloom,
            137,
            &QUICKSWAP_ROUTER,
            &selector,
        ));
        let calldata = selector.to_vec();
        assert!(matches!(
            render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
            Err(crate::tx::erc7730_render::RenderErr::NoFormat)
        ));

        let mut dispatch_proofs = DispatchPageProofs::new();
        dispatch_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &calldata,
                &[0u8; 20],
                None,
                None,
                None,
                Some(&verified),
                None,
                None,
                &resolver,
                &mut dispatch_proofs,
            )
            .is_err(),
            "known excluded QuickSwap call must not fall back: {signature}"
        );

        let mut missing_descriptor_proofs = DispatchPageProofs::new();
        missing_descriptor_proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &calldata,
                &[0u8; 20],
                None,
                None,
                None,
                None,
                None,
                None,
                &resolver,
                &mut missing_descriptor_proofs,
            )
            .is_err(),
            "known excluded QuickSwap call must hard-refuse when the descriptor trailer is omitted: {signature}"
        );
    }
}

#[test]
fn production_quickswap_add_liquidity_renders_exact_bounds_and_token_bindings() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let tx = envelope(137, QUICKSWAP_ROUTER);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let calldata = quickswap_add_calldata(
        TOKEN_IN,
        TOKEN_OUT,
        u256_from_u64(1_500_000),
        u256_from_u64(2_500_000),
        u256_from_u64(1_000_000),
        u256_from_u64(2_000_000),
        recipient,
        deadline,
    );
    assert_selector_matches(&verified.ir, &calldata, QUICKSWAP_ADD);

    let token_a = quickswap_meta(TOKEN_IN, b"TKA");
    let rendered_a = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&token_a),
        &resolver,
        &signer,
    )
    .expect("render QuickSwap addLiquidity with token-A metadata");
    assert_eq!(
        rendered_a.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(
        rendered_a
            .transcript_receipt
            .range_matches(&rendered_a.pages, 0),
        "receipt must bind the complete addLiquidity transcript"
    );
    assert_all_pages_printable(&rendered_a.pages);
    assert_eq!(
        page_strs(&rendered_a.pages, intent_page_index(&rendered_a.pages)),
        [
            "Add Liquidity".to_string(),
            "QuickSwap".to_string(),
            "QuickSwap".to_string(),
            "> next".to_string(),
        ]
    );
    assert_eq!(
        quickswap_rows_with_label(&rendered_a.pages, "Maximum to Add"),
        vec![
            [
                "Maximum to Add".to_string(),
                "1.5 TKA".to_string(),
                String::new(),
                "> next".to_string(),
            ],
            [
                "Maximum to Add".to_string(),
                "2500000".to_string(),
                String::new(),
                "! raw, dec=?".to_string(),
            ],
        ]
    );
    assert_eq!(
        quickswap_rows_with_label(&rendered_a.pages, "Conditional Min"),
        vec![
            [
                "Conditional Min".to_string(),
                "1 TKA".to_string(),
                String::new(),
                "> next".to_string(),
            ],
            [
                "Conditional Min".to_string(),
                "2000000".to_string(),
                String::new(),
                "! raw, dec=?".to_string(),
            ],
        ]
    );
    assert_full_contract_identity_page(&rendered_a.pages, &TOKEN_IN);
    assert_some_full_unverified_token_identity_page(&rendered_a.pages, &TOKEN_OUT);
    assert_full_address_field_page(&rendered_a.pages, "LP Recipient", &recipient);
    assert_eq!(
        page_strs(
            &rendered_a.pages,
            find_page_by_label(&rendered_a.pages, "Deadline"),
        ),
        [
            "Deadline".to_string(),
            "2033-05-18".to_string(),
            "03:33:20 UTC".to_string(),
            "> next".to_string(),
        ]
    );

    // A single metadata proof must bind only its exact chain+contract. Swap
    // the proof to token B and require the scaling/identity pages to swap too;
    // a shared ticker is never allowed to relabel both signed token operands.
    let token_b = quickswap_meta(TOKEN_OUT, b"TKB");
    let rendered_b = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&token_b),
        &resolver,
        &signer,
    )
    .expect("render QuickSwap addLiquidity with token-B metadata");
    assert_eq!(
        quickswap_rows_with_label(&rendered_b.pages, "Maximum to Add"),
        vec![
            [
                "Maximum to Add".to_string(),
                "1500000".to_string(),
                String::new(),
                "! raw, dec=?".to_string(),
            ],
            [
                "Maximum to Add".to_string(),
                "2.5 TKB".to_string(),
                String::new(),
                "> next".to_string(),
            ],
        ]
    );
    assert_eq!(
        quickswap_rows_with_label(&rendered_b.pages, "Conditional Min"),
        vec![
            [
                "Conditional Min".to_string(),
                "1000000".to_string(),
                String::new(),
                "! raw, dec=?".to_string(),
            ],
            [
                "Conditional Min".to_string(),
                "2 TKB".to_string(),
                String::new(),
                "> next".to_string(),
            ],
        ]
    );
    assert_full_contract_identity_page(&rendered_b.pages, &TOKEN_OUT);
    assert_some_full_unverified_token_identity_page(&rendered_b.pages, &TOKEN_IN);
    assert!(
        rendered_b
            .transcript_receipt
            .range_matches(&rendered_b.pages, 0),
        "metadata choice must still produce a fully bound transcript"
    );
    assert!(
        !rendered_a
            .transcript_receipt
            .exact_match(&rendered_b.transcript_receipt),
        "independent token bindings must produce distinct trusted transcripts"
    );
}

#[test]
fn production_quickswap_add_liquidity_native_renders_refundable_maximum_exactly() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let calldata = quickswap_add_native_calldata(
        TOKEN_IN,
        u256_from_u64(1_500_000),
        u256_from_u64(1_000_000),
        u256_from_u64(1_000_000_000_000_000_000),
        recipient,
        deadline,
    );
    assert_selector_matches(&verified.ir, &calldata, QUICKSWAP_ADD_NATIVE);
    let mut tx = envelope(137, QUICKSWAP_ROUTER);
    tx.value = u256_from_u64(2_000_000_000_000_000_000);
    let token = quickswap_meta(TOKEN_IN, b"TKN");

    let rendered = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&token),
        &resolver,
        &signer,
    )
    .expect("render QuickSwap addLiquidityETH");
    assert_eq!(
        rendered.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(rendered
        .transcript_receipt
        .range_matches(&rendered.pages, 0));
    assert_all_pages_printable(&rendered.pages);
    assert_eq!(
        page_strs(&rendered.pages, intent_page_index(&rendered.pages)),
        [
            "Add Liquidity".to_string(),
            "QuickSwap".to_string(),
            "QuickSwap".to_string(),
            "> next".to_string(),
        ]
    );
    assert_eq!(
        quickswap_rows_with_label(&rendered.pages, "Maximum to Add"),
        vec![
            [
                "Maximum to Add".to_string(),
                "2 POL".to_string(),
                String::new(),
                "> next".to_string(),
            ],
            [
                "Maximum to Add".to_string(),
                "1.5 TKN".to_string(),
                String::new(),
                "> next".to_string(),
            ],
        ],
        "msg.value is the refundable native maximum, not an exact deposit claim"
    );
    assert_eq!(
        quickswap_rows_with_label(&rendered.pages, "Conditional Min"),
        vec![
            [
                "Conditional Min".to_string(),
                "1 TKN".to_string(),
                String::new(),
                "> next".to_string(),
            ],
            [
                "Conditional Min".to_string(),
                "1 POL".to_string(),
                String::new(),
                "> next".to_string(),
            ],
        ]
    );
    assert_full_contract_identity_page(&rendered.pages, &TOKEN_IN);
    assert_full_address_field_page(&rendered.pages, "LP Recipient", &recipient);
    assert_eq!(
        page_strs(
            &rendered.pages,
            find_page_by_label(&rendered.pages, "Deadline"),
        ),
        [
            "Deadline".to_string(),
            "2033-05-18".to_string(),
            "03:33:20 UTC".to_string(),
            "> next".to_string(),
        ]
    );
}

#[test]
fn production_quickswap_add_liquidity_mutations_change_transcript_exactly() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let recipient = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let add_calldata = quickswap_add_calldata(
        TOKEN_IN,
        TOKEN_OUT,
        u256_from_u64(1_500_000),
        u256_from_u64(2_500_000),
        u256_from_u64(1_000_000),
        u256_from_u64(2_000_000),
        recipient,
        deadline,
    );
    let add_native_calldata = quickswap_add_native_calldata(
        TOKEN_IN,
        u256_from_u64(1_500_000),
        u256_from_u64(1_000_000),
        u256_from_u64(1_000_000_000_000_000_000),
        recipient,
        deadline,
    );
    let add_tx = envelope(137, QUICKSWAP_ROUTER);
    let mut add_native_tx = envelope(137, QUICKSWAP_ROUTER);
    add_native_tx.value = u256_from_u64(2_000_000_000_000_000_000);

    for (signature, calldata, tx, word_count) in [
        (QUICKSWAP_ADD, add_calldata, &add_tx, 8usize),
        (
            QUICKSWAP_ADD_NATIVE,
            add_native_calldata.clone(),
            &add_native_tx,
            6usize,
        ),
    ] {
        let baseline = render_erc7730_pages_with_signer_checked(
            tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render canonical {signature}: {error:?}"));
        assert!(baseline
            .transcript_receipt
            .range_matches(&baseline.pages, 0));

        for word_index in 0..word_count {
            let mut mutated_calldata = calldata.clone();
            mutated_calldata[4 + word_index * 32 + 31] ^= 1;
            let mutated = render_erc7730_pages_with_signer_checked(
                tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| {
                panic!("exact mutation refused for {signature} word {word_index}: {error:?}")
            });
            assert_ne!(
                baseline.pages.as_slice(),
                mutated.pages.as_slice(),
                "calldata word {word_index} must change trusted pages for {signature}"
            );
            assert!(
                !baseline
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "calldata word {word_index} must change the receipt for {signature}"
            );
        }
    }

    let baseline = render_erc7730_pages_with_signer_checked(
        &add_native_tx,
        &add_native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render canonical addLiquidityETH value");
    let mut changed_value_tx = envelope(137, QUICKSWAP_ROUTER);
    changed_value_tx.value = u256_from_u64(3_000_000_000_000_000_000);
    let changed_value = render_erc7730_pages_with_signer_checked(
        &changed_value_tx,
        &add_native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render changed exact addLiquidityETH maximum");
    assert_ne!(baseline.pages.as_slice(), changed_value.pages.as_slice());
    assert!(!baseline
        .transcript_receipt
        .exact_match(&changed_value.transcript_receipt));

    let mut adjacent_value_tx = envelope(137, QUICKSWAP_ROUTER);
    adjacent_value_tx.value = u256_from_u64(2_000_000_000_000_000_001);
    let adjacent_value = render_erc7730_pages_with_signer_checked(
        &adjacent_value_tx,
        &add_native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("2 POL plus one wei renders exactly");
    let maximum_rows = quickswap_rows_with_label(&adjacent_value.pages, "Maximum to Add");
    assert_eq!(maximum_rows[0][1], "2.00000000000000");
    assert_eq!(maximum_rows[0][2], "0001 POL");
    assert_ne!(baseline.pages.as_slice(), adjacent_value.pages.as_slice());
    assert!(!baseline
        .transcript_receipt
        .exact_match(&adjacent_value.transcript_receipt));
}

#[test]
fn production_quickswap_nonpayable_add_liquidity_shows_nonzero_outer_value() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let calldata = quickswap_add_calldata(
        TOKEN_IN,
        TOKEN_OUT,
        u256_from_u64(1_500_000),
        u256_from_u64(2_500_000),
        u256_from_u64(1_000_000),
        u256_from_u64(2_000_000),
        [0x33; 20],
        u256_from_u64(2_000_000_000),
    );
    let mut tx = envelope(137, QUICKSWAP_ROUTER);
    tx.value = u256_from_u64(1_000_000_000_000_000_000);
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let pages = pick_sign_pages(
        &tx,
        &calldata,
        &signer,
        None,
        None,
        None,
        Some(&verified),
        None,
        None,
        &resolver,
        &mut proofs,
    )
    .expect("nonpayable addLiquidity must display outer value before contract revert");
    assert_eq!(
        page_strs(&pages, find_page_by_label(&pages, "! NATIVE POL")),
        [
            "! NATIVE POL".to_string(),
            "1.000000 POL".to_string(),
            String::new(),
            "> next".to_string(),
        ]
    );
    let mut verdict = crate::fi::FAIL_SENTINEL;
    proofs.final_set_proof(&pages, &tx, false, &mut verdict);
    assert_eq!(
        verdict,
        crate::fi::OK_SENTINEL,
        "dispatcher proof must bind the loud nonpayable outer-value page"
    );
}

#[test]
fn production_quickswap_token_multihop_renders_full_routes_and_exact_operands() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let tx = envelope(137, QUICKSWAP_ROUTER);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let beneficiary = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let route_two = [TOKEN_IN, TOKEN_OUT];
    let route_three = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let route_eight = [
        TOKEN_IN, [0x31; 20], [0x32; 20], [0x33; 20], [0x34; 20], [0x35; 20], [0x36; 20], TOKEN_OUT,
    ];

    for (signature, first, second, first_label, second_label) in [
        (
            QUICKSWAP_SWAP_EXACT_TOKENS,
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
            "Amount to Send",
            "Minimum to Rece~",
        ),
        (
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
            u256_from_u64(1_000_000),
            u256_from_u64(1_500_000),
            "Amount to Recei~",
            "Maximum to Send",
        ),
        // A fee-on-transfer token can debit or deliver a different amount;
        // this word is only the router's signed transferFrom request.
        (
            QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
            "Requested Input",
            "Minimum to Rece~",
        ),
    ] {
        let exact_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_TOKENS | QUICKSWAP_SWAP_EXACT_TOKENS_FOT
        );
        for path in [
            route_two.as_slice(),
            route_three.as_slice(),
            route_eight.as_slice(),
        ] {
            let calldata =
                quickswap_swap_calldata(signature, first, second, path, beneficiary, deadline);
            assert_selector_matches(&verified.ir, &calldata, signature);
            let rendered = render_erc7730_pages_with_signer_checked(
                &tx, &calldata, &verified, None, &resolver, &signer,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "render QuickSwap {signature} with {} tokens: {error:?}",
                    path.len()
                )
            });
            assert_all_pages_printable(&rendered.pages);
            assert_complete_route_pages(&rendered.pages, path);
            assert_full_address_field_page(&rendered.pages, "Beneficiary", &beneficiary);
            let first_rows = page_strs(
                &rendered.pages,
                find_page_by_label(&rendered.pages, first_label),
            );
            let second_rows = page_strs(
                &rendered.pages,
                find_page_by_label(&rendered.pages, second_label),
            );
            assert!(
                first_rows[1..3]
                    .iter()
                    .any(|row| row.contains(if exact_input { "1500000" } else { "1000000" })),
                "first signed amount must render exactly without assumed decimals: {first_rows:?}"
            );
            assert!(
                second_rows[1..3].iter().any(|row| row.contains(
                    if exact_input {
                        "1000000"
                    } else {
                        "1500000"
                    }
                )),
                "second signed amount must render exactly without assumed decimals: {second_rows:?}"
            );
            assert_some_full_unverified_token_identity_page(&rendered.pages, &TOKEN_IN);
            assert_some_full_unverified_token_identity_page(&rendered.pages, &TOKEN_OUT);
            assert_eq!(
                page_strs(
                    &rendered.pages,
                    find_page_by_label(&rendered.pages, "Deadline"),
                ),
                [
                    "Deadline".to_string(),
                    "2033-05-18".to_string(),
                    "03:33:20 UTC".to_string(),
                    "> next".to_string(),
                ],
                "the exact signed deadline must be visible"
            );
            assert!(
                rendered
                    .transcript_receipt
                    .range_matches(&rendered.pages, 0),
                "receipt must bind every QuickSwap page for {signature}"
            );
        }

        // Bind the tokenAmount endpoint paths independently. Metadata for the
        // first route address may scale only the input/max-input field, while
        // metadata for the last address may scale only the output/min-output
        // field. This catches a path.[0] / path.[-1] swap in either selector.
        let calldata = quickswap_swap_calldata(
            signature,
            first,
            second,
            &route_three,
            beneficiary,
            deadline,
        );
        let input_meta = quickswap_meta(TOKEN_IN, b"TIN");
        let input_bound = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            Some(&input_meta),
            &resolver,
            &signer,
        )
        .expect("render QuickSwap input-token binding");
        let input_label = if exact_input {
            first_label
        } else {
            second_label
        };
        let output_label = if exact_input {
            second_label
        } else {
            first_label
        };
        let input_rows = page_strs(
            &input_bound.pages,
            find_page_by_label(&input_bound.pages, input_label),
        );
        assert_eq!(input_rows[1], "1.5 TIN", "input endpoint binding");
        assert_full_contract_identity_page(&input_bound.pages, &TOKEN_IN);
        let unbound_output_rows = page_strs(
            &input_bound.pages,
            find_page_by_label(&input_bound.pages, output_label),
        );
        assert!(
            unbound_output_rows[1..3]
                .iter()
                .any(|row| row.contains("1000000")),
            "input metadata must not scale the unbound output endpoint: {unbound_output_rows:?}"
        );
        assert_some_full_unverified_token_identity_page(&input_bound.pages, &TOKEN_OUT);

        let output_meta = quickswap_meta(TOKEN_OUT, b"TOUT");
        let output_bound = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            Some(&output_meta),
            &resolver,
            &signer,
        )
        .expect("render QuickSwap output-token binding");
        let output_rows = page_strs(
            &output_bound.pages,
            find_page_by_label(&output_bound.pages, output_label),
        );
        assert_eq!(output_rows[1], "1 TOUT", "output endpoint binding");
        assert_full_contract_identity_page(&output_bound.pages, &TOKEN_OUT);
        let unbound_input_rows = page_strs(
            &output_bound.pages,
            find_page_by_label(&output_bound.pages, input_label),
        );
        assert!(
            unbound_input_rows[1..3]
                .iter()
                .any(|row| row.contains("1500000")),
            "output metadata must not scale the unbound input endpoint: {unbound_input_rows:?}"
        );
        assert_some_full_unverified_token_identity_page(&output_bound.pages, &TOKEN_IN);
    }
}

#[test]
fn production_quickswap_native_swaps_render_full_routes_and_exact_operands() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let beneficiary = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let one_native = u256_from_u64(1_000_000_000_000_000_000);

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let route_two = if native_input {
            vec![QUICKSWAP_WMATIC, TOKEN_OUT]
        } else {
            vec![TOKEN_IN, QUICKSWAP_WMATIC]
        };
        let route_three = if native_input {
            vec![QUICKSWAP_WMATIC, TOKEN_MID, TOKEN_OUT]
        } else {
            vec![TOKEN_IN, TOKEN_MID, QUICKSWAP_WMATIC]
        };
        let route_eight = if native_input {
            vec![
                QUICKSWAP_WMATIC,
                [0x31; 20],
                [0x32; 20],
                [0x33; 20],
                [0x34; 20],
                [0x35; 20],
                [0x36; 20],
                TOKEN_OUT,
            ]
        } else {
            vec![
                TOKEN_IN,
                [0x31; 20],
                [0x32; 20],
                [0x33; 20],
                [0x34; 20],
                [0x35; 20],
                [0x36; 20],
                QUICKSWAP_WMATIC,
            ]
        };
        let (
            first,
            second,
            token_label,
            native_label,
            raw_token_amount,
            token_contract,
            token_symbol,
            bound_token_amount,
        ): (U256, U256, &str, &str, &str, [u8; 20], &[u8], &str) = match signature {
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE => (
                u256_from_u64(1_500_000),
                one_native,
                "Amount to Send",
                "Minimum to Rece~",
                "1500000",
                TOKEN_IN,
                b"TIN",
                "1.5 TIN",
            ),
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => (
                u256_from_u64(1_500_000),
                one_native,
                "Requested Input",
                "Minimum to Rece~",
                "1500000",
                TOKEN_IN,
                b"TIN",
                "1.5 TIN",
            ),
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => (
                u256_from_u64(1_000_000),
                U256::default(),
                "Minimum to Rece~",
                "Amount to Send",
                "1000000",
                TOKEN_OUT,
                b"TOUT",
                "1 TOUT",
            ),
            QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS => (
                u256_from_u64(1_000_000),
                U256::default(),
                "Gross Output",
                "Maximum to Send",
                "1000000",
                TOKEN_OUT,
                b"TOUT",
                "1 TOUT",
            ),
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                one_native,
                u256_from_u64(1_500_000),
                "Maximum to Send",
                "Amount to Recei~",
                "1500000",
                TOKEN_IN,
                b"TIN",
                "1.5 TIN",
            ),
            _ => unreachable!(),
        };
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = one_native;
        }

        for path in [&route_two[..], &route_three[..], &route_eight[..]] {
            let calldata =
                quickswap_swap_calldata(signature, first, second, path, beneficiary, deadline);
            assert_selector_matches(&verified.ir, &calldata, signature);
            let rendered = render_erc7730_pages_with_signer_checked(
                &tx, &calldata, &verified, None, &resolver, &signer,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "render QuickSwap {signature} with {} tokens: {error:?}",
                    path.len()
                )
            });
            assert_all_pages_printable(&rendered.pages);
            assert_complete_route_pages(&rendered.pages, path);
            assert_full_address_field_page(&rendered.pages, "Beneficiary", &beneficiary);
            let token_rows = page_strs(
                &rendered.pages,
                find_page_by_label(&rendered.pages, token_label),
            );
            assert!(
                token_rows[1..3]
                    .iter()
                    .any(|row| row.contains(raw_token_amount)),
                "the exact signed token amount must render without invented metadata: {token_rows:?}"
            );
            assert_full_unverified_token_identity_page(&rendered.pages, &token_contract);
            let native_rows = page_strs(
                &rendered.pages,
                find_page_by_label(&rendered.pages, native_label),
            );
            assert_eq!(
                native_rows[1], "1 POL",
                "the native side must use Polygon's authenticated ticker"
            );
            assert_eq!(
                page_strs(
                    &rendered.pages,
                    find_page_by_label(&rendered.pages, "Deadline"),
                ),
                [
                    "Deadline".to_string(),
                    "2033-05-18".to_string(),
                    "03:33:20 UTC".to_string(),
                    "> next".to_string(),
                ],
                "the exact signed deadline must be visible"
            );
            assert!(
                rendered
                    .transcript_receipt
                    .range_matches(&rendered.pages, 0),
                "receipt must bind every QuickSwap page for {signature}"
            );
        }

        let calldata = quickswap_swap_calldata(
            signature,
            first,
            second,
            &route_three,
            beneficiary,
            deadline,
        );
        let metadata = quickswap_meta(token_contract, token_symbol);
        let bound = render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata,
            &verified,
            Some(&metadata),
            &resolver,
            &signer,
        )
        .expect("render QuickSwap native-route token binding");
        let token_rows = page_strs(&bound.pages, find_page_by_label(&bound.pages, token_label));
        assert_eq!(token_rows[1], bound_token_amount);
        assert_full_contract_identity_page(&bound.pages, &token_contract);
    }
}

#[test]
fn production_quickswap_native_swap_mutations_change_transcript_exactly() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let beneficiary = [0x33; 20];
    let deadline = u256_from_u64(2_000_000_000);
    let one_native = u256_from_u64(1_000_000_000_000_000_000);

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let path = if native_input {
            [QUICKSWAP_WMATIC, TOKEN_MID, TOKEN_OUT]
        } else {
            [TOKEN_IN, TOKEN_MID, QUICKSWAP_WMATIC]
        };
        let (first, second, head_words, beneficiary_word, deadline_word) = match signature {
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (u256_from_u64(1_500_000), one_native, 5, 3, 4)
            }
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => {
                (u256_from_u64(1_000_000), U256::default(), 4, 2, 3)
            }
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => {
                (one_native, u256_from_u64(1_500_000), 5, 3, 4)
            }
            _ => unreachable!(),
        };
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = one_native;
        }
        let calldata =
            quickswap_swap_calldata(signature, first, second, &path, beneficiary, deadline);
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .expect("render canonical QuickSwap native swap");
        let mut offsets = vec![
            (4 + 31, "first amount"),
            (4 + beneficiary_word * 32 + 31, "beneficiary"),
            (4 + deadline_word * 32 + 31, "deadline"),
        ];
        if !native_input {
            offsets.push((4 + 32 + 31, "second amount"));
        }
        let path_start = 4 + head_words * 32 + 32;
        for index in 0..path.len() {
            offsets.push((path_start + index * 32 + 31, "route element"));
        }
        for (offset, operand) in offsets {
            let mut mutated_calldata = calldata.clone();
            mutated_calldata[offset] ^= 1;
            let mutated = render_erc7730_pages_with_signer_checked(
                &tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| {
                panic!("exact {operand} mutation refused for {signature}: {error:?}")
            });
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "{operand} mutation must change QuickSwap pages for {signature}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "{operand} mutation must change QuickSwap receipt for {signature}"
            );
        }

        if native_input {
            let mut mutated_tx = tx;
            mutated_tx.value = u256_from_u64(2_000_000_000_000_000_000);
            let mutated = render_erc7730_pages_with_signer_checked(
                &mutated_tx,
                &calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .expect("render mutated QuickSwap native input");
            assert_ne!(rendered.pages.as_slice(), mutated.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt));
        }
    }
}

#[test]
fn production_quickswap_nonpayable_swaps_show_nonzero_outer_value_before_revert() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let path = if matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE
                | QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE
                | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT
        ) {
            [TOKEN_IN, QUICKSWAP_WMATIC]
        } else {
            [TOKEN_IN, TOKEN_OUT]
        };
        let (first, second) = match signature {
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (
                    u256_from_u64(1_500_000),
                    u256_from_u64(1_000_000_000_000_000_000),
                )
            }
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                u256_from_u64(1_000_000_000_000_000_000),
                u256_from_u64(1_500_000),
            ),
            QUICKSWAP_SWAP_EXACT_TOKENS_FOT => (u256_from_u64(1_500_000), u256_from_u64(1_000_000)),
            _ => unreachable!(),
        };
        let calldata = quickswap_swap_calldata(
            signature,
            first,
            second,
            &path,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        tx.value = u256_from_u64(1_000_000_000_000_000_000);
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let pages = pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&verified),
            None,
            None,
            &resolver,
            &mut proofs,
        )
        .unwrap_or_else(|_| {
            panic!("nonpayable {signature} must display value before its contract-level revert")
        });
        let native_rows = page_strs(&pages, find_page_by_label(&pages, "! NATIVE POL"));
        assert_eq!(native_rows[1], "1.000000 POL");
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&pages, &tx, false, &mut verdict);
        assert_eq!(
            verdict,
            crate::fi::OK_SENTINEL,
            "dispatcher receipt must bind the loud outer-value page"
        );
    }
}

#[test]
fn production_quickswap_token_multihop_mutations_change_transcript_or_refuse() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let tx = envelope(137, QUICKSWAP_ROUTER);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
    ] {
        let calldata = quickswap_swap_calldata(
            signature,
            u256_from_u64(1_500_000),
            u256_from_u64(1_000_000),
            &path,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .expect("render canonical QuickSwap swap");

        let mut offsets = vec![
            (4 + 31, "first amount"),
            (4 + 32 + 31, "second amount"),
            (4 + 3 * 32 + 31, "beneficiary"),
            (4 + 4 * 32 + 31, "deadline"),
        ];
        let path_start = 4 + 5 * 32 + 32;
        for index in 0..path.len() {
            offsets.push((path_start + index * 32 + 31, "route element"));
        }
        for (offset, operand) in offsets {
            let mut mutated_calldata = calldata.clone();
            mutated_calldata[offset] ^= 1;
            let mutated = render_erc7730_pages_with_signer_checked(
                &tx,
                &mutated_calldata,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .unwrap_or_else(|error| {
                panic!("canonical {operand} mutation must render for {signature}: {error:?}")
            });
            assert_ne!(
                rendered.pages.as_slice(),
                mutated.pages.as_slice(),
                "{operand} mutation must change QuickSwap pages for {signature}"
            );
            assert!(
                !rendered
                    .transcript_receipt
                    .exact_match(&mutated.transcript_receipt),
                "{operand} mutation must change QuickSwap receipt for {signature}"
            );
        }
    }
}

#[test]
fn production_quickswap_special_beneficiaries_remain_literal() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let mut address_one = [0u8; 20];
    address_one[19] = 1;
    let mut address_two = [0u8; 20];
    address_two[19] = 2;

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let path = if native_input {
            [QUICKSWAP_WMATIC, TOKEN_OUT]
        } else if matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE
                | QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE
                | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT
        ) {
            [TOKEN_IN, QUICKSWAP_WMATIC]
        } else {
            [TOKEN_IN, TOKEN_OUT]
        };
        let (first, second) = match signature {
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => (u256_from_u64(1_000_000), U256::default()),
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (
                    u256_from_u64(1_500_000),
                    u256_from_u64(1_000_000_000_000_000_000),
                )
            }
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                u256_from_u64(1_000_000_000_000_000_000),
                u256_from_u64(1_500_000),
            ),
            _ => (u256_from_u64(1_500_000), u256_from_u64(1_000_000)),
        };
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = u256_from_u64(1_000_000_000_000_000_000);
        }
        for beneficiary in [address_one, address_two] {
            let calldata = quickswap_swap_calldata(
                signature,
                first,
                second,
                &path,
                beneficiary,
                u256_from_u64(2_000_000_000),
            );
            let rendered = render_erc7730_pages_with_signer_checked(
                &tx, &calldata, &verified, None, &resolver, &signer,
            )
            .unwrap_or_else(|error| panic!("literal beneficiary must render: {error:?}"));
            assert_full_address_field_page(&rendered.pages, "Beneficiary", &beneficiary);
            assert_ne!(
                beneficiary, signer,
                "test must distinguish literal from signer"
            );
        }
    }
}

#[test]
fn production_quickswap_invalid_native_endpoint_is_exact_but_contract_reverts() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let wrong_endpoint_path = [TOKEN_IN, TOKEN_OUT];

    // The pinned router requires path[0] == WMATIC for native-input swaps and
    // path[-1] == WMATIC for native-output swaps. The authenticated generic
    // address[] IR has no protocol-specific literal endpoint predicate. It
    // therefore shows both wrong signed addresses exactly; the deployed
    // contract then rejects the request with INVALID_PATH.
    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let (first, second) = match signature {
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (
                    u256_from_u64(1_500_000),
                    u256_from_u64(1_000_000_000_000_000_000),
                )
            }
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => (u256_from_u64(1_000_000), U256::default()),
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                u256_from_u64(1_000_000_000_000_000_000),
                u256_from_u64(1_500_000),
            ),
            _ => unreachable!(),
        };
        let calldata = quickswap_swap_calldata(
            signature,
            first,
            second,
            &wrong_endpoint_path,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = u256_from_u64(1_000_000_000_000_000_000);
        }
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .expect("wrong WMATIC endpoint renders exactly before source-level revert");
        assert_complete_route_pages(&rendered.pages, &wrong_endpoint_path);
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));
    }
}

#[test]
fn production_quickswap_one_token_route_is_exact_but_guaranteed_to_revert() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];

    // The deployed V2 router requires path.length >= 2 and therefore reverts
    // this call. The generic canonical address[] renderer intentionally has no
    // protocol-specific minimum-count guard: it still shows the one signed
    // address exactly. Every tokenAmount endpoint binds to that same address.
    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let one = [
            if matches!(
                signature,
                QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE
                    | QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                    | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                    | QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE
                    | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
                    | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT
            ) {
                QUICKSWAP_WMATIC
            } else {
                TOKEN_IN
            },
        ];
        let (first, second) = match signature {
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => (u256_from_u64(1_000_000), U256::default()),
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (
                    u256_from_u64(1_500_000),
                    u256_from_u64(1_000_000_000_000_000_000),
                )
            }
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                u256_from_u64(1_000_000_000_000_000_000),
                u256_from_u64(1_500_000),
            ),
            _ => (u256_from_u64(1_500_000), u256_from_u64(1_000_000)),
        };
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = u256_from_u64(1_000_000_000_000_000_000);
        }
        let calldata = quickswap_swap_calldata(
            signature,
            first,
            second,
            &one,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .expect("canonical one-element route renders exactly before contract revert");
        assert_complete_route_pages(&rendered.pages, &one);
        let identity_pages = rendered
            .pages
            .as_slice()
            .iter()
            .filter(|page| row_str(&page[0]) == "Token (UNVERIFI~")
            .count();
        let expected_identity_pages = usize::from(matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_TOKENS
                | QUICKSWAP_SWAP_TOKENS_FOR_EXACT
                | QUICKSWAP_SWAP_EXACT_TOKENS_FOT
        )) + 1;
        assert_eq!(
            identity_pages, expected_identity_pages,
            "every tokenAmount endpoint must expose the sole signed token identity"
        );
    }
}

#[test]
fn production_quickswap_multihop_noncanonical_framing_refuses() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let resolver = NameResolver::new();
    let signer = [0x44; 20];

    for signature in [
        QUICKSWAP_SWAP_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS,
        QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS,
        QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOT,
        QUICKSWAP_SWAP_EXACT_NATIVE_FOT,
        QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT,
    ] {
        let native_input = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
                | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
                | QUICKSWAP_SWAP_EXACT_NATIVE_FOT
        );
        let native_output = matches!(
            signature,
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE
                | QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE
                | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT
        );
        let path = if native_input {
            [QUICKSWAP_WMATIC, TOKEN_MID, TOKEN_OUT]
        } else if native_output {
            [TOKEN_IN, TOKEN_MID, QUICKSWAP_WMATIC]
        } else {
            [TOKEN_IN, TOKEN_MID, TOKEN_OUT]
        };
        let (first, second, head_words, path_word, beneficiary_word) = match signature {
            QUICKSWAP_SWAP_EXACT_NATIVE_FOR_TOKENS
            | QUICKSWAP_SWAP_NATIVE_FOR_EXACT_TOKENS
            | QUICKSWAP_SWAP_EXACT_NATIVE_FOT => {
                (u256_from_u64(1_000_000), U256::default(), 4, 1, 2)
            }
            QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE | QUICKSWAP_SWAP_EXACT_TOKENS_FOR_NATIVE_FOT => {
                (
                    u256_from_u64(1_500_000),
                    u256_from_u64(1_000_000_000_000_000_000),
                    5,
                    2,
                    3,
                )
            }
            QUICKSWAP_SWAP_TOKENS_FOR_EXACT_NATIVE => (
                u256_from_u64(1_000_000_000_000_000_000),
                u256_from_u64(1_500_000),
                5,
                2,
                3,
            ),
            _ => (u256_from_u64(1_500_000), u256_from_u64(1_000_000), 5, 2, 3),
        };
        let mut tx = envelope(137, QUICKSWAP_ROUTER);
        if native_input {
            tx.value = u256_from_u64(1_000_000_000_000_000_000);
        }
        let render = |calldata: &[u8]| {
            render_erc7730_pages_with_signer_checked(
                &tx, calldata, &verified, None, &resolver, &signer,
            )
        };
        let baseline = quickswap_swap_calldata(
            signature,
            first,
            second,
            &path,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        assert!(render(&baseline).is_ok(), "canonical route must render");

        let empty = quickswap_swap_calldata(
            signature,
            first,
            second,
            &[],
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        assert!(render(&empty).is_err(), "empty endpoint path must refuse");

        let mut nine = [[0x77; 20]; 9];
        if native_input {
            nine[0] = QUICKSWAP_WMATIC;
        } else if native_output {
            nine[8] = QUICKSWAP_WMATIC;
        }
        let over_cap = quickswap_swap_calldata(
            signature,
            first,
            second,
            &nine,
            [0x33; 20],
            u256_from_u64(2_000_000_000),
        );
        assert!(
            render(&over_cap).is_err(),
            "nine route elements exceed the review cap"
        );

        let offset_word = 4 + path_word * 32;
        let canonical_offset = (head_words * 32) as u64;
        for (offset, case) in [
            (canonical_offset - 32, "head alias"),
            (canonical_offset + 1, "misaligned"),
            (canonical_offset + 32, "gap"),
        ] {
            let mut malformed = baseline.clone();
            malformed[offset_word..offset_word + 32].copy_from_slice(&u256_from_u64(offset).0);
            assert!(render(&malformed).is_err(), "{case} offset must refuse");
        }

        let mut dirty_beneficiary = baseline.clone();
        dirty_beneficiary[4 + beneficiary_word * 32] = 1;
        assert!(
            render(&dirty_beneficiary).is_err(),
            "dirty beneficiary padding must refuse"
        );
        let path_start = 4 + head_words * 32 + 32;
        for index in 0..path.len() {
            let mut dirty_path = baseline.clone();
            dirty_path[path_start + index * 32] = 1;
            assert!(
                render(&dirty_path).is_err(),
                "dirty route-address padding {index} must refuse"
            );
        }

        assert!(
            render(&baseline[..4 + head_words * 32 - 1]).is_err(),
            "truncated static head must refuse"
        );
        let mut short_tail = baseline.clone();
        short_tail.pop();
        assert!(render(&short_tail).is_err(), "truncated tail must refuse");
        let mut trailing = baseline.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert!(render(&trailing).is_err(), "trailing word must refuse");
    }
}

#[test]
fn production_quickswap_remove_liquidity_renders_every_signed_byte_or_refuses() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-QuickSwap.json", 137);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify QuickSwap leaf");
    let tx = envelope(137, QUICKSWAP_ROUTER);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let beneficiary = [0x33; 20];
    let token_a = [0x11; 20];
    let token_b = [0x22; 20];
    let liquidity = quickswap_liquidity_word();

    for signature in [
        QUICKSWAP_REMOVE,
        QUICKSWAP_REMOVE_NATIVE,
        QUICKSWAP_REMOVE_NATIVE_FOT,
    ] {
        let calldata = quickswap_remove_calldata(signature);
        let rendered = render_erc7730_pages_with_signer_checked(
            &tx, &calldata, &verified, None, &resolver, &signer,
        )
        .unwrap_or_else(|error| panic!("render QuickSwap {signature}: {error:?}"));
        assert_all_pages_printable(&rendered.pages);
        assert_raw_word_pages(&rendered.pages, "LP token amount", &liquidity);
        assert_full_address_field_page(&rendered.pages, "Beneficiary", &beneficiary);
        assert_some_page_shows_full_address(&rendered.pages, &token_a);
        if signature == QUICKSWAP_REMOVE {
            assert_some_page_shows_full_address(&rendered.pages, &token_b);
        }
        find_page_by_label(&rendered.pages, "Minimum amount");
        find_page_by_label(&rendered.pages, "Deadline");
        assert!(rendered
            .transcript_receipt
            .range_matches(&rendered.pages, 0));

        for index in 0..calldata.len() {
            let mut mutated = calldata.clone();
            mutated[index] ^= 1;
            if let Ok(changed) = render_erc7730_pages_with_signer_checked(
                &tx, &mutated, &verified, None, &resolver, &signer,
            ) {
                assert_ne!(
                    rendered.pages.as_slice(),
                    changed.pages.as_slice(),
                    "calldata byte {index} changed silently for {signature}"
                );
                assert!(
                    !rendered
                        .transcript_receipt
                        .exact_match(&changed.transcript_receipt),
                    "calldata byte {index} preserved transcript for {signature}"
                );
            }
        }

        let mut short = calldata.clone();
        short.pop();
        assert!(render_erc7730_pages_with_signer_checked(
            &tx, &short, &verified, None, &resolver, &signer,
        )
        .is_err());
        let mut trailing = calldata.clone();
        trailing.push(0);
        assert!(render_erc7730_pages_with_signer_checked(
            &tx, &trailing, &verified, None, &resolver, &signer,
        )
        .is_err());
    }

    assert_eq!(
        cross_check_contract(&verified.ir, 137, &QUICKSWAP_ROUTER),
        Ok(())
    );
    assert!(cross_check_contract(&verified.ir, 1, &QUICKSWAP_ROUTER).is_err());
    assert!(cross_check_contract(&verified.ir, 137, &[0x55; 20]).is_err());
}

#[test]
fn production_uniswap_packed_c1_decoy_cannot_bypass_exact_tuple_preflight() {
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let packed = uniswap_v3_packed_path(&[TOKEN_IN, TOKEN_OUT], &[500]);

    for signature in [UNI_EXACT_INPUT_PACKED, UNI_EXACT_OUTPUT_PACKED] {
        // A canonical *C1 bytes* tail carrying a valid packed path is not the
        // selected `(bytes,address,uint256,uint256)` tuple. The exact enrolled
        // selector must not let this decoy borrow the special C2 renderer.
        let selector = keccak256(signature.as_bytes());
        let padded_len = (packed.len() + 31) / 32 * 32;
        let mut decoy = Vec::with_capacity(4 + 64 + padded_len);
        decoy.extend_from_slice(&selector[..4]);
        decoy.extend_from_slice(&u256_from_u64(32).0);
        decoy.extend_from_slice(&u256_from_u64(packed.len() as u64).0);
        decoy.extend_from_slice(&packed);
        decoy.resize(4 + 64 + padded_len, 0);

        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx, &decoy, &verified, None, &resolver, &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::Reject(_))
        ));
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &decoy,
                &signer,
                None,
                None,
                None,
                Some(&verified),
                None,
                None,
                &resolver,
                &mut proofs,
            )
            .is_err(),
            "C1 decoy must hard-refuse without fallback for {signature}"
        );
    }
}

/// Parse a 64-char hex string into a `[u8; 32]` for the remaining synthetic
/// nested fixture vectors.
fn hx32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

/// v3 catalogue-wide safety: exercise every authenticated production format
/// carrying a nested descent with hostile blobs and require fail-closed,
/// panic/OOB-free behavior.
#[test]
fn v3_all_nested_eip712_leaves_are_panic_safe_and_fail_closed() {
    let mut nested_type_hashes = std::collections::BTreeSet::new();
    let resolver = NameResolver::new();
    for entry in &build_registry().entries {
        let Ok(ir) = Erc7730Ir::parse(&entry.ir_bytes) else {
            continue;
        };
        if !matches!(ir.context_kind, ContextKind::Eip712) {
            continue;
        }
        let chain = ir.chain_id;
        let contract = ir.contract;
        for format in ir.format_iter() {
            let Ok(fmt) = format else { continue };
            if fmt.nested_descent_count == 0 {
                continue; // no nested anchor in this format
            }
            nested_type_hashes.insert(fmt.type_hash);
            let pth = fmt.type_hash;
            let ed = std::vec![0u8; fmt.static_head_words as usize * 32];
            for blob in [
                std::vec::Vec::new(),
                std::vec![0u8; 64],
                std::vec![0xFFu8; 300],
            ] {
                let verified = VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&entry.ir_bytes).unwrap(),
                };
                // A wrong blob must decline (Err), never render a mis-bound
                // page and never panic. Asserting only "returns Result" would
                // make this fail-closed regression vacuous if a hostile blob
                // ever started producing pages.
                assert!(
                    super::erc7730::render_erc7730_eip712_pages_v3(
                        chain, &contract, &pth, &ed, &blob, &verified, None, &resolver,
                    )
                    .is_err(),
                    "hostile nested blob unexpectedly rendered: source={} selector=0x{} blob_len={}",
                    entry.source.display(),
                    hex::encode(fmt.selector),
                    blob.len(),
                );
            }
        }
    }
    for expected in [
        PERMIT_SINGLE_TYPEHASH,
        PERMIT_BATCH_TYPEHASH,
        PERMIT_TRANSFER_FROM_TYPEHASH,
    ] {
        assert!(
            nested_type_hashes.contains(&expected),
            "production Permit2 type 0x{} was not exercised",
            hex::encode(expected)
        );
    }
}

/// The two curated FlyingTulip `Session` descriptors are production leaves for
/// exactly seven domain/deployment contexts. Verify every Merkle leaf and its
/// EIP-712 binding, then render every signed member from the real catalogue.
/// The nested `AssetLimit(token, limit)` vocabulary includes the max-uint
/// threshold message (`Unlimited`), while the formerly-hidden salt is shown as
/// a complete raw word. Exhaustive one-byte mutations must either change the
/// trusted pages or make the request fail closed.
#[test]
fn v3_production_session_manager_eip712_is_complete_and_mutation_bound() {
    use std::collections::BTreeSet;

    use super::erc7730::nested::hash_struct_array;

    const FT_SOURCE: &str = "eip712-SessionManager-FT.json";
    const FTUSD_SOURCE: &str = "eip712-SessionManager-ftUSD.json";
    let pth = hx32("10e2e916a5d944a9c9fa82748951934e444783850c4cb366694967607dbd2fc5");
    let asset_limit_th = hx32("269888c0029efe9424c548a264e5ee66803094ad203b068ca44e278b02db9d6f");
    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let usdc = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let weth = [
        0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27, 0xeA, 0xD9,
        0x08, 0x3C, 0x75, 0x6C, 0xc2,
    ];
    let owner = [0x71; 20];
    let delegate = [0x72; 20];

    // AssetLimit: token, limit (2 words). el0 normal, el1 = max-uint → "Unlimited".
    let mut el0 = std::vec![0u8; 64];
    el0[0..32].copy_from_slice(&wa(usdc));
    el0[32..64].copy_from_slice(&wu(1_000_001)); // a finite limit
    let mut el1 = std::vec![0u8; 64];
    el1[0..32].copy_from_slice(&wa(weth));
    el1[32..64].copy_from_slice(&[0xFFu8; 32]); // max-uint => >= threshold => "Unlimited"
    let limits_word = hash_struct_array(&asset_limit_th, &[&el0[..], &el1[..]]);

    // Session top_ed (8 words): owner, delegate, validAfter, validUntil, maxCalls,
    // maxFeeBps, limits, salt.
    let mut top_ed = std::vec![0u8; 256];
    top_ed[0..32].copy_from_slice(&wa(owner));
    top_ed[32..64].copy_from_slice(&wa(delegate));
    top_ed[64..96].copy_from_slice(&wu(1_735_689_600)); // validAfter (2025)
    top_ed[96..128].copy_from_slice(&wu(1_767_225_600)); // validUntil (2026)
    top_ed[128..160].copy_from_slice(&wu(50)); // maxCalls
    top_ed[160..192].copy_from_slice(&wu(30)); // maxFeeBps
    top_ed[192..224].copy_from_slice(&limits_word); // limits (array)
    top_ed[224..256].copy_from_slice(&[0xAB; 32]); // salt (VISIBLE fixture)

    // nested_blob: the single `limits` array descent — [elem_count=2][el0][el1].
    let mut blob = std::vec::Vec::new();
    blob.extend_from_slice(&2u16.to_be_bytes());
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el1);

    let expected: BTreeSet<(String, u64, String)> = [
        (FT_SOURCE, 1, "f9f3ddf2e96cabef94e2634c326dc6dde99360f8"),
        (FT_SOURCE, 146, "109ae72778a0260571b9767477204f1ce41fbdff"),
        (FTUSD_SOURCE, 1, "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9"),
        (FTUSD_SOURCE, 56, "c85cb743f72b3a9bb594faa7d46ee1efc61b7a42"),
        (
            FTUSD_SOURCE,
            146,
            "2daf4b445e7d659100b22a15c3eeb10e64ac5dc9",
        ),
        (
            FTUSD_SOURCE,
            146,
            "52ef449d44cc4205fa44bf644dee15611fc30734",
        ),
        (
            FTUSD_SOURCE,
            43_114,
            "176592c8ed3f2d94ce4c3f1a4cff7d068176ac54",
        ),
    ]
    .into_iter()
    .map(|(source, chain_id, contract)| (source.to_string(), chain_id, contract.to_string()))
    .collect();

    let registry = build_registry();
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.source.file_name().and_then(|name| name.to_str()),
                Some(FT_SOURCE) | Some(FTUSD_SOURCE)
            )
        })
        .collect();
    let observed: BTreeSet<_> = entries
        .iter()
        .map(|entry| {
            (
                entry
                    .source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("SessionManager source filename")
                    .to_string(),
                entry.chain_id,
                hex::encode(entry.contract),
            )
        })
        .collect();
    assert_eq!(
        observed, expected,
        "exact curated domain/deployment inventory"
    );
    assert_eq!(entries.len(), 7);

    let mut domain_separators = BTreeSet::new();
    for entry in entries {
        let source_name = entry
            .source
            .file_name()
            .and_then(|name| name.to_str())
            .expect("SessionManager source filename");
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &registry.root)
            .expect("production SessionManager Merkle leaf verifies");
        assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
        assert_eq!(verified.ir.chain_id, entry.chain_id);
        assert_eq!(verified.ir.contract, entry.contract);
        assert!(domain_separators.insert(verified.ir.domain_separator));
        assert_eq!(
            cross_check_eip712(&verified.ir, entry.chain_id, &verified.ir.domain_separator,),
            Ok(())
        );
        assert_eq!(
            cross_check_eip712(
                &verified.ir,
                entry.chain_id.wrapping_add(1),
                &verified.ir.domain_separator,
            ),
            Err(BindingError::ChainIdMismatch)
        );
        let mut wrong_domain = verified.ir.domain_separator;
        wrong_domain[0] ^= 0x01;
        assert_eq!(
            cross_check_eip712(&verified.ir, entry.chain_id, &wrong_domain),
            Err(BindingError::DomainSeparatorMismatch)
        );

        let mut formats = verified.ir.format_iter();
        let format = formats
            .next()
            .expect("one Session format")
            .expect("valid Session format");
        assert!(
            formats.next().is_none(),
            "one format per Session descriptor"
        );
        assert_eq!(format.type_hash, pth);
        assert_eq!(format.static_head_words, 8);
        assert_eq!(format.field_count, 8);
        assert_eq!(format.nested_descent_count, 1);

        let resolver = NameResolver::new();
        let render = |type_hash: &[u8; 32], ed: &[u8], nested: &[u8]| {
            super::erc7730::render_erc7730_eip712_pages_v3(
                entry.chain_id,
                &entry.contract,
                type_hash,
                ed,
                nested,
                &verified,
                None,
                &resolver,
            )
        };
        let pages = render(&pth, &top_ed, &blob)
            .unwrap_or_else(|error| panic!("{source_name} must clear-sign: {error:?}"));
        assert_all_pages_printable(&pages);
        assert_full_address_field_page(&pages, "Owner", &owner);
        assert_full_address_field_page(&pages, "Delegate", &delegate);
        assert_raw_word_pages(&pages, "Max calls", &wu(50));
        assert_raw_word_pages(&pages, "Salt", &[0xAB; 32]);

        let dump = dump_pages(&pages).to_lowercase();
        assert!(
            dump.contains("2025-01-01") && dump.contains("2026-01-01"),
            "both exact validity dates render:\n{dump}"
        );
        let max_fee = page_strs(&pages, find_page_by_label(&pages, "Max fee")).join(" ");
        assert!(
            max_fee.to_lowercase().contains("30 bps"),
            "maxFeeBps renders with its unit: {max_fee:?}\n{dump}"
        );
        assert!(
            dump.contains("1000001"),
            "element 0 finite limit renders the number:\n{dump}"
        );
        assert!(
            dump.contains("unlimited"),
            "element 1 max-uint renders Unlimited:\n{dump}"
        );
        assert!(
            dump.contains("a0b86991c6218b") && dump.contains("c02aaa39"),
            "both exact nested token identities render:\n{dump}"
        );
        assert!(
            dump.contains("item 1 of 2") && dump.contains("item 2 of 2"),
            "per-element dividers render:\n{dump}"
        );
        if source_name == FT_SOURCE {
            assert!(
                dump.contains("create session"),
                "FT intent renders:\n{dump}"
            );
        } else {
            assert!(
                dump.contains("create ftusd ses") && dump.contains("| sion |"),
                "ftUSD intent renders:\n{dump}"
            );
        }

        // Every byte in EIP-712 encodeData is signed. A one-byte change must
        // therefore alter at least one trusted page or refuse the request.
        for byte in 0..top_ed.len() {
            let mut changed_ed = top_ed.clone();
            changed_ed[byte] ^= 0x01;
            if let Ok(changed_pages) = render(&pth, &changed_ed, &blob) {
                assert_ne!(
                    changed_pages.as_slice(),
                    pages.as_slice(),
                    "signed encodeData byte {byte} was not represented for {source_name} chain {}",
                    entry.chain_id,
                );
            }
        }
        // Every nested byte is committed by the displayed limits hash; with
        // the top-level commitment fixed, each one-byte change must decline.
        for byte in 0..blob.len() {
            let mut changed_blob = blob.clone();
            changed_blob[byte] ^= 0x01;
            assert!(
                render(&pth, &top_ed, &changed_blob).is_err(),
                "unbound nested byte {byte} rendered for {source_name} chain {}",
                entry.chain_id,
            );
        }

        let mut wrong_type = pth;
        wrong_type[0] ^= 0x01;
        assert!(render(&wrong_type, &top_ed, &blob).is_err());
        assert!(render(&pth, &top_ed[..top_ed.len() - 1], &blob).is_err());
        let mut trailing_ed = top_ed.clone();
        trailing_ed.push(0);
        assert!(render(&pth, &trailing_ed, &blob).is_err());

        // Empty and over-cap arrays are still cryptographically well-bound,
        // but the bounded renderer deliberately refuses them.
        let empty_elements: [&[u8]; 0] = [];
        let mut empty_ed = top_ed.clone();
        empty_ed[192..224].copy_from_slice(&hash_struct_array(&asset_limit_th, &empty_elements));
        assert!(render(&pth, &empty_ed, &[0, 0]).is_err());

        let seven_elements = vec![el0.clone(); 7];
        let seven_refs: Vec<&[u8]> = seven_elements.iter().map(Vec::as_slice).collect();
        let mut seven_ed = top_ed.clone();
        seven_ed[192..224].copy_from_slice(&hash_struct_array(&asset_limit_th, &seven_refs));
        let mut seven_blob = Vec::new();
        seven_blob.extend_from_slice(&7u16.to_be_bytes());
        for element in &seven_elements {
            seven_blob.extend_from_slice(&64u16.to_be_bytes());
            seven_blob.extend_from_slice(element);
        }
        assert!(render(&pth, &seven_ed, &seven_blob).is_err());
    }
    assert_eq!(
        domain_separators.len(),
        7,
        "every deployment/domain is unique"
    );
}

const ONEINCH_V6_SOURCE: &str = "calldata-AggregationRouterV6.json";
const ONEINCH_V6_ZK_SOURCE: &str = "calldata-AggregationRouterV6-zksync.json";
const ONEINCH_CANCEL: &str = "cancelOrder(uint256,bytes32)";
const ONEINCH_EPOCH: &str = "increaseEpoch(uint96)";
const ONEINCH_CANCEL_SELECTOR: [u8; 4] = [0xb6, 0x8f, 0xb0, 0x20];
const ONEINCH_EPOCH_SELECTOR: [u8; 4] = [0xc3, 0xcf, 0x80, 0x43];
const ONEINCH_CANCEL_WARNING: &str = "Traits choose hash or nonce-bit mode; hash may be ignored";
const ONEINCH_EPOCH_WARNING: &str = "Old epoch off; next epoch may activate";

fn oneinch_v6_normal_contract() -> [u8; 20] {
    hex::decode("111111125421ca6dc452d289314280a0f8842a65")
        .expect("1inch V6 common deployment address")
        .try_into()
        .expect("address width")
}

fn oneinch_v6_zk_contract() -> [u8; 20] {
    hex::decode("6fd4383cb451173d5f9304f041c7bcbf27d561ff")
        .expect("1inch V6 zkSync deployment address")
        .try_into()
        .expect("address width")
}

fn is_oneinch_v6_source(entry: &dbgen::erc7730::Emitted) -> bool {
    matches!(
        entry.source.file_name().and_then(|name| name.to_str()),
        Some(ONEINCH_V6_SOURCE) | Some(ONEINCH_V6_ZK_SOURCE)
    )
}

#[test]
fn production_1inch_v6_cancellation_controls_render_complete_neutral_transcripts() {
    use std::collections::BTreeSet;

    use pqsigner_erc7730::bundle::MAX_ERC7730_BUNDLE_LEN;
    use pqsigner_erc7730::display::MAX_PAGES;
    use pqsigner_erc7730::ir::MAX_IR_LEN;
    use pqsigner_erc7730::known_calls::BLOOM_BYTES;

    const NORMAL_CHAINS: [u64; 9] = [1, 10, 56, 100, 137, 8_453, 42_161, 59_144, 1_313_161_554];
    const ZK_CHAIN: u64 = 324;

    assert_eq!(
        &keccak256(ONEINCH_CANCEL.as_bytes())[..4],
        &ONEINCH_CANCEL_SELECTOR
    );
    assert_eq!(
        &keccak256(ONEINCH_EPOCH.as_bytes())[..4],
        &ONEINCH_EPOCH_SELECTOR
    );

    let registry = build_registry();
    let normal_contract = oneinch_v6_normal_contract();
    let zk_contract = oneinch_v6_zk_contract();
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| is_oneinch_v6_source(entry))
        .collect();
    let observed: BTreeSet<_> = entries
        .iter()
        .map(|entry| {
            (
                entry
                    .source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("1inch source filename")
                    .to_string(),
                entry.chain_id,
                entry.contract,
            )
        })
        .collect();
    let mut expected = BTreeSet::new();
    for chain_id in NORMAL_CHAINS {
        expected.insert((ONEINCH_V6_SOURCE.to_string(), chain_id, normal_contract));
    }
    expected.insert((ONEINCH_V6_ZK_SOURCE.to_string(), ZK_CHAIN, zk_contract));
    assert_eq!(observed, expected, "exact reviewed 1inch V6 leaf inventory");
    assert_eq!(entries.len(), 10, "one leaf per reviewed deployment");

    // The catalogue remains a companion artifact. Firmware FLASH growth is
    // bounded by the unchanged 32-byte root and fixed 16-KiB downgrade Bloom;
    // each on-wire proof/IR and the trusted page buffer retain their existing
    // hard limits. This is descriptor-slice evidence, not a whole-firmware
    // stack high-water claim.
    assert_eq!(registry.root.len(), 32);
    assert_eq!(registry.known_calls_bloom.len(), BLOOM_BYTES);
    assert_eq!(
        std::mem::size_of::<Pages>(),
        MAX_PAGES * 4 * DISPLAY_COLS + std::mem::size_of::<usize>(),
        "descriptor growth must not resize the fixed trusted-page stack object"
    );
    for entry in &entries {
        assert!(entry.ir_bytes.len() <= MAX_IR_LEN);
        let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
        assert!(bundle.len() <= MAX_ERC7730_BUNDLE_LEN);
        let verified = verify_erc7730_bundle(&bundle, &registry.root)
            .expect("reviewed 1inch V6 Merkle leaf verifies");
        cross_check_contract(&verified.ir, entry.chain_id, &entry.contract)
            .expect("reviewed 1inch V6 leaf binds its exact deployment");
        assert!(matches!(verified.ir.context_kind, ContextKind::Contract));
        assert_eq!(verified.ir.format_count(), Ok(2));
        let selectors: BTreeSet<_> = verified
            .ir
            .format_iter()
            .map(|format| format.expect("well-formed 1inch format").selector)
            .collect();
        assert_eq!(
            selectors,
            [ONEINCH_CANCEL_SELECTOR, ONEINCH_EPOCH_SELECTOR]
                .into_iter()
                .collect(),
            "each reviewed deployment admits exactly the two cancellation controls"
        );
    }

    let mainnet = find_leaf(registry, ONEINCH_V6_SOURCE, 1);
    assert_eq!(mainnet.contract, normal_contract);
    let mainnet_bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let mainnet_verified = verify_erc7730_bundle(&mainnet_bundle, &registry.root)
        .expect("verify mainnet 1inch V6 leaf");
    cross_check_contract(&mainnet_verified.ir, 1, &normal_contract)
        .expect("bind mainnet 1inch V6 leaf");

    let signer = [0x42; 20];
    let mut changed_signer = signer;
    changed_signer[19] ^= 1;
    let resolver = NameResolver::new();
    let tx = envelope(1, normal_contract);
    let order_hash: [u8; 32] = core::array::from_fn(|index| (index as u8).wrapping_mul(7) ^ 0xa5);

    // Nonce 0x1234 at bit offset 120 with bit 254 clear selects the verified
    // nonce-bit branch. The hash is ignored there but remains fully displayed.
    let mut bit_mode_traits = [0u8; 32];
    bit_mode_traits[15] = 0x12;
    bit_mode_traits[16] = 0x34;
    let bit_mode_words = [bit_mode_traits, order_hash];
    let render_cancel = |words: &[[u8; 32]; 2], candidate_signer: &[u8; 20]| {
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata_static(ONEINCH_CANCEL, words),
            &mainnet_verified,
            None,
            &resolver,
            candidate_signer,
        )
    };
    let bit_mode = render_cancel(&bit_mode_words, &signer)
        .expect("1inch nonce-bit invalidation control renders");
    assert_eq!(
        bit_mode.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(bit_mode
        .transcript_receipt
        .range_matches(&bit_mode.pages, 0));
    assert_all_pages_printable(&bit_mode.pages);
    assert!(bit_mode.pages.len <= MAX_PAGES);
    assert_complete_intent(&bit_mode.pages, "Update 1inch order invalidation");
    assert_raw_word_pages(&bit_mode.pages, "Order maker", &abi_address_word(signer));
    assert_raw_word_pages(&bit_mode.pages, "Maker traits raw", &bit_mode_traits);
    assert_raw_word_pages(&bit_mode.pages, "Order hash raw", &order_hash);
    assert_constant_text_field_pages(&bit_mode.pages, "Effect warning", ONEINCH_CANCEL_WARNING);

    // Bit 254 set with bit 255 clear selects remaining/hash invalidation.
    // The wording remains deliberately neutral in both modes.
    let mut hash_mode_traits = bit_mode_traits;
    hash_mode_traits[0] |= 0x40;
    let hash_mode_words = [hash_mode_traits, order_hash];
    let hash_mode =
        render_cancel(&hash_mode_words, &signer).expect("1inch hash invalidation control renders");
    assert_complete_intent(&hash_mode.pages, "Update 1inch order invalidation");
    assert_raw_word_pages(&hash_mode.pages, "Maker traits raw", &hash_mode_traits);
    assert_raw_word_pages(&hash_mode.pages, "Order hash raw", &order_hash);
    assert_constant_text_field_pages(&hash_mode.pages, "Effect warning", ONEINCH_CANCEL_WARNING);
    assert_ne!(bit_mode.pages.as_slice(), hash_mode.pages.as_slice());
    assert!(!bit_mode
        .transcript_receipt
        .exact_match(&hash_mode.transcript_receipt));

    for (word_index, operand) in [(0usize, "makerTraits"), (1, "orderHash")] {
        let mut mutated_words = bit_mode_words;
        mutated_words[word_index][31] ^= 1;
        let mutated = render_cancel(&mutated_words, &signer)
            .unwrap_or_else(|error| panic!("mutated 1inch {operand} renders: {error:?}"));
        assert_ne!(bit_mode.pages.as_slice(), mutated.pages.as_slice());
        assert!(
            !bit_mode
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "changing only signed {operand} must change the authenticated transcript"
        );
    }
    let changed_cancel_signer =
        render_cancel(&bit_mode_words, &changed_signer).expect("changed 1inch order maker renders");
    assert_raw_word_pages(
        &changed_cancel_signer.pages,
        "Order maker",
        &abi_address_word(changed_signer),
    );
    assert_ne!(
        bit_mode.pages.as_slice(),
        changed_cancel_signer.pages.as_slice()
    );
    assert!(!bit_mode
        .transcript_receipt
        .exact_match(&changed_cancel_signer.transcript_receipt));
    let repeat_cancel = render_cancel(&bit_mode_words, &signer)
        .expect("deterministic 1inch cancellation re-render");
    assert_eq!(bit_mode.pages.as_slice(), repeat_cancel.pages.as_slice());
    assert!(bit_mode
        .transcript_receipt
        .exact_match(&repeat_cancel.transcript_receipt));

    let mut series = [0u8; 32];
    series[20..].copy_from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76,
    ]);
    let epoch_words = [series];
    let render_epoch = |words: &[[u8; 32]; 1], candidate_signer: &[u8; 20]| {
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata_static(ONEINCH_EPOCH, words),
            &mainnet_verified,
            None,
            &resolver,
            candidate_signer,
        )
    };
    let epoch = render_epoch(&epoch_words, &signer).expect("1inch series epoch renders");
    assert_eq!(
        epoch.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(epoch.transcript_receipt.range_matches(&epoch.pages, 0));
    assert_all_pages_printable(&epoch.pages);
    assert!(epoch.pages.len <= MAX_PAGES);
    assert_complete_intent(&epoch.pages, "Advance 1inch series epoch");
    assert_raw_word_pages(&epoch.pages, "Order maker", &abi_address_word(signer));
    assert_raw_word_pages(&epoch.pages, "Series", &series);
    assert_constant_text_field_pages(&epoch.pages, "Effect warning", ONEINCH_EPOCH_WARNING);

    let mut changed_series_words = epoch_words;
    changed_series_words[0][31] ^= 1;
    let changed_series = render_epoch(&changed_series_words, &signer)
        .expect("changed canonical uint96 series renders");
    assert_ne!(epoch.pages.as_slice(), changed_series.pages.as_slice());
    assert!(!epoch
        .transcript_receipt
        .exact_match(&changed_series.transcript_receipt));
    let changed_epoch_signer =
        render_epoch(&epoch_words, &changed_signer).expect("changed epoch maker renders");
    assert_ne!(
        epoch.pages.as_slice(),
        changed_epoch_signer.pages.as_slice()
    );
    assert!(!epoch
        .transcript_receipt
        .exact_match(&changed_epoch_signer.transcript_receipt));
    let repeat_epoch =
        render_epoch(&epoch_words, &signer).expect("deterministic 1inch epoch re-render");
    assert_eq!(epoch.pages.as_slice(), repeat_epoch.pages.as_slice());
    assert!(epoch
        .transcript_receipt
        .exact_match(&repeat_epoch.transcript_receipt));

    for (calldata, direct) in [
        (
            calldata_static(ONEINCH_CANCEL, &bit_mode_words),
            &bit_mode.pages,
        ),
        (calldata_static(ONEINCH_EPOCH, &epoch_words), &epoch.pages),
    ] {
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let dispatched = pick_sign_pages(
            &tx,
            &calldata,
            &signer,
            None,
            None,
            None,
            Some(&mainnet_verified),
            None,
            None,
            &resolver,
            &mut proofs,
        )
        .expect("dispatcher selects exact bound 1inch cancellation control");
        assert_eq!(dispatched.as_slice(), direct.as_slice());
    }

    let zk = find_leaf(registry, ONEINCH_V6_ZK_SOURCE, ZK_CHAIN);
    assert_eq!(zk.contract, zk_contract);
    let zk_bundle = synth_bundle(&registry.blob, &zk.ir_bytes, zk.leaf_index);
    let zk_verified =
        verify_erc7730_bundle(&zk_bundle, &registry.root).expect("verify zkSync 1inch V6 leaf");
    cross_check_contract(&zk_verified.ir, ZK_CHAIN, &zk_contract)
        .expect("bind zkSync 1inch V6 leaf");
    let zk_tx = envelope(ZK_CHAIN, zk_contract);
    let zk_cancel = render_erc7730_pages_with_signer_checked(
        &zk_tx,
        &calldata_static(ONEINCH_CANCEL, &hash_mode_words),
        &zk_verified,
        None,
        &resolver,
        &signer,
    )
    .expect("zkSync 1inch cancellation renders");
    assert_complete_intent(&zk_cancel.pages, "Update 1inch order invalidation");
    assert_raw_word_pages(&zk_cancel.pages, "Maker traits raw", &hash_mode_traits);
    assert_raw_word_pages(&zk_cancel.pages, "Order hash raw", &order_hash);
    assert_constant_text_field_pages(&zk_cancel.pages, "Effect warning", ONEINCH_CANCEL_WARNING);
    assert!(zk_cancel
        .transcript_receipt
        .range_matches(&zk_cancel.pages, 0));
    let zk_epoch = render_erc7730_pages_with_signer_checked(
        &zk_tx,
        &calldata_static(ONEINCH_EPOCH, &epoch_words),
        &zk_verified,
        None,
        &resolver,
        &signer,
    )
    .expect("zkSync 1inch epoch renders");
    assert_complete_intent(&zk_epoch.pages, "Advance 1inch series epoch");
    assert_raw_word_pages(&zk_epoch.pages, "Series", &series);
    assert_constant_text_field_pages(&zk_epoch.pages, "Effect warning", ONEINCH_EPOCH_WARNING);
    assert!(zk_epoch
        .transcript_receipt
        .range_matches(&zk_epoch.pages, 0));
}

#[test]
fn production_1inch_v6_cancellation_controls_reject_noncanonical_binding_and_framing() {
    let registry = build_registry();
    let contract = oneinch_v6_normal_contract();
    let entry = find_leaf(registry, ONEINCH_V6_SOURCE, 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &registry.root).expect("verify mainnet 1inch V6 leaf");
    cross_check_contract(&verified.ir, 1, &contract).expect("bind mainnet 1inch V6 leaf");
    assert!(matches!(
        cross_check_contract(&verified.ir, 10, &contract),
        Err(BindingError::ChainIdMismatch)
    ));
    let wrong_target = [0x55; 20];
    assert!(matches!(
        cross_check_contract(&verified.ir, 1, &wrong_target),
        Err(BindingError::ContractMismatch)
    ));
    let proof_set = crate::tx::erc7730::verify_erc7730_proof_set(&bundle, &registry.root)
        .expect("legacy bundle verifies as a one-element proof set");
    let signer = [0x42; 20];

    for (chain_id, target, label) in [
        (10u64, contract, "wrong chain"),
        (1u64, wrong_target, "wrong target"),
    ] {
        let mut verdict = crate::fi::FAIL_SENTINEL;
        let mut cfi = crate::fi::CfiCounter::new();
        let wrong_tx = envelope(chain_id, target);
        crate::tx::erc7730::prove_contract_proof_set_binding(
            &proof_set,
            &registry.root,
            &wrong_tx,
            &[],
            &signer,
            None,
            &mut verdict,
            &mut cfi,
        );
        assert_ne!(verdict, crate::fi::OK_SENTINEL, "{label} must refuse");
        assert_eq!(
            cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED),
            crate::fi::OK_SENTINEL,
            "rejecting {label} proof still completes its CFI transcript"
        );
    }

    let resolver = NameResolver::new();
    let tx = envelope(1, contract);
    let traits = [0x5a; 32];
    let order_hash = [0xa5; 32];
    let cancel = calldata_static(ONEINCH_CANCEL, &[traits, order_hash]);
    assert_selector_matches(&verified.ir, &cancel, ONEINCH_CANCEL);
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &cancel[..cancel.len() - 1],
        &verified,
        None,
        &resolver,
        &signer,
    )
    .is_err());
    let mut cancel_trailing = cancel.clone();
    cancel_trailing.push(0);
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &cancel_trailing,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .is_err());

    let mut series = [0u8; 32];
    series[20..].copy_from_slice(&[0x11; 12]);
    let epoch = calldata_static(ONEINCH_EPOCH, &[series]);
    assert_selector_matches(&verified.ir, &epoch, ONEINCH_EPOCH);
    render_erc7730_pages_with_signer_checked(&tx, &epoch, &verified, None, &resolver, &signer)
        .expect("canonical zero-padded uint96 is admitted");
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &epoch[..epoch.len() - 1],
        &verified,
        None,
        &resolver,
        &signer,
    )
    .is_err());
    let mut epoch_trailing = epoch.clone();
    epoch_trailing.push(0);
    assert!(render_erc7730_pages_with_signer_checked(
        &tx,
        &epoch_trailing,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .is_err());
    let mut dirty_series = series;
    dirty_series[19] = 1;
    assert!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &calldata_static(ONEINCH_EPOCH, &[dirty_series]),
            &verified,
            None,
            &resolver,
            &signer,
        )
        .is_err(),
        "nonzero high padding above uint96 must refuse"
    );

    let mut wrong_selector = cancel.clone();
    wrong_selector[3] ^= 1;
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &wrong_selector,
            &verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::NoFormat)
    ));
    let mut wrong_selector_proofs = DispatchPageProofs::new();
    wrong_selector_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &tx,
            &wrong_selector,
            &signer,
            None,
            None,
            None,
            Some(&verified),
            None,
            None,
            &resolver,
            &mut wrong_selector_proofs,
        )
        .is_err(),
        "a verified descriptor NoFormat must never fall back to blind signing"
    );

    let mut wrong_root = registry.root;
    wrong_root[0] ^= 1;
    assert!(verify_erc7730_bundle(&bundle, &wrong_root).is_err());
    let mut tampered_ir = bundle.clone();
    tampered_ir[2 + entry.ir_bytes.len() / 2] ^= 1;
    assert!(
        verify_erc7730_bundle(&tampered_ir, &registry.root).is_err(),
        "tampered authenticated 1inch IR must fail verification"
    );
    let mut tampered_proof = bundle.clone();
    *tampered_proof
        .last_mut()
        .expect("1inch bundle carries a Merkle proof") ^= 1;
    assert!(
        verify_erc7730_bundle(&tampered_proof, &registry.root).is_err(),
        "tampered 1inch Merkle path must fail verification"
    );
}

#[test]
fn production_1inch_v6_omitted_deployments_and_sibling_controls_hard_refuse() {
    const ALL_UPSTREAM_CHAINS: [u64; 14] = [
        1,
        10,
        56,
        100,
        137,
        146,
        250,
        324,
        8_217,
        8_453,
        42_161,
        43_114,
        59_144,
        1_313_161_554,
    ];
    const EXCLUDED_CHAINS: [u64; 4] = [146, 250, 8_217, 43_114];
    const CANCEL_ORDERS: &str = "cancelOrders(uint256[],bytes32[])";
    const BITS_INVALIDATE: &str = "bitsInvalidateForOrder(uint256,uint256)";
    const ADVANCE_EPOCH: &str = "advanceEpoch(uint96,uint256)";
    const CANCEL_ORDERS_SELECTOR: [u8; 4] = [0x89, 0xe7, 0xc6, 0x50];
    const BITS_INVALIDATE_SELECTOR: [u8; 4] = [0x05, 0xb1, 0xea, 0x03];
    const ADVANCE_EPOCH_SELECTOR: [u8; 4] = [0x0d, 0x2c, 0x7c, 0x16];

    for (signature, selector) in [
        (CANCEL_ORDERS, CANCEL_ORDERS_SELECTOR),
        (BITS_INVALIDATE, BITS_INVALIDATE_SELECTOR),
        (ADVANCE_EPOCH, ADVANCE_EPOCH_SELECTOR),
    ] {
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
    }

    let registry = build_registry();
    let normal_contract = oneinch_v6_normal_contract();
    let zk_contract = oneinch_v6_zk_contract();
    for chain_id in EXCLUDED_CHAINS {
        assert!(
            !registry.entries.iter().any(|entry| {
                is_oneinch_v6_source(entry)
                    && entry.chain_id == chain_id
                    && entry.contract == normal_contract
            }),
            "unverified 1inch deployment on chain {chain_id} must emit no leaf"
        );
    }

    let mainnet = find_leaf(registry, ONEINCH_V6_SOURCE, 1);
    let bundle = synth_bundle(&registry.blob, &mainnet.ir_bytes, mainnet.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("verify admitted 1inch leaf for NoFormat tests");
    let tx = envelope(1, normal_contract);
    let signer = [0x42; 20];
    let resolver = NameResolver::new();
    for (signature, selector) in [
        (CANCEL_ORDERS, CANCEL_ORDERS_SELECTOR),
        (BITS_INVALIDATE, BITS_INVALIDATE_SELECTOR),
        (ADVANCE_EPOCH, ADVANCE_EPOCH_SELECTOR),
    ] {
        assert_selector_excluded(&verified.ir, signature);
        assert!(matches!(
            render_erc7730_pages_with_signer_checked(
                &tx, &selector, &verified, None, &resolver, &signer,
            ),
            Err(crate::tx::erc7730_render::RenderErr::NoFormat)
        ));
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        assert!(
            pick_sign_pages(
                &tx,
                &selector,
                &signer,
                None,
                None,
                None,
                Some(&verified),
                None,
                None,
                &resolver,
                &mut proofs,
            )
            .is_err(),
            "bound descriptor must hard-refuse omitted {signature} without fallback"
        );
    }

    let all_selectors = [
        ONEINCH_CANCEL_SELECTOR,
        ONEINCH_EPOCH_SELECTOR,
        CANCEL_ORDERS_SELECTOR,
        BITS_INVALIDATE_SELECTOR,
        ADVANCE_EPOCH_SELECTOR,
    ];
    for chain_id in ALL_UPSTREAM_CHAINS {
        let contract = if chain_id == 324 {
            zk_contract
        } else {
            normal_contract
        };
        let deployment_tx = envelope(chain_id, contract);
        for selector in all_selectors {
            assert!(
                registry
                    .known_calls
                    .contains(&(chain_id, contract, selector)),
                "1inch chain {chain_id} selector 0x{} must stay exact-known",
                hex::encode(selector)
            );
            assert!(pqsigner_erc7730::known_calls::may_contain(
                &registry.known_calls_bloom,
                chain_id,
                &contract,
                &selector,
            ));
            let mut proofs = DispatchPageProofs::new();
            proofs.fail_initialize();
            assert!(
                pick_sign_pages(
                    &deployment_tx,
                    &selector,
                    &signer,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    &resolver,
                    &mut proofs,
                )
                .is_err(),
                "known 1inch call on chain {chain_id} must not blind-fallback without its exact bound descriptor"
            );
        }
    }
}

#[test]
fn production_layerswap_routes_render_only_the_signed_funding_action() {
    const CHAIN_ID: u64 = 1;
    const SOURCE: &str = "calldata-LayerswapDepository.json";
    const NATIVE: &str = "depositNative(bytes32,address)";
    const ERC20: &str = "depositERC20(bytes32,address,address,uint256)";
    const ADMIN: &str = "addToWhitelist(address)";
    const NATIVE_SELECTOR: [u8; 4] = [0x80, 0xa6, 0xde, 0x92];
    const ERC20_SELECTOR: [u8; 4] = [0xf4, 0x37, 0x1f, 0x63];
    const ADMIN_SELECTOR: [u8; 4] = [0xe4, 0x32, 0x52, 0xd7];

    assert_eq!(&keccak256(NATIVE.as_bytes())[..4], &NATIVE_SELECTOR);
    assert_eq!(&keccak256(ERC20.as_bytes())[..4], &ERC20_SELECTOR);
    assert_eq!(&keccak256(ADMIN.as_bytes())[..4], &ADMIN_SELECTOR);

    let registry = build_registry();
    let source_entries = registry
        .entries
        .iter()
        .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(SOURCE))
        .collect::<Vec<_>>();
    assert_eq!(
        source_entries.len(),
        1,
        "only the source-verified Ethereum Layerswap deployment may render"
    );
    let entry = find_leaf(registry, SOURCE, CHAIN_ID);
    assert_eq!(
        hex::encode(entry.contract),
        "e226e4825cb215abafad98fdd400583eab6a594f"
    );
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("verify curated Layerswap descriptor");
    assert_eq!(
        cross_check_contract(&verified.ir, CHAIN_ID, &entry.contract),
        Ok(())
    );
    assert_eq!(verified.ir.format_count(), Ok(2));

    let signer = [0x77; 20];
    let resolver = NameResolver::new();
    let reference_id = [0x11; 32];
    let receiver = [0x22; 20];

    let native_calldata = calldata_static(
        NATIVE,
        &[reference_id, abi_address_word(receiver)],
    );
    assert_eq!(&native_calldata[..4], &NATIVE_SELECTOR);
    let mut native_tx = envelope(CHAIN_ID, entry.contract);
    native_tx.value = u256_from_u64(1_000_000_000_000_000_000);
    let native = render_erc7730_pages_with_signer_checked(
        &native_tx,
        &native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("render Layerswap native funding");
    assert_eq!(
        native.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(native.transcript_receipt.range_matches(&native.pages, 0));
    assert_all_pages_printable(&native.pages);
    let native_intent = page_strs(&native.pages, intent_page_index(&native.pages))[0].clone();
    assert_eq!(native_intent, "Forward ETH");
    assert!(!native_intent.to_ascii_lowercase().contains("swap"));
    assert_raw_word_pages(&native.pages, "Reference ID", &reference_id);
    assert_full_address_field_page(&native.pages, "Receiver", &receiver);
    let native_amount = page_strs(
        &native.pages,
        find_page_by_label(&native.pages, "ETH amount"),
    )
    .concat();
    assert!(
        native_amount.contains("1 ETH"),
        "exact forwarded value missing: {native_amount:?}"
    );

    let assert_native_mutation = |tx: &Eip1559Tx, calldata: &[u8], operand: &str| {
        let mutated = render_erc7730_pages_with_signer_checked(
            tx,
            calldata,
            &verified,
            None,
            &resolver,
            &signer,
        )
        .unwrap_or_else(|error| panic!("render mutated native {operand}: {error:?}"));
        assert_ne!(
            mutated.pages.as_slice(),
            native.pages.as_slice(),
            "mutating signed native {operand} must change trusted pages"
        );
        assert!(
            !native
                .transcript_receipt
                .exact_match(&mutated.transcript_receipt),
            "mutating signed native {operand} must change transcript receipt"
        );
    };

    let mut mutated_id = reference_id;
    mutated_id[31] ^= 1;
    let mutated_id_calldata = calldata_static(NATIVE, &[mutated_id, abi_address_word(receiver)]);
    assert_native_mutation(&native_tx, &mutated_id_calldata, "reference id");

    let mut mutated_receiver = receiver;
    mutated_receiver[19] ^= 1;
    let mutated_receiver_calldata = calldata_static(
        NATIVE,
        &[reference_id, abi_address_word(mutated_receiver)],
    );
    assert_native_mutation(&native_tx, &mutated_receiver_calldata, "receiver");

    let mut mutated_value_tx = envelope(CHAIN_ID, entry.contract);
    mutated_value_tx.value = u256_from_u64(2_000_000_000_000_000_000);
    assert_native_mutation(&mutated_value_tx, &native_calldata, "value");

    let mut trailing_native = native_calldata.clone();
    trailing_native.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &native_tx,
            &trailing_native,
            &verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));

    let token: [u8; 20] = hex::decode("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
        .unwrap()
        .try_into()
        .unwrap();
    let amount = u256_from_u64(1_000_000);
    let token_metadata = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: token,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let erc20_calldata = calldata_static(
        ERC20,
        &[
            reference_id,
            abi_address_word(token),
            abi_address_word(receiver),
            amount.0,
        ],
    );
    assert_eq!(&erc20_calldata[..4], &ERC20_SELECTOR);
    let erc20_tx = envelope(CHAIN_ID, entry.contract);
    let erc20 = render_erc7730_pages_with_signer_checked(
        &erc20_tx,
        &erc20_calldata,
        &verified,
        Some(&token_metadata),
        &resolver,
        &signer,
    )
    .expect("render Layerswap ERC20 funding");
    assert_eq!(
        erc20.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert!(erc20.transcript_receipt.range_matches(&erc20.pages, 0));
    assert_all_pages_printable(&erc20.pages);
    let erc20_intent = page_strs(&erc20.pages, intent_page_index(&erc20.pages))[0].clone();
    assert_eq!(erc20_intent, "Forward token");
    assert!(!erc20_intent.to_ascii_lowercase().contains("swap"));
    assert_raw_word_pages(&erc20.pages, "Reference ID", &reference_id);
    assert_full_address_field_page(&erc20.pages, "Token contract", &token);
    assert_full_address_field_page(&erc20.pages, "Receiver", &receiver);
    let requested_amount = page_strs(
        &erc20.pages,
        find_page_by_label(&erc20.pages, "Requested amount"),
    )
    .concat();
    assert!(
        requested_amount.contains("1 USDC"),
        "signed transferFrom request missing: {requested_amount:?}"
    );

    let assert_erc20_mutation = |calldata: &[u8], operand: &str| {
        match render_erc7730_pages_with_signer_checked(
            &erc20_tx,
            calldata,
            &verified,
            Some(&token_metadata),
            &resolver,
            &signer,
        ) {
            Ok(mutated) => {
                assert_ne!(
                    mutated.pages.as_slice(),
                    erc20.pages.as_slice(),
                    "mutating signed ERC20 {operand} must change trusted pages"
                );
                assert!(
                    !erc20
                        .transcript_receipt
                        .exact_match(&mutated.transcript_receipt),
                    "mutating signed ERC20 {operand} must change transcript receipt"
                );
            }
            Err(_) => {}
        }
    };
    let mut mutation_words = [
        reference_id,
        abi_address_word(token),
        abi_address_word(receiver),
        amount.0,
    ];
    for (word, operand) in [
        (0usize, "reference id"),
        (1, "token"),
        (2, "receiver"),
        (3, "requested amount"),
    ] {
        mutation_words[word][31] ^= 1;
        let mutated = calldata_static(ERC20, &mutation_words);
        assert_erc20_mutation(&mutated, operand);
        mutation_words[word][31] ^= 1;
    }

    let mut trailing_erc20 = erc20_calldata.clone();
    trailing_erc20.push(0);
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &erc20_tx,
            &trailing_erc20,
            &verified,
            Some(&token_metadata),
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 static calldata trailing"
        ))
    ));

    for (tx, calldata, metadata, route) in [
        (&native_tx, native_calldata.as_slice(), None, NATIVE),
        (
            &erc20_tx,
            erc20_calldata.as_slice(),
            Some(&token_metadata),
            ERC20,
        ),
    ] {
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let pages = pick_sign_pages(
            tx,
            calldata,
            &signer,
            None,
            None,
            None,
            Some(&verified),
            metadata,
            None,
            &resolver,
            &mut proofs,
        )
        .unwrap_or_else(|error| panic!("dispatcher selects {route}: {error:?}"));
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(&pages, tx, false, &mut verdict);
        assert_eq!(verdict, crate::fi::OK_SENTINEL);

        let mut absent = DispatchPageProofs::new();
        absent.fail_initialize();
        assert!(
            pick_sign_pages(
                tx,
                calldata,
                &signer,
                None,
                None,
                None,
                None,
                metadata,
                None,
                &resolver,
                &mut absent,
            )
            .is_err(),
            "known {route} must hard-refuse when its proof is absent"
        );
    }

    assert!(registry
        .known_calls
        .contains(&(CHAIN_ID, entry.contract, NATIVE_SELECTOR)));
    assert!(registry
        .known_calls
        .contains(&(CHAIN_ID, entry.contract, ERC20_SELECTOR)));
    assert!(registry
        .known_calls
        .contains(&(CHAIN_ID, entry.contract, ADMIN_SELECTOR)));
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &registry.known_calls_bloom,
        CHAIN_ID,
        &entry.contract,
        &ADMIN_SELECTOR
    ));
    assert!(matches!(
        render_erc7730_pages_with_signer_checked(
            &erc20_tx,
            &ADMIN_SELECTOR,
            &verified,
            None,
            &resolver,
            &signer,
        ),
        Err(crate::tx::erc7730_render::RenderErr::NoFormat)
    ));
    let mut omitted_admin = DispatchPageProofs::new();
    omitted_admin.fail_initialize();
    assert!(pick_sign_pages(
        &erc20_tx,
        &ADMIN_SELECTOR,
        &signer,
        None,
        None,
        None,
        Some(&verified),
        None,
        None,
        &resolver,
        &mut omitted_admin,
    )
    .is_err());

    let optimism_chain = 10;
    assert!(!registry.entries.iter().any(|candidate| {
        candidate.source.file_name().and_then(|name| name.to_str()) == Some(SOURCE)
            && candidate.chain_id == optimism_chain
    }));
    assert!(registry
        .known_calls
        .contains(&(optimism_chain, entry.contract, NATIVE_SELECTOR)));
    let optimism_tx = envelope(optimism_chain, entry.contract);
    let mut excluded = DispatchPageProofs::new();
    excluded.fail_initialize();
    assert!(pick_sign_pages(
        &optimism_tx,
        &native_calldata,
        &signer,
        None,
        None,
        None,
        None,
        None,
        None,
        &resolver,
        &mut excluded,
    )
    .is_err());

    assert_eq!(
        cross_check_contract(&verified.ir, optimism_chain, &entry.contract),
        Err(BindingError::ChainIdMismatch)
    );
    let mut tampered_bundle = bundle;
    *tampered_bundle.last_mut().expect("proof byte") ^= 1;
    assert!(verify_erc7730_bundle(&tampered_bundle, &registry.root).is_err());
}
