//! ERC-7730 clear-signing descriptor compiler.
//!
//! Reads JSON descriptors from a directory (one descriptor per file,
//! conforming to the ERC-7730 v2 schema at
//! <https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/specs/erc7730-v2.schema.json>),
//! enforces the ERC-8176 attestation policy from `policy.toml`, and
//! emits one binary IR per `(chainId, contract)` deployment. The IRs
//! are Merkle-tree-hashed into `ERC7730_DESCRIPTORS_ROOT`, pinned in
//! `secure/src/db_roots.rs`.
//!
//! Wire layouts here match the on-device parser in
//! `pqsigner_erc7730::ir`. The 134-byte IR header uses **big-endian**
//! integers (unlike the LE-encoded ERC20 / Names / Selectors DBs); see
//! `docs/handoff-erc7730-phase2.md` "Endianness flip" gotcha.
//!
//! ## Catalog blob layout (`tools/companion-stub/erc7730_db.bin`)
//!
//! ```text
//!   magic[4]              = "P730"
//!   version_le(4)         = ERC7730_DB_VERSION = 1
//!   flags_le(4)           = reserved (0)
//!   entry_cnt_le(4)
//!   ir_pool_off_le(4)
//!   ir_pool_size_le(4)
//!   proof_depth_le(4)
//!   proofs_off_le(4)
//!   // 32-byte header
//!
//!   entries[entry_cnt] (72 B each):
//!     chain_id_le(8) | contract(20) | primary_type_hash(32)
//!     | context_kind(1) | _pad(3) | ir_off_le(4) | ir_len_le(4)
//!
//!   ir_pool (concatenated IR bytes; ir_off is into this region)
//!
//!   proofs (entry_cnt * proof_depth * 32 bytes)
//! ```
//!
//! Sort order: `(chain_id, contract, primary_type_hash, context_kind)`.
//! Companion does a binary search by `(chain_id, to)` and emits the
//! trailer that `pqsigner_erc7730::bundle::verify_erc7730_bundle`
//! consumes.
//!
//! ## ERC-8176 policy
//!
//! Read from `secure/data/erc7730/policy.toml`. In dev mode
//! (`allow_unattested_dev_descriptors = true`) every descriptor is
//! accepted regardless of attestations; CI MUST reject production
//! builds with that flag on. Production mode requires
//! `min_attesters` ≥ N independent CAIP-2 identities from
//! `trusted_attesters`. Today's seed corpus is hand-pulled from the
//! upstream registry without attestations, so dev mode is on by
//! default. Phase 3+ wires the registry-mirror attestation chain.

use crate::merkle::{node_hash, verify_proof, MerkleTree};
use pqsigner_erc7730::bundle::{leaf_hash, verify_erc7730_bundle};
use pqsigner_erc7730::ir::{
    Erc7730Ir, CONTRACT_NAME_FIELD_LEN, CTX_CONTRACT, CTX_EIP712, HEADER_LEN, MAX_FIELDS_PER_FORMAT,
    MAX_FORMATS, MAX_IR_LEN, OWNER_FIELD_LEN, SCHEMA_VER,
};
use pqsigner_tx_core::hash::keccak256;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────
// Catalog header constants (mirrored from the other on-disk DBs).
// ─────────────────────────────────────────────────────────────────────

pub const ERC7730_DB_MAGIC: [u8; 4] = *b"P730";
pub const ERC7730_DB_VERSION: u32 = 1;
pub const ERC7730_DB_HEADER_LEN: usize = 32;
pub const ERC7730_DB_ENTRY_LEN: usize = 72;

// ─────────────────────────────────────────────────────────────────────
// Pool TLV constants (Phase 5 walker MUST match these byte-for-byte).
// ─────────────────────────────────────────────────────────────────────

const PATHOP_ROOT_STRUCT: u8 = 0x10;
const PATHOP_ROOT_CONTAINER: u8 = 0x11;
const PATHOP_ROOT_METADATA: u8 = 0x12;
const PATHOP_FIELD_IDX: u8 = 0x20;
const PATHOP_ARRAY_IDX: u8 = 0x21;
const PATHOP_ARRAY_SLICE: u8 = 0x22;
const PATHOP_ARRAY_LAST: u8 = 0x23;
const PATHOP_ARRAY_ALL: u8 = 0x24;

const FMT_RAW: u8 = 0x01;
const FMT_AMOUNT: u8 = 0x02;
const FMT_TOKEN_AMOUNT: u8 = 0x03;
const FMT_NFT_NAME: u8 = 0x04;
const FMT_DATE: u8 = 0x05;
const FMT_DURATION: u8 = 0x06;
const FMT_ADDRESS_NAME: u8 = 0x07;
const FMT_ENUM: u8 = 0x08;
const FMT_UNIT: u8 = 0x09;
const FMT_CALLDATA: u8 = 0x0A;
const FMT_CHAIN_ID: u8 = 0x0B;
const FMT_TOKEN_TICKER: u8 = 0x0C;
const FMT_INTEROP_ADDR_NAME: u8 = 0x0D;
const FMT_ENCRYPTED: u8 = 0x0E;

const PARAM_TOKEN_PATH: u8 = 0x30;
const PARAM_TOKEN: u8 = 0x31;
const PARAM_THRESHOLD: u8 = 0x32;
const PARAM_MESSAGE: u8 = 0x33;
const PARAM_ADDR_TYPES: u8 = 0x34;
const PARAM_ADDR_SOURCES: u8 = 0x35;
const PARAM_DATE_ENCODING: u8 = 0x36;
const PARAM_ENUM_REF: u8 = 0x37;
const PARAM_DECIMALS: u8 = 0x38;
const PARAM_BASE: u8 = 0x39;
const PARAM_PREFIX: u8 = 0x3A;
const PARAM_SUFFIX: u8 = 0x3B;
const PARAM_NESTED_SELECTOR: u8 = 0x3C;
const PARAM_NESTED_CALLEE: u8 = 0x3D;
const PARAM_FALLBACK_LABEL: u8 = 0x3E;
const PARAM_VISIBILITY: u8 = 0x3F;

// Visibility byte values (matching `pqsigner_erc7730::ir::Visibility`).
const VIS_ALWAYS: u8 = 0x00;
const VIS_NEVER: u8 = 0x01;
const VIS_OPTIONAL: u8 = 0x02;
const VIS_IF_NOT_IN: u8 = 0x03;
const VIS_MUST_MATCH: u8 = 0x04;

// Address-type bitset (PARAM_ADDR_TYPES payload).
const ADDR_TYPE_WALLET: u8 = 0x01;
const ADDR_TYPE_EOA: u8 = 0x02;
const ADDR_TYPE_CONTRACT: u8 = 0x04;
const ADDR_TYPE_NFT_COLLECTION: u8 = 0x08;
const ADDR_TYPE_TOKEN: u8 = 0x10;
const ADDR_TYPE_COLLECTION: u8 = 0x20;

// Address-source bitset (PARAM_ADDR_SOURCES payload).
const ADDR_SRC_LOCAL: u8 = 0x01;
const ADDR_SRC_ENS: u8 = 0x02;
const ADDR_SRC_ETHERSCAN: u8 = 0x04;
const ADDR_SRC_REGISTRY: u8 = 0x08;

// Date-encoding (PARAM_DATE_ENCODING payload).
const DATE_ENC_TIMESTAMP: u8 = 0x00;
const DATE_ENC_BLOCKHEIGHT: u8 = 0x01;

// Maximum bytes per pool TLV payload — same cap the on-device walker
// uses (Phase 5 will enforce).
const MAX_POOL_TLV_PAYLOAD: usize = 254;
// Maximum bytes per path program. Single byte length prefix → 255.
const MAX_PATH_PROGRAM_LEN: usize = 255;

// ─────────────────────────────────────────────────────────────────────
// JSON shapes (subset of the ERC-7730 v2 schema we ingest today).
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "$schema")]
    _schema: Option<String>,
    /// `includes` reference. Phase 2 rejects descriptors that use this
    /// field — the registry's templated permit / common-EIP712 entries
    /// land in Phase 3 once we wire the registry-mirror submodule.
    #[serde(default)]
    includes: Option<String>,
    context: Context,
    metadata: Metadata,
    display: Display,
}

#[derive(Debug, Deserialize)]
struct Context {
    #[serde(rename = "$id", default)]
    id: Option<String>,
    #[serde(default)]
    contract: Option<ContractContext>,
    #[serde(default)]
    eip712: Option<Eip712Context>,
}

#[derive(Debug, Deserialize)]
struct ContractContext {
    deployments: Vec<Deployment>,
    // `abi` field is deprecated in v2 — parameter names live in the
    // format key strings now. We deliberately ignore it.
}

#[derive(Debug, Deserialize)]
struct Eip712Context {
    #[serde(default)]
    deployments: Option<Vec<Deployment>>,
    #[serde(default)]
    domain: Option<Eip712Domain>,
    #[serde(rename = "domainSeparator", default)]
    domain_separator: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Eip712Domain {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(rename = "chainId", default)]
    chain_id: Option<u64>,
    #[serde(rename = "verifyingContract", default)]
    verifying_contract: Option<String>,
    #[serde(default)]
    salt: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Deployment {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
}

#[derive(Debug, Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    owner: Option<String>,
    /// Free-form `info` block (URL, deploymentDate, legalName, …). We
    /// surface it on the review file only; the on-device IR doesn't
    /// carry it.
    #[serde(default)]
    _info: Option<serde_json::Value>,
    #[serde(default)]
    constants: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    enums: Option<serde_json::Map<String, serde_json::Value>>,
    /// Per-descriptor token metadata used by the v2 spec to default
    /// `tokenAmount` decimals/symbol when no `tokenPath` is supplied.
    /// Phase 2 doesn't depend on this since the seed corpus carries
    /// explicit `tokenPath` everywhere.
    #[serde(default)]
    _token: Option<serde_json::Value>,
    #[serde(rename = "contractName", default)]
    contract_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Display {
    formats: BTreeMap<String, Format>,
}

#[derive(Debug, Deserialize)]
struct Format {
    #[serde(rename = "$id", default)]
    _id: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    fields: Vec<FieldDef>,
}

#[derive(Debug, Deserialize)]
struct FieldDef {
    path: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    visible: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────
// Policy.toml shape.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub min_attesters: usize,
    #[serde(default)]
    pub trusted_attesters: Vec<String>,
    #[serde(default)]
    pub allow_unattested_dev_descriptors: bool,
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Compile every `*.json` under `input_dir` with the policy at
/// `policy_path` BUT override `allow_unattested_dev_descriptors` per
/// `force_production`. When `force_production = true`, the override
/// forces production attestation enforcement regardless of the TOML
/// file's value — this is what `dbgen --policy production` wires.
///
/// `force_production = false` keeps the TOML value as-is (which today
/// means dev mode — no attestation requirement). Production CI must
/// build with `force_production = true` and assert the corpus rebuilds
/// clean: a CI matrix entry runs `cargo run -p dbgen -- --policy
/// production` and fails loudly if any descriptor lacks the required
/// attestations.
pub fn build_db_with_policy_override(
    input_dir: &Path,
    policy_path: &Path,
    force_production: bool,
    registry_root: Option<&Path>,
) -> Result<Erc7730BuildResult, String> {
    let mut policy = load_policy(policy_path)?;
    if force_production {
        policy.allow_unattested_dev_descriptors = false;
    }
    build_db_inner(input_dir, &policy, registry_root)
}

// ─────────────────────────────────────────────────────────────────────
// Public build result.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Emitted {
    pub source: PathBuf,
    pub descriptor_id: String,
    pub descriptor_hash: [u8; 32],
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub context_kind: u8,
    pub primary_type_hash: [u8; 32],
    pub ir_bytes: Vec<u8>,
    pub leaf_index: usize,
}

pub struct Erc7730BuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub entries: Vec<Emitted>,
    pub review_text: String,
    pub leaf_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// Top-level build.
// ─────────────────────────────────────────────────────────────────────

/// Compile every `*.json` under `input_dir` against `policy_path` and
/// emit the catalog blob + Merkle root. Caller is expected to also
/// run `round_trip_check` before writing the artifacts to disk.
pub fn build_db(
    input_dir: &Path,
    policy_path: &Path,
) -> Result<Erc7730BuildResult, String> {
    let policy = load_policy(policy_path)?;
    build_db_inner(input_dir, &policy, None)
}

fn build_db_inner(
    input_dir: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
) -> Result<Erc7730BuildResult, String> {
    let mut sources: Vec<PathBuf> = fs::read_dir(input_dir)
        .map_err(|e| format!("read_dir {}: {e}", input_dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    sources.sort();

    if sources.is_empty() {
        return Err(format!(
            "no .json descriptors found under {}",
            input_dir.display()
        ));
    }

    let mut emitted: Vec<Emitted> = Vec::with_capacity(sources.len() * 2);
    for src in &sources {
        let entries = compile_descriptor(src, policy, registry_root).map_err(|e| {
            format!("{}: {e}", src.display())
        })?;
        emitted.extend(entries);
    }

    if emitted.is_empty() {
        return Err("no IR entries emitted (every descriptor rejected by policy)".to_string());
    }

    // 1. Sort by (chain_id, contract, primary_type_hash, context_kind).
    emitted.sort_by(|a, b| {
        (a.chain_id, a.contract, a.primary_type_hash, a.context_kind).cmp(
            &(b.chain_id, b.contract, b.primary_type_hash, b.context_kind),
        )
    });

    // 2. Reject (chain_id, contract, primary_type_hash) duplicates —
    //    almost always a curation bug.
    for w in emitted.windows(2) {
        if w[0].chain_id == w[1].chain_id
            && w[0].contract == w[1].contract
            && w[0].primary_type_hash == w[1].primary_type_hash
            && w[0].context_kind == w[1].context_kind
        {
            return Err(format!(
                "duplicate (chain_id={}, contract=0x{}, primary_type_hash=0x{}, ctx={}) — \
                 sources: {} vs {}",
                w[0].chain_id,
                hex::encode(w[0].contract),
                hex::encode(w[0].primary_type_hash),
                w[0].context_kind,
                w[0].source.display(),
                w[1].source.display(),
            ));
        }
    }

    // 3. Assign leaf indices, compute leaf hashes, build the tree.
    for (i, e) in emitted.iter_mut().enumerate() {
        e.leaf_index = i;
    }
    let leaf_hashes: Vec<[u8; 32]> = emitted.iter().map(|e| leaf_hash(&e.ir_bytes)).collect();
    let tree = MerkleTree::build(leaf_hashes.clone());
    let root = tree.root();
    let proof_depth = tree.depth();

    // 4. Lay out the catalog blob.
    let entry_cnt = emitted.len();
    let entries_size = entry_cnt * ERC7730_DB_ENTRY_LEN;
    let ir_pool_off = ERC7730_DB_HEADER_LEN + entries_size;
    let ir_pool_size: usize = emitted.iter().map(|e| e.ir_bytes.len()).sum();
    let proofs_off = ir_pool_off + ir_pool_size;
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // ── Header (32 B) ────────────────────────────────────────────────
    blob.extend_from_slice(&ERC7730_DB_MAGIC);
    write_u32_le(&mut blob, ERC7730_DB_VERSION);
    write_u32_le(&mut blob, 0); // flags reserved
    write_u32_le(
        &mut blob,
        entry_cnt
            .try_into()
            .map_err(|_| "entry_cnt > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_off
            .try_into()
            .map_err(|_| "ir_pool_off > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_size
            .try_into()
            .map_err(|_| "ir_pool_size > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proof_depth
            .try_into()
            .map_err(|_| "proof_depth > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proofs_off
            .try_into()
            .map_err(|_| "proofs_off > u32::MAX".to_string())?,
    );
    assert_eq!(blob.len(), ERC7730_DB_HEADER_LEN);

    // ── Entries (72 B each) ──────────────────────────────────────────
    let mut current_ir_off = 0u32;
    for e in &emitted {
        let entry_start = blob.len();
        blob.extend_from_slice(&e.chain_id.to_le_bytes()); // 8
        blob.extend_from_slice(&e.contract); // 20
        blob.extend_from_slice(&e.primary_type_hash); // 32
        blob.push(e.context_kind); // 1
        blob.extend_from_slice(&[0u8; 3]); // 3 pad
        write_u32_le(&mut blob, current_ir_off); // 4
        write_u32_le(
            &mut blob,
            e.ir_bytes
                .len()
                .try_into()
                .map_err(|_| "ir_len > u32::MAX".to_string())?,
        ); // 4
        debug_assert_eq!(blob.len() - entry_start, ERC7730_DB_ENTRY_LEN);
        current_ir_off = current_ir_off
            .checked_add(e.ir_bytes.len() as u32)
            .ok_or("ir_off overflow")?;
    }
    assert_eq!(blob.len(), ir_pool_off);

    // ── IR pool ──────────────────────────────────────────────────────
    for e in &emitted {
        blob.extend_from_slice(&e.ir_bytes);
    }
    assert_eq!(blob.len(), proofs_off);

    // ── Proofs ───────────────────────────────────────────────────────
    for i in 0..entry_cnt {
        let proof = tree.proof(i);
        debug_assert_eq!(proof.len(), proof_depth);
        for sib in &proof {
            blob.extend_from_slice(sib);
        }
    }
    assert_eq!(blob.len(), total_size);

    let review_text = render_review(&emitted, policy, &root);

    Ok(Erc7730BuildResult {
        blob,
        root,
        entries: emitted,
        review_text,
        leaf_count: entry_cnt,
    })
}

/// Round-trip every emitted IR back through the on-device parser +
/// Merkle verifier. Catches every shape of format drift between the
/// host compiler and `pqsigner_erc7730::bundle::verify_erc7730_bundle`.
pub fn round_trip_check(result: &Erc7730BuildResult) -> Result<(), String> {
    for e in &result.entries {
        // Parse the IR via the canonical on-device parser.
        let ir = Erc7730Ir::parse(&e.ir_bytes).map_err(|err| {
            format!(
                "round-trip parse failed for {}: {err:?}",
                e.source.display()
            )
        })?;
        if ir.chain_id != e.chain_id {
            return Err(format!(
                "round-trip chain_id mismatch in {}: wrote {} read {}",
                e.source.display(),
                e.chain_id,
                ir.chain_id
            ));
        }
        if ir.contract != e.contract {
            return Err(format!(
                "round-trip contract mismatch in {}: wrote 0x{} read 0x{}",
                e.source.display(),
                hex::encode(e.contract),
                hex::encode(ir.contract)
            ));
        }
        if ir.descriptor_hash != e.descriptor_hash {
            return Err(format!(
                "round-trip descriptor_hash mismatch in {}",
                e.source.display()
            ));
        }

        // Walk the proof region back to the root.
        let proof = extract_proof(&result.blob, e.leaf_index, result_proof_depth(&result.blob)?)?;
        if !verify_proof_via_dbgen(&e.ir_bytes, e.leaf_index, &proof, &result.root) {
            return Err(format!(
                "round-trip dbgen-Merkle proof failed for {}",
                e.source.display()
            ));
        }

        // Also exercise the on-device bundle verifier with a synthetic
        // trailer.
        let bundle = synth_bundle(&e.ir_bytes, e.leaf_index as u32, &proof);
        verify_erc7730_bundle(&bundle, &result.root).map_err(|err| {
            format!(
                "round-trip on-device bundle verify failed for {}: {err:?}",
                e.source.display()
            )
        })?;
    }
    Ok(())
}

fn result_proof_depth(blob: &[u8]) -> Result<usize, String> {
    if blob.len() < ERC7730_DB_HEADER_LEN {
        return Err("blob too small for header".to_string());
    }
    let pd = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    Ok(pd)
}

fn extract_proof(
    blob: &[u8],
    leaf_index: usize,
    proof_depth: usize,
) -> Result<Vec<[u8; 32]>, String> {
    let entry_cnt = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    if leaf_index >= entry_cnt {
        return Err(format!("leaf_index {leaf_index} >= entry_cnt {entry_cnt}"));
    }
    let base = proofs_off + leaf_index * proof_depth * 32;
    if base + proof_depth * 32 > blob.len() {
        return Err("proof region out of bounds".to_string());
    }
    let mut out = Vec::with_capacity(proof_depth);
    for j in 0..proof_depth {
        let off = base + j * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&blob[off..off + 32]);
        out.push(h);
    }
    Ok(out)
}

fn verify_proof_via_dbgen(
    ir_bytes: &[u8],
    leaf_index: usize,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    // Wraps `dbgen::merkle::verify_proof`, whose canonical input is
    // the raw leaf bytes (and which then prefixes 0x00 internally — the
    // same scheme as `pqsigner_erc7730::bundle::leaf_hash`).
    verify_proof(ir_bytes, leaf_index, proof, root)
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

// ─────────────────────────────────────────────────────────────────────
// Per-descriptor compilation.
// ─────────────────────────────────────────────────────────────────────

fn compile_descriptor(
    path: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
) -> Result<Vec<Emitted>, String> {
    let raw = fs::read(path).map_err(|e| format!("read: {e}"))?;
    let mut json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("parse: {e}"))?;

    // ERC-8176 policy gate.
    enforce_policy(&json, policy)?;

    // Phase 5: resolve top-level `includes` references against the
    // local registry mirror at `--registry-root`. The reference can
    // be a relative path (`./templates/erc2612-permit.json`) or a
    // github.com URL whose path segment after the repo name is
    // joined with `registry_root`. We deep-merge the referenced
    // JSON into the current document (current keys win) and recurse
    // until no `includes` remains.
    let mut depth = 0usize;
    while let Some(inc) = json
        .get("includes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        depth += 1;
        if depth > 8 {
            return Err("includes recursion depth > 8 — refusing".to_string());
        }
        let root = registry_root.ok_or_else(|| {
            format!(
                "`includes: \"{inc}\"` requires `--registry-root <dir>`. \
                 See secure/data/erc7730/REGISTRY_MIRROR.md."
            )
        })?;
        let inc_path = resolve_include_path(root, path, &inc)?;
        let inc_raw = fs::read(&inc_path)
            .map_err(|e| format!("read include {}: {e}", inc_path.display()))?;
        let inc_json: serde_json::Value = serde_json::from_slice(&inc_raw)
            .map_err(|e| format!("parse include {}: {e}", inc_path.display()))?;
        // Remove the `includes` key from current json before merge so
        // the loop terminates if the include itself has no further
        // `includes`.
        if let Some(obj) = json.as_object_mut() {
            obj.remove("includes");
        }
        json = merge_descriptors(inc_json, json);
    }

    let descriptor: Descriptor =
        serde_json::from_value(json.clone()).map_err(|e| format!("schema: {e}"))?;

    // After include-resolution `descriptor.includes` must be empty.
    if let Some(inc) = descriptor.includes.as_deref() {
        return Err(format!(
            "post-merge: residual `includes: \"{inc}\"` (recursion didn't reach a leaf)"
        ));
    }

    // Compute the descriptor_hash once over the canonical JSON.
    let descriptor_hash = sha256_of(&jcs_canonicalize(&json)?);

    // Extract the descriptor ID (used for the review file).
    let descriptor_id = descriptor
        .context
        .id
        .clone()
        .or_else(|| descriptor.metadata.contract_name.clone())
        .or_else(|| descriptor.metadata.owner.clone())
        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

    let owner = clean_ascii_truncated(
        descriptor.metadata.owner.as_deref().unwrap_or(""),
        OWNER_FIELD_LEN - 1,
    );
    let contract_name = clean_ascii_truncated(
        descriptor
            .metadata
            .contract_name
            .as_deref()
            .or(descriptor.context.id.as_deref())
            .unwrap_or(""),
        CONTRACT_NAME_FIELD_LEN - 1,
    );

    // Resolve constants and enums into the IR pool (lazily, only
    // entries actually referenced get emitted).
    let mut ctx = CompileCtx {
        constants: descriptor.metadata.constants.unwrap_or_default(),
        enums: descriptor.metadata.enums.unwrap_or_default(),
        descriptor_hash,
        owner: owner.clone(),
        contract_name: contract_name.clone(),
    };

    // Decide context kind + collect deployment tuples.
    let (context_kind, deployments) =
        resolve_deployments(&descriptor.context).map_err(|e| format!("deployments: {e}"))?;

    let (formats_section, pool_initial) = compile_formats(&descriptor.display, context_kind, &mut ctx)?;

    // For each deployment we emit a distinct IR (same body, different
    // header bytes). The pool/format bytes are byte-identical between
    // deployments — the leaf-level differences live entirely in the
    // 134-byte header.
    let mut out = Vec::with_capacity(deployments.len());
    for dep in deployments {
        let (chain_id, contract_addr, domain_separator, primary_type_hash) =
            resolve_per_deployment(context_kind, &descriptor.context, &descriptor.display, &dep)?;

        let ir_bytes =
            build_ir(context_kind, chain_id, contract_addr, &domain_separator, &ctx, &pool_initial, &formats_section)?;

        if ir_bytes.len() > MAX_IR_LEN {
            return Err(format!(
                "IR {} exceeds MAX_IR_LEN ({} > {})",
                descriptor_id,
                ir_bytes.len(),
                MAX_IR_LEN
            ));
        }

        out.push(Emitted {
            source: path.to_path_buf(),
            descriptor_id: descriptor_id.clone(),
            descriptor_hash,
            chain_id,
            contract: contract_addr,
            context_kind,
            primary_type_hash,
            ir_bytes,
            leaf_index: 0, // filled in by build_db after sorting
        });
    }

    Ok(out)
}

fn resolve_deployments(ctx: &Context) -> Result<(u8, Vec<Deployment>), String> {
    if let Some(c) = &ctx.contract {
        if c.deployments.is_empty() {
            return Err("contract.deployments is empty".to_string());
        }
        Ok((
            CTX_CONTRACT,
            c.deployments.iter().map(|d| Deployment {
                chain_id: d.chain_id,
                address: d.address.clone(),
            }).collect(),
        ))
    } else if let Some(e) = &ctx.eip712 {
        let from_deployments = e.deployments.clone().unwrap_or_default();
        let from_domain = match (&e.domain, &e.domain_separator) {
            (
                Some(Eip712Domain {
                    chain_id: Some(cid),
                    verifying_contract: Some(addr),
                    ..
                }),
                _,
            ) => vec![Deployment {
                chain_id: *cid,
                address: addr.clone(),
            }],
            _ => Vec::new(),
        };
        let merged: Vec<Deployment> = if !from_deployments.is_empty() {
            from_deployments
        } else if !from_domain.is_empty() {
            from_domain
        } else {
            return Err(
                "eip712 context lacks both `deployments` and a fully-specified `domain.{chainId,verifyingContract}`"
                    .to_string(),
            );
        };
        Ok((CTX_EIP712, merged))
    } else {
        Err("context has neither `contract` nor `eip712`".to_string())
    }
}

fn resolve_per_deployment(
    context_kind: u8,
    ctx: &Context,
    display: &Display,
    dep: &Deployment,
) -> Result<(u64, [u8; 20], [u8; 32], [u8; 32]), String> {
    let contract = parse_address(&dep.address)?;
    if context_kind == CTX_CONTRACT {
        return Ok((dep.chain_id, contract, [0u8; 32], [0u8; 32]));
    }
    // EIP-712 path: compute domain_separator + primary_type_hash.
    let eip = ctx
        .eip712
        .as_ref()
        .ok_or_else(|| "expected eip712 context".to_string())?;
    let domain_sep: [u8; 32] = if let Some(s) = &eip.domain_separator {
        parse_hex32(s)?
    } else {
        let mut domain = eip.domain.clone().unwrap_or_default();
        // Pin the per-deployment values.
        domain.chain_id = Some(dep.chain_id);
        domain.verifying_contract = Some(dep.address.clone());
        compute_domain_separator(&domain)?
    };

    // Use the *first* format's primary type as the catalog
    // discriminator. The IR's formats table carries the full set so
    // the walker can still dispatch on the actual signed typehash.
    let primary_type_hash = display
        .formats
        .keys()
        .next()
        .map(|sig| keccak256(sig.as_bytes()))
        .unwrap_or([0u8; 32]);

    Ok((dep.chain_id, contract, domain_sep, primary_type_hash))
}

// ─────────────────────────────────────────────────────────────────────
// Format / field compilation.
// ─────────────────────────────────────────────────────────────────────

/// Side-table the compiler builds while walking a single descriptor.
struct CompileCtx {
    constants: serde_json::Map<String, serde_json::Value>,
    enums: serde_json::Map<String, serde_json::Value>,
    #[allow(dead_code)]
    descriptor_hash: [u8; 32],
    #[allow(dead_code)]
    owner: String,
    #[allow(dead_code)]
    contract_name: String,
}

/// Pool-with-cache used while compiling a single descriptor. Interns
/// repeated paths / param blobs to keep the IR compact (the seed
/// corpus has plenty of repeated `"@.to"` / `["eoa","contract"]`
/// addressName params).
struct Pool {
    buf: Vec<u8>,
    interned: BTreeMap<Vec<u8>, u16>,
}

impl Pool {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            interned: BTreeMap::new(),
        }
    }

    /// Push raw bytes (no interning). Returns the offset, or an error
    /// if the resulting offset would overflow u16.
    fn push_raw(&mut self, bytes: &[u8]) -> Result<u16, String> {
        let off = self.buf.len();
        if off + bytes.len() > u16::MAX as usize {
            return Err(format!(
                "IR pool overflow ({} + {} > {})",
                off,
                bytes.len(),
                u16::MAX
            ));
        }
        self.buf.extend_from_slice(bytes);
        Ok(off as u16)
    }

    /// Intern a byte slice — returns the existing offset if already
    /// present, otherwise pushes and returns the new offset.
    fn intern(&mut self, bytes: &[u8]) -> Result<u16, String> {
        if let Some(&off) = self.interned.get(bytes) {
            return Ok(off);
        }
        let off = self.push_raw(bytes)?;
        self.interned.insert(bytes.to_vec(), off);
        Ok(off)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

fn compile_formats(
    display: &Display,
    context_kind: u8,
    ctx: &mut CompileCtx,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let n = display.formats.len();
    if n == 0 {
        return Err("display.formats is empty".to_string());
    }
    if n > MAX_FORMATS {
        return Err(format!(
            "format count {n} > MAX_FORMATS ({MAX_FORMATS})"
        ));
    }

    let mut pool = Pool::new();

    // First pre-intern referenced enum tables so $ref resolution can
    // emit pool offsets without re-walking.
    let mut enum_offsets: BTreeMap<String, u16> = BTreeMap::new();

    // Pre-scan each format's fields for $.metadata.enums.X references.
    for (_sig, fmt) in display.formats.iter() {
        for field in &fmt.fields {
            if let Some(params) = &field.params {
                if let Some(refstr) = params
                    .get("$ref")
                    .and_then(|v| v.as_str())
                    .or_else(|| params.get("ref").and_then(|v| v.as_str()))
                {
                    if let Some(name) = refstr.strip_prefix("$.metadata.enums.") {
                        if !enum_offsets.contains_key(name) {
                            let table = ctx
                                .enums
                                .get(name)
                                .ok_or_else(|| format!("enum `{name}` referenced but not defined"))?;
                            let encoded = encode_enum_table(table).map_err(|e| {
                                format!("enum `{name}` encoding: {e}")
                            })?;
                            let off = pool.push_raw(&encoded)?;
                            enum_offsets.insert(name.to_string(), off);
                        }
                    }
                }
            }
        }
    }

    // Compile each format.
    let mut formats_buf: Vec<u8> = Vec::new();
    formats_buf.push(n as u8);
    for (sig, fmt) in display.formats.iter() {
        compile_one_format(sig, fmt, context_kind, ctx, &mut pool, &enum_offsets, &mut formats_buf)?;
    }

    Ok((formats_buf, pool.into_bytes()))
}

fn compile_one_format(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let parsed = parse_format_key(sig).map_err(|e| format!("format `{sig}`: {e}"))?;

    // Selector / discriminator slot — 4 bytes.
    let selector: [u8; 4] = if context_kind == CTX_CONTRACT {
        // keccak256 of the types-only signature.
        let h = keccak256(parsed.types_signature.as_bytes());
        [h[0], h[1], h[2], h[3]]
    } else {
        // For EIP-712 the format key is a typed-data hash signature
        // like `Permit(address owner,address spender,uint256 value,
        // uint256 nonce,uint256 deadline)`. Use the first 4 bytes of
        // its keccak256 as the discriminator. The IR doc reserves only
        // 4 bytes here; widening to a full typehash is a Phase 3+
        // decision (see plan §3).
        let h = keccak256(sig.as_bytes());
        [h[0], h[1], h[2], h[3]]
    };

    // Sanity: field count.
    if fmt.fields.len() > MAX_FIELDS_PER_FORMAT {
        return Err(format!(
            "format `{sig}`: field count {} > MAX_FIELDS_PER_FORMAT ({MAX_FIELDS_PER_FORMAT})",
            fmt.fields.len()
        ));
    }

    let intent_raw = fmt.intent.as_deref().unwrap_or("Sign");
    let intent = clean_ascii_truncated(intent_raw, 254);
    if intent.is_empty() {
        return Err(format!(
            "format `{sig}`: empty / non-printable `intent` (was {intent_raw:?})"
        ));
    }

    // Compile every field's path + params first (so offsets are
    // stable before we emit the format header).
    let mut compiled: Vec<CompiledFieldOut> = Vec::with_capacity(fmt.fields.len());

    for (i, field) in fmt.fields.iter().enumerate() {
        let cf = compile_one_field(
            sig,
            i,
            field,
            context_kind,
            &parsed,
            ctx,
            pool,
            enum_offsets,
        )?;
        compiled.push(cf);
    }

    // Emit format header.
    out.extend_from_slice(&selector); // 4 B
    out.push(compiled.len() as u8); // 1 B field_count
    out.push(intent.len() as u8); // 1 B intent_len
    out.extend_from_slice(intent.as_bytes()); // intent_len B

    // Emit fields.
    for cf in &compiled {
        out.push(cf.format_op); // 1 B
        out.push(cf.label.len() as u8); // 1 B
        out.extend_from_slice(&cf.label); // label_len B
        out.extend_from_slice(&cf.path_off.to_be_bytes()); // 2 B
        out.extend_from_slice(&cf.param_off.to_be_bytes()); // 2 B
    }

    Ok(())
}

struct CompiledFieldOut {
    format_op: u8,
    label: Vec<u8>,
    path_off: u16,
    param_off: u16,
}

fn compile_one_field(
    sig: &str,
    field_idx: usize,
    field: &FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
) -> Result<CompiledFieldOut, String> {
    // 1. Compile the path bytecode.
    let path_program = compile_path(&field.path, context_kind, parsed)
        .map_err(|e| format!("format `{sig}` field[{field_idx}] path `{}`: {e}", field.path))?;
    if path_program.len() > MAX_PATH_PROGRAM_LEN {
        return Err(format!(
            "format `{sig}` field[{field_idx}] path program too long ({} > {MAX_PATH_PROGRAM_LEN})",
            path_program.len()
        ));
    }
    let mut path_blob = Vec::with_capacity(1 + path_program.len());
    path_blob.push(path_program.len() as u8);
    path_blob.extend_from_slice(&path_program);
    let path_off = pool.intern(&path_blob)?;

    // 2. Decide formatter opcode.
    let format_op = parse_format_name(field.format.as_deref().unwrap_or("raw"))?;

    // 3. Compile params + visibility into a single TLV blob.
    let param_blob = compile_params(
        sig,
        field_idx,
        format_op,
        field.params.as_ref(),
        field.visible.as_deref(),
        context_kind,
        parsed,
        ctx,
        enum_offsets,
    )?;
    let param_off = if param_blob.is_empty() {
        0u16
    } else {
        let mut blob_with_len = Vec::with_capacity(1 + param_blob.len());
        if param_blob.len() > MAX_POOL_TLV_PAYLOAD {
            return Err(format!(
                "format `{sig}` field[{field_idx}] param blob too long ({} > {MAX_POOL_TLV_PAYLOAD})",
                param_blob.len()
            ));
        }
        blob_with_len.push(param_blob.len() as u8);
        blob_with_len.extend_from_slice(&param_blob);
        pool.intern(&blob_with_len)?
    };

    // 4. Label.
    let label_raw = field.label.as_deref().unwrap_or("");
    let label = clean_ascii_truncated(label_raw, 254);
    if label.is_empty() && format_op != FMT_RAW {
        // A blank label on a *visible* field would render as a header-
        // less value page. Allow it on raw because some descriptors
        // (Aave's `referralCode` set to visible=never) intentionally
        // skip labels.
    }

    Ok(CompiledFieldOut {
        format_op,
        label: label.into_bytes(),
        path_off,
        param_off,
    })
}

fn compile_params(
    sig: &str,
    field_idx: usize,
    format_op: u8,
    params: Option<&serde_json::Value>,
    visible: Option<&str>,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    enum_offsets: &BTreeMap<String, u16>,
) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();

    // Visibility — encode only if not the default `always`.
    if let Some(v) = visible {
        let byte = match v {
            "always" => VIS_ALWAYS,
            "never" => VIS_NEVER,
            "optional" => VIS_OPTIONAL,
            "if_not_in" | "ifNotIn" => VIS_IF_NOT_IN,
            "must_match" | "mustMatch" => VIS_MUST_MATCH,
            other => {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] unknown `visible`: {other:?}"
                ))
            }
        };
        if byte != VIS_ALWAYS {
            push_tlv(&mut out, PARAM_VISIBILITY, &[byte])?;
        }
    }

    let Some(params) = params else {
        return Ok(out);
    };
    let params = params.as_object().ok_or_else(|| {
        format!("format `{sig}` field[{field_idx}] `params` is not an object")
    })?;

    // Per-formatter param dispatch.
    match format_op {
        FMT_TOKEN_AMOUNT => {
            if let Some(tp) = params.get("tokenPath").and_then(|v| v.as_str()) {
                let prog = compile_path(tp, context_kind, parsed)
                    .map_err(|e| format!("tokenPath `{tp}`: {e}"))?;
                push_tlv(&mut out, PARAM_TOKEN_PATH, &prog)?;
            }
            if let Some(t) = params.get("token").and_then(|v| v.as_str()) {
                let bytes = resolve_address_or_const(t, ctx)?;
                push_tlv(&mut out, PARAM_TOKEN, &bytes)?;
            }
            if let Some(th) = params.get("threshold") {
                let raw = match th {
                    serde_json::Value::String(s) => resolve_u256_or_const(s, ctx)?,
                    serde_json::Value::Number(n) => {
                        let mut b = [0u8; 32];
                        let v = n
                            .as_u64()
                            .ok_or_else(|| format!("threshold {n} not representable as u64"))?;
                        b[24..32].copy_from_slice(&v.to_be_bytes());
                        b
                    }
                    _ => return Err("threshold must be string or number".to_string()),
                };
                push_tlv(&mut out, PARAM_THRESHOLD, &raw)?;
            }
            if let Some(msg) = params.get("message").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(msg, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_MESSAGE, s.as_bytes())?;
            }
        }
        FMT_ADDRESS_NAME | FMT_INTEROP_ADDR_NAME => {
            if let Some(arr) = params.get("types").and_then(|v| v.as_array()) {
                let mut bits = 0u8;
                for kind in arr {
                    let k = kind.as_str().ok_or_else(|| {
                        "addressName `types` entry must be a string".to_string()
                    })?;
                    bits |= match k {
                        "wallet" => ADDR_TYPE_WALLET,
                        "eoa" => ADDR_TYPE_EOA,
                        "contract" => ADDR_TYPE_CONTRACT,
                        "nft_collection" | "nftCollection" => ADDR_TYPE_NFT_COLLECTION,
                        "token" => ADDR_TYPE_TOKEN,
                        "collection" => ADDR_TYPE_COLLECTION,
                        other => {
                            return Err(format!(
                                "addressName: unknown type `{other}`"
                            ))
                        }
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_TYPES, &[bits])?;
            }
            if let Some(arr) = params.get("sources").and_then(|v| v.as_array()) {
                let mut bits = 0u8;
                for src in arr {
                    let s = src.as_str().ok_or_else(|| {
                        "addressName `sources` entry must be a string".to_string()
                    })?;
                    bits |= match s {
                        "local" => ADDR_SRC_LOCAL,
                        "ens" => ADDR_SRC_ENS,
                        "etherscan" => ADDR_SRC_ETHERSCAN,
                        "registry" => ADDR_SRC_REGISTRY,
                        other => {
                            return Err(format!(
                                "addressName: unknown source `{other}`"
                            ))
                        }
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_SOURCES, &[bits])?;
            }
        }
        FMT_DATE => {
            if let Some(enc) = params.get("encoding").and_then(|v| v.as_str()) {
                let b = match enc {
                    "timestamp" => DATE_ENC_TIMESTAMP,
                    "blockheight" => DATE_ENC_BLOCKHEIGHT,
                    other => return Err(format!("date.encoding: unknown `{other}`")),
                };
                push_tlv(&mut out, PARAM_DATE_ENCODING, &[b])?;
            }
        }
        FMT_DURATION => {
            // No params today; the renderer always reads the value as
            // seconds. Reserved for future use.
        }
        FMT_ENUM => {
            let refstr = params
                .get("$ref")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("ref").and_then(|v| v.as_str()))
                .ok_or_else(|| "enum format requires `$ref`".to_string())?;
            let name = refstr
                .strip_prefix("$.metadata.enums.")
                .ok_or_else(|| format!("enum $ref must start with $.metadata.enums.: `{refstr}`"))?;
            let off = enum_offsets
                .get(name)
                .copied()
                .ok_or_else(|| format!("enum `{name}` was not pre-interned"))?;
            push_tlv(&mut out, PARAM_ENUM_REF, &off.to_be_bytes())?;
        }
        FMT_UNIT => {
            if let Some(d) = params.get("decimals").and_then(|v| v.as_u64()) {
                if d > 255 {
                    return Err("unit.decimals > 255".to_string());
                }
                push_tlv(&mut out, PARAM_DECIMALS, &[d as u8])?;
            }
            if let Some(b) = params.get("base").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(b, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_BASE, s.as_bytes())?;
            }
            if let Some(p) = params.get("prefix").and_then(|v| v.as_bool()) {
                push_tlv(&mut out, PARAM_PREFIX, &[u8::from(p)])?;
            }
            if let Some(s) = params.get("suffix").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(s, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_SUFFIX, s.as_bytes())?;
            }
        }
        FMT_CALLDATA => {
            if let Some(sel) = params.get("selector").and_then(|v| v.as_str()) {
                let sel = parse_hex_fixed::<4>(sel)?;
                push_tlv(&mut out, PARAM_NESTED_SELECTOR, &sel)?;
            }
            if let Some(callee) = params.get("calleePath").and_then(|v| v.as_str()) {
                let prog = compile_path(callee, context_kind, parsed)
                    .map_err(|e| format!("calleePath `{callee}`: {e}"))?;
                push_tlv(&mut out, PARAM_NESTED_CALLEE, &prog)?;
            }
        }
        FMT_ENCRYPTED => {
            let label = params
                .get("fallbackLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("[encrypted]");
            let s = clean_ascii_truncated(label, MAX_POOL_TLV_PAYLOAD);
            push_tlv(&mut out, PARAM_FALLBACK_LABEL, s.as_bytes())?;
        }
        FMT_RAW | FMT_AMOUNT | FMT_NFT_NAME | FMT_CHAIN_ID | FMT_TOKEN_TICKER => {
            // No formatter-specific params on the seed corpus today.
            // Any unrecognized keys are ignored — keeps us forward-
            // compatible with future spec extensions.
        }
        _ => return Err(format!("unknown format opcode: 0x{:02x}", format_op)),
    }

    Ok(out)
}

fn parse_format_name(name: &str) -> Result<u8, String> {
    Ok(match name {
        "raw" => FMT_RAW,
        "amount" => FMT_AMOUNT,
        "tokenAmount" => FMT_TOKEN_AMOUNT,
        "nftName" => FMT_NFT_NAME,
        "date" => FMT_DATE,
        "duration" => FMT_DURATION,
        "addressName" => FMT_ADDRESS_NAME,
        "enum" => FMT_ENUM,
        "unit" => FMT_UNIT,
        "calldata" => FMT_CALLDATA,
        "chainId" => FMT_CHAIN_ID,
        "tokenTicker" => FMT_TOKEN_TICKER,
        "interoperableAddressName" => FMT_INTEROP_ADDR_NAME,
        "encrypted" => FMT_ENCRYPTED,
        other => return Err(format!("unknown format `{other}`")),
    })
}

// ─────────────────────────────────────────────────────────────────────
// Path compiler.
// ─────────────────────────────────────────────────────────────────────

/// Parsed view of a format key like
/// `"exactInputSingle((address tokenIn,address tokenOut,...) params)"`.
/// We strip parameter names for the keccak selector but keep them
/// indexed for path resolution.
struct ParsedFormatKey {
    /// Types-only signature, e.g. `"exactInputSingle((address,address,...))"`.
    types_signature: String,
    /// The top-level argument names (root-level of `#.`).
    top_names: Vec<String>,
    /// For tuple-typed top args, the inner names by top-arg name.
    /// e.g. `"params" -> ["tokenIn","tokenOut",...]`.
    /// For non-tuple top args this map is empty.
    inner_names: BTreeMap<String, Vec<String>>,
}

fn parse_format_key(sig: &str) -> Result<ParsedFormatKey, String> {
    let sig = sig.trim();
    let name_end = sig
        .find('(')
        .ok_or_else(|| format!("missing '(' in format key `{sig}`"))?;
    let fname = &sig[..name_end];
    let rest = &sig[name_end..];

    let (args_str, types_args_str) = split_arg_list(rest)?;

    let types_signature = format!("{fname}{types_args_str}");

    // Now parse the top-level args of `args_str` (which includes the
    // surrounding parens).
    let inner = &args_str[1..args_str.len() - 1]; // strip outer ()
    let top_args = split_top_args(inner);

    let mut top_names = Vec::with_capacity(top_args.len());
    let mut inner_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for arg in top_args {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if let Some(stripped) = arg.strip_prefix('(') {
            // Tuple-typed argument: `(inner_types... innerN names...) outer_name`.
            let close = find_matching_paren(arg.as_bytes(), 0)
                .ok_or_else(|| format!("unbalanced tuple in `{arg}`"))?;
            let tuple_body = &arg[1..close];
            let after = arg[close + 1..].trim();
            let outer_name = first_ident_or_empty(after);
            if outer_name.is_empty() {
                return Err(format!(
                    "top-level tuple arg has no name (need `(...types...) name`): `{arg}`"
                ));
            }
            top_names.push(outer_name.to_string());
            // Parse inner field names.
            let inner_args = split_top_args(tuple_body);
            let mut names = Vec::with_capacity(inner_args.len());
            for inner_arg in inner_args {
                let nm = last_ident(inner_arg.trim());
                names.push(nm.to_string());
            }
            inner_names.insert(outer_name.to_string(), names);
            let _ = stripped; // silence unused
        } else {
            let nm = last_ident(arg);
            top_names.push(nm.to_string());
        }
    }

    Ok(ParsedFormatKey {
        types_signature,
        top_names,
        inner_names,
    })
}

/// `arg_list` starts with `(`. Returns the original substring plus a
/// types-only version (parameter names stripped).
fn split_arg_list(s: &str) -> Result<(String, String), String> {
    if !s.starts_with('(') {
        return Err(format!("expected '(' at start of `{s}`"));
    }
    let close = find_matching_paren(s.as_bytes(), 0)
        .ok_or_else(|| format!("unbalanced parens in `{s}`"))?;
    let args = &s[..=close];

    // Build types-only version by stripping the trailing identifier
    // from each comma-separated argument at every nesting depth.
    let types_only = strip_param_names(args);
    Ok((args.to_string(), types_only))
}

/// Strip parameter names from a type signature like `(address foo, uint256 bar)`
/// → `(address,uint256)`. Recurses into nested parentheses.
fn strip_param_names(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut depth = 0;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '(' => {
                if depth == 0 {
                    out.push('(');
                    start = i + 1;
                }
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = &s[start..i];
                    out.push_str(&strip_names_in_arg_list(inner));
                    out.push(')');
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    out
}

fn strip_names_in_arg_list(inner: &str) -> String {
    let parts = split_top_args(inner);
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&strip_one_arg(p.trim()));
    }
    out
}

fn strip_one_arg(arg: &str) -> String {
    if arg.starts_with('(') {
        // Nested tuple: keep parens, recurse into body, then drop the
        // trailing identifier (and any `[]` array suffix on it).
        let close = find_matching_paren(arg.as_bytes(), 0).unwrap();
        let inner = &arg[1..close];
        let after = arg[close + 1..].trim();
        // `after` may have an array suffix like `[]` before the name.
        let array_suffix = collect_array_suffix(after);
        let mut s = String::new();
        s.push('(');
        s.push_str(&strip_names_in_arg_list(inner));
        s.push(')');
        s.push_str(array_suffix);
        s
    } else {
        // Type can be `address`, `uint256`, `uint256[]`, `bytes32`, etc.
        // Drop any trailing identifier preceded by whitespace.
        let mut ty_end = arg.len();
        for (i, ch) in arg.char_indices() {
            if ch.is_whitespace() {
                ty_end = i;
                break;
            }
        }
        arg[..ty_end].to_string()
    }
}

fn collect_array_suffix(after_close: &str) -> &str {
    let trimmed = after_close.trim_start();
    // Look for `[...]` immediately following.
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        // Find matching ]
        let mut depth = 1;
        i += 1;
        while i < bytes.len() && depth > 0 {
            if bytes[i] == b'[' {
                depth += 1;
            } else if bytes[i] == b']' {
                depth -= 1;
            }
            i += 1;
        }
    }
    &trimmed[..i]
}

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn split_top_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(s[start..].to_string());
    }
    out
}

fn first_ident_or_empty(s: &str) -> &str {
    let s = s.trim_start();
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[..end]
}

fn last_ident(s: &str) -> &str {
    // Walk from the end, skipping `[]` suffixes, to find the trailing
    // identifier. If the entire string is a type (no name), return "".
    let s = s.trim();
    // Drop trailing array suffix(es).
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b']' {
        let mut depth = 1;
        end -= 1;
        while end > 0 && depth > 0 {
            end -= 1;
            if bytes[end] == b']' {
                depth += 1;
            } else if bytes[end] == b'[' {
                depth -= 1;
            }
        }
    }
    let cut = &s[..end].trim_end();
    let start = cut
        .rfind(|c: char| c.is_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    let candidate = &cut[start..];
    // If candidate is a known Solidity type prefix, treat as no-name.
    if candidate.is_empty() || candidate.starts_with(|c: char| c.is_ascii_digit()) {
        return "";
    }
    candidate
}

/// Compile a single ERC-7730 path string into the on-device opcode
/// sequence (without the leading length prefix; caller adds that).
fn compile_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<Vec<u8>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("empty path".to_string());
    }

    // 1. Determine root.
    let (root, rest) = if let Some(r) = path.strip_prefix('#') {
        (PATHOP_ROOT_STRUCT, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('@') {
        (PATHOP_ROOT_CONTAINER, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('$') {
        (PATHOP_ROOT_METADATA, r.trim_start_matches('.'))
    } else {
        // Default root: structured (calldata for contract context;
        // typed-data message for EIP-712 — both addressed by name
        // through the same opcode).
        let _ = context_kind;
        (PATHOP_ROOT_STRUCT, path)
    };

    let mut out = Vec::with_capacity(8);
    out.push(root);

    // 2. Walk the dotted/indexed path.
    let mut cur_top: Option<&str> = None;
    for seg in tokenize_path(rest)? {
        match seg {
            PathSeg::Name(name) => {
                let idx = resolve_field_index(parsed, cur_top, name)?;
                out.push(PATHOP_FIELD_IDX);
                out.extend_from_slice(&idx.to_be_bytes());
                cur_top = Some(name);
            }
            PathSeg::ArrayIdx(i) => {
                out.push(PATHOP_ARRAY_IDX);
                out.extend_from_slice(&i.to_be_bytes());
            }
            PathSeg::ArrayLast => out.push(PATHOP_ARRAY_LAST),
            PathSeg::ArrayAll => out.push(PATHOP_ARRAY_ALL),
            PathSeg::ArraySlice(a, b) => {
                out.push(PATHOP_ARRAY_SLICE);
                out.extend_from_slice(&a.to_be_bytes());
                out.extend_from_slice(&b.to_be_bytes());
            }
        }
    }
    Ok(out)
}

/// Map a name segment to a 2-byte BE field-index opcode arg. For the
/// first name after the root we look it up in `parsed.top_names`;
/// subsequent names use `parsed.inner_names[prev_top]`. If the name
/// isn't found in the parsed format key (e.g. a nested struct we
/// didn't parse), we encode the name's hash as a fall-back so Phase 5
/// can resolve it via the runtime ABI shape table.
fn resolve_field_index(
    parsed: &ParsedFormatKey,
    cur_top: Option<&str>,
    name: &str,
) -> Result<u16, String> {
    let names: &[String] = if let Some(top) = cur_top {
        parsed
            .inner_names
            .get(top)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    } else {
        &parsed.top_names
    };
    if let Some(pos) = names.iter().position(|n| n == name) {
        return u16::try_from(pos).map_err(|_| format!("field index {pos} > u16::MAX"));
    }
    // Fall-back: ABI hash. Compress to 16-bit so it fits the slot.
    // Phase 5 walker resolves this via runtime introspection — for
    // Phase 2 we just need to round-trip parse.
    let h = keccak256(name.as_bytes());
    Ok(u16::from_be_bytes([h[0], h[1]]))
}

enum PathSeg<'a> {
    Name(&'a str),
    ArrayIdx(u32),
    ArrayLast,
    ArrayAll,
    ArraySlice(u32, u32),
}

fn tokenize_path(rest: &str) -> Result<Vec<PathSeg<'_>>, String> {
    let mut out = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
            }
            b'[' => {
                // Find matching ].
                let close = bytes[i..]
                    .iter()
                    .position(|&b| b == b']')
                    .ok_or_else(|| format!("unmatched '[' in path `{rest}`"))?;
                let body = &rest[i + 1..i + close];
                let body_trim = body.trim();
                if body_trim.is_empty() {
                    out.push(PathSeg::ArrayAll);
                } else if body_trim == "-1" || body_trim == "last" {
                    out.push(PathSeg::ArrayLast);
                } else if let Some((a, b)) = body_trim.split_once(':') {
                    let a: u32 = a
                        .trim()
                        .parse()
                        .map_err(|_| format!("slice start `{a}` not u32"))?;
                    let b: u32 = b
                        .trim()
                        .parse()
                        .map_err(|_| format!("slice end `{b}` not u32"))?;
                    out.push(PathSeg::ArraySlice(a, b));
                } else if let Ok(n) = body_trim.parse::<u32>() {
                    out.push(PathSeg::ArrayIdx(n));
                } else {
                    return Err(format!(
                        "unrecognized array segment `[{body_trim}]` in `{rest}`"
                    ));
                }
                i += close + 1;
            }
            b if (b.is_ascii_alphanumeric() || b == b'_') => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                out.push(PathSeg::Name(&rest[start..i]));
            }
            other => {
                return Err(format!(
                    "unexpected byte 0x{:02x} ({:?}) in path `{rest}`",
                    other, other as char
                ))
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// IR builder.
// ─────────────────────────────────────────────────────────────────────

fn build_ir(
    context_kind: u8,
    chain_id: u64,
    contract: [u8; 20],
    domain_separator: &[u8; 32],
    ctx: &CompileCtx,
    pool: &[u8],
    formats: &[u8],
) -> Result<Vec<u8>, String> {
    let pool_len = pool.len();
    let formats_len = formats.len();
    if pool_len > u16::MAX as usize {
        return Err(format!("pool_len {pool_len} > u16::MAX"));
    }
    if formats_len > u16::MAX as usize {
        return Err(format!("formats_len {formats_len} > u16::MAX"));
    }
    let metadata_off = HEADER_LEN as u16;
    let formats_off = (HEADER_LEN + pool_len) as u16;

    let mut buf = vec![0u8; HEADER_LEN];
    buf[0] = SCHEMA_VER;
    buf[1] = context_kind;
    buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
    buf[10..30].copy_from_slice(&contract);
    buf[30..62].copy_from_slice(&ctx.descriptor_hash);
    buf[62..94].copy_from_slice(domain_separator);

    // Owner + contract_name: NUL-padded, ≤ 15 + NUL.
    write_padded_ascii(&mut buf[94..94 + OWNER_FIELD_LEN], &ctx.owner)?;
    write_padded_ascii(
        &mut buf[110..110 + CONTRACT_NAME_FIELD_LEN],
        &ctx.contract_name,
    )?;

    buf[126..128].copy_from_slice(&metadata_off.to_be_bytes());
    buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
    buf[130..132].copy_from_slice(&(pool_len as u16).to_be_bytes());
    buf[132..134].copy_from_slice(&(formats_len as u16).to_be_bytes());

    buf.extend_from_slice(pool);
    buf.extend_from_slice(formats);

    Ok(buf)
}

fn write_padded_ascii(slot: &mut [u8], s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    if bytes.len() >= slot.len() {
        return Err(format!(
            "ASCII field too long ({} >= {} including NUL)",
            bytes.len(),
            slot.len()
        ));
    }
    if !bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(format!("ASCII field has non-printable byte(s): {s:?}"));
    }
    slot.fill(0);
    slot[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Enum tables.
// ─────────────────────────────────────────────────────────────────────

fn encode_enum_table(table: &serde_json::Value) -> Result<Vec<u8>, String> {
    let map = table
        .as_object()
        .ok_or_else(|| "enum table must be an object".to_string())?;
    if map.len() > 255 {
        return Err(format!("enum has {} entries > 255", map.len()));
    }
    let mut entries: Vec<(u64, String)> = Vec::with_capacity(map.len());
    for (k, v) in map {
        let key: u64 = k
            .parse()
            .map_err(|_| format!("enum key `{k}` must be a non-negative integer"))?;
        let val = v
            .as_str()
            .ok_or_else(|| format!("enum value for `{k}` must be a string"))?;
        let val = clean_ascii_truncated(val, 254);
        if val.is_empty() {
            return Err(format!("enum value for `{k}` is empty / non-printable"));
        }
        entries.push((key, val));
    }
    entries.sort_by_key(|(k, _)| *k);

    let mut out = Vec::with_capacity(1 + entries.len() * 12);
    out.push(entries.len() as u8);
    for (k, v) in entries {
        out.extend_from_slice(&k.to_be_bytes()); // 8 B BE
        out.push(v.len() as u8);
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// EIP-712 domain separator.
// ─────────────────────────────────────────────────────────────────────

fn compute_domain_separator(d: &Eip712Domain) -> Result<[u8; 32], String> {
    // EIP-712 §`EIP712Domain` typehash is computed from only the
    // *present* fields. We assemble the field list and the
    // corresponding encoded values, then keccak both.
    let mut typestr = String::from("EIP712Domain(");
    let mut encoded: Vec<u8> = Vec::new();
    let mut first = true;
    let push_field = |t: &str, name: &str, encoded_value: [u8; 32], typestr: &mut String, encoded: &mut Vec<u8>, first: &mut bool| {
        if !*first {
            typestr.push(',');
        }
        typestr.push_str(t);
        typestr.push(' ');
        typestr.push_str(name);
        encoded.extend_from_slice(&encoded_value);
        *first = false;
    };
    if let Some(name) = &d.name {
        push_field("string", "name", keccak256(name.as_bytes()), &mut typestr, &mut encoded, &mut first);
    }
    if let Some(version) = &d.version {
        push_field("string", "version", keccak256(version.as_bytes()), &mut typestr, &mut encoded, &mut first);
    }
    if let Some(cid) = d.chain_id {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&cid.to_be_bytes());
        push_field("uint256", "chainId", buf, &mut typestr, &mut encoded, &mut first);
    }
    if let Some(addr) = &d.verifying_contract {
        let a = parse_address(addr)?;
        let mut buf = [0u8; 32];
        buf[12..32].copy_from_slice(&a);
        push_field("address", "verifyingContract", buf, &mut typestr, &mut encoded, &mut first);
    }
    if let Some(salt) = &d.salt {
        let s = parse_hex32(salt)?;
        push_field("bytes32", "salt", s, &mut typestr, &mut encoded, &mut first);
    }
    typestr.push(')');

    let typehash = keccak256(typestr.as_bytes());
    let mut preimage = Vec::with_capacity(32 + encoded.len());
    preimage.extend_from_slice(&typehash);
    preimage.extend_from_slice(&encoded);
    Ok(keccak256(&preimage))
}

// ─────────────────────────────────────────────────────────────────────
// JCS canonicalization (RFC 8785 subset — integers / strings only).
// ─────────────────────────────────────────────────────────────────────

fn jcs_canonicalize(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out = String::with_capacity(256);
    jcs_render(v, &mut out)?;
    Ok(out.into_bytes())
}

fn jcs_render(v: &serde_json::Value, out: &mut String) -> Result<(), String> {
    match v {
        serde_json::Value::Null => {
            out.push_str("null");
            Ok(())
        }
        serde_json::Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        serde_json::Value::Number(n) => {
            // JCS requires shortest IEEE-754 form for floats. Real
            // ERC-7730 descriptors use only integers and ASCII-coded
            // string values; allow integers + reject finite floats.
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(format!(
                    "JCS: float numbers not supported in Phase 2 (got {n})"
                ));
            }
            Ok(())
        }
        serde_json::Value::String(s) => {
            jcs_render_string(s, out);
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        serde_json::Value::Object(map) => {
            // RFC 8785 sorts object keys by UTF-16 code units. For pure
            // ASCII keys this is identical to byte order, which is what
            // our seed corpus uses. We collect & sort by UTF-16 in case
            // a future descriptor ships non-ASCII keys.
            let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            keys.sort_by(|a, b| utf16_codeunit_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render_string(k, out);
                out.push(':');
                jcs_render(&map[*k], out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

fn jcs_render_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn utf16_codeunit_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ai = a.encode_utf16();
    let bi = b.encode_utf16();
    ai.cmp(bi)
}

// ─────────────────────────────────────────────────────────────────────
// Policy enforcement.
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// `includes` resolution (Phase 5, item 2).
//
// The ERC-7730 registry uses `"includes"` references so the
// templated permit / EIP-712 common entries don't duplicate the
// boilerplate. We resolve these against a local mirror of the
// registry passed in via `--registry-root <dir>`. Three forms are
// supported:
//
//   1. Relative file path           — `./templates/permit.json`
//   2. Registry-relative path       — `registry/templates/permit.json`
//   3. GitHub URL                   — `https://github.com/ethereum/
//      clear-signing-erc7730-registry/blob/<sha>/templates/permit.json`
//      → strip the host + branch prefix and resolve as a relative
//      path under `registry_root`.
//
// Any include that resolves OUTSIDE `registry_root` (e.g. via `..`
// escapes) is rejected — this prevents a hostile descriptor from
// pulling in arbitrary files on the host build machine.
// ─────────────────────────────────────────────────────────────────────

fn resolve_include_path(
    registry_root: &Path,
    descriptor_path: &Path,
    include_ref: &str,
) -> Result<PathBuf, String> {
    let registry_root = registry_root.canonicalize().map_err(|e| {
        format!("canonicalize registry-root {}: {e}", registry_root.display())
    })?;

    let candidate: PathBuf = if let Some(stripped) =
        include_ref.strip_prefix("https://github.com/")
    {
        // `<owner>/<repo>/blob/<ref>/<path>` or
        // `<owner>/<repo>/raw/<ref>/<path>` — strip the first four
        // segments to get the path inside the registry.
        let parts: Vec<&str> = stripped.splitn(5, '/').collect();
        if parts.len() < 5 {
            return Err(format!(
                "github URL include `{include_ref}` has too few path segments"
            ));
        }
        registry_root.join(parts[4])
    } else if include_ref.starts_with("./") || include_ref.starts_with("../") {
        descriptor_path
            .parent()
            .ok_or_else(|| "descriptor path has no parent".to_string())?
            .join(include_ref)
    } else {
        registry_root.join(include_ref)
    };

    let canonical = candidate.canonicalize().map_err(|e| {
        format!("canonicalize include {}: {e}", candidate.display())
    })?;
    if !canonical.starts_with(&registry_root) {
        return Err(format!(
            "include `{include_ref}` resolves to {} which is outside registry-root {} — refusing",
            canonical.display(),
            registry_root.display()
        ));
    }
    Ok(canonical)
}

/// Deep-merge `over` on top of `base`. For object-typed leaves the
/// keys merge recursively; for any non-object leaf `over` wins. This
/// matches the semantics that the ERC-7730 registry expects from its
/// `includes` resolution (the descriptor is the "over" document; the
/// template is the "base").
fn merge_descriptors(
    base: serde_json::Value,
    over: serde_json::Value,
) -> serde_json::Value {
    use serde_json::Value;
    match (base, over) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = if let Some(existing) = b.remove(&k) {
                    merge_descriptors(existing, v)
                } else {
                    v
                };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        // For non-objects, `over` wins.
        (_, over) => over,
    }
}

fn enforce_policy(json: &serde_json::Value, policy: &Policy) -> Result<(), String> {
    if policy.allow_unattested_dev_descriptors {
        return Ok(());
    }
    let atts = json.get("attestations").and_then(|v| v.as_array());
    let atts = atts.ok_or_else(|| {
        "policy requires attestations but descriptor has none".to_string()
    })?;
    let mut hits: Vec<String> = Vec::new();
    for a in atts {
        if let Some(s) = a.get("attester").and_then(|v| v.as_str()) {
            let s_norm = s.to_ascii_lowercase();
            if policy
                .trusted_attesters
                .iter()
                .any(|t| t.to_ascii_lowercase() == s_norm)
                && !hits.iter().any(|h| h == &s_norm)
            {
                hits.push(s_norm);
            }
        }
    }
    if hits.len() < policy.min_attesters {
        return Err(format!(
            "policy: only {} trusted attestation(s); need {}",
            hits.len(),
            policy.min_attesters
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Review file (vendor-readable summary).
// ─────────────────────────────────────────────────────────────────────

fn render_review(entries: &[Emitted], policy: &Policy, root: &[u8; 32]) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("# ERC-7730 descriptor catalogue\n");
    s.push_str("# Generated by `cargo run -p dbgen`. DO NOT EDIT BY HAND.\n");
    s.push_str("#\n");
    s.push_str("# Each row is one entry in the firmware-pinned Merkle tree at\n");
    s.push_str("# ERC7730_DESCRIPTORS_ROOT. Auditors should reconcile every row\n");
    s.push_str("# against the source JSON and the upstream attestation chain.\n");
    s.push_str(&format!("# Root: 0x{}\n", hex::encode(root)));
    s.push_str(&format!(
        "# Policy: min_attesters={} allow_unattested_dev_descriptors={}\n",
        policy.min_attesters, policy.allow_unattested_dev_descriptors
    ));
    s.push_str(&format!("# Trusted attesters ({}):\n", policy.trusted_attesters.len()));
    for t in &policy.trusted_attesters {
        s.push_str(&format!("#   - {t}\n"));
    }
    if policy.allow_unattested_dev_descriptors {
        s.push_str("#\n");
        s.push_str("# WARNING: dev mode is on — attestations were NOT enforced.\n");
        s.push_str("# CI MUST reject production builds in this mode.\n");
    }
    s.push('\n');
    for e in entries {
        let ctx = if e.context_kind == CTX_CONTRACT {
            "contract"
        } else {
            "eip712"
        };
        s.push_str(&format!(
            "[{:04}] ctx={ctx} chain_id={} contract=0x{} \
             primary_type=0x{} descriptor_hash=0x{} ir_len={} source={}\n",
            e.leaf_index,
            e.chain_id,
            hex::encode(e.contract),
            hex::encode(e.primary_type_hash),
            hex::encode(e.descriptor_hash),
            e.ir_bytes.len(),
            e.source.file_name().unwrap().to_string_lossy(),
        ));
    }
    s
}

// ─────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────

fn push_tlv(out: &mut Vec<u8>, kind: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_POOL_TLV_PAYLOAD {
        return Err(format!(
            "param TLV 0x{:02x}: payload too long ({} > {})",
            kind,
            payload.len(),
            MAX_POOL_TLV_PAYLOAD
        ));
    }
    out.push(kind);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    Ok(())
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() > 64 {
        return Err(format!("hex32 too long: {}", s.len()));
    }
    let padded = format!("{:0>64}", s);
    let bytes = hex::decode(&padded).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_address_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 20], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_address(hex);
    }
    parse_address(s)
}

fn resolve_u256_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 32], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_hex32(hex);
    }
    parse_hex32(s)
}

/// Transliterate non-printable / non-ASCII bytes to '?', then trim to
/// `max_len` bytes. The on-device IR header forbids non-printable
/// bytes outright; the host pipeline replaces them rather than
/// rejecting wholesale, which mirrors the spec's "transliterate or
/// reject" guidance (see handoff §"Common gotchas" #3).
fn clean_ascii_truncated(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if out.len() >= max_len {
            break;
        }
        let mut buf = [0u8; 4];
        let enc = c.encode_utf8(&mut buf);
        if enc.len() == 1 && (0x20..0x7f).contains(&(enc.as_bytes()[0])) {
            out.push_str(enc);
        } else {
            out.push('?');
        }
    }
    out
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// Keep clippy happy about the `node_hash` import — we use it
// indirectly via `MerkleTree::build`.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = node_hash;
}

// ─────────────────────────────────────────────────────────────────────
// Tests.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_param_names_basic() {
        assert_eq!(
            strip_param_names("(address _to, uint256 _value)"),
            "(address,uint256)"
        );
    }

    #[test]
    fn strip_param_names_nested_tuple() {
        assert_eq!(
            strip_param_names("((address tokenIn,address tokenOut,uint24 fee) params)"),
            "((address,address,uint24))"
        );
    }

    #[test]
    fn parse_format_key_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        assert_eq!(p.types_signature, "transfer(address,uint256)");
        assert_eq!(p.top_names, vec!["_to".to_string(), "_value".to_string()]);
    }

    #[test]
    fn parse_format_key_nested_tuple() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        assert_eq!(
            p.types_signature,
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(p.top_names, vec!["params".to_string()]);
        let inner = &p.inner_names["params"];
        assert_eq!(inner.len(), 7);
        assert_eq!(inner[0], "tokenIn");
        assert_eq!(inner[4], "amountIn");
    }

    #[test]
    fn compile_path_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        let prog = compile_path("#._value", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 1);
    }

    #[test]
    fn compile_path_nested() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        let prog = compile_path("params.amountIn", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 0); // "params"
        assert_eq!(prog[4], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[5], prog[6]]), 4); // "amountIn"
    }

    #[test]
    fn jcs_object_keys_sorted() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":2,"c":[1,2]}"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"{"a":2,"b":1,"c":[1,2]}"#);
    }

    #[test]
    fn jcs_string_escapes() {
        let v: serde_json::Value = serde_json::Value::String("a\"b\\c\n".to_string());
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#""a\"b\\c\n""#);
    }

    #[test]
    fn jcs_array_in_doc_order() {
        let v: serde_json::Value =
            serde_json::from_str(r#"[3,1,2]"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"[3,1,2]"#);
    }

    #[test]
    fn build_db_seed_corpus() {
        // Find the repo's secure/data/erc7730 directory relative to
        // CARGO_MANIFEST_DIR (dbgen/).
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = root.join("secure/data/erc7730");
        let policy = dir.join("policy.toml");
        let res = build_db(&dir, &policy).expect("build seed corpus");
        assert!(res.leaf_count >= 6, "expected ≥6 leaves, got {}", res.leaf_count);
        round_trip_check(&res).expect("round-trip");
    }
}
