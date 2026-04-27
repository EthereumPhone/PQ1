//! Build-time generator for the embedded ERC20 metadata DB and ZK
//! verification key DB consumed by the secure-world firmware.
//!
//! Reads:
//!   secure/data/erc20.json
//!   secure/data/vks.json
//!   secure/data/vks/<file>.bin
//!
//! Writes (checked into the repo, like the existing
//! tools/export_zk_constants.js outputs):
//!   secure/src/erc20/erc20_db.bin
//!   secure/src/zk/vk_db.bin
//!   secure/data/vks.review.txt
//!
//! Run manually after editing the JSON sources:
//!
//!   cargo run -p dbgen
//!
//! The runtime parser is in:
//!   secure/src/erc20/db.rs   (ERC20 metadata)
//!   secure/src/zk/vk_db.rs   (ZK clear-signing VKs)
//!
//! Both crates physically share the on-disk format definition via
//! sphincs_tz_shared::db_format, so any field-layout change here is a
//! single edit in shared/src/db_format.rs.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

mod erc20;
mod erc20_poseidon;
mod merkle;
mod names;
#[path = "../../secure/src/zk/generated/poseidon_constants.rs"]
mod poseidon_constants;
mod poseidon;
mod selectors;
mod vks;

const REPO_ROOT_CARGO: &str = env!("CARGO_MANIFEST_DIR");

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is .../sphincs_rust/dbgen — go up one
    PathBuf::from(REPO_ROOT_CARGO).parent().unwrap().to_path_buf()
}

fn main() {
    let root = repo_root();
    println!("dbgen: workspace root = {}", root.display());

    // Source data lives under secure/data/ for historical reasons
    // (the curated JSON is the same regardless of which world hosts
    // the resulting blob).
    let erc20_json = root.join("secure/data/erc20.json");
    let vks_json = root.join("secure/data/vks.json");
    let vks_dir = root.join("secure/data/vks");
    let names_json = root.join("secure/data/names.json");
    let selectors_json = root.join("secure/data/selectors.json");
    let selectors_e2e_json = root.join("secure/data/selectors-e2e.json");

    // The full DB blobs ship in the NON-SECURE firmware image as
    // rodata. The secure firmware only embeds the Merkle root via
    // the generated `db_roots.rs` file below.
    let erc20_out = root.join("nonsecure/src/erc20_db.bin");
    let vk_out = root.join("nonsecure/src/vk_db.bin");
    let names_out = root.join("nonsecure/src/names_db.bin");
    // The selectors DB blob is the odd one out: it lives on the host
    // (companion app) instead of in NS rodata, so it ships as a
    // separate artifact under tools/companion-stub/. Only the 32-byte
    // SELECTOR_DB_ROOT crosses into the firmware image.
    let selectors_out = root.join("tools/companion-stub/selectors_db.bin");
    // Tiny parallel fixture used by the QEMU e2e test driver.
    // Production builds DO NOT consume this artifact — it's the only
    // way to keep `make e2e` runnable without baking the full
    // host-side blob into NS rodata (which would overflow flash).
    let selectors_e2e_out = root.join("tools/companion-stub/selectors_db_e2e.bin");
    let roots_out = root.join("secure/src/db_roots.rs");
    let review_out = root.join("secure/data/vks.review.txt");
    // The Poseidon-Merkle tree export is consumed by the off-device
    // witness generator that builds CowSwap EIP-712 v3 proofs. It's
    // committed into the repo so `make e2e-hw` remains deterministic
    // without requiring a live dbgen run.
    let poseidon_tree_out = root.join("circuits/generated/erc20_poseidon_tree.json");

    // ----- ERC20 metadata DB -----
    let erc20_res = erc20::build_db(&erc20_json).expect("erc20 db build failed");
    erc20::round_trip_check(&erc20_res.blob, &erc20_json, &erc20_res.root)
        .expect("erc20 round-trip failed");
    fs::write(&erc20_out, &erc20_res.blob).expect("write erc20_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        erc20_out.display(),
        erc20_res.blob.len(),
        hex::encode(erc20_res.root),
    );
    // ERC20 Poseidon-Merkle companion artifact.
    if let Some(parent) = poseidon_tree_out.parent() {
        fs::create_dir_all(parent).expect("create circuits/generated");
    }
    fs::write(&poseidon_tree_out, &erc20_res.poseidon_tree_json)
        .expect("write erc20_poseidon_tree.json");
    println!(
        "dbgen: wrote {} (poseidon root = {})",
        poseidon_tree_out.display(),
        hex::encode(erc20_res.poseidon_root),
    );

    // ----- VK DB -----
    let vk_res = vks::build_db(&vks_json, &vks_dir).expect("vk db build failed");
    vks::round_trip_check(&vk_res.blob, &vks_json, &vks_dir, &vk_res.root)
        .expect("vk round-trip failed");
    fs::write(&vk_out, &vk_res.blob).expect("write vk_db.bin");
    fs::write(&review_out, &vk_res.review_text).expect("write vks.review.txt");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        vk_out.display(),
        vk_res.blob.len(),
        hex::encode(vk_res.root),
    );
    println!("dbgen: wrote {}", review_out.display());

    // ----- Names DB -----
    let names_res = names::build_db(&names_json).expect("names db build failed");
    names::round_trip_check(&names_res.blob, &names_json, &names_res.root)
        .expect("names round-trip failed");
    fs::write(&names_out, &names_res.blob).expect("write names_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        names_out.display(),
        names_res.blob.len(),
        hex::encode(names_res.root),
    );

    // ----- Selectors DB (host-side blob) -----
    //
    // Unlike the three DBs above, this one's blob does NOT ship in NS
    // rodata. It's written under tools/companion-stub/ for the future
    // companion app (and for the e2e-test driver, which acts as a
    // dev-only companion stub). Only the 32-byte root crosses into
    // the firmware image via db_roots.rs below.
    let selectors_res = selectors::build_db(&selectors_json).expect("selectors db build failed");
    selectors::round_trip_check(&selectors_res.blob, &selectors_json, &selectors_res.root)
        .expect("selectors round-trip failed");
    if let Some(parent) = selectors_out.parent() {
        fs::create_dir_all(parent).expect("create tools/companion-stub");
    }
    fs::write(&selectors_out, &selectors_res.blob).expect("write selectors_db.bin");
    println!(
        "dbgen: wrote {} ({} bytes, root = {})",
        selectors_out.display(),
        selectors_res.blob.len(),
        hex::encode(selectors_res.root),
    );

    // ----- Selectors DB (e2e fixture) -----
    //
    // Tiny parallel set used only when the secure crate is built with
    // `--features e2e-test`. The matching SELECTOR_DB_ROOT_E2E in
    // db_roots.rs is selected at compile time via the same feature
    // gate. This keeps `make e2e` runnable without overflowing NS
    // flash with the multi-hundred-KB production blob.
    let selectors_e2e_res =
        selectors::build_db(&selectors_e2e_json).expect("selectors e2e db build failed");
    selectors::round_trip_check(
        &selectors_e2e_res.blob,
        &selectors_e2e_json,
        &selectors_e2e_res.root,
    )
    .expect("selectors e2e round-trip failed");
    fs::write(&selectors_e2e_out, &selectors_e2e_res.blob)
        .expect("write selectors_db_e2e.bin");
    println!(
        "dbgen: wrote {} ({} bytes, e2e root = {})",
        selectors_e2e_out.display(),
        selectors_e2e_res.blob.len(),
        hex::encode(selectors_e2e_res.root),
    );

    // ----- secure/src/db_roots.rs -----
    //
    // This is the only file the secure-world build sees from the DBs.
    // Four 32-byte Merkle roots are baked into the secure image: the
    // SHA-256 ERC-20 + VK + Names roots (for the transfer display /
    // VK bundle verifier / address-name lookup paths) and the Poseidon
    // ERC-20 root (used as the third public input for the CowSwap
    // EIP-712 v3 Groth16 proof).
    let roots_rs = render_db_roots(
        &erc20_res.root,
        &vk_res.root,
        &erc20_res.poseidon_root,
        &names_res.root,
        &selectors_res.root,
        &selectors_e2e_res.root,
    );
    fs::write(&roots_out, &roots_rs).expect("write db_roots.rs");
    println!("dbgen: wrote {}", roots_out.display());

    println!("dbgen: ok");
}

fn render_db_roots(
    erc20_root: &[u8; 32],
    vk_root: &[u8; 32],
    erc20_poseidon_root: &[u8; 32],
    names_root: &[u8; 32],
    selectors_root: &[u8; 32],
    selectors_e2e_root: &[u8; 32],
) -> String {
    let mut s = String::new();
    s.push_str("//! Merkle roots of the embedded ERC20 + VK + Names + Selectors databases.\n");
    s.push_str("//!\n");
    s.push_str("//! Generated by `cargo run -p dbgen` from secure/data/erc20.json,\n");
    s.push_str("//! secure/data/vks.json, secure/data/names.json, and\n");
    s.push_str("//! secure/data/selectors.json. DO NOT EDIT BY HAND.\n");
    s.push_str("//!\n");
    s.push_str("//! The ERC20 / VK / Names blobs live in non-secure rodata.\n");
    s.push_str("//! The Selectors blob lives on the host (companion app) at\n");
    s.push_str("//! `tools/companion-stub/selectors_db.bin` and never ships in\n");
    s.push_str("//! the firmware image. The secure world only holds these\n");
    s.push_str("//! roots; everything received from NS or the host is\n");
    s.push_str("//! verified against them via `crate::erc20::merkle::verify_proof`.\n");
    s.push_str("//!\n");
    s.push_str("//! `ERC20_POSEIDON_ROOT` is the parallel BLS12-381 Poseidon-Merkle\n");
    s.push_str("//! tree over the same sorted (chain_id, contract) entry set that\n");
    s.push_str("//! the CowSwap EIP-712 v3 Groth16 circuit consumes as its third\n");
    s.push_str("//! public input. It's stored as the 32-byte little-endian canonical\n");
    s.push_str("//! encoding of the root scalar, ready to be fed into\n");
    s.push_str("//! `bls12_381::Scalar::from_bytes`.\n");
    s.push_str("//!\n");
    s.push_str("//! `NAMES_DB_ROOT` anchors the address-name DB. Every trusted-UI\n");
    s.push_str("//! address render consults this root before a human-readable\n");
    s.push_str("//! name is allowed to replace the raw 40-hex address.\n");
    s.push_str("//!\n");
    s.push_str("//! `SELECTOR_DB_ROOT` anchors the function-selector → text-signature\n");
    s.push_str("//! DB. The blob is held by the (untrusted) companion app; bundles\n");
    s.push_str("//! crossing the gateway are Merkle-verified against this root and\n");
    s.push_str("//! cross-checked against `calldata[0..4]` before any text-sig\n");
    s.push_str("//! reaches the trusted UI. Production builds (no `e2e-test`\n");
    s.push_str("//! feature) use the full curated set; `e2e-test` builds swap in\n");
    s.push_str("//! the smaller `selectors-e2e.json` fixture root so the QEMU NS\n");
    s.push_str("//! test driver can bake a tiny companion-stub blob without\n");
    s.push_str("//! overflowing flash.\n");
    s.push_str("\n");
    emit_root(&mut s, "ERC20_DB_ROOT", erc20_root);
    emit_root(&mut s, "VK_DB_ROOT", vk_root);
    emit_root(&mut s, "ERC20_POSEIDON_ROOT", erc20_poseidon_root);
    emit_root(&mut s, "NAMES_DB_ROOT", names_root);
    s.push_str("#[cfg(not(feature = \"e2e-test\"))]\n");
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_root);
    s.push_str("#[cfg(feature = \"e2e-test\")]\n");
    emit_root(&mut s, "SELECTOR_DB_ROOT", selectors_e2e_root);
    s
}

fn emit_root(s: &mut String, name: &str, bytes: &[u8; 32]) {
    s.push_str(&format!("pub static {}: [u8; 32] = [", name));
    for (i, b) in bytes.iter().enumerate() {
        if i % 8 == 0 {
            s.push_str("\n    ");
        }
        s.push_str(&format!("0x{:02x}, ", b));
    }
    s.push_str("\n];\n\n");
}

// === Helpers shared between erc20 and vks modules ============================

fn parse_hex_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

#[derive(Debug, Deserialize, Clone)]
pub struct Erc20Record {
    pub chain_id: u64,
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    #[serde(default)]
    pub flags: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VkProtocol {
    pub protocol: String,
    pub vk_file: String,
    pub deployments: Vec<VkDeployment>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VkDeployment {
    pub chain_id: u64,
    pub address: String,
    #[serde(default)]
    pub label: String,
}

pub fn load_erc20_records(path: &Path) -> Result<Vec<Erc20Record>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[derive(Debug, Deserialize, Clone)]
pub struct NamesRecord {
    /// `chain_id = 0` (or a missing `chain_id` field) marks the entry
    /// as chain-agnostic: the name applies to the address on every
    /// chain. Use it for contracts deterministically deployed to the
    /// same address across every EVM L1/L2 (CreateX, EntryPoint,
    /// Universal Router, Seaport, etc.).
    #[serde(default)]
    pub chain_id: u64,
    pub address: String,
    pub name: String,
}

pub fn load_names_records(path: &Path) -> Result<Vec<NamesRecord>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[derive(Debug, Deserialize, Clone)]
pub struct SelectorsRecord {
    /// Hex-encoded 4-byte selector with optional `0x` prefix, e.g.
    /// `"0xa9059cbb"`.
    pub selector: String,
    /// Canonical Solidity text signature, e.g. `"transfer(address,uint256)"`.
    /// Must be printable ASCII (0x20..=0x7e), 1..=SELECTOR_TEXT_SIG_MAX_LEN
    /// bytes long.
    pub text_sig: String,
}

pub fn load_selectors_records(path: &Path) -> Result<Vec<SelectorsRecord>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

pub fn load_vk_protocols(path: &Path) -> Result<Vec<VkProtocol>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
