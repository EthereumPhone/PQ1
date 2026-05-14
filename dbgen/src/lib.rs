//! dbgen — build-time generator for the embedded ERC-20 / Names /
//! Selectors / ERC-7730 / VK databases consumed by the secure firmware.
//!
//! The canonical CLI lives at `src/main.rs`. This lib exists so the
//! integration tests under `dbgen/tests/` (and any future host tools)
//! can reuse the build pipelines without shell-execing the binary.
//!
//! Source data:
//!
//! - `secure/data/erc20.json`            — ERC-20 metadata
//! - `secure/data/names.json`            — address-name DB
//! - `secure/data/selectors.json`        — function-selector DB
//! - `secure/data/selectors-e2e.json`    — tiny e2e fixture variant
//! - `secure/data/erc7730/*.json`        — ERC-7730 clear-signing descriptors
//! - `secure/data/erc7730/policy.toml`   — ERC-8176 attestation policy
//! - `secure/data/vks.json` + `secure/data/vks/*.bin` — Groth16 VK bundle
//!
//! Generated artifacts:
//!
//! - `nonsecure/src/erc20_db.bin`        — ERC-20 metadata blob (NS rodata)
//! - `nonsecure/src/vk_db.bin`           — VK blob (NS rodata)
//! - `nonsecure/src/names_db.bin`        — Names blob (NS rodata)
//! - `tools/companion-stub/selectors_db.bin`     — Selectors blob (host)
//! - `tools/companion-stub/selectors_db_e2e.bin` — Selectors e2e fixture
//! - `tools/companion-stub/erc7730_db.bin`       — ERC-7730 catalog (host)
//! - `tools/companion-stub/erc7730_db_e2e.bin`   — ERC-7730 e2e fixture
//! - `secure/src/db_roots.rs`            — compiled-in Merkle roots
//! - `secure/data/vks.review.txt`        — VK vendor-signing review
//! - `secure/data/erc7730.review.txt`    — ERC-7730 vendor-signing review
//! - `circles/generated/erc20_poseidon_tree.json` — Poseidon companion

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub mod erc20;
pub mod erc20_poseidon;
pub mod erc7730;
pub mod merkle;
pub mod names;
#[path = "../../secure/src/zk/generated/poseidon_constants.rs"]
pub mod poseidon_constants;
pub mod poseidon;
pub mod selectors;
pub mod vks;

// ─── Helpers shared between sub-modules ──────────────────────────────

pub fn parse_hex_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── Source-record types + loaders ──────────────────────────────────

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
