//! dbgen — build-time generator for the ERC-20 / Names / Selectors /
//! ERC-7730 databases authenticated by the secure firmware.
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
//! - `secure/data/erc7730-registry/registry/**/*.json` — production ERC-7730 corpus
//! - `secure/data/erc7730-registry/ercs/**/*.json` — included format templates
//! - `secure/data/erc7730-e2e/*.json`    — ERC-7730 E2E fixtures
//! - `secure/data/erc7730/policy.toml`   — ERC-8176 attestation policy
//!
//! Generated artifacts:
//!
//! - `tools/companion-stub/erc20_db.bin` — ERC-20 metadata blob (host)
//! - `tools/companion-stub/names_db.bin` — Names blob (host)
//! - `tools/companion-stub/selectors_db.bin`     — Selectors blob (host)
//! - `tools/companion-stub/selectors_db_e2e.bin` — Selectors e2e fixture
//! - `tools/companion-stub/erc7730_db.bin`       — ERC-7730 catalog (host)
//! - `tools/companion-stub/erc7730_db_e2e.bin`   — ERC-7730 e2e fixture
//! - `tools/companion-stub/erc7730_status.bin`   — authenticated catalogue receipt
//! - `tools/companion-stub/erc7730_status_e2e.bin` — e2e receipt
//! - `secure/data/erc7730-forced-eligible.set` — exact refused-known P73K set
//! - `secure/data/erc7730-forced-eligible-e2e.set` — e2e P73K set
//! - `secure/src/db_roots.rs`            — compiled-in Merkle roots
//! - `secure/data/erc7730.review.txt`    — ERC-7730 vendor-signing review

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::fs;
use std::path::Path;

pub mod eip1186;
pub mod erc20;
pub mod erc7730;
pub mod erc8176;
pub mod merkle;
pub mod names;
pub mod selectors;
pub mod token_constant_exceptions;

/// Start of the generated ERC-7730 security tail in `secure/src/db_roots.rs`.
///
/// The drift gate compares the complete tail byte-for-byte through EOF.  The
/// inert anchor is deliberately the first Rust item: an attribute inserted
/// immediately before this suffix can affect only the anchor, never a root or
/// compile fence.  An enclosing construct would require bytes after the exact
/// EOF-bound suffix and therefore fails the comparison.
pub const ERC7730_SECURITY_TAIL_SENTINEL: &str =
    "// BEGIN GENERATED ERC7730 SECURITY TAIL - DO NOT EDIT\n";

/// One immutable prod/e2e input set for the generated ERC-7730 security tail.
#[derive(Clone, Copy)]
pub struct Erc7730SecurityTailInput<'a> {
    pub root: &'a [u8; 32],
    pub descriptor_count: usize,
    pub provenance: erc7730::CatalogueProvenance,
    pub status: &'a [u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    pub forced_eligible_len: usize,
    pub forced_eligible_group_count: usize,
    pub forced_eligible_count: usize,
}

/// Render the one canonical generated suffix that binds the production and
/// e2e roots to their Bloom filters, optional P73K arrays, P73S receipts, and
/// provenance compile fences.
#[must_use]
pub fn render_erc7730_security_tail(
    prod: Erc7730SecurityTailInput<'_>,
    e2e: Erc7730SecurityTailInput<'_>,
) -> String {
    let mut out = String::with_capacity(4 * 1024);
    out.push_str(ERC7730_SECURITY_TAIL_SENTINEL);
    out.push_str("#[doc(hidden)]\n");
    out.push_str("pub const ERC7730_GENERATED_SECURITY_TAIL_ANCHOR: () = ();\n\n");
    // A prefix may legally rebind even the extern-prelude name `core` with
    // `extern crate self as core;`. Give the real core crate a generated,
    // collision-sensitive local alias: any prefix that predeclares this name
    // causes a duplicate-item compile error instead of shadowing a fence or
    // Bloom include. The inert anchor stays first so a stray attribute placed
    // immediately before the suffix cannot disable this alias.
    out.push_str("#[doc(hidden)]\n");
    out.push_str("extern crate core as __pqsigner_erc7730_core;\n\n");

    out.push_str("#[cfg(not(feature = \"e2e-test\"))]\n");
    emit_generated_root(&mut out, "ERC7730_DESCRIPTORS_ROOT", prod.root);
    out.push_str("#[cfg(feature = \"e2e-test\")]\n");
    emit_generated_root(&mut out, "ERC7730_DESCRIPTORS_ROOT", e2e.root);
    writeln!(out, "#[cfg(not(feature = \"e2e-test\"))]").unwrap();
    writeln!(
        out,
        "pub const ERC7730_DESCRIPTOR_COUNT: usize = {};\n",
        prod.descriptor_count
    )
    .unwrap();
    writeln!(out, "#[cfg(feature = \"e2e-test\")]").unwrap();
    writeln!(
        out,
        "pub const ERC7730_DESCRIPTOR_COUNT: usize = {};\n",
        e2e.descriptor_count
    )
    .unwrap();
    out.push_str(
        "#[cfg(not(feature = \"e2e-test\"))]\n\
         pub static ERC7730_KNOWN_CALLS_BLOOM: &[u8; pqsigner_erc7730::known_calls::BLOOM_BYTES] =\n\
             self::__pqsigner_erc7730_core::include_bytes!(\"../data/erc7730-known-calls.bloom\");\n\n\
         #[cfg(feature = \"e2e-test\")]\n\
         pub static ERC7730_KNOWN_CALLS_BLOOM: &[u8; pqsigner_erc7730::known_calls::BLOOM_BYTES] =\n\
             self::__pqsigner_erc7730_core::include_bytes!(\"../data/erc7730-known-calls-e2e.bloom\");\n\n",
    );
    emit_generated_forced_eligible(
        &mut out,
        prod.forced_eligible_len,
        prod.forced_eligible_group_count,
        prod.forced_eligible_count,
        false,
    );
    emit_generated_forced_eligible(
        &mut out,
        e2e.forced_eligible_len,
        e2e.forced_eligible_group_count,
        e2e.forced_eligible_count,
        true,
    );
    emit_generated_catalogue_status(&mut out, prod.status, false);
    emit_generated_catalogue_status(&mut out, e2e.status, true);
    emit_generated_erc7730_provenance(&mut out, prod.provenance, false);
    emit_generated_erc7730_provenance(&mut out, e2e.provenance, true);
    out
}

fn emit_generated_forced_eligible(
    out: &mut String,
    byte_len: usize,
    group_count: usize,
    tuple_count: usize,
    e2e: bool,
) {
    let selected = if e2e {
        "all(feature = \"e2e-test\", feature = \"erc7730-forced-blind\")"
    } else {
        "all(not(feature = \"e2e-test\"), feature = \"erc7730-forced-blind\")"
    };
    let path = if e2e {
        "../data/erc7730-forced-eligible-e2e.set"
    } else {
        "../data/erc7730-forced-eligible.set"
    };
    writeln!(out, "#[cfg({selected})]").unwrap();
    writeln!(
        out,
        "pub const ERC7730_FORCED_ELIGIBLE_GROUP_COUNT: usize = {group_count};"
    )
    .unwrap();
    writeln!(out, "#[cfg({selected})]").unwrap();
    writeln!(
        out,
        "pub const ERC7730_FORCED_ELIGIBLE_TUPLE_COUNT: usize = {tuple_count};"
    )
    .unwrap();
    writeln!(out, "#[cfg({selected})]").unwrap();
    out.push_str(
        "#[used]\n#[no_mangle]\n#[link_section = \".pqsigner.erc7730_forced_eligible\"]\n",
    );
    writeln!(
        out,
        "pub static PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET: [u8; {byte_len}] ="
    )
    .unwrap();
    writeln!(
        out,
        "    *self::__pqsigner_erc7730_core::include_bytes!({path:?});\n"
    )
    .unwrap();
}

fn emit_generated_catalogue_status(
    out: &mut String,
    bytes: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    e2e: bool,
) {
    let selected = if e2e {
        "feature = \"e2e-test\""
    } else {
        "not(feature = \"e2e-test\")"
    };
    writeln!(out, "#[cfg({selected})]").unwrap();
    out.push_str("#[used]\n#[no_mangle]\n#[link_section = \".pqsigner.erc7730_status\"]\n");
    write!(
        out,
        "pub static PQSIGNER_ERC7730_CATALOGUE_STATUS: [u8; {}] = [",
        bytes.len()
    )
    .unwrap();
    for (index, byte) in bytes.iter().enumerate() {
        if index % 8 == 0 {
            out.push_str("\n    ");
        } else {
            out.push(' ');
        }
        write!(out, "0x{byte:02x},").unwrap();
    }
    out.push_str("\n];\n\n");
}

fn emit_generated_root(out: &mut String, name: &str, bytes: &[u8; 32]) {
    write!(out, "pub static {name}: [u8; 32] = [").unwrap();
    for (index, byte) in bytes.iter().enumerate() {
        if index % 8 == 0 {
            out.push_str("\n    ");
        } else {
            out.push(' ');
        }
        write!(out, "0x{byte:02x},").unwrap();
    }
    out.push_str("\n];\n\n");
}

fn emit_generated_erc7730_provenance(
    out: &mut String,
    provenance: erc7730::CatalogueProvenance,
    e2e: bool,
) {
    let selected = if e2e {
        "feature = \"e2e-test\""
    } else {
        "not(feature = \"e2e-test\")"
    };
    writeln!(out, "#[cfg({selected})]").unwrap();
    writeln!(
        out,
        "pub const ERC7730_CATALOGUE_PROVENANCE: &str = {:?};\n",
        provenance.as_str()
    )
    .unwrap();

    match provenance {
        erc7730::CatalogueProvenance::DevUnattested if !e2e => {
            out.push_str(
                "#[cfg(all(not(feature = \"e2e-test\"), feature = \"mode-production\"))]\n\
                 self::__pqsigner_erc7730_core::compile_error!(\"mode-production cannot embed the dev-unattested ERC-7730 catalogue. Implement and run real ERC-8176 EAS verification, regenerate db_roots.rs, and only then build production firmware.\");\n\n",
            );
            out.push_str(
                "#[cfg(all(not(feature = \"e2e-test\"), not(feature = \"mode-production\"), not(feature = \"erc7730-dev-unattested\"), not(test)))]\n\
                 self::__pqsigner_erc7730_core::compile_error!(\"the pinned ERC-7730 catalogue is dev-unattested; enable erc7730-dev-unattested so the trusted display shows the provenance warning, or regenerate from a genuinely ERC-8176-verified corpus\");\n\n",
            );
        }
        erc7730::CatalogueProvenance::DevUnattested => {
            out.push_str(
                "#[cfg(all(feature = \"e2e-test\", not(feature = \"erc7730-dev-unattested\"), not(test)))]\n\
                 self::__pqsigner_erc7730_core::compile_error!(\"the e2e ERC-7730 fixture catalogue is dev-unattested; e2e builds must enable erc7730-dev-unattested so the display warning matches its provenance\");\n\n",
            );
        }
        erc7730::CatalogueProvenance::Erc8176Verified => {
            writeln!(
                out,
                "#[cfg(all({selected}, feature = \"erc7730-dev-unattested\"))]"
            )
            .unwrap();
            out.push_str(
                "self::__pqsigner_erc7730_core::compile_error!(\"erc7730-dev-unattested is enabled but the selected catalogue is ERC-8176-verified; disable the feature so the trusted display does not show false provenance\");\n\n",
            );
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_eligible_statics_are_arrays_used_and_default_off() {
        let status = [0u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN];
        let tail = render_erc7730_security_tail(
            Erc7730SecurityTailInput {
                root: &[0x11; 32],
                descriptor_count: 7,
                provenance: erc7730::CatalogueProvenance::DevUnattested,
                status: &status,
                forced_eligible_len: 33_336,
                forced_eligible_group_count: 560,
                forced_eligible_count: 3_290,
            },
            Erc7730SecurityTailInput {
                root: &[0x22; 32],
                descriptor_count: 3,
                provenance: erc7730::CatalogueProvenance::DevUnattested,
                status: &status,
                forced_eligible_len: 16,
                forced_eligible_group_count: 0,
                forced_eligible_count: 0,
            },
        );

        assert!(tail.contains(
            "#[cfg(all(not(feature = \"e2e-test\"), feature = \"erc7730-forced-blind\"))]"
        ));
        assert!(tail
            .contains("#[cfg(all(feature = \"e2e-test\", feature = \"erc7730-forced-blind\"))]"));
        assert_eq!(tail.matches("#[used]").count(), 4); // P73K prod/e2e + P73S prod/e2e.
        assert_eq!(
            tail.matches("#[link_section = \".pqsigner.erc7730_forced_eligible\"]")
                .count(),
            2
        );
        assert!(tail.contains("pub static PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET: [u8; 33336] ="));
        assert!(tail.contains("pub static PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET: [u8; 16] ="));
        assert!(!tail.contains("pub static PQSIGNER_ERC7730_FORCED_ELIGIBLE_SET: &[u8"));
        assert_eq!(
            tail.matches("ERC7730_FORCED_ELIGIBLE_TUPLE_COUNT").count(),
            2
        );
    }
}
