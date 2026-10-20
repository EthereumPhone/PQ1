//! `pqsigner-xtask` — host-side codegen and tooling.
//!
//! See `Cargo.toml` for the design rationale. Subcommands (run `xtask help`):
//!   * `gen-solidity-constants` — render the Solidity `PqsignerProto` library
//!     from the public constants in `pqsigner-proto`.
//!   * `gen-erc7730-descriptors` — compile + Merkle-anchor the ERC-7730 catalog.
//!   * `scan-registry` / `build-registry` — read-only upstream-registry coverage
//!     probes (how much PQ1 can clear-sign; what the full corpus builds to).
//!   * `diff-registry` — deterministic read-only A/B registry revision review.
//!   * `vendor-registry` — vendor the complete security-relevant registry JSON
//!     corpus and verify both render leaves and refused-call coverage.
//!
//! The `gen-*` commands take `--check` (rebuild-in-memory + drift-diff) for CI.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pqsigner_proto as proto;
use sha2::{Digest, Sha256};

mod erc7730_curation;
mod erc7730_diff;

const SOLIDITY_OUT_PATH: &str = "contracts/smart-wallet/src/generated/PqsignerProto.sol";
/// The firmware's CREATE2 constants, for the deploy scripts and the
/// deploy-profile tests. Deliberately outside `src/`: the values are derived
/// from the compiled contracts, so the contracts must not import them.
const SOLIDITY_DEPLOYMENT_OUT_PATH: &str =
    "contracts/smart-wallet/script/generated/PqsignerDeployment.sol";
const ERC7730_VENDOR_MARKER: &str = ".pqsigner-erc7730-vendor";
const ERC7730_VENDOR_MARKER_BYTES: &[u8] =
    b"PQSigner ERC-7730 tool-managed registry/ and ercs/ directories.\n";
const ERC7730_DEFAULT_CURATION_MANIFEST: &str = "secure/data/erc7730/curations/manifest.json";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let subcmd = args.first().map(String::as_str).unwrap_or("");

    match subcmd {
        "gen-solidity-constants" => cmd_gen_solidity_constants(&args[1..]),
        "gen-erc7730-descriptors" => cmd_gen_erc7730_descriptors(&args[1..]),
        "scan-registry" => cmd_scan_registry(&args[1..]),
        "build-registry" => cmd_build_registry(&args[1..]),
        "diff-registry" => erc7730_diff::cmd_diff_registry(&args[1..], &workspace_root()),
        "vendor-registry" => cmd_vendor_registry(&args[1..]),
        "" | "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown subcommand `{other}`");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "pqsigner-xtask — host-side workspace tooling

Subcommands:
  gen-solidity-constants [--check | --check-deployment]
      Render `{SOLIDITY_OUT_PATH}` and
      `{SOLIDITY_DEPLOYMENT_OUT_PATH}` from `pqsigner-proto`.
      With --check: print the first file's rendered output to stdout
      instead of writing (used by CI to diff against the checked-in copy).
      With --check-deployment: the same for the second file.

  gen-erc7730-descriptors [--check]
                          [--input-dir PATH] [--policy PATH] [--e2e-policy PATH]
                          [--out-binary PATH] [--out-review PATH]
                          [--e2e-input-dir PATH] [--e2e-out-binary PATH]
                          [--known-calls-out PATH]
                          [--known-calls-e2e-out PATH]
                          [--forced-eligible-out PATH]
                          [--forced-eligible-e2e-out PATH]
                          [--status-out PATH] [--status-e2e-out PATH]
      Compile the production ERC-7730 catalogue from
      `secure/data/erc7730-registry/registry` plus
      `secure/data/erc7730-registry/ercs`, and the E2E catalogue from
      `secure/data/erc7730-e2e`. Production uses
      `secure/data/erc7730/policy.toml`; E2E uses its separate, permanently
      dev-unattested `secure/data/erc7730-e2e/policy.toml`.
      Build their Merkle trees and emit:
        tools/companion-stub/erc7730_db.bin
        tools/companion-stub/erc7730_db_e2e.bin
        tools/companion-stub/erc7730_status.bin
        tools/companion-stub/erc7730_status_e2e.bin
        secure/data/erc7730.review.txt
        secure/data/erc7730-known-calls.bloom
        secure/data/erc7730-known-calls-e2e.bloom
        secure/data/erc7730-forced-eligible.set
        secure/data/erc7730-forced-eligible-e2e.set
      With --check: rebuild in-memory and compare against the checked-in
      artifacts, including the capability-defining production/E2E ERC-20
      companion blobs and their exact root sections; exit non-zero on drift.
      In write mode, selecting any custom input or policy requires every
      output flag above to be explicit so a probe cannot overwrite an
      implicit checked-in production artifact.
      `secure/src/db_roots.rs` is validation-only here and is regenerated with
      `cargo run -p dbgen`.

  scan-registry [--registry-root PATH] [--input PATH] [--policy PATH]
                [--report PATH]
      Read-only coverage probe: tolerantly compile every descriptor under
      the upstream registry through the on-device pipeline using the exact
      production `secure/data/erc20.json` capability set, and tally how many
      PQ1 can clear-sign today vs. skipped-and-why. Writes nothing into the
      firmware corpus.

  build-registry [--registry-root PATH] [--input PATH] [--policy PATH]
                 [--report PATH]
      Build the full upstream registry through the capability-aware tolerant
      pipeline and report leaf count, root, skips, and the exact production
      ERC-20 input/root receipt. Read-only: does NOT overwrite the firmware-
      pinned root.

  diff-registry --base-root PATH --candidate-root PATH
                [--policy PATH] [--curation-manifest PATH]
      Deterministically compare tolerant raw-upstream builds from the
      manifest-pinned base and a clean official candidate checkout. Emit
      stable JSON with file, leaf, exact contract-call-state, skip-category,
      and curation-collision deltas. Read-only: does not vendor, apply
      curations, regenerate artifacts, install roots, or grant signing or
      release authority.

  vendor-registry [--registry-root PATH] [--out PATH] [--policy PATH]
                  [--curation-manifest PATH | --no-curation-overlay]
      Scan every `registry/**/*.json` and `ercs/**/*.json` file. Vendor the
      production corpus into `secure/data/erc7730-registry/`, validate the
      pinned upstream Git/schema/corpus identities, and apply the default
      hash-bound full-file curation overlay. Then VERIFY the curated corpus
      receipt and exact manifest-authorized known-call additions with no
      deletions before installation.
      `--no-curation-overlay` is accepted only with a distinct explicit --out
      for disposable pristine-baseline analysis; it cannot replace the
      checked-in production corpus.

  help
      Print this message.
"
    );
}

fn cmd_gen_solidity_constants(args: &[String]) -> ExitCode {
    // CI uses each check output for `diff - <checked-in>`.
    if args.iter().any(|a| a == "--check") {
        print!("{}", render_solidity_library());
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--check-deployment") {
        print!("{}", render_solidity_deployment_library());
        return ExitCode::SUCCESS;
    }

    for (rel, rendered) in [
        (SOLIDITY_OUT_PATH, render_solidity_library()),
        (SOLIDITY_DEPLOYMENT_OUT_PATH, render_solidity_deployment_library()),
    ] {
        let out_path = workspace_root().join(rel);

        if let Some(parent) = out_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("error: cannot create {}: {e}", parent.display());
                return ExitCode::FAILURE;
            }
        }

        if let Err(e) = fs::write(&out_path, &rendered) {
            eprintln!("error: cannot write {}: {e}", out_path.display());
            return ExitCode::FAILURE;
        }

        eprintln!("wrote {}", out_path.display());
    }
    ExitCode::SUCCESS
}

/// Workspace root, derived from `CARGO_MANIFEST_DIR` (which points at
/// `<workspace>/xtask` when invoked via `cargo run -p pqsigner-xtask`).
/// Falls back to the current directory if the env var is missing — that
/// keeps the binary usable when run outside Cargo (manual invocation,
/// debugger, packaged tooling).
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    manifest_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Render the Solidity library text from `pqsigner-proto`'s public
/// constants. Pure function — same input ⇒ same output, byte-for-byte.
fn render_solidity_library() -> String {
    let mut s = String::with_capacity(2 * 1024);

    s.push_str("// SPDX-License-Identifier: MIT\n");
    s.push_str("// AUTO-GENERATED — DO NOT EDIT.\n");
    s.push_str("// Source of truth: `pqsigner-proto` crate (Rust).\n");
    s.push_str("// Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`.\n");
    s.push_str("//\n");
    s.push_str("// Background: docs/archive/handoff-modularity-refactor.md (Phase 4).\n");
    s.push_str("pragma solidity ^0.8.28;\n");
    s.push('\n');
    s.push_str("/// @notice Cross-language protocol constants shared by the firmware\n");
    s.push_str("///         (Rust, `pqsigner-proto` crate) and the on-chain wallet.\n");
    s.push_str("///         The firmware is the source of truth — every constant in\n");
    s.push_str("///         this library is generated from a `pub const` in the Rust\n");
    s.push_str("///         crate. CI diffs the generated file against\n");
    s.push_str("///         `pqsigner-xtask gen-solidity-constants --check` so any\n");
    s.push_str("///         drift is caught at PR review.\n");
    s.push_str("library PqsignerProto {\n");

    section_header(&mut s, "Signature sizes");
    sol_uint256(&mut s, "C10_SIG_LEN", proto::C10_SIG_LEN as u128);
    let padded_inner = padded_to_32(proto::C10_SIG_LEN as u128);
    sol_uint256_with_doc(
        &mut s,
        "SIG_WRAPPER_LEN",
        // abi.encode(uint256, bytes) head + tail:
        // 32 (ownerIndex) + 32 (offset) + 32 (length) + 32-padded inner sig.
        32 + 32 + 32 + padded_inner,
        "abi.encode(uint256 ownerIndex, bytes innerSig) layout: \
         32 (ownerIndex) + 32 (offset) + 32 (length) + ((C10_SIG_LEN + 31) / 32) * 32",
    );

    section_header(&mut s, "Per-chain usage caps");
    sol_uint256(
        &mut s,
        "MAX_BOOTSTRAP_USES",
        u128::from(proto::MAX_BOOTSTRAP_USES),
    );
    sol_uint256(&mut s, "MAX_SLOT_USES", u128::from(proto::MAX_SLOT_USES));
    sol_uint256(
        &mut s,
        "MAX_OFFCHAIN_GAP",
        u128::from(proto::MAX_OFFCHAIN_GAP),
    );

    section_header(&mut s, "Wallet storage layout");
    sol_uint256(&mut s, "OWNER_BYTES_LEN", proto::OWNER_BYTES_LEN as u128);

    section_header(&mut s, "Selectors");
    sol_bytes4(&mut s, "EXECUTE_SELECTOR", &proto::EXECUTE_SELECTOR);
    sol_bytes4(
        &mut s,
        "EXECUTE_BATCH_SELECTOR",
        &proto::EXECUTE_BATCH_SELECTOR,
    );

    section_header(&mut s, "Domain tags");
    sol_bytes(
        &mut s,
        "FACTORY_ADD_SLOT_DOMAIN",
        proto::FACTORY_ADD_SLOT_DOMAIN,
    );

    s.push_str("}\n");
    s
}

/// Render the Solidity `PqsignerDeployment` library: the CREATE2 constants
/// the firmware predicts wallet addresses with. The deploy scripts refuse
/// to broadcast unless the contracts they are about to deploy produce
/// exactly these, and `DeployedBytecodeReproCheck` (deploy profile, CI)
/// fails when the contracts drift from them. Pure function.
fn render_solidity_deployment_library() -> String {
    let mut s = String::with_capacity(2 * 1024);

    s.push_str("// SPDX-License-Identifier: MIT\n");
    s.push_str("// AUTO-GENERATED — DO NOT EDIT.\n");
    s.push_str("// Source of truth: `pqsigner-proto` crate (Rust).\n");
    s.push_str("// Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`.\n");
    s.push_str("//\n");
    s.push_str("// Kept outside `src/`: these values are derived from the compiled\n");
    s.push_str("// contracts, so the contracts themselves must not import them.\n");
    s.push_str("pragma solidity ^0.8.28;\n");
    s.push('\n');
    s.push_str("/// @notice The CREATE2 constants compiled into the device firmware\n");
    s.push_str("///         (`proto/src/lib.rs`). The firmware predicts every wallet\n");
    s.push_str("///         address from them, so a deployment that does not reproduce\n");
    s.push_str("///         them exactly is unreachable from the device.\n");
    s.push_str("library PqsignerDeployment {\n");

    section_header(&mut s, "Firmware CREATE2 constants");
    let factory = pqsigner_erc7730::display::primitives::eip55_hex(&proto::PQ_SMART_WALLET_FACTORY);
    let factory = std::str::from_utf8(&factory).expect("EIP-55 hex is ASCII");
    let _ = writeln!(
        s,
        "    address internal constant PQ_SMART_WALLET_FACTORY = 0x{factory};"
    );
    let mut hash = String::with_capacity(64);
    for b in proto::PROXY_INIT_CODE_HASH {
        let _ = write!(hash, "{b:02x}");
    }
    let _ = writeln!(s, "    bytes32 internal constant PROXY_INIT_CODE_HASH = 0x{hash};");

    s.push_str("}\n");
    s
}

/// Round `v` up to the next multiple of 32 (Solidity ABI word size).
fn padded_to_32(v: u128) -> u128 {
    v.div_ceil(32) * 32
}

fn section_header(s: &mut String, name: &str) {
    s.push('\n');
    let _ = writeln!(s, "    // ─────────────────────────────────────────────");
    let _ = writeln!(s, "    // {name}");
    let _ = writeln!(s, "    // ─────────────────────────────────────────────");
}

fn sol_uint256(s: &mut String, name: &str, value: u128) {
    let _ = writeln!(s, "    uint256 internal constant {name} = {value};");
}

fn sol_uint256_with_doc(s: &mut String, name: &str, value: u128, doc: &str) {
    let _ = writeln!(s, "    /// @dev {doc}");
    let _ = writeln!(s, "    uint256 internal constant {name} = {value};");
}

fn sol_bytes4(s: &mut String, name: &str, bytes: &[u8; 4]) {
    let _ = writeln!(
        s,
        "    bytes4 internal constant {name} = 0x{:02x}{:02x}{:02x}{:02x};",
        bytes[0], bytes[1], bytes[2], bytes[3],
    );
}

/// Render a `bytes` constant. If every byte is printable ASCII (and
/// safe to embed in a Solidity string literal), use a `"..."` literal —
/// otherwise fall back to `hex"..."`. The hex path is defensive: today
/// this codepath only sees domain tags that are printable ASCII by
/// construction.
fn sol_bytes(s: &mut String, name: &str, bytes: &[u8]) {
    if is_solidity_string_safe(bytes) {
        let s_lit = std::str::from_utf8(bytes).expect("ASCII validated above");
        let _ = writeln!(s, "    bytes internal constant {name} = \"{s_lit}\";");
    } else {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(hex, "{b:02x}");
        }
        let _ = writeln!(s, "    bytes internal constant {name} = hex\"{hex}\";");
    }
}

/// Printable ASCII (0x20–0x7E), excluding `"` and `\` which would need
/// escaping inside a Solidity double-quoted string literal.
fn is_solidity_string_safe(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| (0x20..=0x7E).contains(b) && *b != b'"' && *b != b'\\')
}

// ─────────────────────────────────────────────────────────────────────
// gen-erc7730-descriptors
// ─────────────────────────────────────────────────────────────────────

// PROD catalog now sources from the vendored upstream registry (the corpus
// switch); the policy still lives with the hand-authored render-test fixtures.
const ERC7730_DEFAULT_INPUT: &str = "secure/data/erc7730-registry/registry";
const ERC7730_DEFAULT_POLICY: &str = "secure/data/erc7730/policy.toml";
const ERC7730_DEFAULT_E2E_INPUT: &str = "secure/data/erc7730-e2e";
const ERC7730_DEFAULT_E2E_POLICY: &str = "secure/data/erc7730-e2e/policy.toml";
const ERC20_DEFAULT_INPUT: &str = "secure/data/erc20.json";
const ERC20_DEFAULT_E2E_INPUT: &str = "secure/data/erc20-e2e.json";
const ERC20_DEFAULT_OUT: &str = "tools/companion-stub/erc20_db.bin";
const ERC20_DEFAULT_E2E_OUT: &str = "tools/companion-stub/erc20_db_e2e.bin";
const ERC7730_DEFAULT_OUT: &str = "tools/companion-stub/erc7730_db.bin";
const ERC7730_DEFAULT_E2E_OUT: &str = "tools/companion-stub/erc7730_db_e2e.bin";
const ERC7730_DEFAULT_STATUS_OUT: &str = "tools/companion-stub/erc7730_status.bin";
const ERC7730_DEFAULT_STATUS_E2E_OUT: &str = "tools/companion-stub/erc7730_status_e2e.bin";
const ERC7730_DEFAULT_REVIEW: &str = "secure/data/erc7730.review.txt";
const ERC7730_DEFAULT_KNOWN_CALLS: &str = "secure/data/erc7730-known-calls.bloom";
const ERC7730_DEFAULT_KNOWN_CALLS_E2E: &str = "secure/data/erc7730-known-calls-e2e.bloom";
const ERC7730_DEFAULT_FORCED_ELIGIBLE: &str = "secure/data/erc7730-forced-eligible.set";
const ERC7730_DEFAULT_FORCED_ELIGIBLE_E2E: &str = "secure/data/erc7730-forced-eligible-e2e.set";
const ERC7730_COMPANION_GUIDE: &str = "docs/companion/companion-erc7730-implementation-guide.md";
const ERC7730_COMPANION_INTEGRATION: &str = "docs/companion/erc7730-integration.md";
const ERC7730_REGISTRY_README: &str = "secure/data/erc7730-registry/README.md";
const ERC7730_GUIDE_SUMMARY_BEGIN: &str =
    "   <!-- BEGIN XTASK-VERIFIED ERC7730 CATALOGUE SUMMARY -->";
const ERC7730_GUIDE_SUMMARY_END: &str = "   <!-- END XTASK-VERIFIED ERC7730 CATALOGUE SUMMARY -->";
const ERC7730_GUIDE_ROOTS_BEGIN: &str = "<!-- BEGIN XTASK-VERIFIED ERC7730 CATALOGUE ROOTS -->";
const ERC7730_GUIDE_ROOTS_END: &str = "<!-- END XTASK-VERIFIED ERC7730 CATALOGUE ROOTS -->";
const ERC7730_GUIDE_SEMANTICS_BEGIN: &str =
    "<!-- BEGIN XTASK-VERIFIED ERC7730 SEMANTIC CONTRACT -->";
const ERC7730_GUIDE_SEMANTICS_END: &str = "<!-- END XTASK-VERIFIED ERC7730 SEMANTIC CONTRACT -->";
const ERC7730_INTEGRATION_FACTS_BEGIN: &str =
    "<!-- BEGIN XTASK-VERIFIED ERC7730 INTEGRATION FACTS -->";
const ERC7730_INTEGRATION_FACTS_END: &str = "<!-- END XTASK-VERIFIED ERC7730 INTEGRATION FACTS -->";
const ERC7730_REGISTRY_RECEIPT_BEGIN: &str =
    "<!-- BEGIN XTASK-VERIFIED ERC7730 REGISTRY RECEIPT -->";
const ERC7730_REGISTRY_RECEIPT_END: &str = "<!-- END XTASK-VERIFIED ERC7730 REGISTRY RECEIPT -->";

type Erc7730CallKey = (u64, [u8; 20], [u8; 4]);

const XTASK_P730_HEADER_LEN: usize = 32;
const XTASK_P730_ENTRY_LEN: usize = 72;
const XTASK_P73K_MAGIC: &[u8; 4] = b"P73K";
const XTASK_P73K_SCHEMA: u16 = 1;
const XTASK_P73K_HEADER_LEN: usize = 16;
const XTASK_P73K_GROUP_LEN: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Erc20CapabilityReceipt {
    input_sha256: [u8; 32],
    db_root: [u8; 32],
    entry_count: usize,
    capability_count: usize,
}

/// One exact ERC-20 input and the device-verifiable identity set derived from
/// its generated Merkle database.
///
/// ERC-7730 token interpolation is deployment-sensitive. A catalogue build is
/// therefore not identified by the descriptor corpus alone: it is also bound
/// to the exact ERC-20 source bytes, generated root, and capability-derivation
/// result used by the production device verifier.
struct Erc20CapabilityInput {
    source: PathBuf,
    receipt: Erc20CapabilityReceipt,
    /// Exact companion blob whose root and capabilities produced the
    /// capability-bound ERC-7730 catalogue. Retaining it makes descriptor
    /// drift checking atomic with the metadata authority it depends on.
    blob: Vec<u8>,
    capabilities: dbgen::erc20::Erc20Capabilities,
}

fn load_erc20_capability_input(source: &Path, label: &str) -> Result<Erc20CapabilityInput, String> {
    // `dbgen::erc20::build_db` owns parsing and capability derivation. Read
    // around that call so the byte-level receipt cannot silently describe a
    // different file revision from the one that produced the DB root.
    let before = fs::read(source)
        .map_err(|e| format!("read {label} ERC-20 input {}: {e}", source.display()))?;
    let build = dbgen::erc20::build_db(source)
        .map_err(|e| format!("{label} ERC-20 build from {} failed: {e}", source.display()))?;
    let after = fs::read(source)
        .map_err(|e| format!("re-read {label} ERC-20 input {}: {e}", source.display()))?;
    if before != after {
        return Err(format!(
            "{label} ERC-20 input changed while its capability set was being built: {}",
            source.display()
        ));
    }

    Ok(Erc20CapabilityInput {
        source: source.to_path_buf(),
        receipt: Erc20CapabilityReceipt {
            input_sha256: Sha256::digest(&before).into(),
            db_root: build.root,
            entry_count: build.entry_count,
            capability_count: build.capabilities.len(),
        },
        blob: build.blob,
        capabilities: build.capabilities,
    })
}

fn load_production_erc20_capability_input(
    workspace_root: &Path,
) -> Result<Erc20CapabilityInput, String> {
    load_erc20_capability_input(&workspace_root.join(ERC20_DEFAULT_INPUT), "production")
}

fn render_erc20_capability_receipt(input: &Erc20CapabilityInput) -> String {
    render_erc20_capability_receipt_parts(&input.source, &input.receipt)
}

fn render_erc20_capability_receipt_parts(
    source: &Path,
    receipt: &Erc20CapabilityReceipt,
) -> String {
    format!(
        concat!(
            "erc20 input:              {}\n",
            "erc20 input SHA-256:       {}\n",
            "erc20 generated DB root:   {}\n",
            "erc20 entries/capabilities: {}/{}\n",
        ),
        source.display(),
        hex_lower(&receipt.input_sha256),
        hex_lower(&receipt.db_root),
        receipt.entry_count,
        receipt.capability_count,
    )
}

#[derive(Default)]
struct Erc7730Args {
    check: bool,
    input_dir: Option<PathBuf>,
    policy: Option<PathBuf>,
    e2e_policy: Option<PathBuf>,
    out_binary: Option<PathBuf>,
    out_review: Option<PathBuf>,
    e2e_input_dir: Option<PathBuf>,
    e2e_out_binary: Option<PathBuf>,
    known_calls_out: Option<PathBuf>,
    known_calls_e2e_out: Option<PathBuf>,
    forced_eligible_out: Option<PathBuf>,
    forced_eligible_e2e_out: Option<PathBuf>,
    status_out: Option<PathBuf>,
    status_e2e_out: Option<PathBuf>,
}

fn validate_erc7730_probe_output_isolation(args: &Erc7730Args) -> Result<(), String> {
    let uses_custom_inputs = args.input_dir.is_some()
        || args.policy.is_some()
        || args.e2e_input_dir.is_some()
        || args.e2e_policy.is_some();
    if args.check || !uses_custom_inputs {
        return Ok(());
    }

    let mut missing = Vec::new();
    for (flag, provided) in [
        ("--out-binary", args.out_binary.is_some()),
        ("--out-review", args.out_review.is_some()),
        ("--e2e-out-binary", args.e2e_out_binary.is_some()),
        ("--known-calls-out", args.known_calls_out.is_some()),
        ("--known-calls-e2e-out", args.known_calls_e2e_out.is_some()),
        ("--forced-eligible-out", args.forced_eligible_out.is_some()),
        (
            "--forced-eligible-e2e-out",
            args.forced_eligible_e2e_out.is_some(),
        ),
        ("--status-out", args.status_out.is_some()),
        ("--status-e2e-out", args.status_e2e_out.is_some()),
    ] {
        if !provided {
            missing.push(flag);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "custom ERC-7730 input/policy probes in write mode require every output path to be explicit; missing: {}",
            missing.join(", ")
        ))
    }
}

fn parse_erc7730_args(args: &[String]) -> Result<Erc7730Args, String> {
    let mut out = Erc7730Args::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => out.check = true,
            "--input-dir" => {
                i += 1;
                out.input_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--input-dir requires a value")?,
                ));
            }
            "--policy" => {
                i += 1;
                out.policy = Some(PathBuf::from(
                    args.get(i).ok_or("--policy requires a value")?,
                ));
            }
            "--e2e-policy" => {
                i += 1;
                out.e2e_policy = Some(PathBuf::from(
                    args.get(i).ok_or("--e2e-policy requires a value")?,
                ));
            }
            "--out-binary" => {
                i += 1;
                out.out_binary = Some(PathBuf::from(
                    args.get(i).ok_or("--out-binary requires a value")?,
                ));
            }
            "--out-review" => {
                i += 1;
                out.out_review = Some(PathBuf::from(
                    args.get(i).ok_or("--out-review requires a value")?,
                ));
            }
            "--e2e-input-dir" => {
                i += 1;
                out.e2e_input_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--e2e-input-dir requires a value")?,
                ));
            }
            "--e2e-out-binary" => {
                i += 1;
                out.e2e_out_binary = Some(PathBuf::from(
                    args.get(i).ok_or("--e2e-out-binary requires a value")?,
                ));
            }
            "--known-calls-out" => {
                i += 1;
                out.known_calls_out = Some(PathBuf::from(
                    args.get(i).ok_or("--known-calls-out requires a value")?,
                ));
            }
            "--known-calls-e2e-out" => {
                i += 1;
                out.known_calls_e2e_out = Some(PathBuf::from(
                    args.get(i)
                        .ok_or("--known-calls-e2e-out requires a value")?,
                ));
            }
            "--forced-eligible-out" => {
                i += 1;
                out.forced_eligible_out = Some(PathBuf::from(
                    args.get(i)
                        .ok_or("--forced-eligible-out requires a value")?,
                ));
            }
            "--forced-eligible-e2e-out" => {
                i += 1;
                out.forced_eligible_e2e_out = Some(PathBuf::from(
                    args.get(i)
                        .ok_or("--forced-eligible-e2e-out requires a value")?,
                ));
            }
            "--status-out" => {
                i += 1;
                out.status_out = Some(PathBuf::from(
                    args.get(i).ok_or("--status-out requires a value")?,
                ));
            }
            "--status-e2e-out" => {
                i += 1;
                out.status_e2e_out = Some(PathBuf::from(
                    args.get(i).ok_or("--status-e2e-out requires a value")?,
                ));
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok(out)
}

struct Erc7730CatalogueBuild {
    prod: dbgen::erc7730::Erc7730BuildResult,
    prod_skips: Vec<dbgen::erc7730::SkipReport>,
    e2e: dbgen::erc7730::Erc7730BuildResult,
    prod_erc20: Erc20CapabilityInput,
    e2e_erc20: Erc20CapabilityInput,
}

struct CapabilityBoundRegistryBuild {
    catalogue: dbgen::erc7730::Erc7730BuildResult,
    skips: Vec<dbgen::erc7730::SkipReport>,
    erc20: Erc20CapabilityReceipt,
}

fn build_capability_bound_registry(
    input: &Path,
    policy: &Path,
    registry_root: Option<&Path>,
    erc20: &Erc20CapabilityInput,
) -> Result<CapabilityBoundRegistryBuild, String> {
    let (catalogue, skips) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
        input,
        policy,
        registry_root,
        &erc20.capabilities,
    )?;
    Ok(CapabilityBoundRegistryBuild {
        catalogue,
        skips,
        erc20: erc20.receipt,
    })
}

/// Build the same capability-bound production and E2E catalogues as dbgen.
///
/// Token-amount interpolation is deployment-sensitive, so descriptor codegen
/// must derive its capability sets from the exact ERC-20 inputs committed by
/// the corresponding Merkle databases. Keeping this shared by generation and
/// `--check` prevents either path from silently falling back to the
/// conservative, capability-free compiler API.
fn build_erc7730_catalogues(
    workspace_root: &Path,
    input_dir: &Path,
    policy: &Path,
    registry_root: Option<&Path>,
    e2e_input_dir: &Path,
    e2e_policy: &Path,
) -> Result<Erc7730CatalogueBuild, String> {
    let prod_erc20 = load_production_erc20_capability_input(workspace_root)?;
    let e2e_erc20 =
        load_erc20_capability_input(&workspace_root.join(ERC20_DEFAULT_E2E_INPUT), "e2e")?;

    let (prod, prod_skips) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
        input_dir,
        policy,
        registry_root,
        &prod_erc20.capabilities,
    )
    .map_err(|e| format!("prod build failed: {e}"))?;
    let e2e = dbgen::erc7730::build_e2e_db_with_policy_override_and_erc20_capabilities(
        e2e_input_dir,
        e2e_policy,
        false,
        None,
        &e2e_erc20.capabilities,
    )
    .map_err(|e| format!("e2e build failed: {e}"))?;

    Ok(Erc7730CatalogueBuild {
        prod,
        prod_skips,
        e2e,
        prod_erc20,
        e2e_erc20,
    })
}

fn cmd_gen_erc7730_descriptors(args: &[String]) -> ExitCode {
    let parsed = match parse_erc7730_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = validate_erc7730_probe_output_isolation(&parsed) {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let workspace_root = manifest_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let input_dir = parsed
        .input_dir
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_INPUT));
    let policy = parsed
        .policy
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_POLICY));
    let out_binary = parsed
        .out_binary
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_OUT));
    let out_review = parsed
        .out_review
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_REVIEW));
    let e2e_input_dir = parsed
        .e2e_input_dir
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_INPUT));
    let e2e_policy = parsed
        .e2e_policy
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_POLICY));
    let e2e_out_binary = parsed
        .e2e_out_binary
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_OUT));
    let known_calls_out = parsed
        .known_calls_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_KNOWN_CALLS));
    let known_calls_e2e_out = parsed
        .known_calls_e2e_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_KNOWN_CALLS_E2E));
    let forced_eligible_out = parsed
        .forced_eligible_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_FORCED_ELIGIBLE));
    let forced_eligible_e2e_out = parsed
        .forced_eligible_e2e_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_FORCED_ELIGIBLE_E2E));
    let status_out = parsed
        .status_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_STATUS_OUT));
    let status_e2e_out = parsed
        .status_e2e_out
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_STATUS_E2E_OUT));
    let erc20_out = workspace_root.join(ERC20_DEFAULT_OUT);
    let erc20_e2e_out = workspace_root.join(ERC20_DEFAULT_E2E_OUT);

    // Default production generation always verifies the local manifest/tool
    // identities before stamping its upstream commit into the review header.
    // `--check` additionally proves that the checked-in curated corpus is
    // exactly reproducible. Custom-input probes remain unstamped and make no
    // production-corpus provenance claim.
    let default_overlay = if input_dir == workspace_root.join(ERC7730_DEFAULT_INPUT)
        && policy == workspace_root.join(ERC7730_DEFAULT_POLICY)
    {
        let manifest_path = workspace_root.join(ERC7730_DEFAULT_CURATION_MANIFEST);
        let overlay = match erc7730_curation::VerifiedOverlay::load_and_verify_local_inputs(
            &workspace_root,
            &manifest_path,
        ) {
            Ok(overlay) => overlay,
            Err(error) => {
                eprintln!("DRIFT: ERC-7730 curation overlay: {error}");
                return ExitCode::FAILURE;
            }
        };
        if parsed.check {
            let vendored_root = workspace_root.join("secure/data/erc7730-registry");
            if let Err(error) = overlay.verify_checked_in_tree(&vendored_root) {
                eprintln!("DRIFT: ERC-7730 curation overlay: {error}");
                return ExitCode::FAILURE;
            }
        }
        Some(overlay)
    } else {
        None
    };

    // Build both prod + e2e catalogs. PROD is the tolerant registry build
    // (the corpus switch) — `input_dir` is `<registry>/registry`, so its parent
    // is the registry root used to resolve `includes`. E2E stays strict.
    let registry_root = input_dir.parent().map(|p| p.to_path_buf());
    let Erc7730CatalogueBuild {
        mut prod,
        prod_skips,
        e2e,
        prod_erc20,
        e2e_erc20,
    } = match build_erc7730_catalogues(
        &workspace_root,
        &input_dir,
        &policy,
        registry_root.as_deref(),
        &e2e_input_dir,
        &e2e_policy,
    ) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(overlay) = default_overlay.as_ref() {
        let review_source = match dbgen::erc7730::RegistryReviewSource::new(
            overlay.upstream_commit(),
            overlay.upstream_tree(),
            overlay.manifest_sha256(),
        ) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("error: ERC-7730 review provenance failed: {error}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(error) =
            dbgen::erc7730::stamp_registry_review_source(&mut prod.review_text, &review_source)
        {
            eprintln!("error: ERC-7730 review provenance failed: {error}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = dbgen::erc7730::round_trip_check(&prod) {
        eprintln!("error: prod round-trip failed: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = dbgen::erc7730::round_trip_check(&e2e) {
        eprintln!("error: e2e round-trip failed: {e}");
        return ExitCode::FAILURE;
    }
    let prod_curation_sha256 = default_overlay
        .as_ref()
        .map(|overlay| overlay.manifest_sha256())
        .unwrap_or([0; 32]);
    let prod_status = match dbgen::erc7730::catalogue_status_v1(&prod, prod_curation_sha256) {
        Ok(status) => status.to_bytes(),
        Err(error) => {
            eprintln!("error: prod catalogue status failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let e2e_status = match dbgen::erc7730::catalogue_status_v1(&e2e, [0; 32]) {
        Ok(status) => status.to_bytes(),
        Err(error) => {
            eprintln!("error: e2e catalogue status failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = xtask_reconcile_forced_partition("production", &prod, &prod_status) {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = xtask_reconcile_forced_partition("e2e", &e2e, &e2e_status) {
        eprintln!("error: {error}");
        return ExitCode::FAILURE;
    }

    if parsed.check {
        // CI mode: diff against checked-in artifacts.
        let mut drift = false;
        if let Err(e) = diff_erc20_blob_pair(
            &erc20_out,
            &prod_erc20.blob,
            &erc20_e2e_out,
            &e2e_erc20.blob,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes("erc7730_db.bin", &out_binary, &prod.blob) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes("erc7730_db_e2e.bin", &e2e_out_binary, &e2e.blob) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_text("erc7730.review.txt", &out_review, &prod.review_text) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-known-calls.bloom",
            &known_calls_out,
            &prod.known_calls_bloom,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes("erc7730_status.bin", &status_out, &prod_status) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes("erc7730_status_e2e.bin", &status_e2e_out, &e2e_status) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-known-calls-e2e.bloom",
            &known_calls_e2e_out,
            &e2e.known_calls_bloom,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-forced-eligible.set",
            &forced_eligible_out,
            &prod.forced_eligible_set,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-forced-eligible-e2e.set",
            &forced_eligible_e2e_out,
            &e2e.forced_eligible_set,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        // db_roots.rs is owned by `cargo run -p dbgen` (it bakes other roots
        // besides this composed surface). Validate the exact production/E2E
        // ERC-20 sections and the exact ERC-7730 security suffix together.
        let roots_path = workspace_root.join("secure/src/db_roots.rs");
        if let Err(e) = diff_catalogue_roots_in_db_roots(
            &roots_path,
            &prod_erc20.receipt.db_root,
            &e2e_erc20.receipt.db_root,
            &prod.root,
            prod.leaf_count,
            &e2e.root,
            e2e.leaf_count,
            prod.provenance,
            &prod_status,
            prod.forced_eligible_set.len(),
            prod.forced_eligible_group_count,
            prod.forced_eligible_count,
            e2e.provenance,
            &e2e_status,
            e2e.forced_eligible_set.len(),
            e2e.forced_eligible_group_count,
            e2e.forced_eligible_count,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        let companion_guide = workspace_root.join(ERC7730_COMPANION_GUIDE);
        if let Err(e) = diff_erc7730_companion_guide(
            &companion_guide,
            &prod.root,
            prod.leaf_count,
            prod.blob.len(),
            prod.known_call_count,
            &prod.known_call_set_hash,
            prod.provenance,
            &e2e.root,
            e2e.leaf_count,
            e2e.blob.len(),
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        let companion_integration = workspace_root.join(ERC7730_COMPANION_INTEGRATION);
        if let Err(e) = diff_erc7730_companion_integration(
            &companion_integration,
            &prod.root,
            prod.leaf_count,
            prod.known_call_count,
            &prod.known_call_set_hash,
            &prod.known_calls_bloom,
            prod_skips.len(),
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        let registry_readme = workspace_root.join(ERC7730_REGISTRY_README);
        let curation_receipt = default_overlay
            .as_ref()
            .map(|overlay| Erc7730CurationReceipt {
                manifest_sha256: overlay.manifest_sha256(),
                upstream_commit: overlay.upstream_commit(),
                upstream_tree: overlay.upstream_tree(),
                known_call_addition_count: overlay.known_call_addition_count(),
            });
        if let Err(e) = diff_erc7730_registry_readme(
            &registry_readme,
            &prod.root,
            prod.leaf_count,
            prod.blob.len(),
            prod.known_call_count,
            &prod.known_call_set_hash,
            &prod.known_calls_bloom,
            curation_receipt,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if drift {
            eprintln!(
                "\nThe capability-bound ERC-20/ERC-7730 catalog has drifted from the checked-in artifacts.\n\
                 Run `cargo run -p dbgen` (which writes ALL DBs in one pass) and\n\
                 update the XTASK-VERIFIED catalogue facts in the managed docs,\n\
                 then commit the resulting changes."
            );
            return ExitCode::FAILURE;
        }
        eprintln!("erc7730: in sync");
        return ExitCode::SUCCESS;
    }

    // Write artifacts.
    if let Some(parent) = out_binary.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("error: cannot create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = fs::write(&out_binary, &prod.blob) {
        eprintln!("error: write {}: {e}", out_binary.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&e2e_out_binary, &e2e.blob) {
        eprintln!("error: write {}: {e}", e2e_out_binary.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&out_review, &prod.review_text) {
        eprintln!("error: write {}: {e}", out_review.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&known_calls_out, prod.known_calls_bloom) {
        eprintln!("error: write {}: {e}", known_calls_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&known_calls_e2e_out, e2e.known_calls_bloom) {
        eprintln!("error: write {}: {e}", known_calls_e2e_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&forced_eligible_out, &prod.forced_eligible_set) {
        eprintln!("error: write {}: {e}", forced_eligible_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&forced_eligible_e2e_out, &e2e.forced_eligible_set) {
        eprintln!("error: write {}: {e}", forced_eligible_e2e_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&status_out, prod_status) {
        eprintln!("error: write {}: {e}", status_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&status_e2e_out, e2e_status) {
        eprintln!("error: write {}: {e}", status_e2e_out.display());
        return ExitCode::FAILURE;
    }
    eprintln!(
        "wrote {} ({} bytes, {} leaves, root = {})",
        out_binary.display(),
        prod.blob.len(),
        prod.leaf_count,
        hex::encode(prod.root),
    );
    eprintln!(
        "wrote {} ({} bytes, {} leaves, e2e root = {})",
        e2e_out_binary.display(),
        e2e.blob.len(),
        e2e.leaf_count,
        hex::encode(e2e.root),
    );
    eprintln!(
        "wrote {} ({} known calls)",
        known_calls_out.display(),
        prod.known_call_count,
    );
    eprintln!(
        "wrote {} ({} known calls)",
        known_calls_e2e_out.display(),
        e2e.known_call_count,
    );
    eprintln!(
        "wrote {} ({} refused-known tuples)",
        forced_eligible_out.display(),
        prod.forced_eligible_count,
    );
    eprintln!(
        "wrote {} ({} refused-known tuples)",
        forced_eligible_e2e_out.display(),
        e2e.forced_eligible_count,
    );
    eprintln!("wrote {}", out_review.display());
    eprintln!("wrote {}", status_out.display());
    eprintln!("wrote {}", status_e2e_out.display());
    eprintln!(
        "note: secure/src/db_roots.rs is owned by `cargo run -p dbgen` — \
         run that to refresh the ERC7730_DESCRIPTORS_ROOT constant."
    );
    ExitCode::SUCCESS
}

fn diff_bytes(label: &str, path: &Path, fresh: &[u8]) -> Result<(), String> {
    let existing =
        fs::read(path).map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
    if existing == fresh {
        return Ok(());
    }
    Err(format!(
        "{label} at {} differs from fresh build ({} vs {} bytes)",
        path.display(),
        existing.len(),
        fresh.len()
    ))
}

fn diff_erc20_blob_pair(
    prod_path: &Path,
    prod_fresh: &[u8],
    e2e_path: &Path,
    e2e_fresh: &[u8],
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = diff_bytes("erc20_db.bin", prod_path, prod_fresh) {
        errors.push(error);
    }
    if let Err(error) = diff_bytes("erc20_db_e2e.bin", e2e_path, e2e_fresh) {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn diff_text(label: &str, path: &Path, fresh: &str) -> Result<(), String> {
    let existing =
        fs::read_to_string(path).map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
    if existing == fresh {
        return Ok(());
    }
    Err(format!(
        "{label} at {} differs from fresh build",
        path.display()
    ))
}

/// Independently reconcile the generated clear-capable and refused-known
/// partitions against the exact P730/P73K/P73S/Bloom bytes. This deliberately
/// does not call dbgen's partition checker: the drift gate is a second parser
/// and a second derivation of the release relation.
fn xtask_reconcile_forced_partition(
    label: &str,
    result: &dbgen::erc7730::Erc7730BuildResult,
    status_bytes: &[u8],
) -> Result<(), String> {
    let status = pqsigner_erc7730::catalogue_status::CatalogueStatusV1::from_bytes(status_bytes)
        .map_err(|error| format!("{label}: strict P73S parse failed: {error:?}"))?;
    let clear = xtask_recover_clear_calls_from_p730(&result.blob)
        .map_err(|error| format!("{label}: independent P730 parse failed: {error}"))?;
    let forced = xtask_decode_p73k(&result.forced_eligible_set)
        .map_err(|error| format!("{label}: independent P73K parse failed: {error}"))?;

    let known = result
        .known_calls
        .iter()
        .copied()
        .collect::<BTreeSet<Erc7730CallKey>>();
    if known.len() != result.known_calls.len()
        || !result.known_calls.iter().copied().eq(known.iter().copied())
    {
        return Err(format!(
            "{label}: dbgen exact known-call vector is not canonical sorted/unique"
        ));
    }
    if !clear.is_subset(&known) {
        return Err(format!(
            "{label}: P730 clear-capable set is not a subset of exact K"
        ));
    }
    if !clear.is_disjoint(&forced) {
        return Err(format!("{label}: P730 C intersects decoded P73K F"));
    }
    let expected_forced = known.difference(&clear).copied().collect::<BTreeSet<_>>();
    if forced != expected_forced {
        return Err(format!(
            "{label}: decoded P73K does not equal exact K \\ C (decoded={}, expected={})",
            forced.len(),
            expected_forced.len()
        ));
    }
    let reconstructed = clear.union(&forced).copied().collect::<BTreeSet<_>>();
    if reconstructed != known {
        return Err(format!("{label}: C union F does not reconstruct exact K"));
    }

    let known_hash = xtask_known_call_set_hash(&reconstructed)?;
    if known_hash != result.known_call_set_hash
        || known_hash != status.known_call_set_sha256
        || usize::try_from(status.known_call_count).ok() != Some(reconstructed.len())
        || result.known_call_count != reconstructed.len()
    {
        return Err(format!(
            "{label}: reconstructed K count/hash disagrees with dbgen or P73S"
        ));
    }
    let catalogue_sha256: [u8; 32] = Sha256::digest(&result.blob).into();
    if usize::try_from(status.catalogue_blob_size).ok() != Some(result.blob.len())
        || status.catalogue_sha256 != catalogue_sha256
    {
        return Err(format!("{label}: P73S does not bind the exact P730 bytes"));
    }
    let bloom_sha256: [u8; 32] = Sha256::digest(result.known_calls_bloom).into();
    if usize::try_from(status.bloom_size).ok() != Some(result.known_calls_bloom.len())
        || status.bloom_sha256 != bloom_sha256
    {
        return Err(format!(
            "{label}: P73S does not bind the exact all-known Bloom"
        ));
    }
    for (chain_id, contract, selector) in &reconstructed {
        if !pqsigner_erc7730::known_calls::may_contain(
            &result.known_calls_bloom,
            *chain_id,
            contract,
            selector,
        ) {
            return Err(format!(
                "{label}: all-known Bloom has a false negative for reconstructed K tuple chain={chain_id} contract=0x{} selector=0x{}",
                hex::encode(contract),
                hex::encode(selector),
            ));
        }
    }
    Ok(())
}

fn xtask_recover_clear_calls_from_p730(blob: &[u8]) -> Result<BTreeSet<Erc7730CallKey>, String> {
    use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir, CTX_CONTRACT, CTX_EIP712};

    if blob.len() < XTASK_P730_HEADER_LEN || blob.get(..4) != Some(&b"P730"[..]) {
        return Err("missing P730 header".to_string());
    }
    let version = xtask_read_u32_le(blob, 4, "P730 version")?;
    let flags = xtask_read_u32_le(blob, 8, "P730 flags")?;
    let entry_count = usize::try_from(xtask_read_u32_le(blob, 12, "P730 entry count")?)
        .map_err(|_| "P730 entry count does not fit usize".to_string())?;
    let ir_pool_off = usize::try_from(xtask_read_u32_le(blob, 16, "P730 IR pool offset")?)
        .map_err(|_| "P730 IR pool offset does not fit usize".to_string())?;
    let ir_pool_size = usize::try_from(xtask_read_u32_le(blob, 20, "P730 IR pool size")?)
        .map_err(|_| "P730 IR pool size does not fit usize".to_string())?;
    let proof_depth = usize::try_from(xtask_read_u32_le(blob, 24, "P730 proof depth")?)
        .map_err(|_| "P730 proof depth does not fit usize".to_string())?;
    let proofs_off = usize::try_from(xtask_read_u32_le(blob, 28, "P730 proofs offset")?)
        .map_err(|_| "P730 proofs offset does not fit usize".to_string())?;
    if version != dbgen::erc7730::ERC7730_DB_VERSION || flags != 0 || entry_count == 0 {
        return Err("unsupported P730 header fields".to_string());
    }
    let entries_len = entry_count
        .checked_mul(XTASK_P730_ENTRY_LEN)
        .ok_or_else(|| "P730 entry table length overflow".to_string())?;
    let entries_end = XTASK_P730_HEADER_LEN
        .checked_add(entries_len)
        .ok_or_else(|| "P730 entry table end overflow".to_string())?;
    let ir_pool_end = ir_pool_off
        .checked_add(ir_pool_size)
        .ok_or_else(|| "P730 IR pool end overflow".to_string())?;
    let proofs_len = entry_count
        .checked_mul(proof_depth)
        .and_then(|value| value.checked_mul(32))
        .ok_or_else(|| "P730 proof region length overflow".to_string())?;
    let expected_end = proofs_off
        .checked_add(proofs_len)
        .ok_or_else(|| "P730 proof region end overflow".to_string())?;
    let expected_depth = if entry_count <= 1 {
        0
    } else {
        usize::BITS as usize - (entry_count - 1).leading_zeros() as usize
    };
    if ir_pool_off != entries_end
        || proofs_off != ir_pool_end
        || expected_end != blob.len()
        || proof_depth != expected_depth
        || proof_depth > pqsigner_erc7730::bundle::MAX_PROOF_DEPTH
    {
        return Err("non-canonical P730 regions or proof depth".to_string());
    }

    let mut clear = BTreeSet::new();
    let mut next_ir_off = 0usize;
    let mut previous_key: Option<(u64, [u8; 20], [u8; 32], u8)> = None;
    for index in 0..entry_count {
        let base = XTASK_P730_HEADER_LEN
            .checked_add(
                index
                    .checked_mul(XTASK_P730_ENTRY_LEN)
                    .ok_or_else(|| "P730 entry offset overflow".to_string())?,
            )
            .ok_or_else(|| "P730 entry offset overflow".to_string())?;
        let entry = blob
            .get(base..base + XTASK_P730_ENTRY_LEN)
            .ok_or_else(|| format!("P730 entry {index} is truncated"))?;
        let chain_id = u64::from_le_bytes(
            entry[0..8]
                .try_into()
                .map_err(|_| "P730 chain slice".to_string())?,
        );
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&entry[8..28]);
        let mut primary_type_hash = [0u8; 32];
        primary_type_hash.copy_from_slice(&entry[28..60]);
        let context_kind = entry[60];
        if !matches!(context_kind, CTX_CONTRACT | CTX_EIP712) || entry[61..64] != [0; 3] {
            return Err(format!(
                "P730 entry {index} has invalid context/reserved bytes"
            ));
        }
        let ir_off = usize::try_from(u32::from_le_bytes(
            entry[64..68]
                .try_into()
                .map_err(|_| "P730 IR offset slice".to_string())?,
        ))
        .map_err(|_| "P730 IR offset does not fit usize".to_string())?;
        let ir_len = usize::try_from(u32::from_le_bytes(
            entry[68..72]
                .try_into()
                .map_err(|_| "P730 IR length slice".to_string())?,
        ))
        .map_err(|_| "P730 IR length does not fit usize".to_string())?;
        if ir_off != next_ir_off || ir_len == 0 || ir_len > pqsigner_erc7730::ir::MAX_IR_LEN {
            return Err(format!("P730 entry {index} has a non-canonical IR range"));
        }
        let ir_start = ir_pool_off
            .checked_add(ir_off)
            .ok_or_else(|| "P730 IR start overflow".to_string())?;
        let ir_end = ir_start
            .checked_add(ir_len)
            .ok_or_else(|| "P730 IR end overflow".to_string())?;
        if ir_end > proofs_off {
            return Err(format!("P730 entry {index} IR exceeds its pool"));
        }
        let ir = Erc7730Ir::parse(
            blob.get(ir_start..ir_end)
                .ok_or_else(|| format!("P730 entry {index} IR is truncated"))?,
        )
        .map_err(|error| format!("P730 entry {index} IR parse failed: {error:?}"))?;
        let expected_context = if context_kind == CTX_CONTRACT {
            ContextKind::Contract
        } else {
            ContextKind::Eip712
        };
        if ir.chain_id != chain_id
            || ir.contract != contract
            || ir.context_kind != expected_context
            || ir.schema_ver != pqsigner_erc7730::ir::SCHEMA_VER
        {
            return Err(format!("P730 entry {index} index/IR binding mismatch"));
        }

        let key = (chain_id, contract, primary_type_hash, context_kind);
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(format!(
                "P730 entry {index} sort key is not strictly increasing"
            ));
        }
        previous_key = Some(key);

        let mut format_count = 0usize;
        let mut first_type_hash = None;
        for format in ir.format_iter() {
            let format = format
                .map_err(|error| format!("P730 entry {index} format parse failed: {error:?}"))?;
            format_count += 1;
            first_type_hash.get_or_insert(format.type_hash);
            if context_kind == CTX_CONTRACT && !clear.insert((chain_id, contract, format.selector))
            {
                return Err(format!(
                    "P730 duplicates a clear-capable tuple at entry {index} selector 0x{}",
                    hex::encode(format.selector)
                ));
            }
        }
        if format_count == 0 {
            return Err(format!("P730 entry {index} contains no accepted format"));
        }
        let expected_primary = if context_kind == CTX_CONTRACT {
            [0u8; 32]
        } else {
            first_type_hash.ok_or_else(|| "missing EIP-712 format".to_string())?
        };
        if primary_type_hash != expected_primary {
            return Err(format!("P730 entry {index} primary-type index mismatch"));
        }
        next_ir_off = ir_off
            .checked_add(ir_len)
            .ok_or_else(|| "P730 IR cursor overflow".to_string())?;
    }
    if next_ir_off != ir_pool_size {
        return Err("P730 IR entries do not consume the exact pool".to_string());
    }
    Ok(clear)
}

fn xtask_decode_p73k(bytes: &[u8]) -> Result<BTreeSet<Erc7730CallKey>, String> {
    if bytes.len() < XTASK_P73K_HEADER_LEN || bytes.get(..4) != Some(&XTASK_P73K_MAGIC[..]) {
        return Err("missing P73K header".to_string());
    }
    let schema = xtask_read_u16_be(bytes, 4, "P73K schema")?;
    let header_len = usize::from(xtask_read_u16_be(bytes, 6, "P73K header length")?);
    let group_count = usize::try_from(xtask_read_u32_be(bytes, 8, "P73K group count")?)
        .map_err(|_| "P73K group count does not fit usize".to_string())?;
    let tuple_count = usize::try_from(xtask_read_u32_be(bytes, 12, "P73K tuple count")?)
        .map_err(|_| "P73K tuple count does not fit usize".to_string())?;
    if schema != XTASK_P73K_SCHEMA || header_len != XTASK_P73K_HEADER_LEN {
        return Err("unsupported P73K schema/header length".to_string());
    }
    let groups_len = group_count
        .checked_mul(XTASK_P73K_GROUP_LEN)
        .ok_or_else(|| "P73K group table length overflow".to_string())?;
    let selector_pool_len = tuple_count
        .checked_mul(4)
        .ok_or_else(|| "P73K selector pool length overflow".to_string())?;
    let pool_off = XTASK_P73K_HEADER_LEN
        .checked_add(groups_len)
        .ok_or_else(|| "P73K pool offset overflow".to_string())?;
    let expected_len = pool_off
        .checked_add(selector_pool_len)
        .ok_or_else(|| "P73K total length overflow".to_string())?;
    if expected_len != bytes.len() {
        return Err(format!(
            "P73K exact length mismatch: {} != {expected_len}",
            bytes.len()
        ));
    }

    let mut out = BTreeSet::new();
    let mut expected_selector_start = 0usize;
    let mut previous_group: Option<(u64, [u8; 20])> = None;
    for group_index in 0..group_count {
        let base = XTASK_P73K_HEADER_LEN
            .checked_add(
                group_index
                    .checked_mul(XTASK_P73K_GROUP_LEN)
                    .ok_or_else(|| "P73K group offset overflow".to_string())?,
            )
            .ok_or_else(|| "P73K group offset overflow".to_string())?;
        let group = bytes
            .get(base..base + XTASK_P73K_GROUP_LEN)
            .ok_or_else(|| format!("P73K group {group_index} is truncated"))?;
        let chain_id = u64::from_be_bytes(
            group[0..8]
                .try_into()
                .map_err(|_| "P73K chain slice".to_string())?,
        );
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&group[8..28]);
        let selector_start = usize::try_from(u32::from_be_bytes(
            group[28..32]
                .try_into()
                .map_err(|_| "P73K selector start slice".to_string())?,
        ))
        .map_err(|_| "P73K selector start does not fit usize".to_string())?;
        let selector_count = usize::from(u16::from_be_bytes(
            group[32..34]
                .try_into()
                .map_err(|_| "P73K selector count slice".to_string())?,
        ));
        if group[34..36] != [0; 2] || selector_count == 0 {
            return Err(format!(
                "P73K group {group_index} has invalid count/reserved bytes"
            ));
        }
        let group_key = (chain_id, contract);
        if previous_group.is_some_and(|previous| group_key <= previous) {
            return Err(format!("P73K group {group_index} is not strictly sorted"));
        }
        if selector_start != expected_selector_start {
            return Err(format!(
                "P73K group {group_index} selector range has a gap/overlap"
            ));
        }
        let selector_end = selector_start
            .checked_add(selector_count)
            .ok_or_else(|| "P73K selector range overflow".to_string())?;
        if selector_end > tuple_count {
            return Err(format!(
                "P73K group {group_index} selector range exceeds pool"
            ));
        }
        let mut previous_selector: Option<[u8; 4]> = None;
        for selector_index in selector_start..selector_end {
            let selector_off = pool_off
                .checked_add(
                    selector_index
                        .checked_mul(4)
                        .ok_or_else(|| "P73K selector offset overflow".to_string())?,
                )
                .ok_or_else(|| "P73K selector offset overflow".to_string())?;
            let mut selector = [0u8; 4];
            selector.copy_from_slice(
                bytes
                    .get(selector_off..selector_off + 4)
                    .ok_or_else(|| "P73K selector is truncated".to_string())?,
            );
            if previous_selector.is_some_and(|previous| selector <= previous) {
                return Err(format!(
                    "P73K group {group_index} selectors are not strictly sorted"
                ));
            }
            if !out.insert((chain_id, contract, selector)) {
                return Err("P73K contains a duplicate tuple".to_string());
            }
            previous_selector = Some(selector);
        }
        previous_group = Some(group_key);
        expected_selector_start = selector_end;
    }
    if expected_selector_start != tuple_count
        || (group_count == 0) != (tuple_count == 0)
        || out.len() != tuple_count
    {
        return Err("P73K group ranges do not exactly cover the selector pool".to_string());
    }
    Ok(out)
}

fn xtask_known_call_set_hash(tuples: &BTreeSet<Erc7730CallKey>) -> Result<[u8; 32], String> {
    let count = u64::try_from(tuples.len())
        .map_err(|_| "known-call tuple count does not fit u64".to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(b"pqsigner/erc7730-known-call-set-v1");
    hasher.update(count.to_be_bytes());
    for (chain_id, contract, selector) in tuples {
        hasher.update(chain_id.to_be_bytes());
        hasher.update(contract);
        hasher.update(selector);
    }
    Ok(hasher.finalize().into())
}

fn xtask_read_u16_be(bytes: &[u8], offset: usize, label: &str) -> Result<u16, String> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| format!("{label} is truncated"))?;
    Ok(u16::from_be_bytes(
        raw.try_into().map_err(|_| format!("{label} width"))?,
    ))
}

fn xtask_read_u32_be(bytes: &[u8], offset: usize, label: &str) -> Result<u32, String> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("{label} is truncated"))?;
    Ok(u32::from_be_bytes(
        raw.try_into().map_err(|_| format!("{label} width"))?,
    ))
}

fn xtask_read_u32_le(bytes: &[u8], offset: usize, label: &str) -> Result<u32, String> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("{label} is truncated"))?;
    Ok(u32::from_le_bytes(
        raw.try_into().map_err(|_| format!("{label} width"))?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn diff_catalogue_roots_in_db_roots(
    path: &Path,
    erc20_prod_root: &[u8; 32],
    erc20_e2e_root: &[u8; 32],
    prod_root: &[u8; 32],
    prod_count: usize,
    e2e_root: &[u8; 32],
    e2e_count: usize,
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    prod_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    prod_forced_len: usize,
    prod_forced_group_count: usize,
    prod_forced_count: usize,
    e2e_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    e2e_forced_len: usize,
    e2e_forced_group_count: usize,
    e2e_forced_count: usize,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read db_roots.rs at {}: {e}", path.display()))?;
    if !erc20_root_sections_match(&text, erc20_prod_root, erc20_e2e_root) {
        return Err(format!(
            "ERC-20 production/E2E root sections in {} do not exactly match the fresh capability databases (expected prod root {}, e2e root {})",
            path.display(),
            hex::encode(erc20_prod_root),
            hex::encode(erc20_e2e_root),
        ));
    }
    if erc7730_security_tail_matches(
        &text,
        prod_root,
        prod_count,
        e2e_root,
        e2e_count,
        prod_provenance,
        prod_status,
        prod_forced_len,
        prod_forced_group_count,
        prod_forced_count,
        e2e_provenance,
        e2e_status,
        e2e_forced_len,
        e2e_forced_group_count,
        e2e_forced_count,
    ) {
        return Ok(());
    }
    let sentinel_count = text.matches(dbgen::ERC7730_SECURITY_TAIL_SENTINEL).count();
    Err(format!(
        "ERC-7730 generated security tail in {} does not exactly match the fresh byte-for-byte suffix through EOF (sentinels={sentinel_count}, expected prod root {}, e2e root {}, prod provenance {}, e2e provenance {})",
        path.display(),
        hex::encode(prod_root),
        hex::encode(e2e_root),
        prod_provenance.as_str(),
        e2e_provenance.as_str(),
    ))
}

const ERC20_ROOT_SECTION_START: &str =
    "#[cfg(not(feature = \"e2e-test\"))]\npub static ERC20_DB_ROOT";
const ERC20_ROOT_SECTION_END: &str =
    "#[cfg(not(feature = \"e2e-test\"))]\npub static NAMES_DB_ROOT";

fn erc20_root_sections_match(text: &str, prod: &[u8; 32], e2e: &[u8; 32]) -> bool {
    if text.matches(ERC20_ROOT_SECTION_START).count() != 1
        || text.matches(ERC20_ROOT_SECTION_END).count() != 1
        || text.matches("pub static ERC20_DB_ROOT").count() != 2
    {
        return false;
    }
    let Some(start) = text.find(ERC20_ROOT_SECTION_START) else {
        return false;
    };
    let Some(end) = text.find(ERC20_ROOT_SECTION_END) else {
        return false;
    };
    end > start && text[start..end] == render_erc20_root_sections(prod, e2e)
}

fn render_erc20_root_sections(prod: &[u8; 32], e2e: &[u8; 32]) -> String {
    let mut out = String::with_capacity(2 * 320);
    let _ = writeln!(out, "#[cfg(not(feature = \"e2e-test\"))]");
    append_generated_root(&mut out, "ERC20_DB_ROOT", prod);
    let _ = writeln!(out, "#[cfg(feature = \"e2e-test\")]");
    append_generated_root(&mut out, "ERC20_DB_ROOT", e2e);
    out
}

/// Match `dbgen/src/main.rs::emit_root` byte-for-byte. The exact section
/// comparison above intentionally fails on duplicate cfgs, renamed statics,
/// reordered roots, or hand-edited formatting around the load-bearing values.
fn append_generated_root(out: &mut String, name: &str, bytes: &[u8; 32]) {
    let _ = write!(out, "pub static {name}: [u8; 32] = [");
    for (index, byte) in bytes.iter().enumerate() {
        if index % 8 == 0 {
            out.push_str("\n    ");
        } else {
            out.push(' ');
        }
        let _ = write!(out, "0x{byte:02x},");
    }
    let _ = writeln!(out, "\n];\n");
}

fn erc7730_security_tail_matches(
    text: &str,
    prod: &[u8; 32],
    prod_count: usize,
    e2e: &[u8; 32],
    e2e_count: usize,
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    prod_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    prod_forced_len: usize,
    prod_forced_group_count: usize,
    prod_forced_count: usize,
    e2e_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    e2e_forced_len: usize,
    e2e_forced_group_count: usize,
    e2e_forced_count: usize,
) -> bool {
    let expected = dbgen::render_erc7730_security_tail(
        dbgen::Erc7730SecurityTailInput {
            root: prod,
            descriptor_count: prod_count,
            provenance: prod_provenance,
            status: prod_status,
            forced_eligible_len: prod_forced_len,
            forced_eligible_group_count: prod_forced_group_count,
            forced_eligible_count: prod_forced_count,
        },
        dbgen::Erc7730SecurityTailInput {
            root: e2e,
            descriptor_count: e2e_count,
            provenance: e2e_provenance,
            status: e2e_status,
            forced_eligible_len: e2e_forced_len,
            forced_eligible_group_count: e2e_forced_group_count,
            forced_eligible_count: e2e_forced_count,
        },
    );
    text.matches(dbgen::ERC7730_SECURITY_TAIL_SENTINEL).count() == 1 && text.ends_with(&expected)
}

#[allow(clippy::too_many_arguments)]
fn diff_erc7730_companion_guide(
    path: &std::path::Path,
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_size: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_root: &[u8; 32],
    e2e_count: usize,
    e2e_size: usize,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read companion guide at {}: {e}", path.display()))?;
    let summary = render_erc7730_guide_summary(
        prod_count,
        prod_size,
        prod_known_call_count,
        prod_known_call_set_hash,
        prod_provenance,
        e2e_count,
        e2e_size,
    );
    let roots = render_erc7730_guide_roots(
        prod_root, prod_count, prod_size, e2e_root, e2e_count, e2e_size,
    );
    let semantics = render_erc7730_semantic_contract();
    exact_document_block_matches(
        &text,
        ERC7730_GUIDE_SUMMARY_BEGIN,
        ERC7730_GUIDE_SUMMARY_END,
        &summary,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    exact_document_block_matches(
        &text,
        ERC7730_GUIDE_ROOTS_BEGIN,
        ERC7730_GUIDE_ROOTS_END,
        &roots,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    exact_document_block_matches(
        &text,
        ERC7730_GUIDE_SEMANTICS_BEGIN,
        ERC7730_GUIDE_SEMANTICS_END,
        &semantics,
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

fn render_erc7730_guide_summary(
    prod_count: usize,
    prod_size: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_count: usize,
    e2e_size: usize,
) -> String {
    format!(
        concat!(
            "{}\n",
            "   - Development catalogue: {} B, {} compiled leaves, {}\n",
            "     exact registry-declared known-call tuples, provenance `{}`.\n",
            "     The tuple-set SHA-256 receipt is\n",
            "     `{}`.\n",
            "   - E2E fixture: {} B, {} compiled leaves.\n",
            "{}",
        ),
        ERC7730_GUIDE_SUMMARY_BEGIN,
        grouped_decimal(prod_size, ','),
        grouped_decimal(prod_count, ','),
        grouped_decimal(prod_known_call_count, ','),
        prod_provenance.as_str(),
        hex::encode(prod_known_call_set_hash),
        grouped_decimal(e2e_size, ','),
        grouped_decimal(e2e_count, ','),
        ERC7730_GUIDE_SUMMARY_END,
    )
}

fn render_erc7730_guide_roots(
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_size: usize,
    e2e_root: &[u8; 32],
    e2e_count: usize,
    e2e_size: usize,
) -> String {
    format!(
        concat!(
            "{}\n",
            "| Variant | Root | Catalog blob bytes | Compiled leaves |\n",
            "|---------|------|-------------------:|----------------:|\n",
            "| development (non-e2e) | `0x{}` | {} | {} |\n",
            "| e2e | `0x{}` | {} | {} |\n",
            "{}",
        ),
        ERC7730_GUIDE_ROOTS_BEGIN,
        hex::encode(prod_root),
        grouped_decimal(prod_size, ' '),
        grouped_decimal(prod_count, ' '),
        hex::encode(e2e_root),
        grouped_decimal(e2e_size, ' '),
        grouped_decimal(e2e_count, ' '),
        ERC7730_GUIDE_ROOTS_END,
    )
}

fn render_erc7730_semantic_contract() -> String {
    use pqsigner_erc7730::display::erc8213_contract::{
        FINGERPRINT_PAGES, HASH_BYTES, HASH_BYTES_PER_ROW,
    };
    use pqsigner_erc7730::display::render::formatters::formatter_route;
    use pqsigner_erc7730::ir::{FormatOp, SCHEMA_VER};
    use pqsigner_erc7730::render::{RenderErr, VerifiedDescriptorErrorPolicy};

    let mut out = String::with_capacity(2 * 1024);
    let _ = writeln!(out, "{ERC7730_GUIDE_SEMANTICS_BEGIN}");
    let _ = writeln!(out, "### Device semantic manifest (generated)");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- The host compiler and device require **IR schema v{} (`0x{SCHEMA_VER:02X}`)**; this value is generated from `pqsigner_erc7730::ir::SCHEMA_VER`, and older schemas hard-refuse.",
        u16::from(SCHEMA_VER),
    );
    let _ = writeln!(
        out,
        "- Schema v5 authenticates every `uintN`/`intN` width as `1..=32` bytes. Before any trusted ERC-7730 page is published, the device requires exact ABI zero extension for `uintN` and sign extension for `intN`; full-width `uint256`/`int256` retain every 32-byte word unchanged."
    );
    let _ = writeln!(
        out,
        "- Schema v6 admits at most two explicitly enrolled top-level EIP-712 string preimages per format. Authenticated direct-word paths, sequential ordinals, an independent format count, exact witness-stream consumption, and a full 32-byte Keccak comparison bind every displayed byte to the signed member word before publication. Missing, reordered, non-ASCII, over-128-byte, hash-mismatched, trailing, or page-overflow evidence hard-refuses; it never authorizes typed-to-blind fallback."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "| Wire opcode | Registry `format` | Device route |");
    let _ = writeln!(out, "|------------:|-------------------|--------------|");
    for op in FormatOp::ALL {
        let route = formatter_route(op);
        let _ = writeln!(
            out,
            "| `0x{:02X}` | `{}` | {} |",
            op as u8,
            op.registry_name(),
            route.manifest_status(),
        );
    }

    // This call links generation to the exhaustive production policy method.
    // Adding a RenderErr variant cannot compile until that match assigns it a
    // disposition; the manifest deliberately states the universal rule rather
    // than maintaining a second hand-enumerated variant list.
    match RenderErr::NoFormat.verified_descriptor_policy() {
        VerifiedDescriptorErrorPolicy::HardRefuse => {}
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- For a verified, request-bound descriptor, **every `RenderErr` variant is a hard refusal** through an exhaustive production match. A new variant cannot compile until it receives that policy; no variant authorizes typed-call, selector-label, or blind-sign fallback."
    );
    let _ = writeln!(
        out,
        "- ERC-8213 is mandatory and atomic for every companion/dapp-supplied signed payload: exactly {FINGERPRINT_PAGES} pages (banner + hash) surface the complete {HASH_BYTES}-byte digest at {HASH_BYTES_PER_ROW} bytes per display row. If both pages do not fit, the signing caller refuses; it never leaves an orphan banner or signs without the complete hash. The sole current exemption is the firmware-constructed Type-1 slot-rotation operation: its calldata combines firmware constants with seed-derived slot-owner material that is intentionally unavailable before the rotation consent boundary, so that dialog instead renders the complete slot index and bootstrap-use consequence."
    );
    let _ = writeln!(
        out,
        "- Confirmation transcripts use the pinned append-only order. A single UserOp shows renderer pages first; the dispatcher may append native-value/legacy-fee pages, then the handler appends paymaster (when present), signer, target, non-zero nonce lane, exact UserOp gas and ERC-8213 fingerprint pages. When `FLAG_INCLUDE_INIT_CODE` is set, one final `DEPLOY FACTORY:` page shows the complete factory address; the ordinary path proves that page was skipped. A batch member prepends its exact `BATCH SIGN / Tx i of N` banner to the renderer/dispatcher pages, then appends signer, target, nonce lane, gas and fingerprint pages. The batch-final summary appends paymaster, signer, nonce lane, gas, the whole-batch fingerprint, and the same conditional deployment page. A full buffer refuses; no mandatory page is inserted by shifting or overwriting an earlier page."
    );
    out.push_str(ERC7730_GUIDE_SEMANTICS_END);
    out
}

#[allow(clippy::too_many_arguments)]
fn diff_erc7730_companion_integration(
    path: &std::path::Path,
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_known_calls_bloom: &[u8],
    prod_skip_count: usize,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read companion integration doc at {}: {e}", path.display()))?;
    let facts = render_erc7730_integration_facts(
        prod_root,
        prod_count,
        prod_known_call_count,
        prod_known_call_set_hash,
        prod_known_calls_bloom,
        prod_skip_count,
    );
    exact_document_block_matches(
        &text,
        ERC7730_INTEGRATION_FACTS_BEGIN,
        ERC7730_INTEGRATION_FACTS_END,
        &facts,
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

fn render_erc7730_integration_facts(
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_known_calls_bloom: &[u8],
    prod_skip_count: usize,
) -> String {
    use pqsigner_erc7730::ir::SCHEMA_VER;

    let bloom_set_bits: usize = prod_known_calls_bloom
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    let bloom_bits = prod_known_calls_bloom.len().saturating_mul(8);
    format!(
        concat!(
            "{}\n",
            "- The host compiler and device require **IR schema v{} (`0x{:02X}`)**; this value is\n",
            "  generated from `pqsigner_erc7730::ir::SCHEMA_VER`, and older schemas hard-refuse.\n",
            "- Schema v5 authenticates every `uintN`/`intN` width and hard-refuses dirty ABI\n",
            "  zero/sign extension before publishing trusted clear-signing pages; full-width\n",
            "  `uint256`/`int256` words remain unchanged.\n",
            "- Schema v6 binds explicitly enrolled top-level EIP-712 string preimages to their\n",
            "  exact signed words and hard-refuses missing, reordered, mismatched, non-ASCII,\n",
            "  over-128-byte, trailing, or page-overflow display evidence without fallback.\n",
            "- The current regenerated development catalogue has **{} leaves**, root\n",
            "  `{}`,\n",
            "  and **{} exact known-call tuples**. The tuple-set receipt is SHA-256\n",
            "  `{}`;\n",
            "  Bloom occupancy is {} / {} bits under the compiler-enforced generation cap.\n",
            "- The current compiler report records **{}** omitted descriptor/formats.\n",
            "{}",
        ),
        ERC7730_INTEGRATION_FACTS_BEGIN,
        u16::from(SCHEMA_VER),
        SCHEMA_VER,
        grouped_decimal(prod_count, ','),
        hex::encode(prod_root),
        grouped_decimal(prod_known_call_count, ','),
        hex::encode(prod_known_call_set_hash),
        grouped_decimal(bloom_set_bits, ','),
        grouped_decimal(bloom_bits, ','),
        grouped_decimal(prod_skip_count, ','),
        ERC7730_INTEGRATION_FACTS_END,
    )
}

#[derive(Clone, Copy)]
struct Erc7730CurationReceipt<'a> {
    manifest_sha256: [u8; 32],
    upstream_commit: &'a str,
    upstream_tree: &'a str,
    known_call_addition_count: usize,
}

#[allow(clippy::too_many_arguments)]
fn diff_erc7730_registry_readme(
    path: &std::path::Path,
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_size: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_known_calls_bloom: &[u8],
    curation: Option<Erc7730CurationReceipt<'_>>,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read registry README at {}: {e}", path.display()))?;
    let receipt = render_erc7730_registry_receipt(
        prod_root,
        prod_count,
        prod_size,
        prod_known_call_count,
        prod_known_call_set_hash,
        prod_known_calls_bloom,
        curation,
    );
    exact_document_block_matches(
        &text,
        ERC7730_REGISTRY_RECEIPT_BEGIN,
        ERC7730_REGISTRY_RECEIPT_END,
        &receipt,
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

fn render_erc7730_registry_receipt(
    prod_root: &[u8; 32],
    prod_count: usize,
    prod_size: usize,
    prod_known_call_count: usize,
    prod_known_call_set_hash: &[u8; 32],
    prod_known_calls_bloom: &[u8],
    curation: Option<Erc7730CurationReceipt<'_>>,
) -> String {
    let bloom_set_bits: usize = prod_known_calls_bloom
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum();
    let bloom_bits = prod_known_calls_bloom.len().saturating_mul(8);
    let curation = curation
        .map(|receipt| {
            format!(
                concat!(
                    "Curation manifest SHA-256\n",
                    "`{}` binds upstream commit\n",
                    "`{}` and tree\n",
                    "`{}`.\n",
                    "Manifest v3 authorizes exactly **{}** curation-added known-call tuples and no deletions.\n",
                ),
                hex::encode(receipt.manifest_sha256),
                receipt.upstream_commit,
                receipt.upstream_tree,
                grouped_decimal(receipt.known_call_addition_count, ','),
            )
        })
        .unwrap_or_default();
    format!(
        concat!(
            "{}\n",
            "Checked-in curated receipt, verified against a fresh build by `--check`: ",
            "**{} leaves**, **{}-byte**\n",
            "compiled companion catalogue, root\n",
            "`{}`,\n",
            "**{}** canonical known-call tuples, tuple-set SHA-256\n",
            "`{}`.\n",
            "{}",
            "The Bloom contains {} / {} set bits, below the generator's 25% cap.\n",
            "{}",
        ),
        ERC7730_REGISTRY_RECEIPT_BEGIN,
        grouped_decimal(prod_count, ','),
        grouped_decimal(prod_size, ','),
        hex::encode(prod_root),
        grouped_decimal(prod_known_call_count, ','),
        hex::encode(prod_known_call_set_hash),
        curation,
        grouped_decimal(bloom_set_bits, ','),
        grouped_decimal(bloom_bits, ','),
        ERC7730_REGISTRY_RECEIPT_END,
    )
}

fn grouped_decimal(value: usize, separator: char) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len().saturating_sub(1) / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(separator);
        }
        out.push(digit);
    }
    out
}

fn exact_document_block_matches(
    text: &str,
    begin: &str,
    end: &str,
    expected: &str,
) -> Result<(), String> {
    let begin_count = text.matches(begin).count();
    let end_count = text.matches(end).count();
    if begin_count != 1 || end_count != 1 {
        return Err(format!(
            "managed block markers are not unique (begin={begin_count}, end={end_count})"
        ));
    }
    let start = text.find(begin).expect("unique begin marker exists");
    let end_start = text.find(end).expect("unique end marker exists");
    if end_start < start {
        return Err("managed block end precedes its begin marker".to_string());
    }
    let end_offset = end_start + end.len();
    if &text[start..end_offset] == expected {
        Ok(())
    } else {
        Err("managed catalogue facts differ from the fresh build".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn render_test_erc7730_security_tail(
        prod_root: &[u8; 32],
        prod_count: usize,
        prod_provenance: dbgen::erc7730::CatalogueProvenance,
        prod_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
        e2e_root: &[u8; 32],
        e2e_count: usize,
        e2e_provenance: dbgen::erc7730::CatalogueProvenance,
        e2e_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    ) -> String {
        dbgen::render_erc7730_security_tail(
            dbgen::Erc7730SecurityTailInput {
                root: prod_root,
                descriptor_count: prod_count,
                provenance: prod_provenance,
                status: prod_status,
                forced_eligible_len: 16,
                forced_eligible_group_count: 0,
                forced_eligible_count: 0,
            },
            dbgen::Erc7730SecurityTailInput {
                root: e2e_root,
                descriptor_count: e2e_count,
                provenance: e2e_provenance,
                status: e2e_status,
                forced_eligible_len: 16,
                forced_eligible_group_count: 0,
                forced_eligible_count: 0,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn test_erc7730_security_tail_matches(
        text: &str,
        prod_root: &[u8; 32],
        prod_count: usize,
        e2e_root: &[u8; 32],
        e2e_count: usize,
        prod_provenance: dbgen::erc7730::CatalogueProvenance,
        prod_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
        e2e_provenance: dbgen::erc7730::CatalogueProvenance,
        e2e_status: &[u8; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN],
    ) -> bool {
        erc7730_security_tail_matches(
            text,
            prod_root,
            prod_count,
            e2e_root,
            e2e_count,
            prod_provenance,
            prod_status,
            16,
            0,
            0,
            e2e_provenance,
            e2e_status,
            16,
            0,
            0,
        )
    }

    #[test]
    fn padded_to_32_rounds_up_to_word_boundary() {
        assert_eq!(padded_to_32(0), 0);
        assert_eq!(padded_to_32(1), 32);
        assert_eq!(padded_to_32(31), 32);
        assert_eq!(padded_to_32(32), 32);
        assert_eq!(padded_to_32(33), 64);
        assert_eq!(padded_to_32(4008), 4032);
    }

    #[test]
    fn solidity_string_safe_accepts_printable_ascii() {
        assert!(is_solidity_string_safe(b"hello-world_1"));
        assert!(is_solidity_string_safe(b"PQSigner-FactoryAddSlot-v1"));
        assert!(is_solidity_string_safe(b""));
    }

    #[test]
    fn solidity_string_safe_rejects_unsafe_bytes() {
        assert!(!is_solidity_string_safe(b"contains\"quote"));
        assert!(!is_solidity_string_safe(b"contains\\backslash"));
        assert!(!is_solidity_string_safe(&[0x1f])); // below 0x20
        assert!(!is_solidity_string_safe(&[0x7f])); // above 0x7E
        assert!(!is_solidity_string_safe(&[0xff])); // non-ASCII
    }

    #[test]
    fn sol_bytes_emits_string_literal_for_ascii() {
        let mut s = String::new();
        sol_bytes(&mut s, "TAG", b"abc");
        assert_eq!(s, "    bytes internal constant TAG = \"abc\";\n");
    }

    #[test]
    fn sol_bytes_emits_hex_literal_for_non_ascii() {
        let mut s = String::new();
        sol_bytes(&mut s, "TAG", &[0x00, 0xff, 0x10]);
        assert_eq!(s, "    bytes internal constant TAG = hex\"00ff10\";\n");
    }

    #[test]
    fn sol_bytes4_emits_lowercase_hex() {
        let mut s = String::new();
        sol_bytes4(&mut s, "SEL", &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s, "    bytes4 internal constant SEL = 0xdeadbeef;\n");
    }

    #[test]
    fn sol_uint256_emits_decimal() {
        let mut s = String::new();
        sol_uint256(&mut s, "N", 65_536);
        assert_eq!(s, "    uint256 internal constant N = 65536;\n");
    }

    #[test]
    fn erc20_capability_receipt_binds_exact_input_bytes_and_generated_root() {
        let temp = tempfile::tempdir().expect("temporary ERC-20 input");
        let source = temp.path().join("erc20.json");
        let compact = br#"[{"chain_id":1,"address":"0x1111111111111111111111111111111111111111","name":"Token","symbol":"TOK","decimals":18}]"#;
        fs::write(&source, compact).expect("write compact ERC-20 input");

        let compact_input =
            load_erc20_capability_input(&source, "test").expect("load compact capability input");
        let expected_hash: [u8; 32] = Sha256::digest(compact).into();
        assert_eq!(compact_input.receipt.input_sha256, expected_hash);
        assert_eq!(compact_input.receipt.entry_count, 1);
        assert_eq!(compact_input.receipt.capability_count, 1);

        // Whitespace changes no semantic DB row and therefore no Merkle root,
        // but it must change the exact-input receipt. Reporting both values
        // prevents either source identity or generated authority from being
        // silently inferred from the other.
        let pretty = br#"[
  {
    "chain_id": 1,
    "address": "0x1111111111111111111111111111111111111111",
    "name": "Token",
    "symbol": "TOK",
    "decimals": 18
  }
]"#;
        fs::write(&source, pretty).expect("write pretty ERC-20 input");
        let pretty_input =
            load_erc20_capability_input(&source, "test").expect("load pretty capability input");
        assert_eq!(compact_input.receipt.db_root, pretty_input.receipt.db_root);
        assert_eq!(compact_input.blob, pretty_input.blob);
        assert_ne!(
            compact_input.receipt.input_sha256,
            pretty_input.receipt.input_sha256
        );

        let rendered = render_erc20_capability_receipt(&pretty_input);
        assert!(rendered.contains(&hex_lower(&pretty_input.receipt.input_sha256)));
        assert!(rendered.contains(&hex_lower(&pretty_input.receipt.db_root)));
        assert!(rendered.contains("1/1"));
    }

    #[test]
    fn erc7730_check_rejects_stale_erc20_prod_or_e2e_blob() {
        let temp = tempfile::tempdir().expect("temporary ERC-20 outputs");
        let prod = temp.path().join("erc20_db.bin");
        let e2e = temp.path().join("erc20_db_e2e.bin");
        let fresh_prod = b"fresh production metadata";
        let fresh_e2e = b"fresh e2e metadata";

        fs::write(&prod, fresh_prod).expect("write fresh production blob");
        fs::write(&e2e, fresh_e2e).expect("write fresh E2E blob");
        assert!(diff_erc20_blob_pair(&prod, fresh_prod, &e2e, fresh_e2e).is_ok());

        fs::write(&prod, b"stale production metadata").expect("stale production blob");
        fs::write(&e2e, b"stale e2e metadata").expect("stale E2E blob");
        let error = diff_erc20_blob_pair(&prod, fresh_prod, &e2e, fresh_e2e)
            .expect_err("either stale ERC-20 blob must fail the atomic drift check");
        assert!(error.contains("erc20_db.bin"));
        assert!(error.contains("erc20_db_e2e.bin"));
    }

    #[test]
    fn erc7730_check_rejects_stale_erc20_prod_or_e2e_root_section() {
        let prod = [0x11; 32];
        let e2e = [0x22; 32];
        let roots = format!(
            "// generated roots\n{}{}: [u8; 32] = [];\n",
            render_erc20_root_sections(&prod, &e2e),
            ERC20_ROOT_SECTION_END,
        );
        assert!(erc20_root_sections_match(&roots, &prod, &e2e));

        let mut stale_prod = prod;
        stale_prod[0] ^= 0xff;
        assert!(!erc20_root_sections_match(&roots, &stale_prod, &e2e));

        let mut stale_e2e = e2e;
        stale_e2e[31] ^= 0xff;
        assert!(!erc20_root_sections_match(&roots, &prod, &stale_e2e));
    }

    #[test]
    fn erc7730_codegen_matches_capability_aware_dbgen_for_prod_and_e2e() {
        const PROD_TOKEN: &str = "0x1111111111111111111111111111111111111111";
        const E2E_TOKEN: &str = "0x2222222222222222222222222222222222222222";

        let temp = tempfile::tempdir().expect("temporary catalogue workspace");
        let root = temp.path();
        let data_dir = root.join("secure/data");
        let registry_root = root.join("prod-registry");
        let prod_input = registry_root.join("registry");
        let e2e_input = root.join("e2e-input");
        std::fs::create_dir_all(&data_dir).expect("create capability directory");
        std::fs::create_dir_all(&prod_input).expect("create production input");
        std::fs::create_dir_all(&e2e_input).expect("create E2E input");

        let erc20_json = |address: &str, symbol: &str| {
            format!(
                r#"[{{"chain_id":1,"address":"{address}","name":"{symbol}","symbol":"{symbol}","decimals":18}}]"#
            )
        };
        std::fs::write(
            root.join(ERC20_DEFAULT_INPUT),
            erc20_json(PROD_TOKEN, "PROD"),
        )
        .expect("write production capabilities");
        std::fs::write(
            root.join(ERC20_DEFAULT_E2E_INPUT),
            erc20_json(E2E_TOKEN, "E2E"),
        )
        .expect("write E2E capabilities");

        let descriptor = |deployment: &str, token: &str| {
            format!(
                r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "{deployment}" }}
  ] }} }},
  "metadata": {{ "owner": "xtask test", "contractName": "Capability witness" }},
  "display": {{ "formats": {{
    "send(uint256 amount)": {{
      "intent": "Send",
      "fields": [{{
        "path": "amount",
        "label": "Amount",
        "format": "tokenAmount",
        "params": {{ "token": "{token}" }},
        "visible": "always"
      }}],
      "interpolatedIntent": "Send {{amount}}"
    }}
  }} }}
}}"#
            )
        };
        std::fs::write(
            prod_input.join("calldata-prod.json"),
            descriptor("0x3333333333333333333333333333333333333333", PROD_TOKEN),
        )
        .expect("write production descriptor");
        std::fs::write(
            e2e_input.join("calldata-e2e.json"),
            descriptor("0x4444444444444444444444444444444444444444", E2E_TOKEN),
        )
        .expect("write E2E descriptor");

        let policy = workspace_root().join(ERC7730_DEFAULT_POLICY);
        let e2e_policy = root.join("e2e-policy.toml");
        let e2e_policy_bytes = concat!(
            "min_attesters = 2\n",
            "trusted_attesters = []\n",
            "allow_unattested_dev_descriptors = true\n",
        );
        std::fs::write(&e2e_policy, e2e_policy_bytes).expect("write distinct E2E policy");

        let generated = build_erc7730_catalogues(
            root,
            &prod_input,
            &policy,
            Some(&registry_root),
            &e2e_input,
            &e2e_policy,
        )
        .expect("xtask catalogue build");
        assert!(generated.prod_skips.is_empty());

        let prod_erc20 = dbgen::erc20::build_db(&root.join(ERC20_DEFAULT_INPUT))
            .expect("production ERC-20 capabilities");
        let (expected_prod, _) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &prod_input,
            &policy,
            Some(&registry_root),
            &prod_erc20.capabilities,
        )
        .expect("direct production build");
        assert_eq!(generated.prod.root, expected_prod.root);
        assert_eq!(generated.prod.blob, expected_prod.blob);
        assert_eq!(generated.prod.leaf_count, expected_prod.leaf_count);
        assert_eq!(generated.prod_erc20.blob, prod_erc20.blob);
        assert_eq!(generated.prod_erc20.receipt.db_root, prod_erc20.root);

        let empty_capabilities = dbgen::erc20::Erc20Capabilities::default();
        let (empty_prod, _) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &prod_input,
            &policy,
            Some(&registry_root),
            &empty_capabilities,
        )
        .expect("empty-capability production control build");
        assert_ne!(
            generated.prod.root, empty_prod.root,
            "an empty capability set must not masquerade as the production-equivalent catalogue"
        );

        let loaded_prod =
            load_erc20_capability_input(&root.join(ERC20_DEFAULT_INPUT), "test production")
                .expect("load bound production capability input");
        let bound_prod = build_capability_bound_registry(
            &prod_input,
            &policy,
            Some(&registry_root),
            &loaded_prod,
        )
        .expect("capability-bound production build");
        assert_eq!(bound_prod.catalogue.root, generated.prod.root);
        assert_eq!(bound_prod.erc20, loaded_prod.receipt);

        let empty_input = Erc20CapabilityInput {
            source: loaded_prod.source.clone(),
            receipt: Erc20CapabilityReceipt {
                capability_count: 0,
                ..loaded_prod.receipt
            },
            blob: loaded_prod.blob.clone(),
            capabilities: empty_capabilities,
        };
        let bound_empty = build_capability_bound_registry(
            &prod_input,
            &policy,
            Some(&registry_root),
            &empty_input,
        )
        .expect("capability-bound empty control build");
        assert_ne!(bound_prod.catalogue.root, bound_empty.catalogue.root);
        assert_ne!(bound_prod.erc20, bound_empty.erc20);

        let e2e_erc20 = dbgen::erc20::build_db(&root.join(ERC20_DEFAULT_E2E_INPUT))
            .expect("E2E ERC-20 capabilities");
        let (wrong_prod, _) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &prod_input,
            &policy,
            Some(&registry_root),
            &e2e_erc20.capabilities,
        )
        .expect("wrong-capability production control build");
        assert_ne!(
            generated.prod.root, wrong_prod.root,
            "production generation must use production, not E2E, capabilities"
        );

        let expected_e2e = dbgen::erc7730::build_db_with_erc20_capabilities(
            &e2e_input,
            &e2e_policy,
            &e2e_erc20.capabilities,
        )
        .expect("direct E2E build");
        assert_eq!(generated.e2e.root, expected_e2e.root);
        assert_eq!(generated.e2e.blob, expected_e2e.blob);
        assert_eq!(generated.e2e.leaf_count, expected_e2e.leaf_count);
        let expected_e2e_policy_sha256: [u8; 32] = Sha256::digest(e2e_policy_bytes).into();
        assert_eq!(generated.e2e.policy_sha256, expected_e2e_policy_sha256);
        assert_ne!(generated.prod.policy_sha256, generated.e2e.policy_sha256);
        assert_eq!(generated.e2e_erc20.blob, e2e_erc20.blob);
        assert_eq!(generated.e2e_erc20.receipt.db_root, e2e_erc20.root);

        let wrong_e2e = dbgen::erc7730::build_db_with_erc20_capabilities(
            &e2e_input,
            &policy,
            &prod_erc20.capabilities,
        )
        .expect("wrong-capability E2E control build");
        assert_ne!(
            generated.e2e.root, wrong_e2e.root,
            "E2E generation must use E2E, not production, capabilities"
        );
    }

    #[test]
    fn erc7730_companion_guide_facts_accept_fresh_root_count_and_size() {
        use dbgen::erc7730::CatalogueProvenance::DevUnattested;

        let prod = [0x11; 32];
        let e2e = [0x22; 32];
        let tuple_hash = [0x33; 32];
        let summary =
            render_erc7730_guide_summary(420, 334_827, 4_542, &tuple_hash, DevUnattested, 8, 3_917);
        let roots = render_erc7730_guide_roots(&prod, 420, 334_827, &e2e, 8, 3_917);
        let guide = format!("prefix\n{summary}\nbody\n{roots}\nsuffix\n");

        exact_document_block_matches(
            &guide,
            ERC7730_GUIDE_SUMMARY_BEGIN,
            ERC7730_GUIDE_SUMMARY_END,
            &summary,
        )
        .expect("fresh summary");
        exact_document_block_matches(
            &guide,
            ERC7730_GUIDE_ROOTS_BEGIN,
            ERC7730_GUIDE_ROOTS_END,
            &roots,
        )
        .expect("fresh roots table");
    }

    #[test]
    fn erc7730_companion_guide_facts_reject_stale_root_count_or_size() {
        use dbgen::erc7730::CatalogueProvenance::DevUnattested;

        let prod = [0x11; 32];
        let e2e = [0x22; 32];
        let tuple_hash = [0x33; 32];
        let summary =
            render_erc7730_guide_summary(420, 334_827, 4_542, &tuple_hash, DevUnattested, 8, 3_917);
        let roots = render_erc7730_guide_roots(&prod, 420, 334_827, &e2e, 8, 3_917);
        let guide = format!("prefix\n{summary}\nbody\n{roots}\nsuffix\n");

        for stale in [
            guide.replacen(&hex::encode(prod), &hex::encode([0x55; 32]), 1),
            guide.replacen(&hex::encode(e2e), &hex::encode([0x44; 32]), 1),
            guide.replacen("334,827 B", "334,826 B", 1),
            guide.replacen("8 compiled leaves", "7 compiled leaves", 1),
            guide.replacen("3,917 B", "3,916 B", 1),
            guide.replacen("| 3 917 | 8 |", "| 3 916 | 8 |", 1),
            guide.replacen("| 3 917 | 8 |", "| 3 917 | 7 |", 1),
            guide.replacen("| 334 827 | 420 |", "| 334 827 | 419 |", 1),
        ] {
            let summary_result = exact_document_block_matches(
                &stale,
                ERC7730_GUIDE_SUMMARY_BEGIN,
                ERC7730_GUIDE_SUMMARY_END,
                &summary,
            );
            let roots_result = exact_document_block_matches(
                &stale,
                ERC7730_GUIDE_ROOTS_BEGIN,
                ERC7730_GUIDE_ROOTS_END,
                &roots,
            );
            assert!(
                summary_result.is_err() || roots_result.is_err(),
                "stale root/count/size must fail at least one managed block"
            );
        }
    }

    #[test]
    fn erc7730_semantic_contract_is_generated_from_executable_routes() {
        let semantics = render_erc7730_semantic_contract();
        let guide = format!("prefix\n{semantics}\nsuffix\n");
        exact_document_block_matches(
            &guide,
            ERC7730_GUIDE_SEMANTICS_BEGIN,
            ERC7730_GUIDE_SEMANTICS_END,
            &semantics,
        )
        .expect("fresh semantic contract");

        assert_eq!(pqsigner_erc7730::ir::SCHEMA_VER, 0x06);
        assert!(semantics.contains("IR schema v6 (`0x06`)"));
        assert!(!semantics.contains("IR schema v5 (`0x05`)"));
        assert!(semantics
            .contains("exact ABI zero extension for `uintN` and sign extension for `intN`"));
        assert!(semantics
            .contains("at most two explicitly enrolled top-level EIP-712 string preimages"));
        assert!(semantics.contains("typed-to-blind fallback"));
        assert!(
            semantics.contains("full-width `uint256`/`int256` retain every 32-byte word unchanged")
        );
        assert!(semantics.contains(
            "| `0x04` | `nftName` | implemented renderer (fail closed on invalid input) |"
        ));
        assert!(semantics
            .contains("| `0x09` | `unit` | implemented renderer (fail closed on invalid input) |"));
        assert!(semantics.contains(
            "| `0x0A` | `calldata` | one-level proof-set child renderer for exact firmware enrollments; otherwise hard refusal (production enrollments: 0) |"
        ));
        assert!(
            semantics.contains("| `0x0E` | `encrypted` | hard refusal (signed operand hidden) |")
        );
        assert!(semantics.contains(
            "| `0x0F` | `uniswapV3Path` | implemented renderer (fail closed on invalid input) |"
        ));
        assert!(semantics.contains("**every `RenderErr` variant is a hard refusal**"));
        assert!(semantics.contains("exactly 2 pages (banner + hash)"));
        assert!(semantics.contains("complete 32-byte digest at 8 bytes per display row"));
        assert!(semantics.contains("one final `DEPLOY FACTORY:` page"));
        assert!(semantics.contains("ordinary path proves that page was skipped"));
    }

    #[test]
    fn erc7730_semantic_contract_rejects_stale_documented_behavior() {
        let semantics = render_erc7730_semantic_contract();
        let guide = format!("prefix\n{semantics}\nsuffix\n");
        for stale in [
            guide.replacen("IR schema v6 (`0x06`)", "IR schema v5 (`0x05`)", 1),
            guide.replacen("exact ABI zero extension", "best-effort ABI extension", 1),
            guide.replacen(
                "at most two explicitly enrolled top-level EIP-712 string preimages",
                "arbitrary EIP-712 strings",
                1,
            ),
            guide.replacen("`0x04` | `nftName`", "`0x09` | `nftName`", 1),
            guide.replacen(
                "one-level proof-set child renderer for exact firmware enrollments; otherwise hard refusal (production enrollments: 0)",
                "hard refusal (nested calldata unsupported)",
                1,
            ),
            guide.replacen(
                "every `RenderErr` variant is a hard refusal",
                "some `RenderErr` variants may fall back",
                1,
            ),
            guide.replacen("exactly 2 pages", "exactly 1 page", 1),
            guide.replacen("complete 32-byte digest", "truncated 16-byte digest", 1),
            guide.replacen("one final `DEPLOY FACTORY:` page", "no deployment page", 1),
        ] {
            assert!(
                exact_document_block_matches(
                    &stale,
                    ERC7730_GUIDE_SEMANTICS_BEGIN,
                    ERC7730_GUIDE_SEMANTICS_END,
                    &semantics,
                )
                .is_err(),
                "stale security semantics must fail the documentation gate"
            );
        }
    }

    #[test]
    fn erc7730_companion_integration_facts_accept_fresh_receipts() {
        let root = [0x11; 32];
        let tuple_hash = [0x22; 32];
        let mut bloom = [0u8; 16];
        bloom[0] = 0b1010_0001;
        bloom[15] = 0b0000_0011;
        let facts = render_erc7730_integration_facts(&root, 420, 4_542, &tuple_hash, &bloom, 274);
        let doc = format!("prefix\n{facts}\nsuffix\n");
        exact_document_block_matches(
            &doc,
            ERC7730_INTEGRATION_FACTS_BEGIN,
            ERC7730_INTEGRATION_FACTS_END,
            &facts,
        )
        .expect("fresh integration facts");
        assert_eq!(pqsigner_erc7730::ir::SCHEMA_VER, 0x06);
        assert!(facts.contains("IR schema v6 (`0x06`)"));
        assert!(!facts.contains("IR schema v5 (`0x05`)"));
        assert!(facts.contains("hard-refuses dirty ABI"));
        assert!(facts.contains("`uint256`/`int256` words remain unchanged"));
        assert!(facts.contains("binds explicitly enrolled top-level EIP-712 string preimages"));
        assert!(facts.contains("without fallback"));
        assert!(facts.contains("5 / 128 bits"));
    }

    #[test]
    fn erc7730_companion_integration_facts_reject_stale_receipts() {
        let root = [0x11; 32];
        let tuple_hash = [0x22; 32];
        let mut bloom = [0u8; 16];
        bloom[0] = 0b1010_0001;
        bloom[15] = 0b0000_0011;
        let facts = render_erc7730_integration_facts(&root, 420, 4_542, &tuple_hash, &bloom, 274);
        let doc = format!("prefix\n{facts}\nsuffix\n");
        for stale in [
            doc.replacen("IR schema v6 (`0x06`)", "IR schema v5 (`0x05`)", 1),
            doc.replacen("hard-refuses dirty ABI", "accepts dirty ABI", 1),
            doc.replacen(
                "binds explicitly enrolled top-level EIP-712 string preimages",
                "accepts arbitrary EIP-712 strings",
                1,
            ),
            doc.replacen("420 leaves", "419 leaves", 1),
            doc.replacen(&hex::encode(root), &hex::encode([0x33; 32]), 1),
            doc.replacen("4,542 exact", "4,541 exact", 1),
            doc.replacen(&hex::encode(tuple_hash), &hex::encode([0x44; 32]), 1),
            doc.replacen("5 / 128 bits", "4 / 128 bits", 1),
            doc.replacen("**274**", "**273**", 1),
        ] {
            assert!(
                exact_document_block_matches(
                    &stale,
                    ERC7730_INTEGRATION_FACTS_BEGIN,
                    ERC7730_INTEGRATION_FACTS_END,
                    &facts,
                )
                .is_err(),
                "stale integration receipt must fail"
            );
        }
    }

    #[test]
    fn erc7730_registry_readme_accepts_exact_generated_receipt() {
        let root = [0x11; 32];
        let tuple_hash = [0x22; 32];
        let mut bloom = [0u8; 16];
        bloom[0] = 0b1010_0001;
        bloom[15] = 0b0000_0011;
        let manifest_hash = [0x33; 32];
        let upstream_commit = "44".repeat(20);
        let upstream_tree = "55".repeat(20);
        let curation = Erc7730CurationReceipt {
            manifest_sha256: manifest_hash,
            upstream_commit: &upstream_commit,
            upstream_tree: &upstream_tree,
            known_call_addition_count: 4,
        };
        let receipt = render_erc7730_registry_receipt(
            &root,
            428,
            341_328,
            4_542,
            &tuple_hash,
            &bloom,
            Some(curation),
        );
        let readme = format!("human provenance\n{receipt}\nhuman curation list\n");
        exact_document_block_matches(
            &readme,
            ERC7730_REGISTRY_RECEIPT_BEGIN,
            ERC7730_REGISTRY_RECEIPT_END,
            &receipt,
        )
        .expect("fresh registry receipt");
        assert!(receipt.contains("5 / 128 set bits"));
        assert!(receipt.contains(&hex::encode(manifest_hash)));
        assert!(receipt.contains(&upstream_commit));
        assert!(receipt.contains(&upstream_tree));
        assert!(receipt.contains("exactly **4** curation-added known-call tuples"));
    }

    #[test]
    fn erc7730_registry_readme_rejects_stale_values_or_markers() {
        let root = [0x11; 32];
        let tuple_hash = [0x22; 32];
        let mut bloom = [0u8; 16];
        bloom[0] = 0b1010_0001;
        bloom[15] = 0b0000_0011;
        let manifest_hash = [0x33; 32];
        let upstream_commit = "44".repeat(20);
        let upstream_tree = "55".repeat(20);
        let receipt = render_erc7730_registry_receipt(
            &root,
            428,
            341_328,
            4_542,
            &tuple_hash,
            &bloom,
            Some(Erc7730CurationReceipt {
                manifest_sha256: manifest_hash,
                upstream_commit: &upstream_commit,
                upstream_tree: &upstream_tree,
                known_call_addition_count: 4,
            }),
        );
        let readme = format!("prefix\n{receipt}\nsuffix\n");
        let stale_docs = [
            readme.replacen("428 leaves", "427 leaves", 1),
            readme.replacen("341,328-byte", "341,327-byte", 1),
            readme.replacen(&hex::encode(root), &hex::encode([0x33; 32]), 1),
            readme.replacen("4,542** canonical", "4,541** canonical", 1),
            readme.replacen(&hex::encode(tuple_hash), &hex::encode([0x44; 32]), 1),
            readme.replacen(&hex::encode(manifest_hash), &hex::encode([0x66; 32]), 1),
            readme.replacen(&upstream_commit, &"77".repeat(20), 1),
            readme.replacen(&upstream_tree, &"88".repeat(20), 1),
            readme.replacen(
                "exactly **4** curation-added",
                "exactly **3** curation-added",
                1,
            ),
            readme.replacen("5 / 128 set bits", "4 / 128 set bits", 1),
            readme.replacen(ERC7730_REGISTRY_RECEIPT_BEGIN, "", 1),
            format!("{readme}\n{receipt}"),
        ];
        for stale in stale_docs {
            assert!(
                exact_document_block_matches(
                    &stale,
                    ERC7730_REGISTRY_RECEIPT_BEGIN,
                    ERC7730_REGISTRY_RECEIPT_END,
                    &receipt,
                )
                .is_err(),
                "stale or ambiguous registry receipt must fail"
            );
        }
    }

    #[test]
    fn erc7730_codegen_requires_the_complete_exact_security_suffix() {
        use dbgen::erc7730::CatalogueProvenance::DevUnattested;

        let prod = [0x11u8; 32];
        let e2e = [0x22u8; 32];
        let prod_count = 17;
        let e2e_count = 3;
        let prod_status = [0x31; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN];
        let e2e_status = [0x32; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN];
        let tail = render_test_erc7730_security_tail(
            &prod,
            prod_count,
            DevUnattested,
            &prod_status,
            &e2e,
            e2e_count,
            DevUnattested,
            &e2e_status,
        );
        assert_eq!(
            tail.matches("extern crate core as __pqsigner_erc7730_core;")
                .count(),
            1
        );
        assert_eq!(
            tail.matches("self::__pqsigner_erc7730_core::include_bytes!")
                .count(),
            4
        );
        assert_eq!(
            tail.matches("self::__pqsigner_erc7730_core::compile_error!")
                .count(),
            3
        );
        assert!(
            !tail.lines().any(|line| line.starts_with("include_bytes!"))
                && !tail.lines().any(|line| line.starts_with("compile_error!")),
            "generated security macros must resolve through the collision-sensitive core alias"
        );
        let correct = format!("pub static SELECTOR_DB_ROOT: [u8; 32] = [0; 32];\n\n{tail}");
        assert!(test_erc7730_security_tail_matches(
            &correct,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        let swapped_roots = render_test_erc7730_security_tail(
            &e2e,
            e2e_count,
            DevUnattested,
            &e2e_status,
            &prod,
            prod_count,
            DevUnattested,
            &prod_status,
        );
        assert!(!test_erc7730_security_tail_matches(
            &swapped_roots,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        let mut altered_prod_status = prod_status;
        altered_prod_status[31] ^= 0x01;
        let altered_status_tail = render_test_erc7730_security_tail(
            &prod,
            prod_count,
            DevUnattested,
            &altered_prod_status,
            &e2e,
            e2e_count,
            DevUnattested,
            &e2e_status,
        );
        assert!(!test_erc7730_security_tail_matches(
            &altered_status_tail,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        let swapped_filters = tail
            .replace("erc7730-known-calls-e2e.bloom", "TEMP_FILTER")
            .replace("erc7730-known-calls.bloom", "erc7730-known-calls-e2e.bloom")
            .replace("TEMP_FILTER", "erc7730-known-calls.bloom");
        assert!(!test_erc7730_security_tail_matches(
            &swapped_filters,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        let deleted_fence = tail.replacen(
            "compile_error!(\"mode-production cannot embed the dev-unattested ERC-7730 catalogue.",
            "compile_error!(\"disabled: mode-production cannot embed the dev-unattested ERC-7730 catalogue.",
            1,
        );
        assert!(!test_erc7730_security_tail_matches(
            &deleted_fence,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        // This is the concrete false-green that defeated the old lexical
        // marker scan: the expected root bytes remained in Rust code but the
        // effective cfg disabled them. Exact-tail comparison rejects any
        // attribute inserted between the inert anchor and a protected item.
        let cfg_disabled_root = tail.replacen(
            "#[cfg(not(feature = \"e2e-test\"))]\npub static ERC7730_DESCRIPTORS_ROOT",
            "#[cfg(any())]\n#[cfg(not(feature = \"e2e-test\"))]\npub static ERC7730_DESCRIPTORS_ROOT",
            1,
        );
        assert!(!test_erc7730_security_tail_matches(
            &cfg_disabled_root,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            &prod_status,
            DevUnattested,
            &e2e_status,
        ));

        let block_commented = format!("/*\n{tail}\n*/");
        let raw_string = format!("const _: &str = r###\"{tail}\"###;");
        let enclosed = format!("#[cfg(any())]\nmod disabled {{\n{tail}}}\n");
        for forged in [&block_commented, &raw_string, &enclosed] {
            assert!(!test_erc7730_security_tail_matches(
                forged,
                &prod,
                prod_count,
                &e2e,
                e2e_count,
                DevUnattested,
                &prod_status,
                DevUnattested,
                &e2e_status,
            ));
        }
    }

    #[test]
    fn erc7730_generated_core_alias_defeats_extern_prelude_shadowing() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        // `::core::compile_error!` is NOT intrinsically unshadowable: a prefix
        // can rebind `core` to this crate and re-export a no-op macro. The
        // generated suffix instead imports the real crate under a unique local
        // name. A hostile prefix cannot predeclare that name without a
        // duplicate-item error, and cannot redirect this path.
        let source = r#"
extern crate self as core;
macro_rules! compile_error { ($message:literal) => {} }
pub(crate) use compile_error;

mod generated_suffix {
    pub const ERC7730_GENERATED_SECURITY_TAIL_ANCHOR: () = ();
    extern crate core as __pqsigner_erc7730_core;
    self::__pqsigner_erc7730_core::compile_error!("real generated fence fired");
}
"#;
        let temp = tempfile::tempdir().expect("create rustc output directory");
        let metadata = temp.path().join("core-alias-test.rmeta");
        let mut child = Command::new("rustc")
            .args(["--edition=2021", "--crate-type=lib", "--emit=metadata", "-"])
            .arg("-o")
            .arg(&metadata)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rustc for generated-core-alias regression");
        child
            .stdin
            .take()
            .expect("rustc stdin")
            .write_all(source.as_bytes())
            .expect("write rustc source");
        let output = child.wait_with_output().expect("wait for rustc");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "hostile prefix suppressed fence");
        assert!(
            stderr.contains("real generated fence fired"),
            "failure did not come from the real core macro: {stderr}"
        );
    }

    #[test]
    fn erc7730_codegen_verified_provenance_is_also_exact() {
        use dbgen::erc7730::CatalogueProvenance::Erc8176Verified;

        let prod = [0x33u8; 32];
        let e2e = [0x44u8; 32];
        let prod_count = 23;
        let e2e_count = 5;
        let prod_status = [0x41; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN];
        let e2e_status = [0x42; pqsigner_erc7730::catalogue_status::CATALOGUE_STATUS_V1_LEN];
        let correct = render_test_erc7730_security_tail(
            &prod,
            prod_count,
            Erc8176Verified,
            &prod_status,
            &e2e,
            e2e_count,
            Erc8176Verified,
            &e2e_status,
        );
        assert!(test_erc7730_security_tail_matches(
            &correct,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            Erc8176Verified,
            &prod_status,
            Erc8176Verified,
            &e2e_status,
        ));
        let altered = correct.replacen(
            "feature = \"erc7730-dev-unattested\"",
            "not(feature = \"erc7730-dev-unattested\")",
            1,
        );
        assert!(!test_erc7730_security_tail_matches(
            &altered,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            Erc8176Verified,
            &prod_status,
            Erc8176Verified,
            &e2e_status,
        ));
    }

    #[test]
    fn vendor_install_second_move_failure_restores_both_prior_directories() {
        let temp = tempfile::tempdir().expect("create vendor rollback test directory");
        let root = temp.path();
        let out = root.join("installed");
        let staging = root.join("staging");
        fs::create_dir_all(out.join("registry")).unwrap();
        fs::create_dir_all(out.join("ercs")).unwrap();
        fs::create_dir_all(staging.join("registry")).unwrap();
        fs::write(out.join("registry/old.json"), b"old registry").unwrap();
        fs::write(out.join("ercs/old.json"), b"old ercs").unwrap();
        fs::write(staging.join("registry/new.json"), b"new registry").unwrap();
        // Intentionally omit staging/ercs so the second new-directory rename
        // fails after the first succeeded.

        let error = install_vendored_subdirs(&staging, &out).unwrap_err();
        assert!(
            error.contains("checked rollback restored the prior corpus"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(out.join("registry/old.json")).unwrap(),
            b"old registry"
        );
        assert_eq!(fs::read(out.join("ercs/old.json")).unwrap(), b"old ercs");
        assert!(!out.join("registry/new.json").exists());
        assert_eq!(
            fs::read(staging.join("registry/new.json")).unwrap(),
            b"new registry"
        );
        assert!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".vendor-backup-")),
            "successful rollback must not leave a backup"
        );
    }

    #[test]
    fn excluded_fixture_domain_only_eip712_binding_is_rejected() {
        let temp = tempfile::tempdir().expect("create excluded-fixture test directory");
        let root = temp.path();
        let fixture = root.join("domain.tests.json");
        fs::write(
            &fixture,
            br#"{
  "context": {
    "eip712": {
      "deployments": [],
      "domain": {
        "chainId": 1,
        "verifyingContract": "0x0000000000000000000000000000000000000001"
      }
    }
  }
}"#,
        )
        .unwrap();

        let error = validate_excluded_vendor_fixture(&fixture).unwrap_err();
        assert!(
            error.contains("fully-specified EIP-712 domain binding"),
            "unexpected error: {error}"
        );
    }

    /// Guard against accidental drift in the rendered output. The rendered
    /// library is checked into `contracts/smart-wallet/src/generated/`
    /// and CI diffs it on every PR; this test catches drift before CI does.
    #[test]
    fn rendered_library_matches_checked_in_solidity() {
        let rendered = render_solidity_library();

        // Structural invariants we never want to lose.
        assert!(rendered.starts_with("// SPDX-License-Identifier: MIT\n"));
        assert!(rendered.contains("library PqsignerProto {"));
        assert!(rendered.ends_with("}\n"));

        // Every public constant from `pqsigner-proto` must surface.
        for name in [
            "C10_SIG_LEN",
            "SIG_WRAPPER_LEN",
            "MAX_BOOTSTRAP_USES",
            "MAX_SLOT_USES",
            "MAX_OFFCHAIN_GAP",
            "OWNER_BYTES_LEN",
            "EXECUTE_SELECTOR",
            "EXECUTE_BATCH_SELECTOR",
            "FACTORY_ADD_SLOT_DOMAIN",
        ] {
            assert!(rendered.contains(name), "missing constant {name}");
        }

        // The wrapper-size arithmetic must match the spec.
        let expected_wrapper = 32 + 32 + 32 + padded_to_32(proto::C10_SIG_LEN as u128);
        assert!(rendered.contains(&format!(
            "uint256 internal constant SIG_WRAPPER_LEN = {expected_wrapper};"
        )));
    }

    // ─────────────────────────────────────────────────────────────────
    //                       POSITIVE — extended
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn positive_padded_to_32_handles_protocol_relevant_values() {
        // C10_SIG_LEN = 4008 → 4032 (used in SIG_WRAPPER_LEN).
        assert_eq!(padded_to_32(4008), 4032);
        // The EIP-6492 blob is 8608 bytes — already 32-aligned, must
        // round to itself, not the next word.
        assert_eq!(padded_to_32(8608), 8608);
        // Exact multiples must be unchanged.
        assert_eq!(padded_to_32(64), 64);
        assert_eq!(padded_to_32(96), 96);
        // One byte past a multiple must jump exactly one word up.
        assert_eq!(padded_to_32(65), 96);
        assert_eq!(padded_to_32(97), 128);
    }

    #[test]
    fn positive_render_library_is_deterministic() {
        // Pure-function contract: same input ⇒ same output, every time.
        // CI relies on this for the `--check` diff to be stable across
        // re-invocations.
        let a = render_solidity_library();
        let b = render_solidity_library();
        let c = render_solidity_library();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn positive_render_library_emits_pragma_and_header() {
        let s = render_solidity_library();
        assert!(s.contains("pragma solidity ^0.8.28;"));
        assert!(s.contains("AUTO-GENERATED — DO NOT EDIT."));
        assert!(s.contains("Source of truth: `pqsigner-proto` crate (Rust)."));
    }

    #[test]
    fn positive_section_header_format_is_exact() {
        let mut s = String::new();
        section_header(&mut s, "Hello");
        let expected = "\n    // \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n    // Hello\n    // \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n";
        assert_eq!(s, expected);
    }

    #[test]
    fn positive_sol_uint256_with_doc_emits_doc_then_const() {
        let mut s = String::new();
        sol_uint256_with_doc(&mut s, "N", 42, "the answer");
        assert_eq!(
            s,
            "    /// @dev the answer\n    uint256 internal constant N = 42;\n"
        );
    }

    #[test]
    fn positive_sol_uint256_emits_zero_and_large_values() {
        let mut s = String::new();
        sol_uint256(&mut s, "Z", 0);
        assert_eq!(s, "    uint256 internal constant Z = 0;\n");

        let mut s = String::new();
        sol_uint256(&mut s, "BIG", u128::MAX);
        assert_eq!(
            s,
            format!("    uint256 internal constant BIG = {};\n", u128::MAX),
        );
    }

    #[test]
    fn positive_sol_bytes4_zero_and_max() {
        let mut s = String::new();
        sol_bytes4(&mut s, "ZERO", &[0, 0, 0, 0]);
        assert_eq!(s, "    bytes4 internal constant ZERO = 0x00000000;\n");

        let mut s = String::new();
        sol_bytes4(&mut s, "MAX", &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(s, "    bytes4 internal constant MAX = 0xffffffff;\n");
    }

    #[test]
    fn positive_sol_bytes_empty_emits_string_literal() {
        let mut s = String::new();
        sol_bytes(&mut s, "EMPTY", b"");
        assert_eq!(s, "    bytes internal constant EMPTY = \"\";\n");
    }

    #[test]
    fn positive_sol_bytes_uses_string_literal_for_real_domain_tag() {
        let mut s = String::new();
        sol_bytes(&mut s, "T", b"pqwallet-factory-add-slot");
        assert_eq!(
            s,
            "    bytes internal constant T = \"pqwallet-factory-add-slot\";\n"
        );
    }

    #[test]
    fn positive_is_solidity_string_safe_accepts_full_printable_range() {
        // 0x20 (space) through 0x7E (~), excluding " and \.
        for b in 0x20u8..=0x7Eu8 {
            if b == b'"' || b == b'\\' {
                continue;
            }
            assert!(
                is_solidity_string_safe(&[b]),
                "printable byte 0x{b:02x} must be accepted",
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //                       NEGATIVE — adversarial
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn negative_is_solidity_string_safe_rejects_every_control_byte() {
        // Every byte 0x00–0x1F is a control char that would either
        // break a Solidity string literal (e.g. CR/LF/tab inside "...")
        // or render as invisible/garbage in the on-chain source. The
        // generator must always force hex"..." encoding for these.
        for b in 0u8..0x20 {
            assert!(
                !is_solidity_string_safe(&[b]),
                "control byte 0x{b:02x} must be rejected — would corrupt the rendered Solidity",
            );
        }
        // DEL (0x7F) and everything above must also be rejected.
        assert!(!is_solidity_string_safe(&[0x7F]));
    }

    #[test]
    fn negative_is_solidity_string_safe_rejects_quote_and_backslash_within_text() {
        // Single unsafe byte inside otherwise-safe text MUST trip the
        // check; otherwise the rendered Solidity would have an
        // unescaped quote or backslash and fail to compile (or worse,
        // alter the constant's value).
        assert!(!is_solidity_string_safe(b"safe\"quote"));
        assert!(!is_solidity_string_safe(b"safe\\back"));
        assert!(!is_solidity_string_safe(b"\""));
        assert!(!is_solidity_string_safe(b"\\"));
        // Quote/backslash at every position is rejected.
        assert!(!is_solidity_string_safe(b"\"hello"));
        assert!(!is_solidity_string_safe(b"hello\""));
        assert!(!is_solidity_string_safe(b"\\hello"));
        assert!(!is_solidity_string_safe(b"hello\\"));
    }

    #[test]
    fn negative_is_solidity_string_safe_rejects_every_non_ascii_byte() {
        for b in 0x80u8..=0xFFu8 {
            assert!(
                !is_solidity_string_safe(&[b]),
                "non-ASCII byte 0x{b:02x} must be rejected",
            );
        }
    }

    #[test]
    fn negative_sol_bytes_picks_hex_when_input_contains_any_unsafe_byte() {
        // A single 0xff inside otherwise-ASCII payload must force the
        // hex encoding path. A regression would emit an unescaped
        // 0xff inside a string literal, breaking Solidity parsing.
        let mut s = String::new();
        sol_bytes(&mut s, "T", b"hello\xffworld");
        assert!(
            s.starts_with("    bytes internal constant T = hex\""),
            "any unsafe byte must force hex encoding, got: {s}",
        );
        assert!(s.contains("68656c6c6fff776f726c64"));
    }

    /// CLAUDE.md invariant #7: per-chain caps are monotonic and
    /// unresettable. The same numeric values are baked into the
    /// `PQMultiOwnable` storage checks and the rendered Solidity
    /// library; if they drift in `pqsigner-proto`, every consumer
    /// (firmware + on-chain wallet) breaks silently. This test fires
    /// the moment anyone moves them.
    #[test]
    fn negative_proto_caps_match_frozen_on_chain_values() {
        assert_eq!(
            proto::MAX_BOOTSTRAP_USES,
            65_536,
            "MAX_BOOTSTRAP_USES drift — see CLAUDE.md invariant #7",
        );
        assert_eq!(
            proto::MAX_SLOT_USES,
            65_536,
            "MAX_SLOT_USES drift — see CLAUDE.md invariant #7",
        );
        assert_eq!(
            proto::MAX_OFFCHAIN_GAP,
            100,
            "MAX_OFFCHAIN_GAP drift — see CLAUDE.md invariant #9",
        );
    }

    /// `C10_SIG_LEN` is baked into the Yul verifier
    /// (`SPHINCsC10Asm.sol`) AND into every signature wrapper layout
    /// (`SIG_WRAPPER_LEN = 4128`). Drift breaks every signature path.
    #[test]
    fn negative_c10_sig_len_is_frozen_at_4008() {
        assert_eq!(proto::C10_SIG_LEN, 4008);
    }

    /// `OWNER_BYTES_LEN = 64` is the size the on-chain wallet allocates
    /// for each owner entry (`ownerAtIndex`); drifting it would either
    /// truncate slot keys (silent forgery surface) or break ABI decode.
    #[test]
    fn negative_owner_bytes_len_is_frozen_at_64() {
        assert_eq!(proto::OWNER_BYTES_LEN, 64);
    }

    /// `EXECUTE_SELECTOR = keccak256("execute(address,uint256,bytes)")[..4]`
    /// — drift means the firmware emits a calldata prefix the wallet
    /// won't dispatch to, bricking the wallet at the next user tx.
    #[test]
    fn negative_execute_selectors_are_byte_exact() {
        assert_eq!(proto::EXECUTE_SELECTOR, [0x14, 0x44, 0x3c, 0x57]);
        assert_eq!(proto::EXECUTE_BATCH_SELECTOR, [0x7a, 0x38, 0x99, 0x33]);
    }

    /// CLAUDE.md "No casual KDF tag changes." `FACTORY_ADD_SLOT_DOMAIN`
    /// is the domain-separator tag the bootstrap key signs over in
    /// `PQSmartWalletFactory.createAccount`; renaming it invalidates
    /// every already-issued bootstrap signature.
    #[test]
    fn negative_factory_add_slot_domain_tag_is_byte_exact() {
        assert_eq!(proto::FACTORY_ADD_SLOT_DOMAIN, b"pqwallet-factory-add-slot");
        // Length is part of the on-chain hash preimage — pin it.
        assert_eq!(proto::FACTORY_ADD_SLOT_DOMAIN.len(), 25);
    }

    /// `SIG_WRAPPER_LEN` is `abi.encode(uint256 ownerIndex, bytes sig)`
    /// head + tail: 32 (ownerIndex) + 32 (offset) + 32 (length) +
    /// 32-aligned inner sig. For C10 (4008 B → 4032 padded) this is
    /// exactly 4128. Any drift breaks on-chain ABI decoding.
    #[test]
    fn negative_sig_wrapper_len_is_4128_in_rendered_library() {
        let expected = 32u128 + 32 + 32 + padded_to_32(proto::C10_SIG_LEN as u128);
        assert_eq!(expected, 4128, "wrapper arithmetic drifted");
        let rendered = render_solidity_library();
        assert!(
            rendered.contains("uint256 internal constant SIG_WRAPPER_LEN = 4128;"),
            "SIG_WRAPPER_LEN must render as exactly 4128",
        );
    }

    /// The single highest-value test in this suite: render the library
    /// in-process and compare byte-for-byte against the checked-in
    /// Solidity file. Mirrors what
    /// `pqsigner-xtask gen-solidity-constants --check` does in CI —
    /// any code change that alters the generator's output without
    /// regenerating the on-chain library fires here, BEFORE CI.
    #[test]
    fn negative_rendered_output_matches_checked_in_solidity_byte_for_byte() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let checked_in = manifest_dir
            .parent()
            .expect("xtask sits one dir below workspace root")
            .join(SOLIDITY_OUT_PATH);
        let checked_in_text = fs::read_to_string(&checked_in)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", checked_in.display()));
        let rendered = render_solidity_library();
        assert_eq!(
            rendered, checked_in_text,
            "rendered Solidity drifted from checked-in file — \
             regenerate with `cargo run -p pqsigner-xtask -- gen-solidity-constants`",
        );
    }

    /// Same contract for the firmware CREATE2 constants: the checked-in
    /// `PqsignerDeployment.sol` the deploy scripts assert against must be
    /// exactly what the current `proto` constants render to.
    #[test]
    fn negative_rendered_deployment_matches_checked_in_solidity_byte_for_byte() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let checked_in = manifest_dir
            .parent()
            .expect("xtask sits one dir below workspace root")
            .join(SOLIDITY_DEPLOYMENT_OUT_PATH);
        let checked_in_text = fs::read_to_string(&checked_in)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", checked_in.display()));
        assert_eq!(
            render_solidity_deployment_library(),
            checked_in_text,
            "rendered PqsignerDeployment.sol drifted from checked-in file — \
             regenerate with `cargo run -p pqsigner-xtask -- gen-solidity-constants`",
        );
    }

    #[test]
    fn positive_render_deployment_library_is_deterministic_and_carries_proto_constants() {
        let a = render_solidity_deployment_library();
        assert_eq!(a, render_solidity_deployment_library());

        let mut factory = String::new();
        for b in proto::PQ_SMART_WALLET_FACTORY {
            let _ = write!(factory, "{b:02x}");
        }
        let mut hash = String::new();
        for b in proto::PROXY_INIT_CODE_HASH {
            let _ = write!(hash, "{b:02x}");
        }
        let lower = a.to_ascii_lowercase();
        assert!(lower.contains(&format!("pq_smart_wallet_factory = 0x{factory};")));
        assert!(a.contains(&format!("PROXY_INIT_CODE_HASH = 0x{hash};")));
        assert!(a.contains("AUTO-GENERATED — DO NOT EDIT."));
    }

    /// solc rejects an address literal that is not EIP-55 checksummed, so
    /// the factory must render mixed-case, never all-lowercase hex.
    #[test]
    fn negative_render_deployment_factory_is_checksummed() {
        let a = render_solidity_deployment_library();
        let line = a
            .lines()
            .find(|l| l.contains("PQ_SMART_WALLET_FACTORY"))
            .expect("factory line");
        let hex = line.split("0x").nth(1).expect("hex literal");
        let hex = &hex[..40];
        let expected =
            pqsigner_erc7730::display::primitives::eip55_hex(&proto::PQ_SMART_WALLET_FACTORY);
        assert_eq!(hex.as_bytes(), &expected[..]);
    }

    /// Defensive: the rendered library must always include the
    /// auto-generated warning AND a pointer to the regenerator command.
    /// Without these, an auditor could hand-edit the Solidity file and
    /// have it survive a regen (until the next CI run catches the diff).
    #[test]
    fn negative_rendered_output_keeps_do_not_edit_warning() {
        let rendered = render_solidity_library();
        assert!(rendered.contains("AUTO-GENERATED — DO NOT EDIT."));
        assert!(rendered
            .contains("Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`."));
    }

    /// The factory domain tag is printable ASCII; the generator MUST
    /// emit it as a string literal, never as `hex"..."`. A regression
    /// to hex would still be semantically correct on-chain but would
    /// (a) silently flip the rendered diff and (b) hide the tag's
    /// human-readable form from auditors reading the contract.
    #[test]
    fn negative_factory_add_slot_domain_renders_as_string_literal() {
        let rendered = render_solidity_library();
        assert!(rendered.contains(
            "bytes internal constant FACTORY_ADD_SLOT_DOMAIN = \"pqwallet-factory-add-slot\";"
        ));
        assert!(
            !rendered.contains("FACTORY_ADD_SLOT_DOMAIN = hex"),
            "domain tag must NOT fall through to hex encoding for printable ASCII",
        );
    }

    /// `workspace_root()` derives from `CARGO_MANIFEST_DIR`. In a
    /// `cargo test` invocation that env is always set, and the result
    /// must point at the directory above the xtask manifest — i.e.
    /// the workspace root that contains both `xtask/` and
    /// `contracts/`.
    #[test]
    fn positive_workspace_root_is_parent_of_manifest_dir() {
        let root = workspace_root();
        // The workspace root must contain the contracts/ directory and
        // the xtask/ directory; if `workspace_root()` resolves to "."
        // or stays inside xtask/, we've regressed.
        assert!(
            root.join("contracts/smart-wallet/src/generated/PqsignerProto.sol")
                .is_file(),
            "workspace_root() must resolve to the actual workspace root, got {}",
            root.display(),
        );
        assert!(
            root.join("xtask/Cargo.toml").is_file(),
            "workspace_root() must contain xtask/, got {}",
            root.display(),
        );
    }

    /// CLAUDE.md "No classical signer anywhere." The xtask renderer is
    /// the bridge between Rust constants and the on-chain library; if
    /// anyone ever adds a non-C10 sig-length / wrapper / selector
    /// constant to `pqsigner-proto`, this test won't catch it directly
    /// — but it does pin the rendered library to expose ONLY the
    /// approved constant names. New entries are a conscious change.
    #[test]
    fn negative_rendered_library_exposes_only_approved_constants() {
        let rendered = render_solidity_library();
        let approved = [
            "C10_SIG_LEN",
            "SIG_WRAPPER_LEN",
            "MAX_BOOTSTRAP_USES",
            "MAX_SLOT_USES",
            "MAX_OFFCHAIN_GAP",
            "OWNER_BYTES_LEN",
            "EXECUTE_SELECTOR",
            "EXECUTE_BATCH_SELECTOR",
            "FACTORY_ADD_SLOT_DOMAIN",
        ];
        // Every `internal constant` in the rendered output must be one
        // of the approved names. We walk the lines and parse the name.
        for line in rendered.lines() {
            // Match lines like "    uint256 internal constant FOO = …;"
            // or "    bytes4  internal constant FOO = …;" etc.
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("uint256 internal constant ")
                .or_else(|| trimmed.strip_prefix("bytes4 internal constant "))
                .or_else(|| trimmed.strip_prefix("bytes internal constant "))
            else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            assert!(
                approved.contains(&name.as_str()),
                "rendered library exposes unapproved constant `{name}` — \
                 adding constants requires a conscious update to this allowlist",
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// scan-registry — render-coverage scan over the upstream ERC-7730 registry
// ─────────────────────────────────────────────────────────────────────

/// Per-category skip examples retained for the report (the printed summary
/// shows the first few; the `--report` file gets all of them).
const EXAMPLES_PER_CATEGORY: usize = 500;

/// `(count, [(registry-relative path, raw skip reason)])` for one skip category.
type SkipBucket = (usize, Vec<(String, String)>);

/// `scan-registry --registry-root <dir> [--input <dir>] [--policy <path>]
/// [--report <path>]`
///
/// Tolerantly compiles every descriptor under `--input` (default
/// `<registry-root>/registry`) through the same capability-aware
/// `dbgen::erc7730` pipeline the firmware-pinned catalog uses, with the exact
/// production ERC-20 DB input. It tallies how many the on-device renderer can
/// clear-sign today vs. how many are skipped and why. Read-only — writes
/// nothing into the firmware corpus; it answers "how much of the real registry
/// can PQ1 clear-sign, and what is the rest blocked on".
fn cmd_scan_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut input: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--input" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("scan-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let registry_root = match registry_root {
        Some(r) => r,
        None => {
            eprintln!("scan-registry: --registry-root <dir> is required");
            return ExitCode::FAILURE;
        }
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let input = input.unwrap_or_else(|| registry_root.join("registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));

    let prod_erc20 = match load_production_erc20_capability_input(&workspace_root) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("scan-registry: {e}");
            return ExitCode::FAILURE;
        }
    };

    let policy = match dbgen::erc7730::load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("scan-registry: load policy {}: {e}", policy_path.display());
            return ExitCode::FAILURE;
        }
    };

    let mut files: Vec<PathBuf> = Vec::new();
    collect_json_recursive(&input, &mut files);
    files.sort();
    if files.is_empty() {
        eprintln!(
            "scan-registry: no .json descriptors under {}",
            input.display()
        );
        return ExitCode::FAILURE;
    }

    let mut ok_files = 0usize;
    let mut ok_leaves = 0usize;
    let mut covered_projects: std::collections::BTreeSet<String> = Default::default();
    // category -> (count, example (relpath, raw reason) list)
    let mut skips: std::collections::BTreeMap<&'static str, SkipBucket> = Default::default();

    for f in &files {
        let rel = f
            .strip_prefix(&registry_root)
            .unwrap_or(f)
            .to_string_lossy()
            .to_string();
        match dbgen::erc7730::try_compile_one_with_erc20_capabilities(
            f,
            &policy,
            Some(&registry_root),
            &prod_erc20.capabilities,
        ) {
            Ok(entries) => {
                ok_files += 1;
                ok_leaves += entries.len();
                covered_projects.insert(project_of(&rel));
            }
            Err(reason) => {
                let cat = skip_category(&reason);
                let e = skips.entry(cat).or_default();
                e.0 += 1;
                if e.1.len() < EXAMPLES_PER_CATEGORY {
                    e.1.push((rel, reason));
                }
            }
        }
    }

    let total = files.len();
    let skipped: usize = skips.values().map(|(c, _)| c).sum();
    let mut by_count: Vec<(&&'static str, &SkipBucket)> = skips.iter().collect();
    by_count.sort_by_key(|(_, bucket)| std::cmp::Reverse(bucket.0));

    let mut out = String::new();
    let _ = writeln!(out, "# ERC-7730 registry render-coverage scan\n");
    let _ = writeln!(out, "input:    {}", input.display());
    let _ = writeln!(
        out,
        "policy:   {} (allow_unattested_dev_descriptors = {})",
        policy_path.display(),
        policy.allow_unattested_dev_descriptors
    );
    let _ = write!(out, "{}", render_erc20_capability_receipt(&prod_erc20));
    let _ = writeln!(out, "\n## Summary");
    let _ = writeln!(out, "descriptors scanned:        {total}");
    let pct = (ok_files * 100).checked_div(total).unwrap_or(0);
    let _ = writeln!(out, "COMPILE (renderable today):  {ok_files}  ({pct}%) -> {ok_leaves} catalog leaves, across {} projects", covered_projects.len());
    let _ = writeln!(out, "skipped:                     {skipped}");
    let _ = writeln!(out, "\n## Skipped, by reason (what the rest is blocked on)");
    for (cat, (count, examples)) in &by_count {
        let _ = writeln!(out, "\n### {count}  {cat}");
        for (path, reason) in examples.iter() {
            let short: String = reason.chars().take(140).collect();
            let _ = writeln!(out, "    - {path}\n        {short}");
        }
    }
    let _ = writeln!(out, "\n## Covered projects ({})", covered_projects.len());
    let cps: Vec<&String> = covered_projects.iter().collect();
    let _ = writeln!(
        out,
        "    {}",
        cps.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    print!("{out}");
    if let Some(rp) = report_path {
        if let Err(e) = fs::write(&rp, &out) {
            eprintln!("scan-registry: write report {}: {e}", rp.display());
            return ExitCode::FAILURE;
        }
        println!("\nscan-registry: wrote {}", rp.display());
    }
    ExitCode::SUCCESS
}

/// `build-registry --registry-root <dir> [--input <dir>] [--policy <path>]
/// [--report <path>]`
///
/// Tolerantly builds the ERC-7730 catalog (Merkle root + leaves) from the
/// upstream registry via the production ERC-20 capability-aware tolerant
/// pipeline. Reports the leaf count, root, capability input/root, and skips
/// (descriptors / duplicate leaves the on-device renderer cannot take).
/// Read-only: it does not overwrite the firmware-pinned root.
fn cmd_build_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut input: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--input" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("build-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let Some(registry_root) = registry_root else {
        eprintln!("build-registry: --registry-root <dir> is required");
        return ExitCode::FAILURE;
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let input = input.unwrap_or_else(|| registry_root.join("registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));

    let prod_erc20 = match load_production_erc20_capability_input(&workspace_root) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("build-registry: {e}");
            return ExitCode::FAILURE;
        }
    };

    let CapabilityBoundRegistryBuild {
        catalogue: result,
        skips,
        erc20,
    } = match build_capability_bound_registry(
        &input,
        &policy_path,
        Some(&registry_root),
        &prod_erc20,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("build-registry: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("# ERC-7730 tolerant registry build");
    println!("input:   {}", input.display());
    print!(
        "{}",
        render_erc20_capability_receipt_parts(&prod_erc20.source, &erc20)
    );
    println!("leaves:  {}", result.leaf_count);
    println!("root:    {}", hex_lower(&result.root));
    println!("skipped: {} descriptor(s)/leaf(s)", skips.len());

    if let Some(rp) = report_path {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# tolerant registry build — {} leaves, {} skipped\n",
            result.leaf_count,
            skips.len()
        );
        let _ = writeln!(out, "root: {}\n", hex_lower(&result.root));
        let _ = writeln!(
            out,
            "{}",
            render_erc20_capability_receipt_parts(&prod_erc20.source, &erc20)
        );
        // Sorted leaf keys (chain:contract:typehash) for cross-build diffing.
        let mut keys: Vec<String> = result
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{}:{}:{}",
                    e.chain_id,
                    hex_lower(&e.contract),
                    hex_lower(&e.primary_type_hash)
                )
            })
            .collect();
        keys.sort();
        let _ = writeln!(out, "## leaf keys ({})", keys.len());
        for k in &keys {
            let _ = writeln!(out, "LEAF {k}");
        }
        let _ = writeln!(out, "\n## skips");
        for s in &skips {
            let rel = s.source.strip_prefix(&registry_root).unwrap_or(&s.source);
            let short: String = s.reason.chars().take(160).collect();
            let _ = writeln!(out, "- {}\n    {}", rel.display(), short);
        }
        if let Err(e) = fs::write(&rp, &out) {
            eprintln!("build-registry: write report {}: {e}", rp.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", rp.display());
    }
    ExitCode::SUCCESS
}

fn canonical_named_destination(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("destination must be a named directory: {}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", path.display()))?;
    let absolute_parent = if parent.as_os_str().is_empty() {
        env::current_dir().map_err(|error| format!("read current directory: {error}"))?
    } else if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("read current directory: {error}"))?
            .join(parent)
    };
    let canonical_parent = fs::canonicalize(&absolute_parent).map_err(|error| {
        format!(
            "canonicalize destination parent {}: {error}",
            absolute_parent.display()
        )
    })?;
    Ok(canonical_parent.join(name))
}

/// `vendor-registry --registry-root <dir> [--out <dir>] [--policy <path>]
///                  [--curation-manifest <path> | --no-curation-overlay]`
///
/// Vendors the complete security-relevant JSON corpus of the upstream registry
/// into the repo (default `secure/data/erc7730-registry/`) so both accepted
/// render leaves and intentionally-refused call declarations remain
/// reproducible.  A dead-only project contributes no Merkle leaf but still has
/// to remain in the known-call omission filter; therefore root equality alone
/// is explicitly insufficient as a faithfulness proof.
fn cmd_vendor_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut curation_manifest: Option<PathBuf> = None;
    let mut no_curation_overlay = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--curation-manifest" => {
                i += 1;
                curation_manifest = args.get(i).map(PathBuf::from);
            }
            "--no-curation-overlay" => {
                no_curation_overlay = true;
            }
            other => {
                eprintln!("vendor-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let Some(registry_root) = registry_root else {
        eprintln!("vendor-registry: --registry-root <dir> is required");
        return ExitCode::FAILURE;
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    if no_curation_overlay && curation_manifest.is_some() {
        eprintln!(
            "vendor-registry: --curation-manifest and --no-curation-overlay are mutually exclusive"
        );
        return ExitCode::FAILURE;
    }
    let explicit_out = out.is_some();
    let default_out = workspace_root.join("secure/data/erc7730-registry");
    let out = out.unwrap_or_else(|| workspace_root.join("secure/data/erc7730-registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));
    if no_curation_overlay {
        if !explicit_out {
            eprintln!(
                "vendor-registry: --no-curation-overlay requires an explicit disposable --out"
            );
            return ExitCode::FAILURE;
        }
        match (
            canonical_named_destination(&out),
            canonical_named_destination(&default_out),
        ) {
            (Ok(requested), Ok(production)) if requested == production => {
                eprintln!(
                    "vendor-registry: refusing --no-curation-overlay for the checked-in production corpus"
                );
                return ExitCode::FAILURE;
            }
            (Err(error), _) | (_, Err(error)) => {
                eprintln!("vendor-registry: {error}");
                return ExitCode::FAILURE;
            }
            _ => {}
        }
    }
    let overlay = if no_curation_overlay {
        None
    } else {
        let manifest_path = curation_manifest
            .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_CURATION_MANIFEST));
        match erc7730_curation::VerifiedOverlay::load_and_verify_local_inputs(
            &workspace_root,
            &manifest_path,
        ) {
            Ok(overlay) => {
                if let Err(error) = overlay.verify_selected_policy(&workspace_root, &policy_path) {
                    eprintln!("vendor-registry: curation overlay: {error}");
                    return ExitCode::FAILURE;
                }
                Some(overlay)
            }
            Err(error) => {
                eprintln!("vendor-registry: curation overlay: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    let prod_erc20 = match load_production_erc20_capability_input(&workspace_root) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("vendor-registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    match vendor_registry(
        &registry_root,
        &out,
        &policy_path,
        &prod_erc20,
        overlay.as_ref(),
    ) {
        Ok(receipt) => {
            println!(
                "vendored {} files ({} leaf-bearing sources + {} refused/support JSON files)",
                receipt.copied, receipt.descriptor_count, receipt.support_count
            );
            println!("out:   {}", out.display());
            let proof_label = if receipt.overlay.is_some() {
                "hash-bound curated catalogue + exact manifest-authorized known-call additions reproduced ✓"
            } else {
                "exact pristine catalogue + known-call coverage reproduced ✓"
            };
            println!("root:  {} ({proof_label})", hex_lower(&receipt.root));
            println!("leaves: {}", receipt.leaf_count);
            println!("known calls: {}", receipt.known_call_count);
            println!(
                "known-call tuple-set SHA-256: {}",
                hex_lower(&receipt.known_call_set_hash)
            );
            print!(
                "{}",
                render_erc20_capability_receipt_parts(&prod_erc20.source, &receipt.erc20)
            );
            println!(
                "upstream corpus: {} files / {} bytes / SHA-256 {}",
                receipt.upstream_corpus.file_count,
                receipt.upstream_corpus.byte_count,
                hex_lower(&receipt.upstream_corpus.sha256)
            );
            println!(
                "installed corpus: {} files / {} bytes / SHA-256 {}",
                receipt.installed_corpus.file_count,
                receipt.installed_corpus.byte_count,
                hex_lower(&receipt.installed_corpus.sha256)
            );
            if let Some((count, manifest_hash, commit, tree, known_call_additions)) =
                receipt.overlay
            {
                println!(
                    "curation overlay: {count} full-file replacements, manifest SHA-256 {}",
                    hex_lower(&manifest_hash)
                );
                println!("upstream Git: commit {commit}, tree {tree}");
                println!(
                    "known-call policy: {known_call_additions} exact additions, zero deletions"
                );
            } else {
                println!("curation overlay: disabled for disposable baseline output");
            }
            println!(
                "excluded fixture JSON: {} files, SHA-256 {}",
                receipt.excluded_fixture_count,
                hex_lower(&receipt.excluded_fixture_hash)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vendor-registry: {error}");
            ExitCode::FAILURE
        }
    }
}

struct VendorReceipt {
    copied: usize,
    descriptor_count: usize,
    support_count: usize,
    root: [u8; 32],
    leaf_count: usize,
    known_call_count: usize,
    known_call_set_hash: [u8; 32],
    erc20: Erc20CapabilityReceipt,
    upstream_corpus: erc7730_curation::CorpusReceipt,
    installed_corpus: erc7730_curation::CorpusReceipt,
    overlay: Option<(usize, [u8; 32], String, String, usize)>,
    excluded_fixture_count: usize,
    excluded_fixture_hash: [u8; 32],
}

fn vendor_registry(
    registry_root: &std::path::Path,
    out: &std::path::Path,
    policy_path: &std::path::Path,
    prod_erc20: &Erc20CapabilityInput,
    overlay: Option<&erc7730_curation::VerifiedOverlay>,
) -> Result<VendorReceipt, String> {
    let registry_root = fs::canonicalize(registry_root)
        .map_err(|e| format!("canonicalize source {}: {e}", registry_root.display()))?;
    if let Some(overlay) = overlay {
        overlay.verify_upstream_checkout(&registry_root)?;
    }
    if out.file_name().is_none() {
        return Err(format!(
            "unsafe --out {} (must be a distinct named directory)",
            out.display()
        ));
    }
    if out
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(format!("--out may not be a symlink: {}", out.display()));
    }
    let out_parent = out
        .parent()
        .ok_or_else(|| format!("--out has no parent: {}", out.display()))?;
    fs::create_dir_all(out_parent)
        .map_err(|e| format!("create output parent {}: {e}", out_parent.display()))?;
    let canonical_parent = fs::canonicalize(out_parent)
        .map_err(|e| format!("canonicalize output parent {}: {e}", out_parent.display()))?;
    let canonical_out = canonical_parent.join(out.file_name().expect("checked named output"));
    if canonical_out.starts_with(&registry_root) || registry_root.starts_with(&canonical_out) {
        return Err(format!(
            "source/output overlap is forbidden: source={} out={}",
            registry_root.display(),
            canonical_out.display()
        ));
    }

    if canonical_out.exists() {
        let mut entries = fs::read_dir(&canonical_out)
            .map_err(|e| format!("read output {}: {e}", canonical_out.display()))?;
        let nonempty = entries
            .next()
            .transpose()
            .map_err(|e| format!("read output entry {}: {e}", canonical_out.display()))?
            .is_some();
        if nonempty && !canonical_out.join(ERC7730_VENDOR_MARKER).is_file() {
            return Err(format!(
                "refusing to replace unmarked nonempty output {}",
                canonical_out.display()
            ));
        }
    }

    let input = registry_root.join("registry");
    let ercs_input = registry_root.join("ercs");
    validate_vendor_source_directory(&input, "registry")?;
    validate_vendor_source_directory(&ercs_input, "ercs")?;
    let source_build =
        build_capability_bound_registry(&input, policy_path, Some(&registry_root), prod_erc20)
            .map_err(|e| format!("registry build: {e}"))?;
    let result = &source_build.catalogue;
    let mut source_files = std::collections::BTreeSet::<PathBuf>::new();
    let mut excluded_fixtures = std::collections::BTreeSet::<PathBuf>::new();
    for dir in [input, ercs_input] {
        collect_vendor_jsons(&dir, &mut source_files, &mut excluded_fixtures, false)?;
    }
    let source_corpus = vendor_corpus_receipt(&registry_root, &source_files)?;
    let excluded_fixture_corpus =
        vendor_excluded_fixture_receipt(&registry_root, &excluded_fixtures)?;
    if let Some(overlay) = overlay {
        overlay.verify_source_receipts(source_corpus, excluded_fixture_corpus)?;
    }

    let out_name = canonical_out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output directory name must be UTF-8".to_string())?;
    let staging =
        canonical_parent.join(format!(".{out_name}.vendor-staging-{}", std::process::id()));
    if staging.exists() {
        return Err(format!(
            "staging path already exists: {}",
            staging.display()
        ));
    }
    fs::create_dir(&staging)
        .map_err(|e| format!("create staging directory {}: {e}", staging.display()))?;

    for src in &source_files {
        let rel = src
            .strip_prefix(&registry_root)
            .map_err(|_| format!("source escaped registry root: {}", src.display()))?;
        let dst = staging.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::copy(src, &dst).map_err(|e| format!("copy {}: {e}", src.display()))?;
    }

    let mut staged_files = std::collections::BTreeSet::<PathBuf>::new();
    let mut staged_excluded_fixtures = std::collections::BTreeSet::<PathBuf>::new();
    for dir in [staging.join("registry"), staging.join("ercs")] {
        collect_vendor_jsons(
            &dir,
            &mut staged_files,
            &mut staged_excluded_fixtures,
            false,
        )?;
    }
    if !staged_excluded_fixtures.is_empty() {
        return Err("internal error: excluded fixture JSON was copied into staging".to_string());
    }
    let pristine_staged_corpus = vendor_corpus_receipt(&staging, &staged_files)?;
    if pristine_staged_corpus != source_corpus {
        return Err(format!(
            "FAITHFULNESS CHECK FAILED — source corpus files/bytes/hash={}/{}/{} staged={}/{}/{}",
            source_corpus.file_count,
            source_corpus.byte_count,
            hex_lower(&source_corpus.sha256),
            pristine_staged_corpus.file_count,
            pristine_staged_corpus.byte_count,
            hex_lower(&pristine_staged_corpus.sha256)
        ));
    }
    if let Some(overlay) = overlay {
        overlay.apply_to_staging(&staging)?;
        overlay.verify_applied_diff(&registry_root, &source_files, &staging, &staged_files)?;
    }
    let staged_corpus = vendor_corpus_receipt(&staging, &staged_files)?;
    if let Some(overlay) = overlay {
        overlay.verify_curated_receipt(staged_corpus)?;
    } else if staged_corpus != source_corpus {
        return Err(format!(
            "FAITHFULNESS CHECK FAILED — baseline staging corpus changed after copy: source={}/{}/{} staged={}/{}/{}",
            source_corpus.file_count,
            source_corpus.byte_count,
            hex_lower(&source_corpus.sha256),
            staged_corpus.file_count,
            staged_corpus.byte_count,
            hex_lower(&staged_corpus.sha256)
        ));
    }

    let staged_build = build_capability_bound_registry(
        &staging.join("registry"),
        policy_path,
        Some(&staging),
        prod_erc20,
    )
    .map_err(|e| format!("rebuild from staged tree: {e}"))?;
    let vendored = &staged_build.catalogue;
    let known_call_authority_faithful = if let Some(overlay) = overlay {
        overlay
            .verify_known_call_delta(&result.known_calls, &vendored.known_calls)
            .map_err(|error| format!("FAITHFULNESS CHECK FAILED — {error}"))?;
        true
    } else {
        vendored.known_calls == result.known_calls
            && vendored.known_call_count == result.known_call_count
            && vendored.known_call_set_hash == result.known_call_set_hash
            && vendored.known_calls_bloom == result.known_calls_bloom
    };
    let common_authority_faithful = vendored.provenance == result.provenance
        && known_call_authority_faithful
        && staged_build.erc20 == source_build.erc20;
    let catalogue_faithful = overlay.is_some()
        || (vendored.root == result.root
            && vendored.blob == result.blob
            && vendored.leaf_count == result.leaf_count
            && vendored.review_text == result.review_text);
    let faithful = common_authority_faithful && catalogue_faithful;
    if !faithful {
        return Err(format!(
            "FAITHFULNESS CHECK FAILED\n\
             source:   root={} leaves={} provenance={} known_calls={} tuple_hash={}\n\
             staged:   root={} leaves={} provenance={} known_calls={} tuple_hash={}\n\
             ERC-20 capability input: sha256={} root={} entries={} capabilities={}\n\
             exact checks: blob={} known_call_authority={} review={} erc20_receipt={} overlay_mode={}",
            hex_lower(&result.root),
            result.leaf_count,
            result.provenance.as_str(),
            result.known_call_count,
            hex_lower(&result.known_call_set_hash),
            hex_lower(&vendored.root),
            vendored.leaf_count,
            vendored.provenance.as_str(),
            vendored.known_call_count,
            hex_lower(&vendored.known_call_set_hash),
            hex_lower(&prod_erc20.receipt.input_sha256),
            hex_lower(&prod_erc20.receipt.db_root),
            prod_erc20.receipt.entry_count,
            prod_erc20.receipt.capability_count,
            vendored.blob == result.blob,
            known_call_authority_faithful,
            vendored.review_text == result.review_text,
            staged_build.erc20 == source_build.erc20,
            overlay.is_some(),
        ));
    }

    install_vendored_subdirs(&staging, &canonical_out)?;
    let descriptor_count = vendored
        .entries
        .iter()
        .map(|entry| &entry.source)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let support_count = staged_files.len().saturating_sub(descriptor_count);
    Ok(VendorReceipt {
        copied: source_files.len(),
        descriptor_count,
        support_count,
        root: vendored.root,
        leaf_count: vendored.leaf_count,
        known_call_count: vendored.known_call_count,
        known_call_set_hash: vendored.known_call_set_hash,
        erc20: staged_build.erc20,
        upstream_corpus: source_corpus,
        installed_corpus: staged_corpus,
        overlay: overlay.map(|overlay| {
            (
                overlay.replacement_count(),
                overlay.manifest_sha256(),
                overlay.upstream_commit().to_string(),
                overlay.upstream_tree().to_string(),
                overlay.known_call_addition_count(),
            )
        }),
        excluded_fixture_count: excluded_fixture_corpus.file_count,
        excluded_fixture_hash: excluded_fixture_corpus.sha256,
    })
}

fn validate_vendor_source_directory(path: &std::path::Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("inspect {label} source directory {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} source directory may not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{label} source path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Collect every `*.json` under `dir`, including upstream test-fixture paths.
/// Fixture naming may exclude a file from trusted rendering, but it is not a
/// safe omission-filter boundary: moving a declaration under `tests/` or adding
/// `.tests.` to its name must not restore a blind-sign path. Any traversal error
/// or symlink is fatal.
fn collect_vendor_jsons(
    dir: &std::path::Path,
    out: &mut std::collections::BTreeSet<PathBuf>,
    excluded: &mut std::collections::BTreeSet<PathBuf>,
    under_tests_dir: bool,
) -> Result<(), String> {
    validate_vendor_source_directory(dir, "recursive corpus")?;
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("read entry under {}: {e}", dir.display()))?;
        let p = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("file type {}: {e}", p.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is not allowed in vendored corpus: {}",
                p.display()
            ));
        }
        if file_type.is_dir() {
            let child_is_tests = p.file_name().is_some_and(|name| name == "tests");
            collect_vendor_jsons(&p, out, excluded, under_tests_dir || child_is_tests)?;
        } else if file_type.is_file() {
            let name = p
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    "vendored corpus contains a non-UTF-8 regular-file name".to_string()
                })?;
            if name.to_ascii_lowercase().ends_with(".json") && !name.ends_with(".json") {
                return Err(format!(
                    "non-canonical JSON filename `{name}` in vendored corpus — use lowercase `.json`"
                ));
            }
            if name.ends_with(".json") {
                if under_tests_dir || name.contains(".tests.") {
                    validate_excluded_vendor_fixture(&p)?;
                    excluded.insert(p);
                } else {
                    out.insert(p);
                }
            }
        } else {
            return Err(format!(
                "unsupported filesystem entry in vendored corpus: {}",
                p.display()
            ));
        }
    }
    Ok(())
}

/// Excluded upstream fixtures are not copied or trusted for rendering, but the
/// exclusion cannot become a known-call escape hatch. Parse every fixture and
/// refuse a nested include or any live binding: contract/EIP-712 deployment
/// arrays and the EIP-712 domain-only `{chainId, verifyingContract}` form. The
/// inventory is separately receipted for the root-rotation review.
fn validate_excluded_vendor_fixture(path: &std::path::Path) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|e| format!("read excluded fixture {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse excluded fixture {}: {e}", path.display()))?;
    if json.get("includes").is_some() {
        return Err(format!(
            "excluded fixture {} contains `includes`; it must be curated into the security corpus",
            path.display()
        ));
    }
    for pointer in [
        "/context/contract/deployments",
        "/context/eip712/deployments",
    ] {
        if let Some(value) = json.pointer(pointer) {
            let deployments = value.as_array().ok_or_else(|| {
                format!(
                    "excluded fixture {} has non-array `{pointer}`",
                    path.display()
                )
            })?;
            if !deployments.is_empty() {
                return Err(format!(
                    "excluded fixture {} declares deployments at `{pointer}`; fixture naming cannot exclude a live binding",
                    path.display()
                ));
            }
        }
    }
    if let Some(domain) = json.pointer("/context/eip712/domain") {
        let domain = domain.as_object().ok_or_else(|| {
            format!(
                "excluded fixture {} has non-object `/context/eip712/domain`",
                path.display()
            )
        })?;
        let has_chain = domain.get("chainId").is_some_and(|value| !value.is_null());
        let has_contract = domain
            .get("verifyingContract")
            .is_some_and(|value| !value.is_null());
        if has_chain && has_contract {
            return Err(format!(
                "excluded fixture {} declares a fully-specified EIP-712 domain binding; fixture naming cannot exclude a live binding",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Aggregate byte-level receipt for the complete copied corpus. Paths are
/// registry-root-relative and sorted; each file contributes its own SHA-256 so
/// semantically-unused templates remain part of the faithfulness proof.
fn vendor_corpus_receipt(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
) -> Result<erc7730_curation::CorpusReceipt, String> {
    vendor_corpus_receipt_with_domain(root, files, b"pqsigner/erc7730-vendor-corpus-v1")
}

fn vendor_corpus_receipt_with_domain(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
    domain: &[u8],
) -> Result<erc7730_curation::CorpusReceipt, String> {
    erc7730_curation::corpus_receipt(root, files, domain)
}

fn vendor_excluded_fixture_receipt(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
) -> Result<erc7730_curation::CorpusReceipt, String> {
    vendor_corpus_receipt_with_domain(root, files, b"pqsigner/erc7730-excluded-fixture-corpus-v1")
}

/// Install only the two tool-managed subdirectories after every source/staged
/// receipt has passed. This is a checked two-directory transaction, not a
/// filesystem-atomic pair swap: existing directories are moved to a retained
/// sibling backup first, and every rollback operation is checked. Any uncertain
/// rollback reports the backup path and never claims that the prior corpus was
/// restored.
fn install_vendored_subdirs(
    staging: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("create output {}: {e}", out.display()))?;
    let marker = out.join(ERC7730_VENDOR_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => validate_vendor_marker(&marker)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&marker, ERC7730_VENDOR_MARKER_BYTES)
                .map_err(|e| format!("write vendor marker {}: {e}", marker.display()))?;
        }
        Err(error) => {
            return Err(format!(
                "inspect vendor marker {}: {error}",
                marker.display()
            ));
        }
    }

    let parent = out
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", out.display()))?;
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output directory name must be UTF-8".to_string())?;
    let backup = parent.join(format!(".{name}.vendor-backup-{}", std::process::id()));
    if backup.exists() {
        return Err(format!("backup path already exists: {}", backup.display()));
    }
    fs::create_dir(&backup)
        .map_err(|e| format!("create backup directory {}: {e}", backup.display()))?;

    let subdirs = ["registry", "ercs"];
    let mut old_moved = [false; 2];
    for (index, subdir) in subdirs.iter().enumerate() {
        let old = out.join(subdir);
        if old.exists() {
            if let Err(error) = fs::rename(&old, backup.join(subdir)) {
                let rollback = rollback_vendored_install(
                    staging,
                    out,
                    &backup,
                    &subdirs,
                    &old_moved,
                    &[false; 2],
                );
                return Err(install_failure_message(
                    &format!("move existing {} into backup: {error}", old.display()),
                    &backup,
                    rollback,
                ));
            }
            old_moved[index] = true;
        }
    }

    let mut new_moved = [false; 2];
    for (index, subdir) in subdirs.iter().enumerate() {
        let staged = staging.join(subdir);
        let destination = out.join(subdir);
        if let Err(error) = fs::rename(&staged, &destination) {
            let rollback =
                rollback_vendored_install(staging, out, &backup, &subdirs, &old_moved, &new_moved);
            return Err(install_failure_message(
                &format!("install staged directory {}: {error}", staged.display()),
                &backup,
                rollback,
            ));
        }
        new_moved[index] = true;
    }

    fs::remove_dir(staging)
        .map_err(|e| format!("installed corpus but could not remove empty staging dir: {e}"))?;
    fs::remove_dir_all(&backup).map_err(|e| {
        format!(
            "installed corpus but could not remove tool-owned backup {}: {e}",
            backup.display()
        )
    })?;
    Ok(())
}

fn validate_vendor_marker(marker: &std::path::Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(marker)
        .map_err(|e| format!("inspect vendor marker {}: {e}", marker.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "vendor marker must be a regular non-symlink file: {}",
            marker.display()
        ));
    }
    let bytes =
        fs::read(marker).map_err(|e| format!("read vendor marker {}: {e}", marker.display()))?;
    if bytes != ERC7730_VENDOR_MARKER_BYTES {
        return Err(format!(
            "vendor marker content mismatch at {}; refusing to replace tool-managed directories",
            marker.display()
        ));
    }
    Ok(())
}

fn rollback_vendored_install(
    staging: &std::path::Path,
    out: &std::path::Path,
    backup: &std::path::Path,
    subdirs: &[&str; 2],
    old_moved: &[bool; 2],
    new_moved: &[bool; 2],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // First remove every newly-installed directory from the destination so an
    // old directory can be restored without a destination collision.
    for index in (0..subdirs.len()).rev() {
        if new_moved[index] {
            let installed = out.join(subdirs[index]);
            let staged = staging.join(subdirs[index]);
            if let Err(error) = fs::rename(&installed, &staged) {
                errors.push(format!(
                    "move newly installed {} back to staging {}: {error}",
                    installed.display(),
                    staged.display()
                ));
            }
        }
    }

    for index in (0..subdirs.len()).rev() {
        if old_moved[index] {
            let saved = backup.join(subdirs[index]);
            let destination = out.join(subdirs[index]);
            if let Err(error) = fs::rename(&saved, &destination) {
                errors.push(format!(
                    "restore prior {} from {}: {error}",
                    destination.display(),
                    saved.display()
                ));
            }
        }
    }

    if errors.is_empty() {
        if let Err(error) = fs::remove_dir(backup) {
            errors.push(format!(
                "remove empty rollback backup {}: {error}",
                backup.display()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn install_failure_message(
    cause: &str,
    backup: &std::path::Path,
    rollback: Result<(), Vec<String>>,
) -> String {
    match rollback {
        Ok(()) => format!("{cause}; checked rollback restored the prior corpus"),
        Err(errors) => format!(
            "{cause}; ROLLBACK INCOMPLETE — do not use the destination. Retained backup at {}. Rollback errors: {}",
            backup.display(),
            errors.join(" | ")
        ),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn collect_json_recursive(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip the registry's `tests/` fixture dirs.
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_json_recursive(&p, out);
        } else if is_descriptor_file(&p) {
            out.push(p);
        }
    }
}

/// True only for standalone ERC-7730 descriptors. The registry mixes, in
/// the same dirs: `calldata-*.json` / `eip712-*.json` (the descriptors),
/// `common-*.json` (include-only templates with no `context`, pulled in via
/// `includes`), and `*.tests.json` (test fixtures). Only the first kind is a
/// compilable descriptor; counting the rest would mis-report coverage.
fn is_descriptor_file(p: &std::path::Path) -> bool {
    let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".json")
        && !name.contains(".tests.")
        && (name.starts_with("calldata-") || name.starts_with("eip712-"))
}

/// The project segment of a registry-relative path (`registry/aave/...` ->
/// `aave`, `ercs/...` -> `ercs`), for the covered-projects roll-up.
fn project_of(rel: &str) -> String {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        [first, second, ..] if *first == "registry" => second.to_string(),
        [first, ..] => first.to_string(),
        _ => rel.to_string(),
    }
}

/// Bucket a dbgen compile error into a coarse "what's blocking it" category.
/// Ordered most-specific-first; the raw reason is still shown per example.
fn skip_category(msg: &str) -> &'static str {
    let m = msg;
    if m.contains("array index") || m.contains("array slice") || m.contains("ArrayIdx") {
        "array-path (needs dynamic-array walker)"
    } else if m.contains("dynamic tuple") || m.contains("is dynamic") || m.contains("calldata tail")
    {
        "dynamic-ABI-type (needs dynamic-array walker)"
    } else if m.contains("spanning") && m.contains("words") {
        "multi-word static field (>32B)"
    } else if m.contains("includes") {
        "includes-unresolved"
    } else if m.contains("nested calldata") || m.contains("encrypted") {
        "unsupported formatter (nested-calldata / encrypted)"
    } else if m.contains("nft") {
        "unsupported formatter (nft)"
    } else if m.contains("enum") {
        "enum issue"
    } else if m.contains("completeness")
        || m.contains("not covered")
        || m.contains("must cover")
        || m.contains("uncovered")
    {
        "completeness lint (un-displayed field)"
    } else if m.contains("MAX_IR_LEN")
        || m.contains("exceeds")
        || m.contains("too large")
        || m.contains("too long")
    {
        "IR too large (>4KiB)"
    } else if m.contains("policy") || m.contains("attest") {
        "attestation policy"
    } else if m.starts_with("schema")
        || m.starts_with("parse")
        || m.contains("schema:")
        || m.contains("missing field")
        || m.contains("unknown field")
    {
        "schema / parse"
    } else if m.contains("selector")
        || m.contains("signature")
        || m.contains("encodeType")
        || m.contains("primary")
    {
        "selector / type-signature"
    } else {
        "other"
    }
}
