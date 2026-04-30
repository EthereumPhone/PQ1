//! pqsigner-xtask — host-side codegen and tooling.
//!
//! See `Cargo.toml` for the design rationale. Today the single
//! subcommand is `gen-solidity-constants`, which renders a Solidity
//! library from the public constants in `pqsigner-proto`. Phase 4 of
//! the modularity refactor.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use pqsigner_proto as proto;

const SOLIDITY_OUT_PATH: &str =
    "contracts/smart-wallet/src/generated/PqsignerProto.sol";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let subcmd = args.first().map(String::as_str).unwrap_or("");

    match subcmd {
        "gen-solidity-constants" => cmd_gen_solidity_constants(&args[1..]),
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
  gen-solidity-constants [--check]
      Render `{SOLIDITY_OUT_PATH}` from `pqsigner-proto`.
      With --check: print the rendered output to stdout instead of
      writing the file (used by CI to diff against the checked-in copy).
  help
      Print this message.
"
    );
}

fn cmd_gen_solidity_constants(args: &[String]) -> ExitCode {
    let check_mode = args.iter().any(|a| a == "--check");
    let rendered = render_solidity_library();

    if check_mode {
        // CI uses this output for `diff /tmp/expected.sol <checked-in>`.
        print!("{rendered}");
        return ExitCode::SUCCESS;
    }

    // Walk up from CARGO_MANIFEST_DIR (xtask/) to the workspace root
    // before resolving `contracts/smart-wallet/...`. CI invokes
    // `cargo run -p pqsigner-xtask -- gen-solidity-constants` from the
    // workspace root, so CARGO_MANIFEST_DIR is `<workspace>/xtask`.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let workspace_root = manifest_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let out_path = workspace_root.join(SOLIDITY_OUT_PATH);

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
    ExitCode::SUCCESS
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
    s.push_str("// Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md\n");
    s.push_str("// Phase 4 of the modularity refactor.\n");
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
        // 32 (ownerIndex) + 32 (offset) + 32 (length) + padded inner sig
        32 + 32 + 32 + padded_inner,
        "abi.encode(uint256 ownerIndex, bytes innerSig) layout: \
         32 (ownerIndex) + 32 (offset) + 32 (length) + ((C10_SIG_LEN + 31) / 32) * 32",
    );

    section_header(&mut s, "Per-chain usage caps");
    sol_uint256(&mut s, "MAX_BOOTSTRAP_USES", proto::MAX_BOOTSTRAP_USES as u128);
    sol_uint256(&mut s, "MAX_SLOT_USES", proto::MAX_SLOT_USES as u128);
    sol_uint256(&mut s, "MAX_OFFCHAIN_GAP", proto::MAX_OFFCHAIN_GAP as u128);

    section_header(&mut s, "Wallet storage layout");
    sol_uint256(&mut s, "OWNER_BYTES_LEN", proto::OWNER_BYTES_LEN as u128);

    section_header(&mut s, "Selectors");
    sol_bytes4(&mut s, "EXECUTE_SELECTOR", &proto::EXECUTE_SELECTOR);
    sol_bytes4(&mut s, "EXECUTE_BATCH_SELECTOR", &proto::EXECUTE_BATCH_SELECTOR);

    section_header(&mut s, "Domain tags");
    sol_bytes(&mut s, "FACTORY_ADD_SLOT_DOMAIN", proto::FACTORY_ADD_SLOT_DOMAIN);

    s.push_str("}\n");
    s
}

fn padded_to_32(v: u128) -> u128 {
    ((v + 31) / 32) * 32
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
    let hex = format!(
        "0x{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    );
    let _ = writeln!(s, "    bytes4 internal constant {name} = {hex};");
}

fn sol_bytes(s: &mut String, name: &str, bytes: &[u8]) {
    // Solidity `bytes` literal: must be representable as a string literal
    // (so we render printable-ASCII tags as `"..."`). Anything outside
    // printable ASCII falls back to a `hex"..."` literal — defensive
    // default since this codepath only sees domain tags today.
    let printable = bytes
        .iter()
        .all(|b| (0x20..=0x7E).contains(b) && *b != b'"' && *b != b'\\');
    if printable {
        let s_lit = std::str::from_utf8(bytes).expect("ASCII validated above");
        let _ = writeln!(
            s,
            "    bytes internal constant {name} = {sq}{s_lit}{sq};",
            sq = "\""
        );
    } else {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(hex, "{b:02x}");
        }
        let _ = writeln!(
            s,
            "    bytes internal constant {name} = hex{sq}{hex}{sq};",
            sq = "\""
        );
    }
}
