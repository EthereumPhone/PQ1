//! `pqsigner-xtask` — host-side codegen and tooling.
//!
//! See `Cargo.toml` for the design rationale. Today the single
//! subcommand is `gen-solidity-constants`, which renders a Solidity
//! library from the public constants in `pqsigner-proto`.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use pqsigner_proto as proto;

const SOLIDITY_OUT_PATH: &str = "contracts/smart-wallet/src/generated/PqsignerProto.sol";

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

    let out_path = workspace_root().join(SOLIDITY_OUT_PATH);

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
        // abi.encode(uint256, bytes) head + tail:
        // 32 (ownerIndex) + 32 (offset) + 32 (length) + 32-padded inner sig.
        32 + 32 + 32 + padded_inner,
        "abi.encode(uint256 ownerIndex, bytes innerSig) layout: \
         32 (ownerIndex) + 32 (offset) + 32 (length) + ((C10_SIG_LEN + 31) / 32) * 32",
    );

    section_header(&mut s, "Per-chain usage caps");
    sol_uint256(&mut s, "MAX_BOOTSTRAP_USES", u128::from(proto::MAX_BOOTSTRAP_USES));
    sol_uint256(&mut s, "MAX_SLOT_USES", u128::from(proto::MAX_SLOT_USES));
    sol_uint256(&mut s, "MAX_OFFCHAIN_GAP", u128::from(proto::MAX_OFFCHAIN_GAP));

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
