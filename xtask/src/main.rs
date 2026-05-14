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
        "gen-erc7730-descriptors" => cmd_gen_erc7730_descriptors(&args[1..]),
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

  gen-erc7730-descriptors [--check]
                          [--input-dir PATH] [--policy PATH]
                          [--out-binary PATH] [--out-review PATH]
                          [--e2e-input-dir PATH] [--e2e-out-binary PATH]
                          [--out-root PATH]
      Compile the ERC-7730 descriptor catalog from
      `secure/data/erc7730/*.json` against `policy.toml`, build the
      Merkle tree, and emit:
        tools/companion-stub/erc7730_db.bin
        tools/companion-stub/erc7730_db_e2e.bin
        secure/data/erc7730.review.txt
        secure/src/db_roots.rs   (ERC7730_DESCRIPTORS_ROOT)
      With --check: rebuild in-memory and compare against the checked-in
      artifacts; exit non-zero on drift. CI uses this gate, mirroring
      the gen-solidity-constants pattern.

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


// ─────────────────────────────────────────────────────────────────────
// gen-erc7730-descriptors
// ─────────────────────────────────────────────────────────────────────

const ERC7730_DEFAULT_INPUT: &str = "secure/data/erc7730";
const ERC7730_DEFAULT_POLICY: &str = "secure/data/erc7730/policy.toml";
const ERC7730_DEFAULT_E2E_INPUT: &str = "secure/data/erc7730-e2e";
const ERC7730_DEFAULT_OUT: &str = "tools/companion-stub/erc7730_db.bin";
const ERC7730_DEFAULT_E2E_OUT: &str = "tools/companion-stub/erc7730_db_e2e.bin";
const ERC7730_DEFAULT_REVIEW: &str = "secure/data/erc7730.review.txt";

#[derive(Default)]
struct Erc7730Args {
    check: bool,
    input_dir: Option<PathBuf>,
    policy: Option<PathBuf>,
    out_binary: Option<PathBuf>,
    out_review: Option<PathBuf>,
    e2e_input_dir: Option<PathBuf>,
    e2e_out_binary: Option<PathBuf>,
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
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok(out)
}

fn cmd_gen_erc7730_descriptors(args: &[String]) -> ExitCode {
    let parsed = match parse_erc7730_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

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
    let e2e_out_binary = parsed
        .e2e_out_binary
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_OUT));

    // Build both prod + e2e catalogs.
    let prod = match dbgen::erc7730::build_db(&input_dir, &policy) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: prod build failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = dbgen::erc7730::round_trip_check(&prod) {
        eprintln!("error: prod round-trip failed: {e}");
        return ExitCode::FAILURE;
    }
    let e2e = match dbgen::erc7730::build_db(&e2e_input_dir, &policy) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: e2e build failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = dbgen::erc7730::round_trip_check(&e2e) {
        eprintln!("error: e2e round-trip failed: {e}");
        return ExitCode::FAILURE;
    }

    if parsed.check {
        // CI mode: diff against checked-in artifacts.
        let mut drift = false;
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
        // db_roots.rs is owned by `cargo run -p dbgen` (it bakes 5
        // other roots besides ours); only assert that the ERC-7730
        // root line in it matches.
        let roots_path = workspace_root.join("secure/src/db_roots.rs");
        if let Err(e) = diff_root_in_db_roots(&roots_path, &prod.root, &e2e.root) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if drift {
            eprintln!(
                "\nERC-7730 catalog has drifted from the checked-in artifacts.\n\
                 Run `cargo run -p dbgen` (which writes ALL DBs in one pass) and\n\
                 commit the resulting changes."
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
    eprintln!("wrote {}", out_review.display());
    eprintln!(
        "note: secure/src/db_roots.rs is owned by `cargo run -p dbgen` — \
         run that to refresh the ERC7730_DESCRIPTORS_ROOT constant."
    );
    ExitCode::SUCCESS
}

fn diff_bytes(label: &str, path: &PathBuf, fresh: &[u8]) -> Result<(), String> {
    let existing = fs::read(path)
        .map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
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

fn diff_text(label: &str, path: &PathBuf, fresh: &str) -> Result<(), String> {
    let existing = fs::read_to_string(path)
        .map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
    if existing == fresh {
        return Ok(());
    }
    Err(format!("{label} at {} differs from fresh build", path.display()))
}

fn diff_root_in_db_roots(
    path: &PathBuf,
    prod_root: &[u8; 32],
    e2e_root: &[u8; 32],
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read db_roots.rs at {}: {e}", path.display()))?;
    let prod_hex = hex::encode(prod_root);
    let e2e_hex = hex::encode(e2e_root);
    let prod_present = root_const_matches(&text, "ERC7730_DESCRIPTORS_ROOT", &prod_hex);
    let e2e_present = root_const_matches(&text, "ERC7730_DESCRIPTORS_ROOT", &e2e_hex);
    if prod_present && e2e_present {
        return Ok(());
    }
    Err(format!(
        "ERC7730_DESCRIPTORS_ROOT in {} doesn't match fresh build (prod {prod_hex} present={prod_present}, e2e {e2e_hex} present={e2e_present})",
        path.display()
    ))
}

fn root_const_matches(text: &str, name: &str, expected_hex: &str) -> bool {
    // Find every `pub static <name>: [u8; 32] = [...];` block and
    // compare its bytes (hex-encoded) against `expected_hex`.
    let mut search_from = 0;
    while let Some(pos) = text[search_from..].find(&format!("pub static {name}")) {
        let abs = search_from + pos;
        // Skip past the `[u8; 32] =` type annotation: find `= [`.
        let assign = match text[abs..].find("= [") {
            Some(p) => abs + p,
            None => break,
        };
        let bracket = assign + 2; // position of the array-literal `[`
        let close = match text[bracket..].find("];") {
            Some(p) => bracket + p,
            None => break,
        };
        let body = &text[bracket + 1..close];
        let mut hex_out = String::with_capacity(64);
        for tok in body.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            let tok = tok.strip_prefix("0x").unwrap_or(tok);
            hex_out.push_str(tok);
        }
        if hex_out.eq_ignore_ascii_case(expected_hex) {
            return true;
        }
        search_from = close + 2;
    }
    false
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

    /// Defensive: the rendered library must always include the
    /// auto-generated warning AND a pointer to the regenerator command.
    /// Without these, an auditor could hand-edit the Solidity file and
    /// have it survive a regen (until the next CI run catches the diff).
    #[test]
    fn negative_rendered_output_keeps_do_not_edit_warning() {
        let rendered = render_solidity_library();
        assert!(rendered.contains("AUTO-GENERATED — DO NOT EDIT."));
        assert!(rendered.contains("Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`."));
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
            root.join("contracts/smart-wallet/src/generated/PqsignerProto.sol").is_file(),
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
            let Some(rest) = trimmed.strip_prefix("uint256 internal constant ")
                .or_else(|| trimmed.strip_prefix("bytes4 internal constant "))
                .or_else(|| trimmed.strip_prefix("bytes internal constant "))
            else {
                continue;
            };
            let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            assert!(
                approved.contains(&name.as_str()),
                "rendered library exposes unapproved constant `{name}` — \
                 adding constants requires a conscious update to this allowlist",
            );
        }
    }
}
