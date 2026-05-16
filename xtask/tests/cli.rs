//! Spawn-the-binary integration tests for `pqsigner-xtask`.
//!
//! These cover the user-facing CLI contract that the in-crate unit
//! tests can't reach without re-implementing argv parsing: exit codes,
//! help / unknown-subcommand routing, and the critical `--check`
//! mode that CI relies on to diff the rendered Solidity library
//! against the checked-in copy.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqsigner-xtask")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits one dir below the workspace root")
        .to_path_buf()
}

fn checked_in_solidity() -> PathBuf {
    workspace_root().join("contracts/smart-wallet/src/generated/PqsignerProto.sol")
}

// ─────────────────────────────────────────────────────────────────
//                            POSITIVE
// ─────────────────────────────────────────────────────────────────

#[test]
fn positive_help_alias_prints_subcommand_list_and_exits_success() {
    for arg in ["help", "--help", "-h"] {
        let out = Command::new(bin()).arg(arg).output().expect("spawn");
        assert!(
            out.status.success(),
            "help alias `{arg}` must exit success, got {:?}",
            out.status,
        );
        let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
        assert!(
            stdout.contains("gen-solidity-constants"),
            "help alias `{arg}` must list the subcommand, got: {stdout}",
        );
        assert!(
            stdout.contains("pqsigner-xtask"),
            "help alias `{arg}` must self-identify, got: {stdout}",
        );
    }
}

#[test]
fn positive_no_args_prints_help_and_exits_success() {
    let out = Command::new(bin()).output().expect("spawn");
    assert!(out.status.success(), "no-args must exit success");
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    assert!(stdout.contains("Subcommands:"), "no-args must print help");
}

#[test]
fn positive_check_mode_stdout_matches_checked_in_file_byte_for_byte() {
    // The CI invariant: `pqsigner-xtask gen-solidity-constants --check`
    // must reproduce the checked-in Solidity file exactly. Anything
    // else means a developer changed the generator without
    // regenerating, or hand-edited the checked-in copy.
    let out = Command::new(bin())
        .args(["gen-solidity-constants", "--check"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "--check must exit success, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    let checked = std::fs::read_to_string(checked_in_solidity()).expect("read checked-in file");
    assert_eq!(
        stdout, checked,
        "--check output drifted from checked-in Solidity file — \
         regenerate with `cargo run -p pqsigner-xtask -- gen-solidity-constants`",
    );
}

// ─────────────────────────────────────────────────────────────────
//                            NEGATIVE
// ─────────────────────────────────────────────────────────────────

#[test]
fn negative_unknown_subcommand_exits_failure_with_explanation() {
    // Any unknown subcommand must (a) exit non-zero so CI catches a
    // typo'd invocation, and (b) explain what was rejected on stderr.
    let out = Command::new(bin())
        .arg("frobnicate-the-solidity")
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "unknown subcommand must exit non-zero — silently succeeding would \
         hide CI typos and let drift slip through",
    );
    let stderr = String::from_utf8(out.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("unknown subcommand"),
        "stderr must name the rejection reason, got: {stderr}",
    );
    assert!(
        stderr.contains("frobnicate-the-solidity"),
        "stderr must echo the offending subcommand, got: {stderr}",
    );
}

#[test]
fn negative_check_mode_does_not_modify_checked_in_file() {
    // `--check` is the read-only mode. It MUST NOT touch the checked-in
    // Solidity file under any circumstance — that would defeat the
    // whole "diff-only" CI contract and could silently mask drift.
    let path = checked_in_solidity();
    let before = std::fs::read(&path).expect("read before");
    let mtime_before = std::fs::metadata(&path)
        .expect("stat before")
        .modified()
        .expect("mtime before");

    let out = Command::new(bin())
        .args(["gen-solidity-constants", "--check"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "--check must succeed");

    let after = std::fs::read(&path).expect("read after");
    let mtime_after = std::fs::metadata(&path)
        .expect("stat after")
        .modified()
        .expect("mtime after");

    assert_eq!(
        before, after,
        "--check must not modify the checked-in Solidity file contents",
    );
    assert_eq!(
        mtime_before, mtime_after,
        "--check must not modify the checked-in Solidity file mtime",
    );
}

#[test]
fn negative_help_does_not_emit_generated_solidity() {
    // A regression where `help` (or any non-codegen subcommand) silently
    // dumps the Solidity library to stdout would confuse CI pipelines
    // that pipe stdout through `diff` and would also be a subtle
    // surprise to users typing `--help`.
    for arg in ["help", "--help", "-h"] {
        let out = Command::new(bin()).arg(arg).output().expect("spawn");
        let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
        assert!(
            !stdout.contains("library PqsignerProto {"),
            "help variant `{arg}` must not emit the Solidity library, got: {stdout}",
        );
        assert!(
            !stdout.contains("uint256 internal constant"),
            "help variant `{arg}` must not emit Solidity constants, got: {stdout}",
        );
    }
}

#[test]
fn negative_unknown_subcommand_also_prints_help_to_stdout() {
    // The error path is "explain on stderr + print help on stdout +
    // exit non-zero" — verify the help still appears so the user
    // immediately sees the valid subcommands without re-running.
    let out = Command::new(bin()).arg("nope").output().expect("spawn");
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("gen-solidity-constants"),
        "after an unknown subcommand, the help text must still be \
         emitted to stdout so the user sees the valid options, got: {stdout}",
    );
}

#[test]
fn negative_check_mode_produces_no_stderr_diagnostics() {
    // `--check` is consumed by CI as `<bin> --check | diff …`. Any
    // accidental stderr chatter on the happy path would clutter CI
    // logs and could be misread as a failure signal.
    let out = Command::new(bin())
        .args(["gen-solidity-constants", "--check"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("stderr utf8");
    assert!(
        stderr.is_empty(),
        "--check must produce no stderr on the happy path, got: {stderr:?}",
    );
}
