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

fn checked_in_erc7730_outputs() -> Vec<(PathBuf, Vec<u8>)> {
    let workspace = workspace_root();
    [
        "tools/companion-stub/erc7730_db.bin",
        "tools/companion-stub/erc7730_db_e2e.bin",
        "tools/companion-stub/erc7730_status.bin",
        "tools/companion-stub/erc7730_status_e2e.bin",
        "secure/data/erc7730.review.txt",
        "secure/data/erc7730-known-calls.bloom",
        "secure/data/erc7730-known-calls-e2e.bloom",
        "secure/data/erc7730-forced-eligible.set",
        "secure/data/erc7730-forced-eligible-e2e.set",
    ]
    .into_iter()
    .map(|relative| {
        let path = workspace.join(relative);
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "read checked-in ERC-7730 output {}: {error}",
                path.display()
            )
        });
        (path, bytes)
    })
    .collect()
}

fn assert_checked_in_erc7730_outputs_unchanged(before: &[(PathBuf, Vec<u8>)]) {
    for (path, expected) in before {
        let actual = std::fs::read(path).unwrap_or_else(|error| {
            panic!(
                "re-read checked-in ERC-7730 output {}: {error}",
                path.display()
            )
        });
        assert_eq!(
            &actual,
            expected,
            "custom generation probe changed checked-in output {}",
            path.display()
        );
    }
}

fn copy_probe_registry(root: &std::path::Path) -> PathBuf {
    let registry = root.join("probe-registry/registry");
    std::fs::create_dir_all(&registry).expect("create disposable probe registry");
    std::fs::copy(
        workspace_root().join("secure/data/erc7730-e2e/weth.json"),
        registry.join("calldata-weth-probe.json"),
    )
    .expect("copy valid disposable probe descriptor");
    registry
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
        assert!(
            stdout.contains("secure/data/erc7730-registry/registry")
                && stdout.contains("secure/data/erc7730-e2e")
                && stdout.contains("erc7730_status.bin")
                && stdout.contains("erc7730_status_e2e.bin")
                && stdout.contains("erc7730-known-calls.bloom")
                && stdout.contains("erc7730-known-calls-e2e.bloom")
                && stdout.contains("erc7730-forced-eligible.set")
                && stdout.contains("erc7730-forced-eligible-e2e.set"),
            "help alias `{arg}` must describe the actual catalogue inputs and outputs, got: {stdout}",
        );
        assert!(
            stdout.contains("validation-only")
                && stdout.contains("cargo run -p dbgen")
                && !stdout.contains("--out-root")
                && !stdout.contains("secure/data/erc7730/*.json"),
            "help alias `{arg}` must not advertise retired flags or ownership, got: {stdout}",
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

#[test]
fn positive_check_deployment_mode_stdout_matches_checked_in_file_byte_for_byte() {
    // Same CI invariant for the firmware CREATE2 constants the deploy
    // scripts assert against (`script/generated/PqsignerDeployment.sol`).
    let path = workspace_root().join("contracts/smart-wallet/script/generated/PqsignerDeployment.sol");
    let before = std::fs::read(&path).expect("read before");
    let out = Command::new(bin())
        .args(["gen-solidity-constants", "--check-deployment"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "--check-deployment must exit success, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.stderr.is_empty(), "--check-deployment must be quiet on stderr");
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    assert_eq!(
        stdout,
        String::from_utf8(before.clone()).expect("checked-in file utf8"),
        "--check-deployment output drifted from checked-in PqsignerDeployment.sol — \
         regenerate with `cargo run -p pqsigner-xtask -- gen-solidity-constants`",
    );
    assert_eq!(
        std::fs::read(&path).expect("read after"),
        before,
        "--check-deployment must not modify the checked-in file",
    );
    assert!(
        !stdout.contains("library PqsignerProto {"),
        "--check-deployment must print only the deployment library",
    );
}

#[test]
fn positive_custom_erc7730_probe_with_all_explicit_outputs_is_isolated() {
    let temp = tempfile::tempdir().expect("create custom generation probe directory");
    let input = copy_probe_registry(temp.path());
    let output_dir = temp.path().join("outputs");
    std::fs::create_dir_all(&output_dir).expect("create explicit probe output directory");
    let prod_blob = output_dir.join("prod.bin");
    let review = output_dir.join("review.txt");
    let e2e_blob = output_dir.join("e2e.bin");
    let known_calls = output_dir.join("known-calls.bloom");
    let known_calls_e2e = output_dir.join("known-calls-e2e.bloom");
    let forced_eligible = output_dir.join("forced-eligible.set");
    let forced_eligible_e2e = output_dir.join("forced-eligible-e2e.set");
    let status = output_dir.join("status.bin");
    let status_e2e = output_dir.join("status-e2e.bin");
    let protected = checked_in_erc7730_outputs();

    let output = Command::new(bin())
        .arg("gen-erc7730-descriptors")
        .arg("--input-dir")
        .arg(&input)
        .arg("--e2e-input-dir")
        .arg(&input)
        .arg("--out-binary")
        .arg(&prod_blob)
        .arg("--out-review")
        .arg(&review)
        .arg("--e2e-out-binary")
        .arg(&e2e_blob)
        .arg("--known-calls-out")
        .arg(&known_calls)
        .arg("--known-calls-e2e-out")
        .arg(&known_calls_e2e)
        .arg("--forced-eligible-out")
        .arg(&forced_eligible)
        .arg("--forced-eligible-e2e-out")
        .arg(&forced_eligible_e2e)
        .arg("--status-out")
        .arg(&status)
        .arg("--status-e2e-out")
        .arg(&status_e2e)
        .output()
        .expect("run isolated custom ERC-7730 generation probe");
    assert!(
        output.status.success(),
        "fully isolated custom probe failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for path in [
        &prod_blob,
        &review,
        &e2e_blob,
        &known_calls,
        &known_calls_e2e,
        &forced_eligible,
        &forced_eligible_e2e,
        &status,
        &status_e2e,
    ] {
        assert!(
            std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("stat explicit output {}: {error}", path.display()))
                .len()
                > 0,
            "explicit custom output is empty: {}",
            path.display()
        );
    }
    let review_text = std::fs::read_to_string(&review).expect("read disposable probe review");
    assert!(
        !review_text.contains("# Upstream registry commit:"),
        "custom probe must remain provenance-unstamped"
    );
    assert_checked_in_erc7730_outputs_unchanged(&protected);
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
fn negative_custom_erc7730_probe_refuses_before_any_implicit_output_write() {
    let temp = tempfile::tempdir().expect("create custom generation refusal directory");
    let explicit_blob = temp.path().join("sentinel-prod.bin");
    let sentinel = b"must survive pre-write refusal";
    let protected = checked_in_erc7730_outputs();

    // Keep every fixture nonexistent: if the isolation guard regresses, input
    // loading must still fail before any tracked output can be written.
    for custom_flag in ["--input-dir", "--policy", "--e2e-input-dir"] {
        std::fs::write(&explicit_blob, sentinel).expect("write explicit-output sentinel");
        let custom_path = temp.path().join(custom_flag.trim_start_matches('-'));
        let output = Command::new(bin())
            .arg("gen-erc7730-descriptors")
            .arg(custom_flag)
            .arg(&custom_path)
            .arg("--out-binary")
            .arg(&explicit_blob)
            .output()
            .expect("run under-specified custom ERC-7730 generation probe");
        assert!(
            !output.status.success(),
            "custom probe via {custom_flag} with implicit outputs must refuse"
        );
        let stderr = String::from_utf8(output.stderr).expect("custom-probe stderr utf8");
        assert!(
            stderr.contains("custom ERC-7730 input/policy probes in write mode")
                && stderr.contains("--out-review")
                && stderr.contains("--e2e-out-binary")
                && stderr.contains("--known-calls-out")
                && stderr.contains("--known-calls-e2e-out")
                && stderr.contains("--forced-eligible-out")
                && stderr.contains("--forced-eligible-e2e-out")
                && stderr.contains("--status-out")
                && stderr.contains("--status-e2e-out")
                && !stderr.contains("prod build failed"),
            "unexpected pre-write isolation diagnostic for {custom_flag}: {stderr}"
        );
        assert_eq!(
            std::fs::read(&explicit_blob).expect("read explicit-output sentinel after refusal"),
            sentinel,
            "{custom_flag} guard must run before even an explicit output is written"
        );
    }
    assert_checked_in_erc7730_outputs_unchanged(&protected);
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

#[test]
fn vendor_registry_preserves_dead_only_known_calls_not_just_merkle_leaves() {
    use dbgen::erc7730::build_db_tolerant;

    let workspace = workspace_root();
    let temp = tempfile::tempdir().expect("create vendor test directory");
    let test_root = temp.path();
    let upstream = test_root.join("upstream");
    let output = test_root.join("vendored");
    let registry = upstream.join("registry");
    let live_dir = registry.join("live");
    let dead_dir = registry.join("dead-only");
    let tests_dir = registry.join("tests");
    std::fs::create_dir_all(&live_dir).expect("create live fixture dir");
    std::fs::create_dir_all(&dead_dir).expect("create dead fixture dir");
    std::fs::create_dir_all(&tests_dir).expect("create excluded tests dir");
    std::fs::create_dir_all(upstream.join("ercs")).expect("create ercs dir");

    std::fs::copy(
        workspace.join("secure/data/erc7730-e2e/weth.json"),
        live_dir.join("calldata-live.json"),
    )
    .expect("copy accepted control descriptor");

    // These descriptors are syntactically resolvable but intentionally
    // unrenderable: effectful ABI parameters have no visible fields, so the
    // completeness gate drops the format while the known-call preflight must
    // retain its tuple. A broken include is no longer a valid tolerance
    // witness because include-resolution failure correctly aborts the entire
    // catalogue before compilation.
    let dead_descriptor = |address: &str, signature: &str| {
        format!(
            r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "{address}" }}
  ] }} }},
  "metadata": {{ "owner": "Refused", "contractName": "Refused" }},
  "display": {{ "formats": {{
    "{signature}": {{ "intent": "Refused", "fields": [] }}
  }} }}
}}"#
        )
    };
    std::fs::write(
        dead_dir.join("calldata-dead-only.json"),
        dead_descriptor(
            "0x00000000000000000000000000000000000000d1",
            "deadOnly(address target,uint256 amount)",
        ),
    )
    .expect("write dead-only descriptor");
    std::fs::write(
        live_dir.join("calldata-dead-sibling.json"),
        dead_descriptor(
            "0x00000000000000000000000000000000000000d2",
            "deadSibling(bytes32 value)",
        ),
    )
    .expect("write dead sibling descriptor");
    std::fs::write(
        registry.join("renamed-descriptor.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x00000000000000000000000000000000000000d3" }
  ] } },
  "metadata": { "owner": "Renamed", "contractName": "Renamed" },
  "display": { "formats": {
    "renamed(uint256 value)": { "intent": "Renamed", "fields": [] }
  } }
}"#,
    )
    .expect("write nonstandard-name descriptor");
    std::fs::write(upstream.join("ercs/common.json"), "{}\n").expect("write template");
    std::fs::write(tests_dir.join("ignored.json"), "{}\n").expect("write test fixture");
    std::fs::write(registry.join("ignored.tests.json"), "{}\n")
        .expect("write suffix-excluded fixture");

    let policy = workspace.join("secure/data/erc7730/policy.toml");
    let command = Command::new(bin())
        .args([
            "vendor-registry",
            "--no-curation-overlay",
            "--registry-root",
        ])
        .arg(&upstream)
        .arg("--out")
        .arg(&output)
        .arg("--policy")
        .arg(&policy)
        .output()
        .expect("run vendor-registry");
    assert!(
        command.status.success(),
        "vendor-registry failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&command.stdout),
        String::from_utf8_lossy(&command.stderr),
    );

    for relative in [
        "registry/live/calldata-live.json",
        "registry/dead-only/calldata-dead-only.json",
        "registry/live/calldata-dead-sibling.json",
        "registry/renamed-descriptor.json",
        "ercs/common.json",
    ] {
        assert!(
            output.join(relative).is_file(),
            "security-relevant source was not vendored: {relative}"
        );
    }
    assert!(!output.join("registry/tests/ignored.json").exists());
    assert!(!output.join("registry/ignored.tests.json").exists());
    let stdout = String::from_utf8_lossy(&command.stdout);
    assert!(
        stdout.contains("excluded fixture JSON: 2 files"),
        "excluded fixture inventory was not receipted: {stdout}"
    );

    // The marker is an exact machine-owned sentinel, not a hand-maintained
    // provenance receipt. Stale content must stop a future replacement before
    // either managed directory moves.
    let marker = output.join(".pqsigner-erc7730-vendor");
    std::fs::write(&marker, b"stale hand-maintained receipt\n").unwrap();
    let stale_marker = Command::new(bin())
        .args([
            "vendor-registry",
            "--no-curation-overlay",
            "--registry-root",
        ])
        .arg(&upstream)
        .arg("--out")
        .arg(&output)
        .arg("--policy")
        .arg(&policy)
        .output()
        .expect("rerun vendor-registry with stale marker");
    assert!(!stale_marker.status.success());
    assert!(
        String::from_utf8_lossy(&stale_marker.stderr).contains("vendor marker content mismatch"),
        "unexpected stale-marker diagnostic: {}",
        String::from_utf8_lossy(&stale_marker.stderr)
    );
    std::fs::write(
        &marker,
        b"PQSigner ERC-7730 tool-managed registry/ and ercs/ directories.\n",
    )
    .unwrap();

    let (source, _) = build_db_tolerant(&registry, &policy, Some(&upstream)).expect("source build");
    let (vendored, _) = build_db_tolerant(&output.join("registry"), &policy, Some(&output))
        .expect("vendored build");
    assert_eq!(source.root, vendored.root);
    assert_eq!(source.blob, vendored.blob);
    assert_eq!(source.known_call_count, vendored.known_call_count);
    assert_eq!(source.known_call_set_hash, vendored.known_call_set_hash);
    assert_eq!(source.known_calls_bloom, vendored.known_calls_bloom);
    assert_eq!(source.review_text, vendored.review_text);

    // Non-vacuity: removing the dead-only project leaves every accepted leaf
    // and therefore the Merkle root unchanged, but MUST change the exact
    // known-call receipt. This is the hole a root-only vendoring check missed.
    std::fs::remove_file(output.join("registry/dead-only/calldata-dead-only.json"))
        .expect("remove dead-only fixture from disposable vendored tree");
    let (pruned, _) =
        build_db_tolerant(&output.join("registry"), &policy, Some(&output)).expect("pruned build");
    assert_eq!(source.root, pruned.root, "dead-only source emitted no leaf");
    assert!(pruned.known_call_count < source.known_call_count);
    assert_ne!(source.known_call_set_hash, pruned.known_call_set_hash);
    assert_ne!(source.known_calls_bloom, pruned.known_calls_bloom);
}

#[cfg(unix)]
#[test]
fn vendor_registry_rejects_symlinked_security_corpus_roots_before_build() {
    use std::os::unix::fs::symlink;

    let workspace = workspace_root();
    let temp = tempfile::tempdir().expect("create symlink test directory");
    let test_root = temp.path();
    let upstream = test_root.join("upstream");
    let outside = test_root.join("outside");
    std::fs::create_dir_all(&upstream).unwrap();
    std::fs::create_dir_all(outside.join("registry")).unwrap();
    std::fs::create_dir_all(outside.join("ercs")).unwrap();
    symlink(outside.join("registry"), upstream.join("registry")).unwrap();
    symlink(outside.join("ercs"), upstream.join("ercs")).unwrap();

    let output = Command::new(bin())
        .args([
            "vendor-registry",
            "--no-curation-overlay",
            "--registry-root",
        ])
        .arg(&upstream)
        .arg("--out")
        .arg(test_root.join("vendored"))
        .arg("--policy")
        .arg(workspace.join("secure/data/erc7730/policy.toml"))
        .output()
        .expect("run vendor-registry");
    assert!(!output.status.success(), "symlinked source roots must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("source directory may not be a symlink"),
        "unexpected diagnostic: {stderr}"
    );
}
