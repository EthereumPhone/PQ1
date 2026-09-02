//! Executed negative-compilation tests for the temporary rollback quarantine.
//!
//! Source-string assertions are insufficient for a ship blocker: commented
//! text would satisfy them.  These tests invoke Cargo against the real ARM
//! packages and require each unsafe build shape to fail with its dedicated
//! diagnostic.  They are software-only; no probe, flash, OTP, TAMP, or option
//! byte command is run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DESTRUCTIVE_HARNESS_FEATURES: &[&str] = &[
    "se050-factory-reset",
    "se050-reset-e2e",
    "se050-admin-wipe-e2e",
    "se050-crash-safety-e2e",
    "se050-admin-extract-attempt-e2e",
    "se050-stress",
    "optiga-admin-wipe-e2e",
    "optiga-nuclear-reset",
    "dual-se-admin-wipe-e2e",
    "optiga-hw-counter-e2e",
    "duress-probe-e2e",
    "duress-provision-e2e",
    "pin-gate-e2e",
    "dual-se-multi-unlock-e2e",
];

fn workspace_root() -> PathBuf {
    let mut path = std::env::current_dir().expect("current directory");
    loop {
        let manifest = path.join("Cargo.toml");
        if manifest.exists()
            && std::fs::read_to_string(&manifest)
                .unwrap_or_default()
                .contains("[workspace]")
        {
            return path;
        }
        assert!(path.pop(), "workspace Cargo.toml not found");
    }
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_cargo_rejected(
    workspace: &Path,
    target_dir: &Path,
    package: &str,
    features: &str,
    expected: &str,
) {
    let output = Command::new("cargo")
        .current_dir(workspace)
        .env_remove("FSBL_VENDOR_PUBKEY")
        .env_remove("FSBL_ALLOW_DEV_KEY")
        .args([
            "check",
            "--locked",
            "--release",
            "--target",
            "thumbv8m.main-none-eabi",
            "--target-dir",
        ])
        .arg(target_dir)
        .args([
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo for {package}: {error}"));

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "unsafe build unexpectedly succeeded: package={package}, features={features}"
    );
    assert!(
        text.contains(expected),
        "build failed for the wrong reason: package={package}, features={features}\n\
         expected diagnostic: {expected}\n--- cargo output ---\n{text}"
    );
}

fn assert_host_cargo_rejected(
    workspace: &Path,
    target_dir: &Path,
    package: &str,
    features: &str,
    expected: &str,
) {
    let output = Command::new("cargo")
        .current_dir(workspace)
        .env_remove("FSBL_VENDOR_PUBKEY")
        .env_remove("FSBL_ALLOW_DEV_KEY")
        .args(["check", "--locked", "--release", "--target-dir"])
        .arg(target_dir)
        .args([
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo for {package}: {error}"));

    let text = combined_output(&output);
    assert!(
        !output.status.success(),
        "unsafe host-check build unexpectedly succeeded: package={package}, features={features}"
    );
    assert!(
        text.contains(expected),
        "host-check build failed for the wrong reason: package={package}, features={features}\n\
         expected diagnostic: {expected}\n--- cargo output ---\n{text}"
    );
}

/// Positive-control counterpart of `assert_cargo_rejected`: the build
/// MUST succeed with the given env. Used by the real-key fence row to
/// prove the fence is scoped to the production policy hash and is not a
/// blanket rejection of explicit keys.
fn assert_cargo_builds(
    workspace: &Path,
    target_dir: &Path,
    package: &str,
    features: &str,
    set_env: &[(&str, &str)],
    remove_env: &[&str],
) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace)
        .args([
            "check",
            "--locked",
            "--release",
            "--target",
            "thumbv8m.main-none-eabi",
            "--target-dir",
        ])
        .arg(target_dir)
        .args([
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
        ]);
    for (key, value) in set_env {
        cmd.env(key, value);
    }
    for key in remove_env {
        cmd.env_remove(key);
    }
    let output = cmd
        .output()
        .unwrap_or_else(|error| panic!("failed to run cargo for {package}: {error}"));
    assert!(
        output.status.success(),
        "expected successful build: package={package}, features={features}, env={set_env:?}\n\
         --- cargo output ---\n{}",
        combined_output(&output)
    );
}

#[test]
fn rollback_backend_cannot_enter_production_or_factory_images() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/rollback-ship-fence-tests");

    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "mode-production,legacy-fw-rollback-unsafe",
        "FW_ROLLBACK_FSBL_PRODUCTION_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "lcd-test",
        "FW_ROLLBACK_FSBL_UNSAFE_OPT_IN_REQUIRED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "stm32u585,ui-lcd,se050,mode-production,legacy-fw-rollback-unsafe",
        "FW_ROLLBACK_PRODUCTION_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "factory-provisioning,dev-testkey",
        "FW_ROLLBACK_FACTORY_BLOCKED",
    );
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "stm32u585,ui-lcd,se050",
        "FW_ROLLBACK_UNSAFE_OPT_IN_REQUIRED",
    );
}

#[test]
fn prodtest_cannot_compose_with_persistent_or_irreversible_actions() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/prodtest-persistent-action-fence-tests");
    let expected = "PRODTEST_PERSISTENT_ACTION_FORBIDDEN";

    // The irreversible acknowledgement is deliberately present in the first
    // four cases. It must not turn an acceptance-test image into authority to
    // consume a root, rotate an SE credential, or ratchet lifecycle state.
    // `legacy-fw-rollback-unsafe` only passes this branch's independent
    // rollback quarantine so the prodtest diagnostic itself is exercised.
    for features in [
        "prodtest,dev-testkey,bhk,factory-production-irreversible-im-sure,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,se050-rotate-scp03,factory-production-irreversible-im-sure,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,optiga-lock-operational,factory-production-irreversible-im-sure,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,factory-production-irreversible-im-sure,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,rdp-enforce-halt,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,saes-dhuk,tamp-wipe,legacy-fw-rollback-unsafe",
        "prodtest,dev-testkey,saes-dhuk,tzic-wipe,legacy-fw-rollback-unsafe",
        // With neither dev-testkey nor otp-hardcoded-master-key, prodtest
        // would enter the real per-device OTP-master path.
        "prodtest,legacy-fw-rollback-unsafe",
    ] {
        assert_cargo_rejected(
            &workspace,
            &target_dir,
            "sphincs-tz-secure",
            features,
            expected,
        );
    }

    // The factory-provisioning combination is stopped even earlier by the
    // build script's rollback quarantine. It remains listed in the central
    // prodtest fence as defence in depth for the day that quarantine changes.
    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "prodtest,dev-testkey,factory-provisioning,factory-production-irreversible-im-sure,legacy-fw-rollback-unsafe",
        "FW_ROLLBACK_FACTORY_BLOCKED",
    );
}

#[test]
fn production_feature_policy_rejects_all_factory_and_prodtest_aliases() {
    let workspace = workspace_root();

    // Mutation guard for Makefile::PROD_FORBIDDEN. Testing one feature at a
    // time ensures removing any alias changes the failure from the dedicated
    // never-ship diagnosis to an unrelated missing-required-feature result.
    for feature in [
        "prodtest",
        "factory-provisioning",
        "factory-provisioning-rehearsal",
        "factory-production-irreversible-im-sure",
    ]
    .into_iter()
    .chain(DESTRUCTIVE_HARNESS_FEATURES.iter().copied())
    {
        let output = Command::new("make")
            .current_dir(&workspace)
            .arg("prod-feature-check")
            .arg(format!("RELEASE_FEATURES={feature}"))
            .output()
            .unwrap_or_else(|error| panic!("run prod-feature-check for {feature}: {error}"));
        let text = combined_output(&output);
        assert!(
            !output.status.success(),
            "never-ship feature unexpectedly passed production policy: {feature}"
        );
        assert!(
            text.contains("never-ship feature(s)") && text.contains(feature),
            "production policy rejected {feature} for the wrong reason:\n{text}"
        );
    }

    // GNU Make normally gives command-line assignments precedence over
    // Makefile assignments.  The policy sets are security constants, not
    // caller-tunable inputs: an empty override must not erase either half of
    // the production envelope.
    let canonical_plus_prodtest = concat!(
        "stm32u585,se050,optiga-trust-m,dual-se,ui-lcd,usb,iwdg,",
        "saes-dhuk,se050-derived-scp03,mode-production,",
        "optiga-lock-operational,optiga-hw-counter,consumption-mask,",
        "tamp,tamp-wipe,tzic-wipe,prodtest"
    );
    let output = Command::new("make")
        .current_dir(&workspace)
        .arg("prod-feature-check")
        .arg(format!("RELEASE_FEATURES={canonical_plus_prodtest}"))
        .arg("PROD_FORBIDDEN=")
        .output()
        .expect("run prod-feature-check with forbidden-set override");
    let text = combined_output(&output);
    assert!(
        !output.status.success()
            && text.contains("never-ship feature(s)")
            && text.contains("prodtest"),
        "command-line assignment erased PROD_FORBIDDEN:\n{text}"
    );

    let output = Command::new("make")
        .current_dir(&workspace)
        .arg("prod-feature-check")
        .arg("RELEASE_FEATURES=mode-production")
        .arg("PROD_REQUIRED=")
        .output()
        .expect("run prod-feature-check with required-set override");
    let text = combined_output(&output);
    assert!(
        !output.status.success()
            && text.contains("MISSING required hardening feature(s)")
            && text.contains("saes-dhuk"),
        "command-line assignment erased PROD_REQUIRED:\n{text}"
    );

    // The reversible fixture target likewise owns its exact paired feature
    // profiles.  A dry run proves command-line assignments cannot substitute
    // a different secure or nonsecure image while retaining the target name.
    let output = Command::new("make")
        .current_dir(&workspace)
        .args([
            "--no-print-directory",
            "-n",
            "build-hw-prodtest",
            "PRODTEST_SECURE_FEATURES=prodtest,bhk",
            "PRODTEST_NONSECURE_FEATURES=usb",
        ])
        .output()
        .expect("dry-run build-hw-prodtest with profile overrides");
    let text = combined_output(&output);
    assert!(output.status.success(), "prodtest dry run failed:\n{text}");
    assert!(
        text.contains("--features prodtest,dev-testkey,saes-dhuk")
            && text.contains("--features stm32u585,usb,prodtest")
            && !text.contains("--features prodtest,bhk"),
        "command-line assignment changed the exact prodtest profiles:\n{text}"
    );
}

#[test]
fn mode_production_rejects_every_destructive_harness_via_direct_cargo() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/production-destructive-harness-fences");
    for feature in DESTRUCTIVE_HARNESS_FEATURES {
        assert_cargo_rejected(
            &workspace,
            &target_dir,
            "sphincs-tz-secure",
            &format!("mode-production,ui-semihosting,{feature},legacy-fw-rollback-unsafe"),
            "PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN",
        );
    }
}

#[test]
fn retired_optiga_reset_oids_cannot_build_in_any_profile() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/retired-optiga-reset-oids-fence-tests");

    for features in [
        "optiga-reset-oids,dev-testkey,ui-noop,legacy-fw-rollback-unsafe",
        "optiga-reset-oids,e2e-test,dev-testkey,ui-noop,legacy-fw-rollback-unsafe",
        "optiga-reset-oids,factory-production-irreversible-im-sure,ui-noop,legacy-fw-rollback-unsafe",
    ] {
        assert_cargo_rejected(
            &workspace,
            &target_dir,
            "sphincs-tz-secure",
            features,
            "OPTIGA_RESET_OIDS_RETIRED",
        );
    }
}

#[test]
fn optiga_ta_pool_lockdown_cannot_build_before_codec_validation() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/optiga-ta-lockdown-fence-tests");

    assert_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "stm32u585,ui-lcd,optiga-trust-m,dev-testkey,optiga-lock-operational,factory-production-irreversible-im-sure",
        "OPTIGA_TA_POOL_LOCKDOWN_BLOCKED",
    );
}

#[test]
fn production_optiga_cannot_build_while_s2_is_open() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/optiga-s2-production-fence-tests");

    // Use a host check so the independent rollback build-script quarantine
    // cannot preempt rustc before this source-level production fence fires.
    assert_host_cargo_rejected(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        "ui-noop,optiga-trust-m,optiga-hw-counter,optiga-lock-operational,mode-production",
        "OPTIGA_S2_PRODUCTION_BLOCKED",
    );
}

#[test]
fn advertised_ship_and_irreversible_factory_gates_fail_loudly() {
    let workspace = workspace_root();

    let ship = Command::new("make")
        .current_dir(&workspace)
        .arg("prod-check-ship")
        .output()
        .expect("run prod-check-ship");
    let ship_text = combined_output(&ship);
    assert!(
        !ship.status.success(),
        "prod-check-ship must remain blocked"
    );
    assert!(
        ship_text.contains("prod-feature-check: PASS")
            && ship_text.contains("reviewed production rollback backend is not implemented"),
        "prod-check-ship failed for the wrong reason:\n{ship_text}"
    );

    let overridden_ship = Command::new("make")
        .current_dir(&workspace)
        .args(["prod-check-ship", "RELEASE_FEATURES=mode-production"])
        .output()
        .expect("run prod-check-ship with a command-line RELEASE_FEATURES override");
    let overridden_ship_text = combined_output(&overridden_ship);
    assert!(
        !overridden_ship.status.success(),
        "prod-check-ship must remain blocked when RELEASE_FEATURES is supplied"
    );
    assert!(
        overridden_ship_text.contains("prod-feature-check: PASS")
            && overridden_ship_text
                .contains("reviewed production rollback backend is not implemented"),
        "prod-check-ship did not retain its canonical feature envelope:\n{overridden_ship_text}"
    );

    let ignored_ship = Command::new("make")
        .current_dir(&workspace)
        .args(["-n", "-i", "prod-check-ship"])
        .output()
        .expect("run prod-check-ship with make -i");
    let ignored_ship_text = combined_output(&ignored_ship);
    assert!(
        !ignored_ship.status.success(),
        "prod-check-ship must not become false-green under make -i"
    );
    assert!(
        ignored_ship_text.contains("reviewed production rollback backend is not implemented"),
        "prod-check-ship -i failed for the wrong reason:\n{ignored_ship_text}"
    );

    let release = Command::new("make")
        .current_dir(&workspace)
        .args(["-n", "release"])
        .output()
        .expect("run release refusal");
    let release_text = combined_output(&release);
    assert!(!release.status.success(), "release must remain blocked");
    assert!(
        release_text.contains("production firmware rollback backend is not implemented")
            && release_text.contains("Existing release artifacts were not removed or modified"),
        "release failed for the wrong reason:\n{release_text}"
    );

    // GNU make's `-i` ignores ordinary failing shell recipes. Every blocked
    // entry point therefore uses make-time `$(error ...)`, which must remain
    // fatal even under `-i`. `-n` guarantees this regression test can never
    // execute a probe, flash, OTP, or option-byte command if a guard regresses.
    for (target, expected) in [
        ("release", "production firmware rollback backend"),
        ("_release", "production packaging is quarantined"),
        ("fsbl-release", "production firmware rollback backend"),
        (
            "build-hw-factory-provisioning",
            "factory provisioning is quarantined",
        ),
        ("flash-hw-factory-provisioning", "flash path is quarantined"),
        (
            "build-hw-factory-provisioning-rehearsal",
            "factory rehearsal is quarantined",
        ),
        (
            "flash-hw-factory-provisioning-rehearsal",
            "factory rehearsal flash path is quarantined",
        ),
        ("bump-rdp2-after-factory", "RDP2 authority is disabled"),
    ] {
        let guarded = Command::new("make")
            .current_dir(&workspace)
            .args(["-n", "-i", target])
            .output()
            .unwrap_or_else(|error| panic!("run guarded target {target}: {error}"));
        let guarded_text = combined_output(&guarded);
        assert!(
            !guarded.status.success(),
            "{target} must not become false-green under make -i"
        );
        assert!(
            guarded_text.contains(expected),
            "{target} failed for the wrong reason:\n{guarded_text}"
        );
    }

    // A same-named file must not suppress a quarantine recipe. Exercise the
    // `.PHONY` contract from an isolated directory, still under `-n` so this
    // test cannot run hardware commands even if the target regresses.
    let phony_dir = workspace
        .join("target/rollback-ship-fence-tests")
        .join(format!("phony-{}", std::process::id()));
    std::fs::create_dir_all(&phony_dir).expect("create isolated make directory");
    let shadow = phony_dir.join("bump-rdp2-after-factory");
    std::fs::write(&shadow, b"must not suppress the make-time refusal")
        .expect("write same-named target file");
    let phony = Command::new("make")
        .current_dir(&phony_dir)
        .arg("-n")
        .arg("-i")
        .arg("-f")
        .arg(workspace.join("Makefile"))
        .arg("bump-rdp2-after-factory")
        .output()
        .expect("run phony quarantine target");
    let phony_text = combined_output(&phony);
    assert!(
        !phony.status.success() && phony_text.contains("RDP2 authority is disabled"),
        "same-named file suppressed the RDP2 refusal:\n{phony_text}"
    );
    std::fs::remove_file(&shadow).expect("remove isolated target file");
    std::fs::remove_dir(&phony_dir).expect("remove isolated make directory");

    let rdp2 = Command::new("/bin/bash")
        .current_dir(&workspace)
        .env("PATH", "/nonexistent")
        .args(["tools/factory-provisioning-verify.sh", "--bump-rdp2"])
        .output()
        .expect("run factory verifier refusal");
    let rdp2_text = combined_output(&rdp2);
    assert!(!rdp2.status.success(), "--bump-rdp2 must remain disabled");
    assert!(
        rdp2_text.contains("factory OTP receipt is quarantined"),
        "factory verifier failed for the wrong reason:\n{rdp2_text}"
    );

    for value in ["0xfffffffa", "0xfffffff8"] {
        let decode = Command::new("/bin/bash")
            .current_dir(&workspace)
            .env("PATH", "/nonexistent")
            .args([
                "tools/factory-provisioning-verify.sh",
                "--decode-legacy-sentinel",
                value,
            ])
            .output()
            .unwrap_or_else(|error| panic!("decode legacy sentinel {value}: {error}"));
        let decode_text = combined_output(&decode);
        assert!(
            !decode.status.success(),
            "legacy sentinel {value} must never grant RDP2 authority"
        );
        assert!(
            decode_text.contains("NOT RDP2 AUTHORITY"),
            "legacy sentinel {value} was not labeled non-authoritative:\n{decode_text}"
        );
    }
}

/// The secure-world bench feature profile used by the real-key fence
/// row: `make build-hw-se050-oled-standalone`'s exact set plus the two
/// standing ship-blocker feature requirements (`consumption-mask`,
/// `se050-derived-scp03`) and the current dev-unattested ERC-7730
/// catalogue marker. It compiles the full secure image, so a successful
/// check proves the real-key fence does not over-reach.
///
/// `board-iota2` is REQUIRED, not decorative: since a15561b4 every `stm32u585`
/// build must name its board (`secure/src/board/mod.rs`). This is the only
/// fixture here that expects a SUCCESSFUL build, so it is the only one the
/// board rule can break — the rejection fixtures below are unaffected because
/// their `build.rs` fences fire before the board `compile_error!` is reached.
/// Missed by the 2026-08-31 sweep, which covered Makefile targets and CI
/// workflows but not test code that shells out to cargo with its own feature
/// list.
const SECURE_BENCH_FEATURES: &str = concat!(
    "se050,gpio-buttons,ui-lcd,stm32u585,usb,legacy-fw-rollback-unsafe,",
    "erc7730-dev-unattested,consumption-mask,se050-derived-scp03,board-iota2"
);

#[test]
fn real_vendor_key_cannot_compose_with_legacy_backend_outside_production() {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/real-key-fence-tests");

    // Source pins: the fence exists in BOTH build scripts, wired AFTER the
    // all-zero placeholder check, and names the #541 measurement-profile
    // carve-out. In fsbl/build.rs it must also be wired AFTER the
    // dev-fixture branch — the compare covers the RESOLVED embedded key
    // from EITHER key path (wave-2 MEDIUM: the dev-fixture path previously
    // embedded the key with no compare).
    for build_rs in ["fsbl/build.rs", "secure/build.rs"] {
        let src =
            std::fs::read_to_string(workspace.join(build_rs)).expect("read build script");
        let zero_pos = src
            .find("all-zero FSBL_VENDOR_PUBKEY")
            .expect("build script must reject the all-zero placeholder");
        let fence_pos = src
            .find("FW_ROLLBACK_REAL_KEY_BLOCKED:")
            .expect("build script must carry the real-key fence");
        assert!(
            zero_pos < fence_pos,
            "{build_rs}: FW_ROLLBACK_REAL_KEY_BLOCKED must be wired after the all-zero \
             check in the explicit FSBL_VENDOR_PUBKEY path"
        );
        assert!(
            src.contains("PQ_ROLLBACK_MEASUREMENT_PROFILE"),
            "{build_rs}: the #541 measurement-profile carve-out must be named at the fence"
        );
    }
    let fsbl_src = std::fs::read_to_string(workspace.join("fsbl/build.rs"))
        .expect("read fsbl build script");
    let dev_branch_pos = fsbl_src
        .find("public development fixture")
        .expect("fsbl must keep the dev-fixture branch");
    let fsbl_fence_pos = fsbl_src
        .find("reject_real_key_with_legacy_backend(&bytes")
        .expect("fsbl must compare the RESOLVED embedded key");
    assert!(
        dev_branch_pos < fsbl_fence_pos,
        "fsbl/build.rs: the real-key compare must run after BOTH key paths resolve"
    );

    // HONEST SCOPE NOTE: the blocking branch fires only when the explicit
    // key's SHA-256 equals the reviewed production policy hash. The real
    // production credential is deliberately NOT in-tree (the policy hash
    // is in-tree; the key is not — and today the policy file is
    // intentionally UNPROVISIONED, config/README.md), so the negative
    // branch cannot be executed without the credential. The executed
    // controls below prove the fence is SCOPED, not a blanket rejection
    // of explicit keys.

    // Positive control: an explicit, nonzero 32-byte fixture key that is
    // neither the in-tree development key nor the production key still
    // builds with `legacy-fw-rollback-unsafe` in both crates.
    let fixture = [0xA5u8; 32];
    std::fs::create_dir_all(&target_dir).expect("create fixture dir");
    let fixture_path = target_dir.join("nonproduction-fixture-vendor-pubkey.bin");
    std::fs::write(&fixture_path, fixture).expect("write fixture key");
    let fixture_str = fixture_path.to_string_lossy().into_owned();
    // Two-sided fixture hygiene: prove the fixture really is neither
    // credential. Raw-byte compare against the dev key file (hex text);
    // the fixture's SHA-256 (precomputed — the fixture is deterministic)
    // against the policy file, which stays a valid inequality both while
    // the policy is UNPROVISIONED and once it is provisioned.
    let dev_hex = std::fs::read_to_string(
        workspace.join("config/development-firmware-vendor-pubkey.hex"),
    )
    .expect("read development key");
    assert_ne!(
        dev_hex.trim(),
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "fixture must not be the development key"
    );
    let policy = std::fs::read_to_string(
        workspace.join("config/production-firmware-vendor-key.sha256"),
    )
    .expect("read production key policy");
    assert_ne!(
        policy.trim(),
        "fc8b64001c5fdd0f2f40fb67dae4a865a2c5bd17836676d6d5b58b7917e33717",
        "fixture SHA-256 must not equal the production policy hash"
    );
    assert_cargo_builds(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "legacy-fw-rollback-unsafe",
        &[("FSBL_VENDOR_PUBKEY", fixture_str.as_str())],
        &["FSBL_ALLOW_DEV_KEY"],
    );
    assert_cargo_builds(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        SECURE_BENCH_FEATURES,
        &[("FSBL_VENDOR_PUBKEY", fixture_str.as_str())],
        &["FSBL_ALLOW_DEV_KEY"],
    );

    // Dev-fixture-key path: unchanged. The FSBL embeds the in-tree dev
    // key under the explicit FSBL_ALLOW_DEV_KEY opt-in; the secure world
    // embeds its bench placeholder with FSBL_VENDOR_PUBKEY unset. Neither
    // touches the real-key fence.
    assert_cargo_builds(
        &workspace,
        &target_dir,
        "pqsigner-fsbl",
        "legacy-fw-rollback-unsafe",
        &[("FSBL_ALLOW_DEV_KEY", "1")],
        &["FSBL_VENDOR_PUBKEY"],
    );
    assert_cargo_builds(
        &workspace,
        &target_dir,
        "sphincs-tz-secure",
        SECURE_BENCH_FEATURES,
        &[],
        &["FSBL_VENDOR_PUBKEY", "FSBL_ALLOW_DEV_KEY"],
    );
}
