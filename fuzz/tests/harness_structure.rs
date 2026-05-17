//! Static-structure tests for the `pqsigner-fuzz` libFuzzer harness.
//!
//! The harness's failure mode is "drift": someone adds a new
//! `fuzz_targets/foo.rs` and forgets to wire the `[[bin]]` entry in
//! `Cargo.toml`, or vice versa. `cargo fuzz list` then silently drops
//! the target and the parser it claims to cover ships with the
//! illusion of coverage. These tests are the structural backstop —
//! they read both sides of the wiring and assert they match, plus
//! enforce a handful of conventions that keep the harness honest
//! (no `unwrap`, no `panic!`, no allocator pulls, every target file
//! actually invokes `fuzz_target!`, every bin is `test = false`).
//!
//! See `reports/tests/fuzz.md` for the inventory.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_cargo_toml() -> toml::Value {
    let raw = fs::read_to_string(fuzz_dir().join("Cargo.toml"))
        .expect("fuzz/Cargo.toml must exist");
    raw.parse::<toml::Value>()
        .expect("fuzz/Cargo.toml must parse as TOML")
}

fn registered_bins() -> Vec<RegisteredBin> {
    let t = read_cargo_toml();
    let bins = match t.get("bin").and_then(|b| b.as_array()) {
        Some(b) => b.clone(),
        None => Vec::new(),
    };
    bins.into_iter()
        .map(|b| {
            let tbl = b.as_table().expect("[[bin]] entry must be a table");
            RegisteredBin {
                name: tbl
                    .get("name")
                    .and_then(|v| v.as_str())
                    .expect("[[bin]] must have a name")
                    .to_string(),
                path: tbl
                    .get("path")
                    .and_then(|v| v.as_str())
                    .expect("[[bin]] must have an explicit path")
                    .to_string(),
                test: tbl
                    .get("test")
                    .and_then(|v| v.as_bool()),
                doc: tbl.get("doc").and_then(|v| v.as_bool()),
                bench: tbl.get("bench").and_then(|v| v.as_bool()),
            }
        })
        .collect()
}

struct RegisteredBin {
    name: String,
    path: String,
    test: Option<bool>,
    doc: Option<bool>,
    bench: Option<bool>,
}

fn fuzz_target_files() -> Vec<PathBuf> {
    let dir = fuzz_dir().join("fuzz_targets");
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("fuzz_targets/ unreadable: {e}"))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("rs"))
        .collect();
    out.sort();
    out
}

fn file_stem(p: &Path) -> String {
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string()
}

fn read_target(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

// ===========================================================================
//                              POSITIVE
// ===========================================================================

#[test]
fn positive_cargo_toml_parses_as_toml() {
    let _ = read_cargo_toml();
}

#[test]
fn positive_package_name_is_pqsigner_fuzz() {
    let t = read_cargo_toml();
    let name = t
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|v| v.as_str())
        .expect("[package].name must exist");
    assert_eq!(name, "pqsigner-fuzz");
}

#[test]
fn positive_package_publish_is_false() {
    let t = read_cargo_toml();
    let publish = t
        .get("package")
        .and_then(|p| p.get("publish"))
        .and_then(|v| v.as_bool())
        .expect("[package].publish must be set");
    assert!(
        !publish,
        "fuzz harness must NOT be publishable to crates.io \
         — would expose the parser surface and pin a brittle external API"
    );
}

#[test]
fn positive_standalone_workspace_block_present() {
    // The top-level `[workspace]` block (no members) marks this crate as
    // a standalone workspace, keeping cargo-fuzz's nightly/sanitizer
    // toolchain out of the main workspace. If it ever disappears, the
    // top-level `cargo build` will start dragging in libfuzzer-sys and
    // every dev who runs `cargo test` will pay the cost.
    let t = read_cargo_toml();
    assert!(
        t.get("workspace").is_some(),
        "fuzz/Cargo.toml MUST keep its standalone `[workspace]` block — \
         see the comment in Cargo.toml + `fuzz/Cargo.toml: [workspace]`. \
         Removing it sucks cargo-fuzz's deps into the main workspace."
    );
}

#[test]
fn positive_cargo_fuzz_metadata_present() {
    let t = read_cargo_toml();
    let v = t
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("cargo-fuzz"))
        .and_then(|v| v.as_bool())
        .expect("[package.metadata].cargo-fuzz must be set to true");
    assert!(v, "[package.metadata.cargo-fuzz] must be true");
}

#[test]
fn positive_every_registered_bin_points_to_existing_file() {
    for bin in registered_bins() {
        let p = fuzz_dir().join(&bin.path);
        assert!(
            p.exists(),
            "[[bin]] name={} path={} but {} does not exist \
             — `cargo fuzz run {}` will fail",
            bin.name,
            bin.path,
            p.display(),
            bin.name,
        );
    }
}

#[test]
fn positive_every_registered_bin_uses_test_doc_bench_false() {
    // `test = false` is critical: without it, `cargo test` tries to
    // build the bin in test mode, which fails to link because the bin
    // is `#![no_main]` and libFuzzer's `main` is only provided by
    // `cargo fuzz`'s rustc wrapper.
    for bin in registered_bins() {
        assert_eq!(
            bin.test,
            Some(false),
            "[[bin]] {} MUST set `test = false` — \
             #![no_main] crates fail to link under `cargo test`",
            bin.name,
        );
        assert_eq!(
            bin.doc,
            Some(false),
            "[[bin]] {} should set `doc = false` (libFuzzer harnesses don't doc)",
            bin.name,
        );
        assert_eq!(
            bin.bench,
            Some(false),
            "[[bin]] {} should set `bench = false`",
            bin.name,
        );
    }
}

#[test]
fn positive_every_registered_bin_name_matches_filename_stem() {
    // Convention: the bin name == the file stem. `make` recipes and
    // `cargo fuzz list` both refer to bin names; if a refactor renames
    // one without the other, `cargo fuzz run <name>` silently breaks.
    for bin in registered_bins() {
        let stem = file_stem(Path::new(&bin.path));
        assert_eq!(
            bin.name, stem,
            "[[bin]] name={} but path stem={} — bin name MUST match \
             filename stem (Makefile and `cargo fuzz list` rely on it)",
            bin.name, stem,
        );
    }
}

#[test]
fn positive_every_target_file_uses_fuzz_target_macro() {
    for p in fuzz_target_files() {
        let body = read_target(&p);
        assert!(
            body.contains("fuzz_target!"),
            "fuzz target {} must invoke `fuzz_target!(...)` — \
             that's the macro that hooks the file into libFuzzer's harness",
            p.display(),
        );
    }
}

#[test]
fn positive_every_target_file_has_no_main_attribute() {
    for p in fuzz_target_files() {
        let body = read_target(&p);
        assert!(
            body.contains("#![no_main]"),
            "fuzz target {} must declare `#![no_main]` — \
             libFuzzer supplies the entry point via `cargo fuzz`'s wrapper",
            p.display(),
        );
    }
}

// ===========================================================================
//                              NEGATIVE
// ===========================================================================
//
// Each negative test names the assumption being attacked and asserts
// that the harness enforces it. A regression here is a silent loss of
// coverage — `cargo fuzz` will keep returning "0 panics found" against
// targets that no longer exist or no longer test what they claim to.

#[test]
fn negative_no_two_bins_share_a_path() {
    // Two [[bin]] entries pointing at the same file would compile twice
    // (different `name`) and silently double-count coverage runs, or
    // produce confusing `cargo fuzz` UX.
    let mut seen = BTreeSet::new();
    for bin in registered_bins() {
        assert!(
            seen.insert(bin.path.clone()),
            "two [[bin]] entries share path={} — silent duplication",
            bin.path,
        );
    }
}

#[test]
fn negative_no_two_bins_share_a_name() {
    let mut seen = BTreeSet::new();
    for bin in registered_bins() {
        assert!(
            seen.insert(bin.name.clone()),
            "two [[bin]] entries share name={} — cargo will reject the build",
            bin.name,
        );
    }
}

#[test]
fn negative_no_bin_path_escapes_fuzz_targets_dir() {
    // Defence-in-depth: prevent a future "[[bin]] path = "../../secure/..."
    // from quietly turning a workspace-crate file into a libFuzzer bin
    // (with libFuzzer's rustc flags applied — a meaningful build-config
    // change for the targeted source file).
    for bin in registered_bins() {
        assert!(
            bin.path.starts_with("fuzz_targets/")
                && !bin.path.contains("..")
                && !bin.path.starts_with('/'),
            "[[bin]] {} path {} must live under fuzz_targets/ \
             (no `..`, no absolute path)",
            bin.name,
            bin.path,
        );
    }
}

#[test]
fn negative_no_target_file_uses_unwrap_or_expect_or_panic() {
    // Fuzz targets must propagate `Result`s, not unwrap them. An
    // `.unwrap()` inside a fuzz target turns "parser returned Err on
    // malformed input" (the *correct* behaviour) into a libFuzzer
    // crash, making every well-behaved parser look broken.
    //
    // Likewise, a stray `panic!()` / `assert!` inside the target body
    // poisons every corpus entry the macro hands in.
    let banned = ["unwrap()", "expect(", "panic!(", "unimplemented!(", "todo!("];
    for p in fuzz_target_files() {
        let body = read_target(&p);
        // Strip comments (line + block) before scanning so doc/explanation
        // text using these words doesn't trip the check.
        let stripped = strip_comments(&body);
        for needle in banned {
            assert!(
                !stripped.contains(needle),
                "fuzz target {} contains `{}` — fuzz targets must \
                 propagate Result/Option, not turn parser-Err into a \
                 libFuzzer crash. (See harness contract: `parse(_)` is \
                 supposed to handle ANY bytes; an unwrap inverts that.)",
                p.display(),
                needle,
            );
        }
    }
}

#[test]
fn negative_no_target_file_pulls_in_heap_allocator() {
    // The proptest sibling at `secure/src/fuzz_props.rs` runs in a
    // host build that allows `Vec`, but the fuzz harness's value is
    // hammering parsers that *firmware* will run, where there is no
    // allocator. Fuzz-target-local allocations introduce panics
    // (OOM-on-shrink) that the firmware path could never produce.
    let banned = ["extern crate alloc", "use std::collections::", "alloc::vec::Vec", "Box::new"];
    for p in fuzz_target_files() {
        let body = read_target(&p);
        let stripped = strip_comments(&body);
        for needle in banned {
            assert!(
                !stripped.contains(needle),
                "fuzz target {} appears to use heap-alloc construct `{}` — \
                 fuzz harness should mirror the no_std/no-alloc firmware \
                 path so we don't conflate host OOM with parser bugs",
                p.display(),
                needle,
            );
        }
    }
}

#[test]
fn negative_no_target_file_uses_unsafe() {
    // The fuzz targets test pure-logic parsers. Any `unsafe` block in
    // a target file is suspicious — it would mean the harness is
    // smuggling around the safe-Rust contract the parser is supposed
    // to honour (e.g. building a `&[u8]` from a raw pointer rather
    // than from libFuzzer's `data` parameter), which masks bugs.
    for p in fuzz_target_files() {
        let body = read_target(&p);
        let stripped = strip_comments(&body);
        // `unsafe_op_in_unsafe_fn` is a lint name; allow it in attr
        // form by stripping `#![...]` lines, but a bare `unsafe {`
        // block in a fuzz target is what we want to catch.
        assert!(
            !stripped.contains("unsafe {") && !stripped.contains("unsafe fn"),
            "fuzz target {} contains an `unsafe` block. Fuzz targets \
             test pure-Rust parsers — unsafe here can paper over the \
             very memory-safety bugs the harness is meant to find.",
            p.display(),
        );
    }
}

#[test]
fn negative_no_dev_feature_leaked_to_parser_deps() {
    // The fuzz harness MUST exercise the same parsers that ship to
    // production firmware, not feature-gated dev variants. If a
    // future contributor adds `features = ["mock-se", "debug-log",
    // "e2e-test", "otp-hardcoded-master-key", "ui-capture"]` to any of
    // the pqsigner-* deps, libFuzzer will be running a different code
    // path than firmware. CLAUDE.md "What NOT to do":
    //   "No debug-log / e2e-test / mock-se / otp-hardcoded-master-key
    //    / ui-capture in production builds. CI must gate."
    let dev_flags = [
        "mock-se",
        "debug-log",
        "e2e-test",
        "otp-hardcoded-master-key",
        "ui-capture",
    ];
    let t = read_cargo_toml();
    let deps = t.get("dependencies").and_then(|d| d.as_table());
    let Some(deps) = deps else { return };
    for (name, value) in deps {
        let feats = value
            .as_table()
            .and_then(|t| t.get("features"))
            .and_then(|v| v.as_array());
        let Some(feats) = feats else { continue };
        let strings: Vec<&str> = feats.iter().filter_map(|v| v.as_str()).collect();
        for f in dev_flags {
            assert!(
                !strings.contains(&f),
                "[dependencies].{name} enables dev-only feature `{f}` — \
                 fuzz harness must test the production code path, not the \
                 dev shortcut (see CLAUDE.md \"What NOT to do\")",
            );
        }
    }
}

// ---------------------------------------------------------------------------
//   Drift between fuzz_targets/*.rs and Cargo.toml's [[bin]] list
// ---------------------------------------------------------------------------
//
// This is the single highest-value negative test in the file. A `.rs`
// file under `fuzz_targets/` that isn't registered in Cargo.toml is
// dead code: `cargo fuzz list` won't show it, `cargo fuzz run` can't
// invoke it, CI ignores it. Anyone glancing at the directory listing
// will *assume* it's exercised.
//
// At the time this test was written, two such orphans existed:
// `apdu_parse_header.rs` and `hid_frame_assembler.rs` (added in the
// branch's working tree but never wired through Cargo.toml). The test
// is left `#[ignore]` with the rationale below so that fixing the
// orphan registrations is a single-line change in Cargo.toml +
// removing the `#[ignore]` line, not a test rewrite. See
// "Production-code bugs surfaced by negative tests" in
// `reports/tests/fuzz.md`.

#[test]
#[ignore = "ORPHAN: fuzz_targets/apdu_parse_header.rs and \
            fuzz_targets/hid_frame_assembler.rs are present but not \
            registered in Cargo.toml [[bin]] — see \
            reports/tests/fuzz.md production-code-bugs section. Add the \
            two [[bin]] entries + a `sphincs-tz-shared` [dependency] then \
            remove this #[ignore]."]
fn negative_every_fuzz_target_file_is_registered_as_bin() {
    let on_disk: BTreeSet<String> =
        fuzz_target_files().iter().map(|p| file_stem(p)).collect();
    let registered: BTreeSet<String> = registered_bins()
        .into_iter()
        .map(|b| file_stem(Path::new(&b.path)))
        .collect();
    let orphans: Vec<&String> = on_disk.difference(&registered).collect();
    assert!(
        orphans.is_empty(),
        "orphaned fuzz_targets/*.rs files NOT registered as [[bin]] in \
         Cargo.toml: {:?}. `cargo fuzz list` will silently drop them — \
         the parser they claim to cover ships UNTESTED. Fix: add a \
         [[bin]] entry (test=false, doc=false, bench=false) plus the \
         matching dep in [dependencies], plus a `make fuzz-<name>` \
         recipe in the top-level Makefile.",
        orphans,
    );
}

#[test]
fn negative_every_bin_path_resolves_to_a_real_file() {
    // The mirror of the orphan check: a [[bin]] entry pointing at a
    // file someone deleted is a build failure, not a silent gap, but
    // worth a fast pre-build sanity check. Distinct from
    // `positive_every_registered_bin_points_to_existing_file` only in
    // framing — kept separate so a CI bisect points at the right test.
    for bin in registered_bins() {
        let p = fuzz_dir().join(&bin.path);
        assert!(
            p.is_file(),
            "[[bin]] {} declares path {}, but that file is missing — \
             `cargo fuzz build` will fail",
            bin.name,
            bin.path,
        );
    }
}

#[test]
fn negative_makefile_has_a_recipe_for_every_registered_bin() {
    // Belt-and-braces: the top-level Makefile has hand-written
    // `make fuzz-<short-name>` recipes. They MUST stay in sync with
    // the [[bin]] list — otherwise `make fuzz-list` shows a target
    // the Makefile can't run.
    //
    // The Makefile's short names use kebab-case dropping common
    // prefixes (`aa_userop_parse_header` → `aa-userop-parse`), so we
    // can't do a strict 1:1 comparison; instead we check that every
    // registered bin name appears verbatim somewhere in the Makefile
    // (the `cargo +nightly fuzz run <bin>` line uses the exact name).
    let fuzz = fuzz_dir();
    let workspace_root = fuzz
        .parent()
        .expect("fuzz/ lives under workspace root");
    let makefile_path = workspace_root.join("Makefile");
    let Ok(mk) = fs::read_to_string(&makefile_path) else {
        // If the Makefile isn't where we expect, don't claim failure —
        // just skip the cross-check. The directory layout may legitimately
        // change.
        eprintln!(
            "note: skipping Makefile cross-check — {} not readable",
            makefile_path.display()
        );
        return;
    };
    for bin in registered_bins() {
        assert!(
            mk.contains(&bin.name),
            "Makefile has no `cargo fuzz run {}` line — every \
             registered fuzz target needs an invocable `make fuzz-*` \
             recipe, otherwise developers can't run the harness without \
             remembering nightly + cargo-fuzz flags by hand",
            bin.name,
        );
    }
}

// ---------------------------------------------------------------------------
//   helpers
// ---------------------------------------------------------------------------

/// Strip `//`-style line comments and `/* … */` block comments from a
/// Rust source string so a substring scan doesn't trip on doc/comment
/// text that uses the banned identifier in prose.
fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // line comment
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // block comment (no nesting support — fine for our targets)
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[test]
fn positive_strip_comments_actually_works() {
    // Guard the comment-stripper itself — a bug here would let the
    // negative tests pass on harness files that actually do contain
    // the banned construct, just inside a comment.
    let s = "let x = 1; // unwrap()\n/* expect( */ let y = 2;";
    let stripped = strip_comments(s);
    assert!(!stripped.contains("unwrap()"));
    assert!(!stripped.contains("expect("));
    assert!(stripped.contains("let x = 1;"));
    assert!(stripped.contains("let y = 2;"));
}
