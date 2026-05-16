//! Adversarial / negative coverage for `fwmeasure`.
//!
//! Each test pins an assumption the binary holds about its input and
//! asserts that violating the assumption is rejected (non-zero exit,
//! error on stderr, no measurement words emitted). A test that passes
//! here means an attacker / a future refactor cannot quietly slip the
//! corresponding bad input past the tool.

mod common;

use common::{minimal_elf, run_fwmeasure, ElfBuilder, Segment};
use std::io::Write;

fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fwmeasure-neg-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("mkdir tmp");
    let path = dir.join(format!("{name}.bin"));
    let mut f = std::fs::File::create(&path).expect("create tmp file");
    f.write_all(bytes).expect("write tmp file");
    path
}

fn assert_failure_no_word_lines(out: &std::process::Output, assumption: &str) {
    assert!(
        !out.status.success(),
        "Assumption '{assumption}' failed: tool exited 0 with stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // On failure the tool must not have printed any of the 8 BIP-39
    // word lines — otherwise downstream `make verify-release` could
    // proceed with stale/garbage data.
    let stdout = String::from_utf8_lossy(&out.stdout);
    for (i, line) in stdout.lines().enumerate() {
        assert!(
            !line.starts_with(&format!("{} ", i + 1)),
            "On failure the tool must not emit BIP-39 word lines, got: {line:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Argument parsing / CLI surface
// ---------------------------------------------------------------------------

#[test]
fn negative_no_args_exits_nonzero_with_usage() {
    // Assumption: missing ELF path is a hard error. If a future change
    // ever made it default to "./firmware.elf" or similar, a release
    // pipeline could measure a stale file.
    let out = run_fwmeasure(Vec::<&std::ffi::OsStr>::new());
    assert_failure_no_word_lines(&out, "no-args must print usage");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "stderr must contain Usage line, got {stderr:?}"
    );
}

#[test]
fn negative_multiple_elf_paths_rejected() {
    // Assumption: tool refuses ambiguous CLI — exactly one ELF path.
    // A silent "use the last one" policy would allow scripts to
    // accidentally measure the wrong file.
    let elf = minimal_elf(0x100, &[0; 4], 0x120);
    let p1 = write_tmp("one", &elf);
    let p2 = write_tmp("two", &elf);
    let out = run_fwmeasure([p1.as_os_str(), p2.as_os_str()]);
    assert_failure_no_word_lines(&out, "two ELF paths must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Multiple ELF paths"),
        "expected 'Multiple ELF paths' diagnostic, got {stderr:?}"
    );
}

#[test]
fn negative_invalid_hex_in_flash_base_rejected() {
    // Assumption: --flash-base= must be parseable hex; anything else
    // is rejected. A silent "treat as 0" or "skip flag" would point
    // the per-slot measurement at the wrong window.
    let elf = minimal_elf(0x100, &[0; 4], 0x120);
    let path = write_tmp("bad_hex", &elf);
    let out = run_fwmeasure([
        path.as_os_str(),
        std::ffi::OsStr::new("--flash-base=0xZZZZ"),
    ]);
    assert_failure_no_word_lines(&out, "non-hex --flash-base must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cannot parse hex"),
        "expected hex-parse diagnostic, got {stderr:?}"
    );
}

#[test]
fn negative_invalid_hex_in_flash_end_rejected() {
    let elf = minimal_elf(0x100, &[0; 4], 0x120);
    let path = write_tmp("bad_end", &elf);
    let out = run_fwmeasure([
        path.as_os_str(),
        std::ffi::OsStr::new("--flash-end=not_hex"),
    ]);
    assert_failure_no_word_lines(&out, "non-hex --flash-end must be rejected");
}

#[test]
fn negative_nonexistent_elf_path_rejected() {
    // Assumption: a missing file is a hard error.
    let bogus = std::env::temp_dir().join("__fwmeasure_does_not_exist_XYZ123.elf");
    let _ = std::fs::remove_file(&bogus);
    let out = run_fwmeasure([bogus.as_os_str()]);
    assert_failure_no_word_lines(&out, "missing ELF file must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cannot read"),
        "expected 'Cannot read' diagnostic, got {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// File / format parsing
// ---------------------------------------------------------------------------

#[test]
fn negative_non_elf_file_rejected() {
    // Assumption: anything that isn't a valid ELF is rejected before
    // we hash it. The tool must NOT happily SHA-256 arbitrary user
    // data and emit BIP-39 words for it — that would let an attacker
    // who substitutes a non-ELF for the release artifact still get
    // 8 plausible-looking words.
    let path = write_tmp("plain", b"this is not an ELF\n");
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "non-ELF file must be rejected");
}

#[test]
fn negative_truncated_elf_rejected() {
    // Truncate at 8 bytes — keeps magic but cuts the header.
    let elf = minimal_elf(0x100, &[0; 4], 0x120);
    let path = write_tmp("trunc", &elf[..8]);
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "truncated ELF must be rejected");
}

#[test]
fn negative_empty_file_rejected() {
    let path = write_tmp("empty", b"");
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "empty file must be rejected");
}

#[test]
fn negative_elf_without_load_segments_rejected() {
    // Assumption: an ELF with zero PT_LOADs has no measurable image
    // and must be rejected (not silently produce SHA-256("") words).
    let elf = ElfBuilder::new()
        // Only a PT_NOTE — no LOAD at all.
        .add_segment(Segment::note(vec![0xAAu8; 16]))
        .add_default_symbols(0x100, 0, 0x20)
        .build();
    let path = write_tmp("no_load", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "ELF without PT_LOAD must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("No LOAD segments"),
        "expected 'No LOAD segments' diagnostic, got {stderr:?}"
    );
}

#[test]
fn negative_zero_filesz_only_load_segments_rejected() {
    // .bss-only ELF (every LOAD has filesz=0). The fwmeasure base
    // computation filters by `p_filesz > 0`, so this is equivalent
    // to no-LOAD: must reject, not panic on an empty `.min()`.
    let mut elf = ElfBuilder::new().add_default_symbols(0x100, 0, 0x20);
    let mut bss = Segment::load(0x100, Vec::new());
    bss.memsz = Some(0x100);
    elf = elf.add_segment(bss);
    let bytes = elf.build();
    let path = write_tmp("bss_only", &bytes);
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(
        &out,
        "ELF with only zero-filesz LOAD segments must be rejected",
    );
}

#[test]
fn negative_elf_missing_required_symbols_rejected() {
    // Assumption: when `__veneer_limit` is absent (or outside window),
    // the tool needs all three of `__sidata`, `__sdata`, `__edata`.
    // Missing any one is a hard error — not silent zero/garbage end.
    let base: u32 = 0x0800_0000;
    // Missing all three symbols.
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, vec![0; 16]))
        .build();
    let path = write_tmp("missing_syms", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "missing __sidata must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("__sidata") || stderr.contains("missing"),
        "expected diagnostic mentioning missing symbol, got {stderr:?}"
    );
}

#[test]
fn negative_elf_missing_edata_alone_rejected() {
    // Only __edata missing — confirms the per-symbol check fires for
    // each, not just the first one.
    let base: u32 = 0x0800_0000;
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, vec![0; 16]))
        .add_symbol("__sidata", base)
        .add_symbol("__sdata", 0)
        // __edata deliberately omitted
        .build();
    let path = write_tmp("missing_edata", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert_failure_no_word_lines(&out, "missing __edata must be rejected");
}

// ---------------------------------------------------------------------------
// MAX_FLASH_SIZE sanity check on __veneer_limit
// ---------------------------------------------------------------------------

#[test]
fn negative_veneer_limit_below_base_falls_back_not_used() {
    // Assumption: a `__veneer_limit` BELOW the flash base (which can
    // happen if a linker accident moves veneers far away) must NOT be
    // accepted as the measurement end — that would produce a
    // negative-sized window and either panic or hash 4 GiB of memory.
    // The code uses `(base..base+MAX_FLASH_SIZE).contains(&vl)` which
    // excludes any vl < base; the sidata fallback must take over.
    let base: u32 = 0x0800_0000;
    let payload = vec![0xABu8; 32];
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, payload.clone()))
        .add_default_symbols(base, 0, 0x20) // fallback end = base + 0x20
        .add_symbol("__veneer_limit", 0x100) // way below base
        .build();
    let path = write_tmp("veneer_below", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(
        out.status.success(),
        "tool should fall back to sidata path, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Flash end:   0x08000020"),
        "veneer_limit below base must NOT be used as end:\n{stderr}"
    );
}

#[test]
fn negative_veneer_limit_at_window_edge_rejected_inclusive() {
    // Boundary: vl == base + MAX_FLASH_SIZE is the *exclusive* end of
    // the range check, so it must fall back. Catches off-by-one
    // refactors that would swallow a veneer outside the legal window.
    const MAX_FLASH_SIZE: u32 = 2 * 1024 * 1024;
    let base: u32 = 0x0800_0000;
    let payload = vec![0xCDu8; 16];
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, payload))
        .add_default_symbols(base, 0, 0x10) // fallback end
        .add_symbol("__veneer_limit", base + MAX_FLASH_SIZE)
        .build();
    let path = write_tmp("veneer_edge", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Flash end:   0x08000010"),
        "veneer at exclusive upper bound must fall back, not be used:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Hash / format-stability negatives
// ---------------------------------------------------------------------------

#[test]
fn negative_single_byte_change_in_segment_changes_words() {
    // Assumption: the measurement is sensitive to *every* byte in the
    // flash window. If a future change ever started skipping padding,
    // alignment slack, etc., the words would not change with the
    // bytes — defeating the whole point of measured boot.
    let base: u32 = 0x0800_0000;
    let mut data = vec![0u8; 64];
    let elf_a = minimal_elf(base, &data, base + 0x40);
    let path_a = write_tmp("change_a", &elf_a);
    let out_a = run_fwmeasure([path_a.as_os_str()]);
    assert!(out_a.status.success());

    data[42] ^= 1; // flip a single bit
    let elf_b = minimal_elf(base, &data, base + 0x40);
    let path_b = write_tmp("change_b", &elf_b);
    let out_b = run_fwmeasure([path_b.as_os_str()]);
    assert!(out_b.status.success());

    assert_ne!(
        out_a.stdout, out_b.stdout,
        "flipping one byte must change the 8 words"
    );
}

#[test]
fn negative_words_not_emitted_to_stdout_on_failure() {
    // Combined invariant: on ANY failure path the word lines must not
    // appear on stdout. Tested across three error modes here to keep
    // the property visible if a single error path drifts.
    let cases: Vec<(&str, Vec<&std::ffi::OsStr>)> = vec![
        ("no_args", vec![]),
        (
            "bad_path",
            vec![std::ffi::OsStr::new("/definitely/not/here.elf")],
        ),
    ];
    for (name, args) in cases {
        let out = run_fwmeasure(args);
        assert!(!out.status.success(), "{name}: expected non-zero exit");
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            // Reject any "<digit> <something>" line on stdout.
            let mut iter = line.splitn(2, ' ');
            if let Some(first) = iter.next() {
                if first.parse::<u32>().is_ok() {
                    panic!(
                        "{name}: failure path leaked a word-line to stdout: {line:?}"
                    );
                }
            }
        }
    }
}
