//! Positive functional coverage for the `fwmeasure` host binary.
//!
//! Each test crafts a hermetic ELF, runs the real `fwmeasure` binary
//! via `CARGO_BIN_EXE_fwmeasure`, and asserts the expected output
//! shape, byte-exact stdout/stderr, or measurement determinism.

mod common;

use common::{minimal_elf, parse_words, run_fwmeasure, ElfBuilder, Segment};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use std::collections::HashSet;
use std::io::Write;

fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fwmeasure-tests-{}-{}",
        std::process::id(),
        name
    ));
    std::fs::create_dir_all(&dir).expect("mkdir tmp");
    let path = dir.join(format!("{name}.elf"));
    let mut f = std::fs::File::create(&path).expect("create tmp ELF");
    f.write_all(bytes).expect("write tmp ELF");
    path
}

#[test]
fn positive_runs_with_minimal_elf_and_emits_8_words() {
    let elf = minimal_elf(0x0800_0000, &[0xAAu8; 32], 0x0800_0020);
    let path = write_tmp("min8", &elf);

    let out = run_fwmeasure([path.as_os_str()]);
    assert!(
        out.status.success(),
        "expected zero exit, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let words = parse_words(&stdout);
    assert_eq!(words.len(), 8, "must emit exactly 8 words, got {:?}", words);
}

#[test]
fn positive_output_word_count_is_exactly_8() {
    // Wire-format invariant: `make verify-release` greps for the
    // "N word" lines. The count must be exactly 8 — no more, no less.
    let elf = minimal_elf(0x1000, &[0; 1], 0x1020);
    let path = write_tmp("count8", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 8, "stdout had {} lines, expected 8", lines.len());
    for (i, line) in lines.iter().enumerate() {
        let prefix = format!("{} ", i + 1);
        assert!(
            line.starts_with(&prefix),
            "line {} must start with {:?}, got {:?}",
            i + 1,
            prefix,
            line
        );
    }
}

#[test]
fn positive_words_are_all_in_bip39_wordlist() {
    let elf = minimal_elf(0x2000, &[0xDE, 0xAD, 0xBE, 0xEF], 0x2080);
    let path = write_tmp("bip39", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    let valid: HashSet<&'static str> = WORDLIST.iter().copied().collect();
    for (i, word) in parse_words(&stdout) {
        assert!(
            valid.contains(word.as_str()),
            "word #{i} {:?} is not in BIP-39 English wordlist",
            word
        );
    }
}

#[test]
fn positive_stderr_metadata_lines_present() {
    // Wire-format: stderr carries human-readable metadata. Tools that
    // pipe `fwmeasure | grep` rely on words being on stdout only.
    let elf = minimal_elf(0x0C00_E000, &[0x42; 16], 0x0C00_E040);
    let path = write_tmp("meta", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Flash base:"), "stderr missing 'Flash base:': {stderr}");
    assert!(stderr.contains("Flash end:"), "stderr missing 'Flash end:': {stderr}");
    assert!(stderr.contains("SHA-256:"), "stderr missing 'SHA-256:': {stderr}");
}

#[test]
fn positive_stdout_contains_only_word_lines() {
    // Anything that lands on stdout will be picked up by
    // `make verify-release`. If a future change leaks a debug line
    // onto stdout, this test fails.
    let elf = minimal_elf(0x0100, &[1, 2, 3, 4, 5, 6, 7, 8], 0x0180);
    let path = write_tmp("stdoutonly", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for (i, line) in stdout.lines().enumerate() {
        let prefix = format!("{} ", i + 1);
        assert!(
            line.starts_with(&prefix),
            "stdout line {i} must be index-word: {line:?}"
        );
        let word = &line[prefix.len()..];
        assert!(!word.contains(' '), "word contains spaces: {word:?}");
    }
}

#[test]
fn positive_deterministic_repeat_runs_produce_identical_output() {
    let elf = minimal_elf(0x0800_0000, &[0x55; 200], 0x0800_0100);
    let path = write_tmp("determinism", &elf);
    let a = run_fwmeasure([path.as_os_str()]);
    let b = run_fwmeasure([path.as_os_str()]);
    assert_eq!(a.stdout, b.stdout, "same input must produce same stdout");
    assert_eq!(a.stderr, b.stderr, "same input must produce same stderr");
}

#[test]
fn positive_hash_matches_independent_sha256_over_overlaid_image() {
    // Construct ELF whose flash region is a known byte sequence, then
    // compute SHA-256 ourselves and compare to the `SHA-256:` line in
    // stderr. This is the **device-vs-host agreement invariant**: any
    // drift between fwmeasure and the device boot hash silently breaks
    // `make verify-release`.
    let payload: Vec<u8> = (0..64u8).collect();
    let base: u32 = 0x0800_0000;
    let end: u32 = base + 0x80;
    let elf = minimal_elf(base, &payload, end);
    let path = write_tmp("indep_hash", &elf);

    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());

    // Reconstruct what fwmeasure should be hashing: payload at offset
    // 0, rest 0xFF up to (end - base) bytes.
    let mut expected = vec![0xFFu8; (end - base) as usize];
    expected[..payload.len()].copy_from_slice(&payload);
    let h: [u8; 32] = Sha256::digest(&expected).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&hex),
        "expected SHA-256 {hex} in stderr, got:\n{stderr}"
    );

    // And the 8 words must be exactly hash_to_word_indices(h) mapped
    // through WORDLIST.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let got_words: Vec<String> = parse_words(&stdout)
        .into_iter()
        .map(|(_, w)| w)
        .collect();
    let expected_words: Vec<&str> = hash_to_word_indices(&h)
        .iter()
        .map(|&i| WORDLIST[i as usize])
        .collect();
    assert_eq!(got_words, expected_words);
}

#[test]
fn positive_gaps_between_segments_filled_with_0xff() {
    // Two PT_LOADs with a 64-byte gap. The gap must hash as 0xFF
    // (erased flash). If a future refactor zero-fills instead, the
    // resulting hash will diverge from what the device computes.
    let base: u32 = 0x0800_0000;
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, vec![0x11u8; 32]))
        .add_segment(Segment::load(base + 0x60, vec![0x22u8; 32]))
        .add_default_symbols(base, 0, 0x80) // end = base + 0x80
        .build();
    let path = write_tmp("gaps", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let mut expected = vec![0xFFu8; 0x80];
    expected[..32].fill(0x11);
    expected[0x60..0x80].fill(0x22);
    let h: [u8; 32] = Sha256::digest(&expected).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&hex),
        "expected gap-filled hash {hex} in:\n{stderr}"
    );
}

#[test]
fn positive_flash_base_override_changes_window() {
    // Same ELF + same payload but `--flash-base=` 8 bytes higher
    // should produce a *different* hash. Confirms the override is wired
    // through.
    let base: u32 = 0x0800_0000;
    let elf = minimal_elf(base, &[0xCDu8; 64], base + 0x80);
    let path = write_tmp("base_override", &elf);

    let a = run_fwmeasure([path.as_os_str()]);
    let b = run_fwmeasure([
        path.as_os_str(),
        std::ffi::OsStr::new("--flash-base=0x08000008"),
    ]);
    assert!(a.status.success() && b.status.success());
    assert_ne!(
        a.stderr, b.stderr,
        "different --flash-base must change the SHA-256"
    );
}

#[test]
fn positive_flash_end_override_truncates_measurement() {
    let base: u32 = 0x0800_0000;
    let payload: Vec<u8> = (0..0x40u8).collect();
    let elf = minimal_elf(base, &payload, base + 0x80);
    let path = write_tmp("end_override", &elf);

    // Force end to base+0x20 → hash the first 32 bytes only.
    let out = run_fwmeasure([
        path.as_os_str(),
        std::ffi::OsStr::new("--flash-end=0x08000020"),
    ]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let h: [u8; 32] = Sha256::digest(&payload[..0x20]).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(&hex), "truncated-end hash mismatch:\n{stderr}");
}

#[test]
fn positive_veneer_limit_inside_window_used_as_end() {
    // `__veneer_limit` lies just past the payload but inside the
    // 2 MiB window from base → it must override the
    // sidata+(edata-sdata) fallback.
    let base: u32 = 0x0800_0000;
    let payload = vec![0x77u8; 64];
    let veneer_end: u32 = base + 0x40; // exactly past the payload
    let mut elf = ElfBuilder::new()
        .add_segment(Segment::load(base, payload.clone()))
        // sidata-fallback would compute a *different* end — use base+0x100
        .add_default_symbols(base, 0, 0x100);
    // Add veneer_limit symbol.
    elf = elf.add_symbol("__veneer_limit", veneer_end);
    let elf_bytes = elf.build();
    let path = write_tmp("veneer_in", &elf_bytes);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    // Expected hash = SHA-256 over exactly `payload` (0x40 bytes).
    let h: [u8; 32] = Sha256::digest(&payload).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&hex),
        "veneer_limit must be used as end; expected hash {hex}\n{stderr}"
    );
    assert!(
        stderr.contains("Flash end:   0x08000040"),
        "Flash end line missing/wrong:\n{stderr}"
    );
}

#[test]
fn positive_veneer_limit_outside_window_falls_back_to_sidata() {
    // `__veneer_limit` beyond `base + MAX_FLASH_SIZE` (2 MiB) — exactly
    // the QEMU scenario where veneers live in NSC at 0x103F_F000.
    // Must fall back to `__sidata + (__edata - __sdata)`.
    let base: u32 = 0x0800_0000;
    let payload = vec![0x99u8; 32];
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, payload.clone()))
        .add_default_symbols(base, 0, 0x20) // fallback end = base + 0x20
        .add_symbol("__veneer_limit", 0x103F_F000) // way outside the 2 MiB window
        .build();
    let path = write_tmp("veneer_out", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let h: [u8; 32] = Sha256::digest(&payload).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(&hex), "fallback path must hash payload only:\n{stderr}");
    assert!(
        stderr.contains("Flash end:   0x08000020"),
        "fallback end wrong:\n{stderr}"
    );
}

#[test]
fn positive_lowest_p_paddr_chosen_as_base_with_unsorted_segments() {
    // Two LOAD segments in non-ascending p_paddr order. The lower
    // address must become the base.
    let lo: u32 = 0x0800_0000;
    let hi: u32 = lo + 0x100;
    let elf = ElfBuilder::new()
        // Higher first, lower second.
        .add_segment(Segment::load(hi, vec![0xAAu8; 16]))
        .add_segment(Segment::load(lo, vec![0xBBu8; 16]))
        .add_default_symbols(lo, 0, 0x200) // end = lo + 0x200
        .build();
    let path = write_tmp("unsorted", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Flash base:  0x08000000"),
        "base must be lowest p_paddr:\n{stderr}"
    );
}

#[test]
fn positive_pt_note_segments_ignored() {
    // Non-LOAD segments must not affect the measurement.
    let base: u32 = 0x0800_0000;
    let payload = vec![0x33u8; 32];
    let elf_a = ElfBuilder::new()
        .add_segment(Segment::load(base, payload.clone()))
        .add_default_symbols(base, 0, 0x20)
        .build();
    let elf_b = ElfBuilder::new()
        .add_segment(Segment::load(base, payload))
        .add_segment(Segment::note(vec![0xFEu8; 64]))
        .add_default_symbols(base, 0, 0x20)
        .build();
    let pa = write_tmp("pt_note_a", &elf_a);
    let pb = write_tmp("pt_note_b", &elf_b);
    let oa = run_fwmeasure([pa.as_os_str()]);
    let ob = run_fwmeasure([pb.as_os_str()]);
    assert!(oa.status.success() && ob.status.success());
    assert_eq!(oa.stdout, ob.stdout, "PT_NOTE must not change measurement");
}

#[test]
fn positive_segment_outside_window_excluded() {
    // A LOAD segment whose p_paddr is past flash_end must not be
    // included. This guards the per-slot measurement use-case where
    // `--flash-end=` deliberately drops segments living above it.
    let base: u32 = 0x0800_0000;
    let inside = vec![0x11u8; 32];
    let outside = vec![0x22u8; 64];
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, inside.clone()))
        .add_segment(Segment::load(base + 0x1000, outside)) // beyond end
        .add_default_symbols(base, 0, 0x20) // end = base + 0x20
        .build();
    let path = write_tmp("outside", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());

    let h: [u8; 32] = Sha256::digest(&inside).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&hex),
        "out-of-window segment must be ignored:\n{stderr}"
    );
}

#[test]
fn positive_zero_filesz_load_segment_ignored() {
    // p_filesz == 0 LOAD segments (e.g. .bss) must not pull data nor
    // shift the computed base. Use a high p_paddr so it would dominate
    // the `.min()` if filesz were not filtered.
    let base: u32 = 0x0800_0000;
    let mut elf = ElfBuilder::new()
        .add_segment(Segment::load(base, vec![0x44u8; 16]))
        .add_default_symbols(base, 0, 0x20);
    // Add a zero-filesz LOAD at a *lower* paddr.
    let mut bss = Segment::load(0x2000_0000, Vec::new());
    bss.memsz = Some(0x100);
    elf = elf.add_segment(bss);
    let bytes = elf.build();
    let path = write_tmp("zero_filesz", &bytes);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Flash base:  0x08000000"),
        "zero-filesz LOAD must not shift base:\n{stderr}"
    );
}

#[test]
fn positive_partial_overlap_segment_clipped_at_window_end() {
    // A LOAD that crosses the end boundary must be clipped, not
    // truncated entirely. The bytes up to `flash_end` are included,
    // the rest are dropped. Anchor the base with a small first
    // segment so the second one is the overlapper.
    let base: u32 = 0x0800_0000;
    let end: u32 = base + 0x40;
    let anchor = vec![0xEEu8; 8];
    let seg_paddr: u32 = base + 0x20;
    let seg_data: Vec<u8> = (0..0x40u8).collect(); // 64 bytes, half outside
    let elf = ElfBuilder::new()
        .add_segment(Segment::load(base, anchor.clone()))
        .add_segment(Segment::load(seg_paddr, seg_data.clone()))
        .add_default_symbols(base, 0, end - base)
        .build();
    let path = write_tmp("clipped", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));

    let mut expected = vec![0xFFu8; (end - base) as usize];
    expected[..anchor.len()].copy_from_slice(&anchor);
    // Only the first 0x20 bytes of seg_data fit.
    expected[0x20..0x40].copy_from_slice(&seg_data[..0x20]);
    let h: [u8; 32] = Sha256::digest(&expected).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains(&hex), "expected clipped hash {hex}:\n{stderr}");
}
