//! Frozen-format stability tests.
//!
//! The output of `fwmeasure` is a wire format consumed by
//! `make verify-release` (greps stdout for the 8 "N word" lines) and
//! by humans visually comparing the device-displayed words to the
//! ones the tool prints. Any silent reshuffle of either format here
//! breaks downstream tooling — these tests fail loudly when the
//! shape changes, so a maintainer has to consciously update both
//! sides.

mod common;

use common::{minimal_elf, parse_words, run_fwmeasure};
use sha2::{Digest, Sha256};
use sphincs_tz_bip39::{hash_to_word_indices, WORDLIST};
use std::io::Write;

fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fwmeasure-format-{}-{}",
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
fn stability_stdout_is_exactly_index_space_word_one_per_line() {
    // Wire format: lines are "1 word\n" .. "8 word\n", nothing else.
    let elf = minimal_elf(0x0800_0000, &[0xA5; 64], 0x0800_0040);
    let path = write_tmp("shape", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();

    // 8 newline-terminated lines, no trailing blank line beyond that.
    assert!(stdout.ends_with('\n'), "stdout must end with newline");
    let body = stdout.trim_end_matches('\n');
    assert_eq!(
        body.chars().filter(|c| *c == '\n').count(),
        7,
        "expected exactly 7 internal newlines (8 lines), got stdout={stdout:?}"
    );

    for (i, line) in body.lines().enumerate() {
        let expected_prefix = format!("{} ", i + 1);
        assert!(
            line.starts_with(&expected_prefix),
            "line {} doesn't start with {:?}: {:?}",
            i + 1,
            expected_prefix,
            line
        );
        let word = &line[expected_prefix.len()..];
        // No trailing whitespace.
        assert_eq!(word, word.trim(), "word has stray whitespace: {word:?}");
        // ASCII-lowercase letters only.
        assert!(
            word.chars().all(|c| c.is_ascii_lowercase()),
            "word {word:?} must be ASCII-lowercase letters only"
        );
    }
}

#[test]
fn stability_sha256_line_format_in_stderr() {
    // Wire format: stderr `SHA-256:` line shape — auditors visually
    // compare this to a printed receipt. Use a known fixed payload
    // and pin the hex bytes character-for-character.
    let base: u32 = 0x0800_0000;
    let end: u32 = base + 0x20;
    let payload = [0u8; 32]; // all zeros payload
    let elf = minimal_elf(base, &payload, end);
    let path = write_tmp("sha_line", &elf);

    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());

    // Expected: SHA-256(32 bytes of 0x00).
    let mut flat = vec![0xFFu8; 0x20];
    flat[..32].copy_from_slice(&payload);
    let h: [u8; 32] = Sha256::digest(&flat).into();
    let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(&format!("SHA-256:     {hex}")),
        "expected exact 'SHA-256:     {hex}' line, stderr=\n{stderr}"
    );
    assert!(stderr.contains("Flash base:  0x08000000"), "base line:\n{stderr}");
    assert!(stderr.contains("Flash end:   0x08000020"), "end line:\n{stderr}");
    assert!(stderr.contains("(32 bytes)"), "byte-count annotation:\n{stderr}");
}

#[test]
fn stability_words_derived_from_hash_per_published_kdf() {
    // The exact mapping hash → 8 words is part of the device-receipt
    // wire format. If anyone ever reshuffles `hash_to_word_indices`
    // or substitutes a different wordlist, the device-displayed and
    // host-printed words will diverge silently — this test catches it.
    let base: u32 = 0x0800_0000;
    let end: u32 = base + 0x10;
    let payload: Vec<u8> = (0..16u8).collect();
    let elf = minimal_elf(base, &payload, end);
    let path = write_tmp("kdf_words", &elf);

    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());

    let mut flat = vec![0xFFu8; (end - base) as usize];
    flat[..payload.len()].copy_from_slice(&payload);
    let h: [u8; 32] = Sha256::digest(&flat).into();
    let expected: Vec<&str> = hash_to_word_indices(&h)
        .iter()
        .map(|&i| WORDLIST[i as usize])
        .collect();

    let stdout = String::from_utf8(out.stdout).unwrap();
    let got: Vec<String> = parse_words(&stdout).into_iter().map(|(_, w)| w).collect();
    assert_eq!(got, expected, "host words must equal device words");
}

#[test]
fn stability_word_indices_are_one_based_not_zero_based() {
    // Anti-regression: a refactor that drops the `+ 1` would make
    // the lines start at "0" and shift the device-vs-host visual
    // compare off by one. Pin it.
    let elf = minimal_elf(0x100, &[0; 4], 0x120);
    let path = write_tmp("one_based", &elf);
    let out = run_fwmeasure([path.as_os_str()]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("1 "),
        "first word line must start with '1 ', got: {stdout:?}"
    );
    assert!(
        !stdout.starts_with("0 "),
        "indices must be 1-based, not 0-based"
    );
    // Last word index must be 8, never 9 or 7.
    let last = stdout.trim_end_matches('\n').lines().last().unwrap();
    assert!(
        last.starts_with("8 "),
        "last word line must start with '8 ', got: {last:?}"
    );
}

#[test]
fn stability_bip39_wordlist_size_2048() {
    // Indirect but cheap: `hash_to_word_indices` returns 11-bit values
    // (0..2048). Any wordlist change that shrinks it would let the
    // tool panic on indexing. The BIP-39 standard mandates 2048.
    assert_eq!(WORDLIST.len(), 2048, "BIP-39 English wordlist must be 2048 entries");
}
