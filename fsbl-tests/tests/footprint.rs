//! FSBL footprint CI gate.
//!
//! Builds `pqsigner-fsbl --release --target thumbv8m.main-none-eabi`
//! with the current legacy bench link flags, runs `arm-none-eabi-size` on the
//! resulting ELF, and asserts the sections stay under that linker's 32 KB
//! region at `0x0C00_0000` (`fsbl/memory-stm32u585.x: FLASH 32K`).
//!
//! This is a legacy regression check, not production geometry or resource
//! approval. Draft 1.1 proposes a 40,960-byte hard ceiling and separately
//! requires physical LOAD-span and static-RAM/worst-case-stack gates.
//!
//! Toolchain handling (F21): when `arm-none-eabi-size` is absent the test
//! FAILS CLOSED in a CI context (`CI` env var set — a skip there asserts
//! nothing) and skips with a message only on local dev boxes.

use std::path::PathBuf;
use std::process::Command;

/// Legacy bench linker ceiling. This is not the Draft-1.1 candidate ceiling.
/// Matches the current `fsbl/memory-stm32u585.x: FLASH 32K`.
const FSBL_FLASH_CEILING: u64 = 32 * 1024;

/// Returns true if `arm-none-eabi-size` is on PATH.
fn toolchain_available() -> bool {
    Command::new("arm-none-eabi-size")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Walk up from the test's `current_dir` until we find the workspace
/// root (the dir containing `Cargo.toml` with `[workspace]`).
fn workspace_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            let s = std::fs::read_to_string(&candidate).unwrap_or_default();
            if s.contains("[workspace]") {
                return p;
            }
        }
        if !p.pop() {
            panic!("no [workspace] Cargo.toml above cwd");
        }
    }
}

#[test]
fn fsbl_release_flash_sections_fit_in_32kb() {
    if !toolchain_available() {
        // Fail CLOSED in CI (GitHub Actions always sets CI=true): a gate that
        // skips green there asserts nothing at all (F21 — this test silently
        // passed on any toolchain-less CI image). Locally the skip stays
        // ergonomic: install gcc-arm-none-eabi to run the gate for real.
        assert!(
            std::env::var_os("CI").is_none(),
            "arm-none-eabi-size not on PATH in CI — install gcc-arm-none-eabi in \
             the workflow. The FSBL 32 KB footprint gate must never skip green."
        );
        eprintln!(
            "skipping: arm-none-eabi-size not on PATH. Install the \
             gcc-arm-none-eabi toolchain to enable this CI gate."
        );
        return;
    }

    let workspace = workspace_root();
    let target_dir = workspace.join("target/fsbl-footprint-test");

    let status = Command::new("cargo")
        .current_dir(&workspace)
        .env(
            "RUSTFLAGS",
            "-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x",
        )
        // F2: a release FSBL build hard-fails unless a real vendor pubkey
        // (FSBL_VENDOR_PUBKEY) or the explicit dev opt-in (FSBL_ALLOW_DEV_KEY)
        // is set. This is a SIZE test — the key content is irrelevant to the
        // footprint, and the built-in dev fixture key is the right size — so
        // opt into it here. (Production size is identical: a real 32-byte
        // pubkey embeds the same way.)
        .env("FSBL_ALLOW_DEV_KEY", "1")
        .args([
            "build",
            "--locked",
            "--release",
            "--target",
            "thumbv8m.main-none-eabi",
            "--target-dir",
        ])
        .arg(&target_dir)
        .args([
            "-p",
            "pqsigner-fsbl",
            "--features",
            // Board is MANDATORY (`fsbl/src/board/mod.rs`), so this gate must
            // name one — and it names **pq1** deliberately. pq1 is the
            // shipping board and the larger image (it drives a backlight
            // enable and a real reset pulse, and its control lines are on a
            // second GPIO port), so gating iota2 here would leave the board
            // that actually has to fit in the region unmeasured. iota2 is
            // still compiled in CI by the `rollback_ship_fences` build
            // assertions, so neither pin map goes untested.
            "legacy-fw-rollback-unsafe,board-pq1",
        ])
        .status()
        .expect("spawn cargo build");
    assert!(status.success(), "fsbl release build must succeed");

    let elf = target_dir.join("thumbv8m.main-none-eabi/release/pqsigner-fsbl");
    assert!(elf.exists(), "fsbl ELF not produced at {}", elf.display());

    let out = Command::new("arm-none-eabi-size")
        .arg("--format=sysv")
        .arg(&elf)
        .output()
        .expect("arm-none-eabi-size");
    assert!(out.status.success(), "arm-none-eabi-size failed");
    let text = String::from_utf8_lossy(&out.stdout);

    // Sum the sections that consume on-device flash. Mirrors the
    // Makefile's `make fsbl` size printout.
    let flash_sections = [".vector_table", ".text", ".rodata", ".data", ".gnu.sgstubs"];
    let mut total: u64 = 0;
    let mut per_section: Vec<(String, u64)> = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0];
        if !flash_sections.contains(&name) {
            continue;
        }
        let size: u64 = parts[1].parse().unwrap_or(0);
        total += size;
        per_section.push((name.to_string(), size));
    }

    eprintln!("FSBL footprint breakdown:");
    for (name, size) in &per_section {
        eprintln!("  {:<16} {:>6} bytes", name, size);
    }
    eprintln!(
        "  TOTAL            {:>6} bytes (ceiling {})",
        total, FSBL_FLASH_CEILING
    );

    assert!(
        total <= FSBL_FLASH_CEILING,
        "FSBL footprint {} exceeds the legacy 32 KB linker region ({} bytes over). \
         Shrink the legacy bench image; any layout/WRP change belongs to the \
         separately approved candidate resource and factory gates.",
        total,
        total - FSBL_FLASH_CEILING,
    );
}
