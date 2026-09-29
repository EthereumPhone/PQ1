//! Cross-world pins for constants that govern the SAME user-visible property
//! from TWO places, and must therefore move together.
//!
//! WHY THIS FILE EXISTS. On 2026-09-24 the owner asked to shorten the boot
//! fingerprint screen to 4 s. The FSBL said `FINGERPRINT_HOLD_MS = 10_000`;
//! the secure world had said `WORDS_MS = 4_000` for the same eight words,
//! derived from the same digest through the same
//! `sphincs_tz_bip39::firmware_fingerprint_lines`, since 2026-04-14. Two
//! screens, one property, six seconds apart — because the constants were set
//! on different dates by different people and nothing tied them together.
//! Comments at both sites would not have caught it. A failing test does.
//!
//! WHAT BELONGS HERE: a pair only earns a pin if the two values MUST be equal
//! for the system to be correct. Constants that deliberately differ do NOT
//! belong — asserting equality on them would encode a false claim and force a
//! behaviour change nobody decided. The deliberate divergences are listed at
//! the bottom of this file so a future reader does not "fix" them.
//!
//! Textual, in the `source_invariants.rs` / `geometry_consistency.rs` style:
//! `fsbl` and `sphincs-tz-secure` are separate crates with no dependency
//! between them, so a `const _: () = assert!(..)` cannot span them.

#![forbid(unsafe_code)]

use std::fs;

fn read_workspace_file(rel: &str) -> String {
    // Walk up to the workspace root, same shape as geometry_consistency.rs.
    let mut p = std::env::current_dir().expect("cwd");
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            let s = fs::read_to_string(&candidate).unwrap_or_default();
            if s.contains("[workspace]") {
                return fs::read_to_string(p.join(rel))
                    .unwrap_or_else(|e| panic!("read {rel}: {e}"));
            }
        }
        if !p.pop() {
            panic!("no [workspace] Cargo.toml above cwd");
        }
    }
}

/// The integer a `const NAME: ty = <value>;` line binds, ignoring `_`
/// separators. Panics if the constant is absent or not a plain integer — a
/// rename must fail loudly here rather than silently stop checking anything,
/// which is the whole failure mode this file exists to prevent.
fn const_u32(src: &str, path: &str, name: &str) -> u32 {
    let needle = format!("{name}:");
    let line = src
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .find(|l| l.contains(&needle) && l.contains('=') && l.ends_with(';'))
        .unwrap_or_else(|| {
            panic!("{path}: no `const {name}: .. = ..;` line — was it renamed or removed?")
        });

    let rhs = line
        .rsplit_once('=')
        .unwrap_or_else(|| panic!("{path}: `{name}` line has no `=`: {line}"))
        .1
        .trim()
        .trim_end_matches(';')
        .trim()
        .replace('_', "");

    rhs.parse::<u32>()
        .unwrap_or_else(|e| panic!("{path}: `{name}` is not a plain integer ({rhs:?}): {e}"))
}

/// The FSBL's fingerprint hold and the secure world's words-screen dwell show
/// the SAME eight words for the same digest. CLAUDE.md: "The FSBL fingerprint
/// and the secure-world `measured_boot::run` screen show the SAME 8 words for
/// the same active slot ... Honest-row divergence is a strong defect/tamper
/// signal." A user who is told to compare the two rows must be given the same
/// amount of time to read each.
///
/// They are NOT the same kind of wait, and that asymmetry is deliberate: the
/// secure world's is an auto-dismiss ceiling (`input().wait_button`, any
/// button skips it), the FSBL's is a floor (it never initialises the GPIO
/// buttons). The pin is on the NUMBER, which is the reading budget.
#[test]
fn fingerprint_dwell_agrees_between_the_fsbl_and_the_secure_world() {
    let fsbl_src = read_workspace_file("fsbl/src/render.rs");
    let secure_src = read_workspace_file("secure/src/measured_boot.rs");

    let fsbl_ms = const_u32(&fsbl_src, "fsbl/src/render.rs", "FINGERPRINT_HOLD_MS");
    let secure_ms = const_u32(&secure_src, "secure/src/measured_boot.rs", "WORDS_MS");

    assert_eq!(
        fsbl_ms, secure_ms,
        "the two fingerprint screens show the SAME eight words but would give \
         the user different reading time: fsbl/src/render.rs FINGERPRINT_HOLD_MS \
         = {fsbl_ms} ms vs secure/src/measured_boot.rs WORDS_MS = {secure_ms} ms.\n\
         \n\
         This exact divergence (10,000 vs 4,000) shipped unnoticed from \
         2026-09-16 to 2026-09-24 and was caught by the owner, not by CI.\n\
         \n\
         If you are deliberately changing the reading budget, change BOTH. If \
         you believe they should differ, delete this test and say why in the \
         commit — do not widen the assertion."
    );
}

/// Every renderer targets the same logical trusted-display grid. The FSBL's
/// own module doc says so: "Renders the SAME `DISPLAY_COLS=16 x
/// DISPLAY_ROWS=4` char grid". Nothing enforced it until now — the FSBL
/// declares its own private copy because it cannot depend on the secure crate.
///
/// A silent divergence here does not fail to compile; it renders a fingerprint
/// the user cannot compare against the secure world's, which is precisely the
/// cross-check invariant #10 leans on.
#[test]
fn trusted_display_grid_agrees_between_the_fsbl_and_the_secure_world() {
    let fsbl_src = read_workspace_file("fsbl/src/nv3007.rs");
    let secure_src = read_workspace_file("secure/src/ui/mod.rs");

    for name in ["DISPLAY_COLS", "DISPLAY_ROWS"] {
        let fsbl_v = const_u32(&fsbl_src, "fsbl/src/nv3007.rs", name);
        let secure_v = const_u32(&secure_src, "secure/src/ui/mod.rs", name);
        assert_eq!(
            fsbl_v, secure_v,
            "trusted-display grid disagrees on {name}: fsbl/src/nv3007.rs = \
             {fsbl_v}, secure/src/ui/mod.rs = {secure_v}. Both renderers paint \
             the same logical page; the FSBL keeps a private copy only because \
             it cannot depend on the secure crate."
        );
    }

    // Pin the shape itself, so "both sides changed together, to something the
    // page painters do not target" also fails.
    assert_eq!(const_u32(&fsbl_src, "fsbl/src/nv3007.rs", "DISPLAY_COLS"), 16);
    assert_eq!(const_u32(&fsbl_src, "fsbl/src/nv3007.rs", "DISPLAY_ROWS"), 4);
}

// ---------------------------------------------------------------------------
// DELIBERATE divergences — do NOT add pins for these
// ---------------------------------------------------------------------------
//
// Found by the same sweep that caught the fingerprint pair (2026-09-24). Each
// looks like an unintended drift and is not. Recorded here so the next reader
// does not "fix" one into a behaviour change nobody asked for.
//
//   * `pqsigner-ui-px::input::DEBOUNCE_MS` (25) vs `hw::buttons::DEBOUNCE_MS`
//     (30). Same physical switches, but two sampling architectures: the legacy
//     driver polls on its own calibrated delay loop at `POLL_MS = 5`, the pixel
//     FSM consumes a SysTick-timestamped edge ring. Forcing equality would
//     change one of them on no evidence.
//
//   * `pqsigner-ui-px::motion::CHORD_MS` (150) vs `hw::buttons::
//     COMBO_WINDOW_MS` (80) — same reason.
//
//   * `pqsigner-ui-px::motion::HOLD_COMMIT_MS` (2000) vs `hw::buttons::
//     LONG_PRESS_MS` (500). These no longer MEAN the same thing. Since the
//     chord-click decision (2026-09-22) hold-right is a no-op on the pixel
//     path and `HOLD_COMMIT_MS` governs only hold-LEFT, which declines;
//     `LONG_PRESS_MS` on the legacy path is confirm/cancel. Asserting equality
//     would be asserting something false.
//
//   * `pqsigner-ui-px::motion::TAP_MAX_MS` (500) vs the PQ-UI reference (250).
//     ALREADY BOUND, elsewhere: `tools/pq_ui_port_diff.py` diffs every firmware
//     timing constant against the vendored spec and fails on any MISMATCH that
//     is not listed in `tools/pq-ui/PORT_DEVIATIONS.toml`. Do not duplicate
//     that gate here.
//
// One pair is deliberately ABSENT pending an owner decision:
// `PX_COMMIT_REQUIRES_SEEN_LAST` (false, pixel path) against the legacy
// `confirm_core.rs` scroll-to-end gate (enforced). They disagree today. Pinning
// either way would pre-empt a decision that is the owner's to make.
