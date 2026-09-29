//! `secure-miri-tests/build.rs` carries a byte-identical copy of
//! `secure/build.rs::generate_font_flat`, because the mounted
//! `secure/src/ui/secret_text.rs` does
//! `include!(concat!(env!("OUT_DIR"), "/font_flat.rs"))` and must see the same
//! table under Miri that the firmware sees on device. Its header says "KEEP
//! THIS FUNCTION IN SYNC WITH `secure/build.rs`".
//!
//! A comment is not a gate. This is: the two function bodies must be equal
//! after normalising the ONE line they are allowed to differ on — the input
//! path, which differs only because the two crates have different package
//! roots.
//!
//! WHY IT MATTERS. If the firmware's generator changes and this copy does not,
//! Miri keeps proving things about a font table the device no longer has. The
//! `ui_lcd` mount covers the CONSTANT-TIME glyph blit (F-24), so a silent
//! divergence would mean the constant-time property is verified against the
//! wrong glyphs — green, and meaningless.
//!
//! This is the `fsbl-tests/tests/paired_constants.rs` pattern: two settings for
//! the same property, authored in different places, bound by an assert.

use std::fs;
use std::path::{Path, PathBuf};

/// The single line the two copies are allowed to differ on.
const SECURE_RAW_PATH: &str = r#"    let raw_path = "assets/font_5x8.raw";"#;
const MIRI_RAW_PATH: &str = r#"    let raw_path = "../secure/assets/font_5x8.raw";"#;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits one directory below the workspace root")
        .to_path_buf()
}

/// Slice out `fn generate_font_flat(..) { .. }`, ending at the first `}` in
/// column 0 — the file is rustfmt-shaped, so that is the function's close.
fn extract_generator(path: &Path) -> String {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let start = text
        .find("\nfn generate_font_flat")
        .unwrap_or_else(|| panic!("{}: no `fn generate_font_flat`", path.display()))
        + 1;
    let body = &text[start..];
    let end = body
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{}: `generate_font_flat` has no column-0 close", path.display()))
        + 3;
    body[..end].to_string()
}

#[test]
fn the_miri_mount_font_generator_matches_the_firmware_one() {
    let root = workspace_root();
    let secure = root.join("secure/build.rs");
    let miri = root.join("secure-miri-tests/build.rs");

    // The mount crate is committed; if it ever is not, say so plainly rather
    // than skipping, because a skipped parity test is the failure mode this
    // whole file exists to prevent (see #764, where `make miri` referenced an
    // uncommitted crate for eight weeks).
    assert!(
        miri.is_file(),
        "secure-miri-tests/build.rs is missing — `make miri` cannot run (#764)"
    );

    let secure_src = extract_generator(&secure);
    let miri_src = extract_generator(&miri);

    // ANTI-VACUITY: a normalisation that matched everything, or an extractor
    // that returned a stub, would make this test pass on any input. Pin that
    // the slices are substantial and really are the generator.
    for (label, src) in [("secure", &secure_src), ("miri-mount", &miri_src)] {
        assert!(
            src.lines().count() > 60,
            "{label} generator slice is only {} lines — the extractor broke, \
             and a short slice would let this test pass vacuously",
            src.lines().count()
        );
        assert!(
            src.contains("FONT_FLAT_5X8") && src.contains("BYTES_PER_ROW"),
            "{label} slice does not look like generate_font_flat"
        );
    }

    // Each copy must contain its OWN path line, and only that one.
    assert_eq!(
        secure_src.matches(SECURE_RAW_PATH).count(),
        1,
        "secure/build.rs no longer has the expected raw_path line; update this test \
         deliberately rather than loosening the match"
    );
    assert_eq!(
        miri_src.matches(MIRI_RAW_PATH).count(),
        1,
        "secure-miri-tests/build.rs no longer has the expected raw_path line"
    );

    let secure_norm = secure_src.replace(SECURE_RAW_PATH, "<RAW_PATH>");
    let miri_norm = miri_src.replace(MIRI_RAW_PATH, "<RAW_PATH>");

    if secure_norm != miri_norm {
        let diff = secure_norm
            .lines()
            .zip(miri_norm.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map_or_else(
                || "line counts differ".to_string(),
                |(n, (a, b))| format!("first difference at line {}:\n  secure: {a}\n  miri:   {b}", n + 1),
            );
        panic!(
            "generate_font_flat has DRIFTED between secure/build.rs and \
             secure-miri-tests/build.rs.\n\n{diff}\n\nCopy the firmware version \
             verbatim into the mount crate, changing only the raw_path line. \
             Miri is otherwise proving the constant-time glyph blit against a \
             font table the device does not have."
        );
    }
}
