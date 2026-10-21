//! Build script for the first-stage bootloader.
//!
//! Does two things:
//!
//! 1. Places `memory-stm32u585.x` where cortex-m-rt's `link.x` can find
//!    it (copies to OUT_DIR and adds OUT_DIR to the linker search path).
//!    The FSBL only ever builds for `thumbv8m.main-none-eabi`; there is
//!    no host-side smoke test for it because the full bring-up sequence
//!    only makes sense on real hardware.
//!
//! 2. Embeds the vendor SPHINCS+C10 public key from the path in the
//!    `FSBL_VENDOR_PUBKEY` environment variable into a generated
//!    `vendor_pubkey_bytes.rs` source file. Release builds MUST set
//!    this env var. Bench builds may explicitly opt into the public in-tree
//!    development key. Production additionally requires an absolute key
//!    snapshot, an exact match to the reviewed fingerprint policy, and a
//!    final-artifact FSBL↔secure comparison in the release pipeline.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const PRODUCTION_KEY_POLICY: &str = "../config/production-firmware-vendor-key.sha256";
const DEVELOPMENT_VENDOR_KEY: &str = "../config/development-firmware-vendor-pubkey.hex";

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let is_thumbv = target.contains("thumbv");
    let mode_production = env::var_os("CARGO_FEATURE_MODE_PRODUCTION").is_some();
    let legacy_rollback_unsafe = env::var_os("CARGO_FEATURE_LEGACY_FW_ROLLBACK_UNSAFE").is_some();
    let lcd_test = env::var_os("CARGO_FEATURE_LCD_TEST").is_some();

    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MODE_PRODUCTION");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_LCD_TEST");
    println!("cargo:rerun-if-env-changed=FSBL_ALLOW_DEV_KEY");
    println!("cargo:rerun-if-env-changed=PQ_ROLLBACK_MEASUREMENT_PROFILE");
    // Firmware-rollback ship quarantine (FSBL half).  The fence keys on a
    // REACHABLE epoch-bump success path: while the Draft-1.1 rollback
    // candidate is not implementation-approved or implemented
    // (OPEN-OTP-1..3 / OPEN-ECC-1 / OPEN-JRN-HW-1 / OPEN-JRN-DUR-1 open,
    // §14 L4385–4390), no production image may compose with the
    // legacy/unresolved backend, and every bench FSBL build must carry
    // the explicit `legacy-fw-rollback-unsafe` marker so the quarantine
    // cannot go vacuous.  FA-1.5 (§14 L4375) removed the runtime floor
    // writer from the secure world's `cmd_fw_commit`; these FSBL gates
    // are retained unchanged and are negative-control exercised by
    // `fsbl-tests/tests/rollback_ship_fences.rs`.
    //
    // CARVE-OUT (issue #541; stated here per FA-1.5, not left implicit):
    // the named §5 warning-build measurement profile links conservative
    // reservation stubs that fail closed at runtime and therefore has NO
    // reachable epoch-bump success path — it is explicitly not a target
    // of this quarantine.  A green warning build records measurements
    // only and grants no code or hardware authority (§14 L4348–4354).
    if mode_production {
        panic!(
            "FW_ROLLBACK_FSBL_PRODUCTION_BLOCKED: the Draft-1.1 rollback candidate is not implementation-approved or implemented"
        );
    }
    if !legacy_rollback_unsafe {
        panic!(
            "FW_ROLLBACK_FSBL_UNSAFE_OPT_IN_REQUIRED: bench FSBL builds must enable legacy-fw-rollback-unsafe"
        );
    }
    println!(
        "cargo:warning=LEGACY ROLLBACK BACKEND — NONSHIPPING FSBL; Draft 1.1 is an unapproved research candidate"
    );
    if mode_production && env::var_os("CARGO_FEATURE_DEVUNIT_AB").is_some() {
        panic!("FSBL `mode-production` and the dev-unit `devunit-ab` layout are mutually exclusive");
    }
    if mode_production && lcd_test {
        panic!("FSBL `mode-production` and bench-only `lcd-test` are mutually exclusive");
    }
    if mode_production && env::var_os("FSBL_ALLOW_DEV_KEY").is_some() {
        panic!(
            "FSBL_ALLOW_DEV_KEY must be absent in `mode-production`; use the isolated \
             `make fsbl-release` path"
        );
    }

    // --- Linker script (thumbv only) ----------------------------------------
    // Host builds (e.g. `cargo test` for the FSBL integration tests in
    // `fsbl/tests/`) compile the bin only to type-check it / to build
    // build-script outputs; the linker script and on-target link step
    // are not exercised.
    println!("cargo:rerun-if-changed=build.rs");
    if is_thumbv {
        fs::copy("memory-stm32u585.x", out_dir.join("memory.x"))
            .expect("copying memory-stm32u585.x");
        println!("cargo:rustc-link-search={}", out_dir.display());
        println!("cargo:rerun-if-changed=memory-stm32u585.x");
    }

    // --- Vendor pubkey embedding --------------------------------------------
    //
    // Production: FSBL_VENDOR_PUBKEY points at a 32-byte file produced by
    // `fwsign pubkey`. This is the file that will be burned into every
    // production FSBL image; changing it changes the set of releases the
    // device will accept.
    //
    // Dev: if FSBL_VENDOR_PUBKEY is unset with the explicit bench opt-in,
    // read the single public development key under `config/`. `fwsign`
    // independently derives its fixture key and tests equality with that file,
    // so dev FSBLs and dev-signed .pqfw bundles cannot silently drift.
    println!("cargo:rerun-if-env-changed=FSBL_VENDOR_PUBKEY");

    let (pk_seed, pk_root, source_desc): ([u8; 16], [u8; 16], String) = if let Ok(path) =
        env::var("FSBL_VENDOR_PUBKEY")
    {
        if mode_production && !Path::new(&path).is_absolute() {
            panic!(
                "production FSBL_VENDOR_PUBKEY must be an absolute, immutable snapshot path; \
                 got {path:?}. Use `make fsbl-release`."
            );
        }
        println!("cargo:rerun-if-changed={path}");
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        if bytes.len() != 32 {
            panic!(
                "{path}: expected 32 bytes (pk_seed[16] || pk_root[16]), got {}",
                bytes.len()
            );
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        if raw.iter().all(|&byte| byte == 0) {
            panic!(
                "{path}: all-zero FSBL_VENDOR_PUBKEY is the disabled-update \
                     placeholder; refusing an explicitly zero-keyed FSBL"
            );
        }
        if mode_production {
            validate_production_key(&raw, &path);
        }
        let mut s = [0u8; 16];
        let mut r = [0u8; 16];
        s.copy_from_slice(&bytes[..16]);
        r.copy_from_slice(&bytes[16..]);
        (s, r, format!("FSBL_VENDOR_PUBKEY={path}"))
    } else {
        // SECURITY (finding F2): the dev fallback below derives a FIXED,
        // committed SPHINCS+C10 vendor key (the public value is centralized
        // under `config/`). Anyone with the source
        // tree can sign manifests that verify under it, so an FSBL built
        // with this key must NEVER leave the bench. Previously this path
        // only emitted a `cargo:warning` and built anyway — a
        // release-profile FSBL with `FSBL_VENDOR_PUBKEY` unset silently
        // embedded the public dev key. Now the dev fallback is an explicit
        // opt-in: a build with neither the real pubkey nor `FSBL_ALLOW_DEV_KEY`
        // is a hard error. `make fsbl` sets the opt-in for dev convenience;
        // `make fsbl-release` sets neither and provides the real pubkey.
        if mode_production {
            panic!("FSBL_VENDOR_PUBKEY is required for an FSBL `mode-production` build");
        }
        if env::var("FSBL_ALLOW_DEV_KEY").is_err() {
            panic!(
                "FSBL_VENDOR_PUBKEY is unset and FSBL_ALLOW_DEV_KEY is not set. \
                     Refusing to embed the committed development vendor key: an FSBL \
                     built with it accepts firmware signed by anyone holding the \
                     (public, in-tree) dev seed. Provide a real key via \
                     `FSBL_VENDOR_PUBKEY=<32-byte pubkey>` (production, e.g. \
                     `make fsbl-release`), or explicitly opt into the dev key with \
                     `FSBL_ALLOW_DEV_KEY=1` (bench/dev only, e.g. `make fsbl`)."
            );
        }
        println!("cargo:warning=FSBL_VENDOR_PUBKEY unset — using built-in dev fixture key (FSBL_ALLOW_DEV_KEY opt-in). DO NOT USE FOR PRODUCTION.");
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let dev_path = manifest_dir.join(DEVELOPMENT_VENDOR_KEY);
        println!("cargo:rerun-if-changed={}", dev_path.display());
        let dev_text = fs::read_to_string(&dev_path).unwrap_or_else(|e| {
            panic!(
                "reading development firmware key {}: {e}",
                dev_path.display()
            )
        });
        let dev = parse_hex_32(&dev_text, &dev_path.display().to_string());
        (
            dev[..16].try_into().expect("fixed 16-byte pk_seed"),
            dev[16..].try_into().expect("fixed 16-byte pk_root"),
            format!("public development fixture {}", dev_path.display()),
        )
    };

    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&pk_seed);
    bytes[16..].copy_from_slice(&pk_root);

    // Real-vendor-key fence (FA-1.5 follow-up; Draft 1.1 §14 L4376–4390).
    // Keys on the RESOLVED embedded key, covering BOTH the explicit
    // `FSBL_VENDOR_PUBKEY` path and the dev-fixture path above — a real
    // production key placed at the dev fixture's path is fenced exactly
    // like one named by the env var.
    reject_real_key_with_legacy_backend(&bytes, mode_production);

    // Emit a source file with the pubkey as a literal byte array plus
    // its SHA-256 fingerprint. The fingerprint is pre-computed at build
    // time so the FSBL's vendor-fpr check is a plain memcmp at runtime.
    use sha2::{Digest, Sha256};
    let fpr: [u8; 32] = Sha256::digest(&bytes).into();

    let mut src = String::new();
    src.push_str("// AUTO-GENERATED by fsbl/build.rs — do not edit by hand.\n");
    src.push_str(&format!(
        "//\n// Source: {source_desc}\n// SHA-256(pubkey): {}\n\n",
        fpr.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    src.push_str("/// Raw vendor public key: pk_seed[16] || pk_root[16].\n");
    src.push_str(&format!("pub const VENDOR_PUBKEY: [u8; 32] = {bytes:?};\n"));

    fs::write(out_dir.join("vendor_pubkey_bytes.rs"), src).expect("writing vendor_pubkey_bytes.rs");

    // --- Font table for the OLED fingerprint renderer ----------------------
    //
    // FSBL renders the 8-BIP-39-word firmware fingerprint on the OLED
    // BEFORE branching into the slot. It needs an ASCII font; we vendor
    // the same 5×8 raw bitmap the secure-world uses
    // (`secure/assets/font_5x8.raw`, MIT, from embedded-graphics) so the
    // FSBL row and the secure-world `measured_boot` row are visually
    // identical. ~480 bytes of rodata.
    generate_font_flat(&out_dir);
}


// Real-vendor-key fence (FA-1.5 follow-up; Draft 1.1 §14 L4376–4390).
// `mode-production` is panic-blocked in `main()`, but the reviewed
// PRODUCTION vendor key must ALSO never compose with the legacy/unresolved
// rollback backend in any non-mode-production build: the quarantine keys on
// a REACHABLE epoch-bump success path, and today every rollback backend in
// this tree is legacy/unresolved. Scoped EXACTLY to policy-hash equality —
// the dev fixture and any other non-production key build as before.
//
// CARVE-OUT (issue #541; mirrors the quarantine comment in `main()`): the
// named §5 warning-build measurement profile links conservative reservation
// stubs that fail closed at runtime and therefore has NO reachable
// epoch-bump success path — it opts in by setting
// `PQ_ROLLBACK_MEASUREMENT_PROFILE` (any value; unset today) and grants no
// code or hardware authority.
fn reject_real_key_with_legacy_backend(bytes: &[u8; 32], mode_production: bool) {
    use sha2::{Digest, Sha256};
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let policy_path = manifest_dir.join(PRODUCTION_KEY_POLICY);
    println!("cargo:rerun-if-changed={}", policy_path.display());
    let policy = fs::read_to_string(&policy_path).unwrap_or_else(|e| {
        panic!(
            "reading production firmware-key policy {}: {e}",
            policy_path.display()
        )
    });
    // The policy intentionally holds `UNPROVISIONED` before the factory/HSM
    // key ceremony (config/README.md): with no reviewed production
    // fingerprint there is nothing for this fence to match, and every key
    // builds as before. Any OTHER malformed content fails closed in
    // `parse_hex_32`.
    let expected = if policy.trim() == "UNPROVISIONED" {
        None
    } else {
        Some(parse_hex_32(&policy, &policy_path.display().to_string()))
    };
    if !mode_production
        && expected == Some(actual)
        && env::var_os("PQ_ROLLBACK_MEASUREMENT_PROFILE").is_none()
    {
        panic!(
            "FW_ROLLBACK_REAL_KEY_BLOCKED: the embedded vendor key matches the reviewed \
             production vendor-key policy hash. Draft 1.1 §14 L4376–4390 forbids \
             composing the real vendor key with the legacy/unresolved rollback \
             backend in any build (mode-production is separately compile-blocked); \
             only an approved production rollback backend may build with it. The \
             #541 warning-build measurement profile (fail-closed reservation stubs, \
             no reachable epoch-bump success path) opts in when \
             PQ_ROLLBACK_MEASUREMENT_PROFILE is set (unset today)."
        );
    }
}

fn validate_production_key(bytes: &[u8; 32], source_path: &str) {
    if !Path::new(source_path).is_absolute() {
        panic!(
            "production FSBL_VENDOR_PUBKEY must be an absolute, immutable snapshot path; \
             got {source_path:?}. Use `make fsbl-release`."
        );
    }

    use sha2::{Digest, Sha256};
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dev_path = manifest_dir.join(DEVELOPMENT_VENDOR_KEY);
    println!("cargo:rerun-if-changed={}", dev_path.display());
    let dev_text = fs::read_to_string(&dev_path).unwrap_or_else(|e| {
        panic!(
            "reading development firmware key {}: {e}",
            dev_path.display()
        )
    });
    let dev = parse_hex_32(&dev_text, &dev_path.display().to_string());
    if bytes == &dev {
        panic!("refusing the public in-tree development firmware key in a production FSBL");
    }

    let policy_path = manifest_dir.join(PRODUCTION_KEY_POLICY);
    println!("cargo:rerun-if-changed={}", policy_path.display());
    let policy = fs::read_to_string(&policy_path).unwrap_or_else(|e| {
        panic!(
            "reading production firmware-key policy {}: {e}",
            policy_path.display()
        )
    });
    let expected = parse_hex_32(&policy, &policy_path.display().to_string());
    if actual != expected {
        panic!(
            "FSBL_VENDOR_PUBKEY fingerprint does not match reviewed production policy {}: \
             expected {}, got {}",
            policy_path.display(),
            hex_fingerprint(&expected),
            hex_fingerprint(&actual)
        );
    }
}

fn parse_hex_32(text: &str, source: &str) -> [u8; 32] {
    let hex = text.trim();
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        panic!(
            "{source}: expected exactly one lowercase 64-character 32-byte hex value; \
             key policy is not provisioned"
        );
    }
    let mut out = [0u8; 32];
    for (i, dst) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[2 * i]);
        let lo = hex_nibble(hex.as_bytes()[2 * i + 1]);
        *dst = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => unreachable!("validated lowercase hex"),
    }
}

fn hex_fingerprint(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate `glyphs_5x8.rs` in OUT_DIR from `../secure/assets/font_5x8.raw`.
///
/// Output format mirrors `secure/build.rs::generate_font_flat` so the FSBL
/// and the secure world share the same glyph data — only the rendering
/// path differs (FSBL is no_std + minimal, secure-world goes through
/// embedded-graphics). Column-byte format: bit `r` of byte `c` = pixel at
/// column `c`, row `r` (0 = top). Matches SSD1306 page layout so the FSBL
/// blit can OR column-bytes directly into the framebuffer.
fn generate_font_flat(out_dir: &PathBuf) {
    let raw_path = "../secure/assets/font_5x8.raw";
    println!("cargo:rerun-if-changed={raw_path}");

    let raw = fs::read(raw_path)
        .unwrap_or_else(|e| panic!("vendored {raw_path} missing or unreadable: {e}"));

    const BITMAP_W: usize = 80;
    const BITMAP_H: usize = 48;
    const BYTES_PER_ROW: usize = BITMAP_W / 8; // 10
    assert_eq!(
        raw.len(),
        BITMAP_W * BITMAP_H / 8,
        "FONT_5X8 raw must be exactly {} bytes ({}×{}@1bpp); got {}",
        BITMAP_W * BITMAP_H / 8,
        BITMAP_W,
        BITMAP_H,
        raw.len()
    );

    const GLYPH_W: usize = 5;
    const GLYPH_H: usize = 8;
    const CHARS_PER_ROW: usize = 16;
    const FIRST_CHAR: u8 = 0x20;
    const LAST_CHAR: u8 = 0x7F;
    const N_GLYPHS: usize = (LAST_CHAR - FIRST_CHAR + 1) as usize; // 96

    let pixel = |px: usize, py: usize| -> bool {
        let byte = raw[py * BYTES_PER_ROW + px / 8];
        (byte >> (7 - (px % 8))) & 1 != 0
    };

    let mut out = String::new();
    out.push_str(
        "// AUTO-GENERATED by fsbl/build.rs from ../secure/assets/font_5x8.raw.\n\
         // MIT-licensed, vendored from embedded-graphics v0.8.2.\n\
         // See secure/assets/font_5x8.LICENSE for attribution.\n\n",
    );
    out.push_str(&format!(
        "pub const FONT_FIRST_CHAR: u8 = 0x{FIRST_CHAR:02x};\n"
    ));
    out.push_str(&format!(
        "pub const FONT_LAST_CHAR: u8  = 0x{LAST_CHAR:02x};\n"
    ));
    out.push_str(&format!("pub const FONT_GLYPH_W: usize = {GLYPH_W};\n"));
    out.push_str(&format!("pub const FONT_GLYPH_H: usize = {GLYPH_H};\n"));
    out.push_str(&format!("pub const FONT_N_GLYPHS: usize = {N_GLYPHS};\n\n"));
    out.push_str("pub static FONT_FLAT_5X8: [[u8; FONT_GLYPH_W]; FONT_N_GLYPHS] = [\n");

    for ch in FIRST_CHAR..=LAST_CHAR {
        let glyph_idx = (ch - FIRST_CHAR) as usize;
        let glyph_x = (glyph_idx % CHARS_PER_ROW) * GLYPH_W;
        let glyph_y = (glyph_idx / CHARS_PER_ROW) * GLYPH_H;

        let mut cols = [0u8; GLYPH_W];
        for cc in 0..GLYPH_W {
            let mut col_byte: u8 = 0;
            for row in 0..GLYPH_H {
                if pixel(glyph_x + cc, glyph_y + row) {
                    col_byte |= 1u8 << row;
                }
            }
            cols[cc] = col_byte;
        }

        let printable = if ch == b'\\' {
            "\\\\".to_string()
        } else if ch == 0x7F {
            "DEL".to_string()
        } else {
            format!("{}", ch as char)
        };
        out.push_str(&format!(
            "    /* 0x{ch:02x} {printable:>3} */ [0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}],\n",
            cols[0], cols[1], cols[2], cols[3], cols[4]
        ));
    }
    out.push_str("];\n");

    fs::write(out_dir.join("glyphs_5x8.rs"), out).expect("writing glyphs_5x8.rs");
}
