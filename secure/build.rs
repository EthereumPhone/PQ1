use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const PRODUCTION_KEY_POLICY: &str = "../config/production-firmware-vendor-key.sha256";
const DEVELOPMENT_VENDOR_KEY: &str = "../config/development-firmware-vendor-pubkey.hex";

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let is_thumbv = target.contains("thumbv");
    let stm32u585 = env::var_os("CARGO_FEATURE_STM32U585").is_some();
    let mode_production = env::var_os("CARGO_FEATURE_MODE_PRODUCTION").is_some();
    let factory_provisioning = env::var_os("CARGO_FEATURE_FACTORY_PROVISIONING").is_some();
    let legacy_rollback_unsafe = env::var_os("CARGO_FEATURE_LEGACY_FW_ROLLBACK_UNSAFE").is_some();

    // Firmware-rollback ship quarantine.  Keep this in the build script as
    // well as the crate source: it fails before linker/key-policy work can
    // obscure the load-bearing error, and the negative-compilation tests can
    // assert the exact failure reason.  The legacy backend attempted multiple
    // programs of one ECC-protected OTP quad-word, which STM32U585 forbids;
    // FA-1.5 (Draft 1.1 §14 L4375) removed that runtime floor writer from
    // `cmd_fw_commit`, which now refuses fail-closed.
    //
    // The fence keys on a REACHABLE epoch-bump success path: while no
    // reviewed rollback backend exists (OPEN-OTP-1..3 / OPEN-ECC-1 /
    // OPEN-JRN-HW-1 / OPEN-JRN-DUR-1 remain open, §14 L4385–4390), any
    // production, factory, or real-vendor-key image composed with the
    // legacy/unresolved backend must fail here, and Makefile refusals are
    // only defense in depth on top of these build-script panics.
    //
    // CARVE-OUT (issue #541; stated here per FA-1.5, not left implicit):
    // the named §5 warning-build measurement profile links conservative
    // reservation stubs that fail closed at runtime and therefore has NO
    // reachable epoch-bump success path — it is explicitly not a target
    // of this quarantine.  A green warning build records measurements
    // only and grants no code or hardware authority (§14 L4348–4354).
    if is_thumbv && stm32u585 && mode_production {
        panic!(
            "FW_ROLLBACK_PRODUCTION_BLOCKED: the Draft-1.1 rollback candidate is not implementation-approved or implemented"
        );
    }
    if is_thumbv && stm32u585 && factory_provisioning {
        panic!(
            "FW_ROLLBACK_FACTORY_BLOCKED: the factory OTP receipt reprograms one write-once quad-word"
        );
    }
    if is_thumbv && stm32u585 && !legacy_rollback_unsafe {
        panic!(
            "FW_ROLLBACK_UNSAFE_OPT_IN_REQUIRED: non-shipping STM32U585 builds must enable legacy-fw-rollback-unsafe"
        );
    }
    if is_thumbv && stm32u585 && legacy_rollback_unsafe {
        println!(
            "cargo:warning=LEGACY ROLLBACK BACKEND — NONSHIPPING secure firmware; Draft 1.1 is an unapproved research candidate"
        );
    }

    let out_dir_for_font = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Always generate the FONT_5X8 flat table, regardless of target. The
    // table is consumed by `ui/secret_text.rs` which IS host-buildable
    // (under `cfg(test)`) so we can unit-test the constant-time blit on
    // the dev machine without requiring a thumbv8m build.
    generate_font_flat(&out_dir_for_font);

    // When building for the host (cargo test), skip all ARM-specific linker
    // script setup. The unit tests only exercise pure logic (aa, tx) and
    // don't need memory.x or cortex-m-rt's link.x.
    if !target.contains("thumbv") {
        return;
    }

    // Mutually-exclusive UI backend check.
    //
    // Four Display backends, exactly one must be active:
    //   * `ui-semihosting`  QEMU / debugger console
    //   * `ui-noop`         headless
    //   * `ui-lcd`          NV3007 142×428 SPI LCD — the ONLY shipping backend
    //   * `ui-oled-bench`   SSD1306 over bit-banged I2C, BENCH ONLY
    //
    // The SSD1306 backend was removed 2026-06-30 in favour of NV3007-only, and
    // its return is not a reversal of that: `ui-oled-bench` exists because the
    // pq1 production board exposes only a debug header and four pads, so until
    // the NV3007 panel is fitted there is no way to see the trusted UI on the
    // device. It is in the Makefile's PROD_FORBIDDEN list and validates nothing
    // about the shipping display path.
    let ui_semihosting = env::var_os("CARGO_FEATURE_UI_SEMIHOSTING").is_some();
    let ui_noop = env::var_os("CARGO_FEATURE_UI_NOOP").is_some();
    let ui_lcd = env::var_os("CARGO_FEATURE_UI_LCD").is_some();
    let ui_oled_bench = env::var_os("CARGO_FEATURE_UI_OLED_BENCH").is_some();
    let ui_count = ui_semihosting as u32 + ui_noop as u32 + ui_lcd as u32 + ui_oled_bench as u32;
    if ui_count > 1 {
        panic!(
            "UI backends (`ui-semihosting`, `ui-noop`, `ui-lcd`, `ui-oled-bench`) \
             are mutually exclusive"
        );
    }
    if ui_count == 0 {
        panic!(
            "must enable exactly one UI backend (`ui-semihosting`, `ui-noop`, \
             `ui-lcd`, or `ui-oled-bench`)"
        );
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    // Copy the appropriate memory.x for QEMU or real STM32U585
    let mem_x = if stm32u585 {
        "memory-stm32u585.x"
    } else {
        "memory.x"
    };
    fs::copy(mem_x, out_dir.join("memory.x")).unwrap();
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-stm32u585.x");

    // Find cortex-m-rt's link.x. On QEMU we redirect .gnu.sgstubs to a
    // separate NSC region (QEMU 8.2.2 SG workaround). On real STM32U585
    // the veneers stay in FLASH and the SAU marks them NSC — no patching.
    let link_x = find_link_x(&out_dir);
    let modified = if stm32u585 {
        link_x // no patching needed on real hardware
    } else {
        link_x.replace(
            "} > FLASH\n  /* Place `__veneer_limit`",
            "} > NSC\n  /* Place `__veneer_limit`",
        )
    };
    fs::write(out_dir.join("link.x"), modified).unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Vendor pubkey embedding for the firmware-update verifier (C-1 fix).
    //
    // The secure firmware now verifies the SPHINCS+C10 signature on the
    // incoming manifest at BEGIN — same gate FSBL runs at boot. The two
    // must agree on the vendor key; both crates read the same
    // `FSBL_VENDOR_PUBKEY` env var to ensure this by construction.
    //
    // We DO NOT compute the pubkey here (would require sphincs-c10 as
    // a build-dep, which cargo feature-unifies with the target graph
    // and propagates `hw-sha256` to the host build script, breaking
    // its link). Instead, callers MUST point `FSBL_VENDOR_PUBKEY` at
    // a 32-byte file containing `pk_seed[16] || pk_root[16]`. Dev
    // builds can run `make dev-pubkey-fixture` to write one; the
    // Makefile sets the env var for development recipes.
    //
    // For QEMU / host / test builds the fw_update module is gated
    // out (`#[cfg(all(feature = "stm32u585", not(test)))]`), so the
    // pubkey constants are only consumed under stm32u585. We still
    // emit a placeholder file in OUT_DIR so `include!` doesn't break
    // when fw_update is compiled out.
    generate_vendor_pubkey(&out_dir, stm32u585, mode_production);
}

fn generate_vendor_pubkey(out_dir: &PathBuf, stm32u585: bool, mode_production: bool) {
    println!("cargo:rerun-if-env-changed=FSBL_VENDOR_PUBKEY");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MODE_PRODUCTION");
    println!("cargo:rerun-if-env-changed=PQ_ROLLBACK_MEASUREMENT_PROFILE");

    let (bytes, source_desc): ([u8; 32], String) = if let Ok(path) = env::var("FSBL_VENDOR_PUBKEY")
    {
        if stm32u585 && mode_production && !Path::new(&path).is_absolute() {
            panic!(
                "production FSBL_VENDOR_PUBKEY must be an absolute, immutable snapshot path; \
                 got {path:?}. Use `make release`."
            );
        }
        println!("cargo:rerun-if-changed={path}");
        let raw = fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        if raw.len() != 32 {
            panic!(
                "{path}: expected 32 bytes (pk_seed[16] || pk_root[16]), got {}",
                raw.len()
            );
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        if b.iter().all(|&byte| byte == 0) {
            panic!(
                "{path}: all-zero FSBL_VENDOR_PUBKEY is the disabled-update placeholder; \
                 refusing an explicitly zero-keyed firmware verifier"
            );
        }
        // Real-vendor-key fence (FA-1.5 follow-up; Draft 1.1 §14
        // L4376–4390). `stm32u585 + mode-production` is panic-blocked in
        // `main()` above, but the reviewed PRODUCTION vendor key must
        // ALSO never compose with the legacy/unresolved rollback backend
        // in any non-mode-production build: the quarantine keys on a
        // REACHABLE epoch-bump success path, and today every rollback
        // backend in this tree is legacy/unresolved. Scoped EXACTLY to
        // policy-hash equality — the dev fixture and any other
        // non-production key build as before.
        //
        // CARVE-OUT (issue #541; mirrors the quarantine comment in
        // `main()`): the named §5 warning-build measurement profile links
        // conservative reservation stubs that fail closed at runtime and
        // therefore has NO reachable epoch-bump success path — it opts in
        // by setting `PQ_ROLLBACK_MEASUREMENT_PROFILE` (any value; unset
        // today) and grants no code or hardware authority. The fence
        // covers the explicit-key path; the unset stm32u585 branch below
        // embeds zeros (no key at all), so there is nothing to compose.
        {
            use sha2::{Digest, Sha256};
            let actual: [u8; 32] = Sha256::digest(&b).into();
            let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
            let policy_path = manifest_dir.join(PRODUCTION_KEY_POLICY);
            println!("cargo:rerun-if-changed={}", policy_path.display());
            let policy = fs::read_to_string(&policy_path).unwrap_or_else(|e| {
                panic!(
                    "reading production firmware-key policy {}: {e}",
                    policy_path.display()
                )
            });
            // The policy intentionally holds `UNPROVISIONED` before the
            // factory/HSM key ceremony (config/README.md): with no reviewed
            // production fingerprint there is nothing for this fence to
            // match, and every key builds as before. Any OTHER malformed
            // content fails closed in `parse_hex_32`.
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
                    "FW_ROLLBACK_REAL_KEY_BLOCKED: FSBL_VENDOR_PUBKEY matches the reviewed \
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
        if stm32u585 && mode_production {
            validate_production_key(&b, &path);
        }
        (b, format!("FSBL_VENDOR_PUBKEY={path}"))
    } else if stm32u585 {
        if mode_production {
            panic!(
                "FSBL_VENDOR_PUBKEY is required for stm32u585 + mode-production. \
                 Refusing to emit production secure firmware whose update verifier \
                 is permanently keyed to the all-zero disabled-update placeholder."
            );
        }
        // Bench hardware may intentionally build without update credentials.
        // Such an image rejects every manifest and remains clearly marked in
        // its generated source; production is rejected above.
        println!("cargo:warning=FSBL_VENDOR_PUBKEY unset and target=stm32u585 — firmware-update path will reject ALL manifests. Set FSBL_VENDOR_PUBKEY=<path> for production or `make dev-pubkey-fixture` for dev.");
        (
            [0u8; 32],
            "UNSET — placeholder zeros, all manifests will be rejected".to_string(),
        )
    } else {
        // QEMU / non-hardware: fw_update is feature-gated out, so the
        // constants are never read at runtime. Emit zeros to keep
        // include!() syntactically valid.
        (
            [0u8; 32],
            "non-stm32u585 build, fw_update gated out".to_string(),
        )
    };

    use sha2::{Digest, Sha256};
    let fpr: [u8; 32] = Sha256::digest(&bytes).into();

    let mut src = String::new();
    src.push_str("// AUTO-GENERATED by secure/build.rs — do not edit by hand.\n");
    src.push_str(&format!(
        "//\n// Source: {source_desc}\n// SHA-256(pubkey): {}\n\n",
        fpr.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    src.push_str("/// Raw vendor public key: pk_seed[16] || pk_root[16].\n");
    src.push_str(&format!("pub const VENDOR_PUBKEY: [u8; 32] = {bytes:?};\n"));

    fs::write(out_dir.join("vendor_pubkey_bytes.rs"), src).expect("writing vendor_pubkey_bytes.rs");
}

fn validate_production_key(bytes: &[u8; 32], source_path: &str) {
    if !Path::new(source_path).is_absolute() {
        panic!(
            "production FSBL_VENDOR_PUBKEY must be an absolute, immutable snapshot path; \
             got {source_path:?}. Use `make release`, which snapshots the key once for \
             both firmware worlds."
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
        panic!(
            "refusing the public in-tree development firmware key in a production \
             secure-world build"
        );
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

/// Decode the vendored `assets/font_5x8.raw` (embedded-graphics'
/// `MonoFont::FONT_5X8` ASCII variant) into a flat `[[u8; 5]; 96]` table
/// emitted to `OUT_DIR/font_flat.rs`. Consumed by `secure/src/ui/
/// secret_text.rs` for the F-24 constant-time glyph blit.
///
/// The raw file is a 1-bit-per-pixel 80×48 bitmap (480 bytes) laid out
/// as 16 columns × 6 rows of 5×8 glyphs covering ASCII 0x20..=0x7F (96
/// printable chars including DEL). Pixel rows are packed MSB-first
/// into 10 bytes per row (80 / 8). Glyph (ch-0x20) sits at
/// `(px = ((ch-0x20) % 16) * 5, py = ((ch-0x20) / 16) * 8)`.
///
/// Output column-byte format: bit `r` of byte `c` = pixel at column `c`,
/// row `r` (0 = top). Matches the SSD1306 page layout used by
/// `Framebuf::draw_iter`, so the constant-time blit ORs column-bytes
/// directly into the framebuffer.
fn generate_font_flat(out_dir: &PathBuf) {
    let raw_path = "assets/font_5x8.raw";
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

    // Helper: pixel (px, py) of the bitmap = MSB-first bit in
    // `raw[py * BYTES_PER_ROW + px/8]`.
    let pixel = |px: usize, py: usize| -> bool {
        let byte = raw[py * BYTES_PER_ROW + px / 8];
        (byte >> (7 - (px % 8))) & 1 != 0
    };

    let mut out = String::new();
    out.push_str("// AUTO-GENERATED by secure/build.rs — do not edit.\n");
    out.push_str(&format!(
        "// Source: secure/assets/font_5x8.raw (MIT, embedded-graphics v0.8.2,\n\
         //         `fonts/raw/ascii/font_5x8.raw` upstream; vendored verbatim).\n\
         //         See secure/assets/font_5x8.LICENSE for attribution.\n\
         //\n\
         // Layout: glyph for ASCII 0x{FIRST_CHAR:02x}+i at FONT_FLAT_5X8[i].\n\
         //   Each glyph is GLYPH_W (=5) column-bytes; each byte's bit `r`\n\
         //   is the pixel at column .x, row .y=r. Matches SSD1306 page\n\
         //   format so the CT blit can OR directly into the framebuffer.\n\n",
    ));
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

    fs::write(out_dir.join("font_flat.rs"), out).expect("writing font_flat.rs");
}

fn find_link_x(out_dir: &PathBuf) -> String {
    // cortex-m-rt puts link.x in a sibling build directory
    let target_dir = out_dir
        .ancestors()
        .find(|p| p.file_name().map(|f| f == "build").unwrap_or(false))
        .expect("Could not find build directory");

    for entry in fs::read_dir(target_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("cortex-m-rt-") {
            let link_path = entry.path().join("out").join("link.x");
            if link_path.exists() {
                return fs::read_to_string(&link_path).unwrap();
            }
        }
    }
    panic!("Could not find cortex-m-rt's link.x");
}
