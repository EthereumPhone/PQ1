use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
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
    // `ui-lcd` is the NV3007/ZT165M017AT SPI LCD low-level driver
    // (Phase A landed 2026-05-19). It does NOT yet implement the
    // `ui::Display` trait — that's Phase C. For Phase A/B (driver
    // bring-up on bench hardware), `ui-lcd` is paired with one of
    // the existing display backends so the Display trait still
    // resolves; the existing backend handles the wizard UI while
    // `hw::lcd_nv3007` runs as a parallel raw-primitive surface.
    // Once Phase C lands, `ui-lcd` will become a Display backend in
    // its own right and this build check will gain a fourth arm.
    let ui_semihosting = env::var_os("CARGO_FEATURE_UI_SEMIHOSTING").is_some();
    let ui_oled = env::var_os("CARGO_FEATURE_UI_OLED").is_some();
    let ui_noop = env::var_os("CARGO_FEATURE_UI_NOOP").is_some();
    let ui_count = ui_semihosting as u32 + ui_oled as u32 + ui_noop as u32;
    if ui_count > 1 {
        panic!("UI backends (`ui-semihosting`, `ui-oled`, `ui-noop`) are mutually exclusive");
    }
    if ui_count == 0 {
        panic!("must enable exactly one UI backend (`ui-semihosting`, `ui-oled`, or `ui-noop`)");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stm32u585 = env::var_os("CARGO_FEATURE_STM32U585").is_some();

    // Copy the appropriate memory.x for QEMU or real STM32U585
    let mem_x = if stm32u585 { "memory-stm32u585.x" } else { "memory.x" };
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

    // Pre-compute the companion-app QR code when the qr-screen-test feature
    // is active. Writes `qr_matrix.rs` into OUT_DIR for inclusion from
    // `ui/oled.rs`. Keeps the embedded binary heap-free — all QR encoding
    // happens on the host at build time.
    if env::var_os("CARGO_FEATURE_QR_SCREEN_TEST").is_some() {
        generate_qr_matrix(&out_dir);
    }

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
    generate_vendor_pubkey(&out_dir, stm32u585);
}

fn generate_vendor_pubkey(out_dir: &PathBuf, stm32u585: bool) {
    println!("cargo:rerun-if-env-changed=FSBL_VENDOR_PUBKEY");

    let (bytes, source_desc): ([u8; 32], String) = if let Ok(path) = env::var("FSBL_VENDOR_PUBKEY") {
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
        (b, format!("FSBL_VENDOR_PUBKEY={path}"))
    } else if stm32u585 {
        // Building for real hardware without a pubkey is a footgun: the
        // resulting binary would silently accept ANY manifest as
        // legitimately signed (against zero key), so flip the placeholder
        // bits to a value the firmware can sanity-check at runtime.
        // The `verify_signature` call will reject any real signature
        // against an all-zero pk because the C10 verifier returns false
        // for the all-zero key.
        println!("cargo:warning=FSBL_VENDOR_PUBKEY unset and target=stm32u585 — firmware-update path will reject ALL manifests. Set FSBL_VENDOR_PUBKEY=<path> for production or `make dev-pubkey-fixture` for dev.");
        ([0u8; 32], "UNSET — placeholder zeros, all manifests will be rejected".to_string())
    } else {
        // QEMU / non-hardware: fw_update is feature-gated out, so the
        // constants are never read at runtime. Emit zeros to keep
        // include!() syntactically valid.
        ([0u8; 32], "non-stm32u585 build, fw_update gated out".to_string())
    };

    use sha2::{Digest, Sha256};
    let fpr: [u8; 32] = Sha256::digest(&bytes).into();

    let mut src = String::new();
    src.push_str("// AUTO-GENERATED by secure/build.rs — do not edit by hand.\n");
    src.push_str(&format!(
        "//\n// Source: {source_desc}\n// SHA-256(pubkey): {}\n\n",
        fpr.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    src.push_str("/// Vendor pk_seed (first 16 bytes of the 32-byte pubkey).\n");
    src.push_str(&format!("pub const VENDOR_PK_SEED: [u8; 16] = {:?};\n", &bytes[..16]));
    src.push_str("/// Vendor pk_root (last 16 bytes of the 32-byte pubkey).\n");
    src.push_str(&format!("pub const VENDOR_PK_ROOT: [u8; 16] = {:?};\n", &bytes[16..]));
    src.push_str(
        "/// SHA-256(pk_seed || pk_root). Pre-computed at build time so\n\
        /// the runtime vendor-fpr check is a memcmp.\n",
    );
    src.push_str(&format!("pub const VENDOR_PK_FPR: [u8; 32] = {:?};\n", fpr));

    fs::write(out_dir.join("vendor_pubkey_bytes.rs"), src)
        .expect("writing vendor_pubkey_bytes.rs");
}

fn generate_qr_matrix(out_dir: &PathBuf) {
    use qrcodegen::{QrCode, QrCodeEcc};
    const URL: &str = "freedomfactory.io";

    let qr = QrCode::encode_text(URL, QrCodeEcc::Low).expect("QR encode failed");
    let n = qr.size() as usize;

    let mut out = String::new();
    out.push_str("// AUTO-GENERATED by build.rs — do not edit.\n");
    out.push_str(&format!("pub const QR_URL: &str = {:?};\n", URL));
    out.push_str(&format!("pub const QR_SIZE: usize = {n};\n"));
    out.push_str(&format!("pub const QR_MODULES: [[bool; {n}]; {n}] = [\n"));
    for y in 0..n {
        out.push_str("    [");
        for x in 0..n {
            out.push_str(if qr.get_module(x as i32, y as i32) { "true," } else { "false," });
        }
        out.push_str("],\n");
    }
    out.push_str("];\n");
    fs::write(out_dir.join("qr_matrix.rs"), out).unwrap();
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

    let raw = fs::read(raw_path).unwrap_or_else(|e| {
        panic!("vendored {raw_path} missing or unreadable: {e}")
    });

    const BITMAP_W: usize = 80;
    const BITMAP_H: usize = 48;
    const BYTES_PER_ROW: usize = BITMAP_W / 8; // 10
    assert_eq!(raw.len(), BITMAP_W * BITMAP_H / 8,
        "FONT_5X8 raw must be exactly {} bytes ({}×{}@1bpp); got {}",
        BITMAP_W * BITMAP_H / 8, BITMAP_W, BITMAP_H, raw.len());

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
    out.push_str(&format!("pub const FONT_FIRST_CHAR: u8 = 0x{FIRST_CHAR:02x};\n"));
    out.push_str(&format!("pub const FONT_LAST_CHAR: u8  = 0x{LAST_CHAR:02x};\n"));
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

        let printable = if ch == b'\\' { "\\\\".to_string() } else if ch == 0x7F { "DEL".to_string() } else { format!("{}", ch as char) };
        out.push_str(&format!(
            "    /* 0x{ch:02x} {printable:>3} */ [0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x}],\n",
            cols[0], cols[1], cols[2], cols[3], cols[4]
        ));
    }
    out.push_str("];\n");

    fs::write(out_dir.join("font_flat.rs"), out)
        .expect("writing font_flat.rs");
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
