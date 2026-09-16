//! Source-text invariants for `pqsigner-fsbl`.
//!
//! `pqsigner-fsbl` is a `[[bin]]` crate with `#![no_std]` / `#![no_main]`
//! / `panic-halt`, so its modules can't be imported into a `cargo test`
//! binary without tripping duplicate `panic_impl` lang items. Instead
//! we read the source files as strings and pin invariants AST-style —
//! same shape as `secure/src/fw_update_boot_pure_tests.rs`.
//!
//! What's pinned here:
//!
//! 1. `fsbl/src/verify.rs::verify_images` returns `Option<[u8; 32]>`
//!    (not `bool`), so the FSBL render path is wired to the same
//!    trusted bytes FSBL verified.
//! 2. `fsbl/src/main.rs` calls `render::render_fingerprint(...)`
//!    AFTER slot selection and BEFORE `branch::into_slot(...)`. This
//!    is the trust-chain property: the user sees FSBL's verdict for
//!    the slot's bytes before the slot ever gets to display anything.
//! 3. `fsbl/src/nv3007.rs` keeps the hardware-validated NV3007 constants
//!    (`X_OFFSET=12`, SWRESET reset, the `delay_ms` nop calibration). The
//!    OLED backend was removed 2026-06-30; only the NV3007 SPI LCD ships, and
//!    each of these pins silently breaks the boot fingerprint render if wrong.
//! 4. `secure/src/measured_boot.rs` still calls `firmware_hash()` —
//!    the secondary self-attested screen survives as defense in depth.
//! 5. The render glue in `fsbl/src/render.rs` uses the bip39 crate's
//!    `firmware_fingerprint_lines`, NOT a separate copy — ensures
//!    FSBL and measured_boot stay byte-identical.

use std::fs;
use std::path::PathBuf;

fn read_workspace_file(rel: &str) -> String {
    // Walk up to the workspace root, same shape as footprint.rs.
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

// ---------------------------------------------------------------------------
// 1. verify_images returns Option<[u8; 32]>
// ---------------------------------------------------------------------------

#[test]
fn negative_verify_images_returns_digest_option() {
    let src = read_workspace_file("fsbl/src/verify.rs");
    assert!(
        src.contains("pub fn verify_images(slot: Slot, m: &ManifestRef) -> Option<[u8; 32]>"),
        "fsbl::verify::verify_images must return Option<[u8; 32]> so the FSBL render path \
         can drive the OLED from the same trusted bytes — not a bool. \
         Got this signature region:\n{}",
        src.lines()
            .filter(|l| l.contains("verify_images"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    // Sanity: the success arm returns Some(actual_secure).
    assert!(
        src.contains("Some(actual_secure)"),
        "verify_images success arm must return Some(actual_secure) (the SHA-256 of the \
         verified secure image)"
    );
    // Sanity: every failure arm returns None.
    let none_returns = src.matches("return None;").count();
    assert!(
        none_returns >= 4,
        "verify_images should return None on each of: oversized secure_len, oversized \
         ns_len, secure-hash mismatch, ns-hash mismatch. Found {} `return None;`.",
        none_returns
    );
}

// ---------------------------------------------------------------------------
// 2. main.rs renders before branching
// ---------------------------------------------------------------------------

#[test]
fn negative_main_renders_fingerprint_before_branching() {
    let src = read_workspace_file("fsbl/src/main.rs");

    let render_idx = src.find("render::render_fingerprint(").expect(
        "fsbl/src/main.rs must call render::render_fingerprint(...) on the success path \
             — that's the trust-root display the slot can't forge",
    );
    let branch_idx = src
        .find("branch::into_slot(slot)")
        .expect("fsbl/src/main.rs must call branch::into_slot(slot) on the success path");
    assert!(
        render_idx < branch_idx,
        "render_fingerprint MUST be invoked BEFORE branch::into_slot. Otherwise the slot's \
         own measured_boot screen would draw FIRST and the user couldn't tell whether the \
         FSBL row was trustworthy. Found render at byte {} and branch at byte {}.",
        render_idx,
        branch_idx
    );
}

// ---------------------------------------------------------------------------
// 2b. tz-1 option-byte tripwire is wired BEFORE the branch, acts on its
//     verdict, and never writes an option byte
//
// Decided KEEP 2026-07-23 (#366 row `tz-1`), specified by Draft 1.2 §3 row 2.
// The FSBL is the only stage that survives a firmware update, so a tripwire
// that is computed-but-ignored, wired after the branch, or that grows a WRITE
// path (Draft 1.2 §1 corollary C1) would be worse than none: it would read as
// coverage while providing none.
// ---------------------------------------------------------------------------

#[test]
fn negative_tz1_tripwire_runs_before_branch_and_never_writes() {
    let src = read_workspace_file("fsbl/src/main.rs");

    let call_idx = src
        .find("optbytes::persistent_confirmed_match()")
        .expect("fsbl/src/main.rs must consult the tz-1 option-byte tripwire (#366 row tz-1)");
    let branch_idx = src
        .find("branch::into_slot(slot)")
        .expect("fsbl/src/main.rs must call branch::into_slot(slot) on the success path");
    assert!(
        call_idx < branch_idx,
        "tz-1 MUST be consulted BEFORE the slot branch (Draft 1.2 §3 row 2): \
         found the tripwire at byte {call_idx} and the branch at byte {branch_idx}"
    );

    // The verdict must GATE the halt in one contiguous block. A version that
    // computes the boolean and drops it type-checks, passes a `contains` check
    // for the call, and tripwires nothing.
    assert!(
        src.contains("if !optbytes::persistent_confirmed_match() {\n        halt();\n    }"),
        "the tz-1 verdict must gate `halt()` in one contiguous block — computing \
         it and ignoring it is a vacuous tripwire"
    );

    let ob = read_workspace_file("fsbl/src/optbytes.rs");
    assert!(
        !ob.contains("write_volatile("),
        "tz-1 must NEVER write an option byte: the FSBL has no option-byte write \
         path and must not grow one (Draft 1.2 §1 corollary C1)"
    );
    assert!(
        ob.contains("lockdown::verify_confirmed_fields(")
            && ob.contains("lockdown::phase_profile("),
        "tz-1 must reuse the shared `lockdown` profile + comparator so this stage \
         and first-boot Phase A cannot drift apart"
    );
    assert_eq!(
        ob.matches("fi::check_true_into_sentinel(confirmed_fields_match)")
            .count(),
        2,
        "tz-1 halts only on a PERSISTENT mismatch — that needs exactly two \
         independent sentinel-gated passes"
    );
    assert!(
        ob.contains("fi::scrub_sentinel_register();"),
        "the paired sentinel callsites need the stale-r0 scrub between them"
    );
}

// ---------------------------------------------------------------------------
// 2c. The FSBL configures SAU before it reads the NS slot image — and that fix
//     is NOT feature-gated, while the stage-marker diagnostic IS.
//
// Measured root cause (2026-09-16): with TZEN=1 and the SAU disabled the whole
// map defaults to Secure, so the FSBL's secure read of the bank-2 NS alias
// (0x0810_0000, NS-watermarked by SECWM2) returns ZEROS. `verify_images` then
// hashes zeros, the NS hash mismatches the signed manifest, no candidate is
// admissible, and the FSBL halts SILENTLY (it has no logging). An instrumented
// build recorded the NS hash the core computed as SHA-256 of 7,488 zero bytes
// while SWD read the same address correctly.
//
// So: `sau::init()` must exist, must run BEFORE any admission step, and must
// ship in every build. The marker module must do the opposite — never ship.
// ---------------------------------------------------------------------------

#[test]
fn negative_fsbl_configures_sau_before_reading_the_ns_slot() {
    let src = read_workspace_file("fsbl/src/main.rs");

    let sau_idx = src
        .find("sau::init();")
        .expect("fsbl/src/main.rs must call sau::init() — without it the core reads the NS slot as ZEROS");
    let verify_idx = src
        .find("verify::verify_images")
        .expect("fsbl/src/main.rs must call verify::verify_images");
    assert!(
        sau_idx < verify_idx,
        "sau::init() MUST run before verify_images reads the NS region: \
         found sau::init at byte {sau_idx}, verify_images at byte {verify_idx}"
    );

    // The fix ships: `mod sau;` carries no cfg gate. A gated fix would make
    // every default build hash zeros again, silently.
    assert!(
        src.contains("mod render;\nmod sau;\n"),
        "`mod sau;` must be declared UNGATED (it is a fix, not a diagnostic)"
    );
    // The diagnostic does not ship.
    assert!(
        src.contains("#[cfg(feature = \"stage-marker\")]\nmod marker;"),
        "`mod marker;` must stay behind the stage-marker feature — it gives the \
         FSBL a flash-write path, which invariant #10 forbids in a shipping image"
    );

    let sau = read_workspace_file("fsbl/src/sau.rs");
    assert!(
        sau.contains("const NS_FLASH_BASE: u32 = 0x0810_0000;")
            && sau.contains("const NS_FLASH_END: u32 = 0x081F_FFFF;"),
        "the SAU NS-flash window must stay the bank-2 alias bounds that \
         secure/src/sau.rs uses"
    );
    assert!(
        sau.contains("(NS_FLASH_END & 0xFFFF_FFE0) | 1"),
        "RLAR must set bit 0 (ENABLE) over the 32-byte-aligned inclusive limit; \
         dropping the enable bit leaves the region inactive and the NS read zeroed"
    );
    assert!(
        !sau.contains("| 1 << 1") && !sau.contains("| 2"),
        "the FSBL's NS-flash region must not be marked NSC (bit 1)"
    );
}

// ---------------------------------------------------------------------------
// 3. FSBL NV3007 LCD driver keeps the hardware-validated constants
//
// The OLED backend was removed 2026-06-30; the boot fingerprint now renders
// on the NV3007 SPI LCD (`fsbl/src/nv3007.rs`, ported from the bench-validated
// secure `ui-lcd` driver). The three pins below each *silently* break the
// render if wrong (advisor's bring-up landmines), so lock them.
// ---------------------------------------------------------------------------

#[test]
fn negative_nv3007_keeps_hardware_validated_constants() {
    let src = read_workspace_file("fsbl/src/nv3007.rs");

    // Production NV3007 BlockWrite gutter — wrong offset = shifted/torn image.
    assert!(
        src.contains("const X_OFFSET: u16 = 12;"),
        "nv3007.rs must keep the production NV3007 X_OFFSET=12 (BlockWrite gutter)"
    );

    // RES is tied to 3V3 on this board, so the panel is reset in software with
    // SWRESET (0x01), NOT a RES pin pulse (which does nothing here).
    assert!(
        src.contains("write_cmd(0x01); // SWRESET"),
        "nv3007.rs must reset via SWRESET (0x01) — RES is tied to 3V3, a pin pulse is a no-op"
    );

    // delay_ms MUST use the FSBL's nop calibration, NOT the secure driver's
    // 160 MHz `cortex_m::asm::delay` — the FSBL brings up no PLL, so the
    // secure form would run orders of magnitude long and read as a boot hang.
    //
    // RESOLVED (2026-09-16): the 4_000/ms constant is calibrated for 16 MHz,
    // but the FSBL runs at 4 MHz. Established from the vendor SVD's reset
    // values — RCC_CFGR1.SW = 00 (MSIS), RCC_CSR.MSISSRANGE = 4, and the SVD's
    // own enumeration "range 4 around 4 MHz (reset value)" — with ICSCR1's
    // MSISRANGE independently also 4, so MSIRGSEL does not change it. The
    // constant is therefore ~4× long, which is the SAFE direction for panel
    // init, and is pinned here rather than retuned so validated iota2 timing
    // does not move. The user-visible consequence is that render.rs's 3,000 ms
    // fingerprint hold is really ~12 s — an owner decision, not a cleanup.
    assert!(
        src.contains("for _ in 0..4_000 {"),
        "nv3007::delay_ms must use the FSBL's nop calibration (4_000/ms), not the \
         secure driver's 160 MHz cortex_m::asm::delay"
    );
}

// ---------------------------------------------------------------------------
// 3b. The FSBL LCD is board-parameterised, and the board map cannot drift
//
// `pq1` bonds only PA0-15/PB0-15/PC13. Port E exists on the die but drives
// nothing there, so the pre-port driver's hardcoded `GPIOE` writes SUCCEEDED
// and moved no pads: the FSBL rendered nothing and branched anyway, silently
// dropping the boot-fingerprint window invariant #10 rests on. These pins keep
// the parameterisation in place and keep the FSBL's board map in step with the
// secure world's.
// ---------------------------------------------------------------------------

#[test]
fn negative_fsbl_lcd_is_board_parameterised_not_hardcoded_to_port_e() {
    let src = read_workspace_file("fsbl/src/nv3007.rs");

    // Negative control: the old hardcoded port/pin constants must be GONE.
    for gone in [
        "const GPIOE_S: usize",
        "const GPIOE_MODER: usize",
        "const GPIOE_AFRH: usize",
        "const CS_PIN: u32 = 12;",
        "const DC_PIN: u32 = 7;",
    ] {
        assert!(
            !src.contains(gone),
            "nv3007.rs still hardcodes `{gone}` — the LCD pin map must come from \
             `crate::board`, or a pq1 build drives port E, which is unbonded on \
             its 48-pin package and fails SILENTLY"
        );
    }

    // Positive: pins, port bases and the AF number all come from the board.
    for needed in [
        "use crate::board;",
        "const SPI_PORT: u32 = board::LCD_SPI_PORT;",
        "const CS_PIN: u32 = board::LCD_CS_PIN;",
        "const DC_PORT: u32 = board::LCD_DC_PORT;",
        "const RES_PORT: u32 = board::LCD_RST_PORT;",
        "board::gpio_rcc_bit(SPI_PORT)",
        "board::afr_off(pin)",
        "config_af_pin(board::LCD_SCK_PIN);",
        "config_af_pin(board::LCD_MOSI_PIN);",
    ] {
        assert!(
            src.contains(needed),
            "nv3007.rs must derive its LCD pin map from `crate::board` — missing `{needed}`"
        );
    }

    // `afr_off` is the fix for the specific silent failure that pq1's pins are
    // below 8 (AFRL) while iota2's are 12..15 (AFRH).
    let board_mod = read_workspace_file("fsbl/src/board/mod.rs");
    assert!(
        board_mod.contains("if pin < 8 {") && board_mod.contains("0x20"),
        "board::afr_off must select AFRL (0x20) for pins below 8 — pq1's LCD pins \
         are 4/5/7 and the pre-port driver wrote AFRH unconditionally"
    );

    // Both reset paths are present and selected by a const, so the unused arm
    // is dead-code-eliminated rather than reachable on the wrong board.
    assert!(
        src.contains("if board::LCD_RST_IS_DRIVABLE {") && src.contains("hard_reset();"),
        "nv3007.rs must choose the reset path from `board::LCD_RST_IS_DRIVABLE` — \
         iota2's RES is strapped to 3V3 (SWRESET), pq1 drives LCM_RST on PB1"
    );
    // pq1's pulse must match the timings validated in the secure driver.
    assert!(
        src.contains("res_high();")
            && src.contains("delay_ms(10);")
            && src.contains("res_low();")
            && src.contains("delay_ms(200);")
            && src.contains("delay_ms(120);"),
        "nv3007::hard_reset must mirror secure/src/hw/lcd_nv3007.rs::hard_reset \
         (high 10 ms, low 200 ms, high 120 ms)"
    );
}

#[test]
fn negative_fsbl_board_selection_is_mandatory_and_unconditional() {
    let src = read_workspace_file("fsbl/src/board/mod.rs");

    // Both fences must exist.
    assert!(
        src.contains("FSBL_BOARD_UNSET"),
        "board/mod.rs must hard-error when NO board feature is set"
    );
    assert!(
        src.contains("FSBL_BOARD_AMBIGUOUS"),
        "board/mod.rs must hard-error when BOTH board features are set"
    );

    // The critical property: the no-board fence must NOT be gated on a
    // platform feature. The secure world's equivalent is wrapped in
    // `cfg(all(feature = "stm32u585", ...))`; the FSBL has no such feature, so
    // copying that form would produce a fence that can never fire — the exact
    // silent-guard bug that put iota2 pins on pq1 silicon via a recipe with a
    // hardcoded --features list.
    let unset_fence = src
        .split("FSBL_BOARD_UNSET")
        .next()
        .expect("split always yields a first element");
    let guard = unset_fence
        .rfind("#[cfg(")
        .map(|i| &unset_fence[i..])
        .unwrap_or("");
    assert!(
        !guard.contains("stm32u585"),
        "the FSBL's no-board fence must be UNCONDITIONAL — gating it on a platform \
         feature the FSBL does not have makes it unreachable. Guard found: {guard}"
    );
}

#[test]
fn negative_fsbl_board_map_matches_the_secure_board_map() {
    // The FSBL keeps a deliberately narrow COPY of the secure world's board
    // map (LCD facts only), because hoisting the secure map into a shared
    // crate would break the nine `include_str!` pins that read
    // `secure/src/board/*.rs` by relative path. Drift is therefore caught
    // here rather than prevented by construction: every `pub const LCD_` line
    // in the FSBL's copy must appear VERBATIM in the secure file for the same
    // board. Subset, not equality — the secure map also carries LCD_TE and
    // much else the FSBL has no use for.
    for board in ["iota2", "pq1"] {
        let fsbl_src = read_workspace_file(&format!("fsbl/src/board/{board}.rs"));
        let secure_src = read_workspace_file(&format!("secure/src/board/{board}.rs"));

        let lcd_lines: Vec<&str> = fsbl_src
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("pub const LCD_"))
            .collect();

        assert!(
            lcd_lines.len() >= 10,
            "fsbl/src/board/{board}.rs should declare the full LCD pin set; found only {} \
             `pub const LCD_` lines — did a constant get renamed out of the drift check?",
            lcd_lines.len()
        );

        for line in lcd_lines {
            assert!(
                secure_src.lines().map(str::trim).any(|s| s == line),
                "fsbl/src/board/{board}.rs and secure/src/board/{board}.rs have DRIFTED.\n\
                 This line is in the FSBL's copy but not in the secure map:\n    {line}\n\
                 The two must agree: the FSBL renders the boot fingerprint the secure \
                 world re-renders, on the same physical panel. Update whichever copy is \
                 wrong — do not relax this test."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. measured_boot still calls firmware_hash() (defense in depth)
// ---------------------------------------------------------------------------

#[test]
fn negative_secure_measured_boot_still_self_attests() {
    let src = read_workspace_file("secure/src/measured_boot.rs");
    assert!(
        src.contains("let hash = firmware_hash();"),
        "secure/src/measured_boot.rs must still compute its own firmware_hash() — the \
         secure-world screen is advisory (self-attested) and serves as defense in depth \
         against the FSBL display. Removing it would lose the divergence-tamper signal."
    );
    assert!(
        src.contains("use sphincs_tz_bip39::firmware_fingerprint_lines;"),
        "secure measured_boot must import the same pure renderer as FSBL"
    );
    assert!(
        src.contains("let rows = firmware_fingerprint_lines(hash);"),
        "secure measured_boot must use the shared renderer for its display rows"
    );
    assert!(
        src.contains("render_all_words(&hash);"),
        "measured_boot::run must pass its self-measured firmware hash directly to the shared renderer"
    );
}

// ---------------------------------------------------------------------------
// 5. render.rs uses bip39's pure function (no separate copy)
// ---------------------------------------------------------------------------

#[test]
fn negative_render_glue_uses_bip39_pure_function() {
    let src = read_workspace_file("fsbl/src/render.rs");
    assert!(
        src.contains("use sphincs_tz_bip39::firmware_fingerprint_lines"),
        "fsbl/src/render.rs must import firmware_fingerprint_lines from sphincs_tz_bip39. \
         If render keeps its own copy of the layout logic, FSBL and measured_boot risk \
         drifting (different bytes for the same digest), which silently breaks the \
         user-side comparison workflow."
    );
    assert!(
        src.contains("firmware_fingerprint_lines(digest)"),
        "render_fingerprint must call firmware_fingerprint_lines(digest) — that's the \
         shared pure-logic entry point"
    );
}

// Track this so its path stays stable even if the workspace shuffles.
#[test]
fn positive_workspace_layout_sanity() {
    let _ = PathBuf::from("fsbl/src/render.rs");
    let _ = PathBuf::from("fsbl/src/verify.rs");
    let _ = PathBuf::from("fsbl/src/main.rs");
    let _ = PathBuf::from("fsbl/src/nv3007.rs");
    let _ = PathBuf::from("secure/src/measured_boot.rs");
}

// ---------------------------------------------------------------------------
// 6. Production firmware-update key agreement is artifact-proven
// ---------------------------------------------------------------------------

#[test]
fn negative_production_fsbl_cannot_use_missing_zero_relative_or_dev_key() {
    let build = read_workspace_file("fsbl/build.rs");
    let cargo = read_workspace_file("fsbl/Cargo.toml");
    for landmark in [
        "CARGO_FEATURE_MODE_PRODUCTION",
        "FSBL_VENDOR_PUBKEY is required",
        "all-zero FSBL_VENDOR_PUBKEY",
        "absolute, immutable snapshot path",
        "DEVELOPMENT_VENDOR_KEY",
        "production-firmware-vendor-key.sha256",
    ] {
        assert!(
            build.contains(landmark),
            "FSBL release gate lost `{landmark}`"
        );
    }
    assert!(cargo.contains("mode-production = []"));
}

#[test]
fn negative_release_is_quarantined_or_final_artifacts_agree_on_vendor_key() {
    let vendor = read_workspace_file("fsbl/src/vendor_pubkey.rs");
    let makefile = read_workspace_file("Makefile");
    let verifier = read_workspace_file("fwsign/src/artifact_key.rs");
    assert!(vendor.contains(".pqsigner.vendor_pubkey"));
    assert!(vendor.contains("PQSIGNER_FSBL_VENDOR_PUBKEY"));
    assert!(vendor.contains("pub fn key_parts()"));
    if makefile.contains("release: FAIL — production firmware rollback backend is not implemented")
    {
        // While rollback is an explicit NO-GO, no release/package recipe may
        // delete or publish artifacts after `make -i` ignores a failing line.
        let quarantine = makefile
            .split(".PHONY: release _release")
            .nth(1)
            .and_then(|tail| tail.split("# Hardware bring-up test").next())
            .expect("release quarantine block");
        for forbidden in ["rm -", "cp ", "mv ", "verify-repro", "verify-artifact-keys"] {
            assert!(
                !quarantine.contains(forbidden),
                "quarantined release block must not retain executable `{forbidden}`"
            );
        }
        assert!(quarantine.contains("_release: REFUSED"));
    } else {
        for landmark in [
            "RELEASE_VENDOR_KEY_SNAPSHOT",
            "target/release-fsbl",
            "verify-artifact-keys",
            "PRODUCTION_VENDOR_KEY_POLICY",
            "RELEASE_ARTIFACT_TMP",
            "target/pqsigner-release",
            "sha256sum -c SHA256SUMS",
        ] {
            assert!(
                makefile.contains(landmark),
                "release pipeline lost `{landmark}`"
            );
        }
    }
    assert!(verifier.contains("FSBL == secure == reviewed policy"));
    assert!(verifier.contains("VENDOR_KEY_SECTION"));
    assert!(verifier.contains(".pqsigner.vendor_pubkey"));
    assert!(verifier.contains("expected a little-endian ARM ELF32 executable"));
    assert!(verifier.contains("read-only PT_LOAD"));
    assert!(verifier.contains("verify_secure_flat_image"));
    assert!(verifier.contains("signing key does not match firmware artifacts/policy"));
}
