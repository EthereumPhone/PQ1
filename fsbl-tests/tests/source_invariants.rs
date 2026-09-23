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

/// Source text with `//`-comment lines removed, for pins that must match CODE
/// rather than prose.
///
/// This exists because the mistake it prevents happened three times in one
/// afternoon: a `!contains(...)` pin fires on the very doc comment that
/// explains why the thing is forbidden. A text pin cannot tell a prohibition
/// from the thing prohibited. The wrong fix is to weaken the pattern until it
/// stops matching the comment — that leaves a pin which passes for the wrong
/// reason. Strip the comments instead, and keep the pattern exact.
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

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
    // The hazard is the SECURE driver's form, `cortex_m::asm::delay(160_000 *
    // ms)`, which assumes the 160 MHz PLL the FSBL never brings up. Do NOT
    // broaden this to forbid `cortex_m::asm::delay` outright: `spi_end` uses
    // `cortex_m::asm::delay(16)` as the ES0499 mitigation (let the last SCK
    // pulse finish before dropping SPE), which is legitimate and
    // clock-INVARIANT — SCK derives from the core clock through the same
    // `MBR = ÷4`, so 16 core cycles is ~4 SCK periods at 4 MHz or 16 MHz
    // alike. A blanket negative here failed on that line the first time.
    // Match CODE, not prose — see `code_only`. This assertion fired on
    // `delay_ms`'s own doc comment, which quotes the forbidden form verbatim
    // in order to explain why it is forbidden.
    let src_code = code_only(&src);
    assert!(
        !src_code.contains("asm::delay(160_000"),
        "nv3007::delay_ms must not use the secure driver's 160 MHz \
         `cortex_m::asm::delay(160_000 * ms)` form — the FSBL brings up no PLL"
    );
    assert!(
        src.contains("cortex_m::asm::nop();"),
        "nv3007::delay_ms must stay a nop-counted loop"
    );

    // The calibration must be DERIVED from the clock actually achieved, never
    // a hardcoded iteration count. This pin replaced a literal `4_000` pin on
    // 2026-09-16, because that literal was itself the bug: it assumed 4
    // cycles/iteration at 16 MHz, while the part ran at 4 MHz with a measured
    // 8.00 cycles/iteration, so every delay was 8x nominal — 78% of a 39.4 s
    // boot was this loop spinning.
    //
    // Deriving it is also a SAFETY property, not just tidiness. `clock::init`
    // can fail and fall back to MSIS; a constant calibrated for 16 MHz would
    // then run every NV3007 reset / SLPOUT / DISPON wait 4x SHORT, which is
    // the one direction that violates a vendor minimum. Pinning the derivation
    // keeps a failed clock switch merely slow instead of unsafe.
    assert!(
        src.contains("crate::clock::achieved_hz() / (1_000 * CYCLES_PER_ITER)"),
        "nv3007::delay_ms must derive its iteration count from the ACHIEVED clock \
         (`clock::achieved_hz()`), not from a hardcoded constant — a constant that \
         disagrees with the real clock has already produced both an 8x-long boot and \
         (on a failed clock switch) would produce 4x-short panel delays"
    );
    assert!(
        src.contains("const CYCLES_PER_ITER: u32 = 8;"),
        "the measured loop cost (8.00 cycles/iteration on pq1, pinned by a 3,000 ms \
         nominal hold taking 24.003 s at 4 MHz) must stay explicit — it is the one \
         empirical input to the calibration"
    );

    // And the clock module itself must stay BOUNDED. The FSBL becomes
    // permanently unpatchable once WRP + RDP-2 land (invariant #10), so an
    // unbounded spin on a clock-ready flag is a potential brick. The secure
    // world's `rcc.rs` spins unbounded, which is fine there and NOT here.
    // `clk_code` for the negative pins, raw `clk` for the positive ones: the
    // module header documents the FLASH_ACR / VOS / `static mut` constraints in
    // prose, so matching those words against the whole file fires on the
    // explanation rather than on code. Both of the negatives below did exactly
    // that before this was applied.
    let clk = read_workspace_file("fsbl/src/clock.rs");
    let clk_code = code_only(&clk);
    assert!(
        clk.contains("const SPIN_LIMIT: u32") && clk.contains("if spins > SPIN_LIMIT"),
        "fsbl::clock must bound every readiness spin and give up on timeout — an \
         unbounded wait here can brick a die whose FSBL is frozen by WRP + RDP-2. \
         (secure/src/hw/rcc.rs spins unbounded, which is fine there and NOT here.)"
    );
    assert!(
        !clk_code.contains("FLASH_ACR") && !clk_code.contains("VOS"),
        "fsbl::clock must NOT touch flash latency or voltage scaling: 16 MHz is safe \
         at reset VOS and reset latency (secure/src/hw/rcc.rs switches to HSI16 before \
         configuring either), and every extra register poked in the trust root is risk"
    );

    // No mutable state in this module, for an image-layout reason that cost a
    // failed geometry gate: the first version latched the achieved frequency in
    // a `static mut` initialised to MSIS_HZ. A non-zero initialiser puts it in
    // `.data`, which becomes a SECOND LOAD segment, and
    // `scripts/check_fsbl_geometry.py` fails on more than one — the physical
    // span and the derived WRP page range are only trustworthy for a
    // single-segment image (invariant #10 leans on that derivation). `.bss`
    // costs a segment too. Reading `CFGR1.SWS` costs none, and is also the more
    // honest answer: it reports the clock in use rather than a remembered one.
    assert!(
        !clk_code.contains("static mut"),
        "fsbl::clock must hold NO mutable state — a `static mut` with a non-zero \
         initialiser lands in .data and creates a second LOAD segment, which fails \
         the FSBL geometry gate. Derive the clock from CFGR1.SWS instead."
    );
    assert!(
        clk.contains("pub fn achieved_hz() -> u32") && clk.contains("SWS_MASK == SWS_HSI16"),
        "fsbl::clock::achieved_hz must read the live CFGR1.SWS, so a failed clock \
         switch yields LONGER nop delays (safe) rather than 4x-short panel waits"
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

        // The AW99703 transport constants (#705), pq1 only. Asserted BY EXACT
        // NAME rather than added to the `pub const LCD_` sweep above, for two
        // reasons: they do not share that prefix, and the sweep is guarded by a
        // `>= 10` floor, which cannot notice a constant being deleted. A named
        // list can. If one of these is renamed, fix the name here — do not drop
        // the entry.
        if board == "pq1" {
            for name in [
                "AUX_I2C_PORT",
                "AUX_I2C_SCL_PIN",
                "AUX_I2C_SDA_PIN",
                "BACKLIGHT_I2C_ADDR",
            ] {
                let line = fsbl_src
                    .lines()
                    .map(str::trim)
                    .find(|l| l.starts_with(&format!("pub const {name}")))
                    .unwrap_or_else(|| {
                        panic!(
                            "fsbl/src/board/pq1.rs must declare `{name}` — the FSBL's I2C                              stage (#705) drives the backlight through it, and a pin map                              that exists in only one of the two copies is how the wrong                              pins reach silicon."
                        )
                    });
                assert!(
                    secure_src.lines().map(str::trim).any(|s| s == line),
                    "fsbl/src/board/pq1.rs and secure/src/board/pq1.rs have DRIFTED on                      `{name}`.\nThis line is in the FSBL's copy but not in the secure                      map:\n    {line}\nBoth drive the SAME physical AW99703 on the SAME                      bus. Update whichever copy is wrong — do not relax this test."
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3b. The display verdict gates the branch (#705 recoverable fail-closed)
// ---------------------------------------------------------------------------

/// The FSBL must refuse to hand off to the slot when the fingerprint render
/// failed. Owner decision (#705): **recoverable fail-closed**.
///
/// Proceeding instead would mean the immutable stage detected that the display
/// failed and branched anyway — so the first screen the user ever sees comes
/// from the updatable firmware this stage exists to check. That is the
/// forged-fingerprint hole invariant #10 closes, and it was explicitly
/// rejected; the driver's own comment used to argue FOR it ("booting beats
/// hanging"), which is why this is pinned rather than left to a code comment.
///
/// The vacuity trap this is shaped around: a version that computes the verdict
/// and drops it compiles, passes a `contains` check for the call, and gates
/// nothing. So the gate is asserted as one contiguous block, the same trick
/// `negative_tz1_tripwire_runs_before_branch_and_never_writes` uses.
#[test]
fn negative_main_gates_branch_on_display_verdict() {
    let src = read_workspace_file("fsbl/src/main.rs");

    let verdict_idx = src
        .find("let display_verdict = render::render_fingerprint(&secure_digest);")
        .expect(
            "fsbl/src/main.rs must BIND the render verdict — calling \
             render_fingerprint and discarding its result is the plain-proceed \
             policy that #705 rejected",
        );
    let branch_idx = src
        .find("branch::into_slot(slot)")
        .expect("fsbl/src/main.rs must call branch::into_slot(slot) on the success path");
    assert!(
        verdict_idx < branch_idx,
        "the display verdict must be computed BEFORE the slot branch: found the \
         verdict at byte {verdict_idx} and the branch at byte {branch_idx}"
    );

    assert!(
        src.contains("if display_verdict != fi::OK_SENTINEL {"),
        "the verdict must be compared against fi::OK_SENTINEL — a bare truthiness \
         check would accept a glitched return value"
    );
    let gate = &src[verdict_idx..branch_idx];
    assert!(
        gate.contains("halt();"),
        "the display verdict must gate `halt()` between the render and the \
         branch; computing it and ignoring it is a vacuous fail-closed policy"
    );

    // Recoverable, not a latch. A durable fault record would turn a transient
    // failure into a permanent brick in code the RDP-2 self-lock freezes —
    // strictly worse than the plain halt this policy was chosen over.
    //
    // Matched on CODE ONLY. The first version of this check scanned the raw
    // file for "flash" and tripped on the prose "every build ever flashed" —
    // an over-broad matcher asserting something it could not see.
    //
    // `marker::record` is deliberately NOT forbidden: it is `stage-marker`,
    // default-off and bench-only, and the refusal path records through it on
    // purpose so a bench run can tell a display refusal from any other halt.
    let render = read_workspace_file("fsbl/src/render.rs");
    let render_code = code_only(&render);
    for forbidden in ["write_volatile", "boot_state", "crate::otp"] {
        assert!(
            !render_code.contains(forbidden),
            "fsbl/src/render.rs must persist NO state on the refusal path \
             (found `{forbidden}` in code): the policy is recoverable \
             fail-closed, so a power-cycle must retry from an identical state"
        );
    }

    // On failure the hold must be SKIPPED — ten seconds of blank screen before
    // a refusal teaches nothing and delays the only recovery there is.
    let fail_idx = render
        .find("return 0;")
        .expect("render_fingerprint must return a non-OK verdict on failure");
    let hold_idx = render
        .find("delay_ms(FINGERPRINT_HOLD_MS);")
        .expect("render_fingerprint must hold the fingerprint on the success path");
    assert!(
        fail_idx < hold_idx,
        "the failure return must come BEFORE the fingerprint hold: found the \
         return at byte {fail_idx} and the hold at byte {hold_idx}"
    );
}

/// The FSBL's I2C leg gates the boot, and must keep the safety rails that
/// made arming it survivable.
///
/// ARMED 2026-09-23. It was a staged rollout until then: the secure world had
/// confirmed the read-backs on silicon (#705, `ID03 B1=26 MO=15`) but the
/// FSBL's transport is a different code path — a fixed 40-cycle bit-bang
/// quarter-period at HSI16 against the secure world's 400 sized for 160 MHz —
/// so that receipt licensed the VALUES, not the TIMING. A marker-FSBL run on
/// bench board `002F0023 30465002 2033314C` then recorded stage 18 =
/// `0x00032615` from THIS transport, which closed the gap.
///
/// The asymmetry that made the staging worth it has not gone away: a constant
/// that mismatches on HEALTHY silicon means every unit refuses handoff
/// forever, unfixable once the RDP-2 self-lock freezes it, and strictly worse
/// than the plain halt the owner rejected. What this test now pins is the set
/// of properties that keep that from happening — the ones an innocent-looking
/// edit to the driver would break.
#[test]
fn negative_fsbl_i2c_leg_stays_within_its_safety_rails() {
    let render = read_workspace_file("fsbl/src/render.rs");
    let render_code = code_only(&render);
    assert!(
        render.contains("let backlight_on = lcd.backlight_on();"),
        "render must still CALL backlight_on — the illuminate-last step (#730) \
         is what keeps undefined GRAM from being lit"
    );
    assert!(
        render_code.contains("ok &= backlight_on;"),
        "the backlight verdict must stay FOLDED INTO the display verdict: a \
         dark panel is the failure invariant #10's boot-time window cannot \
         absorb, so it refuses handoff like any failed SPI transfer"
    );
    assert!(
        !render_code.contains("let _ = backlight_on"),
        "the backlight verdict must not be discarded again — it was armed on \
         the stage-18 receipt `0x00032615`; unarming it needs its own reason"
    );

    // The receipt must be recorded BEFORE the fold. A unit that refuses
    // handoff has one observable left, and the refusal is worth far less
    // without its reason; recording after the fold erases the diagnostic in
    // exactly the case it is needed.
    let probe_idx = render_code
        .find("Stage::BacklightProbe")
        .expect("render must record the BacklightProbe receipt");
    let fold_idx = render_code
        .find("ok &= backlight_on;")
        .expect("checked above");
    assert!(
        probe_idx < fold_idx,
        "the BacklightProbe receipt must be recorded BEFORE the verdict is \
         folded in (found the receipt at byte {probe_idx} and the fold at byte \
         {fold_idx}), so a refusing unit still says WHY"
    );

    // The FSBL must never touch the fault registers: reading one is a
    // documented IC-restart path once a flag is set, and its effect on a clean
    // part is unspecified. Fine as a patchable secure-world diagnostic (#733),
    // not something to freeze into the FSBL.
    let drv = read_workspace_file("fsbl/src/aw99703.rs");
    let drv_code = code_only(&drv);
    for forbidden in ["0x0E", "0x0F", "FLAGS"] {
        assert!(
            !drv_code.contains(forbidden),
            "fsbl/src/aw99703.rs must not reference the fault registers \
             (found `{forbidden}`): reading one can restart the IC"
        );
    }

    // The bit-bang period must NOT be derived from the achieved clock. This
    // inverts the repo's usual rule on purpose — see the constant's comment.
    assert!(
        drv.contains("const QUARTER: u32 = 40;"),
        "the FSBL bit-bang quarter-period must be a fixed 40 cycles (~100 kHz \
         at HSI16). The secure world's 400 is sized for 160 MHz and would give \
         ~10 kHz here."
    );
    assert!(
        !drv_code.contains("achieved_hz"),
        "fsbl/src/aw99703.rs must not multiply an achieved_hz() value: \
         overflow-checks reaches the release profile and the panic handler is \
         panic_halt, so it would spin on every boot of every unit"
    );
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
