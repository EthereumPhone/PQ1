//! Pixel-level host tests for the mounted NV3007 trusted-display rasterizer
//! (`secure/src/ui/lcd.rs`, mounted verbatim as `ui_lcd`).
//!
//! Security-review finding P0: the on-device golden gate hashes the 16×4
//! CHAR grid, so the final "char grid → pixels" hop (glyph lookup, 3×
//! upscale, landscape→native transpose, FLIP orientation, windowing) had no
//! coverage — a glyph/raster regression was invisible. These tests close
//! that hop: they reassemble the full native panel image from the recording
//! `hw::lcd_nv3007` stub's (window, pixels) log and diff it against an
//! INDEPENDENT forward rasterizer written in this file (glyph columns from
//! the same mounted font, but a deliberately different code path: forward
//! 3×3-block fill into a landscape canvas, then a forward landscape→native
//! transform — not the production blitter's per-native-pixel inverse map).
//!
//! Serialization: `FLIP` is a `static mut` shared by every render and the
//! stub owns one global framebuffer/op-log, so every test holds `SERIAL` for
//! its whole body (the Miri leg additionally runs `--test-threads=1`).

use pqsigner_secure_miri_tests as m;
use m::hw::lcd_nv3007 as stub;
use m::ui_lcd::{set_flip, Display};
use m::{public_glyph_cols, secret_glyph_cols, DISPLAY_COLS, DISPLAY_ROWS};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── geometry (test-side copies of the rasterizer's private constants) ────
// The differential tests pin these: if production geometry drifts, the
// independent reference built from THESE values no longer matches and the
// tests go red, forcing a review of the change.
const PANEL_W: usize = 142; // native X
const PANEL_H: usize = 428; // native Y
const LAND_W: usize = PANEL_H; // landscape X (the wide axis)
const LAND_H: usize = PANEL_W; // landscape Y (the short axis)
const ORIGIN_X: usize = 6;
const ORIGIN_Y: usize = 1;
const COL_PITCH: usize = 26;
const ROW_PITCH: usize = 35;
const SCALE: usize = 3;
const FONT_W: usize = 5;
const FONT_H: usize = 8;
const FG: u16 = 0xFFFF;
const BG: u16 = 0x0000;

const FLIP_COMBOS: [(bool, bool); 4] =
    [(false, false), (true, false), (false, true), (true, true)];

// ── independent reference rasterizer ─────────────────────────────────────

/// Render `grid` the other way around from the production blitter: paint
/// FG pixels into a LANDSCAPE canvas (3×3 block per font pixel), then
/// forward-map each set landscape pixel to its native coordinate under
/// `FLIP = (fx, fy)`:  nx = fx ? PANEL_W-1-ly : ly,
///                     ny = fy ? PANEL_H-1-lx : lx.
/// Everything not painted stays BG (matches the post-`reset()` stub panel).
fn reference_frame(grid: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS], fx: bool, fy: bool) -> Vec<u16> {
    let mut land = vec![false; LAND_W * LAND_H];
    for r in 0..DISPLAY_ROWS {
        for c in 0..DISPLAY_COLS {
            let cols = public_glyph_cols(grid[r][c]);
            for sx in 0..FONT_W {
                for sy in 0..FONT_H {
                    if (cols[sx] >> sy) & 1 == 0 {
                        continue;
                    }
                    for dx in 0..SCALE {
                        for dy in 0..SCALE {
                            let lx = ORIGIN_X + c * COL_PITCH + sx * SCALE + dx;
                            let ly = ORIGIN_Y + r * ROW_PITCH + sy * SCALE + dy;
                            land[ly * LAND_W + lx] = true;
                        }
                    }
                }
            }
        }
    }
    let mut native = vec![BG; PANEL_W * PANEL_H];
    for ly in 0..LAND_H {
        for lx in 0..LAND_W {
            if !land[ly * LAND_W + lx] {
                continue;
            }
            let nx = if fx { PANEL_W - 1 - ly } else { ly };
            let ny = if fy { PANEL_H - 1 - lx } else { lx };
            native[ny * PANEL_W + nx] = FG;
        }
    }
    native
}

// ── render + compare helpers ─────────────────────────────────────────────

/// Reassemble the full native panel image from the stub's recorded writes.
fn actual_frame() -> Vec<u16> {
    let mut fb = vec![0u16; stub::framebuffer_len()];
    stub::copy_framebuffer(&mut fb);
    fb
}

/// Reset the stub, stamp the grid via `draw_line`, `flush()`, return the
/// reassembled panel image. Grids passed here must be pure printable ASCII
/// (draw_line is then the identity, so this differential test does not
/// silently re-implement draw_line's clip/substitute/pad logic — that logic
/// has its own test below with hand-written expectations).
fn render(grid: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS]) -> Vec<u16> {
    stub::reset();
    let mut d = Display::new();
    for (r, row) in grid.iter().enumerate() {
        d.draw_line(r, core::str::from_utf8(row).unwrap());
    }
    d.flush();
    actual_frame()
}

/// Build a grid from printable ASCII row strings (space-padded to 16 cols).
/// Rows must be ≤ 16 printable ASCII chars so `draw_line` is the identity
/// on them.
fn grid_from(rows: [&str; DISPLAY_ROWS]) -> [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
    let mut g = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    for (r, s) in rows.iter().enumerate() {
        assert!(
            s.len() <= DISPLAY_COLS && s.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "grid_from row {r} must be ≤{DISPLAY_COLS} printable ASCII: {s:?}"
        );
        g[r][..s.len()].copy_from_slice(s.as_bytes());
    }
    g
}

fn assert_frames_eq(actual: &[u16], reference: &[u16], ctx: &str) {
    assert_eq!(actual.len(), reference.len(), "{ctx}: frame size");
    let diffs: Vec<usize> = actual
        .iter()
        .zip(reference.iter())
        .enumerate()
        .filter(|(_, (a, r))| a != r)
        .map(|(i, _)| i)
        .collect();
    assert!(
        diffs.is_empty(),
        "{ctx}: {} native px differ; first at (x={}, y={}): actual=0x{:04X} reference=0x{:04X}",
        diffs.len(),
        diffs[0] % PANEL_W,
        diffs[0] / PANEL_W,
        actual[diffs[0]],
        reference[diffs[0]],
    );
}

// ── tests ────────────────────────────────────────────────────────────────

/// `Display::init` must drive the panel driver's `init` exactly once (and
/// the `secure_log!` shim must compile).
#[test]
fn positive_init_drives_lcd_init_once() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    stub::reset();
    let mut d = Display::new();
    d.init();
    assert_eq!(stub::op_count(), 1, "init must issue exactly one driver call");
    assert_eq!(stub::op_at(0).kind, stub::OpKind::Init);
}

/// Differential rasterization, production orientation FLIP=(true,false):
/// every printable ASCII char (0x20..=0x7E) across full 64-cell grids.
#[test]
fn positive_differential_every_printable_char() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_flip(true, false);

    // Grid A: 0x20..0x60 — the first 64 printable chars fill all 64 cells.
    let mut a = [[0u8; DISPLAY_COLS]; DISPLAY_ROWS];
    for i in 0..64u8 {
        a[usize::from(i / 16)][usize::from(i % 16)] = 0x20 + i;
    }
    assert_frames_eq(&render(&a), &reference_frame(&a, true, false), "charset 0x20..0x60");

    // Grid B: 0x60..=0x7E (31 chars) + space padding — covers the rest.
    let mut b = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    for (k, ch) in (0x60u8..=0x7e).enumerate() {
        b[k / 16][k % 16] = ch;
    }
    assert_frames_eq(&render(&b), &reference_frame(&b, true, false), "charset 0x60..=0x7E");
}

/// All four FLIP combos: the reassembled panel must equal the correctly
/// flipped independent reference per combo.
#[test]
fn positive_differential_all_four_flip_combos() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let grid = grid_from([
        "ABCDEFGHIJKLMNOP",
        "0123456789abcdef",
        "pq signer rocks!",
        ".,:;-_/\\|@#$%^&*",
    ]);
    let mut frames = Vec::new();
    for &(fx, fy) in &FLIP_COMBOS {
        set_flip(fx, fy);
        let actual = render(&grid);
        assert_frames_eq(&actual, &reference_frame(&grid, fx, fy), "flip=({fx},{fy})");
        frames.push(actual);
    }
    // Negative control: for this asymmetric content the four orientations
    // must be pairwise distinct — otherwise `set_flip` could be a no-op and
    // every assert above would still pass.
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(
                frames[i], frames[j],
                "flip combos {:?} and {:?} rendered identically",
                FLIP_COMBOS[i], FLIP_COMBOS[j]
            );
        }
    }
}

/// Bounds: every window the rasterizer programs must stay inside the native
/// panel, with the exact 24×15 glyph-cell footprint, and every pixel write
/// must be a full cell (360 px) into the window just set.
#[test]
fn positive_every_window_within_native_panel_bounds() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Pin the stub's mirrored driver constants (the real driver's own host
    // unit tests pin these same values — a stub/driver drift fails here).
    assert_eq!(stub::FRAME_WIDTH, 142);
    assert_eq!(stub::FRAME_HEIGHT, 428);
    assert_eq!(stub::X_OFFSET, 12);
    assert_eq!(stub::Y_OFFSET, 0);

    let grid = grid_from([
        "0123456789ABCDEF",
        "FEDCBA9876543210",
        "The quick brown!",
        "jumps over lazy?",
    ]);
    for &(fx, fy) in &FLIP_COMBOS {
        set_flip(fx, fy);
        render(&grid); // discards the image; this test inspects the op log
        assert_eq!(
            stub::op_count(),
            2 * DISPLAY_COLS * DISPLAY_ROWS,
            "flip=({fx},{fy}): one set_window + one write_pixels per cell"
        );
        assert!(stub::op_count() <= stub::op_cap(), "op log must not truncate");
        for i in 0..stub::op_count() {
            let op = stub::op_at(i);
            if i % 2 == 0 {
                assert_eq!(op.kind, stub::OpKind::SetWindow, "op {i}");
                assert!(
                    op.x0 <= op.x1 && op.x1 < stub::FRAME_WIDTH,
                    "flip=({fx},{fy}) op {i}: native X {}..={} outside 0..{}",
                    op.x0, op.x1, stub::FRAME_WIDTH
                );
                assert!(
                    op.y0 <= op.y1 && op.y1 < stub::FRAME_HEIGHT,
                    "flip=({fx},{fy}) op {i}: native Y {}..={} outside 0..{}",
                    op.y0, op.y1, stub::FRAME_HEIGHT
                );
                assert_eq!(op.x1 - op.x0 + 1, 24, "op {i}: cell native-X extent");
                assert_eq!(op.y1 - op.y0 + 1, 15, "op {i}: cell native-Y extent");
            } else {
                assert_eq!(op.kind, stub::OpKind::WritePixels, "op {i}");
                assert_eq!(op.arg, 360, "op {i}: full 24×15 cell = 360 px");
                let win = stub::op_at(i - 1);
                assert_eq!(
                    (op.x0, op.y0, op.x1, op.y1),
                    (win.x0, win.y0, win.x1, win.y1),
                    "op {i}: write must target the window just set"
                );
            }
        }
    }
}

/// `draw_line` semantics, observed at the pixel level: out-of-range rows are
/// dropped, non-printable bytes become '?', lines truncate at 16 cols and
/// pad with spaces.
#[test]
fn positive_draw_line_substitutes_clips_pads_and_drops_rows() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_flip(true, false);
    stub::reset();
    let mut d = Display::new();
    // Bytes: 'A', 0x01, 0x7F, 'é' (0xC3 0xA9 — two non-ASCII bytes), 'Z'.
    d.draw_line(0, "A\u{1}\u{7F}éZ");
    d.draw_line(1, "0123456789ABCDEFXYZ"); // 19 chars → truncated to 16
    d.draw_line(2, ""); // → all spaces
    d.draw_line(4, "dropped row"); // row >= DISPLAY_ROWS → dropped
    d.draw_line(usize::MAX, "also dropped"); // row >= DISPLAY_ROWS → dropped
    // Row 3 never touched → stays spaces on a fresh Display.
    d.flush();

    let mut expect = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    expect[0][..6].copy_from_slice(b"A????Z"); // 0x01, 0x7F, 0xC3, 0xA9 → '?'
    expect[1].copy_from_slice(b"0123456789ABCDEF");
    assert_frames_eq(
        &actual_frame(),
        &reference_frame(&expect, true, false),
        "draw_line clip/substitute/pad/drop"
    );
}

/// CT-path discipline: `flush_with_secret_rows` must render EVERY column of
/// a secret row regardless of text length (out-of-range positions feed
/// ch=0 → blank glyph, but the full blit still runs), and the produced
/// pixels must equal the public render of the same content with trailing
/// blanks.
#[test]
fn positive_secret_row_blits_all_columns_and_matches_public_pixels() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_flip(true, false);
    let mut d = Display::new();
    d.draw_line(0, "PUBLIC ROW ZERO!");
    d.draw_line(2, "public row two!!");
    d.draw_line(3, "0123456789ABCDEF");
    stub::reset();
    let secret: &[u8] = b"ab"; // 2 chars — 14 columns must STILL be blitted
    d.flush_with_secret_rows(&[(1, secret)]);

    // Every cell of the 16×4 grid is repainted (public pass + secret pass).
    assert_eq!(stub::op_count(), 2 * DISPLAY_COLS * DISPLAY_ROWS);

    // The secret row (r=1) must blit all 16 columns. With FLIP=(true,false):
    //   nx0 = PANEL_W-1 - (ly0 + GLYPH_LH-1) = 141 - (1 + 1*35 + 23) = 82
    //   ny0 = lx0 = ORIGIN_X + c*COL_PITCH
    let mut secret_cols: Vec<u16> = (0..stub::op_count())
        .map(stub::op_at)
        .filter(|op| op.kind == stub::OpKind::SetWindow && op.x0 == 82)
        .map(|op| op.y0)
        .collect();
    secret_cols.sort_unstable();
    let expect_cols: Vec<u16> = (0..DISPLAY_COLS).map(|c| (ORIGIN_X + c * COL_PITCH) as u16).collect();
    assert_eq!(
        secret_cols, expect_cols,
        "secret row must blit every column regardless of text length"
    );

    // Pixel discipline: ch=0 past the text end renders the same blank as a
    // space, so the frame equals the public render with trailing blanks.
    let grid = grid_from([
        "PUBLIC ROW ZERO!",
        "ab",
        "public row two!!",
        "0123456789ABCDEF",
    ]);
    assert_frames_eq(
        &actual_frame(),
        &reference_frame(&grid, true, false),
        "secret-row render vs public reference"
    );
}

/// Multiple secret rows in one flush; an out-of-range secret row must be
/// skipped without disturbing the rest.
#[test]
fn positive_secret_rows_multiple_and_out_of_range_skipped() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_flip(true, false);
    let mut d = Display::new();
    d.draw_line(1, "public middle");
    stub::reset();
    let w0: &[u8] = b"word";
    let w2: &[u8] = b"mnemonic";
    let bad: &[u8] = b"out-of-range row 9";
    d.flush_with_secret_rows(&[(0, w0), (2, w2), (9, bad)]);

    assert_eq!(stub::op_count(), 2 * DISPLAY_COLS * DISPLAY_ROWS);
    let grid = grid_from([
        "word",
        "public middle",
        "mnemonic",
        "",
    ]);
    assert_frames_eq(
        &actual_frame(),
        &reference_frame(&grid, true, false),
        "two secret rows + skipped row 9"
    );
}

/// The constant-time glyph scan must produce the SAME column bytes as the
/// direct public lookup for the entire byte domain (in-range chars resolve
/// identically; out-of-range bytes both render blank).
#[test]
fn positive_public_and_secret_glyph_cols_agree_for_all_256_bytes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for ch in 0..=255u8 {
        assert_eq!(
            public_glyph_cols(ch),
            secret_glyph_cols(ch),
            "glyph columns differ for byte 0x{ch:02X}"
        );
    }
}

/// Font collision analysis over the vendored 5×8 font: which printable
/// ASCII pairs share a pixel-identical glyph (display-spoofing relevant —
/// e.g. a BIP-39 word checksum character rendered as another). The
/// collision set is PINNED: any change (a font swap adding/removing a
/// collision) fails this test. Do NOT "fix" collisions by asserting
/// distinctness that doesn't exist — they are a property of the vendored
/// font and are reported to the owner as findings.
#[test]
fn positive_printable_glyph_collision_set_pinned() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let domain: Vec<u8> = (0x20u8..=0x7e).collect();
    let mut pairs: Vec<(u8, u8)> = Vec::new();
    for (i, &a) in domain.iter().enumerate() {
        for &b in &domain[i + 1..] {
            if public_glyph_cols(a) == public_glyph_cols(b) {
                pairs.push((a, b));
            }
        }
    }

    // Pinned collision set, verified 2026-08-06 against the vendored
    // secure/assets/font_5x8.raw (cross-checked by an independent Python
    // decode of the raw bitmap): **EMPTY** — no two printable ASCII chars
    // share a pixel-identical 5×8 glyph, and SPACE is the only blank glyph.
    // The classic look-alike candidates are all distinct, some by as little
    // as one pixel ('1' vs 'l': col1 0x44 vs 0x42; '8' vs 'B': col0 only;
    // '0' vs 'O': same shape, 1-px horizontal shift) — visually confusable
    // but raster-distinct, so no display-spoofing collision exists to
    // report; only these near-misses are noted to the owner. Any NEW
    // collision (e.g. a font swap) fails this test — do NOT weaken it to
    // assert distinctness case-by-case; keep the whole set pinned here.
    let pinned: &[(u8, u8)] = &[];
    assert_eq!(
        pairs,
        pinned,
        "printable glyph collision set changed; actual pairs with shared bitmaps:\n{}",
        pairs
            .iter()
            .map(|&(a, b)| format!(
                "  0x{a:02X} {:?} == 0x{b:02X} {:?}  cols={:02X?}",
                a as char, b as char, public_glyph_cols(a)
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Independently: inside the printable domain, only SPACE may be blank
    // (an invisible printable glyph would be a display-spoofing primitive).
    for &ch in &domain {
        assert!(
            ch == b' ' || public_glyph_cols(ch) != [0u8; FONT_W],
            "printable char 0x{ch:02X} {:?} renders blank (invisible-glyph spoof risk)",
            ch as char
        );
    }
}
