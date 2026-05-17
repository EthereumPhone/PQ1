//! Host-side positive + negative test suite for the `secure-ui` slice.
//!
//! Slice files in scope:
//!   - `secure/src/ui/mod.rs`         (trait surface, singletons, helpers)
//!   - `secure/src/ui/confirm.rs`     (multi-page confirm dialog)
//!   - `secure/src/ui/pin_entry.rs`   (2-button 8-digit PIN entry)
//!   - `secure/src/ui/seed_wizard.rs` (BIP-39 wizard flows)
//!   - `secure/src/ui/capture.rs`     (`ui-capture` SHA-256 fingerprint emit)
//!   - `secure/src/ui/oled.rs`        (SSD1306 backend)
//!   - `secure/src/ui/semihosting.rs` (QEMU mock backend)
//!   - `secure/src/ui/mirror.rs`      (RTT framebuffer mirror)
//!   - `secure/src/ui/noop.rs`        (headless USB backend)
//!
//! Every file except this scaffold imports hardware-only peers
//! (`cortex_m_semihosting`, `embedded_graphics`, `ssd1306`,
//! `rtt-target`, `crate::timeout`, `crate::rng_strong`, the GPIO
//! button driver, the global `static mut DISPLAY` singleton), so the
//! slice is link-checked only via `include_str!` source-text pins +
//! reference-algorithm re-implementations.
//!
//! Negative tests are framed by the assumption they attack: each
//! `negative_*` test's panic message names the attack and cites the
//! CLAUDE.md invariant or in-file safety comment whose silent removal
//! it would otherwise enable.

#![cfg(test)]

use sphincs_tz_bip39::{lookup_prefix, PrefixLookup, WORDLIST, WORD_COUNT};
use sphincs_tz_shared::PIN_LEN;

const MOD_SRC: &str = include_str!("../ui/mod.rs");
const CONFIRM_SRC: &str = include_str!("../ui/confirm.rs");
const PIN_SRC: &str = include_str!("../ui/pin_entry.rs");
const WIZARD_SRC: &str = include_str!("../ui/seed_wizard.rs");
const CAPTURE_SRC: &str = include_str!("../ui/capture.rs");
const OLED_SRC: &str = include_str!("../ui/oled.rs");
const SEMI_SRC: &str = include_str!("../ui/semihosting.rs");
const MIRROR_SRC: &str = include_str!("../ui/mirror.rs");
const NOOP_SRC: &str = include_str!("../ui/noop.rs");

// ─────────────────────────────────────────────────────────────────────
// Section 1 — POSITIVE: layout constants + trait surface
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_display_grid_is_16x4() {
    assert!(MOD_SRC.contains("pub const DISPLAY_COLS: usize = 16;"));
    assert!(MOD_SRC.contains("pub const DISPLAY_ROWS: usize = 4;"));
}

#[test]
fn positive_pin_len_is_8() {
    assert_eq!(PIN_LEN, 8, "PIN_LEN is wired into SE silicon UserID setup");
}

#[test]
fn positive_ui_trait_surface() {
    // The Phase-10 PR-A trait codifies what every backend exposes.
    assert!(MOD_SRC.contains("pub trait Ui"));
    assert!(MOD_SRC.contains("fn clear(&mut self);"));
    assert!(MOD_SRC.contains("fn draw_line(&mut self, row: usize, text: &str);"));
    assert!(MOD_SRC.contains("fn flush(&mut self);"));
    assert!(MOD_SRC.contains("fn splash(&mut self) {}"));
}

#[test]
fn positive_three_ui_backends_impl_the_trait() {
    // semihosting / oled / noop each get an `impl Ui for X::Display`.
    // Each delegates straight into the inherent method. mirror &
    // capture are non-Display modules and intentionally do NOT.
    assert!(MOD_SRC.contains("impl Ui for semihosting::Display"));
    assert!(MOD_SRC.contains("impl Ui for oled::Display"));
    assert!(MOD_SRC.contains("impl Ui for noop::Display"));
    // Delegation shape: every backend calls into self.<method>(), not
    // a re-implementation. Pin one canonical line per backend.
    assert!(MOD_SRC.contains("fn clear(&mut self) { self.clear() }"));
    assert!(MOD_SRC.contains("fn flush(&mut self) { self.flush() }"));
}

#[test]
fn positive_button_and_press_enums_have_two_variants() {
    assert!(MOD_SRC.contains("pub enum Button"));
    assert!(MOD_SRC.contains("Left,"));
    assert!(MOD_SRC.contains("Right,"));
    assert!(MOD_SRC.contains("pub enum Press"));
    assert!(MOD_SRC.contains("Short,"));
    assert!(MOD_SRC.contains("Long,"));
}

// ─────────────────────────────────────────────────────────────────────
// Section 2 — POSITIVE: progress-bar math (the only "real" pure logic
// inside `ui/mod.rs`)
// ─────────────────────────────────────────────────────────────────────

/// Re-implementation of `show_progress`'s `filled` formula. The
/// production line is `(pct as usize * 14 + 50) / 100` — the `+50`
/// gives round-half-up.
fn ref_filled(pct: u8) -> usize {
    let p = if pct > 100 { 100 } else { pct } as usize;
    (p * 14 + 50) / 100
}

fn ref_render_bar(pct: u8) -> [u8; 16] {
    let filled = ref_filled(pct);
    let mut bar = [b' '; 16];
    bar[0] = b'[';
    bar[15] = b']';
    for i in 0..14 {
        bar[i + 1] = if i < filled { b'#' } else { b'-' };
    }
    bar
}

#[test]
fn positive_progress_bar_formula_matches_source() {
    // The two literals (14 cells, +50 round-half-up, /100) are
    // load-bearing for the rendered output. Pin them verbatim so a
    // silent refactor that changes either fires a test.
    assert!(MOD_SRC.contains("(pct as usize * 14 + 50) / 100"));
    assert!(MOD_SRC.contains("bar[0] = b'[';"));
    assert!(MOD_SRC.contains("bar[15] = b']';"));
}

#[test]
fn positive_progress_bar_endpoints() {
    let bar0 = ref_render_bar(0);
    assert_eq!(&bar0[..], b"[--------------]");
    let bar100 = ref_render_bar(100);
    assert_eq!(&bar100[..], b"[##############]");
}

#[test]
fn positive_progress_bar_midpoint_rounds_half_up() {
    // 50% on 14 cells = 7.0 cells (no rounding needed). The +50
    // matters at edges like 7% → 0.98 cells.
    let bar50 = ref_render_bar(50);
    assert_eq!(&bar50[..], b"[#######-------]");
    // 4% × 14 + 50 = 106 / 100 = 1 → exactly 1 filled cell.
    let bar4 = ref_render_bar(4);
    assert_eq!(bar4[1], b'#');
    assert_eq!(bar4[2], b'-');
}

#[test]
fn positive_progress_clamps_percent_above_100() {
    // The source clamps `if percent > 100 { 100 } else { percent }`
    // BEFORE multiplying, so even u8::MAX = 255 yields a fully-filled
    // bar instead of running off into integer overflow / saturation.
    assert!(MOD_SRC.contains("if percent > 100 { 100 } else { percent }"));
    let bar_overflow = ref_render_bar(u8::MAX);
    assert_eq!(&bar_overflow[..], b"[##############]");
}

// ─────────────────────────────────────────────────────────────────────
// Section 3 — POSITIVE: ASCII filter (homoglyph defence)
// ─────────────────────────────────────────────────────────────────────

/// Mirrors the inline filter in `semihosting::draw_line` and
/// `oled::draw_line`: any byte outside 0x20..=0x7e is rewritten to
/// `'?'`. Pinning this defends the trusted display against a hostile
/// DB row that tries to smuggle Unicode-lookalike glyphs into a value
/// or address row.
fn ref_ascii_filter(text: &[u8]) -> [u8; 16] {
    let mut row = [b' '; 16];
    let mut col = 0;
    for &b in text {
        if col >= 16 {
            break;
        }
        row[col] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
        col += 1;
    }
    row
}

#[test]
fn positive_ascii_filter_pin_in_both_backends() {
    // Both backends MUST run identical filters; the trait contract
    // says "non-ASCII bytes are replaced with '?'". A divergence
    // would mean the on-OLED text differs from the QEMU log used to
    // regression-test UI fingerprints.
    let needle = "if (0x20..=0x7e).contains(&b) { b } else { b'?' };";
    assert!(SEMI_SRC.contains(needle));
    assert!(OLED_SRC.contains(needle));
}

#[test]
fn positive_ascii_filter_passes_printable_ascii() {
    let row = ref_ascii_filter(b"Send 1.0 ETH");
    assert_eq!(&row[..12], b"Send 1.0 ETH");
    // Beyond the input gets space-padded.
    assert_eq!(row[12], b' ');
    assert_eq!(row[15], b' ');
}

#[test]
fn positive_ascii_str_helper_pinned_against_unsafe() {
    // Comment in mod.rs explicitly justifies the choice of safe
    // `from_utf8` over `unsafe { from_utf8_unchecked }`. Pinning the
    // implementation shape means any future "optimisation" that
    // drops the safe path becomes visible in CI.
    assert!(MOD_SRC.contains("core::str::from_utf8(buf).unwrap_or(\"?\")"));
    // The only occurrence of `from_utf8_unchecked` in the file is
    // the doc comment that explains why we avoid it. Find that line
    // and confirm it's inside a comment context — no *call* to the
    // unsafe variant should ever appear.
    for line in MOD_SRC.lines() {
        if line.contains("from_utf8_unchecked") {
            let trimmed = line.trim_start();
            assert!(
                trimmed.starts_with("//") || trimmed.starts_with("///")
                    || trimmed.starts_with("//!"),
                "any mention of from_utf8_unchecked must be inside a comment, never a call site"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Section 4 — POSITIVE: PIN entry digit math + F-20 RNG scrambling
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_pin_increment_uses_mod_10() {
    assert!(PIN_SRC.contains("pin[pos] = (pin[pos] + 1) % 10;"));
    assert!(PIN_SRC.contains("pin[pos] = (pin[pos] + 9) % 10;"));
}

#[test]
fn positive_pin_long_right_advances_position_else_submits() {
    // Long-Right at PIN_LEN-1 returns Pin(...); otherwise advances pos.
    assert!(PIN_SRC.contains("if pos + 1 == PIN_LEN"));
    assert!(PIN_SRC.contains("return PinEntryResult::Pin(ascii);"));
}

#[test]
fn positive_pin_digit_to_ascii_conversion() {
    // PIN compares are done against the ASCII representation
    // because the SE050 MACD chain is keyed on ASCII bytes.
    // A `digit + 0` (without the b'0' offset) would feed the SE the
    // raw byte 0..=9 instead of 0x30..=0x39 and break PIN verify.
    assert!(PIN_SRC.contains("ascii[i] = b'0' + pin[i];"));
}

#[test]
fn positive_pin_random_start_scrambling_is_present() {
    // F-20 — Per-position random starting digit.
    assert!(PIN_SRC.contains("F-20"));
    assert!(PIN_SRC.contains("crate::rng_strong::fill"));
    assert!(PIN_SRC.contains("pin[i] = rand_bytes[i] % 10;"));
    assert!(PIN_SRC.contains("rand_bytes.zeroize();"));
}

#[test]
fn positive_pin_press_count_relationship_target_minus_start_mod_10() {
    // Documents the "target press count" calculation that the
    // shoulder-surf attacker sees. For every (start, target) pair,
    // the user must execute exactly `(target - start) mod 10` Right
    // presses (or `(start - target) mod 10` Left presses) to land
    // on the digit. This is the assertion that future refactors
    // must preserve to keep F-20 effective.
    for start in 0u8..10 {
        for target in 0u8..10 {
            let right_presses = (10 + target - start) % 10;
            let left_presses = (10 + start - target) % 10;
            let mut cursor = start;
            for _ in 0..right_presses {
                cursor = (cursor + 1) % 10;
            }
            assert_eq!(cursor, target);
            cursor = start;
            for _ in 0..left_presses {
                cursor = (cursor + 9) % 10;
            }
            assert_eq!(cursor, target);
        }
    }
}

#[test]
fn positive_wipe_pin_uses_zeroize_and_fi_barrier() {
    // The PIN wipe must hit both `zeroize::Zeroize::zeroize` (to defeat
    // dead-store elimination) and `fi::zeroize_barrier` (to defeat
    // reordering across the function return). Either one alone is
    // insufficient under aggressive optimisation.
    assert!(PIN_SRC.contains("fn wipe_pin(pin: &mut [u8; PIN_LEN])"));
    assert!(PIN_SRC.contains("pin.zeroize();"));
    assert!(PIN_SRC.contains("crate::fi::zeroize_barrier();"));
}

#[test]
fn positive_pin_confirm_zeroes_first_pin_on_second_pin_idle_wipe() {
    // `enter_pin_with_confirm` holds the first PIN in a stack variable
    // while it prompts for the second. On any failure path the first
    // PIN must be zeroed before bailing.
    assert!(PIN_SRC.contains("// We had a first PIN in flight; wipe it before bailing."));
    assert!(PIN_SRC.contains("let mut f = first;"));
    assert!(PIN_SRC.contains("f.zeroize();"));
}

#[test]
fn positive_pin_confirm_compare_is_or_folded_constant_time() {
    // Look for the bitwise OR fold + the explicit "don't early-return"
    // comment. An attacker who can time the confirm-compare would
    // learn the position of the first mismatching digit otherwise.
    assert!(PIN_SRC.contains("Constant-time-ish comparison: don't early-return on mismatch."));
    assert!(PIN_SRC.contains("diff |= first[i] ^ second[i];"));
    assert!(PIN_SRC.contains("if diff != 0 {"));
}

#[test]
fn positive_pin_confirm_zeroes_both_on_mismatch() {
    // Even on the Mismatch path, both PINs must be wiped before
    // returning.
    assert!(PIN_SRC.contains("a.zeroize();"));
    assert!(PIN_SRC.contains("b.zeroize();"));
    // And b is wiped on the success path too, before returning a (==b).
    assert!(PIN_SRC.contains("// a (== b) is the confirmed PIN. Move it out, wipe b."));
}

// ─────────────────────────────────────────────────────────────────────
// Section 5 — POSITIVE: BIP-39 seed wizard
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_seed_wizard_page_geometry() {
    // 24 words / 3 words per page = 8 pages.
    assert!(WIZARD_SRC.contains("const WORDS_PER_PAGE: usize = 3;"));
    assert!(WIZARD_SRC.contains("const TOTAL_PAGES: usize = WORD_COUNT / WORDS_PER_PAGE; // 8"));
    assert_eq!(WORD_COUNT, 24);
    assert_eq!(WORD_COUNT / 3, 8);
}

#[test]
fn positive_seed_wizard_verify_picks_three_distinct_indices() {
    // Re-implement the distinctness invariant locally: if a candidate
    // collides with an already-picked one, the loop continues until
    // three unique indices are filled.
    let mut out = [0u8; 3];
    let mut count = 0usize;
    let canned: [u8; 6] = [5, 5, 11, 11, 7, 5];
    let mut iter = canned.iter().copied();
    while count < 3 {
        let candidate = iter.next().unwrap() % (WORD_COUNT as u8);
        if out[..count].iter().any(|&c| c == candidate) {
            continue;
        }
        out[count] = candidate;
        count += 1;
    }
    assert_eq!(out, [5, 11, 7]);
}

#[test]
fn positive_seed_wizard_wrap_in_range_wraps_correctly() {
    // Mirrors the candidate-picker's cursor: at range start, "left"
    // should land at end-1; at range end-1, "right" should land at
    // start. Pin the algorithm.
    fn ref_wrap(start: usize, end: usize, cur: usize, offset: isize) -> usize {
        let len = (end - start) as isize;
        let pos = (cur as isize - start as isize + offset).rem_euclid(len);
        start + pos as usize
    }
    assert_eq!(ref_wrap(10, 15, 10, -1), 14);
    assert_eq!(ref_wrap(10, 15, 14, 1), 10);
    assert_eq!(ref_wrap(10, 15, 12, 0), 12);
    // The literal expression should also appear verbatim in the source.
    assert!(WIZARD_SRC.contains("(cur as isize - start as isize + offset).rem_euclid(len)"));
}

#[test]
fn positive_seed_wizard_enter_mnemonic_validates_bip39_checksum() {
    // `Mnemonic::from_indices` does the checksum check. The wizard
    // must surface a `Bad checksum` retry on failure (rather than
    // silently accepting a corrupted seed).
    assert!(WIZARD_SRC.contains("Mnemonic::from_indices(indices)"));
    assert!(WIZARD_SRC.contains("show_status(\"Bad checksum\", \"retry...\");"));
    assert!(WIZARD_SRC.contains("indices.zeroize();"));
}

#[test]
fn positive_seed_wizard_show_mnemonic_seen_last_gate() {
    // The user cannot dismiss `show_mnemonic` until they've paged to
    // the last page at least once. Without this gate, a fat-fingered
    // long-Right on page 1 would advance past the wallet seed.
    assert!(WIZARD_SRC.contains("let mut seen_last = false;"));
    assert!(WIZARD_SRC.contains("if page == TOTAL_PAGES - 1 {"));
    assert!(WIZARD_SRC.contains("seen_last = true;"));
    assert!(WIZARD_SRC.contains("if seen_last {"));
}

#[test]
fn positive_seed_wizard_lookup_prefix_works_with_bip39_crate() {
    // Cross-check that the wizard's prefix-search uses the same
    // semantics the BIP-39 crate provides (Unique / None / Multiple).
    match lookup_prefix("aban") {
        PrefixLookup::Unique(idx) => assert_eq!(WORDLIST[idx as usize], "abandon"),
        other => panic!("unexpected lookup result: {:?}", other),
    }
    match lookup_prefix("zzzz") {
        PrefixLookup::None => {}
        other => panic!("unexpected lookup result: {:?}", other),
    }
    // 4-letter prefix that is also an exact word — the wizard
    // explicitly handles this case by routing through pick_candidate.
    // Use "act" / "actor" (3-letter prefix collision).
    match lookup_prefix("act") {
        PrefixLookup::Multiple { start, end } => assert!(end > start),
        PrefixLookup::Unique(_) => {} // OK either way — what matters is the wizard's branch.
        PrefixLookup::None => panic!("'act' must exist in BIP-39 wordlist family"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Section 6 — POSITIVE: confirm dialog state machine
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_confirm_empty_pages_returns_cancelled() {
    // The first thing `confirm` does is check `pages.is_empty()`
    // and bail. Without this, the subsequent `pages[idx]` index
    // would panic.
    assert!(CONFIRM_SRC.contains("if pages.is_empty() {"));
    assert!(CONFIRM_SRC.contains("return ConfirmResult::Cancelled;"));
}

#[test]
fn positive_confirm_long_button_semantics() {
    assert!(CONFIRM_SRC.contains("(Button::Right, Press::Long) => return ConfirmResult::Confirmed,"));
    assert!(CONFIRM_SRC.contains("(Button::Left, Press::Long) => return ConfirmResult::Cancelled,"));
}

#[test]
fn positive_confirm_short_press_page_navigation() {
    assert!(CONFIRM_SRC.contains("if idx + 1 < pages.len() {"));
    assert!(CONFIRM_SRC.contains("idx += 1;"));
    assert!(CONFIRM_SRC.contains("if idx > 0 {"));
    assert!(CONFIRM_SRC.contains("idx -= 1;"));
}

#[test]
fn positive_confirm_e2e_test_fastpath_renders_all_pages_first() {
    // Even in the e2e-test fast-path, every page must be rendered so
    // the test harness can scrape framebox lines — only the input
    // wait is short-circuited. Otherwise harnesses would silently miss
    // page-content regressions.
    assert!(CONFIRM_SRC.contains("#[cfg(feature = \"e2e-test\")]"));
    assert!(CONFIRM_SRC.contains("for page in pages.iter() {"));
    assert!(CONFIRM_SRC.contains("render_page(page);"));
    assert!(CONFIRM_SRC.contains("return ConfirmResult::Confirmed;"));
}

#[test]
fn positive_confirm_idle_wipe_propagates_to_caller() {
    // When `input().wait_button` returns None (idle timeout fired),
    // the dialog must propagate the wipe — not silently retry, not
    // confirm.
    assert!(CONFIRM_SRC.contains("None => return ConfirmResult::IdleWipe,"));
}

// ─────────────────────────────────────────────────────────────────────
// Section 7 — POSITIVE: capture / mirror / oled / noop / semihosting
//   backend invariants
// ─────────────────────────────────────────────────────────────────────

#[test]
fn positive_capture_emit_format_is_ui_fp_prefix_idx_hash() {
    // tools/ui_fixture.py greps for `[UI-FP] `; renaming the prefix
    // would break every fixture file silently.
    assert!(CAPTURE_SRC.contains("[UI-FP]"));
    assert!(CAPTURE_SRC.contains("FRAME_COUNTER.fetch_add(1, Ordering::Relaxed)"));
    assert!(CAPTURE_SRC.contains("static FRAME_COUNTER: AtomicU16 = AtomicU16::new(0);"));
    // The emitted line shape — frame index then sha256-hex.
    assert!(CAPTURE_SRC.contains("\"[UI-FP] {:04x}  {}\""));
}

#[test]
fn positive_capture_hex_uses_lowercase_alphabet() {
    // `nibble_to_hex` uses `b'a'`, not `b'A'`. ui_fixture.py compares
    // hashes case-sensitively (it uses `bytes.fromhex` on stripped
    // tokens), so a flip to uppercase would invalidate every
    // existing fixture.
    assert!(CAPTURE_SRC.contains("10..=15 => b'a' + (n - 10),"));
}

#[test]
fn positive_mirror_frame_magic_and_size() {
    // Frame header: 0xFB 0x32 len_lo len_hi <512-byte fb>.
    // Host decoder hard-codes these magic bytes.
    assert!(MIRROR_SRC.contains("let header = [0xFB, 0x32, (512u16 & 0xFF) as u8, (512u16 >> 8) as u8];"));
    assert!(MIRROR_SRC.contains("pub fn push(fb: &[u8; 512])"));
}

#[test]
fn positive_mirror_button_byte_protocol_matches_semihosting() {
    // mirror.rs reuses semihosting.rs's keymap (h/l/a/d short, H/L/A/D
    // long). Drifting one without the other would break the
    // ui-mirror tool silently.
    assert!(MIRROR_SRC.contains("`h/a`=LEFT short, `l/d`=RIGHT"));
    assert!(MIRROR_SRC.contains("`H/A`=LEFT long, `L/D`=RIGHT long"));
}

#[test]
fn positive_oled_i2c_address_probes_3c_then_3d() {
    assert!(OLED_SRC.contains("const SSD1306_ADDR_PRIMARY: u8 = 0x3C;"));
    assert!(OLED_SRC.contains("const SSD1306_ADDR_ALT: u8 = 0x3D;"));
}

#[test]
fn positive_oled_data_control_byte_is_0x40() {
    // 0x40 == "Co=0, D/C#=1 → data stream". Any other prefix byte
    // would be interpreted as a command and corrupt the display.
    assert!(OLED_SRC.contains("chunk[0] = 0x40; // Co=0, D/C#=1 → data stream"));
}

#[test]
fn positive_oled_framebuffer_is_4_pages_x_128_bytes() {
    assert!(OLED_SRC.contains("buf: [u8; 512]"));
    assert!(OLED_SRC.contains("for page in 0..4 {"));
    assert!(OLED_SRC.contains("let start = page * 128;"));
}

#[test]
fn positive_semihosting_keymap_matches_documented_table() {
    // Source documents the keymap; the match arms must mirror it.
    assert!(SEMI_SRC.contains("b'h' | b'a' => return Some((Button::Left, Press::Short)),"));
    assert!(SEMI_SRC.contains("b'l' | b'd' => return Some((Button::Right, Press::Short)),"));
    assert!(SEMI_SRC.contains("b'H' | b'A' => return Some((Button::Left, Press::Long)),"));
    assert!(SEMI_SRC.contains("b'L' | b'D' => return Some((Button::Right, Press::Long)),"));
}

// ─────────────────────────────────────────────────────────────────────
// Section 8 — NEGATIVE: the most important deliverable.
// Each test challenges an assumption the code holds; passing means the
// slice still enforces the invariant.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_confirm_must_not_reset_activity_on_entry() {
    // HIGH-13 invariant. CLAUDE.md "What NOT to do":
    //   "NS does not control the inactivity timer — only S-world button
    //    presses on confirm dialogs reset it."
    //
    // Attack: an attacker spamming SIGN_USEROP / REQUEST_UNLOCK over
    // USB lands the firmware in `confirm()` over and over. If that
    // function reset the timer on entry (the pre-HIGH-13 behaviour),
    // each NS ping would refresh the unlocked window — turning a
    // 120 s idle timeout into "as long as NS keeps pinging." This
    // test asserts the entry-reset is gone AND that the explanatory
    // comment is intact, so future refactors that re-introduce the
    // reset are caught with a citation to the original bug.
    assert!(
        CONFIRM_SRC.contains("HIGH-13 fix: do NOT reset the inactivity timer on entry."),
        "HIGH-13 comment must remain — it documents why the entry-reset is forbidden"
    );
    // Find the body of `confirm` between the `pages.is_empty()` guard
    // and the start of the `loop {`. There must be NO call to
    // `timeout::reset_activity()` in that prologue.
    let body = &CONFIRM_SRC;
    let prologue_start = body
        .find("pub fn confirm(pages: &[Page]) -> ConfirmResult {")
        .expect("confirm fn must exist");
    let loop_start = body[prologue_start..]
        .find("loop {")
        .expect("confirm must contain a main loop")
        + prologue_start;
    let prologue = &body[prologue_start..loop_start];
    assert!(
        !prologue.contains("timeout::reset_activity()"),
        "HIGH-13: confirm() must NOT call timeout::reset_activity() before the input loop — \
         NS pings would otherwise refresh the inactivity window"
    );
}

#[test]
fn negative_confirm_only_resets_timer_after_a_button_event() {
    // Companion to the previous test: the reset MUST happen inside
    // the loop, AFTER the wait_button call returns Some(ev). If a
    // refactor moves it before wait_button (e.g. into the render
    // path), the timer would tick on every redraw instead of every
    // user press.
    assert!(CONFIRM_SRC.contains("// A button event IS real user activity — reset the timer"));
    // The literal reset call must live inside the post-event block.
    let post_event_marker = "// A button event IS real user activity — reset the timer";
    let pos = CONFIRM_SRC
        .find(post_event_marker)
        .expect("post-event marker must exist");
    // The next non-whitespace line should be the reset call.
    let after = &CONFIRM_SRC[pos..];
    assert!(
        after.contains("timeout::reset_activity();"),
        "reset_activity() must immediately follow the 'real user activity' comment"
    );
}

#[test]
fn negative_pin_compare_must_not_short_circuit_on_first_mismatch() {
    // If the confirm-compare bailed on the first mismatching digit,
    // a timing side-channel would leak the position of the first
    // wrong byte — and from there an attacker can build a digit-by-
    // digit oracle. The OR-fold defends that.
    //
    // Attack via source: assert there is no `if first[i] != second[i] { return ... }`
    // pattern anywhere in the file.
    for line in PIN_SRC.lines() {
        let stripped = line.trim_start();
        // Bail-on-mismatch shapes that would be a regression:
        let suspicious = stripped.starts_with("if first[i] != second[i]")
            || stripped.starts_with("if first != second")
            || stripped.starts_with("if first[i] == second[i]");
        assert!(
            !suspicious,
            "PIN compare must not short-circuit on per-byte mismatch — found: {}",
            stripped
        );
    }
    // And the OR-fold pattern must be present.
    assert!(
        PIN_SRC.contains("diff |= first[i] ^ second[i];"),
        "PIN compare must accumulate diff via OR-fold over all bytes"
    );
}

#[test]
fn negative_pin_entry_must_zeroize_on_idle_wipe_path() {
    // If `wait_button` returns None (backend idle-wipe signal), the
    // PIN buffer holds partially-entered digits. They must be wiped
    // before returning IdleWipe, otherwise a subsequent stack reuse
    // could leak them.
    let idle_block_start = PIN_SRC
        .find("// backend signalled idle wipe")
        .expect("idle wipe comment must exist");
    let next_match = PIN_SRC[idle_block_start..]
        .find("return PinEntryResult::IdleWipe;")
        .expect("idle wipe path must return");
    let block = &PIN_SRC[idle_block_start..idle_block_start + next_match];
    assert!(
        block.contains("wipe_pin(&mut pin);"),
        "PIN buffer must be wiped before returning IdleWipe — leak prevention"
    );
}

#[test]
fn negative_pin_entry_must_zeroize_on_cancel_path() {
    // Same argument as IdleWipe: long-Left at position 0 cancels.
    // The partially-entered PIN (or random-start scramble) must be
    // wiped before returning.
    let needle = "return PinEntryResult::Cancelled;";
    let cancel_pos = PIN_SRC.find(needle).expect("cancel return must exist");
    // Search backwards for the matching `if pos == 0 {` arm.
    let window_start = cancel_pos.saturating_sub(200);
    let window = &PIN_SRC[window_start..cancel_pos];
    assert!(
        window.contains("wipe_pin(&mut pin);"),
        "PIN buffer must be wiped before returning Cancelled — partial entry must not linger"
    );
}

#[test]
fn negative_ascii_filter_must_reject_non_printable_bytes() {
    // Attack: a hostile DB row (e.g. an ERC-20 token name) contains
    // a UTF-8 lookalike or a control byte. Without the 0x20..=0x7e
    // gate, those bytes would land on the OLED and the user could
    // confirm a transfer to "U‍SDC" thinking it was "USDC".
    let null_byte = ref_ascii_filter(&[b'A', 0x00, b'B']);
    assert_eq!(&null_byte[..3], b"A?B", "NUL byte must be replaced with '?'");
    let high_bit = ref_ascii_filter(&[b'X', 0xFF, b'Y']);
    assert_eq!(&high_bit[..3], b"X?Y", "0xFF must be replaced with '?'");
    // 0x1F is the last C0 control byte. 0x20 (space) is the first
    // valid one. 0x7E (`~`) is the last printable, 0x7F (DEL) the
    // first non-printable above.
    let boundary_low = ref_ascii_filter(&[0x1f, 0x20]);
    assert_eq!(boundary_low[0], b'?');
    assert_eq!(boundary_low[1], 0x20);
    let boundary_high = ref_ascii_filter(&[0x7e, 0x7f]);
    assert_eq!(boundary_high[0], 0x7e);
    assert_eq!(boundary_high[1], b'?');
}

#[test]
fn negative_ascii_filter_truncates_at_16_columns() {
    // Attack: a 32-byte input would overflow the row buffer if the
    // bounded-fill loop ever lost its `col >= 16` guard. Pin the
    // 16-col bound by feeding 32 bytes and asserting truncation.
    let long: Vec<u8> = (0..32u8).map(|i| b'A' + (i % 26)).collect();
    let row = ref_ascii_filter(&long);
    assert_eq!(row.len(), 16);
    // First 16 bytes are the rendered cells; nothing past the buffer
    // is written.
    assert_eq!(&row[..], b"ABCDEFGHIJKLMNOP");
    assert!(SEMI_SRC.contains("if col >= DISPLAY_COLS {"));
    assert!(OLED_SRC.contains("if col >= DISPLAY_COLS {"));
}

#[test]
fn negative_draw_line_drops_out_of_range_rows() {
    // Attack: confused-renderer scribbles to row 99. Without the
    // guard, every backend's array index would panic in production
    // (a DoS shape for any code that feeds a row index from a
    // length-prefixed field).
    assert!(SEMI_SRC.contains("if row >= DISPLAY_ROWS {"));
    assert!(SEMI_SRC.contains("return;"));
    assert!(OLED_SRC.contains("if row >= DISPLAY_ROWS {"));
    assert!(OLED_SRC.contains("return;"));
}

#[test]
fn negative_show_mnemonic_seen_last_gate_prevents_early_dismiss() {
    // Attack: user fat-fingers long-Right on page 0 → 1 → 2 and the
    // wizard returns Confirmed without showing pages 3..8. The
    // `seen_last` gate must require the user to land on page 7 at
    // least once before long-Right confirms.
    assert!(WIZARD_SRC.contains("if seen_last {"));
    // The opposite branch must explicitly NOT confirm — it should
    // fall through to "treat long-Right as next page hint".
    assert!(WIZARD_SRC.contains("// Otherwise treat long-Right as \"next page\" hint."));
    // And `seen_last` must only flip true on the last page.
    assert!(WIZARD_SRC.contains("if page == TOTAL_PAGES - 1 {"));
    assert!(WIZARD_SRC.contains("seen_last = true;"));
}

#[test]
fn negative_enter_mnemonic_rejects_bad_bip39_checksum() {
    // Attack: a typo in the recovery flow yields 24 valid wordlist
    // entries whose 256-bit-entropy checksum is wrong. Returning
    // `Mnemonic` to the caller would provision the wallet with the
    // attacker's seed instead of the user's. The wizard must error.
    assert!(WIZARD_SRC.contains("Err(_) =>"));
    assert!(WIZARD_SRC.contains("show_status(\"Bad checksum\", \"retry...\");"));
    assert!(WIZARD_SRC.contains("Err(WizardError::Cancelled)"));
    // And zeroize must run regardless of the Ok/Err branch.
    let from_indices_pos = WIZARD_SRC
        .find("Mnemonic::from_indices(indices)")
        .expect("from_indices call must exist");
    let after = &WIZARD_SRC[from_indices_pos..];
    let ok_zero = after
        .find("Ok(m) => {")
        .and_then(|p| after[p..].find("indices.zeroize();"));
    let err_zero = after
        .find("Err(_) => {")
        .and_then(|p| after[p..].find("indices.zeroize();"));
    assert!(
        ok_zero.is_some(),
        "indices buffer must be zeroized on the Ok branch (post-`Mnemonic` built)"
    );
    assert!(
        err_zero.is_some(),
        "indices buffer must be zeroized on the Err branch (bad checksum) too"
    );
}

#[test]
fn negative_capture_frame_counter_is_monotonic() {
    // Attack: the host fixture pipeline relies on monotonic
    // [UI-FP] frame indices to line up the N-th frame across runs.
    // A reset-to-zero between frames would collide indices and
    // mask a regression.
    assert!(CAPTURE_SRC.contains("FRAME_COUNTER.fetch_add(1, Ordering::Relaxed)"));
    // And the counter is never explicitly reset anywhere in this
    // file (a future refactor that adds a `store(0, ...)` call would
    // be a regression).
    assert!(!CAPTURE_SRC.contains("FRAME_COUNTER.store(0"));
    assert!(!CAPTURE_SRC.contains("FRAME_COUNTER.swap(0"));
}

#[test]
fn negative_mirror_documented_as_never_ship_in_production() {
    // CLAUDE.md "What NOT to do": no `ui-mirror` in production.
    // The header comment in mirror.rs commits to this. Removing it
    // would lose the "make prod-check rejects" guarantee.
    assert!(MIRROR_SRC.contains("NEVER ship in production."));
    assert!(MIRROR_SRC.contains("`make prod-check` rejects any build that has"));
    // Also: the whole file must be feature-gated.
    assert!(MIRROR_SRC.contains("#![cfg(feature = \"ui-mirror\")]"));
}

#[test]
fn negative_capture_documented_as_dev_only_via_debug_log_feature() {
    // ui-capture lights up `secure_log!` lines; if it ever shipped
    // in production it would dump every UI frame to the secure log
    // — a side channel. The Cargo.toml gate already forces
    // `ui-capture = ["debug-log"]`, and the file itself is
    // feature-gated. Both must hold.
    assert!(CAPTURE_SRC.contains("#![cfg(feature = \"ui-capture\")]"));
    // And the rationale comment binds the trust boundary.
    assert!(CAPTURE_SRC.contains("Default OFF so CI runs stay\n//! quiet."));
}

#[test]
fn negative_capture_requires_debug_log_at_cargo_toml_level() {
    // The Cargo manifest must keep `ui-capture` implying `debug-log`.
    // Without it, a `--features ui-capture` build with no
    // `debug-log` would silently fail to emit anything (because
    // `secure_log!` no-ops out) — a worse failure mode than
    // refusing the combination.
    let cargo = include_str!("../../Cargo.toml");
    assert!(
        cargo.contains("ui-capture = [\"debug-log\"]"),
        "ui-capture must imply debug-log at the manifest level"
    );
}

#[test]
fn negative_noop_input_auto_confirms_short_right() {
    // The noop backend is "auto-confirm Right+Short, immediately."
    // That makes it usable for headless USB but is catastrophic if
    // the same code path ever shipped on a device with a real
    // user — every confirm dialog would auto-accept. Pin the
    // auto-confirm shape AND the comment that names the trade-off,
    // so future readers can't accidentally promote it to production.
    assert!(NOOP_SRC.contains("/// Always returns Right+Short immediately (auto-confirm)."));
    assert!(NOOP_SRC.contains("Some((Button::Right, Press::Short))"));
    // And the file's header docstring names "headless USB HID mode".
    assert!(NOOP_SRC.contains("Used when the device\n//! runs headless (USB HID mode"));
}

#[test]
fn negative_oled_init_returns_silently_when_display_absent() {
    // Attack: bench board boots with no OLED attached, and the
    // init() path tries to enter a tight write loop against an
    // unACKed I2C address. Without the early-return, the boot would
    // wedge before the SE drivers come up. The fallback emits a
    // log line and returns — keeps the rest of the firmware alive.
    assert!(OLED_SRC.contains("[S][OLED] no display found on I2C1 — skipping"));
    let probe_pos = OLED_SRC
        .find("[S][OLED] no display found on I2C1 — skipping")
        .expect("no-display message must exist");
    let after = &OLED_SRC[probe_pos..];
    assert!(
        after.contains("return;"),
        "init() must return early when no display is found"
    );
}

#[test]
fn negative_oled_charge_pump_command_is_present() {
    // The 128×32 SSD1306 modules ship without an external charge
    // pump — the display panel pixel high voltage is generated by
    // the on-chip 7.5V charge pump, enabled by the 0x8D, 0x14
    // command pair. Without it, init() runs to completion but the
    // OLED stays dark. Pin the command pair so a refactor that
    // "cleans up" the init sequence catches this regression.
    assert!(OLED_SRC.contains("0x8D, 0x14, // Charge pump ON"));
}

#[test]
fn negative_pin_random_start_falls_through_on_rng_failure() {
    // F-20 fallback: if `rng_strong::fill` errors, the buffer stays
    // at zero (legacy behaviour). The file documents this trade-
    // off — bricking on transient RNG flake would be worse than
    // degrading scrambling. Pin the comment + the `let _ =` pattern
    // that discards the Result.
    assert!(PIN_SRC.contains("**Fallback on RNG failure:**"));
    assert!(PIN_SRC.contains("let _ = crate::rng_strong::fill(&mut rand_bytes);"));
    // And the loop must explicitly mask to mod 10 — not "& 0x0F"
    // which would skew toward digits 0..=5 even more strongly.
    assert!(PIN_SRC.contains("pin[i] = rand_bytes[i] % 10;"));
}

#[test]
fn negative_pin_confirm_compare_iterates_full_length() {
    // The OR-fold must run for the full PIN length, not stop short.
    // A `for i in 0..diff_first_mismatch` would re-introduce the
    // timing leak.
    assert!(PIN_SRC.contains("for i in 0..PIN_LEN {"));
    // And the diff accumulator must be declared with the OR-then-test
    // shape (not == per-byte).
    assert!(PIN_SRC.contains("let mut diff: u8 = 0;"));
}

#[test]
fn negative_progress_bar_clamps_above_100_pct() {
    // Attack: caller passes 250% (e.g. an off-by-one in a fraction
    // computation). Without the clamp, `pct * 14 + 50` = 3550 → /100
    // = 35, far beyond the 14-cell bar. The `i < filled` test would
    // still bound the writes, but the visual would be a fully filled
    // bar — except a refactor that fed `filled` somewhere else
    // (animation timing, a percentage label) could trust it.
    // The clamp `if percent > 100 { 100 } else { percent }` is the
    // single defence.
    assert!(MOD_SRC.contains("let pct = if percent > 100 { 100 } else { percent };"));
    let bar = ref_render_bar(250);
    assert_eq!(&bar[..], b"[##############]");
}

#[test]
fn negative_oled_flush_resets_address_window_each_call() {
    // Attack: after init(), some other peripheral re-uses the OLED
    // I2C bus, leaves the SSD1306 column/page pointer at an
    // arbitrary location, and the next flush_fb writes 512 bytes
    // starting from there — corrupting an entire half of the
    // display. The defense is that `flush_fb` re-issues the col-0
    // page-0 window command (0x21 0x00 0x7F, 0x22 0x00 0x03) on
    // every frame.
    let flush_pos = OLED_SRC
        .find("fn flush_fb(&self) {")
        .expect("flush_fb must exist");
    let body = &OLED_SRC[flush_pos..];
    // Both column- and page-window commands must appear before the
    // 4×128-byte page write loop.
    let col_cmd = body
        .find("hw::i2c::write(addr, &[0x00, 0x21, 0x00, 0x7F]);")
        .expect("flush_fb must re-set column window 0..127");
    let page_cmd = body
        .find("hw::i2c::write(addr, &[0x00, 0x22, 0x00, 0x03]);")
        .expect("flush_fb must re-set page window 0..3");
    let loop_pos = body
        .find("for page in 0..4 {")
        .expect("flush_fb must contain the per-page write loop");
    assert!(
        col_cmd < loop_pos && page_cmd < loop_pos,
        "flush_fb must re-issue both address-window commands before the page write loop"
    );
}

#[test]
fn negative_show_mnemonic_warning_screen_requires_explicit_right_press() {
    // The warning screen "Write 24 words L=cancel R=show" is the
    // last gate before the words hit the display. The user must
    // press Right to advance — Left cancels. An accidental short
    // press of Left should NOT silently advance into showing the
    // words.
    assert!(WIZARD_SRC.contains("show_status(\"Write 24 words\", \"L=cancel R=show\");"));
    assert!(WIZARD_SRC.contains("Some((Button::Right, _)) => {}"));
    assert!(WIZARD_SRC.contains("Some((Button::Left, _)) => return WizardResult::Cancelled,"));
    assert!(WIZARD_SRC.contains("None => return WizardResult::IdleWipe,"));
}

#[test]
fn negative_capture_emits_full_32_byte_hash() {
    // The fingerprint stream is 64 hex chars per frame (SHA-256 over
    // the framebuffer bytes). A refactor that truncated to 16
    // chars (say, for log-volume reduction) would silently make
    // collisions cheap and invalidate the fixture file. Pin the
    // hex-buffer size verbatim.
    assert!(CAPTURE_SRC.contains("let mut hex = [0u8; 64];"));
    assert!(CAPTURE_SRC.contains("let digest: [u8; 32] = h.finalize().into();"));
    assert!(CAPTURE_SRC.contains("hex[i * 2] = nibble_to_hex(hi);"));
    assert!(CAPTURE_SRC.contains("hex[i * 2 + 1] = nibble_to_hex(lo);"));
}

#[test]
fn negative_ui_init_global_singletons_are_constructed_exactly_once() {
    // Attack: a refactor introduces a second `init()` path (e.g. a
    // recovery flow) that re-runs `Display::new()` / `Input::new()`
    // and overwrites a live OLED handle / fd. The current
    // `static mut DISPLAY: Option<Display>` + "must be called once
    // at boot" comment is the contract. Pin both.
    assert!(MOD_SRC.contains("Must be called once at boot."));
    assert!(MOD_SRC.contains("static mut DISPLAY: Option<Display> = None;"));
    assert!(MOD_SRC.contains("static mut INPUT: Option<Input> = None;"));
}

#[test]
fn negative_show_progress_keeps_brackets_at_fixed_indices() {
    // Attack: a refactor that adds a label to the bar shifts the
    // `[` / `]` by one cell — the OLED row width is 16 and there's
    // no slack. Pin both literal index assignments.
    assert!(MOD_SRC.contains("bar[0] = b'[';"));
    assert!(MOD_SRC.contains("bar[15] = b']';"));
    // And the loop must be 0..14, not 0..16 (which would overflow
    // into the bracket positions).
    assert!(MOD_SRC.contains("for i in 0..14 {"));
}

#[test]
fn negative_semihosting_dead_keymap_falls_through_to_continue() {
    // Attack: a stray byte (or a non-recognised char) blocks the
    // dialog with no easy way out. The fall-through MUST loop back
    // for another read, not return a default event.
    let body_pos = SEMI_SRC
        .find("fn wait_button(&mut self,")
        .expect("wait_button must exist");
    let body = &SEMI_SRC[body_pos..];
    assert!(body.contains("_ => continue,"));
    // And `b'q' | b'Q'` is mapped to long-Left (cancel ergonomics).
    assert!(body.contains("b'q' | b'Q' => {"));
    assert!(body.contains("return Some((Button::Left, Press::Long));"));
}

#[test]
fn negative_seed_wizard_enter_word_back_up_at_position_zero_cancels_word() {
    // Attack: a refactor that mishandles `len == 0` in the letter-
    // entry inner loop could either panic on `len -= 1` or return
    // a default word. The current behaviour is `Cancelled` —
    // bubbled up to `enter_mnemonic` which then decides whether to
    // back up one word (if i>0) or bail out (if i==0).
    assert!(WIZARD_SRC.contains("if len == 0 {"));
    assert!(WIZARD_SRC.contains("return EnterWordResult::Cancelled;"));
    // And the outer-loop policy: at i==0 cancel entire flow.
    assert!(WIZARD_SRC.contains("if i == 0 {"));
    assert!(WIZARD_SRC.contains("return Err(WizardError::Cancelled);"));
}

#[test]
fn negative_choose_setup_mode_long_left_is_always_cancel() {
    // A long-Left on the setup mode menu must NOT confirm whatever
    // option is currently highlighted — it must cancel the flow.
    // Without this, a user who long-pressed the wrong button on
    // "Restore" would proceed into mnemonic entry expecting a
    // cancel.
    assert!(WIZARD_SRC.contains("(Button::Left, Press::Long) => return WizardChoice::Cancelled,"));
}
