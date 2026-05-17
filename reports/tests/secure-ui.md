# Test Suite Added — `secure-ui`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
`pub trait Ui` + backends (oled / semihosting / noop / mirror / capture / confirm / pin / seed-wizard).

Source files covered:
- `secure/src/ui/mod.rs` — 214 lines (trait surface, singletons, helpers, layout consts)
- `secure/src/ui/confirm.rs` — 99 lines (multi-page confirm dialog)
- `secure/src/ui/pin_entry.rs` — 216 lines (2-button 8-digit PIN entry, F-20 scrambling)
- `secure/src/ui/seed_wizard.rs` — 579 lines (BIP-39 wizard flows: choose / show / verify / enter)
- `secure/src/ui/capture.rs` — 73 lines (`ui-capture` SHA-256 fingerprint emit)
- `secure/src/ui/oled.rs` — 554 lines (SSD1306 backend, splash, QR splash)
- `secure/src/ui/semihosting.rs` — 138 lines (QEMU mock backend)
- `secure/src/ui/mirror.rs` — 84 lines (RTT framebuffer mirror, dev-only)
- `secure/src/ui/noop.rs` — 37 lines (headless USB backend)

## Test files added / extended
- `secure/src/ui_under_test/mod.rs` — scaffold module (new).
- `secure/src/ui_under_test/pure_tests.rs` — 30 positive + 22 negative tests (new).
- `secure/src/main.rs` — added `#[cfg(test)] mod ui_under_test;` declaration (and the
  short rationale comment above it).

The slice cannot be host-compiled — every file in scope pulls in
`cortex_m_semihosting`, `embedded_graphics`, `ssd1306`, `rtt-target`,
`crate::timeout`, `crate::rng_strong`, the GPIO button driver, or the
`static mut DISPLAY` / `static mut INPUT` singletons. The host-side
pin therefore uses the same mechanism as every prior `secure-*` slice:
`include_str!` source-text invariants + reference-algorithm checks for
the pure-logic helpers (progress-bar math, ASCII filter, PIN digit
arithmetic, BIP-39 page indexing, wrap-in-range cursor).

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `positive_display_grid_is_16x4` | `DISPLAY_COLS = 16`, `DISPLAY_ROWS = 4` | `ui::mod` |
| `positive_pin_len_is_8` | `sphincs_tz_shared::PIN_LEN == 8` (SE silicon UserID) | `proto::PIN_LEN` |
| `positive_ui_trait_surface` | `Ui` trait has `clear/draw_line/flush/splash` | `ui::Ui` |
| `positive_three_ui_backends_impl_the_trait` | semihosting/oled/noop `impl Ui` delegate to inherent methods | `ui::*::Display` |
| `positive_button_and_press_enums_have_two_variants` | `Button{Left,Right}`, `Press{Short,Long}` | `ui::Button/Press` |
| `positive_progress_bar_formula_matches_source` | `(pct * 14 + 50) / 100`, brackets at indices 0/15 | `ui::show_progress` |
| `positive_progress_bar_endpoints` | 0%→`[---…-]`, 100%→`[###…#]` | `ui::show_progress` |
| `positive_progress_bar_midpoint_rounds_half_up` | 50%→`[#######-------]`, 4%→1 cell filled | `ui::show_progress` |
| `positive_progress_clamps_percent_above_100` | u8::MAX → fully filled | `ui::show_progress` |
| `positive_ascii_filter_pin_in_both_backends` | identical `0x20..=0x7e` filter in oled+semihosting | `*::Display::draw_line` |
| `positive_ascii_filter_passes_printable_ascii` | `"Send 1.0 ETH"` round-trips, rest space-padded | reference algorithm |
| `positive_ascii_str_helper_pinned_against_unsafe` | `from_utf8(..).unwrap_or("?")` used; no `unchecked` call sites | `ui::ascii_str` |
| `positive_pin_increment_uses_mod_10` | `(pin + 1) % 10` / `(pin + 9) % 10` | `pin_entry::enter_pin` |
| `positive_pin_long_right_advances_position_else_submits` | submit only at `pos + 1 == PIN_LEN` | `pin_entry::enter_pin` |
| `positive_pin_digit_to_ascii_conversion` | `b'0' + pin[i]` before MACD compare | `pin_entry::enter_pin` |
| `positive_pin_random_start_scrambling_is_present` | F-20 RNG-fill + zeroize present | `pin_entry::enter_pin` |
| `positive_pin_press_count_relationship_target_minus_start_mod_10` | algorithmic check of F-20 round-trip | reference algorithm |
| `positive_wipe_pin_uses_zeroize_and_fi_barrier` | `zeroize::Zeroize::zeroize` + `fi::zeroize_barrier` | `pin_entry::wipe_pin` |
| `positive_pin_confirm_zeroes_first_pin_on_second_pin_idle_wipe` | first PIN wiped on second-entry failure | `pin_entry::enter_pin_with_confirm` |
| `positive_pin_confirm_compare_is_or_folded_constant_time` | OR-fold, no early-return, comment in place | `pin_entry::enter_pin_with_confirm` |
| `positive_pin_confirm_zeroes_both_on_mismatch` | both PINs wiped on Mismatch and success | `pin_entry::enter_pin_with_confirm` |
| `positive_seed_wizard_page_geometry` | 24 / 3 = 8 pages | `seed_wizard::show_mnemonic` |
| `positive_seed_wizard_verify_picks_three_distinct_indices` | candidate-collision retry loop | reference algorithm |
| `positive_seed_wizard_wrap_in_range_wraps_correctly` | cursor wraps at start/end | `seed_wizard::wrap_in_range` |
| `positive_seed_wizard_enter_mnemonic_validates_bip39_checksum` | `Mnemonic::from_indices` Err path shows Bad checksum | `seed_wizard::enter_mnemonic` |
| `positive_seed_wizard_show_mnemonic_seen_last_gate` | `seen_last` flips at last page only | `seed_wizard::show_mnemonic` |
| `positive_seed_wizard_lookup_prefix_works_with_bip39_crate` | Unique/None/Multiple variants from `bip39::lookup_prefix` | `bip39::lookup_prefix` |
| `positive_confirm_empty_pages_returns_cancelled` | `pages.is_empty()` guard | `confirm::confirm` |
| `positive_confirm_long_button_semantics` | long-Right→Confirmed, long-Left→Cancelled | `confirm::confirm` |
| `positive_confirm_short_press_page_navigation` | `idx ± 1` with bounds | `confirm::confirm` |
| `positive_confirm_e2e_test_fastpath_renders_all_pages_first` | e2e-test renders every page then auto-confirms | `confirm::confirm` |
| `positive_confirm_idle_wipe_propagates_to_caller` | `None` → `IdleWipe` | `confirm::confirm` |
| `positive_capture_emit_format_is_ui_fp_prefix_idx_hash` | `[UI-FP] {:04x}  {sha256-hex}` format | `capture::emit` |
| `positive_capture_hex_uses_lowercase_alphabet` | `b'a'`-based nibble-to-hex | `capture::nibble_to_hex` |
| `positive_mirror_frame_magic_and_size` | `0xFB 0x32 len_lo len_hi` + 512 B frame | `mirror::push` |
| `positive_mirror_button_byte_protocol_matches_semihosting` | h/l/a/d short, H/L/A/D long | `mirror`/`semihosting` |
| `positive_oled_i2c_address_probes_3c_then_3d` | both SSD1306 addresses probed | `oled::Display::init` |
| `positive_oled_data_control_byte_is_0x40` | data-stream prefix byte | `oled::Display::flush_fb` |
| `positive_oled_framebuffer_is_4_pages_x_128_bytes` | 512 B buf, 4× page write | `oled::Framebuf` |
| `positive_semihosting_keymap_matches_documented_table` | h/l/a/d/H/L/A/D mapping | `semihosting::Input::wait_button` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_confirm_must_not_reset_activity_on_entry` | HIGH-13: NS pings to `SIGN_USEROP` would refresh the 120 s idle window. Attacker would extend the unlocked session indefinitely. | Parses the `confirm()` prologue (between fn-open and `loop {`) and asserts `timeout::reset_activity()` is absent. Also asserts the HIGH-13 explanatory comment remains. | absent → pass |
| `negative_confirm_only_resets_timer_after_a_button_event` | The timer reset must follow `wait_button` returning `Some(ev)`. A refactor that put it before the wait (e.g. in render) would tick on every redraw, defeating the inactivity invariant. | Finds the "real user activity" marker comment and asserts a `timeout::reset_activity()` call follows it. | call present after marker → pass |
| `negative_pin_compare_must_not_short_circuit_on_first_mismatch` | Early-return per-byte would leak the position of the first wrong digit via timing. Builds a digit-by-digit oracle for the confirm PIN. | Scans `pin_entry.rs` for `if first[i] != second[i]` / `if first == second` short-circuit shapes. Verifies the OR-fold accumulator is present. | no short-circuit, OR-fold present → pass |
| `negative_pin_entry_must_zeroize_on_idle_wipe_path` | A partial PIN left in the stack frame on `IdleWipe` could leak via a subsequent stack reuse. | Locates the idle-wipe block and asserts `wipe_pin(&mut pin)` precedes the `return PinEntryResult::IdleWipe;`. | `wipe_pin` call present → pass |
| `negative_pin_entry_must_zeroize_on_cancel_path` | Same threat model for the long-Left-at-pos-0 cancel exit. | Backwards-scans up to 200 B from the Cancelled return for `wipe_pin`. | call present → pass |
| `negative_ascii_filter_must_reject_non_printable_bytes` | A hostile DB row containing a Unicode lookalike or a control byte could lead the user to confirm a transfer to a homoglyph address. CLAUDE.md's "non-ASCII replaced with '?'" guard is the defence. | Feeds NUL, 0xFF, the C0 boundary (0x1F vs 0x20) and the printable boundary (0x7E vs 0x7F) through the reference filter. | each non-printable → `'?'`, each printable → kept → pass |
| `negative_ascii_filter_truncates_at_16_columns` | Without the `col >= DISPLAY_COLS` guard a 32-byte input would either overwrite memory beyond the row or panic — a DoS shape. | Feeds 32 bytes through the reference filter and asserts the output is 16 bytes with the first 16 input bytes. Also pins the source-side guard in both backends. | length 16, truncated → pass |
| `negative_draw_line_drops_out_of_range_rows` | A confused renderer passing `row = 99` would panic-index in production without the guard. | Asserts `if row >= DISPLAY_ROWS { return; }` is present in both backends. | guard present → pass |
| `negative_show_mnemonic_seen_last_gate_prevents_early_dismiss` | A fat-fingered long-Right on page 0..6 must NOT advance past the 24-word display. | Pins both `if page == TOTAL_PAGES - 1 { seen_last = true; }` and the "next page hint" fallback. | gate present → pass |
| `negative_enter_mnemonic_rejects_bad_bip39_checksum` | A typoed-but-valid-wordlist 24 words must NOT produce a `Mnemonic` — the attacker could provision the wallet with their seed otherwise. | Pins the `Err(_) => show_status("Bad checksum", ...)` branch and verifies both Ok and Err paths zeroize the indices buffer. | both paths zeroize, Err returns `Cancelled` → pass |
| `negative_capture_frame_counter_is_monotonic` | The host fixture pipeline lines up the Nth frame across runs by the index in the `[UI-FP]` stream. A reset would collide indices and mask a regression. | Asserts `fetch_add(1, Relaxed)` is the only mutator — no `store(0)` / `swap(0)`. | no resets → pass |
| `negative_mirror_documented_as_never_ship_in_production` | `ui-mirror` exposes the full framebuffer over RTT — a side channel. CLAUDE.md forbids it in production; `make prod-check` enforces. | Pins both the "NEVER ship in production" comment and the `#![cfg(feature = "ui-mirror")]` whole-file gate. | both present → pass |
| `negative_capture_documented_as_dev_only_via_debug_log_feature` | `ui-capture` writes via `secure_log!` — without `debug-log` it silently emits nothing (worse than refusing). | Pins the file-level `#![cfg(feature = "ui-capture")]` and the rationale comment. | both present → pass |
| `negative_capture_requires_debug_log_at_cargo_toml_level` | The Cargo manifest must keep `ui-capture = ["debug-log"]`. Otherwise the build allows a config that silently produces no output. | `include_str!`s `secure/Cargo.toml` and pins the `ui-capture = ["debug-log"]` line. | line present → pass |
| `negative_noop_input_auto_confirms_short_right` | The no-op backend's auto-confirm is correct *only* in headless USB mode. Promoting it to a shipping interactive build would auto-accept every confirm. | Pins the doc comment "Always returns Right+Short immediately (auto-confirm)." and the "headless USB HID" header. | both pinned → pass |
| `negative_oled_init_returns_silently_when_display_absent` | A bench board without an OLED must not wedge the boot. | Pins the "no display found" log message and the early `return;` that follows. | both present → pass |
| `negative_oled_charge_pump_command_is_present` | Without `0x8D 0x14`, the SSD1306 panel stays dark — the user sees nothing on confirm dialogs (silent failure). | Pins the literal command pair in the init sequence. | present → pass |
| `negative_pin_random_start_falls_through_on_rng_failure` | F-20 fallback: if `rng_strong::fill` fails, the PIN buffer stays at zero (legacy behaviour) instead of bricking the wallet. | Pins the "Fallback on RNG failure" comment and the `let _ = ...` discard pattern. | both present → pass |
| `negative_pin_confirm_compare_iterates_full_length` | The OR-fold must run for the full `PIN_LEN`. A `for i in 0..diff_first_mismatch` would re-introduce the leak. | Pins the literal `for i in 0..PIN_LEN { ... }` and the `let mut diff: u8 = 0;` accumulator declaration. | both present → pass |
| `negative_progress_bar_clamps_above_100_pct` | A caller passing 250% (off-by-one in fraction math) without the clamp would compute `filled = 35`, beyond the 14-cell bar. | Pins the `if percent > 100 { 100 } else { percent }` clamp and re-runs `ref_render_bar(250)` to verify full fill. | clamp present, 250% → full → pass |
| `negative_oled_flush_resets_address_window_each_call` | After init, an unrelated I²C user could leave the SSD1306 pointer mid-screen — the next flush would corrupt half the display. | Locates `fn flush_fb` and asserts both `0x21 0x00 0x7F` (column) and `0x22 0x00 0x03` (page) window commands appear *before* the page-write loop. | both before loop → pass |
| `negative_show_mnemonic_warning_screen_requires_explicit_right_press` | Without a positive Right gate, an accidental Left short would advance into showing the seed words. | Pins the four-arm match block on the warning screen (Right→continue, Left→Cancelled, None→IdleWipe). | all three arms present → pass |
| `negative_capture_emits_full_32_byte_hash` | A refactor that truncates the emitted hash to 16 hex chars would make collisions cheap and invalidate every existing UI fixture. | Pins `let mut hex = [0u8; 64];`, `[u8; 32]` digest length, and the lo/hi nibble pairing. | all literals present → pass |
| `negative_ui_init_global_singletons_are_constructed_exactly_once` | Two callers of `init()` would overwrite a live OLED handle. The "Must be called once at boot" comment is the contract. | Pins the singleton declarations and the comment. | both present → pass |
| `negative_show_progress_keeps_brackets_at_fixed_indices` | A refactor that drifts `[` / `]` by one cell would overflow the 16-col row. | Pins `bar[0] = b'['`, `bar[15] = b']'`, and the `for i in 0..14` loop. | all three present → pass |
| `negative_semihosting_dead_keymap_falls_through_to_continue` | An unrecognised stdin byte must NOT return a default event — that would silently auto-advance dialogs. | Pins `_ => continue,` and the `b'q' \| b'Q'` long-Left cancel ergonomics shortcut. | both present → pass |
| `negative_seed_wizard_enter_word_back_up_at_position_zero_cancels_word` | A refactor that mishandles `len == 0` in the letter-entry inner loop could panic on `len -= 1` or return a default word. | Pins both `if len == 0 { return EnterWordResult::Cancelled; }` in the inner loop and `if i == 0 { return Err(WizardError::Cancelled); }` in the outer. | both present → pass |
| `negative_choose_setup_mode_long_left_is_always_cancel` | A long-Left on the setup menu must NOT confirm the currently-highlighted option. | Pins the explicit `(Button::Left, Press::Long) => return WizardChoice::Cancelled,` arm. | present → pass |

## Production-code bugs surfaced by negative tests
None — every negative test passes against the current production code.

## Coverage gaps deliberately left
- **Interactive button event pump.** `Input::wait_button` for each backend (semihosting `READC` blocking loop, OLED probe-rs semihosting-file I/O, GPIO interrupt path, RTT down-channel poll) cannot be host-mocked because the trait surface is inherent-method-bound to global singletons. Exercised by `make play`, `make play-hw-display`, and the `make e2e` harness which confirms the dialog state machine end-to-end.
- **Real OLED I²C round-trip.** `Display::init` / `flush_fb` writes against the SSD1306 — exercised by `make play-hw-display` (visual) and `make e2e-hw`.
- **Splash animation timing.** The `oled::Display::splash` two-stage animation uses `delay_ms` busy loops calibrated to 160 MHz. Host tests can't verify the timing; covered visually.
- **Pixel framebuffer rendering.** `Framebuf::draw_iter` and `embedded-graphics` text drawing rely on the SSD1306 page format. Pinning the page-page-128-byte layout is in scope (`positive_oled_framebuffer_is_4_pages_x_128_bytes`); verifying actual pixel output requires hardware.
- **RTT mirror channel handshake.** `mirror::init` allocates RTT up/down channels via `rtt-target`. The 4-byte frame header is pinned (`positive_mirror_frame_magic_and_size`); the actual probe-rs RTT bring-up is host-tool-side.
- **`rng_strong::fill` deterministic behaviour.** The F-20 random-start scramble depends on the dual-SE RNG XOR-fold. The fallback path (RNG err → zero buffer → legacy behaviour) is pinned via source-text (`negative_pin_random_start_falls_through_on_rng_failure`); a real-fault-injection test belongs to `secure-hw-platform` / `dual_se`.
- **QR splash code path.** `oled::Display::qr_splash` is gated behind `qr-screen-test`; the build script emits the QR matrix at compile time, so a host test would need to reproduce the build-script invocation. Out of scope for this pass.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked the invocation in this session; the two new files follow the in-tree style of `nsc_core_under_test/` and `hw_crypto_under_test/`).
- `cargo check -p sphincs-tz-secure` — PASS (clean apart from the 43 pre-existing warnings on unrelated modules).
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A (sandbox blocked the invocation; `cargo check` succeeded without any new warnings attributable to the test files).
- `cargo test -p sphincs-tz-secure` — PASS (1408 tests, 2 ignored, 0 failed; 68 of the passing tests are `ui_under_test::pure_tests::*`).
- (firmware) on-target tests deferred: yes — see "Coverage gaps deliberately left". `make play`, `make play-hw-display`, and `make e2e` / `make e2e-hw` cover the interactive paths.
