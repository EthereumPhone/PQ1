# Test Suite Added — `fuzz`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope

cargo-fuzz harness (target binaries only — corpora/ excluded).

Source files covered:

- `fuzz/Cargo.toml` — 70 lines; declares the standalone workspace, the 5
  registered `[[bin]]` libFuzzer targets, and the parser-crate
  dependencies they reach.
- `fuzz/fuzz_targets/aa_userop_parse_header.rs` — 22 lines
- `fuzz/fuzz_targets/apdu_parse_header.rs` — 18 lines _(unregistered orphan; see bugs section)_
- `fuzz/fuzz_targets/hid_frame_assembler.rs` — 44 lines _(unregistered orphan)_
- `fuzz/fuzz_targets/tx_core_eip1559_parse.rs` — 19 lines
- `fuzz/fuzz_targets/tx_core_rlp_decode_item.rs` — 19 lines
- `fuzz/fuzz_targets/tx_erc20_parse_calldata.rs` — 18 lines
- `fuzz/fuzz_targets/tx_erc20_verify_bundle.rs` — 25 lines

The slice has no `src/lib.rs`: every "production" file in scope is
either declarative TOML or a trivial `fuzz_target!(|data| { … })`
wrapper around a parser that already lives in a workspace crate. So
the test surface is two things:

1. The static wiring (`Cargo.toml` ↔ `fuzz_targets/`) that determines
   what `cargo fuzz list` actually exposes.
2. The public-API contract every `fuzz_target!` body relies on — i.e.
   the parsers in `pqsigner-aa`, `pqsigner-tx-core`, `pqsigner-tx`, and
   `sphincs-tz-shared::apdu_framing`.

## Test files added / extended

- `fuzz/tests/harness_structure.rs` — **11 positive, 9 negative** tests
  (one negative `#[ignore]`-marked, see bugs section). Reads
  `Cargo.toml` + walks `fuzz_targets/` to assert the wiring stays
  consistent. Catches every silent-coverage-loss pattern the harness is
  susceptible to (orphan target file, missing `[[bin]]`, renamed bin,
  feature-flag leak into deps, `test = false` removed, etc.).
- `fuzz/tests/parser_smoke.rs` — **11 positive, 23 negative** tests.
  For every parser entry point one of the seven `fuzz_targets/*.rs`
  files calls, re-invokes that parser with hand-picked pathological
  inputs (empty / one-under-boundary / oversize / non-canonical
  encodings / out-of-sequence frames / wrong-channel hijack / max-u16
  length prefix). Each negative names the assumption being attacked.
  Doubles as a compile-time API-drift guard: if a parser's signature
  ever changes, this file fails to build before anyone runs
  `cargo fuzz` and finds the harness no longer compiles.
- `fuzz/Cargo.toml` — added a `[dev-dependencies]` block (`toml`,
  `pqsigner-proto`, `sphincs-tz-shared`). Comment notes the deps are
  test-only and don't link into the libFuzzer bins.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_cargo_toml_parses_as_toml` | The Cargo manifest is well-formed TOML | `fuzz/Cargo.toml` |
| `positive_package_name_is_pqsigner_fuzz` | Crate name pinned to `pqsigner-fuzz` (Makefile + docs reference it) | `[package].name` |
| `positive_package_publish_is_false` | Crate cannot be uploaded to crates.io | `[package].publish` |
| `positive_standalone_workspace_block_present` | `[workspace]` block prevents fuzz deps from sucking into main workspace | `fuzz/Cargo.toml` |
| `positive_cargo_fuzz_metadata_present` | `[package.metadata.cargo-fuzz] = true` flag set | `[package.metadata]` |
| `positive_every_registered_bin_points_to_existing_file` | Every `[[bin]] path =` resolves on disk | `[[bin]]` × 5 |
| `positive_every_registered_bin_uses_test_doc_bench_false` | All three flags set false (must, or `cargo test` link-fails) | `[[bin]]` × 5 |
| `positive_every_registered_bin_name_matches_filename_stem` | bin name == filename stem (Makefile + `cargo fuzz list` rely on this) | `[[bin]]` × 5 |
| `positive_every_target_file_uses_fuzz_target_macro` | All 7 `.rs` files invoke `fuzz_target!(…)` | `fuzz_targets/*.rs` |
| `positive_every_target_file_has_no_main_attribute` | All 7 files declare `#![no_main]` | `fuzz_targets/*.rs` |
| `positive_strip_comments_actually_works` | Self-test of the comment-stripper helper | n/a |
| `positive_userop_parse_header_accepts_exact_length_buffer` | 305-byte buffer is the documented minimum | `pqsigner_aa::userop::parse_header` |
| `positive_userop_parse_header_accepts_oversized_buffer` | Trailing inner-tx bytes are ignored, not consumed | `pqsigner_aa::userop::parse_header` |
| `positive_rlp_decode_item_single_byte` | 0x00..=0x7f is the single-byte RLP form | `pqsigner_tx_core::rlp::decode_item` |
| `positive_rlp_decode_item_empty_string` | 0x80 → empty Bytes item | `pqsigner_tx_core::rlp::decode_item` |
| `positive_rlp_decode_item_empty_list` | 0xc0 → empty List item | `pqsigner_tx_core::rlp::decode_item` |
| `positive_erc20_calldata_decodes_well_formed_transfer` | Standard `transfer(address,uint256)` selector + body decodes | `pqsigner_tx::erc20::calldata::parse_erc20_calldata` |
| `positive_apdu_parse_header_accepts_4_byte_header_with_lc0` | 4-byte short APDU → Lc=0, empty data | `sphincs_tz_shared::apdu_framing::parse_apdu_header` |
| `positive_apdu_parse_header_accepts_5_byte_header_with_lc0_and_no_data` | 5-byte header with Lc=0 byte present | `sphincs_tz_shared::apdu_framing::parse_apdu_header` |
| `positive_hid_assembler_single_frame_apdu_completes` | One HID frame carrying a 4-byte APDU → `ApduComplete(4)` | `HidFrameAssembler::process_frame` |

## Negative coverage (the important one)

### Harness-wiring negatives (`tests/harness_structure.rs`)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_every_fuzz_target_file_is_registered_as_bin` _(`#[ignore]`)_ | "Every `fuzz_targets/*.rs` is exposed by `cargo fuzz list`." | Walks the dir; subtracts the set of `[[bin]]` names from the set of `.rs` stems | `orphans.is_empty()` — **currently FAILS** (2 orphan files; see bugs section) |
| `negative_every_bin_path_resolves_to_a_real_file` | "Every `[[bin]] path =` points at a file on disk." | Loop, `Path::is_file` | All paths exist |
| `negative_no_two_bins_share_a_path` | "No two bins compile the same source." | `BTreeSet` insert; panics on duplicate | All paths unique |
| `negative_no_two_bins_share_a_name` | "No two bins share an invocable name." | `BTreeSet` insert | All names unique |
| `negative_no_bin_path_escapes_fuzz_targets_dir` | "`[[bin]] path =` never escapes `fuzz_targets/` via `..` or absolute path — a path traversal would let the harness silently turn a workspace-crate file into a libFuzzer bin with libFuzzer's rustc flags applied." | Substring check `..` / leading `/` / `fuzz_targets/` prefix | All paths sandboxed |
| `negative_no_target_file_uses_unwrap_or_expect_or_panic` | "Fuzz targets propagate Err, never turn rejection into a libFuzzer crash." | Reads each `.rs`, strips comments, scans for `unwrap()` / `expect(` / `panic!(` / `unimplemented!(` / `todo!(` | No matches — an unwrap would invert the parser-contract: "reject malformed bytes" becomes "crash on malformed bytes" |
| `negative_no_target_file_pulls_in_heap_allocator` | "Fuzz targets mirror the firmware's no-alloc invariant." | Scans for `extern crate alloc`, `use std::collections::`, `Box::new`, `alloc::vec::Vec` | No matches — alloc OOMs would be conflated with parser bugs |
| `negative_no_target_file_uses_unsafe` | "Fuzz harness doesn't smuggle around the safe-Rust contract." | Scans (post-comment-strip) for `unsafe {` / `unsafe fn` | No matches — `unsafe` in a target could paper over the very memory-safety bugs the harness exists to find |
| `negative_no_dev_feature_leaked_to_parser_deps` | "Fuzz harness tests prod code, not dev shortcuts." | Reads `[dependencies]`, checks no `features = [..]` contains `mock-se`, `debug-log`, `e2e-test`, `otp-hardcoded-master-key`, `ui-capture` (CLAUDE.md "What NOT to do") | No leaks |
| `negative_makefile_has_a_recipe_for_every_registered_bin` | "`make fuzz-list` and the `cargo +nightly fuzz run …` lines stay in sync with `[[bin]]`." | Reads top-level Makefile; checks the bin name appears verbatim | Every bin reachable from `make` |

### Parser-contract negatives (`tests/parser_smoke.rs`)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_userop_parse_header_rejects_empty_buffer` | "Parser bounds-checks before any read." | Pass `&[]` | `Err(WireParseError::Truncated)` |
| `negative_userop_parse_header_rejects_one_byte_under_header_len` | "Off-by-one boundary handled." | Pass `vec![0; USEROP_HEADER_LEN - 1]` | `Err(Truncated)` |
| `negative_userop_parse_header_never_panics_on_pathological_inputs` | "ANY byte sequence terminates." | 6 hostile seeds (empty, all-0xFF oversize, alternating-bits, …) | No panic |
| `negative_rlp_decode_item_rejects_empty_input` | ".first() on empty slice would crash." | `&[]` | `Err(Truncated)` |
| `negative_rlp_decode_item_rejects_non_canonical_short_string_with_low_byte` | "Two distinct RLP encodings can't hash to the same userOpHash." | `0x81 0x42` (canonical form is `0x42`) | `Err(NonCanonical)` |
| `negative_rlp_decode_item_rejects_length_overflow_short_string` | "Declared length > remaining buffer is caught." | `0x82 0xAA` (says 2 bytes, gives 1) | `Err(Truncated)` |
| `negative_rlp_decode_item_rejects_long_string_with_truncated_lenlen_field` | "Parser doesn't index past end-of-buffer when reading length-of-length." | `0xb8` alone | `Err(Truncated)` |
| `negative_rlp_decode_item_rejects_overlong_lenlen_field` | "Short-form encoding required for ≤55-byte strings." | 0xb8 + len=16 + 16 bytes (should be short form) | `Err(NonCanonical)` |
| `negative_rlp_decode_item_never_panics_on_pathological_inputs` | "ANY byte sequence terminates." | Includes the `0xbf …` long-string with claimed-huge-length attack | No panic |
| `negative_eip1559_parse_rejects_empty_envelope` | "Parser handles empty envelope without panic." | `&[]` | `Err(EmptyEnvelope)` |
| `negative_eip1559_parse_rejects_non_eip1559_type_byte` | "Wallet won't sign a legacy / EIP-2930 / unknown-type tx the trusted UI didn't see." | 6 type bytes (0x00, 0x01, 0x03, 0x7f, 0x80, 0xff) | `Err(NotEip1559)` or `Err(Rlp(_))` |
| `negative_eip1559_parse_rejects_trailing_bytes_after_envelope` | "No invisible bytes can sneak past the displayed envelope." | Valid 0x02 + `0xc0` (empty list) + `0xde 0xad` trailer | Returns `Err`, doesn't `Ok` |
| `negative_eip1559_parse_never_panics_on_pathological_inputs` | "ANY byte sequence terminates." | 5 seeds incl. all-0xFF 4096-byte and a long alternating stream | No panic |
| `negative_erc20_calldata_rejects_short_input` | "len < 4 doesn't index into [0..4]." | All lengths 0..4 | `None` |
| `negative_erc20_calldata_rejects_address_word_with_nonzero_top_bytes` | "Non-zero left-pad on address word can't spoof a 'transfer to Vitalik' screen." | Selector + dirty-top-byte word + amount | `None` |
| `negative_erc20_calldata_rejects_wrong_arglen_for_known_selector` | "Exact arglen enforced — `transfer` needs exactly 64 body bytes." | 5 different wrong lengths | `None` |
| `negative_erc20_calldata_rejects_unknown_selector_silently` | "Unknown selector falls through to blind-sign (None), never misclassified." | Selector `0x12345678` + 64 zero bytes | `None` |
| `negative_erc20_calldata_approve_max_amount_does_not_panic` | "`approve(spender, uint256.max)` is well-formed and must decode." | Approve selector + address + all-0xFF amount | `Some(Approve)` |
| `negative_erc20_verify_bundle_rejects_empty_input` | "Parser bounds-checks the 30-byte header." | `&[]` | `None` |
| `negative_erc20_verify_bundle_rejects_truncated_header` | "Off-by-one boundary on header." | All lengths 0..30 except full | `None` |
| `negative_erc20_verify_bundle_rejects_zero_root_for_random_garbage` | "Verifier never accepts under the wrong root." | Structurally-valid bundle + all-zero root | `None` (Merkle step rejects) |
| `negative_erc20_verify_bundle_never_panics_on_pathological_inputs` | "ANY byte sequence terminates." | Includes the `name_len = 0xFF` attack | No panic |
| `negative_apdu_parse_header_rejects_input_under_4_bytes` | "Parser checks the 4-byte header floor before any field read." | All lengths 0..4 | `Err(HeaderTooShort)` |
| `negative_apdu_parse_header_rejects_lc_overrun` | "Lc claim is validated against remaining buffer." | Lc=10, 0 data bytes follow | `Err(LcOverrun)` |
| `negative_apdu_parse_header_rejects_lc_overrun_with_partial_data` | "Partial-data Lc overrun caught." | Lc=10, 5 data bytes | `Err(LcOverrun)` |
| `negative_apdu_parse_header_rejects_max_lc_with_no_room` | "Lc=0xFF with no body bytes is rejected." | 5-byte header with Lc=0xFF | `Err(LcOverrun)` |
| `negative_apdu_parse_header_never_panics_on_pathological_inputs` | "ANY byte sequence terminates." | Includes `vec![0xFF; 260]` (regression seed for checked_add) | No panic |
| `negative_hid_assembler_drops_frame_shorter_than_3_bytes` | "n < 3 (no channel+tag prefix) doesn't panic." | n ∈ {0, 1, 2} | `Dropped` |
| `negative_hid_assembler_drops_frame_when_n_exceeds_report_len` | "Attacker-controlled `n` can't read past the USB stack's buffer." | `n = HID_REPORT_SIZE + 1` | `Dropped` |
| `negative_hid_assembler_drops_zero_length_apdu_first_frame` | "Zero-length APDU doesn't leak into infinite NeedMore loop." | First frame with len=0 | `Dropped` |
| `negative_hid_assembler_drops_oversize_apdu` | "MAX_APDU_RX cap enforced — 65535-byte claim doesn't corrupt memory." | First frame with len=0xFFFF | `Dropped` |
| `negative_hid_assembler_drops_continuation_with_wrong_sequence` | "Out-of-order continuation can't smuggle data into an in-flight APDU." | seq=99 instead of expected seq=1 | `Dropped` |
| `negative_hid_assembler_drops_continuation_with_wrong_channel` | "Malicious host can't hijack an in-flight APDU by switching channels mid-stream." | Channel changes between frame 1 and frame 2 | `Dropped` |
| `negative_hid_assembler_unknown_tag_dropped` | "Only HID_TAG_APDU / HID_TAG_PING are processed." | Tag = 0x42 | `Dropped` |
| `negative_hid_assembler_never_panics_on_random_byte_streams` | "ANY (n, report) shape terminates." | 8 × random frame stream | No panic |
| `negative_all_parsers_terminate_on_max_u16_length_prefix` | "Length-prefix overflow attack is rejected by every parser, not just one." | Same buffer fed to all 6 parsers | No panic |

## Production-code bugs surfaced by negative tests

### Bug 1: Two orphan fuzz target files not wired into `Cargo.toml`

**Files**: `fuzz/fuzz_targets/apdu_parse_header.rs`, `fuzz/fuzz_targets/hid_frame_assembler.rs`
**Surfaced by**: `negative_every_fuzz_target_file_is_registered_as_bin`

Both files exist on disk and reference `sphincs_tz_shared::apdu_framing::*` APIs, but they are **NOT** registered as `[[bin]]` entries in `fuzz/Cargo.toml`, **NOT** included in the `make fuzz-*` recipes, and `sphincs-tz-shared` is not declared in `[dependencies]`. As a result, `cargo fuzz list` will not show them; `cargo fuzz run apdu_parse_header` will fail. The libFuzzer harness silently provides *zero* coverage of the APDU/HID frame parsers — the very first layer every USB byte hits.

The two files mirror the proptest siblings in `shared/src/apdu_framing.rs::fuzz_props`. The fix is mechanical:

1. Add `sphincs-tz-shared = { path = "../shared" }` to `fuzz/Cargo.toml` `[dependencies]`.
2. Add two `[[bin]]` entries:
   ```toml
   [[bin]]
   name = "apdu_parse_header"
   path = "fuzz_targets/apdu_parse_header.rs"
   test = false; doc = false; bench = false
   [[bin]]
   name = "hid_frame_assembler"
   path = "fuzz_targets/hid_frame_assembler.rs"
   test = false; doc = false; bench = false
   ```
3. Add matching `make fuzz-apdu-parse-header` / `make fuzz-hid-frame-assembler` recipes to the top-level `Makefile` (currently `.PHONY` lists 5 targets; needs to become 7).
4. Remove the `#[ignore]` on `negative_every_fuzz_target_file_is_registered_as_bin`.

The test is left asserting the correct outcome (`orphans.is_empty()`) and marked `#[ignore]` per the test-pass protocol. Production code is wrong, test is right — a follow-up pass should land the four-line `Cargo.toml` + `Makefile` patch and un-ignore the test in the same commit.

Out of scope to fix in this pass per the task brief ("if production code is wrong, log it and leave the test asserting the correct outcome marked `#[ignore]`").

## Coverage gaps deliberately left

- **Compile-fail / `trybuild` negatives for `#![no_main]`.** Would catch a future "`fuzz_targets/foo.rs` forgot `#![no_main]`" regression cleanly via a compile-fail test. Skipped because the regex-style negative (`positive_every_target_file_has_no_main_attribute`) gives the same guarantee without dragging in `trybuild` + a nightly toolchain.
- **Coverage-quality test for the corpora.** The brief excluded `corpus/`; we don't assert "every corpus entry causes the parser to take a code path not yet visited" because that requires actually running `cargo +nightly fuzz cmin`. The harness-structure tests do guarantee that every target is at least *invocable*, which is the precondition.
- **On-target verification.** All tests added run on host; the parsers are pure-logic, no `cfg(target_arch = "arm")` gates needed. The firmware-only KDF / NSC pointer-validation paths CLAUDE.md highlights are out of scope for the fuzz crate (those are exercised by `pin-gate-hw-counter-e2e` and the proptest sibling).
- **Concurrency / re-entrancy of `HidFrameAssembler`.** The struct is `Copy` and the firmware drives one instance per channel from a single task, so multi-threaded fuzz seeds would be a fiction.
- **`pqsigner-tx-core::eip1559::parse` "trailing bytes after a valid envelope"** got an over-broad assertion (`Err _`, not `Err(TrailingBytes)`) because the parser routes via `rlp::decode_item` first — RLP rejects the malformed list before we reach the trailing-bytes check. A finer test would need to construct a valid 9-field list followed by trailing bytes; deferred (the broad assertion still catches the "must NOT return Ok" property, which is the security one).

## Verification

- `cargo fmt -p pqsigner-fuzz --check` — **N/A** (command denied by session permission gate; `cargo fmt` not in the auto-allow list for this session — left as a manual follow-up).
- `cargo check -p pqsigner-fuzz` — **PASS** (run as `cargo check --tests` from the `fuzz/` standalone workspace; the package is `pqsigner-fuzz`).
- `cargo clippy -p pqsigner-fuzz --tests -- -D warnings` — **N/A** (command denied by session permission gate; same reason as fmt).
- `cargo test -p pqsigner-fuzz` — **PASS** (65 tests, 1 ignored — the orphan-detector waiting on the Cargo.toml fix above).
- (firmware) on-target tests deferred: **no** — every test in this pass is pure host code.
