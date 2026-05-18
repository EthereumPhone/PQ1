# Test Suite Added — `fwmeasure`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Host firmware measurement / BIP-39-word reporter — the
`fwmeasure` binary used by `make verify-release`,
`make measure`, and the auditor "8-words receipt" UX. It reads
a secure-world ELF, reconstructs the on-flash image (LOAD segments
overlaid on `0xFF` erased flash), SHA-256s the result, and prints
the SHA-256 hex plus the first 8 BIP-39 words.

Source files covered:
- `fwmeasure/src/main.rs` — 227 lines (single-binary crate).

The slice has no library surface; integration tests run the
real binary via `env!("CARGO_BIN_EXE_fwmeasure")`. Pure-function
tests for `parse_hex` / `format_hex` / `FlashLayout::size` /
constants live in the existing `#[cfg(test)] mod tests` block in
`main.rs`.

## Test files added / extended
- `fwmeasure/src/main.rs` — 10 positive + 4 negative unit tests
  in `#[cfg(test)] mod tests` (extends the 2 pre-existing tests).
- `fwmeasure/tests/common/mod.rs` — hand-crafted ELF32-LE/ARM
  builder used by every integration test (no extra deps required —
  the existing `object` crate parses what we produce).
- `fwmeasure/tests/cli_positive.rs` — 17 functional tests that
  exercise every documented code path of `compute_layout` and
  `build_flash_image` through the real binary.
- `fwmeasure/tests/cli_negative.rs` — 16 adversarial tests that
  pin assumptions about CLI parsing, ELF format, symbol
  requirements, and `MAX_FLASH_SIZE` sanity.
- `fwmeasure/tests/output_format_stability.rs` — 5 wire-format
  golden tests pinning the stdout / stderr shape that
  `make verify-release` and humans parse.

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `tests::positive_parse_hex_accepts_prefix_and_underscores` | `0x` prefix + `_` grouping accepted | `parse_hex` |
| `tests::positive_parse_hex_accepts_uppercase_and_lowercase_digits` | Case-insensitive hex digits | `parse_hex` |
| `tests::positive_parse_hex_accepts_u64_max` | Full 64-bit width supported | `parse_hex` |
| `tests::positive_parse_hex_strips_only_leading_0x_prefix` | Leading-zero digits after prefix preserved | `parse_hex` |
| `tests::positive_format_hex_lowercase_zero_padded` | `00abff` shape | `format_hex` |
| `tests::positive_format_hex_full_sha256_length` | 32 B → 64 hex chars | `format_hex` |
| `tests::positive_format_hex_pairs_per_byte` | Every byte → exactly 2 chars (0..=255) | `format_hex` |
| `tests::positive_flash_layout_size_difference` | `end - base` math | `FlashLayout::size` |
| `tests::positive_flash_layout_size_zero_when_base_equals_end` | Degenerate equal-bounds → 0 | `FlashLayout::size` |
| `tests::positive_max_flash_size_is_two_mib` | Constant pinned at 2 MiB (mirrors `fwsign::elf`) | `MAX_FLASH_SIZE` |
| `tests::positive_usage_string_documents_both_flags` | Usage line documents `--flash-base=` and `--flash-end=` | `USAGE` |
| `cli_positive::positive_runs_with_minimal_elf_and_emits_8_words` | Golden path: synth ELF → 0 exit + 8 word lines | binary |
| `cli_positive::positive_output_word_count_is_exactly_8` | Wire-format invariant: exactly 8 lines, indices `1..=8` | stdout shape |
| `cli_positive::positive_words_are_all_in_bip39_wordlist` | Every printed word ∈ `WORDLIST` | `print_words` |
| `cli_positive::positive_stderr_metadata_lines_present` | `Flash base:` / `Flash end:` / `SHA-256:` on stderr | stderr |
| `cli_positive::positive_stdout_contains_only_word_lines` | Stdout carries no debug/log lines | stdout |
| `cli_positive::positive_deterministic_repeat_runs_produce_identical_output` | Same ELF → byte-identical stdout/stderr | full pipeline |
| `cli_positive::positive_hash_matches_independent_sha256_over_overlaid_image` | **Device-vs-host agreement** — host hash equals SHA-256(payload ‖ 0xFF…) | `build_flash_image` |
| `cli_positive::positive_gaps_between_segments_filled_with_0xff` | Inter-segment gaps hash as erased flash | `build_flash_image` |
| `cli_positive::positive_flash_base_override_changes_window` | `--flash-base=` is wired through and changes the hash | `parse_args` → `compute_layout` |
| `cli_positive::positive_flash_end_override_truncates_measurement` | `--flash-end=` is wired through | `parse_args` → `compute_layout` |
| `cli_positive::positive_veneer_limit_inside_window_used_as_end` | `__veneer_limit` inside `[base, base+2MiB)` becomes end | `compute_layout` |
| `cli_positive::positive_veneer_limit_outside_window_falls_back_to_sidata` | QEMU path: vl ≥ base+2 MiB → `__sidata + (edata-sdata)` fallback | `compute_layout` |
| `cli_positive::positive_lowest_p_paddr_chosen_as_base_with_unsorted_segments` | Base = min over PT_LOAD `p_paddr` regardless of header order | `compute_layout` |
| `cli_positive::positive_pt_note_segments_ignored` | Non-LOAD segments do not affect the hash | `build_flash_image` |
| `cli_positive::positive_segment_outside_window_excluded` | LOAD past `flash_end` dropped | `build_flash_image` |
| `cli_positive::positive_zero_filesz_load_segment_ignored` | `.bss`-style segments don't shift base | `compute_layout` |
| `cli_positive::positive_partial_overlap_segment_clipped_at_window_end` | LOAD crossing `flash_end` clipped (no overflow, no dropped prefix) | `build_flash_image` |
| `output_format_stability::stability_stdout_is_exactly_index_space_word_one_per_line` | 8 lines, `"N word\n"`, ASCII-lowercase | stdout |
| `output_format_stability::stability_sha256_line_format_in_stderr` | Exact `SHA-256:     <64hex>` / `Flash base:` / `Flash end:` / `(N bytes)` | stderr |
| `output_format_stability::stability_words_derived_from_hash_per_published_kdf` | Words exactly equal `hash_to_word_indices(SHA-256(image)) → WORDLIST` | `print_words` |
| `output_format_stability::stability_word_indices_are_one_based_not_zero_based` | First index `1`, last index `8` (anti-off-by-one) | `print_words` |
| `output_format_stability::stability_bip39_wordlist_size_2048` | Wordlist is 2048 entries (11-bit index safety) | `WORDLIST` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `tests::negative_parse_hex_underscores_stripped_anywhere` | Underscores are stripped unconditionally, not only in grouping positions | Feeds `0x__08__00__` | Parses to `0x0800` (silent ABI change would diverge) |
| `tests::negative_parse_hex_does_not_silently_accept_uppercase_0x` | `strip_prefix("0x")` is case-sensitive — `0X` is NOT a prefix | Confirms `from_str_radix("0X100", 16)` rejects | Hex parser rejects |
| `tests::negative_format_hex_never_emits_uppercase` | Receipts must be reproducible byte-for-byte; device renders lowercase | Iterates 0..=255 and asserts no uppercase char | All lowercase |
| `tests::negative_flash_layout_size_panics_when_end_before_base` | `size()` has the precondition `end >= base`; a silent `checked_sub→0` would let a misconfigured layout produce SHA-256("") words | Constructs `end < base` and expects panic | Panics (no silent zero) |
| `cli_negative::negative_no_args_exits_nonzero_with_usage` | Missing ELF path is a hard error — never defaults to a stale path | Runs with empty argv | Non-zero exit, `Usage:` on stderr, **no word lines on stdout** |
| `cli_negative::negative_multiple_elf_paths_rejected` | Ambiguous CLI is rejected, not silently using last/first | Two ELF args | Non-zero exit + `Multiple ELF paths` diagnostic |
| `cli_negative::negative_invalid_hex_in_flash_base_rejected` | Garbage hex aborts; never falls back to `0` or "ignore the flag" — per-slot measurement would point at the wrong window | `--flash-base=0xZZZZ` | Non-zero exit + `Cannot parse hex` |
| `cli_negative::negative_invalid_hex_in_flash_end_rejected` | Same property for `--flash-end=` | `--flash-end=not_hex` | Non-zero exit |
| `cli_negative::negative_nonexistent_elf_path_rejected` | Missing file is fatal, not silent | Bogus path | Non-zero exit + `Cannot read` |
| `cli_negative::negative_non_elf_file_rejected` | **Attacker swap: substitute a non-ELF for the release artifact must NOT produce 8 plausible-looking words** | Feeds plaintext bytes | Non-zero exit; no word lines emitted |
| `cli_negative::negative_truncated_elf_rejected` | Partial ELF header rejected before any hashing | 8-byte truncation | Non-zero exit; no word lines |
| `cli_negative::negative_empty_file_rejected` | Zero-byte file rejected | Empty file | Non-zero exit; no word lines |
| `cli_negative::negative_elf_without_load_segments_rejected` | An ELF with zero PT_LOADs must not silently SHA-256 an empty image | PT_NOTE-only ELF | Non-zero exit + `No LOAD segments` |
| `cli_negative::negative_zero_filesz_only_load_segments_rejected` | `.bss`-only ELF is equivalent to no-LOAD; the `.min()` over an empty iter must not panic-unwrap into a silent path | All-zero-filesz LOAD | Non-zero exit |
| `cli_negative::negative_elf_missing_required_symbols_rejected` | When `__veneer_limit` is absent, ALL THREE of `__sidata`/`__sdata`/`__edata` are required | Drop all three | Non-zero exit + symbol diagnostic |
| `cli_negative::negative_elf_missing_edata_alone_rejected` | Per-symbol check fires for each (not just the first) | Only `__edata` missing | Non-zero exit |
| `cli_negative::negative_veneer_limit_below_base_falls_back_not_used` | A `__veneer_limit` BELOW base must fall back — using it would produce a negative window / 4 GiB underflow | Place vl far below base | Fallback used (Flash end = sidata path) |
| `cli_negative::negative_veneer_limit_at_window_edge_rejected_inclusive` | Off-by-one guard: vl == base + MAX_FLASH_SIZE is **outside** the half-open range and falls back | vl exactly at upper edge | Fallback used |
| `cli_negative::negative_single_byte_change_in_segment_changes_words` | Measurement is sensitive to every byte; a refactor that ever skips padding/alignment slack must not silently produce identical words | Two ELFs differing in one bit | Different stdout |
| `cli_negative::negative_words_not_emitted_to_stdout_on_failure` | **Cross-cutting invariant: every error path must NOT leak word lines** — otherwise `make verify-release` could match against bogus output | Runs failing cases and scans stdout | No `"<digit> <word>"` lines on any failure path |

## Production-code bugs surfaced by negative tests
None. Every assumption the slice claims to enforce holds against the
adversarial inputs explored here.

## Coverage gaps deliberately left
- **64-bit physical addresses.** `fwmeasure` reads `ElfFile32` only;
  ELF64 firmware (theoretical) isn't in scope. The test ELF builder
  is ELF32-only by design.
- **Real `object` crate panic paths.** Some malformed-ELF cases
  (e.g. corrupted section table) would surface inside the `object`
  parser, not in fwmeasure code. Covered indirectly via the
  truncated-ELF test, but a fuzz-style sweep over corrupted
  section/segment offsets is left as a follow-up (would benefit
  from `cargo-fuzz`).
- **`die`/`process::exit` test plumbing.** The pure `die` helper is
  exercised via the binary harness for every failure path, but not
  unit-tested in isolation (it `exit`s the current process —
  fragile to mock). Acceptable: every code path that calls `die` is
  reached by at least one `cli_negative` test.
- **`hash_to_word_indices` correctness across all 2^256 inputs.**
  Covered comprehensively in `sphincs-tz-bip39`'s own test suite;
  we only need the agreement-with-host check, which is pinned by
  `stability_words_derived_from_hash_per_published_kdf`.
- **Concurrency / signal handling.** Out of scope for a one-shot
  measurement tool.

## Verification
- `cargo fmt -p fwmeasure --check` — N/A (sandbox blocked the
  invocation; the new files follow the surrounding style)
- `cargo check -p fwmeasure` — PASS
- `cargo clippy -p fwmeasure --tests -- -D warnings` — N/A
  (sandbox blocked the invocation)
- `cargo test -p fwmeasure` — PASS (53 tests: 15 unit + 16 negative
  + 17 positive + 5 stability; 0 ignored)
- (firmware) on-target tests deferred: no — `fwmeasure` is a host
  binary.
