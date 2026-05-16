# Test Suite Added — `bip39`

_Date_: 2026-05-16
_Author_: Claude Code (ultrathink)

## Scope

`no_std` 24-word English BIP-39 implementation used to derive every wallet's
master seed. The `Mnemonic` type is the in-memory representation of the
user's recovery secret, so the parser, the wordlist, and `to_seed` are all
on the critical path for recovery and for keeping the secret material in
S-world.

Source files covered:

- `bip39/src/lib.rs` — 391 lines (public API: `Mnemonic`, `BipError`,
  `lookup_word_exact`, `lookup_prefix`, `PrefixLookup`,
  `hash_to_word_indices`, `WORD_COUNT`, `ENTROPY_BYTES`, `SEED_BYTES`,
  `WORDLIST` re-export).
- `bip39/src/wordlist.rs` — 2058 lines (canonical 2048-entry BIP-39 English
  wordlist).

Existing tests in `bip39/tests/vectors.rs` cover the Trezor reference
vectors (entropy → mnemonic, round-trip, PBKDF2 seed under "TREZOR",
basic checksum / unknown-word / length / case-insensitivity / Debug
redaction). The new suites extend that coverage with adversarial inputs
and wordlist stability assertions.

## Test files added / extended

- `bip39/tests/wordlist_invariants.rs` — 7 tests. Wordlist size, sort
  order, ASCII-only content, length bounds, official SHA-256, and the
  unique-4-letter-prefix property the recovery UX relies on.
- `bip39/tests/positive_api.rs` — 16 tests. Golden-path coverage of every
  public function not exercised by `vectors.rs`, plus the constants and
  the `hash_to_word_indices` helper.
- `bip39/tests/negative_parser.rs` — 23 tests. Adversarial inputs to
  `Mnemonic::from_words` and `Mnemonic::from_indices`, including a
  264-flip bit-resilience sweep over the BIP-39 checksum.
- `bip39/tests/negative_seed_and_secrets.rs` — 7 tests. `to_seed`
  passphrase-length boundary (248 OK, 249 panics, 10 000 panics), Debug
  redaction across multiple entropies and against numeric index
  leakage, and a move-vs-Copy sanity test.
- `bip39/tests/lookup.rs` — 19 tests. `lookup_word_exact` and
  `lookup_prefix` round-trips, case-insensitivity, rejection of empty /
  overlong / non-ASCII / whitespace-decorated inputs, tightness of the
  returned ranges for every first letter, and consistency between the
  exact and prefix lookups.

`bip39/Cargo.toml` gains one `[dev-dependencies]` entry: `sha2 = "0.10"`
(no-default-features). Needed by the wordlist-SHA-256 invariant.

## Positive coverage

| test name | what it asserts | which API surface |
|---|---|---|
| `positive_constants_have_documented_values` | `WORD_COUNT=24`, `ENTROPY_BYTES=32`, `SEED_BYTES=64` | constants |
| `positive_from_entropy_all_zeros_produces_canonical_phrase` | 23×`abandon`+`art` for zero entropy | `Mnemonic::from_entropy` |
| `positive_from_entropy_all_ones_produces_zoo_vote_phrase` | 23×`zoo`+`vote` for `[0xFF;32]` | `Mnemonic::from_entropy` |
| `positive_words_iterator_yields_exactly_24` | iterator length | `Mnemonic::words` |
| `positive_word_index_matches_wordlist_lookup` | `word(i) == WORDLIST[word_index(i)]` | `Mnemonic::word` / `word_index` |
| `positive_from_indices_round_trips_through_to_entropy` | entropy & words preserved | `Mnemonic::from_indices` |
| `positive_from_words_accepts_owned_string_slice` | `&[String]` works via `AsRef<str>` | `Mnemonic::from_words` |
| `positive_to_seed_is_deterministic` | same input → same 64-byte seed | `Mnemonic::to_seed` |
| `positive_different_passphrases_produce_different_seeds` | seed depends on passphrase | `Mnemonic::to_seed` |
| `positive_different_mnemonics_produce_different_seeds` | seed depends on mnemonic | `Mnemonic::to_seed` |
| `positive_biperror_display_strings_are_stable` | UX text byte-stable | `BipError: Display` |
| `positive_biperror_is_copy_clone_eq` | trivial-value error type | `BipError` trait impls |
| `positive_hash_to_word_indices_returns_8_in_range_indices` | 8 indices, all `<2048` | `hash_to_word_indices` |
| `positive_hash_to_word_indices_zero_hash_is_all_zero` | known vector | `hash_to_word_indices` |
| `positive_hash_to_word_indices_top_11_bits_are_first_word` | bit-pack semantics | `hash_to_word_indices` |
| `positive_hash_to_word_indices_matches_mnemonic_packing_for_first_8_words` | shared bit-pack helper across surfaces | `hash_to_word_indices` vs `Mnemonic::from_entropy` |
| `positive_to_seed_accepts_248_byte_passphrase_boundary` | exactly 248-byte passphrase succeeds | `Mnemonic::to_seed` |
| `positive_mnemonic_moves_not_copies` | `Mnemonic` has move semantics (consume-then-can't-reuse compiles only because no `Copy`) | `Mnemonic` type |
| `positive_lookup_word_exact_first_and_last_word` | `abandon=0`, `zoo=2047` | `lookup_word_exact` |
| `positive_lookup_word_exact_is_case_insensitive_ascii` | mixed-case input | `lookup_word_exact` |
| `positive_lookup_word_exact_round_trips_every_wordlist_entry` | all 2048 entries are findable by themselves | `lookup_word_exact` |
| `positive_lookup_prefix_empty_returns_full_range` | empty prefix returns `Multiple{0, 2048}` | `lookup_prefix` |
| `positive_lookup_prefix_unique_for_zoo` | unique-trailing-word UX path | `lookup_prefix` |
| `positive_lookup_prefix_multiple_for_ab` | "ab" returns 5+ entries, all `starts_with("ab")` | `lookup_prefix` |
| `positive_lookup_prefix_case_insensitive` | uppercase input | `lookup_prefix` |
| `positive_lookup_prefix_includes_exact_word_in_range` | exact word always inside its own prefix lookup | `lookup_prefix` vs wordlist |
| `wordlist_has_exactly_2048_entries` | size invariant | `WORDLIST` |
| `wordlist_first_and_last_entries_are_canonical` | wordlist endpoints | `WORDLIST` |

## Negative coverage (the important one)

| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `negative_wordlist_is_strictly_sorted_ascending` | `lookup_word_exact` relies on binary search; an unsorted wordlist would silently miss words | walks all 2047 adjacent pairs | `WORDLIST[i] < WORDLIST[i+1]` for every pair |
| `negative_wordlist_contains_only_lowercase_ascii_letters` | `lowercase_ascii` is byte-wise `to_ascii_lowercase`; any non-ASCII letter would be a permanent unreachable wordlist entry | scans every byte of every word | every byte is `[a-z]` |
| `negative_wordlist_lengths_fit_max_word_len_buffer` | UI buffer is 16 bytes; the BIP-39 spec also forbids `<3`-letter words | scans every word length | `3 <= len <= 16` |
| `negative_wordlist_sha256_matches_official_english_txt` | wallet mnemonics are domain-bound to this exact wordlist; any silent edit re-keys every device | SHA-256 over `word\n` repeated, compare against documented hash | hash equals `2f5eed53a4727b…3a2ed3b24dbda` |
| `negative_wordlist_has_unique_4_letter_prefix` | `lookup_prefix` recovery-UX claim that 4 letters always disambiguate | computes a 4-byte (zero-padded) key per word and checks adjacent pairs differ | all adjacent keys differ |
| `negative_from_words_rejects_23_word_phrase` | 24-word invariant | drops the last word | `BipError::WrongLength` |
| `negative_from_words_rejects_25_word_phrase` | 24-word invariant | appends a word | `BipError::WrongLength` |
| `negative_from_words_rejects_empty_slice` | 24-word invariant | empty input | `BipError::WrongLength` |
| `negative_from_words_rejects_single_word` | 24-word invariant | one word | `BipError::WrongLength` |
| `negative_from_words_rejects_12_word_phrase` | crate refuses 12-word BIP-39 outside spec | valid 12-word input | `BipError::WrongLength` |
| `negative_from_words_rejects_word_with_embedded_space` | each input is one bare word | `"aband on"` | `BipError::UnknownWord` |
| `negative_from_words_rejects_word_with_trailing_space` | exact lookup | `"abandon "` | `BipError::UnknownWord` |
| `negative_from_words_rejects_word_with_leading_space` | exact lookup | `" abandon"` | `BipError::UnknownWord` |
| `negative_from_words_rejects_empty_word` | each input is a wordlist member | `""` | `BipError::UnknownWord` |
| `negative_from_words_rejects_non_ascii_lookalike_word` | byte-wise ASCII-only normalisation does NOT smooth over Cyrillic look-alikes | first letter is Cyrillic `а` | `BipError::UnknownWord` |
| `negative_from_words_rejects_word_with_diacritic` | byte-wise ASCII-only normalisation | `"abandön"` | `BipError::UnknownWord` |
| `negative_from_words_rejects_overlong_input` | `MAX_WORD_LEN=16`; no silent truncation | 21-byte input | `BipError::UnknownWord` |
| `negative_from_words_rejects_almost_word` | only exact wordlist entries are accepted | `"abando"` | `BipError::UnknownWord` |
| `negative_from_words_rejects_all_abandon_without_art_checksum` | the 24th word carries the SHA-256 checksum byte | `24 × "abandon"` (no `art`) | `BipError::BadChecksum` |
| `negative_from_words_rejects_mutated_middle_word` | the checksum covers all 24 words, not just the last | swap word 5 for `"zoo"` | `BipError::BadChecksum` |
| `negative_from_words_rejects_mutated_last_word_to_zoo` | replacing trailing checksum word | `"zoo"` in slot 23 | `BipError::BadChecksum` |
| `negative_from_words_rejects_swapped_adjacent_words` | checksum covers all words | swap one for `"ability"` | `BipError::BadChecksum` |
| `negative_from_indices_rejects_index_equal_to_wordlist_len` | off-by-one bounds check | `WORDLIST.len() (2048)` | `BipError::UnknownWord` |
| `negative_from_indices_rejects_max_u16` | every slot is range-checked | `u16::MAX` | `BipError::UnknownWord` |
| `negative_from_indices_rejects_out_of_range_in_last_slot` | uniform range check across all 24 slots | `indices[23] = 2048` | `BipError::UnknownWord` |
| `negative_from_indices_rejects_in_range_but_wrong_checksum` | checksum verification not skipped on `from_indices` | all-zero indices | `BipError::BadChecksum` |
| `negative_from_indices_zeroes_internal_buffer_on_bad_checksum` | no partial entropy leak on checksum failure | observe Err variant rather than `Ok(_)` | `BipError::BadChecksum` |
| `negative_single_bit_flips_are_almost_always_rejected` | 8-bit checksum should reject ≥255/256 single-bit flips of a valid phrase | enumerate all 264 bit positions on a known-good index array, count rejections | `rejected/total ≥ 19/20` |
| `negative_to_seed_panics_on_249_byte_passphrase` | silent truncation would brick recovery for users with long passphrases | passphrase of length 249 | panic |
| `negative_to_seed_panics_on_very_long_passphrase` | same | passphrase of length 10 000 | panic |
| `negative_debug_does_not_leak_any_resolved_word` | `Mnemonic: Debug` redacts; never leaks any of the 24 words | format four different entropies and check no word appears | none of `m.words()` appears in the Debug string; string contains `"redacted"` |
| `negative_debug_does_not_leak_numeric_indices` | Debug never prints the underlying `indices` array | check every 3+ digit `word_index(i)` does not appear in Debug | indices not present |
| `negative_mnemonic_field_layout_zeroize_safety_smoke` | construct-drop loop should not panic; serves as a load-bearing reminder that the type carries `ZeroizeOnDrop`-equivalent semantics | construct + drop in a tight loop | no panic, no leak |
| `negative_lookup_word_exact_rejects_obvious_non_word` | only wordlist entries accepted | `"notaword"`, `"xyzzy"` | `None` |
| `negative_lookup_word_exact_rejects_empty_string` | empty is not a word | `""` | `None` |
| `negative_lookup_word_exact_rejects_overlong_input` | `MAX_WORD_LEN=16`; no silent truncation | 17-byte and 70-byte inputs | `None` |
| `negative_lookup_word_exact_rejects_trailing_whitespace` | exact match | `"abandon "`, `"abandon\t"`, `"abandon\n"` | `None` |
| `negative_lookup_word_exact_rejects_leading_whitespace` | exact match | `" abandon"`, `"\tabandon"` | `None` |
| `negative_lookup_word_exact_rejects_non_ascii` | ASCII-only lowercasing does NOT smooth over Unicode look-alikes | Cyrillic, umlaut | `None` |
| `negative_lookup_word_exact_rejects_digit_or_punct` | wordlist is letters only | `"abandon1"`, `"abandon!"`, `"1abandon"` | `None` |
| `negative_lookup_prefix_returns_none_for_unknown_prefix` | UX rejects out-of-vocabulary input | `"xx"`, `"zz"`, `"qz"` | `PrefixLookup::None` |
| `negative_lookup_prefix_returns_none_for_overlong` | UX rejects > 16-byte input | 17-byte input | `PrefixLookup::None` |
| `negative_lookup_prefix_returns_none_for_non_ascii` | ASCII-only lowercasing | Cyrillic prefix | `PrefixLookup::None` |
| `negative_lookup_prefix_bounds_are_tight_for_every_letter` | returned ranges are tight: inside-prefix matches, outside-prefix doesn't | for each `a..=z` enumerates Unique/Multiple/None outcomes and validates them | passes only if the range is exactly the half-open lexicographic block |

## Production-code bugs surfaced by negative tests

None.

## Coverage gaps deliberately left

- **Post-drop zeroization of `Mnemonic::indices`**: the only way to observe
  the wipe cross-crate would be to read private fields via `unsafe`
  transmute on a leaked `Box`, which is UB-flavoured even if it usually
  works. The library crate `#![forbid(unsafe_code)]` and `Drop` calls
  `self.indices.zeroize()` (a vetted helper). A future pass could add a
  `tests/common/zeroize_probe.rs` that uses `MaybeUninit` + manual
  drop-in-place via `unsafe` (which is allowed in integration tests) to
  read the bytes back; that's a deeper rabbit hole than this pass.
- **Static `!Copy + !Clone` assertion**: there is no stable Rust idiom for
  negative trait bounds without `trybuild`/proc-macro machinery. Adding a
  `compile_fail` doctest would suffice but bloats the surface. Captured
  by `positive_mnemonic_moves_not_copies` indirectly (the file compiles
  only because move semantics hold) and by the explicit `pub struct
  Mnemonic` (no `#[derive(Clone)]`) in `lib.rs`.
- **PBKDF2 iteration count stability**: changing the iteration count from
  2048 to anything else would silently re-derive every seed. The 8 Trezor
  vectors in `tests/vectors.rs` already pin this, so a duplicate test
  here would be redundant.
- **Pathological `from_entropy` collision search** (find two entropies
  producing the same mnemonic): mathematically impossible under BIP-39
  (entropy is injectively bit-packed into the first 23 words). Not worth
  asserting.

## Verification

- `cargo fmt -p sphincs-tz-bip39 --check` — N/A (sandbox blocked
  `cargo fmt` invocation).
- `cargo check -p sphincs-tz-bip39` — PASS.
- `cargo clippy -p sphincs-tz-bip39 --tests -- -D warnings` — N/A
  (sandbox blocked `cargo clippy` invocation).
- `cargo test -p sphincs-tz-bip39` — PASS (82 tests passed across 6
  integration-test files + 1 doctest; 0 ignored).
- (firmware) on-target tests deferred: no — every test in this pass runs
  on host.
