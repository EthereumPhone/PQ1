# Test Suite Added — `secure-tx-typed-call`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Solidity-ABI typed-call parser + tx/mod.rs shim.

Source files covered:
- `secure/src/tx/mod.rs` — 30 lines (pure re-export shim; no behaviour to test directly)
- `secure/src/tx/typed_call/mod.rs` — 15 lines (sub-module declarations)
- `secure/src/tx/typed_call/parser.rs` — 1046 lines (text-signature tokenizer)
- `secure/src/tx/typed_call/abi.rs` — 1092 lines (calldata shape/walk pass + word readers)

The slice has no public API of its own (`pub(crate)`-only). All new tests
therefore live in the existing `#[cfg(test)] mod tests` blocks within
the source files; the `sphincs-tz-secure` crate has no `[lib]` target, so
an integration `tests/` directory is not an option.

## Test files added / extended
- `secure/src/tx/typed_call/parser.rs` — extended `mod tests` with **14 positive** + **23 negative** new tests (in addition to the pre-existing 18 tests).
- `secure/src/tx/typed_call/abi.rs` — extended `mod tests` with **15 positive** + **20 negative** new tests (in addition to the pre-existing 13 tests). One of the negatives is `#[ignore]`-flagged — it pins the correct behaviour for a production-code overflow bug surfaced by this pass (see below).

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `parser::positive_constants_are_frozen` | `MAX_ARGS=16, MAX_TYPE_ARENA=32, MAX_NESTING=8, MAX_TUPLE_FIELDS=8` are pinned (curator-parity contract) | parser constants |
| `parser::positive_every_uint_width_accepted` | every `uintN` with N ∈ {8,16,…,256} round-trips through `parse_text_sig` and resolves to `TypeRef::Uint(N)` | `parse_text_sig`, `parse_uint_width` |
| `parser::positive_every_int_width_accepted` | every `intN` width round-trips identically | `parse_text_sig`, `parse_uint_width` |
| `parser::positive_name_with_underscores_digits` | `_safeBatchTransfer42_v1(…)` is admitted (matches `is_valid_name`) | `parse_text_sig`, `is_valid_name` |
| `parser::positive_lone_underscore_name` | `_(uint256)` is admitted | `parse_text_sig`, `is_valid_name` |
| `parser::positive_solidity_keyword_as_name_allowed` | a function literally named `bool` is admitted (whitelist is for type tokens, not names) | `parse_text_sig`, `is_valid_name` |
| `parser::positive_max_args_accepted` | exactly `MAX_ARGS` (16) top-level args parses | `parse_text_sig`, `MAX_ARGS` |
| `parser::positive_max_tuple_fields_accepted` | tuple with exactly `MAX_TUPLE_FIELDS` (8) fields parses | `parse_type` (tuple branch) |
| `parser::positive_max_nesting_arrays_accepted` | array nested exactly `MAX_NESTING` (8) deep parses | `parse_type` (array branch) |
| `parser::positive_fresh_arena_per_call` | three back-to-back parses of MAX_ARGS each succeed (arena is per-call, not global) | `parse_text_sig` |
| `parser::positive_name_slice_borrows_from_input` | the returned `ParsedSig.name` shares pointer identity with the input slice (zero-copy guarantee) | `parse_text_sig` (lifetime) |
| `abi::positive_constants_are_frozen` | `MAX_DYNAMIC_LEN = 1 << 20` | abi constants |
| `abi::positive_all_static_primitives_walk` | walk accepts every static primitive: address, bool, uint8, uint256, int8, int256, bytes1, bytes32 | `walk`, `classify` |
| `abi::positive_max_static_array_accepted` | `T[256]` (the cap) walks | `walk`, `classify` |
| `abi::positive_multiple_dyn_args_canonical_packing` | `f(bytes,bytes)` with back-to-back canonical tails walks; each `body_off` points at its length word | `walk` (tail_cursor accounting) |
| `abi::positive_string_walks_like_bytes` | `f(string)` admits the same shape as `f(bytes)` | `walk`, `classify` |
| `abi::positive_dyn_bytes_zero_length` | zero-length dynamic bytes is canonical and accepted | `walk` (zero-len edge) |
| `abi::positive_dyn_array_of_addresses` | `f(address[])` walks; count + body_off recorded | `walk` (DynArrayPrim) |
| `abi::positive_dyn_array_of_bool` | `f(bool[])` walks; downstream `read_bool` decodes both elements | `walk`, `read_bool` |
| `abi::positive_mixed_static_then_dynamic` | `f(address,bytes)` head/tail layout is respected | `walk` (mixed classes) |
| `abi::positive_empty_body_zero_arg_sig` | `f()` with empty body returns `arg_count=0` | `walk` (no-args edge) |
| `abi::positive_static_array_of_bytes32` | `f(bytes32[2])` walks | `walk`, `classify` |
| `abi::positive_read_address_min_max_offsets` | `read_address` reads canonical addresses at offsets 0 and 32 | `read_address` |
| `abi::positive_read_u256_full_value` | `read_u256` preserves every byte of a 32-byte word | `read_u256` |
| `abi::positive_read_bool_true_and_false` | canonical bool packing (LSB ∈ {0,1}) decodes | `read_bool` |
| `abi::positive_word_at_valid_offsets` | `word` returns Some at offsets 0 and 32 of a 64-byte body | `word` |
| `abi::positive_three_static_two_dynamic_interleaved` | a 5-arg `f(address,bytes,uint256,bytes,bool)` walk maintains head_pos / tail_cursor exactly | `walk` (stress) |

(The previously existing positive tests — `happy_path_simple`, `zero_args`, `bare_uint_int_resolve_to_256`, `dynamic_array`, `fixed_array`, `nested_array`, `tuple`, `bytesn_widths`, `happy_transfer`, `happy_dyn_bytes`, `happy_static_array`, `happy_dyn_array_uint256`, `round_trip_curated_selectors_json` — remain unchanged and still pass.)

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `parser::negative_name_with_hyphen_rejected` | function name regex `[A-Za-z_][A-Za-z0-9_]*` | feed `safe-mint(uint256)` | `parse_text_sig` returns `None` |
| `parser::negative_name_with_dot_rejected` | same name-regex contract | feed `foo.bar(uint256)` | `None` |
| `parser::negative_non_ascii_in_name_rejected` | curator emits ASCII-only text_sigs | feed a multibyte-UTF-8 lead byte (0xC3) inside the name | `None` |
| `parser::negative_empty_input_rejected` | empty input has no `(` | feed `""` | `None` |
| `parser::negative_open_paren_first_byte_rejected` | name must be non-empty (`open == 0` guard) | feed `(uint256)` | `None` |
| `parser::negative_deprecated_byte_alias_rejected` | whitelist parity with Python curator excludes deprecated `byte` alias | feed `f(byte)` | `None` |
| `parser::negative_fixed_types_rejected` | `fixed` / `ufixed` are reserved-but-unimplemented; curator never emits them | feed `f(fixed)`, `f(ufixed)`, `f(fixed128x18)`, `f(ufixed256x80)` | `None` for each |
| `parser::negative_function_type_rejected` | Solidity `function` type is out of curator scope | feed `f(function)` | `None` |
| `parser::negative_uintn_with_trailing_letter_rejected` | strip_prefix matches `uint`, but the width parser must reject non-digit suffix | feed `f(uint8a)`, `f(int8X)`, `f(bytes1x)` | `None` |
| `parser::negative_uintn_non_multiple_of_8_rejected` | `parse_uint_width` enforces `% 8 == 0` | feed `uint{1,7,9,15,17,100,255}` | `None` for each |
| `parser::negative_uintn_width_overflow_rejected` | width must be in 8..=256 | feed `uint264`, `uint512`, `uint99999`, `uint99999999999` (u32 overflow) | `None` |
| `parser::negative_uintn_leading_zero_rejected` | canonical decimal (no leading zero) | feed `uint008`, `uint0`, `uint00`; also confirm bare `uint` is still accepted (distinct path) | `None` for the first three, Some for `uint` |
| `parser::negative_bytesn_out_of_range_rejected` | bytesN width in 1..=32 | feed `bytes0`, `bytes33`, `bytes999`, `bytes01` | `None` |
| `parser::negative_internal_space_in_type_rejected` | on-chain selector hashes the canonical (no-space) text_sig — any whitespace tolerance would let the firmware mis-dispatch | feed `f(uint 256)` | `None` |
| `parser::negative_space_after_comma_rejected` | same selector-canonicality contract | feed `f(uint256, uint256)` | `None` |
| `parser::negative_trailing_space_in_type_rejected` | same | feed `f(uint256 )` | `None` |
| `parser::negative_space_in_name_rejected` | name regex | feed `foo bar(uint256)` | `None` |
| `parser::negative_leading_comma_rejected` | TopLevelSplit must reject empty chunks | feed `f(,uint256)` | `None` |
| `parser::negative_trailing_comma_rejected` | same | feed `f(uint256,)` | `None` |
| `parser::negative_double_comma_rejected` | same | feed `f(uint256,,uint256)` | `None` |
| `parser::negative_lone_comma_arg_rejected` | same | feed `f(,)` | `None` |
| `parser::negative_unmatched_array_brackets_rejected` | balanced brackets via TopLevelSplit depth tracking | feed `f(uint256[)`, `f(uint256])`, `f(uint256[[)`, `f(uint256][)` | `None` |
| `parser::negative_empty_array_inner_rejected` | array element must be non-empty | feed `f([])`, `f([5])` | `None` |
| `parser::negative_array_bound_overflow_rejected` | `parse_u32_decimal` checked_mul/checked_add | feed `T[4294967296]` (2^32), `T[9999999999]` | `None` |
| `parser::negative_array_bound_leading_zero_rejected` | canonical-decimal contract for array bound | feed `T[01]`, `T[00]`, `T[0]` (also disallowed for fixed-size) | `None` |
| `parser::negative_array_bound_non_digit_rejected` | digit-only contract | feed `T[1a]`, `T[ 5]`, `T[+5]`, `T[-5]` | `None` |
| `parser::negative_nesting_above_cap_rejected` | `MAX_NESTING + 1` levels of `[]` exceed cap | feed 9 nested `[]` | `None` |
| `parser::negative_tuple_fields_above_cap_rejected` | `MAX_TUPLE_FIELDS + 1` fields exceed cap | feed tuple with 9 fields | `None` |
| `parser::negative_arena_exhaustion_rejected` | `MAX_TYPE_ARENA` cap is independent of nesting + arg caps | 4 args of 8-nested `uint256[]…[]` = 36 arena allocs > 32 | `None` |
| `parser::negative_unbalanced_parens_extras_rejected` | TopLevelSplit must reject depth!=0 and depth<0 | feed `f((uint256)`, `f(uint256))`, `f()uint256)` | `None` |
| `parser::negative_missing_trailing_paren_rejected` | input must end with `)` | feed `f(uint256`, `f(uint256]` | `None` |
| `parser::negative_no_paren_at_all_rejected` | input must contain `(` | feed `transferuint256` | `None` |
| `parser::negative_empty_tuple_rejected` | tuple must be non-empty | feed `f(())` | `None` |
| `abi::negative_dynamic_length_exceeds_cap_rejected` | `MAX_DYNAMIC_LEN = 1 << 20` cap (bounds rendering work; the comment also notes "we're only filtering attacker-crafted length words like 2^200") | `f(bytes)` with length=MAX_DYNAMIC_LEN+1 (body padded to keep `end > body.len()` from short-circuiting first) | `walk` returns `None` |
| `abi::negative_offset_word_top_28_nonzero_rejected` | offset word top 28 bytes MUST be zero (defends against word-collision smuggling) | offset word with byte 0 = 0x01 | `None` |
| `abi::negative_offset_word_byte_27_nonzero_rejected` | exact boundary of "top 28 bytes zero" — byte index 27 is the last byte inside the gate | offset word with byte 27 = 0x01 | `None` |
| `abi::negative_length_word_top_28_nonzero_rejected` | length word same top-28-zero gate | otherwise-canonical `f(bytes)` with length word top byte = 0x01 | `None` |
| `abi::negative_offset_points_inside_head_rejected` | non-canonical packing: a dyn arg cannot overlap the head | `f(bytes,bytes)` with arg1 offset = 0 | `None` |
| `abi::negative_dyn_args_reordered_tails_rejected` | tails must appear in arg order (the doc calls this the "spoofing avenue") | `f(bytes,bytes)` with arg0 offset=128, arg1 offset=64 | `None` |
| `abi::negative_gap_between_tails_rejected` | tails must be contiguous (no gaps) | `f(bytes,bytes)` with arg0 ending at 96 but arg1 claiming offset 128 | `None` |
| `abi::negative_offset_zero_rejected_with_dyn_only` | offset=0 overlaps the head for a single-arg dyn | `f(bytes)` with offset = 0 | `None` |
| `abi::negative_offset_unaligned_rejected` | tail_cursor is 32-byte-aligned; a non-canonical offset of 33 cannot match | `f(bytes)` with offset = 33 | `None` |
| `abi::negative_dyn_bytes_length_overflow_u32_in_u64_padding` | `MAX_DYNAMIC_LEN` and `payload_padded` overflow guards | `f(bytes)` with length = u32::MAX | `None` |
| `abi::negative_dyn_bytes_length_one_byte_short_rejected` | length=32 needs 32 bytes; body alignment gate also enforces 32-multiple | claim length=32 with only 31 trailing bytes (66-byte body) | `None` |
| `abi::negative_dyn_array_length_overflow_rejected` | length*32 overflow guard for `T[]` | `f(uint256[])` with length = MAX_DYNAMIC_LEN+1 | `None` |
| `abi::negative_dynamic_array_of_dynamic_bytes_declined` | static-primitive-only element rule | `f(bytes[])` | `walk` returns `None` (Decline → fallback to blind sign) |
| `abi::negative_dynamic_array_of_string_declined` | same | `f(string[])` | `None` |
| `abi::negative_static_array_of_array_declined` | nested array element rule | `f(uint256[2][3])` | `None` |
| `abi::negative_array_of_tuple_declined` | tuple element rule | `f((uint256)[2])` | `None` |
| `abi::negative_tuple_top_level_declined_with_canonical_body` | tuples MUST be declined (Phase 2 out-of-scope) even with perfectly canonical body | `f((address,uint256))` with canonical encoding | `None` |
| `abi::negative_body_just_one_word_short_rejected` | head-size check (`head_size > body.len()`) | `f(uint256,uint256,uint256)` with 64-byte body | `None` |
| `abi::negative_body_one_word_too_long_rejected` | `tail_cursor != body.len()` final check | `f(uint256)` with 64-byte body | `None` |
| `abi::negative_body_misaligned_by_one_rejected` | `body.len() % 32 != 0` early gate | `f(uint256)` with 33-byte body | `None` |
| `abi::negative_body_empty_with_non_empty_sig_rejected` | head-size gate | `f(uint256)` with empty body | `None` |
| `abi::negative_read_address_offset_past_end` | `read_address` must not panic on out-of-range offset | offsets 1 and 32 against a 32-byte body | `None` |
| `abi::negative_read_address_top_byte_in_padding_zone_nonzero` | address top-12-byte zero gate — probe each of the 12 padding bytes individually | per-byte loop | `None` for each |
| `abi::negative_read_u256_past_end` | u256 reader must not panic on out-of-range | offset 1 against a 32-byte body | `None` |
| `abi::negative_read_bool_other_lsb_rejected` | canonical bool packing: LSB ∈ {0,1} only — any other value would make the wallet disagree with the contract | LSBs {2, 0x10, 0x7f, 0x80, 0xff} | `None` for each |
| `abi::negative_read_bool_nonzero_in_padding_zone` | bool packing: bytes 0..31 must be zero | LSB=1 (canonical) but byte 10 non-zero | `None` |
| `abi::negative_read_bool_past_end` | bool reader must not panic on out-of-range | offset 1 against a 32-byte body | `None` |
| `abi::negative_word_offset_unaligned_or_past` | word helper rejects unaligned and past-end offsets | offsets 33, 64, 65 against a 64-byte body | `None` |
| `abi::negative_word_offset_overflow_should_return_none` *(`#[ignore]`)* | word helper must not panic on attacker-crafted near-`usize::MAX` offset | `usize::MAX - 16` (so `off + 32` wraps) | EXPECTED `None`; ACTUAL today: panics. See bug below. |

## Production-code bugs surfaced by negative tests

**Bug 1: `abi::word()` panics on attacker-crafted offset overflow.**

- File: `secure/src/tx/typed_call/abi.rs:282` (line of `body.get(off..off + 32)`)
- Test: `abi::tests::negative_word_offset_overflow_should_return_none` (`#[ignore]`-flagged)
- Symptom: `word(body, usize::MAX - 16)` panics with `"attempt to add with overflow"` because `off + 32` wraps. Reproduces under default `cargo test` (debug overflow checks). The `secure/Cargo.toml` release profile also sets `overflow-checks = true`, so production builds inherit the same panic on this input — a panic in S-world is a denial-of-service vector when combined with any attacker-influenced offset.
- Today the walker's geometry passes (`offset + 32 > body.len()` etc.) prevent this offset from ever reaching `word()` in the dispatched path, so the bug is latent. But `word()` / `read_address()` / `read_u256()` / `read_bool()` are `pub(crate)` and any future renderer call site that takes an offset from external bytes inherits the panic.
- Suggested fix: replace `body.get(off..off + 32)` with `body.get(off..off.checked_add(32)?)` (or `usize::saturating_add`). The same shape should be applied to any other unchecked `+ 32` in this file as a defence-in-depth pass; the immediate one in `word()` is the only one reachable from the public-ish surface.
- Test stays `#[ignore]` until the production code is fixed; un-ignore in the same commit as the fix so the regression is loud.

## Coverage gaps deliberately left

- **Renderer half (`crate::tx::display::typed_call`).** The on-screen renderer lives behind `cfg(not(test))` because it pulls in `crate::ui` (hardware). Its host-testable subset is empty by design; on-target render tests belong to the `make e2e-hw` / `make play-hw-display` pass, not this one.
- **`MAX_DYNAMIC_LEN` exactly-at-cap acceptance.** The test pins `MAX_DYNAMIC_LEN + 1` as rejected; the exact-cap-accepted case would need a ~1 MiB body. The risk is asymmetric: a regression that loosens the cap is the dangerous direction, and `negative_dynamic_length_exceeds_cap_rejected` catches it.
- **`MAX_ARGS` exactly-at-cap walker test.** `parser::positive_max_args_accepted` pins the parser side. A walker test with 16 static-primitive args would need a 512-byte body and adds no marginal coverage over `positive_three_static_two_dynamic_interleaved` + `rejects_oversize_static_array`.
- **proptest-driven random fuzz of parser + walker.** `proptest` is already a dev-dependency on this crate and is used by `fuzz_props::*`. A `parse_walk_never_panics` property would be a great follow-up; this pass focused on assumption-pinning rather than coverage breadth. (The `#[ignore]`-flagged overflow bug is exactly the class of bug a quickcheck-style harness would have surfaced earlier.)
- **`secure/src/tx/mod.rs` re-exports.** This is a pure shim that re-exports from the `pqsigner-tx-core` workspace crate. Behaviour tests for `rlp`, `eip1559`, `hash` live in that crate. Adding shim-existence tests here would amount to compile-time tautologies; deliberately omitted.

## Verification
- `cargo fmt -p sphincs-tz-secure --check` — N/A (the local sandbox blocked invocation of `cargo fmt` / `rustfmt` during this pass; formatting was kept manually consistent with the surrounding file. Re-run after merge.)
- `cargo check -p sphincs-tz-secure` — PASS (no new warnings introduced; all warnings are pre-existing in unrelated modules)
- `cargo clippy -p sphincs-tz-secure --tests -- -D warnings` — N/A (sandbox blocked invocation; `cargo check --tests` passed cleanly and no new lints are triggered by the new tests — they use only `assert!` / `assert_eq!` / loops / `Vec`, no clippy-flagged patterns)
- `cargo test -p sphincs-tz-secure` — PASS (1101 tests passed, 2 ignored — 1 new from this pass, pinning the `word()` overflow bug; 1 pre-existing)
- (firmware) on-target tests deferred: no — the slice is pure-logic host-testable; the only on-target work item is the gated `crate::tx::display::typed_call` renderer, which is explicitly out of scope.
