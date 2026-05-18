# Test Suite Added — `xtask`

_Date_: 2026-05-17
_Author_: Claude Code (ultrathink)

## Scope
Host workspace tooling — codegen / doc-checks / release packaging.

The crate today exposes one subcommand (`gen-solidity-constants`), one
flag (`--check`), and a pure-function Solidity renderer that mirrors
the constants in `pqsigner-proto` into the on-chain library
`contracts/smart-wallet/src/generated/PqsignerProto.sol`. The renderer
is a tiny but **highly load-bearing** generator: every constant it
emits is consumed by the on-chain wallet, so a silent drift between
the Rust `pub const` source-of-truth and the generated Solidity is a
cross-language ABI / cap / domain-tag break.

Source files covered:
- `xtask/src/main.rs` — 292 lines (pre-existing) → 569 lines (after extension)
- `xtask/Cargo.toml` — unchanged
- `xtask/tests/cli.rs` — new (170 lines)

## Test files added / extended
- `xtask/src/main.rs` — extended `#[cfg(test)] mod tests`: **+10 positive**, **+15 negative**
  (existing 8 tests preserved). Covers private helpers (`padded_to_32`,
  `is_solidity_string_safe`, `sol_*`, `section_header`,
  `render_solidity_library`, `workspace_root`) and the cross-file
  drift detector that diffs the live renderer output against the
  checked-in `PqsignerProto.sol`.
- `xtask/tests/cli.rs` — new integration suite: **3 positive**, **5 negative**.
  Spawns the binary via `env!("CARGO_BIN_EXE_pqsigner-xtask")` and
  exercises the CLI contract (help routing, unknown-subcommand
  rejection, `--check`-vs-checked-in equality, mtime-preserving
  read-only `--check`, clean stderr on the happy path).

## Positive coverage
| test name | what it asserts | which API surface |
|---|---|---|
| `padded_to_32_rounds_up_to_word_boundary` (existing) | basic edge cases of word-aligned rounding | `padded_to_32` |
| `positive_padded_to_32_handles_protocol_relevant_values` | rounding behaviour for C10_SIG_LEN (4008→4032), EIP-6492 blob size (8608→8608), one-byte-past-multiple | `padded_to_32` |
| `solidity_string_safe_accepts_printable_ascii` (existing) | accepts representative ASCII strings | `is_solidity_string_safe` |
| `positive_is_solidity_string_safe_accepts_full_printable_range` | every byte 0x20–0x7E (excl. `"` and `\`) accepted | `is_solidity_string_safe` |
| `sol_bytes_emits_string_literal_for_ascii` (existing) | string-literal path for ASCII | `sol_bytes` |
| `sol_bytes_emits_hex_literal_for_non_ascii` (existing) | hex path for non-ASCII | `sol_bytes` |
| `positive_sol_bytes_empty_emits_string_literal` | empty input renders as `""` | `sol_bytes` |
| `positive_sol_bytes_uses_string_literal_for_real_domain_tag` | the actual `FACTORY_ADD_SLOT_DOMAIN` bytes render as a string literal | `sol_bytes` |
| `sol_bytes4_emits_lowercase_hex` (existing) | bytes4 lowercase hex format | `sol_bytes4` |
| `positive_sol_bytes4_zero_and_max` | edge cases `00000000` / `ffffffff` | `sol_bytes4` |
| `sol_uint256_emits_decimal` (existing) | decimal rendering | `sol_uint256` |
| `positive_sol_uint256_emits_zero_and_large_values` | edge cases `0` and `u128::MAX` | `sol_uint256` |
| `positive_sol_uint256_with_doc_emits_doc_then_const` | `/// @dev …\n …` format | `sol_uint256_with_doc` |
| `positive_section_header_format_is_exact` | exact byte format of the divider header | `section_header` |
| `positive_render_library_emits_pragma_and_header` | pragma + "DO NOT EDIT" + source-of-truth pointer present | `render_solidity_library` |
| `positive_render_library_is_deterministic` | same input ⇒ same output across 3 invocations | `render_solidity_library` |
| `rendered_library_matches_checked_in_solidity` (existing) | structural invariants (SPDX, library decl, every constant present) | `render_solidity_library` |
| `positive_workspace_root_is_parent_of_manifest_dir` | resolves to a directory containing both `xtask/` and `contracts/` | `workspace_root` |
| `positive_help_alias_prints_subcommand_list_and_exits_success` | `help` / `--help` / `-h` all exit `SUCCESS` and list the subcommand | CLI surface |
| `positive_no_args_prints_help_and_exits_success` | bare invocation routes to help | CLI surface |
| `positive_check_mode_stdout_matches_checked_in_file_byte_for_byte` | `--check` stdout reproduces the checked-in Solidity exactly | CLI `--check` |

## Negative coverage (the important one)
| test name | assumption being challenged | how the test attacks it | expected outcome |
|---|---|---|---|
| `solidity_string_safe_rejects_unsafe_bytes` (existing) | unsafe bytes within strings | passes `"`, `\`, 0x1f, 0x7f, 0xff | all rejected |
| `negative_is_solidity_string_safe_rejects_every_control_byte` | "no control char will ever sneak into a string literal" | loops 0x00–0x1F (every control byte) + DEL | every byte rejected |
| `negative_is_solidity_string_safe_rejects_quote_and_backslash_within_text` | a single `"` or `\` inside otherwise-safe text is enough to force hex | tries `"` and `\` at start / middle / end of an ASCII payload | every variant rejected |
| `negative_is_solidity_string_safe_rejects_every_non_ascii_byte` | high-bit bytes always force hex encoding | loops 0x80–0xFF | every byte rejected |
| `negative_sol_bytes_picks_hex_when_input_contains_any_unsafe_byte` | renderer must NOT emit an unescaped 0xff inside a string literal | hands `"hello\xffworld"` to `sol_bytes` | output starts with `hex"`, contains the lowercased hex of every byte |
| `negative_proto_caps_match_frozen_on_chain_values` | CLAUDE.md invariant #7 — per-chain caps are frozen (silent drift breaks every consumer) | reads `proto::MAX_BOOTSTRAP_USES`, `MAX_SLOT_USES`, `MAX_OFFCHAIN_GAP` and pins them to 65_536 / 65_536 / 100 | exact equality |
| `negative_c10_sig_len_is_frozen_at_4008` | the Yul verifier and every wrapper layout depend on `C10_SIG_LEN = 4008` | reads `proto::C10_SIG_LEN` | == 4008 |
| `negative_owner_bytes_len_is_frozen_at_64` | on-chain `ownerAtIndex` storage is sized for 64-byte entries; truncation would be a silent forgery surface | reads `proto::OWNER_BYTES_LEN` | == 64 |
| `negative_execute_selectors_are_byte_exact` | `EXECUTE_SELECTOR` / `EXECUTE_BATCH_SELECTOR` drift would brick every signed transaction (calldata prefix mismatch) | byte-compares the 4-byte selectors | exact match against the keccak-256-derived constants |
| `negative_factory_add_slot_domain_tag_is_byte_exact` | CLAUDE.md "No casual KDF tag changes." — renaming this tag invalidates every already-issued bootstrap signature over `addSlot0Digest` | byte-compares to `b"pqwallet-factory-add-slot"` + length to 25 | exact match |
| `negative_sig_wrapper_len_is_4128_in_rendered_library` | the `abi.encode(uint256, bytes)` wrapper arithmetic stays at exactly 4128 (else on-chain ABI decoding breaks) | recomputes 32+32+32+padded(4008) and greps the rendered library for the literal `= 4128;` | both checks pass |
| `negative_rendered_output_matches_checked_in_solidity_byte_for_byte` | **the highest-value drift detector**: live renderer output equals the checked-in `PqsignerProto.sol` byte-for-byte | reads the checked-in file via `env!("CARGO_MANIFEST_DIR")` and compares strings | exact equality |
| `negative_rendered_output_keeps_do_not_edit_warning` | auditor-facing "DO NOT EDIT" warning is never silently removed | greps rendered output for the warning + the regen command | both substrings present |
| `negative_factory_add_slot_domain_renders_as_string_literal` | printable-ASCII tag must NOT regress to `hex"..."` encoding | greps for the explicit string-literal form and verifies the hex form is absent | both checks pass |
| `negative_rendered_library_exposes_only_approved_constants` | adding a new on-chain constant is always a conscious update, never a silent leak | walks every `… internal constant …` line in the rendered output and checks the name against an explicit allowlist | every name accepted |
| `negative_unknown_subcommand_exits_failure_with_explanation` | unknown subcommands must exit non-zero AND name the offender on stderr | spawns the binary with `frobnicate-the-solidity` | exit≠0, stderr contains "unknown subcommand" + the offending name |
| `negative_check_mode_does_not_modify_checked_in_file` | `--check` is the read-only mode — must NEVER touch the on-disk file | snapshots content + mtime, runs `--check`, re-reads both | content and mtime unchanged |
| `negative_help_does_not_emit_generated_solidity` | `help` / `--help` / `-h` must NEVER silently dump the Solidity library (would pollute CI pipelines that pipe stdout through diff) | spawns each help variant and greps stdout for distinctive Solidity content | none of the variants emit the library |
| `negative_unknown_subcommand_also_prints_help_to_stdout` | error path still shows help so the user doesn't need a second invocation | spawns with unknown subcommand, greps stdout | help text present |
| `negative_check_mode_produces_no_stderr_diagnostics` | CI consumes `--check` stdout via `diff`; any stderr chatter could be misread as failure | spawns `--check` and asserts stderr is empty | empty stderr |

## Production-code bugs surfaced by negative tests
None. The byte-for-byte drift detector confirms the checked-in
Solidity is exactly what the current generator emits; the constant
stability tests confirm every cross-language constant is at its
documented value; the CLI tests confirm the documented exit-code /
stdout / stderr contract holds.

## Coverage gaps deliberately left
- **Filesystem-write path of `cmd_gen_solidity_constants` (non-`--check`).**
  The write path mutates `contracts/smart-wallet/src/generated/PqsignerProto.sol`
  in the actual workspace. A test that exercises it would either
  trample the checked-in file (dangerous when `cargo test` is parallel
  with editor saves) or require fork-stubbing `workspace_root()`. The
  read-only `--check` mode delivers the same byte-level coverage of
  the renderer output, so the write path is covered indirectly.
- **`workspace_root()` fallback when `CARGO_MANIFEST_DIR` is unset.**
  Unreachable under `cargo test` (the env var is always set), and
  fork/exec to clear it would need a helper binary or a `std::env::set_var`
  call that races with parallel tests.
- **Compile-fail / `trybuild` tests for the binary.** Not applicable —
  `xtask` is a `[[bin]]`-only crate with no public library surface to
  forbid `Clone`-ing secrets etc.
- **Keccak-256 derivation of `EXECUTE_SELECTOR` from the function
  signature.** Adding a `sha3` / `tiny-keccak` dev-dep to `xtask` to
  recompute `keccak256("execute(address,uint256,bytes)")[..4]` would
  add a non-trivial dep just for one test. The byte-exact frozen value
  test already catches drift in either direction.

## Verification
- `cargo fmt -p pqsigner-xtask -- --check` — **N/A** (sandbox blocked the
  invocation; the new files use the same `    `-indent / `// `-comment
  conventions as the rest of the file and were authored against
  rustfmt defaults).
- `cargo check -p pqsigner-xtask` — **PASS**
- `cargo clippy -p pqsigner-xtask --tests -- -D warnings` — **N/A**
  (sandbox blocked the invocation; `cargo check` is clean and no
  `#[allow(...)]` was added to silence lints).
- `cargo test -p pqsigner-xtask` — **PASS** (41 tests / 0 ignored: 33 unit
  + 8 integration).
- (firmware) on-target tests deferred: **no** — xtask is host-only.
