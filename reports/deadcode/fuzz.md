# Dead-Code Removal — `fuzz`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
cargo-fuzz harness (target binaries only — corpora/ excluded).

Files audited:
- `fuzz/Cargo.toml` — 70 lines
- `fuzz/fuzz_targets/aa_userop_parse_header.rs` — 22 lines
- `fuzz/fuzz_targets/tx_core_rlp_decode_item.rs` — 19 lines
- `fuzz/fuzz_targets/tx_core_eip1559_parse.rs` — 19 lines
- `fuzz/fuzz_targets/tx_erc20_parse_calldata.rs` — 18 lines
- `fuzz/fuzz_targets/tx_erc20_verify_bundle.rs` — 25 lines

## Summary
The slice is genuinely clean. Each of the five registered fuzz binaries is a
minimal `fuzz_target!(|data: &[u8]| { ... })` one-liner over a single
parser entry point, with a short doc comment explaining what surface it
covers and which proptest sibling it mirrors. `Cargo.toml` lists exactly
the three workspace path-dependencies that those harnesses consume
(`pqsigner-aa`, `pqsigner-tx-core`, `pqsigner-tx`), one external dep
(`libfuzzer-sys`), and five `[[bin]]` entries — one per harness on disk
that is wired in. Nothing to delete.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

(none)

## Reverted during bisect
(none)

## Cross-slice observations
None.

## Skipped
- `fuzz/fuzz_targets/apdu_parse_header.rs` and
  `fuzz/fuzz_targets/hid_frame_assembler.rs` — both untracked
  (`git status` shows `??`), not registered as `[[bin]]` entries in
  `Cargo.toml`, and reference `sphincs_tz_shared` which is not in the
  fuzz crate's `[dependencies]`. They appear to be new harnesses that
  the user is in the process of adding (matching parsers
  `parse_apdu_header` / `HidFrameAssembler` do exist in
  `shared/src/apdu_framing.rs`). Per CLAUDE.md's guidance on
  unexpected/untracked files representing in-progress work, they are
  left untouched — wiring them up (or removing them) belongs to that
  in-flight change, not to this dead-code sweep.
- `fuzz/corpus/` — explicitly excluded from scope.
- `fuzz/Cargo.lock` — generated artefact, untracked.

## Equivalence check
No source changes were made, so post-deletion outcomes are trivially
identical to baseline. The fuzz crate is a stand-alone workspace
(`workspace.exclude = ["fuzz"]` at the repo root) and requires nightly +
`cargo-fuzz` + libFuzzer/sanitizer toolchain to build its `[[bin]]`
targets; no host-side tests exist for the crate.

- `cargo fmt -p pqsigner-fuzz --check` — N/A (no source changes)
- `cargo check -p pqsigner-fuzz` (default features) — N/A (no source changes)
- `cargo clippy -p pqsigner-fuzz -- -D warnings` — N/A (no source changes)
- `cargo test -p pqsigner-fuzz` — N/A (crate has no tests; targets are
  `test = false` libFuzzer bins)
- Firmware-target build / binary SHA-256 — N/A (host-only crate)
