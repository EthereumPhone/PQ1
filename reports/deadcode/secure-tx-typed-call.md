# Dead-Code Removal — `secure-tx-typed-call`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
Solidity-ABI typed-call parser + tx/mod.rs shim.

Files audited:
- `secure/src/tx/mod.rs` — 31 lines
- `secure/src/tx/typed_call/mod.rs` — 16 lines
- `secure/src/tx/typed_call/abi.rs` — 479 lines (pre-edit)
- `secure/src/tx/typed_call/parser.rs` — 606 lines

## Summary
The slice is tightly written and almost entirely live under non-test
builds. One genuinely dead helper was found inside `abi.rs`'s test
module: a `build()` concatenator that was defined but never called by
any test. Everything else flagged as "never used" by the compiler is
either consumed by the out-of-slice `secure/src/tx/display/typed_call`
renderer (which is `#[cfg(not(test))]`-gated, so it disappears under
the host test build) or is an intentional parser-API surface kept for
parity with the Python validator (`tools/build_selectors_json.py`) per
the load-bearing whitelist-parity invariant called out in the parser
file header. After the deletion the host test count is unchanged (121
passed) and the host check warning count is strictly smaller by one.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/tx/typed_call/abi.rs:310-321` | `fn build(args: &[(&[u8], &[u8])]) -> Vec<u8>` test helper | 1 (truly unused) | Defined in `#[cfg(test)] mod tests` but never called by any test in the module. Compiler warns "function `build` is never used". |

## Reverted during bisect
None.

## Cross-slice observations
- `secure/src/tx/display/typed_call/mod.rs:265, 323` matches `TypeRef::Tuple { .. }` and never reads the inner `fields`/`len` of the `TypeRef::Tuple` variant. Combined with the walker also declining tuples wholesale (`abi.rs:223`), the `fields: [TypeId; MAX_TUPLE_FIELDS]` and `len: u8` payloads on the `Tuple` variant in `parser.rs:54` are read only by the in-file `parser::tests::tuple` test. Reducing this variant to a unit `Tuple` would simplify the parser and let `MAX_TUPLE_FIELDS` and the per-field tuple recursion in `parse_type` go away — but the pattern is consumed in the out-of-scope `display/typed_call` slice, so cleaning it requires coordinating an edit across both slices. Left as a recommendation.
- `ParsedSig.name: &'a [u8]` (`parser.rs:90`) is set by `parse_text_sig` but never read by any consumer outside the file (the only reads are two `assert_eq!`s in the in-file tests `happy_path_simple` and `zero_args`). The display renderer shows `meta.text_sig`, not the parser-extracted name. Removing it would simplify the struct without changing any user-visible behavior, but the same scope-coordination caveat applies (the parser file is the only one touching it directly, but the `name` slot is part of the documented parser API surface mirroring the Python validator; not deleting it here keeps that parity intact).
- The `#![allow(dead_code)]` at the top of `parser.rs` is currently load-bearing for the two warnings above. If a future pass deletes both the `name` field and the `Tuple { fields, len }` payload (in coordination with `display/typed_call`), the file-level attribute can be removed too.

## Skipped
- No generated files in scope.
- No pre-existing breakage in the baseline (121/121 tests pass in both runs).
- No `Cargo.toml` in scope — `tx/typed_call` is a sub-module of `sphincs-tz-secure`, not its own crate, so there are no slice-local deps/features to prune.

## Equivalence check
For each command, the baseline (pre-deletion) and post-deletion outcomes
must match.

- `cargo fmt -p sphincs-tz-secure -- --check` — **N/A** (command was rejected by the harness sandbox in both baseline and post; not run for either side, so equivalence trivially holds).
- `cargo check -p sphincs-tz-secure --tests` — baseline: 40 warnings, post: 39 warnings → **EQUIV** (strictly fewer; the removed `build is never used` warning is the deletion target).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting` — baseline: 78 warnings, post: 78 warnings → **EQUIV** (the deletion is inside `#[cfg(test)]` and so does not affect the firmware build).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (command was rejected by the harness sandbox in both baseline and post).
- `cargo test -p sphincs-tz-secure --tests` — baseline: 121 passed / 0 failed, post: 121 passed / 0 failed → **EQUIV** (test counts: baseline 121, post 121).
- `make <crate-build-target>` (firmware) — **N/A** (the deletion is gated under `#[cfg(test)]` and cannot affect the firmware image).
- Binary SHA-256 — **N/A** (firmware image is unaffected, see above).
