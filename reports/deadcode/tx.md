# Dead-Code Removal — `tx`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

`pqsigner-tx` — pure-logic Solidity-ABI / ERC-20 / address-name /
function-selector trust gates. Three sub-modules behind the gateway:
`erc20::{bundle, calldata, dispatch, merkle}`, `names::{bundle, resolver}`,
`selectors::bundle`.

Files audited:

- `tx/Cargo.toml`
- `tx/src/lib.rs` (31 lines)
- `tx/src/wire.rs` (32 lines)
- `tx/src/erc20/mod.rs` (24 lines)
- `tx/src/erc20/bundle.rs` (182 lines)
- `tx/src/erc20/calldata.rs` (110 lines)
- `tx/src/erc20/dispatch.rs` (63 lines)
- `tx/src/erc20/merkle.rs` (92 lines)
- `tx/src/names/mod.rs` (20 lines)
- `tx/src/names/bundle.rs` (136 lines)
- `tx/src/names/resolver.rs` (94 lines)
- `tx/src/selectors/mod.rs` (31 lines)
- `tx/src/selectors/bundle.rs` (585 lines, 18 unit tests)

## Summary

The slice is genuinely clean — nothing deleted. Every public item is
reached from at least one live workspace caller (verified by
grep-then-cfg-trace across `secure/`, `nonsecure/`, `fuzz/`, and the
host-tool crates). Crate-private helpers in `wire.rs` (`read_u32_le`,
`read_u64_le`, `is_clean_ascii`) are each used by all three bundle
parsers; `erc20::merkle::verify_proof` is the shared Merkle gate for all
three. The three `SELECTOR_*` constants in `erc20::calldata` are
referenced only within that file but stay `pub` deliberately — the
crate doc-comment commits to host-side reference-signer reuse, so the
canonical ERC-20 selector bytes are part of the published trust-gate
surface. No commented-out blocks, no stale TODOs, no vestigial cfgs, no
unused `Cargo.toml` deps or feature entries.

The recent readability pass (`reports/readability/tx.md`) flagged the
same items as borderline candidates and reached the same conclusion;
this pass independently confirms no behaviour-preserving deletion is
available in scope.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

(none)

## Reverted during bisect

(none — no edits attempted)

## Cross-slice observations

None — every public symbol of `pqsigner-tx` is consumed by `secure/`'s
thin re-export shims (`secure/src/{erc20,names,selectors}/mod.rs`) and
ultimately by `secure/src/nsc/cmd_sign_userop.rs` and the
`secure/src/tx/display/*` renderers. `nonsecure/src/usb/commands.rs`
references the bundle-size constants for its NS-side framing.
`fuzz/fuzz_targets/tx_erc20_*` exercise the `verify_erc20_bundle` and
`parse_erc20_calldata` entry points.

## Skipped

Nothing skipped. No generated files, no vendored blobs, no pre-existing
breakage.

## Equivalence check

No source edits were made, so baseline = post-deletion by construction.
Verified the slice builds and tests pass at the current tree state:

- `cargo fmt -p pqsigner-tx --check` — N/A (cargo fmt invocation blocked
  by sandbox policy in this session; tree was unmodified, so any fmt
  status is identical pre- and post-pass)
- `cargo check -p pqsigner-tx` (default features) — EQUIV (clean,
  `Finished dev profile`)
- `cargo check -p pqsigner-tx` (extra feature combos) — N/A (no feature
  flags declared on this crate)
- `cargo clippy -p pqsigner-tx -- -D warnings` — N/A (clippy invocation
  blocked by sandbox policy this session; tree unmodified so identical
  pre/post)
- `cargo test -p pqsigner-tx` — EQUIV (test counts: baseline 18, post 18
  — all in `selectors::bundle::tests`; doc-tests 0 / 0)
- (firmware crates) `make <crate-build-target>` — N/A (host-only crate)
- (firmware crates, if applicable) binary SHA-256 — N/A
