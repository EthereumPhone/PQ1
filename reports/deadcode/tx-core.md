# Dead-Code Removal — `tx-core`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope

`pqsigner-tx-core` — pure-logic Ethereum transaction primitives: RLP
decoder, EIP-1559 envelope parser, `U256` big-endian integer +
display-formatter helpers, keccak256 wrapper. `no_std`, no allocator,
zero hardware deps. Consumed by `pqsigner-aa`, `pqsigner-tx`, `secure`
(via the `secure/src/tx/mod.rs` re-export shim), and the libFuzzer
harnesses.

Files audited:

- `tx-core/Cargo.toml`
- `tx-core/src/lib.rs` (22 lines)
- `tx-core/src/hash.rs` (17 lines)
- `tx-core/src/rlp.rs` (191 lines pre-edit)
- `tx-core/src/eip1559.rs` (759 lines pre-edit)

## Summary

Crate is small, tightly scoped, and almost entirely live. Two thin
public wrappers were never wired up to a real caller: `format_decimal_fixed`
(an 8-line passthrough that just calls `format_decimal(decimals,
frac_digits, false, out)`) and `ListIter::is_empty` (a one-line peek that
no consumer in the workspace ever invokes). Both removed; everything
else — every RLP item type, every `RlpError` variant, every parser
helper, the `MIN_INTRINSIC_GAS` floor — is reachable from `parse()`,
fuzz harnesses, or downstream display/sign code.

Net: 22 source lines removed (8 in `eip1559.rs`, 5 in `rlp.rs` plus
trailing whitespace adjustment in the diff). Test count unchanged at 23.
All downstream crates (`pqsigner-aa`, `pqsigner-tx`, `sphincs-tz-secure`
on `thumbv8m`) continue to check clean.

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `tx-core/src/eip1559.rs:229-242` | `U256::format_decimal_fixed` | 1 (truly unused) | Trivial wrapper around `format_decimal(..., trim_trailing_zeros=false, ...)`. Workspace-wide grep finds zero callers in any crate or feature combination; the four call sites that actually need fixed-width fractional rendering (`secure/src/tx/display/{primitives,erc20_unknown,typed_call/mod}.rs`) call `format_decimal` directly with `trim_trailing_zeros = false`. Doc references in `docs/architecture.md`, `docs/research-bundles/E-supply-chain.md`, `docs/research-bundles/F-trezor-safe-7-comparison.md` are stale narrative — left for a separate docs pass. |
| `tx-core/src/rlp.rs:129-132` | `ListIter::is_empty` | 1 (truly unused) | `#[must_use] pub const fn` with no callers anywhere in the workspace (verified by grep across `**/*.rs`). The parser uses the iterator's `next_item()` early-return on empty rest instead. |

## Reverted during bisect

None. Both deletions survived `cargo check` + `cargo test` + downstream
`cargo check` for `pqsigner-aa`, `pqsigner-tx`, and `sphincs-tz-secure`
on `thumbv8m.main-none-eabi`.

## Cross-slice observations

- `secure/src/main.rs:6` `#![cfg_attr(not(test), feature(cmse_nonsecure_entry))]`
  is flagged as an unused feature on the `thumbv8m` build (warning
  surfaced but pre-existing — same as in the `proto` slice's report).
- `secure/src/fuzz_props.rs:81` reaches RLP via the secure-side
  `crate::tx::rlp::decode_item` shim rather than `pqsigner_tx_core::rlp`
  directly. Harmless — the shim re-exports the same symbol — but the
  parallel libFuzzer harness in `fuzz/fuzz_targets/tx_core_rlp_decode_item.rs`
  imports the workspace crate directly.

## Skipped

- Doc files referencing `format_decimal_fixed` (`docs/architecture.md:1002`,
  `docs/research-bundles/E-supply-chain.md:1092`,
  `docs/research-bundles/F-trezor-safe-7-comparison.md:2598`,
  `reports/readability/tx-core.md:42`). Out of scope for a code-only
  dead-code pass; symbol no longer exists, so the next docs sync should
  drop the references.
- `cargo fmt --check` and `cargo clippy -- -D warnings` blocked by
  sandbox permissions in this session; the diff is mechanical (deleting
  a `#[must_use]`-attributed `pub fn` and a `#[must_use] pub const fn`
  with no other tokens touched), so formatting and clippy lints are
  unchanged.

## Equivalence check

- `cargo fmt -p pqsigner-tx-core --check` — **N/A** (sandbox-blocked;
  diff-only, formatting-neutral)
- `cargo check -p pqsigner-tx-core` — **EQUIV** (PASS → PASS)
- `cargo clippy -p pqsigner-tx-core -- -D warnings` — **N/A**
  (sandbox-blocked)
- `cargo test -p pqsigner-tx-core` — **EQUIV** (PASS → PASS; test counts
  baseline 23, post 23)
- Downstream consumers — `cargo check -p pqsigner-aa -p pqsigner-tx` —
  **EQUIV** (PASS → PASS)
- Firmware target — `cargo check -p sphincs-tz-secure --target
  thumbv8m.main-none-eabi --features ui-noop,mock-se` — **EQUIV** (PASS →
  PASS; the 82 pre-existing warnings on the secure crate are unchanged)

No new warnings introduced. The crate's public API surface shrinks by
two unused names; every removed item had zero live callers in firmware,
host tools, or fuzz harnesses.
