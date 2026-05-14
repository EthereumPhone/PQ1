# Readability & Excellence Review — `tx`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-tx` is already in good shape: small modules with clear single
purposes, careful bounds-checking, defensive trailing-byte rejection
across all three Merkle bundles, and decent test coverage for the
`selectors` parser. The headline finding is **duplicated wire-decoding
helpers** — three identical copies of `read_u32_le`, `read_u64_le`, and
`is_clean_ascii` across `erc20/bundle.rs`, `names/bundle.rs`, and
`selectors/bundle.rs`. The other notable item is one stretch of
defensive dead code in `erc20/bundle.rs` that was unreachable given the
existing length caps. Both are fixed. All other observations are left
as recommendations because they touch the public API surface that
secure-side shims and fuzz harnesses already depend on.

## Changes applied

- **New `tx/src/wire.rs`** — single source of truth for the three
  helpers (`read_u32_le`, `read_u64_le`, `is_clean_ascii`). All three
  are `pub(crate)` so the public surface is unchanged.
- **`tx/src/lib.rs`** — declares `mod wire;` (private).
- **`tx/src/erc20/bundle.rs`** — imports the shared helpers; removes
  the three local copies (≈14 lines).
- **`tx/src/erc20/bundle.rs:140-145`** — removes the unreachable
  `canonical_len > 8+20+1+1+MAX+1+MAX` guard. With `name_len` and
  `symbol_len` already capped at `MAX_DISPLAY_FIELD`, the expression
  is tautologically false; the buffer's literal size already encodes
  the same invariant at compile time. Replaced with a one-line comment
  explaining the bound.
- **`tx/src/names/bundle.rs`** — imports the shared helpers; removes
  the local copies.
- **`tx/src/selectors/bundle.rs`** — imports the shared helpers;
  removes the local copies.

Net diff: +1 file (32 lines), −45 lines of duplication across three
files, no public-API changes.

## Recommendations not applied

These would be improvements but I left them alone — either invariant-
adjacent or churn-for-modest-gain inside this scope.

- `tx/src/erc20/calldata.rs:81-91` — `decode_address_word` is `pub`
  and re-exported via `secure/src/erc20/mod.rs`. Its 32-byte length
  check is defensive against external callers. Worth visibility
  tightening (`pub(crate)`) only after auditing every downstream use
  in `secure/src/tx/display/*` — out of scope here.
- `tx/src/erc20/calldata.rs:94-98` — `decode_u256_word` will panic via
  `copy_from_slice` if a future caller passes a < 32-byte slice. All
  current call sites in this file pass exactly-32-byte windows after a
  body-length check, so this is provably safe today; tightening it to
  `Option<U256>` would be a backwards-incompatible signature change.
- `tx/src/names/resolver.rs:65-87` — `lookup` has two near-identical
  loops (exact match then wildcard). Extracting a helper closure or
  inner fn would save ~6 lines but obscures the two-phase trust
  semantic that the doc comment leans on. Left intact.
- `tx/src/erc20/bundle.rs:63` — `MAX_ERC20_BUNDLE_LEN = 64 + 1024 +
  32 = 1120` is a sticky public constant. The accompanying doc-comment
  math (`8+20+1+1+64+1+32+4+4 + 32*32`) totals 1191, suggesting the
  constant is ~71 B under the worst-case bundle size. Investigating
  this is invariant-adjacent (the bundle is copied into a stack buffer
  sized to this constant) and should be done with the gateway author,
  not in a readability pass.
- Test coverage for `erc20::bundle::verify_erc20_bundle`,
  `names::bundle::verify_name_bundle`, `erc20::calldata::*`, and
  `erc20::dispatch::dispatch_tx` is currently empty. Only
  `selectors::bundle` has the full battery. Adding the parallel
  battery for the other two bundle modules + a few calldata unit tests
  would be straightforward and high-value, but it's well outside a
  readability pass (≈ 300 LOC of new tests).
- Both `parse_self_attest_bundle` and `verify_*_bundle` use explicit
  `<'a>(bundle: &'a [u8]) -> Option<…<'a>>` signatures. Lifetime
  elision would be valid (`bundle: &[u8] -> Option<…<'_>>`) and is
  what nightly clippy's `needless_lifetimes` lint flags. Left
  unchanged for consistency with the existing style and because
  clippy could not be run in this session (see Verification).

## Verification

Local sandbox blocked `cargo clippy` and `cargo fmt` outright (each
invocation returned "This command requires approval" and the
interactive approval prompt never reached the user). Verification ran
with the cargo subcommands that **were** allowed:

- `cargo check  -p pqsigner-tx --tests` — **PASS**
- `cargo test   -p pqsigner-tx`        — **PASS** (18/18 tests)
- `cargo check  -p sphincs-tz-secure --target thumbv8m.main-none-eabi
  --features mock-se,ui-noop` — **PASS** (downstream firmware crate
  still builds against the refactored helpers)
- `cargo clippy -p pqsigner-tx -- -D warnings` — **N/A — blocked by
  permission policy**. The edits are purely a local extraction of
  identical helpers; they do not introduce new lint surface.
- `cargo fmt    -p pqsigner-tx --check` — **N/A — blocked by
  permission policy**. The new `wire.rs` follows the same formatting
  conventions used elsewhere in the crate; no rustfmt-meaningful
  whitespace was touched in the existing files.

## What this crate already does well

- **Domain-separated Merkle leaf hashing** (`0x00` leaf, `0x01`
  internal) — explicitly defended in `erc20/merkle.rs` doc-comment.
- **Strict trailing-byte rejection** in every bundle verifier — the
  buffer must be exactly the bundle, no padding tolerated.
- **Bounded proof depth** (≤ 32) in every verifier — a hostile NS
  can't force the secure verifier into an unbounded hash chain.
- **Printable-ASCII gating** on every operator-visible string — names,
  symbols, text signatures. Doc-comments explicitly call out the
  homoglyph spoofing reason.
- **Tight `no_std` discipline** — no heap, no `Vec`, fixed-capacity
  buffers sized from compile-time bounds.
- **Cross-check responsibility documented** at every bundle entry
  point — each `verify_*_bundle` docstring spells out which checks
  remain the caller's responsibility (chain-id / contract / selector
  matching).
- **`SelectorProvenance` provenance tagging** distinguishes Merkle-
  verified vs companion-self-attested text signatures, with clear
  trust caveats in the doc-comments.

## Cross-crate observations

- `secure/src/erc20/mod.rs` re-exports `pqsigner_tx::erc20::{calldata,
  dispatch, merkle}` as whole modules. This makes every `pub` item in
  those modules part of the secure-side surface and complicates any
  future visibility tightening here. A future audit pass could
  replace the bulk re-exports with explicit named re-exports and then
  shrink `pqsigner-tx`'s visibility.
- `fuzz/fuzz_targets/tx_erc20_parse_calldata.rs` and
  `tx_erc20_verify_bundle.rs` exercise the two main entry points but
  there is no fuzz harness for `verify_name_bundle`,
  `verify_selector_bundle`, or `parse_self_attest_bundle`. Adding
  three more 15-line harnesses would close the bundle-parser fuzz
  matrix.
- `dbgen` (mentioned in several `MUST match dbgen::*` comments) is the
  host-side mirror for the canonical-leaf serialisation. Worth
  cross-linking the two file paths in each comment for navigation.
