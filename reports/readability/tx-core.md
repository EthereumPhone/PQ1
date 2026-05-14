# Readability & Excellence Review — `tx-core`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-tx-core` is already a tight, well-scoped crate: three focused
modules (`rlp`, `eip1559`, `hash`), no `unsafe`, strict canonical-RLP
enforcement, and good unit-test coverage of the EIP-1559 envelope parser
and the U256 decimal formatter. The pass made small, targeted polish
edits — replacing a hand-rolled `U256::ge` with derived `Ord` (and
fixing one awkward `ge() && !=` site into a plain `>`), trimming an
unused `hex` dev-dependency, broadening the `keccak256` doc to match
its actual EVM-wide use, applying lifetime elision, adding `#[must_use]`
to a handful of pure value-returning fns, deriving `Debug` on `Item`,
making `ListIter::new` `const`, and removing a dead `let _v / _half`
block in a test. No invariant-touching changes; no public ABI breakage
for downstream crates (`pqsigner-aa`, `pqsigner-tx`, `secure`).

## Changes applied

- `tx-core/Cargo.toml` — dropped unused `hex` dev-dependency. No test
  file references `hex`.
- `tx-core/src/hash.rs:1` — broadened the file doc-comment from "EIP-1559
  envelope signing hash" to cover all EVM Keccak-256 use sites
  (userOpHash, EIP-712, CREATE2 init-code) per `CLAUDE.md`'s "Keccak-256
  only for EVM-mandated hashes" rule. Added `#[must_use]` and renamed
  the local `h` binding to `hasher` for grep-ability.
- `tx-core/src/rlp.rs:28` — derived `Debug` on `Item<'a>` so error paths
  and ad-hoc prints in callers can format it.
- `tx-core/src/rlp.rs:125` — made `ListIter::new` and `ListIter::is_empty`
  `const fn`; `is_empty` gained `#[must_use]`.
- `tx-core/src/eip1559.rs:70` — added `PartialOrd, Ord, Hash` to the
  `U256` derive list. The struct wraps a big-endian `[u8; 32]`, so the
  derived lexicographic byte ordering coincides exactly with numeric
  magnitude — documented inline.
- `tx-core/src/eip1559.rs:73-103` — removed the hand-rolled
  `U256::ge`. Grep confirmed it had no external callers; the single
  internal use was already a bug-prone construction (see next item).
  Added `#[must_use]` on `zero`, `is_zero`, `saturating_mul_u64`,
  `format_decimal`, `format_decimal_fixed`.
- `tx-core/src/eip1559.rs:329` — replaced
  `if max_priority.ge(&max_fee) && max_priority != max_fee` (which
  computed `>` via the awkward `(>= && !=)` pattern) with
  `if max_priority > max_fee`. Same behaviour, far clearer intent.
- `tx-core/src/eip1559.rs:301` — collapsed the explicit
  `parse<'a>(envelope: &'a [u8]) -> Result<ParsedTx<'a>, TxError>`
  signature to `parse(envelope: &[u8]) -> Result<ParsedTx<'_>, TxError>`
  via lifetime elision.
- `tx-core/src/eip1559.rs (tests)` — removed two dead `let _v` /
  `let _half` bindings in `format_1_5_eth` (left over from an earlier
  approach that was abandoned for the easier `u128` path).
- `tx-core/src/eip1559.rs (tests)` — renamed `ge_compare` to
  `ord_matches_numeric_magnitude` and extended it to assert
  cross-byte-boundary numeric ordering (`0x0100 > 0x00FF`), the actual
  property the derived `Ord` is relying on.

## Recommendations not applied

- **`saturating_mul_u64`'s `(U256, bool)` return** — the bool is largely
  redundant (callers in `secure/src/tx/display/primitives.rs:475` ignore
  it as `_overflow`). Could be simplified to return just `U256`, but a
  test currently asserts the bool and the API is reasonable as-is.
  Leaving alone — purely cosmetic.
- **`format_decimal` length (~100 lines)** — well-sectioned with
  numbered comments and individually short, so the cyclomatic
  complexity reads cleanly. Splitting into helpers would add parameter
  plumbing without clarity gains. Left alone.
- **`Eip1559Tx`'s `Default` derive** — drives `to: None` and zero
  U256 fields, which is fine for tests but a sentinel value in
  production. Not used in production paths so worth keeping for now;
  re-evaluate if it ever leaks into a sign path.
- **Replace `is_zero` free fn with `U256::is_zero`** — the free version
  takes `&[u8; 32]` because `div10_inplace` mutates the raw byte array.
  Refactoring `div10_inplace` to take `&mut U256` would require either
  exposing the inner field (already public, but ergonomically clunky)
  or adding helpers, so leaving as-is.

## Verification

- `cargo test -p pqsigner-tx-core` — **PASS** (23 / 23).
- `cargo check -p pqsigner-tx-core --all-targets` — **PASS** (no
  warnings emitted).
- `cargo check -p pqsigner-aa -p pqsigner-tx` — **PASS** (confirms the
  public-API surface change of removing `U256::ge` did not break
  downstream).
- `cargo fmt -p pqsigner-tx-core --check` — **NOT RUN**. Repeated
  invocations of `cargo fmt`, `rustfmt`, and any variant carrying
  `--check` were denied in the harness for this session. The edits
  follow the surrounding style (4-space indent, trailing commas,
  doc-comment width matching neighbours); a manual review of the diff
  shows no obvious formatting drift.
- `cargo clippy -p pqsigner-tx-core -- -D warnings` — **NOT RUN**.
  Same harness denial pattern as `cargo fmt`. `cargo check
  --all-targets` is warning-clean, which catches the `-W
  unused_imports` / `-W dead_code` family that would otherwise trip
  clippy's defaults; the deeper lints (`pedantic`/`nursery`) are not
  blanket-deny'd at the crate level, so the residual gap is small.

## What this crate already does well

- Strict, allocation-free RLP decoder with explicit canonical-encoding
  rejection (`NonCanonical`, `LeadingZero`, `LengthOverflow`,
  `IntTooLarge`).
- `ParsedTx<'a>` lifetime-binds the calldata slice into the input
  envelope, so the borrow checker statically enforces what was once a
  convention.
- The U256 decimal formatter has an explicit overflow regression test
  (`format_huge_integer_returns_none_on_tight_buffer`) tied to a
  past whale-display bug — a good "why" rather than a "what" comment.
- `MIN_INTRINSIC_GAS` and the priority/fee invariant are enforced at
  parse time, so the trusted-UI display layer never has to second-guess
  whether a tx can land.
- No `unsafe` anywhere; `#![no_std]` with `deny(unsafe_op_in_unsafe_fn)`
  at the crate level; pure logic; zero hardware deps.

## Cross-crate observations

- `secure/src/tx/display/primitives.rs:475` ignores the overflow flag
  from `saturating_mul_u64` (`let (budget, _overflow) = ...`) without
  surfacing a banner — the comment two lines up says "Silently clamps
  to U256::MAX on overflow." Worth a follow-up to confirm that's the
  intended UX rather than a TODO; not changed here.
- `secure/src/nsc/cmd_sign_userop_batch.rs:69` defines a local
  `struct ParsedTx` that shadows the imported
  `pqsigner_tx_core::eip1559::ParsedTx` (visible only because the local
  one isn't generic). Renaming the local one would aid grep-ability.
  Not touched here.
- The `aa/src/userop.rs` module reaches into `pqsigner_tx_core::hash::keccak256`
  via two `use` lines. After this pass `tx-core/src/hash.rs` lifts its
  doc to cover that exact use case — a future cleanup could move the
  `keccak256` wrapper out of `tx-core` if a thinner "hashes" crate ever
  emerges, but for now the layering is fine.
