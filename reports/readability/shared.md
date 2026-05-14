# Readability & Excellence Review — `shared`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`sphincs-tz-shared` is already an unusually small, focused crate: a re-export
shim over `pqsigner-proto` plus two pure-no_std modules (`apdu_framing`,
`db_format`). Module structure, naming, doc coverage and the proptest
harness are all in good shape. This pass made only small surgical
improvements: removed one dead-store assignment in the HID reassembler,
tightened a handful of public predicates to `const fn`, and added
`#[must_use]` to constructors / accessors / status-word helpers so
callers can't silently drop their return values. No behaviour, ABI, wire
format, or public type signature has changed.

## Changes applied

- `shared/src/apdu_framing.rs:51` — `FramingError::to_sw` made `const fn`
  and `#[must_use]`. Pure SW-code mapping; const-ness lets it appear in
  const contexts and `#[must_use]` enforces the "look at the status word"
  expectation.
- `shared/src/apdu_framing.rs:96` — same treatment for
  `RoutingError::to_sw`.
- `shared/src/apdu_framing.rs:140-153` — `#[must_use]` on
  `ChainState::{new, active_ins, pos}` (all are pure observers /
  constructors; dropping the return value is always a bug).
- `shared/src/apdu_framing.rs:224-232` — `#[must_use]` on
  `ChainStepOutcome::{protocol_error_sw, wrong_length_sw}`.
- `shared/src/apdu_framing.rs:266-285` — `#[must_use]` on
  `HidFrameAssembler::{new, channel_id, rx_expected}`.
- `shared/src/apdu_framing.rs:341` — removed dead store
  `self.rx_pos = 0;`. The line was redundant: it sits between
  `self.rx_seq = 1;` and the unconditional `self.rx_pos = take;` a few
  lines below, so it never had observable effect. Removing it makes the
  first-frame branch read top-down without the reader wondering why
  `rx_pos` is being assigned twice.
- `shared/src/db_format.rs:362-368` — added a 6-line comment block at
  the top of the LE-reader section explaining the panic-on-out-of-range
  policy (the readers are called only against firmware-signed blobs, so
  the panic is correct behaviour, not an oversight).
- `shared/src/db_format.rs:371-394` — `#[must_use]` on `read_u32_le` and
  `read_u64_le`. Both are pure decoders; ignoring the return value is
  always a caller bug.

## Recommendations not applied

- `apdu_framing::HidFrameAssembler::reset()` does not clear `channel_id`.
  This is **intentional** (and structurally required): in
  `nonsecure/src/usb/transport.rs:70` the caller reads `channel_id()`
  *after* `process_frame` returns `ApduComplete(len)` — at which point
  `reset()` has already run inside `process_frame`. Clearing `channel_id`
  in `reset()` would zero the field before the caller can read it,
  silently breaking response framing. Left as-is; flagging here so
  future readers don't "fix" it.
- The four db_format DB layouts (ERC20 / VK / Names / Selectors) share
  identical header / proof layouts and only differ in entry shape. A
  generic `DbHeader` reader trait + per-DB `Entry` impl could deduplicate
  the four `*_HDR_OFF_*` constant blocks. **Not applied** because the
  offsets are mirrored on the host (`dbgen/`) and the consumer crates
  (`tx`, `nonsecure`, `secure/zk`) by name — changing the names would
  cascade into 13 files across the workspace, far past the
  ~300-line-churn budget for this pass.
- `read_u32_le` / `read_u64_le` could be one-line `try_into().unwrap()`
  forms. Left as the explicit byte-array literal because (a) it never
  reaches `unwrap()` (project policy: no `unwrap` outside provably-safe
  paths), and (b) the existing form is byte-by-byte explicit, which
  matches how the wire format is read in the project's host writers
  (`dbgen/`).
- The `apdu_framing::ChainStepOutcome::protocol_error_sw` /
  `wrong_length_sw` helpers and `FramingError::to_sw` /
  `RoutingError::to_sw` could be merged into a single trait
  `IntoStatusWord` so the dispatcher could erase the variant. Not
  applied — the four call sites in `nonsecure/src/usb/commands.rs` are
  clearer with explicit per-error methods than with trait dispatch, and
  the type set is closed.

## Verification

- `cargo check -p sphincs-tz-shared --all-targets` — **PASS**
- `cargo test -p sphincs-tz-shared` — **PASS** (18 tests; proptest cases
  for parser/state-machine non-panic invariants all green).
- `cargo fmt -p sphincs-tz-shared -- --check` — **N/A** (the sandbox
  denied `cargo fmt`; existing file style preserved by editing in place
  without reflowing).
- `cargo clippy -p sphincs-tz-shared -- -D warnings` — **N/A** (same
  sandbox restriction). All edits are mechanical (`#[must_use]` and
  `const`), so they cannot introduce clippy regressions; future CI
  passes will exercise them.

## What this crate already does well

- **Single-responsibility modules.** `lib.rs` is a documented 30-line
  shim, `apdu_framing.rs` covers the USB parsing boundary, `db_format.rs`
  is layout-only. No god-modules.
- **Wire-boundary fuzz coverage.** Every parser in `apdu_framing` has a
  proptest "never panics for arbitrary input" property, plus targeted
  invariant tests for `ChainState::pos` containment and HID-assembler
  bounds. This is exactly where the property-based harness pays off and
  it is hooked up correctly.
- **No `unsafe`.** The crate is fully safe Rust; nothing to audit there.
- **Zero-runtime dependencies.** `pqsigner-proto` is the only dep,
  `proptest` is dev-only. `no_std` is honoured (`#![no_std]` at
  `lib.rs:21`).
- **Pointer-free state machines.** Both `ChainState` and
  `HidFrameAssembler` separate bookkeeping from the caller-owned buffer,
  which is what makes the fuzz harness possible without a USB stack.
- **Defensive bounds checks.** `process_frame` keeps an explicit
  `end <= MAX_APDU_RX` belt-and-braces check even after the first-frame
  validation already guarantees the invariant; that defence-in-depth is
  the right call for code one bus-byte away from a hostile USB host.
- **KDF-tag stability.** `NAMES_SHORT_KEY_TAG = b"pqsigner-name-key-v1"`
  is treated as part of the on-disk format (per CLAUDE.md "no casual
  KDF tag changes") — left untouched.

## Cross-crate observations

- `nonsecure/src/usb/transport.rs:70` reads `self.rx.channel_id()`
  *after* `process_frame` returns `ApduComplete`. This is correct today
  but relies on a non-obvious invariant of `HidFrameAssembler::reset()`
  (it does not clear `channel_id`). A single-line comment at that read
  site, or an explicit `last_completed_channel_id` accessor on the
  assembler, would make the contract local.
- `pqsigner-proto` is re-exported via glob `pub use pqsigner_proto::*;`
  in `lib.rs:30`. Phase 11 cleanup of the modularity refactor (per
  `Cargo.toml:11`) should eventually migrate the ~67 importers to
  `pqsigner_proto::CMD_FOO` directly and retire this shim. Out of scope
  for this readability pass.
- The four DB layout modules across the workspace (`tx/src/erc20/bundle.rs`,
  `tx/src/names/bundle.rs`, `tx/src/selectors/bundle.rs`,
  `secure/src/zk/vk_bundle.rs`) duplicate header-offset reads with the
  same `read_u32_le(slice, OFF_FOO)` pattern against four near-identical
  schemas. A generic `DbHeader<const HDR_LEN: usize>` would compress
  this. Tracked here, deferred to a workspace-wide refactor.
