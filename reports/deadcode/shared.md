# Dead-Code Removal — `shared`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Cross-world `#[repr(C)]` types and NSC status enums. After the Phase-3
modularity refactor, the slice is in fact: a 30-line re-export shim
(`lib.rs`) over `pqsigner-proto`, plus two pure-`no_std` implementation
modules — `apdu_framing.rs` (USB APDU/HID framing parsers) and
`db_format.rs` (ERC20 / VK / Names / Selectors on-disk DB layout
constants).

Files audited:
- `shared/Cargo.toml` — 35 lines
- `shared/src/lib.rs` — 31 lines
- `shared/src/apdu_framing.rs` — 692 lines
- `shared/src/db_format.rs` — 396 lines

## Summary
This slice is already clean. A readability/excellence pass on
2026-05-14 (see `reports/readability/shared.md`) had just landed —
that pass removed one dead store in `HidFrameAssembler::process_frame`
and otherwise tightened `const fn` / `#[must_use]` without changing
behaviour. The current dead-code audit grepped every public item in
both implementation modules across the workspace and confirmed each
has at least one consumer outside `shared/`:

- All 5 `apdu_framing` public types (`ApduHeader`, `FramingError`,
  `RoutingError`, `ChainState`, `ChainStepOutcome`, `HidFrameAssembler`,
  `FrameOutcome`) and all public fns / consts (`parse_apdu_header`,
  `route_v2`, `p1_more_follows`, `MAX_APDU_RX`, `HID_FIRST_DATA`,
  `HID_CONT_DATA`) are consumed by `nonsecure/src/usb/commands.rs`,
  `nonsecure/src/usb/transport.rs`, and the libFuzzer harnesses in
  `fuzz/fuzz_targets/{apdu_parse_header,hid_frame_assembler}.rs`.
- All 70+ `db_format` constants have exactly one consumer outside
  `shared/` — every `ERC20_*`, `VK_*`, `NAMES_*`, `SELECTOR_*` offset
  is read by `dbgen/` (host writer) and the matching reader in
  `nonsecure/src/{erc20_db,vk_db,names_db,selectors_db}.rs`,
  `tx/src/{erc20,names,selectors}/bundle.rs`, or
  `secure/src/zk/vk_bundle.rs`. The two LE readers (`read_u32_le`,
  `read_u64_le`) are likewise consumed.
- The `Default for HidFrameAssembler` impl is structurally
  required by `clippy::new_without_default` (the matching
  `pub const fn new()` is the only constructor; deriving instead would
  drop `const`).
- The few accessors (`ChainState::{active_ins, pos}`,
  `HidFrameAssembler::{rx_expected}`) are exercised only by the
  in-crate proptest harness — they are bucket-2 (intentional
  invariant-assertion surface). They are not bucket-1 dead.

No `#[cfg(test)]` infrastructure, dev-only gates, vestigial `#[allow]`,
or commented-out code remains. `cargo check -p sphincs-tz-shared`
(host + `thumbv8m.main-none-eabi`) compiles with zero warnings and
`cargo test -p sphincs-tz-shared` runs 18 tests green. No deletions
were applied; the slice is healthy.

## Deletions applied

_(none)_

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

## Reverted during bisect

_(none — no deletions to bisect)_

## Cross-slice observations

- `pqsigner-proto` is glob-re-exported by `shared/src/lib.rs:30` —
  `Cargo.toml:11` notes a Phase-11 cleanup that should migrate the
  ~67 `use sphincs_tz_shared::*` import sites to `pqsigner_proto::*`
  and retire the shim entirely. Workspace-wide rename; out of scope
  for a `shared`-only dead-code pass.
- The four DB layout modules across the workspace
  (`tx/src/erc20/bundle.rs`, `tx/src/names/bundle.rs`,
  `tx/src/selectors/bundle.rs`, `secure/src/zk/vk_bundle.rs`,
  plus the four `nonsecure/src/*_db.rs` readers) read the
  `*_HDR_OFF_*` constants with a near-identical
  `read_u32_le(slice, OFF_FOO)` pattern. A generic
  `DbHeader<const HDR_LEN: usize>` reader would compress this. The
  constants themselves are not dead — the duplication lives in the
  consumer crates and would need a workspace-wide refactor.

## Skipped

- `docs/SE050/SE-PLUG-TRUST-MW_04.07.01/**` — vendored NXP middleware
  C sources; out of scope.
- Phase-11 shim retirement (see above) — workspace-scoped refactor,
  not a `shared`-slice dead-code action.

## Equivalence check

No source files under `shared/` changed, so equivalence is
definitionally preserved. Verification runs against the unmodified
crate:

- `cargo fmt -p sphincs-tz-shared --check` — **N/A** (sandbox denies
  `cargo fmt`; same restriction noted in `reports/readability/shared.md`)
- `cargo check -p sphincs-tz-shared` (default features, host) — **EQUIV**
  (clean, no warnings)
- `cargo check -p sphincs-tz-shared --target thumbv8m.main-none-eabi`
  — **EQUIV** (clean, no warnings)
- `cargo clippy -p sphincs-tz-shared -- -D warnings` — **N/A** (sandbox
  denies `cargo clippy`; behaviour-preserving since no source changed)
- `cargo test -p sphincs-tz-shared` — **EQUIV** (18 tests; same set
  as pre-pass)
- Firmware binary build / SHA-256 — **N/A** (this is a host-runnable
  crate; the firmware crates that consume it are out of scope here)
