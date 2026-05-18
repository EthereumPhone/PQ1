# Dead-Code Removal — `hal`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Trait-only HAL surface (Rng/Sha256/Saes/Flash/Otp/...).

Files audited:
- `hal/Cargo.toml` — 15 lines
- `hal/src/lib.rs` — 295 lines

## Summary
`pqsigner-hal` is a single-file, trait-only specification crate (≈300 LOC,
no_std, zero dependencies). It is PR 1 of the Phase 6 modularity refactor;
PRs 2–4 (`pqsigner-hal-stm32u5`, `pqsigner-hal-mock`, and the
`secure`-side wiring that takes `&mut impl Platform`) are documented as
deferred in `docs/handoff-modularity-refactor.md`. Consequently no other
workspace crate currently `use`s anything from `pqsigner_hal::*` — a fact
already called out in the handoff doc (§4.18 "pqsigner-hal trait crate is
unused so far"). Every `pub` item in this crate is therefore part of the
**spec** the future driver impls must match verbatim, not callable code I
can grep-prove unused; bucket 1's "publicly-consumed library API"
exclusion applies to all of it. There is also no commented-out code, no
imports to prune, no `#[cfg]`-gated branches, no `Debug` impls that would
print secrets, and no vestigial items left from an earlier design. The
`OtpRange::Reserved(u8)` and `TamperCause::Other(u8)` catchall variants
are explicitly designed extension points, not stale stubs. **No
deletions made; slice is healthy.**

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_(none — no deletions attempted)_

## Cross-slice observations
None inside `hal/`. The handoff doc identifies the obvious next step
(actually consume `pqsigner-hal` from `secure/src/hw/*`) but that is a
design-progress task, not dead-code removal, and belongs to whichever
slice owns the secure-world driver impls.

## Skipped
- `cargo fmt -p pqsigner-hal --check` — sandbox denied (permission gate
  on the `cargo fmt` invocation).
- `cargo clippy -p pqsigner-hal -- -D warnings` — sandbox denied (same
  permission gate).

The clippy / fmt baseline could not be captured, but since **no source
file was modified**, the post-state is byte-identical to the baseline
for every command, so the equivalence rule is trivially satisfied for
those tools as well.

## Equivalence check
No source changes ⇒ pre- and post-deletion outputs are byte-identical by
construction for every command. Captured outputs:

- `cargo fmt -p pqsigner-hal --check` — N/A (sandbox denied, no source
  change ⇒ trivially equivalent).
- `cargo check -p pqsigner-hal` (default features) — **EQUIV**
  (`Finished \`dev\` profile [optimized + debuginfo] target(s)`; no
  warnings).
- `cargo check -p pqsigner-hal` (extra feature combos) — N/A (crate
  declares no features).
- `cargo clippy -p pqsigner-hal -- -D warnings` — N/A (sandbox denied,
  no source change ⇒ trivially equivalent).
- `cargo test -p pqsigner-hal` — **EQUIV** (0 unit + 0 doc tests; same
  baseline and post).
- (firmware crates) `make <crate-build-target>` — N/A (host-only trait
  crate; no firmware target).
- (firmware crates) binary SHA-256 — N/A (no binary produced).
