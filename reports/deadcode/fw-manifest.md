# Dead-Code Removal — `fw-manifest`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
no_std FW-update manifest format + verify chain.

Files audited:
- `fw-manifest/Cargo.toml` (30 lines)
- `fw-manifest/src/lib.rs` (941 lines)

## Summary
This slice is already clean. Every public item exported from
`fw-manifest` has at least one consumer somewhere in the workspace
(FSBL, secure firmware, fwsign, nonsecure USB transport, the `tools/sca`
fault-sweep harness, or the in-crate test/proptest suite). All internal
helpers (`read_array`, `read_u32_be`, `write_u32_be`, `crc32_ieee`'s loop
body) are reachable through the public surface. No commented-out blocks,
no `#[allow(dead_code)]` patches, no vestigial pre-v0x02 paths, no
unreachable match arms. The compile-time `assert!`s on the layout
constants are intentional wire-format pins. No deletions to apply.

The one borderline observation is the `std = []` feature in
`fw-manifest/Cargo.toml`: nothing in the crate is `#[cfg(feature =
"std")]`-gated, so toggling it does nothing today, even though
`fwsign/Cargo.toml` selects it and a stale comment in
`fsbl/Cargo.toml` references it. Cleaning it up requires edits in
two out-of-scope sibling crates, so it is recorded under
"Cross-slice observations" rather than acted on here.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| _(none)_ | | | |

## Reverted during bisect
_(none — no deletions were attempted.)_

## Cross-slice observations
- `fw-manifest/Cargo.toml:21` declares `std = []`, but no
  `#[cfg(feature = "std")]` exists anywhere in `fw-manifest/src/lib.rs`.
  Consumers: `fwsign/Cargo.toml:15` enables it; `fsbl/Cargo.toml:35`
  carries a stale comment ("sha2 is gated behind fw-manifest's
  default-off std feature") that no longer matches reality (sha2 is an
  unconditional dependency of `fw-manifest`). Recommendation: drop the
  feature from `fw-manifest/Cargo.toml`, drop `features = ["std"]` from
  `fwsign/Cargo.toml:15`, and refresh the comment in
  `fsbl/Cargo.toml:34-36`. Touches three crates so it is left for a
  cross-slice pass.

## Skipped
- The crate has no generated files, no vendored blobs, and no
  pre-existing test breakage. Nothing was skipped.

## Equivalence check
No source edits were made, so post-deletion outcomes are trivially
identical to baseline.

- `cargo fmt -p fw-manifest --check` — N/A (no source edits)
- `cargo check -p fw-manifest` — EQUIV (baseline `Finished dev profile`; no
  post-deletion delta — no source edits)
- `cargo clippy -p fw-manifest -- -D warnings` — N/A (no source edits; clippy
  baseline not re-captured to avoid a no-op delta)
- `cargo test -p fw-manifest` — EQUIV (17 passed, 0 failed pre-edit; no
  source edits → identical post)
- Firmware build targets — N/A (host-runnable crate; not a firmware
  artefact)
- Binary SHA-256 — N/A
