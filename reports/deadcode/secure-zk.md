# Dead-Code Removal — `secure-zk`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
BLS12-381 Groth16 verifier + Poseidon + VK bundle.

Files audited:
- `secure/src/zk/mod.rs` (278 lines)
- `secure/src/zk/groth16.rs` (292 lines)
- `secure/src/zk/poseidon.rs` (212 lines)
- `secure/src/zk/vk_bundle.rs` (128 lines)
- `secure/src/zk/vk_data.rs` (79 lines)
- `secure/src/zk/test_vectors.rs` (82 lines)
- `secure/src/zk/generated/poseidon_constants.rs` (2136 lines, auto-generated — skipped)

## Summary
The `secure-zk` slice is nearly clean. Two genuinely-dead public items
were removed: `VerificationKey::hash` (groth16.rs) and the
`MAX_VK_BUNDLE_LEN` constant (vk_bundle.rs). Neither had any caller in
the workspace; the `hash` docstring referenced a Merkle-leaf use that
the actual `verify_vk_bundle` implementation has long since replaced by
inlining the canonical leaf bytes. Test count (121 passing) and warning
count (39) are byte-identical pre/post; every other apparent dead item
(`vk_data`, `test_vectors`, the `poseidon2` arity arm) turned out to be
consumed by `zk-test/src/main.rs` via `#[path]` re-includes or to be
intentionally exposed surface.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/zk/groth16.rs:20` | `use sha2::{Digest, Sha256};` import | 1 | only consumer was `VerificationKey::hash`, now removed |
| `secure/src/zk/groth16.rs:93-105` | `VerificationKey::hash` | 1 | zero callers workspace-wide; `verify_vk_bundle` builds the canonical leaf bytes inline (chain_id ‖ contract ‖ vk) and walks the SHA-256 Merkle proof itself; the host-side `zk-test` ships its own VK struct without a `hash()` method |
| `secure/src/zk/vk_bundle.rs:28-31` | `pub const MAX_VK_BUNDLE_LEN` | 1 | zero callers workspace-wide; the only mention outside the definition is a sibling-slice removal-report file |

## Reverted during bisect
None.

## Cross-slice observations
None within the audit window.

## Skipped
- `secure/src/zk/generated/poseidon_constants.rs` — auto-generated from
  `tools/export_poseidon_constants.js`, marked DO NOT EDIT.
- `secure/src/zk/vk_data.rs` and `secure/src/zk/test_vectors.rs` —
  declared in `mod.rs` only under `cfg(feature = "debug-log")` (or not
  at all), but each is re-included via `#[path = ...]` from
  `zk-test/src/main.rs`. Live cross-crate consumers — bucket 2.
- `poseidon::poseidon_fields` arity-2 arm — `poseidon_bytes` never
  routes there in this codebase, but `poseidon_fields` is `pub` and the
  module docstring explicitly lists arity 2 as supported. Left intact
  to avoid narrowing a public API surface.
- `secure/src/zk/test_data/vk_bytes.bin`, `vk_hash.bin` — binary blobs,
  referenced from architecture docs as the Aave V3 reference VK
  fixtures. Not consumed by the build, but kept as documented test
  artefacts.

## Equivalence check
Clippy + `cargo check -p sphincs-tz-secure` against the host toolchain
fail pre- and post-deletion alike because the secure binary's
semihosting imports require a Cortex-M target; the host equivalence
gate is `cargo test`.

- `cargo fmt -p sphincs-tz-secure --check` — N/A (sandbox blocked the
  invocation in both baseline and post-deletion runs; no formatting
  changes were made — only line deletions)
- `cargo check -p sphincs-tz-secure` (default features) — N/A
  (`default = []`, crate intentionally requires explicit features; same
  state pre/post)
- `cargo check -p sphincs-tz-secure --features mock-se,debug-log,ui-semihosting`
  — N/A on host (`cortex_m_semihosting` host-incompatible; same pre/post)
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (clippy
  invocation blocked by the sandbox; not retried)
- `cargo test -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting`
  — **EQUIV** (baseline: 121 passed / 0 failed / 39 warnings; post: 121
  passed / 0 failed / 39 warnings)
- Firmware binary SHA-256 — N/A (no firmware build attempted; deletions
  remove only never-emitted symbols, so any thumbv8m image would also
  be byte-equivalent modulo timestamp metadata).
