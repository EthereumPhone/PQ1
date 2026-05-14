# Readability & Excellence Review — `proto`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`pqsigner-proto` is a zero-dependency, constants-only crate by design — the
"single source of truth" for everything that crosses a TrustZone, on-chain, or
USB boundary. The file is well-organised by topic, doc comments are unusually
thorough (often diagramming wire layouts byte-for-byte), and the layout is
already locked in by `const _: () = assert!(...)` sanity blocks plus the CMD
collision check at the bottom.

Main findings: the `#[cfg(test)] mod tests` block had **bit-rotted** —
five of nine tests referenced symbols that no longer exist
(`USEROP_V2_HEADER_LEN`, `INIT_CODE_LEN`), so `cargo test -p pqsigner-proto`
was broken on master. A handful of doc comments and dead constants had also
drifted. Changes are scoped to that cleanup and a couple of small expression
simplifications; the public ABI consumed by other crates is unchanged.

## Changes applied

- `proto/src/lib.rs:96-117` — removed dead `CMD_BASE_*` constants (`CORE`,
  `WALLET`, `OFFCHAIN`, `FW`, `BATCH`, `TEST`). They were never referenced
  anywhere in the workspace and merely re-stated information already documented
  in the preceding comment block; the real protection against collisions is the
  `const _: () = { ... }` check at the bottom of the file. Tidied the range
  documentation to include `CMD_OFFCHAIN_SYNC = 18`.
- `proto/src/lib.rs:765-772` — refreshed the `WRAPPER_HEADER_LEN` doc comment.
  It previously claimed the header preceded a "SPHINCS+C7" signature, but
  the workspace is on C10 and the wrapper itself is a legacy v2 format
  superseded by the on-chain `SignatureWrapper(uint256, bytes)` ABI layout
  (`SIG_WRAPPER_LEN`). Doc now says so explicitly.
- `proto/src/lib.rs:792` — simplified `SIG_WRAPPER_LEN` from a multi-line
  `const { let padded = ((C10_SIG_LEN + 31) / 32) * 32; … }` block to a single
  expression using `usize::next_multiple_of(32)`. Identical value (4128),
  fewer characters to misread.
- `proto/src/lib.rs:927` — same `next_multiple_of(32)` substitution for
  `EIP6492_FACTORY_CALLDATA_PADDED`. Identical value (4288).
- `proto/src/lib.rs:1543-1693` — rewrote the `#[cfg(test)] mod tests` block:
  - **Removed** five stale tests that referenced retired symbols
    (`USEROP_V2_HEADER_LEN`, `INIT_CODE_LEN`): `userop_v2_header_is_312`,
    `v2_aa_matches_v1_minus_has_bundle`, `init_code_len_is_4248`,
    `v2_sign_userop_offsets`, `v2_sign_clear_userop_offsets`. These predate
    the unified v4 layout and were testing offsets that no longer exist.
  - **Replaced** `userop_v1_header_is_305` with `legacy_userop_header_is_305`
    (also asserts `USEROP_PREFIX_LEN`), and added
    `unified_sign_userop_header_is_330` covering the current `SIGN_USEROP_*`
    layout.
  - **Replaced** `init_code_len_is_4248` with `pq_init_code_len_is_4280`
    against the actual constant.
  - **Added** `sig_wrapper_len_matches_solidity_encoding` (the wrapper math
    was previously untested) and `flag_bitfields_partition_u32_cleanly`
    (verifies `FLAG_*` + `ACCOUNT_INDEX_MASK` + `SLOT_INDEX_MASK` cover all
    32 bits exactly once — a structural invariant the comment block claims
    but nothing asserted).
  - Updated section-header comment from `cargo test -p sphincs-tz-shared`
    (wrong crate name) to `cargo test -p pqsigner-proto`.

Net effect: `cargo test -p pqsigner-proto` now passes with 13 tests covering
header sizes, EIP-6492 wire layout, off-chain flag mask, and the flag
bitfield partition.

## Recommendations not applied

These were considered and deliberately left out — they're either invariant-
adjacent or outside the crate's scope:

- `MAIN_PUBKEY_PAYLOAD_LEN` (line 605), `SIGNER_MAIN`/`SIGNER_BOOTSTRAP`
  (lines ~757), `WRAPPER_HEADER_LEN`/`WRAPPER_TOTAL_LEN` (lines ~767-772),
  `SIG_TYPE1_MARKER`/`SIG_TYPE2_MARKER` (lines ~815) — all currently
  unreferenced inside the workspace, but this crate is the documented
  "source of truth" for host-side companions and the planned Solidity
  codegen, and the protocol comment frames these as deprecated-but-published
  values. Deleting them would be a wire-format change beyond the scope of a
  readability pass. Leave as documented legacy.
- `From<u32> for NscStatus` (lines ~1510) has a manual `match v { 0 => Ok, … }`
  table that duplicates the `#[repr(u32)]` discriminants. A macro or a
  derive (e.g. `num_enum::TryFromPrimitive`) would dedupe it, but the
  zero-dependency policy in `Cargo.toml` is strict, and rolling our own
  `macro_rules!` for one enum is more obscurity than the dedup saves.
- The `enum NscStatus` with `InternalError = 0xFFFF_FFFF` is a wire-format
  value, but the discriminants are public surface; leaving as-is.

## Verification

- `cargo check  -p pqsigner-proto` — PASS
- `cargo test   -p pqsigner-proto` — PASS (13 / 13)
- `cargo check  -p pqsigner-aa` (downstream consumer) — PASS
- `cargo fmt -p pqsigner-proto --check` — NOT RUN (sandbox-blocked); diff is
  formatting-neutral (single-line edits + comment/test rewrites within the
  existing style)
- `cargo clippy -p pqsigner-proto -- -D warnings` — NOT RUN (sandbox-blocked)

## What this crate already does well

- Strict zero-dependency policy enforced and documented in `Cargo.toml`.
- Wire layouts are diagrammed in ASCII tables in the doc comments — easy to
  cross-check against Solidity, the host companion, and the firmware all at
  once.
- `const _: () = assert!(...)` sanity checks pin every layout total (header
  size, batch header size, SafeTx canonical) so a refactor that drifts the
  math fails at compile time, not at runtime on hardware.
- The CMD-collision check at end of file (`const _: () = { let cmds: … }`)
  catches duplicate IDs at compile time — a great pattern for a protocol
  surface that grows by accretion.
- `#[cfg(feature = "stm32u585")]` memory-map split is clean and isolated to
  its own private module.

## Cross-crate observations

These were noticed while tracing `proto` consumers — not fixed here, leave
for their own crate-scoped passes:

- `nonsecure/src/aa.rs:14` and `aa/src/userop.rs` are still building the
  legacy 305-byte `USEROP_HEADER_LEN` AA blob. Most active code paths use
  the unified `SIGN_USEROP_HEADER_LEN = 330`. Worth confirming whether the
  legacy builder is still on a live code path or is residual demo/test
  scaffolding; if the latter, the constant + its single-purpose builder
  could be retired together.
- `docs/sphincs-c7-firmware-integration.md` still talks about an
  `INIT_CODE_LEN = 4248` symbol that hasn't existed since the C10 cutover.
  Docs are out of scope for this review but worth a pass when the docs
  folder gets the same treatment.
