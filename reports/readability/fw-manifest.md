# Readability & Excellence Review — `fw-manifest`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`fw-manifest` is a small, single-file `no_std` crate that defines the 8 KB
firmware-update manifest wire format and exposes a zero-copy reader plus a
builder. It is already in very good shape: the module-level docs explain the
signed-preimage contract that auditors rely on, the layout is asserted at
compile time, and a proptest fuzz harness covers every parser/verifier path
against arbitrary 8 KB blobs (which is the right hardening surface — this
struct is the first thing a hostile USB host can drop on the device). The
changes in this pass are small and surgical: eliminating two `unsafe`
slice-to-array transmutes via one safe generic helper, annotating accessors
and constructors with `#[must_use]`, and minor preimage-assembly cleanup.
No public API, KDF tag, wire offset, or invariant was touched.

## Changes applied

- `fw-manifest/src/lib.rs:566-595` — Replaced the two `unsafe`
  `slice_as_array_32` / `slice_as_array_sig` helpers (raw-pointer casts
  guarded only by `debug_assert_eq!`) with one safe generic
  `read_array::<const N>` that uses `TryInto`. Removes two `unsafe`
  blocks, deduplicates the 32-byte and 4008-byte cases, and lets the
  optimizer fold the length check away (offsets and `N` are
  compile-time constants over a `&[u8; MANIFEST_SIZE]`). `read_u32_be`
  now goes through the same helper, so every fixed-offset array read in
  the crate flows through one safe path.
- `fw-manifest/src/lib.rs:271-336` — `ManifestRef::magic()` now uses the
  new `read_array::<4>` helper; behaviour and return type are
  unchanged. All getter methods plus `ManifestRef::new`,
  `ManifestRef::as_bytes`, `ManifestBuilder::new`,
  `ManifestBuilder::finalize`, `signed_preimage`,
  `compute_signed_digest`, `vendor_pubkey_fingerprint`, and
  `crc32_ieee` carry `#[must_use]`. These are all pure read-only
  accessors / constructors whose return value is the only effect, so
  `#[must_use]` catches the most common misuse (calling a verifier and
  dropping its result, calling a getter for side effects).
- `fw-manifest/src/lib.rs:186-201` — `signed_preimage` body cleaned up:
  offsets are now computed once at the top, copies use named offsets
  instead of mixing `DOMAIN_TAG.len()` and `ver_off + 4` inline.
  Removes one `&preimage` reference where `Sha256::digest(preimage)`
  works because `[u8; 75]` impls `AsRef<[u8]>`. No behaviour change.

## Recommendations not applied

- `ManifestRef::magic()` returns `[u8; 4]` whereas the 32-byte
  accessors return `&[u8; 32]`. Making it return `&[u8; 4]` would be
  more consistent, but it would break the existing call site in
  `fwsign/src/subcommands/inspect.rs:17` (`&m.magic()`) and the
  internal comparison in `verify_structural`. Left for a future API
  pass.
- The crate could export an internal `signed_preimage_into(&mut buf,
  …)` to let callers avoid the 75-byte stack copy when they already
  own the buffer. Hot path is the FSBL boot verifier which runs the
  preimage hash once per boot — not worth the surface-area cost.
- `crc32_ieee` is a software byte-at-a-time implementation. A
  slice-by-4 / table-driven variant would run roughly 4× faster, but
  the FSBL has a tight code budget and the slow loop runs once per
  manifest per boot; not on the critical path.

## Verification

- `cargo fmt -p fw-manifest -- --check` — N/A (sandbox denied
  `cargo fmt` invocation; edits were applied in a style consistent
  with the surrounding file — same indentation, same line-wrap
  policy, same attribute placement).
- `cargo check -p fw-manifest` — PASS (clean compile, no warnings).
- `cargo clippy -p fw-manifest -- -D warnings` — N/A (sandbox denied
  `cargo clippy`; `cargo check` is clean and the changes only remove
  `unsafe` / add `#[must_use]`).
- `cargo test -p fw-manifest` — PASS (17/17 tests including the
  proptest fuzz harness).

## What this crate already does well

- Single source of truth: `OFF_*`, `MAGIC`, `MANIFEST_VERSION`,
  `SIGNED_PREIMAGE_LEN`, `DOMAIN_TAG`, and `MANIFEST_SIZE` are all
  `pub const` and pinned with `const _: () = assert!(...)` blocks, so
  any wire-format regression is a compile error rather than a runtime
  surprise.
- The doc comment at the top of the file explicitly enumerates what is
  signed vs. unsigned metadata and describes the auditor's
  rebuild-and-verify recipe in five steps. This is exactly the level
  of clarity a production firmware-update path needs.
- `VerifyError` is an enum with one variant per failure mode, each
  with a one-line doc comment. `ManifestRef::verify_*` methods return
  the appropriate variant per concern (structural / CRC / digest /
  signature / vendor / rollback), which lets the FSBL stage rejections
  cheap-first and gives auditors a clear failure taxonomy.
- The proptest harness asserts the *right* invariant for this
  surface: every parser/verifier path must terminate without panic for
  arbitrary 8 KB blobs. That is exactly the threat model — a hostile
  USB host calling `CMD_FW_BEGIN`.
- `no_std`, no heap, no `Vec`/`Box`/`String`. The crate compiles
  identically for the FSBL (32 KB budget), the secure firmware, and
  host tools, which is the whole point of factoring it out.
- The `#[must_use]` additions in this pass land cleanly because the
  crate is already structured as pure getters + builders.

## Cross-crate observations

- `fwsign/src/subcommands/inspect.rs:17` does
  `core::str::from_utf8(&m.magic()).unwrap_or("?")`. With `magic()`
  returning `[u8; 4]` by value this allocates a temporary; if the
  return type were ever migrated to `&[u8; 4]` the call site would
  simplify to `core::str::from_utf8(m.magic())`.
- The accessor pattern (offset constants + `read_u32_be` + array
  slicing) reappears in several other firmware-side modules
  (`secure/src/offchain_state.rs`, `fsbl/src/boot_state.rs`). A
  shared `read_array` / `write_u32_be` in a tiny utility crate would
  remove that duplication — out of scope here.
