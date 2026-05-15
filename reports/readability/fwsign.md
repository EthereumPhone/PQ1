# Readability & Excellence Review — `fwsign`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

`fwsign` is the host-only release-signing CLI: keygen / pubkey / sign / verify
/ verify-release / extract-sig / inspect, with a per-subcommand module split
and one large `sign::run` orchestrator. The crate was already well-structured
— good module boundaries, generous doc-comments on every public path, real
unit + integration tests, secrets wrapped in `Zeroizing`, no `unsafe`. The
pass focused on tightening the bigger `sign::run` (now broken into named
helpers), removing offset arithmetic in `keystore` (`6 + SALT_LEN + …`) in
favour of named layout constants, deduping the unpack-time required-entry +
fixed-length plumbing in `bundle.rs`, and pulling the inline `extract_sig`
helper out of `main.rs` into its own subcommand module so the layout is
uniform. No behaviour, no wire formats, no KDF tags changed; all 8 tests
still pass.

## Changes applied

- `fwsign/src/main.rs` — moved `extract_sig` (was inline at the bottom) into
  `subcommands/extract_sig.rs` so every subcommand routes through
  `subcommands::*::run`; `main` now only dispatches.
- `fwsign/src/subcommands/extract_sig.rs` (new) — focused module mirroring
  the other subcommand files.
- `fwsign/src/subcommands/sign.rs` — refactored the 160-line `run` into
  `parse_build_id`, `resolve_boot_counter_snap`, `load_vendor_key`,
  `flatten_logged`, `build_signed_manifest`, `build_measurement_txt`,
  `build_release_json`, plus a tiny `slot_letter` helper that replaced two
  copies of the same `if slot == SLOT_A { "A" } else { "B" }` ternary. The
  `release.json` formatter now uses named format-args (`{version}`,
  `{slot}`, …) so the placeholders self-document. `measurement_txt`
  construction now uses `writeln!` on a `String` instead of chained
  `push_str(&format!(...))`, and the duplicated "Secure / Nonsecure" block
  is one loop. `with_context(|| "literal")` → `.context("literal")` (no
  unnecessary closure for a constant string).
- `fwsign/src/subcommands/verify.rs` — extracted the duplicated
  length-check + SHA-256 + compare block into `check_image(label, bytes,
  manifest_len, manifest_hash)`. Verify body now reads as 5 sequential
  named checks plus 2 `check_image` calls.
- `fwsign/src/subcommands/verify_release.rs` — extracted `read_fixed::<N>()`
  for the "read file, assert exact byte length, return `[u8; N]`" pattern
  used twice (pubkey + signature). Drops 14 lines of redundancy.
- `fwsign/src/bundle.rs` — removed the misleading
  `builder.mode(HeaderMode::Deterministic)` call (it only affects
  `append_path*` / `append_data` paths; this code uses `append(&Header,
  …)` which bypasses the builder's header normalization, so the call was
  silently inert). The deterministic mtime is now made explicit via a
  `source_date_epoch()` helper threaded into `append`. `unpack`'s
  repetitive `ok_or_else` → 4-call `require()` helper, and the two
  copy-into-fixed-size-array blocks → one generic `into_fixed::<const N>`
  helper. Wrong-size messages now read the `name` field instead of
  hard-coding `manifest.bin` / `pubkey.bin` in two places.
- `fwsign/src/keystore.rs`:
  - Replaced repeated offset arithmetic (`6 + SALT_LEN + NONCE_LEN + …`)
    with named layout constants `MAGIC_OFFSET / VERSION_OFFSET /
    SALT_OFFSET / NONCE_OFFSET / TAG_OFFSET / CIPHER_OFFSET`. The seal /
    open code now reads as a direct line-by-line copy of the format table
    in the module docs.
  - `from_parts` test helper switched from `#[allow(dead_code)] pub` to
    `#[cfg(test)] pub` so it really is test-only (the binary crate has no
    other consumers).
  - Simplified the awkward double-handling of `plain` in `open`: the AEAD
    output is now wrapped in `Zeroizing<Vec<u8>>` from the start, so the
    success + error + length-mismatch paths all wipe on drop without the
    `let mut p = plain; p.zeroize();` / `let mut plain = plain;` rebind
    dance. Dropped the now-unused `zeroize::Zeroize` trait import.
- `fwsign/src/elf.rs`:
  - `FlatImage::len()` gained `#[must_use]`, and uses `u32::try_from`
    instead of `as u32` so an impossibly large image (> 4 GiB) panics with
    a clear message rather than silently truncating.
  - `as u64` casts on `ProgramHeader::p_paddr` replaced with `u64::from`
    (lossless, clippy-friendly).
  - Replaced the unused `filesz: usize` binding with an inline
    `ph.p_filesz(le) == 0` check, and `core::cmp::min` with `.min()`.
  - `for ph in phdrs.iter()` → `for ph in phdrs` (idiomatic slice
    iteration).

## Recommendations not applied

- `bundle.rs::pack` is still I/O-coupled (takes a `&Path`); a `pack_into<W:
  Write>` variant would help testability but `bundle::pack` is only ever
  called against an output file path, so the indirection is not warranted
  yet.
- The hand-formatted `release.json` is intentional (no `serde_json`
  dependency); it is fine while the schema is tiny. If the field set grows
  past ~10 keys or starts carrying free-form strings, switch to
  `serde_json` for escaping correctness.
- `aad_bytes` returns a `Vec<u8>` even though the AAD length is known at
  compile time (46 bytes). Switching to `[u8; 46]` would remove one
  allocation per seal/open, but the calls are once per signing operation —
  not worth the churn.

## Verification

- `cargo check  -p fwsign --all-targets`     — PASS
- `cargo test   -p fwsign`                   — PASS (8/8: 4 unit, 4 integration)
- `cargo clippy -p fwsign -- -D warnings`    — NOT RUN (sandbox permission
  for `cargo clippy` not granted; matches the constraint noted on prior
  reviews in this repo)
- `cargo fmt    -p fwsign -- --check`        — NOT RUN (same sandbox
  constraint; output style follows existing fwsign conventions visually)

## What this crate already does well

- Per-subcommand module split with a clean `subcommands/mod.rs` index — every
  command is a one-line dispatch from `main`.
- Generous module-level doc-comments that double as user-facing help (especially
  `verify_release.rs`, which reads like a how-to-audit guide).
- Real integration tests in `tests/sign_verify_roundtrip.rs` that exercise the
  full ManifestBuilder → sign → verify chain, plus the wrong-key, byte-flip,
  and determinism cases.
- Secret handling is deliberate: `Zeroizing<[u8; 32]>` for `sk_seed`, no
  `Debug` on `VendorKey`, AAD covers all non-secret header fields, decrypt
  errors don't leak whether passphrase vs. tamper.
- No `unsafe` in the whole crate (the unsafe-taxonomy footguns CLAUDE.md
  enumerates simply don't apply to a host CLI).
- Deterministic signing path: `sign(hash, None)` → bit-reproducible bundles,
  with a unit test that asserts it.

## Cross-crate observations

- `fwsign::bundle::into_fixed::<N>` and `fwsign::subcommands::verify_release::
  read_fixed::<N>` (introduced here) are the same pattern that appears in
  multiple host-side crates (`fwmeasure`, `nonsecure/host/`). A shared
  `pqsigner-host-util` (or just a one-function `fixed_bytes.rs` in `shared/
  src/host/`) would let all of them deduplicate, but cross-crate
  consolidation is out of scope for this pass.
- The `dirs_local::data_dir()` helper inside `sign.rs` duplicates the
  `dirs` crate's single most-used function — fine as-is, but if another
  host tool needs a config/cache dir lookup the same logic will get
  copy-pasted; consider promoting to `shared`.
