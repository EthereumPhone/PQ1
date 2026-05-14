# Readability & Excellence Review — `bip39`

_Date_: 2026-05-14
_Reviewer_: Claude Code (ultrathink)

## Summary

The crate was already in good shape — small, single-file, well-documented, no `unsafe`, with a solid test suite. The audit applied focused polishing: bringing the secret type in line with the project's `!Copy + !Clone` rule for secret types, switching the hand-rolled `Drop` wipe to `Zeroize` (compiler fence), replacing manual binary searches with `slice::binary_search` / `partition_point`, deduplicating the case-folding code path, and adding `#[must_use]`, `#[inline]`, and `Display` polish. No observable behaviour, KDF tag, or wire format changed.

## Changes applied

All edits in `bip39/src/lib.rs`:

- **Removed `Clone` from `Mnemonic`** — CLAUDE.md mandates secret types be `!Copy + !Clone`. No caller in the workspace clones a `Mnemonic`. Doc comment updated so the "`mem::forget` is the only way to leak" claim is now actually true.
- **Replaced hand-rolled `Drop` with `self.indices.zeroize()`** — adds the `zeroize` compiler fence so the wipe cannot be elided; semantically identical to the previous loop.
- **Implemented `Display for BipError`** — error types should be `Display`-able for log lines without leaking `{:?}` debug formatting.
- **`#[must_use]`** on pure constructors / queries: `from_entropy`, `word`, `word_index`, `to_seed`, `hash_to_word_indices`, `lookup_word_exact`, `lookup_prefix`.
- **`#[inline]`** on the bit-pack helpers `read_11_bits` / `write_11_bits` — tight 11-bit chunkers used in inner loops.
- **Replaced manual binary search in `lookup_word_exact`** with `slice::binary_search_by` — fewer lines, same behaviour, no off-by-one risk.
- **Replaced manual binary search in `lookup_prefix`** with `slice::partition_point`, and replaced the bespoke `starts_with` helper with the standard `<[u8]>::starts_with`. The helper function was removed.
- **Factored out `lowercase_ascii`** — the case-folding-into-stack-buffer dance lived in both `lookup_word_exact` and `lookup_prefix`; one helper now backs both. `MAX_WORD_LEN` (16) is named instead of inlined as `16` / `lower.len()` in two places.
- **Tightened `to_seed`**: renamed the ambiguous `len` to `password_len`, hoisted `"mnemonic"` to a `SALT_PREFIX` const, expanded the doc comment with a `# Panics` section describing the passphrase-length assertion.
- **Tightened `pbkdf2_hmac_sha512`**: write directly into `out` (dropped the intermediate `block` buffer — `dk_len == 64 == one HMAC-SHA512 block`, so the buffer was a copy of `out`); the duplicated `Hmac::new_from_slice(...).expect(...)` call collapsed into a `new_mac` closure with a comment justifying why HMAC's `new_from_slice` cannot fail here.
- **Cleaned numeric casts** to `u32::from(byte)` where possible (clippy-style preference over `as u32`).
- **Docstring fixes**: `word_index` now describes what it returns instead of "Equality on word indices"; doc-links use `[`Mnemonic::xxx`]` form so rustdoc cross-links resolve.

## Recommendations not applied

- **`pp.len() <= 248` `assert!`** — kept as `assert!` rather than returning a `Result`; the call site in `secure/src/crypto.rs` passes a fixed `""` passphrase, so turning this into a fallible API would force every caller to handle an impossible error.
- **`Sha256::digest(entropy)[0]` returns a `GenericArray` — could `.zeroize()` the temporary** — the discarded 31 trailing bytes of the checksum hash do not reveal more about the entropy than the entropy itself, so this would be ceremonial.
- **`pbkdf2_hmac_sha512`'s `u_prev` is not wiped on the way out** — it is the last HMAC output, which is one element of the XOR sum already in `out`; wiping does not buy anything useful. Left as-is.
- **No `Display` for `Mnemonic`** — intentional. The `Debug` impl already redacts; adding `Display` would invite logging the words.

## Verification

- `cargo check -p sphincs-tz-bip39` — **PASS** (clean build, no warnings)
- `cargo test -p sphincs-tz-bip39` — **PASS** (9 integration tests + 1 doctest, all pass)
- `cargo fmt -p sphincs-tz-bip39 -- --check` — **N/A** (sandbox blocked `cargo fmt` and `cargo clippy` in this session; the source is rustfmt-compatible and was hand-formatted to match the rest of the workspace style)
- `cargo clippy -p sphincs-tz-bip39 -- -D warnings` — **N/A** (sandbox blocked; no new clippy-flagged patterns introduced — `u32::from`, `inline`, idiomatic slice methods are clippy-preferred)

## What this crate already does well

- Zero `unsafe`. `#![forbid(unsafe_code)]` at the crate root.
- Self-contained, no upstream `bip39` dep, minimal `Cargo.toml`.
- `Debug` redaction on the secret type with a test that asserts the redaction holds.
- Bit-packing helpers are correct and well-commented (the 24-bit window math is the kind of code that earns a comment).
- Test suite includes the official Trezor vectors plus the negative paths (bad checksum, unknown word, wrong length, case-insensitivity).

## Cross-crate observations

- `secure/src/main.rs:434` constructs a `Mnemonic::from_entropy(&entropy)` immediately after generating fresh entropy; the entropy local should be `zeroize::Zeroize`d after use (not in scope for this audit).
- `domain/src/lib.rs:268` similarly passes an `entropy` slice through `Mnemonic::from_entropy`; verify the caller's lifetime of the local entropy buffer is bounded by a zeroize-on-drop type.
- Nothing in `secure/src/ui/seed_wizard.rs` relies on `Mnemonic: Clone`, so removing the bound here is non-breaking.
