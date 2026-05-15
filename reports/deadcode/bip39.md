# Dead-Code Removal — `bip39`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
no_std 24-word English BIP-39.

Files audited:
- `bip39/Cargo.toml` (17 lines)
- `bip39/src/lib.rs` (391 lines)
- `bip39/src/wordlist.rs` (2058 lines — canonical BIP-39 English wordlist)
- `bip39/tests/vectors.rs` (153 lines)

## Summary

This slice is already clean — nothing to remove. The crate received a focused
readability pass on 2026-05-14 (see `reports/readability/bip39.md`) which
removed the only obvious dead helper (a hand-rolled `starts_with`) and
deduplicated `lookup_word_exact` / `lookup_prefix` into one `lowercase_ascii`
backing helper. Every remaining public item has a real consumer in the
workspace and every private helper is on a live path. No vestigial code, no
commented-out blocks, no stale TODOs, no unused deps or features.

Cross-workspace symbol audit (verified by `Grep` across the whole tree):

| Item | Kind | Consumers |
|---|---|---|
| `WORDLIST` | pub const | `secure::ui::seed_wizard`, `secure::fw_update::mod`, `secure::measured_boot`, `fwmeasure::main`, `fwsign::subcommands::sign` |
| `WORD_COUNT` | pub const | `secure::ui::seed_wizard` |
| `ENTROPY_BYTES` | pub const | `domain` (`ENTROPY_LEN = ENTROPY_BYTES`) |
| `SEED_BYTES` | pub const | crate-internal (signature of `to_seed`, `pbkdf2_hmac_sha512`); kept `pub` as a documented API constant for callers reasoning about the seed buffer |
| `Mnemonic` | pub struct | `domain`, `secure::*`, `bip39::tests` |
| `BipError` (+ `Display`) | pub enum | `secure::ui::seed_wizard` (`Mnemonic::from_indices`/`from_words` return), `bip39::tests` |
| `Mnemonic::from_entropy` | pub fn | `domain::lib`, `secure::main`, tests |
| `Mnemonic::from_words` | pub fn | `secure::main`, tests |
| `Mnemonic::from_indices` | pub fn | `secure::ui::seed_wizard` |
| `Mnemonic::to_entropy` | pub fn | `secure::crypto`, tests |
| `Mnemonic::word` | pub fn | `secure::ui::seed_wizard`, tests |
| `Mnemonic::words` | pub fn | `secure::main`, `to_seed` (self), tests |
| `Mnemonic::word_index` | pub fn | `secure::ui::seed_wizard` |
| `Mnemonic::to_seed` | pub fn | `domain::lib` |
| `hash_to_word_indices` | pub fn | `secure::measured_boot`, `secure::fw_update::verify`, `fwmeasure::main`, `fwsign::subcommands::sign` |
| `lookup_prefix`, `PrefixLookup` | pub fn / enum | `secure::ui::seed_wizard` |
| `lookup_word_exact` | pub fn | crate-internal only (`from_words`). Kept as part of the documented BIP-39 helper surface for symmetry with `lookup_prefix`; demoting to `fn` would be a visibility tweak rather than dead-code removal and risks breaking a non-obvious future consumer. Recommendation only — see below. |

Private helpers (`read_11_bits`, `write_11_bits`, `lowercase_ascii`,
`pbkdf2_hmac_sha512`, `HmacSha512`, `MAX_WORD_LEN`, `BITS_PER_WORD`,
`PBKDF2_ITERS`) are each used on the live path. `Drop for Mnemonic` and
`Debug for Mnemonic` are required by the zeroize / redaction invariants.

## Deletions applied

_(none)_

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|

## Reverted during bisect

_(none — nothing was deleted)_

## Cross-slice observations

- `reports/readability/bip39.md:51-52` already flags two consumer-side
  zeroize-on-drop opportunities for `entropy` locals in `secure/src/main.rs`
  and `domain/src/lib.rs`. Out of scope for this slice; not dead code, just a
  hardening recommendation.

## Skipped

- `bip39/src/wordlist.rs` — canonical, hash-pinned BIP-39 English wordlist
  (sha256 documented at the top of the file). All 2048 entries are
  load-bearing.
- No pre-existing test failures or warnings to carry over.

## Recommendations not applied (kept as recommendations)

- **`pub fn lookup_word_exact` → `fn lookup_word_exact`.** Only caller is
  `from_words` in the same file. Demoting visibility is behavior-preserving
  but is a visibility cleanup, not dead-code removal, and the symmetric pair
  with `lookup_prefix` is a reasonable library-surface choice. Risk of
  removal: silently breaks a future external consumer. Leaving alone.
- **`pub const SEED_BYTES`.** Used only inside the crate today (return-type
  of `to_seed`, signature of `pbkdf2_hmac_sha512`). It is, however, the
  documented length of the BIP-39 seed buffer — a constant external callers
  may legitimately want when sizing their own buffers. Leaving `pub`.

## Equivalence check

No source edits were applied; baseline and post-deletion states are the same
working tree, so equivalence is trivially preserved. The baseline commands
that completed successfully:

- `cargo check -p sphincs-tz-bip39` — **EQUIV** (clean build, no warnings)
- `cargo test -p sphincs-tz-bip39` — **EQUIV** (1 unit + 9 integration + 1
  doctest, all pass; same counts as readability-pass baseline)
- `cargo fmt -p sphincs-tz-bip39 -- --check` — **N/A** (sandbox blocked
  `cargo fmt` invocation; no formatting was changed)
- `cargo clippy -p sphincs-tz-bip39 -- -D warnings` — **N/A** (sandbox
  blocked `cargo clippy` invocation; no source was changed so no new lints
  can have been introduced)
- Firmware-target build / binary SHA-256 — N/A (host-only library crate).
